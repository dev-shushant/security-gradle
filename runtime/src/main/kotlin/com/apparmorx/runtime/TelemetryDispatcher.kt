package com.apparmorx.runtime

import android.content.Context
import android.os.Build
import android.util.Log
import java.io.File
import java.io.IOException
import java.net.URI
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.HttpsURLConnection
import kotlin.math.min

private const val TAG = "AppArmorX"
private const val MIN_DISPATCH_INTERVAL_MS = 30000L

/**
 * Self-hostable, offline-resilient, encrypted HTTPS telemetry dispatcher.
 * Delivers structured security incident reports to customer-configured endpoints.
 * Disabled by default. No network requests are made unless explicitly configured.
 *
 * Resiliency features:
 * - Offline persistent disk queueing via [OfflineEventQueue] (max 50 events, zero disk exhaustion).
 * - Exponential backoff and circuit breaker (trips after 5 consecutive failures).
 * - Cryptographic HMAC-SHA256 request authentication signing when telemetryHmacKey is set.
 */
object TelemetryDispatcher {
    internal const val BASE_BACKOFF_MS = 5000L
    internal const val MAX_BACKOFF_MS = 300000L // 5 minutes
    internal const val CIRCUIT_BREAKER_THRESHOLD = 5

    private val executor = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "AppArmorX-telemetry").apply { isDaemon = true }
    }
    private val lastDispatchTime = AtomicLong(0L)
    internal val consecutiveFailures = AtomicInteger(0)
    internal val circuitBreakerUntil = AtomicLong(0L)

    fun dispatchIfDetected(context: Context, snapshot: SecuritySnapshot) {
        val endpoint = snapshot.telemetryUrl.trim()
        if (endpoint.isEmpty() || !endpoint.startsWith("https://")) return

        val queueFile = OfflineEventQueue.defaultQueueFile(context)
        val hmacKey = snapshot.telemetryHmacKey
        val headers = snapshot.enforcement.telemetryHeaders

        // Real threats only. Advisory configuration findings never create an incident report.
        if (TelemetryEvents.incidentChecks(snapshot).isEmpty()) {
            // No new incident: still deliver anything queued while offline, instead of waiting for the next attack.
            if (OfflineEventQueue.size(queueFile) > 0 && System.currentTimeMillis() >= circuitBreakerUntil.get()) {
                executor.execute { flushQueuedEvents(endpoint, hmacKey, queueFile, headers) }
            }
            return
        }

        val now = System.currentTimeMillis()
        if (now - lastDispatchTime.get() < MIN_DISPATCH_INTERVAL_MS) return
        lastDispatchTime.set(now)

        val state = decideProtection(snapshot, now, REQUIRED_EVIDENCE)
        val event = TelemetryEvents.build(UUID.randomUUID().toString(), now, snapshot, state, environment(context), snapshot.enforcement.telemetryDetail)
        executor.execute {
            dispatchOrQueue(endpoint, event.toJson(), hmacKey, queueFile, headers)
        }
    }

    @Suppress("DEPRECATION")
    private fun environment(context: Context): TelemetryEvents.Environment {
        val pm = context.packageManager
        val info = try { pm.getPackageInfo(context.packageName, 0) } catch (_: Exception) { null }
        val installer = try {
            if (Build.VERSION.SDK_INT >= 30) pm.getInstallSourceInfo(context.packageName).installingPackageName else pm.getInstallerPackageName(context.packageName)
        } catch (_: Exception) { null }
        return TelemetryEvents.Environment(
            applicationId = context.packageName,
            appVersionName = info?.versionName.orEmpty(),
            appVersionCode = if (Build.VERSION.SDK_INT >= 28) info?.longVersionCode ?: 0L else (info?.versionCode ?: 0).toLong(),
            debuggable = context.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE != 0,
            sdkInt = Build.VERSION.SDK_INT,
            abi = Build.SUPPORTED_ABIS.firstOrNull().orEmpty(),
            manufacturer = Build.MANUFACTURER.orEmpty(),
            model = Build.MODEL.orEmpty(),
            securityPatch = Build.VERSION.SECURITY_PATCH.orEmpty(),
            installer = installer.orEmpty(),
        )
    }

    internal fun dispatchOrQueue(endpoint: String, jsonBody: String, hmacKey: String, queueFile: File, headers: Map<String, String> = emptyMap()) {
        val now = System.currentTimeMillis()
        if (now < circuitBreakerUntil.get()) {
            OfflineEventQueue.enqueue(queueFile, jsonBody)
            return
        }

        try {
            sendHttpsPost(endpoint, jsonBody, hmacKey, headers)
            consecutiveFailures.set(0)
            circuitBreakerUntil.set(0L)
            flushQueuedEvents(endpoint, hmacKey, queueFile, headers)
        } catch (e: Exception) {
            handleFailure(jsonBody, queueFile, e.message)
        }
    }

    private fun handleFailure(jsonBody: String, queueFile: File, errorMessage: String?) {
        OfflineEventQueue.enqueue(queueFile, jsonBody)
        val failures = consecutiveFailures.incrementAndGet()
        val backoff = calculateBackoff(failures)
        if (failures >= CIRCUIT_BREAKER_THRESHOLD) {
            circuitBreakerUntil.set(System.currentTimeMillis() + backoff)
            Log.w(TAG, "Telemetry circuit-breaker tripped after $failures failures; paused for ${backoff}ms")
        } else {
            Log.w(TAG, "Telemetry delivery failed (attempt $failures): $errorMessage")
        }
    }

    private fun flushQueuedEvents(endpoint: String, hmacKey: String, queueFile: File, headers: Map<String, String> = emptyMap()) {
        val batch = OfflineEventQueue.popBatch(queueFile, 5)
        for ((index, queuedEvent) in batch.withIndex()) {
            try {
                sendHttpsPost(endpoint, queuedEvent, hmacKey, headers)
            } catch (e: Exception) {
                // Re-enqueue the current and remaining un-sent events
                for (remaining in batch.subList(index, batch.size)) {
                    OfflineEventQueue.enqueue(queueFile, remaining)
                }
                val failures = consecutiveFailures.incrementAndGet()
                val backoff = calculateBackoff(failures)
                circuitBreakerUntil.set(System.currentTimeMillis() + backoff)
                break
            }
        }
    }

    internal fun calculateBackoff(failures: Int): Long {
        val exponent = min(failures - 1, 6).coerceAtLeast(0)
        val delay = BASE_BACKOFF_MS * (1L shl exponent)
        return min(delay, MAX_BACKOFF_MS)
    }

    internal fun computeHmacSha256(secret: String, data: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        val keySpec = SecretKeySpec(secret.toByteArray(Charsets.UTF_8), "HmacSHA256")
        mac.init(keySpec)
        val raw = mac.doFinal(data.toByteArray(Charsets.UTF_8))
        return raw.joinToString("") { "%02x".format(it) }
    }

    internal fun sendHttpsPost(rawUrl: String, jsonBody: String, hmacKey: String = "", headers: Map<String, String> = emptyMap()) {
        val uri = URI(rawUrl)
        require(uri.scheme == "https" && !uri.host.isNullOrBlank()) { "Telemetry endpoint must be HTTPS" }
        val connection = uri.toURL().openConnection() as HttpsURLConnection
        connection.requestMethod = "POST"
        // Never follow redirects: auth headers and the signed body must only ever reach the configured host.
        connection.instanceFollowRedirects = false
        connection.connectTimeout = 5000
        connection.readTimeout = 5000
        connection.doOutput = true
        connection.setRequestProperty("Content-Type", "application/json; charset=UTF-8")
        connection.setRequestProperty("User-Agent", "AppArmorX/1.0")
        // Customer-defined headers (for example an API key). Reserved names were rejected when the policy was parsed.
        for ((name, value) in headers) {
            validateTelemetryHeader(name, value)
            connection.setRequestProperty(name, value)
        }

        val timestamp = (System.currentTimeMillis() / 1000).toString()
        connection.setRequestProperty("X-AppArmorX-Timestamp", timestamp)
        if (hmacKey.isNotBlank()) {
            val signature = computeHmacSha256(hmacKey, "$timestamp.$jsonBody")
            connection.setRequestProperty("X-AppArmorX-Signature", signature)
        }

        val bytes = jsonBody.toByteArray(Charsets.UTF_8)
        connection.setFixedLengthStreamingMode(bytes.size)
        try {
            connection.outputStream.use { it.write(bytes) }
            val responseCode = connection.responseCode
            if (responseCode !in 200..299) {
                throw IOException("Telemetry endpoint returned HTTP $responseCode")
            }
        } finally {
            connection.disconnect()
        }
    }

    internal fun resetStateForTesting() {
        consecutiveFailures.set(0)
        circuitBreakerUntil.set(0L)
        lastDispatchTime.set(0L)
    }
}
