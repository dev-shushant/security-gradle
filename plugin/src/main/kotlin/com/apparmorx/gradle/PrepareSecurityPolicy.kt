package com.apparmorx.gradle

import com.apparmorx.policy.SignedPolicy
import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.*
import org.gradle.work.DisableCachingByDefault
import java.net.URI
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.time.Instant
import javax.net.ssl.HttpsURLConnection

private val ALLOWED_ACTIONS = setOf("OBSERVE", "WARN", "BLOCK_SCREEN", "TERMINATE", "MIRAGE")

/** Revalidates freshness on every build, including offline builds; no stale success is cached. */
@DisableCachingByDefault(because = "Network policy freshness and expiry depend on the build clock")
abstract class PrepareSecurityPolicy : DefaultTask() {
    @get:Input abstract val policyUrl: Property<String>
    @get:Input abstract val publicKey: Property<String>
    @get:Input abstract val minimumSequence: Property<Long>
    @get:Input abstract val refresh: Property<Boolean>
    @get:Input abstract val offline: Property<Boolean>
    @get:Input abstract val certificates: ListProperty<String>
    /** Explicit pins win. When empty, the pin is derived from the variant's own signing config below. */
    @get:InputFile @get:Optional @get:PathSensitive(PathSensitivity.NONE) abstract val keystoreFile: RegularFileProperty
    @get:Internal abstract val keystorePassword: Property<String>
    @get:Input @get:Optional abstract val keystoreAlias: Property<String>
    @get:Input @get:Optional abstract val keystoreType: Property<String>
    @get:Input abstract val requirePins: Property<Boolean>
    @get:Input @get:Optional abstract val applicationId: Property<String>
    @get:Input abstract val restrictedAction: Property<String>
    @get:Input abstract val enforceIndeterminate: Property<Boolean>
    @get:Input abstract val failClosedOnStartup: Property<Boolean>
    @get:Input abstract val secureScreen: Property<Boolean>
    @get:Input abstract val filterTouches: Property<Boolean>
    @get:Input abstract val telemetryUrl: Property<String>
    @get:Input abstract val telemetryHmacKey: Property<String>
    @get:Input abstract val telemetryDetail: Property<String>
    @get:Internal abstract val telemetryHeaders: org.gradle.api.provider.MapProperty<String, String>
    @get:Input abstract val firewallClipboard: Property<Boolean>
    @get:Input abstract val firewallIdentifiers: Property<Boolean>
    @get:Input abstract val firewallLocation: Property<Boolean>
    @get:Input abstract val firewallNetworkSecurity: Property<Boolean>
    @get:Input abstract val antiPtraceHardening: Property<Boolean>
    @get:Input abstract val killOnConfirmedHooking: Property<Boolean>
    @get:Input abstract val payloadDigests: org.gradle.api.provider.MapProperty<String, String>
    @get:InputFile @get:Optional @get:PathSensitive(PathSensitivity.NONE)
    abstract val policyFile: RegularFileProperty
    @get:OutputDirectory abstract val outputDirectory: DirectoryProperty

    init { outputs.upToDateWhen { false } }

    @TaskAction fun prepare() {
        var derived = false
        val pins = certificates.get().sorted().ifEmpty {
            if (keystoreFile.isPresent && keystorePassword.isPresent && keystoreAlias.isPresent) {
                derived = true
                listOf(SigningFingerprint.fromKeystore(
                    keystoreFile.get().asFile, keystorePassword.get(), keystoreAlias.get(), keystoreType.orNull,
                ))
            } else emptyList()
        }
        if (derived) logger.lifecycle("AppArmorX: signer pin derived from the release signing config (${pins.single().take(12)}…)")
        require(pins.all { it.matches(Regex("[0-9a-f]{64}")) }) { "Signer pins must be lowercase SHA-256 hex" }
        require(!requirePins.get() || pins.isNotEmpty()) { "Configure security.signingCertificates, or a release signingConfig with a readable keystore, for non-debuggable variants" }
        // Kept in sync by hand with com.apparmorx.runtime.EnforcementAction: the plugin (build JVM)
        // never depends on the runtime (Android) module, so this can't be a shared enum reference.
        val action = restrictedAction.get()
        require(action in ALLOWED_ACTIONS) { "security.restrictedAction must be one of $ALLOWED_ACTIONS, was '$action'" }
        validateTelemetry()
        val url = policyUrl.get()
        val bytes = when {
            refresh.get() && !offline.get() && url.isNotBlank() -> download(url)
            policyFile.isPresent -> policyFile.get().asFile.inputStream().use { it.readNBytes(SignedPolicy.MAX_BYTES + 1) }
            url.isNotBlank() || publicKey.get().isNotBlank() -> error("A signed policyFile is required for pinned/offline builds")
            else -> null
        }
        val policy = bytes?.let { SignedPolicy.verify(it, publicKey.get(), minimumSequence.get(), Instant.now().epochSecond) }
        val markers = policy?.markers ?: listOf("frida-agent", "libfrida-gadget", "libxposed", "liblsposed")
        val content = buildString {
            appendLine("schema=1")
            appendLine("applicationId=${applicationId.getOrElse("")}")
            appendLine("sequence=${policy?.sequence ?: 0}")
            appendLine("expires=${policy?.expires ?: 0}")
            appendLine("sha256=${policy?.sha256 ?: "bundled"}")
            appendLine("markers=${markers.joinToString(",")}")
            appendLine("certificates=${pins.joinToString(",")}")
            appendLine("restrictedAction=$action")
            appendLine("enforceIndeterminate=${enforceIndeterminate.get()}")
            appendLine("failClosedOnStartup=${failClosedOnStartup.get()}")
            appendLine("secureScreen=${secureScreen.get()}")
            appendLine("filterTouches=${filterTouches.get()}")
            appendLine("telemetryUrl=${telemetryUrl.getOrElse("")}")
            appendLine("telemetryHmacKey=${telemetryHmacKey.getOrElse("")}")
            appendLine("telemetryDetail=${telemetryDetail.get().trim().uppercase()}")
            telemetryHeaders.get().toSortedMap().forEach { (name, value) -> appendLine("telemetryHeader.$name=$value") }
            appendLine("firewallClipboard=${firewallClipboard.get()}")
            appendLine("firewallIdentifiers=${firewallIdentifiers.get()}")
            appendLine("firewallLocation=${firewallLocation.get()}")
            appendLine("firewallNetworkSecurity=${firewallNetworkSecurity.get()}")
            appendLine("antiPtraceHardening=${antiPtraceHardening.get()}")
            appendLine("killOnConfirmedHooking=${killOnConfirmedHooking.get()}")
            val digests = payloadDigests.get()
            require(digests.values.all { it.matches(Regex("[0-9a-fA-F]{64}")) }) { "Payload digests must be SHA-256 hex" }
            val serializedDigests = digests.entries.joinToString(",") { "${it.key}:${it.value}" }
            appendLine("payloadDigests=$serializedDigests")
        }
        val directory = outputDirectory.get().asFile.toPath().resolve("apparmorx")
        Files.createDirectories(directory)
        val temporary = Files.createTempFile(directory, "policy-", ".tmp")
        try {
            Files.writeString(temporary, content)
            Files.move(temporary, directory.resolve("policy.properties"), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } finally { Files.deleteIfExists(temporary) }
        logger.lifecycle("AppArmorX: policy sequence ${policy?.sequence ?: 0}, digest ${policy?.sha256 ?: "bundled"}")
    }

    /** Fail the build on telemetry settings the runtime would otherwise silently ignore. */
    private fun validateTelemetry() {
        val endpoint = telemetryUrl.getOrElse("").trim()
        if (endpoint.isNotEmpty()) {
            val uri = runCatching { URI(endpoint) }.getOrNull()
            require(uri != null && uri.scheme == "https" && !uri.host.isNullOrBlank() && uri.userInfo == null && uri.fragment == null) {
                "security.telemetryUrl must be an HTTPS URL without credentials or fragments, was '${endpoint.substringBefore('?')}'"
            }
            if (telemetryHmacKey.getOrElse("").isBlank()) {
                logger.warn("AppArmorX: telemetryUrl is set without telemetryHmacKey; reports will not be signed. Set security.telemetryHmacKey.")
            }
        }
        val detail = telemetryDetail.get().trim().uppercase()
        require(detail in setOf("MINIMAL", "STANDARD", "EXTENDED")) {
            "security.telemetryDetail must be one of [MINIMAL, STANDARD, EXTENDED], was '${telemetryDetail.get()}'"
        }
        // Keep in sync with validateTelemetryHeader in the runtime: custom headers must never forge ours.
        val reserved = setOf("host", "content-type", "content-length", "user-agent", "connection", "transfer-encoding")
        telemetryHeaders.get().forEach { (name, value) ->
            require(Regex("[A-Za-z0-9-]{1,64}").matches(name) && name.lowercase() !in reserved && !name.lowercase().startsWith("x-apparmorx-")) {
                "security.telemetryHeaders has an invalid or reserved header name '$name'"
            }
            require(Regex("[A-Za-z0-9._~+/=: -]{1,512}").matches(value)) {
                "security.telemetryHeaders value for '$name' contains unsupported characters (allowed: letters, digits and . _ ~ + / = : - space)"
            }
        }
    }

    private fun download(raw: String): ByteArray {
        val uri = URI(raw)
        require(uri.scheme == "https" && !uri.host.isNullOrBlank() && uri.userInfo == null && uri.fragment == null) {
            "Policy endpoint must be HTTPS without credentials or fragments"
        }
        val connection = uri.toURL().openConnection() as HttpsURLConnection
        connection.instanceFollowRedirects = false
        connection.connectTimeout = 10000
        connection.readTimeout = 10000
        connection.setRequestProperty("Accept", "application/octet-stream")
        try {
            require(connection.responseCode == 200) { "Policy fetch failed (redirects are forbidden)" }
            require(connection.contentLengthLong <= SignedPolicy.MAX_BYTES) { "Policy exceeds size limit" }
            val deadline = System.nanoTime() + 15_000_000_000L
            return connection.inputStream.use { input ->
                val output = java.io.ByteArrayOutputStream()
                val buffer = ByteArray(4096)
                while (true) {
                    require(System.nanoTime() < deadline) { "Policy download deadline exceeded" }
                    val count = input.read(buffer)
                    if (count < 0) break
                    require(output.size() + count <= SignedPolicy.MAX_BYTES) { "Policy exceeds size limit" }
                    output.write(buffer, 0, count)
                }
                output.toByteArray()
            }
        } finally { connection.disconnect() }
    }
}
