package com.apparmorx.runtime

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Debug
import android.security.NetworkSecurityPolicy
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import java.io.File
import java.security.MessageDigest
import java.util.Collections
import java.util.Properties

/** Worker-only bounded scanner. Device failures remain evidence gaps, not successful checks. */
internal object RuntimeScanner {
    private const val MAX_POLICY_BYTES = 65536
    private const val MAX_MAP_BYTES = 1048576
    private val ROOT_PATHS = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/data/adb/magisk")

    /**
     * Distinguishes "genuinely absent" (ENOENT) from "could not tell" (EACCES, or anything else) by
     * calling stat() directly instead of java.io.File.exists(), which swallows that distinction and
     * returns false for both -- see rootPathStatus's kdoc and RootPathStatusTest for why this matters:
     * a real su binary at mode 4750 (root:shell) denies stat() to an app's own SELinux/POSIX context.
     */
    private fun statPathCheck(path: String): PathCheck = try {
        Os.stat(path)
        PathCheck.Present
    } catch (e: ErrnoException) {
        if (e.errno == OsConstants.ENOENT) PathCheck.Absent else PathCheck.Denied
    } catch (_: Exception) {
        PathCheck.Denied
    }

    private val HOOK_FRAMEWORK_CLASSES = listOf(
        "de.robv.android.xposed.XposedBridge",
        "de.robv.android.xposed.XC_MethodHook",
        "me.weishu.epic.art.Epic",
        "top.canyie.pine.Pine",
        "com.saurik.substrate.MS\$MethodHook"
    )


    fun fastPreflight(context: Context): SecuritySnapshot {
        val evidence = mutableListOf<Evidence>()
        var sequence = 0L
        var enforcement = EnforcementPolicy.DEFAULT
        try {
            val properties = Properties()
            context.assets.open("apparmorx/policy.properties").use { input ->
                val bytes = readBounded(input, MAX_POLICY_BYTES)
                properties.load(bytes.inputStream())
            }
            sequence = properties.getProperty("sequence", "0").toLong()
            enforcement = parseEnforcementPolicy(properties)
            evidence += probe("application-id") { context.packageName != properties.getProperty("applicationId") }
        } catch (_: Exception) {}
        evidence += probe("debugger") { Debug.isDebuggerConnected() || Debug.waitingForDebugger() }
        evidence += probe("debuggable-app") { context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0 }
        evidence += probe("build-tags") { Build.TAGS?.contains("test-keys") == true }
        evidence += Evidence("root-path", rootPathStatus(ROOT_PATHS, ::statPathCheck))
        evidence += probe("hook-classes") { hasHookClass(context.classLoader, HOOK_FRAMEWORK_CLASSES) }
        return SecuritySnapshot(
            checkedAtMillis = System.currentTimeMillis(),
            policySequence = sequence,
            evidence = Collections.unmodifiableList(evidence),
            enforcement = enforcement
        )
    }

    fun scan(context: Context): SecuritySnapshot {
        val evidence = mutableListOf<Evidence>()
        var sequence = 0L
        var enforcement = EnforcementPolicy.DEFAULT
        var payloadDigests = emptyMap<String, String>()
        try {
            val properties = Properties()
            context.assets.open("apparmorx/policy.properties").use { input ->
                val bytes = readBounded(input, MAX_POLICY_BYTES)
                properties.load(bytes.inputStream())
            }
            require(properties.getProperty("schema") == "1")
            sequence = properties.getProperty("sequence").toLong()
            val expires = properties.getProperty("expires").toLong()
            val markers = properties.getProperty("markers").split(',')
            require(markers.size in 1..128 && markers.all { it.matches(Regex("[a-z0-9._-]{4,80}")) })
            val certificates = properties.getProperty("certificates").split(',').filter { it.isNotBlank() }.toSet()
            require(certificates.all { it.matches(Regex("[0-9a-f]{64}")) })
            val rawDigests = properties.getProperty("payloadDigests", "").trim()
            if (rawDigests.isNotBlank()) {
                payloadDigests = rawDigests.split(',')
                    .filter { it.contains(':') }
                    .associate {
                        val parts = it.split(':', limit = 2)
                        parts[0].trim() to parts[1].trim()
                    }
            }
            // Invalid response configuration invalidates policy evidence; never report it as CLEAR.
            enforcement = parseEnforcementPolicy(properties)
            evidence += Evidence("policy", if (expires == 0L || expires > System.currentTimeMillis() / 1000) Status.CLEAR else Status.UNAVAILABLE)
            evidence += probe("application-id") { context.packageName != properties.getProperty("applicationId") }
            evidence += probe("hook-library") {
                File("/proc/self/maps").inputStream().use { stream ->
                    matchesIndicator(readBounded(stream, MAX_MAP_BYTES).toString(Charsets.UTF_8), markers)
                }
            }
            evidence += checkSigners(context, certificates)
        } catch (_: Exception) {
            evidence += Evidence("policy-or-scan", Status.UNAVAILABLE)
        }
        evidence += NativeEngine.scan()
        evidence += probe("debugger") { Debug.isDebuggerConnected() || Debug.waitingForDebugger() }
        evidence += probe("debuggable-app") { context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0 }
        evidence += Evidence("root-path", rootPathStatus(ROOT_PATHS, ::statPathCheck))
        evidence += probe("apk-integrity") {
            val apk = File(context.packageCodePath)
            !ApkIntegrityVerifier.verify(apk, payloadDigests)
        }
        evidence += probe("hook-classes") { hasHookClass(context.classLoader, HOOK_FRAMEWORK_CLASSES) }
        evidence += probe("build-tags") { Build.TAGS?.contains("test-keys") == true }
        evidence += probe("network-cleartext-permitted") {
            NetworkSecurityPolicy.getInstance().isCleartextTrafficPermitted
        }
        evidence += probe("environment-hardware") {
            isEmulatorFingerprint(
                Build.FINGERPRINT.orEmpty(),
                Build.MODEL.orEmpty(),
                Build.BRAND.orEmpty(),
                Build.DEVICE.orEmpty(),
                Build.PRODUCT.orEmpty(),
                Build.HARDWARE.orEmpty()
            )
        }
        evidence += probe("virtual-space") {
            val filesDir = context.filesDir?.absolutePath.orEmpty()
            filesDir.isNotEmpty() && isVirtualSpacePath(filesDir, context.packageName)
        }
        return SecuritySnapshot(System.currentTimeMillis(), sequence, Collections.unmodifiableList(evidence.toList()), enforcement)
    }

    @Suppress("DEPRECATION")
    private fun checkSigners(context: Context, trusted: Set<String>): Evidence = try {
        val info = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        // Use current signers, not any historical signer: an old cert must not bless an untrusted current signer.
        val actual = info.signingInfo?.apkContentsSigners.orEmpty().map { signature ->
            MessageDigest.getInstance("SHA-256").digest(signature.toByteArray()).joinToString("") { "%02x".format(it) }
        }.toSet()
        Evidence("signing-certificate", signerStatus(actual, trusted))
    } catch (_: Exception) { Evidence("signing-certificate", Status.UNAVAILABLE) }

    private fun readBounded(input: java.io.InputStream, limit: Int): ByteArray {
        val output = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(4096)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            require(output.size() + count <= limit) { "Probe input exceeds limit" }
            output.write(buffer, 0, count)
        }
        return output.toByteArray()
    }
}
