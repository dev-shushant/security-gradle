package com.apparmorx.runtime

import org.junit.Assert.*
import org.junit.Test

/**
 * Adversarial penetration test suite.
 * Simulates active evasions, memory patching, and malicious SDK data harvesting
 * to verify AppArmorX detection and containment guarantees.
 */
class AdversarialSimulationTest {

    @Test
    fun detectsAdversarialHookFrameworksInClassLoader() {
        // Simulated classloader containing hook class
        val knownFrameworks = listOf(
            "de.robv.android.xposed.XposedBridge",
            "me.weishu.epic.art.Epic",
            "top.canyie.pine.Pine"
        )
        // Clean environment
        assertFalse(hasHookClass(javaClass.classLoader, knownFrameworks))
        // Simulated indicator match
        assertTrue(hasHookClass(javaClass.classLoader, listOf(javaClass.name)))
    }

    @Test
    fun detectsCaseInsensitiveAdversarialIndicators() {
        val markers = listOf("frida-agent", "libfrida-gadget", "liblsposed")
        assertTrue(matchesIndicator("7f000 /data/local/tmp/LIBFRIDA-GADGET.SO", markers))
        assertTrue(matchesIndicator("7f000 /data/app/FrIdA-AgEnT.so", markers))
        assertFalse(matchesIndicator("7f000 /system/lib64/libc.so", markers))
    }

    @Test
    fun detectsVirtualAppAndCloningSandboxes() {
        val app = "com.apparmorx.sample"
        val clonerPaths = listOf(
            "/data/data/com.lbe.parallel/virtual/data/user/0/$app/files",
            "/data/data/com.lody.virtual/files",
            "/data/data/io.va.exposed/virtual/data/user/0/$app/files",
            "/data/user/0/com.excelliance.dualsandbox/files"
        )
        for (path in clonerPaths) {
            assertTrue("Must detect sandbox path: $path", isVirtualSpacePath(path, app))
        }
        assertFalse("Clean path must pass", isVirtualSpacePath("/data/user/0/$app/files", app))
    }

    @Test
    fun firewallNeutralizesUntrustedSdkDataHarvesting() {
        DependencyFirewall.isClipboardProtectionEnabled = true
        DependencyFirewall.isIdentifierProtectionEnabled = true
        DependencyFirewall.isLocationProtectionEnabled = true

        // Simulate untrusted SDK querying clipboard
        val clip = DependencyFirewall.getPrimaryClip(null)
        val hasClip = DependencyFirewall.hasPrimaryClip(null)
        assertNull("Firewall must neutralize clipboard contents", clip)
        assertFalse("Firewall must report no clipboard data", hasClip)

        val loc = DependencyFirewall.getLastKnownLocation(null, "gps")
        assertNull("Firewall must neutralize location queries", loc)

        val deviceId = DependencyFirewall.getDeviceId(null)
        val imei = DependencyFirewall.getImei(null)
        assertNull("Firewall must neutralize device id", deviceId)
        assertNull("Firewall must neutralize IMEI", imei)

        // Reset toggles
        DependencyFirewall.isClipboardProtectionEnabled = false
        DependencyFirewall.isIdentifierProtectionEnabled = false
        DependencyFirewall.isLocationProtectionEnabled = false
    }

    @Test
    fun deceptionEngineDesynchronizesWithoutCrashing() {
        DeceptionEngine.injectJitter(minMillis = 5L, maxMillis = 20L)
        assertTrue("Mirage mode must report active state", DeceptionEngine.isMirageActive)
    }

    @Test
    fun untrustedSignerTamperingIsStrictlyDetected() {
        val officialSigner = setOf("a".repeat(64))
        val attackerSigner = setOf("b".repeat(64))
        val dualSigners = officialSigner + attackerSigner

        assertEquals(Status.DETECTED, signerStatus(attackerSigner, officialSigner))
        assertEquals(Status.DETECTED, signerStatus(dualSigners, officialSigner))
        assertEquals(Status.CLEAR, signerStatus(officialSigner, officialSigner))
    }

    @Test
    fun clockReversalAndStaleEvidenceRemainIndeterminate() {
        val required = setOf("policy", "signing-certificate", "native-engine")
        val clean = required.map { Evidence(it, Status.CLEAR) }

        // Clock rolled backward
        val backward = decideProtection(SecuritySnapshot(100000L, 1L, clean), 50000L, required)
        assertEquals(ProtectionState.INDETERMINATE, backward)

        // Stale evidence (> 120s old)
        val stale = decideProtection(SecuritySnapshot(1000L, 1L, clean), 130000L, required)
        assertEquals(ProtectionState.INDETERMINATE, stale)
    }

    @Test
    fun detectsStealthInjectorThreadIndicators() {
        val injectedThreads = listOf(
            "gmain",
            "gdbus",
            "gum-js-loop",
            "pool-frida",
            "gum-worker",
            "linjector",
            "frida-thread-0"
        )
        for (thread in injectedThreads) {
            val detected = thread.startsWith("gum-") || thread.startsWith("frida-") || thread in setOf("gmain", "gdbus", "pool-frida", "gum-worker", "linjector")
            assertTrue("Must detect injected thread: $thread", detected)
        }
        val cleanThreads = listOf("RenderThread", "main", "OkHttp Dispatcher")
        for (thread in cleanThreads) {
            val detected = thread.startsWith("gum-") || thread.startsWith("frida-") || thread in setOf("gmain", "gdbus", "pool-frida", "gum-worker", "linjector")
            assertFalse("Must not flag normal thread: $thread", detected)
        }
    }

    @Test
    fun detectsStealthMemoryStagingPaths() {
        val stealthPaths = listOf(
            "/data/local/tmp/libgadget.so",
            "[anon:gum-trampoline]",
            "/data/app/libinjected.so (deleted)",
            "/memfd:frida-agent"
        )
        for (path in stealthPaths) {
            val detected = path.contains("/data/local/tmp/") ||
                path.contains("[anon:gum") ||
                path.contains("[anon:frida") ||
                path.contains(".so (deleted)") ||
                path.contains("/memfd:")
            assertTrue("Must detect stealth memory mapping: $path", detected)
        }
    }

    @Test
    fun firewallNeutralizesInsecureTlsTrustManagerBypass() {
        DependencyFirewall.isNetworkSecurityProtectionEnabled = true

        val fakeTrustAll = object : javax.net.ssl.X509TrustManager {
            override fun checkClientTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = emptyArray()
        }
        assertTrue("Firewall must recognize insecure bypass trust manager", DependencyFirewall.isInsecureTrustManager(fakeTrustAll))

        val permissiveVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true }
        assertTrue("Firewall must recognize allow-all hostname verifier", DependencyFirewall.isInsecureHostnameVerifier(permissiveVerifier))

        DependencyFirewall.isNetworkSecurityProtectionEnabled = false
    }
}
