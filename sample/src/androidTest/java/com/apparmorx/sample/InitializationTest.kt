package com.apparmorx.sample

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.apparmorx.runtime.ProtectionState
import com.apparmorx.runtime.SecurityBlockActivity
import com.apparmorx.runtime.SecurityGuard
import com.apparmorx.runtime.SecurityRuntime
import com.apparmorx.runtime.Status
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Device smoke tests for the consumer fixture in [MainActivity], which contains no AppArmorX calls,
 * startup wiring or detection code of its own — everything here comes from applying the plugin.
 */
@RunWith(AndroidJUnit4::class)
class InitializationTest {
    @Test fun automaticProviderInitializationDoesNotSilentlyClaimClean() {
        val deadline = System.nanoTime() + 10_000_000_000L
        while (SecurityRuntime.snapshot().checkedAtMillis == 0L && System.nanoTime() < deadline) {
            Thread.sleep(50)
        }
        val snapshot = SecurityRuntime.snapshot()
        assertTrue("Provider should initialize runtime", snapshot.checkedAtMillis > 0)
        assertEquals(Status.CLEAR, snapshot.evidence.single { it.check == "policy" }.status)
        assertEquals(Status.CLEAR, snapshot.evidence.single { it.check == "application-id" }.status)
        assertEquals(Status.DETECTED, snapshot.evidence.single { it.check == "debuggable-app" }.status)
        // The fixture deliberately pins an all-zero digest; the actual signer must be rejected.
        assertEquals(Status.DETECTED, snapshot.evidence.single { it.check == "signing-certificate" }.status)
        // Untampered packaged APK code and assets must report CLEAR.
        assertEquals(Status.CLEAR, snapshot.evidence.single { it.check == "apk-integrity" }.status)
        assertEquals(Status.CLEAR, snapshot.evidence.single { it.check == "hook-classes" }.status)
        assertEquals(Status.CLEAR, snapshot.evidence.single { it.check == "build-tags" }.status)
        assertEquals(Status.CLEAR, snapshot.evidence.single { it.check == "network-cleartext-permitted" }.status)
        // SELinux may deny its own status file to untrusted_app. Compare with an actual read in
        // this same instrumented process, rather than claiming a denied probe must be CLEAR.
        val selinuxRead = runCatching { java.io.File("/sys/fs/selinux/enforce").readText() }.getOrNull()
        val expectedSelinux = when {
            selinuxRead.isNullOrEmpty() -> Status.UNAVAILABLE
            selinuxRead.startsWith("0") -> Status.DETECTED
            else -> Status.CLEAR
        }
        assertEquals("SELinux evidence must reflect app-sandbox read availability", expectedSelinux,
            snapshot.evidence.single { it.check == "native-selinux" }.status)
        assertEquals(Status.CLEAR, snapshot.evidence.single { it.check == "native-hook-trampoline" }.status)
        // The native hardware probe includes emulator device paths. CI's x86_64 images expose
        // these, while the local arm64 image may not. Independently stat from the same app sandbox;
        // neither a legitimate emulator finding nor a permission denial may be relabeled clean.
        val hardwarePaths = listOf("/dev/kernelsu", "/dev/apatch", "/dev/qemu_pipe", "/dev/goldfish_pipe", "/dev/vport0p1")
        val pathEvidence = hardwarePaths.map { path ->
            try {
                android.system.Os.lstat(path)
                Status.DETECTED
            } catch (error: android.system.ErrnoException) {
                if (error.errno == android.system.OsConstants.ENOENT || error.errno == android.system.OsConstants.ENOTDIR)
                    Status.CLEAR else Status.UNAVAILABLE
            }
        }
        val expectedHardware = when {
            Status.DETECTED in pathEvidence -> Status.DETECTED
            Status.UNAVAILABLE in pathEvidence -> Status.UNAVAILABLE
            else -> Status.CLEAR
        }
        assertEquals("Native hardware evidence must match actual app-sandbox paths: $pathEvidence",
            expectedHardware, snapshot.evidence.single { it.check == "native-hardware-device" }.status)
        // The environment probe must be right on both kinds of device: CLEAR on real hardware, DETECTED
        // on an emulator. A hardcoded CLEAR would only pass on a physical phone.
        val onEmulator = android.os.Build.HARDWARE.let { it.contains("ranchu") || it.contains("goldfish") } ||
            android.os.Build.FINGERPRINT.startsWith("generic") || android.os.Build.PRODUCT.contains("sdk")
        assertEquals(
            if (onEmulator) Status.DETECTED else Status.CLEAR,
            snapshot.evidence.single { it.check == "environment-hardware" }.status,
        )
        assertEquals(Status.CLEAR, snapshot.evidence.single { it.check == "virtual-space" }.status)
        val wchanRead = runCatching { java.io.File("/proc/self/wchan").readText() }.getOrNull()
        val expectedWchan = when {
            wchanRead.isNullOrEmpty() -> Status.UNAVAILABLE
            listOf("ptrace_stop", "sys_ptrace", "do_signal_stop").any { wchanRead.contains(it) } -> Status.DETECTED
            else -> Status.CLEAR
        }
        assertEquals("Wait-channel probe must preserve read failures", expectedWchan,
            snapshot.evidence.single { it.check == "native-wchan" }.status)
        val tcpReads = listOf("/proc/net/tcp", "/proc/net/tcp6").map { path ->
            runCatching { java.io.File(path).readText() }.getOrNull()
        }
        val expectedPorts = when {
            tcpReads.any { it?.contains(":69a2", ignoreCase = true) == true } -> Status.DETECTED
            tcpReads.any { it == null } -> Status.UNAVAILABLE
            else -> Status.CLEAR
        }
        assertEquals("TCP probe must not treat denied reads as clean", expectedPorts,
            snapshot.evidence.single { it.check == "native-frida-port" }.status)
        assertEquals(Status.CLEAR, snapshot.evidence.single { it.check == "native-memory-rwx" }.status)
        assertEquals(Status.CLEAR, snapshot.evidence.single { it.check == "native-stealth-injection" }.status)
        assertEquals(Status.CLEAR, snapshot.evidence.single { it.check == "native-relocation-integrity" }.status)
    }

    @Test fun launchingUnmodifiedActivityFiresInjectedGuard() {
        val scanDeadline = System.nanoTime() + 10_000_000_000L
        while (SecurityRuntime.snapshot().checkedAtMillis == 0L && System.nanoTime() < scanDeadline) {
            Thread.sleep(50)
        }
        assertTrue("Initial scan completed", SecurityRuntime.snapshot().checkedAtMillis > 0)
        ActivityScenario.launch(MainActivity::class.java).use {
            val deadline = System.nanoTime() + 10_000_000_000L
            while (SecurityGuard.lastObservedState() == ProtectionState.CHECKING && System.nanoTime() < deadline) {
                Thread.sleep(50)
            }
            assertNotEquals(
                "MainActivity declares no onCreate/onStart/onResume override and no AppArmorX call;" +
                    " SecurityGuard.allowActivity must still have been injected and executed",
                ProtectionState.CHECKING,
                SecurityGuard.lastObservedState(),
            )
        }
    }
    @Test fun foregroundActivityReceivesPeriodicScanWithoutLifecycleTransition() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                // Keep this test's own window visible without dismissing the device credential lock.
                activity.setShowWhenLocked(true)
                activity.setTurnScreenOn(true)
                activity.window.addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
            }
            val initialDeadline = System.nanoTime() + 10_000_000_000L
            while (SecurityRuntime.snapshot().checkedAtMillis == 0L && System.nanoTime() < initialDeadline) {
                Thread.sleep(50)
            }
            val initial = SecurityRuntime.snapshot().checkedAtMillis
            assertTrue(initial > 0)
            // A tick can coincide with completion of the first scan; allow two bounded intervals.
            val deadline = System.nanoTime() + 70_000_000_000L
            while (SecurityRuntime.snapshot().checkedAtMillis <= initial && System.nanoTime() < deadline) {
                Thread.sleep(100)
            }
            assertTrue("Foreground monitoring must scan without another lifecycle event",
                SecurityRuntime.snapshot().checkedAtMillis > initial)
        }
    }

    @Test fun securityBlockActivityLaunchesCleanly() {
        ActivityScenario.launch(SecurityBlockActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                assertTrue(activity is SecurityBlockActivity)
                org.junit.Assert.assertFalse(activity.isFinishing)
            }
        }
    }

    @Test fun allowActivityReturnsTrueUnderDefaultObservePolicy() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val proceed = SecurityGuard.allowActivity(activity)
                assertTrue("Under default OBSERVE policy, allowActivity must permit execution", proceed)
            }
        }
    }

    @Test fun allowNonActivityComponentsReturnTrueUnderDefaultObservePolicy() {
        val context = androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().targetContext
        val receiverProceed = SecurityGuard.allowReceiver(context)
        assertTrue("Under active policy, allowReceiver must permit execution", receiverProceed)
    }

    @Test fun allowServiceExecutesUnderActivePolicy() {
        val context = androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().targetContext
        val service = SampleBackgroundService().apply { attachForTesting(context) }
        val proceed = SecurityGuard.allowService(service)
        assertTrue("Under active policy, allowService must permit execution", proceed)
    }

    @Test fun sampleBackgroundServiceExecutesInjectedGuard() {
        SampleBackgroundService.reset()
        val context = androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().targetContext
        val service = SampleBackgroundService().apply { attachForTesting(context) }
        service.onCreate()
        assertTrue("Service onCreate should execute successfully under active policy", SampleBackgroundService.createExecuted)
    }

    @Test fun sampleSecurityReceiverExecutesInjectedGuard() {
        SampleSecurityReceiver.reset()
        val receiver = SampleSecurityReceiver()
        val context = androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().targetContext
        val intent = android.content.Intent("com.apparmorx.test.ACTION_PING")
        receiver.onReceive(context, intent)
        assertEquals("com.apparmorx.test.ACTION_PING", SampleSecurityReceiver.receivedAction)
    }

    @Test fun uiProtectionFlagsAppliedWhenConfigured() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val flags = activity.window.attributes.flags
                assertTrue(
                    "FLAG_SECURE must be applied when secureScreen is enabled",
                    (flags and android.view.WindowManager.LayoutParams.FLAG_SECURE) != 0
                )
                assertTrue(
                    "filterTouchesWhenObscured must be true when filterTouches is enabled",
                    activity.window.decorView.filterTouchesWhenObscured
                )
            }
        }
    }

    @Test fun dependencyFirewallInterceptsClipboardWhenEnabled() {
        val context = androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().targetContext
        val cm = context.getSystemService(android.content.Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
        val clip = com.apparmorx.runtime.DependencyFirewall.getPrimaryClip(cm)
        org.junit.Assert.assertNull("Under active firewall policy, getPrimaryClip must be neutralized", clip)
        val hasClip = com.apparmorx.runtime.DependencyFirewall.hasPrimaryClip(cm)
        org.junit.Assert.assertFalse("Under active firewall policy, hasPrimaryClip must return false", hasClip)
    }

    @Test fun dependencyFirewallInterceptsLocationWhenEnabled() {
        val context = androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().targetContext
        val lm = context.getSystemService(android.content.Context.LOCATION_SERVICE) as? android.location.LocationManager
        val loc = com.apparmorx.runtime.DependencyFirewall.getLastKnownLocation(lm, "gps")
        org.junit.Assert.assertNull("Under active firewall policy, getLastKnownLocation must be neutralized", loc)
    }

    @Test fun dependencyFirewallInterceptsTelephonyWhenEnabled() {
        val context = androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().targetContext
        val tm = context.getSystemService(android.content.Context.TELEPHONY_SERVICE) as? android.telephony.TelephonyManager
        val deviceId = com.apparmorx.runtime.DependencyFirewall.getDeviceId(tm)
        val imei = com.apparmorx.runtime.DependencyFirewall.getImei(tm)
        org.junit.Assert.assertNull("Under active firewall policy, getDeviceId must be neutralized", deviceId)
        org.junit.Assert.assertNull("Under active firewall policy, getImei must be neutralized", imei)
    }

    @Test fun dependencyFirewallEnforcesNetworkSecurity() {
        val permissiveVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true }
        val defaultBefore = javax.net.ssl.HttpsURLConnection.getDefaultHostnameVerifier()
        com.apparmorx.runtime.DependencyFirewall.setDefaultHostnameVerifier(permissiveVerifier)
        val defaultAfter = javax.net.ssl.HttpsURLConnection.getDefaultHostnameVerifier()
        org.junit.Assert.assertEquals("Permissive HostnameVerifier must be rejected", defaultBefore, defaultAfter)
    }
}

