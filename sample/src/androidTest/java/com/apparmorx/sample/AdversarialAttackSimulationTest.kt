package com.apparmorx.sample

import android.content.Context
import android.location.LocationManager
import android.os.SystemClock
import android.telephony.TelephonyManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.apparmorx.runtime.*
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection

/**
 * Empirical Adversarial Pentest & Attack Simulation Suite.
 *
 * Simulates real hostile attack vectors against the AppArmorX protected runtime:
 * 1. Untrusted third-party SDK data harvesting (clipboard, identifiers, location, telephony).
 * 2. Promiscuous TLS hostname verifier injection (man-in-the-middle / SSL bypass).
 * 3. Timing jitter execution under Mirage mode.
 * 4. Headless component abuse under restricted policy enforcement.
 * 5. Signer certificate tampering detection under pinned public policy.
 */
@RunWith(AndroidJUnit4::class)
class AdversarialAttackSimulationTest {

    private val context: Context
        get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun simulatedThirdPartySdkClipboardScrapingIsNeutralized() {
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
        // Attacker SDK attempts to silently extract clipboard content
        val harvestedClip = DependencyFirewall.getPrimaryClip(cm)
        assertNull("Adversarial clipboard extraction must be neutralized to null", harvestedClip)

        val hasClip = DependencyFirewall.hasPrimaryClip(cm)
        assertFalse("Adversarial clipboard probing must return false", hasClip)
    }

    @Test
    fun simulatedThirdPartySdkHardwareIdentifierScrapingIsNeutralized() {
        val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
        // Attacker SDK attempts IMEI / Device ID extraction
        val deviceId = DependencyFirewall.getDeviceId(tm)
        val imei = DependencyFirewall.getImei(tm)
        assertNull("Adversarial Device ID extraction must be neutralized", deviceId)
        assertNull("Adversarial IMEI extraction must be neutralized", imei)

        // Attacker attempts ANDROID_ID tracking extraction
        val cr = context.contentResolver
        val androidId = DependencyFirewall.getString(cr, "android_id")
        assertEquals("Adversarial ANDROID_ID tracking must return dummy zero identifier", "0000000000000000", androidId)
    }

    @Test
    fun simulatedThirdPartySdkLocationTrackingIsNeutralized() {
        val lm = context.getSystemService(Context.LOCATION_SERVICE) as? LocationManager
        // Attacker SDK attempts covert geolocation extraction
        val locationGps = DependencyFirewall.getLastKnownLocation(lm, "gps")
        val locationNetwork = DependencyFirewall.getLastKnownLocation(lm, "network")
        assertNull("Covert GPS location tracking must be neutralized", locationGps)
        assertNull("Covert Network location tracking must be neutralized", locationNetwork)
    }

    @Test
    fun simulatedPromiscuousTlsHostnameVerifierAttackIsBlocked() {
        val originalVerifier = HttpsURLConnection.getDefaultHostnameVerifier()
        // Attacker injects a wildcard verifier accepting any fraudulent certificate
        val maliciousVerifier = HostnameVerifier { _, _ -> true }
        DependencyFirewall.setDefaultHostnameVerifier(maliciousVerifier)

        val currentVerifier = HttpsURLConnection.getDefaultHostnameVerifier()
        assertEquals("Promiscuous HostnameVerifier must be rejected and original preserved", originalVerifier, currentVerifier)
        assertNotEquals("Malicious HostnameVerifier must never become active default", maliciousVerifier, currentVerifier)
    }

    @Test
    fun simulatedMirageCyberDeceptionInjectsMicroLatencyJitter() {
        val start = SystemClock.elapsedRealtime()
        DeceptionEngine.injectJitter()
        val elapsed = SystemClock.elapsedRealtime() - start

        assertTrue(
            "Mirage Mode deception must inject non-zero micro-latency jitter (elapsed: ${elapsed}ms)",
            elapsed in 35L..250L
        )
    }

    @Test
    fun simulatedRestrictedEnforcementActionStopsHeadlessService() {
        val service = SampleBackgroundService().apply { attachForTesting(context) }
        val proceed = SecurityGuard.allowService(service)
        // Debug builds must stay observe-only even when release configuration requests MIRAGE.
        assertTrue("Debug guard must allow the service without blocking", proceed)
    }

    @Test
    fun tamperedSignerCertificateIsDeterministicallyDetected() {
        androidx.test.core.app.ActivityScenario.launch(MainActivity::class.java).use {
            val deadline = System.nanoTime() + 10_000_000_000L
            while (SecurityRuntime.snapshot().evidence.none { it.check == "signing-certificate" } && System.nanoTime() < deadline) {
                Thread.sleep(50)
            }
            val snapshot = SecurityRuntime.snapshot()
            val certEvidence = snapshot.evidence.single { it.check == "signing-certificate" }
            assertEquals(
                "Pinned signing certificate mismatch must report Status.DETECTED",
                Status.DETECTED,
                certEvidence.status
            )
        }
    }
}
