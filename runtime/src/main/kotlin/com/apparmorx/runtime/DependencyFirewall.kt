package com.apparmorx.runtime

import android.content.ClipData
import android.content.ClipboardManager
import android.content.ContentResolver
import android.provider.Settings
import android.util.Log

private const val TAG = "AppArmorX"

/**
 * In-App Dependency Firewall (supported call sites only; direct framework calls from injected code bypass it).
 * Intercepts invocations to sensitive platform getters at runtime.
 * When firewall protection is active, returns sanitized safe responses
 * to prevent unauthorized clipboard snooping and device fingerprint harvesting.
 */
object DependencyFirewall {
    @Volatile
    var isClipboardProtectionEnabled: Boolean = false

    @Volatile
    var isIdentifierProtectionEnabled: Boolean = false

    @Volatile
    var isLocationProtectionEnabled: Boolean = false

    @Volatile
    var isNetworkSecurityProtectionEnabled: Boolean = false

    private fun safeSnapshot(): SecuritySnapshot? = try {
        SecurityRuntime.snapshot()
    } catch (_: Throwable) {
        null
    }

    private fun safeLog(msg: String) {
        try {
            Log.d(TAG, msg)
        } catch (_: Throwable) {
            // Safe fallback on desktop JVM test environments
        }
    }

    /**
     * Intercepted call site for [ClipboardManager.getPrimaryClip].
     * Returns null if clipboard protection is active.
     */
    @JvmStatic
    fun getPrimaryClip(clipboardManager: ClipboardManager?): ClipData? {
        if (clipboardManager == null) return null
        val snapshot = safeSnapshot()
        val enabled = isClipboardProtectionEnabled || (snapshot?.enforcement?.firewallClipboard == true)
        if (enabled) {
            safeLog("DependencyFirewall: neutralized ClipboardManager.getPrimaryClip access")
            return null
        }
        return clipboardManager.primaryClip
    }

    /**
     * Intercepted call site for [ClipboardManager.hasPrimaryClip].
     * Returns false if clipboard protection is active.
     */
    @JvmStatic
    fun hasPrimaryClip(clipboardManager: ClipboardManager?): Boolean {
        if (clipboardManager == null) return false
        val snapshot = safeSnapshot()
        val enabled = isClipboardProtectionEnabled || (snapshot?.enforcement?.firewallClipboard == true)
        if (enabled) {
            return false
        }
        return clipboardManager.hasPrimaryClip()
    }

    /**
     * Intercepted call site for [Settings.Secure.getString].
     * Returns sanitized identifier if identifier protection is active.
     */
    @JvmStatic
    fun getString(resolver: ContentResolver?, name: String?): String? {
        if (resolver == null || name == null) return null
        val snapshot = safeSnapshot()
        val enabled = isIdentifierProtectionEnabled || (snapshot?.enforcement?.firewallIdentifiers == true)
        if (enabled && name == Settings.Secure.ANDROID_ID) {
            safeLog("DependencyFirewall: neutralized Settings.Secure.ANDROID_ID access")
            return "0000000000000000"
        }
        return Settings.Secure.getString(resolver, name)
    }

    /**
     * Intercepted call site for [android.location.LocationManager.getLastKnownLocation].
     * Neutralizes background location scraping from untrusted SDKs.
     */
    @JvmStatic
    @Suppress("MissingPermission")
    fun getLastKnownLocation(locationManager: android.location.LocationManager?, provider: String?): android.location.Location? {
        if (locationManager == null || provider == null) return null
        val snapshot = safeSnapshot()
        val enabled = isLocationProtectionEnabled || (snapshot?.enforcement?.firewallLocation == true)
        if (enabled) {
            safeLog("DependencyFirewall: neutralized LocationManager.getLastKnownLocation access")
            return null
        }
        return try {
            locationManager.getLastKnownLocation(provider)
        } catch (_: SecurityException) {
            null
        }
    }

    /**
     * Intercepted call site for [android.telephony.TelephonyManager.getDeviceId].
     * Neutralizes hardware IMEI/MEID scraping.
     */
    @JvmStatic
    @Suppress("DEPRECATION", "MissingPermission")
    fun getDeviceId(telephonyManager: android.telephony.TelephonyManager?): String? {
        if (telephonyManager == null) return null
        val snapshot = safeSnapshot()
        val enabled = isIdentifierProtectionEnabled || (snapshot?.enforcement?.firewallIdentifiers == true)
        if (enabled) {
            safeLog("DependencyFirewall: neutralized TelephonyManager.getDeviceId access")
            return null
        }
        return try {
            telephonyManager.deviceId
        } catch (_: SecurityException) {
            null
        }
    }

    /**
     * Intercepted call site for [android.telephony.TelephonyManager.getImei].
     * Neutralizes hardware IMEI scraping.
     */
    @JvmStatic
    @Suppress("DEPRECATION", "MissingPermission")
    fun getImei(telephonyManager: android.telephony.TelephonyManager?): String? {
        if (telephonyManager == null) return null
        val snapshot = safeSnapshot()
        val enabled = isIdentifierProtectionEnabled || (snapshot?.enforcement?.firewallIdentifiers == true)
        if (enabled) {
            safeLog("DependencyFirewall: neutralized TelephonyManager.getImei access")
            return null
        }
        return try {
            telephonyManager.imei
        } catch (_: SecurityException) {
            null
        }
    }

    /**
     * Intercepted call site for [javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier].
     * Blocks permissive/allow-all hostname verifiers, enforcing system-default verification.
     */
    @JvmStatic
    fun setDefaultHostnameVerifier(verifier: javax.net.ssl.HostnameVerifier?) {
        if (verifier == null) return
        val snapshot = safeSnapshot()
        val enabled = isNetworkSecurityProtectionEnabled || (snapshot?.enforcement?.firewallNetworkSecurity == true)
        if (enabled && isInsecureHostnameVerifier(verifier)) {
            safeLog("DependencyFirewall: neutralized insecure setDefaultHostnameVerifier, restoring strict default")
            return
        }
        javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(verifier)
    }

    /**
     * Intercepted call site for [javax.net.ssl.HttpsURLConnection.setHostnameVerifier].
     * Neutralizes per-connection permissive hostname verifiers.
     */
    @JvmStatic
    fun setHostnameVerifier(connection: javax.net.ssl.HttpsURLConnection?, verifier: javax.net.ssl.HostnameVerifier?) {
        if (connection == null || verifier == null) return
        val snapshot = safeSnapshot()
        val enabled = isNetworkSecurityProtectionEnabled || (snapshot?.enforcement?.firewallNetworkSecurity == true)
        if (enabled && isInsecureHostnameVerifier(verifier)) {
            safeLog("DependencyFirewall: neutralized insecure setHostnameVerifier on connection")
            return
        }
        connection.hostnameVerifier = verifier
    }

    /**
     * Intercepted call site for [javax.net.ssl.SSLContext.init].
     * Detects and neutralizes permissive TrustManagers (e.g. TrustAllCertificates)
     * by substituting secure system-default trust managers.
     */
    @JvmStatic
    fun sslContextInit(
        context: javax.net.ssl.SSLContext?,
        km: Array<javax.net.ssl.KeyManager>?,
        tm: Array<javax.net.ssl.TrustManager>?,
        sr: java.security.SecureRandom?
    ) {
        if (context == null) return
        val snapshot = safeSnapshot()
        val enabled = isNetworkSecurityProtectionEnabled || (snapshot?.enforcement?.firewallNetworkSecurity == true)
        var effectiveTrustManagers = tm
        if (enabled && tm != null && tm.any { isInsecureTrustManager(it) }) {
            safeLog("DependencyFirewall: neutralized insecure TrustManager in SSLContext.init, enforcing system trust store")
            effectiveTrustManagers = getDefaultTrustManagers()
        }
        context.init(km, effectiveTrustManagers, sr)
    }

    internal fun isInsecureHostnameVerifier(verifier: javax.net.ssl.HostnameVerifier?): Boolean {
        if (verifier == null) return true
        return try {
            verifier.verify("untrusted-subdomain-probe.invalid", null)
        } catch (_: Exception) {
            false
        }
    }

    internal fun isInsecureTrustManager(tm: javax.net.ssl.TrustManager?): Boolean {
        if (tm !is javax.net.ssl.X509TrustManager) return false
        return try {
            // A permissive bypass trust manager does not validate the chain and will return without throwing
            tm.checkServerTrusted(emptyArray(), "RSA")
            true
        } catch (_: Exception) {
            // Legitimate TrustManager throws CertificateException or IllegalArgumentException on empty chain
            false
        }
    }

    private fun getDefaultTrustManagers(): Array<javax.net.ssl.TrustManager>? = try {
        val tmf = javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(null as java.security.KeyStore?)
        tmf.trustManagers
    } catch (_: Exception) {
        null
    }
}
