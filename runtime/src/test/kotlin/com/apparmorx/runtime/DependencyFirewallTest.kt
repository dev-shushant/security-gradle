package com.apparmorx.runtime

import org.junit.Assert.*
import org.junit.Test

class DependencyFirewallTest {
    @Test
    fun handlesNullClipboardManagerSafely() {
        assertNull(DependencyFirewall.getPrimaryClip(null))
        assertFalse(DependencyFirewall.hasPrimaryClip(null))
    }

    @Test
    fun handlesNullContentResolverSafely() {
        assertNull(DependencyFirewall.getString(null, "android_id"))
        assertNull(DependencyFirewall.getString(null, null))
    }

    @Test
    fun protectsClipboardWhenExplicitlyEnabled() {
        DependencyFirewall.isClipboardProtectionEnabled = true
        assertTrue(DependencyFirewall.isClipboardProtectionEnabled)
        assertNull(DependencyFirewall.getPrimaryClip(null))
        assertFalse(DependencyFirewall.hasPrimaryClip(null))
        DependencyFirewall.isClipboardProtectionEnabled = false
    }

    @Test
    fun protectsIdentifierWhenExplicitlyEnabled() {
        DependencyFirewall.isIdentifierProtectionEnabled = true
        assertTrue(DependencyFirewall.isIdentifierProtectionEnabled)
        // With null resolver, it safely guards without throwing NPE
        assertNull(DependencyFirewall.getString(null, "android_id"))
        assertNull(DependencyFirewall.getDeviceId(null))
        assertNull(DependencyFirewall.getImei(null))
        DependencyFirewall.isIdentifierProtectionEnabled = false
    }

    @Test
    fun handlesNullLocationAndTelephonySafely() {
        assertNull(DependencyFirewall.getLastKnownLocation(null, "gps"))
        assertNull(DependencyFirewall.getLastKnownLocation(null, null))
        assertNull(DependencyFirewall.getDeviceId(null))
        assertNull(DependencyFirewall.getImei(null))
    }

    @Test
    fun protectsLocationWhenExplicitlyEnabled() {
        DependencyFirewall.isLocationProtectionEnabled = true
        assertTrue(DependencyFirewall.isLocationProtectionEnabled)
        assertNull(DependencyFirewall.getLastKnownLocation(null, "gps"))
        DependencyFirewall.isLocationProtectionEnabled = false
    }

    @Test
    fun detectsInsecureHostnameVerifier() {
        assertTrue(DependencyFirewall.isInsecureHostnameVerifier(null))
        val permissive = javax.net.ssl.HostnameVerifier { _, _ -> true }
        assertTrue(DependencyFirewall.isInsecureHostnameVerifier(permissive))

        val strict = javax.net.ssl.HostnameVerifier { host, _ -> host == "example.com" }
        assertFalse(DependencyFirewall.isInsecureHostnameVerifier(strict))
    }

    @Test
    fun detectsInsecureTrustManager() {
        val fakeTrustAll = object : javax.net.ssl.X509TrustManager {
            override fun checkClientTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = emptyArray()
        }
        assertTrue(DependencyFirewall.isInsecureTrustManager(fakeTrustAll))

        val strict = object : javax.net.ssl.X509TrustManager {
            override fun checkClientTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {
                if (chain.isNullOrEmpty()) throw java.security.cert.CertificateException("Empty chain")
            }
            override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = emptyArray()
        }
        assertFalse(DependencyFirewall.isInsecureTrustManager(strict))
    }

    @Test
    fun handlesNullNetworkSecurityCallsSafely() {
        DependencyFirewall.setDefaultHostnameVerifier(null)
        DependencyFirewall.setHostnameVerifier(null, null)
        DependencyFirewall.sslContextInit(null, null, null, null)
    }
}
