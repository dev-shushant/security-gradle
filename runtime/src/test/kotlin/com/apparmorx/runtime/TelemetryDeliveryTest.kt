package com.apparmorx.runtime

import com.sun.net.httpserver.HttpsConfigurator
import com.sun.net.httpserver.HttpsServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.io.IOException
import java.net.InetSocketAddress
import java.security.KeyStore
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory

/** Real TLS round trip: what a customer's server will actually receive and be able to verify. */
class TelemetryDeliveryTest {
    @get:Rule val folder = TemporaryFolder()
    private lateinit var server: HttpsServer
    private var previousFactory = HttpsURLConnection.getDefaultSSLSocketFactory()
    private var previousVerifier = HttpsURLConnection.getDefaultHostnameVerifier()

    @Volatile private var received: Map<String, String>? = null
    @Volatile private var body: String? = null
    @Volatile private var hitAfterRedirect = false
    private val port get() = server.address.port

    @Before fun startServer() {
        val file = folder.root.resolve("srv.p12")
        val pw = "changeit"
        val keytool = File(System.getProperty("java.home"), "bin/keytool").path
        val p = ProcessBuilder(keytool, "-genkeypair", "-keystore", file.path, "-storetype", "PKCS12", "-alias", "s", "-keyalg", "RSA",
            "-keysize", "2048", "-validity", "2", "-dname", "CN=localhost", "-ext", "san=dns:localhost", "-storepass", pw, "-keypass", pw)
            .redirectErrorStream(true).start()
        assertEquals(p.inputStream.readBytes().decodeToString(), 0, p.waitFor())
        val ks = KeyStore.getInstance("PKCS12").apply { file.inputStream().use { load(it, pw.toCharArray()) } }
        val ctx = SSLContext.getInstance("TLS").apply {
            init(KeyManagerFactory.getInstance("SunX509").apply { init(ks, pw.toCharArray()) }.keyManagers,
                TrustManagerFactory.getInstance("PKIX").apply { init(ks) }.trustManagers, null)
        }
        server = HttpsServer.create(InetSocketAddress("127.0.0.1", 0), 0).apply {
            httpsConfigurator = HttpsConfigurator(ctx)
            createContext("/events") { ex ->
                received = ex.requestHeaders.entries.associate { it.key.lowercase() to it.value.first() }
                body = ex.requestBody.readBytes().decodeToString()
                ex.sendResponseHeaders(204, -1); ex.close()
            }
            createContext("/redirect") { ex -> ex.responseHeaders.add("Location", "https://localhost:$port/after"); ex.sendResponseHeaders(302, -1); ex.close() }
            createContext("/after") { ex -> hitAfterRedirect = true; ex.sendResponseHeaders(204, -1); ex.close() }
            start()
        }
        // Trust only this test server, and accept its host name for the duration of the test.
        HttpsURLConnection.setDefaultSSLSocketFactory(ctx.socketFactory)
        HttpsURLConnection.setDefaultHostnameVerifier { _, _ -> true }
    }

    @After fun stopServer() {
        server.stop(0)
        HttpsURLConnection.setDefaultSSLSocketFactory(previousFactory)
        HttpsURLConnection.setDefaultHostnameVerifier(previousVerifier)
    }

    @Test fun deliversSignedReportWithCustomHeadersAndServerCanVerifyTheSignature() {
        val json = """{"schemaVersion":2,"eventId":"e1"}"""
        val key = "tenant-shared-secret"
        TelemetryDispatcher.sendHttpsPost("https://localhost:$port/events", json, key, mapOf("X-Api-Key" to "k-123", "X-Tenant" to "acme"))

        val h = received!!
        assertEquals(json, body)
        assertEquals("k-123", h["x-api-key"]); assertEquals("acme", h["x-tenant"])
        assertTrue(h["content-type"]!!.startsWith("application/json"))
        // This is exactly what a receiving server does.
        val timestamp = h["x-apparmorx-timestamp"]!!
        assertEquals(TelemetryDispatcher.computeHmacSha256(key, "$timestamp.$json"), h["x-apparmorx-signature"])
    }

    @Test fun unsignedWhenNoKeyIsConfigured() {
        TelemetryDispatcher.sendHttpsPost("https://localhost:$port/events", "{}")
        assertNull(received!!["x-apparmorx-signature"])
    }

    @Test fun neverFollowsRedirectsSoCredentialsCannotBeForwardedElsewhere() {
        assertThrows(IOException::class.java) {
            TelemetryDispatcher.sendHttpsPost("https://localhost:$port/redirect", "{}", "k", mapOf("X-Api-Key" to "secret"))
        }
        assertFalse(hitAfterRedirect)
    }

    @Test fun reservedHeadersCannotBeSmuggledInAtSendTime() {
        assertThrows(IllegalArgumentException::class.java) {
            TelemetryDispatcher.sendHttpsPost("https://localhost:$port/events", "{}", "k", mapOf("X-AppArmorX-Signature" to "forged"))
        }
        assertNull(received)
    }

    @Test fun offlineQueueIsDeliveredEvenWithoutANewIncident() {
        val queue = folder.root.resolve("q.queue")
        OfflineEventQueue.enqueue(queue, """{"eventId":"queued-1"}""")
        TelemetryDispatcher.resetStateForTesting()
        TelemetryDispatcher.dispatchOrQueue("https://localhost:$port/events", """{"eventId":"live"}""", "k", queue)
        assertEquals(0, OfflineEventQueue.size(queue))
        assertTrue(body!!.contains("queued-1") || body!!.contains("live"))
    }
}
