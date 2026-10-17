package com.apparmorx.gradle

import org.junit.Assert.*
import org.junit.Test

class PayloadDigestConfigTest {
    private val digest = "A".repeat(64)

    @Test fun legacyEmptyPinsSerializeEmpty() { assertEquals("", serializePayloadDigestPins(emptyMap())) }

    @Test fun validPinsSerializeDeterministically() {
        assertEquals("AndroidManifest.xml:${digest.lowercase()},classes.dex:${digest.lowercase()}",
            serializePayloadDigestPins(mapOf("classes.dex" to digest, "AndroidManifest.xml" to digest)))
    }

    @Test fun separatorAndPropertyInjectionAreRejected() {
        for (path in listOf("classes.dex,other", "classes.dex:extra", "classes.dex\nfirewallClipboard=false",
            "a\\b", "../classes.dex", "/classes.dex", "a//b", "a/./b", "a/../b", "classes.dex ")) {
            assertThrows(path, IllegalArgumentException::class.java) { serializePayloadDigestPins(mapOf(path to digest)) }
        }
    }

    @Test fun malformedDigestIsRejected() {
        assertThrows(IllegalArgumentException::class.java) { serializePayloadDigestPins(mapOf("classes.dex" to "wrong")) }
    }
}
