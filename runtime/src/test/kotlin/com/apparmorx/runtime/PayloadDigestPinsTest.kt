package com.apparmorx.runtime

import org.junit.Assert.*
import org.junit.Test

class PayloadDigestPinsTest {
    private val digest = "a".repeat(64)

    @Test fun absentLegacyPinsRemainOptional() {
        assertEquals(emptyMap<String, String>(), parsePayloadDigestPins(null))
        assertEquals(emptyMap<String, String>(), parsePayloadDigestPins(""))
    }

    @Test fun parsesEveryConfiguredPin() {
        assertEquals(mapOf("classes.dex" to digest, "lib/arm64-v8a/libapparmorx.so" to digest),
            parsePayloadDigestPins("classes.dex:$digest,lib/arm64-v8a/libapparmorx.so:$digest"))
    }

    @Test fun malformedPinsCannotSilentlyDisappear() {
        for (value in listOf("missing-colon", "classes.dex:", ":$digest", "classes.dex:xyz",
            "classes.dex:$digest,malformed", "classes.dex:$digest,", "classes.dex:$digest:extra")) {
            assertThrows(value, IllegalArgumentException::class.java) { parsePayloadDigestPins(value) }
        }
    }

    @Test fun duplicatePinsCannotOverwriteEarlierExpectation() {
        assertThrows(IllegalArgumentException::class.java) {
            parsePayloadDigestPins("classes.dex:$digest,classes.dex:${"b".repeat(64)}")
        }
    }

    @Test fun ambiguousOrUnsafeEntryNamesAreRejected() {
        for (path in listOf("../classes.dex", "/classes.dex", "a//b", "a/./b", "a/../b",
            "a\\b", "a\nb", "a,b", "a:b", " classes.dex", "classes.dex ")) {
            assertThrows(path, IllegalArgumentException::class.java) { parsePayloadDigestPins("$path:$digest") }
        }
    }

    @Test fun uppercaseDigestNormalizesWithoutChangingMeaning() {
        assertEquals(mapOf("classes.dex" to digest), parsePayloadDigestPins("classes.dex:${digest.uppercase()}"))
    }
    @Test fun invalidPolicyCannotFallBackToUnpinnedCleanIntegrity() {
        assertEquals(Status.UNAVAILABLE, payloadIntegrityEvidence(java.io.File("unused.apk"), null).status)
    }

    @Test fun oversizedPinsAreRejected() {
        assertThrows(IllegalArgumentException::class.java) { parsePayloadDigestPins("a".repeat(32769)) }
    }
}
