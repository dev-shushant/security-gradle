package com.apparmorx.runtime

import org.junit.Assert.*
import org.junit.Test

class HardwareAttestationTest {

    @Test
    fun rejectsEmptyChallenge() {
        val result = HardwareAttestation.generateAttestedKey(
            context = object : android.content.ContextWrapper(null) {},
            challenge = byteArrayOf()
        )
        assertTrue(result is HardwareAttestation.AttestationResult.Failure)
        assertEquals("Challenge must be between 1 and 128 bytes", (result as HardwareAttestation.AttestationResult.Failure).error)
    }

    @Test
    fun rejectsOversizedChallenge() {
        val oversized = ByteArray(129) { 0x01 }
        val result = HardwareAttestation.generateAttestedKey(
            context = object : android.content.ContextWrapper(null) {},
            challenge = oversized
        )
        assertTrue(result is HardwareAttestation.AttestationResult.Failure)
        assertEquals("Challenge must be between 1 and 128 bytes", (result as HardwareAttestation.AttestationResult.Failure).error)
    }

    @Test
    fun playIntegrityHashesTransactionDeterministically() {
        val data = "order_id=12345;amount=99.99;nonce=abc".toByteArray(Charsets.UTF_8)
        val hash1 = PlayIntegrityAdapter.hashTransaction(data)
        val hash2 = PlayIntegrityAdapter.hashTransaction(data)
        assertEquals(hash1, hash2)
        assertEquals(64, hash1.length) // SHA-256 hex is 64 characters
    }
}
