package com.apparmorx.policy

import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Base64
import org.junit.Assert.*
import org.junit.Test

class SignedPolicyTest {
    private val keys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
    private val key = Base64.getEncoder().encodeToString(keys.public.encoded)
    private fun payload(sequence: Long = 7, expires: Long = 2000) =
        "schema=1\nsequence=$sequence\nissued=1000\nexpires=$expires\nmarkers=frida-agent,libfrida-gadget,libxposed\n"
    private fun envelope(text: String): ByteArray {
        val bytes = text.toByteArray()
        val signature = Signature.getInstance("Ed25519").run { initSign(keys.private); update(bytes); sign() }
        return (Base64.getEncoder().encodeToString(bytes) + "\n" + Base64.getEncoder().encodeToString(signature)).toByteArray()
    }
    @Test fun acceptsAuthenticCurrentPolicy() {
        val result = SignedPolicy.verify(envelope(payload()), key, 7, 1500)
        assertEquals(7L, result.sequence)
        assertEquals(listOf("frida-agent", "libfrida-gadget", "libxposed"), result.markers)
    }
    @Test fun rejectsTampering() { rejects { SignedPolicy.verify(envelope(payload()).also { it[5] = 'A'.code.toByte() }, key, 0, 1500) } }
    @Test fun rejectsExpired() { rejects { SignedPolicy.verify(envelope(payload()), key, 0, 2000) } }
    @Test fun rejectsRollback() { rejects { SignedPolicy.verify(envelope(payload()), key, 8, 1500) } }
    @Test fun rejectsFutureIssued() { rejects { SignedPolicy.verify(envelope(payload()), key, 0, 999) } }
    @Test fun rejectsUnknownFields() { rejects { SignedPolicy.verify(envelope(payload() + "execute=command\n"), key, 0, 1500) } }
    @Test fun rejectsDuplicateFields() { rejects { SignedPolicy.verify(envelope(payload() + "sequence=8\n"), key, 0, 1500) } }
    @Test fun rejectsOversizedEnvelope() { rejects { SignedPolicy.verify(ByteArray(100000), key, 0, 1500) } }
    @Test fun rejectsWrongKey() {
        val other = Base64.getEncoder().encodeToString(KeyPairGenerator.getInstance("Ed25519").generateKeyPair().public.encoded)
        rejects { SignedPolicy.verify(envelope(payload()), other, 0, 1500) }
    }
    private fun rejects(block: () -> Unit) { assertThrows(Exception::class.java, block) }
}
