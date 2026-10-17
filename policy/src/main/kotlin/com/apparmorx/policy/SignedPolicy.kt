package com.apparmorx.policy

import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/** Verified, data-only threat policy. Times use Unix seconds; markers are literal substrings. */
data class ThreatPolicy(val sequence: Long, val expires: Long, val markers: List<String>, val sha256: String)

/** Verifies exact bytes before parsing. The trusted public key must come from reviewed build configuration. */
object SignedPolicy {
    const val MAX_BYTES = 65536

    /**
     * @param envelope two ASCII Base64 lines: payload then Ed25519 signature.
     * @param publicKey Base64 X.509 encoded Ed25519 public key.
     * @param minimumSequence committed rollback floor; CI must advance it after accepting updates.
     * @param now current trusted build clock in Unix seconds.
     * @return authenticated and validated policy.
     * @throws IllegalArgumentException when input violates the protocol or trust policy.
     */
    fun verify(envelope: ByteArray, publicKey: String, minimumSequence: Long, now: Long): ThreatPolicy {
        require(envelope.size in 1..MAX_BYTES) { "Invalid policy size" }
        require(minimumSequence >= 0 && now >= 0) { "Invalid trust constraints" }
        require(envelope.all { it.toInt() in 10..126 }) { "Policy envelope must be ASCII" }
        val lines = envelope.toString(Charsets.US_ASCII).trimEnd('\n').split('\n')
        require(lines.size == 2) { "Expected payload and signature" }
        val decoder = Base64.getDecoder()
        val payload = decoder.decode(lines[0])
        val signature = decoder.decode(lines[1])
        require(signature.size == 64) { "Invalid Ed25519 signature size" }
        val key = KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(decoder.decode(publicKey)))
        require(Signature.getInstance("Ed25519").run { initVerify(key); update(payload); verify(signature) }) {
            "Policy signature verification failed"
        }
        require(payload.all { it.toInt() == 10 || it.toInt() in 32..126 }) { "Policy must be ASCII" }
        val fields = linkedMapOf<String, String>()
        payload.toString(Charsets.US_ASCII).trimEnd('\n').split('\n').forEach {
            val parts = it.split('=', limit = 2)
            require(parts.size == 2 && fields.put(parts[0], parts[1]) == null) { "Malformed or duplicate field" }
        }
        require(fields.keys == setOf("schema", "sequence", "issued", "expires", "markers")) { "Unsupported policy fields" }
        require(fields.getValue("schema") == "1") { "Unsupported schema" }
        val sequence = fields.getValue("sequence").toLong()
        val issued = fields.getValue("issued").toLong()
        val expires = fields.getValue("expires").toLong()
        require(sequence >= minimumSequence) { "Policy rollback rejected" }
        require(issued in 0..now && expires > now && expires - issued in 1..2592000) { "Policy is future-dated, expired or exceeds 30 days" }
        val markers = fields.getValue("markers").split(',')
        require(markers.size in 1..128 && markers.distinct().size == markers.size) { "Invalid marker count" }
        require(markers.all { it.matches(Regex("[a-z0-9._-]{4,80}")) }) { "Invalid literal indicator" }
        val hash = MessageDigest.getInstance("SHA-256").digest(payload).joinToString("") { "%02x".format(it) }
        return ThreatPolicy(sequence, expires, markers.toList(), hash)
    }
}
