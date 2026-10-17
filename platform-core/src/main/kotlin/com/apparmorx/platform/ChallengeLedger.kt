package com.apparmorx.platform

import java.security.SecureRandom
import java.time.Clock
import java.time.Instant
import java.util.Base64

/** Server-derived context. requestSha256 hashes a separately specified canonical payload. */
data class ActionBinding(
    val application: String,
    val session: String,
    val operation: String,
    val requestSha256: String,
) {
    init {
        require(listOf(application, session, operation).all { value ->
            value.isNotBlank() && value.length <= 256 && value.none { it.isISOControl() }
        }) { "Binding identifiers must contain 1–256 non-control characters" }
        require(requestSha256.matches(Regex("[0-9a-f]{64}"))) { "Expected lowercase SHA-256 hex" }
    }
}

data class Challenge(val nonce: String, val expiresAt: Instant)

/** MATCHED confirms a one-time binding only: it is NOT attestation or authorization. */
enum class ConsumeResult { MATCHED, UNKNOWN, EXPIRED, MISMATCH }

/** Single-process prototype. Not a durable or distributed replay store. */
class ChallengeLedger(
    private val clock: Clock = Clock.systemUTC(),
    private val capacity: Int = 1024,
) {
    private data class Entry(val binding: ActionBinding, val expiresAt: Instant)
    private val entries = mutableMapOf<String, Entry>()
    private val random = SecureRandom()

    init { require(capacity in 1..100_000) { "Invalid outstanding challenge capacity" } }

    @Synchronized
    fun issue(binding: ActionBinding, ttlSeconds: Long = 60): Challenge {
        require(ttlSeconds in 1..300) { "Challenge lifetime must be 1–300 seconds" }
        val now = clock.instant()
        entries.entries.removeIf { !now.isBefore(it.value.expiresAt) }
        check(entries.size < capacity) { "Outstanding challenge capacity reached" }
        var nonce: String
        do {
            val bytes = ByteArray(32)
            random.nextBytes(bytes)
            nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
        } while (entries.containsKey(nonce))
        val expiry = now.plusSeconds(ttlSeconds)
        entries[nonce] = Entry(binding, expiry)
        return Challenge(nonce, expiry)
    }

    /** Removal and comparison share one lock; mismatches deliberately burn the challenge. */
    @Synchronized
    fun consume(nonce: String, binding: ActionBinding): ConsumeResult {
        val entry = entries.remove(nonce) ?: return ConsumeResult.UNKNOWN
        if (!clock.instant().isBefore(entry.expiresAt)) return ConsumeResult.EXPIRED
        return if (entry.binding == binding) ConsumeResult.MATCHED else ConsumeResult.MISMATCH
    }
}
