package com.apparmorx.runtime

import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.TimeUnit

internal enum class StartupRecovery { WAIT, RESUME, RESTRICTED, UNAVAILABLE, EXIT }

internal fun startupRecovery(
    state: ProtectionState,
    policy: EnforcementPolicy,
    elapsedMillis: Long,
    timeoutMillis: Long,
): StartupRecovery {
    if (elapsedMillis < 0 || timeoutMillis <= 0) return StartupRecovery.UNAVAILABLE
    if (state == ProtectionState.CHECKING) {
        return if (elapsedMillis < timeoutMillis) StartupRecovery.WAIT else StartupRecovery.UNAVAILABLE
    }
    val response = resolveEnforcementAction(state, policy)
    if (response == EnforcementAction.TERMINATE) return StartupRecovery.EXIT
    val blocks = response == EnforcementAction.BLOCK_SCREEN
    return when {
        !blocks -> StartupRecovery.RESUME
        state == ProtectionState.RESTRICTED -> StartupRecovery.RESTRICTED
        else -> StartupRecovery.UNAVAILABLE
    }
}

/** Process-local, bounded, expiring capabilities. A caller cannot supply its own resume payload. */
internal class ExpiringTickets<T : Any>(
    private val capacity: Int = 16,
    private val ttlMillis: Long = 300_000,
    private val clockMillis: () -> Long = { TimeUnit.NANOSECONDS.toMillis(System.nanoTime()) },
) {
    private data class Entry<T>(val value: T, val created: Long)
    private val values = mutableMapOf<String, Entry<T>>()
    private val random = SecureRandom()
    init { require(capacity in 1..1024 && ttlMillis in 1..600_000) }
    private fun expired(entry: Entry<T>, now: Long): Boolean = now - entry.created !in 0 until ttlMillis

    @Synchronized fun issue(value: T): String {
        val now = clockMillis()
        values.entries.removeIf { expired(it.value, now) }
        check(values.size < capacity) { "Pending startup capacity reached" }
        var token: String
        do {
            val bytes = ByteArray(32)
            random.nextBytes(bytes)
            token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
        } while (token in values)
        values[token] = Entry(value, now)
        return token
    }
    @Synchronized fun isValid(token: String): Boolean {
        val entry = values[token] ?: return false
        if (expired(entry, clockMillis())) { values.remove(token); return false }
        return true
    }
    @Synchronized fun consume(token: String): T? {
        val entry = values.remove(token) ?: return null
        return entry.value.takeUnless { expired(entry, clockMillis()) }
    }
    @Synchronized fun revoke(token: String) { values.remove(token) }
}
