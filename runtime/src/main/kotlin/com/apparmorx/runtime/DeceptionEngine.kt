package com.apparmorx.runtime

import java.util.concurrent.ThreadLocalRandom

/**
 * Mirage engine: a less predictable response than an immediate crash (a deterrent, not prevention).
 * Instead of predictable process crashes or binary exit signals that assist reverse-engineering
 * binary searches, Mirage Mode injects non-deterministic micro-latency jitter and synthetic decoy state.
 */
object DeceptionEngine {
    @Volatile
    var isMirageActive: Boolean = false
        internal set

    /**
     * Injects non-deterministic sleep jitter to desynchronize automated instrumentation scripts,
     * fuzzers, and hooking harnesses without throwing fatal runtime exceptions.
     */
    fun injectJitter(minMillis: Long = 40L, maxMillis: Long = 120L) {
        isMirageActive = true
        try {
            val jitter = ThreadLocalRandom.current().nextLong(minMillis, maxMillis + 1)
            Thread.sleep(jitter)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }
}
