package com.apparmorx.platform

import org.junit.Assert.*
import org.junit.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class ChallengeLedgerTest {
    private val now = Instant.parse("2026-10-18T00:00:00Z")
    private val binding = ActionBinding("app", "session", "transfer", "a".repeat(64))
    private fun ledger() = ChallengeLedger(Clock.fixed(now, ZoneOffset.UTC), capacity = 2)

    @Test fun consumesExactlyOnce() {
        val ledger = ledger()
        val challenge = ledger.issue(binding)
        assertEquals(ConsumeResult.MATCHED, ledger.consume(challenge.nonce, binding))
        assertEquals(ConsumeResult.UNKNOWN, ledger.consume(challenge.nonce, binding))
    }

    @Test fun mismatchBurnsChallenge() {
        val ledger = ledger()
        val challenge = ledger.issue(binding)
        for (other in listOf(binding.copy(application = "other"), binding.copy(session = "other"),
            binding.copy(operation = "other"), binding.copy(requestSha256 = "b".repeat(64)))) {
            val fresh = ledger.issue(binding)
            assertEquals(ConsumeResult.MISMATCH, ledger.consume(fresh.nonce, other))
            assertEquals(ConsumeResult.UNKNOWN, ledger.consume(fresh.nonce, binding))
        }
        assertEquals(ConsumeResult.MATCHED, ledger.consume(challenge.nonce, binding))
    }

    @Test fun expiryBoundaryIsRejected() {
        var instant = now
        val clock = object : Clock() {
            override fun getZone() = ZoneOffset.UTC
            override fun withZone(zone: java.time.ZoneId): Clock = this
            override fun instant() = instant
        }
        val ledger = ChallengeLedger(clock)
        val challenge = ledger.issue(binding, 10)
        instant = now.plusSeconds(10)
        assertEquals(ConsumeResult.EXPIRED, ledger.consume(challenge.nonce, binding))
    }

    @Test fun boundsAndMalformedInputAreRejected() {
        assertThrows(IllegalArgumentException::class.java) { binding.copy(requestSha256 = "not-a-digest") }
        assertThrows(IllegalArgumentException::class.java) { binding.copy(session = " ") }
        val ledger = ledger()
        assertThrows(IllegalArgumentException::class.java) { ledger.issue(binding, 0) }
        assertThrows(IllegalArgumentException::class.java) { ledger.issue(binding, 301) }
        ledger.issue(binding); ledger.issue(binding)
        assertThrows(IllegalStateException::class.java) { ledger.issue(binding) }
        assertEquals(ConsumeResult.UNKNOWN, ledger.consume("unknown", binding))
    }

    @Test fun noncesAreUniqueAndExpiredCapacityIsReclaimed() {
        var instant = now
        val clock = object : Clock() {
            override fun getZone() = ZoneOffset.UTC
            override fun withZone(zone: java.time.ZoneId): Clock = this
            override fun instant() = instant
        }
        val ledger = ChallengeLedger(clock, capacity = 1)
        val first = ledger.issue(binding, 1)
        assertTrue(first.nonce.matches(Regex("[A-Za-z0-9_-]{43}")))
        instant = now.plusSeconds(1)
        val second = ledger.issue(binding)
        assertNotEquals(first.nonce, second.nonce)
        assertEquals(ConsumeResult.UNKNOWN, ledger.consume(first.nonce, binding))
        assertEquals(ConsumeResult.MATCHED, ledger.consume(second.nonce, binding))
    }

    @Test fun concurrentReplayHasOneWinner() {
        val ledger = ledger()
        val challenge = ledger.issue(binding)
        val pool = Executors.newFixedThreadPool(8)
        try {
            val results = (1..32).map { pool.submit<ConsumeResult> { ledger.consume(challenge.nonce, binding) } }
                .map { it.get(5, TimeUnit.SECONDS) }
            assertEquals(1, results.count { it == ConsumeResult.MATCHED })
        } finally { pool.shutdownNow() }
    }
}
