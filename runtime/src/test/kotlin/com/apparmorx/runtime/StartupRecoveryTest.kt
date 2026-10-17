package com.apparmorx.runtime

import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class StartupRecoveryTest {
    private val policy = EnforcementPolicy(EnforcementAction.BLOCK_SCREEN, false, failClosedOnStartup = true)

    @Test fun pendingWaitsAndNeverPretendsToBeReadyAtTimeout() {
        assertEquals(StartupRecovery.WAIT, startupRecovery(ProtectionState.CHECKING, policy, 999, 1000))
        assertEquals(StartupRecovery.UNAVAILABLE, startupRecovery(ProtectionState.CHECKING, policy, 1000, 1000))
    }
    @Test fun completedStateUsesActualPolicyWithoutConvertingUnknownToClear() {
        assertEquals(StartupRecovery.RESUME, startupRecovery(ProtectionState.READY, policy, 10, 1000))
        assertEquals(StartupRecovery.RESTRICTED, startupRecovery(ProtectionState.RESTRICTED, policy, 10, 1000))
        assertEquals(StartupRecovery.RESUME, startupRecovery(ProtectionState.INDETERMINATE, policy, 10, 1000))
        assertEquals(StartupRecovery.UNAVAILABLE, startupRecovery(ProtectionState.INDETERMINATE, policy.copy(enforceIndeterminate = true), 10, 1000))
    }
    @Test fun invalidElapsedTimeDoesNotResume() {
        assertEquals(StartupRecovery.UNAVAILABLE, startupRecovery(ProtectionState.READY, policy, -1, 1000))
    }
    @Test fun ticketCannotBeReplayedOrGuessed() {
        val tickets = ExpiringTickets<String>(clockMillis = { 100L })
        val token = tickets.issue("owned launch request")
        assertTrue(tickets.isValid(token))
        assertNull(tickets.consume("guessed"))
        assertEquals("owned launch request", tickets.consume(token))
        assertNull(tickets.consume(token))
    }
    @Test fun ticketsExpireAtBoundaryAndClockReversalFailsClosed() {
        var clock = 100L
        val tickets = ExpiringTickets<String>(ttlMillis = 100, clockMillis = { clock })
        val token = tickets.issue("launch")
        clock = 200L
        assertFalse(tickets.isValid(token)); assertNull(tickets.consume(token))
        clock = 100L
        val reversed = tickets.issue("launch")
        clock = 99L
        assertNull(tickets.consume(reversed))
    }
    @Test fun ticketCapacityAndRevocationAreBounded() {
        val tickets = ExpiringTickets<String>(capacity = 1, clockMillis = { 100L })
        val token = tickets.issue("launch")
        assertThrows(IllegalStateException::class.java) { tickets.issue("other") }
        tickets.revoke(token)
        assertFalse(tickets.isValid(token))
        assertNotEquals(token, tickets.issue("other"))
    }
    @Test fun concurrentConsumptionHasOneWinner() {
        val tickets = ExpiringTickets<String>(clockMillis = { 100L })
        val token = tickets.issue("launch")
        val pool = Executors.newFixedThreadPool(4)
        try {
            val results = (1..12).map { pool.submit<String?> { tickets.consume(token) } }
                .map { it.get(5, TimeUnit.SECONDS) }
            assertEquals(1, results.count { it != null })
        } finally { pool.shutdownNow() }
    }
    @Test fun explicitTaskClosePolicyDoesNotTurnIntoDifferentUiResponse() {
        assertEquals(StartupRecovery.EXIT, startupRecovery(ProtectionState.RESTRICTED,
            policy.copy(restrictedAction = EnforcementAction.TERMINATE), 10, 1000))
    }
}
