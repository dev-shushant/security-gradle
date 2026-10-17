package com.apparmorx.runtime

import org.junit.Assert.*
import org.junit.Test

class StartupGateTest {
    private val required = setOf("policy", "signing-certificate", "native-engine")
    private val blocking = EnforcementPolicy(EnforcementAction.BLOCK_SCREEN, false, failClosedOnStartup = true)
    private val pending = SecuritySnapshot(100, 0, listOf(Evidence("scan-pending", Status.UNAVAILABLE)), blocking)

    @Test fun partialPreflightIsCheckingNotCompletedIndeterminate() {
        assertEquals(ProtectionState.CHECKING, decideProtection(pending, 101, required))
        assertEquals(EnforcementAction.BLOCK_SCREEN, resolveEnforcementAction(decideProtection(pending, 101, required), blocking))
    }
    @Test fun confirmedPreflightThreatStillRestrictsImmediately() {
        assertEquals(ProtectionState.RESTRICTED, decideProtection(pending.copy(
            evidence = pending.evidence + Evidence("native-hook-library", Status.DETECTED)), 101, required))
    }
    @Test fun completedUnknownScanStaysIndeterminate() {
        assertEquals(ProtectionState.INDETERMINATE, decideProtection(pending.copy(evidence = emptyList()), 101, required))
    }
    @Test fun applicationInitializationCannotBeDeferredAndThenReplayed() {
        assertEquals(EnforcementAction.OBSERVE, resolveEnforcementAction(ProtectionState.CHECKING, blocking,
            debuggable = false, startupGateApplies = false))
        assertEquals(EnforcementAction.BLOCK_SCREEN, resolveEnforcementAction(ProtectionState.RESTRICTED, blocking,
            debuggable = false, startupGateApplies = false))
    }
}
