package com.apparmorx.runtime

import org.junit.Assert.assertEquals
import org.junit.Test

class DebugEnforcementSafetyTest {
    @Test fun debugNeverBlocksOrDelaysEvenWithExplicitPolicyOverrides() {
        for (action in EnforcementAction.entries) for (state in ProtectionState.entries) {
            val policy = EnforcementPolicy(action, enforceIndeterminate = true, failClosedOnStartup = true)
            assertEquals("$action / $state must observe in debug", EnforcementAction.OBSERVE,
                resolveEnforcementAction(state, policy, debuggable = true))
        }
    }

    @Test fun releaseConfirmedThreatResponseStillUsesConfiguredAction() {
        for (action in EnforcementAction.entries) {
            assertEquals(action, resolveEnforcementAction(ProtectionState.RESTRICTED,
                EnforcementPolicy(action, false), debuggable = false))
        }
    }
}
