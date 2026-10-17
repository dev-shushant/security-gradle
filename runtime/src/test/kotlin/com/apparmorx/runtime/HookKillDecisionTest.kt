package com.apparmorx.runtime

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [shouldKillOnConfirmedHooking] is the pure decision for the opt-in `killOnConfirmedHooking` policy
 * (see AGENTS.md for the exact, narrow carve-out this implements). The actual `Process.killProcess()`
 * call lives in EnforcementResponse -- the only place in the enforcement path that touches Android
 * process APIs -- so it is not unit tested here; this file locks down exactly when that call is
 * reached, which is the part that must never be wrong.
 */
class HookKillDecisionTest {
    private val enabledPolicy = EnforcementPolicy(EnforcementAction.BLOCK_SCREEN, false, killOnConfirmedHooking = true)
    private val disabledPolicy = EnforcementPolicy(EnforcementAction.BLOCK_SCREEN, false, killOnConfirmedHooking = false)
    private fun detected(check: String) = listOf(Evidence(check, Status.DETECTED))

    @Test fun falseWhenPolicyDisabled() {
        assertFalse(shouldKillOnConfirmedHooking(detected("native-frida-port"), disabledPolicy, debuggable = false))
    }

    @Test fun falseWhenDebuggableEvenIfPolicyEnabledAndHookingDetected() {
        assertFalse(shouldKillOnConfirmedHooking(detected("native-frida-port"), enabledPolicy, debuggable = true))
    }

    @Test fun falseWhenNoHookingEvidenceDetected() {
        // RESTRICTED for an unrelated reason (e.g. root, signer mismatch) must never trigger this --
        // only hooking/injection-specific checks do.
        val evidence = listOf(Evidence("root-path", Status.DETECTED), Evidence("signing-certificate", Status.DETECTED))
        assertFalse(shouldKillOnConfirmedHooking(evidence, enabledPolicy, debuggable = false))
    }

    @Test fun falseWhenHookingCheckIsOnlyUnavailableNotDetected() {
        // Never treat an unavailable probe as if it were confirmed -- same invariant as everywhere else.
        val evidence = listOf(Evidence("native-frida-port", Status.UNAVAILABLE))
        assertFalse(shouldKillOnConfirmedHooking(evidence, enabledPolicy, debuggable = false))
    }

    @Test fun trueWhenPolicyEnabledHookingDetectedAndNotDebuggable() {
        assertTrue(shouldKillOnConfirmedHooking(detected("native-frida-port"), enabledPolicy, debuggable = false))
    }

    @Test fun trueForEveryRecognizedHookingCheck() {
        for (check in HOOKING_CHECKS) {
            assertTrue("expected kill for $check", shouldKillOnConfirmedHooking(detected(check), enabledPolicy, debuggable = false))
        }
    }

    @Test fun mixedEvidenceWithOneConfirmedHookingCheckAmongOthersStillKills() {
        val evidence = listOf(Evidence("root-path", Status.CLEAR), Evidence("native-tool-thread", Status.DETECTED))
        assertTrue(shouldKillOnConfirmedHooking(evidence, enabledPolicy, debuggable = false))
    }
}
