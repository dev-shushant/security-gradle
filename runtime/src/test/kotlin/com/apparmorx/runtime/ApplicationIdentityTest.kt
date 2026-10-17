package com.apparmorx.runtime

import java.util.Properties
import org.junit.Assert.*
import org.junit.Test

class ApplicationIdentityTest {
    private val app = "com.apparmorx.sample"
    private fun configuration(expected: String?) = parseScanConfiguration(Properties().apply {
        setProperty("restrictedAction", "BLOCK_SCREEN")
        setProperty("enforceIndeterminate", "false")
        if (expected != null) setProperty("applicationId", expected)
    })
    @Test fun absentOrMalformedExpectedIdentityIsUnknownNotAConfirmedMismatch() {
        for (expected in listOf(null, "", " ", "com", ".com.app", "com..app", "com.1app", "com.a-b", "com.app\n", "com.éapp")) {
            assertEquals("Bad configured identity: $expected", Status.UNAVAILABLE, applicationIdentityEvidence(app, expected).status)
        }
    }
    @Test fun missingOrMalformedObservedIdentityIsNotACleanMatchOrConfirmedMismatch() {
        for (actual in listOf(null, "", " ", "com..app")) {
            assertEquals(Status.UNAVAILABLE, applicationIdentityEvidence(actual, app).status)
            assertEquals("Matching malformed values cannot authenticate identity", Status.UNAVAILABLE,
                applicationIdentityEvidence(actual, actual).status)
            assertEquals("Usable configuration cannot bless an unavailable observed identity", Status.UNAVAILABLE,
                configuration(app).policyEvidence(actual, 0, 100).status)
        }
    }
    @Test fun validIdentityIsComparedExactlyIncludingCaseAndSuffixes() {
        assertEquals(Status.CLEAR, applicationIdentityEvidence(app, app).status)
        assertEquals(Status.CLEAR, applicationIdentityEvidence("com.AppArmorX.app_2", "com.AppArmorX.app_2").status)
        assertEquals(Status.DETECTED, applicationIdentityEvidence(app, app + ".other").status)
        assertEquals(Status.DETECTED, applicationIdentityEvidence(app, "com.AppArmorX.sample").status)
    }
    @Test fun policyCannotBeClearWithoutAUsableIdentity() {
        for (expected in listOf(null, "", "com..app")) {
            val config = configuration(expected)
            val evidence = listOf(config.policyEvidence(app, 0, 100), applicationIdentityEvidence(app, expected))
            assertEquals(Status.UNAVAILABLE, evidence.first().status)
            val state = decideProtection(SecuritySnapshot(100, 0, evidence, config.enforcement), 101, setOf("policy"))
            assertEquals(ProtectionState.INDETERMINATE, state)
            assertEquals(EnforcementAction.OBSERVE, resolveEnforcementAction(state, config.enforcement))
        }
    }
    @Test fun validMismatchStillRestrictsEvenWhenUnknownEvidenceIsObserveOnly() {
        val config = configuration(app + ".other")
        val evidence = listOf(config.policyEvidence(app, 0, 100), applicationIdentityEvidence(app, config.applicationId))
        val state = decideProtection(SecuritySnapshot(100, 0, evidence, config.enforcement), 101, setOf("policy"))
        assertEquals(ProtectionState.RESTRICTED, state)
        assertEquals(EnforcementAction.BLOCK_SCREEN, resolveEnforcementAction(state, config.enforcement))
    }
}
