package com.apparmorx.runtime

import org.junit.Assert.assertEquals
import org.junit.Test

class ProtectionDecisionTest {
    private val required = setOf("policy", "signing-certificate", "native-engine")
    private val clean = required.map { Evidence(it, Status.CLEAR) }
    @Test fun pendingIsNotReady() { assertEquals(ProtectionState.CHECKING, decideProtection(SecuritySnapshot(0, 0, emptyList()), 100, required)) }
    @Test fun missingMandatoryEvidenceIsIndeterminate() { assertEquals(ProtectionState.INDETERMINATE, decideProtection(SecuritySnapshot(1, 0, emptyList()), 100, required)) }
    @Test fun unavailableMandatoryEvidenceIsIndeterminate() { assertEquals(ProtectionState.INDETERMINATE, decideProtection(SecuritySnapshot(1, 0, clean.map { if (it.check == "native-engine") it.copy(status = Status.UNAVAILABLE) else it }), 100, required)) }
    @Test fun detectedEvidenceRestricts() { assertEquals(ProtectionState.RESTRICTED, decideProtection(SecuritySnapshot(1, 0, clean + Evidence("native-tracer", Status.DETECTED)), 100, required)) }
    @Test fun freshCompleteEvidenceIsReady() { assertEquals(ProtectionState.READY, decideProtection(SecuritySnapshot(1, 0, clean), 100, required)) }
    @Test fun staleEvidenceIsNotReady() { assertEquals(ProtectionState.INDETERMINATE, decideProtection(SecuritySnapshot(1, 0, clean), 120002, required)) }
    @Test fun clockReversalIsNotReady() { assertEquals(ProtectionState.INDETERMINATE, decideProtection(SecuritySnapshot(1000, 0, clean), 1, required)) }

    // Configuration posture describes the app owner's own settings, not an attack. Enforcing on it would
    // lock out every legitimate user of an app that deliberately allows HTTP, so it is reported only.
    @Test fun advisoryPostureFindingsNeverRestrict() {
        val snapshot = SecuritySnapshot(1, 0, clean + Evidence("network-cleartext-permitted", Status.DETECTED))
        assertEquals(ProtectionState.READY, decideProtection(snapshot, 100, required))
    }
    @Test fun advisoryDoesNotMaskARealThreat() {
        val snapshot = SecuritySnapshot(1, 0, clean + Evidence("network-cleartext-permitted", Status.DETECTED) + Evidence("native-hook-library", Status.DETECTED))
        assertEquals(ProtectionState.RESTRICTED, decideProtection(snapshot, 100, required))
    }
    @Test fun advisoryChecksAreExactlyTheConfigurationPostureSet() {
        assertEquals(setOf("network-cleartext-permitted"), ADVISORY_CHECKS)
    }
}
