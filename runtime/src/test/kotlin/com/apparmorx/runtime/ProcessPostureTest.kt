package com.apparmorx.runtime

import org.junit.Assert.assertEquals
import org.junit.Test

class ProcessPostureTest {
    private val complete = REQUIRED_EVIDENCE.map { Evidence(it, Status.CLEAR) }
    @Test fun previousReadyDoesNotHideNewRestrictedEvidence() {
        val snapshot = SecuritySnapshot(100, 7, complete + Evidence("fixture-threat", Status.DETECTED))
        val report = processPosture(snapshot, ProtectionState.READY, 101)
        assertEquals(ProtectionState.RESTRICTED, report.evidenceState)
        assertEquals(ProtectionState.READY, report.lastObservedState)
    }
    @Test fun unavailableEvidenceNeverInheritsPreviousReady() {
        val snapshot = SecuritySnapshot(100, 7, complete.filterNot { it.check == "native-engine" })
        assertEquals(ProtectionState.INDETERMINATE, processPosture(snapshot, ProtectionState.READY, 101).evidenceState)
    }
    @Test fun pendingAndStaleEvidenceRemainDistinctFromLastGuard() {
        assertEquals(ProtectionState.CHECKING,
            processPosture(SecuritySnapshot(0, 0, emptyList()), ProtectionState.RESTRICTED, 101).evidenceState)
        assertEquals(ProtectionState.INDETERMINATE,
            processPosture(SecuritySnapshot(100, 7, complete), ProtectionState.READY, 120101).evidenceState)
    }
    @Test fun freshCompleteEvidenceDoesNotRewriteLastGuardHistory() {
        val report = processPosture(SecuritySnapshot(100, 7, complete), ProtectionState.CHECKING, 101)
        assertEquals(ProtectionState.READY, report.evidenceState)
        assertEquals(ProtectionState.CHECKING, report.lastObservedState)
    }
}
