package com.apparmorx.runtime

import org.junit.Assert.assertEquals
import org.junit.Test

class FreshScanWaitTest {
    @Test fun cachedResultCannotCompleteAnExplicitRetry() {
        assertEquals(FreshScanState.WAIT, freshScanState(7, 7, 0))
        assertEquals(FreshScanState.WAIT, freshScanState(7, 7, 30_000))
        assertEquals(FreshScanState.FRESH, freshScanState(7, 8, 30_100))
    }
    @Test fun missingCompletionHasABoundedWait() {
        assertEquals(FreshScanState.TIMED_OUT, freshScanState(7, 7, 40_000))
        assertEquals(FreshScanState.TIMED_OUT, freshScanState(7, 7, 90_000))
    }
    @Test fun invalidOrResetClocksNeverCountAsFreshEvidence() {
        assertEquals(FreshScanState.TIMED_OUT, freshScanState(7, 6, 100))
        assertEquals(FreshScanState.TIMED_OUT, freshScanState(7, 8, -1))
        assertEquals(FreshScanState.TIMED_OUT, freshScanState(-1, 0, 100))
    }
}
