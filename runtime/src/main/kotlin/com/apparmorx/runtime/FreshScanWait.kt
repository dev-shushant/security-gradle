package com.apparmorx.runtime

internal enum class FreshScanState { WAIT, FRESH, TIMED_OUT }

/** Wait through the existing 30s scan throttle plus a bounded scan allowance; cached evidence is not a retry. */
internal fun freshScanState(baseline: Long, completed: Long, elapsedMillis: Long): FreshScanState = when {
    baseline < 0 || completed < baseline || elapsedMillis < 0 || elapsedMillis >= 40_000 -> FreshScanState.TIMED_OUT
    completed > baseline -> FreshScanState.FRESH
    else -> FreshScanState.WAIT
}
