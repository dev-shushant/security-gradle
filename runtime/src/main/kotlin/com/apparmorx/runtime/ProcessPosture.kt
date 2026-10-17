package com.apparmorx.runtime

/** Local diagnostics only. Neither field authorizes another process or refreshes a scan. */
internal data class ProcessPosture(val evidenceState: ProtectionState, val lastObservedState: ProtectionState)

internal fun processPosture(snapshot: SecuritySnapshot, lastObserved: ProtectionState, nowMillis: Long): ProcessPosture =
    ProcessPosture(decideProtection(snapshot, nowMillis, REQUIRED_EVIDENCE), lastObserved)
