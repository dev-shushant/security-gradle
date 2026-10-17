package com.apparmorx.runtime

/** Guard state. READY means configured checks completed, never proof against all attacks. */
enum class ProtectionState { CHECKING, READY, RESTRICTED, INDETERMINATE }

/**
 * Findings about the app owner's own configuration rather than about an attacker or the device. They are
 * still reported (UI, telemetry, SARIF) but never move the state to RESTRICTED. Keep this set minimal and
 * only add checks that no attacker can influence.
 */
internal val ADVISORY_CHECKS = setOf("network-cleartext-permitted")

internal fun decideProtection(snapshot: SecuritySnapshot, nowMillis: Long, required: Set<String>): ProtectionState {
    if (snapshot.checkedAtMillis == 0L) return ProtectionState.CHECKING
    if (snapshot.evidence.any { it.status == Status.DETECTED && it.check !in ADVISORY_CHECKS }) return ProtectionState.RESTRICTED
    if (nowMillis < snapshot.checkedAtMillis || nowMillis - snapshot.checkedAtMillis > 120000L) return ProtectionState.INDETERMINATE
    if (required.any { check -> snapshot.evidence.none { it.check == check && it.status == Status.CLEAR } }) return ProtectionState.INDETERMINATE
    return ProtectionState.READY
}
