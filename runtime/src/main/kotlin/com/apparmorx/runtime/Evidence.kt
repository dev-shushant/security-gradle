package com.apparmorx.runtime

import java.util.concurrent.CancellationException

/** CLEAR means this probe found no indicator; it does not prove device trust. */
enum class Status { CLEAR, DETECTED, UNAVAILABLE }

/** Privacy-preserving check result. Contains stable check IDs, never process contents or device identifiers. */
data class Evidence(val check: String, val status: Status)

/** Outcome of checking one filesystem path, keeping "genuinely absent" distinct from "could not tell". */
internal enum class PathCheck { Present, Absent, Denied }

/**
 * Root-binary path check that never silently turns "permission denied" into "absent". A path mode
 * like su's typical 4750 (root:shell, no "other" bits) means an app's own SELinux/POSIX context gets
 * EACCES on stat(), not ENOENT -- and plain `File.exists()` cannot tell those apart (both return
 * false). If every path was genuinely absent, report CLEAR; if any path is confirmed present, report
 * DETECTED; if none is confirmed present but at least one could not be determined, report UNAVAILABLE
 * rather than a false CLEAR.
 */
internal fun rootPathStatus(paths: List<String>, check: (String) -> PathCheck): Status {
    var sawDenied = false
    for (path in paths) {
        when (check(path)) {
            PathCheck.Present -> return Status.DETECTED
            PathCheck.Denied -> sawDenied = true
            PathCheck.Absent -> {}
        }
    }
    return if (sawDenied) Status.UNAVAILABLE else Status.CLEAR
}

/**
 * What a guarded lifecycle call does when [ProtectionState] is not simply READY. Ordered from least
 * to most disruptive; hosts opt into anything past OBSERVE explicitly through the `security {}` DSL.
 */
enum class EnforcementAction { OBSERVE, WARN, BLOCK_SCREEN, TERMINATE, MIRAGE }

/**
 * Host-configured response policy, embedded in the signed/generated build policy and read at scan
 * time — never hardcoded, never silently escalated. [DEFAULT] never does anything beyond recording
 * evidence, so a build that configures nothing behaves exactly like the observation-only slice.
 */
data class EnforcementPolicy(
    val restrictedAction: EnforcementAction,
    val enforceIndeterminate: Boolean,
    val failClosedOnStartup: Boolean = false,
    val secureScreen: Boolean = false,
    val filterTouches: Boolean = false,
    val telemetryUrl: String = "",
    val firewallClipboard: Boolean = false,
    val firewallIdentifiers: Boolean = false,
    val firewallLocation: Boolean = false,
    val firewallNetworkSecurity: Boolean = false,
    val telemetryHmacKey: String = "",
    val telemetryDetail: TelemetryDetail = TelemetryDetail.STANDARD,
    val telemetryHeaders: Map<String, String> = emptyMap(),
    /**
     * Best-effort native self-protection against ptrace-based attach to an already-running process
     * (see `NativeEngine.hardenAgainstPtraceAttach` / `harden_ptrace` in engine.cpp for the exact
     * mechanism and its honest limits). Opt-in and never a profile default, including HARDENED: the
     * mechanism forks a watchdog process at startup, which carries its own small, distinct risk
     * (interaction with native crash reporting, fork() in a multi-threaded process) that is not
     * automatically worth taking for every app the way e.g. the dependency firewall is.
     */
    val antiPtraceHardening: Boolean = false,
    /**
     * Opt-in, narrowly-scoped exception to this project's default "no automatic process termination"
     * rule -- see AGENTS.md for the exact carve-out. Never a profile default (including HARDENED),
     * forced false on debuggable builds at both build time ([com.apparmorx.gradle.ProtectionProfile])
     * and runtime (checked again where this is consumed). When true, [shouldKillOnConfirmedHooking]
     * decides -- never anything else -- whether to hard-kill: only on confirmed (`DETECTED`, never
     * `UNAVAILABLE`) hooking/injection-specific evidence ([HOOKING_CHECKS]), never for any other
     * RESTRICTED cause (root, signer mismatch, etc.). Documented limit, state it everywhere this is
     * described: detection runs periodically/on lifecycle events, not continuously, so this cannot
     * prevent the single action already in flight when detection fires -- only further activity in
     * the same process. See docs/STATUS.md for the on-device test that established this limit.
     */
    val killOnConfirmedHooking: Boolean = false,
) {
    companion object {
        val DEFAULT = EnforcementPolicy(
            restrictedAction = EnforcementAction.OBSERVE,
            enforceIndeterminate = false,
            failClosedOnStartup = false,
            secureScreen = false,
            filterTouches = false,
            telemetryUrl = "",
            firewallClipboard = false,
            firewallIdentifiers = false,
            firewallLocation = false,
            firewallNetworkSecurity = false,
            telemetryHmacKey = "",
            antiPtraceHardening = false,
            killOnConfirmedHooking = false,
        )
    }
}

/**
 * The hooking/code-injection-specific subset of native evidence checks (see RuntimeScanner/NativeEngine).
 * Deliberately excludes root-path, signer-mismatch and every other RESTRICTED cause: [killOnConfirmedHooking]
 * must only ever react to confirmed hooking, never anything else.
 */
internal val HOOKING_CHECKS = setOf(
    "native-frida-port",
    "native-tool-thread",
    "hook-classes",
    "hook-library",
    "native-hook-trampoline",
    "native-stealth-injection",
)

/**
 * Pure decision for the `killOnConfirmedHooking` policy (see its kdoc and AGENTS.md for the full
 * carve-out this implements). The actual `Process.killProcess()` call lives in [EnforcementResponse],
 * the only part of the enforcement path that touches Android process APIs -- this function only
 * decides whether that call should happen, so it can be fully unit tested (see HookKillDecisionTest).
 */
internal fun shouldKillOnConfirmedHooking(
    evidence: List<Evidence>,
    policy: EnforcementPolicy,
    debuggable: Boolean,
): Boolean {
    if (!policy.killOnConfirmedHooking || debuggable) return false
    return evidence.any { it.check in HOOKING_CHECKS && it.status == Status.DETECTED }
}

/**
 * The actual response decision, kept pure and independent of any Android API so it stays fully unit
 * testable. RESTRICTED (a confirmed [Status.DETECTED] signal) applies the host's configured action.
 * INDETERMINATE (missing/stale/unavailable required evidence — a much weaker signal: OEM
 * restrictions and cold-start timing produce this routinely) only escalates when the host explicitly
 * opted in via [EnforcementPolicy.enforceIndeterminate]; otherwise it is always OBSERVE, regardless of
 * how aggressively the host configured [EnforcementPolicy.restrictedAction].
 * CHECKING escalates to restrictedAction only when [EnforcementPolicy.failClosedOnStartup] is explicitly opted in;
 * otherwise it is OBSERVE. READY is always OBSERVE.
 */
internal fun resolveEnforcementAction(state: ProtectionState, policy: EnforcementPolicy, debuggable: Boolean = false, startupGateApplies: Boolean = true): EnforcementAction = when {
    debuggable -> EnforcementAction.OBSERVE
    state == ProtectionState.RESTRICTED -> policy.restrictedAction
    state == ProtectionState.INDETERMINATE && policy.enforceIndeterminate -> policy.restrictedAction
    state == ProtectionState.CHECKING && startupGateApplies && policy.failClosedOnStartup -> policy.restrictedAction
    else -> EnforcementAction.OBSERVE
}

/** Point-in-time evidence. Empty evidence means initialization has not completed, never an allow verdict. */
data class SecuritySnapshot(
    val checkedAtMillis: Long,
    val policySequence: Long,
    val evidence: List<Evidence>,
    val enforcement: EnforcementPolicy = EnforcementPolicy.DEFAULT,
) {
    val secureScreen: Boolean get() = enforcement.secureScreen
    val filterTouches: Boolean get() = enforcement.filterTouches
    val telemetryUrl: String get() = enforcement.telemetryUrl
    val telemetryHmacKey: String get() = enforcement.telemetryHmacKey
}

internal fun probe(id: String, block: () -> Boolean): Evidence = try {
    Evidence(id, if (block()) Status.DETECTED else Status.CLEAR)
} catch (cancelled: CancellationException) {
    throw cancelled
} catch (_: Exception) {
    Evidence(id, Status.UNAVAILABLE)
}

internal fun matchesIndicator(line: String, markers: List<String>): Boolean =
    markers.any { line.contains(it, ignoreCase = true) }

internal fun signerStatus(actual: Set<String>, trusted: Set<String>): Status = when {
    actual.isEmpty() || trusted.isEmpty() -> Status.UNAVAILABLE
    actual.all { it in trusted } -> Status.CLEAR
    else -> Status.DETECTED
}

internal fun hasHookClass(classLoader: ClassLoader?, classNames: List<String>): Boolean {
    val loader = classLoader ?: return false
    return classNames.any { className ->
        try {
            Class.forName(className, false, loader) != null
        } catch (_: ClassNotFoundException) {
            false
        }
    }
}

internal fun isVirtualSpacePath(filesDirPath: String, packageName: String): Boolean {
    if (!filesDirPath.contains(packageName)) return true
    val suspiciousContainers = listOf(
        "com.lbe.parallel", "com.excelliance.dualsandbox", "com.lody.virtual",
        "io.va.exposed", "com.qihoo.magic"
    )
    return suspiciousContainers.any { filesDirPath.contains(it) }
}

/** Ambiguous build labels are evidence gaps, not a confirmed virtual environment. */
internal fun emulatorFingerprintStatus(
    fingerprint: String,
    model: String,
    brand: String,
    device: String,
    product: String,
    hardware: String,
): Status {
    val fp = fingerprint.lowercase()
    val modelName = model.lowercase()
    val productName = product.lowercase()
    val hardwareName = hardware.lowercase()
    val knownHardware = hardwareName in setOf("ranchu", "goldfish", "vbox86", "vbox86p")
    val knownProduct = listOf("sdk_gphone", "sdk_google", "vbox86p").any { productName.startsWith(it) }
    if (knownHardware || knownProduct) return Status.DETECTED
    val ambiguous = listOf(fingerprint, model, brand, device, product, hardware).any { it.isBlank() } ||
        fp.startsWith("unknown") || fp.startsWith("generic") ||
        (brand.lowercase().startsWith("generic") && device.lowercase().startsWith("generic")) ||
        modelName.contains("emulator") || modelName.contains("google_sdk") ||
        modelName.contains("android sdk built for") || productName.contains("emulator")
    return if (ambiguous) Status.UNAVAILABLE else Status.CLEAR
}

internal fun isEmulatorFingerprint(
    fingerprint: String, model: String, brand: String, device: String, product: String, hardware: String,
): Boolean = emulatorFingerprintStatus(fingerprint, model, brand, device, product, hardware) == Status.DETECTED

