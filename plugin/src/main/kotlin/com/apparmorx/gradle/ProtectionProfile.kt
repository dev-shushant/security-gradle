package com.apparmorx.gradle

/** Concrete, fully-resolved protection settings for one build variant. */
data class ProfileSettings(
    val restrictedAction: String,
    val enforceIndeterminate: Boolean,
    val failClosedOnStartup: Boolean,
    val secureScreen: Boolean,
    val filterTouches: Boolean,
    val firewallClipboard: Boolean,
    val firewallIdentifiers: Boolean,
    val firewallLocation: Boolean,
    val firewallNetworkSecurity: Boolean,
    val antiPtraceHardening: Boolean,
    val killOnConfirmedHooking: Boolean,
) {
    /** Stable key order; keys match the `security { }` DSL property names. */
    fun asMap(): Map<String, String> = linkedMapOf(
        "restrictedAction" to restrictedAction,
        "enforceIndeterminate" to enforceIndeterminate.toString(),
        "failClosedOnStartup" to failClosedOnStartup.toString(),
        "secureScreen" to secureScreen.toString(),
        "filterTouches" to filterTouches.toString(),
        "firewallClipboard" to firewallClipboard.toString(),
        "firewallIdentifiers" to firewallIdentifiers.toString(),
        "firewallLocation" to firewallLocation.toString(),
        "firewallNetworkSecurity" to firewallNetworkSecurity.toString(),
        "antiPtraceHardening" to antiPtraceHardening.toString(),
        "killOnConfirmedHooking" to killOnConfirmedHooking.toString(),
    )
}

/**
 * Named protection levels so a bare `plugins { id("com.apparmorx.security") }` actually protects users.
 * Explicit `security { }` values always win over the profile, and the generated report flags any
 * explicit value that is weaker than the profile default.
 *
 * Invariants (see AGENTS.md): no profile enforces on merely unavailable evidence, none terminates the
 * process, and debuggable variants never enforce a response (their own debugger would trigger it).
 */
enum class ProtectionProfile {
    /** Observe and record only; changes no host behavior. */
    DEVELOPMENT,

    /** Default. Blocks the app on confirmed threats and neutralizes SDK data scraping. */
    STANDARD,

    /** STANDARD plus fail-closed startup gate and screen-capture protection. */
    HARDENED;

    fun resolve(debuggable: Boolean): ProfileSettings {
        // antiPtraceHardening and killOnConfirmedHooking are false in every profile, including
        // HARDENED: unlike the other settings here, one forks a watchdog process and the other hard-
        // kills the process -- materially different, distinct risk categories (native crash-reporting
        // interaction; AGENTS.md's narrow exception to no-automatic-process-termination) that a profile
        // default should not silently opt an app into. Both are explicit-opt-in only; see Evidence.kt.
        val base = when (this) {
            DEVELOPMENT -> ProfileSettings(
                restrictedAction = "OBSERVE", enforceIndeterminate = false, failClosedOnStartup = false,
                secureScreen = false, filterTouches = false, firewallClipboard = false,
                firewallIdentifiers = false, firewallLocation = false, firewallNetworkSecurity = false,
                antiPtraceHardening = false, killOnConfirmedHooking = false,
            )
            STANDARD -> ProfileSettings(
                restrictedAction = "BLOCK_SCREEN", enforceIndeterminate = false, failClosedOnStartup = false,
                secureScreen = false, filterTouches = true, firewallClipboard = true,
                firewallIdentifiers = true, firewallLocation = true, firewallNetworkSecurity = true,
                antiPtraceHardening = false, killOnConfirmedHooking = false,
            )
            HARDENED -> ProfileSettings(
                restrictedAction = "BLOCK_SCREEN", enforceIndeterminate = false, failClosedOnStartup = true,
                secureScreen = true, filterTouches = true, firewallClipboard = true,
                firewallIdentifiers = true, firewallLocation = true, firewallNetworkSecurity = true,
                antiPtraceHardening = false, killOnConfirmedHooking = false,
            )
        }
        // debuggable always forces anti-ptrace hardening and the hooking-kill off too: both would
        // fight the developer's own debugger/profiler attach exactly like they fight an attacker's.
        return if (debuggable) {
            base.copy(restrictedAction = "OBSERVE", failClosedOnStartup = false, antiPtraceHardening = false, killOnConfirmedHooking = false)
        } else base
    }

    companion object {
        fun parse(raw: String): ProtectionProfile =
            entries.firstOrNull { it.name == raw.trim().uppercase() }
                ?: throw IllegalArgumentException(
                    "security.profile must be one of ${entries.map { it.name }}, was '$raw'",
                )

        private val ACTION_STRENGTH = listOf("OBSERVE", "WARN", "MIRAGE", "BLOCK_SCREEN", "TERMINATE")

        /** True when [value] gives less protection than [than] for the named setting. */
        fun isWeaker(key: String, value: String, than: String): Boolean = when (key) {
            "restrictedAction" -> ACTION_STRENGTH.indexOf(value) < ACTION_STRENGTH.indexOf(than)
            else -> value == "false" && than == "true"
        }
    }
}
