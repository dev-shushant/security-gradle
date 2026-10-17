package com.apparmorx.runtime

import java.util.Properties
import org.junit.Assert.*
import org.junit.Test

class EnforcementPolicyParsingTest {
    private fun config(action: String = "BLOCK_SCREEN", unavailable: String = "true") = Properties().apply {
        setProperty("restrictedAction", action)
        setProperty("enforceIndeterminate", unavailable)
    }
    @Test fun preservesExplicitPolicy() {
        assertEquals(EnforcementPolicy(EnforcementAction.BLOCK_SCREEN, true), parseEnforcementPolicy(config()))
    }
    @Test fun parsesMirageAndEnterpriseFlags() {
        val props = config(action = "MIRAGE").apply {
            setProperty("failClosedOnStartup", "true")
            setProperty("secureScreen", "true")
            setProperty("filterTouches", "true")
            setProperty("telemetryUrl", "https://secops.example.com/events")
            setProperty("firewallClipboard", "true")
            setProperty("firewallIdentifiers", "true")
            setProperty("firewallLocation", "true")
            setProperty("firewallNetworkSecurity", "true")
            setProperty("antiPtraceHardening", "true")
            setProperty("killOnConfirmedHooking", "true")
        }
        val policy = parseEnforcementPolicy(props)
        assertEquals(EnforcementAction.MIRAGE, policy.restrictedAction)
        assertTrue(policy.enforceIndeterminate)
        assertTrue(policy.failClosedOnStartup)
        assertTrue(policy.secureScreen)
        assertTrue(policy.filterTouches)
        assertEquals("https://secops.example.com/events", policy.telemetryUrl)
        assertTrue(policy.firewallClipboard)
        assertTrue(policy.firewallIdentifiers)
        assertTrue(policy.firewallLocation)
        assertTrue(policy.firewallNetworkSecurity)
        assertTrue(policy.antiPtraceHardening)
        assertTrue(policy.killOnConfirmedHooking)
    }
    @Test fun antiPtraceHardeningDefaultsToFalseWhenAbsent() {
        // Opt-in only: a policy that never mentions it must behave exactly as before this flag existed.
        assertFalse(parseEnforcementPolicy(config()).antiPtraceHardening)
    }
    @Test fun killOnConfirmedHookingDefaultsToFalseWhenAbsent() {
        assertFalse(parseEnforcementPolicy(config()).killOnConfirmedHooking)
    }
    @Test fun rejectsUnknownActionRatherThanDowngrading() {
        assertThrows(IllegalArgumentException::class.java) { parseEnforcementPolicy(config("BLOCK_SCREN")) }
    }
    @Test fun rejectsMalformedBooleanRatherThanDisabling() {
        for (value in listOf("TRUE", "yes", "", " true")) {
            assertThrows(IllegalArgumentException::class.java) { parseEnforcementPolicy(config(unavailable = value)) }
        }
    }
    @Test fun requiresBothGeneratedFields() {
        for (key in listOf("restrictedAction", "enforceIndeterminate")) {
            assertThrows(IllegalArgumentException::class.java) { parseEnforcementPolicy(config().apply { remove(key) }) }
        }
    }
    @Test fun rejectsMalformedOptionalSecurityFlagsRatherThanSilentlyDisablingProtection() {
        val flags = listOf("failClosedOnStartup", "secureScreen", "filterTouches", "firewallClipboard",
            "firewallIdentifiers", "firewallLocation", "firewallNetworkSecurity", "antiPtraceHardening",
            "killOnConfirmedHooking")
        for (flag in flags) {
            for (value in listOf("TRUE", "yes", "", " true", "false ")) {
                assertThrows("$flag=$value", IllegalArgumentException::class.java) {
                    parseEnforcementPolicy(config().apply { setProperty(flag, value) })
                }
            }
        }
    }
    @Test fun optionalSecurityFlagsStillAllowExplicitFalseAndAbsentLegacyDefaults() {
        val flags = listOf("failClosedOnStartup", "secureScreen", "filterTouches", "firewallClipboard",
            "firewallIdentifiers", "firewallLocation", "firewallNetworkSecurity", "antiPtraceHardening",
            "killOnConfirmedHooking")
        val explicit = config().apply { flags.forEach { setProperty(it, "false") } }
        assertEquals(parseEnforcementPolicy(config()), parseEnforcementPolicy(explicit))
    }

}
