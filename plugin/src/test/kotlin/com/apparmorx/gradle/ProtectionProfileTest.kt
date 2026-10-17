package com.apparmorx.gradle

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ProtectionProfileTest {
    @Test fun standardReleaseEnforcesConfirmedThreatsAndEnablesFirewall() {
        val s = ProtectionProfile.STANDARD.resolve(debuggable = false)
        assertEquals("BLOCK_SCREEN", s.restrictedAction)
        assertTrue(s.firewallClipboard && s.firewallIdentifiers && s.firewallLocation && s.firewallNetworkSecurity)
        assertTrue(s.filterTouches)
        // Weak/unavailable evidence must never escalate by default.
        assertFalse(s.enforceIndeterminate)
    }

    @Test fun hardenedAddsFailClosedStartupAndScreenProtection() {
        val s = ProtectionProfile.HARDENED.resolve(debuggable = false)
        assertEquals("BLOCK_SCREEN", s.restrictedAction)
        assertTrue(s.failClosedOnStartup)
        assertTrue(s.secureScreen)
        assertFalse("indeterminate evidence is never enforced by a profile", s.enforceIndeterminate)
    }

    @Test fun antiPtraceHardeningIsNeverAProfileDefaultEvenUnderHardened() {
        // It forks a watchdog process -- a distinct risk category from everything else a profile
        // turns on -- so it must always require an explicit opt-in, never ride in on HARDENED.
        for (profile in ProtectionProfile.entries) {
            assertFalse("$profile must not default antiPtraceHardening to true", profile.resolve(debuggable = false).antiPtraceHardening)
        }
    }

    @Test fun killOnConfirmedHookingIsNeverAProfileDefaultAndNeverSurvivesDebuggable() {
        for (profile in ProtectionProfile.entries) {
            assertFalse("$profile must not default killOnConfirmedHooking to true", profile.resolve(debuggable = false).killOnConfirmedHooking)
            assertFalse("killOnConfirmedHooking must never apply to a debuggable build", profile.resolve(debuggable = true).killOnConfirmedHooking)
        }
    }

    @Test fun developmentIsObserveOnlyWithNothingChangedInHostBehavior() {
        val s = ProtectionProfile.DEVELOPMENT.resolve(debuggable = false)
        assertEquals("OBSERVE", s.restrictedAction)
        assertFalse(s.firewallClipboard || s.firewallIdentifiers || s.firewallLocation || s.firewallNetworkSecurity)
        assertFalse(s.secureScreen || s.failClosedOnStartup || s.filterTouches)
    }

    @Test fun debuggableVariantsNeverBlockTheDeveloperButKeepPassiveProtections() {
        for (profile in ProtectionProfile.entries) {
            val s = profile.resolve(debuggable = true)
            assertEquals("OBSERVE", s.restrictedAction)
            assertFalse("a debugger is always attached to a debuggable build", s.failClosedOnStartup)
        }
        assertTrue(ProtectionProfile.STANDARD.resolve(debuggable = true).firewallClipboard)
    }

    @Test fun parsesCaseInsensitivelyAndRejectsUnknownNames() {
        assertEquals(ProtectionProfile.HARDENED, ProtectionProfile.parse(" hardened "))
        val error = runCatching { ProtectionProfile.parse("PARANOID") }.exceptionOrNull()
        assertTrue(error!!.message!!.contains("security.profile must be one of"))
        assertTrue(error.message!!.contains("PARANOID"))
    }

    @Test fun weakeningIsDetectedForActionsAndToggles() {
        assertTrue(ProtectionProfile.isWeaker("restrictedAction", "OBSERVE", than = "BLOCK_SCREEN"))
        assertFalse(ProtectionProfile.isWeaker("restrictedAction", "TERMINATE", than = "BLOCK_SCREEN"))
        assertTrue(ProtectionProfile.isWeaker("secureScreen", "false", than = "true"))
        assertFalse(ProtectionProfile.isWeaker("secureScreen", "true", than = "false"))
    }
}
