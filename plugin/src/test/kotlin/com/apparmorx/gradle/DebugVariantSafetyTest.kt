package com.apparmorx.gradle

import org.junit.Assert.assertEquals
import org.junit.Test

class DebugVariantSafetyTest {
    @Test fun mandatorySafetyOverridesAreReportedForDebug() {
        assertEquals("OBSERVE", debugSafeSetting("restrictedAction", "TERMINATE", true))
        for (key in listOf("failClosedOnStartup", "antiPtraceHardening", "killOnConfirmedHooking")) {
            assertEquals("false", debugSafeSetting(key, "true", true))
        }
    }
    @Test fun releaseAndPassiveSettingsRemainExplicit() {
        assertEquals("BLOCK_SCREEN", debugSafeSetting("restrictedAction", "BLOCK_SCREEN", false))
        assertEquals("true", debugSafeSetting("killOnConfirmedHooking", "true", false))
        assertEquals("true", debugSafeSetting("firewallClipboard", "true", true))
    }
}
