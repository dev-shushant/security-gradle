package com.apparmorx.runtime

import java.util.Properties
import org.junit.Assert.*
import org.junit.Test

class ScanConfigurationTest {
    private fun properties(action: String = "BLOCK_SCREEN", unknown: Boolean = true) = Properties().apply {
        setProperty("restrictedAction", action)
        setProperty("enforceIndeterminate", unknown.toString())
    }
    @Test fun malformedPinsCannotEraseAnExplicitBlockingResponse() {
        val result = parseScanConfiguration(properties().apply { setProperty("payloadDigests", "classes.dex:bad") })
        assertNull(result.payloadDigests)
        assertEquals(EnforcementAction.BLOCK_SCREEN, result.enforcement.restrictedAction)
        val snapshot = SecuritySnapshot(100, 0, listOf(Evidence("policy", Status.UNAVAILABLE)), result.enforcement)
        val state = decideProtection(snapshot, 101, setOf("policy"))
        assertEquals(ProtectionState.INDETERMINATE, state)
        assertEquals(EnforcementAction.BLOCK_SCREEN, resolveEnforcementAction(state, result.enforcement))
    }
    @Test fun UnknownHandlingStillBelongsToTheOwner() {
        val result = parseScanConfiguration(properties(unknown = false).apply { setProperty("payloadDigests", "bad") })
        assertNull(result.payloadDigests)
        assertEquals(EnforcementAction.OBSERVE, resolveEnforcementAction(ProtectionState.INDETERMINATE, result.enforcement))
        assertEquals(EnforcementAction.BLOCK_SCREEN, resolveEnforcementAction(ProtectionState.RESTRICTED, result.enforcement))
    }
    @Test fun absentPinsAndValidPinsRemainDistinctFromMalformedPins() {
        assertEquals(emptyMap<String,String>(), parseScanConfiguration(properties()).payloadDigests)
        val digest = "a".repeat(64)
        assertEquals(mapOf("classes.dex" to digest), parseScanConfiguration(properties().apply {
            setProperty("payloadDigests", "classes.dex:$digest")
        }).payloadDigests)
    }
    @Test fun invalidResponseIsStillRejectedRatherThanBlessedAsValid() {
        assertThrows(IllegalArgumentException::class.java) { parseScanConfiguration(properties("TYPO")) }
    }
}
