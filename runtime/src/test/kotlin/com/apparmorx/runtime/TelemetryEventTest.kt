package com.apparmorx.runtime

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Properties

class TelemetryEventTest {
    private val env = TelemetryEvents.Environment(
        applicationId = "com.example.shop", appVersionName = "4.2.1", appVersionCode = 421L, debuggable = false,
        sdkInt = 35, abi = "arm64-v8a", manufacturer = "Google", model = "Pixel 7 Pro",
        securityPatch = "2026-09-05", installer = "com.android.vending",
    )
    private val snapshot = SecuritySnapshot(
        checkedAtMillis = 1_000L, policySequence = 7L,
        evidence = listOf(
            Evidence("policy", Status.CLEAR),
            Evidence("native-hook-library", Status.DETECTED),
            Evidence("native-selinux", Status.UNAVAILABLE),
            Evidence("network-cleartext-permitted", Status.DETECTED),
        ),
        enforcement = EnforcementPolicy(EnforcementAction.BLOCK_SCREEN, enforceIndeterminate = false),
    )

    private fun build(detail: TelemetryDetail) = TelemetryEvents.build("evt-1", 1_700_000_000_000L, snapshot, ProtectionState.RESTRICTED, env, detail)

    @Test fun standardCarriesEverythingNeededToTriageAnIncident() {
        val json = build(TelemetryDetail.STANDARD).toJson()
        for (expected in listOf(
            "\"schemaVersion\":2", "\"eventType\":\"incident\"", "\"eventId\":\"evt-1\"", "\"applicationId\":\"com.example.shop\"",
            "\"appVersionName\":\"4.2.1\"", "\"appVersionCode\":421", "\"debuggableBuild\":false",
            "\"protectionState\":\"RESTRICTED\"", "\"enforcementAction\":\"BLOCK_SCREEN\"",
            "\"detectedChecks\":[\"native-hook-library\"]", "\"unavailableChecks\":[\"native-selinux\"]",
            "\"osVersion\":35", "\"abi\":\"arm64-v8a\"", "\"policySequence\":7",
        )) assertTrue("missing $expected in $json", json.contains(expected))
    }

    @Test fun advisoryFindingsAreReportedSeparatelyAndNeverAsThreats() {
        val json = build(TelemetryDetail.STANDARD).toJson()
        assertTrue(json.contains("\"advisoryFindings\":[\"network-cleartext-permitted\"]"))
        assertFalse(json.contains("\"detectedChecks\":[\"native-hook-library\",\"network-cleartext-permitted\"]"))
    }

    @Test fun minimalStaysPrivacyMinimalAndOmitsAppAndDeviceDetail() {
        val json = build(TelemetryDetail.MINIMAL).toJson()
        assertTrue(json.contains("\"detectedChecks\":[\"native-hook-library\"]"))
        for (absent in listOf("appVersionName", "protectionState", "manufacturer", "model", "securityPatch", "installer", "checks")) {
            assertFalse("MINIMAL must not contain $absent: $json", json.contains("\"$absent\""))
        }
    }

    @Test fun deviceDetailIsOnlyEverSentAtExtended() {
        assertFalse(build(TelemetryDetail.STANDARD).toJson().contains("Pixel 7 Pro"))
        val extended = build(TelemetryDetail.EXTENDED).toJson()
        for (expected in listOf("\"manufacturer\":\"Google\"", "\"model\":\"Pixel 7 Pro\"", "\"securityPatch\":\"2026-09-05\"", "\"installer\":\"com.android.vending\"", "\"checks\":{")) {
            assertTrue("missing $expected in $extended", extended.contains(expected))
        }
    }

    @Test fun neverContainsIdentifiersOrFreeText() {
        val json = build(TelemetryDetail.EXTENDED).toJson().lowercase()
        for (banned in listOf("android_id", "imei", "serial", "advertising", "ssaid", "email", "location")) assertFalse(banned, json.contains(banned))
    }

    @Test fun untrustedStringsAreJsonEscaped() {
        val hostile = env.copy(model = "Pixel \"7\"\n\\Pro</script>")
        val json = TelemetryEvents.build("e", 0L, snapshot, ProtectionState.RESTRICTED, hostile, TelemetryDetail.EXTENDED).toJson()
        assertTrue(json, json.contains("\"model\":\"Pixel \\\"7\\\"\\n\\\\Pro</script>\""))
        assertFalse(json.contains('\n'))
    }

    @Test fun onlyRealThreatsTriggerAnIncident() {
        assertTrue(TelemetryEvents.incidentChecks(snapshot).isNotEmpty())
        val advisoryOnly = snapshot.copy(evidence = listOf(Evidence("network-cleartext-permitted", Status.DETECTED), Evidence("policy", Status.CLEAR)))
        assertTrue(TelemetryEvents.incidentChecks(advisoryOnly).isEmpty())
    }

    private fun props(vararg pairs: Pair<String, String>) = Properties().apply {
        setProperty("restrictedAction", "OBSERVE"); setProperty("enforceIndeterminate", "false")
        pairs.forEach { setProperty(it.first, it.second) }
    }

    @Test fun policyDefaultsToStandardDetailWithNoHeaders() {
        val p = parseEnforcementPolicy(props())
        assertEquals(TelemetryDetail.STANDARD, p.telemetryDetail)
        assertTrue(p.telemetryHeaders.isEmpty())
    }

    @Test fun policyParsesDetailAndCustomHeaders() {
        val p = parseEnforcementPolicy(props("telemetryDetail" to "EXTENDED", "telemetryHeader.X-Api-Key" to "abc123", "telemetryHeader.X-Tenant" to "acme"))
        assertEquals(TelemetryDetail.EXTENDED, p.telemetryDetail)
        assertEquals(mapOf("X-Api-Key" to "abc123", "X-Tenant" to "acme"), p.telemetryHeaders)
    }

    @Test fun invalidDetailOrReservedHeadersInvalidateThePolicy() {
        assertThrows(IllegalArgumentException::class.java) { parseEnforcementPolicy(props("telemetryDetail" to "EVERYTHING")) }
        for (reserved in listOf("Host", "Content-Type", "Content-Length", "X-AppArmorX-Signature", "x-apparmorx-timestamp")) {
            assertThrows(reserved, IllegalArgumentException::class.java) { parseEnforcementPolicy(props("telemetryHeader.$reserved" to "v")) }
        }
        assertThrows(IllegalArgumentException::class.java) { parseEnforcementPolicy(props("telemetryHeader.Bad Name" to "v")) }
    }
}
