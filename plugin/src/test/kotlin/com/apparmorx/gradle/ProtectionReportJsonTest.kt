package com.apparmorx.gradle

import groovy.json.JsonSlurper
import org.junit.Assert.assertEquals
import org.junit.Test

class ProtectionReportJsonTest {
    @Test fun manifestFindingsAndArchiveNamesRoundTripWithoutBreakingJson() {
        val finding = "WARNING: android:usesCleartextTraffic=\"true\"\npath\\name\t\u0001\b\u000c"
        val report = ProtectionReport("app-\"release\".apk", false, listOf("arm64-v8a"),
            listOf("bad\"entry"), mapOf("lib/quoted\"path.so" to "a".repeat(64)), 7, listOf(finding))
        val parsed = JsonSlurper().parseText(report.toJson()) as Map<*, *>
        assertEquals(report.archiveName, parsed["archiveName"])
        assertEquals(report.manifestFindings, parsed["manifestFindings"])
        assertEquals(report.failures, parsed["failures"])
        assertEquals(report.entryDigests, parsed["entryDigests"])
    }

    @Test fun everyAsciiControlCharacterRemainsData() {
        val input = (0..31).map { it.toChar() }.joinToString("") + "quote\"slash\\"
        val report = ProtectionReport(input, true, listOf(input), emptyList(), emptyMap(), 0)
        val parsed = JsonSlurper().parseText(report.toJson()) as Map<*, *>
        assertEquals(input, parsed["archiveName"])
        assertEquals(listOf(input), parsed["abis"])
    }
}
