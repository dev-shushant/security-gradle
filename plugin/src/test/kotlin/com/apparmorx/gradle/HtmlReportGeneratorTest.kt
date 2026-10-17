package com.apparmorx.gradle

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class HtmlReportGeneratorTest {
    private val base = HtmlReportGenerator.Input(
        variant = "release",
        profile = "STANDARD",
        report = ProtectionReport(
            archiveName = "app-release.apk",
            isProtected = true,
            abis = listOf("arm64-v8a", "x86_64"),
            failures = emptyList(),
            entryDigests = mapOf("classes.dex" to "ab".repeat(32)),
            timestampSeconds = 1_700_000_000L,
        ),
        settings = ProtectionProfile.STANDARD.resolve(false).asMap(),
        profileDefaults = ProtectionProfile.STANDARD.resolve(false).asMap(),
        findings = emptyList(),
    )

    @Test fun protectedBuildShowsVerdictLayersAndHonestLimits() {
        val html = HtmlReportGenerator.render(base)
        assertTrue(html.contains("PACKAGED CHECKS PASSED"))
        assertTrue(html.contains("Component inventory unavailable"))
        assertTrue(html.contains("Dependency firewall"))
        assertTrue(html.contains("arm64-v8a"))
        assertTrue(html.contains("not unbypassable") || html.contains("Not unbypassable"))
    }

    @Test fun failedCoverageIsNeverShownAsVerified() {
        val failed = base.copy(report = base.report.copy(isProtected = false, failures = listOf("missing-native-engine")))
        val html = HtmlReportGenerator.render(failed)
        assertTrue(html.contains("PACKAGED CHECKS INCOMPLETE"))
        assertTrue(html.contains("missing-native-engine"))
        assertFalse(html.contains("PACKAGED CHECKS PASSED"))
    }

    @Test fun weakenedOverridesAreHighlighted() {
        val weakened = base.settings + ("restrictedAction" to "OBSERVE")
        val html = HtmlReportGenerator.render(base.copy(settings = weakened))
        assertTrue(html.contains("WEAKENED"))
    }

    @Test fun untrustedStringsAreHtmlEscaped() {
        val evil = base.copy(
            variant = "<script>alert(1)</script>",
            findings = listOf(
                ManifestAuditor.Finding(ManifestAuditor.Finding.Level.ERROR, "release-debuggable", "<img src=x onerror=1>"),
            ),
        )
        val html = HtmlReportGenerator.render(evil)
        assertFalse(html.contains("<script>alert(1)"))
        assertFalse(html.contains("<img src=x"))
        assertTrue(html.contains("&lt;script&gt;"))
    }

    @Test fun componentDeclarationsAreEscapedAndDoNotImplyBytecodeCoverage() {
        val inventory = ComponentInventory(listOf(ManifestComponent("provider", "<script>bad</script>",
            ":worker", "true", null, "NOT_LIFECYCLE_GUARDED")), emptyList())
        val html = HtmlReportGenerator.render(base.copy(report = base.report.copy(componentInventory = inventory)))
        assertFalse(html.contains("<script>bad"))
        assertTrue(html.contains("&lt;script&gt;bad"))
        assertTrue(html.contains("NOT_LIFECYCLE_GUARDED"))
        assertTrue(html.contains("Workers are not enumerated"))
        assertTrue(html.contains("executable component guards are not verified"))
    }
}
