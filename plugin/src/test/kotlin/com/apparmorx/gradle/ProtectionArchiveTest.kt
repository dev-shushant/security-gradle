package com.apparmorx.gradle

import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class ProtectionArchiveTest {
    @get:Rule val folder = TemporaryFolder()
    private fun archive(vararg entries: String) = folder.newFile().apply {
        ZipOutputStream(outputStream()).use { zip ->
            entries.forEach { zip.putNextEntry(ZipEntry(it)); zip.write(byteArrayOf(1)); zip.closeEntry() }
        }
    }
    @Test fun missingPolicyIsRejected() {
        assertTrue(auditProtectionArchive(archive("classes.dex", "lib/arm64-v8a/libapparmorx.so")).any { it == "missing-policy" })
    }
    @Test fun everyPackagedAbiRequiresEngine() {
        val failures = auditProtectionArchive(archive("classes.dex", "assets/apparmorx/policy.properties", "lib/arm64-v8a/libapparmorx.so", "lib/x86_64/libhost.so"))
        assertTrue("missing-native-engine:x86_64" in failures)
    }
    @Test fun noNativeEngineIsRejected() {
        assertTrue("missing-native-engine" in auditProtectionArchive(archive("classes.dex", "assets/apparmorx/policy.properties")))
    }
    @Test fun structuralPresencePassesWithoutClaimingAuthenticity() {
        assertTrue(auditProtectionArchive(archive("classes.dex", "AndroidManifest.xml", "assets/apparmorx/policy.properties", "lib/arm64-v8a/libapparmorx.so")).isEmpty())
    }
    @Test fun emptyArchiveDoesNotPass() {
        assertTrue(auditProtectionArchive(archive()).isNotEmpty())
    }

    @Test fun missingClassesDexIsRejected() {
        val failures = auditProtectionArchive(archive("AndroidManifest.xml", "assets/apparmorx/policy.properties", "lib/arm64-v8a/libapparmorx.so"))
        assertTrue("missing-classes-dex" in failures)
    }

    @Test fun missingManifestIsRejected() {
        val failures = auditProtectionArchive(archive("classes.dex", "assets/apparmorx/policy.properties", "lib/arm64-v8a/libapparmorx.so"))
        assertTrue("missing-manifest" in failures)
    }

    @Test fun generatesIntegrityReportWithDigests() {
        val file = archive("classes.dex", "AndroidManifest.xml", "assets/apparmorx/policy.properties", "lib/arm64-v8a/libapparmorx.so")
        val report = generateProtectionReport(file, 1790630000L)
        assertTrue(report.isProtected)
        assertEquals(listOf("arm64-v8a"), report.abis)
        assertTrue(report.failures.isEmpty())
        assertTrue("classes.dex" in report.entryDigests)
        assertTrue("AndroidManifest.xml" in report.entryDigests)
        assertTrue("assets/apparmorx/policy.properties" in report.entryDigests)
        assertTrue("lib/arm64-v8a/libapparmorx.so" in report.entryDigests)
        val json = report.toJson()
        assertTrue(json.contains("\"isProtected\": true"))
        assertTrue(json.contains("\"abis\": [\"arm64-v8a\"]"))
        assertTrue(json.contains("\"classes.dex\":"))
    }
}
