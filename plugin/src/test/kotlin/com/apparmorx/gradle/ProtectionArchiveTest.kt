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
    private val bundleEntries = arrayOf("BundleConfig.pb", "base/dex/classes.dex",
        "base/manifest/AndroidManifest.xml", "base/assets/apparmorx/policy.properties",
        "base/lib/arm64-v8a/libapparmorx.so", "base/lib/x86_64/libapparmorx.so")

    @Test fun bundleBasePayloadPassesStructuralAudit() {
        assertTrue(auditBundleProtectionArchive(archive(*bundleEntries)).isEmpty())
    }

    @Test fun bundleMissingBasePolicyIsRejected() {
        assertTrue("missing-policy" in auditBundleProtectionArchive(archive(*bundleEntries.filterNot {
            it == "base/assets/apparmorx/policy.properties"
        }.toTypedArray())))
    }

    @Test fun featurePolicyCannotStandInForBasePolicy() {
        val entries = bundleEntries.filterNot { it == "base/assets/apparmorx/policy.properties" } +
            "feature/assets/apparmorx/policy.properties"
        assertTrue("missing-policy" in auditBundleProtectionArchive(archive(*entries.toTypedArray())))
    }

    @Test fun bundleRequiresEngineForEveryPackagedAbi() {
        val entries = bundleEntries.filterNot { it == "base/lib/x86_64/libapparmorx.so" } +
            "feature/lib/x86_64/libhost.so"
        assertTrue("missing-native-engine:x86_64" in auditBundleProtectionArchive(archive(*entries.toTypedArray())))
    }

    @Test fun apkLayoutCannotMasqueradeAsBundle() {
        assertTrue(auditBundleProtectionArchive(archive("classes.dex", "AndroidManifest.xml",
            "assets/apparmorx/policy.properties", "lib/arm64-v8a/libapparmorx.so")).isNotEmpty())
    }

    @Test fun bundleReportPreservesPhysicalEntryPaths() {
        val report = generateBundleProtectionReport(archive(*bundleEntries), 123)
        assertTrue(report.isProtected)
        assertEquals(listOf("arm64-v8a", "x86_64"), report.abis)
        assertTrue("base/dex/classes.dex" in report.entryDigests)
        assertEquals(123L, report.timestampSeconds)
    }

    @Test fun bundleMissingConfigIsRejected() {
        assertTrue("missing-bundle-config" in auditBundleProtectionArchive(
            archive(*bundleEntries.filterNot { it == "BundleConfig.pb" }.toTypedArray())))
    }
    private fun duplicateName(file: java.io.File, alias: String, target: String): java.io.File {
        val from=alias.toByteArray();val to=target.toByteArray();require(from.size==to.size)
        val bytes=file.readBytes();var replacements=0
        for(i in 0..bytes.size-from.size) {
            if(from.indices.all { bytes[i+it]==from[it] }) { to.copyInto(bytes,i);replacements++ }
        }
        assertEquals("Both ZIP headers must be rewritten",2,replacements)
        file.writeBytes(bytes)
        java.util.zip.ZipFile(file).use { zip -> assertEquals(2,zip.entries().asSequence().count { it.name==target }) }
        return file
    }

    private val apkEntries = listOf("classes.dex","AndroidManifest.xml","assets/apparmorx/policy.properties","lib/arm64-v8a/libapparmorx.so")
    @Test fun duplicateApkFilesAreRejectedRatherThanCollapsed() {
        for(path in apkEntries) {
            val alias=path.dropLast(1)+(if(path.last()=='x') "y" else "x")
            val file=duplicateName(archive(*(apkEntries+alias).toTypedArray()),alias,path)
            assertTrue("Duplicate $path passed", "duplicate-file-entry:$path" in auditProtectionArchive(file))
            assertFalse(generateProtectionReport(file).isProtected)
        }
    }
    @Test fun duplicateBundleFilesAreRejectedRatherThanCollapsed() {
        for(path in listOf("base/dex/classes.dex","base/assets/apparmorx/policy.properties","base/lib/arm64-v8a/libapparmorx.so")) {
            val alias=path.dropLast(1)+(if(path.last()=='x') "y" else "x")
            val file=duplicateName(archive(*(bundleEntries.toList()+alias).toTypedArray()),alias,path)
            assertTrue("Duplicate $path passed", "duplicate-file-entry:$path" in auditBundleProtectionArchive(file))
            assertFalse(generateBundleProtectionReport(file).isProtected)
        }
    }
    @Test fun onlySecondaryOrDexLikeNamesCannotReplacePrimaryDex() {
        for(name in listOf("classes2.dex","classes-backup.dex")) {
            assertTrue("missing-classes-dex" in auditProtectionArchive(archive(*(apkEntries.filterNot { it=="classes.dex" }+name).toTypedArray())))
            assertTrue("missing-classes-dex" in auditBundleProtectionArchive(archive(*(bundleEntries.filterNot { it=="base/dex/classes.dex" }+("base/dex/"+name)).toTypedArray())))
        }
    }
    @Test fun harmlessRepeatedDirectoryEntriesDoNotFailCoverage() {
        val file=duplicateName(archive(*(apkEntries+listOf("assets/demo/","assets/demx/")).toTypedArray()),"assets/demx/","assets/demo/")
        assertTrue(auditProtectionArchive(file).isEmpty())
    }

}
