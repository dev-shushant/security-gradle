package com.apparmorx.runtime

import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class ApkIntegrityVerifierTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test
    fun syntheticDexPassesStructuralVerification() {
        val payload = "HelloAppArmorXBytecode".toByteArray()
        val dex = ApkIntegrityVerifier.createSyntheticDex(payload)
        assertTrue(ApkIntegrityVerifier.verifyDexStructure(dex, dex.size.toLong()))
    }

    @Test
    fun corruptedMagicFailsVerification() {
        val payload = "CorruptedMagicPayload".toByteArray()
        val dex = ApkIntegrityVerifier.createSyntheticDex(payload)
        dex[0] = 0x00 // corrupt 'd' to 0x00
        assertFalse(ApkIntegrityVerifier.verifyDexStructure(dex, dex.size.toLong()))
    }

    @Test
    fun payloadTamperingFailsAdler32Verification() {
        val payload = "OriginalUntamperedPayload".toByteArray()
        val dex = ApkIntegrityVerifier.createSyntheticDex(payload)

        // Mutate payload byte at offset 115 (payload starts at 112)
        dex[115] = (dex[115] + 1).toByte()

        // Checksum mismatch must fail verification
        assertFalse(ApkIntegrityVerifier.verifyDexStructure(dex, dex.size.toLong()))
    }

    @Test
    fun fileSizeMismatchFailsVerification() {
        val payload = "SizeCheckPayload".toByteArray()
        val dex = ApkIntegrityVerifier.createSyntheticDex(payload)
        assertFalse(ApkIntegrityVerifier.verifyDexStructure(dex, (dex.size + 10).toLong()))
    }

    @Test
    fun syntheticCleanApkPassesFullVerification() {
        val apkFile = tempFolder.newFile("clean-app.apk")
        val dex = ApkIntegrityVerifier.createSyntheticDex("MainClassData".toByteArray())
        val manifest = "<manifest package=\"com.apparmorx.test\"/>".toByteArray()
        val policy = "schema=1\nsequence=1\n".toByteArray()
        val elfSo = byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte(), 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0)

        createZip(apkFile, mapOf(
            "classes.dex" to dex,
            "AndroidManifest.xml" to manifest,
            "assets/apparmorx/policy.properties" to policy,
            "lib/arm64-v8a/libapparmorx.so" to elfSo
        ))

        assertTrue(ApkIntegrityVerifier.verify(apkFile))
    }

    @Test
    fun missingMandatoryEntriesFailVerification() {
        val apkFile = tempFolder.newFile("missing-dex.apk")
        createZip(apkFile, mapOf(
            "AndroidManifest.xml" to "<manifest/>".toByteArray(),
            "assets/apparmorx/policy.properties" to "schema=1\n".toByteArray()
        ))
        assertFalse("Missing classes.dex must fail", ApkIntegrityVerifier.verify(apkFile))
    }

    @Test
    fun repackagingArtifactsFailVerification() {
        val apkFile = tempFolder.newFile("repackaged.apk")
        val dex = ApkIntegrityVerifier.createSyntheticDex("TestData".toByteArray())
        createZip(apkFile, mapOf(
            "classes.dex" to dex,
            "AndroidManifest.xml" to "<manifest/>".toByteArray(),
            "assets/apparmorx/policy.properties" to "schema=1\n".toByteArray(),
            "apktool.yml" to "version: 2.7.0".toByteArray()
        ))
        assertFalse("Apktool marker must fail", ApkIntegrityVerifier.verify(apkFile))
    }

    @Test
    fun payloadDigestMatchingAndMismatch() {
        val apkFile = tempFolder.newFile("digest-verified.apk")
        val dex = ApkIntegrityVerifier.createSyntheticDex("VerifiedDexPayload".toByteArray())
        val manifest = "<manifest package=\"com.apparmorx.test\"/>".toByteArray()
        val policy = "schema=1\n".toByteArray()

        createZip(apkFile, mapOf(
            "classes.dex" to dex,
            "AndroidManifest.xml" to manifest,
            "assets/apparmorx/policy.properties" to policy
        ))

        val manifestSha256 = MessageDigest.getInstance("SHA-256").digest(manifest)
            .joinToString("") { "%02x".format(it) }

        // Expected digest matches
        val matchingDigests = mapOf("AndroidManifest.xml" to manifestSha256)
        assertTrue(ApkIntegrityVerifier.verify(apkFile, matchingDigests))

        // Expected digest mismatch
        val tamperedDigests = mapOf("AndroidManifest.xml" to "0".repeat(64))
        assertFalse(ApkIntegrityVerifier.verify(apkFile, tamperedDigests))
    }

    @Test
    fun corruptedNativeLibraryElfHeaderFails() {
        val apkFile = tempFolder.newFile("corrupted-elf.apk")
        val dex = ApkIntegrityVerifier.createSyntheticDex("DexData".toByteArray())
        val corruptedElf = ByteArray(16) { 0 } // Missing \x7fELF

        createZip(apkFile, mapOf(
            "classes.dex" to dex,
            "AndroidManifest.xml" to "<manifest/>".toByteArray(),
            "assets/apparmorx/policy.properties" to "schema=1\n".toByteArray(),
            "lib/arm64-v8a/libapparmorx.so" to corruptedElf
        ))

        assertFalse("Corrupted ELF header must fail", ApkIntegrityVerifier.verify(apkFile))
    }

    private fun createZip(file: File, entries: Map<String, ByteArray>) {
        ZipOutputStream(FileOutputStream(file)).use { zos ->
            for ((name, data) in entries) {
                val entry = ZipEntry(name)
                zos.putNextEntry(entry)
                zos.write(data)
                zos.closeEntry()
            }
        }
    }
}
