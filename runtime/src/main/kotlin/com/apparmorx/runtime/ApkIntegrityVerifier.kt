package com.apparmorx.runtime

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.zip.Adler32
import java.util.zip.ZipFile

/**
 * APK structure, DEX header self-consistency and optional independently trusted entry digests.
 * DEX SHA-1/Adler-32 fields are self-checks, not APK signer authentication. Signer and policy
 * trust are checked separately; structural success alone is not repackaging resistance.
 */
internal object ApkIntegrityVerifier {

    private val REPACKAGING_MARKERS = setOf(
        "apktool.yml",
        "classes.dex.bak",
        "classes.dex.dex",
        "smali",
        "original/META-INF"
    )

    private val VALID_DEX_MAGICS = listOf(
        byteArrayOf(0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00), // dex\n035\0
        byteArrayOf(0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x37, 0x00), // dex\n037\0
        byteArrayOf(0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x38, 0x00), // dex\n038\0
        byteArrayOf(0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x39, 0x00)  // dex\n039\0
    )

    /**
     * Performs deep structural, checksum, and cryptographic integrity verification
     * on the host package archive.
     *
     * @param apkFile the APK archive file on disk
     * @param expectedDigests optional map of entry path to expected SHA-256 hex digest
     * @return true if APK passes all integrity checks; false if tampered or invalid
     */
    fun verify(apkFile: File, expectedDigests: Map<String, String> = emptyMap()): Boolean {
        if (!apkFile.exists() || !apkFile.canRead()) return false

        return try {
            ZipFile(apkFile).use { zip ->
                val entries = zip.entries().asSequence().toList()
                val entryNames = mutableSetOf<String>()
                for (entry in entries) {
                    if (!entryNames.add(entry.name) && !entry.isDirectory) return false
                }

                // 1. Mandatory base entries
                if ("classes.dex" !in entryNames) return false
                if ("AndroidManifest.xml" !in entryNames) return false
                if ("assets/apparmorx/policy.properties" !in entryNames) return false

                // 2. Anti-repackaging markers (Apktool / Baksmali / Dropper artifacts)
                for (marker in REPACKAGING_MARKERS) {
                    if (entryNames.any { it.contains(marker) }) return false
                }

                // 3. Multi-DEX format & header integrity checks
                val dexEntries = entries.filter { it.name.matches(Regex("""classes\d*\.dex""")) }
                if (dexEntries.isEmpty()) return false

                for (dexEntry in dexEntries) {
                    val bytes = zip.getInputStream(dexEntry).use { it.readBytes() }
                    if (!verifyDexStructure(bytes, dexEntry.size)) {
                        return false
                    }
                }

                // 4. Verification against expected cryptographic payload digests (if configured)
                for ((path, expectedSha256) in expectedDigests) {
                    val entry = zip.getEntry(path) ?: return false
                    val bytes = zip.getInputStream(entry).use { it.readBytes() }
                    val actualSha256 = sha256(bytes)
                    if (!actualSha256.equals(expectedSha256, ignoreCase = true)) {
                        return false
                    }
                }

                // 5. Native library ELF sanity (if present in APK)
                val nativeEntries = entries.filter { it.name.startsWith("lib/") && it.name.endsWith(".so") }
                for (libEntry in nativeEntries) {
                    val header = ByteArray(16)
                    val readCount = zip.getInputStream(libEntry).use { it.read(header) }
                    if (readCount < 16) return false
                    // ELF magic: 0x7f, 'E', 'L', 'F'
                    if (header[0] != 0x7f.toByte() || header[1] != 'E'.code.toByte() ||
                        header[2] != 'L'.code.toByte() || header[3] != 'F'.code.toByte()) {
                        return false
                    }
                }

                true
            }
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Verifies DEX binary header magic, file_size, Adler-32 checksum, and SHA-1 signature.
     */
    internal fun verifyDexStructure(dexBytes: ByteArray, expectedSize: Long): Boolean {
        // Minimal valid DEX header is 112 (0x70) bytes
        if (dexBytes.size < 112) return false
        if (expectedSize > 0 && dexBytes.size.toLong() != expectedSize) return false

        // Check magic (bytes 0..7)
        val validMagic = VALID_DEX_MAGICS.any { magic ->
            magic.indices.all { i -> dexBytes[i] == magic[i] }
        }
        if (!validMagic) return false

        val buffer = ByteBuffer.wrap(dexBytes).order(ByteOrder.LITTLE_ENDIAN)

        // Read stored Adler-32 checksum (bytes 8..11)
        val storedChecksum = buffer.getInt(8)

        // Read stored SHA-1 signature (bytes 12..31)
        val storedSignature = ByteArray(20)
        System.arraycopy(dexBytes, 12, storedSignature, 0, 20)

        // Read stored file_size (bytes 32..35)
        val storedFileSize = buffer.getInt(32)
        if (storedFileSize != dexBytes.size) return false

        // Compute actual Adler-32 checksum over bytes 12..end
        val adler = Adler32()
        adler.update(dexBytes, 12, dexBytes.size - 12)
        val computedChecksum = adler.value.toInt()
        if (computedChecksum != storedChecksum) return false

        // Compute actual SHA-1 signature over bytes 32..end
        val sha1 = MessageDigest.getInstance("SHA-1")
        sha1.update(dexBytes, 32, dexBytes.size - 32)
        val computedSignature = sha1.digest()
        if (!computedSignature.contentEquals(storedSignature)) return false

        return true
    }

    /**
     * Generates a syntactically valid DEX header byte array for testing.
     */
    internal fun createSyntheticDex(payload: ByteArray): ByteArray {
        val totalSize = 112 + payload.size
        val dex = ByteArray(totalSize)

        // Magic: dex\n035\0
        val magic = byteArrayOf(0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00)
        System.arraycopy(magic, 0, dex, 0, 8)

        // Payload
        System.arraycopy(payload, 0, dex, 112, payload.size)

        val buffer = ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN)
        // File size at offset 32
        buffer.putInt(32, totalSize)
        // Header size at offset 36
        buffer.putInt(36, 112)
        // Endian tag at offset 40 (0x12345678)
        buffer.putInt(40, 0x12345678)

        // Compute SHA-1 over bytes 32..end
        val sha1 = MessageDigest.getInstance("SHA-1")
        sha1.update(dex, 32, totalSize - 32)
        val signature = sha1.digest()
        System.arraycopy(signature, 0, dex, 12, 20)

        // Compute Adler-32 over bytes 12..end
        val adler = Adler32()
        adler.update(dex, 12, totalSize - 12)
        buffer.putInt(8, adler.value.toInt())

        return dex
    }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
}
