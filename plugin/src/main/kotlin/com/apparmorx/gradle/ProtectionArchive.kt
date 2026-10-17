package com.apparmorx.gradle

import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipFile

private const val POLICY_ENTRY = "assets/apparmorx/policy.properties"
private const val ENGINE_LIBRARY = "libapparmorx.so"
private val ABI_ENTRY = Regex("""lib/([^/]+)/[^/]+\.so""")

/**
 * Structural coverage and integrity manifest for a packaged app archive (APK).
 */
data class ProtectionReport(
    val archiveName: String,
    val isProtected: Boolean,
    val abis: List<String>,
    val failures: List<String>,
    val entryDigests: Map<String, String>,
    val timestampSeconds: Long,
    val manifestFindings: List<String> = emptyList()
) {
    fun toJson(): String = buildString {
        appendLine("{")
        appendLine("""  "archiveName": "$archiveName",""")
        appendLine("""  "isProtected": $isProtected,""")
        appendLine("""  "abis": [${abis.joinToString(", ") { "\"$it\"" }}],""")
        appendLine("""  "failures": [${failures.joinToString(", ") { "\"$it\"" }}],""")
        appendLine("""  "manifestFindings": [${manifestFindings.joinToString(", ") { "\"$it\"" }}],""")
        appendLine("""  "entryDigests": {""")
        val digestEntries = entryDigests.entries.toList()
        for (i in digestEntries.indices) {
            val (key, value) = digestEntries[i]
            val comma = if (i == digestEntries.size - 1) "" else ","
            appendLine("""    "$key": "$value"$comma""")
        }
        appendLine("  },")
        appendLine("""  "timestampSeconds": $timestampSeconds""")
        append("}")
    }
}

/**
 * Structural coverage audit over a packaged app archive's entry list (APK, or an AAB module zip).
 * Confirms the artifacts the plugin is supposed to have injected actually shipped — catching, for
 * example, a build variant that silently excluded the runtime AAR, or packaged only some of the
 * ABIs it built native code for.
 *
 * @return failure codes; empty means every check this audit performs passed.
 */
internal fun auditProtectionArchive(archive: File): List<String> {
    val entries = ZipFile(archive).use { zip -> zip.entries().asSequence().map { it.name }.toSet() }
    val failures = mutableListOf<String>()
    if (entries.none { it.startsWith("classes") && it.endsWith(".dex") }) {
        failures += "missing-classes-dex"
    }
    if ("AndroidManifest.xml" !in entries) failures += "missing-manifest"
    if (POLICY_ENTRY !in entries) failures += "missing-policy"
    val abis = entries.mapNotNull { ABI_ENTRY.matchEntire(it)?.groupValues?.get(1) }.toSortedSet()
    if (abis.isEmpty()) {
        failures += "missing-native-engine"
    } else {
        for (abi in abis) {
            if ("lib/$abi/$ENGINE_LIBRARY" !in entries) failures += "missing-native-engine:$abi"
        }
    }
    return failures
}

/**
 * Computes payload integrity metadata (SHA-256 digests of classes.dex, AndroidManifest.xml,
 * native libraries, and policy) and produces a machine-readable [ProtectionReport].
 */
internal fun generateProtectionReport(
    archive: File,
    nowSeconds: Long = System.currentTimeMillis() / 1000,
    manifestFindings: List<String> = emptyList()
): ProtectionReport {
    val failures = auditProtectionArchive(archive)
    val digests = linkedMapOf<String, String>()
    val abis = mutableSetOf<String>()
    ZipFile(archive).use { zip ->
        for (entry in zip.entries().asSequence()) {
            val name = entry.name
            val matchAbi = ABI_ENTRY.matchEntire(name)
            if (matchAbi != null) {
                abis += matchAbi.groupValues[1]
            }
            if (name == POLICY_ENTRY || name == "AndroidManifest.xml" ||
                (name.startsWith("classes") && name.endsWith(".dex")) ||
                (name.startsWith("lib/") && name.endsWith(".so"))
            ) {
                val bytes = zip.getInputStream(entry).use { it.readBytes() }
                digests[name] = sha256(bytes)
            }
        }
    }
    return ProtectionReport(
        archiveName = archive.name,
        isProtected = failures.isEmpty(),
        abis = abis.sorted(),
        failures = failures,
        entryDigests = digests,
        timestampSeconds = nowSeconds,
        manifestFindings = manifestFindings
    )
}

private fun sha256(bytes: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
