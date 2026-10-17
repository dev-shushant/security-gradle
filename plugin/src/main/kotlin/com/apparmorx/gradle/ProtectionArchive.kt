package com.apparmorx.gradle

import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipFile

private const val POLICY_ENTRY = "assets/apparmorx/policy.properties"
private const val ENGINE_LIBRARY = "libapparmorx.so"
private val ABI_ENTRY = Regex("""lib/([^/]+)/[^/]+\.so""")

/** Preserve duplicate-file evidence before a name set can hide ambiguous payload paths. */
private fun archiveEntryInventory(archive: File): Pair<Set<String>, Set<String>> = ZipFile(archive).use { zip ->
    val names = linkedSetOf<String>()
    val duplicateFiles = linkedSetOf<String>()
    for (entry in zip.entries().asSequence()) {
        if (!names.add(entry.name) && !entry.isDirectory) duplicateFiles.add(entry.name)
    }
    names to duplicateFiles
}

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
    val manifestFindings: List<String> = emptyList(),
    val componentInventory: ComponentInventory? = null,
) {
    fun toJson(): String = buildString {
        appendLine("{")
        appendLine("""  "archiveName": ${jsonQuote(archiveName)},""")
        appendLine("""  "isProtected": $isProtected,""")
        appendLine("""  "abis": [${abis.joinToString(", ", transform = ::jsonQuote)}],""")
        appendLine("""  "failures": [${failures.joinToString(", ", transform = ::jsonQuote)}],""")
        appendLine("""  "manifestFindings": [${manifestFindings.joinToString(", ", transform = ::jsonQuote)}],""")
        appendLine("""  "componentInventory": ${componentInventory?.toJson() ?: "null"},""")
        appendLine("""  "entryDigests": {""")
        val digestEntries = entryDigests.entries.toList()
        for (i in digestEntries.indices) {
            val (key, value) = digestEntries[i]
            val comma = if (i == digestEntries.size - 1) "" else ","
            appendLine("""    ${jsonQuote(key)}: ${jsonQuote(value)}$comma""")
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
    val (entries, duplicateFiles) = archiveEntryInventory(archive)
    val failures = duplicateFiles.map { "duplicate-file-entry:$it" }.toMutableList()
    if ("classes.dex" !in entries) {
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

/** Structural bundle coverage only; no authenticity or delivered-split claim. */
internal fun auditBundleProtectionArchive(archive: File): List<String> {
    val (entries, duplicateFiles) = archiveEntryInventory(archive)
    val failures = duplicateFiles.map { "duplicate-file-entry:$it" }.toMutableList()
    if ("BundleConfig.pb" !in entries) failures += "missing-bundle-config"
    if ("base/dex/classes.dex" !in entries) failures += "missing-classes-dex"
    if ("base/manifest/AndroidManifest.xml" !in entries) failures += "missing-manifest"
    if ("base/$POLICY_ENTRY" !in entries) failures += "missing-policy"
    val abis = entries.mapNotNull { BUNDLE_ABI_ENTRY.matchEntire(it)?.groupValues?.get(1) }.toSortedSet()
    if (abis.isEmpty()) failures += "missing-native-engine"
    for (abi in abis) {
        if ("base/lib/$abi/$ENGINE_LIBRARY" !in entries) failures += "missing-native-engine:$abi"
    }
    return failures
}

private val BUNDLE_ABI_ENTRY = Regex("[^/]+/lib/([^/]+)/[^/]+\\.so")

internal fun generateBundleProtectionReport(
    archive: File,
    nowSeconds: Long = System.currentTimeMillis() / 1000,
): ProtectionReport {
    val failures = auditBundleProtectionArchive(archive)
    val digests = linkedMapOf<String, String>()
    val abis = sortedSetOf<String>()
    ZipFile(archive).use { zip ->
        for (entry in zip.entries().asSequence()) {
            val name = entry.name
            BUNDLE_ABI_ENTRY.matchEntire(name)?.groupValues?.get(1)?.let(abis::add)
            if (name == "BundleConfig.pb" || name.endsWith("/manifest/AndroidManifest.xml") ||
                name == "base/$POLICY_ENTRY" || name.matches(Regex("[^/]+/dex/classes[0-9]*\\.dex")) ||
                BUNDLE_ABI_ENTRY.matches(name)) {
                digests[name] = zip.getInputStream(entry).use { sha256(it.readBytes()) }
            }
        }
    }
    return ProtectionReport(archive.name, failures.isEmpty(), abis.toList(), failures, digests, nowSeconds)
}
