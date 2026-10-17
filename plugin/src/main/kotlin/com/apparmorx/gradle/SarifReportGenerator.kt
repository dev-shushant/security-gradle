package com.apparmorx.gradle

/**
 * Machine-readable SARIF 2.1.0 generator for AppArmorX static analysis and protection audits.
 * Compatible with GitHub Advanced Security, GitLab SAST, SonarQube, and IDE problem matchers.
 */
object SarifReportGenerator {

    data class RuleDef(
        val id: String,
        val name: String,
        val description: String,
        val defaultLevel: String
    )

    private val RULE_CATALOG = mapOf(
        "release-debuggable" to RuleDef(
            "AAX-101",
            "ReleaseDebuggable",
            "Application is marked debuggable in release artifacts",
            "error"
        ),
        "exported-provider-unprotected" to RuleDef(
            "AAX-102",
            "UnprotectedContentProvider",
            "Exported ContentProvider does not require access permissions",
            "error"
        ),
        "allow-backup-enabled" to RuleDef(
            "AAX-201",
            "ApplicationBackupEnabled",
            "Application allows private data extraction via adb backup",
            "warning"
        ),
        "cleartext-traffic-permitted" to RuleDef(
            "AAX-202",
            "CleartextTrafficPermitted",
            "Application permits unencrypted HTTP cleartext traffic",
            "warning"
        ),
        "exported-service-unprotected" to RuleDef(
            "AAX-203",
            "UnprotectedService",
            "Exported Service does not require caller permissions",
            "warning"
        ),
        "exported-receiver-unprotected" to RuleDef(
            "AAX-204",
            "UnprotectedBroadcastReceiver",
            "Exported BroadcastReceiver does not require sender permissions",
            "warning"
        ),
        "exported-activity-unprotected" to RuleDef(
            "AAX-205",
            "UnprotectedActivity",
            "Exported non-launcher Activity does not require permissions",
            "warning"
        ),
        "wide-grant-uri-permissions" to RuleDef(
            "AAX-206",
            "WideGrantUriPermissions",
            "ContentProvider grants wide URI permissions without restrictive subpaths",
            "warning"
        ),
        "missing-classes-dex" to RuleDef(
            "AAX-001",
            "MissingClassesDex",
            "Packaged archive is missing classes.dex bytecodes",
            "error"
        ),
        "missing-manifest" to RuleDef(
            "AAX-002",
            "MissingManifest",
            "Packaged archive is missing AndroidManifest.xml",
            "error"
        ),
        "missing-policy" to RuleDef(
            "AAX-003",
            "MissingSecurityPolicy",
            "Packaged archive is missing the verified security policy asset",
            "error"
        ),
        "missing-native-engine" to RuleDef(
            "AAX-004",
            "MissingNativeEngine",
            "Packaged archive is missing libapparmorx.so native RASP engine",
            "error"
        )
    )

    fun generateSarif(
        archiveName: String,
        manifestFindings: List<ManifestAuditor.Finding>,
        protectionFailures: List<String> = emptyList()
    ): String = buildString {
        appendLine("{")
        appendLine("""  "${'$'}schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",""")
        appendLine("""  "version": "2.1.0",""")
        appendLine("""  "runs": [""")
        appendLine("    {")
        appendLine("""      "tool": {""")
        appendLine("""        "driver": {""")
        appendLine("""          "name": "AppArmorX Security Auditor",""")
        appendLine("""          "version": "0.1.0",""")
        appendLine("""          "informationUri": "https://apparmorx.com",""")
        appendLine("""          "rules": [""")

        val allRuleCodes = (manifestFindings.map { it.code } + protectionFailures).distinct()
        val ruleDefs = allRuleCodes.mapNotNull { RULE_CATALOG[it] }

        for (i in ruleDefs.indices) {
            val r = ruleDefs[i]
            val comma = if (i == ruleDefs.size - 1) "" else ","
            appendLine("            {")
            appendLine("""              "id": "${r.id}",""")
            appendLine("""              "name": "${r.name}",""")
            appendLine("""              "shortDescription": { "text": "${escapeJson(r.description)}" },""")
            appendLine("""              "defaultConfiguration": { "level": "${r.defaultLevel}" }""")
            appendLine("            }$comma")
        }

        appendLine("          ]")
        appendLine("        }")
        appendLine("      },")
        appendLine("""      "results": [""")

        val resultItems = mutableListOf<String>()

        for (f in manifestFindings) {
            val rule = RULE_CATALOG[f.code]
            val ruleId = rule?.id ?: "AAX-GENERIC"
            val level = if (f.level == ManifestAuditor.Finding.Level.ERROR) "error" else "warning"
            val target = f.componentName ?: "AndroidManifest.xml"
            resultItems += buildString {
                appendLine("        {")
                appendLine("""          "ruleId": "$ruleId",""")
                appendLine("""          "level": "$level",""")
                appendLine("""          "message": { "text": "${escapeJson(f.message)}" },""")
                appendLine("""          "locations": [""")
                appendLine("            {")
                appendLine("""              "physicalLocation": {""")
                appendLine("""                "artifactLocation": { "uri": "${escapeJson(target)}" }""")
                appendLine("              }")
                appendLine("            }")
                appendLine("          ]")
                append("        }")
            }
        }

        for (failure in protectionFailures) {
            val rule = RULE_CATALOG[failure]
            val ruleId = rule?.id ?: "AAX-ARCHIVE"
            resultItems += buildString {
                appendLine("        {")
                appendLine("""          "ruleId": "$ruleId",""")
                appendLine("""          "level": "error",""")
                appendLine("""          "message": { "text": "Archive protection failure: ${escapeJson(failure)}" },""")
                appendLine("""          "locations": [""")
                appendLine("            {")
                appendLine("""              "physicalLocation": {""")
                appendLine("""                "artifactLocation": { "uri": "${escapeJson(archiveName)}" }""")
                appendLine("              }")
                appendLine("            }")
                appendLine("          ]")
                append("        }")
            }
        }

        for (i in resultItems.indices) {
            val comma = if (i == resultItems.size - 1) "" else ","
            appendLine(resultItems[i] + comma)
        }

        appendLine("      ]")
        appendLine("    }")
        appendLine("  ]")
        append("}")
    }

    private fun escapeJson(text: String): String = text
        .replace("\\", "\\\\")
        .replace("\"", "\\\"")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
}
