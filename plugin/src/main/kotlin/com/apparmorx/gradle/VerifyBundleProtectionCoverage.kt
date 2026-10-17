package com.apparmorx.gradle

import org.gradle.api.DefaultTask
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.*
import org.gradle.work.DisableCachingByDefault

/** Passes the signed bundle through byte-for-byte only after structural and manifest checks. */
@DisableCachingByDefault(because = "Audits final signed packaging output")
abstract class VerifyBundleProtectionCoverage : DefaultTask() {
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE)
    abstract val inputBundle: RegularFileProperty

    @get:InputFile @get:PathSensitive(PathSensitivity.NONE)
    abstract val mergedManifest: RegularFileProperty

    @get:Input abstract val debuggable: Property<Boolean>

    @get:OutputFile abstract val outputBundle: RegularFileProperty
    @get:OutputFile abstract val reportFile: RegularFileProperty

    @TaskAction
    fun verify() {
        val input = inputBundle.get().asFile
        val output = outputBundle.get().asFile
        // Remove any previous successful output before a failing revalidation.
        output.delete()
        val manifestXml = mergedManifest.get().asFile.readText()
        val findings = ManifestAuditor.audit(manifestXml, debuggable.get())
        val report = generateBundleProtectionReport(input).copy(
            manifestFindings = findings.map { "${it.level}: [${it.code}] ${it.message}" },
            componentInventory = componentInventory(manifestXml),
        )
        reportFile.get().asFile.apply { parentFile.mkdirs(); writeText(report.toJson()) }
        require(report.isProtected) { "AppArmorX bundle coverage failed: ${report.failures.joinToString()}" }
        require(findings.none { it.level == ManifestAuditor.Finding.Level.ERROR }) {
            "AppArmorX bundle manifest audit failed: " + findings.filter {
                it.level == ManifestAuditor.Finding.Level.ERROR
            }.joinToString { it.code }
        }
        output.parentFile.mkdirs()
        input.copyTo(output, overwrite = true)
        logger.lifecycle("AppArmorX: bundle structural coverage verified; signed bytes preserved")
    }
}
