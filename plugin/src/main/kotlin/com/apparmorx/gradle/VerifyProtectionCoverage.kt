package com.apparmorx.gradle

import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.tasks.*
import org.gradle.work.DisableCachingByDefault

/**
 * Fails the build when the packaged APK is missing an artifact this plugin is supposed to have
 * injected, and generates a structured protection report with SHA-256 payload integrity metadata.
 * Runs against the actual output of `variant.artifacts.get(SingleArtifact.APK)`, so it
 * audits what really shipped — not what the task graph merely intended to produce.
 */
@DisableCachingByDefault(because = "Depends on already-built packaging output; nothing to cache")
abstract class VerifyProtectionCoverage : DefaultTask() {
    @get:InputFiles @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val apkDirectory: DirectoryProperty

    @get:InputFile @get:Optional @get:PathSensitive(PathSensitivity.NONE)
    abstract val mergedManifest: RegularFileProperty

    @get:Input
    abstract val debuggable: org.gradle.api.provider.Property<Boolean>

    @get:Input abstract val variantName: org.gradle.api.provider.Property<String>
    @get:Input abstract val profile: org.gradle.api.provider.Property<String>
    @get:Input abstract val effectiveSettings: org.gradle.api.provider.MapProperty<String, String>
    @get:Input abstract val profileDefaultSettings: org.gradle.api.provider.MapProperty<String, String>

    @get:OutputFile @get:Optional
    abstract val reportFile: RegularFileProperty

    @get:OutputFile @get:Optional
    abstract val htmlReportFile: RegularFileProperty

    @get:OutputFile @get:Optional
    abstract val sarifReportFile: RegularFileProperty

    @TaskAction
    fun verify() {
        val apks = apkDirectory.asFileTree.matching { include("**/*.apk") }.files
        require(apks.isNotEmpty()) { "No packaged APK found to audit for AppArmorX protection coverage" }
        val findings = if (mergedManifest.isPresent && mergedManifest.get().asFile.exists()) {
            ManifestAuditor.audit(mergedManifest.get().asFile.readText(), debuggable.getOrElse(true))
        } else {
            emptyList()
        }
        val findingStrings = findings.map { "${it.level}: [${it.code}] ${it.message}" }
        val reports = apks.map { generateProtectionReport(it, manifestFindings = findingStrings) }
        if (reportFile.isPresent) {
            val file = reportFile.get().asFile
            file.parentFile?.mkdirs()
            file.writeText(reports.joinToString("\n") { it.toJson() })
        }
        if (htmlReportFile.isPresent) {
            val file = htmlReportFile.get().asFile
            file.parentFile?.mkdirs()
            file.writeText(HtmlReportGenerator.render(HtmlReportGenerator.Input(
                variant = variantName.getOrElse("unknown"),
                profile = profile.getOrElse("STANDARD"),
                report = reports.first(),
                settings = effectiveSettings.getOrElse(emptyMap()),
                profileDefaults = profileDefaultSettings.getOrElse(emptyMap()),
                findings = findings,
            )))
            logger.lifecycle("AppArmorX: security report -> ${file.toURI()}")
        }
        val failures = reports.filter { !it.isProtected }
        if (sarifReportFile.isPresent) {
            val sarifFile = sarifReportFile.get().asFile
            sarifFile.parentFile?.mkdirs()
            val allFailures = failures.flatMap { it.failures }
            sarifFile.writeText(SarifReportGenerator.generateSarif(apks.first().name, findings, allFailures))
        }
        require(failures.isEmpty()) {
            "AppArmorX protection coverage check failed:\n" +
                failures.joinToString("\n") { r -> "  ${r.archiveName}: ${r.failures.joinToString(", ")}" }
        }
        val errorFindings = findings.filter { it.level == ManifestAuditor.Finding.Level.ERROR }
        require(errorFindings.isEmpty()) {
            "AppArmorX manifest security audit failed:\n" +
                errorFindings.joinToString("\n") { "  [${it.code}] ${it.message}" }
        }
        logger.lifecycle("AppArmorX: protection coverage verified for ${apks.size} packaged APK(s)")
    }
}
