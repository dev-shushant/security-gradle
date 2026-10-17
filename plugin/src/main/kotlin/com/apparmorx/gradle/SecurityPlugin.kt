package com.apparmorx.gradle

import com.android.build.api.artifact.SingleArtifact
import com.android.build.api.instrumentation.FramesComputationMode
import com.android.build.api.instrumentation.InstrumentationScope
import com.android.build.api.variant.ApplicationAndroidComponentsExtension
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.provider.Provider

/** Android application plugin. Uses AGP variant sources instead of task-name hooks or eager code generation. */
class SecurityPlugin : Plugin<Project> {
    override fun apply(project: Project) {
        val extension = project.extensions.create("security", SecurityExtension::class.java)
        extension.policyUrl.convention("")
        extension.policyPublicKey.convention("")
        extension.minimumSequence.convention(0L)
        extension.refreshOnBuild.convention(true)
        extension.signingCertificates.convention(emptyList())
        extension.requireReleaseSigningPins.convention(true)
        extension.profile.convention("STANDARD")
        extension.telemetryUrl.convention("")
        extension.telemetryHmacKey.convention("")
        extension.telemetryDetail.convention("STANDARD")
        extension.telemetryHeaders.convention(emptyMap())
        extension.payloadDigests.convention(emptyMap())
        val metadata = java.util.Properties()
        requireNotNull(javaClass.getResourceAsStream("/apparmorx-version.properties")).use(metadata::load)
        // Empty (default) = use the runtime bundled inside this plugin. Set coordinates only to override it.
        extension.runtimeCoordinates.convention("")
        val verify = project.tasks.register("securityVerify", PrepareSecurityPolicy::class.java) {
            configurePolicy(extension, project.gradle.startParameter.isOffline, debuggable = false)
            requirePins.set(false)
            outputDirectory.set(project.layout.buildDirectory.dir("security/verified"))
        }
        project.tasks.register("securityCheck") {
            group = "verification"
            description = "Verify the configured AppArmorX policy signature, schema and freshness"
            dependsOn(verify)
        }
        project.pluginManager.withPlugin("com.android.application") {
            val extractRuntime = project.tasks.register("extractApparmorxRuntime", ExtractRuntimeAar::class.java) {
                output.set(project.layout.buildDirectory.file("apparmorx/runtime-${metadata.getProperty("version")}.aar"))
            }
            project.dependencies.add("implementation", project.files(extractRuntime.flatMap { it.output }).builtBy(extractRuntime))
            // The runtime is written in Kotlin; a Java-only host app may not have the stdlib yet.
            project.dependencies.add("implementation", "org.jetbrains.kotlin:kotlin-stdlib:${metadata.getProperty("kotlin")}")
            project.dependencies.addProvider("implementation", extension.runtimeCoordinates.filter { it.isNotBlank() })
            val android = project.extensions.getByType(ApplicationAndroidComponentsExtension::class.java)
            android.onVariants(android.selector().all()) { variant ->
                val isVariantDebuggable = variant.debuggable
                val name = variant.name.replaceFirstChar { it.uppercaseChar() }
                val task = project.tasks.register("prepare${name}SecurityPolicy", PrepareSecurityPolicy::class.java) {
                    configurePolicy(extension, project.gradle.startParameter.isOffline, isVariantDebuggable)
                    applicationId.set(variant.applicationId)
                    requirePins.set(extension.requireReleaseSigningPins.map { it && !isVariantDebuggable })
                    outputDirectory.set(project.layout.buildDirectory.dir("generated/security/${variant.name}/assets"))
                }
                val signing = if (isVariantDebuggable) null else
                    variant.buildType?.let { project.extensions.getByType(com.android.build.api.dsl.ApplicationExtension::class.java).buildTypes.findByName(it)?.signingConfig }
                if (signing != null) {
                    signing.storeFile?.let { task.configure { keystoreFile.set(it) } }
                    signing.storePassword?.let { pw -> task.configure { keystorePassword.set(pw) } }
                    signing.keyAlias?.let { a -> task.configure { keystoreAlias.set(a) } }
                    signing.storeType?.let { t -> task.configure { keystoreType.set(t) } }
                }
                variant.sources.assets?.addGeneratedSourceDirectory(task, PrepareSecurityPolicy::outputDirectory)
                variant.instrumentation.apply {
                    transformClassesWith(GuardClassVisitorFactory::class.java, InstrumentationScope.PROJECT) {}
                    setAsmFramesComputationMode(FramesComputationMode.COMPUTE_FRAMES_FOR_INSTRUMENTED_METHODS)
                }
                val coverage = project.tasks.register("verify${name}ProtectionCoverage", VerifyProtectionCoverage::class.java) {
                    group = "verification"
                    description = "Audit the packaged APK for required AppArmorX protection artifacts"
                    apkDirectory.set(variant.artifacts.get(SingleArtifact.APK))
                    mergedManifest.set(variant.artifacts.get(SingleArtifact.MERGED_MANIFEST))
                    debuggable.set(isVariantDebuggable)
                    variantName.set(variant.name)
                    profile.set(extension.profile)
                    recordSettings(extension, isVariantDebuggable, effectiveSettings, profileDefaultSettings)
                    reportFile.set(project.layout.buildDirectory.file("reports/apparmorx/protection-report-${variant.name}.json"))
                    htmlReportFile.set(project.layout.buildDirectory.file("reports/apparmorx/protection-report-${variant.name}.html"))
                    sarifReportFile.set(project.layout.buildDirectory.file("reports/apparmorx/security-audit-${variant.name}.sarif"))
                }
                // AGP has not necessarily created the "assemble<Variant>" lifecycle task yet at this
                // point, so `tasks.named(...)` would fail eagerly; `matching` tolerates either order.
                project.tasks.matching { it.name == "assemble$name" }.configureEach { dependsOn(coverage) }
            }
        }
        project.pluginManager.withPlugin("com.android.library") {
            error("Apply com.apparmorx.security to the Android application module, not a library")
        }
    }
}

/** Profile defaults for this variant; any explicit `security { }` value overrides the matching field. */
private fun profileDefaults(extension: SecurityExtension, debuggable: Boolean) =
    extension.profile.map { ProtectionProfile.parse(it).resolve(debuggable) }

/** Records, per setting, the effective value and the profile default so the report can flag overrides. */
private fun recordSettings(
    extension: SecurityExtension,
    debuggable: Boolean,
    effective: org.gradle.api.provider.MapProperty<String, String>,
    defaults: org.gradle.api.provider.MapProperty<String, String>,
) {
    val d = profileDefaults(extension, debuggable)
    fun both(key: String, explicit: Provider<String>) {
        defaults.put(key, d.map { it.asMap().getValue(key) })
        effective.put(key, explicit.orElse(d.map { it.asMap().getValue(key) }))
    }
    both("restrictedAction", extension.restrictedAction)
    both("enforceIndeterminate", extension.enforceIndeterminate.map { it.toString() })
    both("failClosedOnStartup", extension.failClosedOnStartup.map { it.toString() })
    both("secureScreen", extension.secureScreen.map { it.toString() })
    both("filterTouches", extension.filterTouches.map { it.toString() })
    both("firewallClipboard", extension.firewallClipboard.map { it.toString() })
    both("firewallIdentifiers", extension.firewallIdentifiers.map { it.toString() })
    both("firewallLocation", extension.firewallLocation.map { it.toString() })
    both("firewallNetworkSecurity", extension.firewallNetworkSecurity.map { it.toString() })
    both("antiPtraceHardening", extension.antiPtraceHardening.map { it.toString() })
    both("killOnConfirmedHooking", extension.killOnConfirmedHooking.map { it.toString() })
}

private fun PrepareSecurityPolicy.configurePolicy(extension: SecurityExtension, isOffline: Boolean, debuggable: Boolean) {
    val defaults = profileDefaults(extension, debuggable)
    group = "security"
    policyUrl.set(extension.policyUrl)
    publicKey.set(extension.policyPublicKey)
    minimumSequence.set(extension.minimumSequence)
    refresh.set(extension.refreshOnBuild)
    offline.set(isOffline)
    certificates.set(extension.signingCertificates)
    policyFile.set(extension.policyFile)
    restrictedAction.set(extension.restrictedAction.orElse(defaults.map { it.restrictedAction }))
    enforceIndeterminate.set(extension.enforceIndeterminate.orElse(defaults.map { it.enforceIndeterminate }))
    failClosedOnStartup.set(extension.failClosedOnStartup.orElse(defaults.map { it.failClosedOnStartup }))
    secureScreen.set(extension.secureScreen.orElse(defaults.map { it.secureScreen }))
    filterTouches.set(extension.filterTouches.orElse(defaults.map { it.filterTouches }))
    telemetryUrl.set(extension.telemetryUrl)
    telemetryHmacKey.set(extension.telemetryHmacKey)
    telemetryDetail.set(extension.telemetryDetail)
    telemetryHeaders.set(extension.telemetryHeaders)
    firewallClipboard.set(extension.firewallClipboard.orElse(defaults.map { it.firewallClipboard }))
    firewallIdentifiers.set(extension.firewallIdentifiers.orElse(defaults.map { it.firewallIdentifiers }))
    firewallLocation.set(extension.firewallLocation.orElse(defaults.map { it.firewallLocation }))
    firewallNetworkSecurity.set(extension.firewallNetworkSecurity.orElse(defaults.map { it.firewallNetworkSecurity }))
    antiPtraceHardening.set(extension.antiPtraceHardening.orElse(defaults.map { it.antiPtraceHardening }))
    killOnConfirmedHooking.set(extension.killOnConfirmedHooking.orElse(defaults.map { it.killOnConfirmedHooking }))
    payloadDigests.set(extension.payloadDigests)
}
