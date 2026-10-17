package com.apparmorx.gradle

import org.gradle.api.DefaultTask
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.TaskAction
import org.gradle.work.DisableCachingByDefault
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/**
 * Unpacks the runtime AAR that ships inside this plugin's own jar. Nothing is downloaded: the runtime a
 * build gets is always exactly the one released together with the plugin version applied.
 */
@DisableCachingByDefault(because = "Copies a resource from the plugin jar; cheaper to rerun than to cache")
abstract class ExtractRuntimeAar : DefaultTask() {
    @get:OutputFile abstract val output: RegularFileProperty

    @TaskAction fun extract() {
        val resource = ExtractRuntimeAar::class.java.getResourceAsStream(RESOURCE)
            ?: error("This AppArmorX plugin build does not embed its runtime ($RESOURCE missing); reinstall the plugin or set security.runtimeCoordinates")
        val target = output.get().asFile.toPath()
        Files.createDirectories(target.parent)
        resource.use { Files.copy(it, target, StandardCopyOption.REPLACE_EXISTING) }
    }

    companion object { const val RESOURCE = "/apparmorx/runtime.aar" }
}
