package com.apparmorx.gradle

import org.gradle.testkit.runner.GradleRunner
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class BundleCoverageTaskTest {
    @get:Rule val folder = TemporaryFolder()
    private val paths = listOf("BundleConfig.pb", "base/dex/classes.dex",
        "base/manifest/AndroidManifest.xml", "base/assets/apparmorx/policy.properties",
        "base/lib/arm64-v8a/libapparmorx.so")

    private fun writeBundle(includePolicy: Boolean) {
        ZipOutputStream(folder.root.resolve("input.aab").outputStream()).use { zip ->
            paths.filter { includePolicy || !it.endsWith("policy.properties") }.forEach {
                zip.putNextEntry(ZipEntry(it)); zip.write(byteArrayOf(1)); zip.closeEntry()
            }
        }
    }

    @Test fun preservesArtifactAndRejectsMissingPolicyWithoutStaleSuccessfulOutput() {
        folder.root.resolve("settings.gradle").writeText("rootProject.name = 'bundle-fixture'")
        folder.root.resolve("manifest.xml").writeText("""<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application android:allowBackup="false" android:usesCleartextTraffic="false" /></manifest>""")
        folder.root.resolve("build.gradle").writeText("""
            plugins { id 'com.apparmorx.security' }
            tasks.register('auditBundle', com.apparmorx.gradle.VerifyBundleProtectionCoverage) {
                inputBundle.set(layout.projectDirectory.file('input.aab'))
                outputBundle.set(layout.buildDirectory.file('verified/output.aab'))
                mergedManifest.set(layout.projectDirectory.file('manifest.xml'))
                debuggable.set(false)
                reportFile.set(layout.buildDirectory.file('reports/bundle.json'))
            }
        """.trimIndent())
        fun runner() = GradleRunner.create().withProjectDir(folder.root).withPluginClasspath()
            .withArguments("auditBundle", "--configuration-cache", "--stacktrace", "--max-workers=1")
        writeBundle(true)
        runner().build()
        val output = folder.root.resolve("build/verified/output.aab")
        assertArrayEquals(folder.root.resolve("input.aab").readBytes(), output.readBytes())
        assertTrue(runner().build().output.contains("Reusing configuration cache"))
        writeBundle(false)
        val failure = runner().buildAndFail()
        assertTrue(failure.output.contains("missing-policy"))
        assertFalse("A failed audit must not leave the previously accepted bundle", output.exists())
        assertTrue(folder.root.resolve("build/reports/bundle.json").readText().contains("\"isProtected\": false"))
    }
}
