package com.apparmorx.gradle

import org.junit.Assert.*
import org.junit.Test

class ManifestAuditorTest {
    @Test
    fun flagsDebuggableInReleaseBuild() {
        val manifest = """
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                <application android:debuggable="true" />
            </manifest>
        """.trimIndent()
        val findings = ManifestAuditor.audit(manifest, isDebuggable = false)
        assertTrue(findings.any { it.code == "release-debuggable" && it.level == ManifestAuditor.Finding.Level.ERROR })
    }

    @Test
    fun permitsDebuggableInDebugBuild() {
        val manifest = """
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                <application android:debuggable="true" />
            </manifest>
        """.trimIndent()
        val findings = ManifestAuditor.audit(manifest, isDebuggable = true)
        assertFalse(findings.any { it.code == "release-debuggable" })
    }

    @Test
    fun flagsAllowBackup() {
        val manifest = """
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                <application android:allowBackup="true" />
            </manifest>
        """.trimIndent()
        val findings = ManifestAuditor.audit(manifest, isDebuggable = false)
        assertTrue(findings.any { it.code == "allow-backup-enabled" && it.level == ManifestAuditor.Finding.Level.WARNING })
    }

    @Test
    fun flagsCleartextTrafficInRelease() {
        val manifest = """
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                <application android:usesCleartextTraffic="true" />
            </manifest>
        """.trimIndent()
        val findings = ManifestAuditor.audit(manifest, isDebuggable = false)
        assertTrue(findings.any { it.code == "cleartext-traffic-permitted" && it.level == ManifestAuditor.Finding.Level.WARNING })
    }

    @Test
    fun flagsUnprotectedExportedServiceAndReceiver() {
        val manifest = """
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                <application>
                    <service android:name=".ExposedService" android:exported="true" />
                    <receiver android:name=".ExposedReceiver" android:exported="true" />
                </application>
            </manifest>
        """.trimIndent()
        val findings = ManifestAuditor.audit(manifest, isDebuggable = false)
        assertTrue(findings.any { it.code == "exported-service-unprotected" && it.componentName == ".ExposedService" })
        assertTrue(findings.any { it.code == "exported-receiver-unprotected" && it.componentName == ".ExposedReceiver" })
    }

    @Test
    fun flagsUnprotectedExportedProviderAsError() {
        val manifest = """
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                <application>
                    <provider android:name=".ExposedProvider" android:exported="true" android:grantUriPermissions="true" />
                </application>
            </manifest>
        """.trimIndent()
        val findings = ManifestAuditor.audit(manifest, isDebuggable = false)
        assertTrue(findings.any { it.code == "exported-provider-unprotected" && it.level == ManifestAuditor.Finding.Level.ERROR })
        assertTrue(findings.any { it.code == "wide-grant-uri-permissions" && it.level == ManifestAuditor.Finding.Level.WARNING })
    }

    @Test
    fun permitsLauncherActivityWithoutPermission() {
        val manifest = """
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                <application>
                    <activity android:name=".MainActivity" android:exported="true">
                        <intent-filter>
                            <action android:name="android.intent.action.MAIN" />
                            <category android:name="android.intent.category.LAUNCHER" />
                        </intent-filter>
                    </activity>
                </application>
            </manifest>
        """.trimIndent()
        val findings = ManifestAuditor.audit(manifest, isDebuggable = false)
        assertFalse(findings.any { it.code == "exported-activity-unprotected" })
    }

    @Test
    fun flagsNonLauncherExportedActivityWithoutPermission() {
        val manifest = """
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                <application>
                    <activity android:name=".SecretActivity" android:exported="true" />
                </application>
            </manifest>
        """.trimIndent()
        val findings = ManifestAuditor.audit(manifest, isDebuggable = false)
        assertTrue(findings.any { it.code == "exported-activity-unprotected" && it.componentName == ".SecretActivity" })
    }

    @Test
    fun cleanManifestProducesNoFindings() {
        val manifest = """
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                <application android:allowBackup="false" android:usesCleartextTraffic="false">
                    <activity android:name=".MainActivity" android:exported="true">
                        <intent-filter>
                            <action android:name="android.intent.action.MAIN" />
                            <category android:name="android.intent.category.LAUNCHER" />
                        </intent-filter>
                    </activity>
                    <service android:name=".ProtectedService" android:exported="false" />
                    <receiver android:name=".ProtectedReceiver" android:exported="false" />
                </application>
            </manifest>
        """.trimIndent()
        val findings = ManifestAuditor.audit(manifest, isDebuggable = false)
        assertTrue(findings.isEmpty())
    }

    @Test
    fun sarifGeneratorProducesValidSarifStructure() {
        val findings = listOf(
            ManifestAuditor.Finding(ManifestAuditor.Finding.Level.ERROR, "release-debuggable", "debuggable is forbidden"),
            ManifestAuditor.Finding(ManifestAuditor.Finding.Level.WARNING, "allow-backup-enabled", "backup enabled")
        )
        val sarif = SarifReportGenerator.generateSarif("test.apk", findings, listOf("missing-classes-dex"))
        assertTrue(sarif.contains(""""version": "2.1.0""""))
        assertTrue(sarif.contains(""""name": "AppArmorX Security Auditor""""))
        assertTrue(sarif.contains("AAX-101"))
        assertTrue(sarif.contains("AAX-201"))
        assertTrue(sarif.contains("AAX-001"))
    }
}
