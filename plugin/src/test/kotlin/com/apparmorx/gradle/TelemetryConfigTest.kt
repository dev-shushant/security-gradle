package com.apparmorx.gradle

import org.gradle.testkit.runner.GradleRunner
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class TelemetryConfigTest {
    @get:Rule val folder = TemporaryFolder()
    private fun fixture(config: String) {
        folder.root.resolve("settings.gradle").writeText("rootProject.name = 'fixture'")
        folder.root.resolve("build.gradle").writeText("plugins { id 'com.apparmorx.security' }\nsecurity { $config }")
    }
    private fun run(vararg a: String) = GradleRunner.create().withProjectDir(folder.root).withPluginClasspath().withArguments(*a, "--stacktrace", "--max-workers=1")
    private fun policy() = folder.root.resolve("build/security/verified/apparmorx/policy.properties").readText()

    @Test fun telemetryIsOffByDefaultAndWritesNoEndpointOrHeaders() {
        fixture("")
        run("securityCheck").build()
        val p = policy()
        assertTrue(p.contains("telemetryUrl=\n"))
        assertFalse(p.contains("telemetryHeader."))
        assertTrue(p.contains("telemetryDetail=STANDARD"))
    }

    @Test fun writesDetailLevelAndCustomHeaders() {
        fixture("telemetryUrl.set('https://secops.example.com/v1/events'); telemetryDetail.set('extended'); telemetryHeaders.put('X-Api-Key', 'k-123'); telemetryHeaders.put('X-Tenant', 'acme')")
        run("securityCheck").build()
        val p = policy()
        assertTrue(p.contains("telemetryDetail=EXTENDED"))
        assertTrue(p.contains("telemetryHeader.X-Api-Key=k-123"))
        assertTrue(p.contains("telemetryHeader.X-Tenant=acme"))
    }

    @Test fun rejectsNonHttpsOrCredentialedEndpointAtBuildTimeInsteadOfSilentlyDroppingReports() {
        for (bad in listOf("http://secops.example.com/e", "https://user:pw@secops.example.com/e", "https://secops.example.com/e#frag", "secops.example.com")) {
            fixture("telemetryUrl.set('$bad')")
            val out = run("securityCheck").buildAndFail().output
            assertTrue("$bad -> $out", out.contains("security.telemetryUrl must be an HTTPS URL"))
        }
    }

    @Test fun rejectsUnknownDetailAndReservedOrMalformedHeaders() {
        fixture("telemetryDetail.set('EVERYTHING')")
        assertTrue(run("securityCheck").buildAndFail().output.contains("security.telemetryDetail must be one of"))
        for (name in listOf("Host", "Content-Type", "X-AppArmorX-Signature", "Bad Name")) {
            fixture("telemetryUrl.set('https://secops.example.com/e'); telemetryHeaders.put('$name', 'v')")
            assertTrue(name, run("securityCheck").buildAndFail().output.contains("telemetryHeaders"))
        }
        fixture("telemetryUrl.set('https://secops.example.com/e'); telemetryHeaders.put('X-Api-Key', 'bad\\nvalue')")
        assertTrue(run("securityCheck").buildAndFail().output.contains("telemetryHeaders"))
    }
}
