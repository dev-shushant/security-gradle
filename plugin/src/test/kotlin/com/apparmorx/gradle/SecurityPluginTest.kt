package com.apparmorx.gradle

import org.gradle.testkit.runner.GradleRunner
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Base64

class SecurityPluginTest {
    @get:Rule val folder = TemporaryFolder()
    private fun fixture(config: String = "") {
        folder.root.resolve("settings.gradle").writeText("rootProject.name = 'fixture'")
        folder.root.resolve("build.gradle").writeText("plugins { id 'com.apparmorx.security' }\n" + config)
    }
    private fun runner(vararg args: String) = GradleRunner.create().withProjectDir(folder.root)
        .withPluginClasspath().withArguments(*args, "--stacktrace", "--max-workers=1")
    @Test fun noPolicyOutputDuringConfigurationAndCacheIsReusable() {
        fixture()
        runner("help", "--configuration-cache").build()
        assertFalse(folder.root.resolve("build/security/verified").exists())
        assertTrue(runner("help", "--configuration-cache").build().output.contains("Reusing configuration cache"))
        runner("securityCheck", "--configuration-cache").build()
        val file = folder.root.resolve("build/security/verified/apparmorx/policy.properties")
        assertTrue(file.readText().contains("sha256=bundled"))
        val second = runner("securityCheck", "--configuration-cache").build()
        assertTrue(second.output.contains("Reusing configuration cache"))
        assertEquals(org.gradle.testkit.runner.TaskOutcome.SUCCESS, second.task(":securityVerify")!!.outcome)
    }
    @Test fun rejectsOfflineFeedWithoutPinnedFile() {
        fixture("security { policyUrl.set('https://apparmorx.com/policy') }")
        assertTrue(runner("securityCheck", "--offline").buildAndFail().output.contains("signed policyFile is required"))
    }
    @Test fun rejectsNonHttpsFeedBeforeConnecting() {
        fixture("security { policyUrl.set('http://127.0.0.1/policy') }")
        assertTrue(runner("securityCheck").buildAndFail().output.contains("endpoint must be HTTPS"))
    }
    @Test fun acceptsPinnedSignedPolicyAndRejectsRollback() {
        val keys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val now = java.time.Instant.now().epochSecond
        val payload = "schema=1\nsequence=9\nissued=${now - 5}\nexpires=${now + 3600}\nmarkers=frida-agent\n".toByteArray()
        val signature = Signature.getInstance("Ed25519").run { initSign(keys.private); update(payload); sign() }
        val encode = Base64.getEncoder()
        folder.root.resolve("policy.signed").writeText(encode.encodeToString(payload) + "\n" + encode.encodeToString(signature))
        val config = "security { policyFile.set(layout.projectDirectory.file('policy.signed')); policyPublicKey.set('${encode.encodeToString(keys.public.encoded)}'); minimumSequence.set(9L) }"
        fixture(config)
        runner("securityCheck", "--offline").build()
        assertTrue(folder.root.resolve("build/security/verified/apparmorx/policy.properties").readText().contains("sequence=9"))
        fixture(config.replace("9L", "10L"))
        assertTrue(runner("securityCheck", "--offline").buildAndFail().output.contains("rollback rejected"))
    }
    private fun policy() = folder.root.resolve("build/security/verified/apparmorx/policy.properties").readText()
    @Test fun zeroConfigDefaultsToStandardProfileThatProtectsReleaseBuilds() {
        fixture()
        runner("securityCheck", "--configuration-cache").build()
        val content = policy()
        assertTrue(content.contains("restrictedAction=BLOCK_SCREEN"))
        assertTrue(content.contains("firewallClipboard=true"))
        assertTrue(content.contains("firewallNetworkSecurity=true"))
        // Weak/unavailable evidence must never trigger enforcement by default.
        assertTrue(content.contains("enforceIndeterminate=false"))
        assertTrue(content.contains("failClosedOnStartup=false"))
    }
    @Test fun developmentProfileIsObserveOnly() {
        fixture("security { profile.set('DEVELOPMENT') }")
        runner("securityCheck").build()
        val content = policy()
        assertTrue(content.contains("restrictedAction=OBSERVE"))
        assertTrue(content.contains("firewallClipboard=false"))
    }
    @Test fun hardenedProfileEnablesFailClosedAndScreenProtection() {
        fixture("security { profile.set('hardened') }")
        runner("securityCheck").build()
        val content = policy()
        assertTrue(content.contains("failClosedOnStartup=true"))
        assertTrue(content.contains("secureScreen=true"))
    }
    @Test fun explicitSettingsOverrideProfileDefaults() {
        fixture("security { profile.set('HARDENED'); restrictedAction.set('WARN'); secureScreen.set(false) }")
        runner("securityCheck").build()
        val content = policy()
        assertTrue(content.contains("restrictedAction=WARN"))
        assertTrue(content.contains("secureScreen=false"))
        assertTrue(content.contains("failClosedOnStartup=true"))
    }
    @Test fun rejectsUnknownProfile() {
        fixture("security { profile.set('PARANOID') }")
        assertTrue(runner("securityCheck").buildAndFail().output.contains("security.profile must be one of"))
    }
    @Test fun rejectsUnrecognizedRestrictedAction() {
        fixture("security { restrictedAction.set('DELETE_EVERYTHING') }")
        val failure = runner("securityCheck").buildAndFail().output
        assertTrue(failure.contains("restrictedAction must be one of"))
        assertTrue(failure.contains("DELETE_EVERYTHING"))
    }
    @Test fun writesConfiguredEnforcementPolicy() {
        fixture("security { restrictedAction.set('BLOCK_SCREEN'); enforceIndeterminate.set(true) }")
        runner("securityCheck").build()
        val content = folder.root.resolve("build/security/verified/apparmorx/policy.properties").readText()
        assertTrue(content.contains("restrictedAction=BLOCK_SCREEN"))
        assertTrue(content.contains("enforceIndeterminate=true"))
    }
    @Test fun writesConfiguredMirageAndEnterprisePolicy() {
        val config = """
            security {
                restrictedAction.set('MIRAGE')
                enforceIndeterminate.set(true)
                failClosedOnStartup.set(true)
                secureScreen.set(true)
                filterTouches.set(true)
                telemetryUrl.set('https://secops.example.com/events')
                firewallClipboard.set(true)
                firewallIdentifiers.set(true)
                firewallLocation.set(true)
                firewallNetworkSecurity.set(true)
            }
        """.trimIndent()
        fixture(config)
        runner("securityCheck").build()
        val content = folder.root.resolve("build/security/verified/apparmorx/policy.properties").readText()
        assertTrue(content.contains("restrictedAction=MIRAGE"))
        assertTrue(content.contains("failClosedOnStartup=true"))
        assertTrue(content.contains("secureScreen=true"))
        assertTrue(content.contains("filterTouches=true"))
        assertTrue(content.contains("telemetryUrl=https://secops.example.com/events"))
        assertTrue(content.contains("firewallClipboard=true"))
        assertTrue(content.contains("firewallIdentifiers=true"))
        assertTrue(content.contains("firewallLocation=true"))
        assertTrue(content.contains("firewallNetworkSecurity=true"))
    }
}
