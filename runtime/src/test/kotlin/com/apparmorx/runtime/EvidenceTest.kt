package com.apparmorx.runtime

import org.junit.Assert.*
import org.junit.Test

class EvidenceTest {
    @Test fun unavailableDoesNotBecomeClear() {
        assertEquals(Status.UNAVAILABLE, probe("maps") { throw java.io.IOException() }.status)
    }
    @Test fun cancellationPropagates() {
        assertThrows(java.util.concurrent.CancellationException::class.java) {
            probe("maps") { throw java.util.concurrent.CancellationException() }
        }
    }
    @Test fun detectsIndicatorsCaseInsensitively() {
        assertTrue(matchesIndicator("7f000 /data/local/tmp/LIBFRIDA-GADGET.so", listOf("libfrida-gadget")))
        assertFalse(matchesIndicator("7f000 /system/lib64/libc.so", listOf("libfrida-gadget")))
    }
    @Test fun allCurrentSignersMustBeTrusted() {
        assertEquals(Status.DETECTED, signerStatus(setOf("trusted", "attacker"), setOf("trusted")))
        assertEquals(Status.CLEAR, signerStatus(setOf("trusted"), setOf("trusted")))
        assertEquals(Status.UNAVAILABLE, signerStatus(emptySet(), setOf("trusted")))
        assertEquals(Status.UNAVAILABLE, signerStatus(setOf("trusted"), emptySet()))
    }
    @Test fun restrictedAppliesTheConfiguredAction() {
        for (action in EnforcementAction.entries) {
            assertEquals(action, resolveEnforcementAction(ProtectionState.RESTRICTED, EnforcementPolicy(action, enforceIndeterminate = false)))
            assertEquals(action, resolveEnforcementAction(ProtectionState.RESTRICTED, EnforcementPolicy(action, enforceIndeterminate = true)))
        }
    }
    @Test fun indeterminateNeverEscalatesUnlessExplicitlyOptedIn() {
        val aggressive = EnforcementPolicy(EnforcementAction.TERMINATE, enforceIndeterminate = false)
        assertEquals(EnforcementAction.OBSERVE, resolveEnforcementAction(ProtectionState.INDETERMINATE, aggressive))
        val optedIn = EnforcementPolicy(EnforcementAction.TERMINATE, enforceIndeterminate = true)
        assertEquals(EnforcementAction.TERMINATE, resolveEnforcementAction(ProtectionState.INDETERMINATE, optedIn))
    }
    @Test fun checkingAndReadyAreAlwaysObserveEvenUnderTheMostAggressivePolicy() {
        val aggressive = EnforcementPolicy(EnforcementAction.TERMINATE, enforceIndeterminate = true)
        assertEquals(EnforcementAction.OBSERVE, resolveEnforcementAction(ProtectionState.CHECKING, aggressive))
        assertEquals(EnforcementAction.OBSERVE, resolveEnforcementAction(ProtectionState.READY, aggressive))
    }
    @Test fun checkingEscalatesWhenFailClosedOnStartupOptedIn() {
        val failClosed = EnforcementPolicy(EnforcementAction.BLOCK_SCREEN, enforceIndeterminate = false, failClosedOnStartup = true)
        assertEquals(EnforcementAction.BLOCK_SCREEN, resolveEnforcementAction(ProtectionState.CHECKING, failClosed))
        assertEquals(EnforcementAction.OBSERVE, resolveEnforcementAction(ProtectionState.READY, failClosed))
    }
    @Test fun mirageActionResolvesForRestrictedState() {
        val miragePolicy = EnforcementPolicy(EnforcementAction.MIRAGE, enforceIndeterminate = true, failClosedOnStartup = true)
        assertEquals(EnforcementAction.MIRAGE, resolveEnforcementAction(ProtectionState.RESTRICTED, miragePolicy))
        assertEquals(EnforcementAction.MIRAGE, resolveEnforcementAction(ProtectionState.CHECKING, miragePolicy))
        DeceptionEngine.injectJitter(1, 5)
        assertTrue(DeceptionEngine.isMirageActive)
    }
    @Test fun defaultPolicyNeverActsBeyondObservation() {
        for (state in ProtectionState.entries) {
            assertEquals(EnforcementAction.OBSERVE, resolveEnforcementAction(state, EnforcementPolicy.DEFAULT))
        }
    }
    @Test fun detectsHookClassPresenceWhenClassExists() {
        assertTrue(hasHookClass(javaClass.classLoader, listOf("java.lang.String")))
        assertFalse(hasHookClass(javaClass.classLoader, listOf("de.robv.android.xposed.XposedBridge", "me.weishu.epic.art.Epic")))
    }
    @Test fun detectsVirtualSpacePaths() {
        assertFalse(isVirtualSpacePath("/data/user/0/com.apparmorx.sample/files", "com.apparmorx.sample"))
        assertFalse(isVirtualSpacePath("/data/data/com.apparmorx.sample/files", "com.apparmorx.sample"))
        assertTrue(isVirtualSpacePath("/data/data/com.lbe.parallel/virtual/data/user/0/com.apparmorx.sample/files", "com.apparmorx.sample"))
        assertTrue(isVirtualSpacePath("/data/data/com.other.sandbox/files", "com.apparmorx.sample"))
    }
    @Test fun detectsEmulatorFingerprints() {
        assertFalse(isEmulatorFingerprint("google/cheetah_beta/cheetah:15", "Pixel 7 Pro", "google", "cheetah", "cheetah_beta", "cheetah"))
        assertTrue(isEmulatorFingerprint("generic/sdk/generic:10", "sdk_gphone64_arm64", "google", "generic", "sdk_gphone64_arm64", "ranchu"))
        assertTrue(isEmulatorFingerprint("unknown", "Android SDK built for x86", "generic", "generic", "sdk_google", "goldfish"))
    }
}
