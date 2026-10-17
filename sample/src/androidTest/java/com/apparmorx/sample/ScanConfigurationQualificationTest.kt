package com.apparmorx.sample

import android.content.Context
import android.content.ContextWrapper
import android.content.res.AssetManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.apparmorx.runtime.*
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Uses malformed test-package assets; does not mutate the running runtime or claim detector accuracy. */
@RunWith(AndroidJUnit4::class)
class ScanConfigurationQualificationTest {
    @Test fun invalidPinsPreserveResponseAndDoNotSuppressSignerOrNativeChecks() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val fixture = object : ContextWrapper(instrumentation.targetContext) {
            override fun getAssets(): AssetManager = instrumentation.context.assets
        }
        val scanner = Class.forName("com.apparmorx.runtime.RuntimeScanner")
        val snapshot = scanner.getMethod("scan", Context::class.java)
            .invoke(scanner.getField("INSTANCE").get(null), fixture) as SecuritySnapshot
        assertEquals(EnforcementAction.BLOCK_SCREEN, snapshot.enforcement.restrictedAction)
        assertTrue(snapshot.enforcement.enforceIndeterminate)
        assertEquals(Status.UNAVAILABLE, snapshot.evidence.single { it.check == "policy" }.status)
        assertEquals(Status.UNAVAILABLE, snapshot.evidence.single { it.check == "apk-integrity" }.status)
        // Known mismatched fixture signer still gets checked despite unrelated malformed digest pins.
        assertEquals(Status.DETECTED, snapshot.evidence.single { it.check == "signing-certificate" }.status)
        assertTrue(snapshot.evidence.any { it.check == "native-engine" })
    }
    private fun identityFixture(actual: String): Context {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        return object : ContextWrapper(instrumentation.targetContext) {
            override fun getAssets(): AssetManager = instrumentation.context.assets
            override fun getPackageName(): String = actual
        }
    }

    private fun runScan(method: String, context: Context): SecuritySnapshot {
        val scanner = Class.forName("com.apparmorx.runtime.RuntimeScanner")
        return scanner.getMethod(method, Context::class.java)
            .invoke(scanner.getField("INSTANCE").get(null), context) as SecuritySnapshot
    }

    @Test fun unavailableObservedIdentityIsNotReportedAsRepackaging() {
        for (method in listOf("fastPreflight", "scan")) {
            val snapshot = runScan(method, identityFixture(""))
            assertEquals(method, Status.UNAVAILABLE, snapshot.evidence.single { it.check == "application-id" }.status)
            assertEquals(EnforcementAction.BLOCK_SCREEN, snapshot.enforcement.restrictedAction)
        }
    }

    @Test fun validDifferentIdentityRemainsDetectedInBothScanPhases() {
        for (method in listOf("fastPreflight", "scan")) {
            val snapshot = runScan(method, identityFixture("com.apparmorx.other"))
            assertEquals(method, Status.DETECTED, snapshot.evidence.single { it.check == "application-id" }.status)
        }
    }

}
