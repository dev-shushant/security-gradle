package com.apparmorx.sample

import android.app.Service
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.ApplicationInfo
import android.os.IBinder
import android.os.Bundle
import org.json.JSONObject
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.core.app.ActivityScenario
import com.apparmorx.runtime.SecurityBlockActivity
import androidx.test.platform.app.InstrumentationRegistry
import com.apparmorx.runtime.SecurityRuntime
import com.apparmorx.runtime.Status
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/** Runs unchanged against observe-only debug and signer-restricted release fixture builds. */
@RunWith(AndroidJUnit4::class)
class ServiceCallbackQualificationTest {
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext

    private fun expectAllowed(): Boolean {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20)
        while (SecurityRuntime.snapshot().evidence.none { it.check == "native-engine" } && System.nanoTime() < deadline) {
            Thread.sleep(50)
        }
        val snapshot = SecurityRuntime.snapshot()
        assertTrue("Full scan required before evaluating callbacks", snapshot.evidence.any { it.check == "native-engine" })
        assertEquals(Status.CLEAR, snapshot.evidence.single { it.check == "policy" }.status)
        assertEquals("Fixture's deliberately incorrect signer must be detected", Status.DETECTED,
            snapshot.evidence.single { it.check == "signing-certificate" }.status)
        val debug = context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
        assertEquals(if (debug) "OBSERVE" else "BLOCK_SCREEN", snapshot.enforcement.restrictedAction.name)
        return debug
    }

    @Test fun callbackBodiesRespectReleaseRestrictionAndDebugObservation() {
        val allowed = expectAllowed()
        instrumentation.runOnMainSync {
            SampleBackgroundService.reset()
            val service = SampleBackgroundService().apply { attachForTesting(context) }
            service.onCreate()
            assertEquals(allowed, SampleBackgroundService.createExecuted)
            assertEquals(Service.START_NOT_STICKY, service.onStartCommand(Intent(), 0, 1))
            assertEquals(allowed, SampleBackgroundService.startExecuted)
            val binder = service.onBind(Intent())
            assertEquals(allowed, binder != null)
            assertEquals(allowed, SampleBackgroundService.bindExecuted)
            service.onRebind(Intent())
            assertEquals(allowed, SampleBackgroundService.rebindExecuted)
            @Suppress("DEPRECATION")
            service.onStart(Intent(), 1)
            assertEquals(allowed, SampleBackgroundService.legacyStartExecuted)
            // Cleanup must run even after new work was denied.
            service.onUnbind(Intent())
            service.onDestroy()
            assertTrue(SampleBackgroundService.unbindExecuted)
            assertTrue(SampleBackgroundService.destroyExecuted)
            instrumentation.sendStatus(0, Bundle().apply {
                putString("stream", "AAX_SERVICE_EVIDENCE " + JSONObject()
                    .put("case", "manual-callbacks").put("allowed", allowed)
                    .put("createExecuted", SampleBackgroundService.createExecuted)
                    .put("startExecuted", SampleBackgroundService.startExecuted)
                    .put("bindExecuted", SampleBackgroundService.bindExecuted)
                    .put("rebindExecuted", SampleBackgroundService.rebindExecuted)
                    .put("legacyStartExecuted", SampleBackgroundService.legacyStartExecuted)
                    .put("cleanupExecuted", SampleBackgroundService.destroyExecuted && SampleBackgroundService.unbindExecuted))
            })
        }
    }

    @Test fun frameworkBindingReturnsBinderOrNullAccordingToActualPolicy() {
        val allowed = expectAllowed()
        val callback = CountDownLatch(1)
        val outcome = AtomicReference<String>()
        val bound = AtomicBoolean(false)
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
                outcome.set(if (binder != null) "connected" else "invalid-connected"); callback.countDown()
            }
            override fun onNullBinding(name: ComponentName?) { outcome.set("null"); callback.countDown() }
            override fun onBindingDied(name: ComponentName?) { outcome.set("died"); callback.countDown() }
            override fun onServiceDisconnected(name: ComponentName?) = Unit
        }
        try {
            instrumentation.runOnMainSync {
                SampleBackgroundService.reset()
                bound.set(context.bindService(Intent(context, SampleBackgroundService::class.java), connection, Context.BIND_AUTO_CREATE))
            }
            assertTrue("Framework must accept the same-app binding request", bound.get())
            assertTrue("Framework binding callback must arrive", callback.await(15, TimeUnit.SECONDS))
            assertEquals(if (allowed) "connected" else "null", outcome.get())
            assertEquals(allowed, SampleBackgroundService.bindExecuted)
            assertEquals(allowed, SampleBackgroundService.createExecuted)
            instrumentation.sendStatus(0, Bundle().apply {
                putString("stream", "AAX_SERVICE_EVIDENCE " + JSONObject()
                    .put("case", "framework-binding").put("allowed", allowed)
                    .put("outcome", outcome.get()).put("bindExecuted", SampleBackgroundService.bindExecuted))
            })
        } finally {
            if (bound.get()) instrumentation.runOnMainSync { context.unbindService(connection) }
        }
    }
    @Test fun frameworkStartedServiceRunsOrStopsAccordingToActualPolicy() {
        val allowed = expectAllowed()
        // An explicit test-owned foreground Activity satisfies Android background-start rules.
        // It is not evidence that the runtime blocked this Activity: the test launches it directly.
        ActivityScenario.launch(SecurityBlockActivity::class.java).use {
            try {
                instrumentation.runOnMainSync {
                    SampleBackgroundService.reset()
                    assertNotNull(context.startService(Intent(context, SampleBackgroundService::class.java)))
                }
                val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15)
                while (!(if (allowed) SampleBackgroundService.startExecuted else SampleBackgroundService.destroyExecuted)
                    && System.nanoTime() < deadline) Thread.sleep(50)
                assertEquals(allowed, SampleBackgroundService.createExecuted)
                assertEquals(allowed, SampleBackgroundService.startExecuted)
                if (!allowed) assertTrue("Restricted framework service must stop", SampleBackgroundService.destroyExecuted)
                instrumentation.sendStatus(0, Bundle().apply {
                    putString("stream", "AAX_SERVICE_EVIDENCE " + JSONObject()
                        .put("case", "framework-start").put("allowed", allowed)
                        .put("createExecuted", SampleBackgroundService.createExecuted)
                        .put("startExecuted", SampleBackgroundService.startExecuted)
                        .put("destroyExecuted", SampleBackgroundService.destroyExecuted))
                })
            } finally {
                instrumentation.runOnMainSync { context.stopService(Intent(context, SampleBackgroundService::class.java)) }
            }
        }
    }
}
