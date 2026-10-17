package com.apparmorx.sample

import android.content.pm.ApplicationInfo
import android.content.Context
import android.content.Intent
import android.os.SystemClock
import android.view.View
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry
import androidx.test.runner.lifecycle.Stage
import com.apparmorx.runtime.*
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.atomic.AtomicBoolean

/** Synthetic controller fixtures, never detector/clean-device evidence. No production test hooks. */
@RunWith(AndroidJUnit4::class)
class StartupRecoveryQualificationTest {
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private fun field(name: String) = SecurityRuntime::class.java.getDeclaredField(name).apply { isAccessible = true }
    private fun await(description: String, condition: () -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + 20_000
        while (!condition() && SystemClock.elapsedRealtime() < deadline) Thread.sleep(50)
        assertTrue(description, condition())
    }
    private fun controlled(block: (SecuritySnapshot) -> Unit) {
        await("Full real scan must finish before the synthetic fixture") {
            SecurityRuntime.snapshot().evidence.any { it.check == "native-engine" } &&
                !(field("scanning").get(SecurityRuntime) as AtomicBoolean).get()
        }
        val original = SecurityRuntime.snapshot()
        val elapsed = field("lastScanElapsed").getLong(SecurityRuntime)
        val revision = field("completedScans").getLong(SecurityRuntime)
        try {
            instrumentation.runOnMainSync { field("lastScanElapsed").setLong(SecurityRuntime, SystemClock.elapsedRealtime()) }
            val policy = original.enforcement.copy(restrictedAction = EnforcementAction.BLOCK_SCREEN,
                enforceIndeterminate = true, failClosedOnStartup = true, killOnConfirmedHooking = false)
            block(original.copy(checkedAtMillis = System.currentTimeMillis(), enforcement = policy,
                evidence = listOf(Evidence("policy", Status.CLEAR), Evidence("signing-certificate", Status.CLEAR),
                    Evidence("native-engine", Status.UNAVAILABLE))))
        } finally {
            instrumentation.runOnMainSync {
                val monitor = ActivityLifecycleMonitorRegistry.getInstance()
                listOf(Stage.CREATED, Stage.STARTED, Stage.RESUMED, Stage.PAUSED, Stage.STOPPED)
                    .flatMap { monitor.getActivitiesInStage(it).toList() }.distinct()
                    .filter { it is StartupProbeActivity || it is SecurityBlockActivity }
                    .forEach { it.finish() }
                field("current").set(SecurityRuntime, original)
                field("lastScanElapsed").setLong(SecurityRuntime, elapsed)
                field("completedScans").setLong(SecurityRuntime, revision)
            }
        }
    }
    private fun ticket(): String {
        val registry = Class.forName("com.apparmorx.runtime.StartupLaunches")
        val tickets = registry.getDeclaredField("tickets").apply { isAccessible = true }.get(null)
        return tickets.javaClass.getMethod("issue", Any::class.java).invoke(tickets,
            Intent(context, StartupProbeActivity::class.java).putExtra("fixture-payload", "preserved")) as String
    }
    private fun waiting(token: String) = Intent(context, SecurityBlockActivity::class.java)
        .putExtra("com.apparmorx.runtime.STARTUP_PENDING", true)
        .putExtra("com.apparmorx.runtime.STARTUP_TICKET", token)
    private fun waitForRetry(scenario: ActivityScenario<SecurityBlockActivity>) = await("Retry must be offered for an incomplete check") {
        var visible = false
        scenario.onActivity { visible = it.findViewById<View>(android.R.id.button1).visibility == View.VISIBLE }
        visible
    }

    @Test fun retryWaitsForFreshCompletionAndSurvivesRecreation() = controlled { unknown ->
        field("current").set(SecurityRuntime, unknown)
        ActivityScenario.launch<SecurityBlockActivity>(waiting(ticket())).use { scenario ->
            waitForRetry(scenario)
            scenario.onActivity { it.findViewById<View>(android.R.id.button1).performClick() }
            scenario.recreate()
            instrumentation.waitForIdleSync()
            scenario.onActivity {
                assertTrue("Cached unknown must not complete retry", it.findViewById<TextView>(android.R.id.message).text.contains("Checking"))
                assertEquals(View.GONE, it.findViewById<View>(android.R.id.button1).visibility)
            }
            // Full scan completion with still-unavailable evidence must stay unavailable, never resume.
            instrumentation.runOnMainSync {
                field("current").set(SecurityRuntime, unknown.copy(checkedAtMillis = System.currentTimeMillis()))
                field("completedScans").setLong(SecurityRuntime, field("completedScans").getLong(SecurityRuntime) + 1)
            }
            waitForRetry(scenario)
        }
    }

    @Test fun freshAllowedResultResumesOriginalIntentOnlyOnce() = controlled { unknown ->
        StartupProbeActivity.launches.set(0)
        StartupProbeActivity.payload = null
        field("current").set(SecurityRuntime, unknown)
        val token = ticket()
        ActivityScenario.launch<SecurityBlockActivity>(waiting(token)).use { scenario ->
            waitForRetry(scenario)
            scenario.onActivity { it.findViewById<View>(android.R.id.button1).performClick() }
            instrumentation.runOnMainSync {
                field("current").set(SecurityRuntime, unknown.copy(checkedAtMillis = System.currentTimeMillis(),
                    evidence = unknown.evidence.map { it.copy(status = Status.CLEAR) }))
                field("completedScans").setLong(SecurityRuntime, field("completedScans").getLong(SecurityRuntime) + 1)
            }
            await("Original guarded target must resume") { StartupProbeActivity.launches.get() == 1 }
            assertEquals("preserved", StartupProbeActivity.payload)
        }
        ActivityScenario.launch<SecurityBlockActivity>(waiting(token)).use { replay ->
            instrumentation.waitForIdleSync()
            replay.onActivity {
                assertTrue(it.findViewById<TextView>(android.R.id.message).text.contains("close and reopen"))
            }
            assertEquals("Consumed ticket must not replay", 1, StartupProbeActivity.launches.get())
        }
    }
    @Test fun deniedApplicationInitializationCannotResumeAfterClearScan() = controlled { unknown ->
        val holder = Class.forName("com.apparmorx.runtime.ApplicationInitializationKt")
        val initialization = holder.getDeclaredMethod("getApplicationInitialization").invoke(null)
        val denied = initialization.javaClass.getDeclaredField("denied").apply { isAccessible = true }
            .get(initialization) as AtomicBoolean
        assertFalse("Fixture must start in an initialized process", denied.get())
        val debug = context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
        StartupProbeActivity.launches.set(0)
        val token = ticket()
        try {
            field("current").set(SecurityRuntime, unknown)
            instrumentation.runOnMainSync {
                assertEquals(debug, SecurityGuard.allowApplication(context.applicationContext as android.app.Application))
            }
            assertEquals(!debug, denied.get())
            field("current").set(SecurityRuntime, unknown.copy(checkedAtMillis = System.currentTimeMillis(),
                evidence = unknown.evidence.map { it.copy(status = Status.CLEAR) }))
            ActivityScenario.launch<SecurityBlockActivity>(waiting(token)).use { scenario ->
                if (!debug) scenario.onActivity {
                    assertTrue(it.findViewById<TextView>(android.R.id.message).text.contains("force stop"))
                    assertEquals(View.GONE, it.findViewById<View>(android.R.id.button1).visibility)
                }
                if (!debug) context.startActivity(Intent(context, StartupProbeActivity::class.java)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                await("Clear evidence must not bypass a denied Application body") {
                    var matched = false
                    instrumentation.runOnMainSync {
                        matched = if (debug) StartupProbeActivity.launches.get() == 1 else
                            ActivityLifecycleMonitorRegistry.getInstance().getActivitiesInStage(Stage.RESUMED)
                                .any { it is BrandedSecurityActivity &&
                                    it.findViewById<TextView>(android.R.id.message).text.contains("force stop") } &&
                                StartupProbeActivity.launches.get() == 0
                    }
                    matched
                }
            }
        } finally {
            // Test-only reflection cleanup; no production reset API or scan-driven latch reset exists.
            denied.set(false)
        }
    }

    @Test fun actualGuardUsesUnavailableReasonAndSkipsReleaseHostBody() = controlled { unknown ->
        StartupProbeActivity.launches.set(0)
        field("current").set(SecurityRuntime, unknown)
        val debug = context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
        // Explicit test-owned foreground setup; this is not a successful protection decision.
        ActivityScenario.launch<SecurityBlockActivity>(Intent(context, SecurityBlockActivity::class.java)).use {
            context.startActivity(Intent(context, StartupProbeActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            await("Actual injected Activity guard must observe in debug or show unavailable in release") {
                var matched = false
                instrumentation.runOnMainSync {
                    val resumed = ActivityLifecycleMonitorRegistry.getInstance().getActivitiesInStage(Stage.RESUMED)
                    matched = if (debug) resumed.any { it is StartupProbeActivity } && StartupProbeActivity.launches.get() == 1
                    else resumed.any { activity ->
                        activity is BrandedSecurityActivity &&
                            activity.findViewById<TextView>(android.R.id.message)?.text?.contains("close and reopen") == true &&
                            activity.findViewById<View>(android.R.id.button1)?.visibility == View.GONE
                    } && StartupProbeActivity.launches.get() == 0
                }
                matched
            }
        }
    }

}
