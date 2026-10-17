package com.apparmorx.sample

import android.app.Activity
import android.app.Application
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.os.Bundle
import android.os.SystemClock
import android.view.View
import android.widget.TextView
import androidx.test.runner.MonitoringInstrumentation
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry
import androidx.test.runner.lifecycle.Stage
import com.apparmorx.runtime.*
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/** Real framework Application dispatch with controlled initial evidence; never a normal JUnit test. */
class ColdStartInstrumentation : MonitoringInstrumentation() {
    private lateinit var args: Bundle
    private var setupFailure: Throwable? = null
    private var intercepted = false
    private var initialBodyRuns = -1
    private fun field(name: String) = SecurityRuntime::class.java.getDeclaredField(name).apply { isAccessible = true }
    private fun bodyRuns(): Int = (Class.forName("com.apparmorx.sample.ColdStartApplication")
        .getField("initialized").get(null) as AtomicInteger).get()
    private fun await(reason: String, condition: () -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + 20_000
        while (!condition() && SystemClock.elapsedRealtime() < deadline) Thread.sleep(50)
        check(condition()) { reason }
    }
    override fun onCreate(arguments: Bundle?) {
        args = arguments ?: Bundle()
        super.onCreate(args)
        start()
    }
    override fun callApplicationOnCreate(app: Application) {
        try {
            check(app.javaClass.name == "com.apparmorx.sample.ColdStartApplication")
            check(!intercepted)
            intercepted = true
            SecurityRuntime.initialize(app)
            await("Real initializer scan still running") {
                !(field("scanning").get(SecurityRuntime) as AtomicBoolean).get()
            }
            val original = SecurityRuntime.snapshot()
            val clear = listOf(Evidence("policy", Status.CLEAR), Evidence("signing-certificate", Status.CLEAR),
                Evidence("native-engine", Status.CLEAR))
            val evidence = when (args.getString("initial")) {
                "pending" -> listOf(Evidence("scan-pending", Status.UNAVAILABLE))
                "clear" -> clear
                "unknown" -> clear.map { if (it.check == "native-engine") it.copy(status = Status.UNAVAILABLE) else it }
                "restricted" -> clear + Evidence("fixture-threat", Status.DETECTED)
                else -> error("Explicit initial evidence required")
            }
            field("lastScanElapsed").setLong(SecurityRuntime, SystemClock.elapsedRealtime())
            field("current").set(SecurityRuntime, original.copy(checkedAtMillis = System.currentTimeMillis(),
                evidence = evidence, enforcement = original.enforcement.copy(
                    restrictedAction = EnforcementAction.BLOCK_SCREEN, enforceIndeterminate = true,
                    failClosedOnStartup = true, killOnConfirmedHooking = false)))
            // Android dispatches the actual instrumented host onCreate, not a direct guard invocation.
            super.callApplicationOnCreate(app)
            initialBodyRuns = bodyRuns()
        } catch (failure: Throwable) { setupFailure = failure }
    }
    override fun onStart() {
        super.onStart()
        val result = JSONObject().put("initial", args.getString("initial"))
        try {
            setupFailure?.let { throw it }
            check(intercepted)
            val debug = targetContext.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
            val denied = !debug && args.getString("initial") in setOf("unknown", "restricted")
            check(initialBodyRuns == if (denied) 0 else 1) { "Unexpected Application host body execution" }
            val snapshot = SecurityRuntime.snapshot()
            runOnMainSync {
                field("lastScanElapsed").setLong(SecurityRuntime, SystemClock.elapsedRealtime())
                field("current").set(SecurityRuntime, snapshot.copy(checkedAtMillis = System.currentTimeMillis(),
                    evidence = listOf(Evidence("policy", Status.CLEAR), Evidence("signing-certificate", Status.CLEAR),
                        Evidence("native-engine", Status.CLEAR))))
                targetContext.startActivity(Intent(targetContext, StartupProbeActivity::class.java)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            }
            await("Protected target or restart UI did not settle") {
                var settled = false
                runOnMainSync {
                    val resumed = ActivityLifecycleMonitorRegistry.getInstance().getActivitiesInStage(Stage.RESUMED)
                    settled = if (denied) resumed.any { activity -> activity is BrandedSecurityActivity &&
                        activity.findViewById<TextView>(android.R.id.message).text.contains("force stop") &&
                        activity.findViewById<View>(android.R.id.button1).visibility == View.GONE }
                    else resumed.any { it is StartupProbeActivity }
                }
                settled
            }
            waitForIdleSync()
            check(StartupProbeActivity.launches.get() == if (denied) 0 else 1)
            check(bodyRuns() == initialBodyRuns) { "Application body was replayed" }
            result.put("debuggable", debug).put("frameworkApplicationDispatch", intercepted)
                .put("applicationBodyRuns", initialBodyRuns).put("targetLaunches", StartupProbeActivity.launches.get())
                .put("requiresFreshProcess", denied).put("status", "passed")
            finish(Activity.RESULT_OK, Bundle().apply { putString("stream", "AAX_COLD_START $result\n") })
        } catch (failure: Throwable) {
            result.put("status", "failed").put("error", failure.javaClass.simpleName + ": " + failure.message)
            finish(Activity.RESULT_CANCELED, Bundle().apply { putString("stream", "AAX_COLD_START $result\n") })
        }
    }
}
