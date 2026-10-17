package com.apparmorx.sample

import android.app.Activity
import android.app.ActivityManager
import android.content.pm.ApplicationInfo
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.Process
import android.os.SystemClock
import android.view.View
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.runner.MonitoringInstrumentation
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry
import androidx.test.runner.lifecycle.Stage
import com.apparmorx.runtime.*
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicBoolean

/** Host-driven two-process protocol, deliberately NOT a discoverable JUnit test or production runner. */
class ProcessDeathInstrumentation : MonitoringInstrumentation() {
    private lateinit var args: Bundle
    private var retainStoppedTask = false
    private val marker get() = File(targetContext.filesDir, "apparmorx-process-death-fixture.json")
    private fun field(name: String) = SecurityRuntime::class.java.getDeclaredField(name).apply { isAccessible = true }
    private fun await(description: String, condition: () -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + 20_000
        while (!condition() && SystemClock.elapsedRealtime() < deadline) Thread.sleep(50)
        check(condition()) { description }
    }
    private fun digest(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    private fun ticketValid(token: String?): Boolean {
        val type = Class.forName("com.apparmorx.runtime.StartupLaunches")
        return type.getMethod("isValid", String::class.java).invoke(type.getField("INSTANCE").get(null), token) as Boolean
    }
    private fun fullScan() = await("Initial real scan did not complete") {
        SecurityRuntime.snapshot().evidence.any { it.check == "native-engine" } &&
            !(field("scanning").get(SecurityRuntime) as AtomicBoolean).get()
    }
    override fun onCreate(arguments: Bundle?) {
        args = arguments ?: Bundle()
        super.onCreate(args)
        start()
    }
    override fun shouldWaitForActivitiesToComplete(): Boolean = !retainStoppedTask
    override fun onStart() {
        super.onStart()
        val result = JSONObject().put("phase", args.getString("phase"))
            .put("debuggable", targetContext.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0)
        try {
            val session = requireNotNull(args.getString("session"))
            require(session.matches(Regex("[a-zA-Z0-9-]{1,80}")))
            fullScan()
            when (args.getString("phase")) {
                "prepare" -> prepare(session, result)
                "verify" -> verify(session, result)
                else -> error("Explicit prepare/verify phase required")
            }
            result.put("status", "passed")
            finish(Activity.RESULT_OK, Bundle().apply { putString("stream", "AAX_PROCESS_DEATH $result\n") })
        } catch (failure: Throwable) {
            retainStoppedTask = false
            result.put("status", "failed").put("error", failure.javaClass.simpleName + ": " + failure.message)
            finish(Activity.RESULT_CANCELED, Bundle().apply { putString("stream", "AAX_PROCESS_DEATH $result\n") })
        }
    }
    private fun prepare(session: String, result: JSONObject) {
        // Remove only previous test-owned security tasks, never unrelated apps/tasks.
        val manager = targetContext.getSystemService(ActivityManager::class.java)
        runOnMainSync {
            manager.appTasks.filter { task ->
                val info = task.taskInfo
                (info?.baseActivity ?: info?.baseIntent?.component)?.className in setOf(
                    SecurityBlockActivity::class.java.name, BrandedSecurityActivity::class.java.name)
            }
                .forEach { it.finishAndRemoveTask() }
        }
        marker.delete()
        StartupProbeActivity.launches.set(0)
        val original = SecurityRuntime.snapshot()
        val policy = original.enforcement.copy(restrictedAction = EnforcementAction.BLOCK_SCREEN,
            enforceIndeterminate = true, failClosedOnStartup = true, killOnConfirmedHooking = false)
        runOnMainSync {
            field("lastScanElapsed").setLong(SecurityRuntime, SystemClock.elapsedRealtime())
            field("current").set(SecurityRuntime, original.copy(checkedAtMillis = System.currentTimeMillis(),
                enforcement = policy, evidence = listOf(Evidence("scan-pending", Status.UNAVAILABLE))))
        }
        val registry = Class.forName("com.apparmorx.runtime.StartupLaunches")
        val tickets = registry.getDeclaredField("tickets").apply { isAccessible = true }.get(null)
        val token = tickets.javaClass.getMethod("issue", Any::class.java).invoke(tickets,
            Intent(targetContext, StartupProbeActivity::class.java).putExtra("fixture-payload", "must-not-resume-after-death")) as String
        check(ticketValid(token)) { "Ticket was not valid before process death" }
        val router = Class.forName("com.apparmorx.runtime.SecurityUiDestination")
        val destination = router.getMethod("intent", Context::class.java)
            .invoke(router.getField("INSTANCE").get(null), targetContext) as Intent
        destination.putExtra("com.apparmorx.runtime.STARTUP_PENDING", true)
            .putExtra("com.apparmorx.runtime.STARTUP_TICKET", token)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_MULTIPLE_TASK)
        // Intentionally not auto-closed: retain a fully STOPPED task across runner process termination.
        val scenario = ActivityScenario.launch<SecurityBlockActivity>(destination)
        var taskId = -1
        scenario.onActivity { activity ->
            check(activity is BrandedSecurityActivity)
            check(activity.intent.getBooleanExtra("com.apparmorx.runtime.STARTUP_PENDING", false))
            check(ticketValid(token))
            taskId = activity.taskId
            check(activity.moveTaskToBack(true)) { "Could not background the test task" }
        }
        await("Security task did not reach STOPPED before process termination") {
            var stopped = false
            runOnMainSync { stopped = ActivityLifecycleMonitorRegistry.getInstance()
                .getActivitiesInStage(Stage.STOPPED).any { it.taskId == taskId && it is SecurityBlockActivity } }
            stopped
        }
        waitForIdleSync()
        await("An activity remains started/resumed before test-process termination") {
            var inactive = false
            runOnMainSync {
                val monitor = ActivityLifecycleMonitorRegistry.getInstance()
                inactive = monitor.getActivitiesInStage(Stage.STARTED).isEmpty() &&
                    monitor.getActivitiesInStage(Stage.RESUMED).isEmpty()
            }
            inactive
        }
        check(StartupProbeActivity.launches.get() == 0)
        check(ticketValid(token))
        val data = JSONObject().put("session", session).put("pid", Process.myPid())
            .put("taskId", taskId).put("ticketHash", digest(token)).put("preparedElapsed", SystemClock.elapsedRealtime())
        marker.writeText(data.toString()) // Only a hash; never persist a usable capability outside the OS Intent.
        result.put("pid", Process.myPid()).put("taskId", taskId)
            .put("ticketValidBeforeDeath", true).put("stoppedBeforeFinish", true)
            .put("allActivitiesStopped", true).put("targetLaunches", 0)
        // MonitoringInstrumentation.finish then terminates this test process without finishing the stopped task.
        retainStoppedTask = true
    }
    private fun verify(session: String, result: JSONObject) {
        check(marker.isFile) { "Preparation marker missing" }
        val saved = JSONObject(marker.readText())
        check(saved.getString("session") == session) { "Stale preparation marker" }
        check(saved.getInt("pid") != Process.myPid()) { "Process did not change" }
        check(SystemClock.elapsedRealtime() - saved.getLong("preparedElapsed") in 0..60_000) {
            "Verification too late to distinguish process death from ticket expiry"
        }
        val taskId = saved.getInt("taskId")
        val manager = targetContext.getSystemService(ActivityManager::class.java)
        val task = manager.appTasks.singleOrNull { it.taskInfo?.taskId == taskId }
            ?: error("Original stopped task was not retained")
        val retained = requireNotNull(task.taskInfo) { "Retained task info disappeared" }
        result.put("retainedActivityRecord", retained.baseActivity != null)
        check(retained.baseIntent.component?.packageName == targetContext.packageName &&
            retained.baseIntent.component?.className == BrandedSecurityActivity::class.java.name) {
            "Retained task root Intent is not the owned security screen"
        }
        val original = SecurityRuntime.snapshot()
        val elapsed = field("lastScanElapsed").getLong(SecurityRuntime)
        StartupProbeActivity.launches.set(0)
        try {
            // Even synthetic READY evidence must not let a dead process's ticket resume the host.
            runOnMainSync {
                field("lastScanElapsed").setLong(SecurityRuntime, SystemClock.elapsedRealtime())
                field("current").set(SecurityRuntime, original.copy(checkedAtMillis = System.currentTimeMillis(),
                    evidence = listOf(Evidence("policy", Status.CLEAR), Evidence("signing-certificate", Status.CLEAR),
                        Evidence("native-engine", Status.CLEAR))))
                task.moveToFront() // Restores the existing task; does not pass a replacement launch Intent.
            }
            var restored: SecurityBlockActivity? = null
            await("Original task did not restore as an unavailable security screen") {
                var ready = false
                runOnMainSync {
                    restored = ActivityLifecycleMonitorRegistry.getInstance().getActivitiesInStage(Stage.RESUMED)
                        .filterIsInstance<SecurityBlockActivity>().singleOrNull { it.taskId == taskId }
                    ready = restored?.findViewById<TextView>(android.R.id.message)?.text?.contains("close and reopen") == true
                }
                ready
            }
            runOnMainSync {
                val activity = requireNotNull(restored)
                val token = requireNotNull(activity.intent.getStringExtra("com.apparmorx.runtime.STARTUP_TICKET"))
                check(digest(token) == saved.getString("ticketHash")) { "Original Intent ticket was not restored" }
                check(!ticketValid(token)) { "Old ticket unexpectedly valid in the new process" }
                check(activity.findViewById<View>(android.R.id.button1).visibility == View.GONE) { "Lost ticket offered retry" }
            }
            waitForIdleSync()
            val quietUntil = SystemClock.elapsedRealtime() + 500
            while (SystemClock.elapsedRealtime() < quietUntil) {
                check(StartupProbeActivity.launches.get() == 0) { "Original guarded target resumed after process death" }
                Thread.sleep(50)
            }
            result.put("oldPid", saved.getInt("pid")).put("pid", Process.myPid()).put("taskId", taskId)
                .put("originalIntentRestored", true).put("ticketValidAfterDeath", false)
                .put("targetLaunches", 0).put("screen", "UNAVAILABLE").put("syntheticReadyEvidence", true)
        } finally {
            runOnMainSync { task.finishAndRemoveTask(); field("current").set(SecurityRuntime, original)
                field("lastScanElapsed").setLong(SecurityRuntime, elapsed) }
            marker.delete()
        }
    }
}
