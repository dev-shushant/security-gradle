package com.apparmorx.runtime.fixture

import android.content.*
import android.database.Cursor
import android.net.Uri
import android.os.*
import com.apparmorx.runtime.*
import com.apparmorx.sample.MultiprocessGuardService
import com.apparmorx.sample.remote.RemoteWorkerProbes
import java.util.concurrent.atomic.AtomicBoolean

/** Explicit qualification-only evidence controller. Excluded from instrumentation, never in default builds. */
class ProcessControlProvider : ContentProvider() {
    private var original: SecuritySnapshot? = null
    private var elapsed = 0L
    private fun field(name: String) = SecurityRuntime::class.java.getDeclaredField(name).apply { isAccessible = true }
    override fun onCreate(): Boolean { SecurityRuntime.initialize(requireNotNull(context)); return true }
    @Synchronized override fun call(method: String, arg: String?, extras: Bundle?): Bundle {
        if (method == "set") {
            if (original == null) {
                val end = SystemClock.elapsedRealtime() + 30_000
                while (SecurityRuntime.snapshot().evidence.none { it.check == "native-engine" } ||
                    (field("scanning").get(SecurityRuntime) as AtomicBoolean).get()) {
                    check(SystemClock.elapsedRealtime() < end) { "Secondary scan did not finish" }
                    Thread.sleep(50)
                }
                original = SecurityRuntime.snapshot()
                elapsed = field("lastScanElapsed").getLong(SecurityRuntime)
            }
            val base = requireNotNull(original)
            val clear = listOf(Evidence("policy", Status.CLEAR), Evidence("signing-certificate", Status.CLEAR), Evidence("native-engine", Status.CLEAR))
            val evidence = when (arg) {
                "clear" -> clear
                "restricted" -> clear + Evidence("fixture-threat", Status.DETECTED)
                "unknown" -> clear.filterNot { it.check == "native-engine" }
                "pending" -> listOf(Evidence("scan-pending", Status.UNAVAILABLE))
                else -> error("Unsupported fixture state")
            }
            field("lastScanElapsed").setLong(SecurityRuntime, SystemClock.elapsedRealtime())
            field("current").set(SecurityRuntime, base.copy(checkedAtMillis = System.currentTimeMillis(), policySequence = 707,
                evidence = evidence, enforcement = base.enforcement.copy(restrictedAction = EnforcementAction.BLOCK_SCREEN,
                    enforceIndeterminate = true, failClosedOnStartup = true, killOnConfirmedHooking = false)))
        } else if (method == "restore") {
            original?.let { field("current").set(SecurityRuntime, it); field("lastScanElapsed").setLong(SecurityRuntime, elapsed) }
            original = null
        } else require(method == "read" || method == "read-work")
        return Bundle().apply {
            putInt("pid", Process.myPid()); putInt("uid", Process.myUid())
            putInt("binds", MultiprocessGuardService.binds.get())
            putString("state", SecurityGuard.lastObservedState().name)
            putLong("sequence", SecurityRuntime.snapshot().policySequence)
            putBoolean("fixtureDetected", SecurityRuntime.snapshot().evidence.any { it.check == "fixture-threat" && it.status == Status.DETECTED })
            if (method == "read-work") {
                val probe = RemoteWorkerProbes.state(requireNotNull(arg))
                putInt("constructed", probe.constructed.get())
                putInt("entered", probe.entered.get())
                putInt("cleaned", probe.cleaned.get())
                putInt("stopCallbacks", probe.stopCallbacks.get())
                putInt("cancelRequests", probe.cancelRequests.get())
                putStringArrayList("cancelPaths", ArrayList(probe.cancelPaths))
                putInt("interruptRequests", probe.interruptRequests.get())
                putBoolean("futureCancelled", probe.futureCancelled.get())
                putBoolean("stopped", RemoteWorkerProbes.instances[arg]?.isStopped == true)
            }
        }
    }
    override fun query(u: Uri, p: Array<out String>?, s: String?, a: Array<out String>?, o: String?): Cursor? = null
    override fun getType(u: Uri): String? = null
    override fun insert(u: Uri, v: ContentValues?): Uri? = null
    override fun delete(u: Uri, s: String?, a: Array<out String>?): Int = 0
    override fun update(u: Uri, v: ContentValues?, s: String?, a: Array<out String>?): Int = 0
}
