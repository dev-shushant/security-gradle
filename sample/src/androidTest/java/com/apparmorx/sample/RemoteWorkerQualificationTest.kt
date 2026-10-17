package com.apparmorx.sample

import android.content.pm.ApplicationInfo
import android.net.Uri
import android.os.*
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.work.*
import com.apparmorx.runtime.*
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Real WorkManager delegation/IPC with qualification-only, process-local synthetic evidence. */
@RunWith(AndroidJUnit4::class)
class RemoteWorkerQualificationTest {
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val manager get() = WorkManager.getInstance(context)
    private val debug get() = context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
    private val jobs = mutableListOf<UUID>()
    private val calls = JSONArray()
    private fun field(name: String) = SecurityRuntime::class.java.getDeclaredField(name).apply { isAccessible = true }
    private fun control(method: String, arg: String? = null) = requireNotNull(context.contentResolver.call(
        Uri.parse("content://${context.packageName}.fixture.process"), method, arg, null))
    private fun await(message: String, predicate: () -> Boolean) {
        val end = SystemClock.elapsedRealtime() + 30_000
        while (!predicate()) { check(SystemClock.elapsedRealtime() < end) { message }; Thread.sleep(50) }
    }
    private fun controlled(case: String, block: () -> Unit) {
        assumeTrue("Explicit process qualification build required", context.packageManager.resolveContentProvider("${context.packageName}.fixture.process", 0) != null)
        await("Main scan did not finish") { SecurityRuntime.snapshot().evidence.any { it.check == "native-engine" } &&
            !(field("scanning").get(SecurityRuntime) as AtomicBoolean).get() }
        val original = SecurityRuntime.snapshot()
        val elapsed = field("lastScanElapsed").getLong(SecurityRuntime)
        try {
            field("lastScanElapsed").setLong(SecurityRuntime, SystemClock.elapsedRealtime())
            field("current").set(SecurityRuntime, original.copy(checkedAtMillis = System.currentTimeMillis(),
                evidence = listOf(Evidence("policy", Status.CLEAR), Evidence("signing-certificate", Status.CLEAR), Evidence("native-engine", Status.CLEAR)),
                enforcement = original.enforcement.copy(restrictedAction = EnforcementAction.BLOCK_SCREEN,
                    enforceIndeterminate = false, failClosedOnStartup = false, killOnConfirmedHooking = false)))
            block()
            instrumentation.sendStatus(0, Bundle().apply {
                putString("stream", "AAX_REMOTE_WORKER_EVIDENCE " + JSONObject().put("case", case)
                    .put("debuggable", debug).put("syntheticEvidence", true).put("calls", calls))
            })
        } finally {
            try {
                jobs.forEach { manager.cancelWorkById(it).result.get(5, TimeUnit.SECONDS) }
                control("restore")
            } finally {
                field("current").set(SecurityRuntime, original)
                field("lastScanElapsed").setLong(SecurityRuntime, elapsed)
            }
        }
    }
    private fun enqueue(kind: String, wait: Boolean = false): UUID {
        val remote = Class.forName("androidx.work.multiprocess.RemoteListenableWorker")
        val delegate = Class.forName("androidx.work.multiprocess.RemoteListenableDelegatingWorker")
        fun key(type: Class<*>, name: String) = type.getField(name).get(null) as String
        val data = Data.Builder().putString(key(remote, "ARGUMENT_PACKAGE_NAME"), context.packageName)
            .putString(key(remote, "ARGUMENT_CLASS_NAME"), "androidx.work.multiprocess.RemoteWorkerService")
            .putString(key(delegate, "ARGUMENT_REMOTE_LISTENABLE_WORKER_NAME"), "com.apparmorx.sample.remote.Remote${kind}ProbeWorker")
            .putBoolean("wait", wait).build()
        val request = OneTimeWorkRequest.Builder(delegate.asSubclass(ListenableWorker::class.java)).setInputData(data).build()
        jobs.add(request.id)
        manager.enqueue(request).result.get(5, TimeUnit.SECONDS)
        return request.id
    }
    private fun info(id: UUID) = requireNotNull(manager.getWorkInfoById(id).get(5, TimeUnit.SECONDS))
    private fun probe(id: UUID) = control("read-work", id.toString())
    private fun terminal(id: UUID): WorkInfo { await("Remote work did not finish") { info(id).state.isFinished }; return info(id) }
    private fun record(id: UUID, kind: String, allowed: Boolean, expectedState: String) {
        val work = terminal(id)
        val remote = probe(id)
        assertNotEquals(Process.myPid(), remote.getInt("pid"))
        assertEquals(Process.myUid(), remote.getInt("uid"))
        assertTrue("Remote constructor must execute", remote.getInt("constructed") >= 1)
        assertEquals(if (allowed) 1 else 0, remote.getInt("entered"))
        assertEquals(expectedState, remote.getString("state"))
        assertEquals(if (allowed) WorkInfo.State.SUCCEEDED else WorkInfo.State.FAILED, work.state)
        if (allowed) {
            assertEquals(remote.getInt("pid"), work.outputData.getInt("remotePid", -1))
            assertEquals("AppArmorX remote worker body", work.outputData.getString("marker"))
            if (kind == "Coroutine") assertEquals(1, remote.getInt("cleaned"))
        } else assertEquals(0, remote.getInt("cleaned"))
        calls.put(JSONObject().put("kind", kind).put("allowed", allowed).put("workState", work.state.name)
            .put("observedState", expectedState).put("mainPid", Process.myPid()).put("remotePid", remote.getInt("pid"))
            .put("uid", remote.getInt("uid")).put("constructed", remote.getInt("constructed"))
            .put("entered", remote.getInt("entered")).put("cleaned", remote.getInt("cleaned")))
    }
    @Test fun clearRemoteWorkersReturnRealRemoteOutputs() = controlled("clear") {
        for (kind in listOf("Async", "Coroutine")) { control("set", "clear"); record(enqueue(kind), kind, true, "READY") }
    }
    @Test fun remoteRestrictionAndStrictUnknownFailBeforeBodies() = controlled("denied") {
        for ((state, expected) in listOf("restricted" to "RESTRICTED", "unknown" to "INDETERMINATE", "pending" to "CHECKING")) {
            for (kind in listOf("Async", "Coroutine")) { control("set", state); record(enqueue(kind), kind, debug, expected) }
        }
    }
    @Test fun cancellationAfterRemoteRestrictionStillRunsCoroutineFinally() = controlled("cleanup") {
        control("set", "clear")
        val id = enqueue("Coroutine", wait = true)
        await("Remote coroutine never entered") { probe(id).getInt("entered") == 1 }
        val before = probe(id)
        assertNotEquals(Process.myPid(), before.getInt("pid"))
        assertEquals(0, before.getInt("cleaned"))
        assertTrue(control("set", "restricted").getBoolean("fixtureDetected"))
        manager.cancelWorkById(id).result.get(5, TimeUnit.SECONDS)
        val deadline = SystemClock.elapsedRealtime() + 30_000
        while (probe(id).getInt("cleaned") != 1) {
            val latest = probe(id)
            check(SystemClock.elapsedRealtime() < deadline) {
                "Remote cancellation skipped finally: work=${info(id).state}, stopped=${latest.getBoolean("stopped")}, entered=${latest.getInt("entered")}, cleaned=${latest.getInt("cleaned")}, pid=${latest.getInt("pid")}"
            }
            Thread.sleep(50)
        }
        val after = probe(id)
        assertEquals(before.getInt("pid"), after.getInt("pid"))
        assertEquals(WorkInfo.State.CANCELLED, info(id).state)
        assertEquals(1, after.getInt("entered"))
        calls.put(JSONObject().put("kind", "Coroutine").put("workState", "CANCELLED").put("entered", 1)
            .put("cleaned", after.getInt("cleaned")).put("mainPid", Process.myPid()).put("remotePid", after.getInt("pid"))
            .put("uid", after.getInt("uid")).put("remoteRestrictionSet", true))
    }
    @Test fun cancellationOfPendingAsyncFuturePreservesHostStopAndCleanup() = controlled("async-cleanup") {
        control("set", "clear")
        val id = enqueue("Async", wait = true)
        await("Pending async worker never entered") { probe(id).getInt("entered") == 1 }
        val before = probe(id)
        assertNotEquals(Process.myPid(), before.getInt("pid"))
        assertEquals(0, before.getInt("cleaned"))
        assertEquals(0, before.getInt("stopCallbacks"))
        assertFalse(before.getBoolean("futureCancelled"))
        assertTrue(control("set", "restricted").getBoolean("fixtureDetected"))
        manager.cancelWorkById(id).result.get(5, TimeUnit.SECONDS)
        await("Async stop did not preserve callback and cancel its pending Future") {
            val current = probe(id)
            current.getInt("cleaned") == 1 && current.getInt("stopCallbacks") == 1 && current.getBoolean("stopped")
        }
        // Repeat the public cancellation request: cleanup and host callback must remain exactly once.
        manager.cancelWorkById(id).result.get(5, TimeUnit.SECONDS)
        val after = probe(id)
        assertEquals(before.getInt("pid"), after.getInt("pid"))
        assertEquals(Process.myUid(), after.getInt("uid"))
        assertEquals(WorkInfo.State.CANCELLED, info(id).state)
        assertEquals(1, after.getInt("entered"))
        assertEquals(1, after.getInt("cleaned"))
        assertEquals(1, after.getInt("stopCallbacks"))
        // WorkManager awaitWithin may propagate cancel(false) again after Future cancellation.
        // Future cancellation requests are idempotent; actual host cleanup must remain once.
        assertTrue(after.getInt("cancelRequests") >= 1)
        assertEquals(0, after.getInt("interruptRequests"))
        assertTrue(after.getBoolean("futureCancelled"))
        calls.put(JSONObject().put("kind", "Async").put("workState", "CANCELLED")
            .put("mainPid", Process.myPid()).put("remotePid", after.getInt("pid")).put("uid", after.getInt("uid"))
            .put("entered", 1).put("cleaned", after.getInt("cleaned")).put("stopped", after.getBoolean("stopped"))
            .put("stopCallbacks", after.getInt("stopCallbacks")).put("cancelRequests", after.getInt("cancelRequests"))
            .put("cancelPaths", JSONArray(after.getStringArrayList("cancelPaths")))
            .put("interruptRequests", after.getInt("interruptRequests")).put("futureCancelled", after.getBoolean("futureCancelled"))
            .put("remoteRestrictionSet", true))
    }

}
