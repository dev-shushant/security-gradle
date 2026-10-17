package com.apparmorx.sample

import android.content.pm.ApplicationInfo
import android.os.SystemClock
import android.os.Bundle
import android.os.Process
import org.json.JSONObject
import com.google.common.util.concurrent.ListenableFuture
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.work.*
import com.apparmorx.runtime.*
import com.apparmorx.sample.work.*
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.util.UUID
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Real WorkManager scheduling with synthetic evidence, not device-threat qualification. */
@RunWith(AndroidJUnit4::class)
class WorkerEntryQualificationTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val manager get() = WorkManager.getInstance(context)
    private val debug get() = context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
    private val owned = mutableListOf<UUID>()
    private fun field(name: String) = SecurityRuntime::class.java.getDeclaredField(name).apply { isAccessible = true }
    private fun await(message: String, predicate: () -> Boolean) {
        val end = SystemClock.elapsedRealtime() + 30_000
        while (!predicate()) {
            check(SystemClock.elapsedRealtime() < end) { message }
            Thread.sleep(50)
        }
    }
    private fun set(snapshot: SecuritySnapshot) { field("current").set(SecurityRuntime, snapshot) }
    private fun controlled(case: String, body: (SecuritySnapshot) -> Unit) {
        await("Initial scan did not complete") {
            SecurityRuntime.snapshot().evidence.any { it.check == "native-engine" } &&
                !(field("scanning").get(SecurityRuntime) as AtomicBoolean).get()
        }
        val original = SecurityRuntime.snapshot()
        val elapsed = field("lastScanElapsed").getLong(SecurityRuntime)
        try {
            field("lastScanElapsed").setLong(SecurityRuntime, SystemClock.elapsedRealtime())
            val base = original.copy(checkedAtMillis = System.currentTimeMillis(),
                evidence = listOf(Evidence("policy", Status.CLEAR), Evidence("signing-certificate", Status.CLEAR),
                    Evidence("native-engine", Status.CLEAR)),
                enforcement = original.enforcement.copy(restrictedAction = EnforcementAction.BLOCK_SCREEN,
                    enforceIndeterminate = false, failClosedOnStartup = false, killOnConfirmedHooking = false))
            set(base)
            body(base)
            InstrumentationRegistry.getInstrumentation().sendStatus(0, Bundle().apply {
                putString("stream", "AAX_WORKER_EVIDENCE " + JSONObject().put("case", case)
                    .put("debuggable", debug).put("uid", Process.myUid()).put("syntheticEvidence", true)
                    .put("assertionsPassed", true).put("ownedRequests", owned.size))
            })
        } finally {
            owned.forEach { manager.cancelWorkById(it).result.get(5, TimeUnit.SECONDS) }
            owned.forEach { id ->
                WorkerProbes.instances.remove(id.toString())
                WorkerProbes.states.remove(id.toString())
            }
            set(original)
            field("lastScanElapsed").setLong(SecurityRuntime, elapsed)
        }
    }
    private fun enqueue(type: Class<out ListenableWorker>, data: Data = Data.EMPTY): UUID {
        val request = OneTimeWorkRequest.Builder(type).setInputData(data).build()
        owned.add(request.id)
        manager.enqueue(request).result.get(5, TimeUnit.SECONDS)
        return request.id
    }
    private fun info(id: UUID) = requireNotNull(manager.getWorkInfoById(id).get(5, TimeUnit.SECONDS))
    private fun terminal(id: UUID): WorkInfo {
        await("Work did not finish: $id") { info(id).state.isFinished }
        return info(id)
    }
    @Test fun clearJobsPreserveAllThreeWorkerBodiesAndOutputs() = controlled("clear") {
        listOf(SampleWorker::class.java, SampleCoroutineWorker::class.java, SampleAsyncWorker::class.java).forEach { type ->
            val id = enqueue(type)
            val result = terminal(id)
            assertEquals(WorkInfo.State.SUCCEEDED, result.state)
            assertEquals("AppArmorX worker body", result.outputData.getString("marker"))
            assertEquals(1, WorkerProbes.state(id.toString()).entered.get())
            if (type == SampleCoroutineWorker::class.java) assertEquals(1, WorkerProbes.state(id.toString()).cleaned.get())
        }
    }
    @Test fun restrictionDeniesBeforeBodiesWhileDebugObserves() = controlled("restricted") { base ->
        set(base.copy(evidence = base.evidence + Evidence("fixture-threat", Status.DETECTED)))
        listOf(SampleWorker::class.java, SampleCoroutineWorker::class.java, SampleAsyncWorker::class.java).forEach { type ->
            val id = enqueue(type)
            assertEquals(if (debug) WorkInfo.State.SUCCEEDED else WorkInfo.State.FAILED, terminal(id).state)
            val probe = WorkerProbes.state(id.toString())
            assertTrue("Constructor still runs", probe.constructed.get() >= 1)
            assertEquals(if (debug) 1 else 0, probe.entered.get())
            assertEquals(ProtectionState.RESTRICTED, SecurityGuard.lastObservedState())
        }
    }
    @Test fun restrictionDuringSuspensionDoesNotSkipCancellationCleanup() = controlled("coroutine-cleanup") { base ->
        val id = enqueue(SampleCoroutineWorker::class.java, Data.Builder().putBoolean("wait", true).build())
        val probe = WorkerProbes.state(id.toString())
        await("Coroutine never entered") { probe.entered.get() == 1 }
        assertEquals(0, probe.cleaned.get())
        set(base.copy(evidence = base.evidence + Evidence("fixture-threat", Status.DETECTED)))
        manager.cancelWorkById(id).result.get(5, TimeUnit.SECONDS)
        await("Coroutine finally was skipped") { probe.cleaned.get() == 1 }
        assertEquals(WorkInfo.State.CANCELLED, info(id).state)
        assertEquals(1, probe.entered.get())
    }
    @Test fun unknownAndPendingKeepTheirStateAndHonorExplicitStrictness() = controlled("unknown-pending") { base ->
        val unknown = base.copy(evidence = base.evidence.map {
            if (it.check == "native-engine") it.copy(status = Status.UNAVAILABLE) else it
        })
        val pending = base.copy(evidence = listOf(Evidence("scan-pending", Status.UNAVAILABLE)))
        val scenarios = listOf(
            Triple(unknown, true, ProtectionState.INDETERMINATE),
            Triple(unknown.copy(enforcement = unknown.enforcement.copy(enforceIndeterminate = true)), debug, ProtectionState.INDETERMINATE),
            Triple(pending, true, ProtectionState.CHECKING),
            Triple(pending.copy(enforcement = pending.enforcement.copy(failClosedOnStartup = true)), debug, ProtectionState.CHECKING))
        scenarios.forEach { (snapshot, allowed, state) ->
            set(snapshot)
            val id = enqueue(SampleAsyncWorker::class.java)
            assertEquals(if (allowed) WorkInfo.State.SUCCEEDED else WorkInfo.State.FAILED, terminal(id).state)
            assertEquals(if (allowed) 1 else 0, WorkerProbes.state(id.toString()).entered.get())
            assertEquals(state, SecurityGuard.lastObservedState())
        }
    }
    @Test fun hostRetryRemainsQueuedAfterAnActualAttempt() = controlled("retry") {
        val id = enqueue(SampleWorker::class.java, Data.Builder().putBoolean("retry", true).build())
        await("Host retry was lost or converted to a terminal result") {
            val current = info(id)
            current.state == WorkInfo.State.ENQUEUED && current.runAttemptCount >= 1 &&
                WorkerProbes.state(id.toString()).entered.get() >= 1
        }
        assertFalse(info(id).state.isFinished)
        manager.cancelWorkById(id).result.get(5, TimeUnit.SECONDS)
        await("Owned retry request did not cancel") { info(id).state == WorkInfo.State.CANCELLED }
    }
    @Test fun foregroundEntryChecksFreshEvidenceWithoutBlockingCleanup() = controlled("foreground") { base ->
        listOf(SampleWorker::class.java, SampleCoroutineWorker::class.java).forEach { type ->
            set(base)
            val id = enqueue(type)
            assertEquals(WorkInfo.State.SUCCEEDED, terminal(id).state)
            val worker = requireNotNull(WorkerProbes.instances[id.toString()])
            val probe = WorkerProbes.state(id.toString())
            fun request(allowed: Boolean) {
                val before = probe.foreground.get()
                var future: ListenableFuture<ForegroundInfo>? = null
                var failure: Throwable? = null
                InstrumentationRegistry.getInstrumentation().runOnMainSync {
                    try { future = worker.getForegroundInfoAsync() } catch (error: Throwable) { failure = error }
                }
                if (allowed) {
                    assertNull(failure)
                    assertEquals(37, requireNotNull(future).get(5, TimeUnit.SECONDS).notificationId)
                } else {
                    assertTrue("Denied before future creation", failure is SecurityException)
                    assertNull(future)
                }
                assertEquals(before + if (allowed) 1 else 0, probe.foreground.get())
            }
            request(true)
            set(base.copy(evidence = base.evidence + Evidence("fixture-threat", Status.DETECTED)))
            request(debug)
            assertEquals(ProtectionState.RESTRICTED, SecurityGuard.lastObservedState())
            if (worker is SampleWorker) {
                val before = probe.stopped.get()
                worker.onStopped()
                assertEquals(before + 1, probe.stopped.get())
            }
        }
    }
}
