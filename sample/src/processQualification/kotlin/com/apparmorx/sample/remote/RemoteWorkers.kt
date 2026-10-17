package com.apparmorx.sample.remote

import android.content.Context
import android.os.Process
import androidx.work.Data
import androidx.work.WorkerParameters
import androidx.work.multiprocess.RemoteCoroutineWorker
import androidx.work.multiprocess.RemoteListenableWorker
import com.google.common.util.concurrent.ListenableFuture
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.delay
import java.util.concurrent.CompletableFuture
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit

class RemoteProbe {
    val constructed = AtomicInteger()
    val entered = AtomicInteger()
    val cleaned = AtomicInteger()
    val stopCallbacks = AtomicInteger()
    val cancelRequests = AtomicInteger()
    val cancelPaths = java.util.concurrent.ConcurrentLinkedQueue<String>()
    val interruptRequests = AtomicInteger()
    val futureCancelled = AtomicBoolean()

}
object RemoteWorkerProbes {
    private val states = ConcurrentHashMap<String, RemoteProbe>()
    val instances = ConcurrentHashMap<String, androidx.work.ListenableWorker>()
    fun state(id: String): RemoteProbe = states.computeIfAbsent(id) { RemoteProbe() }
}
private fun output() = Data.Builder().putInt("remotePid", Process.myPid())
    .putString("marker", "AppArmorX remote worker body").build()

private class CompletedRemoteFuture(private val result: androidx.work.ListenableWorker.Result) : ListenableFuture<androidx.work.ListenableWorker.Result> {
    override fun addListener(listener: Runnable, executor: Executor) { executor.execute(listener) }
    override fun get() = result
    override fun get(timeout: Long, unit: TimeUnit) = result
    override fun isDone() = true
    override fun isCancelled() = false
    override fun cancel(mayInterruptIfRunning: Boolean) = false
}

/** A genuinely pending asynchronous result; cleanup belongs to its cancellation, not onStopped. */
private class PendingRemoteFuture(private val probe: RemoteProbe) : CompletableFuture<androidx.work.ListenableWorker.Result>(), ListenableFuture<androidx.work.ListenableWorker.Result> {
    override fun addListener(listener: Runnable, executor: Executor) { whenComplete { _, _ -> executor.execute(listener) } }
    override fun cancel(mayInterruptIfRunning: Boolean): Boolean {
        probe.cancelRequests.incrementAndGet()
        probe.cancelPaths.add(Throwable().stackTrace.filter {
            it.className.startsWith("androidx.work.") || it.className == "com.apparmorx.runtime.RemoteWorkerCancellation"
        }.take(4).joinToString(" > ") { it.className + "." + it.methodName })
        if (mayInterruptIfRunning) probe.interruptRequests.incrementAndGet()
        val result = super.cancel(mayInterruptIfRunning)
        if (isCancelled && probe.futureCancelled.compareAndSet(false, true)) probe.cleaned.incrementAndGet()
        return result
    }
}

/** Qualification-only workers contain no SDK runtime calls. */
class RemoteAsyncProbeWorker(context: Context, params: WorkerParameters) : RemoteListenableWorker(context, params) {
    init { RemoteWorkerProbes.state(id.toString()).constructed.incrementAndGet(); RemoteWorkerProbes.instances[id.toString()] = this }
    override fun startRemoteWork(): ListenableFuture<Result> {
        val probe = RemoteWorkerProbes.state(id.toString())
        probe.entered.incrementAndGet()
        return if (inputData.getBoolean("wait", false)) PendingRemoteFuture(probe)
            else CompletedRemoteFuture(Result.success(output()))
    }
    override fun onStopped() {
        // Deliberately omit super: framework stop compatibility must preserve host callbacks
        // and must not depend on a host override delegating to its parent.
        RemoteWorkerProbes.state(id.toString()).stopCallbacks.incrementAndGet()
    }
}
class RemoteCoroutineProbeWorker(context: Context, params: WorkerParameters) : RemoteCoroutineWorker(context, params) {
    init { RemoteWorkerProbes.state(id.toString()).constructed.incrementAndGet(); RemoteWorkerProbes.instances[id.toString()] = this }
    override suspend fun doRemoteWork(): Result {
        val probe = RemoteWorkerProbes.state(id.toString())
        probe.entered.incrementAndGet()
        try {
            if (inputData.getBoolean("wait", false)) awaitCancellation()
            delay(25)
            return Result.success(output())
        } finally { probe.cleaned.incrementAndGet() }
    }
}
