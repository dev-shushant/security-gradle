package com.apparmorx.sample.work

import android.app.Notification
import android.content.Context
import androidx.work.*
import com.google.common.util.concurrent.ListenableFuture
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.delay
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/** Sample-only counters; fixture workers contain no manual AppArmorX runtime calls. */
class WorkerProbe {
    @JvmField val constructed = AtomicInteger()
    @JvmField val entered = AtomicInteger()
    @JvmField val cleaned = AtomicInteger()
    @JvmField val stopped = AtomicInteger()
    @JvmField val foreground = AtomicInteger()
}
object WorkerProbes {
    @JvmField val states = ConcurrentHashMap<String, WorkerProbe>()
    @JvmField val instances = ConcurrentHashMap<String, ListenableWorker>()
    fun state(id: String): WorkerProbe = states.getOrPut(id) { WorkerProbe() }
    fun register(worker: ListenableWorker) {
        state(worker.id.toString()).constructed.incrementAndGet()
        instances[worker.id.toString()] = worker
    }
}
private fun foreground(context: Context): ForegroundInfo = ForegroundInfo(37,
    Notification.Builder(context, "apparmorx.fixture.worker").setSmallIcon(android.R.drawable.ic_lock_lock)
        .setContentTitle("AppArmorX worker fixture").build())
private fun output(): Data = Data.Builder().putString("marker", "AppArmorX worker body").build()

class SampleWorker(context: Context, params: WorkerParameters) : Worker(context, params) {
    init { WorkerProbes.register(this) }
    override fun doWork(): Result {
        WorkerProbes.state(id.toString()).entered.incrementAndGet()
        return if (inputData.getBoolean("retry", false)) Result.retry() else Result.success(output())
    }
    override fun getForegroundInfo(): ForegroundInfo {
        WorkerProbes.state(id.toString()).foreground.incrementAndGet()
        return foreground(applicationContext)
    }
    override fun onStopped() { WorkerProbes.state(id.toString()).stopped.incrementAndGet(); super.onStopped() }
}

class SampleCoroutineWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    init { WorkerProbes.register(this) }
    override suspend fun doWork(): Result {
        val probe = WorkerProbes.state(id.toString())
        probe.entered.incrementAndGet()
        try {
            if (inputData.getBoolean("wait", false)) awaitCancellation()
            delay(25)
            return Result.success(output())
        } finally { probe.cleaned.incrementAndGet() }
    }
    override suspend fun getForegroundInfo(): ForegroundInfo {
        WorkerProbes.state(id.toString()).foreground.incrementAndGet()
        delay(25)
        return foreground(applicationContext)
    }
}

/** Completed future belongs only to this fixture; the SDK does not depend on Guava/WorkManager. */
private class FixtureFuture(private val result: ListenableWorker.Result) : ListenableFuture<ListenableWorker.Result> {
    override fun addListener(listener: Runnable, executor: Executor) { executor.execute(listener) }
    override fun get(): ListenableWorker.Result = result
    override fun get(timeout: Long, unit: TimeUnit): ListenableWorker.Result = result
    override fun cancel(mayInterruptIfRunning: Boolean): Boolean = false
    override fun isCancelled(): Boolean = false
    override fun isDone(): Boolean = true
}
class SampleAsyncWorker(context: Context, params: WorkerParameters) : ListenableWorker(context, params) {
    init { WorkerProbes.register(this) }
    override fun startWork(): ListenableFuture<Result> {
        WorkerProbes.state(id.toString()).entered.incrementAndGet()
        return FixtureFuture(Result.success(output()))
    }
}
