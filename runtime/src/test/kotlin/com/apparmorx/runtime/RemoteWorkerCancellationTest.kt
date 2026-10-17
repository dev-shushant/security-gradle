package com.apparmorx.runtime

import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.FutureTask
import java.util.concurrent.atomic.AtomicInteger

/** No WorkManager/Guava dependency: only the actual returned Java Future is cancelled. */
class RemoteWorkerCancellationTest {
    private fun bridge(name: String, vararg values: Any) {
        val type = Class.forName("com.apparmorx.runtime.RemoteWorkerCancellation")
        val params = if (name == "track") arrayOf(Any::class.java, java.util.concurrent.Future::class.java) else arrayOf(Any::class.java)
        type.getMethod(name, *params).invoke(null, *values)
    }
    private fun track(worker: Any, future: java.util.concurrent.Future<*>) = bridge("track", worker, future)
    private fun stop(worker: Any) = bridge("stopped", worker)
    private open class Owner : RemoteWorkerCancellationOwner {
        private var state: Any? = null
        override fun appArmorXGetRemoteCancellationState() = state
        override fun appArmorXSetRemoteCancellationState(state: Any?) { this.state = state }
    }
    private class EqualWorker : Owner() { override fun equals(other: Any?) = other is EqualWorker; override fun hashCode() = 1 }
    @Test fun stoppingOneWorkerCancelsOnlyItsActualReturnedFuture() {
        val a=EqualWorker(); val b=EqualWorker(); val fa=FutureTask { 1 }; val fb=FutureTask { 2 }
        track(a,fa);track(b,fb);stop(a)
        assertTrue(fa.isCancelled);assertFalse(fb.isCancelled);stop(b)
    }
    @Test fun completedResultsAreNotReplacedOrReexecuted() {
        val worker=Owner();val count=AtomicInteger();val future=FutureTask { count.incrementAndGet();42 }
        future.run();track(worker,future);stop(worker)
        assertFalse(future.isCancelled);assertEquals(42,future.get());assertEquals(1,count.get())
    }
    @Test fun repeatedStopsDoNotRepeatCancellationOrInterruptThreads() {
        val worker=Owner();val calls=AtomicInteger()
        val future=object:FutureTask<Int>({ 1 }) { override fun cancel(interrupt:Boolean):Boolean { assertFalse(interrupt);calls.incrementAndGet();return super.cancel(interrupt) } }
        track(worker,future);track(worker,future);stop(worker);stop(worker)
        assertEquals(1,calls.get())
    }
    @Test fun allDistinctReturnedFuturesForSameWorkerAreCancelled() {
        val worker=Owner();val a=FutureTask { 1 };val b=FutureTask { 2 }
        track(worker,a);track(worker,b);stop(worker);assertTrue(a.isCancelled);assertTrue(b.isCancelled)
    }
    @Test fun stopBeforeRegistrationIsHandledByPostRegistrationStoppedCheck() {
        val worker=Owner();stop(worker);val future=FutureTask { 1 };track(worker,future)
        // Woven code rechecks the framework's authoritative isStopped after registration.
        stop(worker);assertTrue(future.isCancelled)
    }
    @Test fun unknownWorkerStopDoesNotCancelOthers() {
        val worker=Owner();val future=FutureTask { 1 };track(worker,future);stop(Any())
        assertFalse(future.isCancelled);stop(worker)
    }
    @Test fun cancellationFailureDoesNotSkipOtherFutureOrBreakStopCallback() {
        val worker=Owner();val bad=object:FutureTask<Int>({ 1 }) { override fun cancel(interrupt:Boolean):Boolean { throw IllegalStateException("fixture") } }
        val good=FutureTask { 2 };track(worker,bad);track(worker,good);stop(worker);assertTrue(good.isCancelled)
    }
    @Test fun registrationRacingStopNeverLosesCancellation() {
        repeat(100) {
            val worker=Owner();val future=FutureTask { 1 }
            val stopped=java.util.concurrent.atomic.AtomicBoolean()
            val start=java.util.concurrent.CountDownLatch(1)
            val executor=java.util.concurrent.Executors.newFixedThreadPool(2)
            try {
                val registration=executor.submit { start.await();track(worker,future);if(stopped.get()) stop(worker) }
                val stopping=executor.submit { start.await();stopped.set(true);stop(worker) }
                start.countDown();registration.get(5,java.util.concurrent.TimeUnit.SECONDS);stopping.get(5,java.util.concurrent.TimeUnit.SECONDS)
                assertTrue("Stop/registration race lost cancellation",future.isCancelled)
            } finally { executor.shutdownNow() }
        }
    }

    private fun weakTrackedFuture(worker: Any): java.lang.ref.WeakReference<FutureTask<Int>> {
        val future=FutureTask { 1 };track(worker,future)
        return java.lang.ref.WeakReference(future)
    }
    private fun gcSentinel() = java.lang.ref.WeakReference(Any())
    @Test fun liveWorkerKeepsItsPendingCancellationFutureReachable() {
        val worker=Owner()
        val future=weakTrackedFuture(worker)
        val sentinel=gcSentinel()
        try {
            val deadline=System.nanoTime()+3_000_000_000L
            while(sentinel.get()!=null && System.nanoTime()<deadline) { System.gc();Thread.sleep(10) }
            assertNull("GC control was not collected; ownership probe is inconclusive",sentinel.get())
            assertNotNull("Pending Future was collected while its worker was still strongly reachable",future.get())
        } finally { stop(worker) }
    }

    @Test fun stoppedOwnerReleasesItsFutureEvenIfOwnerRemainsLive() {
        val worker=Owner();val future=weakTrackedFuture(worker)
        stop(worker)
        repeat(20) { System.gc();Thread.sleep(10) }
        assertNull("Stopped owner retained its Future",future.get())
        assertNull(worker.appArmorXGetRemoteCancellationState())
    }
    private fun abandonedCycle(): Pair<java.lang.ref.WeakReference<Owner>, java.lang.ref.WeakReference<FutureTask<Int>>> {
        val worker=Owner();val future=FutureTask { worker.hashCode() }
        track(worker,future)
        return java.lang.ref.WeakReference(worker) to java.lang.ref.WeakReference(future)
    }
    @Test fun abandonedWorkerFutureCycleHasNoGlobalStrongRoot() {
        val refs=abandonedCycle()
        repeat(20) { System.gc();Thread.sleep(10) }
        assertNull("Global state retained abandoned owner",refs.first.get())
        assertNull("Global state retained abandoned Future",refs.second.get())
    }

}
