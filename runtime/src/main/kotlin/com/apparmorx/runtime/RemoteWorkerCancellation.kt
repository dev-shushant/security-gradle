package com.apparmorx.runtime

import android.util.Log
import java.util.concurrent.Future

/** Worker-owned cancellation state: no global worker/Future roots, timers or WorkManager linkage. */
object RemoteWorkerCancellation {
    private class State { val futures = mutableListOf<Future<*>>() }

    @JvmStatic fun track(worker: Any, future: Future<*>) {
        if (worker !is RemoteWorkerCancellationOwner) {
            Log.w("AppArmorX", "Remote worker ownership instrumentation is unavailable")
            return
        }
        synchronized(worker) {
            val state = worker.appArmorXGetRemoteCancellationState() as? State
                ?: State().also { worker.appArmorXSetRemoteCancellationState(it) }
            if (state.futures.none { it === future }) state.futures.add(future)
        }
        // The woven caller rechecks authoritative isStopped after registration to close the race.
    }

    @JvmStatic fun stopped(worker: Any) {
        if (worker !is RemoteWorkerCancellationOwner) return
        val futures = synchronized(worker) {
            val state = worker.appArmorXGetRemoteCancellationState() as? State
            worker.appArmorXSetRemoteCancellationState(null)
            state?.futures?.toList() ?: emptyList()
        }
        // Never invoke arbitrary Future code under the ownership lock. Cancellation stays cooperative.
        for (future in futures) {
            try { future.cancel(false) }
            catch (_: RuntimeException) { Log.w("AppArmorX", "Remote worker future rejected cancellation") }
        }
    }
}
