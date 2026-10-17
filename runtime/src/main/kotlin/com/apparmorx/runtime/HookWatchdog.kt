package com.apparmorx.runtime

import android.os.Process
import android.util.Log
import java.util.concurrent.atomic.AtomicBoolean

private const val TAG = "AppArmorX"

/**
 * Dedicated fast poll loop for the `killOnConfirmedHooking` policy (see [shouldKillOnConfirmedHooking]
 * for the exact decision and AGENTS.md for the exception this implements), decoupled from the full
 * scan cycle on purpose:
 *
 * - The full scan (`RuntimeScanner.scan`) is throttled to once every 30s
 *   ([SecurityRuntime.MIN_SCAN_INTERVAL_MS]) and only resumes while some guarded Activity is actually
 *   resumed -- see [SecurityRuntime]'s `resumed` tracking. A host whose only guarded component is one
 *   Activity, with `restrictedAction` already finishing it, gets no further re-evaluation at all once
 *   that happens.
 * - This watchdog runs independently of both: once started, it keeps polling for as long as the
 *   process is alive, with no dependency on any Activity's lifecycle state.
 * - It intentionally checks only the native engine's own probes ([NativeEngine.scan]: `native-frida-port`,
 *   `native-tool-thread`, `native-hook-trampoline`, `native-stealth-injection`, plus the two others
 *   `NativeEngine.scan` also returns) -- never the heavier Kotlin-side probes (APK integrity hashing,
 *   policy reload, `hook-classes`/`hook-library`'s own `/proc/self/maps` read), which are too costly to
 *   repeat every [POLL_INTERVAL_MS]. Those two Kotlin-side hooking checks are still covered by the
 *   normal 30s scan cycle; this watchdog narrows the window for the four native ones only.
 *
 * Honest tradeoff, state it everywhere this is described: polling every ~750ms instead of every 30s
 * meaningfully narrows -- but, per [shouldKillOnConfirmedHooking]'s own documented limit, can never
 * guarantee it eliminates -- the gap between an attacker's tool attaching and this process reacting to
 * it. It also has a real, continuous CPU/battery cost for as long as the process lives: that is the
 * explicit, accepted price of the faster reaction, which is exactly why this only starts when the host
 * opted into `killOnConfirmedHooking` -- never unconditionally, never as a profile default.
 */
internal object HookWatchdog {
    private const val POLL_INTERVAL_MS = 750L
    private val started = AtomicBoolean(false)

    /** Idempotent: a second call while already running is a no-op. Never call this on a debuggable build. */
    fun start(policy: EnforcementPolicy, debuggable: Boolean) {
        if (!policy.killOnConfirmedHooking || debuggable) return
        if (!started.compareAndSet(false, true)) return
        val thread = Thread({ loop(policy, debuggable) }, "AppArmorX-hook-watchdog")
        thread.isDaemon = true
        thread.start()
    }

    private fun loop(policy: EnforcementPolicy, debuggable: Boolean) {
        while (true) {
            try {
                val evidence = NativeEngine.scan()
                if (shouldKillOnConfirmedHooking(evidence, policy, debuggable)) {
                    Log.w(TAG, "Confirmed hooking evidence (fast watchdog); killOnConfirmedHooking is enabled, terminating process")
                    Process.killProcess(Process.myPid())
                    return
                }
            } catch (_: Exception) {
                // A probe failure here must never crash the watchdog thread itself -- next iteration retries.
            }
            try {
                Thread.sleep(POLL_INTERVAL_MS)
            } catch (_: InterruptedException) {
                return
            }
        }
    }
}
