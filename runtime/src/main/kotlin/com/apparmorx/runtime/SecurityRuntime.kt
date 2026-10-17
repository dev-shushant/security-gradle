package com.apparmorx.runtime

import android.app.Activity
import android.app.Application
import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import java.util.Collections
import java.util.WeakHashMap
import android.os.SystemClock
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import android.os.Build
import android.net.Uri
import java.io.File

/**
 * Process-scoped observation runtime. Initialization is automatic in the main process through the provider.
 * Snapshots are thread-safe. No result is an authorization decision; hosts define their own responses.
 */
object SecurityRuntime {
    private const val MIN_SCAN_INTERVAL_MS = 30000L
    private val main = Handler(Looper.getMainLooper())
    // Accessed only on the main thread; paused/destroyed activities are removed explicitly.
    private val resumed = Collections.newSetFromMap(WeakHashMap<Activity, Boolean>())
    private val monitor = ForegroundMonitor(
        schedule = { tick -> main.postDelayed({ tick() }, MIN_SCAN_INTERVAL_MS) },
        refresh = { refresh() },
    )
    private val initialized = AtomicBoolean(false)
    private val scanning = AtomicBoolean(false)
    private val executor = Executors.newSingleThreadExecutor { runnable -> Thread(runnable, "AppArmorX-scan").apply { isDaemon = true } }
    @Volatile private var current = SecuritySnapshot(0, 0, emptyList())
    @Volatile private var application: Context? = null
    @Volatile private var lastScanElapsed = -MIN_SCAN_INTERVAL_MS

    /** @return most recently completed evidence; checkedAtMillis=0 means pending/uninitialized. */
    fun snapshot(): SecuritySnapshot = current

    private fun isDebuggableBuild(context: Context): Boolean = try {
        context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
    } catch (_: Exception) { true } // can't tell -> assume debuggable, never harden on an unknown state

    /**
     * Schedules a refresh, coalescing concurrent requests and throttling to once per 30 seconds.
     * @return true if a scan was scheduled; false if uninitialized, throttled or already running.
     */
    fun refresh(): Boolean {
        val context = application ?: return false
        if (!scanning.compareAndSet(false, true)) return false
        if (SystemClock.elapsedRealtime() - lastScanElapsed < MIN_SCAN_INTERVAL_MS) {
            scanning.set(false)
            return false
        }
        executor.execute {
            try {
                current = RuntimeScanner.scan(context)
                lastScanElapsed = SystemClock.elapsedRealtime()
                TelemetryDispatcher.dispatchIfDetected(context, current)
                main.post {
                    resumed.toList().forEach { activity ->
                        if (!activity.isFinishing && !activity.isDestroyed) SecurityGuard.evaluateActivity(activity)
                    }
                }
            } finally { scanning.set(false) }
        }
        return true
    }

    /**
     * Applies UI protection flags (FLAG_SECURE, filterTouchesWhenObscured) if configured by policy.
     */
    fun applyUiProtection(activity: Activity) {
        val snapshot = current
        if (snapshot.secureScreen) {
            activity.window?.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        }
        if (snapshot.filterTouches) {
            activity.window?.decorView?.filterTouchesWhenObscured = true
        }
    }

    /**
     * Idempotent process initialization. Useful if automatic initialization is removed from the manifest.
     * @param context application context; Activity references are not retained.
     */
    fun initialize(context: Context) {
        if (!initialized.compareAndSet(false, true)) return
        application = context.applicationContext
        try {
            current = RuntimeScanner.fastPreflight(context)
        } catch (_: Exception) {}
        // As early as this process can realistically do it: before the activity lifecycle callbacks
        // below are even registered. Never on a debuggable build -- checked here too, defense in
        // depth, even though the build-time policy already forces this false for debuggable variants
        // (see ProtectionProfile.resolve): this would otherwise fight the developer's own debugger.
        if (current.enforcement.antiPtraceHardening && !isDebuggableBuild(context)) {
            try { NativeEngine.hardenAgainstPtraceAttach() } catch (_: Exception) {}
        }
        // Fast, Activity-lifecycle-independent watchdog for killOnConfirmedHooking -- see
        // HookWatchdog's kdoc for exactly why this is separate from the 30s-throttled full scan below.
        HookWatchdog.start(current.enforcement, isDebuggableBuild(context))
        (application as? Application)?.registerActivityLifecycleCallbacks(object : Application.ActivityLifecycleCallbacks {
            override fun onActivityResumed(activity: Activity) {
                if (activity is SecurityBlockActivity) return
                resumed.add(activity)
                monitor.start()
                SecurityGuard.evaluateActivity(activity)
            }
            override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) = Unit
            override fun onActivityStarted(activity: Activity) = Unit
            override fun onActivityPaused(activity: Activity) {
                resumed.remove(activity)
                if (resumed.isEmpty()) monitor.stop()
            }
            override fun onActivityStopped(activity: Activity) = Unit
            override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) = Unit
            override fun onActivityDestroyed(activity: Activity) {
                resumed.remove(activity)
                if (resumed.isEmpty()) monitor.stop()
            }
        })
        refresh()
    }

    /**
     * Resolves the current Linux process name for the calling component.
     */
    fun currentProcessName(context: Context): String {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            return Application.getProcessName()
        }
        return try {
            File("/proc/self/cmdline").readText().trim().trim { it <= ' ' || it == '\u0000' }
        } catch (_: Exception) {
            context.packageName
        }
    }

    /**
     * Synchronizes security posture from the primary process if running in a secondary process.
     * Prevents scanning storms and ensures unified security enforcement.
     */
    fun syncFromPrimaryProcess(context: Context): Boolean {
        val processName = currentProcessName(context)
        if (processName == context.packageName) return false // Already in primary process

        return try {
            val authority = "${context.packageName}.apparmorx.init"
            val uri = Uri.parse("content://$authority")
            val bundle = context.contentResolver.call(uri, "getSecurityState", null, null)
            if (bundle != null) {
                val isMirage = bundle.getBoolean("isMirageActive", false)
                if (isMirage) {
                    DeceptionEngine.injectJitter()
                }
                true
            } else {
                false
            }
        } catch (_: Exception) {
            false
        }
    }
}
