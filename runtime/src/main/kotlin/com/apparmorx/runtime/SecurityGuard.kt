package com.apparmorx.runtime

import android.app.Activity
import android.app.Application
import android.app.Service
import android.content.Context
import android.content.ContentProvider
import android.util.Log
import java.util.concurrent.atomic.AtomicReference

private const val TAG = "AppArmorX"

/** Evidence every guarded lifecycle call re-checks before reporting [ProtectionState]. */
internal val REQUIRED_EVIDENCE = setOf("policy", "signing-certificate", "native-engine")

/**
 * Entry point the AppArmorX Gradle plugin's bytecode instrumentation calls automatically from every
 * guarded component lifecycle method:
 * - Activity: `onCreate`, `onStart`, `onResume`
 * - Application: `onCreate`
 * - Service project callbacks: `onCreate`, `onStartCommand`, `onBind`, `onRebind`, legacy `onStart`
 * - BroadcastReceiver: `onReceive`
 * - ContentProvider: supported declared query/write/call/file/batch operations (not initialization)
 * - WorkManager: supported non-suspending worker/foreground entries (not coroutine resumes or cleanup)
 *
 * Consumer code must never call this directly, and applying the plugin requires no host-written
 * detection or wiring code.
 */
object SecurityGuard {
    private val last = AtomicReference(ProtectionState.CHECKING)

    /** Injected Activity lifecycle call site. */
    @JvmStatic
    fun allowActivity(activity: Activity): Boolean {
        SecurityRuntime.initialize(activity.applicationContext)
        SecurityRuntime.applyUiProtection(activity)
        val proceed = evaluateActivity(activity)
        SecurityRuntime.refresh()
        return proceed
    }

    /** Injected Application lifecycle call site. */
    @JvmStatic
    fun allowApplication(application: Application): Boolean {
        SecurityRuntime.initialize(application.applicationContext)
        SecurityRuntime.syncFromPrimaryProcess(application)
        // Android cannot replay Application.onCreate after deferral. Permit initialization
        // while pending; confirmed threats and completed indeterminate policy still apply.
        val proceed = evaluateComponent(application, startupGateApplies = false)
        applicationInitialization.recordDecision(proceed)
        SecurityRuntime.refresh()
        return proceed
    }

    /** Injected Service callback gate. Stops a started service on denial; cannot revoke issued Binder handles. */
    @JvmStatic
    fun allowService(service: Service): Boolean {
        val app = runCatching { service.applicationContext }.getOrNull()
        if (app != null) {
            SecurityRuntime.initialize(app)
        }
        SecurityRuntime.syncFromPrimaryProcess(app ?: service)
        val proceed = evaluateComponent(app ?: service)
        SecurityRuntime.refresh()
        if (!proceed) {
            runCatching { service.stopSelf() }
        }
        return proceed
    }

    /** Injected BroadcastReceiver lifecycle call site. */
    @JvmStatic
    fun allowReceiver(context: Context): Boolean {
        val app = runCatching { context.applicationContext }.getOrNull() ?: context
        SecurityRuntime.initialize(app)
        SecurityRuntime.syncFromPrimaryProcess(app)
        val proceed = evaluateComponent(app)
        SecurityRuntime.refresh()
        return proceed
    }

    /** Entry gate for supported declared provider operations; no UI launch or provider initialization deferral. */
    @JvmStatic
    fun allowProvider(provider: ContentProvider): Boolean {
        val context = runCatching { provider.context }.getOrNull()
        if (context == null) {
            last.set(ProtectionState.INDETERMINATE)
            return false // Unattached provider has no trustworthy build identity/policy; never report CLEAR.
        }
        val app = context.applicationContext ?: context
        SecurityRuntime.initialize(app)
        // Local evidence only. The primary-process hint channel does not import an authenticated verdict.
        val proceed = evaluateComponent(app)
        SecurityRuntime.refresh()
        return proceed
    }

    /** Worker entry evaluation without a WorkManager dependency in the runtime artifact. */
    @JvmStatic
    fun allowWorker(context: Context): Boolean {
        val app = context.applicationContext ?: context
        SecurityRuntime.initialize(app)
        val proceed = evaluateComponent(app)
        SecurityRuntime.refresh()
        return proceed
    }

    /** Applies newly completed evidence without scheduling another scan. Main thread only. */
    internal fun evaluateActivity(activity: Activity): Boolean {
        if (activity is SecurityBlockActivity || activity.isFinishing || activity.isDestroyed) return true
        if (applicationInitialization.requiresRestart()) {
            last.set(ProtectionState.INDETERMINATE)
            activity.startActivity(SecurityUiDestination.forState(activity, ProtectionState.INDETERMINATE))
            activity.finish()
            return false
        }
        val snapshot = SecurityRuntime.snapshot()
        val state = decideProtection(snapshot, System.currentTimeMillis(), REQUIRED_EVIDENCE)
        last.set(state)
        return EnforcementResponse.apply(activity, state, snapshot.enforcement, snapshot.evidence)
    }

    /** Evaluates non-Activity components (Application, Service, BroadcastReceiver). */
    internal fun evaluateComponent(context: Context, startupGateApplies: Boolean = true): Boolean {
        if (applicationInitialization.requiresRestart()) {
            last.set(ProtectionState.INDETERMINATE)
            return false
        }
        val snapshot = SecurityRuntime.snapshot()
        val state = decideProtection(snapshot, System.currentTimeMillis(), REQUIRED_EVIDENCE)
        last.set(state)
        // See EnforcementResponse.apply's matching check: same opt-in, narrowly-scoped exception to
        // "no automatic process termination" (AGENTS.md), applied here too since Application/Service/
        // BroadcastReceiver guards never go through EnforcementResponse.
        val debuggable = context.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE != 0
        if (shouldKillOnConfirmedHooking(snapshot.evidence, snapshot.enforcement, debuggable)) {
            android.util.Log.w(TAG, "Confirmed hooking evidence; killOnConfirmedHooking is enabled, terminating process")
            android.os.Process.killProcess(android.os.Process.myPid())
            return false
        }
        return when (resolveEnforcementAction(state, snapshot.enforcement, debuggable, startupGateApplies)) {
            EnforcementAction.OBSERVE -> true
            EnforcementAction.WARN -> {
                Log.w(TAG, "Guarded component ${context.javaClass.name} observed protection state $state")
                true
            }
            EnforcementAction.MIRAGE -> {
                DeceptionEngine.injectJitter()
                true
            }
            EnforcementAction.BLOCK_SCREEN, EnforcementAction.TERMINATE -> false
        }
    }

    /** Protection state as of the most recent guarded lifecycle call. Never an authorization decision. */
    fun lastObservedState(): ProtectionState = last.get()
}
