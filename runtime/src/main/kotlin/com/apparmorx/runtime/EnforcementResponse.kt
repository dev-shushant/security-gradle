package com.apparmorx.runtime

import android.app.Activity
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.os.Process
import android.util.Log

private const val TAG = "AppArmorX"

/**
 * Applies [resolveEnforcementAction]'s decision to a guarded activity. This is the only part of the
 * enforcement path that touches Android APIs; the decision itself ([resolveEnforcementAction]) is
 * pure and unit tested. Must run on the activity's own thread (guarded lifecycle methods already are
 * the UI thread, so this never hops threads).
 *
 * @return true if the guarded method should continue running its own body; false if this response
 *   already redirected away from or is closing the activity, so the instrumented call site skips the
 *   rest of the original method (see [com.apparmorx.gradle.GuardVisitor] on the plugin side) instead
 *   of racing pointless work — like a real screen still calling `setContentView`, whose views are not
 *   guaranteed to reach the user — against a teardown already in flight.
 */
internal object EnforcementResponse {
    fun apply(activity: Activity, state: ProtectionState, policy: EnforcementPolicy, evidence: List<Evidence>): Boolean {
        if (activity is SecurityBlockActivity) return true
        // Opt-in, narrowly-scoped exception to this project's default "no automatic process
        // termination" rule -- see AGENTS.md and shouldKillOnConfirmedHooking's kdoc for the exact
        // carve-out and its documented limit (it cannot stop the action already in flight when
        // detection fires, only further activity in the same process). Takes priority over whatever
        // restrictedAction says: a confirmed-hooking kill is a stronger response than any of
        // OBSERVE/WARN/MIRAGE/BLOCK_SCREEN/TERMINATE, so it is not gated behind resolveEnforcementAction.
        val debuggable = activity.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
        if (shouldKillOnConfirmedHooking(evidence, policy, debuggable)) {
            Log.w(TAG, "Confirmed hooking evidence; killOnConfirmedHooking is enabled, terminating process")
            Process.killProcess(Process.myPid())
            return false
        }
        return when (resolveEnforcementAction(state, policy)) {
            EnforcementAction.OBSERVE -> true
            EnforcementAction.WARN -> {
                Log.w(TAG, "Guarded activity ${activity.javaClass.name} observed protection state $state")
                true
            }
            EnforcementAction.BLOCK_SCREEN -> {
                activity.startActivity(Intent(activity, SecurityBlockActivity::class.java))
                activity.finish()
                false
            }
            // finishAffinity() closes this app's task cleanly rather than killing the process
            // mid-write; a blunt Process.killProcess can corrupt in-flight disk/database state.
            EnforcementAction.TERMINATE -> {
                activity.finishAffinity()
                false
            }
            EnforcementAction.MIRAGE -> {
                DeceptionEngine.injectJitter()
                Log.i(TAG, "Mirage active for guarded activity ${activity.javaClass.name}")
                true
            }
        }
    }
}
