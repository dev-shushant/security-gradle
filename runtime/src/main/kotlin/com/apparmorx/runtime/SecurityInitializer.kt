package com.apparmorx.runtime

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import android.os.Bundle

/**
 * Non-exported, multiprocess lifecycle initializer.
 * Initializes the process in which Android creates this provider. With multiprocess=true,
 * a query may reach a local clone rather than the primary process. Guarded entries also
 * initialize their own process. Diagnostics from [call] never authorize another process.
 *
 * Authored by Shushant Tiwari • com.apparmorx
 */
class SecurityInitializer : ContentProvider() {
    override fun onCreate(): Boolean {
        context?.let(SecurityRuntime::initialize)
        return true
    }

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle? {
        return when (method) {
            "getSecurityState" -> {
                val snapshot = SecurityRuntime.snapshot()
                val posture = processPosture(snapshot, SecurityGuard.lastObservedState(), System.currentTimeMillis())
                Bundle().apply {
                    putLong("sequence", snapshot.policySequence)
                    putLong("checkedAtMillis", snapshot.checkedAtMillis)
                    putBoolean("isMirageActive", DeceptionEngine.isMirageActive)
                    // Preserve the legacy last-guard field; fresh evidence is explicitly separate.
                    putString("state", posture.lastObservedState.name)
                    putString("stateSource", "last-guard")
                    putString("evidenceState", posture.evidenceState.name)
                    putString("scope", "responding-process")
                    putInt("responderPid", android.os.Process.myPid())
                    putInt("responderUid", android.os.Process.myUid())
                    putString("responderProcess", android.app.Application.getProcessName() ?: "unknown")
                }
            }
            else -> null
        }
    }

    override fun query(uri: Uri, projection: Array<out String>?, selection: String?, selectionArgs: Array<out String>?, sortOrder: String?): Cursor? = null
    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = 0
}
