package com.apparmorx.runtime

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import android.os.Bundle

/**
 * Non-exported, multiprocess lifecycle initializer.
 * Automatically initializes AppArmorX across all application processes (main, :auth, :sandbox).
 * Supports inter-process posture queries via [call] without external IPC overhead.
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
                Bundle().apply {
                    putLong("sequence", snapshot.policySequence)
                    putLong("checkedAtMillis", snapshot.checkedAtMillis)
                    putBoolean("isMirageActive", DeceptionEngine.isMirageActive)
                    putString("state", SecurityGuard.lastObservedState().name)
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
