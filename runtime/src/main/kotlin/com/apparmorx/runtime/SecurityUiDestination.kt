package com.apparmorx.runtime

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import java.lang.reflect.Modifier

/** Presentation routing only. Invalid host configuration retains the bundled blocking UI. */
internal object SecurityUiDestination {
    const val UNAVAILABLE = "com.apparmorx.runtime.CHECK_UNAVAILABLE"

    /** Display reason only: never creates a ticket, changes policy or authorizes resumption. */
    fun forState(context: Context, state: ProtectionState): Intent = intent(context).apply {
        when (blockScreenPresentation(state)) {
            SecurityScreen.CHECKING -> putExtra(StartupLaunches.PENDING, true)
            SecurityScreen.UNAVAILABLE -> putExtra(UNAVAILABLE, true)
            SecurityScreen.RESTRICTED -> Unit
        }
    }

    const val META_ACTIVITY = "com.apparmorx.security.BLOCK_ACTIVITY"

    @Suppress("DEPRECATION")
    fun intent(context: Context): Intent {
        val fallback = Intent(context, SecurityBlockActivity::class.java)
        return runCatching {
            val metadata = context.packageManager.getApplicationInfo(context.packageName, PackageManager.GET_META_DATA).metaData
            val configured = metadata?.getString(META_ACTIVITY)?.trim().orEmpty()
            if (configured.isEmpty()) return fallback
            val name = if (configured.startsWith('.')) context.packageName + configured else configured
            val type = Class.forName(name, false, context.classLoader)
            if (!SecurityBlockActivity::class.java.isAssignableFrom(type) || Modifier.isAbstract(type.modifiers) ||
                !Modifier.isPublic(type.modifiers) || !Modifier.isPublic(type.getConstructor().modifiers)) return fallback
            val component = ComponentName(context.packageName, name)
            val info = context.packageManager.getActivityInfo(component, 0)
            if (!info.enabled || !info.applicationInfo.enabled || info.exported ||
                info.applicationInfo.uid != context.applicationInfo.uid) return fallback
            Intent().setComponent(component)
        }.getOrDefault(fallback)
    }
}
