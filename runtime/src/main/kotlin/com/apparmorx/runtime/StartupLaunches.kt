package com.apparmorx.runtime

import android.app.Activity
import android.content.Context
import android.content.Intent

/** Non-exported recovery UI receives only an opaque process-local capability, never a supplied target. */
internal object StartupLaunches {
    const val PENDING = "com.apparmorx.runtime.STARTUP_PENDING"
    const val TICKET = "com.apparmorx.runtime.STARTUP_TICKET"
    private val tickets = ExpiringTickets<Intent>()

    fun prepare(activity: Activity): Intent {
        check(!applicationInitialization.requiresRestart()) { "Application initialization requires a new process" }
        val original = Intent(activity.intent ?: Intent())
        original.selector = null
        if (original.component?.packageName != activity.packageName) original.component = activity.componentName
        original.setPackage(activity.packageName)
        require(validTarget(activity, original)) { "No owned startup target" }
        val token = tickets.issue(original)
        return SecurityUiDestination.intent(activity)
            .putExtra(PENDING, true).putExtra(TICKET, token).apply {
                // Retain only grants the existing launch carried, through the same-app waiting UI.
                clipData = original.clipData
                setDataAndType(original.data, original.type)
                addFlags(original.flags and (Intent.FLAG_GRANT_READ_URI_PERMISSION or
                    Intent.FLAG_GRANT_WRITE_URI_PERMISSION or Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION or
                    Intent.FLAG_GRANT_PREFIX_URI_PERMISSION))
            }
    }
    fun isValid(token: String?): Boolean = !applicationInitialization.requiresRestart() && token != null && tickets.isValid(token)
    fun revoke(token: String?) { if (token != null) tickets.revoke(token) }
    fun consume(context: Context, token: String?): Intent? {
        if (token == null) return null
        val target = tickets.consume(token) ?: return null
        if (applicationInitialization.requiresRestart()) return null
        return target.takeIf { validTarget(context, it) }
    }
    @Suppress("DEPRECATION")
    private fun validTarget(context: Context, intent: Intent): Boolean {
        val component = intent.component ?: return false
        if (component.packageName != context.packageName || component.className == SecurityBlockActivity::class.java.name) return false
        return runCatching {
            val info = context.packageManager.getActivityInfo(component, 0)
            val type = Class.forName(info.targetActivity ?: info.name, false, context.classLoader)
            info.enabled && info.applicationInfo.uid == context.applicationInfo.uid &&
                !SecurityBlockActivity::class.java.isAssignableFrom(type)
        }.getOrDefault(false)
    }
}
