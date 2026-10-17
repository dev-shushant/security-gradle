package com.apparmorx.sample

import android.app.Service
import android.content.Intent
import android.os.IBinder
import android.os.Binder

class SampleBackgroundService : Service() {
    companion object {
        @Volatile var createExecuted: Boolean = false
        @Volatile var startExecuted: Boolean = false
        @Volatile var bindExecuted: Boolean = false
        @Volatile var rebindExecuted: Boolean = false
        @Volatile var legacyStartExecuted: Boolean = false
        @Volatile var destroyExecuted: Boolean = false
        @Volatile var unbindExecuted: Boolean = false

        fun reset() {
            createExecuted = false
            startExecuted = false
            bindExecuted = false
            rebindExecuted = false
            legacyStartExecuted = false
            destroyExecuted = false
            unbindExecuted = false
        }
    }

    override fun onCreate() {
        super.onCreate()
        createExecuted = true
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startExecuted = true
        return START_NOT_STICKY
    }

    fun attachForTesting(context: android.content.Context) {
        val method = android.content.ContextWrapper::class.java.getDeclaredMethod("attachBaseContext", android.content.Context::class.java)
        method.isAccessible = true
        method.invoke(this, context)
    }

    override fun onBind(intent: Intent?): IBinder? {
        bindExecuted = true
        return Binder()
    }

    override fun onRebind(intent: Intent?) {
        rebindExecuted = true
    }

    @Suppress("DEPRECATION")
    override fun onStart(intent: Intent?, startId: Int) {
        legacyStartExecuted = true
    }

    override fun onUnbind(intent: Intent?): Boolean {
        unbindExecuted = true
        return false
    }

    override fun onDestroy() {
        destroyExecuted = true
        super.onDestroy()
    }
}
