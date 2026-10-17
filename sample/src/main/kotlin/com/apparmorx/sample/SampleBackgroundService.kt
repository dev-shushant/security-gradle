package com.apparmorx.sample

import android.app.Service
import android.content.Intent
import android.os.IBinder

class SampleBackgroundService : Service() {
    companion object {
        @Volatile var createExecuted: Boolean = false
        @Volatile var startExecuted: Boolean = false

        fun reset() {
            createExecuted = false
            startExecuted = false
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

    override fun onBind(intent: Intent?): IBinder? = null
}
