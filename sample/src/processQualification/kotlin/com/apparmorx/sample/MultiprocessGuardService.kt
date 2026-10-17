package com.apparmorx.sample

import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import java.util.concurrent.atomic.AtomicInteger

/** Real framework callback; no SDK calls. Only the qualification build includes this class. */
class MultiprocessGuardService : Service() {
    companion object { @JvmField val binds = AtomicInteger() }
    override fun onBind(intent: Intent?): IBinder {
        binds.incrementAndGet()
        return Binder()
    }
}
