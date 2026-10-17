package com.apparmorx.sample

import android.app.Service
import android.content.Intent
import android.net.Uri
import android.os.*

/** Debug-only placement probe. No synthetic evidence mutation or manual SDK initialization. */
class RemotePostureService : Service() {
    override fun onBind(intent: Intent?): IBinder = object : Binder() {
        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            if (code != FIRST_CALL_TRANSACTION) return super.onTransact(code, data, reply, flags)
            val response = contentResolver.call(Uri.parse("content://$packageName.apparmorx.init"), "getSecurityState", null, null)
            reply?.writeNoException()
            reply?.writeBundle(Bundle().apply {
                putInt("callerPid", Process.myPid())
                putInt("callerUid", Process.myUid())
                putBundle("posture", response)
            })
            return true
        }
    }
}
