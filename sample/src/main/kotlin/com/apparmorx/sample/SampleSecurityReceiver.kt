package com.apparmorx.sample

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class SampleSecurityReceiver : BroadcastReceiver() {
    companion object {
        @Volatile var receivedAction: String? = null

        fun reset() {
            receivedAction = null
        }
    }

    override fun onReceive(context: Context, intent: Intent) {
        receivedAction = intent.action
    }
}
