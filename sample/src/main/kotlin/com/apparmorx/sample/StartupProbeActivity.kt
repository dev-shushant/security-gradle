package com.apparmorx.sample

import android.app.Activity
import android.os.Bundle
import android.widget.TextView
import java.util.concurrent.atomic.AtomicInteger

/** Qualification target: no runtime calls; the plugin injects the normal Activity guard. */
class StartupProbeActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        payload = intent.getStringExtra("fixture-payload")
        launches.incrementAndGet()
        setContentView(TextView(this).apply { text = "AppArmorX startup qualification" })
    }
    companion object {
        val launches = AtomicInteger()
        @Volatile var payload: String? = null
    }
}
