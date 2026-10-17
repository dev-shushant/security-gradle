package com.apparmorx.sample

import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import com.apparmorx.runtime.SecurityBlockActivity
import com.apparmorx.runtime.SecurityUiState

/** Host-owned presentation; the runtime still controls checks, retry and recovery. */
class BrandedSecurityActivity : SecurityBlockActivity() {
    private lateinit var status: TextView
    private lateinit var checkAgain: Button

    override fun createSecurityContent(): View = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        gravity = Gravity.CENTER
        val padding = (24 * resources.displayMetrics.density).toInt()
        setPadding(padding, padding, padding, padding)
        addView(TextView(context).apply { text = "AppArmorX Sample"; textSize = 26f })
        status = TextView(context).apply { id = android.R.id.message; textSize = 18f }
        addView(status)
        checkAgain = Button(context).apply {
            id = android.R.id.button1
            text = "Try again"
            setOnClickListener { retrySecurityCheck() }
        }
        addView(checkAgain)
        addView(Button(context).apply {
            id = android.R.id.button2
            text = "Close app"
            setOnClickListener { closeProtectedTask() }
        })
    }

    override fun renderSecurityState(state: SecurityUiState) {
        status.text = state.message
        checkAgain.visibility = if (state.canRetry) View.VISIBLE else View.GONE
    }
}
