package com.apparmorx.runtime

import android.annotation.SuppressLint
import android.app.Activity
import android.graphics.Color
import android.os.Bundle
import android.view.Gravity
import android.view.ViewGroup
import android.widget.TextView

/**
 * Bundled fallback screen for [EnforcementAction.BLOCK_SCREEN]. Built programmatically so the
 * runtime AAR needs no `res/` resources of its own. Lives in this module, not the consumer's, so
 * AGP's `InstrumentationScope.PROJECT` guard injection never touches it — it can never trigger
 * [SecurityGuard.allowActivity] itself, so there is no risk of a guard loop through this screen.
 *
 * Intentionally minimal and honest: states that a check failed, takes no destructive action, and
 * lets the user leave. Hosts who want their own recovery UI configure `restrictedAction` to
 * something other than `BLOCK_SCREEN` and read [SecurityGuard.lastObservedState] themselves.
 */
class SecurityBlockActivity : Activity() {
    @SuppressLint("SetTextI18n")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val message = TextView(this).apply {
            text = "This device did not pass a required security check for this app.\n\nPress back to exit."
            gravity = Gravity.CENTER
            setPadding(48, 48, 48, 48)
            setBackgroundColor(Color.BLACK)
            setTextColor(Color.WHITE)
            layoutParams = ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
        }
        setContentView(message)
    }
}
