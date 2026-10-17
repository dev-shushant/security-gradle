package com.apparmorx.runtime

import android.app.Activity
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.ScrollView

/** Presentation phases exposed to a host-owned layout. */
enum class SecurityScreen { CHECKING, RESTRICTED, UNAVAILABLE }

/** Presentation state only; it is not a security verdict or an authorization to resume. */
data class SecurityUiState(val screen: SecurityScreen, val message: String, val canRetry: Boolean)

/** Bundled recovery controller with overridable presentation and final lifecycle management. */
open class SecurityBlockActivity : Activity() {
    private val handler = Handler(Looper.getMainLooper())
    private lateinit var message: TextView
    private lateinit var retry: Button
    private var pending = false
    private var ticket: String? = null
    private var startedAt = 0L
    private var retryRevision: Long? = null
    private val poll = object : Runnable {
        override fun run() {
            if (!pending || isFinishing || isDestroyed) return
            if (!StartupLaunches.isValid(ticket)) { unavailable(retryable = false); return }
            retryRevision?.let { baseline ->
                when (freshScanState(baseline, SecurityRuntime.completedScanRevision(), SystemClock.elapsedRealtime() - startedAt)) {
                    FreshScanState.WAIT -> {
                        // Coalesced/throttled by the runtime; no scan storm from UI polling.
                        SecurityRuntime.refresh()
                        handler.postDelayed(this, 100)
                        return
                    }
                    FreshScanState.TIMED_OUT -> { unavailable(retryable = true); return }
                    FreshScanState.FRESH -> retryRevision = null
                }
            }
            val snapshot = SecurityRuntime.snapshot()
            val state = decideProtection(snapshot, System.currentTimeMillis(), REQUIRED_EVIDENCE)
            when (startupRecovery(state, snapshot.enforcement, SystemClock.elapsedRealtime() - startedAt, 10_000)) {
                StartupRecovery.WAIT -> handler.postDelayed(this, 100)
                StartupRecovery.RESUME -> {
                    val target = StartupLaunches.consume(this@SecurityBlockActivity, ticket)
                    if (target == null) { unavailable(retryable = false); return }
                    pending = false
                    try {
                        startActivity(target)
                        finish()
                    } catch (_: Exception) { unavailable(retryable = false) }
                }
                StartupRecovery.RESTRICTED -> {
                    StartupLaunches.revoke(ticket)
                    pending = false
                    showState(SecurityScreen.RESTRICTED, getString(R.string.apparmorx_security_restricted))
                }
                StartupRecovery.UNAVAILABLE -> unavailable(retryable = true)
                StartupRecovery.EXIT -> {
                    StartupLaunches.revoke(ticket)
                    pending = false
                    finishAffinity()
                }
            }
        }
    }

    final override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        pending = if (savedInstanceState?.containsKey("startupPending") == true) savedInstanceState.getBoolean("startupPending")
            else runCatching { intent.getBooleanExtra(StartupLaunches.PENDING, false) }.getOrDefault(false)
        ticket = runCatching { intent.getStringExtra(StartupLaunches.TICKET) }.getOrNull()
        startedAt = savedInstanceState?.getLong("startupElapsed") ?: SystemClock.elapsedRealtime()
        retryRevision = savedInstanceState?.takeIf { it.containsKey("retryRevision") }?.getLong("retryRevision")
        setContentView(createSecurityContent())
        val missingEvidence = runCatching { intent.getBooleanExtra(SecurityUiDestination.UNAVAILABLE, false) }.getOrDefault(false)
        if (applicationInitialization.requiresRestart() || (!pending && missingEvidence)) unavailable(retryable = false)
        else showState(if (pending) SecurityScreen.CHECKING else SecurityScreen.RESTRICTED,
            getString(if (pending) R.string.apparmorx_security_checking else R.string.apparmorx_security_restricted))
    }

    /** Override for an XML or programmatic View layout. Wire actions to the protected methods below. */
    protected open fun createSecurityContent(): View {
        val spacing = (24 * resources.displayMetrics.density).toInt()
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(spacing, spacing, spacing, spacing)
            setBackgroundColor(getColor(R.color.apparmorx_security_background))
        }
        message = TextView(this).apply {
            id = android.R.id.message
            gravity = Gravity.CENTER
            textSize = 18f
            setTextColor(getColor(R.color.apparmorx_security_text))
            accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE
        }
        retry = Button(this).apply {
            id = android.R.id.button1
            text = getString(R.string.apparmorx_security_retry)
            isAllCaps = false
            minHeight = (48 * resources.displayMetrics.density).toInt()
            setOnClickListener { retrySecurityCheck() }
        }
        val close = Button(this).apply {
            id = android.R.id.button2
            text = getString(R.string.apparmorx_security_close)
            isAllCaps = false
            minHeight = (48 * resources.displayMetrics.density).toInt()
            setOnClickListener { closeProtectedTask() }
        }
        content.addView(message)
        content.addView(retry)
        content.addView(close)
        return ScrollView(this).apply { isFillViewport = true; addView(content) }
    }

    /** Override together with createSecurityContent to render a custom layout. Called on the UI thread. */
    protected open fun renderSecurityState(state: SecurityUiState) {
        if (::message.isInitialized) message.text = state.message
        if (::retry.isInitialized) retry.visibility = if (state.canRetry) View.VISIBLE else View.GONE
    }

    /** Requests another scan; cannot force an allow decision or supply a resume destination. */
    protected fun retrySecurityCheck() {
        if (!pending || !StartupLaunches.isValid(ticket)) { unavailable(false); return }
        startedAt = SystemClock.elapsedRealtime()
        retryRevision = SecurityRuntime.completedScanRevision()
        showState(SecurityScreen.CHECKING, getString(R.string.apparmorx_security_checking))
        SecurityRuntime.refresh()
        handler.removeCallbacks(poll)
        handler.post(poll)
    }

    protected fun closeProtectedTask() {
        StartupLaunches.revoke(ticket)
        pending = false
        handler.removeCallbacks(poll)
        finishAffinity()
    }

    private fun showState(screen: SecurityScreen, text: String, canRetry: Boolean = false) {
        renderSecurityState(SecurityUiState(screen, text, canRetry))
    }

    private fun unavailable(retryable: Boolean) {
        retryRevision = null
        handler.removeCallbacks(poll)
        if (applicationInitialization.requiresRestart()) {
            StartupLaunches.revoke(ticket)
            pending = false
            showState(SecurityScreen.UNAVAILABLE, getString(R.string.apparmorx_security_restart_required))
            return
        }
        val canRetry = retryable && pending && StartupLaunches.isValid(ticket)
        showState(SecurityScreen.UNAVAILABLE, getString(if (canRetry)
            R.string.apparmorx_security_unavailable_retry else R.string.apparmorx_security_unavailable_reopen), canRetry)
    }

    final override fun onResume() {
        super.onResume()
        if (pending) { handler.removeCallbacks(poll); handler.post(poll) }
    }
    final override fun onPause() { handler.removeCallbacks(poll); super.onPause() }
    final override fun onSaveInstanceState(outState: Bundle) {
        outState.putLong("startupElapsed", startedAt)
        outState.putBoolean("startupPending", pending)
        retryRevision?.let { outState.putLong("retryRevision", it) }
        super.onSaveInstanceState(outState)
    }
    final override fun onDestroy() {
        handler.removeCallbacks(poll)
        if (isFinishing) StartupLaunches.revoke(ticket)
        super.onDestroy()
    }
}
