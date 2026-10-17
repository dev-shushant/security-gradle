package com.apparmorx.sample

import android.annotation.SuppressLint
import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.res.Configuration
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.WindowInsets
import android.view.WindowInsetsController
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import com.apparmorx.runtime.DeceptionEngine
import com.apparmorx.runtime.OfflineEventQueue
import com.apparmorx.runtime.ProtectionState
import com.apparmorx.runtime.SecurityEvent
import com.apparmorx.runtime.SecurityGuard
import com.apparmorx.runtime.SecurityRuntime
import com.apparmorx.runtime.Status
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection

/**
 * AppArmorX demo app.
 *
 * This Activity contains NO security code: it never initialises, configures or calls AppArmorX to
 * protect anything. The Gradle plugin protects it at build time. The only AppArmorX calls below are
 * read-only (showing status), so you can see what the plugin did without being told.
 *
 * Authored by Shushant Tiwari • com.apparmorx
 */
class MainActivity : Activity() {

    private enum class Verdict { BLOCKED, EXPOSED, NOT_TESTABLE }
    private data class Outcome(val verdict: Verdict, val detail: String)

    private class AttackCard(val title: String, val story: String, val run: () -> Outcome) {
        lateinit var result: TextView
        lateinit var detail: TextView
        var last: Verdict? = null
    }

    private val handler = Handler(Looper.getMainLooper())
    private val timeFormat = SimpleDateFormat("HH:mm:ss", Locale.US)

    private lateinit var heroTitle: TextView
    private lateinit var heroBody: TextView
    private lateinit var heroCard: LinearLayout
    private lateinit var noteContainer: LinearLayout
    private lateinit var scoreView: TextView
    private lateinit var checksContainer: LinearLayout
    private lateinit var logView: TextView
    private lateinit var mirageResult: TextView
    private lateinit var queueResult: TextView
    private lateinit var headlessResult: TextView

    private val expandedGroups = mutableSetOf<String>()
    private val log = mutableListOf<String>()
    private val attacks = mutableListOf<AttackCard>()

    private val refresh = object : Runnable {
        override fun run() {
            updateStatus()
            handler.postDelayed(this, 1500)
        }
    }

    @SuppressLint("SetTextI18n")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(BG)
            setPadding(dp(18), dp(20), dp(18), dp(40))
        }
        val scroll = ScrollView(this).apply { addView(root); isVerticalScrollBarEnabled = false; setBackgroundColor(BG) }
        setContentView(scroll)
        setUpEdgeToEdge(scroll, root)

        // 1. What is this?
        root.addView(text("AppArmorX", 28f, TEXT, bold = true))
        root.addView(text("Mobile app security you don't have to write.", 15f, MUTED).pad(bottom = 14))
        root.addView(card().apply {
            addView(text("What you're looking at", 12f, ACCENT, bold = true).pad(bottom = 6))
            addView(text(
                "This app has zero lines of security code. A single Gradle plugin added protection while it was built: " +
                    "it watches for tampering, debuggers, rooting and hooking tools, and it stops third-party SDKs from " +
                    "quietly reading your clipboard, device ID or location.\n\nBelow: the live status, then buttons that " +
                    "simulate real attacks so you can see the result.", 13f, TEXT,
            ))
        })

        // 2. Live status
        root.addView(sectionTitle("1  Is this device safe right now?"))
        heroCard = card()
        heroTitle = text("Checking…", 24f, ACCENT, bold = true)
        heroBody = text("Running security checks.", 13f, MUTED).pad(top = 4)
        heroCard.addView(heroTitle)
        heroCard.addView(heroBody)
        root.addView(heroCard)
        noteContainer = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        root.addView(noteContainer)

        // 3. Attacks
        root.addView(sectionTitle("2  Try an attack"))
        root.addView(text(
            "Each button does what a malicious or careless library could do inside any app. " +
                "\"Blocked\" means AppArmorX stopped it, \"Exposed\" means data leaked.", 12f, MUTED,
        ).pad(bottom = 10))
        scoreView = text("Not run yet", 13f, MUTED, bold = true)
        root.addView(card().apply {
            addView(scoreView)
            addView(button("Run all attacks", primary = true) { runAll() }.margin(top = 10))
        })
        attacks += AttackCard(
            "Read the clipboard",
            "Passwords and one-time codes often pass through the clipboard. Many SDKs read it silently.",
            ::attackClipboard,
        )
        attacks += AttackCard(
            "Collect device identifiers",
            "Ad and analytics SDKs read your device ID (and IMEI where allowed) to track you across apps.",
            ::attackIdentifiers,
        )
        attacks += AttackCard(
            "Grab your last location",
            "A library asks the system for your last known GPS position without you opening a map.",
            ::attackLocation,
        )
        attacks += AttackCard(
            "Switch off HTTPS checking",
            "A library installs a \"trust everyone\" hostname verifier, letting anyone on the Wi-Fi read app traffic.",
            ::attackTls,
        )
        attacks.forEach { root.addView(attackView(it)) }

        // 4. Live checks
        root.addView(sectionTitle("3  What is being checked"))
        root.addView(text("Tap a group to see each check. \"Couldn't check\" never counts as safe.", 12f, MUTED).pad(bottom = 10))
        checksContainer = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        root.addView(checksContainer)

        // 5. Advanced
        root.addView(sectionTitle("4  More protections"))
        mirageResult = text("", 12f, MUTED)
        root.addView(simpleActionCard(
            "Deception delay (Mirage mode)",
            "Instead of crashing when it finds a tool, the app can slow tools down with random delays so attackers can't tell which check fired.",
            "Trigger a delay", mirageResult,
        ) {
            val start = System.currentTimeMillis()
            DeceptionEngine.injectJitter(40, 80)
            val ms = System.currentTimeMillis() - start
            mirageResult.text = "Delay applied: ${ms} ms"
            note("Deception delay of ${ms} ms applied")
        })
        headlessResult = text("", 12f, MUTED)
        root.addView(simpleActionCard(
            "Background components",
            "Services and receivers run without a screen. AppArmorX guards them too, not just activities.",
            "Start service & receiver", headlessResult,
        ) { startHeadless() })
        queueResult = text("", 12f, MUTED)
        root.addView(simpleActionCard(
            "Threat reports",
            "Detections can be queued on-device and sent to your own server later, with no personal data. Nothing leaves this phone in the demo.",
            "Queue a test report", queueResult,
        ) { queueReport() })

        // 6. Log + honesty
        root.addView(sectionTitle("Activity log"))
        logView = text("Nothing yet. Run an attack above.", 11f, GREEN).apply { typeface = Typeface.MONOSPACE }
        root.addView(card().apply { addView(logView) })
        root.addView(sectionTitle("Honest limits"))
        root.addView(text(
            "No client-side protection is unbypassable. AppArmorX raises the cost of attacking an app and gives you evidence. " +
                "It does not replace server-side checks. If a check can't run, the app reports \"unknown\", never \"safe\".",
            12f, MUTED,
        ))
        root.addView(text("Built by Shushant Tiwari · com.apparmorx", 11f, MUTED).pad(top = 18))
    }

    /** Draw behind the system bars on every supported API level and keep content clear of them. */
    private fun setUpEdgeToEdge(scroll: View, root: View) {
        val lightBars = !night
        if (Build.VERSION.SDK_INT >= 30) {
            window.setDecorFitsSystemWindows(false)
            window.insetsController?.setSystemBarsAppearance(
                if (lightBars) WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS or WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS else 0,
                WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS or WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS,
            )
        } else {
            @Suppress("DEPRECATION")
            var flags = View.SYSTEM_UI_FLAG_LAYOUT_STABLE or View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN or View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION
            if (lightBars) flags = flags or View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR or (if (Build.VERSION.SDK_INT >= 26) View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR else 0)
            @Suppress("DEPRECATION")
            window.decorView.systemUiVisibility = flags
        }
        scroll.setOnApplyWindowInsetsListener { _, insets ->
            val top: Int
            val bottom: Int
            if (Build.VERSION.SDK_INT >= 30) {
                val bars = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout())
                top = bars.top; bottom = bars.bottom
            } else {
                @Suppress("DEPRECATION") run { top = insets.systemWindowInsetTop; bottom = insets.systemWindowInsetBottom }
            }
            root.setPadding(dp(18), top + dp(20), dp(18), bottom + dp(40))
            insets
        }
        scroll.requestApplyInsets()
    }

    override fun onResume() {
        super.onResume()
        handler.post(refresh)
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(refresh)
    }

    // ---- Attacks (each returns what the "attacker" actually saw) ----

    @Suppress("DEPRECATION")
    private fun attackClipboard(): Outcome {
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val canary = "demo-secret-4242"
        cm.setPrimaryClip(ClipData.newPlainText("demo", canary))
        val read = cm.primaryClip?.getItemAt(0)?.text?.toString()
        return if (read == canary) {
            Outcome(Verdict.EXPOSED, "The library read your clipboard: \"$read\".")
        } else {
            Outcome(Verdict.BLOCKED, "The library got nothing. (This demo put a test value on your clipboard first.)")
        }
    }

    @Suppress("DEPRECATION", "MissingPermission", "HardwareIds")
    private fun attackIdentifiers(): Outcome {
        val id = Settings.Secure.getString(contentResolver, Settings.Secure.ANDROID_ID)
        val tm = getSystemService(Context.TELEPHONY_SERVICE) as? android.telephony.TelephonyManager
        var imeiIntercepted = true
        try { tm?.deviceId } catch (_: SecurityException) { imeiIntercepted = false }
        val sanitized = id.isNullOrBlank() || id.all { it == '0' }
        return if (sanitized) {
            Outcome(Verdict.BLOCKED, "The library received a blank ID (${id ?: "null"}) instead of your real device ID.")
        } else {
            Outcome(Verdict.EXPOSED, "The library got your real device ID: ${id!!.take(4)}…${id.takeLast(2)}" +
                if (imeiIntercepted) "" else " (hardware IMEI was refused by Android itself, not by AppArmorX).")
        }
    }

    @Suppress("MissingPermission")
    private fun attackLocation(): Outcome {
        val lm = getSystemService(Context.LOCATION_SERVICE) as android.location.LocationManager
        return try {
            val loc = lm.getLastKnownLocation("gps")
            if (loc == null) Outcome(Verdict.BLOCKED, "The library asked for your last location and received nothing.")
            else Outcome(Verdict.EXPOSED, "The library read your last location: ${loc.latitude}, ${loc.longitude}")
        } catch (_: SecurityException) {
            Outcome(Verdict.NOT_TESTABLE, "Android refused the request because this demo has no location permission, so the call was not intercepted by AppArmorX. Enable the firewall for location to see it blocked.")
        }
    }

    private fun attackTls(): Outcome {
        val original = HttpsURLConnection.getDefaultHostnameVerifier()
        val trustEveryone = HostnameVerifier { _, _ -> true }
        HttpsURLConnection.setDefaultHostnameVerifier(trustEveryone)
        val installed = HttpsURLConnection.getDefaultHostnameVerifier() === trustEveryone
        // Never leave the demo app vulnerable.
        if (installed) HttpsURLConnection.setDefaultHostnameVerifier(original)
        return if (installed) {
            Outcome(Verdict.EXPOSED, "The \"trust everyone\" verifier was accepted. (Restored afterwards.)")
        } else {
            Outcome(Verdict.BLOCKED, "The unsafe verifier was rejected; the app kept strict HTTPS checking.")
        }
    }

    private fun runAll() {
        attacks.forEach { runAttack(it) }
        val blocked = attacks.count { it.last == Verdict.BLOCKED }
        val exposed = attacks.count { it.last == Verdict.EXPOSED }
        val untested = attacks.count { it.last == Verdict.NOT_TESTABLE }
        scoreView.text = "$blocked of ${attacks.size} attacks blocked" +
            (if (exposed > 0) " · $exposed exposed" else "") + (if (untested > 0) " · $untested not testable" else "")
        scoreView.setTextColor(if (exposed > 0) RED else if (blocked == attacks.size) GREEN else AMBER)
    }

    private fun runAttack(card: AttackCard) {
        val outcome = try { card.run() } catch (e: Exception) { Outcome(Verdict.NOT_TESTABLE, "The attack could not run: ${e.javaClass.simpleName}") }
        card.last = outcome.verdict
        val (label, color) = when (outcome.verdict) {
            Verdict.BLOCKED -> "✓ BLOCKED" to GREEN
            Verdict.EXPOSED -> "✗ EXPOSED" to RED
            Verdict.NOT_TESTABLE -> "– NOT TESTABLE" to AMBER
        }
        card.result.text = label
        card.result.setTextColor(color)
        card.detail.text = outcome.detail
        for (v in listOf(card.result, card.detail)) {
            v.alpha = 0f
            v.visibility = View.VISIBLE
            v.animate().alpha(1f).setDuration(220).start()
        }
        val haptic = when {
            Build.VERSION.SDK_INT >= 30 && outcome.verdict == Verdict.BLOCKED -> android.view.HapticFeedbackConstants.CONFIRM
            Build.VERSION.SDK_INT >= 30 && outcome.verdict == Verdict.EXPOSED -> android.view.HapticFeedbackConstants.REJECT
            else -> android.view.HapticFeedbackConstants.VIRTUAL_KEY
        }
        window.decorView.performHapticFeedback(haptic)
        note("${card.title}: ${label.drop(2)}")
    }

    private fun startHeadless() {
        try {
            SampleBackgroundService.reset()
            SampleSecurityReceiver.reset()
            startService(Intent(this, SampleBackgroundService::class.java))
            sendBroadcast(Intent(this, SampleSecurityReceiver::class.java).setAction("com.apparmorx.sample.ACTION_SECURITY_VERIFY"))
            handler.postDelayed({
                headlessResult.text = "Service ran: ${if (SampleBackgroundService.createExecuted) "yes" else "no"} · " +
                    "Receiver ran: ${if (SampleSecurityReceiver.receivedAction != null) "yes" else "no"}. " +
                    "Both passed through guards added at build time; the policy decides whether to allow, delay or stop them."
            }, 400)
            note("Background service and receiver started")
        } catch (e: Exception) {
            headlessResult.text = "Could not start: ${e.javaClass.simpleName}"
        }
    }

    private fun queueReport() {
        try {
            val file = OfflineEventQueue.defaultQueueFile(this)
            val event = SecurityEvent(
                eventId = UUID.randomUUID().toString(),
                timestampSeconds = System.currentTimeMillis() / 1000,
                applicationId = packageName,
                policySequence = SecurityRuntime.snapshot().policySequence,
                detectedChecks = listOf("simulated-demo-event"),
                osVersion = Build.VERSION.SDK_INT,
                abi = Build.SUPPORTED_ABIS.firstOrNull().orEmpty(),
            )
            OfflineEventQueue.enqueue(file, event.toJson())
            queueResult.text = "Reports waiting on this phone: ${OfflineEventQueue.size(file)} of 50 max"
            note("Test report queued")
        } catch (e: Exception) {
            queueResult.text = "Could not queue: ${e.javaClass.simpleName}"
        }
    }

    // ---- Live status ----

    @SuppressLint("SetTextI18n")
    private fun updateStatus() {
        val snapshot = SecurityRuntime.snapshot()
        val state = SecurityGuard.lastObservedState()
        val isDebuggableBuild = applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
        val total = snapshot.evidence.size
        val detected = snapshot.evidence.filter { it.status == Status.DETECTED }.map { it.check }
        val unavailable = snapshot.evidence.count { it.status == Status.UNAVAILABLE }
        // Two detections are expected in this demo and are explained below instead of alarming the user.
        val demoTamper = "signing-certificate" in detected
        val debugBuild = "debuggable-app" in detected && isDebuggableBuild
        val real = detected.filterNot { it == "signing-certificate" || (it == "debuggable-app" && isDebuggableBuild) }

        val (title, color, body) = when {
            snapshot.checkedAtMillis == 0L || state == ProtectionState.CHECKING ->
                Triple("Checking…", ACCENT, "Running $total+ security checks. This takes a moment.")
            real.isNotEmpty() -> Triple(
                "Threat detected", RED,
                "AppArmorX found: ${real.joinToString { detectedMeaning(it) }}. A real app would now react (block, warn or slow the attacker) as configured.",
            )
            unavailable > 0 -> Triple(
                "Mostly verified", AMBER,
                "${total - unavailable - detected.size} checks passed. $unavailable couldn't run on this device and are treated as unknown, not safe.",
            )
            else -> Triple("Device looks clean", GREEN, "${total - detected.size} of $total checks passed. No tampering, debugger, root or hooking tools found.")
        }
        heroTitle.text = title
        heroTitle.setTextColor(color)
        heroBody.text = body
        heroCard.background = bg(CARD, color, 1)

        noteContainer.removeAllViews()
        val notes = mutableListOf<String>()
        if (demoTamper) notes += "Signer mismatch is on purpose: this demo is pinned to the wrong certificate to show how a repackaged (cracked) copy is flagged."
        if (debugBuild) notes += "Debug build: AppArmorX flags debuggable apps. Release builds pass this check, and debug builds are never blocked."
        if (DeceptionEngine.isMirageActive) notes += "Mirage mode is active: suspected tools get random delays instead of a crash."
        if (notes.isNotEmpty()) noteContainer.addView(infoCard("Why you may see warnings in this demo", notes.joinToString("\n\n• ", prefix = "• ")))
        renderChecks(snapshot.evidence)
    }

    private fun renderChecks(evidence: List<com.apparmorx.runtime.Evidence>) {
        checksContainer.removeAllViews()
        val byGroup = evidence.groupBy { groupOf(it.check) }
        for (group in GROUP_ORDER) {
            val items = byGroup[group] ?: continue
            val clear = items.count { it.status == Status.CLEAR }
            val detected = items.count { it.status == Status.DETECTED }
            val unknown = items.count { it.status == Status.UNAVAILABLE }
            val color = if (detected > 0) RED else if (unknown > 0) AMBER else GREEN
            val open = group in expandedGroups
            val card = card().apply { (layoutParams as LinearLayout.LayoutParams).bottomMargin = dp(8) }
            val header = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
            header.addView(text(group, 14f, TEXT, bold = true).apply { layoutParams = LinearLayout.LayoutParams(0, -2, 1f) })
            header.addView(text("$clear/${items.size} clear" + if (open) "  ▲" else "  ▼", 12f, color, bold = true))
            card.addView(header)
            card.addView(text(GROUP_BLURB.getValue(group), 12f, MUTED).pad(top = 2))
            if (open) for (e in items) {
                val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; setPadding(0, dp(8), 0, 0) }
                val (label, c) = when (e.status) {
                    Status.CLEAR -> "Clear" to GREEN
                    Status.DETECTED -> "Detected" to RED
                    Status.UNAVAILABLE -> "Couldn't check" to AMBER
                }
                row.addView(text(friendly(e.check), 12f, TEXT).apply { layoutParams = LinearLayout.LayoutParams(0, -2, 1f) })
                row.addView(text("● $label", 12f, c))
                card.addView(row)
            }
            card.setOnClickListener {
                if (!expandedGroups.add(group)) expandedGroups.remove(group)
                renderChecks(SecurityRuntime.snapshot().evidence)
            }
            checksContainer.addView(card)
        }
    }

    // ---- Content ----

    private val GROUP_ORDER = listOf("Tampering & identity", "Debugging", "Root & system integrity", "Hooking & code injection", "Environment")
    private val GROUP_BLURB = mapOf(
        "Tampering & identity" to "Is this really the app you published, signed by you?",
        "Debugging" to "Is someone attached to the app, stepping through it?",
        "Root & system integrity" to "Has the phone's protection been unlocked?",
        "Hooking & code injection" to "Are tools like Frida or Xposed rewriting the app while it runs?",
        "Environment" to "Is the app running somewhere unusual, like an emulator or a clone?",
    )

    private fun groupOf(check: String): String = when (check) {
        "policy", "policy-or-scan", "application-id", "signing-certificate", "apk-integrity", "native-engine" -> "Tampering & identity"
        "debugger", "debuggable-app", "native-tracer", "native-wchan" -> "Debugging"
        "root-path", "build-tags", "native-root-path", "native-root-mount", "native-selinux" -> "Root & system integrity"
        "environment-hardware", "native-hardware-device", "virtual-space", "network-cleartext-permitted" -> "Environment"
        else -> "Hooking & code injection"
    }

    /** What a DETECTED result on this check actually means — the opposite of [friendly]'s CLEAR-phrased description. */
    private fun detectedMeaning(check: String): String = when (check) {
        "policy", "policy-or-scan" -> "the security policy is missing, invalid or expired"
        "application-id" -> "the package name does not match the original"
        "signing-certificate" -> "the app is signed with a different certificate than the one it was published with (likely repackaged)"
        "apk-integrity" -> "the app package appears damaged or modified"
        "native-engine" -> "the native protection engine failed to load"
        "debugger" -> "a debugger is attached to the app"
        "debuggable-app" -> "the app is marked debuggable"
        "native-tracer" -> "a tracer is attached to the process (kernel check)"
        "native-wchan" -> "the process appears frozen by a debugger"
        "root-path" -> "root (su) binaries were found on this device"
        "build-tags" -> "this is an unofficial system build (test-keys)"
        "native-root-path" -> "root files were found (kernel-level check)"
        "native-root-mount" -> "a root overlay is mounted over system folders"
        "native-selinux" -> "SELinux is not enforcing"
        "environment-hardware" -> "this looks like an emulator, not real hardware"
        "native-hardware-device" -> "virtual-machine hardware was found (kernel check)"
        "virtual-space" -> "the app appears to be running inside a cloning app"
        "network-cleartext-permitted" -> "unencrypted HTTP is allowed by this app's configuration"
        "hook-library" -> "a hooking library is loaded"
        "hook-classes" -> "Xposed/Substrate classes are present"
        "native-hook-library" -> "a hooking library was found (kernel-level check)"
        "native-tool-thread" -> "a Frida/debugger worker thread was found"
        "native-libc-origin" -> "system functions do not look genuine"
        "native-hook-trampoline" -> "an inline hook was found on a system call"
        "native-frida-port" -> "a Frida server port is open"
        "native-memory-rwx" -> "suspicious writable+executable memory was found"
        "native-stealth-injection" -> "hidden injected code was found in memory"
        "native-relocation-integrity" -> "a native library's layout looks tampered"
        else -> "$check was flagged"
    }

    private fun friendly(check: String): String = when (check) {
        "policy", "policy-or-scan" -> "Security policy is valid and current"
        "application-id" -> "Package name matches the original"
        "signing-certificate" -> "Signing certificate matches the pinned one"
        "apk-integrity" -> "App package is intact"
        "native-engine" -> "Native protection engine loaded"
        "debugger" -> "No debugger attached"
        "debuggable-app" -> "App is not marked debuggable"
        "native-tracer" -> "Nothing is tracing the process (kernel check)"
        "native-wchan" -> "Process is not frozen by a debugger"
        "root-path" -> "No root (su) binaries found"
        "build-tags" -> "Official system build (not test-keys)"
        "native-root-path" -> "No root files (kernel-level check)"
        "native-root-mount" -> "No root overlays on system folders"
        "native-selinux" -> "SELinux is enforcing"
        "environment-hardware" -> "Runs on real hardware, not an emulator"
        "native-hardware-device" -> "No virtual-machine hardware (kernel check)"
        "virtual-space" -> "Not running inside a cloning app"
        "network-cleartext-permitted" -> "Unencrypted HTTP is not allowed"
        "hook-library" -> "No hooking libraries loaded"
        "hook-classes" -> "No Xposed/Substrate classes present"
        "native-hook-library" -> "No hooking libraries (kernel-level check)"
        "native-tool-thread" -> "No Frida/debugger worker threads"
        "native-libc-origin" -> "System functions are the genuine ones"
        "native-hook-trampoline" -> "No inline hooks on system calls"
        "native-frida-port" -> "No Frida server port open"
        "native-memory-rwx" -> "No suspicious writable+executable memory"
        "native-stealth-injection" -> "No hidden injected code in memory"
        "native-relocation-integrity" -> "Native library layout is untampered"
        else -> check
    }

    // ---- View helpers ----

    private fun attackView(card: AttackCard): View = card().apply {
        addView(text(card.title, 16f, TEXT, bold = true))
        addView(text(card.story, 12f, MUTED).pad(top = 4, bottom = 10))
        addView(button("Run this attack") { runAttack(card) })
        card.result = text("", 15f, GREEN, bold = true).pad(top = 10).apply { visibility = View.GONE }
        card.detail = text("", 12f, TEXT).pad(top = 2).apply { visibility = View.GONE }
        addView(card.result)
        addView(card.detail)
    }

    private fun simpleActionCard(title: String, story: String, action: String, result: TextView, onClick: () -> Unit): View = card().apply {
        addView(text(title, 15f, TEXT, bold = true))
        addView(text(story, 12f, MUTED).pad(top = 4, bottom = 10))
        addView(button(action) { onClick() })
        addView(result.pad(top = 8))
    }

    private fun infoCard(title: String, body: String): View = card().apply {
        background = bg(CARD, ACCENT, 1)
        addView(text(title, 13f, ACCENT, bold = true))
        addView(text(body, 12f, MUTED).pad(top = 2))
    }

    private fun sectionTitle(label: String): TextView = text(label.uppercase(Locale.US), 12f, ACCENT, bold = true).apply {
        letterSpacing = 0.08f
        setPadding(0, dp(26), 0, dp(8))
    }

    private fun note(message: String) {
        log += "[${timeFormat.format(Date())}] $message"
        if (log.size > 30) log.removeAt(0)
        logView.text = log.joinToString("\n")
    }

    private fun card(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(16), dp(14), dp(16), dp(14))
        background = bg(CARD, LINE, 1)
        layoutParams = LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = dp(10) }
    }

    private fun text(value: String, sizeSp: Float, color: Int, bold: Boolean = false): TextView = TextView(this).apply {
        text = value
        setTextSize(TypedValue.COMPLEX_UNIT_SP, sizeSp)
        setTextColor(color)
        if (bold) typeface = Typeface.DEFAULT_BOLD
        setLineSpacing(0f, 1.15f)
    }

    private fun button(label: String, primary: Boolean = false, onClick: () -> Unit): Button = Button(this).apply {
        text = label
        isAllCaps = false
        setTextColor(if (primary) Color.WHITE else ACCENT)
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
        typeface = Typeface.DEFAULT_BOLD
        background = if (primary) bg(ACCENT_DARK, ACCENT_DARK, 0) else bg(Color.TRANSPARENT, ACCENT, 1)
        minHeight = dp(46)
        setOnClickListener { onClick() }
        layoutParams = LinearLayout.LayoutParams(-1, -2)
    }

    private fun bg(fill: Int, stroke: Int, strokeDp: Int) = GradientDrawable().apply {
        setColor(fill)
        cornerRadius = dp(14).toFloat()
        if (strokeDp > 0) setStroke(dp(strokeDp), stroke)
    }

    private fun TextView.pad(top: Int = 0, bottom: Int = 0) = apply { setPadding(paddingLeft, dp(top), paddingRight, dp(bottom)) }
    private fun View.margin(top: Int) = apply { (layoutParams as ViewGroup.MarginLayoutParams).topMargin = dp(top) }
    private fun dp(value: Int) = TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, value.toFloat(), resources.displayMetrics).toInt()

    // Palette follows the system light/dark setting (resolved lazily: resources exist only after attach).
    private val night by lazy {
        resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK == Configuration.UI_MODE_NIGHT_YES
    }
    private fun pick(dark: String, light: String) = Color.parseColor(if (night) dark else light)
    private val BG by lazy { pick("#0A0F1C", "#F4F6FB") }
    private val CARD by lazy { pick("#111827", "#FFFFFF") }
    private val LINE by lazy { pick("#1F2A44", "#DDE3F0") }
    private val TEXT by lazy { pick("#E5EAF5", "#0F172A") }
    private val MUTED by lazy { pick("#8B97B5", "#5B6785") }
    private val ACCENT by lazy { pick("#5EB4FF", "#1D6FD1") }
    private val ACCENT_DARK by lazy { Color.parseColor("#1D6FD1") }
    private val GREEN by lazy { pick("#34D399", "#0E9F6E") }
    private val RED by lazy { pick("#F87171", "#DC2626") }
    private val AMBER by lazy { pick("#FBBF24", "#B45309") }
}
