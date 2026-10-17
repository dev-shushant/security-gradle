package com.apparmorx.gradle

import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property

/** Public security DSL. Defaults to bundled observation-only checks; no network destination is implicit. */
abstract class SecurityExtension {
    /**
     * Protection level applied when individual settings are not set: `DEVELOPMENT` (observe only),
     * `STANDARD` (default: block on confirmed threats + dependency firewall) or `HARDENED`
     * (STANDARD + fail-closed startup + screen-capture protection). Any explicit property below
     * overrides the profile; weaker-than-profile overrides are flagged in the build report.
     * Debuggable variants never enforce a response, whatever the profile.
     */
    abstract val profile: Property<String>
    /** Optional HTTPS feed. With refreshOnBuild, every Android build verifies its latest response. */
    abstract val policyUrl: Property<String>
    /** Reviewed Base64 X.509 Ed25519 key; never obtained from the same feed as the policy. */
    abstract val policyPublicKey: Property<String>
    /** Optional signed local policy. Required for pinned/offline feed builds. */
    abstract val policyFile: RegularFileProperty
    /** Committed rollback floor. Increment through review when accepting a newer policy. */
    abstract val minimumSequence: Property<Long>
    /** Fetch at task execution time when online. False selects a pinned local policy. */
    abstract val refreshOnBuild: Property<Boolean>
    /** Current app signing certificate SHA-256 fingerprints, lowercase hex, all accepted signers. */
    abstract val signingCertificates: ListProperty<String>
    /** Require explicit signer pins for non-debuggable variants. */
    abstract val requireReleaseSigningPins: Property<Boolean>
    /** Extra runtime coordinate. Leave unset: the matching runtime is bundled inside the plugin itself. */
    abstract val runtimeCoordinates: Property<String>
    /**
     * Response when a guarded Activity lifecycle call observes [com.apparmorx.runtime.ProtectionState.RESTRICTED]
     * (a confirmed detection, not merely unavailable evidence): `"OBSERVE"` (default — record only),
     * `"WARN"` (log), `"BLOCK_SCREEN"` (show the bundled fallback screen) or `"TERMINATE"` (close the
     * app's task via `finishAffinity`). Validated at build time; an unrecognized value fails the build
     * rather than silently falling back to something more permissive OR more aggressive than intended.
     */
    abstract val restrictedAction: Property<String>
    /**
     * Whether [restrictedAction] also applies to [com.apparmorx.runtime.ProtectionState.INDETERMINATE]
     * (missing/stale/unavailable required evidence — a much weaker signal than a confirmed detection,
     * routinely produced by OEM restrictions or cold-start timing). Defaults to false: indeterminate
     * evidence is always observe-only unless a host explicitly decides false positives are an
     * acceptable cost for their threat model.
     */
    abstract val enforceIndeterminate: Property<Boolean>

    /**
     * Whether [restrictedAction] applies during initial application startup while checks are still
     * pending (fail-closed startup gate). Defaults to false for backward compatibility.
     */
    abstract val failClosedOnStartup: Property<Boolean>

    /**
     * Automatically injects WindowManager.LayoutParams.FLAG_SECURE into guarded activities
     * to prevent screenshot capture, screen-recording, and task-switcher data leakage.
     */
    abstract val secureScreen: Property<Boolean>

    /**
     * Automatically sets filterTouchesWhenObscured = true on root views to prevent tapjacking
     * and overlay hijacking attacks.
     */
    abstract val filterTouches: Property<Boolean>

    /**
     * Optional customer-managed HTTPS telemetry endpoint. When non-blank, structured incident events
     * are delivered via rate-limited, privacy-preserving HTTPS POST requests. Disabled by default.
     */
    abstract val telemetryUrl: Property<String>

    /**
     * Optional pre-shared HMAC-SHA256 key for authenticating telemetry webhook requests.
     * When configured, requests include X-AppArmorX-Timestamp and X-AppArmorX-Signature headers.
     */
    abstract val telemetryHmacKey: Property<String>

    /**
     * How much each report says: `MINIMAL` (threat ids, OS, ABI), `STANDARD` (default: adds app version,
     * protection state, response taken, checks that could not run) or `EXTENDED` (adds manufacturer, model,
     * patch level, installer and every check result). Never includes user data or device identifiers.
     */
    abstract val telemetryDetail: Property<String>

    /**
     * Extra HTTP headers sent with every report, for example `telemetryHeaders.put("X-Api-Key", "...")`.
     * Anything embedded in an app can be extracted from it, so treat these as routing/tenant hints and rate-limit
     * server-side rather than as strong authentication. Reserved names (Host, Content-Type, X-AppArmorX-*) are rejected.
     */
    abstract val telemetryHeaders: org.gradle.api.provider.MapProperty<String, String>

    /**
     * In-App Dependency Firewall: intercept and neutralize ClipboardManager.getPrimaryClip
     * invocations, returning null instead of allowing untrusted SDK clipboard scraping.
     */
    abstract val firewallClipboard: Property<Boolean>

    /**
     * In-App Dependency Firewall: intercept and sanitize Settings.Secure.ANDROID_ID queries,
     * returning sanitized dummy identifiers to prevent device fingerprint harvesting.
     */
    abstract val firewallIdentifiers: Property<Boolean>

    /**
     * In-App Dependency Firewall: intercept and neutralize LocationManager.getLastKnownLocation
     * queries, returning null to block background location harvesting by third-party SDKs.
     */
    abstract val firewallLocation: Property<Boolean>

    /**
     * In-App Dependency Firewall: enforce strict TLS certificate validation and hostname verification,
     * neutralizing permissive TrustManagers and permissive HostnameVerifiers injected by SDKs.
     */
    abstract val firewallNetworkSecurity: Property<Boolean>

    /**
     * Cryptographic payload digest pins for package archive entries (e.g. "classes.dex" to SHA-256 hex).
     * If configured, the runtime strictly verifies these entries against the embedded pins.
     */
    abstract val payloadDigests: org.gradle.api.provider.MapProperty<String, String>

    /**
     * Best-effort native hardening: at process startup, occupies this process's single ptrace
     * "tracer" slot with a small watchdog of our own, so a later attach from an external tool --
     * the mechanism `frida -U` (attach to an already-running process) uses on Android -- fails
     * instead of succeeding. Default `false` in every profile, including `HARDENED`: unlike the
     * other settings here, this forks a child process at startup, a distinct and separate risk
     * (interaction with native crash reporting, fork() in a multi-threaded process) worth an
     * explicit decision rather than a profile default.
     *
     * State its real scope honestly wherever this is described: it does nothing against spawn-time
     * injection (`frida -f`, which runs before this ever executes), and does not stop an attacker
     * who can simply kill the watchdog process directly. It is hardening against the most common
     * real-world attach path, not a guarantee -- never call it unbypassable. Never enabled on a
     * debuggable variant, enforced both at build time (`ProtectionProfile`) and at runtime
     * (`SecurityRuntime`), because it would fight the developer's own debugger the same way it
     * fights an attacker's.
     */
    abstract val antiPtraceHardening: Property<Boolean>

    /**
     * Opt-in, narrowly-scoped exception to this project's default rule against automatic process
     * termination (see AGENTS.md for the exact carve-out). When `true`, a guarded lifecycle call that
     * sees confirmed (`DETECTED`, never merely unavailable) hooking/injection-specific evidence --
     * Frida/Xposed/a native hook trampoline, never root or a signer mismatch -- hard-kills the process
     * via `Process.killProcess`, regardless of [restrictedAction]. Default `false` in every profile
     * including `HARDENED`; forced `false` on a debuggable variant at both build time and runtime, the
     * same as [antiPtraceHardening], because it would fight the developer's own debugger.
     *
     * State its real limit everywhere this is described: evidence is checked periodically and on
     * lifecycle events, not continuously, so this cannot prevent the single action already in flight
     * at the moment detection fires -- it can only stop further activity in the same process. Never
     * describe this as "unbypassable" or as closing the dependency-firewall's framework-API gap.
     */
    abstract val killOnConfirmedHooking: Property<Boolean>
}
