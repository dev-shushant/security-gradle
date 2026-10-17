# AppArmorX Developer Integration & User Guide

**Author:** Shushant Tiwari  
**Product:** AppArmorX (`com.apparmorx.security`)  
**Target Platform:** Android (API 29+)  
**Build System:** Android Gradle Plugin 9.4.1+ / Gradle 9.7+  

---

## 1. Introduction

AppArmorX is designed around a **zero-integration** approach: runtime integrity checks and a dependency firewall for supported third-party SDK calls are added to your application at build time, with no changes to your source code. It raises attacker cost and gives you evidence; it does not make a compromised device trustworthy (see Honest limits in the README).

By applying the Gradle plugin, your application gets:
- A startup preflight gate that runs in `<init>` / `onCreate` (not benchmarked; no latency figure is claimed)
- A dependency firewall that reroutes supported clipboard, device-ID, location and TLS-setup calls
- Optional screen-capture and obscured-touch protection (`FLAG_SECURE`, `filterTouchesWhenObscured`) on guarded Activities
- Direct syscalls (`svc #0` / `syscall`) for sensitive `/proc` reads, so a hooked libc cannot trivially alter them
- An optional Mirage response (random 40-120 ms delays instead of an obvious crash)
- Periodic foreground evaluation

---

## 2. Installation & Quick Setup

### Step 1: Add AppArmorX Plugin

In your application module's `build.gradle.kts` (e.g. `app/build.gradle.kts`):

```kotlin
plugins {
    id("com.android.application")
    id("com.apparmorx.security") version "0.1.0"
}
```

### Step 2: Configure Release Signer Pins

For production release builds, AppArmorX verifies that the APK was signed by your authorized release key:

```kotlin
security {
    // SHA-256 fingerprint of your app release signing certificate
    signingCertificates.set(listOf(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ))
}
```

> **How to get your certificate fingerprint:**
> ```bash
> keytool -list -v -keystore release.jks -alias your-alias
> # Copy the SHA256 string, remove colons, and convert to lowercase hex.
> ```

---

## 3. Configuration DSL Reference

Configure behavior using the `security` extension in `build.gradle.kts`:

```kotlin
security {
    // ------------------------------------------------------------------------
    // Threat Response & Policy Action
    // ------------------------------------------------------------------------
    // Action triggered when a confirmed threat is detected:
    // • "OBSERVE"     : Log and track findings without interrupting UX (default only for DEVELOPMENT profile and debuggable builds)
    // • "WARN"        : Display a non-blocking security warning toast to the user
    // • "BLOCK_SCREEN": Display full-screen security block screen preventing interaction
    // • "TERMINATE"   : Terminate the process cleanly
    restrictedAction.set("BLOCK_SCREEN")

    // Escalate to restrictedAction even on UNAVAILABLE or pending evidence.
    // Recommended: false (prevents false-positives on restrictive OEM forks).
    enforceIndeterminate.set(false)

    // ------------------------------------------------------------------------
    // In-App Dependency Firewall (SDK Sandbox)
    // ------------------------------------------------------------------------
    // Intercepts ClipboardManager.getPrimaryClip / hasPrimaryClip across all SDKs
    firewallClipboard.set(true)

    // Intercepts Settings.Secure.ANDROID_ID, TelephonyManager.getDeviceId / getImei
    firewallIdentifiers.set(true)

    // Intercepts LocationManager.getLastKnownLocation
    firewallLocation.set(true)

    // Intercepts HttpsURLConnection and SSLContext to block insecure verifiers
    firewallNetworkSecurity.set(true)

    // ------------------------------------------------------------------------
    // Mirage mode (random delays instead of an obvious crash)
    // ------------------------------------------------------------------------
    // Mirage is one of the restrictedAction values above, not a separate toggle: set
    // restrictedAction.set("MIRAGE") to inject non-deterministic micro-jitter into sensitive
    // operations instead of an obvious crash, so a reverse engineer can't tell which check fired.

    // ------------------------------------------------------------------------
    // Hooking response (opt-in; see README's "Honest limits" before enabling)
    // ------------------------------------------------------------------------
    // Hard-kills the process (Process.killProcess) the moment CONFIRMED hooking/injection evidence
    // is seen -- never on root/signer/other RESTRICTED causes, never on a debuggable build, never a
    // profile default. Paired with a dedicated ~750ms watchdog thread (independent of restrictedAction
    // and of any Activity's lifecycle), this measurably prevented a live MITM attack from installing
    // when Frida attached to an already-running process -- but cannot, and does not claim to, stop
    // spawn-time injection (`frida -f`), which runs before this library's first instruction. Off by
    // default everywhere. Full repro: docs/VALIDATION.md (Slice 19).
    killOnConfirmedHooking.set(false)

    // Best-effort native self-protection: occupies this process's ptrace "tracer" slot at startup so a
    // later attach-to-a-running-process fails. Tested on a real rooted, SELinux-enforcing device and
    // found to make NO practical difference there -- AOSP's own policy already denies untrusted_app
    // processes ptrace on themselves, independent of root. Kept as a safe, no-op-on-failure opt-in for
    // older/custom builds without that specific hardening; do not rely on it. Off by default everywhere.
    antiPtraceHardening.set(false)

    // ------------------------------------------------------------------------
    // Build & Release Gates
    // ------------------------------------------------------------------------
    // Require signingCertificates to be configured for non-debuggable variants
    requireReleaseSigningPins.set(true)

    // Optional: Authenticated remote policy feed
    // policyUrl.set("https://security.example.com/feed/android-v1.signed")
    // policyPublicKey.set("<Base64 X.509 Ed25519 public key>")
    // minimumSequence.set(100L)
    // refreshOnBuild.set(false)
}
```

---

## 4. How the In-App Dependency Firewall Works

Third-party analytics, ad networks, and attribution SDKs frequently attempt to harvest user clipboard contents, hardware identifiers, and location coordinates in the background, or disable TLS certificate verification to debug requests.

The AppArmorX Dependency Firewall rewrites bytecode call sites across **all libraries and dependencies** during the AGP ASM compilation pass:

| Target Platform API | Bytecode Interception | Resulting Behavior |
|---|---|---|
| `ClipboardManager.getPrimaryClip()` | `DependencyFirewall.getPrimaryClip()` | Returns `null` when active |
| `ClipboardManager.hasPrimaryClip()` | `DependencyFirewall.hasPrimaryClip()` | Returns `false` when active |
| `Settings.Secure.getString(res, ANDROID_ID)` | `DependencyFirewall.getString()` | Returns `"0000000000000000"` |
| `TelephonyManager.getDeviceId()` | `DependencyFirewall.getDeviceId()` | Returns `null` |
| `TelephonyManager.getImei()` | `DependencyFirewall.getImei()` | Returns `null` |
| `LocationManager.getLastKnownLocation()` | `DependencyFirewall.getLastKnownLocation()` | Returns `null` |
| `HttpsURLConnection.setDefaultHostnameVerifier()` | `DependencyFirewall.setDefaultHostnameVerifier()` | Drops allow-all verifiers |
| `HttpsURLConnection.setHostnameVerifier()` | `DependencyFirewall.setHostnameVerifier()` | Drops connection allow-all verifiers |
| `SSLContext.init(km, tm, sr)` | `DependencyFirewall.sslContextInit()` | Substitutes secure system trust store |

---

## 5. Runtime Monitoring & Inspection

If your application wants to build a custom security dashboard, telemetry reporter, or step-up authentication gate, use the `SecurityRuntime` API:

```kotlin
import com.apparmorx.runtime.SecurityRuntime
import com.apparmorx.runtime.SecurityGuard
import com.apparmorx.runtime.ProtectionState
import com.apparmorx.runtime.Status

class DashboardActivity : AppCompatActivity() {

    override fun onResume() {
        super.onResume()
        evaluatePosture()
    }

    private fun evaluatePosture() {
        // Query high-level defense state
        when (SecurityGuard.lastObservedState()) {
            ProtectionState.READY -> {
                // Device integrity verified clean
            }
            ProtectionState.RESTRICTED -> {
                // Tamper detected! Enforce step-up biometric or step-down functionality
                val snapshot = SecurityRuntime.snapshot()
                val threats = snapshot.evidence.filter { it.status == Status.DETECTED }
                println("Active Threats: ${threats.map { it.check }}")
            }
            ProtectionState.INDETERMINATE -> {
                // Evidence pending or partially restricted by OS
            }
            ProtectionState.CHECKING -> {
                // Initial scan in progress
            }
        }
    }
}
```

---

## 6. ProGuard / R8 Rules

No manual ProGuard or R8 rules are required!  
The AppArmorX runtime AAR includes automated consumer rules that preserve necessary JNI entry points and defense classes during R8 shrinking and obfuscation.

---

## 7. Testing Your Defenses

### Running Test Verification in CI / Local Dev

```bash
# 1. Run plugin validation and Android lint
./gradlew validatePlugins lintRelease --configuration-cache

# 2. Build debug and release APKs and verify protection coverage
./gradlew -p sample assembleDebug verifyDebugProtectionCoverage \
                    assembleRelease verifyReleaseProtectionCoverage \
                    --configuration-cache

# 3. Run connected instrumentation tests on attached physical device or emulator
./gradlew -p sample connectedDebugAndroidTest
```

---

## 8. Support & Security Inquiries

For technical questions or to report security issues, refer to [SECURITY.md](../SECURITY.md).  
AppArmorX is authored and maintained by **Shushant Tiwari**.
