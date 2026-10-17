# AppArmorX Design Specification

**Author:** Shushant Tiwari
**Group:** `com.apparmorx` | **Plugin:** `com.apparmorx.security`
**Status:** Living design document for the pre-release `0.1.0`. It describes intent and mechanisms. What was
actually verified, and what was not, is in [VALIDATION.md](VALIDATION.md) and [STATUS.md](STATUS.md); where
this document and those differ, those win.

---

## 1. Purpose

Most Android app-protection tooling arrives as an SDK: you add a dependency, write initialization code and
build your own response screen. Third-party libraries already inside the app can also read the clipboard,
device identifiers or last known location without the app's own developers having asked for it.

AppArmorX explores a different delivery model: a single Gradle plugin that changes the build output, so the
host app needs no integration code. The goals are to raise the cost of common attacks, give the developer
inspectable evidence, and never present "could not check" as "clean".

Non-goals: making a compromised device trustworthy, replacing server-side authorization, or claiming any
protection is unbypassable.

## 2. Mechanisms

```
 [Build-time]                 [Run-time evidence]            [Dependency firewall]        [Reporting]
 - Signed policy check        - Startup preflight            - ASM call rerouting         - HTML report
 - ASM bytecode guards        - 28 probes (JVM, framework,   - Clipboard, identifiers,    - SARIF 2.1.0
 - Native engine bundling       native)                        location, TLS setup       - Optional signed
 - Manifest audit             - Direct syscalls for /proc    - Supported call sites          reports to your
 - Coverage verification      - Three-state evidence           only                          own server
```

### 2.1 Build-time

1. **Signed policy.** The bundled policy is verified (Ed25519, with a rollback floor) before anything else.
2. **Bytecode guards.** Guards are added to Activities, Services, BroadcastReceivers and the Application
   class using the Android Gradle Plugin's instrumentation API.
3. **Payload integrity.** Presence of required artifacts in the packaged APK is verified, with optional
   digest pins. A signed integrity manifest over the full payload is a planned step, not implemented.
4. **Manifest audit.** The merged manifest is audited (release `debuggable`, `allowBackup`, cleartext
   traffic and similar). These findings are advisory and never enforced against users.

### 2.2 Run-time evidence

1. **Startup preflight.** A bounded synchronous check runs in `<init>` / `onCreate` before the first screen.
   It narrows the launch window; it does not stop injection that runs before this code. Latency has not been
   benchmarked.
2. **Probes.** 28 checks across JVM, framework and native code (root, debugger/tracer, Frida/Xposed/Substrate
   artifacts, injected threads, anonymous executable memory, libc hook trampolines, W^X, SELinux state,
   emulator signals, APK integrity).
3. **Direct syscalls.** Sensitive `/proc` reads use `svc #0` (ARM64) and `syscall` (x86_64) so a hooked libc
   cannot trivially alter them. This does not defend against kernel-level interference.
4. **Three-state evidence.** Every check returns `CLEAR`, `DETECTED` or `UNAVAILABLE`. A failed or denied
   probe is `UNAVAILABLE`, never `CLEAR`.

### 2.3 Responses

`OBSERVE`, `WARN`, `MIRAGE`, `BLOCK_SCREEN` and `TERMINATE` (`finishAffinity()`, not a process kill). Debuggable
builds never enforce a response against their own developer. Unavailable or indeterminate evidence does not
trigger enforcement unless the host opts in.

**Mirage** (opt-in) applies non-deterministic 40-120 ms delays instead of an obvious crash, so the response is
less predictable to automated tooling. It is a deterrent, not prevention.

**`killOnConfirmedHooking`** (opt-in, off in every profile, disabled on debuggable builds) hard-kills the
process only on `DETECTED` hooking or injection evidence. Verified against a real Frida attach-mode attack
on a rooted emulator; it does not stop spawn-time injection. Details: [STATUS.md](STATUS.md).

### 2.4 Dependency firewall

Supported call sites in the app and its dependencies are rerouted through a policy layer:

| Intercepted | Effect |
|---|---|
| `ClipboardManager.getPrimaryClip` / `hasPrimaryClip` | returns nothing |
| `Settings.Secure` `ANDROID_ID`, `TelephonyManager.getDeviceId` / `getImei` | sanitised value |
| `LocationManager.getLastKnownLocation` | returns nothing |
| `HttpsURLConnection` hostname verifier, `SSLContext.init` | permissive verifiers and trust-all managers rejected |

Limit: this covers rewritten call sites. Direct framework calls from injected code bypass it; this was
reproduced with Frida.

### 2.5 UI protection

Optional `FLAG_SECURE` (blocks screenshots, recording and the recents thumbnail) and
`filterTouchesWhenObscured` on guarded Activities. These do not stop a physical camera photographing the screen.

### 2.6 Optional telemetry

Off unless the host sets a URL. HTTPS only, HMAC-SHA256 signed, bounded offline queue with backoff and a
circuit breaker, no redirects. Designed not to carry personal data or device identifiers. Schema:
[TELEMETRY.md](TELEMETRY.md).

## 3. The host contract

```kotlin
plugins {
    id("com.android.application")
    id("com.apparmorx.security") version "0.1.0"
}

security {
    profile.set("STANDARD")   // DEVELOPMENT | STANDARD | HARDENED
}
```

Everything else is applied at build time. Any explicit override weaker than the profile is flagged as WEAKENED
in the generated report.

## 4. Design principles

1. **Honest state semantics.** Unavailable or failed probes are reported as `UNAVAILABLE` or `INDETERMINATE`,
   never as `CLEAR`.
2. **No enforcement on things the attacker does not control.** Configuration findings are advisory.
3. **Defaults that protect, with every override visible.**
4. **Detection and prevention are separate claims.** A passing check is evidence, not proof of safety.
5. **Client-side checks complement server-side authorization.** A compromised device cannot provide
   unbypassable trust without backend verification. Hardware-backed, server-verified attestation is a roadmap
   item, not implemented.
