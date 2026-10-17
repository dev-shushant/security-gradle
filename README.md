# AppArmorX

**In-app security for Android, delivered as a single Gradle plugin. Free, inspectable, zero integration.**

> Author & maintainer: **Shushant Tiwari** · `com.apparmorx` · plugin id `com.apparmorx.security` · pre-release `0.1.0` (live on the Gradle Plugin Portal)

Most mobile app protection asks developers to learn an SDK, write initialisation code, wire up callbacks and
build their own "you are rooted" screen. AppArmorX inverts that. You apply one plugin. At build time it
rewrites your app's bytecode, bundles a native detection engine, injects guards into your Activities,
Services, Receivers and Application class, and audits the packaged output. **You write no security code.**

```kotlin
plugins {
    id("com.android.application")
    id("com.apparmorx.security") version "0.1.0"
}
```

That is the whole integration.

> **Status: pre-release `0.1.0`, published on the [Gradle Plugin Portal](https://plugins.gradle.org/plugin/com.apparmorx.security).**
> `gradlePluginPortal()` is enabled by default in Gradle, so no extra repository is needed. To evaluate an
> unreleased local build instead, use `mavenLocal()` (see [QUICKSTART.md](QUICKSTART.md)). Licensed under
> Apache-2.0.

---

## Why it exists

| Problem with typical app-protection tooling | AppArmorX's answer |
|---|---|
| Paid, closed source, per-app licences | Free and inspectable; the core needs no account, no hosted service, no Google Play |
| SDK integration: init calls, listeners, custom block screens | Gradle plugin only; consumer source is never edited |
| Third-party SDKs quietly scrape clipboard, IMEI, location | Compile-time **dependency firewall** reroutes those calls, including calls made inside libraries |
| "Passed" when a check couldn't run | Three-state evidence: `CLEAR`, `DETECTED`, `UNAVAILABLE`. A failed probe is **never** reported as clean |
| Claims of "unbypassable" protection | None made. See [Honest limits](#honest-limits) |

---

## How it works

```
 BUILD TIME (Android Gradle Plugin)                         RUN TIME (device)
 ────────────────────────────────────                       ──────────────────────────────────────────
 1. Verify signed policy (Ed25519, rollback floor)          Startup gate  ── runs in <init>/onCreate,
 2. ASM bytecode rewrite                                                     before the first screen
      • guards in Activity / Application /                  Probe engine  ── 28 checks: JVM, framework
        Service / BroadcastReceiver                                          and native C++ (direct
      • dependency-firewall call rerouting                                   syscalls, bypassing libc)
 3. Bundle native engine (arm64-v8a, x86_64)                Firewall      ── neutralises SDK data scraping
 4. Audit merged manifest, emit SARIF report                Response      ── observe / warn / block / finish
 5. Fail the build if required protection is missing        Multiprocess  ── one posture across :processes
                                                             Hook response ── opt-in fast-kill watchdog
                                                                               (verified; see below)
```

Everything generated lives in build outputs and is inspectable; your source tree is untouched.

---

## What you get

### Runtime self-protection (RASP)
- **Startup preflight gate** that runs before app screens and checks debugger, debuggable flag, signer and
  tracer. Optional **fail-closed** mode holds sensitive execution until the first verdict exists.
- **28 checks** covering root, debugger/tracer attach, Frida/Xposed/Substrate artifacts, injected threads,
  anonymous executable memory, libc hook trampolines, W^X and relocation checks, SELinux state, emulator
  signals and APK integrity. Full list in the [probe matrix](#probe-matrix).
- **Direct syscalls** (`svc #0` on ARM64, `syscall` on x86_64) for the sensitive `/proc` reads, so a hooked
  libc cannot trivially lie to them.
- **Headless coverage**: Services and BroadcastReceivers are gated, not just Activities.
- **Multiprocess aware**: secondary processes share one security state instead of each re-scanning.
- **Mirage mode** (opt-in via `restrictedAction.set("MIRAGE")`): non-deterministic micro-delays instead of an obvious crash that tells a
  reverse engineer which check fired.

### Dependency firewall (supported SDK call sites)
Bytecode rewriting reroutes these calls, including those made by third-party libraries:

| Intercepted | Effect |
|---|---|
| `ClipboardManager.getPrimaryClip` / `hasPrimaryClip` | returns nothing |
| `Settings.Secure` `ANDROID_ID`, `TelephonyManager.getDeviceId` / `getImei` | sanitised values |
| `LocationManager.getLastKnownLocation` | returns nothing |
| `HttpsURLConnection` hostname verifier / `SSLContext.init` | permissive verifiers and trust-all managers rejected |

### UI protection
Optional `FLAG_SECURE` (screenshots, recording, recents thumbnail) and `filterTouchesWhenObscured`
(tapjacking) applied to guarded Activities.

### Hooking response (opt-in, verified on-device)
By default, no profile kills the process; `TERMINATE` is `finishAffinity()`, never a hard kill. Two
narrow, explicit exceptions exist for hosts who want them, both off by default in every profile
including `HARDENED`, both disabled on debuggable builds, and both tested against a real Frida attack
on a rooted device rather than assumed to work:

- **`killOnConfirmedHooking`**: when the device shows confirmed (never merely unavailable)
  hooking/injection evidence — a Frida/Xposed artifact, a native hook trampoline — `Process.killProcess`
  is called. Paired with `HookWatchdog`, a dedicated ~750ms poll loop independent of any Activity's
  lifecycle, this **measurably prevented** a live MITM attack from being installed when Frida attached
  to an already-running process: the script never got past its first line before the process was gone
  (full repro: [docs/VALIDATION.md](docs/VALIDATION.md), Slice 19). It cannot, and does not claim to,
  stop **spawn-time** injection (`frida -f`) — the attacker's code runs before this library's first
  instruction in that case, which no in-process response can outrace. Both outcomes are documented
  side by side; see [Honest limits](#honest-limits).
- **`antiPtraceHardening`**: occupies this process's single ptrace "tracer" slot at startup so a later
  attach (the same mechanism) fails. Implemented, on-device tested, and **found to make no practical
  difference** on a representative modern, SELinux-enforcing rooted device: AOSP's own policy denies
  `untrusted_app` processes `ptrace` on themselves, independent of root, so the one domain that could
  use this trick is blocked from using it by the OS itself. Kept as a safe no-op-on-failure opt-in for
  older/custom builds without that specific hardening; not something to market as closing any gap.

```kotlin
security {
    killOnConfirmedHooking.set(true)   // off by default everywhere; see the scope above before enabling
    antiPtraceHardening.set(true)      // off by default everywhere; tested ineffective on modern devices
}
```

### DevSecOps output
- **HTML security report** per variant (verdict, active layers, overrides, digests), self-contained and
  script-free, so it can be attached to a release or shown to an auditor.
- **SARIF 2.1.0** report (`build/reports/apparmorx/security-audit-<variant>.sarif`), rules `AAX-101`…`AAX-206`,
  ready for GitHub Code Scanning or SonarQube.
- **Manifest auditor**: release `debuggable`, `allowBackup`, cleartext traffic and similar.
- **Protection coverage verifier** (`verify<Variant>ProtectionCoverage`) that fails `assemble<Variant>` if
  required artifacts are absent from the packaged APK.
- Fully **Gradle Configuration Cache** compatible.

### Zero-config signer pin
Release builds require a pinned signing certificate so repackaged (re-signed) APKs are detected. The plugin
reads your release `signingConfig` keystore at build time and derives the SHA-256 pin itself. The keystore
password is used only during the build and is never written to the APK or the reports. (Like AGP's own
signing inputs, it lives in the Gradle configuration cache entry, so keep that directory private.)

### Optional trust & telemetry
- **Hardware-backed key attestation** (Keystore TEE / StrongBox) with nonce binding.
- **Play Integrity adapter**, reflection-based, so there is no hard dependency; absent Play means *no verdict*,
  never a fabricated one.
- **Reports to your own server**: set `telemetryUrl` and get signed (HMAC-SHA256) JSON reports with app
  version, protection state, the response taken, checks that couldn't run and, optionally, coarse device facts
  (`telemetryDetail`: MINIMAL / STANDARD / EXTENDED), plus custom headers. Offline queue, backoff, circuit
  breaker, no redirects. Off unless you set a URL; never any user data or device identifiers.
  Schema and server-side verification code: [docs/TELEMETRY.md](docs/TELEMETRY.md).

---

## Quick start

### 1. Apply the plugin
```kotlin
plugins {
    id("com.android.application")
    id("com.apparmorx.security") version "0.1.0"
}
```

### 2. Build
```bash
./gradlew assembleRelease --configuration-cache
```

### 3. Choose a protection profile (optional)
With no configuration you get the **`STANDARD`** profile. Pick another with one line:

| Profile | Response to a *confirmed* threat | Firewall | Startup gate | Screen capture block |
|---|---|---|---|---|
| `DEVELOPMENT` | observe and record only | off | off | off |
| **`STANDARD`** (default) | `BLOCK_SCREEN` | on (all 4) | off | off |
| `HARDENED` | `BLOCK_SCREEN` | on (all 4) | **fail-closed** | on |

Rules every profile follows:
- **Debuggable variants never enforce a response**, so your own debugger can't lock you out. Passive
  protections (firewall) stay on.
- **Unavailable / indeterminate evidence never triggers enforcement** unless you set `enforceIndeterminate`.
- **Configuration findings are advisory, never enforced.** `network-cleartext-permitted` describes your own
  app's settings, not an attacker, so it is reported (UI, telemetry, SARIF) but cannot block your users.
  Only device/tamper/instrumentation evidence can move the app to RESTRICTED.
- **No profile kills the process by default.** `TERMINATE` is `finishAffinity()`, not a process kill.
  `killOnConfirmedHooking` is a separate, explicit, narrowly-scoped opt-in exception — never a profile
  default, never on a debuggable build — see [Hooking response](#hooking-response-opt-in-verified-on-device) above.
- Release builds on emulators are expected to be flagged (emulator probe), so test release behaviour on
  a real device or use `DEVELOPMENT`.

```kotlin
security {
    profile.set("HARDENED")                              // DEVELOPMENT | STANDARD | HARDENED
    // Signer pin: derived automatically from your release signingConfig. Set explicitly only if you
    // sign outside Gradle or accept several signers (rotation); an explicit list always wins.
    // signingCertificates.set(listOf("<64-hex-sha256>"))

    // Any explicit value overrides the profile. Weaker-than-profile overrides are flagged
    // as WEAKENED in the build report.
    // restrictedAction.set("WARN")  // OBSERVE | WARN | MIRAGE | BLOCK_SCREEN | TERMINATE
}
```

After `assembleRelease`, open **`build/reports/apparmorx/protection-report-release.html`**: a
self-contained report with the verdict, which protection layers are on, overrides and weakenings,
manifest findings and payload digests.

Full walkthrough: [QUICKSTART.md](QUICKSTART.md) · reference: [docs/USER-GUIDE.md](docs/USER-GUIDE.md).

### Optional: read posture from code
Not required for protection, available if you want it:

```kotlin
when (SecurityGuard.lastObservedState()) {
    ProtectionState.READY         -> { /* verified */ }
    ProtectionState.RESTRICTED    -> { /* confirmed detection */ }
    ProtectionState.INDETERMINATE -> { /* evidence missing/stale: not "clean" */ }
    ProtectionState.CHECKING      -> { /* startup scan in progress */ }
}
```

---

## Probe matrix

| Probe | Engine | What it observes |
|---|---|---|
| `policy` | JVM | Ed25519 signature and sequence floor of the bundled policy |
| `application-id` | JVM | Package-name tampering / repackaging |
| `signing-certificate` | JVM | Signer SHA-256 against your pinned allowlist |
| `hook-library` | Managed | Known instrumentation libraries in `/proc/self/maps` |
| `native-engine` | Native | Native core loaded and available |
| `native-tracer` | Native | `TracerPid` via inline syscall |
| `native-root-path` / `native-root-mount` | Native | su/Magisk artifacts; suspicious mounts |
| `native-hook-library` | Native | Frida/Xposed/Substrate mappings via kernel reads |
| `native-tool-thread` | Native | Injected worker threads (`gum-*`, `frida-*`, `gdbus`, …) |
| `native-libc-origin` | Native | Libc symbol interposition (`dlsym` vs `dladdr`) |
| `native-hook-trampoline` | Native | Inline-hook prologues on libc entry points (ARM64, x86_64) |
| `native-selinux` | Native | SELinux enforcing state (reports `UNAVAILABLE`, not clean, if the device denies reading `/sys/fs/selinux/enforce` — confirmed happening on a real SELinux-enforcing device) |
| `native-hardware-device` | Native | Emulator / virtualised hardware (same EACCES-vs-absent distinction as `root-path`) |
| `native-wchan` | Native | `ptrace_stop` wait channel |
| `native-frida-port` | Native | Default Frida listener ports (corroborating signal only; reports `UNAVAILABLE`, not clean, if `/proc/net/tcp[6]` is unreadable — confirmed happening on a real SELinux-enforcing device, see [docs/STATUS.md](docs/STATUS.md)) |
| `native-memory-rwx` | Native | Suspicious RWX anonymous pages |
| `native-stealth-injection` | Native | Anonymous payloads, tmp staging, deleted libraries |
| `native-relocation-integrity` | Native | ELF W^X program headers; relocation pointer bounds |
| `debugger` / `debuggable-app` | Framework | Debugger attached; `FLAG_DEBUGGABLE` set |
| `apk-integrity` | Framework | APK readable and payload digests match (when pinned) |
| `root-path` / `build-tags` | Framework | su/Magisk paths; `test-keys` system build |
| `hook-classes` | Framework | Xposed/Substrate classes loadable |
| `network-cleartext-permitted` | Framework | App permits unencrypted HTTP |
| `environment-hardware` / `virtual-space` | Framework | Emulator fingerprints; cloning/virtual-space paths |

---

## Verification

Evidence is recorded in [docs/STATUS.md](docs/STATUS.md) and [docs/VALIDATION.md](docs/VALIDATION.md).

- Unit tests for `policy`, `plugin` (bytecode visitor, manifest auditor, archive) and `runtime`.
- `validatePlugins`, Android release lint, native AAR for `arm64-v8a` and `x86_64`.
- **Repackaging attack reproduced**: built a release signed with a real keystore (confirmed CLEAR),
  unzipped it, tampered its content, re-signed with a different unrelated keystore, reinstalled — detection
  flipped CLEAR → DETECTED on the live app. Root detection confirmed against an emulator's own root tooling.
  Details: [docs/VALIDATION.md](docs/VALIDATION.md) (14 Oct 2026 entry). Not yet tested: hidden root or Frida.
- **Physical device**: Google Pixel 7 Pro, Android 17 (API 37), `connectedDebugAndroidTest` on the `sample`
  app, **21/21 passing**. The same 21 also pass on an **API 35 arm64 emulator** (where the environment
  probe correctly reports DETECTED). The emulator run also showed `native-hardware-device` staying CLEAR
  there, so the native emulator probe is weaker than the Kotlin one; treat emulator detection as best-effort: 14 runtime/native/component tests plus 7 adversarial simulations (simulated SDK
  clipboard scraping, IMEI/ANDROID_ID harvesting, location harvesting, trust-all TLS verifier, Mirage
  jitter, certificate tamper).
- CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)): a blocking job runs unit tests, plugin
  validation, lint, publish-to-Maven-Local and a minified R8 sample release build. A second job runs the
  sample's instrumented tests on x86_64 emulators (API 29, 34, 35); it is informational until its results
  have been seen on CI hardware (only API 35 arm64 has been run so far).
- **Real Frida/root attack, reproduced and root-caused, not simulated**: a rooted AVD with a real
  `frida-server` attached, a real self-signed-cert attacker server, and a real clean-room consumer app
  built only from the plugin's embedded runtime. Findings, in order: the dependency firewall blocks
  4/4 attacks from the app's own code; a direct framework call from injected Frida code (bypassing the
  firewall entirely) still achieves a full MITM when attaching to an already-running process; enabling
  `killOnConfirmedHooking` + `HookWatchdog` **prevents that same MITM** by killing the process before
  the bypass installs (confirmed via `logcat` and `pidof`, ~1 second reaction time); the same defense
  cannot beat spawn-time injection (`frida -f`), which is architecturally unbeatable by anything running
  inside the process it spawns. Full repro, commands and logs: [docs/VALIDATION.md](docs/VALIDATION.md)
  (Slices 16–19), [docs/STATUS.md](docs/STATUS.md) (Slices 19–23).

The `sample` app includes a live "SOC" HUD with an attack simulator, useful for demos.

---

## Honest limits

Security claims should be falsifiable, so these are stated up front.

- **Nothing here is unbypassable.** A determined attacker with kernel or hypervisor control can analyse and
  patch any client-side protection. AppArmorX raises attacker cost and gives you evidence; it does not
  make a compromised device trustworthy.
- **Client-side checks complement server-side authorisation; they never replace it.**
- **The dependency firewall protects the app's own code; it cannot protect against an attacker who
  bypasses that code entirely.** A root+Frida attacker calling Android framework TLS APIs directly
  (not through the app's own call sites) can still complete a MITM attack — confirmed by a real,
  reproduced attack, not assumed. This is a universal limitation of client-side RASP, not specific to
  AppArmorX: no competing product, free or paid, can sandbox further API calls made by an attacker who
  already has code executing in-process. `killOnConfirmedHooking` + `HookWatchdog` close this for an
  attacker who attaches to an already-running process (verified); nothing closes it for spawn-time
  injection (verified it doesn't, on the same attack, same session). State both outcomes together —
  see [docs/STATUS.md](docs/STATUS.md) Slices 16–23 for the full, honest accounting, including a native
  anti-ptrace trick that was tried and found ineffective on modern SELinux-enforcing devices.
- **Paid RASP products have the same spawn-time limit; they do not publish a fix for it either.** The
  one architecturally different answer — moving the trust decision to a hardware-backed, server-verified
  attestation (Google Play Integrity) that lives outside the vulnerable process — is a deliberately
  deferred roadmap item, not implemented, tracked in [docs/STATUS.md](docs/STATUS.md)'s "Next
  implementation order".
- **Tested on one physical device family so far.** The supported toolchain/OS/ABI matrix is still being
  built. Magisk/Zygisk cloaking evolves and is an ongoing test area. No independent penetration test has
  been performed.
- **Full GOT relocation validation** is not complete; `native-relocation-integrity` covers W^X headers and
  pointer-bounds only.
- **Payload integrity** (the packaged-APK anti-tamper claim) is presence-checked plus optional digest pins;
  a signed integrity manifest over the full payload is the next planned step.
- **Unavailable is not clean.** On OEM-restricted devices some probes report `UNAVAILABLE`/`INDETERMINATE`;
  these only trigger enforcement if you set `enforceIndeterminate`.
- The `sample` release build uses a placeholder signer purely to exercise the packaging gate.
- Application module only: applying the plugin to a library module fails the build by design.
- Flutter / React Native / Unity hosts are untested; protecting the Android shell does not protect Dart or
  JS business logic.

---

## Repository layout

| Module | Role |
|---|---|
| [`plugin/`](plugin) | Gradle plugin: policy verification, ASM visitors, manifest audit, SARIF, coverage verification |
| [`runtime/`](runtime) | Android library: initializer, scanner, firewall, enforcement, telemetry, attestation, native C++ engine |
| [`policy/`](policy) | Pure-JVM signed-policy format and Ed25519 verification |
| [`sample/`](sample) | Demo app consuming the plugin, with on-device and adversarial tests |

## Documentation

[Quickstart](QUICKSTART.md) · [Telemetry](docs/TELEMETRY.md) · [User guide](docs/USER-GUIDE.md) · [Architecture & threat model](docs/ARCHITECTURE.md) ·
[Design specification](docs/DESIGN-SPEC.md) · [Policy format](docs/POLICY.md) ·
[Validation matrix](docs/VALIDATION.md) · [Status](docs/STATUS.md) · [Roadmap research](docs/RESEARCH-ROADMAP.md) ·
[Release notes](docs/RELEASE-NOTES-v0.1.0.md) · [Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md)

## Ownership & license

Authored and maintained by **Shushant Tiwari**. Copyright 2026 Shushant Tiwari.
Licensed under the [Apache License, Version 2.0](LICENSE) -- free to use, modify and redistribute,
including commercially, with attribution and without a warranty.
