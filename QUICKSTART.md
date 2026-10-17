# AppArmorX Quickstart

**Author & maintainer:** Shushant Tiwari (`com.apparmorx`, plugin id `com.apparmorx.security`)
**Version:** `0.1.0` (pre-release, published on the Gradle Plugin Portal)
**Target:** Android application modules, `minSdk` 29+, ABIs `arm64-v8a` and `x86_64`

AppArmorX is applied as a single Gradle plugin. You do not write initialization code or callbacks; the
plugin changes the build output, not your source tree. Read [Honest limits](#honest-limits) before relying
on it for anything.

## Tested toolchain

| Dimension | Verified | Not verified |
|---|---|---|
| AGP / Gradle / JDK | AGP 9.4.1, Gradle 9.8.0, JDK 17 toolchain | other AGP majors |
| `compileSdk` | 34 and 37 | below 34 |
| `minSdk` | 29 | below 29 |
| Devices | Pixel 7 Pro (Android 17), arm64 emulator (API 35) | rooted hardware, other OEMs |

## 1. Make the plugin resolvable

The plugin is published on the [Gradle Plugin Portal](https://plugins.gradle.org/plugin/com.apparmorx.security).
Gradle resolves plugins from the Portal by default; if your `settings.gradle.kts` restricts repositories,
make sure `gradlePluginPortal()` is listed:

```kotlin
// settings.gradle.kts of your app
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
```

To evaluate an unreleased local build of this repository instead, publish to Maven Local and list
`mavenLocal()` first in the same block:

```bash
./gradlew publishToMavenLocal -PreleaseVersion=0.1.0 --configuration-cache
```

## 2. Apply the plugin

In your application module (applying it to a library module fails the build by design):

```kotlin
plugins {
    id("com.android.application")
    id("com.apparmorx.security") version "0.1.0"
}
```

## 3. Build

```bash
./gradlew assembleRelease --configuration-cache
```

During the build the plugin:

1. verifies the signed policy (Ed25519, with a rollback floor);
2. rewrites supported bytecode: guards in Activities, Services, BroadcastReceivers and the Application class,
   and reroutes supported clipboard, identifier, location and TLS-setup calls;
3. bundles the native engine for `arm64-v8a` and `x86_64`;
4. audits the merged manifest and verifies the packaged APK contains the required protection artifacts,
   failing `assemble<Variant>` if it does not.

Outputs (build outputs only; your source is untouched):

- `build/reports/apparmorx/protection-report-release.html`: self-contained report with the verdict, active
  layers, overrides and payload digests.
- `build/reports/apparmorx/security-audit-release.sarif`: SARIF 2.1.0 for GitHub Code Scanning or SonarQube.

## 4. Choose a profile (optional)

With no configuration you get `STANDARD`.

| Profile | Response to a *confirmed* threat | Firewall | Startup gate | Screen-capture block |
|---|---|---|---|---|
| `DEVELOPMENT` | observe and record only | off | off | off |
| `STANDARD` (default) | block screen | on | off | off |
| `HARDENED` | block screen | on | fail-closed | on |

```kotlin
security {
    profile.set("HARDENED")   // DEVELOPMENT | STANDARD | HARDENED
}
```

Rules every profile follows:

- Debuggable variants never enforce a response against their own developer.
- Unavailable or indeterminate evidence does not trigger enforcement unless you set `enforceIndeterminate`.
- Configuration findings (for example cleartext traffic being permitted) are advisory and never block users.
- No profile terminates the process by default. `TERMINATE` is `finishAffinity()`, not a process kill.
- Any explicit override weaker than the profile is flagged as WEAKENED in the HTML report.
- Release builds on emulators are expected to be flagged by the emulator probe. Test release behavior on a
  real device or use `DEVELOPMENT`.

## 5. Optional configuration

Any explicit value overrides the profile.

```kotlin
security {
    restrictedAction.set("WARN")        // OBSERVE | WARN | MIRAGE | BLOCK_SCREEN | TERMINATE
    failClosedOnStartup.set(true)       // hold sensitive execution until the first verdict exists
    secureScreen.set(true)              // FLAG_SECURE on guarded Activities
    filterTouches.set(true)             // filterTouchesWhenObscured on guarded Activities

    firewallClipboard.set(true)
    firewallIdentifiers.set(true)
    firewallLocation.set(true)
    firewallNetworkSecurity.set(true)

    // Signer pin: derived automatically from your release signingConfig. Set it explicitly only if you
    // sign outside Gradle or accept several signers. An explicit list always wins.
    // signingCertificates.set(listOf("<64-hex-sha256>"))

    // Reports to your own server. Off unless you set a URL. Read the key from a secret, never commit it.
    // telemetryUrl.set("https://secops.example.com/api/v1/telemetry")
    // telemetryHmacKey.set(providers.gradleProperty("apparmorx.telemetryKey"))
}
```

Hooking response is a separate, explicit opt-in that is off in every profile and disabled on debuggable
builds. Read its scope and limits in [docs/STATUS.md](docs/STATUS.md) before enabling it:

```kotlin
security {
    killOnConfirmedHooking.set(true)
}
```

## 6. Read posture from code (optional)

Not required for protection.

```kotlin
import com.apparmorx.runtime.ProtectionState
import com.apparmorx.runtime.SecurityGuard

when (SecurityGuard.lastObservedState()) {
    ProtectionState.READY         -> { /* verified */ }
    ProtectionState.RESTRICTED    -> { /* confirmed detection */ }
    ProtectionState.INDETERMINATE -> { /* evidence missing or stale: not "clean" */ }
    ProtectionState.CHECKING      -> { /* startup scan in progress */ }
}
```

`HardwareAttestation` (Android Keystore key attestation) and `PlayIntegrityAdapter` (reflection-based, no hard
dependency) are also available as optional building blocks. Their results only mean something when your
server verifies them. If Play is absent there is no verdict, never a fabricated one.

## 7. CI example: upload SARIF

```yaml
name: Mobile security report
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: '17'
      - run: ./gradlew assembleRelease --configuration-cache
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: app/build/reports/apparmorx/security-audit-release.sarif
          category: apparmorx-security
```

## 8. Try the demo app

The `sample` module is a demo with a live status screen and buttons that simulate SDK-style attacks.

```bash
./gradlew -p sample installDebug
./gradlew -p sample connectedDebugAndroidTest
```

The release build of `sample` uses a placeholder signer purely to exercise the packaging gate.

## Honest limits

- Nothing here is unbypassable. A determined attacker with kernel or hypervisor control can analyze and patch
  any client-side protection. AppArmorX raises attacker cost and gives you evidence.
- Client-side checks complement server-side authorization; they never replace it.
- The dependency firewall covers the app's own supported call sites. Direct framework calls from injected
  code (for example a Frida script) bypass it. This was reproduced, not assumed.
- Spawn-time injection (`frida -f`) runs before this library does and is not stopped by any in-process
  response. See [docs/VALIDATION.md](docs/VALIDATION.md) and [docs/STATUS.md](docs/STATUS.md).
- Unavailable is not clean: a probe that cannot run reports `UNAVAILABLE`, never `CLEAR`.
- Tested on one physical device family so far. No independent penetration test has been performed.
- Flutter, React Native and Unity hosts are untested. Protecting the Android shell does not protect Dart or
  JavaScript business logic.

More: [README](README.md) · [User guide](docs/USER-GUIDE.md) · [Telemetry](docs/TELEMETRY.md) ·
[Architecture](docs/ARCHITECTURE.md) · [Security policy](SECURITY.md)
