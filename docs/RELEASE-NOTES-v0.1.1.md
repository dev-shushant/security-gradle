# AppArmorX 0.1.1 — broader dependency protection, clearer security evidence

AppArmorX delivers Android runtime protection through one Gradle plugin. **0.1.1 extends the dependency firewall to supported calls inside external JAR/AAR libraries** and fixes cases where missing or malformed evidence could look clean or silently disable a setting.

[Get 0.1.1 on the Gradle Plugin Portal](https://plugins.gradle.org/plugin/com.apparmorx.security/0.1.1) · [Quickstart](https://github.com/dev-shushant/security-gradle/blob/main/QUICKSTART.md)

## What you get with AppArmorX

- **Build-integrated protection:** instrumentation, runtime packaging and initialization without adding application initialization code. Your source files stay unchanged.
- **Runtime security evidence:** checks for root, debugging, hooking and tampering signals, with explicit `CLEAR`, `DETECTED` and `UNAVAILABLE` outcomes.
- **A configurable dependency firewall:** supported clipboard, identifier, last-known-location and permissive TLS-setup calls are routed through your policy.
- **Deployment controls and visibility:** DEVELOPMENT, STANDARD and HARDENED profiles, configurable responses, protection coverage reports, manifest findings and HTML/JSON/SARIF output.

These are existing engine capabilities available in this release; the changes below are new in 0.1.1. Local protection needs no hosted account or mandatory telemetry. The engine is Apache-2.0 licensed.

## What's new in 0.1.1

### Protection reaches supported library call sites

0.1.0 instrumented project bytecode only. **0.1.1 also rewrites supported calls in external JAR/AAR bytecode**, including:

| Call category | Policy-controlled behavior |
|---|---|
| Clipboard reads | Neutralize supported primary-clip reads and availability checks |
| Device identifiers | Sanitize supported Android ID, device-ID and IMEI access |
| Last-known location | Return no location for supported calls when configured |
| TLS setup | Reject supported permissive verifier/trust-manager configurations |

Lifecycle guard injection remains scoped to application project components. The dependency pass does not add lifecycle overrides to library components.

### Unknown evidence stays unknown

- Failed or empty native wait-channel reads now return `UNAVAILABLE`, rather than `CLEAR`.
- SELinux parsing accepts valid `0`/`1` values; malformed or missing data returns `UNAVAILABLE`.
- Malformed optional security booleans now invalidate policy parsing instead of silently becoming `false`. Absent legacy fields retain their defaults.

### Stronger release verification

- An independent consumer downloads the published plugin, builds a signed R8 release, verifies both native ABIs and reports, and checks configuration-cache reuse.
- Final DEX inspection confirms an external-JAR clipboard call routes through `DependencyFirewall`.
- Local validation passed 171 unit tests, native regressions, plugin validation, Android lint and 21/21 Android 17 arm64 emulator tests.
- Post-release CI passed build/candidate checks, the public consumer, and both API 29 and API 33 x86_64 emulator jobs. Emulator jobs are now required, and failures retain raw test results and logs. [Verified CI run](https://github.com/dev-shushant/security-gradle/actions/runs/39043122340).

## Upgrade to 0.1.1

```kotlin
plugins {
    id("com.android.application")
    id("com.apparmorx.security") version "0.1.1"
}
```

If your project customizes `pluginManagement.repositories`, include `gradlePluginPortal()` alongside its Android repositories. Rebuild and review the protection report.

**Upgrade impact:** supported calls inside dependencies may now be governed by firewall settings that previously affected project code only. Exercise clipboard, identifier, location and networking flows before rollout. No new application initialization code is required.

## Coverage and release status

AppArmorX remains **pre-1.0**. Framework, AndroidX and AppArmorX runtime namespaces are excluded from the dependency pass. Unsupported APIs, reflection and dynamically injected calls outside rewritten bytecode are not covered by this firewall.

The Play Integrity helper currently provides library-presence and transaction-hashing helpers, not token requests or server verification. Recorded watchdog results apply to the tested payload and timing; periodic checks cannot prevent every action already in flight.

[Coverage and limits](https://github.com/dev-shushant/security-gradle/blob/main/docs/HONEST-LIMITS.md) · [Release qualification](https://github.com/dev-shushant/security-gradle/blob/main/docs/RELEASE-QUALIFICATION-0.1.1.md) · [Source](https://github.com/dev-shushant/security-gradle)
