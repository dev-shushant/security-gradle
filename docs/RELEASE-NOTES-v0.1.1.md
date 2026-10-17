# AppArmorX 0.1.1 — security correctness patch

## Fixed

- Supported clipboard, identifier, location and TLS-setup call rewriting now also runs over external JAR/AAR bytecode. Version 0.1.0 used project-only instrumentation. Lifecycle guard injection remains scoped to application project components.
- Malformed optional enforcement booleans are rejected instead of silently becoming false; absent legacy fields retain their defaults.
- Failed/empty native wait-channel reads report UNAVAILABLE instead of CLEAR. SELinux status accepts valid 0/1 values and reports malformed data as UNAVAILABLE.

## Verification and documentation

- Added an independent signed R8 consumer fixture, configuration-cache checks, native ABI/report checks and final-DEX verification of an external-JAR clipboard call.
- Added dependency-boundary and policy regressions, native regression CI, and environment-aware device assertions for denied probe reads.
- Corrected Play Integrity helper documentation and narrowed watchdog claims to recorded evidence.
- Local validation: 171 unit tests, native regressions, plugin validation, Android lint, signed R8 consumer and 21/21 Android 17 arm64 emulator tests passed. Post-publication 0.1.1 verification also passed: public plugin resolution, signed R8 build, both native ABIs, reports, configuration-cache reuse and external-JAR clipboard rewriting.

## Upgrade

```kotlin
plugins {
    id("com.apparmorx.security") version "0.1.1"
}
```

If pluginManagement.repositories is customized, include gradlePluginPortal(). Rebuild the app and review the protection report; newly covered supported dependency calls can change clipboard/identifier/location/TLS behavior under your configured firewall policy.

AppArmorX remains pre-1.0. Framework/AndroidX/runtime namespaces, unsupported APIs and injected code are outside this dependency instrumentation scope. No independent penetration assessment, universal OEM compatibility or parity with commercial RASP platforms is claimed. See [honest limits](https://github.com/dev-shushant/security-gradle/blob/main/docs/HONEST-LIMITS.md) and [qualification evidence](https://github.com/dev-shushant/security-gradle/blob/main/docs/RELEASE-QUALIFICATION-0.1.1.md).
