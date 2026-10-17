# AppArmorX v0.1.0 Release Notes

**Status:** pre-release, published on the Gradle Plugin Portal
**Author & maintainer:** Shushant Tiwari
**Plugin id:** `com.apparmorx.security`
**Distribution:** Gradle Plugin Portal only. The runtime AAR and the policy verifier are embedded in
the plugin jar; there are no separate runtime or policy artifacts. See [PUBLISHING.md](PUBLISHING.md).

---

## Summary

`0.1.0` is the first pre-release of AppArmorX, an Android Gradle plugin that adds runtime integrity checks and
a dependency firewall at build time, with no source changes in the host app. It raises attacker cost and gives
the developer inspectable evidence. It is not unbypassable and does not replace server-side authorization.
Read the [honest limits](../README.md#honest-limits).

## What is in 0.1.0

### Startup preflight
- A bounded synchronous check runs in `<init>` and `onCreate` before the first screen: policy integrity,
  package id, signing certificate and tracer state.
- Latency has not been benchmarked and no figure is claimed. It narrows the launch window; it cannot stop
  injection that runs before it (for example spawn-time injection).

### Direct syscalls (ARM64 and x86_64)
- Sensitive `/proc/self/maps` and `/proc/self/status` reads use `svc #0` / `syscall`, so a hooked libc or PLT
  entry cannot trivially alter them.
- This does not defend against kernel-level interference.

### Dependency firewall (supported call sites)
- Clipboard: `getPrimaryClip` / `hasPrimaryClip` return nothing.
- Identifiers: `ANDROID_ID`, `getDeviceId`, `getImei` return sanitised values.
- Location: `getLastKnownLocation` returns nothing.
- TLS setup: permissive hostname verifiers and trust-all managers installed via `HttpsURLConnection` and
  `SSLContext.init` are rejected.
- Limit: a direct framework call from injected code (for example a Frida script) bypasses the rewritten call
  sites. This was reproduced.

### UI protection and Mirage response (both opt-in via profile or override)
- `FLAG_SECURE` and `filterTouchesWhenObscured` on guarded Activities. They do not stop a camera
  photographing the screen.
- Mirage: non-deterministic 40-120 ms delays instead of an obvious crash. A deterrent, not prevention.

### Hook and injection evidence
- Injected worker threads (`gum-`, `frida-`, `gdbus`, `linjector`, `pool-frida`) via `/proc/self/task/`.
- Anonymous payloads, tmp-directory staging, deleted libraries and suspicious memory file descriptors in
  `/proc/self/maps`. False-positive measurement across devices has not been done.
- Inline-hook prologue scanning of core libc entry points on ARM64 and x86_64.
- Opt-in `killOnConfirmedHooking` with a watchdog. Verified to stop a real Frida attach-mode MITM on a rooted
  emulator; it does not stop spawn-time injection. See [STATUS.md](STATUS.md).

### Build output
- Self-contained HTML report, SARIF 2.1.0 report, manifest audit, and a coverage verifier that fails
  `assemble<Variant>` when required protection artifacts are missing from the packaged APK.
- Full Gradle Configuration Cache compatibility.

## Verification

- Device: Google Pixel 7 Pro (Android 17 / API 37). `connectedDebugAndroidTest` on the `sample` app: 21/21
  passing. The same 21 pass on an arm64 API 35 emulator.
- Real attacks reproduced and documented: repackaging (CLEAR to DETECTED), root (real `su` binary), and a
  rooted-emulator Frida attack, including what did not hold. See [VALIDATION.md](VALIDATION.md).
- Not verified: hidden root (Magisk/Zygisk cloaking), other OEMs, API 29-33 devices, Flutter / React Native /
  Unity hosts. No independent penetration test has been performed.

## Verification commands

```bash
./gradlew check validatePlugins lintRelease -PreleaseVersion=0.1.0 --configuration-cache
./gradlew -p sample assembleDebug verifyDebugProtectionCoverage \
                    assembleRelease verifyReleaseProtectionCoverage \
                    --configuration-cache
./gradlew -p sample connectedDebugAndroidTest
```
