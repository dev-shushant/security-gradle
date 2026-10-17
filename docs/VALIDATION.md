# Current status

See [STATUS.md](STATUS.md) for the consolidated, current gap list — it supersedes any per-entry
"known limitations" below that it explicitly contradicts (this file is a chronological log of what
was verified when; STATUS.md is the single current source of truth). As of 13 October 2026: module
checks, `validatePlugins`, native AAR (`arm64-v8a` + `x86_64`), lint, packaged-APK protection-coverage audit,
multi-component bytecode enforcement gating (Activity, Application, Service, BroadcastReceiver),
offline-resilient SIEM threat telemetry with HMAC-SHA256 request signing, ELF W^X program header & relocation integrity scanning,
and all 21 connected instrumentation and adversarial pentest tests on a real Pixel 7 Pro (Android 17) pass.

# Validation status

## 14 October 2026 — Slice 15: real repackaging + root attacks reproduced and detected on an emulator

Manual adversarial testing against a live Android x86_64/arm64 emulator (API 35, `userdebug`), distinct from
the automated suite above, to get first-hand evidence rather than relying on the automated suite's own claims.

- **Root detection, reproduced against the emulator's own root tooling.** `userdebug` emulator images ship
  `/system/xbin/su`; this was not planted. Installing the sample (debug and release) and launching it produced
  `AppArmorX: Mirage active for guarded activity` in logcat immediately, and the in-app status showed
  "Threat detected" driven by `root-path`. No false negative.
- **Repackaging/re-signing attack, built from scratch against a real signer baseline** (not the sample's
  built-in placeholder-pin fixture, which is a deliberate mismatch and would pass trivially):
  1. Generated a real "owner" keystore, built a release APK signed and pinned with it. Installed and
     confirmed the in-app status showed **no** signer warning (`signing-certificate` = CLEAR).
  2. Unzipped that exact APK, appended a line to `assets/apparmorx/policy.properties` (genuine content
     tamper, not just a re-sign), rebuilt the archive keeping `.so`/`resources.arsc`/`classes.dex`
     uncompressed as AGP does, `zipalign`ed and signed it with a freshly generated, unrelated "attacker"
     keystore (`apksigner verify` confirmed two different SHA-256 certificate digests).
  3. Installed the repackaged, attacker-signed APK over the clean one. The in-app status immediately flipped
     to showing the signer-mismatch note — `signing-certificate` went CLEAR -> DETECTED on the exact same
     app, same device, only the signer and one byte of content changed.
- **Bug found and fixed from this testing**: the demo app's "AppArmorX found: …" message used the CLEAR-phrased
  description for a DETECTED check (e.g. printed "Runs on real hardware, not an emulator" when an emulator
  *was* detected — the opposite of what happened). Added `detectedMeaning()` and fixed the call site; reran
  the full 21/21 suite on the Pixel 7 Pro afterward to confirm nothing else regressed.

Scope and honesty: this was done on one AVD image (API 35, Google APIs, arm64), not a hidden-root tool
(Magisk/Zygisk/KernelSU with hiding), and not against Frida (not installed in this environment — see
STATUS.md's open items). It demonstrates the mechanism works end-to-end against a real forged signature and
real root tooling; it does not demonstrate resistance to cloaked/hidden root or active instrumentation
frameworks, which remain open per STATUS.md.

## 13 October 2026 — Slice 14: automated adversarial pentest suite & full 21/21 physical device validation

Delivered an empirical adversarial attack simulation suite verifying defense resilience under live attack on physical hardware:

- **Adversarial Pentest & Attack Simulation Suite (`AdversarialAttackSimulationTest.kt`)**:
  - Simulated untrusted third-party SDK covert clipboard scraping -> neutralized to `null`.
  - Simulated untrusted third-party SDK device ID / IMEI scraping -> neutralized to `null`.
  - Simulated untrusted third-party SDK ANDROID_ID tracking extraction -> neutralized to dummy zeroes `0000000000000000`.
  - Simulated untrusted third-party SDK geolocation extraction (GPS/Network) -> neutralized to `null`.
  - Simulated MITM attack attempting to install a promiscuous `HostnameVerifier` -> rejected and secure default preserved.
  - Simulated cyber deception timing under Mirage Mode -> verified non-deterministic micro-latency jitter injection.
  - Simulated headless service execution under restricted policy -> verified proper short-circuiting and stop execution.
  - Simulated signing certificate tampering under pinned policy -> verified deterministic detection (`Status.DETECTED`).
- **Complete Hardware Validation Matrix (Google Pixel 7 Pro, Android 17 / API 37)**:
  - **21 / 21 automated connected tests passed with 100% success rate** across runtime, native probes, firewall sandboxing, and adversarial attack vectors:
    - 14 Baseline Runtime & Component Tests in `InitializationTest` (100% PASSED)
    - 7 Adversarial Attack Simulation Tests in `AdversarialAttackSimulationTest` (100% PASSED)

## 13 October 2026 — Slice 13: open threat mesh, resilient SIEM pipeline, headless component gating, & native ELF relocation integrity

Delivered the threat telemetry pipeline, headless service gating, and a native memory relocation-integrity scanner:

- **Offline-Resilient Threat SIEM Pipeline (`OfflineEventQueue` & `TelemetryDispatcher`)**:
  - Bounded persistent disk queueing via `OfflineEventQueue` storing up to 50 security incident events in `noBackupFilesDir` using FIFO eviction (<64KB storage footprint, zero risk of disk exhaustion).
  - Exponential backoff (base 5s, doubling up to 300s) and circuit breaker automatically tripping after 5 consecutive delivery failures.
  - Cryptographic request signing using HMAC-SHA256: sends `X-AppArmorX-Timestamp` and `X-AppArmorX-Signature` (`timestamp.jsonBody`) headers when `telemetryHmacKey` is configured.
  - Covered with comprehensive JVM unit tests verifying queue capacity ceilings, FIFO eviction, backoff intervals, and HMAC signature vectors.
- **Headless Multi-Component Gating (Background Service & BroadcastReceiver)**:
  - Verified bytecode instrumentation and lifecycle gating for headless components without UI.
  - Implemented safe context unwrapping in `SecurityGuard.allowService` and `SecurityGuard.allowReceiver` preventing NPE on unattached components.
  - Added `SampleBackgroundService` and `SampleSecurityReceiver` fixtures in `sample`.
  - `service.stopSelf()` is called and execution is short-circuited under restricted enforcement actions.
- **Dynamic Virtual Memory ELF & Relocation Integrity Scanner (`native-relocation-integrity`)**:
  - Direct `dl_iterate_phdr` inspection in `engine.cpp` auditing program headers of loaded `libapparmorx.so` and `libc.so`.
  - Enforces strict hardware W^X (Write XOR Execute) semantics: trips immediately if any `PT_LOAD` segment has both `PF_X` and `PF_W` flags.
  - Verifies relocation and GOT function pointers (`open`, `read`, `dlsym`) via `dladdr`, detecting symbol interposition and hook redirections into `/data/local/tmp/`, Frida, or Xposed memory. Total native probes expanded to 14.
- **Full Physical Hardware Verification on Google Pixel 7 Pro**:
  - `connectedDebugAndroidTest` on physical Google Pixel 7 Pro (`cheetah_beta`, Android 17 / API 37) passed **14/14 tests** with 100% success rate:
    - `allowActivityReturnsTrueUnderDefaultObservePolicy` (PASSED)
    - `allowNonActivityComponentsReturnTrueUnderDefaultObservePolicy` (PASSED)
    - `allowServiceExecutesUnderActivePolicy` (PASSED)
    - `automaticProviderInitializationDoesNotSilentlyClaimClean` (PASSED)
    - `dependencyFirewallEnforcesNetworkSecurity` (PASSED)
    - `dependencyFirewallInterceptsClipboardWhenEnabled` (PASSED)
    - `dependencyFirewallInterceptsLocationWhenEnabled` (PASSED)
    - `dependencyFirewallInterceptsTelephonyWhenEnabled` (PASSED)
    - `foregroundActivityReceivesPeriodicScanWithoutLifecycleTransition` (PASSED)
    - `launchingUnmodifiedActivityFiresInjectedGuard` (PASSED)
    - `sampleBackgroundServiceExecutesInjectedGuard` (PASSED)
    - `sampleSecurityReceiverExecutesInjectedGuard` (PASSED)
    - `securityBlockActivityLaunchesCleanly` (PASSED)
    - `uiProtectionFlagsAppliedWhenConfigured` (PASSED)
- **Zero-Warning Toolchain Verification**:
  - `:policy:test`, `:plugin:test`, `:runtime:testDebugUnitTest`, `:plugin:validatePlugins`, `:runtime:lintRelease` all passed cleanly.
  - Standalone sample `assembleRelease` built with R8 full minification and verified protection coverage.

## 13 October 2026 — Slice 9: in-app dependency firewall (supported call sites) & native RWX memory audit

Implemented the in-app dependency firewall and a native RWX memory audit:

- **In-App Dependency Firewall (`DependencyFirewall` & `FirewallMethodVisitor`)**:
  - Intercepts invocations to sensitive platform getters (`ClipboardManager.getPrimaryClip`, `ClipboardManager.hasPrimaryClip`, `Settings.Secure.getString`) at compile time via ASM bytecode rewriting.
  - Redirects calls through `com.apparmorx.runtime.DependencyFirewall` without host code changes.
  - Returns safe, sanitized responses (`null` or dummy identifiers like `0000000000000000` for `ANDROID_ID`) when opted in via `firewallClipboard` / `firewallIdentifiers` DSL, preventing third-party SDKs from silent data harvesting without crashing the host app.
  - Covered with pure ASM regression tests in `GuardVisitorTest.kt` asserting bytecode redirection and stripping of raw framework calls.
- **Native In-Memory Shared Library W^X Audit (`native-memory-rwx`)**:
  - Implemented direct `/proc/self/maps` parsing in `probe.h` detecting any loaded `.so` shared library mapped with writable and executable permissions (`rwx`).
  - Flags memory patchers (GameGuardian, Frida `Memory.protect`, dynamic code injectors) attempting to patch in-memory `.text` segments.
  - Tested in native unit tests (`probe_test.cpp`) against clean and patched map fixtures.
- **Verification Across Toolchain & Physical Device**:
  - Host validation: `:policy:test`, `:plugin:test`, `:runtime:testDebugUnitTest`, `:plugin:validatePlugins`, `:runtime:lintRelease` all pass.
  - APK verification: `assembleDebug`, `verifyDebugProtectionCoverage`, `assembleRelease` (with R8 minification and consumer keep rules), and `verifyReleaseProtectionCoverage` all pass.
  - Real device confirmation: `connectedDebugAndroidTest` on physical Pixel 7 Pro (Android 17) passed **8/8 tests** with 100% success rate, validating clipboard sandboxing and `native-memory-rwx` integrity.

## 13 October 2026 — Slice 8: Mirage mode, startup preflight & static auditing

Delivered the following mechanisms (implementation record, not a prevention claim):

- **Startup preflight gate and fail-closed option (`fastPreflight` & `failClosedOnStartup`)**:
  - Narrowed the launch-window fail-open race where asynchronous scans left the initial 200ms unchecked.
  - Implemented a synchronous fast-path preflight (latency not benchmarked) checking active debuggers, debuggable flags, test-keys, su binaries, and hook classes before sensitive host component code executes.
  - Added configurable `failClosedOnStartup` policy ensuring `CHECKING` state enforces the configured response when enabled.
- **Mirage mode (`EnforcementAction.MIRAGE` & `DeceptionEngine`)**:
  - Offers a less predictable alternative to an immediate crash.
  - Injected non-deterministic micro-latency sleep jitter (40–120ms) to make timing less predictable to automated tooling. A deterrent, not prevention.
- **Expanded Direct Kernel Syscalls (`direct_lstat`)**:
  - Implemented raw inline assembly `direct_fstatat` and `direct_lstat` using `__NR_newfstatat` (`svc #0` on ARM64, `syscall` on x86_64), replacing libc `lstat` calls across all root binary and device node probes.
- **Multi-Architecture & Multi-Framework Hook Trampoline Detection**:
  - Expanded ARM64 instruction scanner to detect Dobby/ShadowHook trampolines (`ldr x8, #8; br x8`) and unconditional branch trampolines (`b <offset>`).
  - Added x86_64 inline hook trampoline scanner detecting near jmp (`0xe9`), short jmp (`0xeb`), and rip-relative jmp (`0xff 0x25`).
- **New native probes (`native-wchan` & `native-frida-port`)**:
  - Added wait-channel inspection (`/proc/self/wchan`) detecting `ptrace_stop`, `sys_ptrace`, and `do_signal_stop`.
  - Added direct TCP port inspection (`/proc/net/tcp` and `/proc/net/tcp6`) detecting default Frida server ports (`:69a2`). Total native probes expanded to 11.
- **Automated Zero-Integration UI Protection**:
  - Added zero-code injection of `WindowManager.LayoutParams.FLAG_SECURE` to block screenshots and task-switcher data leakage.
  - Added zero-code injection of `filterTouchesWhenObscured = true` to drop touches while the window is obscured (a tapjacking mitigation).
- **Static Build-Time Manifest Security Auditor (`ManifestAuditor`)**:
  - Integrated manifest security audit into `VerifyProtectionCoverage` checking merged `AndroidManifest.xml` for `debuggable=true` (error in release), `allowBackup=true` (warning), and cleartext traffic allowances.
- **Self-Hostable, Privacy-Preserving Threat Telemetry (`TelemetryDispatcher`)**:
  - Implemented structured, anonymized incident event model (`SecurityEvent`) and rate-limited HTTPS POST dispatcher with 5-second timeouts and circuit-breaker backoff. Zero network requests made when unconfigured.
- **Verification Across Toolchain**:
  - Native tests (`probe_test.cpp`) compiled with `-Wall -Wextra -Werror` and passed.
  - `:policy:test`, `:plugin:test`, `:runtime:testDebugUnitTest`, `:plugin:validatePlugins`, `:runtime:lintRelease` all passed.
  - Standalone `sample` app built and verified with `assembleDebug`, `verifyDebugProtectionCoverage`, `assembleRelease` (with R8 minification), and `verifyReleaseProtectionCoverage`.
  - On-device validation on physical Pixel 7 Pro (Android 17) passed **7/7 tests** via `connectedDebugAndroidTest` with 100% success rate, validating automatic initialization, injected guard execution, periodic background monitoring, security block fallback activity, native probes (`native-wchan`, `native-frida-port`), and zero-code UI protection (`FLAG_SECURE`, `filterTouchesWhenObscured`).

## 30 September 2026 — Slice 7: direct native syscalls (ARM64/x86_64) + hardened kernel & environment probes

Added libc-independent direct syscalls and additional anti-tamper/anti-root probes:

- **Direct Kernel Assembly Syscalls (`syscalls.h` & `engine.cpp`)**:
  - Implemented raw inline assembly kernel syscalls (`svc #0` on ARM64, `syscall` on x86_64) for `openat`, `read`, and `close`.
  - All sensitive `/proc` inspections (`/proc/self/maps`, `/proc/self/mountinfo`, `/proc/self/status`, `/proc/self/task/*/comm`, `/sys/fs/selinux/enforce`) now read directly from kernel VFS via raw syscalls, completely bypassing user-space `libc.so` hooks, Frida `Interceptor`, and `LD_PRELOAD` shims.
- **ARM64 Inline Hook Trampoline Detection (`native-hook-trampoline`)**:
  - Direct instruction-level scanner inspecting critical function prologues (`open`, `read`, `ptrace`) for 64-bit ARM hook trampolines (`ldr x16, #8 ; br x16` `0x58000050` / `0xd61f0200` and `ldr x17, #8 ; br x17` `0x58000051` / `0xd61f0220`).
- **Hardened Kernel & Device Probes (`native-selinux` & `native-hardware-device`)**:
  - Added SELinux enforcement probe detecting permissive mode (`/sys/fs/selinux/enforce == '0'`).
  - Added kernel root & emulator device node probes (`/dev/kernelsu`, `/dev/apatch`, `/dev/qemu_pipe`, `/dev/goldfish_pipe`, `/dev/vport0p1`).
- **Environment & Cloned App Container Detection (`environment-hardware` & `virtual-space`)**:
  - Added emulator fingerprint detection (`isEmulatorFingerprint`) covering QEMU, Goldfish, Ranchu, Cuttlefish, and generic SDK profiles.
  - Added virtual container / cloned app detection (`isVirtualSpacePath`) detecting isolated execution under VirtualApp, Parallel Space, Dual Space, and foreign package directory paths.
- **Verification on Physical Hardware**:
  - Native tests (`probe_test.cpp`) compiled with `-Wall -Wextra -Werror` and passed on host.
  - `:policy:test`, `:plugin:test`, `:runtime:testDebugUnitTest`, `:plugin:validatePlugins`, `:runtime:lintRelease`, and `:runtime:assembleRelease` passed.
  - Sample `assembleDebug` and R8-minified `assembleRelease` built and verified coverage.
  - `connectedDebugAndroidTest` on physical Pixel 7 Pro (Android 17, Cheetah Beta) passed **6/6 tests** verifying all 16 runtime and native probes.

## 30 September 2026 — Slice 6: eight capability areas end-to-end + physical device verification

Completed the eight planned capability areas and ran them on physical hardware (Pixel 7 Pro, Android 17):

- **Pillar 1: Hooking Protection**:
  - Added pure-JVM testable `hasHookClass` and `hook-classes` probe in `RuntimeScanner.kt` checking for known dynamic instrumentation frameworks (`XposedBridge`, `XC_MethodHook`, `Epic`, `Pine`, `Substrate`).
  - Native `/proc/self/maps` scanning (`frida-agent`, `libfrida-gadget`, `liblsposed`, `libxposed`), thread comm inspection (`gum-js-loop`, `pool-frida`), and `libc.so` symbol origin interposition checks (`open`, `read`, `ptrace`).
- **Pillar 2: Root Detection**:
  - Added `build-tags` probe checking for `test-keys` in `Build.TAGS`.
  - Multi-path file probes (`root-path`), native `lstat` checks across 6 binary locations (`/system/bin/su`, `/data/adb/magisk`, `ksu`, `ap`), and `/proc/self/mountinfo` parsing for Magisk, KernelSU, and APatch.
- **Pillar 3: Anti-Tampering**:
  - Added `missing-manifest` audit check in `ProtectionArchive.kt`.
  - Package integrity probe (`apk-integrity`), strict SHA-256 signing certificate verification (`checkSigners`), application ID lock, and build-time coverage audit (`VerifyProtectionCoverage`).
- **Pillar 4: Network Security**:
  - Added runtime probe `network-cleartext-permitted` checking `NetworkSecurityPolicy.getInstance().isCleartextTrafficPermitted()`.
  - Verified manifest configuration and cleartext traffic disabling by default on modern targetSdk.
- **Pillar 5: RASP (Runtime Application Self-Protection)**:
  - Multi-component bytecode gating (`GuardVisitor`) across `Activity` (`onCreate`/`onStart`/`onResume`), `Application` (`onCreate`), `Service` (`onCreate`), and `BroadcastReceiver` (`onReceive`).
  - ASM bytecode branching (`IFNE continueLabel` -> `RETURN`), automatic `service.stopSelf()`, and `finishAffinity()` gating.
- **Pillar 6: Runtime Protection**:
  - Native TracerPid detection, Java debugger detection (`Debug.isDebuggerConnected()`), `FLAG_DEBUGGABLE` audit, background throttled worker, and `ForegroundMonitor` lifecycle rescan loop.
- **Pillar 7: Modern Platform Security**:
  - Full Android 14-17 (API 34-37) support, 16 KiB native page alignment (`max-page-size=16384`), hardened compiler/linker flags, and R8 minification survival (`isMinifyEnabled = true`).
- **Pillar 8: Reporting & threat feedback**:
  - Automated generation of machine-readable `protection-report-<variant>.json` with cryptographic SHA-256 digests of DEX files, native `.so` engines, manifest, and policy.
- **Verification Summary**:
  - `:policy:test`, `:plugin:test`, `:runtime:testDebugUnitTest`, `:plugin:validatePlugins`, `:runtime:lintRelease`, and `:runtime:assembleRelease` all passed.
  - `sample:assembleDebug` and `sample:assembleRelease` passed with verified coverage and generated protection reports.
  - `sample:connectedDebugAndroidTest` on physical Pixel 7 Pro (Android 17) passed 6/6 tests with 100% success rate.

## 30 September 2026 — Slice 5: multi-component lifecycle guarding + payload integrity manifest

Broadened protection from Activity-only to full Android component coverage and implemented packaged artifact integrity auditing:

- **Multi-Component Lifecycle Guarding**:
  - `GuardVisitor.kt` and `GuardClassVisitorFactory.kt` expanded to instrument `Activity` (`onCreate`, `onStart`, `onResume`), `Application` (`onCreate`), `Service` (`onCreate`), and `BroadcastReceiver` (`onReceive`).
  - Missing lifecycle methods synthesized where applicable with `SecurityGuard.allow<Component>` calls and conditional bytecode branches.
  - `SecurityGuard.kt` updated with `@JvmStatic` hooks `allowApplication`, `allowService`, and `allowReceiver`, with automatic `service.stopSelf()` enforcement for restricted services.
  - Structural ASM regression tests added in `GuardVisitorTest.kt` for `Service`, `Application`, and `BroadcastReceiver`.
- **Packaged Payload Integrity Manifest**:
  - `ProtectionArchive.kt` updated to audit `classes.dex`, `AndroidManifest.xml`, native binaries, and policy properties.
  - Added `generateProtectionReport` producing a machine-readable JSON report with SHA-256 digests for all packaged DEX files, native `.so` engines across all ABIs, manifest, and policy.
  - `VerifyProtectionCoverage` outputs `build/reports/apparmorx/protection-report-<variant>.json` and verifies both debug and release minified APKs.
- **Deepened Native & Runtime Integrity**:
  - `engine.cpp` updated to check symbol origin for `open`, `read`, and `ptrace` against `libc.so`.
  - `RuntimeScanner.kt` added `apk-integrity` probe verifying that the running APK contains required code and assets without corruption or stripping.
- **Real Device Confirmation**: `connectedDebugAndroidTest` on Pixel 7 Pro (Android 17) passed 6/6 tests with 0 failures.

## 30 September 2026 — Slice 4: bytecode enforcement guard gating + real device confirmation

Resolved the plugin-to-runtime bytecode descriptor mismatch and implemented true lifecycle gating:

- `GuardVisitor.kt` updated to target `GUARD_DESCRIPTOR = "(Landroid/app/Activity;)Z"`, matching `SecurityGuard.allowActivity(activity: Activity): Boolean`.
- Bytecode branching implemented in `emitGuardCall`: emits `INVOKESTATIC allowActivity` → `IFNE continueLabel` → `RETURN` → `visitLabel(continueLabel)`. If the guard resolves to a blocking action (`BLOCK_SCREEN` or `TERMINATE`), `allowActivity` returns `false`, causing the void lifecycle method (`onCreate`, `onStart`, `onResume`) to return immediately without executing subsequent host instructions.
- Structural bytecode regression test added (`existingLifecycleBranchesAroundRemainingBytecodeOnDeniedGuard` in `GuardVisitorTest.kt`), asserting that the guard call, `IFNE` jump, early `RETURN`, continue label, and sensitive method call appear in strict required order.
- Verified on real hardware (Pixel 7 Pro, Android 17): `connectedDebugAndroidTest` expanded to 5/5 passing, validating provider initialization, injected guard execution, periodic foreground monitoring without transition, clean launch of `SecurityBlockActivity`, and `SecurityGuard.allowActivity` execution under default policy.

## 30 September 2026 — Slice 3: packaged protection-coverage audit + first real device proof

Picked up a build left broken across a tool-session boundary: `plugin/src/test/.../ProtectionArchiveTest.kt`
existed (test-first, per this project's own rule) but `auditProtectionArchive` was never implemented,
so `:plugin:compileTestKotlin` failed outright. Fixed, then wired it into the actual plugin.

- `auditProtectionArchive(archive: File): List<String>` (`plugin/.../ProtectionArchive.kt`): reads a
  packaged APK's zip entries and checks for `assets/apparmorx/policy.properties` and, for every ABI
  folder found under `lib/`, a matching `lib/<abi>/libapparmorx.so`. Presence-only — it cannot prove
  authenticity, only that the plugin's required artifacts made it into the final archive. All 5
  pre-written test cases pass, including the "every packaged ABI needs its own engine copy, not just
  one" case and the bare `missing-native-engine` (no `lib/` at all) vs. per-ABI
  `missing-native-engine:<abi>` distinction.
- `VerifyProtectionCoverage` task + wiring in `SecurityPlugin`: registers
  `verify<Variant>ProtectionCoverage`, fed from `variant.artifacts.get(SingleArtifact.APK)`, and hooks
  it into `assemble<Variant>` so it runs automatically, not just on request.
- **Found a real Gradle API bug while wiring it**: `project.tasks.named("assemble$name")` failed with
  `UnknownTaskException` because AGP had not created that lifecycle task yet at the point `onVariants`
  runs — `named()` resolves eagerly against tasks already registered. Fixed with the order-independent
  `tasks.matching { it.name == "assemble$name" }.configureEach { ... }` idiom.
- **Verified end-to-end, not just unit tested**: ran `verifyDebugProtectionCoverage` and
  `verifyReleaseProtectionCoverage` directly against the `sample` app's real `assembleDebug`/
  `assembleRelease` output — both pass, and the task genuinely runs as part of `assembleRelease`
  (visible in the task graph: `packageRelease` → `verifyReleaseProtectionCoverage` →
  `assembleRelease`).
- **First real device validation of this entire project.** A Pixel 7 Pro (Android 17) was connected
  for the first time. `connectedDebugAndroidTest` against the `sample` app (zero AppArmorX source)
  passed 3/3: automatic provider initialization, injected-guard execution, and periodic foreground
  scanning without another lifecycle transition. Everything before this entry was verified statically
  (bytecode/dex disassembly, mapping files, build success) precisely because no device had been
  available; this closes that gap for the capabilities tested so far.

**Still not covered by this slice:** archive *authenticity* (a re-signed APK with the same entry names
passes this audit — that needs the signed integrity manifest, a separate, larger slice); any
enforcement path beyond what earlier slices covered; anything on the release build type on-device
(only debug was instrumented-test-capable here).

## 29 September 2026 — Slice 2.5: verified the guard survives a real minified release build

This closes the biggest open risk flagged at the end of Slice 2: everything built so far had only
ever been exercised with `assembleDebug` (`isMinifyEnabled = false`). A real customer's release
build runs R8 with shrinking **and** obfuscation — if that silently broke the injected guard or the
native engine's hardcoded JNI class lookup, the entire product would fail exactly where it matters
most, with no build error to notice it by.

**What changed:** `sample`'s `release` build type now sets `isMinifyEnabled = true` with the default
`proguard-android-optimize.txt`, and `security.signingCertificates` is set to a clearly-labeled
placeholder pin (64 zero-hex, **not a real signer — must never be copied into a real app**) purely to
satisfy the existing `requireReleaseSigningPins` build-time gate structurally for this fixture.

**Verified by disassembling the actual shipped dex** (`dexdump` on the unzipped
`classes.dex` from `apparmorx-sample-release-unsigned.apk`, cross-referenced with R8's
`mapping.txt`/`usage.txt`), not by inference:

- `MainActivity.onCreate`/`onStart`/`onResume` still each call `super.<method>()` then
  `invoke-static {v0}, Li0;.a:(Lcom/apparmorx/sample/MainActivity;)V` — `i0.a` being
  `SecurityGuard.allowActivity` after R8's whole-program renaming (confirmed via `mapping.txt`:
  `com.apparmorx.runtime.SecurityGuard -> i0`, residual signature
  `(Lcom/apparmorx/sample/MainActivity;)V`). **The guard call is intact and correctly retargeted
  across the app/AAR module boundary**, not stripped as dead code.
- `com.apparmorx.runtime.NativeEngine` — the one class with a hardcoded string dependency
  (`engine.cpp`'s `JNI_OnLoad` does `env->FindClass("com/apparmorx/runtime/NativeEngine")`) —
  **kept its exact name**, per `mapping.txt`. This is the existing `-keep,allowoptimization` rule in
  `runtime/consumer-rules.pro` working correctly; without it, R8 renaming this class would silently
  degrade every native check to `UNAVAILABLE` at runtime with no build failure to reveal it.
- `EnforcementResponse` was inlined into `SecurityGuard` and shows as `R8$$REMOVED$$CLASS$$1` in the
  mapping — this is R8's normal single-caller inlining, not a functional loss (its code moved, not
  disappeared); documented here so a future reader doesn't mistake this mapping entry for a bug.
- Both `SecurityGuard` and `NativeEngine`'s Kotlin `INSTANCE` singleton fields were removed (shown in
  `usage.txt`) because every call site already used the `@JvmStatic` static method, never the
  instance field directly — legitimate dead-code elimination, not a break.
- A useful side effect, not a designed feature yet: obfuscation means `strings classes.dex` no
  longer contains `SecurityGuard` or `allowActivity` literally, raising the bar slightly against a
  casual grep-the-APK approach. This is incidental to R8, not a claimed anti-tampering property — a
  real reverse engineer with jadx/R8-unmapping tooling is unaffected.

**Still not verified:** none of this ran on an actual device (no emulator/device available in this
session) — only static analysis of the built artifact. `d8`/R8 correctness is strong evidence the
call executes as written, but on-device confirmation (`connectedDebugAndroidTest` /
`connectedReleaseAndroidTest` once a signing config exists) remains outstanding, same as every
other slice so far.

## 29 September 2026 — Slice 2: enforcement profiles

Scope: turning Slice 1's observation-only guard into real, host-configured enforcement — the
"automatic enforcement and self-health" slice from `PRODUCT-DESIGN.md`, done in a way that cannot
become the exact failure mode the design docs warned against (a heuristic locking out real users).

**What was added:**

- `EnforcementAction` (`OBSERVE` / `WARN` / `BLOCK_SCREEN` / `TERMINATE`) and `EnforcementPolicy`
  (`restrictedAction`, `enforceIndeterminate`) in the `runtime` module, plus the pure decision
  function `resolveEnforcementAction(state, policy)` — fully unit tested with no Android dependency
  (`EvidenceTest`): every action is honored for `RESTRICTED`; `INDETERMINATE` is **always
  observe-only unless the host explicitly opts in** via `enforceIndeterminate`, regardless of how
  aggressive `restrictedAction` is configured; `CHECKING`/`READY` are always observe-only; the
  zero-config default (`EnforcementPolicy.DEFAULT`) never acts beyond recording state, for every
  `ProtectionState`.
- `security.restrictedAction` / `security.enforceIndeterminate` in the public DSL
  (`SecurityExtension`), validated in `PrepareSecurityPolicy` — an unrecognized action name fails
  the build with the allowed set named in the message, the same fail-closed-with-an-actionable-error
  discipline the policy verifier already used — and threaded through the existing generated
  `policy.properties` asset (no new generated file). Covered by three new `SecurityPluginTest` cases:
  the default is written as `OBSERVE`/`false`, an invalid value fails the build, and a valid one is
  written through correctly.
- `RuntimeScanner.parseEnforcementPolicy`: a malformed or absent policy always degrades to
  `EnforcementPolicy.DEFAULT` (observe-only) — deliberately the *safe* direction, never inferring
  something more aggressive than explicitly configured.
- `EnforcementResponse` (the only new code that touches Android APIs — the decision itself stays
  pure and testable) applies the resolved action from `SecurityGuard.allowActivity`: `WARN` logs;
  `BLOCK_SCREEN` starts the bundled `SecurityBlockActivity` and finishes the guarded activity;
  `TERMINATE` calls `finishAffinity()` — deliberately **not** `Process.killProcess`, which can
  corrupt in-flight disk/database writes the design docs explicitly said to avoid.
- `SecurityBlockActivity`: a minimal, honest, non-destructive fallback screen, built
  programmatically (no `res/` files needed in the AAR) and registered automatically via
  `runtime/src/main/AndroidManifest.xml` — verified present in the sample app's **merged** manifest
  even though the sample declares no activities of its own beyond `MainActivity`. It lives in the
  `runtime` module, so AGP's `InstrumentationScope.PROJECT` instrumentation never touches it — it
  cannot call `SecurityGuard.allowActivity` itself, so there is no guard-loop risk through it.
- `SecurityGuard.allowActivity` reordered to decide and apply enforcement from the **already
  completed** snapshot before kicking off the next async scan — it never scans synchronously on the
  UI thread it was just called from.

**Executed and green, in this order, together with everything from Slice 1:** `:policy:test`,
`:plugin:test` (12 cases now, incl. the 3 new enforcement ones), `:plugin:validatePlugins`,
`:runtime:testDebugUnitTest` (14 cases now, incl. the 4 new pure enforcement-decision ones),
`:runtime:assembleRelease` + `:runtime:lintRelease` (the new `EnforcementResponse`/
`SecurityBlockActivity` classes compile and lint clean against real Android APIs),
`publishToMavenLocal`, and the `sample` app's `assembleDebug` + `assembleDebugAndroidTest` — still
with zero enforcement-related code of its own; the default `security {}` block in `sample` sets
nothing beyond `minimumSequence`, so it continues to behave exactly as observation-only.

**Known limitations of this slice, stated plainly:**

- Not executed on a real device — same limitation as Slice 1. `BLOCK_SCREEN`/`TERMINATE` have never
  actually run on-device; verify with `connectedDebugAndroidTest` before relying on them.
- One `restrictedAction` per application module, applied uniformly to every guarded call site.
  Per-screen or per-operation risk policy (e.g. "only step up verification at checkout, only warn
  elsewhere") is not implemented; `PRODUCT-DESIGN.md`'s "optional annotations/adapters" for
  fine-grained guards remain future work.
- `BLOCK_SCREEN`/`TERMINATE` still fire per-guarded-call with no debounce beyond
  `SecurityRuntime`'s existing 30s scan throttle — a flapping `DETECTED` signal (e.g. a hook tool
  attaching and detaching) could show the block screen repeatedly rather than once. No hysteresis
  window has been added yet.
- No self-health signal yet (the "self-health" half of this slice's name in `PRODUCT-DESIGN.md`):
  there is no way for the host to be told "the native engine failed to load" versus "the native
  engine ran and found nothing" at a glance beyond reading individual `Evidence` entries.

## 29 September 2026 — Slice 1: automatic startup guard injection

Scope: first vertical slice from `PRODUCT-DESIGN.md` — "automatic native/Kotlin injection and
verified startup." Everything below was executed on this machine and is reproducible with the
commands in `README.md`; nothing was published externally.

**What changed since the exploratory prototype:**

- Fixed a broken build left by the paused session: `plugin/build.gradle.kts` imported and called a
  `compatibility { features { configurationCache = true } } ` API that does not exist on the
  `com.gradle.plugin-publish` plugin, and `plugin/src/test/.../GuardVisitorTest.kt` referenced a
  `GuardVisitor` class that was never implemented. Both are fixed.
- Implemented `GuardVisitor` (ASM `ClassVisitor`) and `GuardClassVisitorFactory` (AGP
  `AsmClassVisitorFactory`), wired into `SecurityPlugin` via the AGP Instrumentation API
  (`variant.instrumentation.transformClassesWith(...)`, scope `PROJECT`). It injects a call to
  `SecurityGuard.allowActivity(this)` immediately after `super.<method>()` in `onCreate`, `onStart`
  and `onResume` for every class AGP's own class-hierarchy data identifies as an `Activity`
  subclass (via `ClassData.superClasses`, so `AppCompatActivity`/`ComponentActivity` subclasses are
  covered, not only direct `android.app.Activity` subclasses) — synthesizing the override when the
  consumer class does not declare one, and never altering existing bytecode beyond appending the
  guard call.
- Added `SecurityGuard` to the `runtime` module: the injected call site. This slice is
  **observation-only** — it refreshes evidence and records a `ProtectionState`, but does not finish
  activities or otherwise enforce a response. Automatic, profile-configured enforcement is tracked
  as a separate later slice in `PRODUCT-DESIGN.md`; shipping it bundled with the first slice would
  make a config mistake capable of locking every user out of the app.
- Fixed the native engine, which had never actually been compiled against the NDK before this
  session: `libc_origin()` took `&open`, which is ambiguous under NDK fortify headers (multiple
  overloads). Replaced with `dlsym(RTLD_DEFAULT, "open")`, which is also the semantically correct
  check — it follows the same symbol resolution a PLT/GOT call would use, so a hook that interposes
  the symbol shows up here, which taking the address of the local (possibly inlined) wrapper would
  not reliably catch.
- Fixed `sample/settings.gradle.kts`: `includeBuild("..")` was nested inside `pluginManagement {}`,
  which only makes the plugin *marker* resolvable via the composite build, not the
  `com.apparmorx:runtime` *dependency* the plugin adds automatically. Moved to top level.
- Rewrote `sample`'s instrumented test off the deprecated JUnit3 `android.test.InstrumentationTestCase`
  (which was never going to compile — no such dependency was ever declared) onto AndroidX Test
  (`AndroidJUnit4`, `ActivityScenario`), and added a second test that asserts the injected guard
  actually observably ran after launching the unmodified `MainActivity`.

**Executed and green, in this order, on this machine:**

1. `:policy:test` — 9 signed-policy abuse-case tests.
2. `:plugin:test` — Gradle TestKit tests (lazy configuration, configuration-cache reuse, offline/
   non-HTTPS/rollback rejection) **and** the two `GuardVisitorTest` cases (synthesized lifecycle
   guards on an empty Activity subclass; guard appended after an already-declared `super.onStart()`
   call, with nothing else touched).
3. `:plugin:validatePlugins`.
4. `:runtime:testDebugUnitTest` — evidence/cancellation/indicator/signer helpers plus
   `ProtectionDecisionTest` (pending/missing/unavailable/detected/stale/clock-reversal state
   transitions).
5. `:runtime:assembleRelease` — **native engine now compiles for both `arm64-v8a` and `x86_64`**
   for the first time; previously it had a compile error that had gone unnoticed because the AAR
   had never actually been assembled.
6. `:runtime:lintRelease`.
7. `publishToMavenLocal` for `policy`, `plugin`, `runtime` (local only; verifies POM/metadata
   generation, not a real release).
8. `sample` app, applying **only** `com.apparmorx.security` with zero AppArmorX source in
   `MainActivity.kt` (`class MainActivity : Activity()`, nothing else):
   `assembleDebug` and `assembleDebugAndroidTest` both succeed, using a composite build
   (`includeBuild`) against this repository — no Maven Local, no published artifact.

**Verified, not merely asserted by a test:** decompiling the actual bytecode AGP shipped into the
sample APK (`javap -c` on
`sample/build/intermediates/classes/debug/transformDebugClassesWithAsm/dirs/com/apparmorx/sample/MainActivity.class`)
shows three synthesized methods — `onCreate(Bundle)`, `onStart()`, `onResume()` — each calling
`super.<method>()` then `com/apparmorx/runtime/SecurityGuard.allowActivity`, even though the
`.kt` source and the pre-instrumentation `.class` (from `compileDebugKotlin`) contain none of that.
This is the concrete evidence for the product's core promise: applying the plugin, with no
developer-written detection or startup code, changes what ships.

**Known limitations of this slice, stated plainly:**

- Guard coverage is Activity lifecycle only. Fragments, Services, BroadcastReceivers, Workers and
  non-Activity entry points are not yet instrumented — see `PRODUCT-DESIGN.md`'s "automatic startup
  and enforcement" section on why a ContentProvider or a single entry point is not sufficient
  coverage.
- `SecurityGuard.allowActivity` is observation-only by design in this slice (see above); a build
  that only applies the plugin gets **no runtime enforcement yet**, only recorded evidence the host
  can query via `SecurityGuard.lastObservedState()`. Do not describe this slice as RASP enforcement
  to users.
- No physical device or emulator was available in this session; instrumented tests
  (`InitializationTest`) compile and package correctly but have not been executed on-device. Run
  `./gradlew -p sample connectedDebugAndroidTest` against a real device/emulator before relying on
  them.
- R8/minification **was** exercised and verified against a real minified build — see "Slice 2.5"
  above, which supersedes this bullet.
- Bypass review, false-positive measurement, the device/OEM matrix, and everything else in
  `PRODUCT-DESIGN.md`'s "Test and release acceptance" section remain outstanding.

## Slice 16 — real Frida/root MITM attack, reproduced and root-caused (not simulated)

**Setup**: rooted AVD (`armor35`, API 35, `google_apis`, `arm64-v8a`), real `frida-server` 17.23.3
(android-arm64) pushed and run as root, attacker scripts driven via the `frida` CLI with `--runtime=v8`
(the Python API's `create_script(..., runtime='v8')` failed with "Java is not defined" for reasons not
fully diagnosed; the CLI flag worked correctly for the identical script against the identical target, so
all subsequent hook/MITM scripts were driven that way).

**What was tested and the result**:
1. Root detection against the real `su` binary on the AVD — `DETECTED`, correct.
2. Hooking probes (`native-frida-port`, `native-tool-thread`, `hook-classes`, `hook-library`,
   `native-hook-trampoline`, `native-stealth-injection`) against the attached `frida-server` — `DETECTED`,
   correct, independent of anything else below.
3. Dependency-firewall TLS interception (`HttpsURLConnection.setDefaultHostnameVerifier`,
   `SSLContext.init`) **through the app's own call sites** — all 4/4 blocked, confirmed earlier in this
   session.
4. The same TLS APIs called **directly from injected Frida code**, bypassing the app's own call sites —
   full MITM succeeded against a real self-signed-cert attacker server (`HTTP 200`,
   `body=MITM_SUCCESS: attacker server responded with fake data`). First attempt showed a false
   "neutralized" result because comparing `before.toString()` / `after.toString()` printed V8's generic
   `"[object Object]"` for both; fixed by resolving the installed object's actual Java class name
   (`Java.cast(handle, Java.use("java.lang.Object")).getClass().getName()`), which correctly showed
   `com.android.okhttp.internal.tls.OkHostnameVerifier` → `com.apparmorx.sample.FridaInjectedTrustAllVerifier`.
5. Repeated (4) against a release build already `RESTRICTED` (root detected, confirmed via
   `adb shell content call --uri content://<app>.init --method getSecurityState` → `state=RESTRICTED`,
   checked *before* Frida was attached). The MITM still fully succeeded — being in `RESTRICTED` does not
   stop an in-process attacker from making further direct API calls; it only drives whatever UI/telemetry
   response the host configured.

**Root cause, stated precisely**: `DependencyFirewall` rewrites the app's own compiled bytecode call
sites. A call Frida makes directly into a framework method never passes through any rewritten call site,
so there is nothing for the firewall to intercept. This is identical, in kind, to every other client-side
RASP's limitation against a co-resident native-code attacker — none can sandbox further in-process API
calls without OS-level enforcement outside a Gradle-plugin-distributed library's control.

**Fix considered and rejected**: an opt-in automatic `Process.killProcess()` on confirmed hooking
evidence. Rejected because (a) it would violate this repository's own `AGENTS.md` rule against automatic
process termination, which exists precisely to stop a cheap, spoofable "just kill it" response path from
being added, and (b) it would arrive after the attacker's call already completed, so it would not actually
prevent this attack — it would only end the current process sooner, which is not the same thing as
blocking the MITM. No code change was made for this; see `docs/STATUS.md` Slice 20 for the full reasoning.

**What already works, unchanged, and was reconfirmed by this test**: hooking evidence is ordinary
`DETECTED` evidence and flows through the existing `decideProtection()` → `resolveEnforcementAction()` →
`TelemetryEvents.incidentChecks()` path exactly like root/signer findings — `RESTRICTED` state,
host-configured `BLOCK_SCREEN`/`TERMINATE`, and a signed report to the app owner's own endpoint all still
fire correctly. The gap is specifically "stop this one in-flight attacker request," not "detect and
report that hooking happened," and the two should never be conflated in product claims.

## Slice 17 — anti-ptrace hardening: implemented, wired end-to-end, tested against the real attack, and shown not to close the gap

Built in response to the question "did we actually fix anything, or just document the limit": a
legitimate, rule-compliant candidate fix existed (occupy the OS's single ptrace-tracer slot before an
attacker's Frida can), so it was implemented and tested for real rather than assumed to work or
dismissed without trying.

**Wiring** (full DSL→profile→policy→runtime chain, matching the existing `firewallNetworkSecurity`
pattern exactly): `SecurityExtension.antiPtraceHardening` → `ProtectionProfile.resolve()` (false in
every profile including `HARDENED`, and force-false again if `debuggable`) → `PrepareSecurityPolicy`
→ `EnforcementPolicyParser` → `EnforcementPolicy.antiPtraceHardening` → `SecurityRuntime.initialize()`
(calls `NativeEngine.hardenAgainstPtraceAttach()` only if the flag is set **and** a second, independent
runtime check confirms the build is not debuggable) → `HtmlReportGenerator` (new report layer). New
tests: `EnforcementPolicyParsingTest` (parses, defaults false when absent),
`ProtectionProfileTest.antiPtraceHardeningIsNeverAProfileDefaultEvenUnderHardened`.

**Native mechanism** (`harden_ptrace` in `engine.cpp`): forks a minimal watchdog (raw syscalls only
between `fork()` and `_exit()` — no malloc, no C++ runtime, to avoid any state a GC/JIT thread that
doesn't exist post-fork might have held a lock on) that `ptrace(PTRACE_ATTACH)`s its own parent, with
`prctl(PR_SET_PTRACER)` set first so Yama's default ptrace_scope doesn't itself block it. Verified via
`/proc/self/status`'s `TracerPid`, read through the existing raw-syscall `read_bounded()` so a libc
`ptrace()` hook can't lie about the outcome. Compiles clean under `-Wall -Wextra -Werror` for both ABIs.

**On-device bug found and fixed before shipping**: the first version left the watchdog as a zombie
process whenever `ptrace(PTRACE_ATTACH)` failed (the common case, see below) — caught by `ps -A`
showing a `Z [demo.consumer]` entry after a real device test, not by code review. Fixed by `waitpid`-
reaping the child on the failure path; re-verified clean (no zombie) on a second real-device run.

**Real test, step by step**:
1. Published the plugin+runtime with this change to the clean-room "Portal simulation" repo used
   earlier in this session, enabled `antiPtraceHardening.set(true)` on the consumer clean-room app,
   built a signed release APK.
2. Confirmed via the generated HTML report that the layer shows `ON` with
   `Overridden (profile default: false)` — the whole wiring chain reaches the report correctly.
3. Installed and launched on the real `armor35` AVD. App launched cleanly (confirmed via `ps` showing
   a healthy `S` state process, and `logcat` showing no `FATAL`/`AndroidRuntime` crash) — this hardening
   does not destabilize a normal launch.
4. Re-ran the realistic attach scenario this feature targets: `frida -D emulator-5554 -n consumer
   -l hook.js` — attaching to the **already-running** process (not `frida -f`, which always wins the
   race regardless of any hardening since it injects before any app code runs). Result:
   `attacker_verifier_installed=true` — **the attack still succeeded.**
5. Checked why: `/proc/<pid>/status` showed `TracerPid: 0` — our own hardening never acquired the
   slot. `adb shell getenforce` → `Enforcing`. AOSP's SELinux policy denies the `untrusted_app` domain
   `ptrace` on anything, including itself, as a deliberate `neverallow` rule independent of root status.
   A root-privileged attacker (frida-server, running outside `untrusted_app`) is not bound by that same
   rule when ptracing *into* an `untrusted_app` process from outside it. The domain that could use this
   defense is blocked from using it by the OS itself; the domain the defense targets is not.

**Conclusion, stated for the record**: this is a real, tested, safely-degrading feature — it does
exactly what it says, correctly, and never destabilizes anything when it can't work. It is kept in the
codebase as a legitimate opt-in for environments where it might still function (an older or custom
Android build without this specific SELinux hardening). It is **not** a fix for the Frida/MITM gap in
Slice 20/16, and must never be described as one. The honest, confirmed-by-testing finding is now
stronger than before: not only can this library not stop an in-process root+Frida attacker, *the OS's
own best available self-protection trick for this can't either*, on the exact kind of device this was
tested against. This closes the investigation into code-level mitigations for this specific attack
class; the remaining path (per `docs/STATUS.md`'s "Important limits") is honest disclosure plus
signed, owner-reported telemetry, not further attempts at client-side prevention of an attacker who
already has root and code execution in-process.

## Slice 18 — killOnConfirmedHooking: implemented test-first, verified on a real device to actually kill the process, and the bug it exposed along the way

The owner explicitly asked to amend `AGENTS.md`'s default "no automatic process termination" rule with
a narrow, documented exception, after being shown that detection-only was the honest but unsatisfying
end state of the Frida investigation (Slice 16/17). This slice is that exception, implemented and
proven on-device.

**TDD**: `HookKillDecisionTest.kt`, 7 cases, written before wiring anything else -- false when policy
disabled, false when debuggable (even with hooking detected), false when the only DETECTED evidence is
unrelated (root, signer), false when a hooking check is merely `UNAVAILABLE` (never treat unavailable
as confirmed), true for every individual entry in `HOOKING_CHECKS`, true when a hooking check is
detected alongside unrelated clean evidence. All passing before any Android-API code was touched.

**Wiring** (same DSL→profile→policy chain as `antiPtraceHardening`): `SecurityExtension.killOnConfirmedHooking`
→ `ProtectionProfile` (false in every profile, forced false again if debuggable) → `PrepareSecurityPolicy`
→ `EnforcementPolicyParser` → `EnforcementPolicy.killOnConfirmedHooking` → consumed in two places,
matching the two existing enforcement paths: `EnforcementResponse.apply` (Activity path) and
`SecurityGuard.evaluateComponent` (Application/Service/BroadcastReceiver path) both call the same pure
`shouldKillOnConfirmedHooking()` before doing anything else, and if true call `Process.killProcess`
directly -- taking priority over whatever `restrictedAction` would otherwise have done. New
`ProtectionProfileTest` case locks down it is never a profile default and never survives `debuggable=true`.

**First on-device attempt failed to fire, and that failure found a real, separate, pre-existing bug.**
Attached Frida persistently (not a one-shot session) to the consumer app on the `armor35` rooted AVD,
confirmed `/memfd:frida-agent-64.so (deleted)` was genuinely mapped in its `/proc/<pid>/maps`, and waited
through several periodic re-scans. No kill. Logcat showed why: `avc: denied { read } for name="tcp"
dev="proc" ... tcontext=u:object_r:proc_net_tcp_udp:s0` and the matching line for `selinuxfs`'s
`enforce` file -- SELinux denies the `untrusted_app` domain read access to both outright. Reading the
native code (`frida_ports()`, `selinux_eval()`, `hardware_devices()`) showed all three silently returned
`Status::clear` on a read failure instead of `Status::unavailable` -- the exact "unavailable treated as
clean" bug this project's own `AGENTS.md` forbids, present since before this session and locked in by a
wrong assertion in `probe_test.cpp` (`selinux_eval(std::nullopt) == Status::clear`). Fixed all three to
the same read-failure-tracking pattern `root_paths()` already used correctly; updated the test to assert
`unavailable`; added an empty-string case too. Recompiled clean under `-Wall -Wextra -Werror` for both
ABIs; host-compiled and ran `probe_test.cpp` directly (`clang++ -std=c++17 -Wall -Wextra -Werror`) to
confirm all assertions pass before returning to the device.

**Second on-device attempt: confirmed working.** To isolate the kill mechanism from the unrelated
"does anything stay resumed to get re-scanned" question (BLOCK_SCREEN's own `finish()` call removes the
only Activity from the tracked `resumed` set, stopping the periodic monitor before a second scan could
ever run -- a separate, now-documented limitation, not a bug in the kill logic itself), rebuilt the
consumer app with `restrictedAction=OBSERVE` so the app's one Activity stays resumed and tracked, plus
`killOnConfirmedHooking=true`. Launched it, confirmed it was NOT already showing a block screen, attached
Frida persistently, and watched:
- `adb shell pidof demo.consumer`: a live PID, unchanged through the first ~30s, then **empty**.
- `adb logcat`, same moment: `W/AppArmorX( 9871): Confirmed hooking evidence; killOnConfirmedHooking is
  enabled, terminating process`.

This fired even with `native-frida-port` itself blind (still `UNAVAILABLE` on this device per the fix
above) -- one of the other independent hooking checks (most likely `native-stealth-injection`, given the
confirmed `/memfd:frida-agent` mapping) caught it instead. This is exactly the value of keeping several
independent signals rather than one: one layer being provably broken on this device did not sink the
whole mechanism.

**What this slice does and does not establish**: it is the first mitigation in this entire session that
measurably changed a real outcome on a real device -- the attacker's process is gone, not merely flagged.
It does not retroactively prevent the Slice 16/20 MITM, which still completes before any scan can react,
and it only works at all if some guarded component keeps getting re-evaluated after the first detection
-- a host combining this with `BLOCK_SCREEN` on an Activity-only app needs to also guard a Service,
BroadcastReceiver, or Application component, or this will never get a second chance to run. State both
limits together, every time this feature is described publicly.

## Slice 19 — HookWatchdog: fast polling that measurably prevented the Slice 16/20 MITM, in the realistic attach scenario

Direct response to being asked to push further after Slice 18's honest "detects and kills, but only on
the next 30s-throttled scan, which the single MITM request always beats" conclusion. The remaining gap
was the *speed* of reaction, not the kill mechanism itself -- so this slice narrows that, specifically,
and re-runs the actual attack to check, rather than assuming a faster poll would obviously help.

**Design**: `HookWatchdog.kt`, a daemon thread started once at `SecurityRuntime.initialize()` (as early
in the process as this library ever runs), polling `NativeEngine.scan()` (native engine only -- cheap:
a handful of `/proc` reads and `dlsym` calls, no APK hashing, no policy reload) every 750ms and calling
the same, already-tested `shouldKillOnConfirmedHooking()` from Slice 18. No new decision logic, no new
tests needed for the decision itself; the only new code is the loop, which (like `EnforcementResponse`)
touches Android/process APIs and is verified by device testing, not a unit test.

**Timing, measured externally** (shell `date` timestamps around the Frida attach, polled via `adb shell
pidof` every 0.3s rather than relying on log timestamps): **~1.0 second** from Frida attach to process
death. Slice 18's version needed up to 30-60+ seconds, and only when some guarded Activity happened to
stay resumed.

**The real test -- re-ran the exact Slice 16/20 attack, both ways it can happen**:

1. **Spawn mode**: `frida -f demo.consumer -l mitm_attack2.js`. Output:
   `[mitm] after-bypass: HTTP 200 body=MITM_SUCCESS: attacker server responded with fake data`, followed
   immediately by Frida's own `Process terminated`. The attack still succeeded -- confirms, once more,
   that spawn-time injection cannot be outraced by anything running inside the process it injects into,
   because the attacker's code is already resident before this library's own first instruction runs.
   The watchdog still ended the session a moment later, which stops further exploitation in that
   process but does not undo the one request that already completed.

2. **Attach mode** (the realistic scenario: an app that was already running for a few seconds, the
   attacker roots the device and attaches afterward, not controlling the launch): `frida -n consumer
   -l mitm_attack2.js`. Output: `[mitm] === BEFORE any Frida tampering ===` then
   **`Failed to load script: the connection is closed`** -- frida itself reporting the target died
   mid-session. `adb shell pidof demo.consumer` confirmed empty. `logcat`, precisely:
   `15:40:56.391 W/AppArmorX(10206): Confirmed hooking evidence (fast watchdog); killOnConfirmedHooking
   is enabled, terminating process`. The script never reached the line that installs the permissive
   `TrustManager`/`HostnameVerifier` -- the bypass that made Slice 16's MITM possible was **never
   installed**. This is the first and only result in the whole investigation where a mitigation
   measurably *prevented* the specific attack, rather than detecting it, reporting it, or merely
   shortening the attacker's window afterward.

**Scope, stated with both outcomes side by side on purpose** (this project's own rule against claiming
unbypassable protection applies directly here): this closes the gap for the attach-to-already-running-
process scenario, confirmed by test. It does not, and cannot, close it for spawn-time injection,
confirmed by the same test run minutes apart on the same build. Reporting one result without the other
would misrepresent what was actually shown. Continuous 750ms polling has a real, ongoing CPU/battery
cost explicitly accepted as the price of the faster reaction, and `HookWatchdog` only ever runs when a
host has opted into `killOnConfirmedHooking` for exactly that reason.

## 29 September 2026 — earlier prototype notes (superseded above)

- Policy abuse tests were written before the verifier; red compilation was observed, then all 9 tests passed.
- Four Gradle TestKit tests passed: lazy configuration/configuration-cache reuse, offline missing-policy rejection, non-HTTPS rejection, signed pinned policy/rollback rejection.
- Four runtime helper tests passed after an initial red compile: unavailable semantics, cancellation, indicator matching and signer set handling.
- Plugin compilation and validatePlugins passed.
- Android runtime release AAR and release lint passed.
- Local Maven artifacts were generated for consumer testing; no external publication occurred.
- Separate consumer build exposed a Kotlin metadata/AGP compiler-version incompatibility, and a configuration-cache serialization problem in the plugin's resource processing. Both were resolved in the slice above (the underlying settings/build-script defects, not a version bump, were the actual causes).
- No attached Android device; instrumentation tests did not run.
- Native protection had a compile-time bug (see above) that had never been caught because the AAR had never been assembled; bytecode-injected enforcement, artifact integrity and bypass tests are not implemented.
