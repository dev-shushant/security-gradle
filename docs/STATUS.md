# AppArmorX handoff — 2026-10-13 (consolidated)

Historical consolidated evidence. For the current unpublished patch candidate and its release gates,
see [0.1.1 qualification](RELEASE-QUALIFICATION-0.1.1.md). The dated outcomes below retain their original scope.

## Product contract
Apply the plugin to install owned protection artifacts, initialization, monitoring and configured
responses. Consumer code stays unchanged. Zero lines of code required at host app end. Customer-controlled
reporting and reviewed signed improvements are fully supported. Nothing may be published without owner
authorization.

## Verified now, on real output (not just green tests)
- `policy`/`plugin`/`runtime` unit tests, `validatePlugins`, native AAR for `arm64-v8a`+`x86_64`, and
  Android release lint all pass.
- **Implemented capabilities** (each is a build/runtime mechanism, not a guarantee of prevention):
  1. **Startup preflight gate and fail-closed option**: Bounded synchronous preflight probe (latency not benchmarked; no figure claimed) in `SecurityRuntime.initialize` catching active debuggers, debuggable flags, test-keys, su binaries, and hook classes at startup. Configurable `failClosedOnStartup` policy blocks execution of sensitive methods while checks are pending.
  2. **Mirage response (opt-in)**: `EnforcementAction.MIRAGE` and `DeceptionEngine` injecting non-deterministic delays (40-120 ms) so the response is less predictable than a crash. A deterrent, not prevention.
  3. **Dependency firewall (supported call sites)**: Compile-time ASM bytecode rewriting intercepting calls to `ClipboardManager.getPrimaryClip()`, `ClipboardManager.hasPrimaryClip()`, `Settings.Secure.getString()`, `LocationManager.getLastKnownLocation()`, `TelephonyManager.getDeviceId()`, and `TelephonyManager.getImei()`, plus runtime `HostnameVerifier` defense, redirecting them through `DependencyFirewall` with no host source changes. Direct framework calls from injected code bypass it.
  4. **Headless Multi-Component Gating**: Automated bytecode injection and lifecycle gating for background `Service` and `BroadcastReceiver` components. Calls `service.stopSelf()` under restricted enforcement, short-circuits execution before host code runs, and unwraps context safely.
  5. **14 native probes**: TracerPid, root paths, mounts, maps, tool threads, libc origin, SELinux enforcement, hook trampolines, hardware devices, wait-channel `/proc/self/wchan` (`ptrace_wchan`), direct TCP port scanning `/proc/net/tcp` (`frida_ports`), native in-memory shared library W^X protection audit (`native-memory-rwx`), stealth injection audit (`native-stealth-injection`), and dynamic virtual memory ELF W^X program header & relocation integrity (`native-relocation-integrity`).
  6. **Expanded Direct Syscalls**: Inline assembly `direct_fstatat` and `direct_lstat` (`__NR_newfstatat`), `openat`, `read`, `close` bypassing libc.so hooks.
  7. **Multi-Architecture Trampoline Detection**: Expanded ARM64 scanner detecting Dobby/ShadowHook (`ldr x8, #8; br x8`) and branch trampolines (`b <offset>`). x86_64 scanner detecting near/short/rip-relative jumps.
  8. **UI protection (policy-controlled)**: Injection of `FLAG_SECURE` (blocks screenshots and recording by the system) and `filterTouchesWhenObscured` (drops touches while obscured) on guarded activities.
  9. **Static manifest auditor and payload digests**: Automated build-time audit of merged `AndroidManifest.xml` catching release `debuggable=true`, `allowBackup=true`, and cleartext HTTP traffic, plus deep multi-dex checksum verification (`classes.dex` Adler-32 and SHA-1).
  10. **Offline-Resilient SIEM Threat Telemetry**: Bounded persistent disk queueing via `OfflineEventQueue` (max 50 events, <64KB storage footprint), exponential backoff (base 5s up to 300s), circuit-breaker (5 consecutive failures), and cryptographic HMAC-SHA256 request signing (`X-AppArmorX-Timestamp`, `X-AppArmorX-Signature`).
  11. **SARIF 2.1.0 Static Analysis & Audit Pipeline**: Standardized OASIS SARIF report output (`build/reports/apparmorx/security-audit-${variant.name}.sarif`) with deep manifest vulnerability rules (`AAX-101` through `AAX-206`) integrating natively into GitHub Advanced Security (Code Scanning alerts) and SonarQube.
  12. **Key attestation helper**: Android Keystore key attestation (`HardwareAttestation`, TEE / StrongBox where the device provides them) with nonce binding and X.509 chains. Only meaningful when your server verifies the chain.
  13. **Play Integrity adapter**: Reflection-based `PlayIntegrityAdapter` supporting transaction-hash binding without a hard library dependency. Absent Play means no verdict.
  14. **Multiprocess state sharing**: `SecurityInitializer` with `android:multiprocess="true"` and an IPC state channel (`call("getSecurityState")`) so secondary processes (`:auth`, `:sandbox`) share one posture instead of each re-scanning.
- **Repackaging and root attacks, reproduced and detected (14 Oct 2026, see VALIDATION.md Slice 15):** on an
  API 35 emulator, generated a real signer keystore, built+installed a correctly-signed release (confirmed
  `signing-certificate` CLEAR), then unzipped that exact APK, tampered its content, re-signed it with an
  unrelated attacker keystore, and reinstalled — `signing-certificate` flipped to DETECTED. Separately, the
  emulator's own `/system/xbin/su` tripped `root-path` immediately on both debug and release builds. One UI
  bug was found and fixed from this (wrong description shown for a DETECTED check). Not yet tested: hidden
  root (Magisk/Zygisk with cloaking) or live Frida instrumentation.
- Real device validation: with a physical Pixel 7 Pro (Android 17 / API 37) connected,
  `connectedDebugAndroidTest` against the `sample` app passed **21/21 tests** with 100% success rate across:
  - 14 runtime and native probes (including inline syscalls, ELF W^X segments, hook trampolines, and UI protection)
  - 7 empirical adversarial penetration simulations (`AdversarialAttackSimulationTest`: clipboard scraping, IMEI harvesting, ANDROID_ID tracking, geolocation harvesting, promiscuous TLS HostnameVerifier attacks, Mirage timing jitter, and certificate tampering)
  - Headless Service & BroadcastReceiver bytecode gating
  - Offline persistent SIEM threat queueing (`OfflineEventQueue`)
  - Interactive SOC developer HUD with live attack simulator and real-time audit log

15. **Protection profiles** (`DEVELOPMENT`/`STANDARD`/`HARDENED`, default `STANDARD`): zero-config builds enforce `BLOCK_SCREEN`
    on confirmed threats and enable the dependency firewall; debuggable variants never enforce; indeterminate
    evidence never escalates; explicit settings override and weakenings are flagged in the report.
16. **Per-variant HTML security report** (`build/reports/apparmorx/protection-report-<variant>.html`).
17. **Zero-config signer pin**: derived from the release `signingConfig` keystore (verified against `keytool`
    output on a real minified release build); explicit `signingCertificates` still wins.

18. **Advisory checks** (`ADVISORY_CHECKS`): configuration-posture findings (currently only `network-cleartext-permitted`)
    are reported but never RESTRICT the app. Security-architecture decision: enforcement is reserved for evidence
    an attacker or hostile device produces, otherwise the default `STANDARD` profile could lock out all users of an
    app that deliberately allows HTTP.

19. **Root-path check no longer confuses "permission denied" with "absent"** (`rootPathStatus` in
    `Evidence.kt`, `statPathCheck` in `RuntimeScanner.kt`). Reproduced live on a stock AVD: `/system/xbin/su`
    exists (mode `4750`, `root:shell`) but `Os.stat()` from the app's own SELinux/POSIX context raises
    `EACCES`, not `ENOENT`. The previous `File.exists()` swallowed that distinction and reported `CLEAR`
    (no root) when the honest answer was "could not tell." Now any `EACCES`/other I/O failure with no
    confirmed `Present` path reports `UNAVAILABLE`, never `CLEAR`. TDD: `RootPathStatusTest.kt`, 5 cases,
    plus a full 21/21 instrumented-test re-run on-device after the fix.

20. **Real end-to-end Frida/root/MITM attack reproduced on a rooted emulator — and the honest limit this
    exposes.** Pushed a real `frida-server` (17.23.3, android-arm64) to a rooted AVD, attached with the
    `frida` CLI, and:
    - Confirmed the native engine's hooking probes (`native-frida-port`, `native-tool-thread`,
      `hook-classes`, `hook-library`, `native-hook-trampoline`, `native-stealth-injection`) detect Frida's
      presence independently — these checks flip `DETECTED` correctly and drive `ProtectionState.RESTRICTED`.
    - Separately, installed a permissive `X509TrustManager` + `HostnameVerifier` by calling
      `SSLContext.init()` / `HttpsURLConnection.setDefaultHostnameVerifier()` **directly from injected Frida
      code**, bypassing the app's own compiled call sites entirely. A full MITM against a real self-signed
      attacker server succeeded (`HTTP 200`, attacker-controlled body), confirmed by reading the installed
      verifier's actual runtime class name (not its `toString()`, which V8 prints as `"[object Object]"` for
      any Java object and produced a false "neutralized" result on the first attempt).
    - **Re-ran the same attack against a release build already in `RESTRICTED` state** (root detected,
      confirmed via `adb shell content call --uri content://<app>.init --method getSecurityState` showing
      `state=RESTRICTED` *before* Frida was even attached). The MITM still fully succeeded.

    **Why**: the dependency firewall (`DependencyFirewall`) rewrites the *app's own* compiled bytecode call
    sites — `ClipboardManager`, `Settings.Secure`, `LocationManager`, `HttpsURLConnection.setDefault*`,
    `SSLContext.init`. It cannot intercept a framework method called directly by code an attacker injected
    into the running process, because that call never passes through any instrumented call site. This is **not**
    an AppArmorX-specific gap: no client-side RASP product can sandbox a co-resident native-code attacker's
    further API calls without OS-level enforcement (SELinux, a kernel-level LSM, hardware attestation), none
    of which a Gradle-plugin-distributed library controls. Every vendor making an "unhookable" or "unbypassable"
    claim is marketing, not engineering — which is exactly why this project's own docs never make that claim.

    **Considered and explicitly rejected**: an opt-in `Process.killProcess()` triggered automatically on
    confirmed hooking evidence, to deny the attacker's injected session a process to keep running in.
    Rejected for two reasons, not one:
    1. It would violate this repository's own standing rule (`AGENTS.md`): *"No ... automatic process
       termination."* That rule exists for good reason — an automatic kill is itself attacker-triggerable
       (spoof a hooking signal, force-crash the app for any user) and is exactly the kind of blunt response
       the existing `EnforcementAction.TERMINATE` → `finishAffinity()` design deliberately avoids.
    2. It would not actually close the gap. By the time hooking evidence is `DETECTED`, the attacker's
       injected code has already run and the single MITM request has already completed — a kill only
       affects the *next* guarded lifecycle call, after the damage from this one is already done. Shipping
       it would be response theater, not a fix, and this project does not ship theater.

    **What the existing design already does correctly for this case, with no new code needed**: hooking
    checks are ordinary `DETECTED` evidence like any other — they drive `ProtectionState.RESTRICTED` through
    the same `decideProtection()` path as root/signer findings (no special-casing, no severity grading to get
    wrong), they trigger whatever `restrictedAction` the host configured (`BLOCK_SCREEN`/`TERMINATE` under
    `STANDARD`/`HARDENED`), and `TelemetryEvents.incidentChecks()` already includes hooking checks in the
    HMAC-signed report sent to the app owner's own endpoint — so even though the client cannot stop this
    attack, the owner finds out it happened. That reporting path was already correct before this slice;
    this slice only confirms it fires for this specific attack class too.

21. **Anti-ptrace hardening, implemented and tested — and found to make no practical difference on a
    representative modern Android configuration.** Added an opt-in `security.antiPtraceHardening`
    flag (never a profile default, including `HARDENED`; forced off on debuggable builds both at
    build time and again at runtime). When enabled, `NativeEngine.hardenAgainstPtraceAttach()` forks
    a minimal watchdog that attempts `ptrace(PTRACE_ATTACH)` on its own parent at process startup, so
    a later attach from an external tool (how `frida -U` on Android attaches to an already-running
    process) would fail with `EPERM` — Linux allows only one tracer per process. `prctl(PR_SET_PTRACER)`
    is used so Yama's ptrace_scope=1 default doesn't itself block our own watchdog. The outcome is
    verified independently by reading `/proc/self/status`'s `TracerPid` via the existing raw-syscall
    `read_bounded()`, which a libc-level `ptrace()` hook cannot spoof; the function returns `false` and
    changes nothing else if it could not acquire the slot, and reaps its own watchdog in that case (an
    earlier version of this leaked a zombie process on failure — caught during on-device testing,
    fixed before shipping, re-verified clean).

    **Tested for real, end to end, on the `armor35` rooted AVD (API 35, `google_apis`, `arm64-v8a`)**:
    built a release APK with the flag on, confirmed via the generated HTML report that the layer is
    "ON (overridden from profile default: false)", installed it, launched it (clean, no crash, no
    hang — confirmed via `ps` and logcat), then re-ran the exact non-spawn Frida attach
    (`frida -D emulator-5554 -n consumer -l hook.js`, i.e. attaching to an already-running process,
    not `frida -f`) that this feature specifically targets.

    **Result: the attack still succeeded.** `/proc/<pid>/status` showed `TracerPid: 0` after our
    hardening ran — it could not acquire the slot. Root cause, confirmed on-device (`getenforce` →
    `Enforcing`): AOSP's own SELinux policy denies `untrusted_app`-domain processes `ptrace` on
    anything, including themselves, independent of the device being rooted — this is deliberate
    upstream hardening against exactly this class of self-protection trick, present since well before
    this AVD's API level. A root-privileged attacker (`frida-server` running as root, outside the
    `untrusted_app` domain) is not bound by that same restriction and can still ptrace *into* an
    `untrusted_app` process from outside it. So the one domain that could use this defense is
    SELinux-blocked from using it, while the domain the defense is meant to stop is not.

    **Decision: keep the code, do not market it as closing the gap.** It is safe (tested clean, no
    crash, no zombie, no behavior change when it fails), correctly gated (opt-in, never on debuggable,
    verified result not just assumed), and may still help on an older or custom Android build whose
    SELinux policy never added this specific `neverallow` rule, or where root weakens SELinux instead
    of leaving it enforcing (not the case on this AVD, and not something to assume generally). But on
    a representative modern, SELinux-enforcing rooted device — which is the actual, current threat
    model — it changes nothing. State this precisely: this slice is evidence about the *limits* of a
    userspace self-protection trick, not a fix for the Frida/MITM gap documented in Slice 20.

22. **`killOnConfirmedHooking`: a real, working, verified hard-kill — with its scope stated precisely.**
    Per explicit owner direction, `AGENTS.md`'s default "no automatic process termination" rule now
    carries one narrow, documented exception (see that file for the exact wording). Implemented
    test-first (`HookKillDecisionTest`, 7 cases): a pure `shouldKillOnConfirmedHooking(evidence,
    policy, debuggable)` decides, and only `EnforcementResponse`/`SecurityGuard.evaluateComponent`
    (the parts that already touch Android process APIs) call `Process.killProcess()`. Never a profile
    default (including `HARDENED`), forced off on debuggable builds at both build time and runtime,
    fires only on confirmed (`DETECTED`) hooking/injection-specific evidence (`HOOKING_CHECKS`), never
    for root/signer/other RESTRICTED causes, and takes priority over whatever `restrictedAction` says.

    **Verified for real, not assumed**: built the consumer clean-room app with
    `killOnConfirmedHooking.set(true)`, installed the release APK on the rooted `armor35` AVD, attached
    a persistent (not one-shot) Frida session to the already-running process, and waited for the
    existing periodic re-scan. Result, confirmed two independent ways: `logcat` shows
    `W/AppArmorX: Confirmed hooking evidence; killOnConfirmedHooking is enabled, terminating process`,
    and `adb shell pidof demo.consumer` went from a live PID to empty. **This is the one mitigation in
    this entire investigation that genuinely changed an outcome on a real device**, not just detected
    and reported one.

    **Its real limit, stated precisely** (do not oversell this): it cannot prevent the single malicious
    call already in flight at the moment confirmed evidence lands, because detection runs periodically
    (throttled) and on guarded lifecycle events, not continuously — see Slice 20's MITM, which still
    completes before any scan could react. It only denies the attacker's session further time in that
    process. It also only fires again once some guarded component is actually re-evaluated: if the
    configured `restrictedAction` already finishes the app's only Activity (e.g. `BLOCK_SCREEN` with
    nothing else guarded), the periodic `ForegroundMonitor` stops (nothing is left resumed to track) and
    this cannot fire until another guarded entry point runs. The on-device test above used
    `restrictedAction=OBSERVE` specifically to isolate and prove the kill mechanism itself works; a real
    deployment combining `BLOCK_SCREEN`/`TERMINATE` with `killOnConfirmedHooking` needs at least one
    guarded component (Application/Service/BroadcastReceiver, not just a single Activity) to keep
    getting re-evaluated for this to have a chance to fire in practice. State this combination
    requirement wherever this flag is documented.

    **A real, separate bug found as a direct byproduct of this testing** (not predicted, not assumed —
    found because the kill didn't fire on the first attempt and had to be root-caused): `frida_ports()`,
    `selinux_eval()` and `hardware_devices()` in the native engine silently returned `Status::clear`
    whenever their underlying file read failed, instead of `Status::unavailable` -- exactly the
    "unavailable treated as clean" bug this project explicitly forbids, and it was sitting in the
    codebase (even locked in by an assertion in `probe_test.cpp`) undetected until this test exposed it.
    Root cause: AOSP's SELinux policy denies the `untrusted_app` domain read access to `/proc/net/tcp`,
    `/proc/net/tcp6` and `/sys/fs/selinux/enforce` outright (confirmed live via `avc: denied` log lines)
    -- so on any SELinux-enforcing device, `native-frida-port` and `native-selinux` were *always*
    silently reporting clean regardless of whether Frida was actually running, false-negative by
    construction. Fixed all three to the same `rootPathStatus`/`root_paths()` pattern already used
    correctly elsewhere: a read failure now returns `unavailable`, never `clear`. The kill test above
    still succeeded even with `native-frida-port` blind on this device, because the other independent
    hooking checks (stealth-injection/hook-library catching the live `/memfd:frida-agent-64.so` mapping)
    still caught it -- the layered design held even though one layer was known-broken, which is exactly
    why this project keeps multiple independent checks rather than relying on any single one.

23. **`HookWatchdog`: a fast, Activity-lifecycle-independent poll loop for `killOnConfirmedHooking` —
    and it genuinely prevented the MITM attack from Slice 16/20 in the realistic attach scenario,
    verified on-device.** Slice 22's kill mechanism only fired on the next full scan, which is
    throttled to 30s and only resumes while some guarded Activity is resumed. `HookWatchdog` is a
    dedicated daemon thread, started at `SecurityRuntime.initialize()` (as early in the process as
    this library runs at all), that polls only the cheap native engine checks
    (`native-frida-port`, `native-tool-thread`, `native-hook-trampoline`, `native-stealth-injection`,
    plus the two others `NativeEngine.scan` returns) every ~750ms, independent of any Activity state.
    Same gates as Slice 22: opt-in via the same `killOnConfirmedHooking` flag, never on debuggable.

    **Measured, not assumed**: attaching Frida to a running, watchdog-protected process now kills it in
    **~1.0 second** (external wall-clock measurement via `date`, attach-to-pid-gone), down from the
    30-60+ seconds Slice 22 needed when nothing happened to be resumed.

    **The critical test — re-ran the exact Slice 16/20 MITM attack against this:**
    - **Spawn mode** (`frida -f demo.consumer -l mitm_attack2.js`): the attack still succeeded
      (`HTTP 200 ... MITM_SUCCESS`) -- confirms, again, that nothing can win a race against an attacker
      who injects before this process has executed a single instruction of its own. Frida's own output
      showed `Process terminated` immediately afterward: the watchdog still ended the session, just
      too late for this one already-spawned-with-the-attacker-inside launch.
    - **Attach mode** (`frida -n consumer -l mitm_attack2.js`, attaching to an app that had already
      been running a few seconds -- the realistic "attacker roots a phone and attaches Frida/Objection
      to an app they didn't control the launch of" scenario): the script printed
      `[mitm] === BEFORE any Frida tampering ===` and then **`Failed to load script: the connection is
      closed`** -- the process was already dead. `logcat` confirms why and exactly when:
      `15:40:56.391 W/AppArmorX: Confirmed hooking evidence (fast watchdog) ... terminating process`,
      before the script ever reached the line that installs the permissive TrustManager. **The MITM
      bypass was never installed. This is the first result in the entire investigation where a
      mitigation measurably prevented, not merely detected or shortened, the exact attack from Slice
      16/20** -- in this specific, realistic scenario.

    **State the boundary of this precisely, every time**: it closes the gap for an attacker attaching
    to an already-running, already-protected process. It does not, and architecturally cannot, close it
    for spawn-time injection, where the attacker's code runs before this library's first instruction.
    Both outcomes were demonstrated side by side above specifically so neither gets overstated.
    Continuous polling has a real, ongoing CPU/battery cost for as long as the process lives -- the
    explicit, accepted price of the faster reaction, which is why `HookWatchdog` only ever runs when a
    host opts into `killOnConfirmedHooking`, never unconditionally and never as a profile default.

## Important limits — still open
- **Confirmed by real attack, not assumed, with a now-partial mitigation**: a root+Frida attacker who
  gets code running in-process can call Android framework TLS APIs directly and defeat network security
  entirely. With the owner-approved `killOnConfirmedHooking` + `HookWatchdog` (Slice 22/23), the recorded
  attach-mode payload was stopped in its tested environment/timing. This is not proof that every attach
  attack is prevented; periodic checks cannot stop the action already in flight. Spawn-time injection
  (`frida -f`) remains unclosable -- the attacker's code runs before this library's first instruction,
  which no userspace response can outrace. State both outcomes together, never one without the other.
- **Anti-ptrace hardening (`antiPtraceHardening`) does not close that gap either, confirmed by testing
  it against the same attack.** AOSP's SELinux policy denies `untrusted_app` processes `ptrace` on
  themselves regardless of root, so the one thing this feature could have blocked (occupying the
  tracer slot before an attacker's Frida attaches) never gets the chance to run on a representative
  modern device. See Slice 21. Kept as a safe, tested, opt-in no-op on devices where it can't work;
  not a mitigation to cite for the Frida/MITM gap.
- **Adversarial dynamic instrumentation.** Root/hook/tamper checks pass on clean devices, physical hardware, and automated adversarial attack simulation fixtures; ongoing testing against evolving Magisk/Zygisk cloaking modules remains an iterative focus.
- **Relocation-aware executable-segment integrity and GOT entry validation.** Probe 14 (`native-relocation-integrity`) verifies hardware W^X on PT_LOAD segments and symbol pointer authenticity; full GOT table relocation validation remains future work.
- Sample's release build uses an invalid placeholder signer (`0` × 64) purely to exercise the
  `requireReleaseSigningPins` gate structurally — proves packaging/shrinking mechanics, not real
  signer validation.
- `EnforcementAction.TERMINATE` calls `finishAffinity()`, not process termination — finishAffinity is
  the safer default to avoid corrupting in-flight disk/database writes.

## Monitoring implementation, briefly
`ForegroundMonitor` is a small generation-token state machine: `start()` is idempotent, `stop()`
invalidates any already-queued tick via generation comparison so a stopped-then-restarted monitor
can't double-schedule. `SecurityRuntime` keeps weak references to resumed Activities and checks
finishing/destroyed before dispatching a response on the main thread; `SecurityBlockActivity` is
excluded from being tracked. Scanning itself stays on a background worker — no probe I/O was added to
the UI thread. This is foreground monitoring only, not a background service and not a startup gate.

## Next implementation order
1. **Signed integrity manifest over the packaged payload** (the actual "anti-tampering" claim), building
   on the presence-only coverage audit.
2. **Broaden guard coverage past Activity** (Application, Service, BroadcastReceiver, WorkManager).
3. **Deeper native integrity** (PLT/GOT, executable-segment checks) with adversarial + clean-device
   fixtures.
4. **Opt-in bounded reporting and reviewed signed rule promotion** (THREAT-FEEDBACK.md).
5. **Complete optional Play Integrity integration.** Preparatory library-presence and hashing helpers
   exist in PlayIntegrityAdapter.kt; token requesting and server verification are not implemented.
   The app owner must verify request binding, expected app identity, freshness and business authorization
   on their own server. No client-only result makes a compromised process trustworthy.

See [ROADMAP.md](ROADMAP.md) for the 2026-10-17 release sequence; the older order above includes
already-implemented component/reporting work and must not be read as a current implementation checklist.

Preserve: tests-before-security-changes, configuration-cache compatibility, explicit
UNAVAILABLE/INDETERMINATE semantics that never silently escalate or silently clear. Do not call a
packaging check proof of runtime prevention, and do not call a passing test suite "enterprise-ready".

## Release gates (checklist, largely still open)
- Enforcement: startup pending/timeout/denial, malformed configuration, late findings, response
  deduplication, protected host code provably not executing past a denial.
- Coverage: Application, Activity inheritance, providers, services, receivers, workers, multiprocess,
  dynamic features; report unsupported boundaries rather than silently skip them.
- Integrity: post-R8 payload metadata, independent trust anchors, signer rotation, APK/AAB/split
  mutation fixtures, missing-ABI rejection (structural presence is now checked; authenticity is not).
- Native engine: relocation-aware code integrity and hook evidence with measured false-positive and
  performance budgets, not filename-only claims.
- Policy operations: rotation/revocation, rollback/freeze tests, canary promotion, reproducible
  release locks.
- Reporting: opt-in tenant endpoint, bounded/redacted events, encrypted queue, replay/poisoning
  resistance, retention/deletion, no executable remote updates ever.
- Assurance: supported toolchain/OS/ABI/device matrix beyond one Pixel, rooted/hooked clean controls,
  measured startup/CPU/battery cost, independent penetration testing.
- Distribution: owner-approved license, namespace verification, signed reproducible artifacts,
  disclosure process. External publication remains prohibited without explicit owner approval.

See [RESEARCH-ROADMAP.md](RESEARCH-ROADMAP.md) for the research behind these priorities. Differentiator: the *combination*
of zero-integration plugin, firewall, native engine and auditable reports, not any single novel technique.
