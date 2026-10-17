# Verification

Evidence is recorded in [STATUS.md](STATUS.md) and [VALIDATION.md](VALIDATION.md).

- Unit tests for `policy`, `plugin` (bytecode visitor, manifest auditor, archive) and `runtime`.
- `validatePlugins`, Android release lint, native AAR for `arm64-v8a` and `x86_64`.
- **Repackaging attack reproduced**: built a release signed with a real keystore (confirmed CLEAR),
  unzipped it, tampered its content, re-signed with a different unrelated keystore, reinstalled — detection
  flipped CLEAR → DETECTED on the live app. Root detection confirmed against an emulator's own root tooling.
  Details: [VALIDATION.md](VALIDATION.md) (14 Oct 2026 entry). Not yet tested: hidden root or Frida.
- **Physical device**: Google Pixel 7 Pro, Android 17 (API 37), `connectedDebugAndroidTest` on the `sample`
  app, **21/21 passing**. The same 21 also pass on an **API 35 arm64 emulator** (where the environment
  probe correctly reports DETECTED). The emulator run also showed `native-hardware-device` staying CLEAR
  there, so the native emulator probe is weaker than the Kotlin one; treat emulator detection as best-effort: 14 runtime/native/component tests plus 7 adversarial simulations (simulated SDK
  clipboard scraping, IMEI/ANDROID_ID harvesting, location harvesting, trust-all TLS verifier, Mirage
  jitter, certificate tamper).
- CI ([.github/workflows/ci.yml](../.github/workflows/ci.yml)): a blocking job runs unit tests, plugin
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
  inside the process it spawns. Full repro, commands and logs: [VALIDATION.md](VALIDATION.md)
  (Slices 16–19), [STATUS.md](STATUS.md) (Slices 19–23).

The `sample` app includes a live "SOC" HUD with an attack simulator, useful for demos.
