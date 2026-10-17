# 0.1.1 candidate qualification — 17 October 2026

Status: locally qualified 0.1.1 patch candidate on the tested baseline. Final unit/native/lint/plugin, isolated signed-R8 consumer and full emulator checks pass. This is not a 1.0 stability or commercial-parity claim; Owner authorized publishing these fixes as 0.1.1 on 17 October 2026. Publication status is recorded in PUBLISHING.md.
Baseline: main at 883da67 plus the working-tree changes described here.

## Change being qualified

0.1.0 registers its ASM visitor with PROJECT scope. That covers project bytecode, not external dependency
JAR/AAR bytecode. This contradicts broader dependency coverage language in earlier documentation.
The candidate adds a separate ALL-scope firewall visitor, retaining PROJECT-scoped lifecycle guards.
The new library pass deliberately does not synthesize lifecycle methods into third-party components.
Framework, AndroidX and AppArmorX runtime namespaces remain excluded; dynamic injection is outside scope.

The regression fixture supplies a separately compiled external JAR containing a clipboard API call.
Its class and method are retained in the minified APK. Verification inspects that class's actual DEX
instructions for a DependencyFirewall static call and rejects a retained platform clipboard invocation.
This proves this build-time rewriting scenario, not end-to-end device attack prevention or universal coverage.

## Reproduce

Public baseline installation (isolated Gradle home; test-only release signer):

```sh
python3 scripts/verify-public-consumer.py --version 0.1.0
```

Public external-JAR regression (expected to fail on 0.1.0):

```sh
python3 scripts/verify-public-consumer.py --version 0.1.0 --verify-dependency
```

Candidate build and local-only staging (not Plugin Portal publication):

```sh
./gradlew check validatePlugins lintRelease :plugin:publishAllPublicationsToCandidateRepository -PreleaseVersion=0.1.1-SNAPSHOT -Papparmorx.candidateRepository=/tmp/apparmorx-candidate-011-qualified --configuration-cache
python3 scripts/verify-public-consumer.py --version 0.1.1-SNAPSHOT --repository /tmp/apparmorx-candidate-011-qualified --verify-dependency
./gradlew -p sample assembleRelease connectedDebugAndroidTest --configuration-cache
```

The consumer verifier retains logs, reports, test-only keystore and APK under its printed evidence directory.
It uses no Maven Local or source substitution. Candidate runs accept only the explicitly supplied local
Maven repository; public runs resolve through Google, Maven Central and the Plugin Portal.
It checks signed R8 packaging, both native ABIs, JSON/HTML/SARIF and configuration-cache reuse.
The optional --gradle-user-home flag allows cache reuse; label such runs as warm-cache evidence.

## Native regression fixes

The wait-channel probe returned CLEAR when /proc/self/wchan could not be read. It now reports
UNAVAILABLE on missing/empty reads, retaining DETECTED for supported ptrace indicators.
SELinux parsing previously returned CLEAR for arbitrary nonempty text other than a leading zero;
a new malformed-input test failed before the fix. Only valid 0/1 values now establish a result.
The standalone C++ regression executable is now a CI step, built with warnings as errors.
Device expectations independently read these files in the instrumented app sandbox instead of
unconditionally requiring CLEAR when Android denies access. No native result was weakened to pass tests.

ARTEMIS exploration was attempted before editing the device tests. The initial attempt could not launch
the app because connected-test cleanup had uninstalled it. A subsequent installed-app run reached the
app, but secure-screen capture and empty accessibility output prevented reading the probe rows. It was
stopped without disabling security. Device instrumentation provides the actual per-probe assertions.

## Other corrections

- Clarified repository setup for Android apps with custom pluginManagement.repositories.
- Corrected PlayIntegrityAdapter documentation: presence/hash helpers only, no token request or verification.
- Narrowed attach-mode watchdog claims to recorded evidence; periodic detection cannot prevent all in-flight actions.
- Clarified that app-distributed telemetry credentials are not device attestation.
- Added separate published-consumer and candidate dependency-regression CI steps. Remote execution is not yet verified.

## Current measured results

- Published 0.1.0: isolated consumer builds successfully and reuses configuration cache.
- Published 0.1.0: external-JAR regression fails, with an actual invoke-virtual ClipboardManager.getPrimaryClip retained in final DEX.
- Candidate: same retained library class has invoke-static DependencyFirewall.getPrimaryClip in final signed R8 DEX. Both native ABIs, reports and configuration-cache reuse pass.
- Final source checks: 9 policy + 62 plugin + 100 runtime tests, zero failures; validatePlugins and Android lint pass.
- A malformed optional security flag previously silently became false. New regression failed before the fix; parsing now rejects malformed present values while preserving missing-field defaults.
- Initial emulator suite: 20/21 pass; SELinux test incorrectly expected CLEAR when this device denied access. After correcting environment assumptions, the full suite passed 21/21. The final full rerun against the native-hardened source also passed 21/21 on the Android 17 arm64 Pixel_10a emulator. The APK native engine SHA-256 was checked against the final AAR; they match.
- Final native-hardened candidate consumer evidence: /var/folders/3c/hdbx8q9n1tb6fy1_yfy7dxxh0000gn/T/apparmorx-public-consumer-d8n1w01m (warm dependency cache, isolated consumer, explicit local candidate repository).

These are local APK-build results. AAB/split-delivery verification and remote CI execution are not established by this run.

## Remaining stable-release gates

- Final-source local device/candidate checks are complete. Obtain reviewed remote CI evidence before release; emulator lanes remain informational until their own remote runs are proven.
- Exercise the candidate on real supported OEM devices; current emulator evidence cannot replace physical testing.
- Measure cold startup, scan cost, memory, APK/build overhead and watchdog impact with controlled baselines.
- Validate declared toolchain/OS/ABI support; no blanket AGP or OEM compatibility claim.
- Review enforcement false positives, unavailable/stale states and key/policy trust boundaries.
- Independent adversarial review and fuller signed-payload integrity remain roadmap work.

Passing this local scope is sufficient to propose a patch candidate, not to claim parity with commercial
RASP platforms, independent certification, or a completed 1.0 assurance program.


## Final local gate log

- /tmp/apparmorx-qualified-checks.log — check, validatePlugins, lintRelease and local-only candidate staging passed.
- /tmp/apparmorx-qualified-device.log — final assembleRelease and connectedDebugAndroidTest passed (21/21).
- /tmp/apparmorx-release-evidence/final-emulator.xml — preserved final device result.
- /tmp/apparmorx-native-tests — standalone host-native regression executable passed; this is parser/evaluator testing, not a device penetration test.
- Public baseline /var/folders/3c/hdbx8q9n1tb6fy1_yfy7dxxh0000gn/T/apparmorx-public-consumer-5hqpc1m2 used an initially isolated Gradle home. Subsequent candidate runs reused dependency caches and are labeled accordingly.

The final sample release is the repository's packaging fixture with placeholder signing pins, not a
production signer test. The independent consumer uses a generated test keystore, verifies APK v2 signing
and builds without placeholder pins. Neither should be described as production deployment evidence.
