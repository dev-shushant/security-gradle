# AppArmorX research-backed roadmap

Research date: 2026-09-30. These are proposed capabilities, not implemented claims. Sources are primary documentation; no independent vendor benchmarking was performed. Recommendations and priorities below are engineering synthesis. Some pages were available through indexed extracts only; verify exact API/toolchain contracts during implementation.

## Product decision

Build a free, inspectable protection engine with automatic Gradle integration and a self-hostable control plane. Core local protection must not require a hosted account, telemetry, Google Play or a paid service. Optional hosted infrastructure has real operating costs; free software does not imply unlimited free hosting. Public licensing still requires the owner's decision.

Resilience complements secure storage, authentication, networking and platform integration. It cannot repair arbitrary business authorization or make a compromised client trustworthy. OWASP explicitly treats resilience as defense in depth and warns about platform lock-in and legitimate-user exclusion. [MASVS resilience](https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/)

## Prioritized capability matrix

P0 = foundation required before enforcement claims; P1 = next protection expansion; P2 = experimental/optional. All rows describe target behavior.

| Priority / capability            | Integration and trust boundary                                                                                       | Acceptance evidence / main risk                                                                                                                           |
|----------------------------------|----------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| P0 startup and operation gates   | Automatic supported component guards; explicit adapter for customer-defined sensitive operations                     | Pending, timeout, stale and unavailable states cannot accidentally permit a configured protected operation; preserve lifecycle/cleanup contracts          |
| P0 engine health                 | Separate detector health, scan freshness, native ABI/load status and response policy integrity                       | Missing JNI, stopped monitor, malformed policy and removed guard fixtures; no clean verdict from a failed probe                                           |
| P0 tamper integrity              | Build-generated signed inventory of selected DEX/native/config payloads plus deployed signer policy                  | Modified/re-signed/missing-entry APKs, signing rotation, minification and split delivery; no circular whole-APK hash                                      |
| P0 protection coverage report    | Audit packaged outputs and instrumented boundaries; machine-readable JSON/SARIF                                      | Fail required missing coverage; explain unsupported components and explicit waivers rather than claim all code is protected                               |
| P0 evidence correlation          | Stable IDs, family, confidence, availability, age and response eligibility                                           | Multiple readings of the same artifact must not count as independent corroboration; one weak root/tool indicator must not become a universal block        |
| P1 native memory integrity       | Relocation-aware executable segment checks and selected function-pointer ownership                                   | Controlled inline/PLT/GOT patches versus legitimate loaders/JIT; establish trusted baseline before accepting it, not after an attacker may modify memory  |
| P1 root and instrumentation      | Managed/native root artifacts, mount context, debugger/tracer and module/thread evidence                             | Hidden/renamed tools, denial of reads, clean OEM/custom-ROM controls; paths alone cannot establish absence of root                                        |
| P1 UI protection                 | Configured sensitive-screen capture/overlay policies and obscured-touch checks                                       | Views/Compose, accessibility, multiwindow and OS matrix; avoid blanket accessibility-service bans                                                         |
| P1 build vulnerability checks    | Manifest, backup, exported components, URI grants, PendingIntent, deep links, WebView and TLS findings               | Unsafe/clean paired fixtures, scoped expiring waivers; source/bytecode analysis may report uncertainty rather than silently rewrite application semantics |
| P1 optional server attestation   | Play Integrity request binding and independent server verification; separate key-attestation adapter                 | Request substitution, stale tokens, replay handling, chain/revocation failures; no fabricated equivalent verdict on non-Play devices                      |
| P1 secure policy distribution    | TUF-style metadata roles, thresholds, expiry, persisted version floors and reviewed rotation                         | Compromised online key, rollback/freeze/mix-and-match, offline builds, recovery and canary rollback                                                       |
| P1 customer-controlled reporting | Opt-in HTTPS destination, bounded typed events, encrypted expiring queue, tenant-bound ingestion                     | Oversize/replay/poisoned events, offline/backoff limits, server outage; no raw memory or secrets by default                                               |
| P1 supply-chain controls         | Dependency verification/locking, SBOM, signed provenance and reproducible release inputs                             | Reject substituted dependency bytes; review trust bootstrap; SBOM inventory alone is not vulnerability remediation                                        |
| P2 platform hardening            | Evaluate MTE/CFI and other compiler protections for owned native artifacts; version-aware platform security settings | Supported hardware/toolchain/performance measurements; do not imply an AAR hardens arbitrary prebuilt host libraries                                      |
| P2 managed-runtime internals     | Version-specific ART entrypoint analysis behind compatibility gates                                                  | Interpreter/JIT/AOT/OS/OEM matrix; hidden layout assumptions must produce UNSUPPORTED rather than false positives                                         |
| P2 build diversification         | Reproducibly seeded guard placement and selected obfuscation                                                         | Measure bypass cost, size, build time and crash diagnosability; not secret storage or a substitute for cryptography                                       |

## Research findings and implementation consequences

### Structural detection is the important anti-hooking expansion
OWASP distinguishes tool artifacts from modifications to native instructions, bytecode targets and pointer tables. AppArmorX should test these independently. Start with owned native code and selected pointers; arbitrary ART internals come later because layouts and legitimate execution targets vary. A renamed tool should not evade a supported code-integrity check merely by changing its filename. No checksum or pointer check is unhookable. [Runtime integrity verification](https://mas.owasp.org/MASTG-KNOW-0032/)

### Protect actions as well as screens
Play Integrity standard requests support requestHash binding and automatic token replay protection. The server must still validate the expected operation, account/session context and business authorization; token replay protection does not replace idempotent transaction handling. A generic plugin cannot infer what a payment means. Supply an optional narrow adapter while preserving automatic baseline integration. [Standard requests](https://developer.android.com/google/play/integrity/standard)

Google's App Access Risk signals cover capturing/controlling environments without revealing installed-app identities. Its guidance favors checks near important actions and distinguishes verified accessibility tools. Treat this as an optional platform adapter, not local package scraping or proof of a particular malicious application. [Fraud prevention environment](https://developer.android.com/security/fraud-prevention/environment)

### Expand beyond RASP into preventable configuration weaknesses
Implement build rules before invasive runtime rewriting. Prioritize exported-component exposure, unsafe intent forwarding, URI/deep-link validation, WebView bridges/file access, cleartext traffic and permissive certificate validation. Customer allowlists are necessary where intent/URL authorization depends on business semantics. [Android security risks](https://developer.android.com/privacy-and-security/risks), [WebView URI validation](https://developer.android.com/privacy-and-security/risks/unsafe-uri-loading), [tapjacking](https://developer.android.com/privacy-and-security/risks/tapjacking)

Audit effective Network Security Configuration. Current documentation adds certificate transparency on API 36+, with changed defaults on API 37, and ECH on API 37 where the networking library supports it. Detect configuration regressions and report stack-specific coverage; never claim every native/custom TLS client obeys platform XML. Certificate pinning requires customer-managed rotation/recovery, so do not impose it globally. [Network security configuration](https://developer.android.com/privacy-and-security/security-config)

### Harden our native engine itself
CFI constrains indirect control transfers; MTE can detect classes of memory errors on supported hardware. Evaluate them for AppArmorX-owned code and test their overhead and build constraints. These are memory-safety mitigations, not general Frida detectors. Platform build support is not automatically equivalent to portable third-party NDK support. [AOSP CFI](https://source.android.com/docs/security/test/cfi), [NDK MTE](https://developer.android.google.cn/ndk/guides/arm-mte?hl=en)

Advanced Protection Mode can inform an explicitly selected stronger policy on supported Android versions. Its absence must not mean compromise. [Advanced Protection Mode](https://developer.android.com/privacy-and-security/advanced-protection-mode)

### Attestation needs lifecycle management
Hardware-backed key attestation requires certificate-chain, security-level and revocation validation, with trust-root maintenance. An attested key does not establish ongoing integrity of all application memory. Keep verification off the untrusted client and bind enrollment to a fresh server challenge. [Key attestation](https://developer.android.google.cn/privacy-and-security/security-key-attestation?hl=en)

### A single signed feed is insufficient for enterprise updates
TUF separates trust roles and uses signed versioned/expiring metadata with configurable thresholds. Adopt its threat model and evaluate maintained implementations instead of inventing a superficially similar protocol. AppArmorX still needs promotion, recovery, offline policy and engine-capability compatibility. Never let a report or feed install executable hooks or change customer reporting destinations. [TUF overview](https://theupdateframework.io/docs/overview/), [metadata roles](https://theupdateframework.io/docs/metadata/)

Gradle locking stabilizes resolved versions; verification checks artifacts against reviewed trust metadata. Both belong in release engineering, with explicit bootstrap/review rather than blindly trusting newly generated checksums. [Dependency locking](https://docs.gradle.org/current/userguide/dependency_locking.html), [dependency verification](https://docs.gradle.org/current/userguide/dependency_verification.html)

## Controlled improvement loop

Proposal: collect minimal opt-in anomaly facts, deduplicate and isolate by tenant, cluster candidates, reproduce in a sandbox, test against hostile and clean fixtures, review, sign, canary and measure. Candidate generation can be automated. Promotion to globally enforced rules must remain reviewed. Record false-positive rate, unavailable rate, coverage, event drops, scan latency, CPU/battery and regression rate. Public benchmark fixtures and supported-version evidence are stronger differentiators than an undocumented detector count.

## Deliberately exclude from default behavior

No indiscriminate port/package scans, automatic data deletion/process killing, blanket root/accessibility/VPN/emulator bans, remote executable updates, home-grown cryptography, implicit reporting endpoint, universal certificate pinning, or promises that app-embedded encryption hides secrets from its owner. No broad memory collection for a speculative learning system.

## Execution sequence

1. Fix and validate existing monitoring; independent response trust and startup denial behavior.
2. Add packaged coverage audits and signer/payload tamper fixtures.
3. Native structural integrity, component coverage and correlated evidence.
4. Build vulnerability rules and optional action-bound server attestation.
5. Hardened policy operations and self-hostable reporting/review pipeline.
6. Compatibility, performance, adversarial and independent assurance gates before public protection claims.

Each capability requires a threat model, explicit support matrix, adversarial and clean fixtures, failure behavior, overhead budget and coverage report. Research does not change the current alpha status or the recorded failing foreground-device test.
