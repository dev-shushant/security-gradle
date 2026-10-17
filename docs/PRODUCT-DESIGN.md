# AppArmorX: automatically injected application protection

**Design for review — Shushant Tiwari — 29 September 2026**

This document supersedes the initial observation-only prototype as the product direction. The prototype is not an accepted implementation of the requested product. No external publication is authorized.

## Product contract

The developer applies `com.apparmorx.security` to the Android app and supplies trust settings and a protection profile. The plugin supplies, configures, injects and verifies the security artifacts. The developer must not write root, Frida, hooking or tamper checks; edit their Application for startup; register monitoring; add JNI/CMake code; or wire a custom rejection screen just to obtain baseline protection.

The shipped APK/AAB, not the Gradle task list, is the deliverable. A release that lacks a required artifact or guard must fail the build. A runtime that loses a required engine must enter its configured restricted state, not report a clean result.

The trust settings cannot be invented: deployed signing identities, distribution channel, acceptable device policy and any backend verification endpoint are app-owner inputs. These are configuration, not hand-written detection code.

## Independent community product

AppArmorX is designed for arbitrary Android applications. Its public contracts must remain independent of consumer architecture, dependency injection, configuration schemas and business logic.

“More powerful” must mean greater verified protection and coverage, not a longer list of root paths or more aggressive process killing. The differentiators are structural runtime integrity, independent native/managed observations, distributed guard coverage, automatic enforcement, secure engine/policy lifecycle and published adversarial test evidence.

### Consumer independence

- Kotlin and Java applications, Compose and Views; no required UI framework, DI container, networking library, analytics SDK or architecture.
- Existing Application classes, providers, service-only processes, WorkManager, deep-link entry points, dynamic features and product flavors are compatibility cases, not special assumptions.
- Flutter, React Native and Unity Android hosts may consume the Gradle integration, but support cannot be claimed until their startup/native loading/shrinking behavior has been tested. Protecting the Android host does not automatically validate Dart, JavaScript or game scripting business logic.
- Ship owned prebuilt native AAR artifacts for supported ABIs so ordinary consumers do not need to install an NDK or maintain CMake. Build-specific native generation, if needed for a hardened profile, must be explicit and justified by measured protection value.
- No dependency on Google Play for the core engine. Play-backed attestation is an optional supported adapter; alternative stores and enterprise deployments require explicit distribution profiles and cannot receive fabricated Play verdicts.
- Consumer source stays unchanged. Generated code, transformed bytecode, resources and manifest changes live in build outputs and are inspectable in the protection report.

### Public contracts

Keep the developer experience small: plugin, profile, trust inputs and documented exceptions. Make internals modular: detector capability/version, evidence, compatibility, health, response decision and signed-policy protocol. Use stable typed check IDs rather than obfuscated public interfaces. Obfuscation belongs in shipped implementation, not the maintenance API.

The main `com.apparmorx.security` plugin composes the required features. Separate public plugins should exist only when useful independently—for example build-only security verification—not merely because there are internal modules. Avoid forcing developers to assemble a security engine themselves.

Every capability has a support contract: API/ABI requirements, what it observes, unavailable conditions, cost budget, response eligibility, false-positive cases and bypass tests. A detector unsupported on a device is not a clean check. Community extensions must never load arbitrary remote detector code or bypass signed capability policy.

### Protection profiles and defaults

Supply production and development profiles with documented automatic responses. Profiles are generic and versioned, with consumer-defined variant mappings. Selected production protection must actually enforce supported boundaries without a callback supplied by the app. Developers may override a response within documented bounds, and weakening changes must be visible in release reports.

No silent changes to host authentication, storage formats, network routing or backend business rules. Network adapters must identify which stacks they cover. Build-time findings should fail unsafe supported configurations or explain coverage gaps; broad claims to repair every vulnerability automatically are prohibited.

### Compatibility and community release discipline

Publish a verified matrix rather than promise “all Android.” Establish minimum SDK, Gradle/AGP/Kotlin ranges, JDK, ABIs, 16 KiB support, shrinking and bundle/split behavior from tests. Unsupported combinations fail early with a precise message. The prototype's local toolchain is not the eventual community compatibility floor.

Community readiness also requires clear licensing and ownership, security disclosure, reproducible release provenance, dependency policy, documentation with no unpublished prerequisites, independent consumer fixtures, versioned migration guidance and independent bypass/false-positive evaluation. These are part of the product, not marketing follow-ups.

## Engine engineering requirements

1. Represent missing or failed evidence explicitly. Propagate cancellation rather than converting exceptions into a clean verdict.
2. Use an idempotent, restartable monitoring state machine. Prevent duplicate loops and correctly recreate cancelled execution scopes.
3. Validate complete current signer sets, with explicit rotation and distribution-channel policies.
4. Compare decoded certificate digest bytes or validated canonical hex. Base64 representations are case-sensitive.
5. Corroborate tool indicators. An open TCP port alone must not establish instrumentation; any protocol probe needs strict limits.
6. Reject empty or malformed indicators before matching. An empty substring must never become a universal detection hit.
7. Bound all probe I/O. Treat platform visibility restrictions as unavailable evidence, not proof of absence.
8. Resolve one effective protection profile per variant and verify it in the final artifact. Initialization and monitoring must use the same policy.
9. Distinguish native loading failures from successful native checks. File-existence probes alone do not establish native code integrity.
10. Treat embedded configuration encoding as an extraction obstacle, not secret storage. Public certificate material cannot be a secret root of trust.
11. Test active monitoring, enforcement, concurrent starts and restart behavior with observable assertions.
12. Validate network security configuration against supported Android elements and actual client behavior. Do not claim TLS enforcement from unsupported XML settings.
13. Generate artifacts through supported build APIs with explicit dependencies. Avoid executing task actions during configuration or IDE sync.
14. Verify final artifact coverage, required ABIs, guard retention and integrity metadata; absence of recognizable strings alone is not a security guarantee.

## Required protection layers

| User requirement | Automatically injected/provided artifacts | Verification required before claiming support |
|---|---|---|
| Anti-tampering | Release identity binding, signed integrity manifest, own code/native/config digests, missing-guard detection, generated enforcement gates | Re-sign/repackage, modified DEX/native/config, removed initializer, missing ABI, split delivery, signing rotation and store transformations |
| Anti-hooking | Owned native engine; checked function ownership and selected relocation-aware native integrity checks; supported framework hook signals; multiple guard locations | Actual Java/native hooking, inline and PLT/GOT changes, renamed tooling, unsupported OS behavior, legitimate instrumentation false positives |
| Root detection | Independent Kotlin/native checks for binaries/artifacts, mount context, SELinux/system properties and supported manager indicators | Magisk, Zygisk, KernelSU, APatch, hidden root, stock production devices and OEM variation |
| Frida detection | Process-local module/thread/file-descriptor indicators, native integrity corroboration, gadget/server scenarios; optional bounded protocol probe | Frida attach/spawn/Gadget, renamed binaries, nondefault ports and hidden mappings; report bypass limits |
| Other vulnerability controls | Final manifest/network-policy checks; dangerous exported components/backup/debug flags; dependency/SBOM/provenance checks; optional supported WebView/network guards | Unsafe fixtures must fail, waivers must be scoped/expiring; static finding is not proof of exploitability or full vulnerability coverage |
| RASP | Startup gate, runtime state machine, foreground/continuous monitoring, correlated risk decisions, automatic profile response, self-health, optional telemetry adapter | Late attachment, monitor restart, process death, background components, concurrent triggers, response behavior and resource budgets |
| Modern platform security | Platform-aware protection, optional Play Integrity transport with server verification, verified policy updates, release signing/ABI/R8 validation | Server request binding/replay/expiry tests, non-Play handling, Android/ABI/toolchain compatibility matrix |

Artifact-based tool checks and memory/code integrity must complement one another. A filename list cannot carry the anti-hooking claim on its own. Native code is also hookable; it raises cost and provides another evidence path, not an absolute trust boundary.

## Artifact architecture

Proposed module boundaries (not all implemented):

- `security-gradle-plugin`: public DSL, profile/variant resolution, AGP wiring, artifact coverage report.
- `security-build-engine`: deterministic generation, instrumentation plan, integrity manifest creation and artifact audit.
- `security-runtime-core`: lifecycle, immutable evidence, correlation, freshness and enforcement state machine.
- `security-runtime-android`: automatic initialization, component/lifecycle integration and framework detectors.
- `security-runtime-native`: AppArmorX-owned C/C++ JNI engine, ABI builds and native integrity probes.
- `security-policy`: versioned schema, canonical verification, trust-root rotation, expiry and rollback policy.
- `security-response-android`: built-in blocking/recovery UI and component guard behaviors for selected profile.
- `security-attestation-play`: optional platform attestation adapter. A verified backend contract is required.
- `security-build-checks`: manifest/network/dependency/artifact rules, machine-readable findings and scoped exceptions.
- `security-test-fixtures`: hostile APK mutations, root/hook environments, lifecycle fixtures and clean-device controls.

Consumer artifacts should include the required engine, not require consumers to manage ten dependencies. Keep public API narrow; module decomposition is internal. The owned runtime is still a runtime dependency even when the plugin installs it invisibly.

## Build and injection pipeline

1. Resolve effective profile for each variant and distribution channel. Reject incompatible/missing trust inputs and forbidden release bypasses.
2. Fetch/verify policy metadata in an execution task; or use a pinned verified bundle. Record version/digest. Never run downloaded code.
3. Produce a deterministic build identity and generated configuration, independent from app secrets. Select required ABI artifacts and check coverage.
4. Inject entry guards through supported AGP instrumentation APIs and merge owned runtime/resources/manifest entries. Generate source only where app-specific values require it. Keep consumer source files untouched.
5. Run normal compile/R8/native linking. Retain only actual JNI/entry contracts; verify R8 has not removed the required guards.
6. Produce integrity metadata from the final protected payload at an explicitly tested artifact stage; sign it with a separate integrity signing key. Do not hash an APK and then change that same APK, and do not create a source→DEX→source dependency cycle.
7. Package/align/sign through the supported pipeline. Never patch an already signed final APK in place. AAB/split delivery and store-side transformations need their own verified strategy; do not reuse a whole-APK checksum for every installed split.
8. Audit the final output: injected guards, initialization, required native ABIs, effective profile, signature assumptions, R8 rules, policy identity and manifest settings. Emit human-readable and JSON/SARIF coverage reports.
9. Make release packaging/distribution depend on successful verification, not just an optional report task or a filename-based finalizer.

The artifact API and ordering for post-R8 integrity data are an engineering spike and acceptance gate, not a solved detail in the prototype. An unsupported combination must fail with an actionable message rather than silently removing protection.

## Automatic startup and enforcement

A ContentProvider alone starts after `Application.attachBaseContext` and cannot guarantee protection before arbitrary host providers or all app work. Hardened coverage needs a tested combination of generated/manifest initialization and bytecode-injected guards at supported app component entry points. Multi-process, providers, services, receivers, workers, deep links and applications without custom Application classes are part of the matrix.

Do not blindly insert `return` into arbitrary application methods: it can violate Android lifecycle contracts, corrupt coroutine continuations or suppress required cleanup. Injection is limited to explicitly supported entry points with defined guard behavior. Unknown frameworks or uninstrumented critical components must appear as coverage gaps.

Proposed runtime states:

`UNINITIALIZED → CHECKING → READY | RESTRICTED | INDETERMINATE → STOPPED`

- `READY` requires the mandatory checks for that profile; it is not a universal security guarantee.
- `INDETERMINATE` represents unavailable/expired required evidence and has an explicit configured response.
- `RESTRICTED` activates the supplied response automatically, without host-written detector callbacks.
- Monitoring can be restarted without reviving a cancelled scope and cannot start duplicate loops.
- Expensive scans run off the main thread; startup has a bounded preflight budget. Components must not become usable merely because asynchronous checks have not completed.
- A selected protection profile determines automatic warn/block/terminate behavior. Debug, enterprise-managed and production profiles are explicit. Keep irreversible data deletion out of generic responses.
- App-specific server transactions still require operation binding. Optional annotations/adapters can add fine-grained guards; baseline device/app protection must not depend on them.

A generic library cannot cancel every possible host network stack or undo an already-submitted payment. State exactly which component/action boundaries are guarded. Server authorization remains independent.

## What applying the plugin should require

Proposed DSL semantics, not a currently implemented API:

- Profile: development observation, hardened production, or a controlled assessment profile.
- Per-channel deployed signing identities and legitimate rotation policy.
- Required root/hook/tamper/Frida checks and behavior for unavailable evidence, with safe documented profile defaults.
- Policy trust roots and update channel; a pinned release-policy lock.
- Supported platform-attestation endpoint if that module is enabled.

What the app developer should **not** need: copy detection classes, instantiate scanners, call startup/monitor APIs, add native code, maintain Frida lists, manually merge components, create a blocking screen or handwrite keep rules.

## Automatic updates without a supply-chain backdoor

There are three independently versioned things: engine binaries, detector policy data and application response policy. Only signed bounded detector data is eligible for unattended build-time refresh. Engine changes are pinned dependency upgrades. Feed data cannot grant itself new capabilities, execute scripts or silently strengthen the app owner's response policy.

Production feed design must add threshold/offline trust roots, delegated signing, root rotation/revocation, rollback/freeze protection, signed timestamps, schema/capability compatibility, promotion channels and audited recovery. The prototype's single Ed25519 key plus minimum sequence is useful groundwork, not that complete operational service.

Default experience can check for current vetted policy automatically during a build. CI must retain the selected signed bundle and provenance so the shipped binary is reproducible. Strict release builds fail when freshness cannot be established; explicitly configured grace/offline policy may use a still-trusted bundle. Never silently claim “latest.” Already installed apps do not change just because the next build can fetch a feed.

## Test and release acceptance

- Specify detector and enforcement behavior in independent consumer fixtures. Tests must observe behavior, not just instantiate classes.
- Test each detector as detected / absent / unavailable / unsupported / malformed input, including cancellation and deadlines.
- Test monitor start/start, start/stop/start, concurrent scans, process death, late hook attachment and stale evidence.
- Test the **consumer** with only the plugin/config: no security code in Application or Activity. Assert guards/native/config/response are present in APK/AAB and actually run.
- Mutate APK entries/signers/config/initializer and validate build/runtime outcomes. A passing unit test is not proof of tamper prevention.
- Validate stock and compromised devices, false positives, crash behavior, startup latency, CPU and battery, all shipped ABIs and 16 KiB devices.
- Exercise real release shrinking and split/store delivery. Use the correct Play signing certificate, not the upload certificate.
- Audit release artifacts/dependencies and conduct an independent bypass review. Map supported controls to MASVS and evidence; never advertise blanket compliance.

Implementation should proceed in vertical slices: automatic native/Kotlin injection and verified startup; layered managed and native detectors; automatic enforcement and self-health; genuine integrity/anti-hooking; secure update operations; build vulnerability checks and release hardening. Each slice includes an adversarial consumer test and a protection coverage report before it is called complete.

## Current state, honestly

Implementation is active. Managed/native probes, signed build-time indicator policies, Activity instrumentation and configurable responses exist. See [STATUS.md](STATUS.md) for the current validation and prioritized gaps. This remains an alpha: startup gating, continuous monitoring, complete component coverage, payload integrity and threat reporting are not complete. No external publication is authorized.

## Primary references checked 2026-09-29

- OWASP MASVS resilience: https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/
- OWASP runtime hooking hardening: https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0041/
- OWASP runtime integrity: https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0032/
- OWASP tool detection and bypass limits: https://mas.owasp.org/MASTG-KNOW-0030/
- Android Play Integrity: https://developer.android.com/google/play/integrity/overview
- Android Network Security Configuration: https://developer.android.com/privacy-and-security/security-config
- Gradle Portal namespace/publishing rules: https://plugins.gradle.org/docs/publish-plugin

## Threat feedback and learning

See [THREAT-FEEDBACK.md](THREAT-FEEDBACK.md) for customer-controlled reporting, unknown memory-integrity evidence, poisoning-resistant analysis, reviewed rule/engine changes and signed staged rollout. This is a product requirement; no backend or telemetry transport is implemented yet.
