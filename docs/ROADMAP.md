# AppArmorX Android execution roadmap

Updated: 2026-10-17. Current documentation baseline: main at ce17368.

The umbrella direction is now **free security infrastructure across Android, iOS, backend and web**.
Read [Platform vision and execution strategy](PLATFORM-STRATEGY.md) for the agreed free-offering charter,
shared architecture, cross-platform sequence and acceptance gates. This file retains the Android workstream.
The original planning baseline below was 883da67; historical gaps must be read with this completion update:

- 0.1.1 is published; isolated public/candidate signed-R8 consumers and dependency final-DEX verification exist.
- Required API 29/33 emulator jobs and the public consumer passed in recorded CI run 39043122340 at e8fa713.
- Play Integrity documentation now distinguishes presence/hash helpers from token requests/server verification.
- Performance, broader physical-device coverage, signed final-payload integrity and independent review remain open.
- The next integrated platform milestone is Android + a backend verification slice, with bounded iOS feasibility in parallel.

The remaining dated schedule and baseline observations are historical planning context, not current pending-task status.
This is a proposed execution plan, not a statement that future capabilities exist.
Timing assumes one primary maintainer and is indicative; evidence gates determine releases.
No code, device tests, independent assessment or remote CI status was freshly verified for this plan.

## Product direction

Make Android protection easy to adopt, observable in the shipped artifact, and safe to operate.
The engine is the product; Gradle is its delivery mechanism.
Lead with supported dependency-call protection, runtime evidence and build reports.
Local protection stays usable without an account, mandatory telemetry or a hosted service.
Success means developers can install it, understand its coverage and deploy it without unexplained user blocks.

## What the current checkout establishes

- Public 0.1.0 distribution is live, verified separately in this session; release does not establish production assurance.
- Separate plugin, policy and runtime modules; bundled runtime AAR; profiles, native probes, component guards, firewall and HTML/SARIF output exist.
- Recorded device and adversarial outcomes exist in VALIDATION.md; they are historical scoped evidence.
- sample/settings.gradle.kts uses includeBuild(".."). CI builds that source consumer; it does not prove an isolated Portal installation.
- Emulator CI is continue-on-error. Inspect actual remote runs before changing the gate.
- One physical device family is documented; startup, CPU and battery budgets are not established.
- Full GOT relocation validation and a signed final-payload inventory remain open.
- PlayIntegrityAdapter.kt exists, despite STATUS.md describing client support as not started. Reconcile source, tests and docs before advertising it.
- Telemetry configuration serializes an HMAC key into generated policy. An app-distributed shared key is extractable and cannot authenticate uncompromised clients.

## Release sequence

| Milestone | Proposed window | Outcome | Release gate |
|---|---|---|---|
| 0.1.1: adoption and truth | First 1–2 weeks | A stranger can install the published plugin and understand the result | Isolated public consumer, accurate docs, actionable errors, repeatable CI |
| 0.2: compatibility and operational safety | Following 3–5 weeks | Known supported environments, measured overhead, safe rollout | Toolchain/device matrix, benchmark evidence, controlled false-positive evaluation |
| 0.3: verified coverage and integrity | Following 4–6 weeks | Report describes what survives packaging and where enforcement applies | Mutation fixtures, signed inventory design, guard-boundary evidence |
| 0.4 beta: sensitive-action integration | After those gates | Optional server-backed decisions for valuable operations | Verified request binding, outage/replay tests, no fabricated non-Play result |
| 1.0: stable Android contract | Evidence-driven | Supported API/configuration and reproducible releases | Pilot acceptance, independent review, regression and compatibility gates |

## 0.1.1 — remove adoption friction first

1. Create a tiny independent consumer fixture using only a pinned Portal version: no includeBuild, Maven Local or project substitution. Exercise clean GRADLE_USER_HOME, assembleRelease, R8, report generation and configuration-cache reuse. Use a dedicated test signer; never production signing secrets.
2. Keep a second fixture for the candidate artifact in an isolated temporary Maven repository before publication. Candidate testing and published-artifact testing are separate checks.
3. Document supported versus untested Gradle/AGP/Kotlin/JDK combinations. Distinguish maintainer build requirements from consumer requirements; test compatibility rather than lowering requirements speculatively.
4. Fix README/quickstart repository setup for Android projects with custom pluginManagement.repositories. Reconcile STATUS, VALIDATION, adapter availability and policy-signing claims.
5. Replace broad claims that the watchdog closes attach-mode attacks with the exact reproduced payload, environment and timing; periodic checks cannot stop every in-flight action. Remove unsupported comparisons with all competing RASP products.
6. Explain telemetry's client-held HMAC trust boundary; prohibit its use as authoritative device-health or authorization evidence. Plan endpoint authentication/rate limits accordingly.
7. Add a troubleshooting path: unsupported AGP, missing native ABI, signing setup, R8 failures, unavailable probes and build reports. A doctor task should print safe diagnostics without policy secrets, headers or signing material.
8. Recruit 3–5 volunteer Android developers through owner-approved outreach. Target: each gets an understandable report in 15 minutes; record actual setup time and blockers. These are targets, not current adoption figures.

Gate: public fixture reproducible in CI, documented supported baseline, no unresolved misleading setup/security claims, release notes and upgrade instructions. Publishing remains owner-authorized.

## 0.2 — compatibility, performance and false positives

- Establish a small declared toolchain matrix around the tested baseline, including one earlier supported AGP line if feasible. Explicitly fail unsupported combinations with useful diagnostics.
- Stabilize emulator infrastructure; make validated lanes required only after repeated green runs. Add physical OEM coverage, beginning with Pixel plus Samsung, then another available OEM. Do not equate emulators with physical-device coverage.
- Exercise Compose and Views, debug/release, R8, background/foreground, process restart, offline operation, services and receivers. Record accessibility, managed-device and clean OEM controls.
- Benchmark the same consumer with/without the plugin: cold startup p50/p95, main-thread stalls, scan duration, allocations/memory, APK size, build time and background CPU/battery. Measure watchdog separately and define budgets from data before claiming low overhead.
- Provide explicit observation-first rollout guidance, explain reasons for restriction and scope any waivers by rule/variant with an expiry. Changing enforcement defaults requires a migration decision and regression tests.
- Report detector availability, stale evidence and engine health independently of threat state.

Gate: published compatibility/benchmark results, failures explainable and reproducible, no unresolved crashes/ANRs or unintended blocks in agreed clean fixtures. Small pilot samples cannot establish a universal false-positive rate.

## 0.3 — coverage and stronger integrity

- Inventory each instrumented API/component and report protected, unsupported and skipped boundaries. Prioritize workers/providers/multiprocess based on pilot usage; do not reimplement already-present Service/Application/Receiver guards.
- Design a signed inventory of selected final DEX/native/config payloads after shrinking, with signing-key ownership and independent trust anchors. Avoid circular whole-APK hashing and never bundle a private signing key.
- Validate APK/AAB/split delivery, signer rotation, missing ABI, removed guard, modified DEX/native payload, altered config and stale inventory. Build-time presence and runtime authenticity must remain distinct results.
- Add structural native integrity only with clean and hostile controls: relocation-aware segment checks and selected PLT/GOT targets. Legitimate loaders/JIT/OEM variation must not become universal detections.
- Expand static manifest/network findings with paired safe/unsafe fixtures and documented suppressions. Avoid silently rewriting business-specific security semantics.

Gate: each claimed boundary has executable positive/negative evidence; unsupported delivery modes are explicitly rejected or reported.

## 0.4 beta — protect valuable actions with optional server participation

- Review and stabilize the existing Play Integrity helper before adding another abstraction. Keep local protection independent of Play services.
- Add an explicit sensitive-operation API only where the application can supply business context. Automatic integration cannot infer which operation is a payment or token exchange.
- Provide a reference verifier with request binding, expected app/signing identity, freshness, replay handling and server-side authorization. Verify non-Play, outage, timeout and account/session mismatch behavior.
- Keep verifier deployment optional; no implicit endpoint, mandatory tracking or authoritative trust based solely on client telemetry.
- Telemetry ingestion needs tenant isolation, schema/size limits, redaction, bounded retention, replay controls and abuse limits before any dashboard. Enrollment/device credentials still do not prove an uncompromised client.

Gate: independent review of the end-to-end protocol; demonstrate allowed/denied/outage cases. Attestation adds evidence and does not make a compromised client trustworthy.

## 1.0 acceptance

- Stable documented DSL/runtime API, support lifecycle, migration guides and deprecation policy.
- Required candidate + published-consumer CI, supported OS/ABI/toolchain lanes, clean/adversarial regression suite and performance budgets.
- Reproducible release inputs, dependency verification/locking, SBOM, provenance, credential-safe publishing and rollback instructions.
- Pilot applications complete a release cycle with owners explicitly accepting measured limitations; define observation period and environments before the pilot.
- Independent security assessment with remediated release blockers and public scope/remaining limits. Assessment is not certification.
- Documented vulnerability reporting, triage ownership, supported-version fixes and response commitments the maintainer can sustain.

## Growth after the engine earns adoption

Prioritize managed policy rollout, fleet compatibility/health reports and optional self-hosted operations only when pilot teams request them. All planned AppArmorX security capabilities remain free, including self-hosted operations. Optional public hosting needs an explicit funding and cost decision; no hosted service or paid feature tier is promised. See the platform strategy for sustainability constraints.
Flutter/React Native/Unity adapters follow demonstrated demand and dedicated validation; Android-shell coverage does not protect all Dart/JavaScript/game logic. iOS is a first-class platform direction with its own architecture and validation gates; begin with bounded feasibility alongside the shared backend foundation.
Avoid a detector-count race, an early dashboard, mandatory cloud dependency, remote executable rules and AI-generated enforcement without review.

## Next ten working days

1–2: isolated published-consumer fixture and docs/claims reconciliation.
3–4: candidate fixture, diagnostics and configuration-cache/R8 checks.
5–6: establish baseline performance measurements and stabilize current CI lanes.
7–8: first external integrations and reproduce their blockers.
9–10: fix prioritized blockers, publish compatibility/evidence summary, assess 0.1.1 readiness.
This is a planning allocation, not a delivery promise. Device exploration must precede new device-test authoring under AGENTS.md.

Track: successful external setups, setup time, unsupported-build failures, unexplained restrictions, crashes/ANRs, p95 startup overhead, scan cost, published-consumer CI health, and pilot retention. Stars/impressions are secondary discovery signals.

## Sources and interpretation

Repository facts: README.md, QUICKSTART.md, docs/STATUS.md, docs/VALIDATION.md, docs/HONEST-LIMITS.md, .github/workflows/ci.yml, sample/settings.gradle.kts, plugin/src/main/kotlin/com/apparmorx/gradle/PrepareSecurityPolicy.kt.
External guidance checked 2026-10-17:
- https://developer.android.com/google/play/integrity/overview — server decisions, request binding and tiered rollout.
- https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/ — resilience as defense in depth.
- https://docs.gradle.org/current/userguide/compatibility.html — validate toolchain support against current contracts.
Release sequencing, windows and adoption targets are recommendations derived from the inspected gaps, not vendor requirements.
