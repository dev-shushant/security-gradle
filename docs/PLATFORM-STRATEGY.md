# AppArmorX platform vision and execution strategy

Decision date: 17 October 2026. Owner: Shushant Tiwari.
Status: agreed product direction; architecture and future deliverables below are proposals, not shipped capabilities.
Current implementation baseline: Android 0.1.1; repository main inspected at `ce17368`.

> Free, open security infrastructure. Starting with Android.

## 1. Mission and scope

AppArmorX will make inspectable security capabilities accessible across Android, iOS, backend and web under one umbrella. Developers should be able to integrate protection, understand its boundaries, operate their own infrastructure and make informed decisions without buying access to essential security features.

The Android engine delivered through `com.apparmorx.security` is the first component. The platform vision is broader than a Gradle plugin or a collection of runtime detectors. It connects build evidence, platform-specific runtime evidence and server-side decisions for valuable application operations.

Long-term scope includes client protection, backend verification, API/session protection, policy lifecycle, security events and self-hosted operations. This does not yet mean a general-purpose cloud security suite, SIEM replacement, WAF, network appliance or infrastructure-as-code scanner. Each expansion needs a concrete threat model, maintainer capacity and acceptance evidence.

Success means safer applications with understandable coverage and sustainable operation. Detector count, dashboards, impressions and comparison slogans do not establish security effectiveness.

## 2. Free offering charter

The owner direction is to offer all AppArmorX security capabilities free. Product planning must not depend on a paid feature tier.

- No paid unlock for stronger checks, platforms, policies, reports or the self-hosted control plane.
- No AppArmorX per-app, per-device or event-volume licence fee for self-hosted software.
- Publish inspectable source and reproducible integration examples. The current Android repository is Apache-2.0; new components need an explicit compatible licence and dependency review before release.
- Preserve local protection without an AppArmorX account or mandatory telemetry.
- Keep deployment, event storage, policy keys and retention under the operator's control.
- No advertising SDK, data resale, hidden tracking or mandatory AppArmorX endpoint.
- Publish security updates and migration instructions without a subscription gate.

Free software does not eliminate infrastructure costs. Self-hosting consumes the operator's compute, storage and network. Platform attestation services, distribution accounts and third-party dependencies have their own terms and availability. AppArmorX must disclose these dependencies and keep optional services optional where the security design permits.

A free public hosted service is **not currently promised**. Before offering one, document funding, quotas, abuse prevention, isolation, retention and shutdown/export procedures. Potential sustainability routes are voluntary donations, grants, sponsorship and community contribution; none is established funding or a reason to sell protection features. Do not promise an enterprise SLA without staffing and funding.

## 3. What exists today

Use [0.1.1 release notes](RELEASE-NOTES-v0.1.1.md), [qualification](RELEASE-QUALIFICATION-0.1.1.md) and [honest limits](HONEST-LIMITS.md) for detailed evidence. These are recorded results, not fresh execution in this strategy-writing task.

| Area | Established baseline | Boundary |
|---|---|---|
| Android delivery | Public 0.1.1 Gradle plugin; separate plugin, policy and runtime modules | Pre-1.0; not general commercial parity |
| Instrumentation | Project lifecycle guards; supported external dependency JAR/AAR firewall calls | Not a universal sandbox; unsupported, reflected and dynamically injected calls remain outside coverage |
| Runtime evidence | JVM/native checks, explicit unavailable states, configurable responses | Signals can be evaded; failed checks must never imply safety |
| Build visibility | Coverage/reporting, manifest findings, HTML/JSON/SARIF | Build-time presence is not runtime authenticity |
| Distribution verification | Isolated public consumer, signed R8 APK, final-DEX dependency regression, cache reuse | Does not establish all delivery modes/toolchains |
| Recorded validation | 171 unit tests; native regression; lint/plugin checks; required API 29/33 emulator CI | Tests are scoped evidence, not independent penetration assessment or broad OEM assurance |
| Trust helpers | Android key-attestation building blocks and Play Integrity presence/hash helpers | No complete token-request/server-verification flow |
| Other platforms | Product direction only | No shipped iOS SDK, web SDK or backend verifier |

Recorded green CI: [run 39043122340](https://github.com/dev-shushant/security-gradle/actions/runs/39043122340), at `e8fa713`; later documentation commits do not extend that runtime evidence.

Open gaps include measured performance/false positives, broader physical-device evidence, final signed-payload inventory, split-delivery validation, independent review and real external adoption evidence.

## 4. Position and differentiation

AppArmorX currently stands as an early Android security engine with working public distribution and scoped regression evidence. It is not yet a mature replacement for comprehensive commercial application shielding or fleet operations.

The intended competitive strengths are free access, inspectable implementation, automated integration, explicit build coverage, operator-controlled data and reproducible evidence. These are product commitments and hypotheses to validate with users, not proof that AppArmorX defeats more attacks than another vendor.

Competitive evaluation should compare the same attack, application, OS, configuration and response outcome. Record detection, prevention, latency and usability separately. Respect SDK licences and evaluation terms; do not redistribute competitor binaries without permission. No head-to-head benchmark is established by this document.

## 5. Platform architecture

```text
Android build integration + runtime     iOS integration + runtime
                  \                    /
                   Versioned evidence contracts
                              |
Web integration --------> Backend verifier / action authorization
                              |
                 Operator policy and event services
                              |
                  Self-hosted operational console
```

This is a conceptual architecture, not an existing deployment or a requirement to send every client event to a server. Local protection continues independently where supported. The business backend remains responsible for authorization.

### Shared foundations

Define schemas and conformance fixtures before building a large shared framework:

- Evidence envelope: schema version, platform/engine version, check identifier, outcome, collection time, freshness and availability reason. Separate untrusted client assertions from independently verified platform evidence.
- Policy envelope: version, intended application/environment, validity, signing-key identifier, explicit allowed settings and rollback rules.
- Verification result: verified issuer/source, binding context, freshness, policy result and stable reason codes. Verification failure is distinct from a confirmed threat.
- Event envelope: minimal identifiers, event version and bounded payload; no tokens, raw personal data or business secrets by default.
- Capability manifest: supported and skipped boundaries, toolchain and engine version, report provenance and delivery assumptions.

Do not assume cross-device wall clocks are authoritative. Specify clock-skew handling and server-owned expiry. Canonical encoding, signature algorithms, key rotation, compatibility and malformed-input behavior require protocol decisions and tests.

### Android

Keep Gradle integration, authenticated policy parsing and Android runtime separate. Preserve configuration-cache support and existing identities. Expand protection through explicit API/component inventories and paired fixtures rather than universal claims. Validate APK, AAB and split delivery before declaring support. Instrumentation of an Android shell does not automatically cover Flutter, JavaScript, Unity or all native logic.

### iOS

Start with a native Swift package and a small sample. Investigate signing/receipt assumptions, runtime instrumentation indicators and platform-supported attestation separately. Review App Store restrictions, extensions, simulator versus physical-device behavior and distribution channels before committing to integration mechanisms.

An iOS implementation must respect its sandbox and available APIs. Android root/hook logic and Gradle bytecode instrumentation are not portable protection mechanisms. App Attest/DeviceCheck integration, if adopted, needs official-contract review and a real server verifier. They are proposals, not current integrations.

### Backend

Start with verification and sensitive-action authorization, not a dashboard. Supply a deployable reference service, clear API and application integration example. The host application must supply authenticated identity and business context; the security service cannot infer which transfer, token exchange or account change should be permitted.

Separate external evidence verification from local policy evaluation and business authorization. Later services can add policy distribution and bounded event ingestion. Hosting language and storage choices remain open until an architecture decision compares operator burden and security requirements.

### Web

Start from session and API threats: replay, cross-session token misuse, unsafe integration and misuse of valuable operations. Provide server-enforced controls and clearly scoped browser helpers. Decide whether an adapter actually improves on established framework protections before adding it.

Browser JavaScript runs in an attacker-controlled environment. A client-generated health flag, device fingerprint or hidden script is not reliable proof of integrity. AppArmorX cannot embed a secret in JavaScript and treat it as confidential. A general bot-management service, WAF or browser anti-tamper guarantee is outside the initial scope.

## 6. First end-to-end security slice

Target: an Android application requests authorization for one sensitive operation from its own backend.

1. The authenticated application requests an expiring, server-generated challenge for a named operation.
2. The server binds the challenge to the session, intended action, relevant canonical request fields and application identity; it limits outstanding requests.
3. The client obtains supported platform evidence bound to that challenge/context. Local AppArmorX findings may be included as advisory context, explicitly labelled as client-controlled.
4. The backend verifies the evidence through the platform's supported verification mechanism, validates expected identity, binding and freshness, then applies replay protection.
5. The business backend evaluates account permissions and operation-specific policy. A valid attestation does not independently authorize a transaction.
6. The server consumes the challenge atomically with the decision/execution design. Retries use explicit idempotency semantics rather than reusable approval tokens.
7. The app receives a narrow, short-lived result with a stable reason code; events redact sensitive context.

Specify behavior for non-Play distribution, unsupported devices, unavailable attestation, offline use, timeout, stale evidence and verifier outage. Never fabricate a successful attestation or silently downgrade an operation that requires verified evidence. Outage behavior is an explicit business decision with documented risk, not a universal fail-open/fail-closed default.

The acceptance demonstration must include valid, altered, expired, replayed, cross-session and wrong-app requests plus concurrency and outage cases. No production secrets or implicit hosted endpoint may be required.

## 7. Trust and response rules

- Treat the client as potentially compromised. TLS and client-held HMAC credentials do not prove a clean client.
- Keep local signal state, evidence availability, engine health and server verification separate.
- Device/root/emulator/accessibility signals need contextual policy; do not introduce blanket user bans.
- Runtime checks run periodically or at lifecycle boundaries; detection may occur after an action has already executed.
- Preserve the existing narrow `killOnConfirmedHooking` contract: explicit opt-in, false by default in every profile, forced off for debug, confirmed hooking/injection evidence only. It cannot prevent an in-flight action; it can only stop later activity in that process. Unknown evidence and unrelated restrictions cannot trigger it.
- Signed policy is configuration, never downloaded executable security logic. Define signer ownership, recovery and revocation before remote distribution.
- Keep signing private keys and backend credentials out of applications, generated policy, logs and examples.
- Before accepting tenant events, specify authentication, authorization, isolation, quotas, payload limits, redaction, retention and deletion.
- Any management console is itself a privileged attack surface requiring access control and auditability.

## 8. Execution milestones and acceptance gates

Sequence is evidence-driven. Versions and durations below are planning labels, not release promises. Parallel exploration must not overload Android maintenance.

| Milestone | Deliverable | Gate to move forward |
|---|---|---|
| M1: dependable Android baseline | Proposed Android 0.2; compatibility, coverage and overhead evidence | Reproducible candidate/public installation; clean/adversarial controls; declared support matrix; no unresolved release-blocking regressions |
| M2: shared contracts | Versioned schemas, threat model and protocol decisions | Malformed/version/replay fixtures; key lifecycle reviewed; privacy fields justified |
| M3: Android + backend preview | One sample operation and self-hosted reference verifier | Request binding, replay/concurrency, wrong-identity and outage cases pass; client telemetry cannot authorize |
| M4: iOS feasibility then preview | Swift package/sample and explicitly scoped server evidence path | Physical-device evidence, distribution review and documented supported/unsupported cases |
| M5: web/backend integration preview | One framework-neutral session/API example, then a justified adapter | Server-enforced authorization and replay tests; no browser-held trust secret |
| M6: self-hosted operations | Policy lifecycle, minimal events, operational UI | Tenant isolation, auth, recovery, retention/export and upgrade tests |
| Stable releases per component | Supported contracts and sustainable maintenance | Independent review, pilot release evidence, security response process and reproducible releases |

Backend preview does not require Android to reach 1.0 first, but must not bypass M2 protocol gates. iOS feasibility can run alongside M1/M2 in a bounded investigation. Android, backend, iOS and web should have independent maturity/version labels; an Android release cannot imply platform-wide stability.

### Immediate next implementation cycle

1. Create the Android baseline evidence table: exact versions, OS/ABI/device, clean/adversarial scenario, commit and retained artifact.
2. Measure paired builds with/without protection: cold-start p50/p95, scan cost, main-thread impact, memory, build time, package size and background cost. Define budgets after establishing the baseline; do not invent low-overhead numbers.
3. Reproduce clean-device restrictions and unavailable/stale states; record root cause and migration implications before changing enforcement.
4. Draft shared evidence/challenge schemas and a focused threat model. Resolve canonical request binding, challenge storage, atomic consumption and key ownership in architecture decisions.
5. Build one backend vertical slice only after its protocol review and negative fixtures are defined.
6. Time-box iOS feasibility: available APIs, integration/distribution constraints, physical test access and smallest demonstrable scope. Produce a go/no-go and open questions before an SDK commitment.

Signed final-payload integrity is a separate Android design track: selected final DEX/native/config inputs, signing ownership, independent trust anchors, split delivery and mutation fixtures. Avoid circular whole-APK hashing. Do not block all backend protocol research on this track or claim it already exists.

## 9. Validation and readiness

Every claimed protection needs paired clean and hostile controls, environment metadata and a reproducible result. Separate detection from action prevention, build evidence from device behavior and simulator evidence from physical hardware.

- Android: keep policy/plugin/runtime/native regression gates, plugin validation, lint, signed R8 consumer, configuration-cache reuse and required emulator lanes. Explore device behavior before authoring mobile tests under contributor instructions.
- Physical devices: grow beyond the recorded Pixel family; select available OEM/OS coverage explicitly. No broad false-positive claim from a small sample.
- iOS: physical devices and supported distribution contexts; simulator results alone cannot qualify runtime protection.
- Backend/web: malformed requests, authorization boundaries, replay/races, expiry, key rotation, overload, outage and data isolation.
- Releases: compatibility policy, dependency review, SBOM/provenance plan, upgrade/rollback instructions and credential-safe publishing.
- External evaluation: target 3–5 consenting pilot integrations, measure actual setup friction and a release cycle. This is a recruitment target, not current adoption.
- Independent review: prioritize protocol/trust boundaries and high-impact enforcement before broad stability claims. A review is not certification or proof of unbypassability.

Track setup completion/time, unsupported builds, unexplained restrictions, crashes/ANRs, measured overhead, regression coverage, verifier replay rejection and pilot retention. Report denominator and environment with each result.

## 10. Repository and governance plan

Keep this repository focused on the Android implementation for now. Do not move code or create empty platform repositories as a branding exercise. When a component has an executable prototype and ownership, choose its repository boundaries in an architecture decision.

Future components should have separate maintainers/owners, support matrices, threat models, licences, releases and security advisories. Shared schemas require compatibility fixtures across implementations. A shared contract does not require one runtime language or a shared mobile binary.

Maintain a vulnerability reporting path, supported-version policy, issue triage and release checklist before claiming stable support. State realistic response expectations for a small team. Funding and contributor growth should improve sustainability without gating security capabilities.

## 11. Communication rules

Website umbrella: **AppArmorX — free, open security infrastructure. Starting with Android.**

Current offering: **Android runtime protection delivered through a Gradle plugin.**

Use clear labels: available, preview, research or planned. Android 0.1.1 is available/pre-1.0; iOS, backend and web are planned. Do not present the architecture diagram as a functioning suite or use competitor pricing/licensing statements without current primary-source review.

Avoid promises of unbypassable protection, universal SDK interception, enterprise readiness, zero false positives, comprehensive attestation or parity with paid suites. Explain supported boundaries alongside integration instructions. Public marketing changes and publication require a separate owner instruction.

## 12. Open decisions before implementation

- Which sample sensitive operation and backend stack provide the smallest useful reference?
- Which Android distribution channels must the first verifier support, and how should unsupported evidence affect that operation?
- What schema encoding, compatibility policy and policy-signing recovery model will be adopted?
- Which physical Android/iOS devices and pilot applications are available?
- What measured overhead budgets can the baseline support?
- Who can maintain each component and independently review the protocol?
- Is public hosting ever needed, and what confirmed funding could sustain it without feature gating?

These are implementation decisions to resolve next, not reasons to defer documenting the vision.

## Related documents

- [Execution roadmap](ROADMAP.md)
- [Android architecture](ARCHITECTURE.md)
- [Android release offering](RELEASE-NOTES-v0.1.1.md)
- [Qualification evidence](RELEASE-QUALIFICATION-0.1.1.md)
- [Honest limits](HONEST-LIMITS.md)
- [Historical validation](VALIDATION.md)

No production code or release behavior changes are introduced by this document.
