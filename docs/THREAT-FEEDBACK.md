# Threat feedback and controlled improvement

Status: accepted product direction; backend and transport are not implemented.

## Vision

AppArmorX learns from detection outcomes and unknown anomalies across consenting deployments. Customers choose an AppArmorX-operated endpoint, their own endpoint, an adapter to their security platform, or no reporting. Baseline local protection works without telemetry. No endpoint is implicit and no customer data is shared between tenants.

## Event contract

A versioned event carries a random event ID, engine/policy/build identifiers, coarse OS/ABI information, stable detector IDs, confidence and availability states, expected-versus-observed integrity result, selected response and bounded timing data. Memory anomalies describe the protected module/segment category and mismatch/ownership evidence. Do not send raw process memory, stack contents, full memory maps, arbitrary file paths, authentication material, screenshots, advertising IDs or persistent device identifiers by default.

Evidence hashes can still identify sensitive artifacts; apply classification and customer controls. Additional forensic collection requires a separately designed explicit customer policy and data handling agreement, not a remote command that silently expands collection.

## Pipeline

1. The runtime emits bounded typed evidence, including unknown/unsupported states and false-positive feedback.
2. An optional transport redacts, batches, rate-limits and delivers to the customer-selected HTTPS destination. Offline queues need encrypted bounded storage, TTL, backoff, circuit breaking and clear deletion rules. Failure never blocks the UI or disables local checks.
3. Ingestion authenticates the application/tenant, validates schemas, deduplicates and rate-limits. Mobile credentials are extractable; do not treat possession of an embedded API key as trusted evidence. Customer enrollment and token issuance need a backend contract.
4. Analysis groups related anomalies and proposes hypotheses. Treat compromised-device reports as hostile input: defend against poisoning, fabricated prevalence, replay and cross-tenant contamination.
5. Reproduce in an isolated authorized test fixture. Label false positives, unsupported environments and confirmed threats. Preserve review provenance.
6. A proposal becomes a detection rule or an engine change, with adversarial and clean-device tests, performance budgets and compatibility declarations.
7. Approved releases are signed and promoted through internal/canary/stable channels. Monitor false positives and crash/latency regressions; rollback changes through a signed, versioned recovery procedure.

## Rules versus hooks

A signed rule can select only capabilities already shipped in the engine, with bounded declarative matching and parameters. It cannot execute code, introduce native instructions, call arbitrary methods, read arbitrary memory, change reporting destinations or increase collection privileges.

A new executable hook or memory analysis technique is an engine release: code review, native/managed tests, signing and app-store-compatible distribution through a new app build. Build-time policy refresh cannot change apps already installed. Runtime data-only rule refresh is a separate future capability requiring on-device signature verification, persistence, rollback/freeze protection and store-policy review.

## Learning boundary

Automate clustering, triage prioritization, candidate rules, test generation and rollout measurement. Do not autonomously turn untrusted reports into globally enforced protections. Begin with reviewer approval and curated releases. Track precision/recall on labeled fixtures, false-positive rate, unsupported-device rate, event drop rate, latency/CPU cost and time to mitigation. Publish what the evidence supports; do not call unreviewed heuristics prevention.

## Customer controls

Reporting off by default; explicit endpoint and tenant configuration; consent/retention/regional controls; tenant isolation; customer-owned keys where supported; export and deletion; auditable policy history; staged rollout and emergency disable of a faulty rule. The response policy and reporting policy remain owned by the customer and cannot be broadened by detector feed content.

## Implementation acceptance

Test malformed/oversized/replayed/poisoned events, tenant separation, queue limits, no secrets in fixtures, retry storms, unavailable servers, revoked keys, rollback/freeze attacks, rejected rule capabilities and canary rollback. Backend, transport and rule refresh must not be called complete until these tests and privacy review are recorded.
