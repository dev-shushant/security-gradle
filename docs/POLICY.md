# Signed policy protocol v1

The feed is data, not a code-delivery service. No hosted feed or production trust key has been created.

## Envelope

Two ASCII Base64 lines, optionally followed by a newline:

1. Base64 of exact payload bytes.
2. Base64 of the 64-byte Ed25519 signature over those exact bytes.

The trust key is Base64 of an X.509 SubjectPublicKeyInfo Ed25519 public key, configured independently in the consuming build. Private keys must remain outside source control and build consumers.

Payload example (times must be current Unix seconds):

```text
schema=1
sequence=42
issued=1790630000
expires=1790716400
markers=frida-agent,libfrida-gadget,libxposed,liblsposed
```

Required fields only; duplicates and unknown keys are rejected. Sequence must meet the committed nonnegative minimum. Issued must not be in the future. Expiry must be after the build clock and no more than 30 days after issued. Between 1 and 128 unique lowercase literal markers of 4–80 ASCII letters/digits/period/underscore/hyphen; no regex, executable expressions, paths, commands, URLs or host responses. Envelope limit: 64 KiB.

## Operational workflow

1. Review a threat indicator with provenance and reproduce it in a controlled device test. Broad markers create false positives.
2. Create payload with a monotonically increasing sequence and bounded expiry.
3. Sign exact bytes using a protected Ed25519 key; verify with the public key before promotion.
4. Publish only the envelope via your controlled HTTPS service; never its private key.
5. Development builds can refresh live. Release CI accepts a reviewed envelope, updates the committed sequence floor and builds from pinned bytes.
6. Retain plugin/runtime versions, source revision, policy digest and release signer identity with build provenance.

No automatic feed harvesting is implemented. New threats require curation; no tool can reliably translate arbitrary security news into safe production detections. Key compromise requires a reviewed trust-key replacement and app rebuild. Production feed operations need staged rollout, revocation, threshold/offline roots, transparency and incident procedures before broad deployment.

## Failure behavior

Network failure, redirect, invalid signature, malformed payload, rollback below floor or expired policy fails the Gradle task. Outputs from an older successful run do not permit dependent packaging tasks to proceed after failure. Offline requires a valid local envelope if a feed or key is configured. Configuration-cache reuse still executes freshness checks. Verification/download tasks deliberately do not use the build cache.

Connection and read timeouts are 10 seconds. Body reads additionally have a 15-second checked deadline; an in-flight blocking read may extend it by up to the read timeout. Downloads have a 64 KiB cap and reject redirects. The endpoint is trusted build configuration; this is not a general untrusted-URL proxy and does not enforce a public-IP allowlist.

## Limits

The sequence floor is configured, not an automatic persistent high-water mark. Valid older policies above that floor can be replayed until expiry. Freshness depends on the CI clock. A signed malicious marker can create noise but cannot execute code or change the response mode. Runtime policy expiry is reported as UNAVAILABLE; the observation engine still runs other probes. Bundled indicators have no expiry and make no freshness claim.
