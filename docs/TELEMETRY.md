# Sending security reports to your own server

AppArmorX can post a report to **your** HTTPS endpoint when it confirms a threat. It is **off by default**: no
network request is ever made unless you set a URL. Nothing is sent to AppArmorX or any third party.

```kotlin
security {
    telemetryUrl.set("https://secops.example.com/v1/appsec-events")   // HTTPS only; the build fails otherwise
    telemetryHmacKey.set(providers.environmentVariable("APPSEC_HMAC_KEY").get())
    telemetryDetail.set("STANDARD")                                   // MINIMAL | STANDARD | EXTENDED
    telemetryHeaders.put("X-Tenant", "acme")                          // optional extra headers
}
```

Keep secrets out of source: read them from the environment or Gradle properties as above.

## What is in a report (schema version 2)

Content type `application/json`. A report is sent only for **confirmed threats** (device, tamper or
instrumentation evidence), at most one per 30 seconds. Advisory configuration findings never create a report.

| Field | MINIMAL | STANDARD | EXTENDED | Meaning |
|---|:-:|:-:|:-:|---|
| `schemaVersion`, `eventType`, `eventId`, `timestampSeconds` | ✓ | ✓ | ✓ | Version, `"incident"`, random UUID (dedupe key), event time |
| `applicationId`, `policySequence` | ✓ | ✓ | ✓ | Your package; the policy revision that produced the verdict |
| `detectedChecks` | ✓ | ✓ | ✓ | Check ids that confirmed a threat, e.g. `native-hook-library` |
| `osVersion`, `abi` | ✓ | ✓ | ✓ | Android API level, primary ABI |
| `protectionState` | | ✓ | ✓ | `RESTRICTED`, `INDETERMINATE`, ... |
| `enforcementAction` | | ✓ | ✓ | What the app did: `OBSERVE`, `BLOCK_SCREEN`, `MIRAGE`, ... |
| `unavailableChecks` | | ✓ | ✓ | Checks that could not run (unknown, **not** safe) |
| `advisoryFindings` | | ✓ | ✓ | Configuration findings, e.g. `network-cleartext-permitted` |
| `appVersionName`, `appVersionCode`, `debuggableBuild` | | ✓ | ✓ | Which build reported it |
| `manufacturer`, `model`, `securityPatch`, `installer` | | | ✓ | Coarse device facts; installer is e.g. `com.android.vending` |
| `checks` | | | ✓ | Every check's result (`CLEAR` / `DETECTED` / `UNAVAILABLE`) |

**Never included at any level:** user data, account or advertising identifiers, ANDROID_ID, IMEI, serial,
location, memory contents, stack traces. The `eventId` is random per report and is not a device identifier.

Example (`STANDARD`):

```json
{"schemaVersion":2,"eventType":"incident","eventId":"7d0c…","timestampSeconds":1791970000,
 "applicationId":"com.example.shop","policySequence":0,"detectedChecks":["native-hook-library"],
 "osVersion":35,"abi":"arm64-v8a","protectionState":"RESTRICTED","enforcementAction":"BLOCK_SCREEN",
 "unavailableChecks":["native-selinux"],"advisoryFindings":[],"appVersionName":"4.2.1",
 "appVersionCode":421,"debuggableBuild":false}
```

## Verifying a report on your server

Each request carries `X-AppArmorX-Timestamp` (unix seconds) and, when a key is set,
`X-AppArmorX-Signature` = lowercase hex `HMAC-SHA256(key, "<timestamp>.<raw body>")`. Verify against the
**raw bytes** of the body, compare in constant time, and reject stale timestamps.

```python
import hmac, hashlib, time

def verify(key: str, timestamp: str, raw_body: bytes, signature: str, max_age=300) -> bool:
    if abs(time.time() - int(timestamp)) > max_age:
        return False
    expected = hmac.new(key.encode(), timestamp.encode() + b"." + raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
```

```js
const crypto = require("crypto");
function verify(key, timestamp, rawBody, signature, maxAge = 300) {
  if (Math.abs(Date.now() / 1000 - Number(timestamp)) > maxAge) return false;
  const expected = crypto.createHmac("sha256", key).update(`${timestamp}.`).update(rawBody).digest("hex");
  return expected.length === signature.length && crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
}
```

Also: dedupe on `eventId`, respond `2xx` quickly (any other status makes the app retry), and rate-limit per tenant.

## Delivery behaviour

- HTTPS only, 5 s timeouts, **redirects are never followed** (your headers and signature only reach the configured host).
- Offline or failing endpoint: reports wait in a bounded on-device queue (50 events, oldest evicted, kept out of
  backups), retried with exponential backoff (5 s up to 5 min) and a circuit breaker after 5 consecutive failures.
  Queued reports are also delivered on a later scan even if no new threat occurs.
- Telemetry can never crash the host app: all failures are contained.

## Honest security notes

- The HMAC key and any header value are embedded in the APK and can be extracted by someone who unpacks it. They
  identify **your app's reports**, they do not prove a particular device is genuine. Treat reports as evidence,
  rate-limit and sanity-check server side, and use hardware key attestation or Play Integrity (see README) when you
  need to bind a request to a genuine device.
- A compromised device can suppress or forge reports. Absence of reports is not proof of safety.
- Rotate the key by shipping a new build; old builds keep using the key they were built with.


Client-held HMAC credentials must never be accepted as proof of an uncompromised app or used to
authorize valuable operations. Treat incident reports as untrusted input even when the signature verifies.
