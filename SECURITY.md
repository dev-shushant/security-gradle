# Security Policy — AppArmorX

AppArmorX is maintained and authored by **Shushant Tiwari** (`com.apparmorx`, `com.apparmorx.security`).

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x | :white_check_mark: Active |
| < 0.1.0 | :x: Unsupported |

## Security Principles

1. **No unbypassable claims**: AppArmorX never claims unbypassable protection. On a compromised operating system, an attacker with kernel or hypervisor access can analyze and patch client-side code. AppArmorX raises the cost of attack and gives you evidence; it does not make a compromised device trustworthy.
2. **Never Treat Failed/Unavailable Probes as CLEAR**: Any check that cannot execute or inspects an unreadable target reports `UNAVAILABLE` or `INDETERMINATE`, never false clean.
3. **No host source changes**: Protection is added through build-time bytecode instrumentation, not edits to your source tree.
4. **Privacy-preserving telemetry**: Telemetry is off unless you set a URL. Reports are designed not to include personal data, user identifiers, memory dumps or persistent device IDs.
5. **Fail-Closed on Startup**: When configured, execution is blocked while initial security posture verification is in progress.

## Reporting a Vulnerability

If you discover a security vulnerability or bypass vector in AppArmorX:

1. **Do NOT open a public GitHub issue.**
2. Send an advisory report directly to the author and maintainer:
   - **Author**: Shushant Tiwari
   - **Repository Owner**: `com.apparmorx`
3. Please include:
   - Detailed description of the bypass or vulnerability.
   - Proof of Concept (PoC) code or script (e.g. Frida script, Magisk module, or APK patch).
   - Target Android OS version and device architecture (e.g. Android 17 / ARM64).
   - Expected behavior vs observed behavior.

We acknowledge receipt within 48 hours and work with the reporter on responsible remediation before public disclosure.
