# Honest limits

Security claims should be falsifiable, so these are stated up front. This is the full list; the
[README](../README.md) carries a short summary.

- **Nothing here is unbypassable.** A determined attacker with kernel or hypervisor control can analyse and
  patch any client-side protection. AppArmorX raises attacker cost and gives you evidence; it does not
  make a compromised device trustworthy.
- **Client-side checks complement server-side authorisation; they never replace it.**
- **The dependency firewall covers supported rewritten call sites, not arbitrary code executing in the process.**
  A reproduced Frida payload called framework TLS APIs directly and completed a MITM request. The opt-in
  watchdog stopped the recorded attach-mode payload in its tested timing/environment, but cannot promise
  prevention of every attach attack or the action already in flight. Spawn-time injection also succeeded.
  See [VALIDATION.md](VALIDATION.md) for both results; no independent comparison with commercial products was performed.
- **Server-side decisions remain necessary for valuable operations.** PlayIntegrityAdapter currently
  provides library-presence and hashing helpers only, not token requests or a verified client/server flow.
  Attestation integration is future work and would complement server authorization, not replace it.
- **Tested on one physical device family so far.** The supported toolchain/OS/ABI matrix is still being
  built. Magisk/Zygisk cloaking evolves and is an ongoing test area. No independent penetration test has
  been performed.
- **Full GOT relocation validation** is not complete; `native-relocation-integrity` covers W^X headers and
  pointer-bounds only.
- **Payload integrity** (the packaged-APK anti-tamper claim) is presence-checked plus optional digest pins;
  a signed integrity manifest over the full payload is the next planned step.
- **Unavailable is not clean.** On OEM-restricted devices some probes report `UNAVAILABLE`/`INDETERMINATE`;
  these only trigger enforcement if you set `enforceIndeterminate`.
- The `sample` release build uses a placeholder signer purely to exercise the packaging gate.
- Application module only: applying the plugin to a library module fails the build by design.
- Flutter / React Native / Unity hosts are untested; protecting the Android shell does not protect Dart or
  JS business logic.
