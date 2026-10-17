# Honest limits

Security claims should be falsifiable, so these are stated up front. This is the full list; the
[README](../README.md) carries a short summary.

- **Nothing here is unbypassable.** A determined attacker with kernel or hypervisor control can analyse and
  patch any client-side protection. AppArmorX raises attacker cost and gives you evidence; it does not
  make a compromised device trustworthy.
- **Client-side checks complement server-side authorisation; they never replace it.**
- **The dependency firewall protects the app's own code; it cannot protect against an attacker who
  bypasses that code entirely.** A root+Frida attacker calling Android framework TLS APIs directly
  (not through the app's own call sites) can still complete a MITM attack — confirmed by a real,
  reproduced attack, not assumed. This is a universal limitation of client-side RASP, not specific to
  AppArmorX: no competing product, free or paid, can sandbox further API calls made by an attacker who
  already has code executing in-process. `killOnConfirmedHooking` + `HookWatchdog` close this for an
  attacker who attaches to an already-running process (verified); nothing closes it for spawn-time
  injection (verified it doesn't, on the same attack, same session). State both outcomes together —
  see [STATUS.md](STATUS.md) Slices 16–23 for the full, honest accounting, including a native
  anti-ptrace trick that was tried and found ineffective on modern SELinux-enforcing devices.
- **Paid RASP products have the same spawn-time limit; they do not publish a fix for it either.** The
  one architecturally different answer — moving the trust decision to a hardware-backed, server-verified
  attestation (Google Play Integrity) that lives outside the vulnerable process — is a deliberately
  deferred roadmap item, not implemented, tracked in [STATUS.md](STATUS.md)'s "Next
  implementation order".
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
