# Hooking response (opt-in, verified on-device)

By default, no profile kills the process; `TERMINATE` is `finishAffinity()`, never a hard kill. Two
narrow, explicit exceptions exist for hosts who want them, both off by default in every profile
including `HARDENED`, both disabled on debuggable builds, and both tested against a real Frida attack
on a rooted device rather than assumed to work:

- **`killOnConfirmedHooking`**: when the device shows confirmed (never merely unavailable)
  hooking/injection evidence — a Frida/Xposed artifact, a native hook trampoline — `Process.killProcess`
  is called. Paired with `HookWatchdog`, a dedicated ~750ms poll loop independent of any Activity's
  lifecycle, this **measurably prevented** a live MITM attack from being installed when Frida attached
  to an already-running process: the script never got past its first line before the process was gone
  (full repro: [VALIDATION.md](VALIDATION.md), Slice 19). It cannot, and does not claim to,
  stop **spawn-time** injection (`frida -f`) — the attacker's code runs before this library's first
  instruction in that case, which no in-process response can outrace. Both outcomes are documented
  side by side; see [Honest limits](HONEST-LIMITS.md).
- **`antiPtraceHardening`**: occupies this process's single ptrace "tracer" slot at startup so a later
  attach (the same mechanism) fails. Implemented, on-device tested, and **found to make no practical
  difference** on a representative modern, SELinux-enforcing rooted device: AOSP's own policy denies
  `untrusted_app` processes `ptrace` on themselves, independent of root, so the one domain that could
  use this trick is blocked from using it by the OS itself. Kept as a safe no-op-on-failure opt-in for
  older/custom builds without that specific hardening; not something to market as closing any gap.

```kotlin
security {
    killOnConfirmedHooking.set(true)   // off by default everywhere; see the scope above before enabling
    antiPtraceHardening.set(true)      // off by default everywhere; tested ineffective on modern devices
}
```
