# AppArmorX contributor instructions

- Preserve owner identity: Shushant Tiwari, com.apparmorx, com.apparmorx.security.
- Do not publish or upload anything without explicit owner authorization.
- Keep Gradle integration, authenticated policy parsing and Android runtime separate.
- Write abuse/regression tests before changing security behavior.
- Never treat failed/unavailable probes as CLEAR or claim unbypassable protection.
- No downloaded code, implicit endpoints, private keys, app secrets or broad telemetry.
- Automatic process termination is prohibited by default. The sole exception: an explicit, opt-in
  `killOnConfirmedHooking` policy flag (default `false` in every profile including `HARDENED`; forced
  `false` on debuggable builds at both build time and runtime; never a side effect of any other
  setting). It may hard-kill the process ONLY when hooking/injection-specific evidence is `DETECTED`
  (never on `UNAVAILABLE`/`INDETERMINATE`, never for root/signer/other RESTRICTED causes). Document its
  real limit everywhere it is described: evidence is checked periodically/on lifecycle events, not
  continuously, so it cannot prevent the single action already in flight when detection fires -- only
  further activity in the same process. See docs/STATUS.md for the full reasoning and on-device test.
- Keep configuration-cache support; never run tasks manually during configuration or IDE sync.
- Validate with policy/plugin/runtime tests, validatePlugins, Android lint and separate sample builds.
- State device-test and penetration-test limits honestly. Review docs before changing trust or response policy.

- Keep source, documentation, examples and metadata exclusively branded for AppArmorX. Do not identify reference applications, their organizations or their internal implementation details.
