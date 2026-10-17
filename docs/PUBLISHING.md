# Publishing plan: Gradle Plugin Portal only

Owner: Shushant Tiwari · Plugin ID: `com.apparmorx.security` · Artifact: `com.apparmorx:apparmorx-security-plugin`

**Status (17 October 2026): version `0.1.0` is live on the Gradle Plugin Portal.**
Approval followed submission on 16 October 2026 after two automated checks were resolved: domain ownership
of `apparmorx.com` (DNS TXT proof) and a public source repository. Public resolution was verified from a clean
consumer build that lists only `gradlePluginPortal()`; the published jar contains the embedded runtime AAR
and policy verifier. This does not cover a full Android application build against the published artifact
or any device test. `publishToMavenLocal` remains the path for evaluating unreleased local changes.
Versions are immutable: ship fixes as a new version.

Pre-submission checks passed: `check validatePlugins lintRelease` and `publishPlugins --validate-only`.
The upload task reported submission for approval. Gradle requested a Configuration Cache compatibility
declaration as a recommendation; it did not reject the upload. Domain DNS TXT proof must use the exact
challenge supplied by Portal administrators. The gate table below records the earlier release checklist;
source accessibility, remote CI and broader device coverage still need verification.

## Distribution model (one artifact, one place)

The Plugin Portal serves plugins, not libraries, so everything a consumer needs travels inside the plugin jar:

- the signed-policy verifier is compiled into the plugin (no separate `policy` artifact);
- the matching runtime AAR (classes, both native engines, consumer ProGuard rules) is embedded and unpacked at
  build time into `build/apparmorx/`. Nothing is downloaded and no Maven Central account is needed;
- the plugin's only external dependencies are `asm` and `asm-commons` (Maven Central) and
  `kotlin-stdlib` added to the consumer app.

This was verified from a clean project that had **only** the plugin in its repository list (no AppArmorX
runtime anywhere) building a Java-only app at `compileSdk 34`: coverage verified, signer pin derived, app
launched on a Pixel 7 Pro.

## Go / no-go gate (all must be true)

| # | Gate | Who | State |
|---|---|---|---|
| 1 | License chosen and added (`LICENSE`, POM license block). "All rights reserved" contradicts a free plugin | Owner | **done**: Apache-2.0 in `LICENSE` and the POM |
| 2 | Public source repository; real URL passed as `-Papparmorx.vcsUrl=` | Owner | **done**: repository is public |
| 3 | Plugin Portal account; API key/secret as environment secrets (`GRADLE_PUBLISH_KEY`/`SECRET`) | Owner | **done**: account in use; keys are never committed |
| 4 | Plugin-ID namespace `com.apparmorx` accepted by the Portal (domain/organisation verification) | Owner | **done**: `apparmorx.com` ownership proven by Portal DNS TXT challenge; namespace accepted |
| 5 | CI green on GitHub (build job blocking; emulator matrix reviewed) | Both | **open**: `check validatePlugins lintRelease` passes locally; remote run not yet confirmed |
| 6 | Tested on a rooted/hooked control device and a second physical phone | Owner/devices | **open** |
| 7 | Honest launch copy reviewed (see `docs/launch/`), no unbypassable/"enterprise-certified" claims | Owner | drafts ready |
| 8 | Credential hygiene: remote URL contains no token; leaked tokens revoked; commit author email is the intended public one | Owner | **partly done**: history rewritten to the intended author email; token review still open |

Do not publish while any row is open. A security product that ships with a broken first-run experience or an
overstated claim is worse than one that ships a week later.

## Release steps (after the gate)

```bash
# 1. verify exactly what will ship
./gradlew check validatePlugins lintRelease -PreleaseVersion=0.1.0 --configuration-cache

# 2. dry run: nothing is uploaded, but the Portal still requires your real keys even for --validate-only
./gradlew :plugin:publishPlugins --validate-only -PreleaseVersion=0.1.0 -Papparmorx.vcsUrl=https://github.com/<owner>/<repo>

# 3. publish (credentials from the environment, never from committed files)
export GRADLE_PUBLISH_KEY=...  GRADLE_PUBLISH_SECRET=...
./gradlew :plugin:publishPlugins -PreleaseVersion=0.1.0 -Papparmorx.vcsUrl=https://github.com/<owner>/<repo>
```

Versions are immutable on the Portal; `SNAPSHOT` is rejected by the build. First publication of a new plugin
id goes through Gradle's manual approval, which cannot be hurried or guaranteed.

## Compatibility actually tested

| Dimension | Verified | Not verified |
|---|---|---|
| AGP / Gradle / JDK | AGP 9.4.1, Gradle 9.8.0, JDK 17 toolchain, daemon JDK 25 | other AGP majors |
| Consumer `compileSdk` | 34 (clean-room), 37 (sample) | below 34 |
| `minSdk` | 29 | below 29 |
| ABIs | arm64-v8a (device + emulator), x86_64 (built, not run) | 32-bit ABIs (unsupported) |
| Devices | Pixel 7 Pro (Android 17), arm64 emulator API 35 | rooted device, other OEMs, API 29-33 |
| Host language | Kotlin (sample), Java-only (clean-room) | Flutter, React Native, Unity |

State this table, not "works on all Android", in every public post.
