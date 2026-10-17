# Contributing to AppArmorX

Thank you for your interest in contributing to **AppArmorX**!

AppArmorX is an open, zero-integration mobile application security platform authored and maintained by **Shushant Tiwari** (`com.apparmorx`, `com.apparmorx.security`).

## Architectural Invariants

Every contribution must preserve the following architectural boundaries:

1. **Strict Module Separation**:
   - `:policy`: JVM-only Ed25519 authenticated policy verifier and parser. Never depends on Android SDK or Gradle runtime.
   - `:plugin`: Gradle build-time plugin, ASM bytecode transformer (`GuardVisitor`), and APK packaging coverage auditor (`VerifyProtectionCoverage`). Runs on JVM during build.
   - `:runtime`: Android runtime AAR (`libapparmorx.so` + Kotlin core). Performs startup preflight, background monitoring, dependency firewall, and local enforcement.
2. **Configuration Cache Compatibility**:
   - All Gradle tasks must support `--configuration-cache`. Never access Project instances during task execution or register tasks dynamically outside project configuration.
3. **No Unauthenticated Code or Private Endpoints**:
   - No downloaded executable code, implicit telemetry endpoints, private keys, or broad tracking telemetry.
4. **Honest Evaluation Semantics**:
   - Never treat failed or unavailable probes as `CLEAR`. If a probe cannot verify an invariant, report `UNAVAILABLE`.
5. **Preserve Owner Identity**:
   - Source, documentation, examples, and metadata must remain exclusively branded for AppArmorX and authored by Shushant Tiwari.

## Development & Verification Workflow

Before submitting a Pull Request, ensure all quality gates pass locally:

```bash
# 1. Run core verification suite with configuration cache
./gradlew check validatePlugins lintRelease publishToMavenLocal -PreleaseVersion=0.1.0 --configuration-cache

# 2. Verify sample app minification with R8
./gradlew :sample:assembleRelease --configuration-cache

# 3. (Optional with attached physical device) Run connected hardware test suite
./gradlew :sample:connectedDebugAndroidTest
```

## Pull Request Guidelines

- Write abuse and regression tests before introducing security behavior changes.
- Ensure 100% Kotlin code style and absence of Android Lint errors or Gradle warnings.
- Keep commit messages concise and descriptive following Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`).
