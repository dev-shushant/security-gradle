# AppArmorX Architecture and Threat Model

**Author & Maintainer:** Shushant Tiwari  
**Group:** `com.apparmorx` · **Plugin:** `com.apparmorx.security` · **Release:** `v0.1.0`  

---

## 1. System Architecture & Multi-Tier Defense

AppArmorX is a zero-integration mobile application security platform operating at the intersection of compile-time bytecode rewriting, native kernel syscall interposition, and autonomous runtime self-defense.

```
+---------------------------------------------------------------------------------------------------------+
|                                        COMPILE-TIME PIPELINE (AGP)                                      |
|                                                                                                         |
|   +-----------------------+     +-------------------------------+     +-----------------------------+   |
|   |   Policy Bundling     | --> |   ASM Bytecode Transformation | --> |   Coverage Verification     |   |
|   |   • Ed25519 signature |     |   • Activity Guard Injection  |     |   • Validates packaged APKs |   |
|   |   • Digest stamping   |     |   • Preflight Gate Injection  |     |   • Strict release gates    |   |
|   |   • Sequence floor    |     |   • Dependency Firewall Hook  |     |   • Config-cache verified   |   |
|   +-----------------------+     +-------------------------------+     +-----------------------------+   |
+---------------------------------------------------------------------------------------------------------+
                                                     |
                                                     v
+---------------------------------------------------------------------------------------------------------+
|                                        RUNTIME EXECUTION (Android)                                      |
|                                                                                                         |
|   +---------------------------------------+             +-------------------------------------------+   |
|   |         Zero-Window Preflight         |             |        In-App Dependency Firewall         |   |
|   | • Executes in <init> / onCreate       |             | • Clipboard read rerouting                |   |
|   | • Bounded synchronous fast path       |             | • Hardware/OS ID sanitization             |   |
|   | • Optional fail-closed hold           |             | • Last-location read rerouting           |   |
|   +---------------------------------------+             | • HostnameVerifier / TLS enforcement      |   |
|                       |                                 +-------------------------------------------+   |
|                       v                                                               |                 |
|   +---------------------------------------+                                           |                 |
|   |      Automated UI / Mirage Mode       | <-----------------------------------------+                 |
|   | • FLAG_SECURE on guarded activities   |                                                             |
|   | • Obscured-touch filtering (opt-in)   |                                                             |
|   | • Mirage delay (40-120 ms, opt-in)    |                                                             |
|   +---------------------------------------+                                                             |
|                       |                                                                                 |
|                       v                                                                                 |
|   +-------------------------------------------------------------------------------------------------+   |
|   |                                  Native C++ Security Core                                       |   |
|   | • Direct inline kernel syscalls (svc #0 ARM64, syscall x86_64) bypassing libc/PLT               |   |
|   | • Dynamic thread auditing (/proc/self/task/) for Frida gum/gdbus worker threads                 |   |
|   | • Memory staging audit (/proc/self/maps) for stealth tmp execution, memfd, deleted .so          |   |
|   | • Trampoline prologue inspection for inline libc hooks (open, read, ptrace, connect)           |   |
|   +-------------------------------------------------------------------------------------------------+   |
+---------------------------------------------------------------------------------------------------------+
```

---

## 2. Threat Model & Trust Boundaries

AppArmorX identifies the following core assets and adversaries:

- **Target Assets**: Host application integrity, signing identity, build reproducibility, user privacy, device identifiers, TLS encryption integrity, and server-authorized transactions.
- **Threat Actors**: Repackagers, dynamic instrumentation operators (Frida, Xposed, Magisk), malicious SDKs in the dependency tree, compromised build inputs, and network eavesdroppers.

### Trust Boundaries & Mitigations

| Boundary | Threat Vector | AppArmorX Controls | Residual Risk |
|---|---|---|---|
| **Feed to Build** | Malicious feed tampering, MITM | HTTPS without redirects, size/time bounds, Ed25519 signature over exact bytes, strict schema, committed minimum sequence floor. | Compromised feed signing key or build clock manipulation. |
| **Build to APK** | Compromised 3rd-party dependencies | AGP ASM visitor rewrites sensitive call sites (`ClipboardManager`, `Settings.Secure`, `LocationManager`, `HttpsURLConnection`). | Bytecode reflection or raw JNI calls from untrusted native libraries. |
| **Device to Runtime** | Dynamic hook attach, Frida staging, stealth ptrace | Direct inline kernel syscalls (`svc #0`), memory staging inspection, `/proc/self/task/` worker thread audit, trampoline prologue checks. | Kernel-level rootkits or compromised OS hypervisors; direct framework calls from injected code; spawn-time injection that runs before this library (both reproduced, see VALIDATION.md). |
| **UI to Display** | Screenshot scrapers, screen recorders, overlay tapjacking | `FLAG_SECURE` and `filterTouchesWhenObscured` on guarded activities where the profile enables them. | Physical optical capture (camera photographing screen). |
| **Runtime to Host** | Disruptive false-positives, app crashing | Distinct probe states (`CLEAR`, `DETECTED`, `UNAVAILABLE`), configurable `restrictedAction`, false-positive containment (`enforceIndeterminate=false`). | Host misconfiguration choosing `TERMINATE` on observe-only channels. |

---

## 3. Core Architectural Subsystems

### 3.1. Zero-Window Startup Preflight Gate
Rather than waiting for delayed background worker threads or asynchronous callbacks, the preflight gate runs synchronously at the earliest possible lifecycle event (`<init>` and `onCreate`). It queries a small set of critical probes (signing certificate, package ID, native tracer). Its latency has not been benchmarked and no figure is claimed. It narrows the launch window in which an attacker can act; it cannot prevent injection that runs before this code (for example spawn-time injection).

### 3.2. Direct Inline Kernel Syscalls
Standard C library functions (`openat`, `read`, `close`) route through the Procedure Linkage Table (PLT) and Global Offset Table (GOT), making them trivial targets for hooking frameworks like Frida or Dobby. AppArmorX implements direct inline assembly syscalls:
- **ARM64**: Raw `svc #0` with registers `x8` (syscall number), `x0`-`x3` (arguments).
- **x86_64**: Raw `syscall` with registers `rax` (syscall number), `rdi`, `rsi`, `rdx`, `r10`.

This enables memory map (`/proc/self/maps`) and status (`/proc/self/status`) reading directly through the kernel, ignoring any user-space hooks on libc.

### 3.3. In-App Dependency Firewall
Third-party SDKs frequently extract sensitive telemetry without developer consent. AppArmorX intercepts target calls at the bytecode level across all transitive dependencies:
- **Clipboard**: `ClipboardManager.getPrimaryClip` and `hasPrimaryClip` -> returns `null` / `false`.
- **Identifiers**: `Settings.Secure.getString(ANDROID_ID)` -> returns `"0000000000000000"`; `TelephonyManager.getDeviceId` / `getImei` -> return `null`.
- **Location**: `LocationManager.getLastKnownLocation` -> returns `null`.
- **TLS Security**: Permissive `HostnameVerifier` (e.g. `return true`) and allow-all `TrustManager` instances -> dropped and substituted with system default trust managers.

### 3.4. Mirage mode
Crude binary crashing (`exit(0)` / `kill(pid)`) provides immediate feedback to reverse engineers. AppArmorX introduces Mirage Mode:
- Injects non-deterministic delays (40-120 ms) into guarded activity resumes when Mirage is the configured response.
- Makes the response timing less predictable to automated tooling. This is a deterrent, not a prevention mechanism.

---

## 4. Verification and Release Criteria

Every change in AppArmorX must satisfy the following verification gates:
1. **Plugin Validation**: `./gradlew validatePlugins` must pass without warnings.
2. **Configuration Cache**: Build tasks must succeed with `--configuration-cache`.
3. **Android Lint**: `./gradlew lintRelease` must produce zero errors.
4. **Unit Test Suite**: all tests pass across `:policy`, `:plugin`, and `:runtime`.
5. **Physical Device Validation**: Connected instrumentation tests on physical hardware (e.g., Pixel 7 Pro on Android 17) must execute and pass completely.
