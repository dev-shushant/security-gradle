# Probe matrix

Every check AppArmorX runs, by engine. A probe that cannot run reports `UNAVAILABLE`, never `CLEAR`.

| Probe | Engine | What it observes |
|---|---|---|
| `policy` | JVM | Ed25519 signature and sequence floor of the bundled policy |
| `application-id` | JVM | Package-name tampering / repackaging |
| `signing-certificate` | JVM | Signer SHA-256 against your pinned allowlist |
| `hook-library` | Managed | Known instrumentation libraries in `/proc/self/maps` |
| `native-engine` | Native | Native core loaded and available |
| `native-tracer` | Native | `TracerPid` via inline syscall |
| `native-root-path` / `native-root-mount` | Native | su/Magisk artifacts; suspicious mounts |
| `native-hook-library` | Native | Frida/Xposed/Substrate mappings via kernel reads |
| `native-tool-thread` | Native | Injected worker threads (`gum-*`, `frida-*`, `gdbus`, …) |
| `native-libc-origin` | Native | Libc symbol interposition (`dlsym` vs `dladdr`) |
| `native-hook-trampoline` | Native | Inline-hook prologues on libc entry points (ARM64, x86_64) |
| `native-selinux` | Native | SELinux enforcing state (reports `UNAVAILABLE`, not clean, if the device denies reading `/sys/fs/selinux/enforce` — confirmed happening on a real SELinux-enforcing device) |
| `native-hardware-device` | Native | Emulator / virtualised hardware (same EACCES-vs-absent distinction as `root-path`) |
| `native-wchan` | Native | `ptrace_stop` wait channel |
| `native-frida-port` | Native | Default Frida listener ports (corroborating signal only; reports `UNAVAILABLE`, not clean, if `/proc/net/tcp[6]` is unreadable — confirmed happening on a real SELinux-enforcing device, see [STATUS.md](STATUS.md)) |
| `native-memory-rwx` | Native | Suspicious RWX anonymous pages |
| `native-stealth-injection` | Native | Anonymous payloads, tmp staging, deleted libraries |
| `native-relocation-integrity` | Native | ELF W^X program headers; relocation pointer bounds |
| `debugger` / `debuggable-app` | Framework | Debugger attached; `FLAG_DEBUGGABLE` set |
| `apk-integrity` | Framework | APK readable and payload digests match (when pinned) |
| `root-path` / `build-tags` | Framework | su/Magisk paths; `test-keys` system build |
| `hook-classes` | Framework | Xposed/Substrate classes loadable |
| `network-cleartext-permitted` | Framework | App permits unencrypted HTTP |
| `environment-hardware` / `virtual-space` | Framework | Emulator fingerprints; cloning/virtual-space paths |
