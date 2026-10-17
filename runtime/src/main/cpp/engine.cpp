#include "probe.h"
#include "syscalls.h"
#include <jni.h>
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cerrno>
#include <chrono>
#include <optional>

namespace {
using apparmorx::Status;
constexpr size_t kMaxBytes = 1024 * 1024;
static jintArray scan(JNIEnv* env, jclass);

std::optional<std::string> read_bounded(const char* path) {
    const int fd = apparmorx::sys::direct_open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return std::nullopt;
    std::string result;
    char buffer[4096];
    while (true) {
        const auto count = apparmorx::sys::direct_read(fd, buffer, sizeof(buffer));
        if (count == 0) { apparmorx::sys::direct_close(fd); return result; }
        if (count < 0 || result.size() + static_cast<size_t>(count) > kMaxBytes) {
            apparmorx::sys::direct_close(fd);
            return std::nullopt;
        }
        result.append(buffer, static_cast<size_t>(count));
    }
}

Status root_paths() {
    bool unavailable = false;
    for (const auto* path : {"/system/bin/su", "/system/xbin/su", "/sbin/su", "/data/adb/magisk", "/data/adb/ksu", "/data/adb/ap"}) {
        struct stat info{};
        if (apparmorx::sys::direct_lstat(path, &info) == 0) return Status::detected;
        if (errno != ENOENT && errno != ENOTDIR) unavailable = true;
    }
    return unavailable ? Status::unavailable : Status::clear;
}

Status thread_indicators() {
    DIR* directory = opendir("/proc/self/task");
    if (!directory) return Status::unavailable;
    Status result = Status::clear;
    size_t entries = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(30);
    while (const auto* entry = readdir(directory)) {
        if (entry->d_name[0] == '.') continue;
        if (++entries > 512 || std::chrono::steady_clock::now() > deadline) { result = Status::unavailable; break; }
        const auto content = read_bounded((std::string("/proc/self/task/") + entry->d_name + "/comm").c_str());
        if (!content) { result = Status::unavailable; continue; }
        if (apparmorx::is_injected_thread_comm(*content)) { result = Status::detected; break; }
    }
    closedir(directory);
    return result;
}

Status libc_origin() {
    // dlsym(RTLD_DEFAULT, ...) follows the same resolution a PLT/GOT call would use, so a hook that
    // interposes the symbol (fishhook-style patching, Frida's Interceptor, an LD_PRELOAD shim) shows
    // up here. Checks critical syscall wrappers: open, read, ptrace, __openat, connect, kill, mprotect.
    for (const auto* symbol : {"open", "read", "ptrace", "__openat", "connect", "kill", "mprotect"}) {
        void* resolved = dlsym(RTLD_DEFAULT, symbol);
        if (resolved == nullptr) return Status::unavailable;
        Dl_info info{};
        if (dladdr(resolved, &info) == 0 || !info.dli_fname) return Status::unavailable;
        const std::string name(info.dli_fname);
        const auto slash = name.find_last_of('/');
        const auto base = name.substr(slash == std::string::npos ? 0 : slash + 1);
        if (base != "libc.so") return Status::detected;
    }
    return Status::clear;
}

Status selinux_status() {
    return apparmorx::selinux_eval(read_bounded("/sys/fs/selinux/enforce"));
}

Status hook_trampolines() {
#if defined(__aarch64__) || defined(__arm64__)
    for (const auto* symbol : {"open", "read", "ptrace", "__openat", "connect", "pthread_create", "mprotect", "kill"}) {
        void* resolved = dlsym(RTLD_DEFAULT, symbol);
        if (resolved == nullptr) continue;
        const auto* code = reinterpret_cast<const uint32_t*>(resolved);
        if (apparmorx::is_arm64_trampoline(code[0], code[1])) return Status::detected;
    }
    const auto* self_code = reinterpret_cast<const uint32_t*>(reinterpret_cast<void*>(scan));
    if (apparmorx::is_arm64_trampoline(self_code[0], self_code[1])) return Status::detected;
#elif defined(__x86_64__)
    for (const auto* symbol : {"open", "read", "ptrace", "__openat", "connect", "pthread_create", "mprotect", "kill"}) {
        void* resolved = dlsym(RTLD_DEFAULT, symbol);
        if (resolved == nullptr) continue;
        const auto* code = reinterpret_cast<const uint8_t*>(resolved);
        if (apparmorx::is_x86_64_trampoline(code)) return Status::detected;
    }
    const auto* self_code = reinterpret_cast<const uint8_t*>(reinterpret_cast<void*>(scan));
    if (apparmorx::is_x86_64_trampoline(self_code)) return Status::detected;
#endif
    return Status::clear;
}

Status hardware_devices() {
    // Same fix as root_paths(): a stat() denial (EACCES/EPERM, e.g. an SELinux rule on a locked-down
    // device) must not look identical to "this path genuinely does not exist" -- only ENOENT/ENOTDIR
    // mean that.
    bool unavailable = false;
    for (const auto* path : {"/dev/kernelsu", "/dev/apatch", "/dev/qemu_pipe", "/dev/goldfish_pipe", "/dev/vport0p1"}) {
        struct stat info{};
        if (apparmorx::sys::direct_lstat(path, &info) == 0) return Status::detected;
        if (errno != ENOENT && errno != ENOTDIR) unavailable = true;
    }
    return unavailable ? Status::unavailable : Status::clear;
}

Status ptrace_wchan() {
    const auto wchan = read_bounded("/proc/self/wchan");
    if (!wchan) return Status::clear;
    if (apparmorx::contains_indicator(*wchan, {"ptrace_stop", "sys_ptrace", "do_signal_stop"})) {
        return Status::detected;
    }
    return Status::clear;
}

Status frida_ports() {
    // Reproduced live on a SELinux-enforcing device (see docs/STATUS.md): untrusted_app is denied
    // read of /proc/net/tcp[6] outright. The old version of this function treated that denial the
    // same as "read it, port not open" -- silently CLEAR instead of UNAVAILABLE -- which is exactly
    // the invariant this project otherwise holds everywhere else (see rootPathStatus in the Kotlin
    // runtime). A read failure must never look identical to a clean result.
    bool any_read_failed = false;
    for (const auto* path : {"/proc/net/tcp", "/proc/net/tcp6"}) {
        const auto content = read_bounded(path);
        if (!content) { any_read_failed = true; continue; }
        if (apparmorx::contains_indicator(*content, {":69a2"})) return Status::detected;
    }
    return any_read_failed ? Status::unavailable : Status::clear;
}

Status memory_rwx(const std::optional<std::string>& maps) {
    if (!maps) return Status::unavailable;
    return apparmorx::has_rwx_shared_library(*maps) ? Status::detected : Status::clear;
}

Status stealth_injection(const std::optional<std::string>& maps) {
    if (!maps) return Status::unavailable;
    return apparmorx::has_stealth_injection_mapping(*maps) ? Status::detected : Status::clear;
}

#if defined(__ANDROID__)
#include <link.h>
#include <elf.h>

struct PhdrContext {
    uintptr_t libc_min = UINTPTR_MAX;
    uintptr_t libc_max = 0;
    bool libc_found = false;
    bool wx_violation = false;
};

static int phdr_callback(struct dl_phdr_info* info, size_t, void* data) {
    auto* ctx = reinterpret_cast<PhdrContext*>(data);
    if (!info || !info->dlpi_name) return 0;
    std::string_view name(info->dlpi_name);

    const bool is_apparmorx = name.find("libapparmorx.so") != std::string_view::npos;
    const bool is_libc = name.find("libc.so") != std::string_view::npos;

    if (is_apparmorx || is_libc) {
        for (ElfW(Half) i = 0; i < info->dlpi_phnum; ++i) {
            const auto& phdr = info->dlpi_phdr[i];
            if (phdr.p_type == PT_LOAD) {
                if ((phdr.p_flags & PF_X) && (phdr.p_flags & PF_W)) {
                    ctx->wx_violation = true;
                }
                if (is_libc) {
                    uintptr_t start = info->dlpi_addr + phdr.p_vaddr;
                    uintptr_t end = start + phdr.p_memsz;
                    ctx->libc_found = true;
                    if (start < ctx->libc_min) ctx->libc_min = start;
                    if (end > ctx->libc_max) ctx->libc_max = end;
                }
            }
        }
    }
    return 0;
}

Status relocation_integrity() {
    PhdrContext ctx{};
    if (dl_iterate_phdr(phdr_callback, &ctx) != 0) return Status::unavailable;
    if (ctx.wx_violation) return Status::detected;

    for (const auto* symbol : {"open", "read", "dlsym"}) {
        void* sym = dlsym(RTLD_DEFAULT, symbol);
        if (!sym) continue;
        Dl_info dlinfo{};
        if (dladdr(sym, &dlinfo) == 0 || !dlinfo.dli_fname) return Status::unavailable;
        std::string_view fname(dlinfo.dli_fname);
        if (fname.find("/data/local/tmp/") != std::string_view::npos ||
            fname.find("frida") != std::string_view::npos ||
            fname.find("xposed") != std::string_view::npos) {
            return Status::detected;
        }
    }
    return Status::clear;
}
#else
Status relocation_integrity() {
    return Status::clear;
}
#endif

/**
 * Best-effort self-protection, NOT detection: occupies this process's single ptrace "tracer" slot
 * with a minimal watchdog child of our own, so a later `ptrace(PTRACE_ATTACH, ...)` from an external
 * tool -- the mechanism frida-server uses to attach to an already-running process on Android --
 * fails with EPERM instead of succeeding, because Linux only ever allows one tracer per process.
 *
 * Explicit, honest scope (document this precisely everywhere this is described, per AGENTS.md):
 * - Blocks: attaching Frida (or any ptrace-based tool) to this app's process AFTER this function has
 *   already run and won the race for the tracer slot. This is the common real-world attack path --
 *   an attacker roots a device and attaches Frida/Objection to an app that is already installed and
 *   running, which they did not control the launch of.
 * - Does NOT block: spawn-time injection (`frida -f <package>`), where the attacker's tool injects
 *   before this process even begins executing app code, so it always wins that specific race. Does
 *   NOT block an attacker with enough privilege to simply kill or ptrace-detach our watchdog child
 *   directly, or a Frida version with an anti-anti-ptrace bypass. This is hardening, not a boundary;
 *   never describe it as "unhookable" or "unbypassable."
 * - Degrades safely everywhere else: SELinux policy, a kernel without Yama, fork() failure, or a
 *   tracer already present (e.g. an attacker who won the race, or a real debugger on a debug build)
 *   all make this a no-op that returns false. Nothing here ever reports Status or touches evidence;
 *   a caller that never invokes this gets identical behavior to today.
 *
 * The child touches no C++ runtime beyond raw syscalls between fork() and _exit() -- no malloc, no
 * std::string, nothing that could deadlock on state only the parent's other (non-forked) threads held
 * locks on. Verification reads /proc/self/status's TracerPid directly via the existing raw-syscall
 * read_bounded(), which a libc-level ptrace() hook cannot spoof.
 */
jboolean harden_ptrace(JNIEnv*, jclass) {
    if (const auto before = read_bounded("/proc/self/status")) {
        if (apparmorx::tracer_status(*before) == Status::detected) return JNI_FALSE; // already traced
    }

    int sync_pipe[2];
    if (pipe(sync_pipe) != 0) return JNI_FALSE;

    const pid_t parent = getpid();
    const pid_t child = fork();
    if (child < 0) {
        apparmorx::sys::direct_close(sync_pipe[0]);
        apparmorx::sys::direct_close(sync_pipe[1]);
        return JNI_FALSE;
    }

    if (child == 0) {
        // --- Child watchdog: raw syscalls only, from here to _exit(), no exceptions. ---
        apparmorx::sys::direct_close(sync_pipe[1]);
        char go = 0;
        if (apparmorx::sys::direct_read(sync_pipe[0], &go, 1) != 1 || go != 1) _exit(1);
        apparmorx::sys::direct_close(sync_pipe[0]);
        if (ptrace(PTRACE_ATTACH, parent, nullptr, nullptr) != 0) _exit(1);
        int status = 0;
        if (waitpid(parent, &status, 0) < 0) _exit(1); // consumes the attach-induced stop
        ptrace(PTRACE_CONT, parent, nullptr, nullptr);
        while (true) {
            if (waitpid(parent, &status, 0) < 0) _exit(0); // parent is gone; nothing left to hold
            if (WIFEXITED(status) || WIFSIGNALED(status)) _exit(0);
            const int sig = WIFSTOPPED(status) ? WSTOPSIG(status) : 0;
            ptrace(PTRACE_CONT, parent, nullptr, reinterpret_cast<void*>(static_cast<long>(sig)));
        }
    }

    // --- Parent: explicitly allow this one descendant to trace us, then let it race the attacker. ---
    apparmorx::sys::direct_close(sync_pipe[0]);
    // Without this, Yama's ptrace_scope=1 default (an app-process default on many Android builds)
    // would itself block the child's attach above: that mode requires the tracer to be an ancestor
    // of the target, and our watchdog is a descendant of the process it is about to trace.
    prctl(PR_SET_PTRACER, child, 0, 0, 0);
    const char go = 1;
    const bool signaled = write(sync_pipe[1], &go, 1) == 1;
    apparmorx::sys::direct_close(sync_pipe[1]);
    if (!signaled) return JNI_FALSE;

    for (int attempt = 0; attempt < 40; ++attempt) {
        usleep(5000);
        if (const auto status_text = read_bounded("/proc/self/status")) {
            if (apparmorx::tracer_status(*status_text) == Status::detected) return JNI_TRUE;
        }
    }
    // Failed (commonly: SELinux denies untrusted_app -> self ptrace outright, independent of root --
    // see docs/STATUS.md). The child already exited in that case; reap it so it doesn't sit as a
    // zombie for the rest of the process's life. Non-blocking: if it is still alive for some other
    // reason, leave it rather than risk hanging here.
    waitpid(child, nullptr, WNOHANG);
    return JNI_FALSE;
}

jintArray scan(JNIEnv* env, jclass) {
    const auto status = read_bounded("/proc/self/status");
    const auto mounts = read_bounded("/proc/self/mountinfo");
    const auto maps = read_bounded("/proc/self/maps");
    const auto matched = [](const std::optional<std::string>& text, const std::vector<std::string>& markers) {
        if (!text) return Status::unavailable;
        return apparmorx::contains_indicator(*text, markers) ? Status::detected : Status::clear;
    };
    const jint results[] = {
        static_cast<jint>(status ? apparmorx::tracer_status(*status) : Status::unavailable),
        static_cast<jint>(root_paths()),
        static_cast<jint>(matched(mounts, {"magisk", "kernelsu", "apatch"})),
        static_cast<jint>(matched(maps, {"frida-agent", "libfrida-gadget", "liblsposed", "libxposed"})),
        static_cast<jint>(thread_indicators()),
        static_cast<jint>(libc_origin()),
        static_cast<jint>(selinux_status()),
        static_cast<jint>(hook_trampolines()),
        static_cast<jint>(hardware_devices()),
        static_cast<jint>(ptrace_wchan()),
        static_cast<jint>(frida_ports()),
        static_cast<jint>(memory_rwx(maps)),
        static_cast<jint>(stealth_injection(maps)),
        static_cast<jint>(relocation_integrity()),
    };
    auto output = env->NewIntArray(14);
    if (output) env->SetIntArrayRegion(output, 0, 14, results);
    return output;
}
}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    auto clazz = env->FindClass("com/apparmorx/runtime/NativeEngine");
    if (!clazz) return JNI_ERR;
    const JNINativeMethod methods[] = {
        {"scanNative", "()[I", reinterpret_cast<void*>(scan)},
        {"hardenPtraceNative", "()Z", reinterpret_cast<void*>(harden_ptrace)},
    };
    const auto result = env->RegisterNatives(clazz, methods, 2);
    env->DeleteLocalRef(clazz);
    return result == JNI_OK ? JNI_VERSION_1_6 : JNI_ERR;
}
