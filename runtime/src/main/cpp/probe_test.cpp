#include "probe.h"
#include <cassert>
int main() {
    using namespace apparmorx;
    assert(tracer_status("Name:\ttest\nTracerPid:\t0\n") == Status::clear);
    assert(tracer_status("TracerPid:\t42\n") == Status::detected);
    assert(tracer_status("TracerPid:\tx\n") == Status::unavailable);
    assert(tracer_status("TracerPid:\t-1\n") == Status::unavailable);
    assert(tracer_status("TracerPid:\t0junk\n") == Status::unavailable);
    assert(tracer_status("Name:\ttest\n") == Status::unavailable);
    assert(contains_indicator("/data/LIBFRIDA-GADGET.so", {"libfrida-gadget"}));
    assert(!contains_indicator("/system/lib64/libc.so", {"frida-agent"}));
    assert(!contains_indicator("anything", {""}));
    assert(selinux_eval(std::string("1\n")) == Status::clear);
    assert(selinux_eval(std::string("0\n")) == Status::detected);
    // A read failure (SELinux itself denying read of its own /sys/fs/selinux/enforce to the
    // untrusted_app domain -- reproduced live, see docs/STATUS.md) must report unavailable, never
    // the "clean" clear this used to return: that silently hid every such denial as a pass.
    assert(selinux_eval(std::nullopt) == Status::unavailable);
    assert(selinux_eval(std::string("")) == Status::unavailable);
    assert(is_arm64_trampoline(0x58000050, 0xd61f0200));
    assert(is_arm64_trampoline(0x58000051, 0xd61f0220));
    assert(is_arm64_trampoline(0x58000048, 0xd61f0100)); // ldr x8, #8; br x8
    assert(is_arm64_trampoline(0x14000004, 0x00000000)); // b +16
    assert(!is_arm64_trampoline(0xd503201f, 0xd65f03c0)); // nop; ret

    const uint8_t x86_jmp32[] = {0xe9, 0x10, 0x20, 0x30, 0x40};
    const uint8_t x86_jmp8[] = {0xeb, 0x05};
    const uint8_t x86_rip[] = {0xff, 0x25, 0x00, 0x00, 0x00, 0x00};
    const uint8_t x86_nop[] = {0x90, 0x90};
    assert(is_x86_64_trampoline(x86_jmp32));
    assert(is_x86_64_trampoline(x86_jmp8));
    assert(is_x86_64_trampoline(x86_rip));
    assert(!is_x86_64_trampoline(x86_nop));

    assert(contains_indicator("ptrace_stop\n", {"ptrace_stop", "sys_ptrace", "do_signal_stop"}));
    assert(!contains_indicator("futex_wait_queue_me\n", {"ptrace_stop", "sys_ptrace", "do_signal_stop"}));
    assert(contains_indicator("  0: 00000000:69A2 00000000:0000 0A ...", {":69a2"}));
    assert(!contains_indicator("  0: 00000000:0050 00000000:0000 0A ...", {":69a2"}));

    const std::string clean_maps =
        "7f001000-7f002000 r-xp 00000000 08:01 12345 /system/lib64/libc.so\n"
        "7f002000-7f003000 r--p 00001000 08:01 12345 /system/lib64/libc.so\n"
        "7f003000-7f004000 rw-p 00002000 08:01 12345 /system/lib64/libc.so\n";
    assert(!has_rwx_shared_library(clean_maps));

    const std::string patched_maps =
        "7f001000-7f002000 rwxp 00000000 08:01 12345 /data/app/pkg/lib/arm64/libapparmorx.so\n";
    assert(has_rwx_shared_library(patched_maps));

    assert(is_injected_thread_comm("gum-js-loop\n"));
    assert(is_injected_thread_comm("gmain"));
    assert(is_injected_thread_comm("gdbus"));
    assert(is_injected_thread_comm("pool-frida"));
    assert(is_injected_thread_comm("gum-worker"));
    assert(is_injected_thread_comm("linjector"));
    assert(is_injected_thread_comm("frida-thread-0"));
    assert(!is_injected_thread_comm("RenderThread\n"));
    assert(!is_injected_thread_comm("main"));
    assert(!is_injected_thread_comm("OkHttp Dispatcher"));

    const std::string tmp_staged_maps =
        "7f001000-7f002000 r-xp 00000000 08:01 12345 /data/local/tmp/libgadget.so\n";
    assert(has_stealth_injection_mapping(tmp_staged_maps));

    const std::string anon_gum_maps =
        "7f001000-7f002000 r-xp 00000000 00:00 0       [anon:gum-trampoline]\n";
    assert(has_stealth_injection_mapping(anon_gum_maps));

    const std::string deleted_so_maps =
        "7f001000-7f002000 r-xp 00000000 08:01 12345 /data/app/libinjected.so (deleted)\n";
    assert(has_stealth_injection_mapping(deleted_so_maps));

    const std::string memfd_maps =
        "7f001000-7f002000 r-xp 00000000 00:01 99999 /memfd:frida-agent\n";
    assert(has_stealth_injection_mapping(memfd_maps));
    assert(!has_stealth_injection_mapping(clean_maps));

    const std::string jit_maps =
        "44020000-46020000 r-xs 02000000 00:01 3077 /memfd:jit-zygote-cache (deleted)\n"
        "4a31f000-4c31f000 r-xs 02000000 00:01 346637 /memfd:jit-cache (deleted)\n";
    assert(!has_stealth_injection_mapping(jit_maps));
}
