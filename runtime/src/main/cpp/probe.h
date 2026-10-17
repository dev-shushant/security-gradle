#pragma once
#include <algorithm>
#include <charconv>
#include <cctype>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace apparmorx {
enum class Status : int { clear = 0, detected = 1, unavailable = 2 };
inline bool contains_indicator(std::string text, const std::vector<std::string>& markers) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) { return std::tolower(c); });
    for (const auto& marker : markers) {
        if (!marker.empty() && text.find(marker) != std::string::npos) return true;
    }
    return false;
}
inline Status tracer_status(const std::string& text) {
    const std::string key = "TracerPid:";
    const auto start = text.find(key);
    if (start == std::string::npos || (start != 0 && text[start - 1] != '\n')) return Status::unavailable;
    auto value = text.substr(start + key.size(), text.find('\n', start) - start - key.size());
    const auto first = value.find_first_not_of(" \t\r");
    if (first == std::string::npos) return Status::unavailable;
    value = value.substr(first, value.find_last_not_of(" \t\r") - first + 1);
    unsigned int pid = 0;
    const auto result = std::from_chars(value.data(), value.data() + value.size(), pid);
    if (result.ec != std::errc() || result.ptr != value.data() + value.size()) return Status::unavailable;
    return pid > 0 ? Status::detected : Status::clear;
}
inline Status selinux_eval(const std::optional<std::string>& text) {
    // A read failure (nullopt) or an empty read is "could not tell", never "clean" -- SELinux
    // itself denies untrusted_app read access to /sys/fs/selinux/enforce on some devices, and that
    // denial must not be silently reported as "SELinux is enforcing" (clear).
    if (!text || text->empty()) return Status::unavailable;
    const auto first = text->find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return Status::unavailable;
    const auto value = text->substr(first, text->find_last_not_of(" \t\r\n") - first + 1);
    if (value == "0") return Status::detected;
    if (value == "1") return Status::clear;
    return Status::unavailable;
}
inline Status wchan_eval(const std::optional<std::string>& text) {
    if (!text || text->empty()) return Status::unavailable;
    return contains_indicator(*text, {"ptrace_stop", "sys_ptrace", "do_signal_stop"})
        ? Status::detected : Status::clear;
}
inline bool is_arm64_trampoline(uint32_t insn0, uint32_t insn1) {
    // 1. ldr x16, #8 ; br x16 (Frida / Substrate)
    if (insn0 == 0x58000050 && insn1 == 0xd61f0200) return true;
    // 2. ldr x17, #8 ; br x17 (Frida alternative)
    if (insn0 == 0x58000051 && insn1 == 0xd61f0220) return true;
    // 3. ldr x8, #8 ; br x8 (Dobby / ShadowHook)
    if (insn0 == 0x58000048 && insn1 == 0xd61f0100) return true;
    // 4. Unconditional immediate branch (b offset)
    if ((insn0 & 0xfc000000) == 0x14000000) return true;
    return false;
}

inline bool is_x86_64_trampoline(const uint8_t* code) {
    if (!code) return false;
    if (code[0] == 0xe9) return true; // jmp rel32
    if (code[0] == 0xeb) return true; // jmp rel8
    if (code[0] == 0xff && code[1] == 0x25) return true; // jmp [rip + offset]
    return false;
}

inline bool has_rwx_shared_library(const std::string& maps_text) {
    std::string_view text(maps_text);
    size_t line_start = 0;
    while (line_start < text.size()) {
        size_t line_end = text.find('\n', line_start);
        if (line_end == std::string_view::npos) line_end = text.size();
        std::string_view line = text.substr(line_start, line_end - line_start);
        size_t first_space = line.find(' ');
        if (first_space != std::string_view::npos) {
            size_t perm_start = line.find_first_not_of(' ', first_space);
            if (perm_start != std::string_view::npos && perm_start + 3 <= line.size()) {
                std::string_view perms = line.substr(perm_start, 4);
                if (perms.size() >= 3 && perms[1] == 'w' && perms[2] == 'x') {
                    if (line.find(".so") != std::string_view::npos) {
                        return true;
                    }
                }
            }
        }
        line_start = line_end + 1;
    }
    return false;
}

inline bool is_injected_thread_comm(std::string_view comm) {
    while (!comm.empty() && (comm.back() == '\n' || comm.back() == '\r' || comm.back() == ' ')) comm.remove_suffix(1);
    while (!comm.empty() && (comm.front() == ' ' || comm.front() == '\t')) comm.remove_prefix(1);
    if (comm.rfind("gum-", 0) == 0 || comm.rfind("frida-", 0) == 0) return true;
    for (const auto* marker : {"gmain", "gdbus", "gum-js-loop", "pool-frida", "gum-worker", "linjector"}) {
        if (comm == marker) return true;
    }
    return false;
}

inline bool has_stealth_injection_mapping(const std::string& maps_text) {
    std::string_view text(maps_text);
    size_t line_start = 0;
    while (line_start < text.size()) {
        size_t line_end = text.find('\n', line_start);
        if (line_end == std::string_view::npos) line_end = text.size();
        std::string_view line = text.substr(line_start, line_end - line_start);
        if (line.find("/data/local/tmp/") != std::string_view::npos) {
            return true;
        }
        if (line.find("[anon:gum") != std::string_view::npos ||
            line.find("[anon:frida") != std::string_view::npos) {
            return true;
        }
        if (line.find(".so (deleted)") != std::string_view::npos) {
            return true;
        }
        if (line.find("/memfd:frida") != std::string_view::npos ||
            line.find("/memfd:gum") != std::string_view::npos ||
            line.find("/memfd:gadget") != std::string_view::npos ||
            line.find("/memfd:agent") != std::string_view::npos) {
            return true;
        }
        line_start = line_end + 1;
    }
    return false;
}
}

