#pragma once
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#if defined(__linux__) || defined(__ANDROID__)
#include <sys/syscall.h>
#endif

namespace apparmorx {
namespace sys {

#if (defined(__aarch64__) || defined(__arm64__)) && (defined(__linux__) || defined(__ANDROID__))

inline long raw_syscall3(long n, long a1, long a2, long a3) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a1;
    register long x1 __asm__("x1") = a2;
    register long x2 __asm__("x2") = a3;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory", "cc");
    return x0;
}

inline long raw_syscall4(long n, long a1, long a2, long a3, long a4) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a1;
    register long x1 __asm__("x1") = a2;
    register long x2 __asm__("x2") = a3;
    register long x3 __asm__("x3") = a4;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3) : "memory", "cc");
    return x0;
}

inline long raw_syscall5(long n, long a1, long a2, long a3, long a4, long a5) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a1;
    register long x1 __asm__("x1") = a2;
    register long x2 __asm__("x2") = a3;
    register long x3 __asm__("x3") = a4;
    register long x4 __asm__("x4") = a5;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4) : "memory", "cc");
    return x0;
}

#elif defined(__x86_64__) && (defined(__linux__) || defined(__ANDROID__))

inline long raw_syscall3(long n, long a1, long a2, long a3) {
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory");
    return ret;
}

inline long raw_syscall4(long n, long a1, long a2, long a3, long a4) {
    long ret;
    register long r10 __asm__("r10") = a4;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10) : "rcx", "r11", "memory");
    return ret;
}

inline long raw_syscall5(long n, long a1, long a2, long a3, long a4, long a5) {
    long ret;
    register long r10 __asm__("r10") = a4;
    register long r8 __asm__("r8") = a5;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8) : "rcx", "r11", "memory");
    return ret;
}

#endif

inline int direct_open(const char* path, int flags) {
#if (defined(__aarch64__) || defined(__arm64__) || defined(__x86_64__)) && (defined(__linux__) || defined(__ANDROID__))
    #if defined(__NR_openat)
    long ret = raw_syscall4(__NR_openat, -100 /* AT_FDCWD */, reinterpret_cast<long>(path), flags, 0);
    if (ret >= 0) return static_cast<int>(ret);
    #endif
#endif
    return open(path, flags);
}

inline ssize_t direct_read(int fd, void* buf, size_t count) {
#if (defined(__aarch64__) || defined(__arm64__) || defined(__x86_64__)) && (defined(__linux__) || defined(__ANDROID__))
    #if defined(__NR_read)
    long ret = raw_syscall3(__NR_read, fd, reinterpret_cast<long>(buf), count);
    if (ret >= 0) return static_cast<ssize_t>(ret);
    #endif
#endif
    return read(fd, buf, count);
}

inline int direct_close(int fd) {
#if (defined(__aarch64__) || defined(__arm64__) || defined(__x86_64__)) && (defined(__linux__) || defined(__ANDROID__))
    #if defined(__NR_close)
    long ret = raw_syscall3(__NR_close, fd, 0, 0);
    if (ret >= 0) return static_cast<int>(ret);
    #endif
#endif
    return close(fd);
}

inline int direct_fstatat(int dirfd, const char* path, struct stat* buf, int flags) {
#if (defined(__aarch64__) || defined(__arm64__) || defined(__x86_64__)) && (defined(__linux__) || defined(__ANDROID__))
    #if defined(__NR_newfstatat)
    long ret = raw_syscall4(__NR_newfstatat, dirfd, reinterpret_cast<long>(path), reinterpret_cast<long>(buf), flags);
    if (ret >= 0) return static_cast<int>(ret);
    #endif
#endif
    return fstatat(dirfd, path, buf, flags);
}

inline int direct_lstat(const char* path, struct stat* buf) {
#if defined(AT_FDCWD) && defined(AT_SYMLINK_NOFOLLOW)
    return direct_fstatat(AT_FDCWD, path, buf, AT_SYMLINK_NOFOLLOW);
#else
    return lstat(path, buf);
#endif
}

inline long direct_prctl(int option, unsigned long arg2 = 0, unsigned long arg3 = 0, unsigned long arg4 = 0, unsigned long arg5 = 0) {
#if (defined(__aarch64__) || defined(__arm64__) || defined(__x86_64__)) && (defined(__linux__) || defined(__ANDROID__))
    #if defined(__NR_prctl)
    return raw_syscall5(__NR_prctl, option, arg2, arg3, arg4, arg5);
    #endif
#endif
    return -1;
}

} // namespace sys
} // namespace apparmorx
