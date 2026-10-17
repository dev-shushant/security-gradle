package com.apparmorx.runtime

/** Owned JNI probes. Native unavailability is never converted into successful evidence. */
internal object NativeEngine {
    private val loaded = try { System.loadLibrary("apparmorx"); true } catch (_: LinkageError) { false } catch (_: SecurityException) { false }
    private val checks = listOf(
        "native-tracer",
        "native-root-path",
        "native-root-mount",
        "native-hook-library",
        "native-tool-thread",
        "native-libc-origin",
        "native-selinux",
        "native-hook-trampoline",
        "native-hardware-device",
        "native-wchan",
        "native-frida-port",
        "native-memory-rwx",
        "native-stealth-injection",
        "native-relocation-integrity"
    )
    fun scan(): List<Evidence> {
        if (!loaded) return listOf(Evidence("native-engine", Status.UNAVAILABLE))
        return try {
            val result = scanNative()
            if (result.size != checks.size || result.any { it !in 0..2 }) return listOf(Evidence("native-engine", Status.UNAVAILABLE))
            listOf(Evidence("native-engine", Status.CLEAR)) + checks.mapIndexed { index, name -> Evidence(name, Status.entries[result[index]]) }
        } catch (_: LinkageError) { listOf(Evidence("native-engine", Status.UNAVAILABLE)) }
    }

    /**
     * Best-effort self-protection against the common "attach a ptrace-based tool to an already
     * running process" attack path -- NOT detection, never reports [Status], never throws. See
     * `harden_ptrace` in `engine.cpp` for the exact mechanism and its honest, explicit limits
     * (does nothing against spawn-time injection; degrades to a no-op on SELinux/Yama denial or
     * if a tracer is already present). Caller is responsible for never invoking this on a
     * debuggable build -- it would fight the developer's own debugger.
     */
    fun hardenAgainstPtraceAttach(): Boolean {
        if (!loaded) return false
        return try { hardenPtraceNative() } catch (_: LinkageError) { false }
    }

    @JvmStatic private external fun scanNative(): IntArray
    @JvmStatic private external fun hardenPtraceNative(): Boolean
}
