package com.apparmorx.runtime

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * [rootPathStatus] must distinguish "genuinely absent" from "could not determine" (permission denied,
 * or any other I/O failure), per the project's own rule: platform visibility restriction is never
 * silently treated as clean. Reproduced live: on a stock AVD, /system/xbin/su exists (mode 4750,
 * root:shell) but `stat()` from an app's own SELinux/POSIX context returns EACCES, not ENOENT --
 * a naive `File.exists()` (which swallows that distinction) reports CLEAR instead of UNAVAILABLE.
 */
class RootPathStatusTest {
    @Test fun allPathsGenuinelyAbsentIsClear() {
        val status = rootPathStatus(listOf("/a", "/b")) { PathCheck.Absent }
        assertEquals(Status.CLEAR, status)
    }

    @Test fun anyPathPresentIsDetectedEvenIfAnotherIsDenied() {
        val status = rootPathStatus(listOf("/a", "/b")) { path -> if (path == "/a") PathCheck.Denied else PathCheck.Present }
        assertEquals(Status.DETECTED, status)
    }

    @Test fun deniedAccessWithNoConfirmedPresenceIsUnavailableNotClear() {
        // Reproduces the real EACCES-on-/system/xbin/su case: we could not actually verify this path,
        // so we must not report CLEAR just because no exception was thrown.
        val status = rootPathStatus(listOf("/system/xbin/su")) { PathCheck.Denied }
        assertEquals(Status.UNAVAILABLE, status)
    }

    @Test fun mixOfAbsentAndDeniedWithNoPresenceIsUnavailable() {
        val status = rootPathStatus(listOf("/a", "/b", "/c")) { path -> if (path == "/b") PathCheck.Denied else PathCheck.Absent }
        assertEquals(Status.UNAVAILABLE, status)
    }

    @Test fun emptyPathListIsClear() {
        assertEquals(Status.CLEAR, rootPathStatus(emptyList()) { PathCheck.Absent })
    }
}
