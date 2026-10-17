package com.apparmorx.runtime

import org.junit.Assert.*
import org.junit.Test

class ForegroundMonitorTest {
    @Test fun repeatedStartDoesNotDuplicateAndStopInvalidatesQueuedTicks() {
        val queued = mutableListOf<() -> Unit>()
        var scans = 0
        val monitor = ForegroundMonitor({ queued += it }, { scans++ })
        monitor.start(); monitor.start()
        assertEquals(1, scans)
        assertEquals(1, queued.size)
        monitor.stop()
        queued.removeAt(0).invoke()
        assertEquals(1, scans)
        assertTrue(queued.isEmpty())
    }
    @Test fun restartDoesNotReviveOldGeneration() {
        val queued = mutableListOf<() -> Unit>()
        var scans = 0
        val monitor = ForegroundMonitor({ queued += it }, { scans++ })
        monitor.start(); monitor.stop(); monitor.start()
        queued.removeAt(0).invoke()
        assertEquals(2, scans)
        queued.removeAt(0).invoke()
        assertEquals(3, scans)
        assertEquals(1, queued.size)
    }
}
