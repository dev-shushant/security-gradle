package com.apparmorx.runtime

import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class TelemetryDispatcherTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test
    fun formatsSecurityEventJsonCorrectly() {
        val event = SecurityEvent(
            eventId = "test-uuid-1234",
            timestampSeconds = 1700000000L,
            applicationId = "com.apparmorx.sample",
            policySequence = 42L,
            detectedChecks = listOf("native-tracer", "root-path"),
            osVersion = 35,
            abi = "arm64-v8a"
        )
        val json = event.toJson()
        assertTrue(json.contains(""""eventId":"test-uuid-1234""""))
        assertTrue(json.contains(""""applicationId":"com.apparmorx.sample""""))
        assertTrue(json.contains(""""policySequence":42"""))
        assertTrue(json.contains(""""detectedChecks":["native-tracer","root-path"]"""))
        assertTrue(json.contains(""""osVersion":35"""))
        assertTrue(json.contains(""""abi":"arm64-v8a""""))
    }

    @Test
    fun rejectsNonHttpsTelemetryEndpoint() {
        assertThrows(IllegalArgumentException::class.java) {
            TelemetryDispatcher.sendHttpsPost("http://insecure.example.com/events", "{}")
        }
    }

    @Test
    fun computesHmacSha256Deterministically() {
        val secret = "my-super-secret-key-123"
        val payload = "1700000000.{\"eventId\":\"abc\"}"
        val hmac1 = TelemetryDispatcher.computeHmacSha256(secret, payload)
        val hmac2 = TelemetryDispatcher.computeHmacSha256(secret, payload)

        assertEquals(hmac1, hmac2)
        assertEquals(64, hmac1.length) // 256 bits = 64 hex chars
        assertTrue(hmac1.matches(Regex("[0-9a-f]{64}")))

        // Different payload yields different signature
        val hmacDifferent = TelemetryDispatcher.computeHmacSha256(secret, "different")
        assertNotEquals(hmac1, hmacDifferent)
    }

    @Test
    fun calculatesExponentialBackoffCorrectly() {
        assertEquals(5000L, TelemetryDispatcher.calculateBackoff(1))
        assertEquals(10000L, TelemetryDispatcher.calculateBackoff(2))
        assertEquals(20000L, TelemetryDispatcher.calculateBackoff(3))
        assertEquals(40000L, TelemetryDispatcher.calculateBackoff(4))
        assertEquals(80000L, TelemetryDispatcher.calculateBackoff(5))
        assertEquals(160000L, TelemetryDispatcher.calculateBackoff(6))
        assertEquals(300000L, TelemetryDispatcher.calculateBackoff(7))
        assertEquals(300000L, TelemetryDispatcher.calculateBackoff(10))
    }

    @Test
    fun offlineEventQueueEnforcesCapacityAndFifoEviction() {
        val queueFile = File(tempFolder.root, "test.queue")
        assertEquals(0, OfflineEventQueue.size(queueFile))

        // Enqueue 5 items with capacity ceiling of 3
        OfflineEventQueue.enqueue(queueFile, "event-1", maxCapacity = 3)
        OfflineEventQueue.enqueue(queueFile, "event-2", maxCapacity = 3)
        OfflineEventQueue.enqueue(queueFile, "event-3", maxCapacity = 3)
        assertEquals(3, OfflineEventQueue.size(queueFile))

        OfflineEventQueue.enqueue(queueFile, "event-4", maxCapacity = 3)
        assertEquals(3, OfflineEventQueue.size(queueFile))

        OfflineEventQueue.enqueue(queueFile, "event-5", maxCapacity = 3)
        assertEquals(3, OfflineEventQueue.size(queueFile))

        // Oldest (1, 2) were evicted; remaining should be 3, 4, 5
        val popped = OfflineEventQueue.popBatch(queueFile, count = 2)
        assertEquals(listOf("event-3", "event-4"), popped)
        assertEquals(1, OfflineEventQueue.size(queueFile))

        val last = OfflineEventQueue.popBatch(queueFile, count = 10)
        assertEquals(listOf("event-5"), last)
        assertEquals(0, OfflineEventQueue.size(queueFile))
    }

    @Test
    fun offlineEventQueueClearsReliably() {
        val queueFile = File(tempFolder.root, "clear_test.queue")
        OfflineEventQueue.enqueue(queueFile, "ev1")
        OfflineEventQueue.enqueue(queueFile, "ev2")
        assertEquals(2, OfflineEventQueue.size(queueFile))

        OfflineEventQueue.clear(queueFile)
        assertEquals(0, OfflineEventQueue.size(queueFile))
        assertFalse(queueFile.exists())
    }
}
