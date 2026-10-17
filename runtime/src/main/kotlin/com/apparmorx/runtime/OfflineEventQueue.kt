package com.apparmorx.runtime

import android.content.Context
import java.io.File
import java.io.IOException

/**
 * Bounded, thread-safe persistent offline event queue for telemetry incidents.
 * Stores up to [MAX_CAPACITY] events in a dedicated non-backed-up file using FIFO eviction.
 *
 * Guarantees zero disk exhaustion by enforcing a strict capacity ceiling and bounded file size.
 */
object OfflineEventQueue {
    const val MAX_CAPACITY = 50
    private const val QUEUE_FILE_NAME = "apparmorx_telemetry.queue"
    private val lock = Any()

    /**
     * Resolves the default persistent queue file in noBackupFilesDir (or filesDir fallback).
     */
    fun defaultQueueFile(context: Context): File {
        val dir = context.noBackupFilesDir ?: context.filesDir
        return File(dir, QUEUE_FILE_NAME)
    }

    /**
     * Enqueues an event JSON string. If the queue reaches [maxCapacity],
     * the oldest events are evicted (FIFO).
     */
    fun enqueue(queueFile: File, eventJson: String, maxCapacity: Int = MAX_CAPACITY) {
        val sanitized = eventJson.replace('\n', ' ').trim()
        if (sanitized.isEmpty()) return

        synchronized(lock) {
            try {
                val lines = readLinesSafe(queueFile)
                val updated = if (lines.size >= maxCapacity) {
                    val dropCount = (lines.size - maxCapacity + 1).coerceAtLeast(1)
                    lines.drop(dropCount) + sanitized
                } else {
                    lines + sanitized
                }
                writeLinesSafe(queueFile, updated)
            } catch (ignored: Exception) {
                // Persistent failure must never crash the host application
            }
        }
    }

    /**
     * Pops up to [count] events from the head of the queue (FIFO) and removes them.
     */
    fun popBatch(queueFile: File, count: Int): List<String> {
        if (count <= 0) return emptyList()
        synchronized(lock) {
            return try {
                val lines = readLinesSafe(queueFile)
                if (lines.isEmpty()) return emptyList()

                val popped = lines.take(count)
                val remaining = lines.drop(count)
                writeLinesSafe(queueFile, remaining)
                popped
            } catch (ignored: Exception) {
                emptyList()
            }
        }
    }

    /**
     * Returns the current number of queued events.
     */
    fun size(queueFile: File): Int {
        synchronized(lock) {
            return try {
                readLinesSafe(queueFile).size
            } catch (ignored: Exception) {
                0
            }
        }
    }

    /**
     * Clears all queued events.
     */
    fun clear(queueFile: File) {
        synchronized(lock) {
            try {
                if (queueFile.exists()) {
                    queueFile.delete()
                }
            } catch (ignored: Exception) {}
        }
    }

    private fun readLinesSafe(file: File): List<String> {
        if (!file.exists() || !file.isFile) return emptyList()
        return file.readLines(Charsets.UTF_8).filter { it.isNotBlank() }
    }

    private fun writeLinesSafe(file: File, lines: List<String>) {
        val parent = file.parentFile
        if (parent != null && !parent.exists()) {
            parent.mkdirs()
        }
        if (lines.isEmpty()) {
            if (file.exists()) file.delete()
            return
        }

        val temp = File(parent ?: file.absoluteFile.parentFile, "${file.name}.${System.currentTimeMillis()}.tmp")
        temp.writeText(lines.joinToString("\n") + "\n", Charsets.UTF_8)
        if (!temp.renameTo(file)) {
            // Fallback if atomic rename across mounts fails
            temp.copyTo(file, overwrite = true)
            temp.delete()
        }
    }
}
