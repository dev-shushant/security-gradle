package com.apparmorx.runtime

/** Single-thread confined scheduler. Generation tokens make already queued callbacks harmless. */
internal class ForegroundMonitor(
    private val schedule: (() -> Unit) -> Unit,
    private val refresh: () -> Unit,
) {
    private var active = false
    private var generation = 0L

    fun start() {
        if (active) return
        active = true
        val token = ++generation
        tick(token)
    }

    fun stop() {
        active = false
        generation++
    }

    private fun tick(token: Long) {
        if (!active || token != generation) return
        refresh()
        schedule { tick(token) }
    }
}
