package com.apparmorx.runtime

import java.util.concurrent.atomic.AtomicBoolean

/** A skipped Application body cannot be replayed by a later scan or Activity recreation. */
internal class ApplicationInitialization {
    private val denied = AtomicBoolean(false)

    fun recordDecision(allowed: Boolean) {
        if (!allowed) denied.set(true)
    }

    fun requiresRestart(): Boolean = denied.get()
}

/** Never reset in production: only a new process can safely run Application initialization again. */
internal val applicationInitialization = ApplicationInitialization()
