package com.apparmorx.runtime

import org.junit.Assert.*
import org.junit.Test

class ApplicationInitializationTest {
    @Test fun allowedInitializationDoesNotPoisonTheProcess() {
        val initialization = ApplicationInitialization()
        initialization.recordDecision(true)
        assertFalse(initialization.requiresRestart())
    }

    @Test fun deniedInitializationCannotBeRepairedByALaterAllowDecision() {
        val initialization = ApplicationInitialization()
        initialization.recordDecision(false)
        initialization.recordDecision(true)
        assertTrue(initialization.requiresRestart())
    }

    @Test fun onlyANewProcessHasAnUnlatchedInitializationState() {
        val oldProcess = ApplicationInitialization()
        oldProcess.recordDecision(false)
        assertTrue(oldProcess.requiresRestart())
        assertFalse(ApplicationInitialization().requiresRestart())
    }
}
