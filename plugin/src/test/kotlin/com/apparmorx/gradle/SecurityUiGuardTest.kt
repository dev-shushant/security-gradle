package com.apparmorx.gradle

import org.junit.Assert.*
import org.junit.Test

class SecurityUiGuardTest {
    @Test fun recoveryScreenHierarchyIsExcludedButOrdinaryActivitiesAreNot() {
        assertTrue(isSecurityUiHierarchy(listOf("com.apparmorx.runtime.SecurityBlockActivity", "android.app.Activity")))
        assertFalse(isSecurityUiHierarchy(listOf("android.app.Activity")))
        assertFalse(isSecurityUiHierarchy(listOf("example.SecurityBlockActivity")))
    }
}
