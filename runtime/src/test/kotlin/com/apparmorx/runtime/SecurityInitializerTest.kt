package com.apparmorx.runtime

import org.junit.Assert.*
import org.junit.Test

class SecurityInitializerTest {

    @Test
    fun callGetSecurityStateReturnsNonNullBundle() {
        val initializer = SecurityInitializer()
        val bundle = initializer.call("getSecurityState", null, null)
        assertNotNull(bundle)
    }

    @Test
    fun callUnsupportedMethodReturnsNull() {
        val initializer = SecurityInitializer()
        val bundle = initializer.call("unsupportedMethod", null, null)
        assertNull(bundle)
    }
}
