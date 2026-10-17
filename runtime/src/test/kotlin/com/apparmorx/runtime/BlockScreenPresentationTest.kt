package com.apparmorx.runtime

import org.junit.Assert.assertEquals
import org.junit.Test

class BlockScreenPresentationTest {
    @Test fun incompleteEvidenceMustNotBePresentedAsConfirmedFailure() {
        assertEquals(SecurityScreen.UNAVAILABLE, blockScreenPresentation(ProtectionState.INDETERMINATE))
    }
    @Test fun readyIsNotAConfirmedFailureIfPresentationIsRequestedDirectly() {
        assertEquals(SecurityScreen.UNAVAILABLE, blockScreenPresentation(ProtectionState.READY))
    }
    @Test fun startupAndConfirmedRestrictionRemainDistinct() {
        assertEquals(SecurityScreen.CHECKING, blockScreenPresentation(ProtectionState.CHECKING))
        assertEquals(SecurityScreen.RESTRICTED, blockScreenPresentation(ProtectionState.RESTRICTED))
    }
}
