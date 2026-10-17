package com.apparmorx.runtime

/** Presentation only; choosing a screen cannot grant access or create a resume ticket. */
internal fun blockScreenPresentation(state: ProtectionState): SecurityScreen =
    when (state) {
        ProtectionState.CHECKING -> SecurityScreen.CHECKING
        ProtectionState.RESTRICTED -> SecurityScreen.RESTRICTED
        ProtectionState.INDETERMINATE, ProtectionState.READY -> SecurityScreen.UNAVAILABLE
    }
