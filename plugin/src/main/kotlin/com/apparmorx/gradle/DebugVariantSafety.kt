package com.apparmorx.gradle

/** Report effective debug settings consistently with generated policy's mandatory overrides. */
internal fun debugSafeSetting(key: String, configured: String, debuggable: Boolean): String = when {
    !debuggable -> configured
    key == "restrictedAction" -> "OBSERVE"
    key in setOf("failClosedOnStartup", "antiPtraceHardening", "killOnConfirmedHooking") -> "false"
    else -> configured
}
