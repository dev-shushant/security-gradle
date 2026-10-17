package com.apparmorx.runtime

import java.util.Properties

/** Null pins mean invalid configuration, while an empty map means intentionally unpinned. */
internal data class ScanConfiguration(
    val enforcement: EnforcementPolicy,
    val payloadDigests: Map<String, String>?,
    val applicationId: String?,
) {
    fun policyEvidence(actualId: String?, expires: Long, nowSeconds: Long): Evidence = Evidence("policy",
        if (payloadDigests != null && applicationIdentityEvidence(actualId, applicationId).status != Status.UNAVAILABLE &&
            (expires == 0L || expires > nowSeconds)) Status.CLEAR else Status.UNAVAILABLE)
}

/** A pin-format error must not erase a separately valid host response or skip independent probes. */
internal fun parseScanConfiguration(properties: Properties): ScanConfiguration {
    val enforcement = parseEnforcementPolicy(properties)
    val pins = try {
        parsePayloadDigestPins(properties.getProperty("payloadDigests"))
    } catch (_: IllegalArgumentException) {
        null
    }
    return ScanConfiguration(enforcement, pins, properties.getProperty("applicationId"))
}

// Android application IDs have at least two ASCII segments; each starts with a letter.
private val APPLICATION_ID = Regex("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+")

/** Missing/malformed identity is an evidence gap, not proof that the app was repackaged. */
internal fun applicationIdentityEvidence(actual: String?, expected: String?): Evidence = Evidence("application-id", when {
    actual == null || expected == null || !APPLICATION_ID.matches(actual) || !APPLICATION_ID.matches(expected) -> Status.UNAVAILABLE
    actual == expected -> Status.CLEAR
    else -> Status.DETECTED
})
