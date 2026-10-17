package com.apparmorx.runtime

import java.util.Properties

/** Generated response configuration is mandatory. Invalid data must invalidate policy evidence. */
internal fun parseEnforcementPolicy(properties: Properties): EnforcementPolicy {
    val action = requireNotNull(properties.getProperty("restrictedAction")) { "Missing restrictedAction" }
    val unavailable = requireNotNull(properties.getProperty("enforceIndeterminate")) { "Missing enforceIndeterminate" }
    require(unavailable == "true" || unavailable == "false") { "Invalid enforceIndeterminate" }
    val failClosed = properties.optionalBoolean("failClosedOnStartup")
    val secureScreen = properties.optionalBoolean("secureScreen")
    val filterTouches = properties.optionalBoolean("filterTouches")
    val telemetryUrl = properties.getProperty("telemetryUrl", "").trim()
    val firewallClipboard = properties.optionalBoolean("firewallClipboard")
    val firewallIdentifiers = properties.optionalBoolean("firewallIdentifiers")
    val firewallLocation = properties.optionalBoolean("firewallLocation")
    val firewallNetworkSecurity = properties.optionalBoolean("firewallNetworkSecurity")
    val antiPtraceHardening = properties.optionalBoolean("antiPtraceHardening")
    val killOnConfirmedHooking = properties.optionalBoolean("killOnConfirmedHooking")
    val telemetryHmacKey = properties.getProperty("telemetryHmacKey", "").trim()
    val detailRaw = properties.getProperty("telemetryDetail", TelemetryDetail.STANDARD.name).trim()
    val telemetryDetail = TelemetryDetail.entries.firstOrNull { it.name == detailRaw }
        ?: throw IllegalArgumentException("Invalid telemetryDetail")
    val telemetryHeaders = properties.stringPropertyNames()
        .filter { it.startsWith(TELEMETRY_HEADER_PREFIX) }.sorted()
        .associate { key ->
            val name = key.removePrefix(TELEMETRY_HEADER_PREFIX)
            val value = properties.getProperty(key)
            validateTelemetryHeader(name, value)
            name to value
        }
    return EnforcementPolicy(
        restrictedAction = EnforcementAction.valueOf(action),
        enforceIndeterminate = unavailable == "true",
        failClosedOnStartup = failClosed,
        secureScreen = secureScreen,
        filterTouches = filterTouches,
        telemetryUrl = telemetryUrl,
        firewallClipboard = firewallClipboard,
        firewallIdentifiers = firewallIdentifiers,
        firewallLocation = firewallLocation,
        firewallNetworkSecurity = firewallNetworkSecurity,
        telemetryHmacKey = telemetryHmacKey,
        telemetryDetail = telemetryDetail,
        telemetryHeaders = telemetryHeaders,
        antiPtraceHardening = antiPtraceHardening,
        killOnConfirmedHooking = killOnConfirmedHooking,
    )
}

/** Missing optional fields retain legacy defaults; malformed present fields invalidate policy. */
private fun Properties.optionalBoolean(name: String): Boolean {
    val value = getProperty(name) ?: return false
    require(value == "true" || value == "false") { "Invalid $name" }
    return value == "true"
}
