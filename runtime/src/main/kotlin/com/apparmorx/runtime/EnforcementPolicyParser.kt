package com.apparmorx.runtime

import java.util.Properties

/** Generated response configuration is mandatory. Invalid data must invalidate policy evidence. */
internal fun parseEnforcementPolicy(properties: Properties): EnforcementPolicy {
    val action = requireNotNull(properties.getProperty("restrictedAction")) { "Missing restrictedAction" }
    val unavailable = requireNotNull(properties.getProperty("enforceIndeterminate")) { "Missing enforceIndeterminate" }
    require(unavailable == "true" || unavailable == "false") { "Invalid enforceIndeterminate" }
    val failClosed = properties.getProperty("failClosedOnStartup", "false") == "true"
    val secureScreen = properties.getProperty("secureScreen", "false") == "true"
    val filterTouches = properties.getProperty("filterTouches", "false") == "true"
    val telemetryUrl = properties.getProperty("telemetryUrl", "").trim()
    val firewallClipboard = properties.getProperty("firewallClipboard", "false") == "true"
    val firewallIdentifiers = properties.getProperty("firewallIdentifiers", "false") == "true"
    val firewallLocation = properties.getProperty("firewallLocation", "false") == "true"
    val firewallNetworkSecurity = properties.getProperty("firewallNetworkSecurity", "false") == "true"
    val antiPtraceHardening = properties.getProperty("antiPtraceHardening", "false") == "true"
    val killOnConfirmedHooking = properties.getProperty("killOnConfirmedHooking", "false") == "true"
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
