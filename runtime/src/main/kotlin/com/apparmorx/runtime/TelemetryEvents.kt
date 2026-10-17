package com.apparmorx.runtime

internal const val TELEMETRY_HEADER_PREFIX = "telemetryHeader."
internal const val TELEMETRY_SCHEMA_VERSION = 2

/**
 * How much a report says about the app and device. The endpoint is always customer-owned and opt-in.
 * No level ever includes user data, advertising/device identifiers, location, memory or stack traces.
 *
 * - [MINIMAL]: threat check ids, OS level and ABI only.
 * - [STANDARD] (default): adds what is needed to triage an incident: app version, protection state,
 *   the response taken, checks that could not run, and advisory findings.
 * - [EXTENDED]: adds coarse device facts (manufacturer, model, patch level, installer) and every check's result.
 */
enum class TelemetryDetail { MINIMAL, STANDARD, EXTENDED }

private val HEADER_NAME = Regex("[A-Za-z0-9-]{1,64}")
private val HEADER_VALUE = Regex("[A-Za-z0-9._~+/=: -]{1,512}")
private val RESERVED_HEADERS = setOf("host", "content-type", "content-length", "user-agent", "connection", "transfer-encoding")

/** Shared rule (the Gradle plugin enforces the same at build time): custom headers may never forge ours. */
internal fun validateTelemetryHeader(name: String, value: String?) {
    require(HEADER_NAME.matches(name)) { "Invalid telemetry header name" }
    val lower = name.lowercase()
    require(lower !in RESERVED_HEADERS && !lower.startsWith("x-apparmorx-")) { "Reserved telemetry header" }
    require(value != null && HEADER_VALUE.matches(value)) { "Invalid telemetry header value" }
}

internal fun jsonEscape(value: String): String = buildString(value.length + 2) {
    for (c in value) when {
        c == '"' -> append("\\\"")
        c == '\\' -> append("\\\\")
        c == '\n' -> append("\\n")
        c == '\r' -> append("\\r")
        c == '\t' -> append("\\t")
        c < ' ' -> append("\\u%04x".format(c.code))
        else -> append(c)
    }
}

/** Privacy-preserving security report (schema v2). Optional fields are omitted unless the detail level allows them. */
data class SecurityEvent(
    val eventId: String,
    val timestampSeconds: Long,
    val applicationId: String,
    val policySequence: Long,
    val detectedChecks: List<String>,
    val osVersion: Int,
    val abi: String,
    val eventType: String = "incident",
    val protectionState: String? = null,
    val enforcementAction: String? = null,
    val unavailableChecks: List<String>? = null,
    val advisoryFindings: List<String>? = null,
    val appVersionName: String? = null,
    val appVersionCode: Long? = null,
    val debuggableBuild: Boolean? = null,
    val manufacturer: String? = null,
    val model: String? = null,
    val securityPatch: String? = null,
    val installer: String? = null,
    val checks: Map<String, String>? = null,
) {
    private fun list(values: List<String>) = values.joinToString(",", "[", "]") { "\"${jsonEscape(it)}\"" }

    fun toJson(): String = buildString {
        append("{")
        append("\"schemaVersion\":$TELEMETRY_SCHEMA_VERSION,")
        append("\"eventType\":\"${jsonEscape(eventType)}\",")
        append("\"eventId\":\"${jsonEscape(eventId)}\",")
        append("\"timestampSeconds\":$timestampSeconds,")
        append("\"applicationId\":\"${jsonEscape(applicationId)}\",")
        append("\"policySequence\":$policySequence,")
        append("\"detectedChecks\":${list(detectedChecks)},")
        append("\"osVersion\":$osVersion,")
        append("\"abi\":\"${jsonEscape(abi)}\"")
        protectionState?.let { append(",\"protectionState\":\"${jsonEscape(it)}\"") }
        enforcementAction?.let { append(",\"enforcementAction\":\"${jsonEscape(it)}\"") }
        unavailableChecks?.let { append(",\"unavailableChecks\":${list(it)}") }
        advisoryFindings?.let { append(",\"advisoryFindings\":${list(it)}") }
        appVersionName?.let { append(",\"appVersionName\":\"${jsonEscape(it)}\"") }
        appVersionCode?.let { append(",\"appVersionCode\":$it") }
        debuggableBuild?.let { append(",\"debuggableBuild\":$it") }
        manufacturer?.let { append(",\"manufacturer\":\"${jsonEscape(it)}\"") }
        model?.let { append(",\"model\":\"${jsonEscape(it)}\"") }
        securityPatch?.let { append(",\"securityPatch\":\"${jsonEscape(it)}\"") }
        installer?.let { append(",\"installer\":\"${jsonEscape(it)}\"") }
        checks?.let { append(",\"checks\":{${it.entries.joinToString(",") { e -> "\"${jsonEscape(e.key)}\":\"${jsonEscape(e.value)}\"" }}}") }
        append("}")
    }
}

internal object TelemetryEvents {
    data class Environment(
        val applicationId: String, val appVersionName: String, val appVersionCode: Long, val debuggable: Boolean,
        val sdkInt: Int, val abi: String, val manufacturer: String, val model: String,
        val securityPatch: String, val installer: String,
    )

    /** Confirmed threat checks only: advisory configuration findings never create an incident. */
    fun incidentChecks(snapshot: SecuritySnapshot): List<String> =
        snapshot.evidence.filter { it.status == Status.DETECTED && it.check !in ADVISORY_CHECKS }.map { it.check }

    fun build(
        eventId: String, nowMillis: Long, snapshot: SecuritySnapshot, state: ProtectionState,
        env: Environment, detail: TelemetryDetail,
    ): SecurityEvent {
        val base = SecurityEvent(
            eventId = eventId, timestampSeconds = nowMillis / 1000, applicationId = env.applicationId,
            policySequence = snapshot.policySequence, detectedChecks = incidentChecks(snapshot),
            osVersion = env.sdkInt, abi = env.abi,
        )
        if (detail == TelemetryDetail.MINIMAL) return base
        val standard = base.copy(
            protectionState = state.name,
            enforcementAction = resolveEnforcementAction(state, snapshot.enforcement).name,
            unavailableChecks = snapshot.evidence.filter { it.status == Status.UNAVAILABLE }.map { it.check },
            advisoryFindings = snapshot.evidence.filter { it.status == Status.DETECTED && it.check in ADVISORY_CHECKS }.map { it.check },
            appVersionName = env.appVersionName, appVersionCode = env.appVersionCode, debuggableBuild = env.debuggable,
        )
        if (detail == TelemetryDetail.STANDARD) return standard
        return standard.copy(
            manufacturer = env.manufacturer, model = env.model, securityPatch = env.securityPatch, installer = env.installer,
            checks = snapshot.evidence.associate { it.check to it.status.name },
        )
    }
}
