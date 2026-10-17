package com.apparmorx.runtime

/** Strict parsing: a configured pin must never silently disappear or overwrite another pin. */
internal fun parsePayloadDigestPins(raw: String?): Map<String, String> {
    if (raw == null || raw.isEmpty()) return emptyMap()
    require(raw.length <= 32768) { "Payload digest configuration too large" }
    val result = linkedMapOf<String, String>()
    for (pin in raw.split(',')) {
        val parts = pin.split(':')
        require(parts.size == 2) { "Malformed payload digest pin" }
        val (path, digest) = parts
        require(path.length in 1..256 && path.split('/').all {
            it != "." && it != ".." && it.matches(Regex("[A-Za-z0-9_.-]+"))
        }) { "Invalid payload archive entry name" }
        require(digest.matches(Regex("[0-9a-fA-F]{64}"))) { "Payload digest must be SHA-256 hex" }
        require(path !in result) { "Duplicate payload archive entry" }
        result[path] = digest.lowercase()
    }
    return result
}

/** Missing valid policy/pin parsing leaves integrity unknown, never an unpinned CLEAR result. */
internal fun payloadIntegrityEvidence(apk: java.io.File, pins: Map<String, String>?): Evidence =
    if (pins == null) Evidence("apk-integrity", Status.UNAVAILABLE)
    else probe("apk-integrity") { !ApkIntegrityVerifier.verify(apk, pins) }
