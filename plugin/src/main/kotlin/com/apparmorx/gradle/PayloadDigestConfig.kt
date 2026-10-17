package com.apparmorx.gradle

/** Matches runtime wire constraints; forbids delimiter and Java-properties injection in paths. */
internal fun serializePayloadDigestPins(pins: Map<String, String>): String {
    for ((path, digest) in pins) {
        require(path.length in 1..256 && path.split('/').all {
            it != "." && it != ".." && it.matches(Regex("[A-Za-z0-9_.-]+"))
        }) { "Invalid payload archive entry name" }
        require(digest.matches(Regex("[0-9a-fA-F]{64}"))) { "Payload digests must be SHA-256 hex" }
    }
    val serialized = pins.toSortedMap().entries.joinToString(",") { "${it.key}:${it.value.lowercase()}" }
    require(serialized.length <= 32768) { "Payload digest configuration too large" }
    return serialized
}
