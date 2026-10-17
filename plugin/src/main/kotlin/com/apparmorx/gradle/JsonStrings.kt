package com.apparmorx.gradle

/** Quotes untrusted report text, including every JSON-forbidden ASCII control character. */
internal fun jsonQuote(text: String): String = buildString {
    append('"')
    for (c in text) when (c) {
        '"' -> append("\\\"")
        '\\' -> append("\\\\")
        '\n' -> append("\\n")
        '\r' -> append("\\r")
        '\t' -> append("\\t")
        '\b' -> append("\\b")
        '\u000c' -> append("\\f")
        else -> if (c.code < 32) append("\\u" + c.code.toString(16).padStart(4, '0')) else append(c)
    }
    append('"')
}
