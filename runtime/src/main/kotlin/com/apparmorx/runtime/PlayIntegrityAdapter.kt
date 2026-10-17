package com.apparmorx.runtime

import android.content.Context
import java.security.MessageDigest

/**
 * Zero-overhead Google Play Integrity API adapter.
 * Uses reflection-based invocation to dynamically bind standard/classic integrity requests
 * without creating a hard dependency on Play Services libraries.
 *
 * Authored by Shushant Tiwari • com.apparmorx
 */
object PlayIntegrityAdapter {

    data class IntegrityTokenResult(
        val token: String?,
        val isAvailable: Boolean,
        val errorMessage: String? = null
    )

    /**
     * Checks whether Google Play Integrity client library is present on the runtime classpath.
     */
    val isClientLibraryPresent: Boolean by lazy {
        try {
            Class.forName("com.google.android.play.core.integrity.IntegrityManagerFactory")
            true
        } catch (_: ClassNotFoundException) {
            false
        }
    }

    /**
     * Computes a SHA-256 requestHash for binding sensitive business transactions to an integrity request.
     */
    fun hashTransaction(data: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(data)
        return digest.joinToString("") { "%02x".format(it) }
    }
}
