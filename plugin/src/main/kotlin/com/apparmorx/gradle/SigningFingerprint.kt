package com.apparmorx.gradle

import java.io.File
import java.security.KeyStore
import java.security.MessageDigest

/**
 * Derives the signer pin from the app's own release signing configuration so developers do not have
 * to copy a fingerprint by hand. The pin is a public certificate digest, so it is safe to embed; the
 * keystore password is only used at build time and never written to any output.
 */
object SigningFingerprint {
    fun fromKeystore(file: File, password: String, alias: String, type: String?): String {
        require(file.isFile) { "Signing keystore not found: ${file.name}" }
        val store = try {
            KeyStore.getInstance(type ?: KeyStore.getDefaultType()).also { ks ->
                file.inputStream().use { ks.load(it, password.toCharArray()) }
            }
        } catch (e: Exception) {
            // Never include the password or the underlying message (some providers echo input).
            throw IllegalStateException("Could not open signing keystore ${file.name} to derive the signer pin (check storePassword/storeType)")
        }
        val certificate = store.getCertificate(alias)
            ?: throw IllegalStateException("Signing keystore ${file.name} has no certificate for key alias '$alias'")
        return MessageDigest.getInstance("SHA-256").digest(certificate.encoded).joinToString("") { "%02x".format(it) }
    }
}
