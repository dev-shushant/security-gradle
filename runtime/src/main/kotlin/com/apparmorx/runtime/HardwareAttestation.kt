package com.apparmorx.runtime

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.cert.X509Certificate

/**
 * Hardware-backed key attestation engine and cryptographic transaction signing.
 * Provides hardware root-of-trust verification via Android Keystore TEE / StrongBox Keymaster.
 *
 * Implements hardware key attestation according to OWASP MASVS-RESILIENCE and Android Keystore standards.
 * Authored by Shushant Tiwari • com.apparmorx
 */
object HardwareAttestation {

    const val DEFAULT_KEY_ALIAS = "apparmorx_hardware_attestation"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"

    sealed class AttestationResult {
        data class Success(
            val keyAlias: String,
            val certificateChain: List<ByteArray>,
            val isHardwareBacked: Boolean,
            val isStrongBox: Boolean,
            val securityLevel: String
        ) : AttestationResult()

        data class Unsupported(val reason: String) : AttestationResult()
        data class Failure(val error: String) : AttestationResult()
    }

    /**
     * Generates a hardware-attested EC P-256 key pair in the Android KeyStore bound to [challenge].
     * The resulting certificate chain can be verified off-device by an authentication server.
     */
    fun generateAttestedKey(
        context: Context,
        challenge: ByteArray,
        keyAlias: String = DEFAULT_KEY_ALIAS,
        preferStrongBox: Boolean = true
    ): AttestationResult {
        if (challenge.isEmpty() || challenge.size > 128) {
            return AttestationResult.Failure("Challenge must be between 1 and 128 bytes")
        }

        return try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (keyStore.containsAlias(keyAlias)) {
                keyStore.deleteEntry(keyAlias)
            }

            // Attempt StrongBox if available and requested (Android 9.0+ / API 28+)
            val isStrongBox = if (preferStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                try {
                    generateKeyPair(keyAlias, challenge, useStrongBox = true)
                    true
                } catch (_: Exception) {
                    generateKeyPair(keyAlias, challenge, useStrongBox = false)
                    false
                }
            } else {
                generateKeyPair(keyAlias, challenge, useStrongBox = false)
                false
            }

            val chain = keyStore.getCertificateChain(keyAlias)
            if (chain.isNullOrEmpty()) {
                return AttestationResult.Failure("Keystore did not produce an attestation certificate chain")
            }

            val leafCert = chain[0] as? X509Certificate
                ?: return AttestationResult.Failure("Leaf certificate is not an X509Certificate")

            val extensionBytes = leafCert.getExtensionValue(ATTESTATION_OID)
            val isAttested = extensionBytes != null

            val chainEncoded = chain.map { it.encoded }

            AttestationResult.Success(
                keyAlias = keyAlias,
                certificateChain = chainEncoded,
                isHardwareBacked = isAttested,
                isStrongBox = isStrongBox,
                securityLevel = if (isStrongBox) "STRONGBOX" else if (isAttested) "TEE" else "SOFTWARE"
            )
        } catch (e: Exception) {
            AttestationResult.Failure(e.message ?: "Key generation failed")
        }
    }

    private fun generateKeyPair(alias: String, challenge: ByteArray, useStrongBox: Boolean) {
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        val specBuilder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(challenge)

        if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            specBuilder.setIsStrongBoxBacked(true)
        }

        kpg.initialize(specBuilder.build())
        kpg.generateKeyPair()
    }

    /**
     * Signs transaction or authorization payload using the hardware-backed private key.
     */
    fun signPayload(keyAlias: String, payload: ByteArray): ByteArray? {
        return try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            val entry = keyStore.getEntry(keyAlias, null) as? KeyStore.PrivateKeyEntry ?: return null
            val signature = Signature.getInstance("SHA256withECDSA").apply {
                initSign(entry.privateKey)
                update(payload)
            }
            signature.sign()
        } catch (_: Exception) {
            null
        }
    }
}
