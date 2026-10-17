package com.apparmorx.gradle

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.security.KeyStore
import java.security.MessageDigest

class SigningFingerprintTest {
    @get:Rule val folder = TemporaryFolder()

    private fun keystore(alias: String = "release", password: String = "s3cret-pass", type: String = "PKCS12"): File {
        val file = folder.root.resolve("release.$type")
        val java = File(System.getProperty("java.home"), "bin/keytool").path
        val process = ProcessBuilder(
            java, "-genkeypair", "-keystore", file.path, "-storetype", type, "-alias", alias,
            "-keyalg", "RSA", "-keysize", "2048", "-validity", "30", "-dname", "CN=AppArmorX Test",
            "-storepass", password, "-keypass", password,
        ).redirectErrorStream(true).start()
        val out = process.inputStream.readBytes().decodeToString()
        assertEquals(out, 0, process.waitFor())
        return file
    }

    @Test fun derivesLowercaseSha256OfTheSigningCertificate() {
        val file = keystore()
        val expected = KeyStore.getInstance("PKCS12").run {
            file.inputStream().use { load(it, "s3cret-pass".toCharArray()) }
            MessageDigest.getInstance("SHA-256").digest(getCertificate("release").encoded).joinToString("") { "%02x".format(it) }
        }
        val actual = SigningFingerprint.fromKeystore(file, "s3cret-pass", "release", "PKCS12")
        assertEquals(expected, actual)
        assertTrue(actual.matches(Regex("[0-9a-f]{64}")))
    }

    @Test fun wrongPasswordFailsWithoutLeakingIt() {
        val file = keystore()
        val error = runCatching { SigningFingerprint.fromKeystore(file, "WRONG-PASSWORD-123", "release", "PKCS12") }.exceptionOrNull()
        assertTrue(error != null)
        assertTrue(!error!!.message!!.contains("WRONG-PASSWORD-123"))
    }

    @Test fun missingAliasIsAnExplicitError() {
        val file = keystore()
        val error = runCatching { SigningFingerprint.fromKeystore(file, "s3cret-pass", "nope", "PKCS12") }.exceptionOrNull()
        assertTrue(error!!.message!!.contains("alias"))
    }

    @Test fun missingKeystoreFileIsAnExplicitError() {
        val error = runCatching { SigningFingerprint.fromKeystore(folder.root.resolve("absent.jks"), "x", "a", null) }.exceptionOrNull()
        assertTrue(error!!.message!!.contains("not found"))
    }
}
