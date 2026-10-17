package com.apparmorx.gradle

import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.zip.ZipInputStream

/** The Plugin Portal only serves the plugin, so the runtime must travel inside the plugin jar. */
class BundledRuntimeTest {
    private fun entries(): Set<String> {
        val stream = ExtractRuntimeAar::class.java.getResourceAsStream(ExtractRuntimeAar.RESOURCE)
        assertNotNull("runtime AAR must be embedded in the plugin", stream)
        return stream!!.use { raw ->
            ZipInputStream(raw).use { zip -> generateSequence { zip.nextEntry }.map { it.name }.toSet() }
        }
    }

    @Test fun embeddedAarContainsClassesManifestAndBothNativeEngines() {
        val e = entries()
        assertTrue(e.toString(), "classes.jar" in e)
        assertTrue("AndroidManifest.xml" in e)
        assertTrue("jni/arm64-v8a/libapparmorx.so" in e)
        assertTrue("jni/x86_64/libapparmorx.so" in e)
    }

    @Test fun embeddedAarDeclaresConsumerShrinkerRules() {
        assertTrue("proguard.txt" in entries())
    }
}
