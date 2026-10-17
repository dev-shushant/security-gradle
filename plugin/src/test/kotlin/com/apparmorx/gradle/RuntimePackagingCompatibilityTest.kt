package com.apparmorx.gradle

import org.junit.Assert.*
import org.junit.Test
import org.objectweb.asm.AnnotationVisitor
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.Opcodes
import java.io.ByteArrayInputStream
import java.util.Properties
import java.util.zip.ZipInputStream

/** Prevent the bundled runtime from silently raising a consumer's Kotlin compiler floor. */
class RuntimePackagingCompatibilityTest {
    @Test fun bundledRuntimeAndHostStdlibRemainReadableByKotlin22() {
        val properties = Properties().apply {
            requireNotNull(RuntimePackagingCompatibilityTest::class.java.getResourceAsStream("/apparmorx-version.properties")).use { load(it) }
        }
        val version = properties.getProperty("kotlin").split('.').map(String::toInt)
        assertTrue("Host stdlib must not require Kotlin newer than 2.2", version[0] < 2 || version[0] == 2 && version[1] <= 2)
        val aar = requireNotNull(javaClass.getResourceAsStream("/apparmorx/runtime.aar")).use { it.readBytes() }
        var classes: ByteArray? = null
        ZipInputStream(ByteArrayInputStream(aar)).use { zip ->
            while (true) {
                val entry = zip.nextEntry ?: break
                if (entry.name == "classes.jar") classes = zip.readBytes()
            }
        }
        var metadataClasses = 0
        ZipInputStream(ByteArrayInputStream(requireNotNull(classes))).use { zip ->
            while (true) {
                val entry = zip.nextEntry ?: break
                if (!entry.name.endsWith(".class")) continue
                ClassReader(zip.readBytes()).accept(object : ClassVisitor(Opcodes.ASM9) {
                    override fun visitAnnotation(descriptor: String, visible: Boolean): AnnotationVisitor? {
                        if (descriptor != "Lkotlin/Metadata;") return null
                        return object : AnnotationVisitor(Opcodes.ASM9) {
                            override fun visit(name: String, value: Any) {
                                if (name != "mv") return
                                val metadata = value as IntArray
                                metadataClasses++
                                assertTrue("${entry.name} has incompatible metadata ${metadata.toList()}",
                                    metadata[0] < 2 || metadata[0] == 2 && metadata[1] <= 2)
                            }
                        }
                    }
                }, ClassReader.SKIP_CODE or ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)
            }
        }
        assertTrue("Must inspect actual bundled Kotlin classes", metadataClasses > 0)
    }
}
