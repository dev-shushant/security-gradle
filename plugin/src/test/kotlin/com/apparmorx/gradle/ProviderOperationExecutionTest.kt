package com.apparmorx.gradle

import org.junit.Assert.*
import org.junit.Test
import org.objectweb.asm.*
import java.lang.reflect.InvocationTargetException

/** Executes the same hierarchy dispatcher used by AGP, with tiny independent Android/JNI-free stubs. */
class ProviderOperationExecutionTest {
    private class Definitions : ClassLoader(ProviderOperationExecutionTest::class.java.classLoader) {
        fun define(name: String, bytes: ByteArray): Class<*> = defineClass(name, bytes, 0, bytes.size)
    }
    private fun bytes(name: String, parent: String = "java/lang/Object", body: ClassWriter.() -> Unit = {}): ByteArray {
        val w = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        w.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, name, null, parent, null)
        w.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null).apply {
            visitCode(); visitVarInsn(Opcodes.ALOAD, 0)
            visitMethodInsn(Opcodes.INVOKESPECIAL, parent, "<init>", "()V", false)
            visitInsn(Opcodes.RETURN); visitMaxs(0, 0); visitEnd()
        }
        w.body(); w.visitEnd(); return w.toByteArray()
    }
    private val operations = listOf(
        "getType" to "(Landroid/net/Uri;)Ljava/lang/String;",
        "delete" to "(Landroid/net/Uri;Ljava/lang/String;[Ljava/lang/String;)I",
        "refresh" to "(Landroid/net/Uri;Landroid/os/Bundle;Landroid/os/CancellationSignal;)Z",
        "call" to "(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)Landroid/os/Bundle;",
        "call" to "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)Landroid/os/Bundle;",
        "applyBatch" to "(Ljava/util/ArrayList;)[Landroid/content/ContentProviderResult;"
    )
    private fun fixture(allowed: Boolean, libraryParent: Boolean = false): Class<*> {
        val loader = Definitions()
        for (name in listOf("android/content/ContentProvider", "android/net/Uri", "android/os/Bundle",
            "android/os/CancellationSignal", "android/content/ContentProviderResult")) loader.define(name.replace('/', '.'), bytes(name))
        loader.define("com.apparmorx.runtime.SecurityGuard", bytes("com/apparmorx/runtime/SecurityGuard") {
            visitField(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "allowed", "Z", null, null).visitEnd()
            visitField(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "invocations", "I", null, null).visitEnd()
            visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "allowProvider", "(Landroid/content/ContentProvider;)Z", null, null).apply {
                visitCode()
                visitFieldInsn(Opcodes.GETSTATIC, "com/apparmorx/runtime/SecurityGuard", "invocations", "I")
                visitInsn(Opcodes.ICONST_1); visitInsn(Opcodes.IADD)
                visitFieldInsn(Opcodes.PUTSTATIC, "com/apparmorx/runtime/SecurityGuard", "invocations", "I")
                visitFieldInsn(Opcodes.GETSTATIC, "com/apparmorx/runtime/SecurityGuard", "allowed", "Z")
                visitInsn(Opcodes.IRETURN); visitMaxs(0, 0); visitEnd()
            }
        }).getField("allowed").setBoolean(null, allowed)
        val owner = if (libraryParent) "com/apparmorx/fixture/vendor/LibraryProvider" else "fixture/Provider"
        val input = bytes(owner, "android/content/ContentProvider") {
            visitField(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "executed", "Z", null, null).visitEnd()
            for ((name, descriptor) in operations + listOf("onCreate" to "()Z", "shutdown" to "()V", "call" to "(Ljava/lang/String;)Ljava/lang/String;")) {
                val access = Opcodes.ACC_PUBLIC or if (libraryParent && name == "getType") Opcodes.ACC_FINAL else 0
                visitMethod(access, name, descriptor, null, null).apply {
                    visitCode(); visitInsn(Opcodes.ICONST_1)
                    visitFieldInsn(Opcodes.PUTSTATIC, owner, "executed", "Z")
                    when (Type.getReturnType(descriptor).sort) {
                        Type.VOID -> visitInsn(Opcodes.RETURN)
                        Type.INT -> { visitIntInsn(Opcodes.BIPUSH, 37); visitInsn(Opcodes.IRETURN) }
                        Type.BOOLEAN -> { visitInsn(Opcodes.ICONST_1); visitInsn(Opcodes.IRETURN) }
                        else -> { visitInsn(Opcodes.ACONST_NULL); visitInsn(Opcodes.ARETURN) }
                    }
                    visitMaxs(0, 0); visitEnd()
                }
            }
        }
        val output = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        val supers = listOf("android.content.ContentProvider")
        val all = DependencyFirewallClassVisitorFactory.allScopeVisitor(owner.replace('/', '.'), supers, output)
        ClassReader(input).accept(if (libraryParent) all else componentGuardVisitor(supers, all), 0)
        if (libraryParent) {
            loader.define(owner.replace('/', '.'), output.toByteArray())
            val child = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
            val inherited = listOf(owner.replace('/', '.'), "android.content.ContentProvider")
            ClassReader(bytes("fixture/Provider", owner)).accept(componentGuardVisitor(inherited,
                DependencyFirewallClassVisitorFactory.allScopeVisitor("fixture.Provider", inherited, child)), 0)
            return loader.define("fixture.Provider", child.toByteArray())
        }
        return loader.define("fixture.Provider", output.toByteArray())
    }
    private fun method(type: Class<*>, pair: Pair<String, String>) = type.methods.single {
        it.name == pair.first && Type.getMethodDescriptor(it) == pair.second
    }
    @Test fun restrictionThrowsBeforeHostWorkAcrossReturnShapesAndCallOverloads() {
        val type = fixture(false); val instance = type.getConstructor().newInstance()
        for (pair in operations) {
            type.getField("executed").setBoolean(null, false)
            try {
                method(type, pair).invoke(instance, *arrayOfNulls<Any>(Type.getArgumentTypes(pair.second).size))
                fail("Denied ${pair.first} returned instead of throwing SecurityException")
            } catch (failure: InvocationTargetException) { assertTrue(failure.cause is SecurityException) }
            assertFalse(type.getField("executed").getBoolean(null))
        }
    }
    @Test fun allowedCallsRetainHostBodiesAndOriginalReturnValues() {
        val type = fixture(true); val instance = type.getConstructor().newInstance()
        for (pair in operations) {
            type.getField("executed").setBoolean(null, false)
            val result = method(type, pair).invoke(instance, *arrayOfNulls<Any>(Type.getArgumentTypes(pair.second).size))
            assertTrue(type.getField("executed").getBoolean(null))
            when (Type.getReturnType(pair.second).sort) { Type.INT -> assertEquals(37, result); Type.BOOLEAN -> assertEquals(true, result); else -> assertNull(result) }
        }
    }
    @Test fun initializationCleanupAndUnrelatedOverloadsAreNotShortCircuited() {
        val type = fixture(false); val instance = type.getConstructor().newInstance()
        assertEquals(true, type.getMethod("onCreate").invoke(instance))
        type.getMethod("shutdown").invoke(instance)
        assertNull(type.getMethod("call", String::class.java).invoke(instance, "helper"))
    }
    @Test fun laterRestrictionIsNotCachedAsAnEarlierAllow() {
        val type = fixture(true); val instance = type.getConstructor().newInstance()
        val getType = method(type, operations.first())
        getType.invoke(instance, null)
        type.getField("executed").setBoolean(null, false)
        type.classLoader.loadClass("com.apparmorx.runtime.SecurityGuard").getField("allowed").setBoolean(null, false)
        try { getType.invoke(instance, null); fail("Later restriction was ignored") }
        catch (failure: InvocationTargetException) { assertTrue(failure.cause is SecurityException) }
        assertFalse(type.getField("executed").getBoolean(null))
    }

    @Test fun inheritedFinalLibraryBodyIsGuardedWithoutSynthesizingAnOverride() {
        val type = fixture(false, libraryParent = true)
        assertTrue(type.declaredMethods.isEmpty())
        val callback = method(type, operations.first())
        assertTrue(java.lang.reflect.Modifier.isFinal(callback.modifiers))
        try { callback.invoke(type.getConstructor().newInstance(), null); fail("Library provider body ran") }
        catch (failure: InvocationTargetException) { assertTrue(failure.cause is SecurityException) }
        assertFalse(type.getField("executed").getBoolean(null))
    }

    @Test fun allowedInheritedFinalMethodsKeepTheirBehavior() {
        val type = fixture(true, libraryParent = true)
        val instance = type.getConstructor().newInstance()
        assertEquals(true, type.getMethod("onCreate").invoke(instance))
        assertNull(method(type, operations.first()).invoke(instance, null))
        assertTrue(type.getField("executed").getBoolean(null))
    }

    @Test fun projectAndAllPassesDoNotDoubleGateProviderMethods() {
        val type = fixture(true)
        method(type, operations.first()).invoke(type.getConstructor().newInstance(), null)
        assertEquals(1, type.classLoader.loadClass("com.apparmorx.runtime.SecurityGuard").getField("invocations").getInt(null))
    }

    @Test fun androidxProviderSelectionDoesNotBroadenTheUnrelatedFirewallPass() {
        val provider = listOf("android.content.ContentProvider")
        assertTrue(DependencyFirewallClassVisitorFactory.isAllScopeInstrumentable("androidx.core.content.FileProvider", provider))
        assertFalse(DependencyFirewallClassVisitorFactory.isAllScopeInstrumentable("androidx.example.Other", emptyList()))
        assertFalse(DependencyFirewallClassVisitorFactory.isAllScopeInstrumentable("com.apparmorx.runtime.SecurityInitializer", provider))
        assertFalse(DependencyFirewallClassVisitorFactory.isAllScopeInstrumentable("android.content.ContentProvider", emptyList()))
    }
}
