package com.apparmorx.gradle

import org.junit.Assert.*
import org.junit.Test
import org.objectweb.asm.*

/** Executes transformed classes in a JVM with tiny framework/guard stubs; checks real control flow. */
class ServiceCallbackExecutionTest {
    private class Definitions : ClassLoader(ServiceCallbackExecutionTest::class.java.classLoader) {
        fun define(name: String, bytes: ByteArray): Class<*> = defineClass(name, bytes, 0, bytes.size)
    }

    private fun classBytes(name: String, parent: String = "java/lang/Object", body: ClassWriter.() -> Unit = {}): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, name, null, parent, null)
        writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null).apply {
            visitCode(); visitVarInsn(Opcodes.ALOAD, 0)
            visitMethodInsn(Opcodes.INVOKESPECIAL, parent, "<init>", "()V", false)
            visitInsn(Opcodes.RETURN); visitMaxs(0,0); visitEnd()
        }
        writer.body(); writer.visitEnd(); return writer.toByteArray()
    }

    private fun fixture(allowed: Boolean, inheritStart: Boolean = false): Pair<Class<*>, Class<*>> {
        val loader = Definitions()
        loader.define("android.content.Intent", classBytes("android/content/Intent"))
        loader.define("android.os.IBinder", classBytes("android/os/IBinder"))
        loader.define("android.app.Service", classBytes("android/app/Service") {
            visitField(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "baseExecuted", "Z", null, null).visitEnd()
            visitMethod(Opcodes.ACC_PUBLIC, "onCreate", "()V", null, null).apply {
                visitCode(); visitInsn(Opcodes.RETURN); visitMaxs(0,0); visitEnd()
            }
            visitMethod(Opcodes.ACC_PUBLIC, "onStartCommand", "(Landroid/content/Intent;II)I", null, null).apply {
                visitCode(); visitInsn(Opcodes.ICONST_1)
                visitFieldInsn(Opcodes.PUTSTATIC, "android/app/Service", "baseExecuted", "Z")
                visitIntInsn(Opcodes.BIPUSH, 99); visitInsn(Opcodes.IRETURN); visitMaxs(0,0); visitEnd()
            }
        })
        loader.define("com.apparmorx.runtime.SecurityGuard", classBytes("com/apparmorx/runtime/SecurityGuard") {
            visitField(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "allowed", "Z", null, null).visitEnd()
            visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null).apply {
                visitCode(); visitInsn(if (allowed) Opcodes.ICONST_1 else Opcodes.ICONST_0)
                visitFieldInsn(Opcodes.PUTSTATIC, "com/apparmorx/runtime/SecurityGuard", "allowed", "Z")
                visitInsn(Opcodes.RETURN); visitMaxs(0,0); visitEnd()
            }
            visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "allowService", "(Landroid/app/Service;)Z", null, null).apply {
                visitCode(); visitFieldInsn(Opcodes.GETSTATIC, "com/apparmorx/runtime/SecurityGuard", "allowed", "Z")
                visitInsn(Opcodes.IRETURN); visitMaxs(0,0); visitEnd()
            }
        })
        val bytes = classBytes("fixture/ProtectedService", "android/app/Service") {
            visitField(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "executed", "Z", null, null).visitEnd()
            for ((name, descriptor) in listOf("onCreate" to "()V", "onStartCommand" to "(Landroid/content/Intent;II)I",
                "onBind" to "(Landroid/content/Intent;)Landroid/os/IBinder;",
                "onRebind" to "(Landroid/content/Intent;)V", "onStart" to "(Landroid/content/Intent;I)V",
                "onDestroy" to "()V", "onUnbind" to "(Landroid/content/Intent;)Z")) {
                if (inheritStart && name == "onStartCommand") continue
                visitMethod(Opcodes.ACC_PUBLIC, name, descriptor, null, null).apply {
                    visitCode(); visitInsn(Opcodes.ICONST_1)
                    visitFieldInsn(Opcodes.PUTSTATIC, "fixture/ProtectedService", "executed", "Z")
                    when (Type.getReturnType(descriptor).sort) {
                        Type.INT -> { visitIntInsn(Opcodes.BIPUSH, 37); visitInsn(Opcodes.IRETURN) }
                        Type.BOOLEAN -> { visitInsn(Opcodes.ICONST_1); visitInsn(Opcodes.IRETURN) }
                        Type.OBJECT -> {
                            visitTypeInsn(Opcodes.NEW, "android/os/IBinder"); visitInsn(Opcodes.DUP)
                            visitMethodInsn(Opcodes.INVOKESPECIAL, "android/os/IBinder", "<init>", "()V", false)
                            visitInsn(Opcodes.ARETURN)
                        }
                        else -> visitInsn(Opcodes.RETURN)
                    }
                    visitMaxs(0,0); visitEnd()
                }
            }
        }
        val transformed = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        ClassReader(bytes).accept(GuardVisitor(transformed, ComponentType.SERVICE), 0)
        return loader.define("fixture.ProtectedService", transformed.toByteArray()) to loader.loadClass("android.content.Intent")
    }

    @Test fun deniedStartedServiceReturnsNotStickyWithoutHostBody() {
        val (service, intent) = fixture(false)
        assertEquals(2, service.getMethod("onStartCommand", intent, Int::class.javaPrimitiveType, Int::class.javaPrimitiveType)
            .invoke(service.getConstructor().newInstance(), null, 0, 1))
        assertFalse(service.getField("executed").getBoolean(null))
    }
    @Test fun deniedBindReturnsNullWithoutHostBody() {
        val (service, intent) = fixture(false)
        assertNull(service.getMethod("onBind", intent).invoke(service.getConstructor().newInstance(), null))
        assertFalse(service.getField("executed").getBoolean(null))
    }
    @Test fun serviceCreateWithoutSuperStillChecksBeforeHostCode() {
        val (service, _) = fixture(false)
        service.getMethod("onCreate").invoke(service.getConstructor().newInstance())
        assertFalse(service.getField("executed").getBoolean(null))
    }
    @Test fun deniedRebindAndLegacyStartDoNotRunHostCode() {
        val (service, intent) = fixture(false)
        val instance = service.getConstructor().newInstance()
        service.getMethod("onRebind", intent).invoke(instance, null)
        service.getMethod("onStart", intent, Int::class.javaPrimitiveType).invoke(instance, null, 1)
        assertFalse(service.getField("executed").getBoolean(null))
    }
    @Test fun allowedCallbacksRetainTheirReturnValues() {
        val (service, intent) = fixture(true)
        val instance = service.getConstructor().newInstance()
        assertEquals(37, service.getMethod("onStartCommand", intent, Int::class.javaPrimitiveType, Int::class.javaPrimitiveType).invoke(instance, null, 0, 1))
        assertNotNull(service.getMethod("onBind", intent).invoke(instance, null))
        assertTrue(service.getField("executed").getBoolean(null))
    }
    @Test fun cleanupRemainsRunnableWhenProtectionDeniesNewWork() {
        val (service, intent) = fixture(false)
        val instance = service.getConstructor().newInstance()
        service.getMethod("onDestroy").invoke(instance)
        assertTrue(service.getField("executed").getBoolean(null))
        service.getField("executed").setBoolean(null, false)
        assertEquals(true, service.getMethod("onUnbind", intent).invoke(instance, null))
        assertTrue(service.getField("executed").getBoolean(null))
    }
    @Test fun laterRestrictionIsCheckedEvenAfterAllowedCreation() {
        val (service, intent) = fixture(true)
        val instance = service.getConstructor().newInstance()
        service.getMethod("onCreate").invoke(instance)
        assertTrue(service.getField("executed").getBoolean(null))
        service.getField("executed").setBoolean(null, false)
        service.classLoader.loadClass("com.apparmorx.runtime.SecurityGuard").getField("allowed").setBoolean(null, false)
        assertEquals(2, service.getMethod("onStartCommand", intent, Int::class.javaPrimitiveType, Int::class.javaPrimitiveType).invoke(instance, null, 0, 2))
        assertFalse(service.getField("executed").getBoolean(null))
    }
    @Test fun synthesizedStartChecksBeforeDelegatingAndRetainsFrameworkReturnWhenAllowed() {
        for (allowed in listOf(false, true)) {
            val (service, intent) = fixture(allowed, inheritStart = true)
            val result = service.getMethod("onStartCommand", intent, Int::class.javaPrimitiveType, Int::class.javaPrimitiveType)
                .invoke(service.getConstructor().newInstance(), null, 0, 1)
            assertEquals(if (allowed) 99 else 2, result)
            assertEquals(allowed, service.superclass.getField("baseExecuted").getBoolean(null))
        }
    }
    @Test fun inheritedFinalLifecycleDoesNotProduceIllegalSubclassOverride() {
        val loader = Definitions()
        loader.define("android.app.Service", classBytes("android/app/Service"))
        loader.define("fixture.FinalBase", classBytes("fixture/FinalBase", "android/app/Service") {
            visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_FINAL, "onCreate", "()V", null, null).apply {
                visitCode(); visitInsn(Opcodes.RETURN); visitMaxs(0,0); visitEnd()
            }
        })
        val input = classBytes("fixture/InheritedService", "fixture/FinalBase")
        val writer = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        ClassReader(input).accept(GuardVisitor(writer, ComponentType.SERVICE), 0)
        val service = loader.define("fixture.InheritedService", writer.toByteArray())
        assertFalse("Inherited Service callbacks are guarded at their declaring project class, not by blindly overriding final methods",
            service.declaredMethods.any { it.name == "onCreate" })
        service.getMethod("onCreate").invoke(service.getConstructor().newInstance())
    }
}
