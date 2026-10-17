package com.apparmorx.gradle

import org.junit.Assert.*
import org.junit.Test
import org.objectweb.asm.*
import java.lang.reflect.InvocationTargetException

/** Executes entry guards against independent JVM protocol stubs; real WorkManager is qualified separately. */
class WorkerOperationExecutionTest {
    private class Definitions : ClassLoader(WorkerOperationExecutionTest::class.java.classLoader) {
        fun define(name: String, bytes: ByteArray): Class<*> = defineClass(name, bytes, 0, bytes.size)
    }
    private fun bytes(name: String, parent: String = "java/lang/Object", body: ClassWriter.() -> Unit = {}): ByteArray {
        val w = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        w.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, name, null, parent, null)
        w.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null).apply {
            visitCode(); visitVarInsn(Opcodes.ALOAD, 0); visitMethodInsn(Opcodes.INVOKESPECIAL, parent, "<init>", "()V", false)
            visitInsn(Opcodes.RETURN); visitMaxs(0, 0); visitEnd()
        }
        w.body(); w.visitEnd(); return w.toByteArray()
    }
    private val entries = listOf(
        "startWork" to "()Lcom/google/common/util/concurrent/ListenableFuture;",
        "getForegroundInfoAsync" to "()Lcom/google/common/util/concurrent/ListenableFuture;",
        "doWork" to "()Landroidx/work/ListenableWorker\$Result;",
        "getForegroundInfo" to "()Landroidx/work/ForegroundInfo;"
    )
    private fun fixture(allowed: Boolean, supers: List<String> = listOf("androidx.work.Worker", "androidx.work.ListenableWorker"), remote: Boolean = false): Class<*> {
        val loader = Definitions()
        for (name in listOf("android/content/Context", "com/google/common/util/concurrent/ListenableFuture",
            "androidx/work/ListenableWorker\$Result", "androidx/work/ForegroundInfo", "kotlin/coroutines/Continuation"))
            loader.define(name.replace('/', '.'), bytes(name, if (name.endsWith("ListenableFuture")) "java/util/concurrent/CompletableFuture" else "java/lang/Object"))
        loader.define("com.apparmorx.runtime.RemoteWorkerCancellation", bytes("com/apparmorx/runtime/RemoteWorkerCancellation") {
            for ((name, desc) in listOf("track" to "(Ljava/lang/Object;Ljava/util/concurrent/Future;)V", "stopped" to "(Ljava/lang/Object;)V")) {
                visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, name, desc, null, null).apply {
                    visitCode(); visitInsn(Opcodes.RETURN); visitMaxs(0, 0); visitEnd()
                }
            }
        })
        loader.define("androidx.work.ListenableWorker", bytes("androidx/work/ListenableWorker") {
            visitMethod(Opcodes.ACC_PUBLIC, "isStopped", "()Z", null, null).apply {
                visitCode(); visitInsn(Opcodes.ICONST_0); visitInsn(Opcodes.IRETURN); visitMaxs(0, 0); visitEnd()
            }
            visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_FINAL, "getApplicationContext", "()Landroid/content/Context;", null, null).apply {
                visitCode(); visitTypeInsn(Opcodes.NEW, "android/content/Context"); visitInsn(Opcodes.DUP)
                visitMethodInsn(Opcodes.INVOKESPECIAL, "android/content/Context", "<init>", "()V", false)
                visitInsn(Opcodes.ARETURN); visitMaxs(0, 0); visitEnd()
            }
        })
        loader.define("androidx.work.Worker", bytes("androidx/work/Worker", "androidx/work/ListenableWorker"))
        loader.define("androidx.work.multiprocess.RemoteListenableWorker", bytes("androidx/work/multiprocess/RemoteListenableWorker", "androidx/work/ListenableWorker"))
        loader.define("androidx.work.multiprocess.RemoteCoroutineWorker", bytes("androidx/work/multiprocess/RemoteCoroutineWorker", "androidx/work/multiprocess/RemoteListenableWorker"))
        loader.define("com.apparmorx.runtime.SecurityGuard", bytes("com/apparmorx/runtime/SecurityGuard") {
            visitField(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "allowed", "Z", null, null).visitEnd()
            visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "allowWorker", "(Landroid/content/Context;)Z", null, null).apply {
                visitCode(); visitFieldInsn(Opcodes.GETSTATIC, "com/apparmorx/runtime/SecurityGuard", "allowed", "Z")
                visitInsn(Opcodes.IRETURN); visitMaxs(0, 0); visitEnd()
            }
        }).getField("allowed").setBoolean(null, allowed)
        val parent = when {
            remote && "androidx.work.multiprocess.RemoteCoroutineWorker" in supers -> "androidx/work/multiprocess/RemoteCoroutineWorker"
            remote -> "androidx/work/multiprocess/RemoteListenableWorker"
            else -> "androidx/work/Worker"
        }
        val input = bytes("fixture/Work", parent) {
            visitField(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "executed", "Z", null, null).visitEnd()
            for ((name, descriptor) in entries + listOf("onStopped" to "()V",
                "startRemoteWork" to "()Lcom/google/common/util/concurrent/ListenableFuture;",
                "doRemoteWork" to "(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
                "doWork" to "(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;")) {
                visitMethod(Opcodes.ACC_PUBLIC, name, descriptor, null, null).apply {
                    visitCode(); visitInsn(Opcodes.ICONST_1); visitFieldInsn(Opcodes.PUTSTATIC, "fixture/Work", "executed", "Z")
                    if (Type.getReturnType(descriptor).sort == Type.VOID) visitInsn(Opcodes.RETURN)
                    else {
                        val result = Type.getReturnType(descriptor).internalName
                        visitTypeInsn(Opcodes.NEW, result); visitInsn(Opcodes.DUP)
                        visitMethodInsn(Opcodes.INVOKESPECIAL, result, "<init>", "()V", false); visitInsn(Opcodes.ARETURN)
                    }
                    visitMaxs(0, 0); visitEnd()
                }
            }
        }
        val output = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        ClassReader(input).accept(componentGuardVisitor(supers,
            DependencyFirewallClassVisitorFactory.allScopeVisitor("fixture.Work", supers, output)), 0)
        return loader.define("fixture.Work", output.toByteArray())
    }
    private fun method(type: Class<*>, pair: Pair<String, String>) = type.methods.single { it.name == pair.first && Type.getMethodDescriptor(it) == pair.second }

    @Test fun blockingEntryDoesNotExecuteHostOrPretendAResult() {
        val type = fixture(false); val instance = type.getConstructor().newInstance()
        for (entry in entries) {
            try { method(type, entry).invoke(instance); fail("Worker entry ${entry.first} was not denied") }
            catch (failure: InvocationTargetException) { assertTrue(failure.cause is SecurityException) }
            assertFalse(type.getField("executed").getBoolean(null))
        }
    }
    @Test fun allowedEntriesRetainOriginalReturnTypesAndBodies() {
        val type = fixture(true); val instance = type.getConstructor().newInstance()
        for (entry in entries) {
            type.getField("executed").setBoolean(null, false)
            val result = method(type, entry).invoke(instance)
            assertEquals(Type.getReturnType(entry.second).className, result.javaClass.name)
            assertTrue(type.getField("executed").getBoolean(null))
        }
    }
    @Test fun stoppedAndSuspendStateMachineMethodsRemainRunnableWhenRestricted() {
        val type = fixture(false); val instance = type.getConstructor().newInstance()
        type.getMethod("onStopped").invoke(instance)
        assertTrue(type.getField("executed").getBoolean(null))
        type.getField("executed").setBoolean(null, false)
        val suspendMethod = type.methods.single { it.name == "doWork" && it.parameterCount == 1 }
        assertNotNull(suspendMethod.invoke(instance, null))
        assertTrue(type.getField("executed").getBoolean(null))
    }
    @Test fun frameworkWorkerSelectionDoesNotEnableUnrelatedAndroidxClasses() {
        assertTrue(DependencyFirewallClassVisitorFactory.isAllScopeInstrumentable("androidx.work.Worker", listOf("androidx.work.ListenableWorker")))
        assertFalse(DependencyFirewallClassVisitorFactory.isAllScopeInstrumentable("androidx.work.OtherHelper", emptyList()))
        assertFalse(DependencyFirewallClassVisitorFactory.isAllScopeInstrumentable("com.apparmorx.runtime.Worker", listOf("androidx.work.ListenableWorker")))
    }
    @Test fun directWorkerParentsRemainEligibleWithoutTransitiveMetadata() {
        val type = fixture(false, listOf("androidx.work.Worker"))
        val instance = type.getConstructor().newInstance()
        try { method(type, entries[2]).invoke(instance); fail("Direct Worker metadata skipped denial") }
        catch (failure: InvocationTargetException) { assertTrue(failure.cause is SecurityException) }
        assertFalse(type.getField("executed").getBoolean(null))
    }
    @Test fun remoteEntryDeniesBeforeBodyWithOnlyDirectRemoteParentMetadata() {
        val type = fixture(false, listOf("androidx.work.multiprocess.RemoteListenableWorker"), remote = true)
        try { type.getMethod("startRemoteWork").invoke(type.getConstructor().newInstance()); fail("Remote body was entered") }
        catch (failure: InvocationTargetException) { assertTrue(failure.cause is SecurityException) }
        assertFalse(type.getField("executed").getBoolean(null))
    }
    @Test fun allowedRemoteEntryPreservesItsFutureAndHostBody() {
        val type = fixture(true, listOf("androidx.work.multiprocess.RemoteListenableWorker"), remote = true)
        val result = type.getMethod("startRemoteWork").invoke(type.getConstructor().newInstance())
        assertEquals("com.google.common.util.concurrent.ListenableFuture", result.javaClass.name)
        assertTrue(type.getField("executed").getBoolean(null))
    }
    @Test fun remoteCoroutineEntryAlsoDeniesWithDirectParentMetadata() {
        val type = fixture(false, listOf("androidx.work.multiprocess.RemoteCoroutineWorker"), remote = true)
        try { type.getMethod("startRemoteWork").invoke(type.getConstructor().newInstance()); fail("Remote coroutine entry was not denied") }
        catch (failure: InvocationTargetException) { assertTrue(failure.cause is SecurityException) }
        assertFalse(type.getField("executed").getBoolean(null))
    }
    @Test fun unrelatedSameNamedMethodOnOrdinaryWorkerIsNotRemoteEntry() {
        val type = fixture(false)
        assertNotNull(type.getMethod("startRemoteWork").invoke(type.getConstructor().newInstance()))
        assertTrue(type.getField("executed").getBoolean(null))
    }
    @Test fun remoteSuspendBodyAndCleanupRemainRunnableAfterRestriction() {
        val type = fixture(false, listOf("androidx.work.multiprocess.RemoteCoroutineWorker"), remote = true)
        val instance = type.getConstructor().newInstance()
        type.methods.single { it.name == "doRemoteWork" }.invoke(instance, null)
        assertTrue(type.getField("executed").getBoolean(null))
        type.getField("executed").setBoolean(null, false)
        type.getMethod("onStopped").invoke(instance)
        assertTrue(type.getField("executed").getBoolean(null))
    }
}
