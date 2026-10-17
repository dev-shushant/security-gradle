package com.apparmorx.gradle

import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.Label
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes

/** Non-suspending entry points only: never short-circuit a resumed coroutine's finally/cleanup. */
internal class WorkerOperationVisitor(next: ClassVisitor, private val synchronousWorker: Boolean, private val remoteWorker: Boolean = false) : ClassVisitor(Opcodes.ASM9, next) {
    override fun visitMethod(access: Int, name: String, descriptor: String, signature: String?, exceptions: Array<out String>?): MethodVisitor {
        val delegate = super.visitMethod(access, name, descriptor, signature, exceptions)
        val future = descriptor == "()Lcom/google/common/util/concurrent/ListenableFuture;" &&
            (name in setOf("startWork", "getForegroundInfoAsync") || remoteWorker && name == "startRemoteWork")
        val synchronous = synchronousWorker && ((name == "doWork" && descriptor == "()Landroidx/work/ListenableWorker\$Result;") ||
            (name == "getForegroundInfo" && descriptor == "()Landroidx/work/ForegroundInfo;"))
        if ((!future && !synchronous) || access and (Opcodes.ACC_STATIC or Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE) != 0) return delegate
        return object : MethodVisitor(Opcodes.ASM9, delegate) {
            override fun visitInsn(opcode: Int) {
                if (remoteWorker && name == "startRemoteWork" && future && opcode == Opcodes.ARETURN) {
                    // Keep the exact returned object on the stack; never wrap a host Future.
                    super.visitInsn(Opcodes.DUP)
                    super.visitVarInsn(Opcodes.ALOAD, 0)
                    super.visitInsn(Opcodes.SWAP)
                    super.visitMethodInsn(Opcodes.INVOKESTATIC, "com/apparmorx/runtime/RemoteWorkerCancellation", "track", "(Ljava/lang/Object;Ljava/util/concurrent/Future;)V", false)
                    super.visitVarInsn(Opcodes.ALOAD, 0)
                    super.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "androidx/work/ListenableWorker", "isStopped", "()Z", false)
                    val running = Label()
                    super.visitJumpInsn(Opcodes.IFEQ, running)
                    super.visitVarInsn(Opcodes.ALOAD, 0)
                    super.visitMethodInsn(Opcodes.INVOKESTATIC, "com/apparmorx/runtime/RemoteWorkerCancellation", "stopped", "(Ljava/lang/Object;)V", false)
                    super.visitLabel(running)
                }
                super.visitInsn(opcode)
            }
            override fun visitCode() {
                super.visitCode()
                visitVarInsn(Opcodes.ALOAD, 0)
                visitMethodInsn(Opcodes.INVOKEVIRTUAL, "androidx/work/ListenableWorker", "getApplicationContext", "()Landroid/content/Context;", false)
                visitMethodInsn(Opcodes.INVOKESTATIC, "com/apparmorx/runtime/SecurityGuard", "allowWorker", "(Landroid/content/Context;)Z", false)
                val allowed = Label()
                visitJumpInsn(Opcodes.IFNE, allowed)
                visitTypeInsn(Opcodes.NEW, "java/lang/SecurityException")
                visitInsn(Opcodes.DUP)
                visitLdcInsn("AppArmorX denied this worker entry")
                visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/SecurityException", "<init>", "(Ljava/lang/String;)V", false)
                visitInsn(Opcodes.ATHROW)
                visitLabel(allowed)
            }
        }
    }
}
