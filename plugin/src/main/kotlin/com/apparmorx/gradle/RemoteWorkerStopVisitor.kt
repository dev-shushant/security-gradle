package com.apparmorx.gradle

import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.Label
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes

/** Observe the framework stop dispatch, including inherited/final callbacks; never gate cleanup. */
internal class RemoteWorkerStopVisitor(next: ClassVisitor) : ClassVisitor(Opcodes.ASM9, next) {
    private var ownerName = ""
    private var stateField = false
    private val accessors = mutableSetOf<String>()
    private val ownerInterface = "com/apparmorx/runtime/RemoteWorkerCancellationOwner"
    private val fieldName = "apparmorxRemoteCancellationState"
    override fun visit(version: Int, access: Int, name: String, signature: String?, superName: String?, interfaces: Array<out String>?) {
        ownerName = name
        super.visit(version, access, name, signature, superName, ((interfaces?.toList() ?: emptyList()) + ownerInterface).distinct().toTypedArray())
    }
    override fun visitField(access: Int, name: String, descriptor: String, signature: String?, value: Any?): org.objectweb.asm.FieldVisitor {
        if (name == fieldName) {
            check(descriptor == "Ljava/lang/Object;") { "AppArmorX remote ownership field collision" }
            stateField = true
        }
        return super.visitField(access, name, descriptor, signature, value)
    }
    override fun visitEnd() {
        if (!stateField) super.visitField(Opcodes.ACC_PRIVATE or Opcodes.ACC_SYNTHETIC, fieldName, "Ljava/lang/Object;", null, null).visitEnd()
        for ((name, descriptor) in listOf("appArmorXGetRemoteCancellationState" to "()Ljava/lang/Object;", "appArmorXSetRemoteCancellationState" to "(Ljava/lang/Object;)V")) {
            if (name in accessors) continue
            val method = super.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_FINAL or Opcodes.ACC_SYNTHETIC, name, descriptor, null, null)
            method.visitCode(); method.visitVarInsn(Opcodes.ALOAD, 0)
            if (name.startsWith("appArmorXGet")) {
                method.visitFieldInsn(Opcodes.GETFIELD, ownerName, fieldName, "Ljava/lang/Object;")
                method.visitInsn(Opcodes.ARETURN)
            } else {
                method.visitVarInsn(Opcodes.ALOAD, 1)
                method.visitFieldInsn(Opcodes.PUTFIELD, ownerName, fieldName, "Ljava/lang/Object;")
                method.visitInsn(Opcodes.RETURN)
            }
            method.visitMaxs(2, 2); method.visitEnd()
        }
        super.visitEnd()
    }
    override fun visitMethod(access: Int, name: String, descriptor: String, signature: String?, exceptions: Array<out String>?): MethodVisitor {
        if (name == "appArmorXGetRemoteCancellationState" || name == "appArmorXSetRemoteCancellationState") accessors.add(name)
        val delegate = super.visitMethod(access, name, descriptor, signature, exceptions)
        if (name != "stop" || descriptor != "(I)V" || access and (Opcodes.ACC_STATIC or Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE) != 0) return delegate
        return object : MethodVisitor(Opcodes.ASM9, delegate) {
            private val start = Label()
            private val end = Label()
            private val handler = Label()
            private fun notifyStopped() {
                super.visitVarInsn(Opcodes.ALOAD, 0)
                super.visitMethodInsn(Opcodes.INVOKESTATIC, "com/apparmorx/runtime/RemoteWorkerCancellation", "stopped", "(Ljava/lang/Object;)V", false)
            }
            override fun visitCode() {
                super.visitCode()
                super.visitLabel(start)
            }
            override fun visitInsn(opcode: Int) {
                if (opcode == Opcodes.RETURN) notifyStopped()
                super.visitInsn(opcode)
            }
            override fun visitMaxs(maxStack: Int, maxLocals: Int) {
                // Append after original handlers so host catch semantics retain priority.
                super.visitTryCatchBlock(start, end, handler, null)
                super.visitLabel(end)
                super.visitLabel(handler)
                // Preserve the original callback exception on the stack while cancelling tracked work.
                notifyStopped()
                super.visitInsn(Opcodes.ATHROW)
                super.visitMaxs(maxStack + 1, maxLocals)
            }
        }
    }
}
