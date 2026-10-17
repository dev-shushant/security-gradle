package com.apparmorx.gradle

import org.junit.Assert.*
import org.junit.Test
import org.objectweb.asm.*

/** The ALL-scope firewall must rewrite library calls without synthesizing library lifecycle guards. */
class DependencyFirewallBoundaryTest {
    private fun library(): ByteArray = ClassWriter(ClassWriter.COMPUTE_MAXS).run {
        visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "vendor/LibraryActivity", null, "android/app/Activity", null)
        visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "read", "(Landroid/content/ClipboardManager;)Landroid/content/ClipData;", null, null).apply {
            visitCode(); visitVarInsn(Opcodes.ALOAD, 0)
            visitMethodInsn(Opcodes.INVOKEVIRTUAL, "android/content/ClipboardManager", "getPrimaryClip", "()Landroid/content/ClipData;", false)
            visitInsn(Opcodes.ARETURN); visitMaxs(0, 0); visitEnd()
        }
        visitEnd(); toByteArray()
    }

    @Test fun libraryPassRewritesClipboardWithoutAddingComponentMethodsAndIsIdempotent() {
        fun transform(input: ByteArray): ByteArray = ClassWriter(ClassWriter.COMPUTE_MAXS).run {
            ClassReader(input).accept(DependencyFirewallClassVisitorFactory.firewallVisitor(this), 0)
            toByteArray()
        }
        for (output in listOf(transform(library()), transform(transform(library())))) {
            val methods = mutableListOf<String>()
            val calls = mutableListOf<String>()
            ClassReader(output).accept(object : ClassVisitor(Opcodes.ASM9) {
                override fun visitMethod(access: Int, name: String, descriptor: String, signature: String?, exceptions: Array<out String>?): MethodVisitor {
                    methods += name
                    return object : MethodVisitor(Opcodes.ASM9) {
                        override fun visitMethodInsn(opcode: Int, owner: String, name: String, descriptor: String, isInterface: Boolean) {
                            calls += "$opcode:$owner.$name:$descriptor"
                        }
                    }
                }
            }, 0)
            assertEquals(listOf("read"), methods)
            assertEquals(listOf("${Opcodes.INVOKESTATIC}:com/apparmorx/runtime/DependencyFirewall.getPrimaryClip:(Landroid/content/ClipboardManager;)Landroid/content/ClipData;"), calls)
        }
    }
}
