package com.apparmorx.gradle

import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.Label
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes

/** Exact public SDK operation signatures. No synthetic overrides or provider-init deferral. */
internal val PROVIDER_OPERATIONS = setOf(
    "query" to "(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;",
    "query" to "(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Landroid/os/CancellationSignal;)Landroid/database/Cursor;",
    "query" to "(Landroid/net/Uri;[Ljava/lang/String;Landroid/os/Bundle;Landroid/os/CancellationSignal;)Landroid/database/Cursor;",
    "getType" to "(Landroid/net/Uri;)Ljava/lang/String;",
    "getTypeAnonymous" to "(Landroid/net/Uri;)Ljava/lang/String;",
    "getStreamTypes" to "(Landroid/net/Uri;Ljava/lang/String;)[Ljava/lang/String;",
    "insert" to "(Landroid/net/Uri;Landroid/content/ContentValues;)Landroid/net/Uri;",
    "insert" to "(Landroid/net/Uri;Landroid/content/ContentValues;Landroid/os/Bundle;)Landroid/net/Uri;",
    "bulkInsert" to "(Landroid/net/Uri;[Landroid/content/ContentValues;)I",
    "delete" to "(Landroid/net/Uri;Ljava/lang/String;[Ljava/lang/String;)I",
    "delete" to "(Landroid/net/Uri;Landroid/os/Bundle;)I",
    "update" to "(Landroid/net/Uri;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I",
    "update" to "(Landroid/net/Uri;Landroid/content/ContentValues;Landroid/os/Bundle;)I",
    "openFile" to "(Landroid/net/Uri;Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;",
    "openFile" to "(Landroid/net/Uri;Ljava/lang/String;Landroid/os/CancellationSignal;)Landroid/os/ParcelFileDescriptor;",
    "openAssetFile" to "(Landroid/net/Uri;Ljava/lang/String;)Landroid/content/res/AssetFileDescriptor;",
    "openAssetFile" to "(Landroid/net/Uri;Ljava/lang/String;Landroid/os/CancellationSignal;)Landroid/content/res/AssetFileDescriptor;",
    "openTypedAssetFile" to "(Landroid/net/Uri;Ljava/lang/String;Landroid/os/Bundle;)Landroid/content/res/AssetFileDescriptor;",
    "openTypedAssetFile" to "(Landroid/net/Uri;Ljava/lang/String;Landroid/os/Bundle;Landroid/os/CancellationSignal;)Landroid/content/res/AssetFileDescriptor;",
    "openPipeHelper" to "(Landroid/net/Uri;Ljava/lang/String;Landroid/os/Bundle;Ljava/lang/Object;Landroid/content/ContentProvider\$PipeDataWriter;)Landroid/os/ParcelFileDescriptor;",
    "call" to "(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)Landroid/os/Bundle;",
    "call" to "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)Landroid/os/Bundle;",
    "applyBatch" to "(Ljava/util/ArrayList;)[Landroid/content/ContentProviderResult;",
    "applyBatch" to "(Ljava/lang/String;Ljava/util/ArrayList;)[Landroid/content/ContentProviderResult;",
    "canonicalize" to "(Landroid/net/Uri;)Landroid/net/Uri;",
    "uncanonicalize" to "(Landroid/net/Uri;)Landroid/net/Uri;",
    "refresh" to "(Landroid/net/Uri;Landroid/os/Bundle;Landroid/os/CancellationSignal;)Z"
)

/** Guards eligible executable method bodies in projects/dependencies; no synthesis, native or runtime-generated wrapping. */
internal class ProviderOperationVisitor(next: ClassVisitor) : ClassVisitor(Opcodes.ASM9, next) {
    override fun visitMethod(access: Int, name: String, descriptor: String, signature: String?, exceptions: Array<out String>?): MethodVisitor {
        val delegate = super.visitMethod(access, name, descriptor, signature, exceptions)
        if ((name to descriptor) !in PROVIDER_OPERATIONS ||
            access and (Opcodes.ACC_STATIC or Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE) != 0) return delegate
        return object : MethodVisitor(Opcodes.ASM9, delegate) {
            override fun visitCode() {
                super.visitCode()
                visitVarInsn(Opcodes.ALOAD, 0)
                visitMethodInsn(Opcodes.INVOKESTATIC, "com/apparmorx/runtime/SecurityGuard", "allowProvider",
                    "(Landroid/content/ContentProvider;)Z", false)
                val allowed = Label()
                visitJumpInsn(Opcodes.IFNE, allowed)
                visitTypeInsn(Opcodes.NEW, "java/lang/SecurityException")
                visitInsn(Opcodes.DUP)
                visitLdcInsn("AppArmorX denied this provider operation")
                visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/SecurityException", "<init>", "(Ljava/lang/String;)V", false)
                visitInsn(Opcodes.ATHROW)
                visitLabel(allowed)
            }
        }
    }
}
