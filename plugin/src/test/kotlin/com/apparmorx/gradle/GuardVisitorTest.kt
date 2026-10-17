package com.apparmorx.gradle

import org.junit.Assert.*
import org.junit.Test
import org.objectweb.asm.*

class GuardVisitorTest {
    @Test fun synthesizesLifecycleGuardsForEmptyActivity() {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "demo/MainActivity", null, "android/app/Activity", null)
        writer.visitEnd()
        val transformed = ClassWriter(ClassWriter.COMPUTE_MAXS)
        ClassReader(writer.toByteArray()).accept(GuardVisitor(transformed, true), 0)
        val calls = mutableListOf<String>()
        ClassReader(transformed.toByteArray()).accept(object : ClassVisitor(Opcodes.ASM9) {
            override fun visitMethod(access: Int, name: String, descriptor: String, signature: String?, exceptions: Array<out String>?): MethodVisitor = object : MethodVisitor(Opcodes.ASM9) {
                override fun visitMethodInsn(opcode: Int, owner: String, method: String, desc: String, isInterface: Boolean) { calls += "$name:$owner.$method" }
            }
        }, 0)
        assertEquals(3, calls.count { it.contains("SecurityGuard.allowActivity") })
        assertTrue(calls.indexOf("onCreate:android/app/Activity.onCreate") < calls.indexOf("onCreate:com/apparmorx/runtime/SecurityGuard.allowActivity"))
    }
    @Test fun existingLifecycleCallsSuperBeforeGuard() {
        val input = ClassWriter(0)
        input.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "demo/MainActivity", null, "android/app/Activity", null)
        input.visitMethod(Opcodes.ACC_PROTECTED, "onStart", "()V", null, null).apply {
            visitCode(); visitVarInsn(Opcodes.ALOAD, 0)
            visitMethodInsn(Opcodes.INVOKESPECIAL, "android/app/Activity", "onStart", "()V", false)
            visitInsn(Opcodes.RETURN); visitMaxs(1,1); visitEnd()
        }
        input.visitEnd()
        val output = ClassWriter(ClassWriter.COMPUTE_MAXS)
        ClassReader(input.toByteArray()).accept(GuardVisitor(output, true), 0)
        val calls = mutableListOf<String>()
        ClassReader(output.toByteArray()).accept(object : ClassVisitor(Opcodes.ASM9) {
            override fun visitMethod(access: Int, name: String, descriptor: String, signature: String?, exceptions: Array<out String>?): MethodVisitor? {
                if (name != "onStart") return null
                return object : MethodVisitor(Opcodes.ASM9) {
                    override fun visitMethodInsn(opcode: Int, owner: String, name: String, descriptor: String, isInterface: Boolean) { calls += "$owner.$name" }
                }
            }
        }, 0)
        assertEquals(listOf("android/app/Activity.onStart", "com/apparmorx/runtime/SecurityGuard.allowActivity"), calls)
    }

    @Test fun existingLifecycleBranchesAroundRemainingBytecodeOnDeniedGuard() {
        val input = ClassWriter(0)
        input.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "demo/MainActivity", null, "android/app/Activity", null)
        input.visitMethod(Opcodes.ACC_PROTECTED, "onCreate", "(Landroid/os/Bundle;)V", null, null).apply {
            visitCode()
            visitVarInsn(Opcodes.ALOAD, 0)
            visitVarInsn(Opcodes.ALOAD, 1)
            visitMethodInsn(Opcodes.INVOKESPECIAL, "android/app/Activity", "onCreate", "(Landroid/os/Bundle;)V", false)
            visitVarInsn(Opcodes.ALOAD, 0)
            visitMethodInsn(Opcodes.INVOKEVIRTUAL, "demo/MainActivity", "sensitiveWork", "()V", false)
            visitInsn(Opcodes.RETURN)
            visitMaxs(2, 2)
            visitEnd()
        }
        input.visitEnd()

        val output = ClassWriter(ClassWriter.COMPUTE_MAXS)
        ClassReader(input.toByteArray()).accept(GuardVisitor(output, true), 0)

        val events = mutableListOf<String>()
        var jumpTarget: Label? = null
        ClassReader(output.toByteArray()).accept(object : ClassVisitor(Opcodes.ASM9) {
            override fun visitMethod(access: Int, name: String, descriptor: String, signature: String?, exceptions: Array<out String>?): MethodVisitor? {
                if (name != "onCreate") return null
                return object : MethodVisitor(Opcodes.ASM9) {
                    override fun visitMethodInsn(opcode: Int, owner: String, name: String, descriptor: String, isInterface: Boolean) {
                        events += "call:$owner.$name:$descriptor"
                    }
                    override fun visitJumpInsn(opcode: Int, label: Label) {
                        jumpTarget = label
                        events += "jump:$opcode"
                    }
                    override fun visitInsn(opcode: Int) {
                        events += "insn:$opcode"
                    }
                    override fun visitLabel(label: Label) {
                        if (label == jumpTarget) {
                            events += "label:continue"
                        }
                    }
                }
            }
        }, 0)

        val guardCallIdx = events.indexOf("call:com/apparmorx/runtime/SecurityGuard.allowActivity:(Landroid/app/Activity;)Z")
        val jumpIdx = events.indexOf("jump:${Opcodes.IFNE}")
        val earlyReturnIdx = events.indexOf("insn:${Opcodes.RETURN}")
        val continueLabelIdx = events.indexOf("label:continue")
        val sensitiveCallIdx = events.indexOf("call:demo/MainActivity.sensitiveWork:()V")

        assertTrue("Guard call must exist with (Landroid/app/Activity;)Z descriptor", guardCallIdx >= 0)
        assertTrue("Jump IFNE must exist", jumpIdx >= 0)
        assertTrue("Early return must exist", earlyReturnIdx >= 0)
        assertTrue("Continue label must exist", continueLabelIdx >= 0)
        assertTrue("Sensitive call must exist", sensitiveCallIdx >= 0)

        assertTrue("Guard call precedes jump", guardCallIdx < jumpIdx)
        assertTrue("Jump precedes early return", jumpIdx < earlyReturnIdx)
        assertTrue("Early return precedes continue label", earlyReturnIdx < continueLabelIdx)
        assertTrue("Continue label precedes sensitive work", continueLabelIdx < sensitiveCallIdx)
    }

    @Test fun synthesizesLifecycleGuardForService() {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "demo/MyService", null, "android/app/Service", null)
        writer.visitEnd()
        val transformed = ClassWriter(ClassWriter.COMPUTE_MAXS)
        ClassReader(writer.toByteArray()).accept(GuardVisitor(transformed, ComponentType.SERVICE), 0)
        val calls = mutableListOf<String>()
        ClassReader(transformed.toByteArray()).accept(object : ClassVisitor(Opcodes.ASM9) {
            override fun visitMethod(access: Int, name: String, descriptor: String, signature: String?, exceptions: Array<out String>?): MethodVisitor = object : MethodVisitor(Opcodes.ASM9) {
                override fun visitMethodInsn(opcode: Int, owner: String, method: String, desc: String, isInterface: Boolean) { calls += "$name:$owner.$method:$desc" }
            }
        }, 0)
        assertTrue(calls.any { it == "onCreate:com/apparmorx/runtime/SecurityGuard.allowService:(Landroid/app/Service;)Z" })
    }

    @Test fun synthesizesLifecycleGuardForApplication() {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "demo/MyApplication", null, "android/app/Application", null)
        writer.visitEnd()
        val transformed = ClassWriter(ClassWriter.COMPUTE_MAXS)
        ClassReader(writer.toByteArray()).accept(GuardVisitor(transformed, ComponentType.APPLICATION), 0)
        val calls = mutableListOf<String>()
        ClassReader(transformed.toByteArray()).accept(object : ClassVisitor(Opcodes.ASM9) {
            override fun visitMethod(access: Int, name: String, descriptor: String, signature: String?, exceptions: Array<out String>?): MethodVisitor = object : MethodVisitor(Opcodes.ASM9) {
                override fun visitMethodInsn(opcode: Int, owner: String, method: String, desc: String, isInterface: Boolean) { calls += "$name:$owner.$method:$desc" }
            }
        }, 0)
        assertTrue(calls.any { it == "onCreate:com/apparmorx/runtime/SecurityGuard.allowApplication:(Landroid/app/Application;)Z" })
    }

    @Test fun instrumentsBroadcastReceiverOnReceive() {
        val input = ClassWriter(0)
        input.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "demo/MyReceiver", null, "android/content/BroadcastReceiver", null)
        input.visitMethod(Opcodes.ACC_PUBLIC, "onReceive", "(Landroid/content/Context;Landroid/content/Intent;)V", null, null).apply {
            visitCode()
            visitVarInsn(Opcodes.ALOAD, 0)
            visitVarInsn(Opcodes.ALOAD, 1)
            visitMethodInsn(Opcodes.INVOKEVIRTUAL, "demo/MyReceiver", "handleIntent", "(Landroid/content/Context;)V", false)
            visitInsn(Opcodes.RETURN)
            visitMaxs(2, 3)
            visitEnd()
        }
        input.visitEnd()

        val output = ClassWriter(ClassWriter.COMPUTE_MAXS)
        ClassReader(input.toByteArray()).accept(GuardVisitor(output, ComponentType.RECEIVER), 0)

        val events = mutableListOf<String>()
        var jumpTarget: Label? = null
        ClassReader(output.toByteArray()).accept(object : ClassVisitor(Opcodes.ASM9) {
            override fun visitMethod(access: Int, name: String, descriptor: String, signature: String?, exceptions: Array<out String>?): MethodVisitor? {
                if (name != "onReceive") return null
                return object : MethodVisitor(Opcodes.ASM9) {
                    override fun visitVarInsn(opcode: Int, `var`: Int) {
                        events += "var:$opcode:$`var`"
                    }
                    override fun visitMethodInsn(opcode: Int, owner: String, name: String, descriptor: String, isInterface: Boolean) {
                        events += "call:$owner.$name:$descriptor"
                    }
                    override fun visitJumpInsn(opcode: Int, label: Label) {
                        jumpTarget = label
                        events += "jump:$opcode"
                    }
                    override fun visitInsn(opcode: Int) {
                        events += "insn:$opcode"
                    }
                    override fun visitLabel(label: Label) {
                        if (label == jumpTarget) {
                            events += "label:continue"
                        }
                    }
                }
            }
        }, 0)

        val loadContextIdx = events.indexOf("var:${Opcodes.ALOAD}:1")
        val guardCallIdx = events.indexOf("call:com/apparmorx/runtime/SecurityGuard.allowReceiver:(Landroid/content/Context;)Z")
        val jumpIdx = events.indexOf("jump:${Opcodes.IFNE}")
        val earlyReturnIdx = events.indexOf("insn:${Opcodes.RETURN}")
        val continueLabelIdx = events.indexOf("label:continue")
        val handleIntentIdx = events.indexOf("call:demo/MyReceiver.handleIntent:(Landroid/content/Context;)V")

        assertTrue("Context argument must be loaded", loadContextIdx >= 0)
        assertTrue("Guard call must exist", guardCallIdx >= 0)
        assertTrue("Jump IFNE must exist", jumpIdx >= 0)
        assertTrue("Early return must exist", earlyReturnIdx >= 0)
        assertTrue("Continue label must exist", continueLabelIdx >= 0)
        assertTrue("Handle intent must exist", handleIntentIdx >= 0)

        assertTrue(loadContextIdx < guardCallIdx)
        assertTrue(guardCallIdx < jumpIdx)
        assertTrue(jumpIdx < earlyReturnIdx)
        assertTrue(earlyReturnIdx < continueLabelIdx)
        assertTrue(continueLabelIdx < handleIntentIdx)
    }

    @Test fun rewritesClipboardManagerAndSettingsSecureInvocations() {
        val input = ClassWriter(0)
        input.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "demo/UntrustedSdk", null, "java/lang/Object", null)
        input.visitMethod(Opcodes.ACC_PUBLIC, "harvestData", "(Landroid/content/ClipboardManager;Landroid/content/ContentResolver;)V", null, null).apply {
            visitCode()
            visitVarInsn(Opcodes.ALOAD, 1)
            visitMethodInsn(Opcodes.INVOKEVIRTUAL, "android/content/ClipboardManager", "hasPrimaryClip", "()Z", false)
            visitInsn(Opcodes.POP)
            visitVarInsn(Opcodes.ALOAD, 1)
            visitMethodInsn(Opcodes.INVOKEVIRTUAL, "android/content/ClipboardManager", "getPrimaryClip", "()Landroid/content/ClipData;", false)
            visitInsn(Opcodes.POP)
            visitVarInsn(Opcodes.ALOAD, 2)
            visitLdcInsn("android_id")
            visitMethodInsn(Opcodes.INVOKESTATIC, "android/provider/Settings\$Secure", "getString", "(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;", false)
            visitInsn(Opcodes.POP)
            visitInsn(Opcodes.RETURN)
            visitMaxs(2, 3)
            visitEnd()
        }
        input.visitEnd()

        val output = ClassWriter(ClassWriter.COMPUTE_MAXS)
        ClassReader(input.toByteArray()).accept(GuardVisitor(output, null as ComponentType?), 0)

        val calls = mutableListOf<String>()
        ClassReader(output.toByteArray()).accept(object : ClassVisitor(Opcodes.ASM9) {
            override fun visitMethod(access: Int, name: String, descriptor: String, signature: String?, exceptions: Array<out String>?): MethodVisitor = object : MethodVisitor(Opcodes.ASM9) {
                override fun visitMethodInsn(opcode: Int, owner: String, method: String, desc: String, isInterface: Boolean) {
                    calls += "$opcode:$owner.$method:$desc"
                }
            }
        }, 0)

        assertTrue(calls.any { it.contains("com/apparmorx/runtime/DependencyFirewall.hasPrimaryClip") })
        assertTrue(calls.any { it.contains("com/apparmorx/runtime/DependencyFirewall.getPrimaryClip") })
        assertTrue(calls.any { it.contains("com/apparmorx/runtime/DependencyFirewall.getString") })
        assertFalse(calls.any { it.contains("android/content/ClipboardManager.getPrimaryClip") })
        assertFalse(calls.any { it.contains("android/provider/Settings\$Secure.getString") })
    }

    @Test fun rewritesLocationManagerAndTelephonyManagerInvocations() {
        val input = ClassWriter(0)
        input.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "demo/TrackingSdk", null, "java/lang/Object", null)
        input.visitMethod(Opcodes.ACC_PUBLIC, "trackUser", "(Landroid/location/LocationManager;Landroid/telephony/TelephonyManager;)V", null, null).apply {
            visitCode()
            visitVarInsn(Opcodes.ALOAD, 1)
            visitLdcInsn("gps")
            visitMethodInsn(Opcodes.INVOKEVIRTUAL, "android/location/LocationManager", "getLastKnownLocation", "(Ljava/lang/String;)Landroid/location/Location;", false)
            visitInsn(Opcodes.POP)
            visitVarInsn(Opcodes.ALOAD, 2)
            visitMethodInsn(Opcodes.INVOKEVIRTUAL, "android/telephony/TelephonyManager", "getDeviceId", "()Ljava/lang/String;", false)
            visitInsn(Opcodes.POP)
            visitVarInsn(Opcodes.ALOAD, 2)
            visitMethodInsn(Opcodes.INVOKEVIRTUAL, "android/telephony/TelephonyManager", "getImei", "()Ljava/lang/String;", false)
            visitInsn(Opcodes.POP)
            visitInsn(Opcodes.RETURN)
            visitMaxs(2, 3)
            visitEnd()
        }
        input.visitEnd()

        val output = ClassWriter(ClassWriter.COMPUTE_MAXS)
        ClassReader(input.toByteArray()).accept(GuardVisitor(output, null as ComponentType?), 0)

        val calls = mutableListOf<String>()
        ClassReader(output.toByteArray()).accept(object : ClassVisitor(Opcodes.ASM9) {
            override fun visitMethod(access: Int, name: String, descriptor: String, signature: String?, exceptions: Array<out String>?): MethodVisitor = object : MethodVisitor(Opcodes.ASM9) {
                override fun visitMethodInsn(opcode: Int, owner: String, method: String, desc: String, isInterface: Boolean) {
                    calls += "$opcode:$owner.$method:$desc"
                }
            }
        }, 0)

        assertTrue(calls.any { it.contains("com/apparmorx/runtime/DependencyFirewall.getLastKnownLocation") })
        assertTrue(calls.any { it.contains("com/apparmorx/runtime/DependencyFirewall.getDeviceId") })
        assertTrue(calls.any { it.contains("com/apparmorx/runtime/DependencyFirewall.getImei") })
        assertFalse(calls.any { it.contains("android/location/LocationManager.getLastKnownLocation") })
        assertFalse(calls.any { it.contains("android/telephony/TelephonyManager.getDeviceId") })
        assertFalse(calls.any { it.contains("android/telephony/TelephonyManager.getImei") })
    }

    @Test fun rewritesNetworkSecurityInvocations() {
        val input = ClassWriter(0)
        input.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "demo/NetworkSdk", null, "java/lang/Object", null)
        input.visitMethod(Opcodes.ACC_PUBLIC, "configureTls", "(Ljavax/net/ssl/HttpsURLConnection;Ljavax/net/ssl/HostnameVerifier;Ljavax/net/ssl/SSLContext;)V", null, null).apply {
            visitCode()
            visitVarInsn(Opcodes.ALOAD, 2)
            visitMethodInsn(Opcodes.INVOKESTATIC, "javax/net/ssl/HttpsURLConnection", "setDefaultHostnameVerifier", "(Ljavax/net/ssl/HostnameVerifier;)V", false)
            visitVarInsn(Opcodes.ALOAD, 1)
            visitVarInsn(Opcodes.ALOAD, 2)
            visitMethodInsn(Opcodes.INVOKEVIRTUAL, "javax/net/ssl/HttpsURLConnection", "setHostnameVerifier", "(Ljavax/net/ssl/HostnameVerifier;)V", false)
            visitVarInsn(Opcodes.ALOAD, 3)
            visitInsn(Opcodes.ACONST_NULL)
            visitInsn(Opcodes.ACONST_NULL)
            visitInsn(Opcodes.ACONST_NULL)
            visitMethodInsn(Opcodes.INVOKEVIRTUAL, "javax/net/ssl/SSLContext", "init", "([Ljavax/net/ssl/KeyManager;[Ljavax/net/ssl/TrustManager;Ljava/security/SecureRandom;)V", false)
            visitInsn(Opcodes.RETURN)
            visitMaxs(4, 4)
            visitEnd()
        }
        input.visitEnd()

        val output = ClassWriter(ClassWriter.COMPUTE_MAXS)
        ClassReader(input.toByteArray()).accept(GuardVisitor(output, null as ComponentType?), 0)

        val calls = mutableListOf<String>()
        ClassReader(output.toByteArray()).accept(object : ClassVisitor(Opcodes.ASM9) {
            override fun visitMethod(access: Int, name: String, descriptor: String, signature: String?, exceptions: Array<out String>?): MethodVisitor = object : MethodVisitor(Opcodes.ASM9) {
                override fun visitMethodInsn(opcode: Int, owner: String, method: String, desc: String, isInterface: Boolean) {
                    calls += "$opcode:$owner.$method:$desc"
                }
            }
        }, 0)

        assertTrue(calls.any { it.contains("com/apparmorx/runtime/DependencyFirewall.setDefaultHostnameVerifier") })
        assertTrue(calls.any { it.contains("com/apparmorx/runtime/DependencyFirewall.setHostnameVerifier") })
        assertTrue(calls.any { it.contains("com/apparmorx/runtime/DependencyFirewall.sslContextInit") })
        assertFalse(calls.any { it.contains("javax/net/ssl/HttpsURLConnection.setDefaultHostnameVerifier") })
        assertFalse(calls.any { it.contains("javax/net/ssl/HttpsURLConnection.setHostnameVerifier") })
        assertFalse(calls.any { it.contains("javax/net/ssl/SSLContext.init") })
    }
}

