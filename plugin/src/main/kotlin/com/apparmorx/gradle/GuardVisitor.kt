package com.apparmorx.gradle

import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.Label
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes

private const val GUARD_OWNER = "com/apparmorx/runtime/SecurityGuard"

enum class ComponentType {
    ACTIVITY,
    APPLICATION,
    SERVICE,
    RECEIVER
}

private class ComponentConfig(
    val defaultSuperName: String,
    val lifecycle: Map<String, String>,
    val guardMethod: String,
    val guardDescriptor: String,
    val canSynthesize: Boolean,
    val injectAtMethodStart: Boolean
)

private val COMPONENT_CONFIGS = mapOf(
    ComponentType.ACTIVITY to ComponentConfig(
        defaultSuperName = "android/app/Activity",
        lifecycle = mapOf(
            "onCreate" to "(Landroid/os/Bundle;)V",
            "onStart" to "()V",
            "onResume" to "()V"
        ),
        guardMethod = "allowActivity",
        guardDescriptor = "(Landroid/app/Activity;)Z",
        canSynthesize = true,
        injectAtMethodStart = false
    ),
    ComponentType.APPLICATION to ComponentConfig(
        defaultSuperName = "android/app/Application",
        lifecycle = mapOf(
            "onCreate" to "()V"
        ),
        guardMethod = "allowApplication",
        guardDescriptor = "(Landroid/app/Application;)Z",
        canSynthesize = true,
        injectAtMethodStart = false
    ),
    ComponentType.SERVICE to ComponentConfig(
        defaultSuperName = "android/app/Service",
        lifecycle = mapOf(
            "onCreate" to "()V"
        ),
        guardMethod = "allowService",
        guardDescriptor = "(Landroid/app/Service;)Z",
        canSynthesize = true,
        injectAtMethodStart = false
    ),
    ComponentType.RECEIVER to ComponentConfig(
        defaultSuperName = "android/content/BroadcastReceiver",
        lifecycle = mapOf(
            "onReceive" to "(Landroid/content/Context;Landroid/content/Intent;)V"
        ),
        guardMethod = "allowReceiver",
        guardDescriptor = "(Landroid/content/Context;)Z",
        canSynthesize = false,
        injectAtMethodStart = true
    )
)

/**
 * Injects guard calls into Android component lifecycle methods (Activity, Application, Service,
 * and BroadcastReceiver), synthesizing overrides for missing lifecycle methods where appropriate.
 */
class GuardVisitor(
    next: ClassVisitor,
    private val componentType: ComponentType?
) : ClassVisitor(Opcodes.ASM9, next) {

    constructor(next: ClassVisitor, isActivitySubclass: Boolean) : this(
        next,
        if (isActivitySubclass) ComponentType.ACTIVITY else null
    )

    private val config = componentType?.let { COMPONENT_CONFIGS[it] }
    private var className: String = ""
    private var superName: String = config?.defaultSuperName ?: "android/app/Activity"
    private val presentLifecycle = mutableSetOf<String>()

    override fun visit(
        version: Int,
        access: Int,
        name: String,
        signature: String?,
        superName: String?,
        interfaces: Array<out String>?,
    ) {
        className = name
        this.superName = superName ?: this.superName
        super.visit(version, access, name, signature, superName, interfaces)
    }

    override fun visitMethod(
        access: Int,
        name: String,
        descriptor: String,
        signature: String?,
        exceptions: Array<out String>?,
    ): MethodVisitor {
        var delegate = super.visitMethod(access, name, descriptor, signature, exceptions)
        if (config != null && config.lifecycle[name] == descriptor) {
            presentLifecycle += name
            delegate = GuardInjectingMethodVisitor(delegate, superName, name, componentType!!, config)
        }
        return FirewallMethodVisitor(delegate)
    }

    override fun visitEnd() {
        if (config != null && config.canSynthesize) {
            for ((name, descriptor) in config.lifecycle) {
                if (name !in presentLifecycle) synthesizeGuardedOverride(name, descriptor)
            }
        }
        super.visitEnd()
    }

    private fun synthesizeGuardedOverride(name: String, descriptor: String) {
        val method = super.visitMethod(Opcodes.ACC_PROTECTED, name, descriptor, null, null)
        method.visitCode()
        method.visitVarInsn(Opcodes.ALOAD, 0)
        var slot = 1
        for (type in org.objectweb.asm.Type.getArgumentTypes(descriptor)) {
            method.visitVarInsn(type.getOpcode(Opcodes.ILOAD), slot)
            slot += type.size
        }
        method.visitMethodInsn(Opcodes.INVOKESPECIAL, superName, name, descriptor, false)
        emitGuardCall(method, componentType!!)
        method.visitInsn(Opcodes.RETURN)
        method.visitMaxs(0, 0)
        method.visitEnd()
    }
}

private class GuardInjectingMethodVisitor(
    next: MethodVisitor,
    private val superName: String,
    private val methodName: String,
    private val componentType: ComponentType,
    private val config: ComponentConfig,
) : MethodVisitor(Opcodes.ASM9, next) {
    private var injected = false

    override fun visitCode() {
        super.visitCode()
        if (!injected && config.injectAtMethodStart) {
            injected = true
            emitGuardCall(this, componentType)
        }
    }

    override fun visitMethodInsn(opcode: Int, owner: String, name: String, descriptor: String, isInterface: Boolean) {
        super.visitMethodInsn(opcode, owner, name, descriptor, isInterface)
        if (!injected && !config.injectAtMethodStart && opcode == Opcodes.INVOKESPECIAL && owner == superName && name == methodName) {
            injected = true
            emitGuardCall(this, componentType)
        }
    }
}

private fun emitGuardCall(method: MethodVisitor, type: ComponentType) {
    val config = COMPONENT_CONFIGS.getValue(type)
    if (type == ComponentType.RECEIVER) {
        method.visitVarInsn(Opcodes.ALOAD, 1) // context argument in onReceive(Context, Intent)
    } else {
        method.visitVarInsn(Opcodes.ALOAD, 0) // this
    }
    method.visitMethodInsn(Opcodes.INVOKESTATIC, GUARD_OWNER, config.guardMethod, config.guardDescriptor, false)
    val continueLabel = Label()
    method.visitJumpInsn(Opcodes.IFNE, continueLabel)
    method.visitInsn(Opcodes.RETURN)
    method.visitLabel(continueLabel)
}

private class FirewallMethodVisitor(next: MethodVisitor) : MethodVisitor(Opcodes.ASM9, next) {
    override fun visitMethodInsn(
        opcode: Int,
        owner: String,
        name: String,
        descriptor: String,
        isInterface: Boolean
    ) {
        if (opcode == Opcodes.INVOKEVIRTUAL && owner == "android/content/ClipboardManager") {
            if (name == "getPrimaryClip" && descriptor == "()Landroid/content/ClipData;") {
                super.visitMethodInsn(
                    Opcodes.INVOKESTATIC,
                    "com/apparmorx/runtime/DependencyFirewall",
                    "getPrimaryClip",
                    "(Landroid/content/ClipboardManager;)Landroid/content/ClipData;",
                    false
                )
                return
            }
            if (name == "hasPrimaryClip" && descriptor == "()Z") {
                super.visitMethodInsn(
                    Opcodes.INVOKESTATIC,
                    "com/apparmorx/runtime/DependencyFirewall",
                    "hasPrimaryClip",
                    "(Landroid/content/ClipboardManager;)Z",
                    false
                )
                return
            }
        }
        if (opcode == Opcodes.INVOKESTATIC && owner == "android/provider/Settings\$Secure") {
            if (name == "getString" && descriptor == "(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;") {
                super.visitMethodInsn(
                    Opcodes.INVOKESTATIC,
                    "com/apparmorx/runtime/DependencyFirewall",
                    "getString",
                    "(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;",
                    false
                )
                return
            }
        }
        if (opcode == Opcodes.INVOKEVIRTUAL && owner == "android/location/LocationManager") {
            if (name == "getLastKnownLocation" && descriptor == "(Ljava/lang/String;)Landroid/location/Location;") {
                super.visitMethodInsn(
                    Opcodes.INVOKESTATIC,
                    "com/apparmorx/runtime/DependencyFirewall",
                    "getLastKnownLocation",
                    "(Landroid/location/LocationManager;Ljava/lang/String;)Landroid/location/Location;",
                    false
                )
                return
            }
        }
        if (opcode == Opcodes.INVOKEVIRTUAL && owner == "android/telephony/TelephonyManager") {
            if (name == "getDeviceId" && descriptor == "()Ljava/lang/String;") {
                super.visitMethodInsn(
                    Opcodes.INVOKESTATIC,
                    "com/apparmorx/runtime/DependencyFirewall",
                    "getDeviceId",
                    "(Landroid/telephony/TelephonyManager;)Ljava/lang/String;",
                    false
                )
                return
            }
            if (name == "getImei" && descriptor == "()Ljava/lang/String;") {
                super.visitMethodInsn(
                    Opcodes.INVOKESTATIC,
                    "com/apparmorx/runtime/DependencyFirewall",
                    "getImei",
                    "(Landroid/telephony/TelephonyManager;)Ljava/lang/String;",
                    false
                )
                return
            }
        }
        if (opcode == Opcodes.INVOKESTATIC && owner == "javax/net/ssl/HttpsURLConnection") {
            if (name == "setDefaultHostnameVerifier" && descriptor == "(Ljavax/net/ssl/HostnameVerifier;)V") {
                super.visitMethodInsn(
                    Opcodes.INVOKESTATIC,
                    "com/apparmorx/runtime/DependencyFirewall",
                    "setDefaultHostnameVerifier",
                    "(Ljavax/net/ssl/HostnameVerifier;)V",
                    false
                )
                return
            }
        }
        if (opcode == Opcodes.INVOKEVIRTUAL && owner == "javax/net/ssl/HttpsURLConnection") {
            if (name == "setHostnameVerifier" && descriptor == "(Ljavax/net/ssl/HostnameVerifier;)V") {
                super.visitMethodInsn(
                    Opcodes.INVOKESTATIC,
                    "com/apparmorx/runtime/DependencyFirewall",
                    "setHostnameVerifier",
                    "(Ljavax/net/ssl/HttpsURLConnection;Ljavax/net/ssl/HostnameVerifier;)V",
                    false
                )
                return
            }
        }
        if (opcode == Opcodes.INVOKEVIRTUAL && owner == "javax/net/ssl/SSLContext") {
            if (name == "init" && descriptor == "([Ljavax/net/ssl/KeyManager;[Ljavax/net/ssl/TrustManager;Ljava/security/SecureRandom;)V") {
                super.visitMethodInsn(
                    Opcodes.INVOKESTATIC,
                    "com/apparmorx/runtime/DependencyFirewall",
                    "sslContextInit",
                    "(Ljavax/net/ssl/SSLContext;[Ljavax/net/ssl/KeyManager;[Ljavax/net/ssl/TrustManager;Ljava/security/SecureRandom;)V",
                    false
                )
                return
            }
        }
        super.visitMethodInsn(opcode, owner, name, descriptor, isInterface)
    }
}

