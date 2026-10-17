package com.apparmorx.gradle

import com.android.build.api.instrumentation.AsmClassVisitorFactory
import com.android.build.api.instrumentation.ClassContext
import com.android.build.api.instrumentation.ClassData
import com.android.build.api.instrumentation.InstrumentationParameters
import org.objectweb.asm.ClassVisitor

private const val ACTIVITY_CLASS = "android.app.Activity"
private const val APPLICATION_CLASS = "android.app.Application"
private const val SERVICE_CLASS = "android.app.Service"
private const val RECEIVER_CLASS = "android.content.BroadcastReceiver"

private val FRAMEWORK_BASE_CLASSES = setOf(
    ACTIVITY_CLASS,
    APPLICATION_CLASS,
    SERVICE_CLASS,
    RECEIVER_CLASS
)

/**
 * AGP bytecode-instrumentation entry point. AGP calls [isInstrumentable] with the full,
 * cross-dependency class hierarchy, then [createClassVisitor] for every class it accepted.
 * Guards project Activity, Application, Service and BroadcastReceiver callbacks.
 */
abstract class GuardClassVisitorFactory : AsmClassVisitorFactory<InstrumentationParameters.None> {
    override fun createClassVisitor(classContext: ClassContext, nextClassVisitor: ClassVisitor): ClassVisitor =
        componentGuardVisitor(classContext.currentClassData.superClasses, nextClassVisitor)

    override fun isInstrumentable(classData: ClassData): Boolean =
        !isSecurityUiHierarchy(classData.superClasses) &&
        classData.className !in FRAMEWORK_BASE_CLASSES &&
        !classData.className.startsWith("com.apparmorx.runtime.") &&
        !classData.className.startsWith("android.") &&
        !classData.className.startsWith("androidx.")

}

internal fun componentGuardVisitor(superClasses: List<String>, next: ClassVisitor): ClassVisitor {
    return GuardVisitor(next, when {
    ACTIVITY_CLASS in superClasses -> ComponentType.ACTIVITY
    APPLICATION_CLASS in superClasses -> ComponentType.APPLICATION
    SERVICE_CLASS in superClasses -> ComponentType.SERVICE
    RECEIVER_CLASS in superClasses -> ComponentType.RECEIVER
    else -> null
    })
}

/** Recovery UI owns its lifecycle; synthesized guards would recurse or override final controller methods. */
internal fun isSecurityUiHierarchy(superClasses: List<String>): Boolean =
    "com.apparmorx.runtime.SecurityBlockActivity" in superClasses
