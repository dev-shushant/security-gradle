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
 * Guards Activity, Application, Service, and BroadcastReceiver components.
 */
abstract class GuardClassVisitorFactory : AsmClassVisitorFactory<InstrumentationParameters.None> {
    override fun createClassVisitor(classContext: ClassContext, nextClassVisitor: ClassVisitor): ClassVisitor =
        GuardVisitor(nextClassVisitor, resolveComponentType(classContext.currentClassData))

    override fun isInstrumentable(classData: ClassData): Boolean =
        classData.className !in FRAMEWORK_BASE_CLASSES &&
        !classData.className.startsWith("com.apparmorx.runtime.") &&
        !classData.className.startsWith("android.") &&
        !classData.className.startsWith("androidx.")

    private fun resolveComponentType(classData: ClassData): ComponentType? = when {
        ACTIVITY_CLASS in classData.superClasses -> ComponentType.ACTIVITY
        APPLICATION_CLASS in classData.superClasses -> ComponentType.APPLICATION
        SERVICE_CLASS in classData.superClasses -> ComponentType.SERVICE
        RECEIVER_CLASS in classData.superClasses -> ComponentType.RECEIVER
        else -> null
    }
}
