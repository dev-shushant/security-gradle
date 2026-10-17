package com.apparmorx.gradle

import com.android.build.api.instrumentation.AsmClassVisitorFactory
import com.android.build.api.instrumentation.ClassContext
import com.android.build.api.instrumentation.ClassData
import com.android.build.api.instrumentation.InstrumentationParameters
import org.objectweb.asm.ClassVisitor

/** Rewrite supported dependency calls, without injecting lifecycle methods into library components. */
abstract class DependencyFirewallClassVisitorFactory : AsmClassVisitorFactory<InstrumentationParameters.None> {
    override fun createClassVisitor(classContext: ClassContext, nextClassVisitor: ClassVisitor): ClassVisitor =
        firewallVisitor(nextClassVisitor)

    override fun isInstrumentable(classData: ClassData): Boolean =
        !classData.className.startsWith("com.apparmorx.runtime.") &&
        !classData.className.startsWith("android.") &&
        !classData.className.startsWith("androidx.")

    companion object {
        internal fun firewallVisitor(next: ClassVisitor): ClassVisitor = GuardVisitor(next, null)
    }
}
