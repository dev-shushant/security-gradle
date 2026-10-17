package com.apparmorx.gradle

import com.android.build.api.instrumentation.AsmClassVisitorFactory
import com.android.build.api.instrumentation.ClassContext
import com.android.build.api.instrumentation.ClassData
import com.android.build.api.instrumentation.InstrumentationParameters
import org.objectweb.asm.ClassVisitor

/** ALL-scope supported firewall calls and concrete provider-operation bodies; never synthesize lifecycle overrides. */
abstract class DependencyFirewallClassVisitorFactory : AsmClassVisitorFactory<InstrumentationParameters.None> {
    override fun createClassVisitor(classContext: ClassContext, nextClassVisitor: ClassVisitor): ClassVisitor =
        allScopeVisitor(classContext.currentClassData.className, classContext.currentClassData.superClasses, nextClassVisitor)

    override fun isInstrumentable(classData: ClassData): Boolean =
        isAllScopeInstrumentable(classData.className, classData.superClasses)

    companion object {
        private val remoteWorkerParents = setOf("androidx.work.multiprocess.RemoteListenableWorker", "androidx.work.multiprocess.RemoteCoroutineWorker")
        private val workerParents = setOf("androidx.work.ListenableWorker", "androidx.work.Worker", "androidx.work.CoroutineWorker") + remoteWorkerParents
        internal fun firewallVisitor(next: ClassVisitor): ClassVisitor = GuardVisitor(next, null)
        internal fun isAllScopeInstrumentable(name: String, superClasses: List<String>): Boolean =
            name == "androidx.work.ListenableWorker" || providerEligible(name, superClasses) || workerEligible(name, superClasses) || firewallEligible(name)
        private fun firewallEligible(name: String): Boolean =
            !name.startsWith("com.apparmorx.runtime.") && !name.startsWith("android.") && !name.startsWith("androidx.")
        private fun providerEligible(name: String, superClasses: List<String>): Boolean =
            "android.content.ContentProvider" in superClasses &&
                !name.startsWith("com.apparmorx.runtime.") && !name.startsWith("android.")
        private fun workerEligible(name: String, superClasses: List<String>): Boolean =
            superClasses.any { it in workerParents } &&
                !name.startsWith("com.apparmorx.runtime.") && !name.startsWith("android.")
        internal fun allScopeVisitor(name: String, superClasses: List<String>, next: ClassVisitor): ClassVisitor {
            if (name == "androidx.work.ListenableWorker") return RemoteWorkerStopVisitor(next)
            var visitor = next
            if (providerEligible(name, superClasses)) visitor = ProviderOperationVisitor(visitor)
            if (workerEligible(name, superClasses)) visitor = WorkerOperationVisitor(visitor,
                name == "androidx.work.Worker" || "androidx.work.Worker" in superClasses,
                name in remoteWorkerParents || superClasses.any { it in remoteWorkerParents })
            if (firewallEligible(name)) visitor = firewallVisitor(visitor)
            return visitor
        }
    }
}
