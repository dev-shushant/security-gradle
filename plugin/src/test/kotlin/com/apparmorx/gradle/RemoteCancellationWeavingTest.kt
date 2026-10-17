package com.apparmorx.gradle

import org.junit.Assert.*
import org.junit.Test
import org.objectweb.asm.*
import java.lang.reflect.InvocationTargetException
import java.util.concurrent.Future

class RemoteCancellationWeavingTest {
    private class Loader:ClassLoader(RemoteCancellationWeavingTest::class.java.classLoader) {
        fun define(name:String,bytes:ByteArray)=defineClass(name.replace('/','.'),bytes,0,bytes.size)
    }
    private fun emit(name:String,parent:String="java/lang/Object",body:ClassWriter.()->Unit={}):ByteArray {
        val w=ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        w.visit(Opcodes.V17,Opcodes.ACC_PUBLIC,name,null,parent,null)
        w.visitMethod(Opcodes.ACC_PUBLIC,"<init>","()V",null,null).apply {
            visitCode();visitVarInsn(Opcodes.ALOAD,0);visitMethodInsn(Opcodes.INVOKESPECIAL,parent,"<init>","()V",false)
            visitInsn(Opcodes.RETURN);visitMaxs(0,0);visitEnd()
        };w.body();w.visitEnd();return w.toByteArray()
    }
    private fun woven(name:String,parent:String,input:ByteArray):ByteArray {
        val w=ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        ClassReader(input).accept(DependencyFirewallClassVisitorFactory.allScopeVisitor(name.replace('/','.'),listOf(parent.replace('/','.')),w),0)
        return w.toByteArray()
    }
    private fun fixture(throwOnStop:Boolean=false, observeStop:Boolean=true, hostCatchesStop:Boolean=false):Class<*> {
        val loader=Loader()
        loader.define("android/content/Context",emit("android/content/Context"))
        loader.define("com/google/common/util/concurrent/ListenableFuture",emit("com/google/common/util/concurrent/ListenableFuture","java/util/concurrent/CompletableFuture"))
        loader.define("com/apparmorx/runtime/SecurityGuard",emit("com/apparmorx/runtime/SecurityGuard") {
            visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC,"allowWorker","(Landroid/content/Context;)Z",null,null).apply {
                visitCode();visitInsn(Opcodes.ICONST_1);visitInsn(Opcodes.IRETURN);visitMaxs(0,0);visitEnd()
            }
        })
        // Executable protocol bridge delegates to this test's Java-Future-only implementation.
        loader.define("com/apparmorx/runtime/RemoteWorkerCancellation",emit("com/apparmorx/runtime/RemoteWorkerCancellation") {
            for ((name,desc) in listOf("track" to "(Ljava/lang/Object;Ljava/util/concurrent/Future;)V","stopped" to "(Ljava/lang/Object;)V")) {
                visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC,name,desc,null,null).apply {
                    visitCode();visitVarInsn(Opcodes.ALOAD,0);if(name=="track")visitVarInsn(Opcodes.ALOAD,1)
                    visitMethodInsn(Opcodes.INVOKESTATIC,"com/apparmorx/gradle/RemoteCancellationWeavingTest",name,desc,false)
                    visitInsn(Opcodes.RETURN);visitMaxs(0,0);visitEnd()
                }
            }
        })
        val owner=ClassWriter(0)
        owner.visit(Opcodes.V17,Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT or Opcodes.ACC_INTERFACE,"com/apparmorx/runtime/RemoteWorkerCancellationOwner",null,"java/lang/Object",null)
        owner.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT,"appArmorXGetRemoteCancellationState","()Ljava/lang/Object;",null,null).visitEnd()
        owner.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT,"appArmorXSetRemoteCancellationState","(Ljava/lang/Object;)V",null,null).visitEnd()
        owner.visitEnd();loader.define("com/apparmorx/runtime/RemoteWorkerCancellationOwner",owner.toByteArray())
        val base="androidx/work/ListenableWorker"
        val rawBase=emit(base) {
            visitField(Opcodes.ACC_PUBLIC,"stopped","Z",null,null).visitEnd()
            visitMethod(Opcodes.ACC_PUBLIC,"getApplicationContext","()Landroid/content/Context;",null,null).apply { visitCode();visitInsn(Opcodes.ACONST_NULL);visitInsn(Opcodes.ARETURN);visitMaxs(0,0);visitEnd() }
            visitMethod(Opcodes.ACC_PUBLIC,"isStopped","()Z",null,null).apply { visitCode();visitVarInsn(Opcodes.ALOAD,0);visitFieldInsn(Opcodes.GETFIELD,base,"stopped","Z");visitInsn(Opcodes.IRETURN);visitMaxs(0,0);visitEnd() }
            visitMethod(Opcodes.ACC_PUBLIC,"onStopped","()V",null,null).apply { visitCode();visitInsn(Opcodes.RETURN);visitMaxs(0,0);visitEnd() }
            visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_FINAL,"stop","(I)V",null,null).apply {
                visitCode();visitVarInsn(Opcodes.ALOAD,0);visitInsn(Opcodes.ICONST_1);visitFieldInsn(Opcodes.PUTFIELD,base,"stopped","Z")
                val start=Label();val end=Label();val caught=Label();val done=Label()
                if(hostCatchesStop) visitTryCatchBlock(start,end,caught,"java/lang/IllegalArgumentException")
                visitLabel(start)
                visitVarInsn(Opcodes.ALOAD,0);visitMethodInsn(Opcodes.INVOKEVIRTUAL,base,"onStopped","()V",false)
                visitLabel(end)
                if(hostCatchesStop) { visitJumpInsn(Opcodes.GOTO,done);visitLabel(caught);visitInsn(Opcodes.POP);visitLabel(done) }
                visitInsn(Opcodes.RETURN);visitMaxs(0,0);visitEnd()
            }
        }
        loader.define(base,if(observeStop) woven(base,"java/lang/Object",rawBase) else rawBase)
        val name="fixture/RemoteWorker"
        val raw=emit(name,base) {
            visitField(Opcodes.ACC_PUBLIC,"future","Lcom/google/common/util/concurrent/ListenableFuture;",null,null).visitEnd()
            visitField(Opcodes.ACC_PUBLIC,"callbacks","I",null,null).visitEnd()
            visitMethod(Opcodes.ACC_PUBLIC,"startRemoteWork","()Lcom/google/common/util/concurrent/ListenableFuture;",null,null).apply {
                visitCode();visitVarInsn(Opcodes.ALOAD,0);visitTypeInsn(Opcodes.NEW,"com/google/common/util/concurrent/ListenableFuture");visitInsn(Opcodes.DUP)
                visitMethodInsn(Opcodes.INVOKESPECIAL,"com/google/common/util/concurrent/ListenableFuture","<init>","()V",false)
                visitFieldInsn(Opcodes.PUTFIELD,name,"future","Lcom/google/common/util/concurrent/ListenableFuture;")
                visitVarInsn(Opcodes.ALOAD,0);visitFieldInsn(Opcodes.GETFIELD,name,"future","Lcom/google/common/util/concurrent/ListenableFuture;")
                visitInsn(Opcodes.ARETURN);visitMaxs(0,0);visitEnd()
            }
            visitMethod(Opcodes.ACC_PUBLIC,"onStopped","()V",null,null).apply {
                visitCode();visitVarInsn(Opcodes.ALOAD,0);visitInsn(Opcodes.DUP);visitFieldInsn(Opcodes.GETFIELD,name,"callbacks","I");visitInsn(Opcodes.ICONST_1);visitInsn(Opcodes.IADD);visitFieldInsn(Opcodes.PUTFIELD,name,"callbacks","I")
                if(throwOnStop) { visitTypeInsn(Opcodes.NEW,"java/lang/IllegalArgumentException");visitInsn(Opcodes.DUP);visitLdcInsn("fixture callback")
                    visitMethodInsn(Opcodes.INVOKESPECIAL,"java/lang/IllegalArgumentException","<init>","(Ljava/lang/String;)V",false);visitInsn(Opcodes.ATHROW)
                } else visitInsn(Opcodes.RETURN)
                visitMaxs(0,0);visitEnd()
            }
        }
        val w=ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        ClassReader(raw).accept(WorkerOperationVisitor(w,false,true),0)
        return loader.define(name,w.toByteArray())
    }
    @Test fun remoteFutureCancelledAfterOriginalStopCallback() {
        val t=fixture();val w=t.getConstructor().newInstance();val future=t.getMethod("startRemoteWork").invoke(w) as Future<*>
        assertFalse(future.isCancelled);t.getMethod("stop",Int::class.javaPrimitiveType).invoke(w,1)
        assertTrue(future.isCancelled);assertEquals(1,t.getField("callbacks").getInt(w))
    }
    @Test fun stopBeforeFutureReturnIsNotLost() {
        val t=fixture();val w=t.getConstructor().newInstance();t.getMethod("stop",Int::class.javaPrimitiveType).invoke(w,1)
        val future=t.getMethod("startRemoteWork").invoke(w) as Future<*>
        assertTrue(future.isCancelled)
    }
    @Test fun throwingHostStopStillCancelsAndPreservesOriginalException() {
        val t=fixture(true);val w=t.getConstructor().newInstance();val future=t.getMethod("startRemoteWork").invoke(w) as Future<*>
        try { t.getMethod("stop",Int::class.javaPrimitiveType).invoke(w,1);fail("Expected original callback exception") }
        catch(e:InvocationTargetException) { assertEquals("fixture callback",e.cause?.message) }
        assertTrue(future.isCancelled);assertEquals(1,t.getField("callbacks").getInt(w))
    }
    @Test fun negativeControlWithoutStopObserverRetainsUpstreamFailure() {
        val t=fixture(observeStop=false);val w=t.getConstructor().newInstance()
        val future=t.getMethod("startRemoteWork").invoke(w) as Future<*>
        t.getMethod("stop",Int::class.javaPrimitiveType).invoke(w,1)
        assertEquals(1,t.getField("callbacks").getInt(w));assertFalse(future.isCancelled)
        stopped(w) // Release protocol-fixture references after this negative control.
    }
    @Test fun hostExceptionHandlersKeepPriorityOverCompatibilityFinally() {
        val t=fixture(throwOnStop=true,hostCatchesStop=true);val w=t.getConstructor().newInstance()
        val future=t.getMethod("startRemoteWork").invoke(w) as Future<*>
        t.getMethod("stop",Int::class.javaPrimitiveType).invoke(w,1)
        assertTrue(future.isCancelled);assertEquals(1,t.getField("callbacks").getInt(w))
    }
    companion object {
        private val futures=java.util.IdentityHashMap<Any,MutableList<Future<*>>>()
        @JvmStatic @Synchronized fun track(worker:Any,future:Future<*>) { futures.getOrPut(worker){ mutableListOf() }.add(future) }
        @JvmStatic @Synchronized fun stopped(worker:Any) { futures.remove(worker)?.forEach { it.cancel(false) } }
    }
}
