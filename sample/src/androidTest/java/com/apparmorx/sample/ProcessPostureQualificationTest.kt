package com.apparmorx.sample

import android.app.Application
import android.content.*
import android.content.pm.ApplicationInfo
import android.net.Uri
import android.os.*
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.apparmorx.runtime.*
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import org.json.JSONObject

@RunWith(AndroidJUnit4::class)
class ProcessPostureQualificationTest {
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private fun field(name: String) = SecurityRuntime::class.java.getDeclaredField(name).apply { isAccessible = true }
    private fun report() = requireNotNull(context.contentResolver.call(
        Uri.parse("content://${context.packageName}.apparmorx.init"), "getSecurityState", null, null))
    private fun controlled(block: (SecuritySnapshot) -> Unit) {
        val end = SystemClock.elapsedRealtime() + 30_000
        while (SecurityRuntime.snapshot().evidence.none { it.check == "native-engine" } ||
            (field("scanning").get(SecurityRuntime) as AtomicBoolean).get()) {
            check(SystemClock.elapsedRealtime() < end) { "Initial scan did not finish" }
            Thread.sleep(50)
        }
        val original = SecurityRuntime.snapshot()
        val elapsed = field("lastScanElapsed").getLong(SecurityRuntime)
        try {
            field("lastScanElapsed").setLong(SecurityRuntime, SystemClock.elapsedRealtime())
            block(original)
        } finally {
            field("current").set(SecurityRuntime, original)
            field("lastScanElapsed").setLong(SecurityRuntime, elapsed)
        }
    }
    @Test fun localResponseIdentifiesResponderAndSeparatesFreshEvidenceFromGuardHistory() = controlled { original ->
        val last = SecurityGuard.lastObservedState().name
        val now = System.currentTimeMillis()
        val cases = listOf(
            SecuritySnapshot(now, 37, listOf(Evidence("fixture-threat", Status.DETECTED))) to "RESTRICTED",
            SecuritySnapshot(now, 37, emptyList()) to "INDETERMINATE",
            SecuritySnapshot(0, 37, emptyList()) to "CHECKING")
        for ((snapshot, expected) in cases) {
            field("current").set(SecurityRuntime, snapshot.copy(enforcement = original.enforcement))
            val response = report()
            assertEquals(expected, response.getString("evidenceState"))
            assertEquals(last, response.getString("state"))
            assertEquals("last-guard", response.getString("stateSource"))
            assertEquals("responding-process", response.getString("scope"))
            assertEquals(Process.myPid(), response.getInt("responderPid"))
            assertEquals(Process.myUid(), response.getInt("responderUid"))
            assertEquals(Application.getProcessName(), response.getString("responderProcess"))
        }
    }
    @Test fun secondaryProcessReportsActualProviderPlacementWithoutImportingMainSnapshot() {
        assumeTrue("Placement fixture exists only in debug", context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0)
        controlled { original ->
            val sentinel = 987654321L
            field("current").set(SecurityRuntime, original.copy(policySequence = sentinel))
            val connected = CountDownLatch(1)
            var binder: IBinder? = null
            val connection = object : ServiceConnection {
                override fun onServiceConnected(name: ComponentName, service: IBinder) { binder = service; connected.countDown() }
                override fun onServiceDisconnected(name: ComponentName) = Unit
            }
            val intent = Intent().setClassName(context.packageName, "com.apparmorx.sample.RemotePostureService")
            assertTrue(context.bindService(intent, connection, Context.BIND_AUTO_CREATE))
            try {
                assertTrue("Secondary service did not bind", connected.await(20, TimeUnit.SECONDS))
                val data = Parcel.obtain(); val reply = Parcel.obtain()
                try {
                    assertTrue(requireNotNull(binder).transact(IBinder.FIRST_CALL_TRANSACTION, data, reply, 0))
                    reply.readException()
                    val result = requireNotNull(reply.readBundle(javaClass.classLoader))
                    val secondaryPid = result.getInt("callerPid")
                    assertNotEquals(Process.myPid(), secondaryPid)
                    assertEquals(Process.myUid(), result.getInt("callerUid"))
                    val posture = requireNotNull(result.getBundle("posture"))
                    val responder = posture.getInt("responderPid")
                    assertTrue("Unexpected responder process", responder == secondaryPid || responder == Process.myPid())
                    assertEquals(Process.myUid(), posture.getInt("responderUid"))
                    assertEquals("responding-process", posture.getString("scope"))
                    if (responder == secondaryPid) assertNotEquals(sentinel, posture.getLong("sequence"))
                    else assertEquals(sentinel, posture.getLong("sequence"))
                    instrumentation.sendStatus(0, Bundle().apply {
                        putString("stream", "AAX_PROCESS_EVIDENCE " + JSONObject().put("mainPid", Process.myPid())
                            .put("secondaryPid", secondaryPid).put("responderPid", responder)
                            .put("uid", Process.myUid()).put("localClone", responder == secondaryPid)
                            .put("mainSequence", sentinel).put("responderSequence", posture.getLong("sequence")))
                    })
                } finally { data.recycle(); reply.recycle() }
            } finally { context.unbindService(connection) }
        }
    }
}
