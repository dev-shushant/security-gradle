package com.apparmorx.sample

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
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

@RunWith(AndroidJUnit4::class)
class MultiprocessEnforcementQualificationTest {
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private fun field(name: String) = SecurityRuntime::class.java.getDeclaredField(name).apply { isAccessible = true }
    private fun control(method: String, state: String? = null) = requireNotNull(context.contentResolver.call(
        Uri.parse("content://${context.packageName}.fixture.process"), method, state, null))

    @Test fun frameworkBindingUsesSecondaryEvidenceRatherThanMainVerdict() {
        assumeTrue("Explicit process qualification build required", context.packageManager.resolveContentProvider(
            "${context.packageName}.fixture.process", 0) != null)
        val debug = context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
        val end = SystemClock.elapsedRealtime() + 30_000
        while (SecurityRuntime.snapshot().evidence.none { it.check == "native-engine" } ||
            (field("scanning").get(SecurityRuntime) as AtomicBoolean).get()) {
            check(SystemClock.elapsedRealtime() < end) { "Main scan did not finish" }; Thread.sleep(50)
        }
        val original = SecurityRuntime.snapshot()
        val elapsed = field("lastScanElapsed").getLong(SecurityRuntime)
        val calls = JSONArray()
        try {
            field("lastScanElapsed").setLong(SecurityRuntime, SystemClock.elapsedRealtime())
            for ((index, secondaryState) in listOf("clear", "restricted", "unknown", "pending", "clear").withIndex()) {
                val mainRestricted = index == 4
                val clear = listOf(Evidence("policy", Status.CLEAR), Evidence("signing-certificate", Status.CLEAR), Evidence("native-engine", Status.CLEAR))
                field("current").set(SecurityRuntime, original.copy(checkedAtMillis = System.currentTimeMillis(), policySequence = 808,
                    evidence = clear + if (mainRestricted) listOf(Evidence("fixture-main-threat", Status.DETECTED)) else emptyList()))
                val main = requireNotNull(context.contentResolver.call(Uri.parse("content://${context.packageName}.apparmorx.init"), "getSecurityState", null, null))
                assertEquals(if (mainRestricted) "RESTRICTED" else "READY", main.getString("evidenceState"))
                val before = control("set", secondaryState)
                assertNotEquals(Process.myPid(), before.getInt("pid"))
                assertEquals(Process.myUid(), before.getInt("uid"))
                val connected = CountDownLatch(1)
                var outcome = "missing"
                val connection = object : ServiceConnection {
                    override fun onServiceConnected(name: ComponentName, service: IBinder) { outcome = "bound"; connected.countDown() }
                    override fun onNullBinding(name: ComponentName) { outcome = "null"; connected.countDown() }
                    override fun onBindingDied(name: ComponentName) { outcome = "died"; connected.countDown() }
                    override fun onServiceDisconnected(name: ComponentName) = Unit
                }
                val intent = Intent("com.apparmorx.fixture.BIND.$index").setClassName(context.packageName, "com.apparmorx.sample.MultiprocessGuardService")
                assertTrue("Framework rejected bind request", context.bindService(intent, connection, Context.BIND_AUTO_CREATE))
                try {
                    assertTrue("No binding callback", connected.await(20, TimeUnit.SECONDS))
                    val allowed = debug || secondaryState == "clear"
                    assertEquals(if (allowed) "bound" else "null", outcome)
                    val after = control("read")
                    assertEquals(before.getInt("pid"), after.getInt("pid"))
                    assertEquals(before.getInt("binds") + if (allowed) 1 else 0, after.getInt("binds"))
                    val expected = when (secondaryState) { "clear" -> "READY"; "restricted" -> "RESTRICTED"; "unknown" -> "INDETERMINATE"; else -> "CHECKING" }
                    assertEquals(expected, after.getString("state"))
                    assertEquals(707L, after.getLong("sequence"))
                    calls.put(JSONObject().put("secondaryState", secondaryState).put("mainState", main.getString("evidenceState"))
                        .put("mainPid", Process.myPid()).put("secondaryPid", after.getInt("pid")).put("uid", after.getInt("uid"))
                        .put("observedState", expected).put("binding", outcome).put("allowed", allowed)
                        .put("before", before.getInt("binds")).put("after", after.getInt("binds")))
                } finally { context.unbindService(connection) }
            }
            instrumentation.sendStatus(0, Bundle().apply {
                putString("stream", "AAX_MULTIPROCESS_EVIDENCE " + JSONObject().put("debuggable", debug)
                    .put("syntheticEvidence", true).put("calls", calls))
            })
        } finally {
            try { control("restore") } finally {
                field("current").set(SecurityRuntime, original)
                field("lastScanElapsed").setLong(SecurityRuntime, elapsed)
            }
        }
    }
}
