package com.apparmorx.sample

import android.content.ContentProviderClient
import android.content.pm.ApplicationInfo
import android.net.Uri
import android.os.Process
import android.os.Bundle
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.apparmorx.runtime.*
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import com.apparmorx.fixture.vendor.LibraryProvider
import org.json.JSONArray
import org.json.JSONObject

/** Actual same-app resolver/client routing with synthetic policy/evidence; not a remote-UID attack test. */
@RunWith(AndroidJUnit4::class)
class ProviderOperationQualificationTest {
    private val calls = JSONArray()
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val debug get() = context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
    private val uri get() = Uri.parse("content://${context.packageName}.apparmorx.fixture/data")
    private fun field(name: String) = SecurityRuntime::class.java.getDeclaredField(name).apply { isAccessible = true }
    private fun controlled(case: String, test: (SecuritySnapshot) -> Unit) {
        val deadline = SystemClock.elapsedRealtime() + 20_000
        while (SecurityRuntime.snapshot().evidence.none { it.check == "native-engine" } ||
            (field("scanning").get(SecurityRuntime) as AtomicBoolean).get()) {
            check(SystemClock.elapsedRealtime() < deadline) { "Initial full scan did not finish" }
            Thread.sleep(50)
        }
        val original = SecurityRuntime.snapshot()
        val elapsed = field("lastScanElapsed").getLong(SecurityRuntime)
        try {
            field("lastScanElapsed").setLong(SecurityRuntime, SystemClock.elapsedRealtime())
            val base = original.copy(checkedAtMillis = System.currentTimeMillis(),
                evidence = listOf(Evidence("policy", Status.CLEAR), Evidence("signing-certificate", Status.CLEAR),
                    Evidence("native-engine", Status.CLEAR)),
                enforcement = original.enforcement.copy(restrictedAction = EnforcementAction.BLOCK_SCREEN,
                    enforceIndeterminate = false, failClosedOnStartup = false, killOnConfirmedHooking = false))
            assertTrue("Provider initialization must remain available", SampleContentProvider.initializations.get() >= 1)
            test(base)
            InstrumentationRegistry.getInstrumentation().sendStatus(0, Bundle().apply {
                putString("stream", "AAX_PROVIDER_EVIDENCE " + JSONObject().put("case", case)
                    .put("debuggable", debug).put("uid", Process.myUid()).put("syntheticEvidence", true)
                    .put("providerInitialized", SampleContentProvider.initializations.get() >= 1)
                    .put("libraryProviderInitialized", LibraryProvider.initializations.get() >= 1).put("calls", calls))
            })
        } finally {
            field("current").set(SecurityRuntime, original)
            field("lastScanElapsed").setLong(SecurityRuntime, elapsed)
        }
    }
    private fun set(snapshot: SecuritySnapshot) { field("current").set(SecurityRuntime, snapshot) }
    private fun client(): ContentProviderClient = requireNotNull(context.contentResolver.acquireContentProviderClient(uri))
    private fun checkCall(allowed: Boolean, counter: AtomicInteger = SampleContentProvider.operations, block: () -> Any?) {
        val before = counter.get()
        var denied = false
        try {
            block()
            assertTrue("Restricted operation returned instead of denying", allowed)
        } catch (failure: SecurityException) {
            denied = true
            assertFalse("Allowed/debug operation was denied", allowed)
        }
        assertEquals("Denied calls must not enter host body", before + if (allowed) 1 else 0,
            counter.get())
        calls.put(JSONObject().put("expectedAllowed", allowed).put("denied", denied)
            .put("hostBodyBefore", before).put("hostBodyAfter", counter.get())
            .put("counterOwner", if (counter === LibraryProvider.operations) "dependency" else "project")
            .put("observedState", SecurityGuard.lastObservedState().name))
    }

    @Test fun clearEvidencePreservesFrameworkCallQueryAndDeleteResults() = controlled("clear") { base ->
        set(base)
        client().use { client ->
            checkCall(true) { assertEquals("AppArmorX provider body", client.call("probe", null, null)?.getString("marker")) }
            checkCall(true) { client.query(uri, null, null, null, null)!!.use { cursor ->
                assertTrue(cursor.moveToFirst()); assertEquals("AppArmorX", cursor.getString(0))
            } }
            checkCall(true) { assertEquals(37, client.delete(uri, null, null)) }
        }
    }

    @Test fun restrictedEvidenceDeniesBeforeHostWorkButDebugStillObserves() = controlled("restricted") { base ->
        set(base.copy(evidence = base.evidence + Evidence("fixture-threat", Status.DETECTED)))
        val pid = Process.myPid()
        client().use { client ->
            checkCall(debug) { client.call("probe", null, null) }
            checkCall(debug) { client.query(uri, null, null, null, null)?.close() }
            checkCall(debug) { client.delete(uri, null, null) }
        }
        assertEquals("No default process termination on denial", pid, Process.myPid())
    }

    @Test fun unavailableAndCheckingHonorExplicitResponseWithoutBecomingClear() = controlled("unknown-pending") { base ->
        client().use { client ->
            val unknown = base.copy(evidence = base.evidence.map { if (it.check == "native-engine") it.copy(status = Status.UNAVAILABLE) else it })
            set(unknown)
            checkCall(true) { client.call("probe", null, null) }
            set(unknown.copy(enforcement = unknown.enforcement.copy(enforceIndeterminate = true)))
            checkCall(debug) { client.call("probe", null, null) }
            val pending = base.copy(evidence = listOf(Evidence("scan-pending", Status.UNAVAILABLE)))
            set(pending)
            checkCall(true) { client.call("probe", null, null) }
            set(pending.copy(enforcement = pending.enforcement.copy(failClosedOnStartup = true)))
            checkCall(debug) { client.call("probe", null, null) }
        }
    }

    @Test fun cachedClientRechecksLaterRestrictionAndCanUseFreshAllowedEvidence() = controlled("cached-client") { base ->
        client().use { cached ->
            set(base)
            checkCall(true) { cached.call("probe", null, null) }
            set(base.copy(evidence = base.evidence + Evidence("fixture-threat", Status.DETECTED)))
            checkCall(debug) { cached.call("probe", null, null) }
            set(base)
            checkCall(true) { cached.call("probe", null, null) }
        }
    }

    @Test fun inheritedFinalDependencyBodiesAreGuardedWithoutAppOverrides() = controlled("inherited-library") { base ->
        assertTrue(LibraryProvider.initializations.get() >= 1)
        assertFalse(InheritedContentProvider::class.java.declaredMethods.any { it.name == "getType" || it.name == "call" })
        val inherited = InheritedContentProvider::class.java.getMethod("getType", Uri::class.java)
        assertEquals(LibraryProvider::class.java, inherited.declaringClass)
        assertTrue(java.lang.reflect.Modifier.isFinal(inherited.modifiers))
        val authority = Uri.parse("content://${context.packageName}.apparmorx.inherited/data")
        requireNotNull(context.contentResolver.acquireContentProviderClient(authority)).use { cached ->
            set(base)
            checkCall(true, LibraryProvider.operations) {
                assertEquals("AppArmorX library body", cached.call("probe", null, null)?.getString("marker"))
            }
            checkCall(true, LibraryProvider.operations) { assertEquals("vnd.android.cursor.item/apparmorx-library", cached.getType(authority)) }
            set(base.copy(evidence = base.evidence + Evidence("fixture-threat", Status.DETECTED)))
            checkCall(debug, LibraryProvider.operations) { cached.call("probe", null, null) }
            set(base)
            checkCall(true, LibraryProvider.operations) { cached.call("probe", null, null) }
        }
    }
}
