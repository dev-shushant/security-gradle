package com.apparmorx.sample

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.apparmorx.runtime.SecurityRuntime
import com.apparmorx.runtime.Status
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Explicit app-sandbox evidence capture for paired clean/root-enabled AVD qualification. */
@RunWith(AndroidJUnit4::class)
class DeviceEvidenceReportTest {
    @Test fun recordsProbeEvidenceAndChecksIndependentRootPathObservations() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val deadline = System.nanoTime() + 20_000_000_000L
        while (SecurityRuntime.snapshot().evidence.none { it.check == "native-engine" } && System.nanoTime() < deadline) {
            Thread.sleep(50)
        }
        val snapshot = SecurityRuntime.snapshot()
        assertTrue("Full scan must complete", snapshot.evidence.any { it.check == "native-engine" })
        val checks = JSONObject()
        snapshot.evidence.forEach { checks.put(it.check, it.status.name) }
        val paths = JSONObject()
        val parentListings = JSONObject()
        for (path in listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/data/adb/magisk")) {
            val state = try {
                android.system.Os.stat(path)
                Status.DETECTED
            } catch (error: android.system.ErrnoException) {
                if (error.errno == android.system.OsConstants.ENOENT) Status.CLEAR else Status.UNAVAILABLE
            } catch (_: Exception) { Status.UNAVAILABLE }
            paths.put(path, state.name)
            val file = java.io.File(path)
            val listed = runCatching { file.parentFile?.list()?.contains(file.name) }.getOrNull()
            parentListings.put(path, listed ?: JSONObject.NULL)
        }
        val observations = paths.keys().asSequence().map { paths.getString(it) }.toList()
        val expectedRootPath = when {
            Status.DETECTED.name in observations -> Status.DETECTED
            Status.UNAVAILABLE.name in observations -> Status.UNAVAILABLE
            else -> Status.CLEAR
        }
        val report = JSONObject()
            .put("schema", 1)
            .put("api", android.os.Build.VERSION.SDK_INT)
            .put("appUid", android.os.Process.myUid())
            .put("buildType", android.os.Build.TYPE)
            .put("checks", checks)
            .put("rootPathObservations", paths)
            .put("rootParentListsEntry", parentListings)
            .put("restrictedAction", snapshot.enforcement.restrictedAction.name)
        context.filesDir.resolve("apparmorx-device-evidence.json").writeText(report.toString(2))
        assertTrue("Tests must run in an application sandbox, not as root", android.os.Process.myUid() >= 10000)
        assertEquals("Root path result must match actual app-sandbox stat results", expectedRootPath,
            snapshot.evidence.single { it.check == "root-path" }.status)
        assertEquals("Packaged policy must parse", Status.CLEAR, snapshot.evidence.single { it.check == "policy" }.status)
        assertEquals("Unmodified APK must pass structural integrity", Status.CLEAR,
            snapshot.evidence.single { it.check == "apk-integrity" }.status)
        // This fixture intentionally uses a placeholder signer. Never call that mismatch a device threat.
        assertEquals(Status.DETECTED, snapshot.evidence.single { it.check == "signing-certificate" }.status)
        assertEquals("Debug fixture must observe without blocking", "OBSERVE", snapshot.enforcement.restrictedAction.name)
    }
}
