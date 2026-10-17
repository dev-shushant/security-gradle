package com.apparmorx.sample

import android.content.ComponentName
import android.content.pm.PackageManager
import android.content.Context
import android.content.Intent
import android.view.View
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.apparmorx.runtime.SecurityBlockActivity
import com.apparmorx.runtime.ProtectionState
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Presentation fixtures only, not proof that this device is clean or rooted. */
@RunWith(AndroidJUnit4::class)
class SecurityUiQualificationTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun manifestChoosesOwnedCustomSubclass() {
        val router = Class.forName("com.apparmorx.runtime.SecurityUiDestination")
        val destination = router.getMethod("intent", Context::class.java)
            .invoke(router.getField("INSTANCE").get(null), context) as Intent
        assertEquals(BrandedSecurityActivity::class.java.name, destination.component?.className)
    }

    @Test fun disabledCustomScreenFallsBackToBundledScreen() {
        val component = ComponentName(context, BrandedSecurityActivity::class.java)
        val manager = context.packageManager
        val original = manager.getComponentEnabledSetting(component)
        try {
            manager.setComponentEnabledSetting(component, PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                PackageManager.DONT_KILL_APP)
            val router = Class.forName("com.apparmorx.runtime.SecurityUiDestination")
            val destination = router.getMethod("intent", Context::class.java)
                .invoke(router.getField("INSTANCE").get(null), context) as Intent
            assertEquals(SecurityBlockActivity::class.java.name, destination.component?.className)
        } finally {
            manager.setComponentEnabledSetting(component, original, PackageManager.DONT_KILL_APP)
        }
    }

    @Test fun customLayoutReceivesRestrictionWithoutRedirectLoop() {
        ActivityScenario.launch<BrandedSecurityActivity>(Intent(context, BrandedSecurityActivity::class.java)).use { scenario ->
            scenario.onActivity { activity ->
                assertFalse(activity.isFinishing)
                assertTrue(activity.findViewById<TextView>(android.R.id.message).text.contains("cannot continue"))
                assertEquals(View.GONE, activity.findViewById<View>(android.R.id.button1).visibility)
                assertEquals(View.VISIBLE, activity.findViewById<View>(android.R.id.button2).visibility)
            }
            scenario.recreate()
            scenario.onActivity { assertFalse(it.isFinishing) }
        }
    }

    @Test fun missingStartupTicketShowsUnavailableNotADeviceFailure() {
        ActivityScenario.launch<SecurityBlockActivity>(Intent(context, SecurityBlockActivity::class.java)
            .putExtra("com.apparmorx.runtime.STARTUP_PENDING", true)).use { scenario ->
            // onActivity is scheduled after onResume; poll is posted from onResume on the same looper.
            InstrumentationRegistry.getInstrumentation().waitForIdleSync()
            scenario.onActivity { activity ->
                assertTrue(activity.findViewById<TextView>(android.R.id.message).text.contains("close and reopen"))
                assertEquals(View.GONE, activity.findViewById<View>(android.R.id.button1).visibility)
                assertFalse(activity.isFinishing)
            }
        }
    }
    @Test fun incompleteCheckExplainsReopenWithoutUnticketedRetry() {
        val router = Class.forName("com.apparmorx.runtime.SecurityUiDestination")
        val destination = router.getMethod("forState", Context::class.java, ProtectionState::class.java)
            .invoke(router.getField("INSTANCE").get(null), context, ProtectionState.INDETERMINATE) as Intent
        ActivityScenario.launch<SecurityBlockActivity>(destination).use { scenario ->
            fun assertUnavailable() = scenario.onActivity { activity ->
                assertTrue(activity.findViewById<TextView>(android.R.id.message).text.contains("close and reopen"))
                assertEquals(View.GONE, activity.findViewById<View>(android.R.id.button1).visibility)
                assertFalse(activity.isFinishing)
            }
            assertUnavailable()
            scenario.recreate()
            assertUnavailable()
            scenario.onActivity { activity ->
                activity.findViewById<View>(android.R.id.button2).performClick()
                assertTrue("Close app must finish the blocked task", activity.isFinishing)
            }
        }
    }

}
