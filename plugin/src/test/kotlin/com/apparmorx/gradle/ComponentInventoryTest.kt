package com.apparmorx.gradle

import groovy.json.JsonSlurper
import org.junit.Assert.*
import org.junit.Test

class ComponentInventoryTest {
    private fun manifest(body: String) = """<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.apparmorx.fixture"><application android:name=".HostApp" android:process=":host">$body</application></manifest>"""

    @Test fun recordsComponentsAliasesAndInheritedProcessesWithoutClaimingGuards() {
        val inventory = componentInventory(manifest("""
            <activity android:name=".Main" android:exported="true"/>
            <activity-alias android:name=".Entry" android:targetActivity=".Main"/>
            <service android:name="Sync" android:process=":sync"/>
            <receiver android:name=".Events"/>
            <provider android:name=".Data" android:exported="false"/>
        """))
        assertTrue(inventory.issues.isEmpty())
        assertEquals(6, inventory.components.size)
        assertEquals(":host", inventory.components.first { it.kind == "activity" }.process)
        assertEquals(":sync", inventory.components.first { it.kind == "service" }.process)
        assertEquals("com.apparmorx.fixture.Main", inventory.components.first { it.kind == "activity-alias" }.target)
        assertEquals("ALL_SCOPE_PROVIDER_OPERATIONS_UNVERIFIED", inventory.components.first { it.kind == "provider" }.coverage)
        val json = JsonSlurper().parseText(inventory.toJson()) as Map<*, *>
        assertEquals(false, json["bytecodeVerified"])
        assertTrue(inventory.toJson().contains("Workers are not enumerated"))
    }

    @Test fun frameworkDefaultApplicationIsDistinctFromHostGuardCoverage() {
        val inventory = componentInventory("<manifest><application/></manifest>")
        assertEquals("android.app.Application", inventory.components.single().name)
        assertEquals("FRAMEWORK_DEFAULT", inventory.components.single().coverage)
    }

    @Test fun malformedOrMissingManifestIsUnavailableNotEmptySuccess() {
        assertFalse(componentInventory(null).issues.isEmpty())
        assertFalse(componentInventory("<manifest>").issues.isEmpty())
        assertFalse(componentInventory("<not-android/>").issues.isEmpty())
    }

    @Test fun externalEntitiesAreRejected() {
        val xml = """<!DOCTYPE manifest [<!ENTITY x SYSTEM "file:///etc/passwd">]><manifest><application android:name="&x;"/></manifest>"""
        assertFalse(componentInventory(xml).issues.isEmpty())
    }

    @Test fun manifestTextCannotInjectJsonOrHtml() {
        val inventory = componentInventory(manifest("""<activity android:name="evil&amp;quot;&lt;script&gt;" android:process="&quot;quoted&quot;"/>"""))
        val parsed = JsonSlurper().parseText(inventory.toJson()) as Map<*, *>
        assertEquals(false, parsed["bytecodeVerified"])
        assertEquals("\"quoted\"", inventory.components.last().process)
    }
}
