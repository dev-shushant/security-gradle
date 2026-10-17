package com.apparmorx.gradle

import org.w3c.dom.Element
import java.io.ByteArrayInputStream
import javax.xml.parsers.DocumentBuilderFactory

/**
 * Static vulnerability auditor for merged Android manifests.
 * Identifies high-risk configuration weaknesses prior to release packaging.
 */
object ManifestAuditor {
    data class Finding(
        val level: Level,
        val code: String,
        val message: String,
        val componentName: String? = null
    ) {
        enum class Level { WARNING, ERROR }
    }

    private const val ANDROID_NS = "http://schemas.android.com/apk/res/android"

    fun audit(manifestXml: String, isDebuggable: Boolean): List<Finding> {
        val findings = mutableListOf<Finding>()

        try {
            val factory = DocumentBuilderFactory.newInstance().apply {
                isNamespaceAware = true
                setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
                setFeature("http://xml.org/sax/features/external-general-entities", false)
                setFeature("http://xml.org/sax/features/external-parameter-entities", false)
            }
            val builder = factory.newDocumentBuilder()
            val doc = builder.parse(ByteArrayInputStream(manifestXml.toByteArray(Charsets.UTF_8)))
            val root = doc.documentElement

            val appList = root.getElementsByTagName("application")
            val app = if (appList.length > 0) appList.item(0) as? Element else null

            if (app != null) {
                // 1. Release debuggable
                val debuggableAttr = app.getAndroidAttr("debuggable")
                if (!isDebuggable && debuggableAttr == "true") {
                    findings += Finding(
                        Finding.Level.ERROR,
                        "release-debuggable",
                        "android:debuggable=\"true\" is forbidden in release artifacts"
                    )
                }

                // 2. Allow backup
                val allowBackupAttr = app.getAndroidAttr("allowBackup")
                if (allowBackupAttr == "true") {
                    findings += Finding(
                        Finding.Level.WARNING,
                        "allow-backup-enabled",
                        "android:allowBackup=\"true\" allows application private data extraction via adb backup"
                    )
                }

                // 3. Cleartext traffic
                val cleartextAttr = app.getAndroidAttr("usesCleartextTraffic")
                if (!isDebuggable && cleartextAttr == "true") {
                    findings += Finding(
                        Finding.Level.WARNING,
                        "cleartext-traffic-permitted",
                        "android:usesCleartextTraffic=\"true\" permits unencrypted HTTP traffic"
                    )
                }

                // 4. Inspect Services
                val services = app.getElementsByTagName("service")
                for (i in 0 until services.length) {
                    val s = services.item(i) as Element
                    val exported = s.getAndroidAttr("exported")
                    val permission = s.getAndroidAttr("permission")
                    val name = s.getAndroidAttr("name").ifBlank { "Service #$i" }
                    if (exported == "true" && permission.isBlank()) {
                        findings += Finding(
                            Finding.Level.WARNING,
                            "exported-service-unprotected",
                            "Exported Service '$name' does not require permission",
                            componentName = name
                        )
                    }
                }

                // 5. Inspect BroadcastReceivers
                val receivers = app.getElementsByTagName("receiver")
                for (i in 0 until receivers.length) {
                    val r = receivers.item(i) as Element
                    val exported = r.getAndroidAttr("exported")
                    val permission = r.getAndroidAttr("permission")
                    val name = r.getAndroidAttr("name").ifBlank { "Receiver #$i" }
                    if (exported == "true" && permission.isBlank()) {
                        findings += Finding(
                            Finding.Level.WARNING,
                            "exported-receiver-unprotected",
                            "Exported BroadcastReceiver '$name' does not require permission",
                            componentName = name
                        )
                    }
                }

                // 6. Inspect Activities
                val activities = app.getElementsByTagName("activity")
                for (i in 0 until activities.length) {
                    val a = activities.item(i) as Element
                    val exported = a.getAndroidAttr("exported")
                    val permission = a.getAndroidAttr("permission")
                    val name = a.getAndroidAttr("name").ifBlank { "Activity #$i" }
                    if (exported == "true" && permission.isBlank()) {
                        val isLauncher = isLauncherActivity(a)
                        if (!isLauncher) {
                            findings += Finding(
                                Finding.Level.WARNING,
                                "exported-activity-unprotected",
                                "Exported Activity '$name' does not require permission",
                                componentName = name
                            )
                        }
                    }
                }

                // 7. Inspect Providers
                val providers = app.getElementsByTagName("provider")
                for (i in 0 until providers.length) {
                    val p = providers.item(i) as Element
                    val exported = p.getAndroidAttr("exported")
                    val permission = p.getAndroidAttr("permission")
                    val readPerm = p.getAndroidAttr("readPermission")
                    val writePerm = p.getAndroidAttr("writePermission")
                    val grantUri = p.getAndroidAttr("grantUriPermissions")
                    val name = p.getAndroidAttr("name").ifBlank { "Provider #$i" }

                    if (exported == "true" && permission.isBlank() && readPerm.isBlank() && writePerm.isBlank()) {
                        findings += Finding(
                            Finding.Level.ERROR,
                            "exported-provider-unprotected",
                            "Exported ContentProvider '$name' does not require permissions",
                            componentName = name
                        )
                    }
                    if (grantUri == "true") {
                        findings += Finding(
                            Finding.Level.WARNING,
                            "wide-grant-uri-permissions",
                            "ContentProvider '$name' grants wide URI permissions",
                            componentName = name
                        )
                    }
                }
            }
        } catch (_: Exception) {
            // Fallback string-based checks if XML parsing encounters non-standard formats
            if (!isDebuggable && manifestXml.contains("""android:debuggable="true"""")) {
                findings += Finding(
                    Finding.Level.ERROR,
                    "release-debuggable",
                    "android:debuggable=\"true\" is forbidden in release artifacts"
                )
            }
            if (manifestXml.contains("""android:allowBackup="true"""")) {
                findings += Finding(
                    Finding.Level.WARNING,
                    "allow-backup-enabled",
                    "android:allowBackup=\"true\" allows application private data extraction via adb backup"
                )
            }
            if (!isDebuggable && manifestXml.contains("""android:usesCleartextTraffic="true"""")) {
                findings += Finding(
                    Finding.Level.WARNING,
                    "cleartext-traffic-permitted",
                    "android:usesCleartextTraffic=\"true\" permits unencrypted HTTP traffic"
                )
            }
        }

        return findings
    }

    private fun Element.getAndroidAttr(name: String): String {
        val ns = getAttributeNS(ANDROID_NS, name)
        if (ns.isNotBlank()) return ns
        return getAttribute("android:$name")
    }

    private fun isLauncherActivity(activity: Element): Boolean {
        val filters = activity.getElementsByTagName("intent-filter")
        for (i in 0 until filters.length) {
            val filter = filters.item(i) as Element
            var hasMain = false
            var hasLauncher = false
            val actions = filter.getElementsByTagName("action")
            for (j in 0 until actions.length) {
                val act = actions.item(j) as Element
                if (act.getAndroidAttr("name") == "android.intent.action.MAIN") {
                    hasMain = true
                }
            }
            val categories = filter.getElementsByTagName("category")
            for (k in 0 until categories.length) {
                val cat = categories.item(k) as Element
                if (cat.getAndroidAttr("name") == "android.intent.category.LAUNCHER") {
                    hasLauncher = true
                }
            }
            if (hasMain && hasLauncher) return true
        }
        return false
    }
}
