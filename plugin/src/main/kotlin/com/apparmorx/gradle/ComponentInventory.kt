package com.apparmorx.gradle

import org.w3c.dom.Element
import java.io.ByteArrayInputStream
import javax.xml.parsers.DocumentBuilderFactory

data class ManifestComponent(val kind: String, val name: String, val process: String,
                             val exported: String, val target: String?, val coverage: String)

data class ComponentInventory(val components: List<ManifestComponent>, val issues: List<String>) {
    fun toJson(): String = """{"bytecodeVerified":false,"issues":[${issues.joinToString(",", transform = ::jsonQuote)}],"limitations":[${LIMITS.joinToString(",", transform = ::jsonQuote)}],"components":[${components.joinToString(",") { c ->
        """{"kind":${jsonQuote(c.kind)},"name":${jsonQuote(c.name)},"process":${jsonQuote(c.process)},"exported":${jsonQuote(c.exported)},"target":${c.target?.let(::jsonQuote) ?: "null"},"coverage":${jsonQuote(c.coverage)}}"""
    }}]}"""

    companion object {
        val LIMITS = listOf(
            "Declarations only: final bytecode guards and class ownership are not verified here.",
            "Lifecycle instrumentation is PROJECT scoped; inherited library callbacks are not proven guarded.",
            "Workers are not enumerated by the manifest. ALL-scope provider operation guards do not defer initialization or prove native/runtime-generated coverage.",
            "A secondary-process declaration does not prove runtime initialization or response parity."
        )
    }
}

/** Static merged-manifest inventory, deliberately never an assertion of executable guard coverage. */
internal fun componentInventory(xml: String?): ComponentInventory {
    if (xml.isNullOrBlank()) return ComponentInventory(emptyList(), listOf("Merged manifest unavailable"))
    return try {
        val factory = DocumentBuilderFactory.newInstance().apply {
            isNamespaceAware = true
            setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
            setFeature("http://xml.org/sax/features/external-general-entities", false)
            setFeature("http://xml.org/sax/features/external-parameter-entities", false)
        }
        val root = factory.newDocumentBuilder().parse(ByteArrayInputStream(xml.toByteArray(Charsets.UTF_8))).documentElement
        require(root.tagName == "manifest")
        val apps = root.getElementsByTagName("application")
        require(apps.length == 1)
        val app = apps.item(0) as Element
        val namespace = root.getAttribute("package")
        fun Element.attr(name: String) = getAttributeNS("http://schemas.android.com/apk/res/android", name)
        fun qualified(name: String) = when {
            namespace.isBlank() || name.isBlank() -> name
            name.startsWith('.') -> namespace + name
            '.' !in name -> "$namespace.$name"
            else -> name
        }
        val issues = mutableListOf<String>()
        val defaultProcess = app.attr("process").ifBlank { "(default)" }
        val components = mutableListOf<ManifestComponent>()
        fun add(kind: String, node: Element) {
            val raw = node.attr("name").ifBlank { if (kind == "application") "android.app.Application" else "" }
            if (raw.isBlank()) issues += "Missing $kind name"
            val name = qualified(raw)
            val coverage = when {
                kind == "application" && name == "android.app.Application" -> "FRAMEWORK_DEFAULT"
                kind == "provider" && name == "com.apparmorx.runtime.SecurityInitializer" -> "RUNTIME_INITIALIZER_DECLARED"
                kind == "activity" && name == "com.apparmorx.runtime.SecurityBlockActivity" -> "RUNTIME_RECOVERY_UI_DECLARED"
                kind == "provider" -> "ALL_SCOPE_PROVIDER_OPERATIONS_UNVERIFIED"
                kind == "activity-alias" -> "TARGET_DEPENDENT"
                else -> "PROJECT_SCOPE_GUARDS_UNVERIFIED"
            }
            val target = node.attr("targetActivity").takeIf { it.isNotBlank() }?.let(::qualified)
            if (kind == "activity-alias" && target == null) issues += "Missing activity-alias target"
            components += ManifestComponent(kind, name, node.attr("process").ifBlank { defaultProcess },
                node.attr("exported").ifBlank { "unspecified" }, target, coverage)
        }
        add("application", app)
        for (i in 0 until app.childNodes.length) {
            val child = app.childNodes.item(i) as? Element ?: continue
            if (child.tagName in setOf("activity", "activity-alias", "service", "receiver", "provider")) add(child.tagName, child)
        }
        ComponentInventory(components, issues)
    } catch (_: Exception) {
        ComponentInventory(emptyList(), listOf("Merged manifest could not be safely inventoried"))
    }
}
