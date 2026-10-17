package com.apparmorx.gradle

import java.time.Instant

/**
 * Self-contained (no external assets, no scripts) HTML security report for one packaged variant.
 * Every dynamic string is escaped. The verdict reflects only what this build verified, and the
 * report always states what AppArmorX does not guarantee.
 */
object HtmlReportGenerator {
    data class Input(
        val variant: String,
        val profile: String,
        val report: ProtectionReport,
        val settings: Map<String, String>,
        val profileDefaults: Map<String, String>,
        val findings: List<ManifestAuditor.Finding>,
    )

    private data class Layer(val key: String, val title: String, val detail: String, val enabled: (String) -> Boolean)

    private val LAYERS = listOf(
        Layer("restrictedAction", "Automatic response", "Reacts when a threat is confirmed on-device") { it != "OBSERVE" },
        Layer("failClosedOnStartup", "Fail-closed startup gate", "Holds execution until the first integrity verdict") { it == "true" },
        Layer("secureScreen", "Screen-capture protection", "FLAG_SECURE against screenshots, recording, recents preview") { it == "true" },
        Layer("filterTouches", "Overlay / tapjacking defense", "Ignores touches while another window obscures the app") { it == "true" },
        Layer("firewallClipboard", "Dependency firewall: clipboard", "Stops SDKs reading the clipboard") { it == "true" },
        Layer("firewallIdentifiers", "Dependency firewall: identifiers", "Sanitizes ANDROID_ID / IMEI scraping") { it == "true" },
        Layer("firewallLocation", "Dependency firewall: location", "Blocks cached-location harvesting by SDKs") { it == "true" },
        Layer("firewallNetworkSecurity", "Dependency firewall: TLS", "Rejects trust-all and allow-all verifiers") { it == "true" },
        Layer(
            "antiPtraceHardening", "Anti-ptrace hardening (best-effort)",
            "Blocks attaching a debugger/Frida to an already-running process; does not block spawn-time injection or an attacker who can kill the watchdog directly",
        ) { it == "true" },
        Layer(
            "killOnConfirmedHooking", "Kill on confirmed hooking (opt-in)",
            "Hard-kills the process when hooking/injection evidence is confirmed; cannot prevent the single action already in flight when detection fires, only further activity in the same process",
        ) { it == "true" },
    )

    fun render(input: Input): String {
        val r = input.report
        val verified = r.isProtected && input.findings.none { it.level == ManifestAuditor.Finding.Level.ERROR }
        val enabledCount = LAYERS.count { it.enabled(input.settings[it.key] ?: "false") }
        val sb = StringBuilder()
        sb.append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
        sb.append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
        sb.append("<title>AppArmorX Security Report</title><style>$CSS</style></head><body><main>")
        sb.append("<header><div class=\"brand\">AppArmorX</div><div class=\"sub\">Build security report &middot; ")
        sb.append("${esc(input.variant)} &middot; profile ${esc(input.profile)}</div></header>")
        sb.append("<section class=\"verdict ${if (verified) "ok" else "bad"}\"><div class=\"big\">")
        sb.append(if (verified) "PACKAGED CHECKS PASSED" else "PACKAGED CHECKS INCOMPLETE")
        sb.append("</div><div>${esc(r.archiveName)} &middot; ABIs: ")
        sb.append(if (r.abis.isEmpty()) "none" else r.abis.joinToString(", ") { esc(it) })
        sb.append(" &middot; $enabledCount of ${LAYERS.size} protection layers enabled</div>")
        if (r.failures.isNotEmpty()) {
            sb.append("<ul>").append(r.failures.joinToString("") { "<li><code>${esc(it)}</code></li>" }).append("</ul>")
        }
        sb.append("</section>")
        sb.append("<p class=\"muted\">This verdict covers packaged artifacts and manifest findings; executable component guards are not verified by this inventory.</p>")

        sb.append("<h2>Component declarations and guard boundaries</h2>")
        val inventory = r.componentInventory
        if (inventory == null) sb.append("<p class=\"warning\">Component inventory unavailable.</p>")
        else {
            for (issue in inventory.issues) sb.append("<p class=\"warning\">${esc(issue)}</p>")
            sb.append("<table><tr><th>Kind</th><th>Component / target</th><th>Process</th><th>Coverage status</th></tr>")
            for (c in inventory.components) {
                sb.append("<tr><td>${esc(c.kind)}</td><td><code>${esc(c.name)}</code>")
                c.target?.let { sb.append("<br>Target: <code>${esc(it)}</code>") }
                sb.append("</td><td>${esc(c.process)}</td><td>${esc(c.coverage)}</td></tr>")
            }
            sb.append("</table><ul class=\"muted\">")
            for (limit in ComponentInventory.LIMITS) sb.append("<li>${esc(limit)}</li>")
            sb.append("</ul>")
        }

        sb.append("<h2>Protection layers</h2><div class=\"grid\">")
        for (layer in LAYERS) {
            val value = input.settings[layer.key] ?: "false"
            val on = layer.enabled(value)
            val default = input.profileDefaults[layer.key]
            val weakened = default != null && ProtectionProfile.isWeaker(layer.key, value, default)
            sb.append("<div class=\"card ${if (on) "on" else "off"}\"><div class=\"t\">${esc(layer.title)}")
            sb.append("<span class=\"pill\">${if (on) "ON" else "OFF"}</span></div>")
            sb.append("<div class=\"d\">${esc(layer.detail)}</div>")
            if (layer.key == "restrictedAction") sb.append("<div class=\"d\">Action: <code>${esc(value)}</code></div>")
            if (weakened) sb.append("<div class=\"warn\">WEAKENED vs ${esc(input.profile)} default (${esc(default!!)})</div>")
            else if (default != null && default != value) sb.append("<div class=\"note\">Overridden (profile default: ${esc(default)})</div>")
            sb.append("</div>")
        }
        sb.append("</div>")

        sb.append("<h2>Manifest audit</h2>")
        if (input.findings.isEmpty()) {
            sb.append(if (inventory == null || inventory.issues.isNotEmpty())
                "<p class=\"warning\">Manifest completeness is unverified; no findings alone is not a clean-manifest verdict.</p>"
                else "<p class=\"muted\">No manifest findings.</p>")
        } else {
            sb.append("<table><tr><th>Severity</th><th>Rule</th><th>Finding</th></tr>")
            for (f in input.findings) {
                val sev = if (f.level == ManifestAuditor.Finding.Level.ERROR) "ERROR" else "WARNING"
                sb.append("<tr><td class=\"${sev.lowercase()}\">$sev</td><td><code>${esc(f.code)}</code></td>")
                sb.append("<td>${esc(f.message)}${f.componentName?.let { " (<code>${esc(it)}</code>)" } ?: ""}</td></tr>")
            }
            sb.append("</table>")
        }

        sb.append("<h2>Packaged payload digests (SHA-256)</h2><table>")
        for ((name, digest) in r.entryDigests) sb.append("<tr><td><code>${esc(name)}</code></td><td><code>${esc(digest)}</code></td></tr>")
        sb.append("</table>")

        sb.append("<h2>What this report does not claim</h2><ul class=\"muted\">")
        sb.append("<li>Client-side protection is not unbypassable; it raises attacker cost and produces evidence.</li>")
        sb.append("<li>Packaging checks prove artifacts shipped, not that every runtime attack is prevented.</li>")
        sb.append("<li>Unavailable or indeterminate probe results are never treated as clean.</li>")
        sb.append("<li>Server-side authorization remains required for anything sensitive.</li></ul>")
        sb.append("<footer>Generated ${Instant.ofEpochSecond(r.timestampSeconds)} by AppArmorX &middot; Shushant Tiwari</footer>")
        sb.append("</main></body></html>")
        return sb.toString()
    }

    private fun esc(s: String): String = buildString(s.length) {
        for (c in s) when (c) {
            '&' -> append("&amp;"); '<' -> append("&lt;"); '>' -> append("&gt;")
            '"' -> append("&quot;"); '\'' -> append("&#39;"); else -> append(c)
        }
    }

    private const val CSS = """
:root{color-scheme:dark light;--bg:#0b1020;--fg:#e6ebff;--mut:#8f9bc0;--card:#141b34;--line:#243056;--ok:#2ee59d;--bad:#ff5d73;--warn:#ffb454}
@media(prefers-color-scheme:light){:root{--bg:#f5f7ff;--fg:#10162e;--mut:#56608a;--card:#fff;--line:#d9def5;--ok:#0a9b64;--bad:#d62d49;--warn:#b86e00}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:960px;margin:0 auto;padding:32px 16px 64px}.brand{font-size:28px;font-weight:800;letter-spacing:.5px}
.sub,.muted{color:var(--mut)}h2{margin:36px 0 12px;font-size:16px;text-transform:uppercase;letter-spacing:1.5px;color:var(--mut)}
.verdict{margin-top:20px;padding:22px;border-radius:14px;border:1px solid var(--line);background:var(--card)}
.verdict.ok{border-color:var(--ok)}.verdict.bad{border-color:var(--bad)}.big{font-size:24px;font-weight:800}
.ok .big{color:var(--ok)}.bad .big{color:var(--bad)}.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(270px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px}.card.on{border-left:4px solid var(--ok)}.card.off{border-left:4px solid var(--line);opacity:.85}
.t{font-weight:700;display:flex;justify-content:space-between;gap:8px}.d{color:var(--mut);font-size:13px;margin-top:4px}
.pill{font-size:11px;padding:2px 8px;border-radius:99px;border:1px solid var(--line)}.on .pill{color:var(--ok);border-color:var(--ok)}
.warn{margin-top:8px;color:var(--warn);font-weight:700;font-size:12px}.note{margin-top:8px;color:var(--mut);font-size:12px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--line);vertical-align:top;word-break:break-all}
.error{color:var(--bad);font-weight:700}.warning{color:var(--warn);font-weight:700}code{font:12px ui-monospace,Menlo,monospace}
footer{margin-top:40px;color:var(--mut);font-size:12px}
"""
}
