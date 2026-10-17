# Slack message (DRAFT, for a community/dev channel you are a member of)

Hey all, I built an Android security Gradle plugin and would love feedback (and bypass attempts).

*AppArmorX*: one line in `build.gradle.kts`, no app code. It guards components, blocks SDK data scraping (clipboard, device ID, location, trust-all TLS), derives your signer pin from your release signingConfig, and writes an HTML report.

v0.1, tested on a Pixel 7 Pro + API 35 emulator, not yet on rooted devices. Repo + demo: <LINK>
If you break it, please report privately first (see SECURITY.md).
