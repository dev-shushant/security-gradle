pluginManagement {
    repositories { google(); gradlePluginPortal(); mavenCentral() }
}
plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}
// Top-level (not pluginManagement-scoped) so Gradle substitutes com.apparmorx:runtime with the
// included build's :runtime project too, not just the com.apparmorx.security plugin marker.
includeBuild("..")
dependencyResolutionManagement { repositories { google(); mavenCentral() } }
rootProject.name = "apparmorx-sample"
