@file:Suppress("UnstableApiUsage")

pluginManagement { repositories { google(); gradlePluginPortal(); mavenCentral() } }
plugins {
    // Provisions the JDKs named in gradle/gradle-daemon-jvm.properties and jvmToolchain(17) on machines
    // (e.g. clean CI runners) that don't already have them; without it a fresh checkout cannot build.
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}
dependencyResolutionManagement { repositories { google(); mavenCentral() } }
rootProject.name = "security-gradle"
include(":policy", ":plugin", ":runtime")

include(":platform-core")
