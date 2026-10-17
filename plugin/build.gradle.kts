plugins { `kotlin-dsl`; id("com.gradle.plugin-publish") version "2.2.1" }
repositories { google(); mavenCentral(); gradlePluginPortal() }
kotlin {
    jvmToolchain(17)
    // The signed-policy verifier is compiled INTO the plugin instead of depending on a separate
    // com.apparmorx:policy artifact: the Plugin Portal only serves plugins, so a second published
    // module would be an unresolvable dependency for every consumer.
    sourceSets.main { kotlin.srcDir("../policy/src/main/kotlin") }
}
dependencies {
    implementation(libs.asm)
    implementation(libs.asm.commons)
    compileOnly(libs.gradle)
    testImplementation(libs.junit)
    testImplementation(gradleTestKit())
    testImplementation(libs.gradle)
}
gradlePlugin {
    website.set("https://apparmorx.com")
    vcsUrl.set(providers.gradleProperty("apparmorx.vcsUrl"))
    plugins {
        create("security") {
            id = "com.apparmorx.security"
            implementationClass = "com.apparmorx.gradle.SecurityPlugin"
            displayName = "AppArmorX Security — by Shushant Tiwari"
            description = "Signed security policy and observable Android runtime integrity checks"
            tags.set(listOf("android", "security", "rasp", "integrity"))
        }
    }
}

// Plain locals inside run{} so the doFirst lambda captures values, not the build script object
// (capturing the script makes publishPlugins incompatible with the configuration cache).
run {
    val vcsUrl = providers.gradleProperty("apparmorx.vcsUrl")
    val version = project.version.toString()
    tasks.named("publishPlugins") {
        doFirst {
            require(!version.endsWith("SNAPSHOT")) { "Choose an immutable release version" }
            require(vcsUrl.isPresent) { "Set -Papparmorx.vcsUrl to the actual public source repository" }
        }
    }
}

// The matching runtime AAR ships inside the plugin jar, so applying the plugin from the Plugin Portal is
// enough: no Maven Central artifact, no extra repository and no network fetch of code at build time.
val runtimeAar = project(":runtime").layout.buildDirectory.file("outputs/aar/runtime-release.aar")
tasks.processResources {
    val pluginVersion = project.version.toString()
    val kotlinVersion = libs.versions.runtime.kotlin.get()
    inputs.property("apparmorxVersion", pluginVersion)
    inputs.property("kotlinVersion", kotlinVersion)
    filesMatching("apparmorx-version.properties") { expand("version" to pluginVersion, "kotlin" to kotlinVersion) }
    dependsOn(":runtime:bundleReleaseAar")
    from(runtimeAar) { into("apparmorx"); rename { "runtime.aar" } }
}
publishing.publications.withType<MavenPublication>().configureEach {
    // "plugin" is far too generic as a published artifact id on a shared portal.
    if (name == "pluginMaven") artifactId = "apparmorx-security-plugin"
    pom {
        licenses { license { name.set("The Apache License, Version 2.0"); url.set("https://www.apache.org/licenses/LICENSE-2.0.txt") } }
        developers { developer { name.set("Shushant Tiwari"); organization.set("AppArmorX"); organizationUrl.set("https://apparmorx.com") } }
    }
}

// Explicit local-only candidate repository for release qualification; never a publication endpoint.
providers.gradleProperty("apparmorx.candidateRepository").orNull?.let { candidatePath ->
    publishing.repositories {
        maven {
            name = "candidate"
            url = uri(file(candidatePath))
        }
    }
}
