plugins {
    kotlin("jvm") version "2.4.10" apply false
    id("com.android.application") version "9.4.1"
    id("com.apparmorx.security") version "0.1.0-SNAPSHOT"
}
android {
    namespace = "com.apparmorx.sample"
    testBuildType = providers.gradleProperty("sample.testBuildType").getOrElse("debug")
    compileSdk = 37
    defaultConfig {
        applicationId = "com.apparmorx.sample"
        minSdk = 29
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"
        val coldStart = providers.gradleProperty("sample.coldStart").getOrElse("false") == "true"
        manifestPlaceholders["sampleApplication"] = if (coldStart)
            "com.apparmorx.sample.ColdStartApplication" else "android.app.Application"
        // Dedicated host-driven protocol; never counted as an ordinary JUnit pass.
        testInstrumentationRunner = if (coldStart) "com.apparmorx.sample.ColdStartInstrumentation"
            else if (providers.gradleProperty("sample.processDeath").getOrElse("false") == "true")
            "com.apparmorx.sample.ProcessDeathInstrumentation" else "androidx.test.runner.AndroidJUnitRunner"
    }
    if (providers.gradleProperty("sample.coldStart").getOrElse("false") == "true") {
        sourceSets.getByName("main").java.srcDir("src/coldStart/java")
    }
    if (providers.gradleProperty("sample.processQualification").getOrElse("false") == "true") {
        sourceSets.getByName("main").apply {
            kotlin.directories.add("src/processQualification/kotlin")
            manifest.srcFile("src/processQualification/AndroidManifest.xml")
        }
    }
    buildTypes {
        // Minification ON so the sample actually exercises R8 against the injected guard — this is
        // the configuration every real release build ships with, and it's the one nothing had ever
        // verified yet (see docs/VALIDATION.md).
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
            if (testBuildType == "release") {
                // Test-only signer/API retention for release instrumentation, never a production key.
                signingConfig = signingConfigs.getByName("debug")
                proguardFiles("service-qualification.pro")
                testProguardFiles("service-test-qualification.pro")
            }
        }
    }
}
if (providers.gradleProperty("sample.remoteNoGuardsBaseline").getOrElse("false") == "true") {
    require(providers.gradleProperty("sample.processQualification").getOrElse("false") == "true") {
        "The no-guards baseline is permitted only in explicit process qualification builds"
    }
    androidComponents.onVariants(androidComponents.selector().withBuildType("debug")) { variant ->
        variant.instrumentation.excludes.add("**")
    }
}
dependencies {
    if (providers.gradleProperty("sample.processQualification").getOrElse("false") == "true") {
        implementation("androidx.work:work-multiprocess:2.11.1")
    }
    implementation(project(":provider-fixture"))
    implementation("androidx.work:work-runtime:2.11.1")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test:core:1.7.0")
    // AndroidX test references these annotations; release test shrinking needs their definitions.
    androidTestImplementation("com.google.errorprone:error_prone_annotations:2.30.0")
}
security {
    minimumSequence.set(0L)
    // Placeholder pin ONLY to exercise the requireReleaseSigningPins build-time gate structurally in
    // this fixture. It is not a real signer and must never be copied into a real app's build.
    signingCertificates.set(listOf("0".repeat(64)))
    restrictedAction.set(providers.gradleProperty("sample.restrictedAction").orElse("MIRAGE"))
    failClosedOnStartup.set(true)
    // Demo apps block screenshots by design; pass -Psample.screenshots=true to capture portfolio images.
    secureScreen.set(providers.gradleProperty("sample.screenshots").map { false }.orElse(true))
    filterTouches.set(true)
    firewallClipboard.set(true)
    firewallIdentifiers.set(true)
    firewallLocation.set(true)
    firewallNetworkSecurity.set(true)
}
