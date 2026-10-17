plugins {
    kotlin("jvm") version "2.4.10" apply false
    id("com.android.application") version "9.4.1"
    id("com.apparmorx.security") version "0.1.0-SNAPSHOT"
}
android {
    namespace = "com.apparmorx.sample"
    compileSdk = 37
    defaultConfig {
        applicationId = "com.apparmorx.sample"
        minSdk = 29
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    buildTypes {
        // Minification ON so the sample actually exercises R8 against the injected guard — this is
        // the configuration every real release build ships with, and it's the one nothing had ever
        // verified yet (see docs/VALIDATION.md).
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
        }
    }
}
dependencies {
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test:core:1.7.0")
}
security {
    minimumSequence.set(0L)
    // Placeholder pin ONLY to exercise the requireReleaseSigningPins build-time gate structurally in
    // this fixture. It is not a real signer and must never be copied into a real app's build.
    signingCertificates.set(listOf("0".repeat(64)))
    restrictedAction.set("MIRAGE")
    failClosedOnStartup.set(true)
    // Demo apps block screenshots by design; pass -Psample.screenshots=true to capture portfolio images.
    secureScreen.set(providers.gradleProperty("sample.screenshots").map { false }.orElse(true))
    filterTouches.set(true)
    firewallClipboard.set(true)
    firewallIdentifiers.set(true)
    firewallLocation.set(true)
    firewallNetworkSecurity.set(true)
}
