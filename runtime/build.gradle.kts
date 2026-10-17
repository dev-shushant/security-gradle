plugins { id("com.android.library"); `maven-publish` }
android {
    namespace = "com.apparmorx.runtime"
    compileSdk = 34
    ndkVersion = "29.0.14206865"
    externalNativeBuild { cmake { path = file("src/main/cpp/CMakeLists.txt"); version = "3.22.1" } }
    defaultConfig { minSdk = 29; ndk { abiFilters += listOf("arm64-v8a", "x86_64") }; consumerProguardFiles("consumer-rules.pro") }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    testOptions { unitTests { isReturnDefaultValues = true } }
    publishing { singleVariant("release") { withSourcesJar() } }
}
dependencies { testImplementation(libs.junit) }
afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])
                pom {
                    licenses { license { name.set("The Apache License, Version 2.0"); url.set("https://www.apache.org/licenses/LICENSE-2.0.txt") } }
                    name.set("AppArmorX Runtime")
                    description.set("Zero-integration Android native RASP runtime engine with direct syscalls and dependency firewall")
                    url.set("https://apparmorx.com")
                    developers {
                        developer {
                            name.set("Shushant Tiwari")
                            organization.set("AppArmorX")
                            organizationUrl.set("https://apparmorx.com")
                        }
                    }
                }
            }
        }
    }
}
