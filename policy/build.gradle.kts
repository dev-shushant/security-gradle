plugins { kotlin("jvm"); `maven-publish` }
kotlin { jvmToolchain(17) }
java { withSourcesJar() }
dependencies { testImplementation(libs.junit) }
publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
            pom {
                licenses { license { name.set("The Apache License, Version 2.0"); url.set("https://www.apache.org/licenses/LICENSE-2.0.txt") } }
                name.set("AppArmorX Policy")
                description.set("Cryptographically signed security policy parser for Android runtime integrity")
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
