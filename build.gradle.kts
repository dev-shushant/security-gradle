plugins {
    kotlin("jvm") version "2.4.10" apply false
    id("com.android.library") version "9.4.1" apply false
    id("com.android.application") version "9.4.1" apply false
}
allprojects {
    group = "com.apparmorx"
    version = providers.gradleProperty("releaseVersion").getOrElse("0.1.0-SNAPSHOT")
}
