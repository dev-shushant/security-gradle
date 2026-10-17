plugins { id("com.android.library") }
android {
    namespace = "com.apparmorx.fixture.vendor"
    compileSdk = 34
    defaultConfig { minSdk = 29 }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
}
