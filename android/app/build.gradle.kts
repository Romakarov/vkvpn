plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.vkvpn"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.vkvpn"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    // Go tunnel library (built by gomobile, placed as .aar)
    implementation(fileTree(mapOf("dir" to "libs", "include" to listOf("*.aar"))))
    // AndroidX
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.activity:activity-ktx:1.9.3")
    // Encrypted storage for WG keys
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    // QR code scanner
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
}
