plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.outline.proxy"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.outline.proxy"
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
        ndk {
            // Match the Rust ABIs produced by cargo-ndk (see android/README.md).
            abiFilters += listOf("arm64-v8a")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
    }
    testOptions {
        // The unit tests cover pure Kotlin logic (URI parsing, access checks);
        // stubbed android.jar calls return defaults instead of throwing.
        unitTests.isReturnDefaultValues = true
    }
    // The Rust .so files are dropped here by cargo-ndk; see README.
    // src/main/jniLibs/<abi>/liboutline_android.so
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2024.10.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    // Provides the XML theme (Theme.Material3.DayNight) referenced by the
    // activity in AndroidManifest.xml.
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")

    // JNA is required at runtime by the UniFFI-generated Kotlin bindings.
    // 5.16.0+ ships 16 KB-page-aligned native libs (libjnidispatch.so); older
    // builds fail to dlopen on Android 15 / 16 KB-page devices and emulators
    // ("program alignment (8192) cannot be smaller than system page size").
    implementation("net.java.dev.jna:jna:5.17.0@aar")

    testImplementation("junit:junit:4.13.2")
}
