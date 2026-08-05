plugins {
    id("com.android.application")
    // AGP 9 compiles Kotlin itself ("built-in Kotlin"); `org.jetbrains.kotlin.android`
    // is gone. The Compose compiler plugin stays — AGP looks it up by id and wires
    // it into its own Kotlin compile tasks.
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.outline.proxy"
    // androidx 2026.x (compose-bom 2026.06 -> lifecycle-runtime-compose 2.11)
    // refuses to be consumed below API 37.
    compileSdk = 37

    defaultConfig {
        applicationId = "com.outline.proxy"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
        ndk {
            // Match the Rust ABIs produced by cargo-ndk (see android/README.md).
            abiFilters += listOf("arm64-v8a")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    compileOptions {
        // Built-in Kotlin defaults its jvmTarget to `targetCompatibility` and fails the
        // build if the two ever diverge, so this one setting covers both compilers.
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
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
    implementation(platform("androidx.compose:compose-bom:2026.06.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    // Provides the XML theme (Theme.Material3.DayNight) referenced by the
    // activity in AndroidManifest.xml.
    implementation("com.google.android.material:material:1.14.0")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.11.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")

    // JNA is required at runtime by the UniFFI-generated Kotlin bindings.
    // 5.16.0+ ships 16 KB-page-aligned native libs (libjnidispatch.so); older
    // builds fail to dlopen on Android 15 / 16 KB-page devices and emulators
    // ("program alignment (8192) cannot be smaller than system page size").
    implementation("net.java.dev.jna:jna:5.19.1@aar")

    testImplementation("junit:junit:4.13.2")
}
