import java.util.Properties

plugins {
    id("com.android.application")
    // AGP 9 compiles Kotlin itself ("built-in Kotlin"); `org.jetbrains.kotlin.android`
    // is gone. The Compose compiler plugin stays — AGP looks it up by id and wires
    // it into its own Kotlin compile tasks.
    id("org.jetbrains.kotlin.plugin.compose")
}

// Release-signing credentials, resolved once at configuration time. Primary source is
// `android/keystore.properties` (git-ignored, holds an absolute path to a keystore kept
// outside the work tree); CI and one-off builds can pass the same four values through the
// environment instead. When neither is present the release build still runs and simply
// produces an unsigned APK, so a fresh clone is never blocked on secrets it cannot have.
val signingProps: Map<String, String>? = run {
    val file = rootProject.file("keystore.properties")
    val fromFile = if (file.exists()) {
        Properties().apply { file.inputStream().use { load(it) } }
            .entries.associate { (k, v) -> k.toString() to v.toString() }
    } else {
        mapOf(
            "storeFile" to System.getenv("OUTLINE_KEYSTORE_FILE"),
            "storePassword" to System.getenv("OUTLINE_KEYSTORE_PASSWORD"),
            "keyAlias" to System.getenv("OUTLINE_KEY_ALIAS"),
            "keyPassword" to System.getenv("OUTLINE_KEY_PASSWORD"),
        ).filterValues { !it.isNullOrBlank() }.mapValues { it.value!! }
    }
    val required = listOf("storeFile", "storePassword", "keyAlias", "keyPassword")
    // An incomplete set is a misconfiguration, not a request for an unsigned build:
    // fail loudly rather than silently handing back an APK that cannot be installed
    // over a previous release.
    when {
        fromFile.keys.containsAll(required) -> fromFile
        fromFile.isEmpty() -> null
        else -> throw GradleException(
            "Incomplete release-signing config; missing: ${required - fromFile.keys}",
        )
    }
}

// Build identity. CI overrides these through the environment so a published APK
// carries the release version and the exact commit it was built from; a local
// build falls back to the checked-in version and the current git short SHA (or
// "dev" outside a work tree). Surfaced in-app via BuildConfig.
val buildVersionName: String =
    System.getenv("BUILD_VERSION_NAME")?.takeIf { it.isNotBlank() } ?: "0.1.0"
val buildVersionCode: Int =
    System.getenv("BUILD_VERSION_CODE")?.toIntOrNull() ?: 1
// Which pipeline produced this build: "release" (a tagged release, identified by
// its version), "nightly" (a rolling build, identified by its commit), or "dev"
// for a local one. Drives what the in-app footer shows.
val buildChannel: String =
    System.getenv("BUILD_CHANNEL")?.takeIf { it.isNotBlank() } ?: "dev"
val buildGitSha: String =
    System.getenv("BUILD_GIT_SHA")?.takeIf { it.isNotBlank() }
        ?: runCatching {
            ProcessBuilder("git", "rev-parse", "--short", "HEAD")
                .directory(rootDir)
                .start()
                .inputStream.bufferedReader().readText().trim()
        }.getOrNull()?.takeIf { it.isNotBlank() } ?: "dev"

android {
    namespace = "com.outline.proxy"
    // androidx 2026.x (compose-bom 2026.06 -> lifecycle-runtime-compose 2.11)
    // refuses to be consumed below API 37.
    compileSdk = 37

    defaultConfig {
        applicationId = "com.outline.proxy"
        minSdk = 24
        targetSdk = 36
        versionCode = buildVersionCode
        versionName = buildVersionName
        buildConfigField("String", "GIT_SHA", "\"$buildGitSha\"")
        buildConfigField("String", "CHANNEL", "\"$buildChannel\"")
        ndk {
            // Match the Rust ABIs produced by cargo-ndk (see android/README.md).
            abiFilters += listOf("arm64-v8a")
        }
    }

    signingConfigs {
        signingProps?.let { props ->
            create("release") {
                storeFile = file(props.getValue("storeFile"))
                storePassword = props.getValue("storePassword")
                keyAlias = props.getValue("keyAlias")
                keyPassword = props.getValue("keyPassword")
                // minSdk is 24 (Android 7.0), the release that introduced v2, so the
                // legacy JAR signature buys nothing and only slows packaging down.
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.findByName("release")
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
        buildConfig = true
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
    // Home-screen and profile-action glyphs (Tune, MonitorHeart, AltRoute, …).
    // R8 strips the unused ones from the release build.
    implementation("androidx.compose.material:material-icons-extended")
    // Provides the XML theme (Theme.Material3.DayNight) referenced by the
    // activity in AndroidManifest.xml.
    implementation("com.google.android.material:material:1.14.0")
    implementation("androidx.activity:activity-compose:1.13.0")
    // ContextCompat.startForegroundService: the raw API is 26+, minSdk is 24.
    implementation("androidx.core:core-ktx:1.19.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.11.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
    // Periodic background refresh of subscription configs; its schedule is
    // persisted by the framework and restored after reboot.
    implementation("androidx.work:work-runtime-ktx:2.11.0")

    // JNA is required at runtime by the UniFFI-generated Kotlin bindings.
    // 5.16.0+ ships 16 KB-page-aligned native libs (libjnidispatch.so); older
    // builds fail to dlopen on Android 15 / 16 KB-page devices and emulators
    // ("program alignment (8192) cannot be smaller than system page size").
    implementation("net.java.dev.jna:jna:5.19.1@aar")

    testImplementation("junit:junit:4.13.2")
}
