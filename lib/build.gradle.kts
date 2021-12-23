import com.android.build.gradle.tasks.JavaPreCompileTask

version = "1.0.0"

plugins {
    id("com.android.library")
    id("kotlin-android")
    id("org.mozilla.rust-android-gradle.rust-android")
}

android {
    compileSdk = 31

    defaultConfig {
        minSdk = 24
        targetSdk = 29
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFile("proguard-rules.pro")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    kotlinOptions {
        jvmTarget = "11"
    }
}

cargo {
    module = "./rust"
    profile = "release"
    libname = "dexaccessmodifier"
    targets = listOf("arm", "arm64")
}

tasks.whenTaskAdded {
    if (listOf("javaPreCompileDebug", "javaPreCompileRelease").contains(this.name))
        dependsOn("cargoBuild")
}

//tasks.withType<JavaPreCompileTask> {
//    dependsOn("cargoBuild")
//}