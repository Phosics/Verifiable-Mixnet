plugins {
    kotlin("jvm") version "2.0.21"
    id("com.google.protobuf") version "0.9.3" // Protobuf Gradle plugin
    kotlin("plugin.serialization") version "1.8.10"
}

group = "org.example"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral() // Central repository for dependencies
    google() // Google repository for Android and Protobuf tools
}

dependencies {
    implementation(kotlin("stdlib")) // Kotlin Standard Library

    // Bouncy Castle for cryptographic operations
    implementation("org.bouncycastle:bcprov-jdk15on:1.70") // Use the latest version

    // Protobuf dependencies
    implementation("com.google.protobuf:protobuf-java:3.21.12") // Use the latest version
    implementation("com.google.protobuf:protobuf-kotlin:3.21.12")

    // For Protobuf Kotlin code generation
    implementation("com.google.protobuf:protobuf-java-util:3.21.12")

    // For concurrency
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.0")

    // Log4j2
    // Log4j 2 Core
    implementation("org.apache.logging.log4j:log4j-core:2.20.0")
    // Log4j 2 API
    implementation("org.apache.logging.log4j:log4j-api:2.20.0")

    // Ktor Client
    implementation("io.ktor:ktor-client-core:3.0.3")
    implementation("io.ktor:ktor-client-cio:3.0.3")
    implementation("io.ktor:ktor-serialization-kotlinx-json:3.0.3")
    implementation("io.ktor:ktor-client-content-negotiation:3.0.3") // Content Negotiation
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.8.0") // Kotlinx Serialization

    // Testing dependencies
    testImplementation(kotlin("test")) // Kotlin test library
}

protobuf {
    protoc {
        artifact = "com.google.protobuf:protoc:3.21.12" // Use the latest version
    }
    generateProtoTasks {
        all().forEach { task ->
            task.builtins {
                create("kotlin") // Use Java code generation for Protobuf
            }
        }
    }
}

tasks.test {
    useJUnitPlatform() // Use JUnit for testing
}