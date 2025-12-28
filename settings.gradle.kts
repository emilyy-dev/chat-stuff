plugins {
  id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

rootProject.name = "chat-stuff"
include("java")
project(":java").name = rootProject.name
