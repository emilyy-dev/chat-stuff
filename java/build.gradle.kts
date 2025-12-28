plugins {
  `java-library`
  application
  id("com.google.protobuf") version "0.9.6"
}

java.toolchain.languageVersion = JavaLanguageVersion.of(25)

repositories {
  mavenCentral()
}

dependencies {
  implementation("org.jspecify:jspecify:1.0.0")

  implementation(platform("com.google.protobuf:protobuf-bom:4.33.2"))
  implementation("com.google.protobuf:protobuf-java")

  implementation("org.slf4j:slf4j-api:2.0.17")
  runtimeOnly("org.tinylog:slf4j-tinylog:2.7.0")
  runtimeOnly("org.tinylog:tinylog-impl:2.7.0")
  runtimeOnly("org.tinylog:jsl-tinylog:2.7.0")
}

application {
  mainModule = "ar.emily.chat.stuff"
  mainClass = "ar.emily.chat.stuff.ServerMain"
  applicationDefaultJvmArgs = listOf("--enable-preview", "-Dfile.encoding=UTF-8")
}

tasks {
  compileJava {
    options.compilerArgs = listOf("--enable-preview")
  }
}

sourceSets {
  main {
    proto {
      srcDir(rootProject.layout.projectDirectory.dir("proto"))
    }
  }
}
