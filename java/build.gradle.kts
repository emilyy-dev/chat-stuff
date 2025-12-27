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
  implementation(platform("com.google.protobuf:protobuf-bom:4.33.2"))
  implementation("com.google.protobuf:protobuf-java")
}

application {
  mainModule = "ar.emily.chat.stuff"
  mainClass = "ar.emily.chat.stuff.Main"
}

tasks {
  compileJava {
    options.compilerArgs = listOf("--enable-preview")
  }

  named<JavaExec>("run") {
    jvmArgs("--enable-preview")
  }
}

sourceSets {
  main {
    proto {
      srcDir(rootProject.layout.projectDirectory.dir("proto"))
    }
  }
}
