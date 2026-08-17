# HD Wallet Kit KMP

Kotlin Multiplatform BIP-39/BIP-32 HD wallet primitives for Android and 64-bit Desktop JVM applications. The shared API includes mnemonic/seed handling, HD derivation, Base58, ECDSA signing and verification, and Taproot output-key tweaks.

## Supported targets

- Android (minSdk 24)
- Desktop JVM 21 on Linux x64, Windows x64, and macOS ARM64

Kotlin/Native, iOS, 32-bit Desktop, Linux ARM64, and macOS x64 are not release targets.

## Dependency

```kotlin
repositories {
    maven("https://jitpack.io")
    mavenCentral()
}

dependencies {
    implementation("com.github.piratecash.hd-wallet-kit-android:hd-wallet-kit-kmp:<version>")
}
```

The Kotlin Multiplatform metadata coordinate selects the standard Android and `desktop` target artifacts automatically.

## KMP API migration

Common APIs are platform-neutral. Legacy JVM public APIs that used `BigInteger`, `ECPoint`, `InputStream`, or JCA types have byte-oriented replacements: private scalars and ECDSA signature components are fixed-size `ByteArray` values, SEC public keys are `ByteArray`, and DER signatures are encoded `ByteArray` values. Use `ECKey.fromPrivate`, `ECKey.pubKeyCompressed`/`pubKeyUncompressed`, `ECKey.recoverPublicKeyFromSignature`, `ECKey.signSchnorr`, and `ECDSASignature` instead of JVM crypto types. `privKeyBytes` is deliberately non-null and throws for public-only keys; use `privateKeyOrNull` when that flow is intended.

The selected ACINQ secp256k1 KMP artifact publishes Kotlin 2.3 metadata. Kotlin 2.3 is therefore a prerequisite for the future Bitcoin Kit KMP migration; the current Android-only Bitcoin Kit branch on Kotlin 2.0.21 is not a supported consumer until it upgrades. Current Pcash Kotlin 2.3.x call shapes are covered by the isolated consumer build.

## Local verification (JDK 21)

```bash
export JAVA_HOME=/path/to/jdk-21
./gradlew desktopTest testDebugUnitTest
./gradlew publishAllPublicationsToLocalBuildRepository
./gradlew -p consumer-smoke compileKotlinDesktop compileDebugKotlinAndroid
```

The publication task writes only to `build/maven-repo`; the consumer build resolves the root metadata coordinate from that repository and compiles both target variants.

## Releases

Local builds default to `0.0.0-SNAPSHOT`. Versioned releases are distributed through JitPack: push a Git tag whose name is exact numeric SemVer (`MAJOR.MINOR.PATCH`, for example `1.2.3`), then use that tag as the dependency version. JitPack builds the tagged source with `jitpack.yml` and publishes the Kotlin Multiplatform metadata plus Android and Desktop JVM artifacts. The Android and cross-platform Desktop verification workflow remains separate from publication.
