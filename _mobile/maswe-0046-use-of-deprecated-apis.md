---
title: "MASWE-0046: Use of Deprecated APIs or Functionality"
date: 2026-11-10 10:05:00 +0000
subcategory: code
summary: "Finding deprecated security-relevant Android and iOS APIs: what deprecation means, a catalogue of replacements, and three static tests."
refs: [MASWE-0046, MASVS-CODE-3, MASVS-CRYPTO-2, CWE-327, CWE-477, CWE-522]
tags: [android, ios, masvs-code, deprecated-apis, lint, api-migration]
---

This note is part of our [MASVS-CODE guide](/mobile/masvs-code-code-quality-guide/) and covers OWASP [MASWE-0046](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0046/): apps that still call platform or library APIs their vendor has deprecated, removed or switched off. Most deprecated APIs are harmless. They have been renamed, moved or replaced by something more convenient, and an app that still calls them is merely untidy. A small number were deprecated *because* they were dangerous: world-readable files, keychain items that stay readable while the device is locked, a trust-evaluation function whose return value people kept misreading, a WebView that runs in the app's own process, an attestation service that no longer answers. The job here is to tell the two apart. Below you will find what "deprecated" actually means on Android and iOS and what survives of it in a compiled app, a catalogue of the security-relevant deprecated APIs on both platforms with their replacements and the note in this site that covers each one in depth, three tests of our own (OWASP has none for this weakness yet), the three OWASP best practices that illustrate it, and how to rate what you find. Detailed cryptography, TLS and WebView testing lives in the CRYPTO, NETWORK and PLATFORM series; this note links there rather than repeating it.

> **Note:** OWASP has not yet published any tests or Knowledge items for MASWE-0046. The tests in this note are Guler Tech methodology, labelled `GT-CODE-0046-x`. OWASP tests that cover *individual* deprecated APIs under other weaknesses (for example MASTG-TEST-0331 for `UIWebView` and MASTG-TEST-0312 for removed crypto providers) are listed in [Tests](#tests) and documented in the notes that own them. No MASTG v1 test is replaced by this note.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Background](#background)
  - [Generic: deprecated, removed, turned down and merely old](#generic-deprecated-removed-turned-down-and-merely-old)
  - [Android: how APIs are deprecated, restricted and removed](#android-how-apis-are-deprecated-restricted-and-removed)
  - [iOS: how APIs are deprecated and what the compiler tells you](#ios-how-apis-are-deprecated-and-what-the-compiler-tells-you)
  - [Android: catalogue of security-relevant deprecated APIs](#android-catalogue-of-security-relevant-deprecated-apis)
  - [iOS: catalogue of security-relevant deprecated APIs](#ios-catalogue-of-security-relevant-deprecated-apis)
  - [Generic: deprecations that are not findings](#generic-deprecations-that-are-not-findings)
- [Tests](#tests)
  - [GT-CODE-0046-1: Deprecated security APIs in decompiled code (Android)](#gt-code-0046-1-deprecated-security-apis-in-decompiled-code-android)
  - [GT-CODE-0046-2: Deprecated security symbols imported by the app binary (iOS)](#gt-code-0046-2-deprecated-security-symbols-imported-by-the-app-binary-ios)
  - [GT-CODE-0046-3: Suppressed deprecation warnings in source and build configuration (Android and iOS)](#gt-code-0046-3-suppressed-deprecation-warnings-in-source-and-build-configuration-android-and-ios)
- [Best practices](#best-practices)
  - [MASTG-BEST-0020: Update the GMS Security Provider](#mastg-best-0020-update-the-gms-security-provider)
  - [MASTG-BEST-0032: Migrate from UIWebView to WKWebView](#mastg-best-0032-migrate-from-uiwebview-to-wkwebview)
  - [MASTG-BEST-0006: Use Up-to-Date APK Signing Schemes](#mastg-best-0006-use-up-to-date-apk-signing-schemes)
  - [Secure implementation (Guler Tech)](#secure-implementation-guler-tech)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

MASWE-0046 applies when an app relies on APIs or functionality that are no longer maintained, may no longer receive security fixes, or have been superseded by safer alternatives. The OWASP requirement is *"The app does not use deprecated APIs or functionality."* It maps to MASVS-CODE-3 ("The app only uses software components without known vulnerabilities") and MASVS-CRYPTO-2 ("The app performs key management according to industry best practices"), and to three CWEs: [CWE-477: Use of Obsolete Function](https://cwe.mitre.org/data/definitions/477.html), [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html) and [CWE-522: Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html). The weakness is tagged for the L2 and EUDIW profiles only, so OWASP treats it as a hardening expectation for apps that handle sensitive data, not as an L1 baseline. Its MASVS v1 ancestor is MSTG-CRYPTO-4 ("The app does not use cryptographic protocols or algorithms that are widely considered deprecated for security purposes"), which explains the crypto bias of the CWE list. In the beta MASWE catalogue the weakness carried the number MASWE-0015; that number now belongs to [key rotation](/mobile/maswe-0015-key-rotation-not-implemented/), so do not confuse the two. OWASP's threat and attack references are MAS-THREAT-0046 and MAS-ATTACK-0058.

OWASP's own example is the Android KeyStore implemented with Bouncy Castle (BKS), with references to the [Android 12 Bouncy Castle removal](https://developer.android.com/about/versions/12/behavior-changes-all#bouncy-castle), the [`KeyStore` reference](https://developer.android.com/reference/java/security/KeyStore) and WithSecure's research [How secure is your Android Keystore authentication?](https://labs.withsecure.com/publications/how-secure-is-your-android-keystore-authentication). The weakness is broader than that, though: it covers deprecated cryptography, storage, networking, authentication, WebView and platform features in general.

A deprecated API is a finding when **at least one** of these holds:

1. **It was deprecated for a security reason**, and the old behaviour is still in effect on devices the app supports (world-readable files on an app targeting Android 6, `kSecAttrAccessibleAlways`).
2. **Its replacement has safer defaults or enforces something the old API left to the caller**, and the app's use of the old API gets that something wrong (`SecTrustEvaluate` result misread; `KeyPairGeneratorSpec` keys with no purpose or authentication restrictions; `FingerprintManager` without a `CryptoObject`).
3. **It is no longer maintained or no longer operates**, and the app depends on it for a security decision (SafetyNet Attestation, an abandoned crypto library, a removed provider).

If none of these holds, the deprecation is a maintenance note, not a vulnerability, and should be reported as Info or not at all.

Keep the neighbouring weaknesses apart:

| Question | Where it lives |
|---|---|
| Does the app call an API its vendor has deprecated, removed or turned down, in a security-relevant way? | This note (MASWE-0046) |
| Does a third-party library have a known CVE? | [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/) |
| Does the app target an old API level, so that it misses newer platform protections? | [MASWE-0042](/mobile/maswe-0042-latest-platform-version-not-targeted/) |
| Does it still install on OS versions where the old behaviour applies? | [MASWE-0041](/mobile/maswe-0041-running-on-recent-platform-version-not-ensured/) |
| Does it implement security functionality itself, or with non-standard components, instead of with platform APIs? | [MASWE-0047](/mobile/maswe-0047-non-standard-security-apis/) |
| Is the algorithm itself weak (DES, ECB, MD5, SHA-1 signatures), regardless of which API is used? | [MASWE-0007](/mobile/maswe-0007-improper-encryption/), [MASWE-0008](/mobile/maswe-0008-improper-hashing/) and the rest of the [CRYPTO series](/mobile/masvs-crypto-cryptography-guide/) |

The overlap with MASWE-0041 and MASWE-0042 matters in practice. Many deprecated APIs only behave insecurely when the app *targets* an old API level, or only on *devices* running an old OS. A deprecated API in an `if (Build.VERSION.SDK_INT < 23)` branch of an app whose `minSdkVersion` is 26 is dead code; the same branch in an app with `minSdkVersion` 21 runs on real devices. Every finding in this note therefore records the app's minimum and target versions.

## Modes of Introduction

**Deprecated cryptographic providers and key stores.** The app names a provider that has been deprecated or removed (`"BC"`, `"Crypto"`), keeps application secrets in a password-protected BKS or PKCS#12 file instead of the hardware-backed Android Keystore, or generates keys with `KeyPairGeneratorSpec`. These are the cases OWASP had in mind.

**Deprecated platform APIs kept for old OS versions.** The new API arrived at API level 28 or iOS 13, so the developer wrapped it in a version check and kept the old call in the `else` branch. That branch is live on every supported device below the cut-off, and it is usually the least-tested code in the app.

**Tutorial and Stack Overflow code.** Snippets age badly. The Android "SimpleCrypto" helper that derived keys from `SecureRandom.getInstance("SHA1PRNG", "Crypto")` with a fixed seed, `SecTrustEvaluate` examples that check only `errSecSuccess`, raw `SecKeyRawSign` calls with `kSecPaddingNone`: all were copied widely and all use APIs that are now deprecated.

**Deprecation warnings ignored or suppressed.** `@SuppressWarnings("deprecation")`, `@Suppress("DEPRECATION")` and `#pragma clang diagnostic ignored "-Wdeprecated-declarations"` placed to make a build green, a lint baseline that hides every existing issue, or CocoaPods' `inhibit_all_warnings!`. On Apple platforms there is a quieter cause: the compiler only warns about an API deprecated in iOS 13 if the deployment target is iOS 13 or later, so an app that still supports iOS 12 sees no warning at all.

**Third-party SDKs and cross-platform plugins.** A Flutter, React Native or Cordova plugin, an analytics SDK or an old authentication library calls the deprecated API on the app's behalf. The app's own code is clean; the binary is not.

**Services that are switched off.** Some deprecations are server-side. When Google turned down the SafetyNet Attestation API, apps that still called it started receiving errors. If the app or its backend treats an error as "pass", the integrity check disappears without anyone noticing.

**Half-finished migrations.** The app moved from `LocalBroadcastManager` to global broadcasts, from `UIWebView` to `WKWebView` but kept the old delegate logic, or from `FingerprintManager` to `BiometricPrompt` but still without a `CryptoObject`. The replacement API is used, but without the property that made it safer.

## Impact

- **Compromise of sensitive data.** Files created with world-readable modes, keychain items readable while the device is locked, keys held in a software key store in the app's process, or MD5-based integrity checks expose exactly the data those APIs were meant to protect.
- **Authentication or authorisation bypass.** Deprecated authentication and key-store APIs that return a boolean (a fingerprint callback without a `CryptoObject`, a device-credential activity result) or that create keys without authentication requirements can be bypassed by hooking the callback on a compromised device or by a malicious app on old platform versions.
- **Silent loss of a security control.** A removed provider, a turned-down attestation API or an ignored manifest attribute does not crash the app if errors are swallowed. The control that the security design relies on is simply no longer there.
- **Hidden migration risk.** Deprecated APIs eventually change behaviour when the app raises its target SDK or deployment target. If the team does not know where they are used, the security-relevant ones get migrated in a hurry, which is how half-finished migrations happen.

## Mitigations

- **Migrate off deprecated APIs**, starting with the security-relevant ones in the catalogues below. Use the vendor's documented replacement, and make sure the property that makes the replacement safer is actually used (a `CryptoObject`, `NSSecureCoding` with an allow-list, `SecTrustEvaluateWithError`'s Boolean).
- **Treat deprecation warnings as actionable.** Surface them in CI, fail release builds on new ones, and track any deliberate suppression with a reason and an expiry.
- **Read platform release notes.** Android behaviour changes per target SDK, Jetpack and Google Play services release notes, and Apple's SDK release notes announce deprecations a year or more before they bite.
- **Raise the minimum OS version** where the deprecated call only exists to support old devices ([MASWE-0041](/mobile/maswe-0041-running-on-recent-platform-version-not-ensured/)). Removing the old branch is often easier than securing it.
- **Test on every supported OS version.** A legacy branch that only runs on Android 8 or iOS 12 must be exercised on Android 8 or iOS 12.
- **Fail closed** when a security service (attestation, provider update) returns an error.

## Background

OWASP has no Knowledge items for this weakness, so this section is ours.

### Generic: deprecated, removed, turned down and merely old

Four different situations get called "deprecated", and they are not equally serious:

| Situation | What it means | Example | What the app sees |
|---|---|---|---|
| **Deprecated** | Still works; the vendor recommends a replacement and may remove it later | `FingerprintManager` (API 28), `SecTrustEvaluate` (iOS 13) | A compiler warning, if anything |
| **Behaviour changed by target version** | The API still exists but behaves differently once the app opts in to a newer target | `MODE_WORLD_READABLE` throws `SecurityException` for apps targeting API 24+ | Nothing until the target is raised |
| **Removed** | Gone from the platform or the SDK | The `Crypto` provider (removed in Android 9), Apache HTTP client (removed from the SDK in Android 6) | `NoSuchAlgorithmException`, `NoSuchProviderException`, `ClassNotFoundException`, or a fallback path |
| **Turned down** | The client library still links, but the service behind it no longer answers | SafetyNet Attestation | An API error at runtime |

"Merely old" is a fifth category: an API that is not deprecated at all but has a better successor (`Cipher.getInstance("AES")` with its provider-chosen defaults, `setAllowFileAccess` whose default changed). Those are covered where they matter, mostly in the CRYPTO and PLATFORM notes.

### Android: how APIs are deprecated, restricted and removed

**Framework APIs.** Android marks a deprecated framework API with the Java `@Deprecated` annotation and a `@deprecated` Javadoc tag. The API reference shows *"This method was deprecated in API level N"* with the replacement. Deprecated framework APIs almost never disappear from `android.jar`; Android preserves binary compatibility and changes *behaviour* by `targetSdkVersion` instead. That is why the same call can be harmless in one app and a finding in another. The few real removals were security-motivated: the `Crypto` provider (deprecated in Android 7, removed in Android 9), Bouncy Castle implementations of algorithms that Conscrypt also provides (deprecated in Android 9, mostly removed in Android 12), and the Apache HTTP client (removed from the SDK in Android 6; apps targeting Android 9 or higher must declare `<uses-library android:name="org.apache.http.legacy" android:required="false"/>` to use it at all). Android 9 also began [restricting non-SDK interfaces](https://developer.android.com/guide/app-compatibility/restrictions-non-sdk-interfaces): private methods reached by reflection or JNI are blocked or warned about depending on the target SDK. Apps that relied on such interfaces for security functionality are relying on something with no compatibility promise at all.

**Libraries.** Jetpack (AndroidX) libraries deprecate through their release notes and Kotlin's `@Deprecated(message, ReplaceWith(...), level)`, where `level` can be `WARNING`, `ERROR` (compilation fails) or `HIDDEN`. Google Play services deprecations are announced on developer.android.com and sometimes end with the service being switched off. The Google Play SDK Index flags library versions that their authors have marked deprecated or outdated, and Android lint reports that through `PlaySdkIndexDeprecated`.

**What the compilers and lint report.** `javac` only prints a summary note (*"Some input files use or override a deprecated API. Recompile with -Xlint:deprecation for details."*) unless you pass `-Xlint:deprecation`, after which each use gets a `warning: [deprecation] … has been deprecated` line; `-Werror` turns warnings into errors. `kotlinc` reports each deprecated call as a warning by default (and as an error for `DeprecationLevel.ERROR`); `allWarningsAsErrors` turns all of them into errors. Android lint adds checks that know about *Android* deprecations and their security consequences. The ones relevant here (IDs as listed in the [lint check index](https://googlesamples.github.io/android-custom-lint-rules/checks/index.md.html)):

| Lint ID | What it catches |
|---|---|
| `DeprecatedProvider` | Use of the `BC` provider |
| `DeprecatedSinceApi` | Calls to methods annotated `@DeprecatedSinceApi` where they apply |
| `Deprecated` | Deprecated resources and manifest/XML attributes |
| `WorldReadableFiles`, `WorldWriteableFiles` | `MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE` |
| `SSLCertificateSocketFactoryGetInsecure`, `SSLCertificateSocketFactoryCreateSocket` | The insecure factory and its hostname-less `createSocket` |
| `AllowAllHostnameVerifier`, `BadHostnameVerifier`, `TrustAllX509TrustManager`, `CustomX509TrustManager` | Legacy and home-made TLS validation shortcuts |
| `GetInstance` | `Cipher.getInstance` with ECB, including the bare `"AES"` default |
| `PlaySdkIndexDeprecated` | A dependency version marked deprecated in the Play SDK Index |

**What survives in an APK.** Calls to framework classes (`android.*`, `java.*`, `javax.*`) cannot be renamed by R8, because the classes live on the device, not in the APK. In jadx output and in smali they appear with their real names (`Landroid/hardware/fingerprint/FingerprintManager;`), which makes framework deprecations easy to find statically. Bundled libraries are different: R8 may rename AndroidX or third-party classes, so `LocalBroadcastManager` or `EncryptedSharedPreferences` may show up as `a.b.c`. For those, use metadata the build leaves behind: `META-INF/<group>_<artifact>.version` files for AndroidX (for example `META-INF/androidx.security_security-crypto.version`), `<artifact>.properties` files at the APK root for Google Play services libraries (for example `play-services-safetynet.properties`), and string constants the library writes at runtime. Annotations such as `@SuppressWarnings` are source-only and are gone from the APK; checking suppressions needs the source (GT-CODE-0046-3).

### iOS: how APIs are deprecated and what the compiler tells you

**Annotations.** Apple's C and Objective-C headers mark deprecations with availability macros from `<os/availability.h>`: `API_DEPRECATED("message", ios(2.0, 13.0))` (introduced in 2.0, deprecated in 13.0), `API_DEPRECATED_WITH_REPLACEMENT("NewName", ios(...))` and `API_UNAVAILABLE(ios)`. Swift APIs use `@available(iOS, introduced: 2.0, deprecated: 13.0, message: "...")`, with `renamed:` for a replacement and `obsoleted:` for a version from which the API can no longer be called; `@available(*, deprecated, message: "...")` deprecates on every platform. Apple's documentation shows the range as, for example, "iOS 2.0–13.0 Deprecated".

**Warnings depend on the deployment target.** Clang's `-Wdeprecated-declarations` (on by default, controlled by the `GCC_WARN_ABOUT_DEPRECATED_FUNCTIONS` build setting) and the Swift compiler only warn about an API when the deployment target is at or above the version in which it was deprecated. An app whose deployment target is iOS 12 that calls `SecTrustEvaluate` (deprecated in iOS 13) builds without a warning. Many teams therefore discover their deprecated calls only when they raise the deployment target. This is worth stating in reports: "no warnings in the build" is not evidence of "no deprecated calls".

**Removal and store enforcement.** Apple rarely removes C functions from the SDK, but it does enforce migrations through App Store submission checks. `UIWebView` is the example everyone remembers: Apple stopped accepting new apps that contained it in April 2020 and updates in December 2020, flagging them with the *ITMS-90809: Deprecated API Usage* message. Apps distributed outside the App Store (enterprise and ad hoc builds) are not subject to that check.

**What survives in a Mach-O binary.** Imported C functions and data symbols keep their names: `_SecTrustEvaluate`, `_CC_MD5`, `_kSecAttrAccessibleAlways` appear in the symbol table as undefined (imported) symbols. Objective-C classes appear as class references (`_OBJC_CLASS_$_UIWebView`). Objective-C methods, including those called from Swift, appear as selector strings in the `__objc_methname` section (`unarchiveObjectWithData:`). Enum values and constants that the compiler folds into immediates (`kSecPaddingNone`, `tls_protocol_version_t` values) do not have symbols; you find them only by reading the code around a call.

### Android: catalogue of security-relevant deprecated APIs

This list is deliberately limited to APIs whose deprecation has a security angle. "Replacement" is the vendor's documented successor; "Covered in" points to the note that tests the underlying security property.

| API or feature | Status | Why it matters for security | Replacement | Covered in |
|---|---|---|---|---|
| `Context.MODE_WORLD_READABLE`, `MODE_WORLD_WRITEABLE` (in `openFileOutput`, `getSharedPreferences`, `openOrCreateDatabase`) | Deprecated in API 17; `SecurityException` for apps targeting API 24+ | Any app on the device can read or write the file. On apps targeting API 23 or lower, the mode still works on every Android version | `MODE_PRIVATE`; share with `FileProvider` and URI grants | [MASWE-0001](/mobile/maswe-0001-sensitive-data-unencrypted-private-storage/), [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/) |
| `Environment.getExternalStorageDirectory()`, `getExternalStoragePublicDirectory()` | Deprecated in API 29 (scoped storage) | Shared storage was readable by any app with storage permission; code that still writes there leaks on older devices and on apps that opt out of scoped storage | `getExternalFilesDir()`, `MediaStore`, Storage Access Framework | [MASWE-0002](/mobile/maswe-0002-sensitive-data-unencrypted-outside-private-storage/) |
| `android:sharedUserId` | Deprecated in API 29 | Several apps signed with the same key share one UID and one sandbox; a flaw in any of them exposes the data of all | Signature-protected IPC; `android:sharedUserMaxSdkVersion` (API 33) to leave a shared UID | [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/) |
| `LocalBroadcastManager` (AndroidX) | Deprecated library | Not insecure itself; migrations often replace it with global `sendBroadcast()`, turning an in-process event into a device-wide broadcast | `LiveData`/`Flow`, or broadcasts with `setPackage()` and `RECEIVER_NOT_EXPORTED` | [MASWE-0032](/mobile/maswe-0032-insecure-intents/) |
| `Intent.getParcelableExtra(String)`, `getSerializableExtra(String)`, `Bundle.getParcelable(String)` | Deprecated in API 33 | Untyped unparcelling of data from another app; type-confusion and unexpected-class bugs | Typed overloads `getParcelableExtra(name, Class)` (API 33), `IntentCompat`/`BundleCompat` | [MASWE-0032](/mobile/maswe-0032-insecure-intents/), [MASWE-0050](/mobile/maswe-0050-unsafe-handling-of-untrusted-data/) |
| `PackageManager.GET_SIGNATURES`, `PackageInfo.signatures` | Deprecated in API 28 | Does not model APK key rotation or multiple signers; app-identity checks (partner-app trust, self-integrity checks) built on it can compare the wrong certificate | `GET_SIGNING_CERTIFICATES` with `PackageInfo.signingInfo`, or `PackageManager.hasSigningCertificate()` | [MASTG-KNOW-0003 note](/mobile/mastg-know-0003-app-signing/) |
| `Crypto` security provider (`SecureRandom.getInstance("SHA1PRNG", "Crypto")`) | Deprecated in Android 7, removed in Android 9 | Was used to derive keys from a seeded PRNG ("SimpleCrypto"); after removal, such code either crashes or falls back to something else, and existing ciphertext becomes unreadable or the fallback is weak | A real KDF (PBKDF2, Argon2 via a vetted library) or a random key in the Keystore | [MASWE-0012](/mobile/maswe-0012-improper-random-number-generation/), [MASWE-0014](/mobile/maswe-0014-improper-key-derivation/) |
| `BC` provider named in `getInstance(..., "BC")` | Duplicated algorithms deprecated in Android 9, mostly removed in Android 12 | `NoSuchAlgorithmException` on new targets; the app pins itself to an implementation that no longer receives platform updates | Default provider (Conscrypt / `AndroidOpenSSL`), no provider argument | [MASWE-0007](/mobile/maswe-0007-improper-encryption/) (MASTG-TEST-0312) |
| BKS / PKCS#12 key store files for app secrets (`KeyStore.getInstance("BKS")`) | Type still supported (API 1+); superseded for app keys by `AndroidKeyStore` (API 18) | A software key store: a file plus a password the app must also store, with keys loaded into the app's memory. This is OWASP's headline example. A BKS file used only as a *trust store* for pinning is a different matter | `AndroidKeyStore` keys, optionally StrongBox-backed | [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/) |
| `KeyPairGeneratorSpec` | Deprecated in API 23 | Cannot express purposes, digests, paddings, block modes, user-authentication requirements or StrongBox; keys made with it carry none of those restrictions | `KeyGenParameterSpec` | [MASWE-0013](/mobile/maswe-0013-improper-key-generation/), [MASWE-0016](/mobile/maswe-0016-key-access-not-restricted/) |
| `KeyGenParameterSpec.Builder.setUserAuthenticationValidityDurationSeconds()` | Deprecated in API 30 | Implicit semantics (`-1` means per-use biometric only); easy to misconfigure what counts as authentication | `setUserAuthenticationParameters(timeout, KeyProperties.AUTH_BIOMETRIC_STRONG or AUTH_DEVICE_CREDENTIAL)` | [MASWE-0016](/mobile/maswe-0016-key-access-not-restricted/) |
| Jetpack `security-crypto` (`EncryptedSharedPreferences`, `EncryptedFile`, `MasterKey`) | All APIs deprecated in 1.1.0-alpha07 (April 2025) and in the 1.1.0 stable release (July 2025) | Not insecure today, but no further releases are planned. Treat as an unmaintained dependency, not as a vulnerability | Keystore-held AES-GCM key used directly; DataStore with `datastore-tink` | [MASWE-0001](/mobile/maswe-0001-sensitive-data-unencrypted-private-storage/) |
| `FingerprintManager` | Deprecated in API 28 | Custom UI, no notion of biometric class, and in practice often used without a `CryptoObject`, so "authentication" is a callback that can be hooked (the WithSecure research OWASP cites) | `BiometricPrompt` (AndroidX Biometric) with a `CryptoObject` | [FingerprintManager note](/mobile/mastg-know-0002-fingerprintmanager/), [MASWE-0020](/mobile/maswe-0020-local-authentication-bypass/) |
| `KeyguardManager.createConfirmDeviceCredentialIntent()` | Deprecated in API 29 | Returns an activity result, which is a boolean unless paired with a key that requires authentication | `BiometricPrompt` with `setAllowedAuthenticators(... or DEVICE_CREDENTIAL)` | [MASWE-0020](/mobile/maswe-0020-local-authentication-bypass/) |
| Legacy Google Sign-In (`GoogleSignIn`, `GoogleSignInClient` in `play-services-auth`), Smart Lock for Passwords | Deprecated; Google has announced removal of legacy Google Sign-In from the Play services Auth SDK | Authentication flow on a library with no future fixes | Credential Manager (`androidx.credentials`) for sign-in, `AuthorizationClient` for authorisation | [MASWE-0019](/mobile/maswe-0019-no-autofill-support-for-credential-providers/), [MASWE-0047](/mobile/maswe-0047-non-standard-security-apis/) |
| SafetyNet Attestation API (`SafetyNet.getClient(...).attest(...)`) | Deprecated in 2022 and since turned down by Google | Calls fail. If the app or backend treats failure as success, device and app integrity checks are gone | Play Integrity API, verdicts verified on the server | MASVS-RESILIENCE |
| `android.net.SSLCertificateSocketFactory` | Deprecated in API 29 | `getInsecure()` disables certificate checks; `createSocket(InetAddress, int)` does no hostname verification | `SSLSocketFactory.getDefault()`/`SSLContext` plus hostname verification, or `HttpsURLConnection`/OkHttp | [MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/) |
| Apache HTTP client (`org.apache.http.*`, `AllowAllHostnameVerifier`, `ALLOW_ALL_HOSTNAME_VERIFIER`) | Removed from the SDK in Android 6; opt-in legacy library since Android 9 | A frozen pre-release snapshot with no fixes, and permissive hostname verifiers built in | `HttpsURLConnection`, OkHttp, Cronet | [MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/) |
| `android:usesCleartextTraffic` | Android documents it as being deprecated and ignored for apps targeting API level 38 and above | Mostly a functional risk: once ignored, the Network Security Configuration (NSC) default applies. Put the cleartext policy in the NSC where it is reviewed | `cleartextTrafficPermitted` in the NSC | [MASWE-0026 cleartext](/mobile/maswe-0026-cleartext-network-traffic/) |
| `WebSettings.setAllowFileAccessFromFileURLs()`, `setAllowUniversalAccessFromFileURLs()` | Deprecated in API 30; default `false` for apps targeting API 16+ | Setting either to `true` lets a `file://` page read other local files or any origin | Leave at default; serve local content with `WebViewAssetLoader` | [MASWE-0034](/mobile/maswe-0034-webviews-allow-access-to-local-resources/) |
| `WebSettings.setSavePassword()` | Deprecated in API 18, no effect since | Historical: WebView stored form passwords in a plaintext database | None needed | Info only |
| APK signed with v1 (JAR) scheme only | Apps targeting Android 11 must also be signed with v2 or higher | v1 does not protect the whole file; v1-only APKs were exposed to Janus (CVE-2017-13156) on Android 5.0 to 8.0 | v2 or v3 (plus v1 only if `minSdkVersion` < 24) | [MASTG-BEST-0006](#mastg-best-0006-use-up-to-date-apk-signing-schemes), [MASTG-KNOW-0003 note](/mobile/mastg-know-0003-app-signing/) |
| Non-SDK (hidden) interfaces via reflection or JNI | Restricted since Android 9, by target SDK | No compatibility promise; a security feature built on one can stop working silently | Public SDK APIs | GT-CODE-0046-1 step 6 |

### iOS: catalogue of security-relevant deprecated APIs

| API or feature | Status | Why it matters for security | Replacement | Covered in |
|---|---|---|---|---|
| `UIWebView` | Deprecated in iOS 12; rejected by App Store submission since 2020 | Renders in the app's process, so a WebKit memory-corruption bug in rendered content affects the app itself; JavaScript cannot be fully disabled; no modern navigation and content controls | `WKWebView` | [MASWE-0035](/mobile/maswe-0035-webviews-loading-untrusted-content/) (MASTG-TEST-0331), [MASTG-BEST-0032](#mastg-best-0032-migrate-from-uiwebview-to-wkwebview) |
| `SFAuthenticationSession` | Deprecated in iOS 12 | Not insecure in itself; signals an authentication flow that has not been maintained | `ASWebAuthenticationSession` | [MASWE-0047](/mobile/maswe-0047-non-standard-security-apis/) |
| `NSKeyedUnarchiver` `unarchiveObjectWithData:`, `unarchiveObjectWithFile:` | Deprecated in iOS 12 | Decodes any class named in the archive; with untrusted input this is object substitution | `unarchivedObjectOfClass:fromData:error:` / `unarchivedObjectOfClasses:...` with `NSSecureCoding` | [MASWE-0050](/mobile/maswe-0050-unsafe-handling-of-untrusted-data/) |
| `kSecAttrAccessibleAlways`, `kSecAttrAccessibleAlwaysThisDeviceOnly` | Deprecated in iOS 12 | Keychain item readable while the device is locked; `Always` items also migrate to a new device through encrypted backups | `kSecAttrAccessibleWhenUnlocked(ThisDeviceOnly)` or, for background access, `AfterFirstUnlock(ThisDeviceOnly)` | [MASWE-0001](/mobile/maswe-0001-sensitive-data-unencrypted-private-storage/), [MASWE-0016](/mobile/maswe-0016-key-access-not-restricted/) |
| `kSecAccessControlTouchIDAny`, `kSecAccessControlTouchIDCurrentSet` | Deprecated in iOS 11.3 (renamed) | Same semantics as the replacements; the deprecation itself is cosmetic. Check that `CurrentSet` (not `Any`) is used where enrolment changes must invalidate the key | `.biometryAny`, `.biometryCurrentSet` | [MASWE-0022](/mobile/maswe-0022-keys-not-invalidated-on-biometric-enrollment/) |
| `LAContext.evaluatedPolicyDomainState` | Deprecated in iOS 18 | Used to detect biometric enrolment changes in app logic | `LAContext.domainState` (`LADomainState`, iOS 18) | [MASWE-0022](/mobile/maswe-0022-keys-not-invalidated-on-biometric-enrollment/) |
| `SecTrustEvaluate` | Deprecated in iOS 13 | Its `OSStatus` says only whether evaluation ran; the verdict is in a separate `SecTrustResultType`. Code that checks only `errSecSuccess` trusts everything | `SecTrustEvaluateWithError` (iOS 12), `SecTrustEvaluateAsyncWithError` (iOS 13) | [MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/) |
| `SecTrustCopyPublicKey`, `SecTrustGetCertificateAtIndex` | Deprecated in iOS 14 and iOS 15 | Used in pinning code; the replacements make the chain and key handling explicit | `SecTrustCopyKey`, `SecTrustCopyCertificateChain` | [MASWE-0028](/mobile/maswe-0028-insecure-identity-pinning/) |
| `SecKeyRawSign`, `SecKeyRawVerify`, `SecKeyEncrypt`, `SecKeyDecrypt` | Deprecated in iOS 15 | The caller chooses padding (including `kSecPaddingNone`) and must hash the data first; textbook RSA and signing unhashed data are easy mistakes | `SecKeyCreateSignature`, `SecKeyVerifySignature`, `SecKeyCreateEncryptedData`, `SecKeyCreateDecryptedData` with an explicit `SecKeyAlgorithm` | [MASWE-0010](/mobile/maswe-0010-improper-signature-generation/), [MASWE-0011](/mobile/maswe-0011-improper-signature-verification/), [MASWE-0007](/mobile/maswe-0007-improper-encryption/) |
| `CC_MD5` (CommonCrypto) | Deprecated in iOS 13 with the message that it is cryptographically broken and should not be used in security contexts | MD5 collisions are practical; integrity checks, signatures or password hashing built on it fail | SHA-256 via CryptoKit or `CC_SHA256`; CryptoKit's `Insecure.MD5` for non-security checksums | [MASWE-0008](/mobile/maswe-0008-improper-hashing/) |
| Secure Transport (`SSLCreateContext`, `SSLHandshake`, `SSLSetEnabledCiphers` and friends) | Deprecated in iOS 13 | Low-level TLS outside ATS, with legacy protocol versions available | `URLSession`, or Network framework (`NWConnection`) | [MASWE-0026 TLS versions](/mobile/maswe-0026-insecure-tls-protocol-versions/) |
| `URLSessionConfiguration.tlsMinimumSupportedProtocol` (`SSLProtocol`); `tls_protocol_version_t.TLSv10`, `.TLSv11` | Deprecated in iOS 13; TLS 1.0/1.1 values deprecated in iOS 15 | Explicitly lowers the TLS floor for a session | `tlsMinimumSupportedProtocolVersion = .TLSv12` or higher | [MASWE-0026 TLS versions](/mobile/maswe-0026-insecure-tls-protocol-versions/) |
| `NSURLConnection` | Deprecated in iOS 9 | ATS applies to it as to `URLSession`; the risk lies in old delegate code (`connection:willSendRequestForAuthenticationChallenge:`) that accepts any server trust | `URLSession` | [MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/) |

### Generic: deprecations that are not findings

Do not report a deprecated API as a security weakness just because a scanner lists it. `UIAlertView`, `UIActionSheet`, `UIApplication openURL:`, `AsyncTask`, `Handler()` without a `Looper`, `startActivityForResult()` and most layout and UI deprecations have no security relevance; neither do deprecated Gradle DSL properties. Mention them in a code-quality appendix if the client wants one. Similarly, a deprecated call inside a version check whose branch can never run (because `minSdkVersion` or the deployment target is above the cut-off) is dead code: note it as Info and recommend removing it.

## Tests

OWASP has no tests linked to MASWE-0046. Several OWASP tests that live under other weaknesses check one deprecated API each, and they are documented in full in the notes that own them:

| OWASP test | Deprecated API it checks | Weakness | Our note |
|---|---|---|---|
| [MASTG-TEST-0312](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0312/) | Explicitly named, deprecated or removed security providers (`BC`, `Crypto`) | MASWE-0007 | [Improper Encryption](/mobile/maswe-0007-improper-encryption/) |
| [MASTG-TEST-0295](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0295/) | GMS security provider not updated (MASTG-BEST-0020) | MASWE-0027 | [Insecure Certificate Validation](/mobile/maswe-0027-insecure-certificate-validation/) |
| [MASTG-TEST-0331](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0331/) | `UIWebView` (MASTG-BEST-0032) | MASWE-0035 | [WebViews Loading Untrusted Content](/mobile/maswe-0035-webviews-loading-untrusted-content/) |
| [MASTG-TEST-0224](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0224/) | APK signed only with the v1 scheme (MASTG-BEST-0006) | MASWE-0056 | Summarised under [MASTG-BEST-0006](#mastg-best-0006-use-up-to-date-apk-signing-schemes); background in [App Signing](/mobile/mastg-know-0003-app-signing/) |

Our three tests below sweep for the whole catalogue at once, so that you get one inventory per app, and then send each hit to the note that judges the underlying property. GT-CODE-0046-1 and -2 work on the release binary and need nothing from the developer. GT-CODE-0046-3 needs the source and build files, and finds the cases where the team was told about a deprecation and chose to silence it.

### GT-CODE-0046-1: Deprecated security APIs in decompiled code (Android)

*Guler Tech methodology — not an OWASP test.*

Platform: Android. Type: static (code, manifest, packaging), with optional dynamic confirmation. Tools: jadx ([MASTG-TOOL-0018](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/)), Apktool ([MASTG-TOOL-0011](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/)), semgrep ([MASTG-TOOL-0110](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/)), `aapt2`, apksigner ([MASTG-TOOL-0123](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0123/)), optionally Frida ([MASTG-TOOL-0031](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/)). Techniques: [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/) (reverse engineering Android apps) and [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/) (static analysis on Android).

#### Overview

The test builds an inventory of every call to a security-relevant deprecated API from the [Android catalogue](#android-catalogue-of-security-relevant-deprecated-apis), attributes each call to first-party code or a named SDK, and decides whether the call is reachable on the Android versions the app supports. Framework calls keep their names after R8, so a smali search is reliable for them; bundled libraries need the metadata searches in step 4.

#### Prerequisites

- The release APK (or all splits of an app bundle install, pulled with `adb shell pm path com.example.app` and `adb pull`).
- `aapt2` from the Android SDK build tools, jadx, Apktool, ripgrep or grep, semgrep.
- For step 7: a test device or emulator on the oldest Android version the app supports, with Frida.

#### Steps

1. **Record the version window.** Deprecations matter only on devices the app can run on:

   ```bash
   aapt2 dump badging app.apk | grep -E "^(package|sdkVersion|targetSdkVersion)"
   ```

   ```text
   package: name='com.example.app' versionCode='4120' versionName='4.12.0' ...
   sdkVersion:'24'
   targetSdkVersion:'35'
   ```

   `sdkVersion` is the `minSdkVersion`. Keep both numbers; every finding refers to them.

2. **Decompile twice.** jadx gives readable Java; Apktool gives smali, which is the more reliable source for exact method signatures because it does not depend on jadx successfully decompiling every method:

   ```bash
   jadx -d out-jadx app.apk
   apktool d -f -o out-smali app.apk
   ```

3. **Search smali for framework deprecations.** Framework references are written as `Lpackage/Class;->method(args)ret`. The list below covers the Android catalogue; extend it as needed.

   ```bash
   cat > deprecated-android.txt <<'LIST'
   Landroid/hardware/fingerprint/FingerprintManager;
   Landroid/security/KeyPairGeneratorSpec
   ;->setUserAuthenticationValidityDurationSeconds(I)
   Landroid/app/KeyguardManager;->createConfirmDeviceCredentialIntent
   Landroid/net/SSLCertificateSocketFactory;
   Lorg/apache/http/conn/ssl/
   Lorg/apache/http/impl/client/DefaultHttpClient;
   Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs(Z)V
   Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V
   Landroid/webkit/WebSettings;->setSavePassword(Z)V
   Landroid/os/Environment;->getExternalStorageDirectory()
   Landroid/os/Environment;->getExternalStoragePublicDirectory(
   Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;
   Landroid/content/Intent;->getSerializableExtra(Ljava/lang/String;)Ljava/io/Serializable;
   Landroid/os/Bundle;->getParcelable(Ljava/lang/String;)Landroid/os/Parcelable;
   Landroid/content/pm/PackageInfo;->signatures:
   Lcom/google/android/gms/safetynet/
   Lcom/google/android/gms/auth/api/signin/GoogleSignIn
   Lcom/google/android/gms/auth/api/credentials/
   LIST
   while IFS= read -r p; do
     n=$(grep -rlF -- "$p" out-smali/smali* | wc -l | tr -d ' ')
     [ "$n" -gt 0 ] && printf '%4s files  %s\n' "$n" "$p"
   done < deprecated-android.txt
   ```

   Then pull the call sites for each hit, with the class they are in:

   ```bash
   grep -rnF -- 'Landroid/hardware/fingerprint/FingerprintManager;->authenticate' out-smali/smali* | cut -c1-200
   ```

   The `com/google/android/gms/auth/api/credentials/` package is the Smart Lock for Passwords API. Hits *inside* `smali*/com/google/android/gms/` are the library itself; what matters is which app or SDK packages call into it.

4. **Search for constants and for bundled deprecated libraries.** Some deprecated usages are a constant, not a method:

   ```bash
   # MODE_WORLD_READABLE = 1, MODE_WORLD_WRITEABLE = 2 passed to the mode parameter
   rg -n 'openFileOutput\([^,]+,\s*[12]\)|getSharedPreferences\([^,]+,\s*[12]\)|MODE_WORLD_(READ|WRITE)ABLE' out-jadx/sources/
   # GET_SIGNATURES = 64 (0x40)
   rg -n 'GET_SIGNATURES|getPackageInfo\([^,]+,\s*64\)' out-jadx/sources/
   # Named providers (detail and evaluation in MASTG-TEST-0312)
   rg -n 'getInstance\([^)]*,\s*"(BC|Crypto)"\)|"SHA1PRNG"' out-jadx/sources/
   # Software key stores for app secrets
   rg -n 'KeyStore\.getInstance\("(BKS|BouncyCastle|PKCS12)"' out-jadx/sources/
   # Bundled AndroidX and Play services libraries, even when R8 renamed the classes
   unzip -l app.apk | grep -E 'META-INF/androidx\.(security_security-crypto|localbroadcastmanager_localbroadcastmanager)\.version|play-services-(safetynet|auth)\.properties'
   rg -l '__androidx_security_crypto_encrypted_prefs_(key|value)_keyset__' out-jadx/
   ```

   The two `__androidx_security_crypto_encrypted_prefs_…_keyset__` strings are the preference names under which `EncryptedSharedPreferences` stores its Tink keysets; on a device you will also see them inside `shared_prefs/*.xml`.

5. **Check the manifest and the signature.** In `out-jadx/resources/AndroidManifest.xml` (or `out-smali/AndroidManifest.xml`) look for `android:sharedUserId`, `android:usesCleartextTraffic` without a `networkSecurityConfig`, and `<uses-library android:name="org.apache.http.legacy"`. Then the signing schemes:

   ```bash
   apksigner verify --verbose app.apk | grep -E 'Verified using v[1-4]'
   ```

6. **Optionally check non-SDK interfaces.** AOSP's `veridex` tool (shipped as `appcompat.sh` in the AOSP prebuilts) lists reflection and JNI uses of hidden APIs: `./appcompat.sh --dex-file=app.apk`. On a test device, `StrictMode.VmPolicy.Builder().detectNonSdkApiUsage()` in a debug build reports the same at runtime. Only hits that implement a security feature are relevant here.

7. **Decide reachability for each hit.** Open the call site in jadx and record:
   - **Who calls it**: an app package (`com.example.app`) or an SDK (`com.vendor.sdk`). SDK findings go to the client as "update or replace SDK X" and are cross-checked against [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/).
   - **Version guard**: `if (Build.VERSION.SDK_INT < 28)` or `>= 28` with the old call in the `else`. Compare the cut-off with `minSdkVersion` from step 1. If every supported version takes the new path, the old call is dead.
   - **Target-gated behaviour**: `MODE_WORLD_READABLE` throws for `targetSdkVersion` 24+, so in a current app it is a crash path, not a leak (still worth reporting as broken code). The `BC` provider fails for apps targeting API 28+ that request duplicated algorithms.
   - **What it protects**: the file, key, credential or decision involved.

   Where reachability is unclear, confirm on the oldest supported Android version with a Frida hook that logs calls made from the app's own code:

   ```javascript
   // deprecated-calls.js: log selected deprecated framework calls made by the app under test
   const APP = 'com.example.app';
   const targets = [
     ['android.hardware.fingerprint.FingerprintManager', 'authenticate'],
     ['android.security.KeyPairGeneratorSpec$Builder', '$init'],
     ['android.app.KeyguardManager', 'createConfirmDeviceCredentialIntent'],
   ];
   Java.perform(() => {
     const Log = Java.use('android.util.Log');
     const Ex = Java.use('java.lang.Exception');
     for (const [cls, name] of targets) {
       let C;
       try { C = Java.use(cls); } catch (e) { console.log('[-] not present: ' + cls); continue; }
       C[name].overloads.forEach(ov => {
         ov.implementation = function (...args) {
           const st = Log.getStackTraceString(Ex.$new());
           if (st.includes(APP)) {
             console.log('[deprecated] ' + cls + '.' + name + '\n' + st.split('\n').slice(2, 7).join('\n'));
           }
           return ov.apply(this, args);
         };
       });
     }
   });
   ```

   ```bash
   frida -U -f com.example.app -l deprecated-calls.js
   ```

   Exercise the flows that use the API (biometric unlock, key creation, PIN confirmation). The hook only observes; it passes every call through unchanged.

8. **Optionally codify the search with semgrep** over the jadx output, so it can run in the client's CI later. A starting rule file:

   ```yaml
   rules:
     - id: gt-0046-world-accessible-file-mode
       languages: [java]
       severity: ERROR
       message: World-readable/writeable file mode (deprecated in API 17, SecurityException for targetSdk 24+)
       pattern-either:
         - pattern: $C.openFileOutput($N, 1)
         - pattern: $C.openFileOutput($N, 2)
         - pattern: $C.getSharedPreferences($N, 1)
         - pattern: $C.getSharedPreferences($N, 2)
     - id: gt-0046-keypairgeneratorspec
       languages: [java]
       severity: WARNING
       message: KeyPairGeneratorSpec is deprecated since API 23; keys carry no purpose or authentication restrictions
       pattern: new KeyPairGeneratorSpec.Builder($CTX)
     - id: gt-0046-webview-file-url-access
       languages: [java]
       severity: ERROR
       message: Deprecated file URL access setting enabled in a WebView
       pattern-either:
         - pattern: $S.setAllowFileAccessFromFileURLs(true)
         - pattern: $S.setAllowUniversalAccessFromFileURLs(true)
     - id: gt-0046-untyped-parcelable-extra
       languages: [java]
       severity: INFO
       message: Untyped getParcelableExtra(String), deprecated in API 33
       pattern: $I.getParcelableExtra($K)
   ```

   ```bash
   semgrep --config gt-0046.yaml --metrics=off out-jadx/sources/
   ```

   jadx sometimes resolves constants to their names (`Context.MODE_WORLD_READABLE`) and sometimes leaves the number; the regex in step 4 covers both, the semgrep rule above only the numbers.

#### Observation

A table with one row per hit: API, file and method (from jadx), first-party or SDK (with the SDK's name and version), version guard and whether it is live given `minSdkVersion`, what data or decision it touches, and Frida output where you used it. Add `minSdkVersion`, `targetSdkVersion` and the apksigner output.

#### Evaluation

The test **fails** if live code (reachable on at least one Android version within the app's supported range) uses an API from the Android catalogue in a way that meets one of the three conditions in the [Overview](#overview): the deprecation was security-motivated and the old behaviour still applies, the use lacks the property that makes the replacement safer, or the API no longer works and the app depends on it for a security decision. Examples: `FingerprintManager` without a `CryptoObject` gating access to secrets; a SafetyNet call whose failure is treated as success; app secrets in a BKS file; `setAllowUniversalAccessFromFileURLs(true)` on a WebView; a v1-only signature.

The test **passes** if no catalogue API is used, if every use is dead code given `minSdkVersion`, or if the use is security-neutral (for example `EncryptedSharedPreferences` used correctly, which is a maintenance item). Report SDK-originated hits under the SDK's name. Each failing hit is then judged in the note listed in the catalogue's "Covered in" column, which sets the real severity.

#### Demo

A banking-style app with `minSdkVersion` 24 that kept its Android 8 biometric path:

```kotlin
fun unlock(onOk: () -> Unit) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
    } else {
        @Suppress("DEPRECATION")
        val fm = getSystemService(FingerprintManager::class.java)
        fm.authenticate(null, CancellationSignal(), 0, object : FingerprintManager.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(r: FingerprintManager.AuthenticationResult) = onOk()
        }, null)                                   // no CryptoObject: a callback, nothing more
    }
}
```

Step 3 output:

```text
   1 files  Landroid/hardware/fingerprint/FingerprintManager;
```

```text
out-smali/smali_classes2/com/example/app/auth/Unlocker.smali:88:    invoke-virtual {v0, v1, v2, v3, v4, v5}, Landroid/hardware/fingerprint/FingerprintManager;->authenticate(Landroid/hardware/fingerprint/FingerprintManager$CryptoObject;Landroid/os/CancellationSignal;ILandroid/hardware/fingerprint/FingerprintManager$AuthenticationCallback;Landroid/os/Handler;)V
```

`v1` is loaded with `const/4 v1, 0x0` a few lines earlier: the `CryptoObject` is `null`. The branch runs on Android 7.0 to 8.1 (API 24 to 27), which `minSdkVersion` 24 supports. The test fails; the bypass itself is assessed under [MASWE-0020](/mobile/maswe-0020-local-authentication-bypass/), and the fix is to raise `minSdkVersion` to 28 or to use AndroidX `BiometricPrompt` (which supports older versions) with a `CryptoObject` on every path.

### GT-CODE-0046-2: Deprecated security symbols imported by the app binary (iOS)

*Guler Tech methodology — not an OWASP test.*

Platform: iOS. Type: static (binary), with optional dynamic confirmation. Tools: otool ([MASTG-TOOL-0060](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0060/)), `nm` (Xcode command-line tools or `llvm-nm`), rabin2 ([MASTG-TOOL-0129](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/)) and radare2 ([MASTG-TOOL-0073](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/)), `plutil`, optionally Frida. Techniques: [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/) (exploring the app package), [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/) (static analysis on iOS) and [MASTG-TECH-0082](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0082/) (extracting bundled libraries).

#### Overview

Deprecated C functions, data symbols and Objective-C classes from Apple frameworks are imported by name, so they show up as undefined symbols in each Mach-O. Deprecated Objective-C methods show up as selector strings. The test searches every Mach-O in the bundle (main executable, frameworks, app extensions) for the [iOS catalogue](#ios-catalogue-of-security-relevant-deprecated-apis), attributes each hit to a binary, and checks whether the calling code is live given the deployment target.

#### Prerequisites

- A decrypted IPA (App Store binaries are FairPlay-encrypted; decrypt on a jailbroken device or test a development or ad hoc build supplied by the client).
- macOS with Xcode command-line tools, or Linux with `llvm-nm`/`llvm-otool`; radare2.
- For step 6: a jailbroken device or a debuggable build with Frida, on the oldest iOS version the app supports.

#### Steps

1. **Unpack and list every Mach-O.**

   ```bash
   unzip -o -q App.ipa -d ipa
   APP=$(ls -d ipa/Payload/*.app)
   find "$APP" -type f -exec sh -c 'file "$1" | grep -q "Mach-O" && echo "$1"' _ {} \; > macho.txt
   cat macho.txt
   ```

2. **Record the deployment target**, because it decides which deprecated paths are live:

   ```bash
   plutil -p "$APP/Info.plist" | grep -E 'MinimumOSVersion|CFBundleIdentifier'
   EXE=$(plutil -extract CFBundleExecutable raw "$APP/Info.plist")
   otool -l "$APP/$EXE" | grep -A4 LC_BUILD_VERSION | grep -E 'minos|sdk'
   ```

   `minos` is the deployment target the binary was built for, `sdk` the SDK it was built with.

3. **Search imported symbols.** Use exact symbol names; `_SecTrustEvaluate` must not match `_SecTrustEvaluateWithError`:

   ```bash
   cat > deprecated-ios-symbols.txt <<'LIST'
   _SecTrustEvaluate
   _SecTrustCopyPublicKey
   _SecTrustGetCertificateAtIndex
   _SecKeyRawSign
   _SecKeyRawVerify
   _SecKeyEncrypt
   _SecKeyDecrypt
   _CC_MD5
   _CC_MD5_Init
   _CC_MD5_Update
   _CC_MD5_Final
   _kSecAttrAccessibleAlways
   _kSecAttrAccessibleAlwaysThisDeviceOnly
   _SSLCreateContext
   _SSLHandshake
   _SSLSetEnabledCiphers
   _SSLSetProtocolVersionMin
   _OBJC_CLASS_$_UIWebView
   _OBJC_CLASS_$_SFAuthenticationSession
   _OBJC_CLASS_$_NSURLConnection
   LIST
   while read -r b; do
     nm -u "$b" 2>/dev/null | grep -xFf deprecated-ios-symbols.txt | sed "s|^|$(basename "$b"): |"
   done < macho.txt
   ```

   `nm -u` prints one undefined symbol per line, so `grep -x` matches whole names. `otool -Iv "$b"` (the indirect symbol table) and `rabin2 -i "$b"` give the same information in other formats and are useful cross-checks when a binary confuses one tool.

4. **Search selectors** for deprecated Objective-C methods, which are not symbols:

   ```bash
   while read -r b; do
     otool -v -s __TEXT __objc_methname "$b" 2>/dev/null \
       | grep -oE 'unarchiveObjectWithData:|unarchiveObjectWithFile:|evaluatedPolicyDomainState|setTLSMinimumSupportedProtocol:|connection:willSendRequestForAuthenticationChallenge:' \
       | sort -u | sed "s|^|$(basename "$b"): |"
   done < macho.txt
   ```

   A selector string only proves that some code in the binary *names* the method; Apple's own frameworks are not in the IPA, so a hit in the app's binary means the app or a bundled SDK uses it.

5. **Find the callers** in radare2 and read the code around each call:

   ```bash
   r2 -q -c 'aaa; axt @ sym.imp.SecTrustEvaluate; axt @ sym.imp.CC_MD5' "$APP/$EXE"
   ```

   For each caller, record:
   - **Version guard**: `if #available(iOS 13, *)` in Swift and `if (@available(iOS 13, *))` in Objective-C compile to a runtime version check (a call to a helper such as `__isPlatformVersionAtLeast`, `__isOSVersionAtLeast` or Swift's `_stdlib_isOSVersionAtLeast`) just before the branch. If the deprecated call is in the "older" branch and `minos` is at or above the cut-off, the branch is dead.
   - **How the result is used**: for `SecTrustEvaluate`, whether the code reads `SecTrustResultType` or only compares the `OSStatus`; for `SecKeyRawSign`/`SecKeyEncrypt`, which padding constant is passed (`kSecPaddingNone` is `0`, `kSecPaddingPKCS1` is `1`); for `CC_MD5`, what is hashed and why.
   - **What the keychain item holds**, for `kSecAttrAccessibleAlways*`: find the `SecItemAdd` or `SecItemUpdate` call that uses the constant and the `kSecAttrService`/`kSecAttrAccount` strings near it.

6. **Optionally confirm at runtime** on the oldest supported iOS version:

   ```bash
   frida-trace -U -f com.example.app -i 'SecTrustEvaluate' -i 'CC_MD5' -i 'SecKeyRawSign' \
     -m '+[NSKeyedUnarchiver unarchiveObjectWithData:]'
   ```

   Exercise login, network calls and any feature that stores or restores data. A trace line shows that the deprecated path executes on that OS version.

#### Observation

Per Mach-O: the deprecated symbols and selectors found, the calling functions (from `axt`), the version guard and whether it is live given `minos`, and the security-relevant detail (padding constant, how the trust result is read, keychain item identity). Include `MinimumOSVersion`, `minos` and `sdk`.

#### Evaluation

The test **fails** if live code uses an API from the iOS catalogue in a security-relevant way: `UIWebView` anywhere in the bundle (also a store-rejection risk); `SecTrustEvaluate` whose result is judged only by its `OSStatus`; `SecKeyRawSign`/`SecKeyEncrypt` with `kSecPaddingNone` or on unhashed data; `kSecAttrAccessibleAlways*` for credentials, tokens or keys; `unarchiveObjectWithData:` on data that can come from outside the app; `CC_MD5` in an integrity, signature, key-derivation or password context; Secure Transport configured below TLS 1.2. Each failure is then rated in the note listed in the catalogue.

The test **passes** if no catalogue symbol or selector is present, if every use is in a branch that cannot run given `minos`, or if the use is security-neutral (for example `CC_MD5` used as a cache key, which you should still note as Info, recommending CryptoKit's `Insecure.MD5` to make the intent explicit).

#### Demo

A token cache written years ago and still shipped:

```swift
let add: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: "com.example.app.session",
    kSecAttrAccessible as String: kSecAttrAccessibleAlways,   // deprecated in iOS 12
    kSecValueData as String: refreshToken
]
SecItemAdd(add as CFDictionary, nil)
```

With a deployment target of iOS 15 the build shows a deprecation warning, which the team had silenced (see GT-CODE-0046-3). Step 3 output:

```text
MyApp: _kSecAttrAccessibleAlways
```

`axt` leads to `SessionStore.save(_:)`, which stores the refresh token. The refresh token is readable from the keychain while the device is locked and migrates with encrypted backups. The test fails; severity is set in [MASWE-0001](/mobile/maswe-0001-sensitive-data-unencrypted-private-storage/) (typically Medium for a refresh token, since exploitation needs physical access to a locked device or access to an encrypted backup and its password). The fix is `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` if background refresh needs the token, otherwise `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, plus a one-time migration of existing items with `SecItemUpdate`.

### GT-CODE-0046-3: Suppressed deprecation warnings in source and build configuration (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

Platform: Android and iOS. Type: manual source and build-configuration review, plus a build. Tools: ripgrep, Gradle, Android lint, Xcode (`xcodebuild`).

#### Overview

GT-CODE-0046-1 and -2 find what is in the binary. This test finds out *why* it is there: whether the toolchain was told to stop reporting deprecations, either for one call (an annotation or pragma) or for the whole project (a compiler flag, a lint configuration, a CocoaPods directive). A suppression on a security-relevant API is the strongest evidence that the issue was known and accepted without a plan. A global suppression means nobody will see the next one either. Annotations and pragmas do not survive compilation, so this test needs the source.

#### Prerequisites

- Read access to the app's source repository, including Gradle files, `lint.xml`, lint baselines, `.xcodeproj`/`.xcworkspace`, `.xcconfig` files and the `Podfile`.
- Ideally the ability to build the release variant or scheme locally.

#### Steps

1. **Find per-call suppressions (Android).**

   ```bash
   rg -n --glob '*.{java,kt,kts}' \
     -e '@SuppressWarnings\(\s*(\{[^)]*)?"deprecation"' \
     -e '@Suppress\([^)]*"DEPRECATION"' \
     -e '@file:Suppress\([^)]*"DEPRECATION"' \
     -e '@SuppressLint\([^)]*"(DeprecatedProvider|WorldReadableFiles|WorldWriteableFiles|TrustAllX509TrustManager|BadHostnameVerifier|SSLCertificateSocketFactoryGetInsecure|GetInstance)"'
   rg -n --glob '*.xml' 'tools:ignore="[^"]*(Deprecated|WorldReadable|Insecure)'
   ```

   For each hit, read the suppressed call. A suppression on a catalogue API is a candidate finding; a suppression on `Handler()` or `onBackPressed()` is not.

2. **Find project-wide suppressions (Android).**

   ```bash
   rg -n --glob '*.gradle*' -e 'Xlint:-deprecation' -e '-nowarn' -e 'suppressWarnings' \
     -e 'allWarningsAsErrors' -e 'warningsAsErrors' -e 'abortOnError' -e 'checkReleaseBuilds' \
     -e 'baseline' -e 'disable\s*(\+=|\.add)'
   find . -name lint.xml -exec grep -Hn 'severity="ignore"' {} +
   rg -n 'id="(DeprecatedProvider|WorldReadableFiles|WorldWriteableFiles|TrustAllX509TrustManager|BadHostnameVerifier|GetInstance|DeprecatedSinceApi)"' --glob 'lint-baseline*.xml'
   ```

   `kotlinOptions { suppressWarnings = true }` (or `compilerOptions { suppressWarnings.set(true) }`) silences every Kotlin warning, deprecations included. A lint baseline (`lint { baseline = file("lint-baseline.xml") }`) hides every issue that existed when it was created; security checks listed in it are effectively disabled. `abortOnError = false` or `checkReleaseBuilds = false` stops lint from blocking the release.

3. **Find per-call and project-wide suppressions (iOS).**

   ```bash
   rg -n -e 'clang diagnostic ignored "-Wdeprecated' -e 'clang diagnostic ignored "-Wdeprecated-declarations"' --glob '*.{m,mm,h,c,cpp}'
   rg -n -e 'GCC_WARN_ABOUT_DEPRECATED_FUNCTIONS\s*=\s*NO' -e 'Wno-deprecated' \
     -e 'SWIFT_SUPPRESS_WARNINGS\s*=\s*YES' -e 'GCC_WARN_INHIBIT_ALL_WARNINGS\s*=\s*YES' \
     -e 'suppress-warnings' --glob '*.{pbxproj,xcconfig}'
   rg -n 'inhibit_all_warnings!|:inhibit_warnings\s*=>\s*true' Podfile
   ```

   Swift has no per-line pragma. The usual workaround is to mark the *calling* function `@available(*, deprecated)`, which makes the compiler stop warning about deprecated calls inside it; search for it with `rg -n '@available\(\*,\s*deprecated' --glob '*.swift'` and read each annotated function. Swift 6.1 also added per-group warning controls (SE-0443, the `-Werror <group>` and `-Wwarning <group>` flags); read `OTHER_SWIFT_FLAGS` for any group settings that affect deprecations.

4. **Build and collect the warnings.** The suppressions show you what was hidden; the build shows you what is still visible but ignored.

   ```bash
   # Android: per-call deprecation warnings from javac and kotlinc, then lint
   ./gradlew :app:compileReleaseJavaWithJavac :app:compileReleaseKotlin --warning-mode all 2>&1 | grep -iE 'deprecat'
   ./gradlew :app:lintRelease
   ```

   ```text
   warning: [deprecation] getParcelableExtra(String) in Intent has been deprecated
   w: file:///src/app/src/main/java/com/example/app/auth/Unlocker.kt:41:22 'FingerprintManager' is deprecated. Deprecated in Java.
   ```

   For Java, the per-call lines only appear with `-Xlint:deprecation` in `options.compilerArgs`; without it you get the summary note only, which is itself worth recording. Lint writes its reports under `app/build/reports/`.

   ```bash
   # iOS
   xcodebuild -workspace App.xcworkspace -scheme App -configuration Release \
     -destination 'generic/platform=iOS' CODE_SIGNING_ALLOWED=NO build 2>&1 | grep -E 'deprecated'
   ```

   ```text
   SessionStore.swift:18:38: warning: 'kSecAttrAccessibleAlways' was deprecated in iOS 12.0: Use an accessibility level that provides some user protection, such as kSecAttrAccessibleAfterFirstUnlock
   Pinning.m:52:9: warning: 'SecTrustEvaluate' is deprecated: first deprecated in iOS 13.0 [-Wdeprecated-declarations]
   ```

   Remember the deployment-target rule: if the target is below the deprecation version, there is no warning to suppress. Temporarily raising `IPHONEOS_DEPLOYMENT_TARGET` on a local build (`xcodebuild ... IPHONEOS_DEPLOYMENT_TARGET=17.0`) reveals the hidden ones; do this only on your own copy.

5. **Map each suppression and each warning to the catalogue**, and ask the team for the tracking ticket or justification for any security-relevant one.

#### Observation

Lists of per-call suppressions (file, line, API), project-wide suppressions (file, setting), lint baseline entries for security checks, and the deprecation warnings from the build, each marked security-relevant or not.

#### Evaluation

The test **fails** if:

- a catalogue API is used under a per-call suppression with no documented justification and migration plan; or
- deprecation warnings are suppressed project-wide (`suppressWarnings`, `-Xlint:-deprecation`, `GCC_WARN_ABOUT_DEPRECATED_FUNCTIONS = NO`, `SWIFT_SUPPRESS_WARNINGS = YES`, `inhibit_all_warnings!` on security-relevant pods), or security lint checks are disabled or baselined, in a way that would hide a catalogue API.

It **passes** if suppressions are limited to non-security APIs, or each security-relevant suppression has a reason and a tracked migration, and the release build reports deprecations. On its own, a failure here is a process finding (Low or Info); it raises the confidence and priority of the matching GT-CODE-0046-1/-2 finding.

#### Demo

```java
@SuppressWarnings("deprecation")
static SSLSocket open(String host, int port) throws IOException {
    SSLCertificateSocketFactory f =
        (SSLCertificateSocketFactory) SSLCertificateSocketFactory.getInsecure(0, null);
    return (SSLSocket) f.createSocket(host, port);        // no certificate or hostname checks
}
```

with, in `app/build.gradle.kts`:

```kotlin
android {
    lint { baseline = file("lint-baseline.xml") }     // contains SSLCertificateSocketFactoryGetInsecure
}
```

Step 1 finds the annotation, step 2 finds the baselined lint ID. The test fails, and the underlying issue (no certificate validation) is a [MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/) finding, typically High or Critical depending on the data on that connection.

## Best practices

OWASP links no best practices to MASWE-0046 directly. The three below belong to other weaknesses but are good illustrations of "use the maintained replacement", so we summarise them here and link to where they are tested.

### MASTG-BEST-0020: Update the GMS Security Provider

Source: [MASTG-BEST-0020](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0020/). Platform: Android. Knowledge: MASTG-KNOW-0011 (security provider). Tested by MASTG-TEST-0295 (in our [MASWE-0027 note](/mobile/maswe-0027-insecure-certificate-validation/)) and referenced by MASTG-TEST-0312 (in our [MASWE-0007 note](/mobile/maswe-0007-improper-encryption/)).

This is the positive counterpart to the deprecated-provider problem. Android devices update slowly and unevenly, so the platform's own TLS and crypto implementation can lag behind known fixes. Google Play services ships its own copy of the platform security provider (Conscrypt, backed by BoringSSL) and updates it independently of the OS. The app asks for that update with `ProviderInstaller` early at start-up, before its first TLS connection:

```kotlin
class App : Application() {
    override fun onCreate() {
        super.onCreate()
        ProviderInstaller.installIfNeededAsync(this, object : ProviderInstaller.ProviderInstallListener {
            override fun onProviderInstalled() { /* safe to start networking */ }
            override fun onProviderInstallFailed(errorCode: Int, recoveryIntent: Intent?) {
                // Play services missing or outdated: offer GoogleApiAvailability's resolution,
                // and decide deliberately whether sensitive connections may proceed
            }
        })
    }
}
```

`installIfNeeded(context)` is the blocking variant (call it off the main thread); it throws `GooglePlayServicesRepairableException` or `GooglePlayServicesNotAvailableException` when it cannot update. After a successful install, `Security.getProviders()[0].name` is `GmsCore_OpenSSL`. On devices without Google Play services (some Huawei and Amazon devices, AOSP builds), OWASP recommends bundling [Conscrypt](https://github.com/google/conscrypt) (`org.conscrypt:conscrypt-android`) and inserting it with `Security.insertProviderAt(Conscrypt.newProvider(), 1)`. Two things link this back to MASWE-0046: the app should rely on the *default* provider (which this practice keeps current) rather than naming an old one, and the bundled-Conscrypt fallback is a vetted, maintained library, not the kind of non-standard component [MASWE-0047](/mobile/maswe-0047-non-standard-security-apis/) warns about.

### MASTG-BEST-0032: Migrate from UIWebView to WKWebView

Source: [MASTG-BEST-0032](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0032/). Platform: iOS. Knowledge: MASTG-KNOW-0076 (iOS WebViews). Tested by MASTG-TEST-0331 (in our [MASWE-0035 note](/mobile/maswe-0035-webviews-loading-untrusted-content/)).

`UIWebView` was deprecated in iOS 12. `WKWebView` renders web content in a separate WebContent process, so a memory-corruption bug triggered by a page does not run inside the app's own process; JavaScript can be disabled per navigation (`WKWebpagePreferences.allowsContentJavaScript`, iOS 14); and native bridges are explicit (`WKScriptMessageHandler`) rather than inferred from URL schemes. Migration is mostly mechanical, but the delegate model differs (`WKNavigationDelegate` instead of `UIWebViewDelegate`), and the security decisions the old delegate made (which URLs to load, which schemes to intercept) must be re-implemented, not dropped. Since 2020 the App Store has refused submissions that contain `UIWebView`, so in store builds you will usually find it only in old enterprise apps or in a bundled SDK that the team never rebuilt; GT-CODE-0046-2 step 3 tells you which binary it is in.

### MASTG-BEST-0006: Use Up-to-Date APK Signing Schemes

Source: [MASTG-BEST-0006](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0006/). Platform: Android. Knowledge: MASTG-KNOW-0003 (app signing; see our [App Signing note](/mobile/mastg-know-0003-app-signing/)). Tested by MASTG-TEST-0224 (MASWE-0056, MASVS-RESILIENCE).

The v1 (JAR) scheme verifies individual ZIP entries and leaves parts of the file unprotected; it was the root of the Janus vulnerability (CVE-2017-13156) on Android 5.0 to 8.0. The v2 scheme (Android 7.0) signs the whole APK, v3 (Android 9) adds key rotation, and v4 (Android 11) is a separate signature file for incremental installation that must accompany v2 or v3. Apps targeting Android 11 must be signed with v2 or higher. Keep v1 only if `minSdkVersion` is below 24. With the Android Gradle plugin:

```kotlin
android {
    signingConfigs {
        create("release") {
            // storeFile, storePassword, keyAlias, keyPassword from a secure source
            enableV1Signing = false        // only if minSdk >= 24
            enableV2Signing = true
            enableV3Signing = true
            enableV4Signing = true         // optional
        }
    }
}
```

Apps distributed through Google Play with Play App Signing are re-signed by Google, so check the APK that users receive (download it from a test device) rather than the upload artefact. `apksigner verify --verbose app.apk` shows which schemes verified.

### Secure implementation (Guler Tech)

**Make deprecations visible and blocking for release builds (Android).**

```kotlin
// app/build.gradle.kts
kotlin {
    compilerOptions { allWarningsAsErrors.set(true) }          // or narrower: fail CI on new warnings
}
tasks.withType<JavaCompile>().configureEach {
    options.compilerArgs.addAll(listOf("-Xlint:deprecation", "-Werror"))
}
android {
    lint {
        abortOnError = true
        checkReleaseBuilds = true
        checkDependencies = true
        error += setOf(
            "DeprecatedProvider", "DeprecatedSinceApi", "WorldReadableFiles", "WorldWriteableFiles",
            "SSLCertificateSocketFactoryGetInsecure", "TrustAllX509TrustManager", "BadHostnameVerifier",
            "GetInstance", "PlaySdkIndexDeprecated"
        )
    }
}
```

If `allWarningsAsErrors` is too disruptive for an existing codebase, keep a short, reviewed list of accepted warnings and fail on anything new. Never baseline the security lint IDs above.

**Make deprecations visible and blocking (iOS).** Leave `GCC_WARN_ABOUT_DEPRECATED_FUNCTIONS` at its default (`YES`); set `GCC_TREAT_WARNINGS_AS_ERRORS = YES` and `SWIFT_TREAT_WARNINGS_AS_ERRORS = YES` for Release, or at least in CI. Avoid `inhibit_all_warnings!` in the `Podfile`; if it must stay, exclude security-relevant pods. Periodically build with the deployment target raised to the current iOS version, so that APIs deprecated after your minimum version appear.

**Suppress narrowly and with a reason.** When a deprecated API is genuinely needed (for example for an OS version the business must still support), suppress at the smallest scope, with a comment naming the replacement, the reason, and the ticket:

```kotlin
// DEPRECATION: FingerprintManager kept for API 23-27 until minSdk 28 (ticket SEC-142). Uses CryptoObject.
@Suppress("DEPRECATION")
private fun legacyUnlock(cipher: Cipher) { /* ... */ }
```

**Use the replacements' safety properties, not just their names.**

```kotlin
// Typed extras (API 33+, with AndroidX fallback for older versions)
val target = IntentCompat.getParcelableExtra(intent, "target", Uri::class.java)

// Keys with explicit restrictions instead of KeyPairGeneratorSpec
val spec = KeyGenParameterSpec.Builder("sig", KeyProperties.PURPOSE_SIGN)
    .setDigests(KeyProperties.DIGEST_SHA256)
    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
    .setUserAuthenticationRequired(true)
    .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
    .build()
```

```swift
// Secure decoding instead of unarchiveObject(with:)
let profile = try NSKeyedUnarchiver.unarchivedObject(ofClass: Profile.self, from: data)

// Trust evaluation with a Boolean verdict instead of SecTrustEvaluate
var error: CFError?
guard SecTrustEvaluateWithError(serverTrust, &error) else { return reject(error) }

// Signatures with an explicit algorithm instead of SecKeyRawSign
let sig = SecKeyCreateSignature(privateKey, .ecdsaSignatureMessageX962SHA256, message as CFData, &error)
```

**Fail closed when a service is gone.** Integrity checks (Play Integrity, App Attest) and provider updates return errors as well as verdicts. Decide on the server what an error means for a sensitive action, and never map "no verdict" to "trusted".

**Keep an inventory.** Run GT-CODE-0046-1/-2 (or the semgrep rules) in CI against release builds, so that a deprecated API arriving through an SDK update is noticed the day it arrives.

## Rating findings

Rate the *underlying* security property, using the note in the catalogue's "Covered in" column; this note's job is to find the use and decide whether it is live. Three questions set the level: **what the deprecated API protects or decides** (credentials and keys, other sensitive data, an integrity or authentication decision, nothing), **who can exploit the old behaviour** (any app on the device, a network attacker, someone with the unlocked or locked device, someone with a backup, only a compromised device), and **on which devices the path is live** (all supported versions, only old ones within `minSdkVersion`/`minos`, none).

| Rating | Conditions |
|---|---|
| **Critical** | Rare for this weakness alone. A deprecated API whose old behaviour still applies on supported devices exposes authentication material or keys without user interaction to any app or network attacker: for example, world-readable files holding tokens in an app that still targets API 23 or lower, or a deprecated TLS API configured so that certificate validation is skipped for the authentication endpoint (rated under MASWE-0027). |
| **High** | A security decision rests on a deprecated mechanism that no longer works or is trivially bypassed on supported devices: SafetyNet attestation that fails open; biometric unlock of secrets through `FingerprintManager` or a device-credential intent without a key bound to authentication; app secrets kept in a BKS/PKCS#12 file whose password is in the app; `SecTrustEvaluate` result misread for sensitive hosts; `unarchiveObjectWithData:` on data an attacker can supply; `UIWebView` rendering remote content with a native bridge. |
| **Medium** | The deprecated API weakens protection of sensitive data but exploitation needs a stronger position: `kSecAttrAccessibleAlways*` for tokens (locked device or encrypted backup); `CC_MD5` or raw RSA with weak padding in an integrity or signature context that is not directly exposed; keys from `KeyPairGeneratorSpec` without use restrictions; v1-only signing on an app that supports Android 7.0 to 8.0; any High condition that is live only on old OS versions still within the supported range. |
| **Low** | A security-relevant deprecated API used correctly or with limited impact: `getParcelableExtra(String)` with type checks; `LocalBroadcastManager`; `setUserAuthenticationValidityDurationSeconds` with correct semantics; `SecTrustCopyPublicKey` in otherwise correct pinning; security-relevant deprecation warnings suppressed project-wide (GT-CODE-0046-3) without a matching live finding. |
| **Info** | `EncryptedSharedPreferences`/`security-crypto` in use (plan a migration); deprecated calls in branches that are dead given the minimum OS version; `NSURLConnection` without custom trust handling; `setSavePassword`; non-security deprecations; per-call suppressions with a documented reason and ticket. |

Raise one level when the deprecated path runs automatically (start-up, background refresh) or affects every user; when the hit is in an SDK the client cannot change quickly and that SDK handles credentials; or when GT-CODE-0046-3 shows the issue was suppressed rather than tracked. Lower one level when the live range is a small and shrinking share of the client's install base *and* the client has a dated plan to raise the minimum version. In the report, give the API, the code location (class and method from jadx, or function from radare2), the binary or SDK, the version guard and the minimum and target versions, the evidence (smali line, symbol list, build warning, Frida trace), the replacement, and the note where the underlying property is rated.

## References

- OWASP MASWE: [MASWE-0046: Use of Deprecated APIs or Functionality](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0046/); related [MASWE-0041](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0041/), [MASWE-0042](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0042/), [MASWE-0044](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0044/), [MASWE-0047](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0047/), [MASWE-0050](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0050/), [MASWE-0015](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0015/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-CODE-3](https://mas.owasp.org/MASVS/controls/MASVS-CODE-3/), [MASVS-CRYPTO-2](https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-2/) (CC BY-SA 4.0)
- OWASP MASTG best practices: [MASTG-BEST-0020](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0020/), [MASTG-BEST-0032](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0032/), [MASTG-BEST-0006](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0006/), [MASTG-BEST-0050](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0050/) (CC BY-SA 4.0)
- OWASP MASTG tests referenced: [MASTG-TEST-0312](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0312/), [MASTG-TEST-0295](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0295/), [MASTG-TEST-0331](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0331/), [MASTG-TEST-0224](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0224/) (CC BY-SA 4.0)
- OWASP MASTG knowledge: [MASTG-KNOW-0011](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0011/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0082](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0082/) (CC BY-SA 4.0)
- OWASP MASTG tools: [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [Apktool (MASTG-TOOL-0011)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/), [apksigner (MASTG-TOOL-0123)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0123/), [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/), [Frida (MASTG-TOOL-0031)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/), [otool (MASTG-TOOL-0060)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0060/), [rabin2 (MASTG-TOOL-0129)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/), [radare2 for iOS (MASTG-TOOL-0073)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/) (CC BY-SA 4.0)
- Android Developers: [Android 12 behaviour changes: Bouncy Castle](https://developer.android.com/about/versions/12/behavior-changes-all#bouncy-castle), [Android 11 behaviour changes (APK Signature Scheme v2 required)](https://developer.android.com/about/versions/11/behavior-changes-11), [`java.security.KeyStore`](https://developer.android.com/reference/java/security/KeyStore), [`<application>` element (`usesCleartextTraffic`)](https://developer.android.com/guide/topics/manifest/application-element), [Restrictions on non-SDK interfaces](https://developer.android.com/guide/app-compatibility/restrictions-non-sdk-interfaces), [Jetpack Security release notes](https://developer.android.com/jetpack/androidx/releases/security), [Cryptography (Jetpack Security deprecation)](https://developer.android.com/privacy-and-security/cryptography), [Update your security provider](https://developer.android.com/privacy-and-security/security-gms-provider), [SafetyNet Attestation API deprecation](https://developer.android.com/privacy-and-security/safetynet/deprecation-timeline), [Play Integrity API](https://developer.android.com/google/play/integrity/overview), [Migrate from legacy Google Sign-In to Credential Manager and AuthorizationClient](https://developer.android.com/identity/sign-in/legacy-gsi-migration), [Android lint check index](https://googlesamples.github.io/android-custom-lint-rules/checks/index.md.html)
- Apple Developer: [`SecTrustEvaluateWithError`](https://developer.apple.com/documentation/security/sectrustevaluatewitherror%28_:_:%29), [`SecKeyRawSign`](https://developer.apple.com/documentation/security/seckeyrawsign%28_:_:_:_:_:_:%29), [`SecKeyEncrypt`](https://developer.apple.com/documentation/security/seckeyencrypt%28_:_:_:_:_:_:%29), [`SecTrustCopyPublicKey`](https://developer.apple.com/documentation/security/sectrustcopypublickey%28_:%29), [`SecTrustGetCertificateAtIndex`](https://developer.apple.com/documentation/security/sectrustgetcertificateatindex%28_:_:%29), [`kSecAttrAccessibleAlways`](https://developer.apple.com/documentation/security/ksecattraccessiblealways), [`LAContext.evaluatedPolicyDomainState`](https://developer.apple.com/documentation/localauthentication/lacontext/evaluatedpolicydomainstate), [`tls_protocol_version_t`](https://developer.apple.com/documentation/security/tls_protocol_version_t), [`UIWebView`](https://developer.apple.com/documentation/uikit/uiwebview), [`WKWebView`](https://developer.apple.com/documentation/webkit/wkwebview), [`NSKeyedUnarchiver`](https://developer.apple.com/documentation/foundation/nskeyedunarchiver)
- WithSecure Labs: [How secure is your Android Keystore authentication?](https://labs.withsecure.com/publications/how-secure-is-your-android-keystore-authentication)
- CWE: [CWE-327](https://cwe.mitre.org/data/definitions/327.html), [CWE-477](https://cwe.mitre.org/data/definitions/477.html), [CWE-522](https://cwe.mitre.org/data/definitions/522.html); [CVE-2017-13156 (Janus)](https://nvd.nist.gov/vuln/detail/CVE-2017-13156)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
