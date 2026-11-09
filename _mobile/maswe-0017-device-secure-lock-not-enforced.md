---
title: "Device Secure Lock Not Enforced (MASWE-0017)"
date: 2026-11-09 12:19:00 +0000
subcategory: crypto
summary: "Why app crypto on a phone with no passcode protects little, how to detect the secure lock screen on Android and iOS, and how to test and rate MASWE-0017."
refs: [MASWE-0017, MASVS-CRYPTO-2, CWE-306, CWE-693]
tags: [android, ios, masvs-crypto, screen-lock, local-authentication, data-protection]
---

This note is part of our [MASVS-CRYPTO guide](/mobile/masvs-crypto-cryptography-guide/) and covers OWASP [MASWE-0017](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0017/): an app that turns on sensitive functionality without checking that the device has a secure lock screen. It is the last weakness in the CRYPTO series, and in some ways it underpins the rest. Keystore keys bound to user authentication, Android credential-encrypted storage, iOS Data Protection classes and passcode-gated Keychain items all assume that the device owner has set a PIN, pattern, password or passcode. Remove that and the strongest key configuration in [MASWE-0016](/mobile/maswe-0016-key-access-not-restricted/) either cannot be created or protects nothing. Below you will find what the lock screen actually contributes to cryptography on each platform, the detection APIs and their pitfalls, the iOS Local Authentication framework in depth, the four OWASP tests with their demos, our supplementary checks for the "stale assumption" and "check without consequence" cases, working Kotlin and Swift, guidance on how an app should respond, and severity guidance.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: Biometric Authentication (MASTG-KNOW-0001)](#android-biometric-authentication-mastg-know-0001)
  - [Android: The secure lock screen as a key-management dependency](#android-the-secure-lock-screen-as-a-key-management-dependency)
  - [Android: APIs for detecting the secure lock screen](#android-apis-for-detecting-the-secure-lock-screen)
  - [iOS: Local Authentication Framework (MASTG-KNOW-0056)](#ios-local-authentication-framework-mastg-know-0056)
  - [iOS: Data Protection, the Keychain and the passcode](#ios-data-protection-the-keychain-and-the-passcode)
- [Tests](#tests)
  - [MASTG-TEST-0247 (Android, static)](#mastg-test-0247-references-to-apis-for-detecting-secure-screen-lock-android)
  - [MASTG-TEST-0249 (Android, dynamic)](#mastg-test-0249-runtime-use-of-secure-screen-lock-detection-apis-android)
  - [MASTG-TEST-0248 (iOS, static)](#mastg-test-0248-references-to-apis-for-detecting-secure-screen-lock-ios)
  - [MASTG-TEST-0246 (iOS, dynamic)](#mastg-test-0246-runtime-use-of-secure-screen-lock-detection-apis-ios)
  - [Supplementary checks (Guler Tech methodology)](#supplementary-checks-guler-tech-methodology)
- [Secure implementation](#secure-implementation)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

The MAS requirement is short: *the app verifies that the device has a secure lock configured.* "Secure lock" means a knowledge factor the OS enforces before it unlocks — a PIN, pattern or password on Android, a passcode on iOS. Biometrics count only because neither platform lets a user enrol a fingerprint or face without first setting one of those; "Swipe" and "None" on Android, and "Turn Passcode Off" on iOS, are not secure locks.

Why does a weakness about the lock screen sit under MASVS-CRYPTO-2 (key management) rather than authentication? Because on both platforms the device credential is a **key-management input**. It is mixed into the keys that protect app files, it is the precondition for keys that require user authentication, and it is what turns "the phone is locked" into a cryptographic state rather than a UI state:

| Protection | With a secure lock | Without one |
|---|---|---|
| Android credential-encrypted (CE) storage | Keys derived using the user's credential; locked until the user unlocks after boot | Unlocked automatically at boot; still bound to the device's hardware, but no user secret is involved |
| Android Keystore keys with `setUserAuthenticationRequired(true)` | Usable only after the user authenticates | Cannot be created; existing ones are permanently invalidated when the lock is removed |
| Android Keystore keys with `setUnlockedDeviceRequired(true)` | Unusable while the device is locked | The device is never in a secure locked state, so the restriction has nothing to enforce |
| iOS Data Protection (`NSFileProtectionComplete` and the other classes) | Class keys wrapped with a key derived from the passcode and the device UID | Class keys protected only by the hardware UID: available whenever the device is on |
| iOS Keychain `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` | Item available while unlocked | Item cannot be created; existing items are deleted when the passcode is removed |
| iOS Keychain items with `.userPresence` / `.biometry*` access control | Read requires Face ID, Touch ID or the passcode | No passcode means no biometric enrolment, so the item cannot be protected this way |

An app cannot set or force a device lock. What it can do is *detect* the state, *refuse or degrade* when the lock is missing, and *bind* its keys to platform authentication so that the OS itself refuses to cooperate without one. MASWE-0017 is the failure to do those things.

**Profiles: L2 and EUDIW.** OWASP tags every MASWE entry with the [MAS profiles](https://mas.owasp.org/Profiles/) it applies to. **L1** is the baseline every app should meet. **L2** is defence-in-depth for apps that handle sensitive data or functionality — banking and payments, health, government services, enterprise apps with access to corporate data. **R** (resilience) and **P** (privacy) cover anti-tampering and privacy controls. **EUDIW** groups the weaknesses relevant to European Digital Identity Wallet apps under the revised eIDAS Regulation (Regulation (EU) 2024/1183), where a wallet holds person identification data and attestations that relying parties trust. MASWE-0017 is tagged `[L2, EUDIW]` and **not** L1: a weather or recipe app is not expected to refuse to run on an unlocked phone, but a banking app, a wallet or anything that holds high-value credentials is. In practice that means you raise this weakness when the app's own risk profile justifies it, and you rate it accordingly (see [Rating findings](#rating-findings)).

**Mappings and history.** The weakness maps to MASVS v1 `MSTG-STORAGE-11` ("The app enforces a minimum device-access-security policy, such as requiring the user to set a device passcode"), which was itself an L2 requirement tested by the legacy (MASTG v1) test [MASTG-TEST-0012 "Testing the Device-Access-Security Policy"](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0012/), now marked deprecated and covered by MASTG-TEST-0247 and MASTG-TEST-0249. In MASVS v2 it maps to MASVS-CRYPTO-2. OWASP links it to threat MAS-THREAT-0017 (attackers with physical access read the app's data and use its keys when no device credential protects them) and attack MAS-ATTACK-0063 (accessing a lost or stolen device that has no secure lock screen). MASWE does not assign a CWE; we use CWE-306 (Missing Authentication for Critical Function) and CWE-693 (Protection Mechanism Failure) as the closest fits.

You will notice that the four OWASP tests live in `MASVS-RESILIENCE` folders, not `MASVS-CRYPTO`. They were written when lock-screen detection was grouped with other environment checks such as root and jailbreak detection, and the weakness was later placed in CRYPTO-2 because of the key-management dependency described above. The test URLs therefore contain `MASVS-RESILIENCE`; the content applies here.

**What this weakness is not.** It is not about an app-level PIN (that is authentication, MASVS-AUTH), and it is not about root or jailbreak detection. An app-level PIN does not substitute for a device lock: it does not feed Data Protection or CE storage, and unless the app derives keys from it, it is a UI gate in front of data the OS considers unprotected.

## Modes of Introduction

**No secure-lock check.** The app enrols a user, stores tokens, provisions keys or enables payments without ever calling [`KeyguardManager.isDeviceSecure()`](https://developer.android.com/reference/android/app/KeyguardManager#isDeviceSecure()) on Android or [`LAContext.canEvaluatePolicy(_:error:)`](https://developer.apple.com/documentation/localauthentication/lacontext/canevaluatepolicy%28_:error:%29) on iOS, and without any key or Keychain configuration that would fail in the absence of a lock. This is the default state of most apps.

**Data protection not tied to the passcode.** On iOS, sensitive items are stored with accessibility classes that do not depend on a passcode (`kSecAttrAccessibleWhenUnlocked`, `kSecAttrAccessibleAfterFirstUnlock` and their `ThisDeviceOnly` variants), so the data stays available on a device with no passcode. On Android the equivalent is keys generated without `setUserAuthenticationRequired(true)` for data whose design says "only the user can open this".

**Stale device-lock assumption.** The app checks the lock once — at onboarding, at biometric enrolment, when the user turns on "quick login" — and never again. The user later removes the PIN; the app carries on because a flag in `SharedPreferences` or `UserDefaults` still says "secure". On Android the auth-bound key is now dead and the app's error handling decides what happens next; on iOS `WhenPasscodeSet` items have been silently deleted.

Patterns we see repeatedly that OWASP does not list separately:

- **Proxy checks.** The app asks a related but different question: `canAuthenticate(BIOMETRIC_STRONG)` or `.deviceOwnerAuthenticationWithBiometrics` (fails on locked-but-no-biometric devices, so users get blocked or the check gets removed), `isKeyguardSecure()` (also true while a SIM PIN is pending), `isDeviceLocked()` (is it locked *now*, not is it *protected*), or the long-deprecated `Settings.Secure.LOCK_PATTERN_ENABLED`, which only ever covered patterns.
- **Check without consequence.** The API is called — often by a fraud, analytics or RASP SDK — and the result is logged or sent to a server, but nothing in the app changes. This passes a reference-only test and fails the weakness.
- **Silent downgrade.** Key generation with `setUserAuthenticationRequired(true)` throws, or `SecItemAdd` with `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` fails, and the `catch` block retries without the restriction "so the feature still works". The app now stores the same secret with no user binding, and nobody is told.

## Impact

- **Compromise of sensitive data.** Anyone holding a lost or stolen device with no lock opens the app and reads what it shows, and anyone with a forensic tool reads what it stores, because the OS-level encryption that was supposed to need the user's secret does not.
- **Authentication or authorisation bypass.** Long-lived sessions, refresh tokens and device-bound keys let the holder act as the victim: approve payments, present identity attributes, read messages, change account settings.
- **Undermining of other controls.** Biometric login, auth-bound keys, "unlocked device required" keys and passcode-gated Keychain items cannot be configured, so an app that does not check either fails at runtime or (worse) quietly falls back to unprotected storage.
- **Non-repudiation and regulatory exposure.** If a signature or approval can come from anyone holding the phone, the app cannot argue that the user made it. For payment and identity apps that is a compliance problem as well as a security one (see [UX and regulatory considerations](#ux-and-regulatory-considerations)).

## Mitigations

- **Verify the device lock state** with the platform API: `KeyguardManager.isDeviceSecure()` (API 23+) or `BiometricManager.canAuthenticate(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)` on Android; `LAContext.canEvaluatePolicy(.deviceOwnerAuthentication, error:)` on iOS, inspecting the error for `LAError.passcodeNotSet`.
- **Re-check before enabling protected functionality**, not just at onboarding: on every return to the foreground, before showing sensitive data, and before each high-risk operation (payment approval, credential presentation, key export, settings changes).
- **Bind sensitive key use to platform authentication** so the OS enforces the dependency: Android Keystore keys with `setUserAuthenticationRequired(true)` and `setUserAuthenticationParameters(...)`, used through `BiometricPrompt` with a `CryptoObject`; iOS Keychain items with `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` and a `SecAccessControl` such as `.userPresence` or `.biometryCurrentSet`. A device with no lock then cannot hold the key at all, which is the strongest possible enforcement.
- **Handle loss of the lock deliberately.** Catch `KeyPermanentlyInvalidatedException` on Android and `errSecItemNotFound` for items that used to exist on iOS; treat both as "re-enrol", wipe the data the key protected, and never retry with a weaker configuration.
- **Choose and document a response policy** — warn, degrade or refuse — that matches the app's profile (see [Choosing a response](#choosing-a-response-warn-degrade-or-refuse)), and guide the user to the system settings to fix it.
- **Give the server a signal it can trust** where it matters. On Android, a key attestation record states whether the attested key requires user authentication (`noAuthRequired`, `userAuthType`, `authTimeout`) and whether it is `unlockedDeviceRequired`; an auth-bound key cannot exist on a device without a lock, so a backend that checks those fields knows the lock existed when the key was created. iOS App Attest has no equivalent field, so there the backend has to rely on the app's own check and on keys that only work with user presence.

## Knowledge

OWASP links two Knowledge pages to this weakness, both from MASVS-AUTH: Android biometric authentication (MASTG-KNOW-0001) and the iOS Local Authentication framework (MASTG-KNOW-0056). Neither page says much about the lock screen itself, so we add three **supplementary** sections that explain the platform mechanisms the tests rely on. Keystore and Keychain fundamentals are in [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/) and key-access restrictions in [MASWE-0016](/mobile/maswe-0016-key-access-not-restricted/); we do not repeat them here.

### Android: Biometric Authentication (MASTG-KNOW-0001)

Source: [MASTG-KNOW-0001](https://mas.owasp.org/MASTG/knowledge/android/MASVS-AUTH/MASTG-KNOW-0001/). We cover this page in full in our note [Android Biometric Authentication (MASTG-KNOW-0001)](/mobile/mastg-know-0001-biometric-authentication/), including the event-bound versus crypto-bound distinction and the Frida bypass. What matters for MASWE-0017:

- **Biometrics require a secure lock.** Android will not let a user enrol a fingerprint or face until a PIN, pattern or password exists, and if none is configured the enrolment flow makes the user create one. A device with a usable biometric therefore always has a secure lock; the reverse is not true.
- **`BiometricManager.canAuthenticate(int)`** answers "can this combination of authenticators be used right now?". The constants are `BIOMETRIC_STRONG` (Class 3, value `0x000F`), `BIOMETRIC_WEAK` (Class 2, value `0x00FF`, which includes the strong bits) and `DEVICE_CREDENTIAL` (value `0x8000`). Because `DEVICE_CREDENTIAL` *is* the lock screen, `canAuthenticate(DEVICE_CREDENTIAL)` and `canAuthenticate(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)` are lock-screen checks; `canAuthenticate(BIOMETRIC_STRONG)` on its own is not (it also fails on a locked device where the user simply has not enrolled a fingerprint). The platform method needs API 30 and the `USE_BIOMETRIC` permission; the `androidx.biometric` version works back to API 23 but not every authenticator combination is supported before API 30, so handle `BIOMETRIC_ERROR_UNSUPPORTED`.
- **Keystore-backed authentication** is the reason a lock matters for crypto. A key generated with `setUserAuthenticationRequired(true)` can only be used after the user authenticates — per operation through `BiometricPrompt.CryptoObject` when the timeout passed to `setUserAuthenticationParameters(timeout, type)` (API 30+) is `0`, or for a time window otherwise. `setUserAuthenticationValidityDurationSeconds(int)` is the deprecated pre-API-30 form. `DEVICE_CREDENTIAL` with a `CryptoObject` works from Android 11 (API 30).
- **Invalidation.** Biometric-only keys are invalidated by default when a new biometric is enrolled (`setInvalidatedByBiometricEnrollment`), and *every* auth-bound key is permanently invalidated when the secure lock screen is removed. That second rule is what makes auth-bound keys the most reliable lock-screen enforcement an app can have.

### Android: The secure lock screen as a key-management dependency

Supplementary, from the AOSP documentation on file-based encryption and the Android Keystore reference.

#### File-based encryption: CE and DE storage

Every device that launched with Android 10 or later uses file-based encryption (FBE); full-disk encryption was removed entirely in Android 13. FBE gives each user two storage areas:

- **Device-encrypted (DE) storage** (`/data/user_de/<user>/<package>/`, reached with `Context.createDeviceProtectedStorageContext()`) is available as soon as the device boots, before the user has entered anything. Apps that declare `android:directBootAware="true"` can run and read it during Direct Boot.
- **Credential-encrypted (CE) storage** (`/data/user/<user>/<package>/` — the normal app data directory, including `shared_prefs/`, `databases/` and `files/`) is available only after the user has unlocked the device for the first time since boot.

The CE keys are protected by the user's lock-screen knowledge factor (LSKF) through a **synthetic password** that is unwrapped only after Gatekeeper (or Weaver, on devices with a secure element) verifies the credential and enforces attempt throttling. That is what makes brute-forcing a seized, powered-off phone hard: the attacker has to guess the PIN on the device, at the rate the secure hardware allows.

When the user has **no** secure lock, the synthetic password is protected without any user secret and CE storage is unlocked automatically during boot. The encryption is still bound to the device's hardware — a chip-off image of the flash is still ciphertext — but anybody who powers the device on gets the same view as the owner. The CE/DE distinction collapses, and so does the "before first unlock" protection that forensic tools otherwise have to defeat.

#### Keystore keys that need a lock screen

| `KeyGenParameterSpec.Builder` method | API | Behaviour without a secure lock |
|---|---|---|
| `setUserAuthenticationRequired(true)` | 23 | Key generation fails: `KeyGenerator.init` / `generateKey` throws (typically `InvalidAlgorithmParameterException` caused by `IllegalStateException: Secure lock screen must be enabled to create keys requiring user authentication`) |
| `setUserAuthenticationParameters(timeout, type)` | 30 | Same; `type` is `AUTH_BIOMETRIC_STRONG` and/or `AUTH_DEVICE_CREDENTIAL` |
| `setUnlockedDeviceRequired(true)` | 28 | The key is created, but the device is never in a secure locked state, so the restriction never applies |
| `setInvalidatedByBiometricEnrollment(...)` | 24 | Irrelevant: no biometrics without a lock |
| `setUserConfirmationRequired(true)` | 28 | Protected Confirmation still works, but it proves a human pressed a button, not which human |

The same rules apply to `KeyProtection` when a key is imported. The practical consequence for testers: if every sensitive key in the app is auth-bound, the app *cannot* hold those keys on a device without a lock, whether or not it calls `isDeviceSecure()`. That is the outcome MASWE-0017 is after, achieved by the OS. Look for it before failing an app on the absence of a detection call.

#### What changes when the user removes the lock

When the user switches the lock screen to Swipe or None:

- Every key with `setUserAuthenticationRequired(true)` is permanently invalidated. The next `Cipher.init`, `Signature.initSign` or `Mac.init` throws `KeyPermanentlyInvalidatedException`. The key cannot be recovered; the data it encrypted is gone unless it is also held elsewhere.
- Keys without authentication binding keep working, including those with `setUnlockedDeviceRequired(true)`.
- CE storage becomes unlocked at every subsequent boot without user input.
- Apps are not notified. There is no broadcast an ordinary app can receive for "lock screen removed" (device admin receivers get `onPasswordChanged`, but device admin is not an option for consumer apps — see below). The app finds out the next time it checks, or the next time it uses an auth-bound key.

### Android: APIs for detecting the secure lock screen

Supplementary, from the Android API reference. MASTG-TEST-0247 lists `KeyguardManager` and `BiometricManager#canAuthenticate`; this is the full set you will meet.

#### KeyguardManager

| Method | API | Question it answers | Notes |
|---|---|---|---|
| `isDeviceSecure()` | 23 | Is the current user's device secured with a PIN, pattern or password? | **The right check.** Ignores SIM lock state. |
| `isKeyguardSecure()` | 16 | Is the keyguard secured by a PIN, pattern or password, *or is a SIM card currently locked*? | Not formally deprecated, but superseded by `isDeviceSecure()` for this purpose: it can report "secure" while a SIM PIN is pending on a device with no screen lock. Acceptable only in apps that still support API 16–22. |
| `isDeviceLocked()` | 22 | Is the device locked *right now* (and requires a credential to unlock)? | A different question; useful for "lock the UI when the device locks", not for policy. |
| `isKeyguardLocked()` | 16 | Is the keyguard currently showing? | True even for a Swipe lock; says nothing about security. |
| `createConfirmDeviceCredentialIntent(...)` | 21 | Prompt for the device credential | Deprecated in API 29; use `BiometricPrompt` with `DEVICE_CREDENTIAL` |

`KeyguardManager.KeyguardLock`, `newKeyguardLock()` and `exitKeyguardSecurely()` are deprecated APIs for disabling the keyguard and have nothing to do with detection; if you find them in a modern app, ask why.

OWASP's test page notes that `BiometricManager` can serve as an alternative "when KeyguardManager is unavailable or restricted by device manufacturers". We have not seen a mainstream device where `isDeviceSecure()` misreports, but the cross-check costs one call, and on API 30+ the AndroidX `BiometricManager` simply delegates to the platform service, which consults the same lock settings.

#### BiometricManager

| Call | Lock screen set, no biometric | Lock screen set, biometric enrolled | No lock screen |
|---|---|---|---|
| `canAuthenticate(DEVICE_CREDENTIAL)` | `BIOMETRIC_SUCCESS` (0) | `BIOMETRIC_SUCCESS` | `BIOMETRIC_ERROR_NONE_ENROLLED` (11) |
| `canAuthenticate(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)` | `BIOMETRIC_SUCCESS` | `BIOMETRIC_SUCCESS` | `BIOMETRIC_ERROR_NONE_ENROLLED` |
| `canAuthenticate(BIOMETRIC_STRONG)` | `BIOMETRIC_ERROR_NONE_ENROLLED` | `BIOMETRIC_SUCCESS` (if Class 3) | `BIOMETRIC_ERROR_NONE_ENROLLED` |

Other results you must handle: `BIOMETRIC_ERROR_NO_HARDWARE` (12), `BIOMETRIC_ERROR_HW_UNAVAILABLE` (1), `BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED` (15) and, in AndroidX, `BIOMETRIC_ERROR_UNSUPPORTED` (-2) and `BIOMETRIC_STATUS_UNKNOWN` (-1). The no-argument `canAuthenticate()` (API 29) is deprecated and checks only weak-or-better biometrics.

The last row is the trap. A biometric-only check never says "success" on a device without a lock, so as a security gate it is conservative, but it also says "no" to every user who has a PIN and no fingerprint. Apps that use it as their lock check tend to accumulate bug reports and then delete the check.

#### DevicePolicyManager and password complexity

The Device Administration API used to be the way to *enforce* a password policy (`setPasswordQuality`, `setPasswordMinimumLength`, `isActivePasswordSufficient`). For ordinary apps that route is closed: Android 9 deprecated the password policies for plain device admins, and apps targeting API 29+ get a `SecurityException` when they call them without being a device owner or profile owner. They remain available to Android Enterprise device policy controllers, which is where corporate passcode policy belongs. `setPasswordQuality` is deprecated from API 31 in favour of `setRequiredPasswordComplexity`, which is also for DPCs.

What a consumer app *can* do from Android 10 (API 29):

- Declare `android.permission.REQUEST_PASSWORD_COMPLEXITY` (a normal permission) and call `DevicePolicyManager.getPasswordComplexity()`. It returns `PASSWORD_COMPLEXITY_NONE`, `LOW` (pattern, or a PIN with repeating or ordered sequences such as `4444` or `1234`), `MEDIUM` (PIN without such sequences and at least 4 digits, or an alphabetic/alphanumeric password of at least 4 characters) or `HIGH` (PIN of at least 8 digits without sequences, or a password of at least 6 characters).
- Start `DevicePolicyManager.ACTION_SET_NEW_PASSWORD` with `EXTRA_PASSWORD_COMPLEXITY` to send the user to the system screen to set a lock of at least that complexity.

`PASSWORD_COMPLEXITY_NONE` is a third way to detect "no secure lock"; the higher values let a high-assurance app ask for more than a four-digit pattern.

#### Legacy and non-SDK approaches you will still see

- `Settings.Secure.LOCK_PATTERN_ENABLED` / `Settings.System.LOCK_PATTERN_ENABLED`: deprecated in API 23, only ever reflected the pattern lock, and returns nothing useful on modern devices.
- Reflection into `com.android.internal.widget.LockPatternUtils` (`isSecure`, `getActivePasswordQuality`): a hidden API, blocked by the non-SDK interface restrictions from Android 9. Treat it as broken.
- Querying `KeyguardManager` once from a `ContentProvider` or `Application.onCreate` and caching it in a static: technically the right API, functionally the stale assumption.

### iOS: Local Authentication Framework (MASTG-KNOW-0056)

Source: [MASTG-KNOW-0056](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-AUTH/MASTG-KNOW-0056/), extended with Apple's LocalAuthentication documentation. The OWASP page is a short introduction written in the Touch ID era; this section covers what you need to test lock-screen enforcement and to understand why `LAContext` alone is not enough.

#### LAContext and the two policies

[`LocalAuthentication`](https://developer.apple.com/documentation/localauthentication) gives apps access to the device owner's authentication mechanisms through `LAContext`. An app creates a context, asks whether a **policy** can be evaluated, and then evaluates it, which shows the system authentication UI. The two policies on iOS:

| Policy (Swift / Objective-C) | Raw value | Accepts | Fails when |
|---|---|---|---|
| `.deviceOwnerAuthenticationWithBiometrics` / `LAPolicyDeviceOwnerAuthenticationWithBiometrics` | 1 | Face ID, Touch ID or Optic ID only | No biometric hardware, nothing enrolled, biometry locked out, or no passcode |
| `.deviceOwnerAuthentication` / `LAPolicyDeviceOwnerAuthentication` | 2 | Biometrics if available, otherwise (or after biometric failures) the device passcode; on macOS also a paired Apple Watch | **No passcode is set** (`LAError.passcodeNotSet`) |

The raw values matter when you read disassembly or Frida output: the OWASP demos below identify the policy by the `2` in register `w2`. Further policies exist for macOS and watchOS (`.deviceOwnerAuthenticationWithWatch`, `.deviceOwnerAuthenticationWithBiometricsOrWatch`, `.deviceOwnerAuthenticationWithWristDetection`) and do not apply to iPhone apps.

Because `.deviceOwnerAuthentication` can only fail on a device without a passcode in one specific way, `canEvaluatePolicy(.deviceOwnerAuthentication, error:)` is the standard passcode check. Apple's documentation states it directly: on iOS, policy evaluation fails with `passcodeNotSet` if the device passcode is not enabled. The biometric policy is a worse proxy for the same reason as Android's biometric-only check: it also fails for users who have a passcode but have not set up Face ID.

Face ID needs `NSFaceIDUsageDescription` in `Info.plist`; without it the app cannot use Face ID. That key in the plist is a quick static hint that the app uses LocalAuthentication.

#### canEvaluatePolicy and its errors

```swift
let context = LAContext()
var error: NSError?
let ok = context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)
```

`canEvaluatePolicy` does not show any UI. It returns `true` if the policy can be evaluated now, or `false` with an `NSError` in `LAErrorDomain`. The codes you will see in this context:

| `LAError.Code` | Value | Meaning for lock-screen checks |
|---|---|---|
| `.passcodeNotSet` | -5 | **No passcode.** This is the signal MASWE-0017 is about. |
| `.biometryNotAvailable` | -6 | No biometric hardware, or the app is not allowed to use it (biometric policy only) |
| `.biometryNotEnrolled` | -7 | Passcode may be set, no biometric enrolled (biometric policy only) |
| `.biometryLockout` | -8 | Too many failed biometric attempts; `.deviceOwnerAuthentication` falls back to the passcode |
| `.notInteractive` | -1004 | The context was set to `interactionNotAllowed` and UI would be needed |
| `.invalidContext` | -10 | The context was invalidated |

Two implementation errors are common. The first is passing `error: nil` (as the OWASP demo does): the app then cannot tell "no passcode" from any other failure. The second is calling `canEvaluatePolicy` on a cached context created at launch; create a fresh `LAContext` for each check so the answer reflects the current device state.

#### evaluatePolicy, biometryType and evaluatedPolicyDomainState

`evaluatePolicy(_:localizedReason:reply:)` (or the `async` form) shows the system sheet and calls back with `success` and an optional error (`.userCancel`, `.userFallback`, `.authenticationFailed`, `.systemCancel`, `.appCancel` and so on). Useful context properties:

- `biometryType` (`.none`, `.touchID`, `.faceID`, `.opticID`) — populated only after `canEvaluatePolicy` has been called.
- `localizedFallbackTitle` and `localizedCancelTitle` — the button labels; an empty fallback title hides the "Enter Password" button for the biometric policy.
- `touchIDAuthenticationAllowableReuseDuration` — lets a recent device unlock count as authentication, up to `LATouchIDAuthenticationMaximumAllowableReuseDuration` (five minutes). Any non-zero value means "the user unlocked the phone recently", not "the user just authenticated to this app"; review it for high-risk actions.
- `interactionNotAllowed` — makes evaluation fail instead of prompting, for background checks.
- `invalidate()` — cancels any pending evaluation.
- `evaluatedPolicyDomainState` — an opaque `Data` value that changes when the set of enrolled biometrics changes, and is `nil` when no biometrics are enrolled. Apps compare it with a stored value to detect "someone added a new face". It is deprecated from iOS 18 in favour of `domainState` (`LADomainState`, with `domainState.biometry.stateHash`). Note that it tracks biometric enrolment, **not** the passcode: a passcode change does not alter it, and it cannot tell you whether a passcode exists. For enrolment changes, a Keychain item with `.biometryCurrentSet` is the stronger control because the OS deletes access rather than leaving the comparison to app code.

#### Why LAContext alone is event-bound

`evaluatePolicy` returns a Boolean to app code. Nothing cryptographic happens: no key is released, no data is decrypted. If the app's logic is "if success, show the account", the protection is an `if` statement in process memory, and anyone who can run code in the process — Frida, a debugger, a tweak on a jailbroken device, or a repackaged build — can call the reply block with `true`. objection ships this as a one-liner (`ios ui biometrics_bypass`). The same is true of `canEvaluatePolicy`: a hooked call returns whatever the hook says.

That is acceptable for a *check* (MASWE-0017 is about stopping an opportunistic finder of a lost phone, not an attacker with instrumentation on a jailbroken device), but it is not acceptable as the only thing protecting a key. The crypto-bound alternative is a Keychain item or Secure Enclave key whose access control requires user presence; the authentication then happens inside `securityd` and the Secure Enclave, and the data only comes back if it succeeded. An `LAContext` can still be used with that item — passed as `kSecUseAuthenticationContext` so you control the prompt text and reuse a recent authentication — but the context then *feeds* the Keychain rather than replacing it. iOS 16 added `LARight` and `LAPersistedRight`, which wrap the same idea (a right backed by a Secure Enclave key and a secret) in a higher-level API.

### iOS: Data Protection, the Keychain and the passcode

Supplementary, from Apple's Platform Security Guide and the Security framework reference. MASTG-TEST-0246 and MASTG-TEST-0248 list `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` as a detection API; this section explains why.

#### Data Protection classes without a passcode

iOS encrypts every file with a per-file key, wraps that key with a **class key**, and protects the class keys in the Secure Enclave. For the classes apps use, the class key is wrapped with a key derived from the user's passcode *entangled* with the device's hardware UID key, which never leaves the Secure Enclave. Because the derivation is tied to the UID, passcode guessing has to happen on the device, at a rate the Secure Enclave controls (with escalating delays and optional erase after ten attempts).

| Class | API constant | Available | Default for |
|---|---|---|---|
| A — Complete | `NSFileProtectionComplete` / `.complete` | Only while unlocked; key discarded shortly after lock | Opt-in |
| B — Complete unless open | `NSFileProtectionCompleteUnlessOpen` | Files already open stay usable after lock; new files can be created while locked | Opt-in |
| C — Until first user authentication | `NSFileProtectionCompleteUntilFirstUserAuthentication` | After first unlock until reboot | **Default for app data** |
| D — None | `NSFileProtectionNone` | Always | Opt-in |

All of this is keyed off the passcode. **With no passcode, the class keys are protected only by the UID**, so they can be unwrapped by the device itself at any time without user input. `NSFileProtectionComplete` still encrypts the file — the data is not readable from a raw flash image — but on the powered device it is as available as `NSFileProtectionNone`. You can usually see this at runtime: on a device without a passcode, `UIApplication.shared.isProtectedDataAvailable` stays `true` after the screen locks and `protectedDataWillBecomeUnavailableNotification` does not fire.

The same applies to the app-wide default set with the `com.apple.developer.default-data-protection` entitlement (`NSFileProtectionComplete`): it is a good L2 control on a device with a passcode and almost no control on a device without one. That is why OWASP's "Data protection not tied to the passcode" mode of introduction exists.

#### Keychain accessibility and the WhenPasscodeSet class

Keychain items get the same treatment: each item's accessibility (`kSecAttrAccessible`) maps to a class key, and only one class depends on a passcode *existing*:

| Accessibility constant | Stored value (`pdmn`) | Needs a passcode? | On passcode removal |
|---|---|---|---|
| `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` | `akpu` | **Yes — the item cannot be added without one** | **Item is deleted** |
| `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` | `aku` | No | Kept, available whenever the device is on |
| `kSecAttrAccessibleWhenUnlocked` (default) | `ak` | No | Kept |
| `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` | `cku` | No | Kept |
| `kSecAttrAccessibleAfterFirstUnlock` | `ck` | No | Kept |
| `kSecAttrAccessibleAlways*` (deprecated, iOS 12) | `dk` / `dku` | No | Kept |

The stored values are what you see in the `pdmn` column of `keychain-2.db` and in Frida hooks on `SecItemAdd`, so they are worth memorising. `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` items are also never migrated to another device: they are left out when a backup is restored anywhere but the original device.

Access-control flags created with `SecAccessControlCreateWithFlags` (`.userPresence`, `.biometryAny`, `.biometryCurrentSet`, `.devicePasscode`) sit on top of an accessibility class. Biometric flags need enrolled biometrics, which need a passcode, and Apple's guidance is to pair them with `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` so the item disappears if the passcode is turned off. A Secure Enclave key created with only `.privateKeyUsage` does **not** need a passcode: it is hardware-protected against extraction but usable by anyone holding an unlocked phone — exactly the "hardware backing is not user binding" point from MASWE-0003.

#### Detecting the passcode: two methods

There are two supported ways for an app to find out whether a passcode is set, and both appear in the OWASP tests:

1. **LocalAuthentication.** `LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)` returns `false` with `LAError.passcodeNotSet`. Cheap, no side effects, no UI.
2. **The Keychain probe.** Try to add a throwaway item with `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`. If `SecItemAdd` succeeds, a passcode is set (delete the item again); if it fails, it is not — or the device is locked, so only run the probe in the foreground. Before `LAError.passcodeNotSet` was reliable this was the standard trick, and it is still useful as a cross-check.

The better pattern combines detection with enforcement: store the real secret with `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` (plus a user-presence flag where appropriate). The `SecItemAdd` failure is then the detection, and the OS deletes the item if the passcode is later removed, which turns the stale-assumption problem into a clean "item not found" on next launch.

## Tests

OWASP maps four tests to MASWE-0017: a static and a dynamic test for each platform. All four ask the same question — does the app use an API that detects the secure lock? — and fail if it does not. That is a necessary condition, not a sufficient one, so after the four tests we add [supplementary checks](#supplementary-checks-guler-tech-methodology) for what the app does with the answer, for the stale-assumption case, and for whether the enforcement is cryptographic.

Before you start, set up your devices. You need to be able to switch between "secure lock" and "no lock" freely, which **destroys auth-bound keys and passcode-gated Keychain items on that device for every app**. Use a dedicated test device, never one with your own accounts on it.

```bash
# Android: set and clear a PIN from the host (needs USB debugging; no root required)
adb shell locksettings set-pin 1234
adb shell locksettings clear --old 1234
```

On iOS there is no command-line equivalent; use Settings > Face ID & Passcode (or Touch ID & Passcode) > Turn Passcode Off / On. Be aware that some jailbreaks constrain this: palera1n on A11 devices running iOS 16 or later requires the passcode to be disabled, so on such a device you can only test the "no passcode" side.

### MASTG-TEST-0247: References to APIs for Detecting Secure Screen Lock (Android)

Source: [MASTG-TEST-0247](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0247/). Platform: Android. Type: static (code). Related knowledge: MASTG-KNOW-0001.

#### Overview

The test looks for calls to `KeyguardManager.isDeviceSecure()` / `isKeyguardSecure()` and `BiometricManager.canAuthenticate(int)` in the decompiled app. A reference means the app at least asks; no reference means it almost certainly does not (unless it relies on auth-bound keys, which we add to the sweep). OWASP's page also makes the point that apps **cannot force** users to enable a lock or biometrics at the system level; they can only refuse or restrict their own functionality.

#### Prerequisites

- The APK, or all split APKs, of the build under test: `adb shell pm path <package>` and `adb pull` each path.
- jadx (MASTG-TOOL-0018) for decompilation — OWASP's MASTG-TECH-0013/0017 "reverse engineer the app" step — and apktool for smali, which survives obfuscation better.
- semgrep (MASTG-TOOL-0110) for the pattern search (MASTG-TECH-0014, static analysis on Android).

#### Steps

1. **Decompile.**

   ```bash
   jadx -d out/ base.apk
   apktool d base.apk -o smali_out/
   ```

2. **Run the OWASP rule** (`mastg-android-device-passcode-present.yml`) against the jadx Java output:

   ```yaml
   rules:
     - id: mastg-android-device-passcode-present
       languages:
         - java
       severity: INFO
       metadata:
         summary: This rule searches for API that checks whether the device passcode is set.
       message: "[MASVS-STORAGE] Make sure to verify that your app runs on a device with a passcode set"
       pattern-either:
         - pattern: |
             $X.getSystemService("keyguard");
             ...
             $Y.isDeviceSecure();
         - pattern: |
             BiometricManager $BM = (BiometricManager) $X.getSystemService(BiometricManager.class);
             ...
             $BM.canAuthenticate($VAL);
   ```

   ```bash
   semgrep -c mastg-android-device-passcode-present.yml out/sources/
   ```

   Understand its limits: both patterns require the service lookup and the call to be in the **same method**, and the first requires the string form `getSystemService("keyguard")`. Code that obtains `KeyguardManager` via `getSystemService(KeyguardManager.class)`, `ContextCompat.getSystemService`, dependency injection or a field initialised elsewhere is missed, as is `androidx.biometric.BiometricManager.from(context)`.

3. **Run a broader rule** that matches the calls themselves and the enforcement APIs:

   ```yaml
   rules:
     - id: gt-android-secure-lock-apis
       languages: [java]
       severity: INFO
       message: Secure lock screen detection or enforcement API
       pattern-either:
         - pattern: $X.isDeviceSecure()
         - pattern: $X.isKeyguardSecure()
         - pattern: $X.canAuthenticate(...)
         - pattern: $X.getPasswordComplexity()
         - pattern: $X.setUserAuthenticationRequired(true)
         - pattern: $X.setUserAuthenticationParameters(...)
         - pattern: $X.setUnlockedDeviceRequired(true)
   ```

   ```bash
   semgrep -c gt-android-secure-lock-apis.yml out/sources/ --exclude 'androidx' --exclude 'kotlin'
   ```

4. **Grep the smali** for the framework method references. Platform classes are never renamed by R8, so this works on obfuscated builds where jadx output is hard to read:

   ```bash
   grep -rnE 'Landroid/app/KeyguardManager;->(isDeviceSecure|isKeyguardSecure|isDeviceLocked)\(\)Z' smali_out/
   grep -rnE 'BiometricManager;->canAuthenticate\((I)?\)I' smali_out/
   grep -rnE 'KeyGenParameterSpec\$Builder;->(setUserAuthenticationRequired|setUserAuthenticationParameters|setUnlockedDeviceRequired)' smali_out/
   grep -rn 'KeyPermanentlyInvalidatedException' smali_out/ | grep -v '/androidx/'
   ```

5. **Check the manifest** for related permissions:

   ```bash
   grep -nE 'USE_BIOMETRIC|USE_FINGERPRINT|REQUEST_PASSWORD_COMPLEXITY|BIND_DEVICE_ADMIN' out/resources/AndroidManifest.xml
   ```

6. **Attribute and follow each hit.** For every call site, decide whether it is in app code or in a library (`androidx.biometric` itself calls `KeyguardManager.isDeviceSecure()` internally; fraud-detection and RASP SDKs often call it for telemetry). Then use jadx-gui's *Find Usage* on the enclosing method and follow the Boolean or result code until it either changes behaviour (blocks a screen, disables a feature, throws) or disappears into a log or analytics call.

#### Observation

A list of call sites with class, method and line; whether each is app or SDK code; which API variant is used (`isDeviceSecure` versus `isKeyguardSecure`, which authenticators are passed to `canAuthenticate`); where in the user journey it runs (application start, onboarding, every resume, before specific actions); what the result controls; and, separately, which `KeyGenParameterSpec` builders set user-authentication or unlocked-device requirements and how `KeyPermanentlyInvalidatedException` is handled.

#### Evaluation

OWASP's criterion: the test **fails** if the app does not use any API to verify the presence of a secure screen lock.

How we apply it in practice:

- **Fail** if no detection API is called from app code and no sensitive key is auth-bound. A call that exists only inside a third-party SDK and whose result never reaches app logic counts as no call.
- **Fail** if the only check is a proxy that cannot detect the lock (`isDeviceLocked`, `isKeyguardLocked`, `LOCK_PATTERN_ENABLED`, reflection into `LockPatternUtils`).
- **Pass, with a note**, if the app uses `canAuthenticate(BIOMETRIC_STRONG)` alone or `isKeyguardSecure()`: the first is conservative but blocks legitimate users, the second has the SIM-lock false positive.
- **Pass** if `isDeviceSecure()`, `canAuthenticate(DEVICE_CREDENTIAL ...)` or `getPasswordComplexity()` is called and its result gates sensitive functionality.
- **Pass in substance** if the app does not call a detection API but every sensitive key is generated with `setUserAuthenticationRequired(true)`, the generation failure is handled by refusing the feature, and `KeyPermanentlyInvalidatedException` leads to re-enrolment. The OS is enforcing the lock. Report it as satisfying the weakness, and recommend an explicit check anyway for a clear user message.

Static analysis cannot tell you whether the result is enforced at runtime; confirm with MASTG-TEST-0249 and the [supplementary checks](#supplementary-checks-guler-tech-methodology).

#### Demo

From [MASTG-DEMO-0028](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0028/MASTG-DEMO-0028/). The Kotlin sample checks both APIs and reports the result:

```kotlin
fun isDeviceSecure(context: Context): Boolean {
    val keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
    return keyguardManager.isDeviceSecure
}

fun checkStrongBiometricStatus(): String {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        val biometricManager = context.getSystemService(BiometricManager::class.java)
        val result = biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        return when (result) {
            BiometricManager.BIOMETRIC_SUCCESS -> "BIOMETRIC_SUCCESS - Strong biometric authentication is available."
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> "BIOMETRIC_ERROR_NONE_ENROLLED - No biometrics enrolled."
            else -> "Unknown biometric status: $result"
        }
    }
    return "Strong biometric authentication check is not supported on this API level."
}
```

After jadx, the Kotlin property access becomes a method call, the service name becomes the string `"keyguard"` and `BIOMETRIC_STRONG` becomes its value `15`:

```java
Object systemService = context.getSystemService("keyguard");
KeyguardManager keyguardManager = (KeyguardManager) systemService;
return keyguardManager.isDeviceSecure();
// ...
BiometricManager biometricManager = (BiometricManager) this.context.getSystemService(BiometricManager.class);
int result = biometricManager.canAuthenticate(15);
```

`semgrep -c ../../../../rules/mastg-android-device-passcode-present.yml ./MastgTest_reversed.java` reports both:

```text
┌─────────────────┐
│ 2 Code Findings │
└─────────────────┘

    MastgTest_reversed.java
     ❱ rules.mastg-android-device-passcode-present
          [MASVS-STORAGE] Make sure to verify that your app runs on a device with a passcode set

           30┆ Object systemService = context.getSystemService("keyguard");
           31┆ Intrinsics.checkNotNull(systemService, "null cannot be cast to non-null type
               android.app.KeyguardManager");
           32┆ KeyguardManager keyguardManager = (KeyguardManager) systemService;
           33┆ return keyguardManager.isDeviceSecure();
            ⋮┆----------------------------------------
           38┆ BiometricManager biometricManager = (BiometricManager)
               this.context.getSystemService(BiometricManager.class);
           39┆ int result = biometricManager.canAuthenticate(15);
```

OWASP marks this as a pass: `isDeviceSecure` on line 33 and `canAuthenticate` on line 39. Two observations for real assessments. First, the sample only *displays* the result; it does not restrict anything, so on our criteria it would be a "check without consequence" until the supplementary checks show otherwise. Second, the `canAuthenticate` call passes `BIOMETRIC_STRONG` only (15), so on its own it would not distinguish "no lock" from "no fingerprint". The `isDeviceSecure` call is the one that answers the MASWE-0017 question. (The rule message still says `[MASVS-STORAGE]`, a leftover from the MASVS v1 mapping.)

### MASTG-TEST-0249: Runtime Use of Secure Screen Lock Detection APIs (Android)

Source: [MASTG-TEST-0249](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0249/). Platform: Android. Type: dynamic (hooks). Related knowledge: MASTG-KNOW-0001.

#### Overview

The dynamic counterpart to MASTG-TEST-0247. Instead of finding references, you hook `KeyguardManager.isDeviceSecure` and `BiometricManager.canAuthenticate` and exercise the app, which catches calls made through reflection, dependency injection or obfuscated wrappers, and tells you *when* the check runs — the piece of information static analysis cannot give you.

#### Prerequisites

- The app installed on a test device or emulator (MASTG-TECH-0005: `adb install base.apk`, or `adb install-multiple` for splits).
- Frida (MASTG-TOOL-0001) on the host and `frida-server` running on a rooted device. For a non-rooted device, inject Frida Gadget into a repackaged APK; the hooks are the same.
- Optional: objection (MASTG-TOOL-0038) for quick one-off hooks.

#### Steps

1. **Start from a known lock state** — run the test twice, once with a PIN set and once without (see the commands at the top of [Tests](#tests)).

2. **Hook the detection APIs** (OWASP's MASTG-TECH-0043, method hooking). A trimmed version of the OWASP script with the backtrace kept:

   ```javascript
   // lock-apis.js
   Java.perform(() => {
     const Log = Java.use('android.util.Log');
     const Exception = Java.use('java.lang.Exception');
     const trace = () => Log.getStackTraceString(Exception.$new()).split('\n').slice(1, 9).join('\n  ');

     const KM = Java.use('android.app.KeyguardManager');
     ['isDeviceSecure', 'isKeyguardSecure'].forEach((name) => {
       KM[name].overload().implementation = function () {
         const r = this[name]();
         console.log(`\n[*] KeyguardManager.${name}() -> ${r}\n  ${trace()}`);
         return r;
       };
     });

     const BM = Java.use('android.hardware.biometrics.BiometricManager');
     BM.canAuthenticate.overload('int').implementation = function (auth) {
       const r = this.canAuthenticate(auth);
       console.log(`\n[*] BiometricManager.canAuthenticate(0x${auth.toString(16)}) -> ${r}\n  ${trace()}`);
       return r;
     };
   });
   ```

   ```bash
   frida -U -f com.example.app -l lock-apis.js -o lock-apis.log
   ```

   On API 30+ the AndroidX `BiometricManager` forwards to the platform class, so this one hook covers both. On older versions AndroidX answers credential queries from `KeyguardManager`, which the first hook already covers.

3. **Alternatives without writing a script:**

   ```bash
   frida-trace -U -f com.example.app -j 'android.app.KeyguardManager!isDevice*' -j 'android.app.KeyguardManager!isKeyguard*'
   ```

   ```text
   objection -g com.example.app explore
   android hooking watch class_method android.app.KeyguardManager.isDeviceSecure --dump-return --dump-backtrace
   ```

4. **Exercise the app thoroughly**: first launch, registration, login, enabling biometric or "quick" login, viewing sensitive screens, payments or signing, sending the app to the background and back, killing and relaunching it. Enter test data wherever you can.

5. **Log the enforcement layer at the same time** so you can see whether the app relies on auth-bound keys:

   ```javascript
   // keyspec.js
   Java.perform(() => {
     const B = Java.use('android.security.keystore.KeyGenParameterSpec$Builder');
     B.$init.overload('java.lang.String', 'int').implementation = function (alias, purposes) {
       console.log(`[KeyGenParameterSpec] alias=${alias} purposes=${purposes}`);
       return this.$init(alias, purposes);
     };
     B.setUserAuthenticationRequired.implementation = function (v) {
       console.log(`[KeyGenParameterSpec] setUserAuthenticationRequired(${v})`);
       return this.setUserAuthenticationRequired(v);
     };
     B.setUnlockedDeviceRequired.implementation = function (v) {
       console.log(`[KeyGenParameterSpec] setUnlockedDeviceRequired(${v})`);
       return this.setUnlockedDeviceRequired(v);
     };
   });
   ```

   ```bash
   frida -U -f com.example.app -l lock-apis.js -l keyspec.js
   ```

#### Observation

The log of each call with its result and backtrace, annotated with the user action that triggered it. Note in particular: whether the check runs on every return to the foreground or only once; whether its result differs between your two device states; what the app visibly did in each state; and which key aliases were generated with authentication required.

#### Evaluation

The test **fails** if, across all exercised flows, the app never calls an API to verify that a secure lock is present (OWASP's criterion). Apply the same refinements as for MASTG-TEST-0247: a call from an SDK whose result changes nothing, or a call made only at first launch, does not satisfy the weakness; auth-bound keys that fail generation without a lock do. Where the app calls the API and behaves identically in both device states, record it as a "check without consequence".

#### Demo

From [MASTG-DEMO-0027](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0027/MASTG-DEMO-0027/), using the same Kotlin sample as the static demo, run with `frida -U -f org.owasp.mastestapp -l ./script.js -o output.txt` on a device with no lock screen:

```text
[*] KeyguardManager.isDeviceSecure() called - RESULT: false

Backtrace:
android.app.KeyguardManager.isDeviceSecure(Native Method)
org.owasp.mastestapp.MastgTest.isDeviceSecure(MastgTest.kt:24)
org.owasp.mastestapp.MastgTest.mastgTest(MastgTest.kt:10)
org.owasp.mastestapp.MainActivityKt.MainScreen$lambda$9$lambda$8(MainActivity.kt:53)

[*] BiometricManager.canAuthenticate called with: BIOMETRIC_STRONG (15) - RESULT: BIOMETRIC_ERROR_NONE_ENROLLED (11)

Backtrace:
android.hardware.biometrics.BiometricManager.canAuthenticate(Native Method)
org.owasp.mastestapp.MastgTest.checkStrongBiometricStatus(MastgTest.kt:38)
org.owasp.mastestapp.MastgTest.mastgTest(MastgTest.kt:11)
```

The test passes on OWASP's criterion: both APIs are used at runtime, from `MastgTest.isDeviceSecure` (line 24) and `MastgTest.checkStrongBiometricStatus` (line 38). Two details worth reading out of the output. `isDeviceSecure()` returned `false` — this device has no lock — and the app carried on and displayed the result, so in a real app this is where you would start the supplementary checks. And `canAuthenticate(BIOMETRIC_STRONG)` returned `11`, the same value it would return on a device *with* a PIN but no fingerprint, which is why the biometric call cannot stand in for the keyguard call. The `(Native Method)` frame at the top is Frida's replacement, not real native code. As OWASP notes, file names and line numbers appear only because this is a debug build; release builds usually show obfuscated class names, but the call and its timing are what you need.

### MASTG-TEST-0248: References to APIs for Detecting Secure Screen Lock (iOS)

Source: [MASTG-TEST-0248](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0248/). Platform: iOS. Type: static (code). Related knowledge: MASTG-KNOW-0056.

#### Overview

On iOS the test looks for two things in the binary: calls to `LAContext.canEvaluatePolicy(_:error:)` with `.deviceOwnerAuthentication` (or the biometric policy), and Keychain items stored with `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`. Either one shows the app takes the passcode into account; the second also shows it *depends* on one.

#### Prerequisites

- A decrypted IPA. Check with `otool -l Payload/App.app/App | grep -A4 LC_ENCRYPTION_INFO`; `cryptid 1` means you must decrypt it on a jailbroken device first. Builds supplied directly by the client are usually unencrypted.
- The extracted bundle (MASTG-TECH-0058, "Exploring the App Package": `unzip App.ipa`, the binary is `Payload/App.app/App`; frameworks are in `Payload/App.app/Frameworks/`).
- radare2 (MASTG-TOOL-0073) and the macOS command-line tools (`otool`, `nm`, `strings`, `codesign`, `plutil`) for MASTG-TECH-0066, static analysis on iOS.

#### Steps

1. **Extract and orient.**

   ```bash
   unzip -q App.ipa -d ipa/
   BIN=ipa/Payload/App.app/App
   otool -L "$BIN" | grep -E 'LocalAuthentication|Security'
   plutil -p ipa/Payload/App.app/Info.plist | grep -i NSFaceIDUsageDescription
   codesign -d --entitlements :- ipa/Payload/App.app 2>/dev/null | grep -A1 default-data-protection
   ```

   A linked `LocalAuthentication.framework` and a Face ID usage string mean the app uses `LAContext` somewhere. The entitlement tells you the app-wide file protection default (worth recording because, as explained above, `NSFileProtectionComplete` means little without a passcode).

2. **Look for the selectors and constants.** Swift calls to `LAContext` go through the Objective-C runtime, so the selector names are in `__objc_methname`; Keychain constants are imported symbols:

   ```bash
   strings -a "$BIN" | grep -E '^(canEvaluatePolicy:error:|evaluatePolicy:localizedReason:reply:|evaluatedPolicyDomainState|domainState)$'
   nm -u "$BIN" | grep -E 'kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly|SecAccessControlCreateWithFlags|kSecUseAuthenticationContext|kSecAttrAccessControl'
   for f in ipa/Payload/App.app/Frameworks/*.framework; do
     b="$f/$(basename "$f" .framework)"
     nm -u "$b" 2>/dev/null | grep -q WhenPasscodeSet && echo "== $b uses WhenPasscodeSet"
     strings -a "$b" 2>/dev/null | grep -q 'canEvaluatePolicy:error:' && echo "== $b uses canEvaluatePolicy"
   done
   ```

   Hits in a framework rather than the main binary need attributing, exactly as with Android SDKs.

3. **Find the call sites in radare2**:

   ```text
   r2 -A ipa/Payload/App.app/App
   [0x...]> f~canEvaluatePolicy        # selector string and selector reference flags
   [0x...]> axt @ <selector string address>
   [0x...]> axt @ <selector reference address>
   [0x...]> pdf @ <calling function> ~canEvaluatePolicy,w2,x3
   [0x...]> f~WhenPasscodeSet          # relocation for the imported Keychain constant
   [0x...]> axt @ <relocation address>
   ```

4. **Read the arguments.** At the `objc_msgSend` for `canEvaluatePolicy:error:`, `x0` is the `LAContext`, `x1` the selector, `w2`/`x2` the policy (1 = biometrics only, 2 = device owner authentication) and `x3` the `NSError **` (zero means the app passed `nil` and cannot see `passcodeNotSet`). After the call, look at what the code does with `w0`: a branch to a "set up a passcode" screen or a disabled feature is enforcement; a call into analytics or logging is not. Comparisons against `-5` near the call mean the app inspects `LAError.passcodeNotSet`.

5. **Check what the Keychain constant is used for.** A load of `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` that ends up in the dictionary passed to `SecItemAdd` or `SecAccessControlCreateWithFlags` is the pattern you want; find the item's service and account strings nearby so you can match them in the dynamic test.

#### Observation

The functions and addresses that call `canEvaluatePolicy:error:`, with the policy value and whether an error pointer is passed; the uses of `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` and any access-control flags; which binary (app or framework) each is in; and, from the disassembly, what the result controls.

#### Evaluation

OWASP's criterion: the test **fails** if the app doesn't use any API to verify the presence of a secure screen lock. As on Android, we treat `.deviceOwnerAuthenticationWithBiometrics` alone as a pass with a usability note; a call in a framework whose result never reaches app logic as no call; and an app that stores every sensitive item with `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` and handles the add failure by refusing the feature as satisfying the weakness even without an `LAContext` check.

#### Demo

From [MASTG-DEMO-0024](https://mas.owasp.org/MASTG/demos/ios/MASVS-RESILIENCE/MASTG-DEMO-0024/MASTG-DEMO-0024/). The Swift sample:

```swift
import LocalAuthentication

struct MastgTest {
    static func mastgTest(completion: @escaping (String) -> Void) {
        if devicePasscodeSet() {
            completion("This device is protected with a passcode ✅")
        } else {
            completion("This device doesn't have a passcode ⚠️")
        }
    }

    static func devicePasscodeSet() -> Bool {
        // "In iOS, policy evaluation fails with the error passcodeNotSet if the device passcode isn't enabled"
        return LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
    }
}
```

The r2 script (`r2 -q -i isDevicePasscodeSet.r2 -e emu.str=true -A MASTestApp`) finds the selector, its cross-references and the disassembly around the call:

```text
e asm.bytes=false
e scr.color=false
e asm.var=false
f~canEvaluatePolicy
axt @ 0x100008360
axt @ 0x1000100a0
pdf @ 0x100004f10 | grep -C 5 "canEvaluatePolicy:error:"
```

Output, trimmed:

```text
0x100008360 24 str.canEvaluatePolicy:error:
sym.func.100004ea8 0x100004f10 [STRING] ldr x1, [x8, 0xa0]
│  0x100004f10   ldr x1, [x8, 0xa0]     ; 0x100008360 ; char *selector ; x1 -> "canEvaluatePolicy:error:"
│  0x100004f14   movz w2, 0x2           ; w2=0x2
│  0x100004f18   movz x3, 0             ; x3=0x0
│  0x100004f1c   bl sym.imp.objc_msgSend ; objc_msgSend(-1, "canEvaluatePolicy:error:")
```

The Swift call has become `objc_msgSend(context, "canEvaluatePolicy:error:", 2, NULL)`: the selector is loaded into `x1`, `w2 = 2` is `LAPolicyDeviceOwnerAuthentication`, and `x3 = 0` is the `nil` error pointer. OWASP marks this as a pass because the passcode-verification API is referenced. As with the Android demo, the sample only reports the result. And the `nil` error means that in a real app you could not distinguish "no passcode" from any other failure — record that as an implementation note.

### MASTG-TEST-0246: Runtime Use of Secure Screen Lock Detection APIs (iOS)

Source: [MASTG-TEST-0246](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0246/). Platform: iOS. Type: dynamic (hooks). Related knowledge: MASTG-KNOW-0056.

#### Overview

The dynamic counterpart to MASTG-TEST-0248: hook `-[LAContext canEvaluatePolicy:error:]` and the Keychain functions, exercise the app, and record when the passcode is checked and which items are stored with a passcode-dependent class.

#### Prerequisites

- The app installed (MASTG-TECH-0056: for example `ideviceinstaller -i App.ipa`, or Xcode/`xcrun devicectl` for development builds).
- Frida (MASTG-TOOL-0039) with `frida-server` on a jailbroken device, or Frida Gadget injected into a re-signed IPA (MASTG-TECH-0090) on a non-jailbroken one.
- A physical device. The Simulator does not model the passcode faithfully, so its answers are not evidence.

#### Steps

1. **Hook LocalAuthentication** (MASTG-TECH-0095, method hooking on iOS). This version also reads the returned error code, which the OWASP script does not:

   ```javascript
   // la-check.js
   const LAPolicy = { 1: 'deviceOwnerAuthenticationWithBiometrics', 2: 'deviceOwnerAuthentication' };

   Interceptor.attach(ObjC.classes.LAContext['- canEvaluatePolicy:error:'].implementation, {
     onEnter(args) {
       this.policy = args[2].toInt32();
       this.errPtr = args[3];
       this.bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
         .slice(0, 6).map(DebugSymbol.fromAddress).join('\n  ');
     },
     onLeave(retval) {
       let code = 'n/a (nil error pointer)';
       if (!this.errPtr.isNull()) {
         const err = this.errPtr.readPointer();
         code = err.isNull() ? 'none' : new ObjC.Object(err).code();
       }
       console.log(`\n[LAContext canEvaluatePolicy:${LAPolicy[this.policy] || this.policy}] -> ${retval.toInt32()} error=${code}\n  ${this.bt}`);
     }
   });

   Interceptor.attach(ObjC.classes.LAContext['- evaluatePolicy:localizedReason:reply:'].implementation, {
     onEnter(args) {
       console.log(`[LAContext evaluatePolicy:${args[2].toInt32()}] reason="${new ObjC.Object(args[3])}"`);
     }
   });
   ```

2. **Hook the Keychain** to see accessibility classes and access control:

   ```javascript
   // keychain-classes.js
   const sec = Process.getModuleByName('Security');

   Interceptor.attach(sec.getExportByName('SecItemAdd'), {
     onEnter(args) {
       const q = new ObjC.Object(args[0]);
       this.desc = `svc=${q.objectForKey_('svce')} acct=${q.objectForKey_('acct')} pdmn=${q.objectForKey_('pdmn')} accc=${q.objectForKey_('accc') ? 'yes' : 'no'}`;
     },
     onLeave(retval) {
       console.log(`[SecItemAdd] ${this.desc} status=${retval.toInt32()}`);
     }
   });

   Interceptor.attach(sec.getExportByName('SecAccessControlCreateWithFlags'), {
     onEnter(args) {
       console.log(`[SecAccessControlCreateWithFlags] protection=${new ObjC.Object(args[1])} flags=0x${args[2].toString(16)}`);
     }
   });
   ```

   `pdmn` is the accessibility (`akpu` = `WhenPasscodeSetThisDeviceOnly`; see the table in the Knowledge section). When access control is used, the protection class is passed to `SecAccessControlCreateWithFlags` instead and `pdmn` is absent from the query. The flags are a bitmask: `0x1` `.userPresence`, `0x2` `.biometryAny`, `0x8` `.biometryCurrentSet`, `0x10` `.devicePasscode`, `0x4000` `.or`, `0x8000` `.and`, `0x40000000` `.privateKeyUsage`.

3. **Run and exercise the app**, with the passcode on and then off:

   ```bash
   frida -U -f com.example.app -l la-check.js -l keychain-classes.js -o ios-lock.log
   ```

   A quicker first look without scripts:

   ```bash
   frida-trace -U -f com.example.app -m '-[LAContext canEvaluatePolicy:error:]' -m '-[LAContext evaluatePolicy:localizedReason:reply:]' -i SecItemAdd -i SecAccessControlCreateWithFlags
   ```

4. **Confirm what was stored** on a jailbroken device:

   ```text
   objection -g com.example.app explore
   ios keychain dump --json keychain.json
   ```

   Each entry shows its accessibility (`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` and so on) and access-control flags.

#### Observation

Each `canEvaluatePolicy` call with policy, result, error code and backtrace; the triggering user action; each `SecItemAdd` with service, account, accessibility and status; and the difference in app behaviour between the two device states.

#### Evaluation

The test **fails** if the app doesn't use any API to verify the presence of a secure screen lock during the exercised flows. Apply the same refinements as for the static test, and note specifically: a `SecItemAdd` with `akpu` that **fails** on the no-passcode run, followed by another `SecItemAdd` for the same account with a weaker class, is the silent-downgrade pattern and a finding in its own right.

#### Demo

From [MASTG-DEMO-0026](https://mas.owasp.org/MASTG/demos/ios/MASVS-RESILIENCE/MASTG-DEMO-0026/MASTG-DEMO-0026/), the same Swift sample as the static demo, hooked with OWASP's script:

```javascript
Interceptor.attach(ObjC.classes.LAContext['- canEvaluatePolicy:error:'].implementation, {
  onEnter(args) {
    const LAPolicy = { 1: '.deviceOwnerAuthenticationWithBiometrics', 2: '.deviceOwnerAuthentication' };
    const policy = args[2].toInt32();
    console.log(`\nLAContext.canEvaluatePolicy(${args[2]}) called with ${LAPolicy[policy] || 'Unknown Policy'} (${args[2]})\n`);
    const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
    console.log('\nBacktrace:');
    backtrace.slice(0, 8).forEach((frame) => console.log(frame));
  }
});
```

```bash
frida -U -f org.owasp.mastestapp.MASTestApp-iOS -l ./script.js -o output.txt
```

Output, trimmed (the SwiftUI frame is a very long mangled symbol):

```text
LAContext.canEvaluatePolicy(0x2) called with .deviceOwnerAuthentication (0x2)

Backtrace:
0x100f58110 MASTestApp.debug.dylib!static MastgTest.devicePasscodeSet()
0x100f5802c MASTestApp.debug.dylib!static MastgTest.mastgTest(completion:)
0x100f599d4 MASTestApp.debug.dylib!$s10MASTestApp11ContentViewV4bodyQrvg7SwiftUI05TupleD0V...
0x19afc6e30 SwiftUI!partial apply for implicit closure #2 in implicit closure #1 in WrappedButtonStyle.Body.body.getter
```

The test passes: the app calls `canEvaluatePolicy` with `.deviceOwnerAuthentication` (`0x2`) from `MastgTest.devicePasscodeSet()`, triggered by a button press. The OWASP script logs only `onEnter`, so it does not show the result; our version above adds `onLeave` so you can see `-> 0 error=n/a` on a device without a passcode — and, because the sample passes `nil` for the error, that "n/a" is itself evidence that the app cannot see `passcodeNotSet`.

### Supplementary checks (Guler Tech methodology)

The four OWASP tests establish that a detection API is called. They do not establish that anything is *enforced*, that the enforcement survives the user removing the lock later, or whether the enforcement is cryptographic or just an `if`. These checks close those gaps. Run them on every L2 or EUDIW assessment.

#### Check A: what the app does without a lock

**Overview.** Determine the app's response policy — warn, degrade or refuse — and whether it matches what the client says it does.

**Prerequisites.** Test device with the ability to remove the lock, or Frida to simulate it; a test account.

**Steps.**

1. On a device with **no** lock, install the app fresh and go through onboarding, login, enrolment of biometric or quick login, and every sensitive feature.
2. Record every warning, blocked feature and changed behaviour.
3. If you cannot remove the lock (for instance, because you need the keys you already have), simulate it by forcing the detection APIs to say "no lock" on a device that has one:

   ```javascript
   // force-lock-state.js — FORCE: true (pretend locked), false (pretend no lock), null (observe)
   const FORCE = false;
   Java.perform(() => {
     const KM = Java.use('android.app.KeyguardManager');
     ['isDeviceSecure', 'isKeyguardSecure'].forEach((name) => {
       KM[name].overload().implementation = function () {
         const real = this[name]();
         const ret = FORCE === null ? real : FORCE;
         console.log(`[KeyguardManager.${name}] real=${real} returned=${ret}`);
         return ret;
       };
     });
     const BM = Java.use('android.hardware.biometrics.BiometricManager');
     BM.canAuthenticate.overload('int').implementation = function (auth) {
       const real = this.canAuthenticate(auth);
       const ret = FORCE === null ? real : (FORCE ? 0 : 11);   // SUCCESS or NONE_ENROLLED
       console.log(`[BiometricManager.canAuthenticate(0x${auth.toString(16)})] real=${real} returned=${ret}`);
       return ret;
     };
   });
   ```

   The iOS equivalent changes the return value in `onLeave`:

   ```javascript
   // force-passcode-state.js
   const FORCE = false;
   Interceptor.attach(ObjC.classes.LAContext['- canEvaluatePolicy:error:'].implementation, {
     onLeave(retval) {
       console.log(`[canEvaluatePolicy] real=${retval.toInt32()} returned=${FORCE ? 1 : 0}`);
       retval.replace(ptr(FORCE ? 1 : 0));
     }
   });
   ```

   With objection, the same thing is `android hooking set return_value android.app.KeyguardManager.isDeviceSecure false` or `ios hooking set return_value "-[LAContext canEvaluatePolicy:error:]" false`, if your objection build supports your Frida version.

   Note that forcing `false` on iOS this way returns no `NSError`, so an app that branches on `LAError.passcodeNotSet` will treat it as "some other failure". If that matters, test with the passcode actually off.

**Observation.** The app's behaviour per feature with and without a lock, and the evidence (screenshots, logs) for each.

**Evaluation.** For an L2 or EUDIW app, the response must be at least *degrade* for anything that stores credentials or keys on the device, and *refuse* for high-assurance functions (credential presentation, transaction signing, payment approval). A warning that the user can dismiss once and never see again is a finding for those apps. For an app whose documented policy is "warn only", verify that the warning appears and that nothing marketed as "protected by your device lock" is enabled.

#### Check B: lock removed after enrolment (stale assumption)

**Overview.** Tests OWASP's "stale device-lock assumption" mode directly.

**Prerequisites.** A device whose lock you can remove; Frida optional for logging.

**Steps.**

1. With a PIN or passcode set, install the app, log in and enable every feature that depends on the lock (biometric login, offline vault, wallet credentials).
2. Background the app (do not kill it). Remove the lock: `adb shell locksettings clear --old 1234` on Android, Settings on iOS.
3. Return to the app. Then kill and relaunch it. At each step, try to use the protected features.
4. While doing so, run the hooks from MASTG-TEST-0249 / 0246 and watch for `KeyPermanentlyInvalidatedException` on Android:

   ```javascript
   Java.perform(() => {
     const KPIE = Java.use('android.security.keystore.KeyPermanentlyInvalidatedException');
     KPIE.$init.overload('java.lang.String').implementation = function (msg) {
       console.log(`[!] KeyPermanentlyInvalidatedException: ${msg}`);
       return this.$init(msg);
     };
   });
   ```

   and for `SecItemCopyMatching` returning `-25300` (`errSecItemNotFound`) on iOS for items that existed before.

5. On a rooted or jailbroken device, list what remains: `ls -la /data/data/<package>/shared_prefs/` and the keystore listing (`objection` `android keystore list`), or `ios keychain dump`.

**Observation.** Whether the app re-checks on resume and on relaunch; what it does when the auth-bound key fails or the Keychain item has gone; whether new keys or items are created, and with what configuration.

**Evaluation.** The app **fails** if protected features keep working on resume or relaunch without a lock, if it recreates keys without user authentication or items with a passcode-independent class, or if it crashes in a way that leaves sensitive data on disk. It **passes** if it detects the change (by explicit check or by the invalidated key), wipes or locks the protected data, and requires re-enrolment once a lock is set again.

#### Check C: is the enforcement cryptographic?

**Overview.** Separates "the app checks and refuses" from "the OS refuses". Use the `FORCE = true` setting of the scripts in Check A on a device with **no** lock, so the app believes a lock exists.

**Steps.**

1. Remove the lock. Run `force-lock-state.js` (Android) or `force-passcode-state.js` (iOS) with `FORCE = true`, together with `keyspec.js` or `keychain-classes.js`.
2. Go through enrolment of the sensitive features.
3. Watch what happens after the check passes: on Android, does `KeyGenerator.init` throw for an auth-bound key? On iOS, does `SecItemAdd` with `akpu` fail?

**Observation.** Whether the app could enable the feature once the check was faked, and which platform call (if any) then failed.

**Evaluation.** This is a characterisation, not a pass/fail on its own:

- **Platform-enforced**: key generation or `SecItemAdd` fails and the feature cannot be enabled. The check is a UX layer over a cryptographic requirement — the best result.
- **App-enforced only**: the feature enables and stores its secrets in keys or items that do not need a lock. The check is the only control; that is acceptable for the MASWE-0017 threat (see below) but should be recommended for hardening in L2/EUDIW apps.
- **Silent downgrade**: the platform call fails and the app retries with a weaker configuration. Report it.

#### What bypassing the check proves and does not prove

Testers sometimes report "the passcode check can be bypassed with Frida" as the MASWE-0017 finding. Be careful with that.

What a bypass **does** prove: that the check is client-side code (always true), how the app behaves in each state without destroying the device's keys, and — via Check C — whether a second, cryptographic layer exists.

What it **does not** prove: that the weakness is exploitable. The MASWE-0017 attacker (MAS-ATTACK-0063) is someone who finds or steals a phone that has no lock. They have the UI, and with forensic tools, the storage; they do not have code execution inside a release build on a stock device. Injecting Frida requires a rooted or jailbroken device, or a repackaged and re-signed app — and a repackaged app cannot read the original app's data or Keystore keys, because it is a different install with a different signature. An attacker who can hook the app has already defeated the platform security model, and that is the domain of the resilience weaknesses (root/jailbreak detection, runtime integrity), not this one.

So: rate MASWE-0017 on what happens on a real device without a lock (Checks A and B). Use hooking to explore and to characterise the enforcement layer (Check C). Do not raise the severity because a hook flips the Boolean, and do not lower it because "it's only bypassable with Frida" when the app does not check at all.

## Secure implementation

The pattern on both platforms has three layers: **detect** the lock with the platform API and re-check it when it matters, **respond** according to a documented policy, and **bind** sensitive keys to platform authentication so the OS enforces the dependency even if the first two are skipped or bypassed.

### Android: check, respond and bind keys

Detection (API 23+), with the complexity check where a stronger lock is wanted:

```kotlin
import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.os.Build

fun hasSecureLock(context: Context): Boolean =
    context.getSystemService(KeyguardManager::class.java)?.isDeviceSecure == true   // PIN, pattern or password

// Optional, API 29+: needs <uses-permission android:name="android.permission.REQUEST_PASSWORD_COMPLEXITY" />
fun lockComplexity(context: Context): Int? =
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q)
        context.getSystemService(DevicePolicyManager::class.java)?.passwordComplexity
    else null   // PASSWORD_COMPLEXITY_NONE / LOW / MEDIUM / HIGH
```

Re-check whenever the app comes to the foreground, not just at onboarding:

```kotlin
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner

class LockPolicyObserver(
    private val context: Context,
    private val onLockMissing: () -> Unit
) : DefaultLifecycleObserver {
    override fun onStart(owner: LifecycleOwner) {
        if (!hasSecureLock(context)) onLockMissing()   // lock sensitive UI, drop in-memory secrets
    }
}

// In Application.onCreate():
// ProcessLifecycleOwner.get().lifecycle.addObserver(LockPolicyObserver(this) { session.lockDown() })
```

Bind the key so the Keystore enforces the lock. Generation fails on a device without one — that failure is your enforcement, so do not catch it and retry without the restriction:

```kotlin
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import javax.crypto.KeyGenerator

fun createAuthBoundKey(alias: String) {
    val builder = KeyGenParameterSpec.Builder(
        alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    )
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setKeySize(256)
        .setUserAuthenticationRequired(true)

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        // 0 = authenticate every operation via BiometricPrompt.CryptoObject
        builder.setUserAuthenticationParameters(
            0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
        )
    } else {
        @Suppress("DEPRECATION")
        builder.setUserAuthenticationValidityDurationSeconds(30)
    }
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        builder.setUnlockedDeviceRequired(true)
    }

    KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
        init(builder.build())   // throws if there is no secure lock screen
        generateKey()
    }
}
```

Handle invalidation as "re-enrol", not as an error to work around:

```kotlin
import android.security.keystore.KeyPermanentlyInvalidatedException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.SecretKey

sealed interface CipherResult {
    data class Ready(val cipher: Cipher) : CipherResult
    object ReEnrolRequired : CipherResult
}

fun encryptCipher(alias: String): CipherResult {
    val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val key = ks.getKey(alias, null) as? SecretKey ?: return CipherResult.ReEnrolRequired
    return try {
        CipherResult.Ready(Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key) })
    } catch (e: KeyPermanentlyInvalidatedException) {
        ks.deleteEntry(alias)          // lock removed (or, for biometric-only keys, a new biometric enrolled)
        CipherResult.ReEnrolRequired   // caller wipes data under this key and restarts enrolment
    }
}
// Ready.cipher is then passed to BiometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher)).
```

The `BiometricPrompt` side, including `setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)` and the API-level caveats, is in our [MASTG-KNOW-0001 note](/mobile/mastg-know-0001-biometric-authentication/).

Send the user to the right settings screen when the lock is missing:

```kotlin
import android.app.Activity
import android.content.Intent
import android.provider.Settings

fun openLockScreenSettings(activity: Activity) {
    val intent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
        Intent(DevicePolicyManager.ACTION_SET_NEW_PASSWORD)
            .putExtra(DevicePolicyManager.EXTRA_PASSWORD_COMPLEXITY, DevicePolicyManager.PASSWORD_COMPLEXITY_MEDIUM)
    } else {
        Intent(Settings.ACTION_SECURITY_SETTINGS)
    }
    activity.startActivity(intent)
}
```

`EXTRA_PASSWORD_COMPLEXITY` is honoured only if the app holds `REQUEST_PASSWORD_COMPLEXITY`. For a backend that needs proof, generate the auth-bound key with `setAttestationChallenge(serverChallenge)` and have the server check the attestation record's `noAuthRequired` (must be absent), `userAuthType` and `unlockedDeviceRequired` fields alongside the checks described in [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/).

### iOS: check, respond and bind items

Detection with the error code inspected, so "no passcode" is distinguishable from other failures:

```swift
import LocalAuthentication

enum PasscodeState { case set, notSet, unknown(Int) }

func passcodeState() -> PasscodeState {
    let context = LAContext()                     // fresh context for every check
    var error: NSError?
    if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) { return .set }
    guard let error, error.domain == LAErrorDomain else { return .unknown(0) }
    return error.code == LAError.Code.passcodeNotSet.rawValue ? .notSet : .unknown(error.code)
}
```

The Keychain probe as a cross-check (foreground only — it also fails while the device is locked):

```swift
import Security

func passcodeSetViaKeychain() -> Bool {
    let base: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "com.example.app.passcode-probe",
        kSecAttrAccount as String: "probe"
    ]
    SecItemDelete(base as CFDictionary)
    var add = base
    add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
    add[kSecValueData as String] = Data([0x01])
    let status = SecItemAdd(add as CFDictionary, nil)
    SecItemDelete(base as CFDictionary)
    return status == errSecSuccess
}
```

Re-check on every return to the foreground (UIKit shown; in SwiftUI, react to `scenePhase` becoming `.active`):

```swift
import UIKit

final class LockPolicyMonitor {
    private var token: NSObjectProtocol?

    func start(onPasscodeMissing: @escaping () -> Void) {
        token = NotificationCenter.default.addObserver(
            forName: UIApplication.willEnterForegroundNotification, object: nil, queue: .main
        ) { _ in
            if case .notSet = passcodeState() { onPasscodeMissing() }
        }
    }
}
```

Bind the secret to the passcode and to user presence. The add fails without a passcode, and the item is deleted if the passcode is removed later:

```swift
enum VaultError: Error { case status(OSStatus), missing }

private let vaultService = "com.example.app.vault"

func storeSecret(_ secret: Data, account: String) throws {
    var cfError: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
        .userPresence,                         // or .biometryCurrentSet for biometric-only
        &cfError
    ) else { throw cfError!.takeRetainedValue() as Error }

    let base: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: vaultService,
        kSecAttrAccount as String: account
    ]
    SecItemDelete(base as CFDictionary)
    var add = base
    add[kSecAttrAccessControl as String] = access
    add[kSecValueData as String] = secret
    let status = SecItemAdd(add as CFDictionary, nil)
    // No passcode: this fails. Do NOT retry with kSecAttrAccessibleWhenUnlocked or similar.
    guard status == errSecSuccess else { throw VaultError.status(status) }
}

func readSecret(account: String, reason: String) throws -> Data {
    let context = LAContext()
    context.localizedReason = reason
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: vaultService,
        kSecAttrAccount as String: account,
        kSecReturnData as String: true,
        kSecUseAuthenticationContext as String: context
    ]
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    switch status {
    case errSecSuccess:
        guard let data = item as? Data else { throw VaultError.missing }
        return data
    case errSecItemNotFound:
        throw VaultError.missing            // e.g. passcode was turned off: wipe local state, re-enrol
    default:
        throw VaultError.status(status)
    }
}
```

For signing keys, the Secure Enclave equivalent is `SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, [.privateKeyUsage, .userPresence], &error)` passed to `SecKeyCreateRandomKey` or `SecureEnclave.P256.Signing.PrivateKey(accessControl:)`; full code is in [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/). Leaving out the user-presence flag gives you a key that is hardware-protected but usable by anyone holding the unlocked phone.

There is no public URL that opens the passcode screen in Settings. `UIApplication.openSettingsURLString` opens the app's own settings page, and private `App-prefs:` URLs risk App Review rejection, so tell the user where to go ("Settings > Face ID & Passcode") rather than deep-linking.

### Choosing a response: warn, degrade or refuse

There is no universally right answer; pick per feature and document it, so the tester can verify it and the user can understand it.

| Response | What it means | Fits |
|---|---|---|
| **Warn** | Explain the risk once per session (not once per install) and continue | L1 apps; low-sensitivity features in L2 apps |
| **Degrade** | Keep the app usable but keep nothing valuable on the device: no "remember me", no offline cache of sensitive data, short server sessions, step-up (OTP, re-login) for each sensitive action, no biometric login | Most L2 apps: banking read-only views, health records viewing, enterprise email with server-side policy |
| **Refuse** | Do not enable the feature, or the app, until a lock is set; explain why and how | Credential wallets (EUDIW), transaction signing and payment approval, apps holding long-term private keys, high-assurance enterprise apps |

Rules that apply whichever you choose:

- Decide at the **feature** level. A banking app can let the user see branch opening hours without a lock and still refuse to provision a payment card.
- Make the decision **server-visible** for high-risk features: report the lock state (and, on Android, the auth-bound key's attestation) to the backend so it can apply the same policy and so a modified client cannot simply skip it.
- On loss of the lock, **remove** rather than hide: wipe tokens and cached data, delete keys, and require re-enrolment.
- Never let the fallback be a weaker key or Keychain class "so that it still works".

### UX and regulatory considerations

The user did not choose to have no lock for no reason; often it is convenience, sometimes accessibility, occasionally a corporate device with a managed policy that the app should defer to. Good practice:

- Say what is at risk in plain language ("Anyone who picks up your phone could open your wallet"), not "Device not secure".
- Offer the fix in one tap on Android (`ACTION_SET_NEW_PASSWORD`) and clear directions on iOS.
- Re-evaluate automatically when the app returns to the foreground so the user does not have to restart it after setting a PIN.
- Do not nag on every launch for warn-only features; once per session is enough.
- Do not ship a check that blocks users with a PIN but no fingerprint (the biometric-only proxy).

The regulatory angle depends on the sector. For identity wallets, the EUDI Wallet framework under Regulation (EU) 2024/1183 and its Architecture and Reference Framework expect the wallet to authenticate the user before person identification data or attestations are used and to protect the wallet's keys in a secure cryptographic device or application; a wallet that uses the platform keystore for user binding cannot meet that on a device with no credential, which is why "refuse" is the norm there (check the current ARF and implementing acts for the exact wording). For UK and EU payments, strong customer authentication under the SCA regulatory technical standards (Commission Delegated Regulation (EU) 2018/389 and the FCA's UK version) commonly uses a device-bound key as the possession element and the device biometric or PIN as the inherence or knowledge element; Article 9 requires mitigating measures where the elements share a multi-purpose device, and a phone with no lock makes "possession" mean "whoever is holding it". More generally, UK GDPR Article 32 asks for security appropriate to the risk, and an app that knowingly stores special-category data on unprotected devices without telling the user is hard to defend. None of this makes MASWE-0017 a legal finding; it is context for the rating.

## Rating findings

Rate on the app's profile (L1, L2, EUDIW), what the absent lock exposes, and whether the platform enforces the dependency anyway. Use these as starting points.

| Rating | Conditions |
|---|---|
| **Critical** | A high-assurance credential or approval function — identity wallet presentation, transaction signing, payment approval, long-term private key — is enabled on a device with no lock, and its key is not bound to user authentication, so anyone holding the phone can present the credential or approve the transaction with no user verification at all. |
| **High** | An L2 or EUDIW app performs no lock check and stores credentials, long-lived tokens or keys whose design relies on the device credential (CE storage, `NSFileProtectionComplete`, "protected by Face ID" marketing). Also: the stale-assumption case where removing the lock leaves protected features working, and the silent-downgrade case where a failed auth-bound key or `WhenPasscodeSet` item is recreated without the restriction. |
| **Medium** | The app checks but only warns, for features that hold sensitive data on the device; the check runs once at onboarding and never again, but the keys are auth-bound so the impact is limited to what is cached outside them; the check is made only by an SDK and the result is not used. |
| **Low** | The app uses a proxy check (`canAuthenticate(BIOMETRIC_STRONG)` alone, `.deviceOwnerAuthenticationWithBiometrics` alone, `isKeyguardSecure()`), passes `nil` for the `LAContext` error, or caches the lock state — conservative or nearly correct, but brittle. No re-check on foreground where the platform enforces the dependency through auth-bound keys. |
| **Info** | L1 apps with no sensitive local data and no lock check (outside the weakness's profiles — mention it as a recommendation). Apps with no explicit check but complete platform enforcement (every sensitive key auth-bound, failures handled), which fail OWASP's reference test but meet the requirement's intent. The check being bypassable with Frida, on its own. |

When you report, state the profile you assessed against, the device state you tested (lock set, lock removed, lock removed after enrolment), what the app did in each, the call sites of the detection API (or their absence), and the configuration of the keys or Keychain items that protect the data. A one-line reproduction — "on a device with no PIN, install, log in, enable quick login: the refresh token is stored in a non-auth-bound key and the app opens without prompting" — makes the rating self-explanatory.

## References

- OWASP MASWE — [MASWE-0017: Device Secure Lock Not Enforced](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0017/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0001: Biometric Authentication](https://mas.owasp.org/MASTG/knowledge/android/MASVS-AUTH/MASTG-KNOW-0001/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0056: Local Authentication Framework](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-AUTH/MASTG-KNOW-0056/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0247: References to APIs for Detecting Secure Screen Lock (Android)](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0247/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0249: Runtime Use of Secure Screen Lock Detection APIs (Android)](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0249/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0248: References to APIs for Detecting Secure Screen Lock (iOS)](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0248/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0246: Runtime Use of Secure Screen Lock Detection APIs (iOS)](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0246/) (CC BY-SA 4.0)
- OWASP MASTG — legacy (MASTG v1) [MASTG-TEST-0012: Testing the Device-Access-Security Policy](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0012/) (CC BY-SA 4.0)
- OWASP MASTG — demos [MASTG-DEMO-0024](https://mas.owasp.org/MASTG/demos/ios/MASVS-RESILIENCE/MASTG-DEMO-0024/MASTG-DEMO-0024/), [MASTG-DEMO-0026](https://mas.owasp.org/MASTG/demos/ios/MASVS-RESILIENCE/MASTG-DEMO-0026/MASTG-DEMO-0026/), [MASTG-DEMO-0027](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0027/MASTG-DEMO-0027/), [MASTG-DEMO-0028](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0028/MASTG-DEMO-0028/) (CC BY-SA 4.0)
- OWASP MASTG — techniques [MASTG-TECH-0005](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/), [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/), [MASTG-TECH-0056](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0056/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0090](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0090/), [MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/); tools [Frida for Android (MASTG-TOOL-0001)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0001/), [Frida for iOS (MASTG-TOOL-0039)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/), [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/), [radare2 (MASTG-TOOL-0073)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/), [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [objection (MASTG-TOOL-0038)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0038/) (CC BY-SA 4.0)
- OWASP — [MAS Profiles](https://mas.owasp.org/Profiles/) (CC BY-SA 4.0)
- [Android Developers — `KeyguardManager`](https://developer.android.com/reference/android/app/KeyguardManager) (`isDeviceSecure()`, `isKeyguardSecure()`, `isDeviceLocked()`)
- [Android Developers — `BiometricManager`](https://developer.android.com/reference/android/hardware/biometrics/BiometricManager) and [`androidx.biometric.BiometricManager`](https://developer.android.com/reference/androidx/biometric/BiometricManager)
- [Android Developers — `KeyGenParameterSpec.Builder`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder) and [`KeyPermanentlyInvalidatedException`](https://developer.android.com/reference/android/security/keystore/KeyPermanentlyInvalidatedException)
- [Android Developers — `DevicePolicyManager`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager) (`getPasswordComplexity()`, `ACTION_SET_NEW_PASSWORD`) and [Device administration deprecation](https://developers.google.com/android/work/device-admin-deprecation)
- [Android Developers — Android Keystore system](https://developer.android.com/privacy-and-security/keystore) and [Verifying hardware-backed key pairs with key attestation](https://developer.android.com/privacy-and-security/security-key-attestation)
- [AOSP — File-based encryption](https://source.android.com/docs/security/features/encryption/file-based) and [Direct Boot](https://developer.android.com/privacy-and-security/direct-boot)
- [Apple — LocalAuthentication](https://developer.apple.com/documentation/localauthentication), [`LAContext.canEvaluatePolicy(_:error:)`](https://developer.apple.com/documentation/localauthentication/lacontext/canevaluatepolicy%28_:error:%29), [`LAPolicy.deviceOwnerAuthentication`](https://developer.apple.com/documentation/localauthentication/lapolicy/deviceownerauthentication), [`LAError.Code`](https://developer.apple.com/documentation/localauthentication/laerror/code)
- [Apple — Logging a user into your app with Face ID or Touch ID](https://developer.apple.com/documentation/localauthentication/logging_a_user_into_your_app_with_face_id_or_touch_id) and [Accessing Keychain items with Face ID or Touch ID](https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id)
- [Apple — `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`](https://developer.apple.com/documentation/security/ksecattraccessiblewhenpasscodesetthisdeviceonly) and [`SecAccessControlCreateFlags`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags)
- [Apple Platform Security Guide — Data Protection overview](https://support.apple.com/guide/security/data-protection-overview-secf6276da8a/web), [Data Protection classes](https://support.apple.com/guide/security/data-protection-classes-secb010e978a/web) and [Keychain data protection](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [Regulation (EU) 2024/1183 (European Digital Identity Framework)](https://eur-lex.europa.eu/eli/reg/2024/1183/oj) and the [EUDI Wallet Architecture and Reference Framework](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework)
- [Commission Delegated Regulation (EU) 2018/389 — RTS on strong customer authentication](https://eur-lex.europa.eu/eli/reg_del/2018/389/oj)
- [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html) and [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
