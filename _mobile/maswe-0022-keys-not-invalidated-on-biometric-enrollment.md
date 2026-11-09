---
title: "Crypto Keys Not Invalidated on New Biometric Enrollment (MASWE-0022)"
date: 2026-11-09 08:34:00 +0000
subcategory: auth
summary: "Why biometric keys must die when someone enrols a new finger or face: Android and iOS invalidation, domain state, safe recovery and device tests."
refs: [MASWE-0022, MASVS-AUTH-2, MASVS-CRYPTO-2, CWE-287, CWE-522]
tags: [android, ios, masvs-auth, biometrics, keystore, keychain]
---

This note is part of our [MASVS-AUTH guide](/mobile/masvs-auth-authentication-guide/) and covers OWASP [MASWE-0022](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0022/): keys and Keychain items protected by biometrics that stay usable after someone adds a new fingerprint or face to the device. The attack it describes is low-tech and realistic. Somebody who knows the victim's passcode — a partner, a flatmate, a thief who watched them unlock the phone — opens Settings, enrols their own finger or an "alternate appearance", and from then on passes every biometric prompt in the victim's banking or wallet app with their own body. Platform invalidation exists precisely to stop this; whether it applies depends on details of the key configuration that are easy to get wrong, and on what the app does when a key is invalidated. Below you will find the invalidation semantics on Android (including where `setInvalidatedByBiometricEnrollment` does *not* apply) and iOS, what `evaluatedPolicyDomainState` and `domainState` do and do not prove, the three OWASP tests with their demos, the device procedure that settles the question — enrol a new biometric and try the protected action — a recovery and backend test, secure Kotlin and Swift, and severity guidance.

> **Note:** OWASP links three tests and one best practice to MASWE-0022: [MASTG-TEST-0328](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0328/) (Android, static), [MASTG-TEST-0270](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0270/) (iOS, static), [MASTG-TEST-0271](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0271/) (iOS, dynamic) and [MASTG-BEST-0037](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0037/). The weakness page links no Knowledge page; the tests refer to MASTG-KNOW-0001 and MASTG-KNOW-0056. We summarise those, add **supplementary** Knowledge, and add three tests labelled **Guler Tech methodology**, two of which are the hands-on enrolment procedure the OWASP tests do not include.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: Biometric Authentication (MASTG-KNOW-0001)](#android-biometric-authentication-mastg-know-0001)
  - [Android: when enrolment invalidates a key](#android-when-enrolment-invalidates-a-key)
  - [Android: KeyPermanentlyInvalidatedException and re-enrolment](#android-keypermanentlyinvalidatedexception-and-re-enrolment)
  - [iOS: Local Authentication Framework and domain state (MASTG-KNOW-0056)](#ios-local-authentication-framework-and-domain-state-mastg-know-0056)
  - [iOS: biometryCurrentSet versus biometryAny (MASTG-KNOW-0057)](#ios-biometrycurrentset-versus-biometryany-mastg-know-0057)
  - [Both platforms: the attacker who knows the passcode](#both-platforms-the-attacker-who-knows-the-passcode)
- [Tests](#tests)
  - [MASTG-TEST-0328 (Android, static)](#mastg-test-0328-references-to-apis-detecting-biometric-enrollment-changes-android)
  - [MASTG-TEST-0270 (iOS, static)](#mastg-test-0270-references-to-apis-detecting-biometric-enrollment-changes-ios)
  - [MASTG-TEST-0271 (iOS, dynamic)](#mastg-test-0271-runtime-use-of-apis-detecting-biometric-enrollment-changes-ios)
  - [GT-0022-1: Enrolling a new biometric on a test device (Android)](#gt-0022-1-enrolling-a-new-biometric-on-a-test-device-android)
  - [GT-0022-2: Enrolling a new biometric on a test device (iOS)](#gt-0022-2-enrolling-a-new-biometric-on-a-test-device-ios)
  - [GT-0022-3: Invalidation recovery and re-enrolment (Android, iOS, backend)](#gt-0022-3-invalidation-recovery-and-re-enrolment-android-ios-backend)
- [Best practices](#best-practices)
  - [MASTG-BEST-0037: Invalidate Biometric Keys on Enrollment Changes (Android)](#mastg-best-0037-invalidate-biometric-keys-on-enrollment-changes-android)
  - [iOS counterpart: current-set access control with safe recovery (Guler Tech)](#ios-counterpart-current-set-access-control-with-safe-recovery-guler-tech)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

The OWASP requirement is *"The app invalidates keys after any enrollment of new biometric data."* A biometric-bound key is meant to be usable only by the person whose biometrics were enrolled when it was created. The platform cannot know *whose* finger is on the sensor — only whether it matches one of the enrolled templates — so if the set of templates grows, the set of people who can use the key grows with it. Invalidation on enrolment change closes that gap: the key is destroyed (Android) or becomes inaccessible (iOS) the moment the enrolled set changes, and the app has to establish the user's identity again by some other means before it creates a new one.

The defaults differ between the platforms, and that drives most of what you will find:

| | Android Keystore | iOS Keychain / Secure Enclave |
|---|---|---|
| Mechanism | `KeyGenParameterSpec.Builder.setInvalidatedByBiometricEnrollment(boolean)` | `SecAccessControlCreateFlags.biometryCurrentSet` (formerly `touchIDCurrentSet`) instead of `.biometryAny` |
| Default | **On** — but only for keys that require authentication per operation with biometrics only | **Off** — the developer has to choose `.biometryCurrentSet` |
| What triggers it | A new biometric enrolled, or all biometrics removed | Any change to the enrolled set: a finger added or removed, Face ID reset and re-enrolled, an alternate appearance added |
| Failure seen by the app | `KeyPermanentlyInvalidatedException` when the key is initialised for use | The Keychain read or key operation fails |
| How the app detects it in advance | No public API; only by the key failing | `LAContext.evaluatedPolicyDomainState` (deprecated in iOS 18) or `domainState.biometry.stateHash` |

**The attack, step by step.** OWASP's attack for this weakness is MAS-ATTACK-0035, *"Enrolling additional biometrics on the device after obtaining the device credential"*, and the threat MAS-THREAT-0022, *"Attackers can use biometric-protected keys without the legitimate user's biometrics."* In practice:

1. The attacker learns the device passcode — by watching, guessing, or because they share a home with the victim.
2. They get the phone for a minute, unlock it with the passcode, and add their fingerprint (Settings > Security > Fingerprint on Android; Settings > Touch ID & Passcode > Add a Fingerprint, or Face ID & Passcode > Set Up an Alternate Appearance on iOS). Both platforms ask for the passcode, which the attacker has.
3. They hand the phone back. Neither platform makes the extra biometric obvious to the owner.
4. Later — even after the victim changes the passcode, which does not remove enrolled biometrics — the attacker unlocks the phone with their own finger or face and approves transactions in the victim's app, which accepts any enrolled biometric.

**How it relates to MASWE-0021 and MASWE-0020.** If the app also accepts the device passcode for the same operation ([MASWE-0021](/mobile/maswe-0021-non-biometric-fallback-for-sensitive-transactions/)), the attacker does not need step 2 at all, and enrolment invalidation adds nothing; fix the fallback first and rate the two together. If the flow is event-bound — a prompt with no key behind it, which our [MASWE-0020 note](/mobile/maswe-0020-local-authentication-bypass/) covers — there is nothing to invalidate: any enrolled biometric passes the prompt by design. Invalidation is only meaningful for crypto-bound, biometric-only flows, which is exactly the configuration L2 apps should have.

**Detection is not invalidation.** OWASP's test titles say "APIs Detecting Biometric Enrollment Changes", and iOS does offer a detection API (the domain state). But detection in app code is an `if` statement that an attacker with instrumentation can flip, and it only helps if the app then does the right thing. Invalidation is enforced by the Keystore or the Secure Enclave: the key is unusable whatever the app does. The tests look for invalidation; detection is a useful UX signal on top.

**Profiles and mappings.** MASWE-0022 is tagged L2 and EUDIW: invalidation matters where biometrics protect high-value operations or identity credentials, not for a note-taking app's lock screen. It maps to MASVS-AUTH-2 (local authentication according to platform best practices) and MASVS-CRYPTO-2 (key management), to [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html) and [CWE-522: Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html), and was numbered MASWE-0046 in the beta catalogue.

**What you can prove from the client, and what you cannot.** On the device you can prove whether a newly enrolled biometric unlocks the key or completes the transaction — that is a clean, reproducible result. What happens *after* invalidation is partly a backend question: whether the server stops accepting the old key, what it demands before it registers a new one, and whether it tells the user. Android key attestation does not report enrolment invalidation (the attestation authorisation list has no field for it), and iOS has no key attestation for third-party keys, so the server cannot verify this property; it can only make re-enrolment hard to abuse. Our [GT-0022-3](#gt-0022-3-invalidation-recovery-and-re-enrolment-android-ios-backend) covers that side.

## Modes of Introduction

OWASP lists three:

- **Invalidation disabled on Android.** Keys created with `setInvalidatedByBiometricEnrollment(false)` remain usable after new biometrics are enrolled.
- **Invalidation not enabled on iOS.** Keychain items or keys protected with `.biometryAny` (or `.userPresence`) rather than `.biometryCurrentSet`, so any biometric enrolled later can unlock them.
- **Unsafe invalidation recovery.** The app silently re-creates an invalidated key, or falls back to weaker authentication, instead of re-verifying the user's identity first.

Variants we see that are easy to miss:

- **Invalidation that never applied.** On Android the flag only affects keys that require authentication for every operation with biometrics only. A key with a validity window (`setUserAuthenticationParameters(300, …)`), a key that also accepts the device credential (`AUTH_BIOMETRIC_STRONG or AUTH_DEVICE_CREDENTIAL`), or a key built with the deprecated `setUserAuthenticationValidityDurationSeconds` and any value other than `-1` is not invalidated by enrolment — even though the code never says `false`, so MASTG-TEST-0328 passes it.
- **The passcode branch on iOS.** `[.biometryCurrentSet, .or, .devicePasscode]`: the biometric branch is invalidated, the passcode branch is not, so the item stays reachable — the MASWE-0021 problem in disguise.
- **Detection only.** The app compares `evaluatedPolicyDomainState` with a stored value and shows "Your Face ID settings have changed" — then lets the user carry on after a new biometric prompt, which the attacker passes.
- **Re-enable with biometrics.** After invalidation the app says "Re-enable Face ID?", shows a biometric prompt (passed by the attacker's new face) and registers a new key with the server using the existing session token. The platform did its job; the app undid it.
- **The secret already escaped.** The biometric-bound key decrypts a refresh token once, and the app caches the plaintext token in preferences or the Keychain without access control. Invalidating the key later protects nothing.
- **Framework options.** `react-native-keychain` exposes `BIOMETRY_ANY` and `BIOMETRY_CURRENT_SET` (and their `_OR_DEVICE_PASSCODE` variants); other plugins hard-code one. Check which the app passes, and which the plugin version actually maps it to.

## Impact

- **Authentication or authorisation bypass.** The attacker passes biometric prompts with their own enrolled biometric and approves payments, presentations or signatures bound to the victim's identity.
- **Compromise of sensitive data.** Data encrypted under biometric-bound keys — tokens, health records, wallet credentials — is decrypted for the attacker.
- **Persistence.** The extra biometric survives passcode changes. Until the victim notices it, the attacker keeps access, and every approval carries a valid device-key signature that fraud monitoring sees as the genuine customer.
- **Liability and non-repudiation.** If an attacker-enrolled finger can approve transactions, the bank cannot credibly argue that a biometric approval proves the customer's consent, and the customer cannot prove it was not theirs.

## Mitigations

- **Keep enrolment invalidation enabled on Android**: never call `setInvalidatedByBiometricEnrollment(false)` for keys that protect sensitive data or operations, and make those keys per-operation and biometric-only (`setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)`) so the default actually applies.
- **Enable enrolment invalidation on iOS**: create access control with `.biometryCurrentSet` (plus `.privateKeyUsage` for Secure Enclave keys), not `.biometryAny`, `.userPresence` or an `.or` with `.devicePasscode`.
- **Handle invalidation safely**: on `KeyPermanentlyInvalidatedException` or an inaccessible current-set item, delete the key, tell the server to stop accepting it, and require full re-authentication with account credentials (a server-verified flow, for example password plus a one-time code) before creating and registering a new key. Never re-enable biometrics with only a biometric prompt or the existing session, and never fall back to a weaker key.
- **Tell the user**: notify on another channel (email, push to other devices) when biometric approval is re-enabled, so a victim learns that their phone's biometrics changed.
- **Do not let the secret escape**: keep data encrypted under the biometric-bound key and decrypt per use; anything cached outside it is not protected by invalidation.

## Knowledge

The OWASP tests refer to MASTG-KNOW-0001 (Android biometrics) and MASTG-KNOW-0056 (iOS LocalAuthentication). We summarise them as they apply to enrolment changes and add supplementary sections on invalidation semantics, recovery and the attacker model. General key restrictions are in our [MASWE-0016 note](/mobile/maswe-0016-key-access-not-restricted/), and the iOS LocalAuthentication API surface in our [MASWE-0017 note](/mobile/maswe-0017-device-secure-lock-not-enforced/#ios-local-authentication-framework-mastg-know-0056); we link rather than repeat.

### Android: Biometric Authentication (MASTG-KNOW-0001)

Source: [MASTG-KNOW-0001](https://mas.owasp.org/MASTG/knowledge/android/MASVS-AUTH/MASTG-KNOW-0001/); our full treatment is in [Android Biometric Authentication (MASTG-KNOW-0001)](/mobile/mastg-know-0001-biometric-authentication/). For this weakness:

- Keystore-backed authentication — a key generated with `setUserAuthenticationRequired(true)` and used through `BiometricPrompt.CryptoObject` — is the only flow in which invalidation can do anything. A prompt without a key accepts whatever biometrics are enrolled at the time.
- `setUserAuthenticationParameters(timeout, type)` (API 30) replaces the deprecated `setUserAuthenticationValidityDurationSeconds(int)`; a timeout of `0` means per-operation authentication.
- The OWASP page states the rule in one sentence: when a key only supports biometric credentials, it is invalidated by default when new biometrics are enrolled, and `setInvalidatedByBiometricEnrollment(boolean)` controls this.
- Only Class 3 (`BIOMETRIC_STRONG`) biometrics can authorise Keystore keys.

### Android: when enrolment invalidates a key

Supplementary, from the `KeyGenParameterSpec.Builder` and `KeyPermanentlyInvalidatedException` reference pages.

The Android documentation for `setInvalidatedByBiometricEnrollment(boolean)` says, in substance: the setting applies only to keys that require user authentication and have no positive validity duration — keys "valid for biometric authentication only". By default (`true`) such keys are irreversibly invalidated when a new biometric is enrolled or when all existing biometrics are deleted; passing `false` keeps them valid. The stated purpose is exactly the attack above: an unauthorised person who obtains the password cannot gain the use of biometric-authenticated keys by enrolling their own biometric.

Read the conditions carefully, because they define what a test has to check:

| Key configuration | New biometric enrolled | All biometrics removed | Secure lock screen removed |
|---|---|---|---|
| `setUserAuthenticationRequired(true)`, per-operation, `AUTH_BIOMETRIC_STRONG` only, flag default or `true` | **Invalidated** | **Invalidated** | Invalidated |
| Same, with `setInvalidatedByBiometricEnrollment(false)` | Still valid | Not invalidated by this mechanism | Invalidated |
| Per-operation, `AUTH_BIOMETRIC_STRONG or AUTH_DEVICE_CREDENTIAL` | Not invalidated — the flag does not apply | Not invalidated | Invalidated |
| Time-bound (timeout `> 0`), any authenticator type | Not invalidated — the flag does not apply | Not invalidated | Invalidated |
| Deprecated `setUserAuthenticationValidityDurationSeconds(-1)` | Invalidated (equivalent to row 1) | Invalidated | Invalidated |
| Deprecated `setUserAuthenticationValidityDurationSeconds(n)`, `n >= 0` | Not invalidated | Not invalidated | Invalidated |
| `setUserAuthenticationRequired(false)` | Not applicable — the key needs no authentication at all (MASWE-0016) | — | Not affected |

Rows 3, 4 and 6 follow from the documented condition ("valid for biometric authentication only") rather than from an explicit sentence in the reference, and the behaviour is implemented by the Keystore rather than by the app. Confirm them on a test device with [GT-0022-1](#gt-0022-1-enrolling-a-new-biometric-on-a-test-device-android) before you rely on them in a report. In AOSP the mechanism works through the identifiers a key is bound to: a biometric-only key with invalidation enabled is bound to the biometric sensor's current authenticator identifier, which changes on enrolment, while keys that accept the device credential are also bound to the lock-screen credential's identifier, which does not. That is why credential-accepting keys survive enrolment changes.

Other details that matter in testing:

- **Removing one of several fingerprints** does not trigger invalidation according to the documentation (only "new biometric enrolled" and "all biometrics deleted" do). That differs from iOS, where any change to the set counts.
- **Creating** a per-operation biometric-only key requires at least one enrolled Class 3 biometric; key generation fails otherwise. Apps sometimes "fix" that failure by retrying with a configuration that accepts the device credential — check the `catch` block.
- **Class 2 enrolments.** Only Class 3 biometrics can authorise keys; enrolling a Class 2 face does not give access to a biometric-only key, so on devices with Class 2 face unlock the attacker needs to add a fingerprint.
- **`KeyInfo.isInvalidatedByBiometricEnrollment()`** reports the setting for an existing key (obtain `KeyInfo` as shown in our [MASWE-0016 note](/mobile/maswe-0016-key-access-not-restricted/#android-verifying-restrictions-with-keyinfo-and-attestation-mastg-know-0044)). Treat it as indicative: read it together with `getUserAuthenticationValidityDurationSeconds()` and `getUserAuthenticationType()` to decide whether invalidation can apply, and confirm with the enrolment test.
- **No pre-check API.** Android has no public equivalent of iOS's domain state. Apps that want to tell the user "your fingerprints changed" before a transaction sometimes keep a small biometric-only "canary" key and try to initialise a `Cipher` with it; `KeyPermanentlyInvalidatedException` means the enrolled set changed. That is detection for UX, not a control.
- **Platform theft protections.** Android 15 introduced Identity Check on supported devices, which requires biometric authentication for some sensitive system settings when the device is away from trusted places. Which settings it covers depends on the device and version, it may not be enabled, and at home it does not apply — the app cannot rely on it.

### Android: KeyPermanentlyInvalidatedException and re-enrolment

Supplementary. [`KeyPermanentlyInvalidatedException`](https://developer.android.com/reference/android/security/keystore/KeyPermanentlyInvalidatedException) is a subclass of `InvalidKeyException`. When a key has been invalidated:

- `KeyStore.getKey(alias, null)` still returns the key object — the entry exists until the app deletes it;
- `Cipher.init`, `Signature.initSign` or `Mac.init` throws `KeyPermanentlyInvalidatedException`, so the failure happens **before** the `BiometricPrompt` is shown (apps normally initialise the crypto object first and pass it to the prompt);
- the key can never be used again; the only way forward is `KeyStore.deleteEntry(alias)` and a new key.

OWASP's best practice notes that invalidation is immediate and permanent and that the app must handle the exception and guide the user to re-authenticate before a new key is created. What "re-authenticate" means is the security decision:

| Recovery after invalidation | Verdict |
|---|---|
| Delete the key, discard data encrypted under it, revoke the key on the server, require login with account credentials and a server-verified second factor, then create and register a new key; notify the user on another channel | **Safe.** The attacker who enrolled a finger is stopped at the account login. |
| Delete the key and require the account password only | Acceptable for moderate risk; weaker if the password is stored on the device or autofilled |
| Show a biometric prompt "to re-enable", then create a new key and register it with the existing session | **Unsafe.** The attacker's new finger passes the prompt; invalidation achieved nothing. |
| Catch the exception and create a new key silently | **Unsafe.** Same outcome without even a prompt. |
| Catch the exception and fall back to a device-credential prompt or a key without authentication | **Unsafe.** MASWE-0021 or MASWE-0016 on top. |
| Crash, or loop on an error message | Not a security failure, but a support problem that tempts developers into the unsafe options |

Note that every auth-bound key is also invalidated when the user removes the secure lock screen ([MASWE-0017](/mobile/maswe-0017-device-secure-lock-not-enforced/)); the same recovery path should handle both causes.

### iOS: Local Authentication Framework and domain state (MASTG-KNOW-0056)

Source: [MASTG-KNOW-0056](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-AUTH/MASTG-KNOW-0056/). The policies, errors and context properties are described in our [MASWE-0017 note](/mobile/maswe-0017-device-secure-lock-not-enforced/#evaluatepolicy-biometrytype-and-evaluatedpolicydomainstate). For enrolment changes, one property matters.

**`LAContext.evaluatedPolicyDomainState`** is an opaque `Data` value describing the current set of enrolled biometrics. It is populated only after `canEvaluatePolicy` has succeeded for a biometric policy, or after a successful biometric `evaluatePolicy`; otherwise it is `nil`. It is deprecated from iOS 18 in favour of `LAContext.domainState` (an `LADomainState`), whose `biometry.stateHash` plays the same role. Apps store the value when the user enables biometrics and compare it later; a different value means the enrolled set has changed since.

What a domain-state comparison **does** tell the app:

- that fingers were added or removed, or Face ID was re-enrolled (and, as far as we can tell from Apple's description, that an alternate appearance was added), since the stored value was taken.

What it does **not** tell the app, and why you should not accept it as the control:

- **Who.** A changed value says nothing about whether the current user is the account holder. An unchanged value does not prove it either: if the attacker enrolled *before* the app stored its reference, the comparison never fires. The same is true of `.biometryCurrentSet` — both only protect against enrolments after the key or reference was created.
- **Anything about the passcode.** Passcode changes do not alter it.
- **Anything enforced.** The comparison runs in app code. On a jailbroken device, or with a repackaged build, a hook on the getter returns the stored value, or the stored reference is overwritten; and the data the app wants to protect is still available, because nothing cryptographic depends on the comparison. Use it as an early, friendly signal ("Face ID settings changed — please sign in again") in front of a `.biometryCurrentSet` item that enforces the same thing.
- **Equality semantics beyond "same or different".** Treat the value as opaque: compare for equality and nothing else. Store the reference in the Keychain rather than `UserDefaults`, so it is at least not trivially editable in a backup.

### iOS: biometryCurrentSet versus biometryAny (MASTG-KNOW-0057)

Related: [MASTG-KNOW-0057](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-AUTH/MASTG-KNOW-0057/), whose example stores a password with `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` and `.biometryCurrentSet` — the configuration this weakness asks for. The full flag table is in our [MASWE-0016 note](/mobile/maswe-0016-key-access-not-restricted/#ios-access-control-flags-mastg-know-0056-mastg-know-0057).

| Flag (raw bit) | Enrolment change | Notes |
|---|---|---|
| `.biometryCurrentSet` (`0x8`) | Item or key becomes inaccessible | Touch ID: any finger added or removed. Face ID: re-enrolment (Reset Face ID) or an alternate appearance. Named `touchIDCurrentSet` before iOS 11.3. |
| `.biometryAny` (`0x2`) | Survives | Any biometric enrolled now or later unlocks it. Named `touchIDAny` before iOS 11.3. |
| `.userPresence` (`0x1`) | Survives; passcode also accepted | MASWE-0021 as well |
| `[.biometryCurrentSet, .or, .devicePasscode]` (`0x4018`) | Biometric branch invalidated, passcode branch survives | Effectively not invalidated against an attacker who knows the passcode |
| `[.privateKeyUsage, .biometryCurrentSet]` (`0x40000008`) | Secure Enclave key unusable | The recommended form for signing keys |

The legacy (MASTG v1) test [MASTG-TEST-0064](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0064/) put the trade-off fairly: `.biometryAny` is convenient (a user whose fingerprint changes, or who adds a finger, keeps access) but means anyone who manages to enrol their biometrics can access the entries; `.biometryCurrentSet` makes sure only users enrolled when the item was added can unlock it.

**What the app sees after a change.** The item is not deleted; it remains in the Keychain but can no longer be decrypted, because the Secure Enclave will not satisfy its access control. Reading it typically fails with `errSecItemNotFound` (−25300); depending on the iOS version and the kind of query you may see a different error, such as `errSecAuthFailed` (−25293), and for Secure Enclave keys the failure may surface at the signing call rather than the lookup. Robust apps treat "an item I know I stored cannot be read after the user authenticated" as invalidation, delete it (`SecItemDelete` needs no authentication) and start the re-enrolment flow. The same recovery rules as on Android apply: full re-authentication with account credentials before a new item or key is created.

**Stolen Device Protection.** Since iOS 17.3, when Stolen Device Protection is on and the iPhone is away from familiar locations, adding or removing Face ID or Touch ID is subject to a security delay that requires a biometric, an hour's wait and a second biometric. That blunts the thief who learned the passcode. It does not apply at familiar locations — at home, where the partner or flatmate is — and it is the user's setting, not the app's. Disable it on test devices, or test at a familiar location, or the enrolment step of GT-0022-2 will be delayed.

### Both platforms: the attacker who knows the passcode

Supplementary. MASWE-0022 is about one attacker, and it pays to be precise about them when you rate a finding.

**Who they are.** Someone who learned the device credential and can hold the phone for a minute: a partner or family member (the most common case in financial abuse), a flatmate or colleague, a thief who watched the victim unlock the phone before taking it, someone at a repair shop. They do not need malware, a jailbreak or technical skill.

**What they can do without the app's help.** With the passcode they can unlock the phone and use anything the phone itself protects. Whether they can use the *app's* protected operations depends on MASWE-0021 (does the app accept the passcode?) and on this weakness (does the app accept a biometric they enrolled?).

**What enrolment gives them that the passcode does not.** Persistence and stealth. A passcode can be changed by a suspicious victim; an extra fingerprint usually stays unnoticed. Biometric unlocks also do not look suspicious to an onlooker.

**What invalidation buys, and its limits.** With crypto-bound, biometric-only keys that are invalidated on enrolment change, the attacker's enrolment destroys the app's keys. The next time anyone opens the app, it must re-establish identity through account credentials the attacker hopefully does not have. Invalidation does not help against enrolments made *before* the user enabled biometrics in the app, against a coerced victim, or against an app whose recovery flow re-enables biometrics with a biometric prompt. It also costs legitimate users something: anyone who adds a finger or re-enrols Face ID has to sign in again. That cost is small, rare and well understood by users of banking apps, which is why the platforms make it the default (Android) or the documented choice (iOS) for sensitive keys.

## Tests

OWASP maps three tests to MASWE-0022: a static test for Android and a static/dynamic pair for iOS. They establish whether the configuration *should* invalidate keys. The decisive test is physical: enrol a new biometric on a test device and see whether the protected action still works. We add that procedure for each platform, and a recovery test that follows the app (and its backend) through what happens next.

Before you start:

- **Agree which operations are sensitive** with the client. Every OWASP evaluation is worded "for sensitive data resources worth protecting".
- **Dedicate test devices.** You will add and remove biometrics, which invalidates keys for every app on the device. Android: set a known PIN with `adb shell locksettings set-pin 1234`. iOS: a physical device with a passcode and one enrolled biometric; turn off Stolen Device Protection for the test.
- **Have a second biometric available**: another finger, a colleague's finger or face, or the emulator's virtual fingerprint IDs (`adb -e emu finger touch <id>`).
- **Run GT-0022-1/2 last** on a given device, or be ready to re-enable biometrics in the app afterwards: they destroy the keys you are testing.

### MASTG-TEST-0328: References to APIs Detecting Biometric Enrollment Changes (Android)

Source: [MASTG-TEST-0328](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0328/). Platform: Android. Type: static (code). Related: MASTG-KNOW-0001, MASTG-BEST-0037.

#### Overview

The test looks for keys generated with `setInvalidatedByBiometricEnrollment(false)`. With the default (`true`), a key becomes permanently invalidated when a new biometric is enrolled, so only users whose biometrics were enrolled when the key was created can use it. We extend the sweep to the configurations in which the flag never applies, and to the exception handling that decides whether invalidation is effective.

#### Prerequisites

- The APK and split APKs; jadx ([MASTG-TOOL-0018](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/)) and apktool. OWASP's steps are "reverse engineer the app" ([MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), in practice [MASTG-TECH-0017](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0017/) "Decompiling Java Code") and "look for the relevant APIs" ([MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), static analysis with grep and semgrep).
- semgrep ([MASTG-TOOL-0110](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/)).

#### Steps

1. **Decompile.**

   ```bash
   jadx -d out/ base.apk
   apktool d base.apk -o smali_out/
   ```

2. **Run the OWASP rule** `mastg-android-biometric-invalidated-enrollment.yml`:

   ```yaml
   rules:
     - id: mastg-android-biometric-invalidated-enrollment
       languages:
         - java
         - kotlin
       severity: WARNING
       message: "[MASVS-AUTH-2] Key configured with setInvalidatedByBiometricEnrollment(false). For sensitive operations, keys should be invalidated when biometric enrollment changes to prevent unauthorized access by newly enrolled biometrics."
       pattern: $BUILDER.setInvalidatedByBiometricEnrollment(false)
   ```

   ```bash
   semgrep -c mastg-android-biometric-invalidated-enrollment.yml out/sources/ --exclude 'androidx' --text
   ```

3. **Find keys the flag does not protect.** A key without `setInvalidatedByBiometricEnrollment(false)` is not necessarily invalidated. This rule finds the configurations from the [Knowledge table](#android-when-enrolment-invalidates-a-key) where the flag does not apply:

   ```yaml
   rules:
     - id: gt-android-auth-key-not-enrolment-invalidated
       languages: [java]
       severity: WARNING
       message: Auth-bound key that enrolment invalidation cannot apply to (time window or device credential accepted)
       pattern-either:
         - patterns:
             - pattern: $B.setUserAuthenticationParameters($T, $TYPE)
             - metavariable-comparison:
                 metavariable: $T
                 comparison: $T > 0
         - patterns:
             - pattern: $B.setUserAuthenticationParameters($T, $TYPE)
             - metavariable-comparison:
                 metavariable: $TYPE
                 comparison: $TYPE == 1 or $TYPE == 3
         - patterns:
             - pattern: $B.setUserAuthenticationValidityDurationSeconds($S)
             - metavariable-comparison:
                 metavariable: $S
                 comparison: $S >= 0
   ```

   ```bash
   semgrep -c gt-android-enrolment.yml out/sources/ --exclude 'androidx' --text
   ```

   In decompiled code the authenticator type is an integer: `1` is `AUTH_DEVICE_CREDENTIAL`, `2` is `AUTH_BIOMETRIC_STRONG`, `3` is both.

4. **Grep the smali** (framework classes keep their names under R8):

   ```bash
   grep -rnE 'KeyGenParameterSpec\$Builder;->(setInvalidatedByBiometricEnrollment|setUserAuthenticationParameters|setUserAuthenticationValidityDurationSeconds|setUserAuthenticationRequired)' smali_out/ \
     | grep -v '/androidx/'
   grep -rn 'KeyPermanentlyInvalidatedException' smali_out/ | grep -v '/androidx/'
   ```

   For `setInvalidatedByBiometricEnrollment`, look at the `const/4 vN, 0x0` (false) or `0x1` (true) loaded into the argument register just before the call.

5. **Reconstruct each key and what it protects.** For each `KeyGenParameterSpec.Builder` chain, record user-authentication requirement, timeout, authenticator type and the invalidation flag; follow the alias to the `Cipher`/`Signature` that uses it and to the data or request it protects (see GT-0016-1 in our [MASWE-0016 note](/mobile/maswe-0016-key-access-not-restricted/#gt-0016-1-keystore-key-restrictions-in-code-android) for the extraction commands).

6. **Read the invalidation handling.** For each `catch` of `KeyPermanentlyInvalidatedException` (or of its parent `InvalidKeyException`, or a bare `Exception` around `Cipher.init`), note what follows: `deleteEntry` and a new `KeyGenParameterSpec` in the same method (silent re-creation), a device-credential prompt (fallback), a call to the login screen (good), or nothing.

#### Observation

Per key: alias, purpose, authentication requirement, timeout, authenticator type, explicit or default invalidation flag, whether invalidation can apply, what the key protects, and the code path taken on `KeyPermanentlyInvalidatedException`.

#### Evaluation

OWASP's criterion: the test **fails** if the app uses `setInvalidatedByBiometricEnrollment(false)` for keys used to protect sensitive data resources.

How we apply it:

- **Fail** for `setInvalidatedByBiometricEnrollment(false)` on a key that protects a sensitive operation or data.
- **Fail** for a key protecting a sensitive operation that is meant to be biometric-only but is time-bound or accepts the device credential, because enrolment invalidation cannot apply to it. (The device-credential part is also a [MASWE-0021](/mobile/maswe-0021-non-biometric-fallback-for-sensitive-transactions/) finding.)
- **Fail** if `KeyPermanentlyInvalidatedException` is handled by re-creating the key without full re-authentication, or by falling back to a weaker key or prompt.
- **Pass** if every sensitive key is per-operation, `AUTH_BIOMETRIC_STRONG` only, without `false`, and invalidation leads to re-authentication. Confirm with [GT-0022-1](#gt-0022-1-enrolling-a-new-biometric-on-a-test-device-android).

#### Demo

From [MASTG-DEMO-0091](https://mas.owasp.org/MASTG/demos/android/MASVS-AUTH/MASTG-DEMO-0091/MASTG-DEMO-0091/), which reuses the sample of [MASTG-DEMO-0090](https://mas.owasp.org/MASTG/demos/android/MASVS-AUTH/MASTG-DEMO-0090/MASTG-DEMO-0090/). The key that protects a secret token is generated like this:

```kotlin
keyGenerator.init(
    KeyGenParameterSpec.Builder(KEY_NAME,
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setUserAuthenticationRequired(false)
        .setInvalidatedByBiometricEnrollment(false)
        .setUserAuthenticationParameters(86400, 0)
        .setUserAuthenticationValidityDurationSeconds(86400)
        .build()
)
```

The OWASP rule reports the decompiled line once:

```text
┌────────────────┐
│ 1 Code Finding │
└────────────────┘

    ../MASTG-DEMO-0090/MastgTest_reversed.java
    ❯❱ rules.mastg-android-biometric-invalidated-enrollment
          [MASVS-AUTH-2] Key configured with setInvalidatedByBiometricEnrollment(false). For sensitive
          operations, keys should be invalidated when biometric enrollment changes to prevent unauthorized
          access by newly enrolled biometrics.

           52┆ keyGenerator.init(new KeyGenParameterSpec.Builder(this.KEY_NAME, 3).setBlockModes("GCM").se
               tEncryptionPaddings("NoPadding").setUserAuthenticationRequired(false).setInvalidatedByBiome
               tricEnrollment(false).setUserAuthenticationParameters(86400,
               0).setUserAuthenticationValidityDurationSeconds(86400).build());
```

The test fails on line 52. Our rule adds two more hits on the same line (the 86400-second window in both setters). For a real report, put the root cause first: `setUserAuthenticationRequired(false)` means the key needs no authentication at all, so the window and the invalidation flag are moot — even though the sample wraps the key in a `CryptoObject` and shows a `BIOMETRIC_STRONG` prompt. The fix is a per-operation, biometric-only, auth-bound key, at which point the default invalidation applies by itself.

### MASTG-TEST-0270: References to APIs Detecting Biometric Enrollment Changes (iOS)

Source: [MASTG-TEST-0270](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0270/). Platform: iOS. Type: static (code). Related: MASTG-KNOW-0056.

#### Overview

The test identifies Keychain items and keys created through `SecAccessControlCreateWithFlags` **without** `kSecAccessControlBiometryCurrentSet`. With that flag, the item becomes inaccessible when the biometric database changes, so only users enrolled when it was created can unlock it. We also look for `evaluatedPolicyDomainState`/`domainState` use, to describe any detection logic to the client.

#### Prerequisites

- A decrypted IPA ([MASTG-TECH-0054](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0054/) "Obtaining and Extracting Apps") or a client-provided development build.
- radare2 ([MASTG-TOOL-0073](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/)), `rabin2`, `plutil`.

#### Steps

1. **Unpack and find the binaries** ([MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/) "Exploring the App Package"), including frameworks and extensions:

   ```bash
   unzip -q app.ipa -d ipa/
   APP=$(ls -d ipa/Payload/*.app)
   BIN="$APP/$(plutil -extract CFBundleExecutable raw -o - "$APP/Info.plist")"
   for b in "$BIN" "$APP"/Frameworks/*.framework/* "$APP"/PlugIns/*.appex/*; do
     [ -f "$b" ] && rabin2 -i "$b" 2>/dev/null | grep -q SecAccessControlCreateWithFlags && echo "[+] $b"
   done
   ```

2. **List the call sites and read the flags** ([MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/) "Static Analysis on iOS"):

   ```bash
   r2 -A "$BIN"
   ```

   ```text
   [0x100004000]> axt @ sym.imp.SecAccessControlCreateWithFlags
   [0x100004000]> pd -8 @ <each call address>
   ```

   The third argument, `flags`, is in `w2`/`x2`. Decode it: bit `0x8` is `.biometryCurrentSet`, `0x2` `.biometryAny`, `0x1` `.userPresence`, `0x10` `.devicePasscode`, `0x4000` `.or`, `0x40000000` `.privateKeyUsage`. A value such as `0x40000008` passes; `0x2`, `0x1`, `0x40000002` or `0x4018` do not. If `w2` comes from another register, trace it back or use MASTG-TEST-0271.

3. **Look for domain-state detection.**

   ```bash
   rabin2 -zz "$BIN" | grep -E 'evaluatedPolicyDomainState|domainState|stateHash'
   ```

   If present, find the code that compares the value and what it does on a mismatch (cross-reference the selector or the `objc_msgSend$evaluatedPolicyDomainState` stub with `afl~DomainState` and `axt`).

4. **Map each access control to the item or key it protects** and to the operation that uses it (the `SecItemAdd` or `SecKeyCreateRandomKey` that receives it; the `kSecAttrAccount`, `kSecAttrService` or `kSecAttrApplicationTag`).

#### Observation

The decoded flags of every `SecAccessControlCreateWithFlags` call, the item or key and operation each protects, and any domain-state comparison with its consequence.

#### Evaluation

OWASP's criterion: the test **fails** if the app uses `SecAccessControlCreateWithFlags` with any flag except `kSecAccessControlBiometryCurrentSet` for any sensitive data resource worth protecting.

Read "any flag except" as "without `.biometryCurrentSet`": `.privateKeyUsage` is required alongside it for Secure Enclave keys and does not weaken it. We apply it as follows:

- **Fail** for `.biometryAny`, `.userPresence` or `.devicePasscode` on a sensitive item or key.
- **Fail** for `.biometryCurrentSet` combined with `.or` and `.devicePasscode` — the passcode branch is not invalidated.
- **Fail** if the only protection is an `LAContext` flow with a domain-state comparison (event-bound detection; report with MASWE-0020).
- **Pass** for `.biometryCurrentSet` (optionally with `.privateKeyUsage` or `.and`) on every sensitive item and key, confirmed with [GT-0022-2](#gt-0022-2-enrolling-a-new-biometric-on-a-test-device-ios).

#### Demo

From [MASTG-DEMO-0045](https://mas.owasp.org/MASTG/demos/ios/MASVS-AUTH/MASTG-DEMO-0045/MASTG-DEMO-0045/). The sample stores a token protected by any enrolled biometric:

```swift
guard let accessControl = SecAccessControlCreateWithFlags(
    nil,
    kSecAttrAccessibleWhenUnlocked,
    .biometryAny,
    nil
) else { return }
```

The disassembly shows the flags argument:

```text
sym.MASTestApp.MastgTest.createAccessControl.Sec.Ref.d_n 0x100004194 [CALL:--x] bl sym.imp.SecAccessControlCreateWithFlags

│           0x10000418c      mov x1, x19
│           0x100004190      mov w2, 2
│           0x100004194      bl sym.imp.SecAccessControlCreateWithFlags
```

`w2 = 2` is `kSecAccessControlBiometryAny`: a fingerprint or face enrolled after the item was stored can read it. The test fails; the fix is `.biometryCurrentSet` (and, for a real app, `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` instead of `kSecAttrAccessibleWhenUnlocked`). A small quirk if you reproduce the demo: its `run.sh` invokes `biometricAuthenticationFallback.r2`, the script name from MASTG-DEMO-0043, while the file in the 0045 folder is `biometricAuthenticationEnrollmentChange.r2`; the two scripts are identical.

### MASTG-TEST-0271: Runtime Use Of APIs Detecting Biometric Enrollment Changes (iOS)

Source: [MASTG-TEST-0271](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0271/). Platform: iOS. Type: dynamic (hooks). Related: MASTG-KNOW-0056.

#### Overview

The dynamic counterpart to MASTG-TEST-0270: hook `SecAccessControlCreateWithFlags`, print the flags and a backtrace, and exercise the app. It catches flags computed at runtime and calls made by SDKs or cross-platform plugins. We add hooks that make the enrolment tests below easier to read.

#### Prerequisites

- The app installed ([MASTG-TECH-0056](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0056/) "Installing Apps") on a jailbroken device with `frida-server`, or as a Frida-Gadget-repackaged build.
- Frida ([MASTG-TOOL-0039](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/)); hooking as in [MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/) "Method Hooking".
- A fresh install, so that access-control objects are created while you watch (typically when the user enables Face ID / Touch ID in the app).

#### Steps

1. **Use OWASP's flag hook** (shared by MASTG-DEMO-0044 and MASTG-DEMO-0046), or the extended version in our [MASWE-0021 note](/mobile/maswe-0021-non-biometric-fallback-for-sensitive-transactions/#mastg-test-0269-runtime-use-of-apis-allowing-fallback-to-non-biometric-authentication-ios). For this weakness, add the following hooks, which show what the app reads and how it reacts to an enrolment change:

   ```javascript
   // gt-ios-enrolment.js
   const ERR = { '0': 'errSecSuccess', '-25300': 'errSecItemNotFound', '-25293': 'errSecAuthFailed',
                 '-128': 'errSecUserCanceled', '-25308': 'errSecInteractionNotAllowed' };

   Interceptor.attach(Module.getGlobalExportByName('SecItemCopyMatching'), {
     onEnter(args) {
       const q = new ObjC.Object(args[0]);
       this.desc = `class=${q.objectForKey_('class')} acct=${q.objectForKey_('acct')} ` +
                   `svce=${q.objectForKey_('svce')} tag=${q.objectForKey_('atag')}`;
     },
     onLeave(ret) {
       const s = ret.toInt32();
       console.log(`[SecItemCopyMatching] ${this.desc} -> ${s} ${ERR[String(s)] || ''}`);
     }
   });

   Interceptor.attach(Module.getGlobalExportByName('SecKeyCreateSignature'), {
     onEnter(args) { this.errp = args[3]; },
     onLeave(ret) {
       if (!ret.isNull()) { console.log('[SecKeyCreateSignature] ok'); return; }
       const e = this.errp.isNull() ? null : this.errp.readPointer();
       console.log('[SecKeyCreateSignature] failed' +
         (e && !e.isNull() ? ': ' + new ObjC.Object(e).domain() + ' ' + new ObjC.Object(e).code() : ''));
     }
   });

   const LAContext = ObjC.classes.LAContext;
   Interceptor.attach(LAContext['- evaluatedPolicyDomainState'].implementation, {
     onLeave(ret) {
       console.log('[LAContext] evaluatedPolicyDomainState = ' +
         (ret.isNull() ? 'nil' : new ObjC.Object(ret).base64EncodedStringWithOptions_(0)));
     }
   });
   if (LAContext['- domainState']) {
     Interceptor.attach(LAContext['- domainState'].implementation, {
       onLeave(ret) {
         if (ret.isNull()) return;
         const h = new ObjC.Object(ret).biometry().stateHash();
         console.log('[LAContext] domainState.biometry.stateHash = ' +
           (h === null ? 'nil' : h.base64EncodedStringWithOptions_(0)));
       }
     });
   }
   ```

   The query keys are the raw strings of the Keychain constants: `class` (`kSecClass`), `acct`, `svce`, and `atag` (`kSecAttrApplicationTag`). With Frida older than 17, use `Module.findExportByName(null, name)`.

2. **Spawn the app with both scripts** and exercise every flow that enables or uses biometrics:

   ```bash
   frida -U -f com.example.bank -l script.js -l gt-ios-enrolment.js -o enrolment.log
   ```

#### Observation

The flags of every access-control object with its backtrace; the Keychain reads and signatures with their status codes; and any domain-state reads.

#### Evaluation

OWASP's criterion: the test **fails** if the app uses `SecAccessControlCreateWithFlags` with any flag except `kSecAccessControlBiometryCurrentSet` for any sensitive data resource worth protecting. Apply it with the same reading as MASTG-TEST-0270. The additional hooks do not change the verdict on their own; they provide the evidence for GT-0022-2 and GT-0022-3.

#### Demo

From [MASTG-DEMO-0046](https://mas.owasp.org/MASTG/demos/ios/MASVS-AUTH/MASTG-DEMO-0046/MASTG-DEMO-0046/), which runs OWASP's script against the MASTG-DEMO-0045 sample (`frida -U -f org.owasp.mastestapp.MASTestApp-iOS -l ../MASTG-DEMO-0044/script.js -o output.txt`):

```text
SecAccessControlCreateWithFlags(..., 0x2) called with kSecAccessControlBiometryAny

Backtrace:
0x102350198 MASTestApp!specialized static MastgTest.createAccessControl()
0x1023504b0 MASTestApp!specialized static MastgTest.storeTokenInKeychain(secretToken:)
0x102351b98 MASTestApp!closure #1 in closure #1 in closure #1 in ContentView.body.getter
```

`0x2` is `.biometryAny`, created from `storeTokenInKeychain(secretToken:)`: the token will be readable with biometrics enrolled later. The test fails.

### GT-0022-1: Enrolling a new biometric on a test device (Android)

Guler Tech methodology. Platform: Android. Type: dynamic (device procedure, optional hooks).

#### Overview

The test that settles the question: with the app set up normally, enrol an additional fingerprint (or face, where it is Class 3), then try the protected action with the new biometric. Static analysis tells you what *should* happen; this tells you what does, including for keys created by libraries, configurations in which the flag does not apply, and event-bound flows that have no key at all.

#### Prerequisites

- A test device or emulator (API 30+ makes the enrolment intent below available) with a known PIN and one enrolled fingerprint — "finger A". On an emulator, enrol in Settings > Security > Fingerprint and touch the virtual sensor with `adb -e emu finger touch 1` each time the wizard asks.
- The app installed, logged in, with biometric login or transaction approval enabled; a test account.
- Optional: rooted device or emulator with `frida-server` for the hooks in step 2; a proxy for step 7.

#### Steps

1. **Baseline.** Perform each protected action once with finger A and confirm it works. This also makes sure the app has created its keys.

2. **Optional: attach hooks** that show invalidation and recovery as they happen:

   ```javascript
   // gt-android-enrolment.js
   Java.perform(function () {
     const trace = () => Java.use('android.util.Log')
       .getStackTraceString(Java.use('java.lang.Exception').$new()).split('\n').slice(2, 8).join('\n');
     const KPIE = Java.use('android.security.keystore.KeyPermanentlyInvalidatedException');
     KPIE.$init.overloads.forEach(function (o) {
       o.implementation = function () {
         console.log('\n[!] KeyPermanentlyInvalidatedException\n' + trace());
         return o.apply(this, arguments);
       };
     });
     const KS = Java.use('java.security.KeyStore');
     KS.deleteEntry.implementation = function (alias) {
       console.log('[*] KeyStore.deleteEntry(' + alias + ')');
       return this.deleteEntry(alias);
     };
     const KB = Java.use('android.security.keystore.KeyGenParameterSpec$Builder');
     KB.build.implementation = function () {
       const s = this.build();
       console.log('[*] new key alias=' + s.getKeystoreAlias() + ' authRequired=' + s.isUserAuthenticationRequired() +
         ' timeout=' + s.getUserAuthenticationValidityDurationSeconds() + ' type=' + s.getUserAuthenticationType() +
         ' invalidatedByEnrollment=' + s.isInvalidatedByBiometricEnrollment() + '\n' + trace());
       return s;
     };
   });
   ```

3. **Stop the app** so that nothing is cached in memory:

   ```bash
   adb shell am force-stop com.example.bank
   ```

4. **Enrol a second fingerprint, "finger B".** Open the enrolment flow, confirm the PIN, and complete it:

   ```bash
   adb shell am start -a android.settings.BIOMETRIC_ENROLL      # API 30+
   # on the emulator, while the wizard asks for touches:
   adb -e emu finger touch 2
   ```

   On API 28–29 use `adb shell am start -a android.settings.FINGERPRINT_ENROLL` or Settings > Security. Confirm that two fingerprints are now enrolled in Settings (or with `adb shell dumpsys fingerprint`, whose output format differs between versions).

5. **Start the app with the hooks and try the protected action with finger B.**

   ```bash
   frida -U -f com.example.bank -l gt-android-enrolment.js -o enrolment.log
   # at the prompt, on the emulator:
   adb -e emu finger touch 2
   ```

   Watch logcat in parallel for the exception if you are not using Frida:

   ```bash
   adb logcat -v time | grep -iE 'KeyPermanentlyInvalidated|UserNotAuthenticated|BiometricPrompt'
   ```

6. **Try finger A as well.** With effective invalidation, even the original finger cannot use the old key — the key is gone, not the match. That distinguishes "invalidated" from "the new finger simply wasn't recognised".

7. **Record what the app does next**: a message, a login screen, a "re-enable fingerprint" prompt, silent success. Capture the network traffic of any re-registration. Then continue with [GT-0022-3](#gt-0022-3-invalidation-recovery-and-re-enrolment-android-ios-backend).

8. **Variations.** If the device only supports one biometric (some face-only devices), you cannot add without removing; removing all biometrics also triggers invalidation, so a "pass" in that case does not separate the two causes — note it. To check the removal case on purpose, delete all fingerprints, re-enrol finger A only, and repeat step 5.

9. **Restore the device** (remove finger B) and re-enable biometrics in the app before other tests.

#### Observation

For each protected action: whether it completed with finger B, whether it completed with finger A, the exception and stack trace (or logcat line), the keys deleted and created, the screens shown, and the traffic of any re-registration.

#### Evaluation

The test **fails** if any sensitive action completes with finger B (or with finger A) using the old key or session, without the user first re-authenticating with account credentials. This covers `setInvalidatedByBiometricEnrollment(false)`, keys the flag does not apply to, event-bound flows (which always accept new fingerprints) and recovery flows that re-bind the new finger with only a biometric prompt. It **passes** if the old key fails with `KeyPermanentlyInvalidatedException` and the app requires full re-authentication before any sensitive action is possible again.

#### Demo

`enrolment.log` for a lab app whose payment key uses the default flag but a 30-second window:

```text
[*] new key alias=pay_key authRequired=true timeout=30 type=2 invalidatedByEnrollment=true
    at com.example.bank.keys.PaymentKeys.create(PaymentKeys.java:44)
```

After enrolling finger B, the payment completed with finger B and no exception was thrown. `invalidatedByEnrollment=true` in the specification is misleading: with a positive timeout, the flag does not apply. The test fails. With the fix (`timeout=0`), the same procedure produced:

```text
[!] KeyPermanentlyInvalidatedException
    at javax.crypto.Cipher.init(Cipher.java:...)
    at com.example.bank.pay.Approver.prepare(Approver.java:63)
[*] KeyStore.deleteEntry(pay_key)
```

followed by the app's login screen: pass, subject to GT-0022-3.

### GT-0022-2: Enrolling a new biometric on a test device (iOS)

Guler Tech methodology. Platform: iOS. Type: dynamic (device procedure, optional hooks).

#### Overview

The iOS version of the decisive test: add a fingerprint or an alternate Face ID appearance, then try the protected action with it. It works on a non-jailbroken device with a production build; the Frida hooks from MASTG-TEST-0271 are optional evidence.

#### Prerequisites

- A physical device with a passcode and one enrolled biometric: one Touch ID finger, or Face ID with no alternate appearance set up.
- **Stolen Device Protection** turned off (Settings > Face ID & Passcode > Stolen Device Protection), or the test performed at a familiar location; otherwise the enrolment change may be held behind a security delay.
- The app installed, logged in, with biometrics enabled; a second person (or your other finger) for the new biometric.
- Optional: jailbreak or Frida Gadget build for the hooks; a proxy.

#### Steps

1. **Baseline.** Perform each protected action with the original biometric.
2. **Optional:** spawn the app with `gt-ios-enrolment.js` (MASTG-TEST-0271) to log Keychain status codes, signing failures and domain-state reads.
3. **Swipe the app away** from the app switcher.
4. **Add a biometric.**
   - Touch ID: Settings > Touch ID & Passcode > enter passcode > Add a Fingerprint, using a different finger or a colleague's.
   - Face ID: Settings > Face ID & Passcode > enter passcode > Set Up an Alternate Appearance, using a colleague's face. If an alternate appearance already exists, Reset Face ID and set it up again with the colleague's face — that both removes and adds, so note it.
5. **Open the app and try the protected action with the new biometric.**
6. **Try the original biometric as well**, to distinguish invalidation (both fail at the key) from a non-match.
7. **Record the app's behaviour and the hook output**, then continue with [GT-0022-3](#gt-0022-3-invalidation-recovery-and-re-enrolment-android-ios-backend).
8. **Simulator shortcut.** For builds that run on the iOS Simulator, toggling Features > Face ID > Enrolled off and on is commonly used to simulate an enrolment change; it is convenient for developers reproducing a fix, but confirm on hardware before reporting.
9. **Restore the device**: remove the added finger or reset Face ID and enrol yourself again; re-enable biometrics in the app.

#### Observation

Whether each protected action completed with the new biometric and with the original one; the status codes from `SecItemCopyMatching` and `SecKeyCreateSignature`; any domain-state values before and after; the screens shown; the re-registration traffic.

#### Evaluation

The test **fails** if any sensitive action completes with the newly enrolled biometric without the user first re-authenticating with account credentials — whether because the item uses `.biometryAny` or `.userPresence`, because the passcode branch of an `.or` was offered and used, because the flow is event-bound, or because the app re-bound the new biometric with only a biometric prompt. It **passes** if the item or key becomes inaccessible and the app requires full re-authentication.

#### Demo

Hook output for a lab app that stores a refresh token with `.biometryAny`, after adding a second fingerprint:

```text
[LAContext] evaluatedPolicyDomainState = 1kq4tN0kGv8yQJ1p4bwz8w==
[SecItemCopyMatching] class=genp acct=refresh_token svce=com.example.bank -> 0 errSecSuccess
```

The domain state differs from the value logged before enrolment (`Z3d8…`), the app read it, and did nothing with it; the Keychain returned the token to the new finger. The test fails. After switching the item to `.biometryCurrentSet`:

```text
[SecItemCopyMatching] class=genp acct=refresh_token svce=com.example.bank -> -25300 errSecItemNotFound
```

and the app showed its sign-in screen: pass, subject to GT-0022-3.

### GT-0022-3: Invalidation recovery and re-enrolment (Android, iOS, backend)

Guler Tech methodology. Platforms: Android and iOS. Type: dynamic (app flow and backend).

#### Overview

OWASP's third mode of introduction — unsafe recovery — is where many apps that configure keys correctly still fail, and it is partly a backend matter. After invalidation, the app needs a new key; the question is what it takes to get one registered, and whether the old one is dead on the server too. This test also gives you the evidence MASVS-AUTH asks for: whether the server, not the client, enforces re-authentication. It relates to OWASP WSTG-ATHN-09 "Testing for Weak Password Change or Reset Functionalities" and WSTG-ATHN-10 "Testing for Weaker Authentication in Alternative Channel", and to the authentication chapter (V6) of OWASP ASVS 5.0.

#### Prerequisites

- A device on which GT-0022-1 or GT-0022-2 has just invalidated the app's keys.
- A proxy capturing the app's traffic, with the baseline traffic from before invalidation (biometric enable/registration request, a signed approval).

#### Steps

1. **Follow the app's recovery flow as an attacker would.** You know the device passcode and have a new biometric enrolled, but not the account password or the one-time-code channel. Can you get back to approving transactions? Note every screen and what it asks for.
2. **Capture the re-registration request** (new public key, device binding, "enable biometrics" call). Note what authenticates it: the existing session or refresh token only, a fresh login, a one-time code, a step-up token.
3. **Replay re-registration with less.** Send the captured request again with only the existing session token (drop any step-up token or OTP field). If the server registers the key, it relies on the client to enforce re-authentication.
4. **Check the old key server-side.** Replay a signed approval captured before invalidation (or one signed by the old key if you extracted it on a lab build). If the server still accepts the old key's signatures after the app reported invalidation, revocation is client-side only. If the app never tells the server about invalidation, note that too.
5. **Check notifications.** After re-enabling biometrics, does the account holder receive an email, SMS or push on another device saying biometric approval was re-enabled?
6. **Check what survived.** Is the session still valid? Can you perform sensitive actions that the biometric key did not protect (because, say, the session token is stored without access control)? Was data previously encrypted under the old key re-downloaded without re-authentication?

#### Observation

The screens and credentials required to recover, the re-registration request and the server's response to the reduced replay, the server's response to old-key signatures, the notifications received, and what remained usable without re-authentication.

#### Evaluation

The test **fails** if, after invalidation, a person with the device passcode and a newly enrolled biometric can restore the ability to perform sensitive operations without the account credentials — through a biometric-only "re-enable" prompt, silent key re-creation, a passcode fallback, a server that accepts re-registration with only the session token, or a session that was never bound to the key. It also fails if the server keeps accepting the old key. It **passes** if recovery requires a server-verified login with a second factor, the server revokes the old key, and the user is notified.

#### Demo

A lab app's re-enable flow after invalidation:

```text
POST /api/v2/devices/biometric-key HTTP/2
Authorization: Bearer <session token>
Content-Type: application/json

{"publicKey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...","attestation":null}

HTTP/2 201 Created
```

The app had shown "Your fingerprints changed. Confirm with your fingerprint to continue", which the newly enrolled finger passed, and then sent this request authenticated only by the existing session. The server registered the new key and sent no notification. Platform invalidation worked; the recovery flow handed the attacker a fresh key. The test fails, and the report should recommend a server-side step-up (password and one-time code) before `/devices/biometric-key` accepts a new key, revocation of the previous key, and a notification to the user.

## Best practices

OWASP links one best practice, MASTG-BEST-0037, which is Android-only. We add the iOS counterpart as Guler Tech guidance.

### MASTG-BEST-0037: Invalidate Biometric Keys on Enrollment Changes (Android)

Source: [MASTG-BEST-0037](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0037/). Related: MASTG-KNOW-0001.

OWASP's guidance: ensure keys used for biometric authentication are invalidated when new biometrics are enrolled — either set `setInvalidatedByBiometricEnrollment(true)` explicitly or rely on the default; never use `false`, because an attacker who obtains the device passcode could enrol a new biometric and use it to access existing encrypted data or trigger sensitive operations. Invalidation is immediate and permanent, so the app must handle `KeyPermanentlyInvalidatedException` and guide the user to re-authenticate before creating a new key.

One precision. The best practice says the default invalidates keys "when `setUserAuthenticationRequired(true)` is set". That is true for the configuration that call produces on its own (per-operation, biometric-only), but not for keys that also set a validity window or accept the device credential. State the full requirement in recommendations: auth-bound, per-operation, `AUTH_BIOMETRIC_STRONG` only, flag not set to `false`.

```kotlin
private const val ALIAS = "payment_signing"
private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

fun createSigningKey(challenge: ByteArray) {
    KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply {
        initialize(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                .setInvalidatedByBiometricEnrollment(true)   // the default; explicit for reviewers
                .setAttestationChallenge(challenge)
                .build()
        )
    }.generateKeyPair()
}

sealed interface Prepared {
    data class Ready(val signature: Signature) : Prepared
    object ReEnrolmentRequired : Prepared
}

fun prepareSignature(): Prepared = try {
    val sig = Signature.getInstance("SHA256withECDSA")
    sig.initSign(keyStore.getKey(ALIAS, null) as PrivateKey)
    Prepared.Ready(sig)
} catch (e: KeyPermanentlyInvalidatedException) {
    // Biometrics changed (or the screen lock was removed). The key is dead: delete it,
    // tell the server to stop accepting it, and require a full, server-verified login.
    keyStore.deleteEntry(ALIAS)
    Prepared.ReEnrolmentRequired
}
```

On `ReEnrolmentRequired`, the app should call the backend to revoke the device key, discard local data encrypted under it, send the user to the normal login (password and second factor), and only then call `createSigningKey` with a fresh server challenge and register the new public key and attestation. The backend should refuse to register a biometric key without a recent step-up, and notify the user on another channel when it does. Do **not** offer "confirm with your fingerprint to re-enable": the new fingerprint is the attacker's.

### iOS counterpart: current-set access control with safe recovery (Guler Tech)

Guler Tech guidance; OWASP has no iOS best-practice page for this weakness. Create the key with `.biometryCurrentSet`, use the domain state only for a friendly early message, and treat any failure to use the key after a successful match as invalidation:

```swift
let tag = Data("com.example.bank.payment".utf8)

func createSigningKey() throws {
    var error: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
        [.privateKeyUsage, .biometryCurrentSet],     // invalidated by any enrolment change
        &error) else { throw error!.takeRetainedValue() as Error }
    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: tag,
            kSecAttrAccessControl as String: access,
        ],
    ]
    guard SecKeyCreateRandomKey(attributes as CFDictionary, &error) != nil else {
        throw error!.takeRetainedValue() as Error
    }
    storeDomainStateReference(currentBiometricState())   // UX only; keep it in the Keychain
}

func currentBiometricState() -> Data? {
    let context = LAContext()
    var error: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else { return nil }
    if #available(iOS 18.0, *) {
        return context.domainState.biometry.stateHash
    }
    return context.evaluatedPolicyDomainState
}

/// Call before showing the approval sheet. A mismatch is a hint, not proof:
/// the access control above is what actually enforces invalidation.
func biometricsChangedSinceEnrolment() -> Bool {
    currentBiometricState() != loadDomainStateReference()
}

func discardApprovalKey() {
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: tag,
    ]
    SecItemDelete(query as CFDictionary)                 // no authentication needed
}
```

When `biometricsChangedSinceEnrolment()` is true, or when the key lookup or `SecKeyCreateSignature` fails after the user authenticated (rather than cancelled), call `discardApprovalKey()`, revoke the key on the server, and send the user through full sign-in before creating a new one. `storeDomainStateReference` and `loadDomainStateReference` are your own helpers; keep the reference in the Keychain. Do not combine `.biometryCurrentSet` with `.or` and `.devicePasscode`, and do not re-enable biometric approval with only a Face ID prompt.

## Rating findings

Rate on four things: the sensitivity of what the key protects; whether you demonstrated access with a newly enrolled biometric (GT-0022-1/2) or only observed the configuration; whether the app also allows passcode fallback (MASWE-0021), which makes this weakness redundant; and whether recovery and the backend undo or support invalidation (GT-0022-3). The attack needs physical access and the device passcode, which limits the top of the scale.

| Rating | Conditions |
|---|---|
| **Critical** | Not appropriate for MASWE-0022 on its own, because the attacker needs the device and its passcode. If a related backend flaw removes those prerequisites — for example, a biometric key can be registered for any account through the API without step-up — report that flaw separately and rate it on its own merits. |
| **High** | L2 or EUDIW app; a high-value operation (payments, new payees, limit changes, card or secret reveal, wallet presentation or qualified signature) completed with a newly enrolled biometric in GT-0022-1 or GT-0022-2, without account re-authentication; the app is otherwise biometric-only for that operation (no passcode fallback). Also High: platform invalidation works, but the recovery flow re-binds biometrics with only a biometric prompt or the existing session (GT-0022-3), with the same outcome. |
| **Medium** | The same demonstrated access for moderately sensitive data or operations (biometric login to an account with read access, health or personal records); or high-value operations with effective server-side compensation (low limits, cooling-off, notifications on another channel); or `setInvalidatedByBiometricEnrollment(false)`, a non-invalidating key configuration, `.biometryAny` or a `.biometryCurrentSet`-or-passcode combination on a sensitive key observed statically but not demonstrated on a device; or domain-state detection used as the only control. |
| **Low** | Invalidation effective, but recovery is weak in ways that do not restore access for the attacker (no user notification, old key not revoked server-side when the app cannot use it anyway, password-only re-authentication); or non-invalidating configuration on keys for low-value features. |
| **Info** | The same operation also accepts the device passcode — report and rate the fallback under [MASWE-0021](/mobile/maswe-0021-non-biometric-fallback-for-sensitive-transactions/) and record this weakness as dependent; deliberate `.biometryAny` or `false` with a documented rationale for non-sensitive features; any instance in an app outside the L2/EUDIW profiles. |

In the report, give the key alias or Keychain identifier, what it protects, the exact configuration (decompiled builder call or decoded flags), and — for anything above Low — the enrolment evidence: the device, the biometric added, a recording of the action completing with it (or the hook log), and the recovery-flow traffic. State plainly that the attacker needs the passcode and brief physical access, and explain why that is a realistic threat for the app's users (shared households, observed passcodes). Pair the recommendation with the MASWE-0021 result for the same operation.

## References

- OWASP MASWE — [MASWE-0022: Crypto Keys Not Invalidated on New Biometric Enrollment](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0022/) (CC BY-SA 4.0)
- OWASP MASWE — [MASWE-0020: Local Authentication Can Be Bypassed](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0020/) and [MASWE-0021: Fallback to Non-biometric Credentials Allowed for Sensitive Transactions](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0021/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0328: References to APIs Detecting Biometric Enrollment Changes (Android)](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0328/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0270: References to APIs Detecting Biometric Enrollment Changes (iOS)](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0270/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0271: Runtime Use Of APIs Detecting Biometric Enrollment Changes](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0271/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-BEST-0037: Invalidate Biometric Keys on Enrollment Changes](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0037/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0001: Biometric Authentication](https://mas.owasp.org/MASTG/knowledge/android/MASVS-AUTH/MASTG-KNOW-0001/), [MASTG-KNOW-0056: Local Authentication Framework](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-AUTH/MASTG-KNOW-0056/), [MASTG-KNOW-0057: Keychain Services](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-AUTH/MASTG-KNOW-0057/) (CC BY-SA 4.0)
- OWASP MASTG — demos [MASTG-DEMO-0090](https://mas.owasp.org/MASTG/demos/android/MASVS-AUTH/MASTG-DEMO-0090/MASTG-DEMO-0090/), [MASTG-DEMO-0091](https://mas.owasp.org/MASTG/demos/android/MASVS-AUTH/MASTG-DEMO-0091/MASTG-DEMO-0091/), [MASTG-DEMO-0044](https://mas.owasp.org/MASTG/demos/ios/MASVS-AUTH/MASTG-DEMO-0044/MASTG-DEMO-0044/), [MASTG-DEMO-0045](https://mas.owasp.org/MASTG/demos/ios/MASVS-AUTH/MASTG-DEMO-0045/MASTG-DEMO-0045/), [MASTG-DEMO-0046](https://mas.owasp.org/MASTG/demos/ios/MASVS-AUTH/MASTG-DEMO-0046/MASTG-DEMO-0046/) (CC BY-SA 4.0)
- OWASP MASTG — legacy (MASTG v1) tests [MASTG-TEST-0018: Testing Biometric Authentication (Android)](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0018/) and [MASTG-TEST-0064: Testing Biometric Authentication (iOS)](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0064/) (CC BY-SA 4.0)
- OWASP MASTG — techniques [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0017](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0017/), [MASTG-TECH-0054](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0054/), [MASTG-TECH-0056](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0056/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/); tools [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [Frida for iOS (MASTG-TOOL-0039)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/), [radare2 (MASTG-TOOL-0073)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/), [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/) (CC BY-SA 4.0)
- OWASP MAS Profiles — [MAS-L2](https://mas.owasp.org/Profiles/MAS-L2/) and [MAS-EUDIW](https://mas.owasp.org/Profiles/MAS-EUDIW/) (CC BY-SA 4.0)
- [OWASP WSTG — Testing for Weak Password Change or Reset Functionalities (WSTG-ATHN-09)](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/04-Authentication_Testing/09-Testing_for_Weak_Password_Change_or_Reset_Functionalities), [Testing for Weaker Authentication in Alternative Channel (WSTG-ATHN-10)](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/04-Authentication_Testing/10-Testing_for_Weaker_Authentication_in_Alternative_Channel) and [OWASP ASVS 5.0](https://owasp.org/www-project-application-security-verification-standard/) (V6 Authentication)
- [Android Developers — `KeyGenParameterSpec.Builder#setInvalidatedByBiometricEnrollment(boolean)`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setInvalidatedByBiometricEnrollment(boolean)), [`KeyPermanentlyInvalidatedException`](https://developer.android.com/reference/android/security/keystore/KeyPermanentlyInvalidatedException), [`KeyInfo`](https://developer.android.com/reference/android/security/keystore/KeyInfo)
- [Android Developers — Show a biometric authentication dialog](https://developer.android.com/training/sign-in/biometric-auth) and [Android Keystore system](https://developer.android.com/privacy-and-security/keystore)
- [Android Developers — `Settings.ACTION_BIOMETRIC_ENROLL`](https://developer.android.com/reference/android/provider/Settings#ACTION_BIOMETRIC_ENROLL)
- [Apple — `SecAccessControlCreateFlags.biometryCurrentSet`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset), [`biometryAny`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometryany), [`SecAccessControlCreateWithFlags`](https://developer.apple.com/documentation/security/secaccesscontrolcreatewithflags%28_:_:_:_:%29)
- [Apple — `LAContext.evaluatedPolicyDomainState`](https://developer.apple.com/documentation/localauthentication/lacontext/evaluatedpolicydomainstate), [`LAContext.domainState`](https://developer.apple.com/documentation/localauthentication/lacontext/domainstate), [Accessing keychain items with Face ID or Touch ID](https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id)
- [Apple Support — About Stolen Device Protection for iPhone](https://support.apple.com/en-us/120340) and [Apple Platform Security — Face ID and Touch ID security](https://support.apple.com/guide/security/face-id-and-touch-id-security-sec067eb0c9e/web)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html) and [CWE-522: Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
