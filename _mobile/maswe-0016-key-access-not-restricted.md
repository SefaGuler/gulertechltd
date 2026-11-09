---
title: "Cryptographic Key Access Not Restricted (MASWE-0016)"
date: 2026-11-09 12:20:00 +0000
subcategory: crypto
summary: "Binding Keystore, Keychain and Secure Enclave keys to user authentication, the unlocked device and the device itself, and testing what a key really allows."
refs: [MASWE-0016, MASVS-CRYPTO-2, MASVS-AUTH-2, MASVS-AUTH-3, CWE-284, CWE-306]
tags: [android, ios, masvs-crypto, masvs-auth, keystore, keychain]
---

This note is part of our [MASVS-CRYPTO guide](/mobile/masvs-crypto-cryptography-guide/) and covers OWASP [MASWE-0016](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0016/): cryptographic keys that anyone — or any code — can use. Our [MASWE-0003 note](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/) explains why keys belong in the Android Keystore, the iOS Keychain or the Secure Enclave; this note picks up where that one stops. A key the attacker cannot extract is still a key the attacker can *use*, unless the app tells the platform under which conditions it may be used: only after the user authenticates, only for one operation, only while the device is unlocked, only on this device, only for one purpose. You will find each of those restrictions on both platforms, the difference between event-bound and crypto-bound biometrics, the related OWASP MASVS-AUTH and MASVS-CRYPTO tests, our own static and dynamic tests (including how to prove that a key works without authentication), secure Kotlin and Swift, and severity guidance.

> **Note:** At the time of writing, MASWE-0016 has no linked Knowledge pages or Tests on mas.owasp.org; the weakness page says "No Tests Yet". The MASTG does contain beta tests for neighbouring weaknesses that check parts of the same key configuration (biometric binding, validity duration, enrolment invalidation, key purposes); we list them in [Related OWASP material](#related-owasp-material). The Knowledge and Testing sections below are **Guler Tech methodology**, citing OWASP IDs only where the material genuinely exists.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: Keystore key authorisations (MASTG-KNOW-0043, MASTG-KNOW-0012)](#android-keystore-key-authorisations-mastg-know-0043-mastg-know-0012)
  - [Android: user authentication binding and validity (MASTG-KNOW-0001)](#android-user-authentication-binding-and-validity-mastg-know-0001)
  - [Android: unlocked device, user presence and Protected Confirmation](#android-unlocked-device-user-presence-and-protected-confirmation)
  - [Android: purposes, paddings, digests and usage limits](#android-purposes-paddings-digests-and-usage-limits)
  - [Android: verifying restrictions with KeyInfo and attestation (MASTG-KNOW-0044)](#android-verifying-restrictions-with-keyinfo-and-attestation-mastg-know-0044)
  - [Both platforms: event-bound versus crypto-bound biometrics](#both-platforms-event-bound-versus-crypto-bound-biometrics)
  - [iOS: Keychain accessibility and device binding (MASTG-KNOW-0057)](#ios-keychain-accessibility-and-device-binding-mastg-know-0057)
  - [iOS: access control flags (MASTG-KNOW-0056, MASTG-KNOW-0057)](#ios-access-control-flags-mastg-know-0056-mastg-know-0057)
  - [iOS: Keychain access groups (MASTG-KNOW-0126)](#ios-keychain-access-groups-mastg-know-0126)
  - [iOS: Secure Enclave keys need access control too (MASTG-KNOW-0066)](#ios-secure-enclave-keys-need-access-control-too-mastg-know-0066)
- [Testing](#testing)
  - [Related OWASP material](#related-owasp-material)
  - [GT-0016-1: Keystore key restrictions in code (Android)](#gt-0016-1-keystore-key-restrictions-in-code-android)
  - [GT-0016-2: Key restrictions at creation and in KeyInfo (Android)](#gt-0016-2-key-restrictions-at-creation-and-in-keyinfo-android)
  - [GT-0016-3: Using Keystore keys without authentication (Android)](#gt-0016-3-using-keystore-keys-without-authentication-android)
  - [GT-0016-4: Keychain access control in the binary (iOS)](#gt-0016-4-keychain-access-control-in-the-binary-ios)
  - [GT-0016-5: Keychain item attributes at runtime (iOS)](#gt-0016-5-keychain-item-attributes-at-runtime-ios)
  - [GT-0016-6: Using Keychain items and Secure Enclave keys without authentication (iOS)](#gt-0016-6-using-keychain-items-and-secure-enclave-keys-without-authentication-ios)
- [Secure implementation](#secure-implementation)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

MASWE-0016 applies when a key can be used without restrictions on **who** may use it, **under which device conditions**, **where**, and **for how long**. The OWASP requirement is *"The app restricts access to cryptographic keys."* Both platforms let the developer attach those restrictions to a key when it is created, and enforce them outside the app process — in the Keystore service and its TEE or StrongBox on Android, in `securityd` and the Secure Enclave on iOS. When the developer does not ask, the default is permissive: a key that is usable by any code running as the app, at any time the device is on.

The restrictions fall into a handful of dimensions:

| Dimension | Question | Android Keystore | iOS Keychain / Secure Enclave |
|---|---|---|---|
| Who | Must the user authenticate? With what? | `setUserAuthenticationRequired`, `setUserAuthenticationParameters(…, type)` | `SecAccessControl` flags: `.biometryCurrentSet`, `.biometryAny`, `.userPresence`, `.devicePasscode` |
| How long | One operation, or a window after authentication? | `setUserAuthenticationParameters(timeout, …)`; timeout `0` = per operation | Per access by default; `LAContext` reuse can widen it |
| Which biometrics | Only those enrolled when the key was made? | `setInvalidatedByBiometricEnrollment(true)` | `.biometryCurrentSet` |
| Device state | Only while unlocked? Only with a passcode set? | `setUnlockedDeviceRequired(true)` | `kSecAttrAccessibleWhenUnlocked…`, `…WhenPasscodeSetThisDeviceOnly` |
| Where | Can the key leave this device? | Keystore keys are non-exportable | `…ThisDeviceOnly` classes; not `kSecAttrSynchronizable`; Secure Enclave |
| What | Which operations, modes, paddings, digests, how many uses? | Purposes, block modes, paddings, digests, `setMaxUsageCount` | Key type (signing vs key agreement), Secure Enclave supports P-256 only |
| Which code | Which apps or extensions? | The app's UID | Keychain access groups |
| Intent | Did the user approve *this* message? | `setUserConfirmationRequired` (Protected Confirmation) | No direct equivalent |

The single most important idea: **hardware backing prevents extraction, not use.** A key generated in StrongBox or the Secure Enclave without restrictions is unextractable — and freely usable by malware with code execution in the app, by a tester with Frida on a rooted or jailbroken device, by a compromised third-party SDK, or by whoever has the unlocked phone in their hand. OWASP lists this explicitly as a mode of introduction ("Assuming Hardware Implies Restriction"), and it is the most common reason this weakness appears in apps that otherwise use the keystores correctly.

The attackers this weakness is about, mapped to OWASP's attack list for MASWE-0016:

- **Code running as the app** — debugging the app at runtime (MAS-ATTACK-0002) or dynamic instrumentation (MAS-ATTACK-0003) on a rooted or jailbroken device, or a malicious library inside the app. Without user-authentication binding, they can decrypt, sign and unwrap at will.
- **A person with the device** — invoking keystore operations on a compromised or stolen device when key use does not require user authentication (MAS-ATTACK-0027). That includes the unlocked phone left on a desk, the phone unlocked under coercion, and the locked phone whose app process is still running.

**Profiles: L2 and EUDIW.** MASWE-0016 is tagged with the [MAS-L2](https://mas.owasp.org/Profiles/MAS-L2/) and [MAS-EUDIW](https://mas.owasp.org/Profiles/MAS-EUDIW/) profiles, not L1. MAS-L2 ("Advanced Security") covers apps where compromise has serious consequences — banking, payments, health, government, enterprise access — and expects defence in depth beyond the L1 baseline. MAS-EUDIW is the OWASP MAS profile for European Digital Identity Wallet apps under the revised eIDAS framework (Regulation (EU) 2024/1183); it draws on the other profiles and extends beyond them. For a wallet, the device keys bound to the user's credentials are the security model: a presentation or signature made with an unrestricted key is a presentation the user may never have approved. If your engagement is scoped to L1 only, treat missing key restrictions as hardening observations; for L2 apps and wallets they are findings.

The weakness maps to MASVS-CRYPTO-2 (key management), MASVS-AUTH-2 (local authentication performed securely according to platform best practices) and MASVS-AUTH-3 (sensitive operations secured with additional authentication), and to [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html) and [CWE-306: Missing Authentication for Critical Functionality](https://cwe.mitre.org/data/definitions/306.html). OWASP's threat for it is MAS-THREAT-0016: "Attackers can use the app's cryptographic keys without authorization."

## Modes of Introduction

**No user authentication requirement.** The key that decrypts the refresh token, signs the payment, or unwraps the vault DEK is created without `setUserAuthenticationRequired(true)` on Android or without a user-presence flag on iOS. The app may still show a biometric prompt — but as UI, not as a condition on the key (see [event-bound versus crypto-bound](#both-platforms-event-bound-versus-crypto-bound-biometrics)).

**Usable while the device is locked.** Android keys without `setUnlockedDeviceRequired(true)`; iOS items in `kSecAttrAccessibleAfterFirstUnlock` (or the deprecated `…Always` classes). A process that is still running on a locked, stolen phone — or a background job triggered by a push message — can use the key.

**Not device-bound.** Keychain items without a `…ThisDeviceOnly` class migrate to other devices through encrypted backups and device-to-device transfer; items with `kSecAttrSynchronizable` sync through iCloud Keychain. On Android the Keystore itself is non-exportable, so this mode usually appears as raw key material stored or backed up outside it (a MASWE-0003 problem).

**Unbounded authorisation validity.** An Android key with `setUserAuthenticationParameters(3600, …)` or the deprecated `setUserAuthenticationValidityDurationSeconds(86400)` is usable for an hour or a day after any authentication — including the user simply unlocking the phone. On iOS, a long-lived, already-evaluated `LAContext` reused across Keychain queries, or a generous `touchIDAuthenticationAllowableReuseDuration`, has the same effect.

**Assuming hardware implies restriction.** `setIsStrongBoxBacked(true)` or `kSecAttrTokenIDSecureEnclave` with no other restriction. A CryptoKit `SecureEnclave.P256.Signing.PrivateKey()` created with default arguments is the textbook example: its access control requires only that the device is unlocked, not that the user is present.

Further variants we see regularly:

- **Weak authenticators for strong operations:** `AUTH_DEVICE_CREDENTIAL` or `.userPresence`/`.devicePasscode` allowed for transaction signing (OWASP tracks this as MASWE-0021).
- **Enrolment changes not invalidating keys:** `setInvalidatedByBiometricEnrollment(false)` or `.biometryAny` (MASWE-0022).
- **Over-broad key capabilities:** one key pair for encryption *and* signing, RSA with `ENCRYPTION_PADDING_NONE`, `setRandomizedEncryptionRequired(false)`.
- **Over-broad Keychain sharing:** keys stored in a shared access group visible to every app and extension of the team, often because a shared group was listed first and became the default.

## Impact

- **Compromise of sensitive data.** An attacker decrypts protected data — tokens, cached records, wrapped DEKs — by asking the keystore to do it, without ever seeing the key. Hardware backing does not help.
- **Authentication or authorisation bypass.** Signing keys meant to prove the user's consent (transaction signing, device-bound login, step-up authentication, credential presentation in a wallet) produce valid signatures for operations the user never approved. The backend sees a cryptographically valid request.
- **Persistence after device loss.** A key usable while the device is locked, or one that migrates through backups to another device, extends the attacker's window well beyond the moment of access.
- **Local authentication becomes decorative.** If the key behind a biometric prompt is not bound to authentication, bypassing the prompt (a single Frida hook) yields everything the prompt was supposed to protect. That links this weakness directly to MASVS-AUTH-2 and AUTH-3.

## Mitigations

- **Bind keys for sensitive operations to user authentication**: on Android `setUserAuthenticationRequired(true)` with `setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)` and use through `BiometricPrompt.CryptoObject`; on iOS an access-control object with `.biometryCurrentSet` (or `.userPresence` where passcode fallback is acceptable).
- **Make authorisation per operation** for anything that moves money, discloses identity data or changes security settings; keep any time window short and justified.
- **Invalidate on enrolment change**: keep Android's default `setInvalidatedByBiometricEnrollment(true)`; use `.biometryCurrentSet` rather than `.biometryAny` on iOS.
- **Require the unlocked state**: `setUnlockedDeviceRequired(true)`; `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` or `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`.
- **Bind to the device**: `…ThisDeviceOnly` classes, no `kSecAttrSynchronizable` for keys, Secure Enclave or StrongBox where the algorithm allows.
- **Restrict capabilities**: one purpose per key, only the modes, paddings and digests you use, randomised encryption left on, `setMaxUsageCount` for one-shot keys.
- **Narrow the audience**: keep keys in the app's own Keychain access group; share only what must be shared.
- **Apply the same restrictions to hardware-backed keys**, and where the backend relies on them, verify them server-side with Android key attestation.

## Knowledge

None of the sections below is an OWASP Knowledge page dedicated to MASWE-0016. Where a MASTG Knowledge page covers the underlying platform mechanism we name it in the heading and build on it; the restriction-focused material is ours. Keystore and Keychain basics (security levels, StrongBox, Secure Enclave, storage locations) are in our [MASWE-0003 note](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/#knowledge) and are not repeated here.

### Android: Keystore key authorisations (MASTG-KNOW-0043, MASTG-KNOW-0012)

Related: [MASTG-KNOW-0043](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0043/) and [MASTG-KNOW-0012](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0012/).

Everything you pass to `KeyGenParameterSpec.Builder` (or `KeyProtection.Builder` for imported keys) becomes the key's **authorisation list**. It is fixed at creation, stored with the key, and enforced by the Keystore service and by KeyMint in the TEE or StrongBox. The app cannot loosen it later, which is good for security and means a badly configured key can only be fixed by creating a new one.

The setters that restrict *access* (as opposed to algorithm choice):

| Setter | API | Default | What it restricts | Testing note |
|---|---|---|---|---|
| `setUserAuthenticationRequired(true)` | 23 | `false` | Key unusable until the user authenticates | Without it, every other auth setting below is ignored |
| `setUserAuthenticationParameters(timeout, type)` | 30 | timeout `0`, `AUTH_BIOMETRIC_STRONG` | Per-operation (`0`) or a window in seconds; which authenticators count | Look at both values |
| `setUserAuthenticationValidityDurationSeconds(s)` | 23, deprecated in 30 | `-1` | `-1` = per operation, biometric only; any value `>= 0` = window, biometric **or** device credential | Common in older code |
| `setInvalidatedByBiometricEnrollment(b)` | 24 | `true` | Destroys the key when a new biometric is enrolled | Applies only to per-operation, biometric-only keys |
| `setUserAuthenticationValidWhileOnBody(b)` | 24 | `false` | Keeps a time-bound authorisation alive while an on-body sensor says the device is worn | Rare; wearables |
| `setUnlockedDeviceRequired(b)` | 28 | `false` | Key unusable while the device is locked | Independent of user-auth binding |
| `setUserPresenceRequired(b)` | 28 | `false` | Requires a hardware test of presence (such as a button press) between `initSign` and `sign` | Needs hardware support; uncommon |
| `setUserConfirmationRequired(b)` | 28 | `false` | Key only signs messages the user approved in Protected Confirmation | Transaction signing |
| `setMaxUsageCount(n)` | 31 | unlimited | Key deleted after `n` uses | One-shot keys |
| `setIsStrongBoxBacked(b)` | 28 | `false` | Where the key lives, not who may use it | Not a restriction on use |

Two properties of enforcement matter in a test:

- **Symmetric versus asymmetric.** For AES and HMAC keys, every operation runs inside the Keystore and is subject to the authorisation list. For RSA and EC key pairs, only private-key operations (signing, decryption, key agreement) are restricted; public-key operations (verification, encryption) run in ordinary app code with the public key and need no authentication.
- **Where enforcement happens.** On hardware-backed keys the user-authentication requirement is enforced in secure hardware using authentication tokens issued by the lock screen and biometric stack. `KeyInfo.isUserAuthenticationRequirementEnforcedBySecureHardware()` tells you whether that is the case for a given key.

### Android: user authentication binding and validity (MASTG-KNOW-0001)

Related: [MASTG-KNOW-0001](https://mas.owasp.org/MASTG/knowledge/android/MASVS-AUTH/MASTG-KNOW-0001/); our walkthrough of biometrics on Android is in the [MASTG-KNOW-0001 note](/mobile/mastg-know-0001-biometric-authentication/).

An authentication-bound key works in one of two modes, and the difference is the heart of this weakness:

- **Per-operation (timeout `0`).** Each `Cipher`, `Signature` or `Mac` operation must be authorised by a `BiometricPrompt` that was given that object wrapped in a `BiometricPrompt.CryptoObject`. The Keystore links the authentication to that specific operation. `Cipher.init` succeeds, but `doFinal`/`sign` fails unless the prompt for *this* operation succeeded. Per-operation keys with `AUTH_DEVICE_CREDENTIAL` require Android 11 (API 30) or later.
- **Time-bound (timeout `> 0`).** Any successful authentication of an allowed type within the last *timeout* seconds authorises the key. Crucially, **unlocking the phone counts**: the lock-screen PIN, pattern, password or a Class 3 biometric unlock all produce authentication tokens the Keystore accepts. A key with `setUserAuthenticationParameters(300, AUTH_BIOMETRIC_STRONG or AUTH_DEVICE_CREDENTIAL)` is usable for five minutes after every unlock without the app ever showing a prompt. Outside the window, `Cipher.init` throws `UserNotAuthenticatedException`.

Other rules to keep in mind:

- Only **Class 3 (`BIOMETRIC_STRONG`)** biometrics can authorise Keystore keys. A prompt configured with `BIOMETRIC_WEAK` cannot unlock a `CryptoObject`, so apps that accept Class 2 biometrics are necessarily event-bound for those users.
- Creating an auth-bound key requires a secure lock screen; per-operation biometric-only keys also require at least one enrolled biometric. Removing the secure lock screen permanently invalidates all auth-bound keys, and enrolling a new biometric invalidates per-operation biometric-only keys (unless `setInvalidatedByBiometricEnrollment(false)`). Invalidated keys throw `KeyPermanentlyInvalidatedException` at `init`; the app must delete them and re-enrol the user, not fall back to an unprotected key.
- The OWASP beta tests [MASTG-TEST-0330](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0330/) (extended validity duration) and [MASTG-TEST-0328](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0328/) (enrolment invalidation) check exactly these settings; their demo also shows a trap worth knowing: a key built with `setUserAuthenticationRequired(false)` *and* `setUserAuthenticationParameters(86400, 0)` is not auth-bound at all — the timeout is simply ignored.

### Android: unlocked device, user presence and Protected Confirmation

**`setUnlockedDeviceRequired(true)`** (API 28) makes a key unusable while the device is locked, regardless of whether it is also bound to user authentication. It protects against the scenario user-auth binding with a timeout does not: an app process (or a malicious one acting as it on a rooted device) still running on a locked phone. Keys protecting data at rest that the app only needs in the foreground should carry it. Background features that legitimately need a key while locked — syncing, notifications — are a design decision to document, not a default.

**`setUserPresenceRequired(true)`** (API 28) asks for a test of user presence performed by the secure hardware itself between `initSign` and `sign`, for example a physical button wired to the secure element. It is distinct from authentication (it proves a human is present, not who) and supported on few devices, so you will rarely see it.

**`setUserConfirmationRequired(true)`** (API 28) binds a signing key to **Android Protected Confirmation**. The app shows a `ConfirmationPrompt` with a short text ("Pay £50.00 to J. Smith"); the prompt is rendered by a trusted UI in the TEE, and on approval the app receives `dataThatWasConfirmed` (a CBOR structure containing the prompt text and the app's extra data). The Keystore will only sign that exact structure with the key. This is the strongest form of "what you see is what you sign" available to apps, and it is what an L2 payment or EUDIW signing flow should aspire to. Device support is limited; check `ConfirmationPrompt.isSupported(context)` and have a fallback (per-operation biometric signing with the transaction details in the signed payload).

### Android: purposes, paddings, digests and usage limits

The algorithm parameters in the spec are restrictions too: a key can be used only for the listed **purposes** and only with the listed **block modes**, **encryption and signature paddings** and **digests**. They matter for MASWE-0016 because they limit what an attacker with code execution in the app can *do* with a key they can reach.

Purpose constants appear as integers in decompiled code:

| Constant | Value |
|---|---|
| `PURPOSE_ENCRYPT` | 1 |
| `PURPOSE_DECRYPT` | 2 |
| `PURPOSE_SIGN` | 4 |
| `PURPOSE_VERIFY` | 8 |
| `PURPOSE_WRAP_KEY` | 32 |
| `PURPOSE_ATTEST_KEY` (API 31) | 128 |
| `PURPOSE_AGREE_KEY` (API 31) | 256 |

A purpose of `3` is a normal symmetric encryption key; `12` a signing key; `15` a key pair that both encrypts and signs, which OWASP's [MASTG-TEST-0307](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0307/) and [MASTG-TEST-0308](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0308/) flag under MASWE-0007. From an access-control angle, the dangerous combinations are those that turn a reachable key into an oracle: an RSA key with `PURPOSE_DECRYPT` and `ENCRYPTION_PADDING_NONE` performs raw private-key operations on attacker-chosen input, which is equivalent to signing; an RSA key with PKCS#1 v1.5 encryption padding exposed through an app interface invites padding-oracle attacks; `DIGEST_NONE` on a signing key lets the caller sign arbitrary pre-hashed values. `setRandomizedEncryptionRequired(false)` lets callers supply their own IVs, which usually means fixed or reused ones.

`setMaxUsageCount(n)` (API 31) creates a limited-use key that the Keystore deletes after `n` operations; `KeyInfo.getRemainingUsageCount()` reports the remainder. It suits one-time enrolment or recovery keys.

### Android: verifying restrictions with KeyInfo and attestation (MASTG-KNOW-0044)

Related: [MASTG-KNOW-0044](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0044/).

**`KeyInfo`** reports most of a key's authorisation list at runtime. Obtain it with `SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java)` for secret keys and `KeyFactory.getInstance(key.algorithm, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java)` for private keys. Useful getters: `isUserAuthenticationRequired()`, `getUserAuthenticationValidityDurationSeconds()`, `getUserAuthenticationType()` (API 30), `isInvalidatedByBiometricEnrollment()`, `isUserAuthenticationRequirementEnforcedBySecureHardware()`, `isUserConfirmationRequired()`, `isTrustedUserPresenceRequired()`, `getPurposes()`, `getBlockModes()`, `getDigests()`, `getEncryptionPaddings()`, `getSignaturePaddings()`, `getRemainingUsageCount()` (API 31) and `getSecurityLevel()` (API 31). `KeyInfo` does **not** report whether the key requires an unlocked device; take that from the creation spec (`KeyGenParameterSpec.isUnlockedDeviceRequired()`) or from attestation.

`KeyInfo` is self-reported by the device. When the **server** relies on a key being restricted — "this signature proves the user authenticated with a strong biometric" — it should verify that through **key attestation**: generate the key with `setAttestationChallenge(serverNonce)`, send `KeyStore.getCertificateChain(alias)` to the backend, validate the chain to Google's root and check the attestation extension (OID `1.3.6.1.4.1.11129.2.1.17`). Its authorisation lists include the restrictions themselves — `noAuthRequired`, `userAuthType`, `authTimeout`, `unlockedDeviceRequired`, `trustedConfirmationRequired`, `trustedUserPresenceRequired`, `purpose`, `digest`, `padding` — in the hardware-enforced list when secure hardware enforces them. A backend that accepts device-bound signatures without checking these is trusting the client's word for MASWE-0016. The attestation flow itself is described in our [MASWE-0003 note](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/#android-key-attestation-mastg-know-0044).

### Both platforms: event-bound versus crypto-bound biometrics

This distinction decides whether local authentication is a security control or a user-interface element, and it is where MASWE-0016 meets MASVS-AUTH. Our [MASTG-KNOW-0001 note](/mobile/mastg-know-0001-biometric-authentication/) covers the Android side in depth; in short:

- **Event-bound.** The app shows a prompt (`BiometricPrompt.authenticate(promptInfo)` without a `CryptoObject` on Android; `LAContext.evaluatePolicy` on iOS) and, on success, does something in its own code: unlocks the screen, reads a token from storage, enables a button. The secret was accessible all along; only app logic stood in the way. One hook on the success callback (or the `reply` block) bypasses it. OWASP tracks this as MASWE-0020, with tests [MASTG-TEST-0327](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0327/), [MASTG-TEST-0266](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0266/) and [MASTG-TEST-0267](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0267/).
- **Crypto-bound.** The secret can only be produced by a key operation that the platform will not perform until the user authenticates: an Android Keystore key with `setUserAuthenticationRequired(true)` used through a `CryptoObject`; an iOS Keychain item or Secure Enclave key whose access control requires user presence, so `SecItemCopyMatching` or `SecKeyCreateSignature` triggers the system prompt itself. Hooking the app's callback gains nothing, because the attacker still cannot make the key operate.

MASWE-0016 is, in effect, the key-side half of this: an event-bound flow is almost always a key (or Keychain item) whose access is not restricted. Two subtler failures to look for in apps that *do* use a `CryptoObject`:

- **The crypto result is not used.** The app authenticates with a `CryptoObject` but then ignores the output, or calls `doFinal` on dummy data and treats "no exception" as success. Reversec's research, referenced by the legacy MASTG v1 test [MASTG-TEST-0018](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0018/), includes Frida scripts for both the callback bypass and this exception-handling variant.
- **The secret escapes after first use.** The auth-bound key decrypts a token once, and the app then caches the plaintext token in preferences or memory for the rest of the session or forever. The key was restricted; the data it protected is not.

### iOS: Keychain accessibility and device binding (MASTG-KNOW-0057)

Related: [MASTG-KNOW-0057](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-AUTH/MASTG-KNOW-0057/). The full accessibility table is in our [MASWE-0003 note](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/#ios-keychain-services-and-key-management-mastg-know-0057-mastg-know-0069); here is what each class means for *access*:

| `kSecAttrAccessible…` | Raw value (`pdmn`) | Usable when | Leaves the device |
|---|---|---|---|
| `WhenPasscodeSetThisDeviceOnly` | `akpu` | Unlocked, and only while a passcode is set (item deleted if the passcode is removed) | No |
| `WhenUnlockedThisDeviceOnly` | `aku` | Unlocked | No |
| `WhenUnlocked` (default) | `ak` | Unlocked | Yes (backup, transfer) |
| `AfterFirstUnlockThisDeviceOnly` | `cku` | From first unlock until reboot, including while locked | No |
| `AfterFirstUnlock` | `ck` | From first unlock until reboot, including while locked | Yes |
| `AlwaysThisDeviceOnly` (deprecated) | `dku` | Always | No |
| `Always` (deprecated) | `dk` | Always | Yes |

The raw values are what you see in Frida hooks and in `objection` output. For keys, the defensible choices are `aku` or `akpu`; `cku` is acceptable only for keys that background work genuinely needs while locked; anything without `ThisDeviceOnly` lets the key travel with backups and device migration; and `kSecAttrSynchronizable = true` sends it to every device on the user's iCloud account (synchronizable items cannot use `ThisDeviceOnly` classes).

An accessibility class restricts *when* the item is available, not *who* may use it. Without an access-control object, an `aku` item is readable by any code running as the app whenever the device is unlocked — the OWASP KNOW-0057 page makes the same point: once the device is unlocked, the item is accessible.

### iOS: access control flags (MASTG-KNOW-0056, MASTG-KNOW-0057)

Related: [MASTG-KNOW-0056](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-AUTH/MASTG-KNOW-0056/) (Local Authentication framework) and [MASTG-KNOW-0057](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-AUTH/MASTG-KNOW-0057/).

`SecAccessControlCreateWithFlags(allocator, protection, flags, &error)` combines an accessibility class (`protection`) with **user-presence constraints** (`flags`). The resulting object goes into the item's `kSecAttrAccessControl` attribute, which replaces `kSecAttrAccessible` (the two are mutually exclusive in a query). From then on, `securityd` and the Secure Enclave demand authentication before releasing the item's data or performing an operation with the key — the system shows the prompt, not the app.

| Flag | Raw bit | Meaning |
|---|---|---|
| `.userPresence` | `0x1` | Biometry if available, otherwise device passcode |
| `.biometryAny` | `0x2` | Any enrolled Touch ID / Face ID, including biometrics enrolled later |
| `.biometryCurrentSet` | `0x8` | Only the biometrics enrolled when the item was created; any change makes the item unusable |
| `.devicePasscode` | `0x10` | Device passcode |
| `.or` / `.and` | `0x4000` / `0x8000` | Combine constraints |
| `.privateKeyUsage` | `0x40000000` | Allows private-key operations; required for Secure Enclave keys; **not** a user-presence requirement |
| `.applicationPassword` | `0x80000000` | Additional app-supplied password |

The raw bits are what you will see in a disassembler (`mov w2, 0x8`) or a Frida hook (`flags=0x40000008` is `.privateKeyUsage | .biometryCurrentSet`). OWASP's MASVS-AUTH tests check the flag choice: [MASTG-TEST-0268](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0268/)/[0269](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0269/) for passcode fallback (`.userPresence`, `.devicePasscode`), and [MASTG-TEST-0270](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0270/)/[0271](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0271/) for `.biometryAny` versus `.biometryCurrentSet`.

**Validity windows on iOS.** The KNOW-0057 page notes that iOS has no per-item "valid for N seconds after authentication" setting like Android's timeout. Two mechanisms nevertheless widen authorisation, and both are worth reviewing:

- `LAContext.touchIDAuthenticationAllowableReuseDuration` lets a recent device unlock with Touch ID satisfy the prompt, up to `LATouchIDAuthenticationMaximumAllowableReuseDuration` (five minutes). Passed to Keychain queries through `kSecUseAuthenticationContext`, it is the closest iOS analogue of Android's "unlocking the phone counts".
- An app can pass the same `LAContext` to multiple Keychain operations. Keeping one evaluated context alive for the whole session, instead of creating a fresh one per sensitive operation, can let later operations proceed without a new prompt. Look for contexts stored in long-lived properties.

### iOS: Keychain access groups (MASTG-KNOW-0126)

Related: [MASTG-KNOW-0126](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0126/).

Keychain items belong to an **access group**. Every app and extension whose `keychain-access-groups` entitlement lists that group (always prefixed with the team's App ID prefix) can read, update and delete items in it, subject to their accessibility and access control. That is the iOS answer to "which code may use the key", and it has two traps:

- **Over-broad sharing.** A key stored in `TEAMID.com.example.shared` is available to every app of the team that declares the group and to every extension — keyboard, widget, share or notification service extension — of those apps. Extensions are separate binaries with their own attack surface. Keys that only the main app needs belong in its private group.
- **Accidental default.** When `kSecAttrAccessGroup` is omitted, `SecItemAdd` uses the app's default group, which is the **first** entry of `keychain-access-groups` (then the application identifier, then App Groups). If a shared group is listed first, every item the developer thought was private lands in the shared group.

Extract entitlements with `rabin2 -OC <binary>` or `ldid -e <binary>` (OWASP [MASTG-TECH-0111](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0111/)). Do not confuse this with App Groups (`com.apple.security.application-groups`), which share a *file container*; OWASP's [MASTG-TEST-0388](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0388/) covers that side.

### iOS: Secure Enclave keys need access control too (MASTG-KNOW-0066)

Related: [MASTG-KNOW-0066](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0066/). How to generate Secure Enclave keys is in our [MASWE-0003 note](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/#ios-secure-enclave-keys-and-cryptokit-mastg-know-0066).

A Secure Enclave P-256 key can never leave the Enclave, which tempts developers to treat it as "secure by construction". It is not restricted by construction:

- `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave` requires an access-control object containing `.privateKeyUsage`. With **only** `.privateKeyUsage`, the key signs or decrypts for any code running as the app whenever the protection class allows (usually whenever the device is unlocked).
- CryptoKit's `SecureEnclave.P256.Signing.PrivateKey()` and `SecureEnclave.P256.KeyAgreement.PrivateKey()` with default arguments create exactly that: a key available when unlocked, with no user-presence requirement. Pass an explicit `accessControl:` containing `.privateKeyUsage` plus `.biometryCurrentSet` (or `.userPresence`) for keys that represent user consent.
- CryptoKit's types also restrict the operation class: a `Signing` key cannot do key agreement and vice versa — a useful purpose restriction you get for free.

Unlike Android, iOS gives third-party apps no general way to attest a Secure Enclave key's access control to a server (App Attest attests its own key and the app's integrity, not the ACL of your keys). The backend has to trust the app's code for this, which makes code review and the dynamic tests below more important.

## Testing

The tests below are **Guler Tech methodology**. They are organised around a simple principle: first find every key and what it protects, then establish what the key *allows* (from code, from the creation call, from `KeyInfo` or the Keychain), and finally prove it by using the key without authentication. The last step is the one that turns a configuration observation into a finding a client cannot argue with.

Before you start, classify what each key protects. The same configuration can be fine for a cache key and a finding for a payment-signing key, and every OWASP test in this area is worded "for sensitive data resources worth protecting". A short table — key, protects, sensitivity, expected restrictions — saves arguments later.

### Related OWASP material

No OWASP test is mapped to MASWE-0016, but these existing items check parts of the same configuration. We searched the MASTG knowledge, tests, beta tests, techniques, best practices, rules and demos; the IDs below all exist.

| ID | Platform | What it checks | Weakness it is mapped to | Dimension of MASWE-0016 |
|---|---|---|---|---|
| [MASTG-TEST-0327](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0327/) | Android | `BiometricPrompt.authenticate` without `CryptoObject`; keys without `setUserAuthenticationRequired(true)` | MASWE-0020 | Who |
| [MASTG-TEST-0330](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0330/) | Android | Authentication validity duration > 0 | MASWE-0020 | How long |
| [MASTG-TEST-0328](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0328/) | Android | `setInvalidatedByBiometricEnrollment(false)` | MASWE-0022 | Which biometrics |
| [MASTG-TEST-0326](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0326/) | Android | `DEVICE_CREDENTIAL` fallback | MASWE-0021 | Who |
| [MASTG-TEST-0329](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0329/) | Android | `setConfirmationRequired(false)` on the prompt | MASWE-0020 | Intent |
| [MASTG-TEST-0307](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0307/), [MASTG-TEST-0308](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0308/) | Android | Asymmetric keys with multiple purposes (static and Frida) | MASWE-0007 | What |
| [MASTG-TEST-0266](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0266/), [MASTG-TEST-0267](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0267/) | iOS | `LAContext.evaluatePolicy` without a user-presence Keychain ACL | MASWE-0020 | Who |
| [MASTG-TEST-0268](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0268/), [MASTG-TEST-0269](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0269/) | iOS | `.userPresence` / `.devicePasscode` fallback | MASWE-0021 | Who |
| [MASTG-TEST-0270](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0270/), [MASTG-TEST-0271](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0271/) | iOS | `.biometryAny` instead of `.biometryCurrentSet` | MASWE-0022 | Which biometrics |
| [MASTG-TEST-0017](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0017/), [MASTG-TEST-0018](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0018/), [MASTG-TEST-0015](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0015/) | Android | Legacy (MASTG v1): confirm credentials, biometric authentication, key purposes | — | Who, how long, what |
| [MASTG-TEST-0064](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0064/), [MASTG-TEST-0062](https://mas.owasp.org/MASTG/tests/ios/MASVS-CRYPTO/MASTG-TEST-0062/) | iOS | Legacy (MASTG v1): biometric authentication, key management (including "keys are not synchronized over devices") | — | Who, where |

The relevant semgrep rules ship in the MASTG repository as `mastg-android-biometric-event-bound.yml`, `mastg-android-biometric-validity-duration.yml`, `mastg-android-biometric-invalidated-enrollment.yml`, `mastg-android-biometric-device-credential-fallback.yml` and `mastg-android-asymmetric-key-pair-used-for-multiple-purposes.yml`, with demos MASTG-DEMO-0090 to MASTG-DEMO-0093 (Android) and MASTG-DEMO-0041 to MASTG-DEMO-0046 (iOS). Run them as part of GT-0016-1 and GT-0016-4; our tests add the dimensions they do not cover (unlocked-device, device binding, access groups, Secure Enclave ACLs, KeyInfo, and proof of use).

### GT-0016-1: Keystore key restrictions in code (Android)

Guler Tech methodology. Platform: Android. Type: static (code).

#### Overview

Extract every `KeyGenParameterSpec.Builder` and `KeyProtection.Builder` chain from the decompiled app, reconstruct each key's authorisation list, and compare it with what the key protects. jadx output is Java even for Kotlin sources, string constants are inlined (`setBlockModes("GCM")`) and purposes appear as integers, so you can read restrictions directly from the decompiled builder call.

#### Prerequisites

- APK and splits; `jadx` ([MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)) and `semgrep` ([MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [semgrep MASTG-TOOL-0110](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/)).
- The OWASP rules listed above (from the `rules/` directory of the MASTG repository).

#### Steps

1. **Decompile and list every key specification with its full chain.**

   ```bash
   jadx -d out/ app.apk
   grep -rn -A12 -E 'new KeyGenParameterSpec\.Builder\(|new KeyProtection\.Builder\(' out/sources/ \
     | grep -vE '^out/sources/(androidx|com/google/crypto/tink)/' > keyspecs.txt
   ```

   jadx sometimes splits a fluent chain into statements on a local `builder` variable, and Kotlin `apply {}` blocks decompile into separate calls, so read a dozen lines after each constructor rather than relying on one-line matches.

2. **Run the OWASP rules.**

   ```bash
   for r in biometric-event-bound biometric-validity-duration biometric-invalidated-enrollment \
            biometric-device-credential-fallback asymmetric-key-pair-used-for-multiple-purposes; do
     semgrep -c "mastg/rules/mastg-android-$r.yml" out/sources/ --text
   done
   ```

   Note that OWASP's event-bound rule only flags keys without `setUserAuthenticationRequired(true)` in files that import `BiometricPrompt`. Keys created elsewhere — the common case for a storage KEK — are not covered, which is why the next rule exists.

3. **Run rules for the restrictions OWASP does not cover.**

   ```yaml
   rules:
     - id: gt-keystore-key-without-user-auth
       languages: [java]
       severity: WARNING
       message: Keystore key created without setUserAuthenticationRequired(true)
       patterns:
         - pattern: new KeyGenParameterSpec.Builder(...)
         - pattern-not-inside: new KeyGenParameterSpec.Builder(...). ... .setUserAuthenticationRequired(true)
     - id: gt-keystore-key-without-unlocked-device
       languages: [java]
       severity: INFO
       message: Keystore key usable while the device is locked (no setUnlockedDeviceRequired(true))
       patterns:
         - pattern: new KeyGenParameterSpec.Builder(...)
         - pattern-not-inside: new KeyGenParameterSpec.Builder(...). ... .setUnlockedDeviceRequired(true)
     - id: gt-keystore-key-loose-crypto-restrictions
       languages: [java]
       severity: WARNING
       message: Key restriction weakened ($X)
       pattern-either:
         - pattern: $X.setRandomizedEncryptionRequired(false)
         - pattern: $X.setEncryptionPaddings(..., "NoPadding", ...)
         - pattern: $X.setDigests(..., "NONE", ...)
   ```

   ```bash
   semgrep -c gt-keystore-restrictions.yml out/sources/ --text
   ```

   `"NoPadding"` is expected for AES-GCM; it matters only on RSA keys, so triage those hits by algorithm.

4. **Check library-created keys.** Tink's `AndroidKeysetManager` creates its master key without authentication, and Jetpack Security's `MasterKey.Builder` takes `setUserAuthenticationRequired(boolean, int)` only if the developer asks. Record which data each library key protects.

5. **Map each key to what it protects.** Follow the alias from the builder to `KeyStore.getKey(alias, …)`, then to the `Cipher`/`Signature`/`Mac` that uses it, then to the data (a token in preferences, a database, a request header). Note whether the operation is wrapped in `BiometricPrompt.CryptoObject`.

#### Observation

Per key: alias, algorithm, purposes (decoded), user-auth required, timeout and authenticator types, enrolment invalidation, unlocked-device, user confirmation, max usage count, StrongBox, and what it protects; plus semgrep output.

#### Evaluation

The test **fails** for a key that protects sensitive data or authorises a sensitive operation if:

- it is created without `setUserAuthenticationRequired(true)`, or is used outside a `CryptoObject` flow while the design claims biometric protection;
- it is time-bound with a timeout longer than the operation needs (minutes or hours for payment, identity or credential keys), or uses the deprecated `setUserAuthenticationValidityDurationSeconds` with a positive value;
- it sets `setInvalidatedByBiometricEnrollment(false)`;
- it lacks `setUnlockedDeviceRequired(true)` and nothing in the design requires use while locked;
- its purposes, paddings or digests are broader than its use (multiple roles, RSA `NoPadding`, `DIGEST_NONE`, randomised encryption disabled).

It **passes** when each key's authorisation list matches its sensitivity and use. Keys that protect non-sensitive data, or that must work in the background, can legitimately be unrestricted — record the justification.

#### Demo

The OWASP sample shared by [MASTG-DEMO-0091](https://mas.owasp.org/MASTG/demos/android/MASVS-AUTH/MASTG-DEMO-0091/MASTG-DEMO-0091/) and [MASTG-DEMO-0093](https://mas.owasp.org/MASTG/demos/android/MASVS-AUTH/MASTG-DEMO-0093/MASTG-DEMO-0093/) creates the key that protects a secret token like this:

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

jadx renders it on one line (`new KeyGenParameterSpec.Builder(this.KEY_NAME, 3).setBlockModes("GCM")…`). The OWASP validity-duration rule reports line 52 twice (once per timeout setter) and the enrolment rule reports it once. Our rule adds the root cause:

```text
    MastgTest_reversed.java
    ❯❱ gt-keystore-key-without-user-auth
          Keystore key created without setUserAuthenticationRequired(true)

           52┆ keyGenerator.init(new KeyGenParameterSpec.Builder(this.KEY_NAME, 3).setBlockModes("GCM").se
               tEncryptionPaddings("NoPadding").setUserAuthenticationRequired(false).setInvalidatedByBiome
               tricEnrollment(false).setUserAuthenticationParameters(86400,
               0).setUserAuthenticationValidityDurationSeconds(86400).build());
```

The test fails, and the order of findings matters for the report: because `setUserAuthenticationRequired(false)` is set, the 24-hour timeout and the enrolment flag are irrelevant — the key needs no authentication at all, even though the app wraps it in a `CryptoObject` and shows a `BIOMETRIC_STRONG` prompt. The prompt is decorative.

### GT-0016-2: Key restrictions at creation and in KeyInfo (Android)

Guler Tech methodology. Platform: Android. Type: dynamic (hooks).

#### Overview

Static analysis misses keys created by libraries, by reflection, or with values computed at runtime. This test records the actual `KeyGenParameterSpec` each key is created with, and reads `KeyInfo` for keys that already exist, so you know the real authorisation list of every key the app owns.

#### Prerequisites

- Rooted device or emulator with `frida-server` ([MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/)); Android 11+ for every getter used below (wrap version-specific getters in `try` on older devices).
- Clear app data first (`adb shell pm clear com.example.app`) so keys are created while you watch.

#### Steps

1. **Hook spec creation** (generated keys) and protection specs (imported keys):

   ```javascript
   // gt-keyspec-dump.js
   Java.perform(function () {
     const P = { 1: 'ENCRYPT', 2: 'DECRYPT', 4: 'SIGN', 8: 'VERIFY', 32: 'WRAP_KEY', 128: 'ATTEST_KEY', 256: 'AGREE_KEY' };
     const purposes = (p) => Object.keys(P).filter((b) => (p & b) !== 0).map((b) => P[b]).join('|');
     const arr = (a) => { if (a === null) return '[]'; const o = []; for (let i = 0; i < a.length; i++) o.push(String(a[i])); return '[' + o.join(',') + ']'; };
     const safe = (f) => { try { return f(); } catch (e) { return 'n/a'; } };

     const GenBuilder = Java.use('android.security.keystore.KeyGenParameterSpec$Builder');
     GenBuilder.build.implementation = function () {
       const s = this.build();
       console.log('\n[KeyGenParameterSpec] alias=' + s.getKeystoreAlias() + ' purposes=' + purposes(s.getPurposes()) +
         '\n  userAuthRequired=' + s.isUserAuthenticationRequired() +
         ' timeout=' + s.getUserAuthenticationValidityDurationSeconds() +
         ' authType=' + safe(() => s.getUserAuthenticationType()) +
         ' invalidatedByEnrollment=' + s.isInvalidatedByBiometricEnrollment() +
         '\n  unlockedDeviceRequired=' + safe(() => s.isUnlockedDeviceRequired()) +
         ' userConfirmation=' + safe(() => s.isUserConfirmationRequired()) +
         ' userPresence=' + safe(() => s.isUserPresenceRequired()) +
         ' strongBox=' + safe(() => s.isStrongBoxBacked()) +
         ' maxUsage=' + safe(() => s.getMaxUsageCount()) +
         '\n  blockModes=' + arr(s.getBlockModes()) + ' paddings=' + arr(s.getEncryptionPaddings()) +
         ' sigPaddings=' + arr(s.getSignaturePaddings()) + ' digests=' + safe(() => arr(s.getDigests())) +
         ' randomizedEnc=' + s.isRandomizedEncryptionRequired());
       console.log(Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new()).split('\n').slice(1, 6).join('\n'));
       return s;
     };

     const ProtBuilder = Java.use('android.security.keystore.KeyProtection$Builder');
     ProtBuilder.build.implementation = function () {
       const s = this.build();
       console.log('\n[KeyProtection] purposes=' + purposes(s.getPurposes()) +
         ' userAuthRequired=' + s.isUserAuthenticationRequired() +
         ' timeout=' + s.getUserAuthenticationValidityDurationSeconds() +
         ' unlockedDeviceRequired=' + safe(() => s.isUnlockedDeviceRequired()));
       return s;
     };
   });
   ```

   `getDigests()` throws if no digests were set, hence the `safe` wrapper.

   ```bash
   frida -U -f com.example.app -l gt-keyspec-dump.js -o keyspecs.log
   ```

2. **Exercise every flow that creates keys:** onboarding, login, enabling biometric login, enabling a PIN, adding a payment method, signing a transaction, enabling offline mode.

3. **Read `KeyInfo` for keys that already exist** (for example, keys created before you attached). Reuse the `inventory()` script from our [MASWE-0015 note](/mobile/maswe-0015-key-rotation-not-implemented/#gt-0015-3-key-lifecycle-at-runtime-android), replacing the printed fields with:

   ```javascript
   line += ' authRequired=' + info.isUserAuthenticationRequired() +
     ' timeout=' + info.getUserAuthenticationValidityDurationSeconds() +
     ' authType=' + info.getUserAuthenticationType() +
     ' hwEnforced=' + info.isUserAuthenticationRequirementEnforcedBySecureHardware() +
     ' invalidatedByEnrollment=' + info.isInvalidatedByBiometricEnrollment() +
     ' confirmation=' + info.isUserConfirmationRequired() +
     ' purposes=' + info.getPurposes() +
     ' level=' + info.getSecurityLevel();
   ```

   `getSecurityLevel()` returns `0` (software), `1` (TEE), `2` (StrongBox) or a negative "unknown" value. Remember that `KeyInfo` does not expose the unlocked-device flag; take it from step 1.

4. **Optionally, read the attestation record.** For asymmetric keys created with an attestation challenge, dump `KeyStore.getCertificateChain(alias)[0].getEncoded()` to a file and inspect the extension `1.3.6.1.4.1.11129.2.1.17` (`openssl asn1parse -inform DER -in leaf.der`, or Google's attestation parsing sample) to see the authorisation list as the secure hardware reports it.

#### Observation

The log of every key specification with a short stack trace (which class created it), the `KeyInfo` inventory, and, where available, the attested authorisation list.

#### Evaluation

Apply the same criteria as [GT-0016-1](#gt-0016-1-keystore-key-restrictions-in-code-android) to the observed values. Additionally, the test **fails** if `hwEnforced=false` (or the security level is software) for a key the design presents as hardware-protected and user-gated, and the backend accepts that key's output as proof of user authentication.

#### Demo

Output for a vulnerable lab app that "protects" its refresh token with biometrics:

```text
[KeyGenParameterSpec] alias=token_key purposes=ENCRYPT|DECRYPT
  userAuthRequired=false timeout=0 authType=2 invalidatedByEnrollment=true
  unlockedDeviceRequired=false userConfirmation=false userPresence=false strongBox=true maxUsage=-1
  blockModes=[GCM] paddings=[NoPadding] sigPaddings=[] digests=n/a randomizedEnc=true
    at com.example.auth.TokenVault.createKey(TokenVault.java:41)
    at com.example.auth.TokenVault.enableBiometricLogin(TokenVault.java:88)
```

StrongBox-backed, created from `enableBiometricLogin`, and not bound to authentication or to the unlocked state: the test fails. This is OWASP's "assuming hardware implies restriction" mode in one line of output.

### GT-0016-3: Using Keystore keys without authentication (Android)

Guler Tech methodology. Platform: Android. Type: dynamic (hooks, exploitation).

#### Overview

The decisive test: from inside the app process, without any prompt, ask the Keystore to use each key. If the operation succeeds, any code running as the app can do the same, and whatever the key protects is available to an attacker with instrumentation, root, or a malicious library. Running the same probe right after unlocking the phone, and with the screen locked, measures the time-window and unlocked-device restrictions as well.

#### Prerequisites

- As GT-0016-2, with the app running and the user logged in.
- Test data only: the probe encrypts and signs throwaway values and does not modify app data, but run it on a test account.

#### Steps

1. **Load the probe** into the running app:

   ```javascript
   // gt-key-use-probe.js
   Java.perform(function () {
     const KeyStore = Java.use('java.security.KeyStore');
     const Cipher = Java.use('javax.crypto.Cipher');
     const Mac = Java.use('javax.crypto.Mac');
     const Signature = Java.use('java.security.Signature');
     const SecretKey = Java.use('javax.crypto.SecretKey');
     const PrivateKey = Java.use('java.security.PrivateKey');
     const probe = Java.array('byte', [0x70, 0x72, 0x6f, 0x62, 0x65]);

     globalThis.probeAll = function () {
       Java.perform(function () {
         const ks = KeyStore.getInstance('AndroidKeyStore');
         ks.load(null, null);
         const e = ks.aliases();
         while (e.hasMoreElements()) {
           const alias = e.nextElement().toString();
           let result;
           try {
             const key = ks.getKey(alias, null);
             const alg = key.getAlgorithm();
             if (SecretKey.class.isInstance(key) && alg === 'AES') {
               const c = Cipher.getInstance('AES/GCM/NoPadding');
               c.init.overload('int', 'java.security.Key').call(c, 1, key);
               result = 'ENCRYPT ok (' + c.doFinal.overload('[B').call(c, probe).length + ' bytes)';
             } else if (SecretKey.class.isInstance(key) && alg.indexOf('Hmac') === 0) {
               const m = Mac.getInstance(alg);
               m.init.overload('java.security.Key').call(m, key);
               result = 'MAC ok (' + m.doFinal.overload('[B').call(m, probe).length + ' bytes)';
             } else if (PrivateKey.class.isInstance(key)) {
               const s = Signature.getInstance(alg === 'EC' ? 'SHA256withECDSA' : 'SHA256withRSA');
               s.initSign.overload('java.security.PrivateKey').call(s, Java.cast(key, PrivateKey));
               s.update.overload('[B').call(s, probe);
               result = 'SIGN ok (' + s.sign.overload().call(s).length + ' bytes)';
             } else {
               result = 'skipped (' + alg + ')';
             }
             result = '[!] ' + result + ' WITHOUT user authentication';
           } catch (err) {
             result = '[+] refused: ' + err;
           }
           console.log(alias + ': ' + result);
         }
       });
     };
   });
   ```

   ```bash
   frida -U -F -l gt-key-use-probe.js    # attach to the app in the foreground
   # then, in the REPL:
   probeAll()
   ```

   A key whose purposes do not include the attempted operation (for example decrypt-only, or an RSA key restricted to OAEP decryption) is refused for that reason, not because of authentication; read the exception text and, if needed, adapt the probe to the key's real purpose (decrypt a value the app stored, using the stored IV).

2. **Run it in three device states:**

   | State | How | What it measures |
   |---|---|---|
   | A. Unlocked, long after the last unlock | Unlock, wait longer than the longest configured timeout, bring the app to the foreground, run `probeAll()` | Whether keys need authentication at all |
   | B. Just unlocked | Lock the device, unlock it with the PIN, immediately run `probeAll()` | Whether time-bound keys are authorised by a plain device unlock |
   | C. Locked | Run `probeAll()` from the REPL a few seconds after locking the screen | Whether keys work while locked (`setUnlockedDeviceRequired`) |

   On recent Android versions the cached-apps freezer can pause a backgrounded app after a few seconds; if the REPL stops responding in state C, run the probe from a component that the app keeps alive (a foreground service) or on an emulator, and say so in the report.

3. **For keys that pass state A, confirm the real-world impact.** Use the same access to decrypt the data the key protects (read the ciphertext and IV from storage, `cipher.init(DECRYPT_MODE, key, GCMParameterSpec(128, iv))`), or produce a signature the backend accepts (sign a request body exactly as the app does and replay it). One decrypted token or one accepted signature is your proof.

4. **For event-bound flows**, demonstrate the bypass directly: hook the app's `onAuthenticationSucceeded` path (see our [MASTG-KNOW-0001 note](/mobile/mastg-know-0001-biometric-authentication/) and the Reversec scripts referenced by MASTG-TEST-0018) and show the protected screen or secret without a valid biometric.

#### Observation

For each alias and device state: operation attempted, success or the exact exception (`UserNotAuthenticatedException`, `KeyPermanentlyInvalidatedException`, `IllegalBlockSizeException` caused by a Keystore "key user not authenticated" error, or a locked-device error), plus the impact evidence from step 3.

#### Evaluation

The test **fails** for a key protecting sensitive data or a sensitive operation if:

- the probe succeeds in state A (no authentication requirement in practice);
- the probe succeeds in state B for a key that is supposed to require explicit, per-operation authentication (time window satisfied by a device unlock);
- the probe succeeds in state C for a key that protects data the app only needs in the foreground.

It **passes** if sensitive keys are refused in state A and C, and in state B unless a short, justified window is part of the design.

#### Demo

Probe output on a vulnerable lab app in state A:

```text
token_key: [!] ENCRYPT ok (21 bytes) WITHOUT user authentication
device_binding_key: [!] SIGN ok (71 bytes) WITHOUT user authentication
records_kek_v2: [+] refused: android.security.keystore.UserNotAuthenticatedException: User not authenticated
```

`records_kek_v2` is time-bound and outside its window; the other two keys need nothing. Repeating in state B:

```text
records_kek_v2: [!] ENCRYPT ok (21 bytes) WITHOUT user authentication
```

The records KEK has a 300-second window satisfied by unlocking the phone. With `device_binding_key` you then sign a login challenge exactly as the app does and the backend accepts it: device-bound login is usable by anyone with code execution in the app, so the test fails with a demonstrated authentication bypass.

### GT-0016-4: Keychain access control in the binary (iOS)

Guler Tech methodology, building on OWASP [MASTG-TEST-0266](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0266/), [MASTG-TEST-0268](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0268/) and [MASTG-TEST-0270](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0270/). Platform: iOS. Type: static (binary).

#### Overview

Swift and Objective-C reference Keychain attributes as imported symbols (`kSecAttrAccessibleAfterFirstUnlock`, `kSecAttrSynchronizable`, `kSecAttrTokenIDSecureEnclave`…), and pass access-control flags to `SecAccessControlCreateWithFlags` as an integer in register `w2`. That makes the binary a reliable source for which protection classes and flags the app uses at all, and, with some disassembly, where.

#### Prerequisites

- A decrypted IPA and the main binary plus any app extensions (`Payload/App.app/PlugIns/*.appex`) and embedded frameworks ([MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/)).
- `radare2`/`rabin2` ([MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/)) and optionally `ldid` or `ipsw` for entitlements.

#### Steps

1. **List the Keychain-related imports of every binary.**

   ```bash
   unzip -q app.ipa -d ipa/
   for b in ipa/Payload/App.app/App ipa/Payload/App.app/PlugIns/*.appex/* ipa/Payload/App.app/Frameworks/*.framework/*; do
     [ -f "$b" ] && file "$b" | grep -q Mach-O || continue
     echo "== $b"
     rabin2 -i "$b" | grep -oE 'kSecAttrAccessible[A-Za-z]*|kSecAttrSynchronizable|kSecAttrAccessGroup|kSecAttrTokenIDSecureEnclave|kSecUseAuthenticationContext|SecAccessControlCreateWithFlags|SecKeyCreateRandomKey|LAContext|SecureEnclave' | sort -u
   done
   ```

   Imports of `kSecAttrAccessibleAfterFirstUnlock`, `kSecAttrAccessibleAlways*` or non-`ThisDeviceOnly` classes, of `kSecAttrSynchronizable`, or of `kSecAttrTokenIDSecureEnclave` without `SecAccessControlCreateWithFlags` are leads. `LAContext` without `SecAccessControlCreateWithFlags` is the event-bound pattern (MASTG-TEST-0266).

2. **Read the flags at each `SecAccessControlCreateWithFlags` call** (the approach of OWASP [MASTG-DEMO-0045](https://mas.owasp.org/MASTG/demos/ios/MASVS-AUTH/MASTG-DEMO-0045/MASTG-DEMO-0045/)):

   ```bash
   r2 -q -e scr.color=false -c 'aaa; axt @ sym.imp.SecAccessControlCreateWithFlags' ipa/Payload/App.app/App
   # for each caller address:
   r2 -q -e scr.color=false -c 'aaa; pd -12 @ 0x100004194' ipa/Payload/App.app/App
   ```

   `w2`/`x2` holds the flags and `x1` the protection class, usually loaded from a relocation such as `reloc.kSecAttrAccessibleWhenUnlocked`. Values above 16 bits are built with `mov` plus `movk` (for example `mov w2, 8` and `movk w2, 0x4000, lsl 16` for `0x40000008`). Decode with the flag table in [Knowledge](#ios-access-control-flags-mastg-know-0056-mastg-know-0057).

3. **Check the access groups.**

   ```bash
   rabin2 -OC ipa/Payload/App.app/App          # or: ldid -e ipa/Payload/App.app/App
   for x in ipa/Payload/App.app/PlugIns/*.appex; do echo "== $x"; rabin2 -OC "$x/$(basename "$x" .appex)"; done
   ```

   Note every group in `keychain-access-groups`, which group is listed **first** (the default), and which extensions share it.

4. **Look for long-lived authentication contexts.** Search for `touchIDAuthenticationAllowableReuseDuration` (an Objective-C selector, so it shows in strings: `rabin2 -zz App | grep -i reuseduration`) and for `LAContext` stored in properties rather than created per operation (requires reading the disassembly or a class dump).

#### Observation

Per binary: protection classes imported, Secure Enclave and synchronizable use, every `SecAccessControlCreateWithFlags` call with decoded flags and protection class, entitlements and access groups, and reuse-duration usage.

#### Evaluation

The test **fails** if keys or secrets protecting sensitive operations are created with: no access-control object (only an accessibility class); flags limited to `.privateKeyUsage`; `.biometryAny` where enrolment changes should invalidate access; `.userPresence`/`.devicePasscode` where policy requires biometrics; a protection class that is usable while locked or migratable; `kSecAttrSynchronizable`; or if sensitive keys are in a shared access group (explicitly, or via the first-listed default) that untrusted extensions can reach. Static results are leads for GT-0016-5 and GT-0016-6, which confirm which item each call creates.

#### Demo

OWASP's [MASTG-DEMO-0045](https://mas.owasp.org/MASTG/demos/ios/MASVS-AUTH/MASTG-DEMO-0045/MASTG-DEMO-0045/) stores a token with:

```swift
let accessControl = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlocked, .biometryAny, nil)
```

and the disassembly around the call shows the flag value directly:

```text
│           0x10000418c      mov x1, x19
│           0x100004190      mov w2, 2
│           0x100004194      bl sym.imp.SecAccessControlCreateWithFlags
```

`w2 = 2` is `.biometryAny` and the protection class is `kSecAttrAccessibleWhenUnlocked` (migratable). For MASWE-0016 this fails twice: newly enrolled biometrics unlock the item (MASWE-0022), and the token can leave the device in a backup because the class is not `ThisDeviceOnly`.

### GT-0016-5: Keychain item attributes at runtime (iOS)

Guler Tech methodology, building on OWASP [MASTG-TEST-0267](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0267/), [MASTG-TEST-0269](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0269/) and [MASTG-TEST-0271](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0271/). Platform: iOS. Type: dynamic.

#### Overview

Record the exact attributes of every Keychain item and key the app creates — accessibility, access control, access group, synchronizable, token — and tie each to a code path. Then dump the Keychain to see the state of items that already exist.

#### Prerequisites

- Jailbroken device with `frida-server`, or a repackaged app with the Frida gadget ([MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/)); `objection` for dumping ([MASTG-TECH-0061](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0061/)).
- Delete and reinstall the app first so items are created while you watch (and remember items from older installs may persist; see our [MASWE-0015 note](/mobile/maswe-0015-key-rotation-not-implemented/#ios-keychain-and-secure-enclave-key-versioning)).

#### Steps

1. **Hook item creation and access-control construction.**

   ```javascript
   // gt-keychain-acl.js (Frida 17; on older Frida use Module.findExportByName(null, name))
   const exp = (n) => Module.getGlobalExportByName(n);
   const FLAGS = [[0x1, 'userPresence'], [0x2, 'biometryAny'], [0x8, 'biometryCurrentSet'],
     [0x10, 'devicePasscode'], [0x20, 'watch/companion'], [0x4000, 'or'], [0x8000, 'and'],
     [0x40000000, 'privateKeyUsage'], [0x80000000, 'applicationPassword']];
   const decode = (v) => FLAGS.filter(([b]) => ((v & b) >>> 0) === b).map(([, n]) => n).join('|') || 'none';
   const bt = (ctx) => Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, 4).map(DebugSymbol.fromAddress).join('\n    ');

   Interceptor.attach(exp('SecAccessControlCreateWithFlags'), {
     onEnter(args) {
       const flags = args[2].toUInt32();
       console.log('[SecAccessControlCreateWithFlags] protection=' + new ObjC.Object(args[1]) +
         ' flags=0x' + flags.toString(16) + ' (' + decode(flags) + ')\n    ' + bt(this.context));
     }
   });

   const show = ['class', 'svce', 'acct', 'atag', 'pdmn', 'accc', 'agrp', 'sync', 'tkid'];
   function dump(tag, dictPtr, ctx) {
     const d = new ObjC.Object(dictPtr);
     const out = show.map((k) => { const v = d.objectForKey_(k); return v === null ? null : k + '=' + v; }).filter((x) => x);
     console.log('[' + tag + '] ' + out.join(' ') + '\n    ' + bt(ctx));
   }
   Interceptor.attach(exp('SecItemAdd'), { onEnter(args) { dump('SecItemAdd', args[0], this.context); } });
   Interceptor.attach(exp('SecKeyCreateRandomKey'), { onEnter(args) { dump('SecKeyCreateRandomKey', args[0], this.context); } });
   ```

   ```bash
   frida -U -f com.example.app -l gt-keychain-acl.js -o keychain-acl.log
   ```

   `pdmn` is the accessibility class (`ak`, `aku`, `ck`, `cku`, `akpu`, `dk`, `dku`), `accc` the access-control object, `agrp` the access group, `sync` the synchronizable flag, and `tkid = com.apple.setoken` marks a Secure Enclave key. For `SecKeyCreateRandomKey`, the private-key attributes (including `accc`) sit in a nested dictionary printed as part of the top-level object, so read the full description if the summary line misses them.

2. **Exercise every flow** that stores secrets or creates keys (login, "remember me", enabling Face ID, adding a card, enrolling the device).

3. **Dump the resulting Keychain state.**

   ```bash
   objection -n com.example.app start
   # in the REPL:
   ios keychain dump --json keychain.json
   ```

   The *Accessible* column shows the class, *ACL* the decoded access-control constraints (objection decodes them with the private `SecAccessControlGetConstraints` call), and *Data* whether the content was readable. objection only sees the app's own access groups.

#### Observation

For every item: who created it (backtrace), class, accessibility, access-control flags, access group, synchronizable, Secure Enclave token, and what it contains or protects.

#### Evaluation

Same criteria as [GT-0016-4](#gt-0016-4-keychain-access-control-in-the-binary-ios), applied to observed values. Typical failures: a refresh token or key in `ck`/`ak` with no `accc`; a Secure Enclave key whose `accc` decodes to `privateKeyUsage` only; `sync=1` on a key; a sensitive item stored in the team-shared group.

#### Demo

A vulnerable lab app that offers "Face ID login":

```text
[SecAccessControlCreateWithFlags] protection=aku flags=0x40000000 (privateKeyUsage)
    0x1022f81c4 App!DeviceBinding.createKey()
[SecKeyCreateRandomKey] tkid=com.apple.setoken
    0x1022f8240 App!DeviceBinding.createKey()
[SecItemAdd] class=genp svce=com.example.auth acct=refresh pdmn=ck agrp=ABCDE12345.com.example.shared
    0x1022f9a10 App!TokenStore.save(_:)
```

```text
Created                    Accessible        ACL    Type      Account  Service           Data
-------------------------  ----------------  -----  --------  -------  ----------------  ------------------
2026-11-09 10:41:07 +0000  AfterFirstUnlock  None   Password  refresh  com.example.auth  rt.6f3e...(redacted)
```

The device-binding key lives in the Secure Enclave but needs no user presence; the refresh token is readable whenever the phone has been unlocked once since boot, by every app and extension in the shared group, with no ACL — and the dump displayed it without any prompt. The Face ID prompt the app shows at launch is event-bound. The test fails.

### GT-0016-6: Using Keychain items and Secure Enclave keys without authentication (iOS)

Guler Tech methodology. Platform: iOS. Type: dynamic (hooks, exploitation).

#### Overview

The iOS counterpart of GT-0016-3. From inside the app, ask the Keychain for each item's data with user interaction forbidden, and ask each Secure Enclave key to sign. Protected items fail with `errSecInteractionNotAllowed` (-25308) instead of prompting; unprotected ones simply return. This proves, without guesswork, which secrets any code in the app can take.

#### Prerequisites

- As GT-0016-5, app running and logged in. The probe reads secrets: run it on a test account and redact the output.

#### Steps

1. **Probe generic-password items.**

   ```javascript
   // gt-keychain-probe.js (Frida 17)
   const exp = (n) => Module.getGlobalExportByName(n);
   const K = (n) => new ObjC.Object(exp(n).readPointer());
   const copyMatching = new NativeFunction(exp('SecItemCopyMatching'), 'int', ['pointer', 'pointer']);
   ObjC.classes.NSBundle.bundleWithPath_('/System/Library/Frameworks/LocalAuthentication.framework').load();
   const YES = ObjC.classes.NSNumber.numberWithBool_(true);

   function run(dict) {
     const out = Memory.alloc(Process.pointerSize);
     out.writePointer(NULL);
     const st = copyMatching(dict.handle, out);
     return { st: st, res: out.readPointer() };
   }

   globalThis.probeItems = function () {
     const list = ObjC.classes.NSMutableDictionary.dictionary();
     list.setObject_forKey_(K('kSecClassGenericPassword'), K('kSecClass'));
     list.setObject_forKey_(YES, K('kSecReturnAttributes'));
     list.setObject_forKey_(K('kSecMatchLimitAll'), K('kSecMatchLimit'));
     const r = run(list);
     if (r.st !== 0) { console.log('list failed: ' + r.st); return; }
     const items = new ObjC.Object(r.res);
     for (let i = 0; i < items.count(); i++) {
       const it = items.objectAtIndex_(i);
       const ctx = ObjC.classes.LAContext.alloc().init();
       ctx.setInteractionNotAllowed_(true);
       const q = ObjC.classes.NSMutableDictionary.dictionary();
       q.setObject_forKey_(K('kSecClassGenericPassword'), K('kSecClass'));
       ['svce', 'acct', 'agrp'].forEach(function (a) { const v = it.objectForKey_(a); if (v !== null) q.setObject_forKey_(v, a); });
       q.setObject_forKey_(YES, K('kSecReturnData'));
       q.setObject_forKey_(K('kSecMatchLimitOne'), K('kSecMatchLimit'));
       q.setObject_forKey_(ctx, K('kSecUseAuthenticationContext'));
       const d = run(q);
       const label = it.objectForKey_('svce') + '/' + it.objectForKey_('acct') + ' pdmn=' + it.objectForKey_('pdmn');
       console.log(label + ' -> ' + (d.st === 0 ? '[!] READ without user interaction' :
         d.st === -25308 ? '[+] interaction required' : 'status ' + d.st));
     }
   };
   ```

   ```bash
   frida -U -F -l gt-keychain-probe.js
   # then: probeItems()
   ```

2. **Probe Secure Enclave and other private keys.** Query `kSecClassKey` with `kSecAttrKeyClass = kSecAttrKeyClassPrivate`, `kSecReturnRef = true` and the same non-interactive `LAContext` in `kSecUseAuthenticationContext`, then call `SecKeyCreateSignature(key, kSecKeyAlgorithmECDSASignatureMessageX962SHA256, data, &error)` through a `NativeFunction`. A signature returned without a prompt means the key is not presence-gated; an error mentioning that interaction is not allowed means it is. If you skip the non-interactive context, the system prompt appearing is itself the evidence — cancel it.

3. **Check reuse windows.** Hook `-[LAContext setTouchIDAuthenticationAllowableReuseDuration:]` and `-[LAContext evaluatePolicy:localizedReason:reply:]` and note whether the app reuses one evaluated context for later Keychain operations; if so, check whether a second sensitive operation proceeds without a new prompt.

4. **Event-bound flows.** Where the app relies on `LAContext.evaluatePolicy` alone, demonstrate the bypass with objection's `ios ui biometrics_bypass` or a hook on the `reply` block (OWASP [MASTG-TEST-0267](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0267/)), and then use the probe from step 1 to show that the secret behind the prompt was readable all along.

5. **Device state.** Lock the device and repeat the probe through a background execution path if the app has one (a background fetch or a notification service extension). Items in `ck`/`cku` remain readable after first unlock; `ak`/`aku`/`akpu` items return `errSecInteractionNotAllowed` while locked.

#### Observation

For each item and key: readable or signable without interaction (yes/no, status code), protection class, and what it is. Keep the redacted output and, for a pass, the -25308 results.

#### Evaluation

The test **fails** if any item or key protecting a sensitive resource is readable or usable without user interaction while the design says it is protected by Face ID, Touch ID or the passcode; if a Secure Enclave key representing user consent signs without a prompt; or if one authentication silently authorises later sensitive operations through a reused context beyond what the design requires. It **passes** if sensitive items and keys return `errSecInteractionNotAllowed` (or prompt) every time.

#### Demo

Probe output for the vulnerable lab app from GT-0016-5:

```text
com.example.auth/refresh pdmn=ck -> [!] READ without user interaction
com.example.auth/pin-hash pdmn=akpu -> [+] interaction required
com.example.prefs/theme pdmn=ak -> [!] READ without user interaction
```

The refresh token — the secret the Face ID screen is supposed to protect — is readable without interaction; the theme preference is irrelevant; the PIN hash is correctly gated. Together with the Secure Enclave device-binding key signing a challenge silently in step 2, the test fails with a demonstrated bypass of the app's biometric login.

## Secure implementation

Pick restrictions per key, from what the key protects. A reasonable baseline for L2 apps and wallets:

| Key protects | User auth | Window | Unlocked device | Device-bound | Notes |
|---|---|---|---|---|---|
| Transaction or consent signatures, credential presentation | Class 3 biometric (or Face ID / Touch ID current set) | Per operation | Yes | Yes | Protected Confirmation where supported; server verifies attestation (Android) |
| Long-lived session secrets (refresh tokens, vault KEK) | Biometric or device credential | Per operation, or a short window | Yes | Yes | Re-enrol on invalidation, never fall back |
| Data the app needs in the background | None, or as the design allows | — | Documented exception | Yes | Keep the data minimal; separate key from foreground-only data |
| Non-sensitive caches | None | — | Optional | Yes | Record the decision |

### Android: transaction-signing key bound to strong biometrics

```kotlin
fun createTxSigningKey(alias: String, attestationChallenge: ByteArray, strongBox: Boolean): PublicKey {
    val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
        .setDigests(KeyProperties.DIGEST_SHA256)
        .setUserAuthenticationRequired(true)
        .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)  // per operation, Class 3 only
        .setInvalidatedByBiometricEnrollment(true)                                // the default, stated explicitly
        .setUnlockedDeviceRequired(true)
        .setAttestationChallenge(attestationChallenge)                            // server verifies all of the above
        .setIsStrongBoxBacked(strongBox)
        .build()
    val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
    kpg.initialize(spec)
    return kpg.generateKeyPair().public   // retry with strongBox = false on StrongBoxUnavailableException
}
```

On `minSdk` below 30, replace `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)` with `setUserAuthenticationValidityDurationSeconds(-1)`, which means the same thing. Use the key only through a `CryptoObject`, and send the signature — not the callback — to the server:

```kotlin
fun signWithBiometric(activity: FragmentActivity, alias: String, payload: ByteArray, onSigned: (ByteArray) -> Unit) {
    val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val signature = Signature.getInstance("SHA256withECDSA")
    try {
        signature.initSign(ks.getKey(alias, null) as PrivateKey)
    } catch (e: KeyPermanentlyInvalidatedException) {
        ks.deleteEntry(alias)          // biometrics or lock screen changed: re-enrol, never fall back
        throw e
    }
    val callback = object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
            val s = result.cryptoObject?.signature ?: return
            s.update(payload)          // payload includes the transaction details the user saw
            onSigned(s.sign())         // the backend verifies this signature against the attested key
        }
    }
    val info = BiometricPrompt.PromptInfo.Builder()
        .setTitle("Confirm payment")
        .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        .setNegativeButtonText("Cancel")
        .build()
    BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), callback)
        .authenticate(info, BiometricPrompt.CryptoObject(signature))
}
```

Where `ConfirmationPrompt.isSupported(context)` returns true, add `setUserConfirmationRequired(true)` to the key and sign the `dataThatWasConfirmed` returned by Protected Confirmation instead of `payload`; the backend then verifies that the signed CBOR contains the transaction it expects.

### Android: session-secret KEK with a short window

For a key that unwraps a refresh token or vault DEK, per-operation biometrics may be too intrusive. A short window with both authenticator types is a defensible compromise, as long as it is short and the key is unusable while locked:

```kotlin
val spec = KeyGenParameterSpec.Builder("session.kek.v1",
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
    .setKeySize(256)
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    .setUserAuthenticationRequired(true)
    .setUserAuthenticationParameters(
        30, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
    .setUnlockedDeviceRequired(true)
    .build()
```

Be explicit in the design that a 30-second window is satisfied by a device unlock, and that keys with a window are not invalidated by new biometric enrolment. If either is unacceptable for the data, use per-operation authentication. Handle `UserNotAuthenticatedException` at `Cipher.init` by showing a `BiometricPrompt` (or the device-credential prompt) without a `CryptoObject`, then retrying.

### iOS: Secure Enclave signing key with current-set biometrics

```swift
import CryptoKit
import LocalAuthentication
import Security

func makeConsentKey() throws -> SecureEnclave.P256.Signing.PrivateKey {
    guard SecureEnclave.isAvailable else { throw CryptoKitError.underlyingCoreCryptoError(error: -1) }
    var error: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,   // unlocked, passcode set, never leaves the device
        [.privateKeyUsage, .biometryCurrentSet],           // Enclave key AND current biometrics, per use
        &error
    ) else { throw error!.takeRetainedValue() as Error }
    return try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
}

// Persist key.dataRepresentation in the Keychain (ThisDeviceOnly). Each signature prompts:
// let signature = try key.signature(for: transactionBytes)
```

Compare with `SecureEnclave.P256.Signing.PrivateKey()` — same hardware, no user presence. Use `.userPresence` instead of `.biometryCurrentSet` only if passcode fallback is acceptable for the operation (OWASP MASWE-0021), and handle the item becoming unusable after an enrolment change by re-enrolling the user.

### iOS: Keychain secret readable only with user presence on this device

```swift
func storeRefreshToken(_ token: Data) throws {
    var error: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .biometryCurrentSet, &error
    ) else { throw error!.takeRetainedValue() as Error }

    let base: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "com.example.auth",
        kSecAttrAccount as String: "refresh-token"
        // no kSecAttrAccessGroup: stays in the app's own default group (check the entitlement order)
    ]
    SecItemDelete(base as CFDictionary)
    var add = base
    add[kSecAttrAccessControl as String] = access        // replaces kSecAttrAccessible
    add[kSecValueData as String] = token
    let status = SecItemAdd(add as CFDictionary, nil)
    guard status == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(status)) }
}

func readRefreshToken() throws -> Data {     // call off the main thread; the system shows the prompt
    let context = LAContext()
    context.touchIDAuthenticationAllowableReuseDuration = 0   // a recent unlock does not count
    context.localizedReason = "Sign in to your account"
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "com.example.auth",
        kSecAttrAccount as String: "refresh-token",
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne,
        kSecUseAuthenticationContext as String: context    // fresh context per sensitive operation
    ]
    var out: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &out)
    guard status == errSecSuccess, let data = out as? Data else {
        throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
    }
    return data
}
```

Do not cache the token in memory or `UserDefaults` after reading it; the access control protects the Keychain item, not copies of it.

### Both platforms: let the server check

- **Android:** have the backend verify the key attestation chain at enrolment and check the authorisation list — `userAuthType` includes strong biometrics, `authTimeout` is absent or zero for per-operation keys, `unlockedDeviceRequired` and `trustedConfirmationRequired` as designed, `purpose` is sign only, and the restrictions appear in the hardware-enforced list. Reject keys that do not match; this turns MASWE-0016 from a client-side promise into a server-side check.
- **iOS:** there is no general attestation of Secure Enclave key ACLs for apps. Combine App Attest (to know the request comes from your genuine app) with a design in which the consent signature is the only thing the server accepts, and verify the restrictions in code review and with GT-0016-5/GT-0016-6.
- **Both:** a signature from a device key should cover the exact operation (amount, payee, nonce, timestamp), so a signature obtained once cannot be replayed for another operation.

## Rating findings

Rate on what the unrestricted key protects, how the attacker gets to use it (instrumentation on a rooted or jailbroken device, a malicious library, physical access to an unlocked or locked phone), and whether the backend treats its output as proof of the user's consent.

| Rating | Conditions |
|---|---|
| **Critical** | A key whose output the backend accepts as proof of user consent (payment or transaction signing, device-bound login, credential presentation in an identity wallet) is usable without user authentication **and** the app exposes a path that triggers the operation without user interaction (an exported component, deep link, push-driven flow, or JavaScript bridge), so abuse does not require device compromise. |
| **High** | The same class of key is usable without user authentication, or only behind an event-bound prompt, with exploitation needing code execution in the app (instrumentation on a compromised device, a malicious SDK) or brief physical access to an unlocked device — demonstrated with GT-0016-3 or GT-0016-6. Also: a refresh token or vault KEK readable without interaction while the app advertises biometric protection; a consent key with an authorisation window of many minutes or hours. |
| **Medium** | Auth-bound keys with weaker-than-required settings: windows longer than needed (tens of seconds to minutes) for sensitive data, `setInvalidatedByBiometricEnrollment(false)` or `.biometryAny`, device-credential fallback for high-value operations, sensitive keys usable while locked (`AfterFirstUnlock`, no `setUnlockedDeviceRequired`), non-`ThisDeviceOnly` or synchronizable classes for keys, sensitive keys in a Keychain group shared with extensions. |
| **Low** | Over-broad purposes, paddings or digests with no demonstrated oracle; missing `setUnlockedDeviceRequired` on keys for moderately sensitive data that are otherwise auth-bound; Secure Enclave or StrongBox available but unused for a high-assurance key; restrictions present but never verified server-side (no attestation check on Android). |
| **Info** | Unrestricted keys for non-sensitive purposes, or background keys with a documented justification; restrictions configured correctly but `KeyInfo` reports software enforcement on a specific test device. |

When you report, give the alias or Keychain identifier, what it protects, the exact configuration (decompiled builder call or decoded flags), the probe output proving use without authentication, and the impact evidence: the decrypted secret (redacted) or the signature the backend accepted. For wallets and payment apps, state explicitly whether the server can tell an unrestricted key from a restricted one — usually it cannot, which is why this finding tends to be rated higher than its configuration-only appearance suggests.

## References

- OWASP MASWE — [MASWE-0016: Cryptographic Key Access Not Restricted](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0016/) (CC BY-SA 4.0)
- OWASP MASWE — [MASWE-0020: Local Authentication Can Be Bypassed](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0020/), [MASWE-0021: Fallback to Non-biometric Credentials Allowed for Sensitive Transactions](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0021/), [MASWE-0022: Crypto Keys Not Invalidated on New Biometric Enrollment](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0022/) (CC BY-SA 4.0)
- OWASP MAS Profiles — [MAS-L2](https://mas.owasp.org/Profiles/MAS-L2/) and [MAS-EUDIW](https://mas.owasp.org/Profiles/MAS-EUDIW/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0001: Biometric Authentication](https://mas.owasp.org/MASTG/knowledge/android/MASVS-AUTH/MASTG-KNOW-0001/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0012: Key Generation](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0012/), [MASTG-KNOW-0043: Android KeyStore](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0043/), [MASTG-KNOW-0044: Key Attestation](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0044/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0056: Local Authentication Framework](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-AUTH/MASTG-KNOW-0056/), [MASTG-KNOW-0057: Keychain Services](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-AUTH/MASTG-KNOW-0057/), [MASTG-KNOW-0066: CryptoKit](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0066/), [MASTG-KNOW-0126: Keychain Access Groups](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0126/) (CC BY-SA 4.0)
- OWASP MASTG — beta tests [MASTG-TEST-0326](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0326/), [MASTG-TEST-0327](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0327/), [MASTG-TEST-0328](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0328/), [MASTG-TEST-0329](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0329/), [MASTG-TEST-0330](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0330/), [MASTG-TEST-0307](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0307/), [MASTG-TEST-0308](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0308/), [MASTG-TEST-0266](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0266/), [MASTG-TEST-0267](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0267/), [MASTG-TEST-0268](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0268/), [MASTG-TEST-0269](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0269/), [MASTG-TEST-0270](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0270/), [MASTG-TEST-0271](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0271/), [MASTG-TEST-0388](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0388/) (CC BY-SA 4.0)
- OWASP MASTG — legacy (MASTG v1) tests [MASTG-TEST-0015](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0015/), [MASTG-TEST-0017](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0017/), [MASTG-TEST-0018](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0018/), [MASTG-TEST-0062](https://mas.owasp.org/MASTG/tests/ios/MASVS-CRYPTO/MASTG-TEST-0062/), [MASTG-TEST-0064](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0064/) (CC BY-SA 4.0)
- OWASP MASTG — demos [MASTG-DEMO-0045](https://mas.owasp.org/MASTG/demos/ios/MASVS-AUTH/MASTG-DEMO-0045/MASTG-DEMO-0045/), [MASTG-DEMO-0046](https://mas.owasp.org/MASTG/demos/ios/MASVS-AUTH/MASTG-DEMO-0046/MASTG-DEMO-0046/), [MASTG-DEMO-0091](https://mas.owasp.org/MASTG/demos/android/MASVS-AUTH/MASTG-DEMO-0091/MASTG-DEMO-0091/), [MASTG-DEMO-0093](https://mas.owasp.org/MASTG/demos/android/MASVS-AUTH/MASTG-DEMO-0093/MASTG-DEMO-0093/), [MASTG-DEMO-0072](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0072/MASTG-DEMO-0072/) (CC BY-SA 4.0)
- OWASP MASTG — techniques [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0061](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0061/), [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/), [MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/), [MASTG-TECH-0111](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0111/); tool [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/) (CC BY-SA 4.0)
- [Android Developers — `KeyGenParameterSpec.Builder`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder) (including [`setUnlockedDeviceRequired`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setUnlockedDeviceRequired(boolean))), [`KeyInfo`](https://developer.android.com/reference/android/security/keystore/KeyInfo), [`KeyProperties`](https://developer.android.com/reference/android/security/keystore/KeyProperties)
- [Android Developers — Show a biometric authentication dialog](https://developer.android.com/training/sign-in/biometric-auth#prompt-the-user-to-authenticate-with-biometrics) and [Android Keystore system](https://developer.android.com/privacy-and-security/keystore) (including [StrongBox](https://developer.android.com/privacy-and-security/keystore#StrongBoxKeyMint))
- [Android Developers — Android Protected Confirmation](https://developer.android.com/privacy-and-security/security-android-protected-confirmation) and [Verifying hardware-backed key pairs with key attestation](https://developer.android.com/privacy-and-security/security-key-attestation)
- [Apple — Restricting keychain item accessibility](https://developer.apple.com/documentation/security/restricting-keychain-item-accessibility), [`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`](https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlockedthisdeviceonly), [`SecAccessControlCreateFlags`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags)
- [Apple — Accessing keychain items with Face ID or Touch ID](https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id) and [Sharing access to keychain items among a collection of apps](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps)
- [Apple — Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave), [`kSecAttrTokenIDSecureEnclave`](https://developer.apple.com/documentation/security/ksecattrtokenidsecureenclave), [CryptoKit `SecureEnclave`](https://developer.apple.com/documentation/cryptokit/secureenclave)
- [Apple Platform Security Guide — Keychain data protection](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [Reversec Labs — How secure is your Android Keystore authentication?](https://labs.reversec.com/posts/2019/08/how-secure-is-your-android-keystore-authentication)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html) and [CWE-306: Missing Authentication for Critical Functionality](https://cwe.mitre.org/data/definitions/306.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
