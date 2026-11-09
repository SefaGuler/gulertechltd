---
title: "Fallback to Non-biometric Credentials Allowed for Sensitive Transactions (MASWE-0021)"
date: 2026-11-09 08:35:00 +0000
subcategory: auth
summary: "When a PIN or passcode can approve what biometrics should: Android authenticators, iOS policies and ACLs, the OWASP tests and the honest trade-off."
refs: [MASWE-0021, MASVS-AUTH-2, CWE-288, CWE-287]
tags: [android, ios, masvs-auth, biometrics, local-authentication, keystore]
---

This note is part of our [MASVS-AUTH guide](/mobile/masvs-auth-authentication-guide/) and covers OWASP [MASWE-0021](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0021/): a sensitive transaction that the app protects with biometrics, but which can also be approved with the device PIN, pattern, password or passcode. The weakness looks small on paper — one constant in a builder, one flag in an access-control object — and in practice it decides whether the person who watched the victim unlock their phone on the bus can also approve a payment from it. Below you will find how fallback is configured on Android (prompt authenticators *and* key authenticator types, which are not the same thing) and iOS (LocalAuthentication policies *and* Keychain access-control flags), the threat model and an honest discussion of when fallback is acceptable, including accessibility, the three OWASP tests with their demos, our supplementary tests for runtime behaviour, the lockout path and the backend, secure Kotlin and Swift, and severity guidance.

> **Note:** OWASP links three tests and one best practice to MASWE-0021: [MASTG-TEST-0326](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0326/) (Android, static), [MASTG-TEST-0268](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0268/) (iOS, static), [MASTG-TEST-0269](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0269/) (iOS, dynamic) and [MASTG-BEST-0031](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0031/). The weakness page links no Knowledge page; the tests themselves refer to MASTG-KNOW-0001 (Android biometrics) and MASTG-KNOW-0056 (iOS LocalAuthentication). We summarise those and add **supplementary** Knowledge sections, plus three supplementary tests labelled **Guler Tech methodology**.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: Biometric Authentication (MASTG-KNOW-0001)](#android-biometric-authentication-mastg-know-0001)
  - [Android: prompt authenticators and their combinations](#android-prompt-authenticators-and-their-combinations)
  - [Android: key authenticator types decide the real assurance](#android-key-authenticator-types-decide-the-real-assurance)
  - [iOS: Local Authentication Framework (MASTG-KNOW-0056)](#ios-local-authentication-framework-mastg-know-0056)
  - [iOS: Keychain access control flags and passcode fallback (MASTG-KNOW-0057)](#ios-keychain-access-control-flags-and-passcode-fallback-mastg-know-0057)
  - [Both platforms: threat model and when fallback is acceptable](#both-platforms-threat-model-and-when-fallback-is-acceptable)
- [Tests](#tests)
  - [MASTG-TEST-0326 (Android, static)](#mastg-test-0326-references-to-apis-allowing-fallback-to-non-biometric-authentication-android)
  - [MASTG-TEST-0268 (iOS, static)](#mastg-test-0268-references-to-apis-allowing-fallback-to-non-biometric-authentication-ios)
  - [MASTG-TEST-0269 (iOS, dynamic)](#mastg-test-0269-runtime-use-of-apis-allowing-fallback-to-non-biometric-authentication-ios)
  - [GT-0021-1: Runtime authenticator configuration and result type (Android)](#gt-0021-1-runtime-authenticator-configuration-and-result-type-android)
  - [GT-0021-2: Approving a sensitive transaction without biometrics (Android, iOS)](#gt-0021-2-approving-a-sensitive-transaction-without-biometrics-android-ios)
  - [GT-0021-3: Does the backend know how the user authenticated (Android, iOS)](#gt-0021-3-does-the-backend-know-how-the-user-authenticated-android-ios)
- [Best practices](#best-practices)
  - [MASTG-BEST-0031: Enforce Strong Biometrics for Sensitive Operations (Android)](#mastg-best-0031-enforce-strong-biometrics-for-sensitive-operations-android)
  - [iOS counterpart: biometry-only access control (Guler Tech)](#ios-counterpart-biometry-only-access-control-guler-tech)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

The OWASP requirement is *"The app does not allow fallback to non-biometric credentials for sensitive transactions."* The weakness exists when a transaction that is supposed to need the user's fingerprint or face can, silently or one tap away, be authorised with the device credential instead. On Android that means `DEVICE_CREDENTIAL` among the authenticators a `BiometricPrompt` accepts, or `AUTH_DEVICE_CREDENTIAL` among the authenticator types a Keystore key accepts. On iOS it means `LAPolicy.deviceOwnerAuthentication` instead of `.deviceOwnerAuthenticationWithBiometrics`, or a Keychain access-control object built with `.userPresence` or `.devicePasscode` instead of a biometry flag.

Why does this matter if the device credential is, after all, what protects the whole phone? Because the two factors fail differently:

| Property | Device credential (PIN, pattern, password, passcode) | Biometric (Class 3 fingerprint or face, Touch ID, Face ID) |
|---|---|---|
| Can be observed | Yes: shoulder surfing, cameras, smudges on the screen | Not in a reusable form |
| Can be guessed | Short PINs and common patterns, especially 4-digit and 6-digit | Only by spoofing, at rates the platform certifies |
| Can be shared | Routinely: partners, children, colleagues, a repair shop | Only by enrolling another person (MASWE-0022) |
| Needs the victim present at the time of use | No — learned once, usable later | Yes, the victim's body must be there |
| Can be coerced | Yes | Yes, arguably more easily |

The last two rows are the honest core of the weakness. Biometrics do not defend against coercion; what they defend against is the **delayed, remote-in-time use of a secret someone learned once**. A thief who watched the victim type a passcode in a pub can open the phone an hour later, and if the banking app accepts that passcode for a transfer, the thief can move money. If the transfer needs the victim's face, they cannot.

**Three layers, three places to get it wrong.** A sensitive transaction on a mobile app passes through three decisions, and fallback can be introduced at each:

| Layer | Android | iOS | What allows fallback |
|---|---|---|---|
| Prompt | `BiometricPrompt` authenticators | `LAContext.evaluatePolicy` policy | `DEVICE_CREDENTIAL`; `.deviceOwnerAuthentication`; the app's own handling of "Use PIN", `userFallback` and lockout errors |
| Key | `KeyGenParameterSpec` authenticator types | `SecAccessControl` flags on the Keychain item or Secure Enclave key | `AUTH_DEVICE_CREDENTIAL`, time-bound keys, deprecated validity setter; `.userPresence`, `.devicePasscode`, `.or` with `.devicePasscode` |
| Server | What the backend requires before it executes the transaction | Same | Accepting an approval without a signature from a biometric-only key, or trusting a client-reported "authenticated with Face ID" claim |

The key layer is the one that counts when the app does crypto-bound authentication, because the platform enforces it outside the app process. The prompt layer is all there is when the app is event-bound — and then the fallback question is secondary to the fact that a Frida hook bypasses the prompt entirely. That distinction belongs to MASWE-0020, which our [local authentication bypass note](/mobile/maswe-0020-local-authentication-bypass/) covers in depth; here we assume you have established which kind of flow you are looking at, and ask a narrower question: **with the platform working exactly as designed, can a non-biometric credential approve this transaction?**

**What "sensitive transaction" means.** OWASP's tests fail "for any sensitive data resource that needs protection", which leaves the judgement to you. In our assessments the following are sensitive by default; agree the list with the client before testing:

- payments and transfers, especially to new payees, and changes to payment limits;
- adding a payee, card, device or authenticator; changing the registered phone number or email address;
- revealing full card numbers, card PINs, recovery phrases, private keys or backup codes;
- in an identity wallet (EUDIW), presenting person identification data or attestations to a relying party, and creating qualified electronic signatures;
- turning security features off (biometric login, transaction notifications, device binding).

Unlocking the app to look at a balance is normally **not** in the list, and fallback there is fine (see [when fallback is acceptable](#both-platforms-threat-model-and-when-fallback-is-acceptable)).

**Profiles and mappings.** MASWE-0021 is tagged L2 and EUDIW, not L1: OWASP does not expect a general-purpose app to refuse the device passcode, but it does expect a banking, payment, health, government or wallet app to protect its high-value operations with something stronger. It maps to MASVS-AUTH-2 ("The app performs local authentication securely according to the platform best practices"), to [CWE-288: Authentication Bypass Using an Alternate Path or Channel](https://cwe.mitre.org/data/definitions/288.html) and [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html), to the Android Core App Quality guideline *Biometric_Authentication*, and was numbered MASWE-0045 in the beta catalogue. OWASP's threat is MAS-THREAT-0021, *"Attackers can authenticate sensitive transactions without the user's biometrics"*, and the attack is MAS-ATTACK-0034, *"Using a known, guessed, or shoulder-surfed device credential (PIN, pattern, or password)."*

**What you can prove from the client, and what you cannot.** MASVS-AUTH says enforcement belongs on the remote endpoint. From the app you can prove which authenticators the prompt and the key accept, and you can demonstrate on a real device that the transaction completes after entering the PIN. You cannot prove from the app alone whether the backend would have refused a passcode-approved transaction — on iOS the server has no way to know, and on Android it only knows if it verifies key attestation. That is why we add a backend-facing test ([GT-0021-3](#gt-0021-3-does-the-backend-know-how-the-user-authenticated-android-ios)) and why the rating depends on server-side compensating controls.

## Modes of Introduction

OWASP lists three:

- **Device credential allowed for sensitive actions.** `DEVICE_CREDENTIAL` is passed to `setAllowedAuthenticators` (alone or OR-ed with a biometric class) for a high-value operation, or the deprecated `setDeviceCredentialAllowed(true)` is used.
- **Generic authentication policy on iOS.** The app evaluates `.deviceOwnerAuthentication`, which offers the passcode after failed or unavailable biometrics, instead of `.deviceOwnerAuthenticationWithBiometrics`.
- **Operation not bound to a biometric-only key.** The operation is protected by a UI-level prompt rather than a key that only the platform's strong biometric path can unlock.

Variants we see often that OWASP does not list separately:

- **Fallback at the key, not the prompt.** The prompt says `BIOMETRIC_STRONG`, but the key was created with `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG or AUTH_DEVICE_CREDENTIAL)`, with a time window, or with the deprecated `setUserAuthenticationValidityDurationSeconds` and any non-negative value. A time-bound key is authorised by the user *unlocking the phone with the PIN*, so the biometric-only prompt is decoration. On iOS the equivalent is an item protected by `.userPresence` while the app evaluates a biometrics-only `LAContext` in front of it.
- **Explicit OR on iOS.** `[.biometryCurrentSet, .or, .devicePasscode]` reads as "biometrics", and the flag name even promises enrolment invalidation, but the passcode branch satisfies the constraint on its own.
- **The lockout handler is the fallback.** After five failed matches the platform locks biometrics (`ERROR_LOCKOUT` / `ERROR_LOCKOUT_PERMANENT` on Android, `LAError.biometryLockout` on iOS). Apps "unlock" by evaluating `.deviceOwnerAuthentication` or launching a device-credential prompt — and then treat that success as approval of the pending transaction. An attacker only has to fail five times on purpose.
- **`userFallback` handled with the passcode.** On iOS the biometric policy shows an "Enter Password" button after a failed match unless `localizedFallbackTitle` is empty; tapping it returns `LAError.userFallback` to the app, which then calls `evaluatePolicy(.deviceOwnerAuthentication…)`. The fallback OWASP's test looks for has been rebuilt in app code.
- **Availability downgrade.** `canAuthenticate(BIOMETRIC_STRONG)` returns `BIOMETRIC_ERROR_NONE_ENROLLED` or `BIOMETRIC_ERROR_NO_HARDWARE`, and the app quietly retries with `BIOMETRIC_WEAK or DEVICE_CREDENTIAL` "so the user isn't locked out". The same happens with `canEvaluatePolicy` on iOS.
- **Framework defaults.** Cross-platform plugins often default to allowing the device credential: Flutter's `local_auth` has a `biometricOnly` option, Expo's `expo-local-authentication` a `disableDeviceFallback` option, `react-native-biometrics` an `allowDeviceCredentials` option, and `react-native-keychain` offers access-control constants such as `BIOMETRY_CURRENT_SET_OR_DEVICE_PASSCODE`. Option names and defaults change between versions; check the version the app ships.
- **Legacy confirm-credential flows.** `KeyguardManager.createConfirmDeviceCredentialIntent` (deprecated in API 29) used as the "re-authenticate before payment" step: a device-credential-only path by design.
- **Server trusts the client's claim.** The approval request carries `"authMethod": "FACE_ID"` or similar, and the backend uses it to choose limits or skip an OTP. Anything the client asserts, an attacker with the PIN and a proxy can assert too.

## Impact

- **Authentication or authorisation bypass.** The attacker completes a challenge that was meant to require the user's biometrics, so the backend executes an operation the user never approved.
- **Financial loss.** With the device and its credential — stolen together, or the credential learned first — an attacker authorises payments or transfers. Because the transaction carries a valid device-bound signature, the bank's fraud systems see a genuine customer device, and the customer may struggle to dispute liability.
- **Identity misuse.** In a wallet, a passcode-approved presentation or signature is indistinguishable from one the holder made, which undermines the reliance relying parties place on it.
- **Domestic and insider abuse.** In shared households the device credential is often known to partners or children. Fallback turns "knows my phone PIN" into "can spend my money" — a common pattern in financial abuse cases.
- **Weakened downstream controls.** MASWE-0022 enrolment invalidation and Android Protected Confirmation lose most of their value if the same operation can be approved with the passcode.

## Mitigations

- **Require strong biometrics for sensitive transactions**: `BIOMETRIC_STRONG` only on Android, `.deviceOwnerAuthenticationWithBiometrics` with an empty `localizedFallbackTitle` on iOS.
- **Bind the operation to a biometric-only key**: Android `setUserAuthenticationRequired(true)` with `setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)` used through `BiometricPrompt.CryptoObject`; iOS a Keychain item or Secure Enclave key whose access control is `.biometryCurrentSet` (with `.privateKeyUsage` for keys). Keep enrolment invalidation on ([MASWE-0022](/mobile/maswe-0022-keys-not-invalidated-on-biometric-enrollment/)).
- **Match assurance to sensitivity**: allow device-credential fallback for low-risk convenience features only, never for the transactions that motivated biometric protection.
- **Handle lockout and unavailability without approving anything**: unlocking biometrics with the passcode must not complete the pending transaction; a user who cannot use biometrics gets a deliberate, server-verified alternative path, not a silent downgrade.
- **Let the server check**: on Android, verify key attestation at registration and require `userAuthType` to be biometric-only for transaction-signing keys; on both platforms, never accept a client-reported authentication method, and keep server-side controls (limits, cooling-off periods for new payees, out-of-band notifications) on every path that does not use the biometric key.

## Knowledge

The OWASP tests refer to two Knowledge pages, MASTG-KNOW-0001 and MASTG-KNOW-0056. We summarise them as they apply here and add supplementary sections on what neither page covers: the authenticator combinations, the key-level authenticator types, the Keychain flags as they relate to fallback, and the threat model. Key restrictions in general are in our [MASWE-0016 note](/mobile/maswe-0016-key-access-not-restricted/); the iOS LocalAuthentication error codes and context properties are in our [MASWE-0017 note](/mobile/maswe-0017-device-secure-lock-not-enforced/#ios-local-authentication-framework-mastg-know-0056). We do not repeat them.

### Android: Biometric Authentication (MASTG-KNOW-0001)

Source: [MASTG-KNOW-0001](https://mas.owasp.org/MASTG/knowledge/android/MASVS-AUTH/MASTG-KNOW-0001/); our full treatment is in [Android Biometric Authentication (MASTG-KNOW-0001)](/mobile/mastg-know-0001-biometric-authentication/). The points that matter for fallback:

- Apps should use the Jetpack `androidx.biometric` library (`BiometricPrompt`, `BiometricManager`), which wraps the framework `android.hardware.biometrics` APIs back to API 23. `FingerprintManager` is deprecated since API 28 (see our [MASTG-KNOW-0002 note](/mobile/mastg-know-0002-fingerprintmanager/)).
- Android classifies biometrics by **security class**, not by modality. Class 3 (formerly "strong") and Class 2 (formerly "weak") are exposed to apps as `BIOMETRIC_STRONG` and `BIOMETRIC_WEAK`; Class 1 ("convenience") is not usable through `BiometricPrompt`. The classes come from measured spoof and imposter acceptance rates defined in the AOSP biometric documentation.
- Only Class 3 biometrics can authorise Keystore keys. A flow that accepts `BIOMETRIC_WEAK` cannot be crypto-bound for users whose only biometric is Class 2 — which includes many camera-based face unlock implementations.
- Two flows exist: prompt-based (the app reacts to a callback) and Keystore-backed (the prompt authorises a `Cipher`, `Signature` or `Mac` wrapped in a `CryptoObject`). Fallback matters in both, but only the Keystore-backed flow is enforced outside the app.

### Android: prompt authenticators and their combinations

Supplementary, from the Android Developers reference for `BiometricManager.Authenticators`, `BiometricPrompt` and `BiometricPrompt.PromptInfo.Builder`.

**Constants.** Decompiled code shows integers, never names, so learn the values:

| Constant | Value | Hex | Meaning |
|---|---|---|---|
| `BIOMETRIC_STRONG` | 15 | `0x000F` | Class 3 biometric |
| `BIOMETRIC_WEAK` | 255 | `0x00FF` | Class 2 **or** Class 3 biometric (the strong bits are included) |
| `DEVICE_CREDENTIAL` | 32768 | `0x8000` | Screen-lock PIN, pattern or password |
| `BIOMETRIC_STRONG or DEVICE_CREDENTIAL` | 32783 | `0x800F` | Class 3 biometric or the device credential |
| `BIOMETRIC_WEAK or DEVICE_CREDENTIAL` | 33023 | `0x80FF` | Any biometric or the device credential |

Any value with bit `0x8000` set allows device-credential fallback. A value of `0x00FF` does not allow the device credential, but accepts Class 2 biometrics, which MASTG-BEST-0031 also rules out for sensitive operations.

**Supported combinations depend on the API level.** The androidx documentation states that `DEVICE_CREDENTIAL` on its own is unsupported before Android 11 (API 30) and `BIOMETRIC_STRONG or DEVICE_CREDENTIAL` is unsupported on Android 9 and 10 (API 28–29); `build()` rejects unsupported combinations on affected versions. Apps that support old devices therefore often ship `BIOMETRIC_WEAK or DEVICE_CREDENTIAL` "because it works everywhere" — which accepts Class 2 face unlock *and* the PIN for the operation.

**Builder rules that help you read code.**

- **Negative button versus device credential.** If the device credential is allowed, the prompt has no negative button: the system shows "Use PIN" (or pattern/password) instead. If it is not allowed, a negative button is mandatory. With androidx, `PromptInfo.Builder.build()` throws `IllegalArgumentException` if you set `setNegativeButtonText` while allowing `DEVICE_CREDENTIAL`, or omit it while not allowing it. The framework builder has the same rule with `setNegativeButton(text, executor, listener)`. A prompt built with a negative button is therefore biometric-only; one built without a negative button almost certainly allows the device credential. This is a useful sanity check when the authenticator value is computed at runtime.
- **`setDeviceCredentialAllowed(true)`** is the API 29 way of allowing the credential. It is **deprecated since API 30** in favour of `setAllowedAuthenticators(… or DEVICE_CREDENTIAL)` on the framework builder, and deprecated in androidx too. Seeing it means device-credential fallback, full stop.
- **`CryptoObject` with the device credential** works only from API 30. On older versions androidx refuses to combine the two, so apps that need crypto-bound authentication there are biometric-only by necessity.
- **`setConfirmationRequired(false)`** is a different matter (passive biometrics without an explicit confirm tap); OWASP covers it under MASWE-0020 with MASTG-TEST-0329.

**Which credential did the user actually use?** `BiometricPrompt.AuthenticationResult.getAuthenticationType()` returns `AUTHENTICATION_RESULT_TYPE_BIOMETRIC` (2) or `AUTHENTICATION_RESULT_TYPE_DEVICE_CREDENTIAL` (1); androidx adds `AUTHENTICATION_RESULT_TYPE_UNKNOWN` (−1) for old platforms. An app *could* check it and refuse a credential-based approval, but that is an event-bound check in the app process; a key that only accepts biometrics enforces the same thing without trusting app code. For testing, the value is gold: it tells you exactly how a given approval was made ([GT-0021-1](#gt-0021-1-runtime-authenticator-configuration-and-result-type-android)).

**Where fallback hides in error handling.** The prompt reports errors through `onAuthenticationError(errorCode, errString)`. The ones that drive fallback logic:

| Constant | Value | When | Typical (risky) app response |
|---|---|---|---|
| `ERROR_LOCKOUT` | 7 | Too many failed attempts; temporary lockout | Show a device-credential prompt "to continue" |
| `ERROR_LOCKOUT_PERMANENT` | 9 | Repeated lockouts; biometrics disabled until the user enters the device credential | Same, and treat its success as approval |
| `ERROR_NO_BIOMETRICS` | 11 | Nothing enrolled | Retry with `DEVICE_CREDENTIAL` |
| `ERROR_HW_NOT_PRESENT` | 12 | No suitable sensor | Same |
| `ERROR_NEGATIVE_BUTTON` | 13 | User tapped the negative button | App-specific "Use PIN" flow — check what that PIN is |

`BiometricManager.canAuthenticate(int)` returns `BIOMETRIC_SUCCESS` (0), `BIOMETRIC_ERROR_HW_UNAVAILABLE` (1), `BIOMETRIC_ERROR_NONE_ENROLLED` (11), `BIOMETRIC_ERROR_NO_HARDWARE` (12), `BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED` (15) or `BIOMETRIC_ERROR_UNSUPPORTED` (−2). Apps that branch on these values to pick a weaker authenticator set implement the availability downgrade described above.

**Confirm-credential intents.** `KeyguardManager.createConfirmDeviceCredentialIntent(title, description)` shows the device-credential screen and returns `RESULT_OK`. It is deprecated since API 29 in favour of `BiometricPrompt` with `DEVICE_CREDENTIAL`, and was the subject of the legacy (MASTG v1) test [MASTG-TEST-0017 "Testing Confirm Credentials"](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0017/). Any sensitive operation gated by it is device-credential-only.

### Android: key authenticator types decide the real assurance

Supplementary, from the `KeyGenParameterSpec.Builder` and `KeyProperties` reference. Background on user-authentication binding and validity windows is in our [MASWE-0016 note](/mobile/maswe-0016-key-access-not-restricted/#android-user-authentication-binding-and-validity-mastg-know-0001).

When a key is created with `setUserAuthenticationRequired(true)`, `setUserAuthenticationParameters(timeout, type)` (API 30) says which authentications count:

| `type` | Value in decompiled code | Accepts |
|---|---|---|
| `KeyProperties.AUTH_DEVICE_CREDENTIAL` | 1 | Device PIN, pattern or password |
| `KeyProperties.AUTH_BIOMETRIC_STRONG` | 2 | Class 3 biometric |
| `AUTH_BIOMETRIC_STRONG or AUTH_DEVICE_CREDENTIAL` | 3 | Either |

If the app only calls `setUserAuthenticationRequired(true)`, the default is per-operation and biometric-only. The deprecated `setUserAuthenticationValidityDurationSeconds(int)` maps onto the new API: `-1` means per-operation and biometric-only; any other value means the device credential is accepted as well (and, if positive, a time window).

The prompt and the key interact. What actually protects the operation is the **intersection**: the Keystore will not perform an operation unless an authentication token of an accepted type exists, whatever the prompt allowed.

| Prompt allows | Key accepts | Per-operation (`CryptoObject`)? | Effective result |
|---|---|---|---|
| `BIOMETRIC_STRONG` | `AUTH_BIOMETRIC_STRONG` | Yes | **Biometric-only, enforced by the Keystore.** The target configuration. |
| `BIOMETRIC_STRONG or DEVICE_CREDENTIAL` | `AUTH_BIOMETRIC_STRONG` | Yes | The user can authenticate with the PIN, but the key operation should then fail because the token type does not match. Effectively biometric-only, with a confusing UX. Confirm on the device: if the transaction completes after the PIN, the key is not what you think it is. |
| `BIOMETRIC_STRONG` | `AUTH_BIOMETRIC_STRONG or AUTH_DEVICE_CREDENTIAL` | Yes | Biometric-only *today*, by app choice. One prompt change away from fallback; also not invalidated on enrolment (MASWE-0022). Report as hardening. |
| `BIOMETRIC_STRONG or DEVICE_CREDENTIAL` | `AUTH_BIOMETRIC_STRONG or AUTH_DEVICE_CREDENTIAL` | Yes | **Fallback, enforced by the Keystore.** MASWE-0021 applies in full. |
| Any | Credential accepted, timeout `> 0` | No | **Fallback by device unlock**: unlocking the phone with the PIN authorises the key for the window, with no app prompt at all. |
| Any | No authentication required | — | Not a fallback problem: the key is unrestricted (MASWE-0016) and the prompt is event-bound (MASWE-0020). |

**What the server can see.** If the key was generated with an attestation challenge, its attestation certificate's authorisation list includes `userAuthType` — a bitmask in which `1` is password (device credential) and `2` is biometric — and `authTimeout` when a window is set (absence of `noAuthRequired` shows authentication is required at all). A backend that verifies attestation at registration can refuse transaction-signing keys whose `userAuthType` includes the password bit or which carry a timeout. This is the only way, on either platform, for a server to *know* that a passcode cannot approve a transaction. The attestation flow is described in our [MASWE-0003 note](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/#android-key-attestation-mastg-know-0044).

### iOS: Local Authentication Framework (MASTG-KNOW-0056)

Source: [MASTG-KNOW-0056](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-AUTH/MASTG-KNOW-0056/). The policy table, `canEvaluatePolicy` errors and context properties are covered in our [MASWE-0017 note](/mobile/maswe-0017-device-secure-lock-not-enforced/#ios-local-authentication-framework-mastg-know-0056). For fallback, four things matter.

**The two policies.**

| Policy | Raw value | Fallback behaviour |
|---|---|---|
| `.deviceOwnerAuthenticationWithBiometrics` | 1 | No system passcode fallback. After a failed match the sheet can show a fallback button whose title is `localizedFallbackTitle`; tapping it ends evaluation with `LAError.userFallback` (−3) and hands the decision back to the app. |
| `.deviceOwnerAuthentication` | 2 | Biometrics first if available; the system offers the device passcode after failed matches, and goes straight to the passcode when biometrics are not enrolled, not available or locked out. |

OWASP's static test (MASTG-TEST-0268) explicitly excludes `.deviceOwnerAuthentication`, because a LocalAuthentication-only flow is event-bound and is tested under MASWE-0020 (MASTG-TEST-0266/0267). We still look at the policy in our tests: an event-bound flow with passcode fallback has *two* problems, and the client needs to fix both.

**`localizedFallbackTitle`.** `nil` (the default) shows a button labelled "Enter Password" after a failed match; an empty string hides it; any other string renames it. The button does not lead to the device passcode under the biometric policy — the app decides what happens on `userFallback`. Look at that handler: if it evaluates `.deviceOwnerAuthentication`, shows an app PIN that is verified locally, or simply proceeds, the fallback exists.

**Lockout.** After five failed matches, biometry is locked (`LAError.biometryLockout`, −8) until the user enters the passcode. The usual way to unlock it from an app is to evaluate `.deviceOwnerAuthentication`. That is fine *as long as nothing is approved by it*: with a crypto-bound design the passcode evaluation cannot unlock a biometry-only key, so it is harmless; with an event-bound design, the success callback of that evaluation is often the same code path that approves the transaction.

**The context and the Keychain.** An `LAContext` can be passed to Keychain queries through `kSecUseAuthenticationContext`, to control the prompt text and to reuse an evaluation. The Keychain item's own access control still decides what is acceptable: a context evaluated with the passcode does not satisfy a biometry-only constraint. So the access-control flags (next section) are what you rate; the policy evaluated on the context is supporting evidence. iOS 16 added `LARight`, whose requirement can be `.default` (biometry or passcode), `.biometry(fallback:)` or `.devicePasscode`; check the SDK headers for the exact cases in the version the app targets, and treat any requirement that admits the passcode like `.userPresence`.

### iOS: Keychain access control flags and passcode fallback (MASTG-KNOW-0057)

Related: [MASTG-KNOW-0057](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-AUTH/MASTG-KNOW-0057/). The full flag table and the accessibility classes are in our [MASWE-0016 note](/mobile/maswe-0016-key-access-not-restricted/#ios-access-control-flags-mastg-know-0056-mastg-know-0057); here is the fallback view.

`SecAccessControlCreateWithFlags(allocator, protection, flags, error)` returns a `SecAccessControl` that is attached to a Keychain item (`kSecAttrAccessControl`) or a Secure Enclave key. From then on, `securityd` and the Secure Enclave show the authentication UI and refuse to return the data or perform the key operation unless the constraint is met. The flags you will meet, with their raw values as they appear in disassembly and Frida output:

| Flags | Raw value | Passcode can satisfy it? | Notes |
|---|---|---|---|
| `.userPresence` | `0x1` | **Yes** | "Lets the system choose": biometry if available, passcode otherwise or after failures |
| `.devicePasscode` | `0x10` | **Yes** — it is the only option | Passcode-only |
| `.biometryAny` | `0x2` | No | Survives enrolment changes (MASWE-0022) |
| `.biometryCurrentSet` | `0x8` | No | Invalidated when the enrolled set changes |
| `[.biometryCurrentSet, .or, .devicePasscode]` | `0x4018` | **Yes** | Explicit fallback; the passcode branch also outlives enrolment changes |
| `[.biometryAny, .or, .devicePasscode]` | `0x4012` | **Yes** | Same, without the enrolment protection on the biometric branch |
| `[.biometryCurrentSet, .and, .devicePasscode]` | `0x8018` | Passcode is *required in addition* | Both factors; stronger, rarely used |
| `[.privateKeyUsage, .userPresence]` | `0x40000001` | **Yes** | Secure Enclave key with fallback |
| `[.privateKeyUsage, .biometryCurrentSet]` | `0x40000008` | No | Secure Enclave key, biometric-only |

OWASP's tests flag `.userPresence` and `.devicePasscode`. Add the `.or` combinations: any value with bit `0x4000` set and bit `0x10` set offers the passcode, regardless of the biometric bit next to it. Apple's documentation describes `.userPresence` as the usual choice for general items, which is exactly why it appears in banking apps — and why the OWASP test page notes that using it is "not inherently a vulnerability" but a weakness for high-security apps.

Remember that the flags sit on top of an accessibility class. Biometric flags are normally paired with `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` (`akpu`), so the item disappears if the passcode is turned off; the [MASWE-0017 note](/mobile/maswe-0017-device-secure-lock-not-enforced/#keychain-accessibility-and-the-whenpasscodeset-class) explains why.

### Both platforms: threat model and when fallback is acceptable

Supplementary. This is the section to read before you write the finding, because the weakness is a trade-off rather than a bug, and clients will push back.

**How device credentials are lost.**

- **Shoulder surfing and cameras.** Phones are unlocked dozens of times a day in public. In 2023 widely reported thefts in the US involved thieves watching victims type their iPhone passcode in bars and then taking the phone; with the passcode they changed account settings and drained banking apps. Apple's response, Stolen Device Protection (iOS 17.3), requires Face ID or Touch ID with no passcode fallback for some of Apple's own sensitive actions when the phone is away from familiar locations, and adds a security delay for others. It protects Apple's settings; as far as Apple documents it, it does not change how a third-party app's LocalAuthentication policy or Keychain access control evaluates. Android 15 introduced a comparable "Identity Check" on supported devices for system settings. Neither is under the app's control, and neither is enabled on every device.
- **Guessing.** Four-digit PINs and simple patterns are guessable; lists of the most common PINs cover a large share of real users. The device's own throttling limits online guessing, but not a guess informed by smudges or a birthday.
- **Sharing.** In households the phone PIN is routinely known to partners, children and parents. Many people give it to repair shops.
- **Coercion.** A PIN can be demanded; so can a fingerprint or a glance at the phone. Biometrics are not a defence against a present, coercive attacker, and you should not claim they are.

**What biometrics add, and what they do not.** A Class 3 biometric, or Face ID / Touch ID, requires the enrolled person's body *at the moment of approval*. That defeats the delayed use of a learned secret, which is the realistic theft and insider scenario. It does not defeat coercion; it is weaker for look-alike relatives (Apple notes that the probability of a Face ID false match is higher for twins, look-alike siblings and children under 13); and it can be defeated by someone who knows the passcode and enrols their own biometric — which is precisely why [MASWE-0022](/mobile/maswe-0022-keys-not-invalidated-on-biometric-enrollment/) exists alongside this weakness. The two should be assessed together: fallback makes enrolment invalidation pointless, and enrolment without invalidation makes biometric-only pointless.

**When fallback is acceptable.**

| Operation | Device-credential fallback | Reasoning |
|---|---|---|
| Unlocking the app to view balances or non-sensitive content | Acceptable | Same assurance as the phone itself; the user already has the device unlocked |
| Re-entering an existing session after a timeout | Acceptable for low-risk apps; consider biometric-only for L2 | The session token is the asset; fallback leaves it as safe as the phone |
| Viewing statements or moderately sensitive personal data | Acceptable with care; document the decision | Disclosure risk rather than irreversible action |
| Payments to existing payees under a low limit | Acceptable *with server-side controls* (limits, velocity rules, notifications) | Risk-based; the server must not rely on the client |
| Payments to new payees, limit increases, adding payees, devices or cards | **Not acceptable** | High-value and irreversible; the core MASWE-0021 case |
| Revealing card details, recovery phrases or keys; disabling security features | **Not acceptable** | Enables follow-on fraud or account takeover |
| EUDIW presentations and qualified signatures | **Not acceptable** | The user's consent is the security model |

**Accessibility and inclusion — the honest trade-off.** Requiring biometrics excludes people. Some users cannot enrol a usable fingerprint (missing fingers, worn ridges from manual work, some skin conditions, tremor); some cannot use face recognition (facial differences, some visual impairments, face coverings worn for religious or medical reasons); and many Android devices have no Class 3 sensor at all, so `BIOMETRIC_STRONG` is simply unavailable. Others cannot reliably memorise a passcode, which is the point of WCAG 2.2 success criterion 3.3.8 *Accessible Authentication (Minimum)* — biometrics *help* them. In the UK the Equality Act 2010 requires reasonable adjustments, and in the EU the European Accessibility Act applies to consumer banking services from 28 June 2025. Industry practice also accepts the device credential more readily than MASWE-0021 does: FIDO2 platform authenticators (passkeys) set the WebAuthn user-verification flag whether the user used a biometric or the device PIN, and NIST SP 800-63B treats a biometric as one way to *activate* a device-bound authenticator, alongside an activation secret, rather than as an authenticator in its own right. MASWE-0021 is an L2 position, stricter than the baseline, and that is appropriate only for genuinely high-value operations.

The way out is not "allow the passcode" but **a deliberate alternative path of comparable assurance**:

- offered explicitly ("I can't use biometrics"), not as a silent downgrade inside the prompt;
- verified by the server, not on the device: an app-specific PIN or password checked server-side with attempt limits (and different from the device passcode), an out-of-band confirmation, a hardware token or card reader, or a call to the bank;
- with compensating server-side controls on that path: lower limits, a cooling-off period for new payees, notifications on another channel;
- recorded per user, so the backend knows which path the user is on and can apply the right risk rules.

When you report, say whether such a path exists. "The app allows the passcode because some users can't use biometrics" is a design decision the client may legitimately make; "the app allows the passcode because nobody thought about it" is the finding.

## Tests

OWASP maps three tests to MASWE-0021: a static test for Android and a static/dynamic pair for iOS. They establish *whether the app references* a fallback-allowing configuration. That is necessary but not sufficient, so we add three supplementary tests: the Android runtime counterpart (including which credential was actually used), the device procedure that proves a transaction can be approved without biometrics, and the backend check.

Before you start:

- **Agree the list of sensitive transactions** with the client (see [Overview](#overview)). Every OWASP evaluation is worded "for any sensitive data resource that needs protection"; without the list you cannot fail anything.
- **Prepare test devices** with a known device credential and an enrolled biometric. On Android you can set a PIN from the host with `adb shell locksettings set-pin 1234` (no root needed) and clear it with `adb shell locksettings clear --old 1234`. On an emulator, enrol fingerprints in Settings and touch the virtual sensor with `adb -e emu finger touch 1`; a finger ID that was never enrolled (`adb -e emu finger touch 9`) produces a failed match. On the iOS Simulator use Features > Face ID (or Touch ID) > Enrolled, Matching and Non-matching. Use dedicated devices: changing credentials invalidates keys for every app.
- **Use a test account** with test money or a sandbox backend; you will be approving transactions.

### MASTG-TEST-0326: References to APIs Allowing Fallback to Non-Biometric Authentication (Android)

Source: [MASTG-TEST-0326](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0326/). Platform: Android. Type: static (code). Related: MASTG-KNOW-0001, MASTG-BEST-0031.

#### Overview

The test looks for `BiometricPrompt` configurations — framework `android.hardware.biometrics.BiometricPrompt` or Jetpack `androidx.biometric.BiometricPrompt` — whose allowed authenticators include `DEVICE_CREDENTIAL`, alone or OR-ed with a biometric class, and for the deprecated `setDeviceCredentialAllowed(true)`. OWASP's own note on the test is worth quoting in substance: using `DEVICE_CREDENTIAL` is not inherently a vulnerability, but in high-security apps (finance, government, health) it is a weakness that reduces the intended security posture — a hardening issue, not a critical vulnerability. We extend the sweep to the key layer, where the decisive configuration usually lives.

#### Prerequisites

- The APK and any split APKs of the build under test (`adb shell pm path <package>`, then `adb pull` each path).
- jadx ([MASTG-TOOL-0018](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/)) for decompilation — OWASP's step "reverse engineer the app" ([MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), in practice [MASTG-TECH-0017](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0017/) "Decompiling Java Code") — and apktool for smali.
- semgrep ([MASTG-TOOL-0110](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/)) for the pattern search — OWASP's "look for the relevant APIs" step, [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/) (static analysis with grep and semgrep).
- The client's list of sensitive transactions.

#### Steps

1. **Decompile.**

   ```bash
   jadx -d out/ base.apk
   apktool d base.apk -o smali_out/
   ```

2. **Run the OWASP rule** `mastg-android-biometric-device-credential-fallback.yml` (from the `rules/` directory of the MASTG repository):

   ```yaml
   rules:
     - id: mastg-android-biometric-device-credential-fallback
       languages:
         - java
       severity: WARNING
       message: "[MASVS-AUTH-3] BiometricPrompt allows fallback to device credentials. For sensitive operations, consider using BIOMETRIC_STRONG only."
       pattern-either:
         - patterns:
             - pattern: $BUILDER.setAllowedAuthenticators($VALUE)
             - metavariable-pattern:
                 metavariable: $VALUE
                 patterns:
                   - pattern-not: BiometricManager.Authenticators.BIOMETRIC_STRONG
                   - pattern-not: 15
         - patterns:
             - pattern: $BM.canAuthenticate($VALUE)
             - metavariable-pattern:
                 metavariable: $VALUE
                 patterns:
                   - pattern-not: BiometricManager.Authenticators.BIOMETRIC_STRONG
                   - pattern-not: 15
         - pattern: |
             $BUILDER.setDeviceCredentialAllowed(true)
   ```

   ```bash
   semgrep -c mastg-android-biometric-device-credential-fallback.yml out/sources/ \
     --exclude 'androidx' --text
   ```

   Read the rule's behaviour before you read its output. It flags **any** authenticator value other than `BIOMETRIC_STRONG`, so `BIOMETRIC_WEAK` (255) is reported too — correct under MASTG-BEST-0031, but it is a weak-biometric finding, not a fallback finding. It also flags every `canAuthenticate` call with another value; `canAuthenticate(DEVICE_CREDENTIAL)` or `canAuthenticate(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)` is very often a *lock-screen check* for MASWE-0017 and not a fallback at all. Its message says MASVS-AUTH-3, while the weakness maps to MASVS-AUTH-2; that is a labelling quirk.

3. **Run a key-layer rule.** The OWASP rule does not look at keys. This one does:

   ```yaml
   rules:
     - id: gt-android-key-accepts-device-credential
       languages: [java]
       severity: WARNING
       message: Keystore key accepts the device credential (type 1 or 3) or uses the deprecated validity setter with a value other than -1
       pattern-either:
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
     - id: gt-android-confirm-device-credential
       languages: [java]
       severity: WARNING
       message: Device-credential-only confirmation (deprecated KeyguardManager API)
       pattern: $K.createConfirmDeviceCredentialIntent(...)
   ```

   ```bash
   semgrep -c gt-android-fallback-keys.yml out/sources/ --exclude 'androidx' --text
   ```

4. **Grep the smali** for the same APIs. Framework classes are never renamed by R8, so this works on obfuscated builds; androidx classes may be renamed, in which case rely on jadx and on the runtime test.

   ```bash
   grep -rnE 'BiometricPrompt\$Builder;->(setAllowedAuthenticators|setDeviceCredentialAllowed|setNegativeButton)' smali_out/
   grep -rnE 'PromptInfo\$Builder;->(setAllowedAuthenticators|setDeviceCredentialAllowed|setNegativeButtonText)' smali_out/
   grep -rnE 'const(/16)? v[0-9]+, 0x80(0f|ff|00)$' smali_out/ | grep -v '/androidx/'
   grep -rnE 'KeyGenParameterSpec\$Builder;->setUserAuthentication(Parameters|ValidityDurationSeconds)' smali_out/
   grep -rn 'createConfirmDeviceCredentialIntent' smali_out/
   ```

   The constant grep is noisy (0x8000 is a common value); use it to locate candidates, then read the surrounding method.

5. **Check cross-platform layers.** For React Native, search the JavaScript bundle for plugin options; for Flutter and .NET MAUI the options live in compiled Dart or IL, so the runtime test is more reliable.

   ```bash
   grep -oE '(disableDeviceFallback|allowDeviceCredentials|biometricOnly|BIOMETRY_[A-Z_]+|DEVICE_PASSCODE)[^,;)]{0,30}' \
     out/resources/assets/index.android.bundle | sort | uniq -c
   ```

6. **Map each hit to an operation.** For each prompt, follow the builder to the `authenticate()` call and from there to what happens on success: which screen, which API request, which key. For each key, follow the alias to the `Cipher`/`Signature` that uses it and to what it protects. Record whether the prompt passes a `CryptoObject`, because that decides which layer is authoritative (see the [prompt/key matrix](#android-key-authenticator-types-decide-the-real-assurance)).

7. **Read the error handlers.** In each `AuthenticationCallback`, look at `onAuthenticationError`: what happens on codes 7, 9, 11, 12 and 13? A second `BiometricPrompt` with `DEVICE_CREDENTIAL`, a `createConfirmDeviceCredentialIntent`, or a call into the success path is a fallback even if the first prompt is biometric-only.

#### Observation

For each `BiometricPrompt` and key: file, class, method, line; the decoded authenticator value and whether a negative button is set; `CryptoObject` or not; the key's authenticator type, timeout and invalidation setting; the operation it protects and its sensitivity; and how error codes are handled.

#### Evaluation

OWASP's criterion: the test **fails** if the app uses `BiometricPrompt` with authenticators that include `DEVICE_CREDENTIAL` for any sensitive data resource that needs protection.

How we apply it:

- **Fail** if a prompt protecting a sensitive transaction allows `DEVICE_CREDENTIAL` (bit `0x8000`) or calls `setDeviceCredentialAllowed(true)`, and the transaction is either event-bound or protected by a key that accepts the device credential.
- **Fail** if the key protecting a sensitive transaction accepts the device credential (type 1 or 3, deprecated setter with a value other than `-1`, or any positive timeout), whatever the prompt says.
- **Fail** if an error or negative-button handler routes a sensitive transaction to a device-credential prompt or a confirm-credential intent.
- **Report separately** (MASTG-BEST-0031): `BIOMETRIC_WEAK` for sensitive transactions.
- **Pass** if every sensitive transaction uses `BIOMETRIC_STRONG` only, a `CryptoObject`, and a key with `AUTH_BIOMETRIC_STRONG` only and timeout `0`. `DEVICE_CREDENTIAL` on non-sensitive features (app unlock) is not a failure.
- **Not this test**: `canAuthenticate` with `DEVICE_CREDENTIAL` used to detect a secure lock screen.

Static results tell you what is configured, not what happens; confirm with [GT-0021-1](#gt-0021-1-runtime-authenticator-configuration-and-result-type-android) and [GT-0021-2](#gt-0021-2-approving-a-sensitive-transaction-without-biometrics-android-ios).

#### Demo

From [MASTG-DEMO-0089](https://mas.owasp.org/MASTG/demos/android/MASVS-AUTH/MASTG-DEMO-0089/MASTG-DEMO-0089/). The sample builds two framework prompts. The first allows fallback in two ways at once:

```kotlin
// FAIL: device credential allowed
val prompt1 = BiometricPrompt.Builder(context)
    .setTitle("Test 1: Device Credential")
    .setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
    .setDeviceCredentialAllowed(true)   // deprecated since API 30
    .build()

// PASS: strong biometrics only, so a negative button is required
val prompt2 = BiometricPrompt.Builder(context)
    .setTitle("Test 2: Biometric Strong")
    .setAllowedAuthenticators(BIOMETRIC_STRONG)
    .setNegativeButton("Cancel", context.mainExecutor) { _, _ -> }
    .build()
```

After jadx, the named constants are gone and the OR has been folded into a single integer:

```java
final BiometricPrompt prompt1 = new BiometricPrompt.Builder(this.context).setTitle("Test 1: Device Credential")
    .setSubtitle("Using DEVICE_CREDENTIAL (Security: FAIL)").setDescription("This allows also PIN/pattern/password authentication")
    .setAllowedAuthenticators(32783).setDeviceCredentialAllowed(true).build();
```

The OWASP rule reports line 38 twice — once for `setAllowedAuthenticators(32783)` and once for `setDeviceCredentialAllowed(true)`:

```text
┌─────────────────┐
│ 2 Code Findings │
└─────────────────┘

    MastgTest_reversed.java
    ❯❱ rules.mastg-android-biometric-device-credential-fallback
          [MASVS-AUTH-3] BiometricPrompt allows fallback to device credentials. For sensitive operations,
          consider using BIOMETRIC_STRONG only.

           38┆ final BiometricPrompt prompt1 = new BiometricPrompt.Builder(this.context).setTitle("Test 1:
               Device Credential")...setAllowedAuthenticators(32783).setDeviceCredentialAllowed(true).build();
            ⋮┆----------------------------------------
           38┆ final BiometricPrompt prompt1 = new BiometricPrompt.Builder(this.context).setTitle("Test 1:
               Device Credential")...setAllowedAuthenticators(32783).setDeviceCredentialAllowed(true).build();
```

32783 is 32768 + 15, `DEVICE_CREDENTIAL | BIOMETRIC_STRONG`. The test fails. `prompt2` (value 15, negative button set) is not reported. Note that both prompts in the demo call `authenticate` without a `CryptoObject`, so even the passing one is event-bound — a separate MASWE-0020 finding that this test does not look at.

### MASTG-TEST-0268: References to APIs Allowing Fallback to Non-Biometric Authentication (iOS)

Source: [MASTG-TEST-0268](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0268/). Platform: iOS. Type: static (code). Related: MASTG-KNOW-0056.

#### Overview

The test looks for `SecAccessControlCreateWithFlags` calls whose `flags` argument is `kSecAccessControlUserPresence` or `kSecAccessControlDevicePasscode`. Both let the passcode satisfy the Keychain item's or key's access control. OWASP deliberately leaves `LAPolicy.deviceOwnerAuthentication` out of scope, since a LocalAuthentication-only flow is event-bound and covered by MASTG-TEST-0266; we add it as an extra step because the client needs to know about both problems. As on Android, OWASP classifies a positive result as a weakness or hardening issue for high-security apps rather than a critical vulnerability.

#### Prerequisites

- A **decrypted** IPA. App Store binaries are FairPlay-encrypted; obtain a decrypted copy as described in [MASTG-TECH-0054](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0054/) "Obtaining and Extracting Apps", or test a development or enterprise build from the client.
- radare2 ([MASTG-TOOL-0073](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/)), `rabin2`, and `plutil` on macOS.
- The list of sensitive transactions and, ideally, which Keychain items or keys back them.

#### Steps

1. **Unpack the app and find the binaries** ([MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/) "Exploring the App Package"). Check the main executable and every framework and extension, because SDKs and app extensions call the Keychain too.

   ```bash
   unzip -q app.ipa -d ipa/
   APP=$(ls -d ipa/Payload/*.app)
   BIN="$APP/$(plutil -extract CFBundleExecutable raw -o - "$APP/Info.plist")"
   find "$APP" -type f -perm -u+x -o -name '*.dylib' | grep -vE '\.(png|nib|car|plist)$' > binaries.txt
   while read -r b; do
     rabin2 -i "$b" 2>/dev/null | grep -qE 'SecAccessControlCreateWithFlags' && echo "[+] $b"
   done < binaries.txt
   ```

2. **Find each call site** ([MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/) "Static Analysis on iOS"). Open the binary in r2 with analysis and list cross-references to the import:

   ```bash
   r2 -A "$BIN"
   ```

   ```text
   [0x100004000]> axt @ sym.imp.SecAccessControlCreateWithFlags
   [0x100004000]> pd -8 @ 0x100004194
   ```

   `axt` lists every caller; `pd -8 @ <addr>` disassembles the eight instructions *before* each call (a negative count goes backwards), which is where the arguments are set up. OWASP's demo script instead runs `pdf` on a hard-coded address and greps around the call, which only works for that binary.

3. **Read the `flags` argument.** `SecAccessControlCreateWithFlags(allocator, protection, flags, error)` takes `flags` as its third argument, so on arm64 it is in `x2`/`w2`. A constant compiles to `mov w2, <value>` (or `mov w2, 0x4018` and similar for combinations). Decode it with the table in the [Knowledge section](#ios-keychain-access-control-flags-and-passcode-fallback-mastg-know-0057): `0x1` is `.userPresence`, `0x10` is `.devicePasscode`, and any value with both `0x4000` and `0x10` set is a biometry-or-passcode combination. If `w2` is copied from another register (`mov w2, w8`), follow it backwards, or use the dynamic test.

4. **Check LocalAuthentication policies as well** (our addition). Look for the selector and the policy constant passed with it:

   ```bash
   rabin2 -zz "$BIN" | grep -E 'evaluatePolicy:localizedReason:reply:|localizedFallbackTitle|evaluateAccessControl'
   ```

   ```text
   [0x100004000]> afl~evaluatePolicy
   [0x100004000]> axt @ <address of the objc_msgSend$evaluatePolicy... stub or selector reference>
   ```

   In the caller, the policy is the first method argument (`x2`/`w2` on arm64): `1` is `.deviceOwnerAuthenticationWithBiometrics`, `2` is `.deviceOwnerAuthentication`. Recent Xcode versions emit per-selector `objc_msgSend$…` stubs, which `afl` lists by name; with older binaries, cross-reference the selector string instead. Also check whether `setLocalizedFallbackTitle:` is called with an empty string.

5. **Attribute each call** to the item or key it protects. Follow the returned `SecAccessControl` to the `SecItemAdd` or `SecKeyCreateRandomKey` that uses it, and note the `kSecAttrAccount`/`kSecAttrService` or `kSecAttrApplicationTag`.

#### Observation

A list of `SecAccessControlCreateWithFlags` call sites with the decoded `flags`, the accessibility class passed as `protection`, the item or key each protects and whether that backs a sensitive transaction; plus any `evaluatePolicy` call sites with their policy and fallback title.

#### Evaluation

OWASP's criterion: the test **fails** if the app uses `SecAccessControlCreateWithFlags` with the `kSecAccessControlUserPresence` or `kSecAccessControlDevicePasscode` flags for any sensitive data resource that needs protection.

How we apply it:

- **Fail** for `.userPresence`, `.devicePasscode` and any `.or` combination that includes `.devicePasscode`, on an item or key that backs a sensitive transaction.
- **Fail** (and report together with the MASWE-0020 finding) if a sensitive transaction is gated only by `evaluatePolicy(.deviceOwnerAuthentication…)`, or by the biometric policy with a `userFallback` or lockout handler that leads to the passcode.
- **Pass** if sensitive items and keys use `.biometryCurrentSet` (or `.biometryAny`, which then fails MASWE-0022) without a passcode alternative. `.userPresence` on non-sensitive items is not a failure.

#### Demo

From [MASTG-DEMO-0043](https://mas.owasp.org/MASTG/demos/ios/MASVS-AUTH/MASTG-DEMO-0043/MASTG-DEMO-0043/). The sample stores a token in the Keychain with `.userPresence` and reads it back, which makes the system prompt for Face ID or, failing that, the passcode:

```swift
guard let accessControl = SecAccessControlCreateWithFlags(
    nil,
    kSecAttrAccessibleWhenUnlocked,
    .userPresence,
    nil
) else { return }

let storeQuery: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "com.mastg.sectoken",
    kSecValueData as String: tokenData,
    kSecAttrAccessControl as String: accessControl,
]
SecItemDelete(storeQuery as CFDictionary)
let storeStatus = SecItemAdd(storeQuery as CFDictionary, nil)
```

The r2 script finds the single caller and the argument setup:

```text
sym.MASTestApp.MastgTest.createAccessControl.Sec.Ref.d_n 0x100004194 [CALL:--x] bl sym.imp.SecAccessControlCreateWithFlags

│           0x100004188      mov x0, 0
│           0x10000418c      mov x1, x19
│           0x100004190      mov w2, 1
│           0x100004194      bl sym.imp.SecAccessControlCreateWithFlags
```

`w2 = 1` is `kSecAccessControlUserPresence`. The test fails: the token can be read with the device passcode. OWASP recommends `.biometryCurrentSet` (preferred) or `.biometryAny` instead. Two side observations for a real report: the accessibility class is `kSecAttrAccessibleWhenUnlocked`, which lets the item migrate to other devices through backups (prefer `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`), and `x0 = 0` is just the default allocator.

### MASTG-TEST-0269: Runtime Use Of APIs Allowing Fallback to Non-Biometric Authentication (iOS)

Source: [MASTG-TEST-0269](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0269/). Platform: iOS. Type: dynamic (hooks). Related: MASTG-KNOW-0056.

#### Overview

The dynamic counterpart to MASTG-TEST-0268. Hooking `SecAccessControlCreateWithFlags` catches calls the static test misses — flags computed at runtime, calls from SDKs, Swift wrappers that hide the constant — and, with a backtrace, tells you which feature created each access-control object. We extend OWASP's hook with `SecItemAdd` (to tie the access control to a Keychain item) and with `LAContext` (to see policies, fallback titles and the outcome of each evaluation).

#### Prerequisites

- The app installed on a device ([MASTG-TECH-0056](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0056/) "Installing Apps"): a jailbroken device with `frida-server`, or a non-jailbroken device with a Frida-Gadget-repackaged build.
- Frida ([MASTG-TOOL-0039](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/)) on the host; hooking as in [MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/) "Method Hooking".
- Clear app state (delete and reinstall) so that access-control objects are created while you watch: most apps create them at enrolment ("Enable Face ID"), not at every use.

#### Steps

1. **Load the hook script.** OWASP's script decodes the flags and prints a backtrace; this version adds the other hooks and handles bit 31 correctly (`1 << 31` is negative in JavaScript):

   ```javascript
   // gt-ios-fallback.js
   const FLAGS = {
     userPresence: 0x1, biometryAny: 0x2, biometryCurrentSet: 0x8, devicePasscode: 0x10,
     watch: 0x20, or: 0x4000, and: 0x8000, privateKeyUsage: 0x40000000, applicationPassword: 0x80000000
   };
   const decode = (v) => Object.keys(FLAGS).filter((k) => ((v & FLAGS[k]) >>> 0) === FLAGS[k]).join('|') || 'none';
   const bt = (ctx) => Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, 6).map(DebugSymbol.fromAddress).join('\n    ');

   Interceptor.attach(Module.getGlobalExportByName('SecAccessControlCreateWithFlags'), {
     onEnter(args) {
       const v = args[2].toUInt32();
       const prot = new ObjC.Object(args[1]).toString();
       const passcodeOk = (v & 0x1) || ((v & 0x10) && !(v & 0x8000));
       console.log(`\n[ACL] flags=0x${v.toString(16)} (${decode(v)}) protection=${prot}` +
         (passcodeOk ? '  <-- passcode can satisfy' : ''));
       console.log('    ' + bt(this.context));
     }
   });

   Interceptor.attach(Module.getGlobalExportByName('SecItemAdd'), {
     onEnter(args) {
       const q = new ObjC.Object(args[0]);
       if (q.objectForKey_('accc') !== null) {
         console.log(`[SecItemAdd] class=${q.objectForKey_('class')} acct=${q.objectForKey_('acct')} ` +
           `svce=${q.objectForKey_('svce')} with access control`);
       }
     }
   });

   const POLICY = { 1: 'deviceOwnerAuthenticationWithBiometrics', 2: 'deviceOwnerAuthentication' };
   Interceptor.attach(ObjC.classes.LAContext['- evaluatePolicy:localizedReason:reply:'].implementation, {
     onEnter(args) {
       const ctx = new ObjC.Object(args[0]);
       const p = args[2].toInt32();
       const fb = ctx.localizedFallbackTitle();
       console.log(`\n[LAContext] evaluatePolicy(${POLICY[p] || p}) reason="${new ObjC.Object(args[3])}" ` +
         `fallbackTitle=${fb === null ? 'default ("Enter Password")' : '"' + fb + '"'}`);
       const block = new ObjC.Block(args[4]);
       const orig = block.implementation;
       block.implementation = function (success, error) {
         const e = (error && !error.isNull()) ? new ObjC.Object(error) : null;
         console.log(`[LAContext]   -> success=${success} error=${e ? e.code() : 'nil'}`);
         return orig(success, error);
       };
     }
   });
   ```

   `accc` is the raw value of `kSecAttrAccessControl` in the query dictionary (`acct` and `svce` are `kSecAttrAccount` and `kSecAttrService`). With Frida older than 17, replace `Module.getGlobalExportByName(name)` with `Module.findExportByName(null, name)`.

2. **Spawn the app with the script.**

   ```bash
   frida -U -f com.example.bank -l gt-ios-fallback.js -o fallback.log
   ```

3. **Exercise every flow**: enable Face ID / Touch ID login, log in with it, and perform each sensitive transaction — payment, new payee, card reveal, limit change, wallet presentation. Then repeat a transaction and deliberately fail biometrics (Simulator: Non-matching Face; device: wrong finger, or look away) until the fallback button or the passcode keypad appears; tap it and note the log. Finally trigger biometry lockout (five failures) and observe how the app recovers.

#### Observation

The log of access-control objects (flags, protection class, backtrace), the Keychain items created with them, and every `LAContext` evaluation with its policy, fallback title and result code (`-3` userFallback, `-8` biometryLockout and so on).

#### Evaluation

OWASP's criterion: the test **fails** if the app uses `SecAccessControlCreateWithFlags` with the `kSecAccessControlUserPresence` or `kSecAccessControlDevicePasscode` flags for any sensitive data resource that needs protection.

We additionally fail the test if a sensitive transaction is approved after an `LAContext` evaluation of `.deviceOwnerAuthentication`, or after a `userFallback` (−3) or `biometryLockout` (−8) result is followed by a passcode evaluation that leads to approval. Use the backtrace and the order of log lines to tie each object or evaluation to the feature that triggered it.

#### Demo

From [MASTG-DEMO-0044](https://mas.owasp.org/MASTG/demos/ios/MASVS-AUTH/MASTG-DEMO-0044/MASTG-DEMO-0044/), which runs OWASP's script against the same sample as MASTG-DEMO-0043 (`frida -U -f org.owasp.mastestapp.MASTestApp-iOS -l ./script.js -o output.txt`, then tap **Start**):

```text
SecAccessControlCreateWithFlags(..., 0x1) called with kSecAccessControlUserPresence

Backtrace:
0x100a4c27c MASTestApp.debug.dylib!static MastgTest.mastgTest(completion:)
0x100a4f000 MASTestApp.debug.dylib!$s10MASTestApp11ContentViewV4bodyQrvg7SwiftUI05TupleD0V...
0x19ffdae30 SwiftUI!partial apply for implicit closure #2 in implicit closure #1 in WrappedButtonStyle.Body.body.getter
```

The flags are `0x1`, `.userPresence`, created from `MastgTest.mastgTest(completion:)`: the test fails. With our script the same call prints `[ACL] flags=0x1 (userPresence) protection=ak  <-- passcode can satisfy`, followed by `[SecItemAdd] class=genp acct=com.mastg.sectoken svce=null with access control`; `ak` is the stored value of `kSecAttrAccessibleWhenUnlocked`.

### GT-0021-1: Runtime authenticator configuration and result type (Android)

Guler Tech methodology. Platform: Android. Type: dynamic (hooks).

#### Overview

The Android counterpart that OWASP does not (yet) have. Hooking the framework builders catches prompts built by androidx, by cross-platform plugins and by obfuscated code, because on API 30 and later androidx builds a framework `BiometricPrompt` under the hood and calls `setAllowedAuthenticators` on it. Hooking the key specification shows the key layer. Hooking the authentication result shows which credential the user actually used for each approval — the single most persuasive piece of evidence for this weakness.

#### Prerequisites

- Android 11 (API 30) or later device or emulator with `frida-server` (OWASP [MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/) "Method Hooking"; [Frida for Android, MASTG-TOOL-0001](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0001/)), with a PIN set and a fingerprint enrolled.
- App data cleared (`adb shell pm clear <package>`) so keys are created while you watch.

#### Steps

1. **Load the hooks.**

   ```javascript
   // gt-android-fallback.js
   Java.perform(function () {
     const dec = (v) => {
       const out = [];
       if ((v & 0xFF) === 0xFF) out.push('BIOMETRIC_WEAK'); else if ((v & 0x0F) === 0x0F) out.push('BIOMETRIC_STRONG');
       if (v & 0x8000) out.push('DEVICE_CREDENTIAL');
       return out.join('|') || String(v);
     };
     const where = () => Java.use('android.util.Log')
       .getStackTraceString(Java.use('java.lang.Exception').$new()).split('\n').slice(2, 7).join('\n');

     const B = Java.use('android.hardware.biometrics.BiometricPrompt$Builder');
     B.setAllowedAuthenticators.implementation = function (v) {
       console.log('\n[prompt] setAllowedAuthenticators(' + v + ') = ' + dec(v) + '\n' + where());
       return this.setAllowedAuthenticators(v);
     };
     B.setDeviceCredentialAllowed.implementation = function (b) {
       console.log('\n[prompt] setDeviceCredentialAllowed(' + b + ')  (deprecated)\n' + where());
       return this.setDeviceCredentialAllowed(b);
     };

     const R = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');
     R.$init.overloads.forEach(function (o) {
       o.implementation = function () {
         const t = arguments[arguments.length - 1];
         const name = t === 1 ? 'DEVICE_CREDENTIAL' : t === 2 ? 'BIOMETRIC' : String(t);
         console.log('[result] authenticated with ' + name + ', crypto=' + (arguments[0] !== null));
         return o.apply(this, arguments);
       };
     });

     const K = Java.use('android.security.keystore.KeyGenParameterSpec$Builder');
     K.build.implementation = function () {
       const s = this.build();
       const type = s.getUserAuthenticationType();
       console.log('\n[key] alias=' + s.getKeystoreAlias() + ' authRequired=' + s.isUserAuthenticationRequired() +
         ' timeout=' + s.getUserAuthenticationValidityDurationSeconds() +
         ' type=' + type + ((type & 1) ? ' (DEVICE_CREDENTIAL accepted)' : '') +
         ' invalidatedByEnrollment=' + s.isInvalidatedByBiometricEnrollment() + '\n' + where());
       return s;
     };
   });
   ```

   The `AuthenticationResult` constructor is hidden API; Frida hooks it regardless. On the Android versions we have used it takes the `CryptoObject` (null for event-bound prompts) and the authentication type as its last argument; if a newer release changes the signature, print all arguments once and adjust the index. For the full key-specification dump, use the script in our [MASWE-0016 note](/mobile/maswe-0016-key-access-not-restricted/#gt-0016-2-key-restrictions-at-creation-and-in-keyinfo-android).

2. **Run it and exercise the flows.**

   ```bash
   frida -U -f com.example.bank -l gt-android-fallback.js -o fallback.log
   ```

   Enable biometric login and transaction approval, then perform each sensitive transaction twice: once with the fingerprint, once tapping "Use PIN" (if offered) and entering the PIN.

3. **Exercise the error paths.** Fail five times with an unenrolled finger (`adb -e emu finger touch 9` on an emulator) to cause `ERROR_LOCKOUT`; keep failing after the timeout to reach `ERROR_LOCKOUT_PERMANENT`; tap the negative button where there is one. Note any new prompt and its authenticators.

#### Observation

For each transaction: the prompt's authenticators, the key's authenticator type and timeout, the `CryptoObject` presence, and the `[result]` line showing whether the approval was made with `BIOMETRIC` or `DEVICE_CREDENTIAL`; plus the prompts shown on error paths.

#### Evaluation

The test **fails** if any sensitive transaction completes with a `[result] authenticated with DEVICE_CREDENTIAL` line — that is direct evidence of fallback, regardless of how it was configured. It also fails if a prompt for a sensitive transaction is built with `DEVICE_CREDENTIAL`, or a key protecting one has type 1 or 3 or a positive timeout, even if you did not manage to complete the transaction with the PIN. It passes if every sensitive approval is `BIOMETRIC` with a `CryptoObject`, and error paths end in cancellation or a deliberate alternative flow that does not use the device credential.

#### Demo

Output for a lab app whose payment prompt is biometric-only but whose lockout handler is not:

```text
[key] alias=payment_signing authRequired=true timeout=0 type=3 (DEVICE_CREDENTIAL accepted) invalidatedByEnrollment=true
    at com.example.bank.keys.SigningKeys.create(SigningKeys.java:58)

[prompt] setAllowedAuthenticators(15) = BIOMETRIC_STRONG
    at androidx.biometric.BiometricFragment.showBiometricPromptForAuthentication(...)
    at com.example.bank.pay.ApproveFragment.approve(ApproveFragment.java:112)
[result] authenticated with BIOMETRIC, crypto=true

[prompt] setAllowedAuthenticators(32768) = DEVICE_CREDENTIAL
    at com.example.bank.pay.ApproveFragment$callback$1.onAuthenticationError(ApproveFragment.java:141)
[result] authenticated with DEVICE_CREDENTIAL, crypto=true
```

The first approval used the fingerprint. After deliberate lockout, the error handler built a credential-only prompt, the key (type 3) accepted the PIN, and the payment was signed. The test fails, and the report should name both causes: the key's authenticator type and the lockout handler.

### GT-0021-2: Approving a sensitive transaction without biometrics (Android, iOS)

Guler Tech methodology. Platforms: Android and iOS. Type: dynamic (device procedure, no instrumentation).

#### Overview

The black-box proof. You use the app as an attacker who knows the device credential would: start a sensitive transaction, avoid or fail the biometric, and try to complete it with the PIN or passcode. No hooks are needed, which matters because it reproduces on a production build, on a non-rooted device, and in front of the client.

#### Prerequisites

- A test device (not rooted or jailbroken is fine) with a known device credential and one enrolled biometric; a test account with funds or a sandbox backend.
- Optional: a proxy (Burp Suite) to capture the approval request and response for the report.

#### Steps

1. **Baseline.** Perform the transaction normally with the biometric. Capture the approval request (headers and body) and note what proves the approval — a signature, an assertion, a token.
2. **Look for the fallback affordance.** Start the transaction again and, at the prompt:
   - Android: is there a "Use PIN" / "Use pattern" / "Use password" button? A negative button labelled "Cancel" means biometric-only; "Use PIN" means `DEVICE_CREDENTIAL`.
   - iOS: fail Face ID or Touch ID once (look away, wrong finger, Simulator Non-matching Face). Does an "Enter Passcode" or "Enter Password" button appear? Tap it and see whether the system passcode keypad or an app screen appears.
3. **Complete it with the credential.** Enter the device PIN or passcode. Record whether the transaction completes, and whether the server accepted it.
4. **Trigger lockout.** Fail the biometric five times. On Android wait out `ERROR_LOCKOUT` and fail again to reach `ERROR_LOCKOUT_PERMANENT`; on iOS the fifth failure gives `biometryLockout`. See what the app offers, enter the credential when asked, and record whether the *pending transaction* completes or whether you are merely returned to the biometric prompt.
5. **Remove the biometric.** Delete all enrolled fingerprints/faces (keep the credential) and start the transaction. Does the app refuse, offer an explicit alternative path, or quietly accept the credential? Re-enrol afterwards — and note that this invalidates the app's biometric keys, so you will have to re-enable biometrics in the app.
6. **Check the app's alternative.** If the app offers its own PIN, find out how it is verified: is the PIN sent to the server (look for it in the proxy), or checked on the device? A locally verified app PIN is only as strong as its storage (see our [MASWE-0016 note](/mobile/maswe-0016-key-access-not-restricted/)); a server-verified one with attempt limits is a legitimate alternative path.

#### Observation

Screenshots or a screen recording of each prompt (showing the fallback affordance), the outcome of steps 3–5 for each sensitive transaction, and the proxy evidence of the accepted approval.

#### Evaluation

The test **fails** if any sensitive transaction completes after entering the device PIN, pattern, password or passcode — at step 3, at step 4 (lockout path) or at step 5 (no biometrics enrolled). It **passes** if the transaction can only complete with the biometric, and lockout or missing biometrics lead either to cancellation or to a deliberate alternative path that is verified by the server and does not use the device credential. Record the alternative path either way; it affects the rating.

#### Demo

What a failing run looks like on Android, in words: the payment prompt shows a fingerprint icon and a "Use PIN" button; tapping "Use PIN" shows the system keypad; entering `1234` returns to the app with "Payment sent". The proxy shows the same `POST /payments/approve` with an ECDSA signature in the body as in the biometric baseline, and a `200 OK`. On iOS: after one failed Face ID attempt the sheet shows "Enter Passcode"; the passcode completes the transaction. Either is the whole finding in thirty seconds of video.

### GT-0021-3: Does the backend know how the user authenticated (Android, iOS)

Guler Tech methodology. Platforms: Android and iOS. Type: dynamic (backend).

#### Overview

MASVS-AUTH requires enforcement on the remote endpoint. For this weakness that means: can the server tell a biometric approval from a passcode approval, and does it rely on anything the client merely *claims*? This test establishes what the backend checks, so that you can say whether a client-side fix is sufficient. It maps to OWASP WSTG-ATHN-10 "Testing for Weaker Authentication in Alternative Channel" and the authentication chapter (V6) of OWASP ASVS 5.0.

#### Prerequisites

- Proxy access to the app's traffic (certificate pinning bypassed where necessary) and a test account.
- For the Android attestation step: a rooted device or emulator with Frida, and an app that sends key attestation at device registration.

#### Steps

1. **Look for client claims.** In the approval and registration requests, search for fields describing the authentication: `authMethod`, `authType`, `biometric`, `faceId`, `userVerification`, `amr`, `acr`. If present, replay a transaction approved with the device credential but with the field changed to the biometric value, and vice versa. If the server's behaviour (limits, extra OTP, risk score) changes, it is trusting a client claim.
2. **Look for proof.** Determine whether the approval carries a signature from a device-bound key, and whether that key was registered with attestation (Android: a certificate chain with the key attestation extension `1.3.6.1.4.1.11129.2.1.17` sent at registration; iOS: App Attest objects, which attest the app, not the key's access control).
3. **Android: test whether the server checks `userAuthType`.** Re-register the device after modifying, with Frida, the key specification the app builds — for example, in the `KeyGenParameterSpec$Builder.setUserAuthenticationParameters` hook, call the original with type `3` instead of `2`, or add a timeout. If the server accepts the registration and later approvals with that key, it does not verify that transaction keys are biometric-only.

   ```javascript
   Java.perform(function () {
     const K = Java.use('android.security.keystore.KeyGenParameterSpec$Builder');
     K.setUserAuthenticationParameters.implementation = function (timeout, type) {
       console.log('[tamper] setUserAuthenticationParameters(' + timeout + ', ' + type + ') -> (' + timeout + ', 3)');
       return this.setUserAuthenticationParameters(timeout, 3);
     };
   });
   ```

4. **Look for compensating controls** on paths that do not use the biometric key: transaction limits, cooling-off for new payees, notifications on another channel (email, SMS), server-side step-up (OTP) for high-value operations. Note which apply to a credential-approved transaction from GT-0021-2.

#### Observation

The relevant request fields, whether approvals carry a device-key signature, whether attestation is sent and what the server does with a key whose attestation shows device-credential acceptance, and the compensating controls you observed.

#### Evaluation

The test **fails** if the server changes its decision based on a client-reported authentication method, or (Android) accepts a transaction-signing key whose attestation shows `userAuthType` including the password bit or an `authTimeout`, for a transaction class the design says requires biometrics. On iOS the server cannot verify the access control of a key; record that as a design limitation, and rely on GT-0021-2 and on compensating controls for the rating.

#### Demo

A lab backend's approval request:

```json
{
  "paymentId": "pay_7c1e",
  "authMethod": "BIOMETRIC",
  "signature": "MEUCIQDf...",
  "deviceId": "dev_42"
}
```

Changing `"authMethod"` to `"BIOMETRIC"` on a payment approved with the device PIN raised the per-transaction limit from £250 to £5,000. The signature was valid in both cases because the key accepted the PIN (type 3). The server trusted the client's claim: the test fails, and the finding is the combination of the key configuration and the server's reliance on a client field.

## Best practices

OWASP links one best practice, MASTG-BEST-0031, which is Android-only. We add the iOS counterpart as Guler Tech guidance.

### MASTG-BEST-0031: Enforce Strong Biometrics for Sensitive Operations (Android)

Source: [MASTG-BEST-0031](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0031/). Related: MASTG-KNOW-0001.

OWASP's guidance has two parts: require `BIOMETRIC_STRONG` (Class 3) rather than allowing weaker classes, and do not include `DEVICE_CREDENTIAL` when the operation is meant to be biometric-only, because the screen-lock credential is more susceptible to shoulder surfing and social engineering. It repeats that the device credential is not inherently a vulnerability but reduces the security posture of high-security apps.

In practice, apply it at both layers and handle the edge cases deliberately:

```kotlin
private const val ALIAS = "payment_signing"

fun createSigningKey(challenge: ByteArray) {
    val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
    kpg.initialize(
        KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG) // no device credential, no window
            .setInvalidatedByBiometricEnrollment(true)                                // MASWE-0022
            .setAttestationChallenge(challenge)                                       // server verifies userAuthType
            .build()
    )
    kpg.generateKeyPair()
}

fun approve(activity: FragmentActivity, payload: ByteArray, onSigned: (ByteArray) -> Unit) {
    val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val sig = Signature.getInstance("SHA256withECDSA").apply {
        initSign(ks.getKey(ALIAS, null) as PrivateKey)  // may throw KeyPermanentlyInvalidatedException
    }
    val info = BiometricPrompt.PromptInfo.Builder()
        .setTitle("Approve payment")
        .setSubtitle("£250.00 to J. Smith")
        .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        .setNegativeButtonText("Cancel")
        .build()
    BiometricPrompt(activity, ContextCompat.getMainExecutor(activity),
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                val s = result.cryptoObject?.signature ?: return
                s.update(payload)
                onSigned(s.sign())
            }
            override fun onAuthenticationError(code: Int, msg: CharSequence) {
                // Lockout, no biometrics, negative button: cancel the transaction.
                // Never build a DEVICE_CREDENTIAL prompt here to "continue".
            }
        }).authenticate(info, BiometricPrompt.CryptoObject(sig))
}
```

Points to carry into a remediation recommendation:

- The key is the control; the prompt configuration is the user interface. `AUTH_BIOMETRIC_STRONG` with timeout `0` means a device-credential authentication cannot sign, whatever the app does later.
- Check availability first with `BiometricManager.from(context).canAuthenticate(BIOMETRIC_STRONG)`. If it is not `BIOMETRIC_SUCCESS`, do not offer the biometric feature for sensitive transactions; route the user to the deliberate alternative path, and tell the server which path they are on.
- After lockout, it is fine to let the user unlock biometrics with the device credential — but in a separate step that approves nothing.
- Verify the attestation on the server and reject transaction keys whose `userAuthType` includes the password bit or which carry an `authTimeout`.
- Where the device supports it, Android Protected Confirmation (`setUserConfirmationRequired(true)`) shows the transaction text in trusted UI; see our [MASWE-0016 note](/mobile/maswe-0016-key-access-not-restricted/#android-unlocked-device-user-presence-and-protected-confirmation).

### iOS counterpart: biometry-only access control (Guler Tech)

Guler Tech guidance; OWASP has no iOS best-practice page for this weakness. Protect the operation with a Secure Enclave key (or a Keychain item) whose access control admits biometrics only, and hide the fallback button:

```swift
let tag = Data("com.example.bank.payment".utf8)

func createSigningKey() throws {
    var error: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
        [.privateKeyUsage, .biometryCurrentSet],          // 0x40000008: no passcode branch
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
}

// Call off the main thread: the signing call blocks while the system prompt is shown.
func approve(_ payload: Data, summary: String) throws -> Data {
    let context = LAContext()
    context.localizedFallbackTitle = ""        // no "Enter Password" button
    context.localizedReason = summary          // e.g. "Approve £250.00 to J. Smith"
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: tag,
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecReturnRef as String: true,
        kSecUseAuthenticationContext as String: context,
    ]
    var item: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let ref = item else {
        throw NSError(domain: NSOSStatusErrorDomain, code: Int(errSecItemNotFound))
    }
    let key = ref as! SecKey
    var error: Unmanaged<CFError>?
    guard let signature = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256,
                                                payload as CFData, &error) else {
        throw error!.takeRetainedValue() as Error  // includes user cancel and biometry lockout
    }
    return signature as Data
}
```

The same principles as on Android apply: the access control is the control, `localizedFallbackTitle = ""` only tidies the UI, lockout recovery (evaluating `.deviceOwnerAuthentication` to re-enable biometry) must not approve anything — and with this key it cannot, because a passcode evaluation does not satisfy `.biometryCurrentSet`. Users without biometrics go to the deliberate, server-verified alternative path. If the app stores a secret rather than a key, use the same access control on a `kSecClassGenericPassword` item.

## Rating findings

Rate on four things: how sensitive the transaction is; at which layer the fallback is enforced (key-level fallback is a demonstrated property of the platform, prompt-level fallback in an event-bound flow is secondary to the bypass); whether you demonstrated approval with the credential (GT-0021-1 or GT-0021-2); and what the server does on that path. OWASP's own position is that device-credential use is a weakness or hardening issue for high-security apps, not a critical vulnerability; we agree for the configuration alone and rate higher only when the impact is demonstrated and uncompensated.

| Rating | Conditions |
|---|---|
| **Critical** | Not appropriate for MASWE-0021 on its own. If a "fallback" path approves a sensitive transaction with **no** credential at all (negative button, error callback or cancelled prompt treated as success), report it as an authentication bypass under [MASWE-0020](/mobile/maswe-0020-local-authentication-bypass/) and rate it there. |
| **High** | L2 or EUDIW app; a high-value transaction (new payee, transfer above a low threshold, limit change, card or secret reveal, wallet presentation or qualified signature) was approved with the device credential in GT-0021-1 or GT-0021-2 — via the prompt, the key, the lockout handler or a missing-biometrics downgrade; the app presents the operation as biometric-protected; and the server applies no compensating control on that path, or trusts a client-reported authentication method (GT-0021-3). |
| **Medium** | The same demonstrated fallback with meaningful server-side compensation (low limits, cooling-off for new payees, out-of-band notification); or fallback configured at the key or prompt for a sensitive transaction but not demonstrable end to end; or `BIOMETRIC_WEAK` accepted for sensitive transactions (MASTG-BEST-0031); or `.userPresence` / `.or .devicePasscode` on the item or key backing a sensitive transaction. |
| **Low** | Fallback on moderately sensitive features (statements, personal data views); a biometric-only prompt in front of a key that accepts the device credential, where the app never offers the credential (hardening); a locally verified app PIN offered as the alternative path for users without biometrics. |
| **Info** | Fallback for app unlock and session re-entry; a deliberate, documented, server-verified alternative path for users who cannot use biometrics; any fallback in an app outside the L2/EUDIW profiles. |

In the report, give the transaction, the exact configuration at each layer (decoded authenticator values or flags), the evidence that the transaction completed with the credential (the `[result]` line, a screen recording, the accepted request), and the server-side controls you observed. Pair the finding with the MASWE-0022 result for the same key: a recommendation to remove the fallback should come with a recommendation to keep enrolment invalidation, or the attacker who knows the passcode simply enrols their own finger. And include the accessibility paragraph: recommend a deliberate alternative path, not "biometrics or nothing".

## References

- OWASP MASWE — [MASWE-0021: Fallback to Non-biometric Credentials Allowed for Sensitive Transactions](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0021/) (CC BY-SA 4.0)
- OWASP MASWE — [MASWE-0020: Local Authentication Can Be Bypassed](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0020/) and [MASWE-0022: Crypto Keys Not Invalidated on New Biometric Enrollment](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0022/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0326: References to APIs Allowing Fallback to Non-Biometric Authentication (Android)](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0326/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0268: References to APIs Allowing Fallback to Non-Biometric Authentication (iOS)](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0268/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0269: Runtime Use Of APIs Allowing Fallback to Non-Biometric Authentication](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0269/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-BEST-0031: Enforce Strong Biometrics for Sensitive Operations](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0031/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0001: Biometric Authentication](https://mas.owasp.org/MASTG/knowledge/android/MASVS-AUTH/MASTG-KNOW-0001/), [MASTG-KNOW-0056: Local Authentication Framework](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-AUTH/MASTG-KNOW-0056/), [MASTG-KNOW-0057: Keychain Services](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-AUTH/MASTG-KNOW-0057/) (CC BY-SA 4.0)
- OWASP MASTG — demos [MASTG-DEMO-0089](https://mas.owasp.org/MASTG/demos/android/MASVS-AUTH/MASTG-DEMO-0089/MASTG-DEMO-0089/), [MASTG-DEMO-0043](https://mas.owasp.org/MASTG/demos/ios/MASVS-AUTH/MASTG-DEMO-0043/MASTG-DEMO-0043/), [MASTG-DEMO-0044](https://mas.owasp.org/MASTG/demos/ios/MASVS-AUTH/MASTG-DEMO-0044/MASTG-DEMO-0044/) (CC BY-SA 4.0)
- OWASP MASTG — legacy (MASTG v1) tests [MASTG-TEST-0017: Testing Confirm Credentials](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0017/), [MASTG-TEST-0018: Testing Biometric Authentication](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0018/), [MASTG-TEST-0064: Testing Biometric Authentication (iOS)](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0064/) (CC BY-SA 4.0)
- OWASP MASTG — techniques [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0017](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0017/), [MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/), [MASTG-TECH-0054](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0054/), [MASTG-TECH-0056](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0056/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/); tools [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [Frida for Android (MASTG-TOOL-0001)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0001/), [Frida for iOS (MASTG-TOOL-0039)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/), [radare2 (MASTG-TOOL-0073)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/), [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/) (CC BY-SA 4.0)
- OWASP MAS Profiles — [MAS-L2](https://mas.owasp.org/Profiles/MAS-L2/) and [MAS-EUDIW](https://mas.owasp.org/Profiles/MAS-EUDIW/) (CC BY-SA 4.0)
- [OWASP WSTG — Testing for Weaker Authentication in Alternative Channel (WSTG-ATHN-10)](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/04-Authentication_Testing/10-Testing_for_Weaker_Authentication_in_Alternative_Channel) and [OWASP ASVS 5.0](https://owasp.org/www-project-application-security-verification-standard/) (V6 Authentication)
- [Android Developers — Show a biometric authentication dialog, "Allow fallback to non-biometric credentials"](https://developer.android.com/training/sign-in/biometric-auth#allow-fallback)
- [Android Developers — `BiometricManager.Authenticators`](https://developer.android.com/reference/androidx/biometric/BiometricManager.Authenticators), [`BiometricPrompt.PromptInfo.Builder`](https://developer.android.com/reference/androidx/biometric/BiometricPrompt.PromptInfo.Builder), [framework `BiometricPrompt.Builder`](https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt.Builder) (including the deprecated `setDeviceCredentialAllowed`)
- [Android Developers — `KeyGenParameterSpec.Builder`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder), [`KeyProperties`](https://developer.android.com/reference/android/security/keystore/KeyProperties) and [Verifying hardware-backed key pairs with key attestation](https://developer.android.com/privacy-and-security/security-key-attestation)
- [AOSP — Biometrics](https://source.android.com/docs/security/features/biometric) and [Measuring biometric unlock security](https://source.android.com/docs/security/features/biometric/measure)
- [Apple — Logging a user into your app with Face ID or Touch ID](https://developer.apple.com/documentation/localauthentication/logging-a-user-into-your-app-with-face-id-or-touch-id), [`LAPolicy.deviceOwnerAuthenticationWithBiometrics`](https://developer.apple.com/documentation/localauthentication/lapolicy/deviceownerauthenticationwithbiometrics), [`LAContext.localizedFallbackTitle`](https://developer.apple.com/documentation/localauthentication/lacontext/localizedfallbacktitle)
- [Apple — `SecAccessControlCreateWithFlags`](https://developer.apple.com/documentation/security/secaccesscontrolcreatewithflags%28_:_:_:_:%29), [`SecAccessControlCreateFlags`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags) and [Accessing keychain items with Face ID or Touch ID](https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id)
- [Apple Support — About Stolen Device Protection for iPhone](https://support.apple.com/en-us/120340) and [Apple Platform Security — Face ID and Touch ID security](https://support.apple.com/guide/security/face-id-and-touch-id-security-sec067eb0c9e/web)
- [NIST SP 800-63B-4 — Digital Identity Guidelines: Authentication and Authenticator Management](https://csrc.nist.gov/pubs/sp/800/63/b/4/final)
- [W3C — WCAG 2.2, Success Criterion 3.3.8 Accessible Authentication (Minimum)](https://www.w3.org/WAI/WCAG22/Understanding/accessible-authentication-minimum.html)
- [CWE-288: Authentication Bypass Using an Alternate Path or Channel](https://cwe.mitre.org/data/definitions/288.html) and [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
