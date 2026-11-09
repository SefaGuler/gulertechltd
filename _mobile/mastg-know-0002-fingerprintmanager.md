---
title: "FingerprintManager: Testing Legacy Android Fingerprint Auth (MASTG-KNOW-0002)"
date: 2026-09-02
subcategory: auth
summary: "The deprecated pre-API 28 fingerprint API — what a correct implementation looks like, the five prerequisite checks, and how to spot the null-CryptoObject pattern."
refs: [MASTG-KNOW-0002, MASVS-AUTH-2, CWE-287]
tags: [android, biometrics, fingerprintmanager, keystore, legacy]
---

## What it is

`android.hardware.fingerprint.FingerprintManager` was introduced in Android 6.0 (API 23) as the first public fingerprint API and deprecated in Android 9 (API 28) in favour of `BiometricPrompt` and the Jetpack Biometric library. You will still find it in apps with long support windows, in vendor SDKs, and in code paths guarded by `Build.VERSION.SDK_INT` checks. It is worth knowing because the legacy API makes the insecure pattern easier to write than the secure one.

An app requests authentication by instantiating a `FingerprintManager` and calling:

```java
fingerprintManager.authenticate(cryptoObject, cancellationSignal, flags, callback, handler);
```

and registering callbacks for success, failure and error.

## Why the API itself is not proof of authentication

The `authenticate()` callback tells the app that the system reported a successful fingerprint match. It does not constitute cryptographic proof that authentication occurred. The check runs in the app's own process, so an attacker can patch out the branch in a repackaged APK, or overload `onAuthenticationSucceeded()` with dynamic instrumentation and invoke it directly. This is the same event-bound weakness described in MASTG-KNOW-0001, and it is the default outcome if the developer passes `null` as the first argument to `authenticate()`.

Two designs make the control real:

**Symmetric.** Create an AES key in the Android Keystore with `setUserAuthenticationRequired(true)`. Use it to encrypt the authentication token, and store the ciphertext locally (SharedPreferences is acceptable for the ciphertext). The token cannot be recovered without a fingerprint that unlocks the key.

**Asymmetric — stronger.** Generate an EC key pair in the Keystore, enrol the public key with the backend during registration, and sign each transaction with the private key. The server verifies the signature. The client cannot produce a valid signature without a successful fingerprint authentication, and the proof is verified off-device, so a compromised client cannot forge it. Add a server-issued nonce to the signed payload or transactions are replayable.

## The five prerequisite checks

A safe implementation must confirm all of these before offering fingerprint auth. Their absence is itself a finding, because the app will otherwise present a biometric option that silently degrades.

```xml
<uses-permission android:name="android.permission.USE_FINGERPRINT" />
```

```java
// 1. hardware present
FingerprintManager fpm = (FingerprintManager) context.getSystemService(Context.FINGERPRINT_SERVICE);
fpm.isHardwareDetected();

// 2. secure lock screen configured
KeyguardManager km = (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
km.isKeyguardSecure();

// 3. at least one finger enrolled
fpm.hasEnrolledFingerprints();

// 4. runtime permission granted
context.checkSelfPermission(Manifest.permission.USE_FINGERPRINT) == PackageManager.PERMISSION_GRANTED;

// 5. API level >= 23
```

If any check fails, the fingerprint option must not be offered — it must not fall through to an unauthenticated path.

## Correct key generation

Symmetric key bound to authentication:

```java
KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
generator.init(new KeyGenParameterSpec.Builder(KEY_ALIAS,
        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
        .setUserAuthenticationRequired(true)
        .build());
generator.generateKey();
```

The `Cipher` is then wrapped and passed through the fingerprint flow:

```java
cryptoObject = new FingerprintManager.CryptoObject(cipher);
fingerprintManager.authenticate(cryptoObject, new CancellationSignal(), 0, this, null);
```

and retrieved from the result on success:

```java
public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
    Cipher cipher = result.getCryptoObject().getCipher();
    // use the authenticated cipher
}
```

Asymmetric key pair:

```java
KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
kpg.initialize(new KeyGenParameterSpec.Builder(MY_KEY, KeyProperties.PURPOSE_SIGN)
        .setDigests(KeyProperties.DIGEST_SHA256)
        .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
        .setUserAuthenticationRequired(true)
        .build());
kpg.generateKeyPair();
```

## How to test

### 1. Find every authenticate() call and inspect argument one

```bash
jadx -d out/ target.apk
grep -rn "FingerprintManager" out/sources/ | grep -i "authenticate\|CryptoObject"
```

`authenticate(null, ...)` is the finding: the flow is purely event-bound. Report it directly.

### 2. Trace the CryptoObject back to key creation

Where a `CryptoObject` is present, follow the `Cipher`/`Signature` to the `KeyGenerator` or `KeyPairGenerator` call and confirm `setUserAuthenticationRequired(true)` is set on the `KeyGenParameterSpec`. A `CryptoObject` wrapping a key that was created without that flag is cosmetic — the key would decrypt with or without the fingerprint.

```bash
grep -rn "KeyGenParameterSpec\|setUserAuthenticationRequired\|setInvalidatedByBiometricEnrollment" out/sources/
```

### 3. Verify the prerequisite checks exist

```bash
grep -rn "isHardwareDetected\|hasEnrolledFingerprints\|isKeyguardSecure\|USE_FINGERPRINT" out/sources/
```

Missing `isKeyguardSecure()` in particular means the app may offer fingerprint auth on a device with no secure lock screen, which undermines the Keystore binding.

### 4. Check hardware backing at runtime

```java
SecretKeyFactory factory = SecretKeyFactory.getInstance(key.getAlgorithm(), "AndroidKeyStore");
KeyInfo info = (KeyInfo) factory.getKeySpec(key, KeyInfo.class);
info.isInsideSecureHardware();
info.isUserAuthenticationRequirementEnforcedBySecureHardware();
```

Not every device has hardware-backed key storage. Where the requirement is enforced only in software, an attacker with root can lift the key material.

### 5. Bypass attempt

```bash
frida -U -f com.target.app -l bypass.js
```

```javascript
Java.perform(function () {
  var FPM = Java.use('android.hardware.fingerprint.FingerprintManager');
  FPM.authenticate.overload(
    'android.hardware.fingerprint.FingerprintManager$CryptoObject',
    'android.os.CancellationSignal', 'int',
    'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback',
    'android.os.Handler'
  ).implementation = function (crypto, signal, flags, cb, handler) {
    console.log('[+] authenticate() called, CryptoObject = ' + crypto);
    if (crypto === null) {
      console.log('[!] event-bound: firing success callback directly');
      var Result = Java.use('android.hardware.fingerprint.FingerprintManager$AuthenticationResult');
      cb.onAuthenticationSucceeded(Result.$new(null, null, 0));
      return;
    }
    return this.authenticate(crypto, signal, flags, cb, handler);
  };
});
```

Log the `CryptoObject` value first — that single line often settles the finding before any bypass is attempted. If it is `null`, invoking the callback will move the app past the gate. If it is non-null and key-bound, the app will move past the UI but fail at the cryptographic operation.

### 6. Verify the server actually requires the proof

For the asymmetric design, confirm the backend rejects a request with a missing or invalid signature, and that the signed payload includes a server-issued nonce. An implementation that signs correctly but whose server does not verify is equivalent to no authentication at all — this is a common and high-impact finding.

## Impact

A `null`-`CryptoObject` fingerprint flow is bypassed with a few lines of Frida, or by patching a single conditional in a repackaged APK. If it guards a stored session token or local PII, the impact is account takeover on a device the attacker controls, and complete local data disclosure. On its own the vulnerability requires device access or a malicious app on a rooted device; it is usually reported Medium, rising to High when the guarded asset is a long-lived credential or a payment capability.

Presence of `FingerprintManager` in a current app is also a maintenance signal: the API has been deprecated since 2018 and receives no new platform hardening.

## Remediation

- Migrate to `androidx.biometric.BiometricPrompt`; do not write new `FingerprintManager` code.
- Always pass a `CryptoObject` backed by a Keystore key created with `setUserAuthenticationRequired(true)`.
- Prefer the asymmetric design with server-side signature verification and a server-issued nonce.
- Perform all five prerequisite checks and fail closed when any of them fails.
- Verify `isInsideSecureHardware()` and degrade the feature on devices without hardware-backed storage.

## References

- OWASP MASTG — [MASTG-KNOW-0002: FingerprintManager](https://mas.owasp.org/MASTG/knowledge/android/MASVS-AUTH/MASTG-KNOW-0002/) (CC BY-SA 4.0)
- [Android Developers Blog — Authenticating to remote servers using the Fingerprint API](https://android-developers.googleblog.com/2015/10/new-in-android-samples-authenticating.html)
- [Jetpack Biometric library](https://developer.android.com/jetpack/androidx/releases/biometric)
