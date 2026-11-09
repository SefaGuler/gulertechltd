---
title: "Cryptographic Keys Stored Outside of Platform Keystore (MASWE-0003)"
date: 2026-11-08 12:02:00 +0000
summary: "Why keys kept outside the Android Keystore or iOS Keychain/Secure Enclave are recoverable, how to find hardcoded keys, and how to store keys properly."
refs: [MASWE-0003, MASVS-STORAGE-1, MASVS-CRYPTO-2, CWE-321]
tags: [android, ios, masvs-storage, keystore, keychain, hardcoded-keys]
---

This note is part of our [MASVS-STORAGE-1 secure storage guide](/mobile/masvs-storage-1-secure-storage-guide/) and covers OWASP [MASWE-0003](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0003/): cryptographic keys that live somewhere other than the platform keystore. It sits between the notes on [unencrypted data in private storage](/mobile/maswe-0001-sensitive-data-unencrypted-private-storage/) and [secrets hardcoded in the app package](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/), and it is the weakness that quietly undoes most "we encrypt everything" claims: encryption is only as strong as the place the key is kept. You will find the platform mechanisms (Android Keystore, TEE and StrongBox, key attestation, wrapped import, iOS Keychain and Secure Enclave), the three OWASP tests with their demos, supplementary checks for the storage and import cases the OWASP tests do not cover, working Kotlin and Swift for the secure patterns, and severity guidance.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: Key Generation (MASTG-KNOW-0012)](#android-key-generation-mastg-know-0012)
  - [Android: Android Keystore, TEE and StrongBox (MASTG-KNOW-0043)](#android-android-keystore-tee-and-strongbox-mastg-know-0043)
  - [Android: Key Attestation (MASTG-KNOW-0044)](#android-key-attestation-mastg-know-0044)
  - [Android: Secure Key Import into Keystore (MASTG-KNOW-0045)](#android-secure-key-import-into-keystore-mastg-know-0045)
  - [Android: Cryptographic Key Storage options (MASTG-KNOW-0047)](#android-cryptographic-key-storage-options-mastg-know-0047)
  - [iOS: Keychain Services and Key Management (MASTG-KNOW-0057, MASTG-KNOW-0069)](#ios-keychain-services-and-key-management-mastg-know-0057-mastg-know-0069)
  - [iOS: Secure Enclave keys and CryptoKit (MASTG-KNOW-0066)](#ios-secure-enclave-keys-and-cryptokit-mastg-know-0066)
- [Tests](#tests)
  - [MASTG-TEST-0212 (Android)](#mastg-test-0212-use-of-hardcoded-cryptographic-keys-in-code-android)
  - [MASTG-TEST-0213 (iOS)](#mastg-test-0213-use-of-hardcoded-cryptographic-keys-in-code-ios)
  - [MASTG-TEST-0214 (iOS)](#mastg-test-0214-hardcoded-cryptographic-keys-in-files-ios)
  - [Supplementary checks](#supplementary-checks-not-owasp-tests)
- [Secure implementation](#secure-implementation)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

MASWE-0003 applies when an app keeps cryptographic key material outside the storage the platform provides for it. In practice that means one of three places:

- **In the package**: a byte array, hex string or Base64 string in Kotlin, Java, Swift or native code, or a `.pem`, `.p12`, `.der` or `.bks` file shipped in `assets/`, `res/raw/` or the `.app` bundle.
- **In ordinary app storage**: a key written to `SharedPreferences`, a DataStore file, `NSUserDefaults`, a plist, a SQLite table or a plain file — private to the app on a healthy device, but readable to anyone with root, a jailbreak, a backup, or code execution in the app's sandbox.
- **Transiently in app memory on its way into the keystore**: a key imported in plaintext, which means it existed in the clear in the app process (and usually on the network and in the backend) before it was protected.

The platform keystores exist precisely so that none of this is necessary. The [Android Keystore](https://developer.android.com/privacy-and-security/keystore) and the [iOS Keychain](https://developer.apple.com/documentation/security/keychain_services) (with the Secure Enclave behind it for supported key types) let an app generate a key, use it by reference, and never hold the raw bytes. On hardware-backed implementations the key material is confined to a Trusted Execution Environment (TEE), a secure element (StrongBox) or the Secure Enclave, and the OS kernel itself cannot read it.

The distinction you should keep in your head throughout the assessment:

| Key location | What an attacker with code execution in the app gets |
|---|---|
| Hardcoded in the package | The key itself, once, for every install, with no device access at all |
| App storage (prefs, files, DB) | The key itself, per device, given root/jailbreak/backup access |
| Software-backed keystore | Use of the key on the device; extraction is possible with OS compromise |
| Hardware-backed keystore (TEE/SE) | Use of the key on the device while the attacker's code runs; no extraction |
| Hardware-backed and auth-bound | Use only when the real user authenticates; no extraction |

Hardware backing prevents *extraction*, not *use*. That is why the strongest configurations combine a hardware keystore with user-authentication binding and server-side checks (attestation), and why a hardcoded key is categorically worse than everything else in the table: it removes the device from the attack entirely.

The weakness is mapped to MASVS-STORAGE-1 and MASVS-CRYPTO-2, and to CWE-321 (Use of Hard-coded Cryptographic Key), CWE-312 (Cleartext Storage of Sensitive Information) and CWE-318 (Cleartext Storage of Sensitive Information in Executable).

## Modes of Introduction

**Insecure storage locations.** The app generates or receives a key correctly but persists the raw bytes somewhere that is not designed to protect keys: a preferences XML file, a DataStore protobuf, `NSUserDefaults`, a JSON config in `Documents/`, a column in the app database, or — worst — shared or external storage. Developers often reason that "the sandbox protects it". The sandbox protects against other unprivileged apps; it does not protect against root, jailbreak, backup extraction, or forensic acquisition.

**Hardcoded cryptographic keys.** The key is a constant in code or a file in resources. This is common for "encrypt the local database", "sign requests to our API", "decrypt the config we ship", mutual TLS client certificates bundled as `.p12` with the password in code, and licence or entitlement verification using a symmetric key (which then also lets an attacker *create* valid licences). Moving the constant into native code, splitting it into pieces, XOR-ing it with another constant, or deriving it from stable values such as the package name or `ANDROID_ID` does not change the category; it raises the effort by minutes.

**Insecure key import.** The app (or its backend) produces a key outside the device and installs it into the keystore with a plaintext import — on Android `KeyStore.setEntry` with a `SecretKeyEntry` built from a `SecretKeySpec`, on iOS `SecKeyCreateWithData` followed by `SecItemAdd`. The resulting key is protected *from that moment on*, but the raw material passed through the network, the app's heap and possibly logs. Android 9 and later provide wrapped import (`WrappedKeyEntry`) so that an externally generated key is only ever decrypted inside secure hardware.

## Impact

- **Compromise of sensitive data.** With the key, an attacker decrypts whatever it protects: local databases, cached documents, tokens, backups, or ciphertext intercepted from the network. With a hardcoded key this applies to every install at once.
- **Authentication or authorisation bypass.** Keys used to sign requests, generate HMACs, or derive session material let an attacker produce valid values and impersonate the app or its users.
- **Bypass of protection mechanisms.** A key that signs or verifies licences, entitlements, feature flags or integrity tokens lets an attacker forge them and unlock functionality the app is supposed to restrict.
- **Financial loss.** A key that authenticates to a paid or metered backend (cloud APIs, SMS gateways, mapping, AI inference) can be abused to run up charges on the owner's account.

## Mitigations

- **Generate keys on the device, inside the keystore.** Use `KeyGenerator`/`KeyPairGenerator` with the `AndroidKeyStore` provider, and `SecKeyCreateRandomKey` or CryptoKit with storage in the Keychain on iOS. The app should hold an alias or reference, never the bytes.
- **Use the strongest hardware available for the use case.** Request StrongBox (`setIsStrongBoxBacked(true)`) on Android where it is present and supports the algorithm, and use the Secure Enclave (`kSecAttrTokenIDSecureEnclave`, `SecureEnclave.P256`) on iOS for P-256 keys. These resist physical and side-channel attacks that a TEE may not.
- **Use a server-side key management system** (AWS KMS or Secrets Manager, Azure Key Vault, Google Cloud KMS or Secret Manager) when the key must be shared or must not live on the device at all. The app authenticates to your backend; the backend talks to the KMS. Where the key really has to reach the device, deliver it wrapped to an attested device key rather than in plaintext.
- **Encrypt and wrap keys you cannot keep in the keystore.** Use envelope encryption: a data encryption key (DEK) protects the data, a key encryption key (KEK) in the keystore protects the DEK, and only the wrapped DEK is persisted (NIST SP 800-175B Rev. 1, section 5.3.5).
- **Follow standard key management practice**: one key per purpose, defined cryptoperiods and rotation, and integrity and confidentiality protection for keys in storage (NIST SP 800-57 Part 1 Rev. 5, section 6.2.2).

## Knowledge

MASWE-0003's only linked Knowledge page is MASTG-KNOW-0012 (via MASTG-TEST-0212). Because the weakness is fundamentally about keystores, the sections after it cover the related MASTG Knowledge pages that exist for the Android Keystore and the iOS Keychain. Each of those sections is marked **supplementary**; where we add material that is not on the cited OWASP page, we say so.

### Android: Key Generation (MASTG-KNOW-0012)

Source: [MASTG-KNOW-0012](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0012/).

Since Android 6.0 (API 23), keys for the `AndroidKeyStore` provider are described by a `KeyGenParameterSpec`. The spec is not advisory: it becomes the key's **authorisation list**, enforced by the keystore (and by secure hardware where present), and it cannot be changed after generation. A key created only for `PURPOSE_ENCRYPT | PURPOSE_DECRYPT` with `BLOCK_MODE_GCM` cannot be used to sign, or used with CBC; trying throws an exception at `Cipher.init`. Setting the provider to `"AndroidKeyStore"` in `KeyGenerator.getInstance` is what makes the key a keystore key. Using `KeyGenerator.getInstance("AES")` without the provider gives you a perfectly random key whose bytes live on the Java heap — and which the app will then have to store somewhere, which is how this weakness usually starts.

The OWASP page shows a CBC/PKCS#7 example and then recommends GCM. Use GCM: it is authenticated, needs no padding, and is what you should expect to see in a modern app. The keystore generates the IV for you when `setRandomizedEncryptionRequired(true)` (the default) is in force; your code reads it with `cipher.iv` after `init` and stores it alongside the ciphertext. If code passes its own IV on encryption with randomised encryption required, the keystore rejects it — a useful thing to know when an app sets `setRandomizedEncryptionRequired(false)`, because that usually means a fixed or derived IV, which is a separate finding.

Points from the source that need correcting or updating when you read it:

- The OWASP snippet `AndroidKeyStore.getInstance("AndroidKeyStore")` should be `KeyStore.getInstance("AndroidKeyStore")`, and the keystore must be loaded with `load(null)` before `getKey`.
- `KeyPairGeneratorSpec` (the pre-API-23 way of creating RSA keys) is deprecated; any app with `minSdkVersion` 23 or above should use `KeyGenParameterSpec` for asymmetric keys too.
- EC keys in `AndroidKeyStore` cannot encrypt or decrypt; they sign, and from Android 12 (API 31) they can also do ECDH key agreement (`PURPOSE_AGREE_KEY`).
- For password-based keys, `PBKDF2WithHmacSHA256` is available from API 26. The 10,000 iterations in the OWASP example are well below current guidance: the OWASP Password Storage Cheat Sheet recommends 600,000 iterations for PBKDF2-HMAC-SHA256. The sample also calls `toCharArray()` on a parameter that is already a `char[]`. A PBKDF2-derived key is acceptable when the user supplies the secret each time; the salt can be stored in app storage, but ideally excluded from backup or encrypted under a keystore key.

The OWASP page's closing note matters most for this weakness: **moving a key into native code does not hide it.** A `.so` file is as extractable as a `.dex`, constants show up in `strings` or a disassembler, and even a key reconstructed at runtime can be dumped from memory with Frida or r2frida (`r2 frida://usb//<package>` then search memory). The Android 7.0 restriction the page mentions (apps may no longer link against private platform libraries) is unrelated to key hiding; it simply means native code cannot reach undocumented system internals.

### Android: Android Keystore, TEE and StrongBox (MASTG-KNOW-0043)

Supplementary. Source: [MASTG-KNOW-0043](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0043/), extended with the current Android documentation.

**What it is.** The Android Keystore system lets an app create and use keys without the key material entering the app process. The app talks to the `keystore2` system service (Android 12+; `keystore` before that) through the JCA `AndroidKeyStore` provider. The service forwards operations to a **KeyMint** (Android 12+) or **Keymaster** (Android 6–11) implementation.

**Security levels.**

| Level | Where the key lives | Typical hardware | Resists |
|---|---|---|---|
| Software | Encrypted blob handled by the OS | Emulators, very old or low-end devices | Other unprivileged apps only |
| TEE (`TrustedEnvironment`) | Isolated secure world on the application processor | Arm TrustZone OSes such as Trusty or QSEE | Root and kernel compromise of the normal-world OS |
| StrongBox | Separate secure element with its own CPU, storage and RNG | Titan M/M2 and other discrete secure elements | The above plus many physical and side-channel attacks |

StrongBox arrived with Android 9 (API 28). It is slower and supports a narrower set of algorithms (RSA 2048, AES 128/256, EC P-256, HMAC-SHA256 and 3DES), so you request it explicitly with `setIsStrongBoxBacked(true)` and handle `StrongBoxUnavailableException` (a `ProviderException`) by falling back. Check availability with `PackageManager.FEATURE_STRONGBOX_KEYSTORE`.

**Verifying the level at runtime.** `KeyInfo` (obtained through `SecretKeyFactory` or `KeyFactory` for the `AndroidKeyStore` provider) reports where a key lives. `KeyInfo.isInsideSecureHardware()` is deprecated from API 31; use `KeyInfo.getSecurityLevel()`, which returns `SECURITY_LEVEL_SOFTWARE`, `SECURITY_LEVEL_TRUSTED_ENVIRONMENT`, `SECURITY_LEVEL_STRONGBOX`, or one of the `UNKNOWN` values. The OWASP page notes that on some devices secret (AES/HMAC) keys were reported as software-backed even though private keys were in hardware, so check each key type you rely on rather than assuming. `KeyInfo` is self-reported by the device; for a claim you can trust from the server side, use attestation (next section).

**Authorisations that matter for storage.**

- `setUserAuthenticationRequired(true)` — the key is unusable until the user authenticates. Combine with `setUserAuthenticationParameters(timeout, type)` (API 30+), where a timeout of `0` means per-operation authentication via `BiometricPrompt.CryptoObject`, and `type` is `AUTH_BIOMETRIC_STRONG` and/or `AUTH_DEVICE_CREDENTIAL`. `setUserAuthenticationValidityDurationSeconds` is the deprecated predecessor. A key bound to authentication is permanently invalidated if the user removes the secure lock screen.
- `setInvalidatedByBiometricEnrollment(true)` (default for auth-bound keys, API 24+) destroys the key when a new biometric is enrolled.
- `setUnlockedDeviceRequired(true)` (API 28+) refuses use of the key while the device is locked, so a process left running on a locked, stolen phone cannot decrypt.
- `setIsStrongBoxBacked(true)` (API 28+) as above.
- `setAttestationChallenge(byte[])` (API 24+, asymmetric keys) produces an attestation certificate chain.

**Where keys live on disk (for testers).** On a rooted device, keystore data sits under `/data/misc/keystore/`. Before Android 12 you will see per-key blob files named after the app UID and alias (for example `10123_USRPKEY_myalias`); from Android 12 the `keystore2` service keeps a SQLite database (`persistent.sqlite`). For hardware-backed keys these blobs are encrypted by and bound to the secure hardware of that specific device: copying them to another device or decrypting them offline does not work. This is the property you are paying for. It does not stop an attacker who runs code as the app (via Frida, a repackaged APK or root) from *using* the key on the device, which is why authentication binding and server-side checks matter.

### Android: Key Attestation (MASTG-KNOW-0044)

Supplementary. Source: [MASTG-KNOW-0044](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0044/).

Key attestation lets a **server** verify that a key pair was generated in secure hardware and with the authorisations it expects. The device returns an X.509 certificate chain for the key; the leaf contains the Android attestation extension (OID `1.3.6.1.4.1.11129.2.1.17`), which records the challenge, the attestation and KeyMint security levels (`Software`, `TrustedEnvironment`, `StrongBox`), the key's authorisation list, and a root-of-trust block with the verified boot key, bootloader lock state and verified boot state. The chain ends at a Google hardware attestation root for devices certified for Google services; any other root means Google makes no claim about the hardware. Attestation has been mandatory for devices that ship with Google services since Android 8.0.

The secure implementation, as OWASP describes it, lives on the server:

1. The server generates a random challenge with a CSPRNG and sends it to the app.
2. The app generates the key with `setAttestationChallenge(challenge)` and returns `KeyStore.getCertificateChain(alias)`.
3. The server validates the chain to a pinned Google root, checks every certificate against Google's revocation status list (`https://android.googleapis.com/attestation/status`), matches the challenge, and checks the security level, the key's purposes and authentication requirements, and the root-of-trust fields (locked bootloader, `Verified` boot state).

What to look for in an assessment: attestation performed only on the client (patchable); a static or reused challenge (replay); a server that accepts `Software` security level for a flow that requires hardware; a server that does not check revocation or the root; and a server that never actually uses the attested key afterwards. The OWASP page also illustrates a WebAuthn-style `android-key` attestation statement (`fmt`, `authData`, `attStmt` with `alg`, `sig`, `x5c`), which is the same chain packaged for FIDO2.

> **Note:** A failed attestation means you cannot prove the key is in secure hardware. It does not prove the key is compromised; decide in policy what the backend does in that case (deny, step up, or allow with reduced privileges).

### Android: Secure Key Import into Keystore (MASTG-KNOW-0045)

Supplementary. Source: [MASTG-KNOW-0045](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0045/), with the flow detail from the `WrappedKeyEntry` documentation and the AOSP CTS import tests.

Sometimes a key must originate off the device — a key escrowed by the backend, shared between a user's devices, or provisioned by an enterprise. Android 9 (API 28) supports importing it so that it is only ever decrypted inside secure hardware:

1. The app generates an RSA **wrapping key** in the keystore with `PURPOSE_WRAP_KEY` (OAEP padding, SHA-256 digest), ideally with an attestation challenge so the server can confirm it is hardware-backed.
2. The server verifies the attestation, then generates an ephemeral AES-256 transport key, encrypts the secret key with AES-GCM under the transport key, and encrypts the transport key with RSA-OAEP under the wrapping public key.
3. The server packages everything as a DER-encoded `SecureKeyWrapper`:

```text
KeyDescription ::= SEQUENCE {
    keyFormat         INTEGER,
    authorizationList AuthorizationList
}

SecureKeyWrapper ::= SEQUENCE {
    wrapperFormatVersion  INTEGER,
    encryptedTransportKey OCTET_STRING,
    initializationVector  OCTET_STRING,
    keyDescription        KeyDescription,
    secureKey             OCTET_STRING,
    tag                   OCTET_STRING
}
```

4. The app passes the blob to the keystore as a `WrappedKeyEntry` naming the wrapping key alias. The secure hardware unwraps it internally; the app never sees the plaintext.

The `authorizationList` inside the wrapper (algorithm, key size, block modes, padding, digests, purposes, authentication requirements) defines what the imported key can do, so review what the server puts in it with the same care as a local `KeyGenParameterSpec`. The contrast you are testing for is a plaintext import: `KeyStore.setEntry(alias, KeyStore.SecretKeyEntry(SecretKeySpec(bytes, "AES")), KeyProtection.Builder(...).build())`, where `bytes` came over the network. The key ends up in the keystore, but MASWE-0003's "insecure key import" mode still applies.

### Android: Cryptographic Key Storage options (MASTG-KNOW-0047)

Supplementary. Source: [MASTG-KNOW-0047](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0047/).

OWASP ranks the options from most to least secure. In condensed form:

1. Key in the hardware-backed Android Keystore.
2. Keys held on a server and released after strong authentication.
3. Master key on the server, used to wrap other keys stored on the device.
4. Key derived each time from a strong user passphrase with a proper salt and KDF.
5. Key in the software-backed Android Keystore.
6. Master key in the software keystore wrapping other keys stored in `SharedPreferences`.
7. **Not recommended:** keys in `SharedPreferences`; hardcoded keys; a predictable derivation from stable attributes; keys in public storage such as `/sdcard/`.

The page also covers envelope encryption — DEKs encrypted with a KEK held in the keystore, with the wrapped DEKs stored in preferences or files — which is the pattern we implement in [Secure implementation](#secure-implementation). It cites `EncryptedSharedPreferences` from Jetpack Security as an example of that pattern.

> **Warning:** The Jetpack Security crypto library (`androidx.security:security-crypto`, including `EncryptedFile`, `EncryptedSharedPreferences` and `MasterKey`) is deprecated by Google. Existing uses still provide a Keystore-wrapped key, so do not report them as MASWE-0003 on that basis alone, but do not recommend the library for new code. Use the Android Keystore directly, as below, or a maintained library such as Tink with a Keystore-held master key.

Two further points from the page worth carrying into a report: hardcoded keys mean every install shares one key, so one reverse-engineering effort decrypts data from every device; and key material in garbage-collected memory is hard to wipe, so keep raw keys in `ByteArray`/`char[]` and zero them after use rather than in `String`.

### iOS: Keychain Services and Key Management (MASTG-KNOW-0057, MASTG-KNOW-0069)

Supplementary. Sources: [MASTG-KNOW-0057 Keychain Services](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-AUTH/MASTG-KNOW-0057/), [MASTG-KNOW-0069 Key Management](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0069/) and [MASTG-KNOW-0126 Keychain Access Groups](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0126/); the on-disk and accessibility detail is from Apple's Platform Security Guide.

**What it is.** The iOS Keychain is an encrypted SQLite database (`/private/var/Keychains/keychain-2.db`) managed by the `securityd` daemon. Each item is encrypted with its own key, which is wrapped with a class key tied to the item's accessibility; class keys are protected by the Secure Enclave and, for most classes, by the user's passcode. Apps reach it through `SecItemAdd`, `SecItemCopyMatching`, `SecItemUpdate` and `SecItemDelete`, and only see items in their own keychain access groups (`keychain-access-groups` entitlement, prefixed with the Team ID; see KNOW-0126).

**Accessibility (`kSecAttrAccessible`)** — choose the narrowest one that works:

| Value | Available | Leaves the device in backups/migration |
|---|---|---|
| `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` | Unlocked, and only while a passcode is set | No |
| `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` | Unlocked | No |
| `kSecAttrAccessibleWhenUnlocked` (default) | Unlocked | Yes |
| `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` | After first unlock until reboot | No |
| `kSecAttrAccessibleAfterFirstUnlock` | After first unlock until reboot | Yes |

`kSecAttrAccessibleAlways` and `kSecAttrAccessibleAlwaysThisDeviceOnly` are deprecated since iOS 12; finding them on a key is a finding. For keys, prefer a `ThisDeviceOnly` class so the item cannot be restored to another device, and avoid `kSecAttrSynchronizable` (iCloud Keychain) unless syncing keys between the user's devices is a deliberate design decision.

**Access control (`kSecAttrAccessControl`)**, created with `SecAccessControlCreateWithFlags`, adds user-presence requirements on top of accessibility (and replaces `kSecAttrAccessible` in the query — the two are mutually exclusive). Useful flags: `.userPresence` (biometry or passcode), `.biometryAny`, `.biometryCurrentSet` (invalidated when enrolment changes), `.devicePasscode`, `.privateKeyUsage` (required for Secure Enclave private keys), `.applicationPassword`, and the `.and`/`.or` combinators. The older `.touchIDAny`/`.touchIDCurrentSet` names are deprecated aliases. The OWASP KNOW-0057 page notes that iOS has no "valid for N seconds after auth" setting for items: without an access-control flag, an item is available whenever its accessibility class allows.

**Storing keys.** Key-type items use `kSecClassKey` (`SecKey` objects: RSA and EC); CryptoKit `SymmetricKey` and Curve25519 keys are normally stored as `kSecClassGenericPassword` data, which is the pattern in Apple's "Storing CryptoKit Keys in the Keychain" sample. KNOW-0069 makes the same ranking as Android: derive the key from a password (PBKDF2 via `CCKeyDerivationPBKDF`) if you can avoid storing it at all; otherwise use the Keychain with an accessibility class other than "always"; never `NSUserDefaults`, plists, Core Data or Realm for key material, even with `NSFileProtectionComplete`. It also repeats two rules worth enforcing in review: one key per purpose, and encrypt/verify with the public key, decrypt/sign with the private key.

**What testers should know.** Keychain items survive app deletion, so stale keys from an old install may be picked up by a new one. On a jailbroken device, `objection -g <bundle-id> explore` followed by `ios keychain dump` lists the app's items with their accessibility and access-control settings; generic-password items show their data. Keys protected with `.userPresence` or biometry prompt the user when read, and Secure Enclave keys never reveal key material at all.

### iOS: Secure Enclave keys and CryptoKit (MASTG-KNOW-0066)

Supplementary. Source: [MASTG-KNOW-0066 CryptoKit](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0066/), which notes that CryptoKit "can utilize the hardware based key manager from the Secure Enclave"; the Secure Enclave detail below is supplementary and drawn from Apple's documentation ("Protecting keys with the Secure Enclave").

KNOW-0069 summarises the two Keychain models correctly: a key is either *protected by* a key in the Secure Enclave (every normal Keychain item) or *lives in* the Secure Enclave. The second model is available only for **NIST P-256 private keys**. Such a key is generated inside the Secure Enclave and can never be imported or exported; the app receives a reference, and operations (ECDSA signing, ECDH key agreement, and ECIES decryption via `SecKeyCreateDecryptedData`) run inside the Enclave.

Two APIs give you Secure Enclave keys:

- **Security framework**: `SecKeyCreateRandomKey` with `kSecAttrKeyType = kSecAttrKeyTypeECSECPrimeRandom`, `kSecAttrKeySizeInBits = 256`, `kSecAttrTokenID = kSecAttrTokenIDSecureEnclave`, and an access-control object containing `.privateKeyUsage`. With `kSecAttrIsPermanent = true` and a `kSecAttrApplicationTag` in `kSecPrivateKeyAttrs`, the reference is stored in the Keychain and retrieved later with `SecItemCopyMatching`.
- **CryptoKit**: `SecureEnclave.P256.Signing.PrivateKey` and `SecureEnclave.P256.KeyAgreement.PrivateKey`, created with an optional `SecAccessControl`. Their `dataRepresentation` is an opaque blob encrypted by this device's Secure Enclave; you persist it (in the Keychain) and recreate the key with `init(dataRepresentation:)`. The blob is useless on any other device. Check `SecureEnclave.isAvailable` first; the Simulator does not have one.

For symmetric encryption, which the Secure Enclave does not do directly for apps, wrap a CryptoKit `SymmetricKey` (the DEK) with ECIES under a Secure Enclave key (the KEK). The pattern is in [Secure implementation](#secure-implementation).

Static signals worth noting during review: `kSecAttrTokenIDSecureEnclave`, `SecureEnclave.P256`, `.privateKeyUsage` mean the app is using the Enclave; `SecKeyCreateWithData`, `P256.Signing.PrivateKey(rawRepresentation:)`, `SymmetricKey(data:)` with constant input, and `CCCrypt` with a constant key mean it is not — which is exactly what the next two tests hunt for.

## Tests

OWASP maps three tests to MASWE-0003, all static and all aimed at the hardcoded-key mode. The insecure-storage and insecure-import modes have no beta tests yet, so we add [supplementary checks](#supplementary-checks-not-owasp-tests) after them that you should run on every assessment.

### MASTG-TEST-0212: Use of Hardcoded Cryptographic Keys in Code (Android)

Source: [MASTG-TEST-0212](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0212/). Type: static (code). Related knowledge: MASTG-KNOW-0012.

#### Overview

The test looks for keys that are built from constant data and then used for cryptography. On Android the main entry point is `javax.crypto.spec.SecretKeySpec`, which turns any `byte[]` into a `SecretKey` that `Cipher`, `Mac` and friends will accept. A key made this way is by definition outside the keystore; the only question is where its bytes came from. If they came from a literal — a byte array, `"string".toByteArray()`, a hex or Base64 constant, a resource, a native function returning a constant — the key is hardcoded. Related sinks worth including in the same sweep: `IvParameterSpec` (a fixed IV is a related crypto finding), `PBEKeySpec` with a constant password, `KeyStore.load(stream, "literal".toCharArray())` for bundled BKS/PKCS#12 keystores, and `KeyFactory.generatePrivate(PKCS8EncodedKeySpec(constant))` for hardcoded private keys.

#### Prerequisites

- The APK (or the split APKs) of the build under test: `adb shell pm path <package>` then `adb pull` each path.
- `jadx` for decompilation (this is the OWASP "reverse engineer the app" technique, MASTG-TECH-0013), `apktool` for resources, and `semgrep` for the pattern search (MASTG-TECH-0014 with MASTG-TOOL-0110).
- Optional for confirmation: a rooted device or emulator with `frida-server`, and `radare2` for native libraries.

#### Steps

1. **Decompile.**

   ```bash
   jadx -d out/ app.apk
   apktool d app.apk -o res_out/
   ```

2. **Run the OWASP semgrep rule** against the decompiled Java (jadx output is Java even when the source was Kotlin, which is why the rule targets Java):

   ```yaml
   rules:
     - id: mastg-android-hardcoded-crypto-keys-usage
       severity: WARNING
       languages:
         - java
       metadata:
         summary: This rule looks for hardcoded keys in use.
       message: "[MASVS-CRYPTO-1] Hardcoded cryptographic keys found in use."
       pattern-either:
         - pattern: SecretKeySpec $_ = new SecretKeySpec($KEY, $ALGO);
         - pattern: |-
             byte[] $KEY = {...};
             ...
             new SecretKeySpec($KEY, $ALGO);
   ```

   ```bash
   semgrep -c mastg-android-hardcoded-crypto-keys-usage.yml out/sources/
   ```

   Understand what this rule does: the first pattern matches **every** `SecretKeySpec` assignment, constant or not, and the second matches the case where a byte-array literal and its use are in the same method. It is a candidate finder; you triage every hit.

3. **Widen the sweep** with patterns the rule does not cover (string-derived and Base64 keys, bundled keystores, private keys):

   ```yaml
   rules:
     - id: gt-android-key-from-literal
       languages: [java]
       severity: WARNING
       message: Key or keystore password built from a literal
       pattern-either:
         - pattern: new SecretKeySpec("...".getBytes(...), $ALGO)
         - pattern: new SecretKeySpec(Base64.decode("...", $FLAGS), $ALGO)
         - pattern: new PBEKeySpec("...".toCharArray(), ...)
         - pattern: $KS.load($IN, "...".toCharArray())
         - pattern: new PKCS8EncodedKeySpec(Base64.decode("...", $FLAGS))
   ```

   ```bash
   grep -rnE 'SecretKeySpec|IvParameterSpec|PBEKeySpec|PKCS8EncodedKeySpec|KeyStore\.getInstance\("(BKS|PKCS12|JKS)"\)' out/sources/ \
     | grep -vE '^out/sources/(androidx|kotlin|com/google)/'
   ```

4. **Check native libraries.** Keys moved to C/C++ are a common "mitigation":

   ```bash
   unzip -o app.apk 'lib/*' -d native/
   for so in native/lib/arm64-v8a/*.so; do
     echo "== $so"
     strings -a -n 16 "$so" | grep -E '^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{64}$|^[A-Za-z0-9+/]{22}==$|^[A-Za-z0-9+/]{43}=$'
   done
   ```

   The regexes target 128- and 256-bit keys in hex and Base64. For a hit, open the library in radare2 (`r2 -A libfoo.so`, then `iz~<string>` and `axt @ <addr>`) to see which JNI function returns it.

5. **Confirm at runtime (recommended).** Static analysis misses keys assembled at runtime or returned from native code. Hook the sink instead and let the app tell you:

   ```javascript
   // hook-secretkeyspec.js
   Java.perform(function () {
     const SKS = Java.use('javax.crypto.spec.SecretKeySpec');
     const Log = Java.use('android.util.Log');
     const Exc = Java.use('java.lang.Exception');
     function hex(a) {
       return Array.from(a, function (b) { return ('0' + (b & 0xff).toString(16)).slice(-2); }).join('');
     }
     SKS.$init.overload('[B', 'java.lang.String').implementation = function (key, algo) {
       console.log('[SecretKeySpec] ' + algo + ' ' + key.length * 8 + '-bit key=' + hex(key));
       console.log(Log.getStackTraceString(Exc.$new()));
       return this.$init(key, algo);
     };
   });
   ```

   ```bash
   frida -U -f com.example.app -l hook-secretkeyspec.js
   ```

   Restart the app twice (clear data in between with `adb shell pm clear com.example.app`). A key that is identical across fresh installs, or identical on two devices, is hardcoded or deterministically derived; a key that changes is generated and you move on to *where it is stored*.

#### Observation

Record, for each candidate: the class and method (from jadx), the line in the decompiled source, the literal or its location (Java constant, resource ID, native symbol), the algorithm and mode it is used with, and what it protects (follow the `Cipher`/`Mac` output to its sink — a file, preference, network request). If you used Frida, keep the hex key and stack trace from two runs.

#### Evaluation

The test **fails** if a key derived from constant data is used for a security-relevant purpose: encrypting or decrypting stored or transmitted data, computing a MAC or signature that anything relies on, or authenticating to a service. That includes keys split, XOR-ed or encoded in the package, keys in native code, and keys derived from stable public values (package name, `ANDROID_ID`, build fingerprint).

It **passes** for that candidate if the bytes come from a runtime source that is itself acceptable: a keystore-wrapped DEK being unwrapped, a PBKDF2/Argon2 derivation from user input with a random salt, an ECDH or KEM shared secret. These all look like `new SecretKeySpec(bytes, "AES")` in decompiled code — triage, do not report on the rule hit alone.

Common false positives: test or sample code in third-party SDKs that is never called; constants used as non-secret identifiers (HKDF `info` strings, protocol labels); and public keys or certificates (a hardcoded public key is not a secret; a hardcoded *private* key is).

#### Demo

From [MASTG-DEMO-0017](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0017/). The vulnerable Kotlin:

```kotlin
// Bad: hardcoded 128-bit AES key from bytes
val keyBytes = byteArrayOf(0x6C, 0x61, 0x6B, 0x64, 0x73, 0x6C, 0x6A, 0x6B,
                           0x61, 0x6C, 0x6B, 0x6A, 0x6C, 0x6B, 0x6C, 0x73)
val cipher = Cipher.getInstance("AES/GCM/NoPadding")
val secretKey = SecretKeySpec(keyBytes, "AES")
cipher.init(Cipher.ENCRYPT_MODE, secretKey)

// Bad: key derived from a string literal
val badSecretKeySpec = SecretKeySpec("my secret here".toByteArray(), "AES")
```

After compilation and jadx, the same method reads:

```java
byte[] keyBytes = {108, 97, 107, 100, 115, 108, 106, 107, 97, 108, 107, 106, 108, 107, 108, 115};
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
cipher.init(1, secretKey);
byte[] bytes = "my secret here".getBytes(Charsets.UTF_8);
SecretKeySpec badSecretKeySpec = new SecretKeySpec(bytes, "AES");
```

Running `semgrep -c ../../../../rules/mastg-android-hardcoded-crypto-keys-usage.yml ./MastgTest_reversed.java` produces three findings:

```text
┌─────────────────┐
│ 3 Code Findings │
└─────────────────┘

    MastgTest_reversed.java
    ❯❱ rules.mastg-android-hardcoded-crypto-keys-usage
          [MASVS-CRYPTO-1] Hardcoded cryptographic keys found in use.

           24┆ byte[] keyBytes = {108, 97, 107, 100, 115, 108, 106, 107, 97, 108, 107, 106, 108, 107, 108,
               115};
           25┆ Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
           26┆ SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
            ⋮┆----------------------------------------
           26┆ SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
            ⋮┆----------------------------------------
           30┆ SecretKeySpec badSecretKeySpec = new SecretKeySpec(bytes, "AES");
```

The test fails: line 24 is a 16-byte key literal (the ASCII string `lakdsljkalkjlkls`), used on line 26; line 30 is a key built from a string literal. Note that line 26 is reported twice (once by each pattern) and that line 30 is caught only by the catch-all first pattern — jadx split the string conversion into a separate variable, so a stricter pattern would have missed it. That is the practical reason to keep a broad candidate rule and triage by hand. Also note the demo uses AES-GCM with a fixed key and no explicit IV; the cipher choice is sound, which shows why "uses GCM" is not evidence of safe key handling.

### MASTG-TEST-0213: Use of Hardcoded Cryptographic Keys in Code (iOS)

Source: [MASTG-TEST-0213](https://mas.owasp.org/MASTG/tests/ios/MASVS-CRYPTO/MASTG-TEST-0213/). Type: static (code), manual review.

#### Overview

On iOS you look for calls to APIs that accept **raw key bytes** and then trace where those bytes come from:

- **Security framework**: `SecKeyCreateWithData(data, attributes, &error)` builds a `SecKey` (RSA or EC, public or private) from external representation bytes.
- **CommonCrypto**: `CCCrypt` (and `CCCryptorCreate`, `CCHmac`) takes a `key` pointer and `keyLength`.
- **CryptoKit**: `SymmetricKey(data:)`, `P256.Signing.PrivateKey(rawRepresentation:)` and its `x963Representation:`, `derRepresentation:` and `pemRepresentation:` siblings, and the same for P-384, P-521 and Curve25519.

Hardcoded keys appear as `[UInt8]` literals, `Data` built from them, Base64 strings decoded with `Data(base64Encoded:)`, or hex strings converted at runtime.

#### Prerequisites

- A **decrypted** IPA. App Store binaries are FairPlay-encrypted; check with `otool -l Payload/App.app/App | grep -A4 LC_ENCRYPTION_INFO` — `cryptid 1` means you need to decrypt it on a jailbroken device first (for example with a frida-based dumper). Development, ad hoc and enterprise builds supplied by the client are usually not encrypted.
- radare2 (MASTG-TOOL-0073); macOS `nm`, `otool`, `xcrun swift-demangle`.

#### Steps

1. **Extract the binary** (MASTG-TECH-0058, "Exploring the App Package"):

   ```bash
   unzip -q App.ipa -d ipa/
   BIN=ipa/Payload/App.app/App      # the executable has the bundle name without .app
   ls ipa/Payload/App.app/Frameworks/  # embedded frameworks need the same treatment
   ```

2. **Quick import check** — which raw-key APIs the binary links against:

   ```bash
   nm -u "$BIN" | grep -E 'SecKeyCreateWithData|CCCrypt|CCHmac|CCKeyDerivationPBKDF'
   nm -u "$BIN" | xcrun swift-demangle | grep -E 'CryptoKit\.(SymmetricKey|P256|P384|P521|Curve25519)' | sort -u
   ```

3. **Locate call sites in radare2** (MASTG-TECH-0066, static analysis on iOS):

   ```text
   r2 -A ipa/Payload/App.app/App
   [0x...]> afl~SecKeyCreateWithData       # import stub address
   [0x...]> axt @ sym.imp.SecKeyCreateWithData
   [0x...]> afl~rawRepresentation
   [0x...]> afl~CCCrypt
   [0x...]> pdf @ <calling function>
   ```

4. **Follow the key argument back to data.** On arm64 the first argument is in `x0` (for `SecKeyCreateWithData`, the `CFData`) and for `CCCrypt` the key pointer is the fourth argument (`x3`) with its length in `x4`. In the disassembly look for `adrp`/`add` pairs that point into `__DATA` or `__TEXT,__const`, then dump that region with `px <len> @ <addr>`. A DER RSA private key starts `30 82 xx xx 02 01 00`; a P-256 raw private key is 32 bytes with no header.

5. **Search for encoded keys directly.**

   ```text
   [0x...]> iz~BEGIN
   [0x...]> /x 308202
   [0x...]> izz~PRIVATE
   ```

   Swift stores strings of up to 15 UTF-8 bytes inline in the `String` value itself and materialises them with immediate `mov`/`movk` instructions, so a short key such as `"my secret here"` will not appear in `strings` output at all. Short literals must be found through the call site, not the string table.

6. **Confirm at runtime (recommended)** on a jailbroken device, which also catches keys assembled at runtime:

   ```javascript
   // hook-ios-rawkeys.js (Frida 17 syntax)
   const cc = Process.getModuleByName('libcommonCrypto.dylib');
   Interceptor.attach(cc.getExportByName('CCCrypt'), {
     onEnter(args) {
       const len = args[4].toInt32();
       console.log('CCCrypt op=' + args[0].toInt32() + ' alg=' + args[1].toInt32() + ' keyLen=' + len);
       console.log(hexdump(args[3], { length: len }));
     }
   });
   const sec = Process.getModuleByName('Security');
   Interceptor.attach(sec.getExportByName('SecKeyCreateWithData'), {
     onEnter(args) {
       const d = new ObjC.Object(args[0]);
       console.log('SecKeyCreateWithData len=' + d.length());
       console.log(hexdump(d.bytes(), { length: Math.min(d.length(), 64) }));
     }
   });
   ```

   ```bash
   frida -U -f com.example.app -l hook-ios-rawkeys.js
   ```

   CryptoKit does not route through CommonCrypto, so for CryptoKit keys rely on the static trace (or hook the Swift initialisers by their mangled names, which you can list with `nm "$BIN" | xcrun swift-demangle | grep rawRepresentation`).

#### Observation

For each call site: the function and address, the API and algorithm, the location and bytes of the key (address in `__DATA`/`__const`, or the string), its decoded form (for DER, `openssl asn1parse -inform DER -in key.der`), and what the key does (sign requests, decrypt a bundled resource, encrypt local data).

#### Evaluation

The test **fails** if a raw-key API is fed constant key material from the binary for a security-relevant purpose. Inspect each hit by reviewing the disassembly (MASTG-TECH-0076) to confirm that the value really is a key and really is used — configuration constants, test vectors and public keys are frequent false positives.

It **passes** for a call site when the bytes come from a Keychain lookup, a Secure Enclave `dataRepresentation`, a key agreement, a KDF over user input, or a server response that is itself properly protected (and see the supplementary import check below for the last case).

#### Demo

Two OWASP demos cover this test.

**[MASTG-DEMO-0013](https://mas.owasp.org/MASTG/demos/ios/MASVS-CRYPTO/MASTG-DEMO-0013/): hardcoded RSA private key in `SecKeyCreateWithData`.**

```swift
// Hardcoded RSA private key in DER (PKCS#1) form — truncated
let privateKeyBytes: [UInt8] = [
    0x30, 0x82, 0x02, 0x5b, 0x02, 0x01, 0x00, 0x02, 0x81, 0x81, 0x00, 0xbd, 0xf6, 0x89, 0x8f, 0xbd,
    // ...
]
let keyAttributes: [String: Any] = [
    kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
    kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
    kSecAttrKeySizeInBits as String: 1024,
    kSecReturnPersistentRef as String: true
]
var error: Unmanaged<CFError>?
let privateKey = SecKeyCreateWithData(Data(privateKeyBytes) as CFData,
                                      keyAttributes as CFDictionary, &error)
// ...later used with SecKeyCreateSignature(.rsaSignatureMessagePKCS1v15SHA256)
```

The r2 script (`r2 -q -i sec_hardcoded_rsa.r2 -A MASTestApp`):

```text
e asm.bytes=false
e scr.color=false
e asm.var=false
?e Uses of SecKeyCreateWithData:
afl~SecKeyCreateWithData
?e xrefs to SecKeyCreateWithData:
axt @ 0x100007904
pdf @ sym.func.10000491c > function.asm
px 607 @ 0x1000100c8 > key.asm
```

Output:

```text
Uses of SecKeyCreateWithData:
0x100007904    1     12 sym.imp.SecKeyCreateWithData

xrefs to SecKeyCreateWithData:
sym.func.10000491c 0x100004b7c [CALL:--x] bl sym.imp.SecKeyCreateWithData
```

```text
- offset -   C8C9 CACB CCCD CECF D0D1 D2D3 D4D5 D6D7  89ABCDEF01234567
0x1000100c8  3082 025b 0201 0002 8181 00bd f689 8fbd  0..[............
0x1000100d8  0ce6 4f9a 97ec 301a 4893 4d2a bfdf f708  ..O...0.H.M*....
...
```

The import is called once, from `sym.func.10000491c`, and the `__DATA` segment at `0x1000100c8` starts with `30 82 02 5b 02 01 00` — an ASN.1 SEQUENCE of length `0x25b` (603) bytes containing version 0, i.e. an RSA private key. The 607 in the `px` command is those 603 bytes plus the 4-byte header, so the dump is exactly the whole key. Save it with `pr 607 @ 0x1000100c8 > key.der` and `openssl rsa -inform DER -in key.der -noout -text` will print the modulus and private exponent. The test fails. (The demo also uses 1024-bit RSA with PKCS#1 v1.5, which is a separate MASVS-CRYPTO finding.)

**[MASTG-DEMO-0014](https://mas.owasp.org/MASTG/demos/ios/MASVS-CRYPTO/MASTG-DEMO-0014/): hardcoded ECDSA P-256 key in CryptoKit.**

```swift
let privateKeyBytes: [UInt8] = [
    0x7c, 0x02, 0x2a, 0x7e, 0x53, 0x7e, 0x1a, 0x2d, 0x44, 0x77, 0xd4, 0xf6, 0x20, 0x8b, 0x14, 0xdb,
    0x4e, 0x8d, 0x84, 0x19, 0xd6, 0x23, 0x5f, 0xf2, 0x4e, 0x4b, 0x8d, 0x18, 0xf4, 0x2c, 0x76, 0xe2
]
let privateKey = try P256.Signing.PrivateKey(rawRepresentation: Data(privateKeyBytes))
let signature = try privateKey.signature(for: dataToSign)
```

The r2 script lists the CryptoKit symbols with `afl~CryptoKit.P256.Signing.PrivateKey`, takes cross-references, prints the instructions before the `rawRepresentation` initialiser call (`pd-- 9 @ 0x1000048d4`), and dumps 32 bytes at `0x1000100c8`:

```text
Uses of CryptoKit.P256.Signing.PrivateKey:
0x100007364    1     12 sym.imp.CryptoKit.P256.Signing.PrivateKey.public...
0x100007370    1     12 sym.imp.CryptoKit.P256.Signing.PrivateKey.rawRepresentation.Foundation.ContiguousBytes...
0x10000737c    1     12 sym.imp.CryptoKit.P256.Signing.PrivateKey.signature.for.ECDSASignature...
0x100007388    1     12 sym.imp.CryptoKit.P256.Signing.PrivateKey...VMa

Use of CryptoKit.P256.Signing.PrivateKey.rawRepresentation:
│  0x1000048c8      sub x0, x29, 0x80
│  0x1000048cc      mov x8, x20
│  0x1000048d0      mov x21, 0
│  0x1000048d4      bl sym CryptoKit.P256.Signing.PrivateKey.rawRepresentation...
```

```text
- offset -   C8C9 CACB CCCD CECF D0D1 D2D3 D4D5 D6D7  89ABCDEF01234567
0x1000100c8  7c02 2a7e 537e 1a2d 4477 d4f6 208b 14db  |.*~S~.-Dw.. ...
0x1000100d8  4e8d 8419 d623 5ff2 4e4b 8d18 f42c 76e2  N....#_.NK...,v.
```

The 32 bytes in `__DATA` match the Swift literal byte for byte: the P-256 private scalar is in the binary, so anyone can sign as the app. The test fails. One detail if you reproduce it: the demo's "xrefs" step queries `0x100007388`, which is the type metadata accessor (`...VMa`) rather than the `rawRepresentation` stub at `0x100007370`; querying `axt @ 0x100007370` gives you the initialiser call directly.

OWASP's demos include an AI-assisted "decompiled" Swift rendering of the function. That is a reading aid, not evidence; base the finding on the disassembly and the dumped bytes.

### MASTG-TEST-0214: Hardcoded Cryptographic Keys in Files (iOS)

Source: [MASTG-TEST-0214](https://mas.owasp.org/MASTG/tests/ios/MASVS-CRYPTO/MASTG-TEST-0214/). Type: static, manual review. The same procedure applies unchanged to an Android APK's `assets/` and `res/raw/`.

#### Overview

Keys are often shipped as files rather than code: PEM private keys, PKCS#12 bundles for mutual TLS (with the passphrase in code), DER blobs, keys embedded in `Info.plist` or a custom plist, JSON config with a Base64 `encryptionKey`, or data assets in `Assets.car`. Signals:

- **Extensions**: `.key`, `.pem`, `.p12`, `.pfx`, `.der`, `.cer`, `.crt` (and on Android `.bks`, `.jks`, `.keystore`).
- **PEM markers**: `-----BEGIN PRIVATE KEY-----`, `-----BEGIN RSA PRIVATE KEY-----`, `-----BEGIN EC PRIVATE KEY-----`, `-----BEGIN ENCRYPTED PRIVATE KEY-----`, `-----BEGIN CERTIFICATE-----`.
- **DER/PKCS#12 bytes**: files starting with `30 82` (an ASN.1 SEQUENCE with a two-byte length).
- **Config values**: keys named `privateKey`, `secret`, `key`, `aesKey`, `hmacKey` with long Base64 or hex values.

#### Prerequisites

- The IPA, unzipped (decryption is not needed — FairPlay encrypts only the executable, not resources).
- `find`, `grep`, `xxd`, `plutil`, `openssl` (3.x), and on macOS `xcrun assetutil` for asset catalogues.

#### Steps

1. **Extract the bundle** (MASTG-TECH-0058) and list candidate files by extension:

   ```bash
   unzip -q App.ipa -d ipa/ && cd ipa/Payload/App.app
   find . -type f \( -iname '*.pem' -o -iname '*.key' -o -iname '*.p12' -o -iname '*.pfx' \
        -o -iname '*.der' -o -iname '*.cer' -o -iname '*.crt' \) -print
   ```

2. **Search all files for PEM markers** (text and binary):

   ```bash
   grep -rlaE -- '-----BEGIN ([A-Z]+ )?PRIVATE KEY-----' .
   grep -rlaE -- '-----BEGIN CERTIFICATE-----' .
   ```

3. **Find DER blobs by magic bytes**, independent of extension:

   ```bash
   find . -type f -size -20k -exec sh -c \
     'h=$(xxd -p -l 2 "$1"); [ "$h" = "3082" ] && echo "$1"' _ {} \;
   ```

4. **Dump plists and JSON** and look for key-like values:

   ```bash
   find . -name '*.plist' -exec sh -c 'echo "== $1"; plutil -convert xml1 -o - "$1"' _ {} \; \
     | grep -iE -A1 '<key>[^<]*(key|secret|private|token)[^<]*</key>'
   find . -name '*.json' -exec grep -HnoiE '"[^"]*(key|secret|private)[^"]*"[[:space:]]*:[[:space:]]*"[A-Za-z0-9+/=]{24,}"' {} \;
   ```

5. **Check asset catalogues** for data assets (`xcrun assetutil --info Assets.car`) and embedded frameworks (`Frameworks/*.framework`) with the same commands.

6. **Identify what each hit is**:

   ```bash
   openssl x509 -inform DER -in file.der -noout -subject -issuer   # certificate?
   openssl pkey -inform DER -in file.der -noout -text              # private key?
   openssl pkcs12 -info -in client.p12 -nokeys -passin pass:'<from code>'   # add -legacy for old RC2-encrypted files
   ```

   For a `.p12`, find the passphrase: `nm -u "$BIN" | grep SecPKCS12Import` locates the import, and the `kSecImportExportPassphrase` value is usually a nearby string constant.

#### Observation

A list of files containing key material, with path, type (private key, certificate, PKCS#12, symmetric key in config), algorithm and size, and — from the code — what the app uses each one for.

#### Evaluation

The test **fails** if the bundle contains **private or secret** key material used for a security-relevant purpose: a PEM/DER private key, a PKCS#12 whose passphrase is in the binary (or which has no passphrase), or a symmetric key or HMAC secret in a plist or JSON file. Confirm usage by reviewing the code that loads it (MASTG-TECH-0076).

It **passes** for public material: X.509 certificates and public keys used for pinning or signature verification are not secrets. Also exclude files belonging to third-party SDK test resources that are never loaded, and encrypted private keys whose passphrase is genuinely not in the app (rare — check).

#### Demo

OWASP has no demo for this test yet; the following is our illustrative example. An app ships a client certificate for mutual TLS and an encryption key in its config:

```swift
// Loads the bundled client identity for mTLS — passphrase in code
let url = Bundle.main.url(forResource: "client", withExtension: "p12")!
let options = [kSecImportExportPassphrase as String: "Sup3rS3cret!"]
var items: CFArray?
let status = SecPKCS12Import(try Data(contentsOf: url) as CFData, options as CFDictionary, &items)

// Info.plist contains <key>storageKey</key><string>q0yJ1n...=</string>
let b64 = Bundle.main.object(forInfoDictionaryKey: "storageKey") as! String
let storageKey = SymmetricKey(data: Data(base64Encoded: b64)!)
```

Detection:

```text
$ find . -type f \( -iname '*.p12' -o -iname '*.pem' \) -print
./client.p12
$ plutil -convert xml1 -o - Info.plist | grep -A1 storageKey
	<key>storageKey</key>
	<string>q0yJ1n...=</string>
$ openssl pkcs12 -info -in client.p12 -nokeys -passin pass:'Sup3rS3cret!' | head -3
MAC: sha256, Iteration 2048
...
subject=CN = mobile-client
```

Both items fail: anyone with the IPA can impersonate the app to the mTLS endpoint, and the storage key decrypts the local data of every user.

### Supplementary checks (not OWASP tests)

The beta tests above cover hardcoded keys. The other two modes of MASWE-0003 need runtime checks; these are ours.

**Keys in app storage (Android).** After exercising the app (log in, enable offline mode, use any "secure" feature), pull the data directory and look for key-sized values:

```bash
adb shell su -c 'tar -cf /data/local/tmp/app.tar /data/data/com.example.app'
adb pull /data/local/tmp/app.tar && tar -xf app.tar
grep -rnoE '[A-Za-z0-9+/]{43}=|[A-Za-z0-9+/]{22}==|[0-9a-fA-F]{64}' data/data/com.example.app/shared_prefs/ data/data/com.example.app/files/
grep -rliE 'key|secret|aes|master' data/data/com.example.app/shared_prefs/
```

On a non-rooted device with a debuggable build, `adb shell run-as com.example.app` gives the same access. A Base64 value that the Frida `SecretKeySpec` hook shows being decoded into a key is the finding; tie the two together in the report.

**Keys in app storage (iOS).** On a jailbroken device:

```bash
objection -g com.example.app explore
# then, inside objection:
ios nsuserdefaults get
ios plist cat Library/Preferences/com.example.app.plist
ios keychain dump
```

Keys found in `NSUserDefaults`, a plist, `Documents/` or `Library/` fail. Keys found in the Keychain pass this check, but review their accessibility: `kSecAttrAccessibleAlways*` fails, and a non-`ThisDeviceOnly` class or `kSecAttrSynchronizable` for a device-bound key is a weaker configuration to report at Low.

**Plaintext key import.** Search the decompiled code for import paths and follow the source of the bytes:

```bash
grep -rnE 'KeyProtection\.Builder|SecretKeyEntry|PrivateKeyEntry|WrappedKeyEntry' out/sources/
```

`setEntry` with a `SecretKeyEntry`/`PrivateKeyEntry` whose key came from the network or a file is a plaintext import; `WrappedKeyEntry` is the secure form. On iOS, `SecKeyCreateWithData` or `SymmetricKey(data:)` fed from a network response and then stored with `SecItemAdd` is the equivalent. Report it where a key that protects long-lived or high-value data is delivered this way; intercepting the provisioning response with a proxy (the TLS-pinning bypass is a separate step) demonstrates it neatly.

**Keystore key quality (Android).** Where the app does use the keystore, check that the key is what the design claims. Grep `KeyGenParameterSpec.Builder` and read the chain of setters; at runtime, hook `KeyGenerator.init` or query `KeyInfo` with Frida. A banking or wallet app whose "hardware-protected" key reports `SECURITY_LEVEL_SOFTWARE` on a device that has a TEE, or whose signing key lacks `setUserAuthenticationRequired(true)` where the design relies on it, is worth reporting even though the key is technically in the keystore.

## Secure implementation

MASWE-0003 links no Best Practice pages, so this section is ours. The examples are deliberately small; they compile against current SDKs (Android API 23+ with the version checks shown, iOS 13+ for CryptoKit) and are meant as a reference for what "good" looks like when you review code or write a remediation.

### Android: generate an AES-256-GCM key in the keystore, preferring StrongBox

```kotlin
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.security.ProviderException
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

private const val ANDROID_KEYSTORE = "AndroidKeyStore"

fun getOrCreateAesKey(context: Context, alias: String): SecretKey {
    val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    (ks.getKey(alias, null) as? SecretKey)?.let { return it }

    fun spec(strongBox: Boolean): KeyGenParameterSpec {
        val b = KeyGenParameterSpec.Builder(
            alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)          // keystore picks the IV
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            b.setUnlockedDeviceRequired(true)               // only if never needed while locked
            if (strongBox) b.setIsStrongBoxBacked(true)
        }
        return b.build()
    }

    val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
    val wantStrongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
        context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
    return try {
        kg.init(spec(wantStrongBox))
        kg.generateKey()
    } catch (e: ProviderException) {                        // includes StrongBoxUnavailableException
        if (!wantStrongBox) throw e
        kg.init(spec(false))
        kg.generateKey()
    }
}
```

For data that should only be readable after the user authenticates, add `setUserAuthenticationRequired(true)` and, on API 30+, `setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)`, then use the cipher through `BiometricPrompt.CryptoObject`. Log the resulting security level so you can see it in testing:

```kotlin
import android.security.keystore.KeyInfo
import javax.crypto.SecretKeyFactory

fun securityLevel(key: SecretKey): String {
    val info = SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
        .getKeySpec(key, KeyInfo::class.java) as KeyInfo
    return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        when (info.securityLevel) {
            KeyProperties.SECURITY_LEVEL_STRONGBOX -> "StrongBox"
            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "TEE"
            KeyProperties.SECURITY_LEVEL_SOFTWARE -> "Software"
            else -> "Unknown secure"
        }
    } else {
        @Suppress("DEPRECATION")
        if (info.isInsideSecureHardware) "Secure hardware" else "Software"
    }
}
```

### Android: encrypt and decrypt with the keystore key

```kotlin
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec

private const val TRANSFORMATION = "AES/GCM/NoPadding"
private const val IV_LEN = 12
private const val TAG_BITS = 128

fun seal(key: SecretKey, plaintext: ByteArray, aad: ByteArray? = null): ByteArray {
    val cipher = Cipher.getInstance(TRANSFORMATION)
    cipher.init(Cipher.ENCRYPT_MODE, key)                // no IV supplied: keystore generates it
    if (aad != null) cipher.updateAAD(aad)
    return cipher.iv + cipher.doFinal(plaintext)         // IV || ciphertext || tag
}

fun open(key: SecretKey, blob: ByteArray, aad: ByteArray? = null): ByteArray {
    val cipher = Cipher.getInstance(TRANSFORMATION)
    cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, blob, 0, IV_LEN))
    if (aad != null) cipher.updateAAD(aad)
    return cipher.doFinal(blob, IV_LEN, blob.size - IV_LEN)
}
```

Use the AAD to bind ciphertext to its context (record ID, user ID, key version) so a blob cannot be swapped between records.

### Android: envelope encryption (DEK wrapped by a keystore KEK)

Use this when you need a raw key the keystore cannot hold for you — a SQLCipher passphrase, a key handed to a native library, or bulk encryption where per-call keystore IPC is too slow. The KEK never leaves the keystore; only the wrapped DEK is persisted.

```kotlin
import android.content.SharedPreferences
import android.util.Base64
import java.security.SecureRandom
import javax.crypto.spec.SecretKeySpec

class DekStore(private val kek: SecretKey, private val prefs: SharedPreferences) {
    private val aad = "dek:v1".toByteArray()

    fun getOrCreateDek(): SecretKey {
        val raw = prefs.getString("dek_v1", null)
            ?.let { open(kek, Base64.decode(it, Base64.NO_WRAP), aad) }
            ?: ByteArray(32).also { fresh ->
                SecureRandom().nextBytes(fresh)
                val wrapped = seal(kek, fresh, aad)
                prefs.edit().putString("dek_v1", Base64.encodeToString(wrapped, Base64.NO_WRAP)).apply()
            }
        return try { SecretKeySpec(raw, "AES") } finally { raw.fill(0) }   // SecretKeySpec copies the bytes
    }
}
```

This is the legitimate `SecretKeySpec` case that MASTG-TEST-0212's rule will still flag; in triage you confirm the bytes come from `open(kek, ...)` or `SecureRandom`, not from a literal. For rotation, generate `dek_v2`, re-encrypt data lazily or in a migration, and include the version in the AAD and alias. If you prefer a library, Tink's `AndroidKeysetManager` implements the same idea with a keystore-held master key (`android-keystore://` URI); Jetpack Security did too, but it is deprecated (see the warning above).

### Android: wrapped import of a server-provided key

Only if the key genuinely has to come from the server. Step 1 creates an attested wrapping key and sends its chain to the backend; step 2 imports the `SecureKeyWrapper` the backend returns.

```kotlin
import android.security.keystore.WrappedKeyEntry
import java.security.KeyPairGenerator
import java.security.spec.MGF1ParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

fun createWrappingKey(alias: String, serverChallenge: ByteArray): List<ByteArray> {
    val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE)
    kpg.initialize(
        KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_WRAP_KEY)
            .setKeySize(2048)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
            .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
            .setAttestationChallenge(serverChallenge)
            .build()
    )
    kpg.generateKeyPair()
    val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    return ks.getCertificateChain(alias).map { it.encoded }      // send to the server for verification
}

fun importWrapped(alias: String, wrappingAlias: String, secureKeyWrapper: ByteArray) {
    val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    val oaep = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)
    ks.setEntry(alias, WrappedKeyEntry(secureKeyWrapper, wrappingAlias, "RSA/ECB/OAEPPadding", oaep), null)
}
```

The `null` protection parameter is correct: the imported key's authorisations come from the `authorizationList` the server put in the wrapper. On the server, verify the attestation chain first (Google root, revocation, challenge, `TrustedEnvironment` or `StrongBox`), then build the wrapper with an ephemeral AES-256-GCM transport key, using the DER-encoded `KeyDescription` as the GCM additional data, and RSA-OAEP-SHA-256 to encrypt the transport key. The AOSP CTS test for wrapped import is a good reference for the exact encoding.

### iOS: store a CryptoKit key in the Keychain

```swift
import CryptoKit
import Foundation
import Security

enum KeyStoreError: Error { case unexpectedStatus(OSStatus) }

func saveKey(_ key: SymmetricKey, account: String) throws {
    let data = key.withUnsafeBytes { Data($0) }
    let base: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "com.example.app.keys",
        kSecAttrAccount as String: account
    ]
    SecItemDelete(base as CFDictionary)
    var add = base
    add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    add[kSecValueData as String] = data
    let status = SecItemAdd(add as CFDictionary, nil)
    guard status == errSecSuccess else { throw KeyStoreError.unexpectedStatus(status) }
}

func loadKey(account: String) throws -> SymmetricKey? {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "com.example.app.keys",
        kSecAttrAccount as String: account,
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne
    ]
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    if status == errSecItemNotFound { return nil }
    guard status == errSecSuccess, let data = item as? Data else {
        throw KeyStoreError.unexpectedStatus(status)
    }
    return SymmetricKey(data: data)
}

func databaseKey() throws -> SymmetricKey {
    if let existing = try loadKey(account: "db") { return existing }
    let fresh = SymmetricKey(size: .bits256)               // generated on device, never shipped
    try saveKey(fresh, account: "db")
    return fresh
}
```

Use `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` only if background tasks need the key while the device is locked, and replace `kSecAttrAccessible` with a `kSecAttrAccessControl` object (for example `.userPresence`) when access should require the user.

### iOS: generate a key in the Secure Enclave

Security framework form:

```swift
func createEnclaveKey(tag: Data) throws -> SecKey {
    var error: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage, .biometryCurrentSet],
        &error
    ) else { throw error!.takeRetainedValue() as Error }

    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: tag,
            kSecAttrAccessControl as String: access
        ] as [String: Any]
    ]
    guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        throw error!.takeRetainedValue() as Error
    }
    return key
}
```

CryptoKit form:

```swift
import CryptoKit

func makeSigningKey() throws -> SecureEnclave.P256.Signing.PrivateKey {
    guard SecureEnclave.isAvailable else { throw KeyStoreError.unexpectedStatus(errSecUnimplemented) }
    var error: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .userPresence], &error
    ) else { throw error!.takeRetainedValue() as Error }
    return try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
}

// Persist key.dataRepresentation (an Enclave-encrypted blob) in the Keychain, then later:
// let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
// let signature = try key.signature(for: challenge)
```

### iOS: envelope encryption with a Secure Enclave KEK

The Enclave key wraps a CryptoKit DEK with ECIES; the wrapped DEK can sit in a file or the Keychain, and unwrapping requires the Enclave (and the user, if the access control demands it).

```swift
let wrapAlg: SecKeyAlgorithm = .eciesEncryptionCofactorVariableIVX963SHA256AESGCM

func wrap(_ dek: SymmetricKey, with enclaveKey: SecKey) throws -> Data {
    guard let pub = SecKeyCopyPublicKey(enclaveKey),
          SecKeyIsAlgorithmSupported(pub, .encrypt, wrapAlg) else {
        throw KeyStoreError.unexpectedStatus(errSecUnimplemented)
    }
    var error: Unmanaged<CFError>?
    let raw = dek.withUnsafeBytes { Data($0) }
    guard let wrapped = SecKeyCreateEncryptedData(pub, wrapAlg, raw as CFData, &error) as Data? else {
        throw error!.takeRetainedValue() as Error
    }
    return wrapped
}

func unwrap(_ wrapped: Data, with enclaveKey: SecKey) throws -> SymmetricKey {
    var error: Unmanaged<CFError>?
    guard let raw = SecKeyCreateDecryptedData(enclaveKey, wrapAlg, wrapped as CFData, &error) as Data? else {
        throw error!.takeRetainedValue() as Error
    }
    return SymmetricKey(data: raw)
}

func encrypt(_ plaintext: Data, dek: SymmetricKey, context: Data) throws -> Data {
    let box = try AES.GCM.seal(plaintext, using: dek, authenticating: context)
    guard let combined = box.combined else { throw KeyStoreError.unexpectedStatus(errSecParam) }
    return combined                                       // nonce || ciphertext || tag
}

func decrypt(_ combined: Data, dek: SymmetricKey, context: Data) throws -> Data {
    try AES.GCM.open(AES.GCM.SealedBox(combined: combined), using: dek, authenticating: context)
}
```

### Both platforms: never ship the key — fetch or derive it

- **Remove every hardcoded key.** There is no safe way to embed a secret in an app package. If a key is used to talk to a third-party service, move the call behind your own backend, which holds the credential and enforces per-user authorisation and rate limits; see [MASWE-0004](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/).
- **Server-side KMS pattern.** The app authenticates the user (OAuth/OIDC), proves it is a genuine install where it matters (Play Integrity on Android, App Attest via `DCAppAttestService` on iOS), and calls your API. The API, not the app, talks to AWS KMS, Azure Key Vault or Google Cloud KMS with its own workload identity. Prefer designs where the key never leaves the KMS (the server decrypts or signs on the app's behalf); where a per-user key must reach the device, have the KMS-backed service wrap it to the device's attested wrapping key (Android `WrappedKeyEntry`) or deliver it over pinned TLS and store it immediately in the Keychain with a `ThisDeviceOnly` class, then zero the buffer.
- **Derive from the user when it fits.** For a local vault, derive the KEK from the user's passphrase with PBKDF2-HMAC-SHA256 (600,000+ iterations) or Argon2id and a random per-install salt, and keep the derived key only as long as the vault is open.
- **Rotate and scope.** One key per purpose, versioned aliases, a migration path, and server-side revocation for any key the backend trusts.

## Rating findings

Rate on what the key protects, how many installs share it, and what the attacker needs to exploit it. Use these as starting points and adjust for context.

| Rating | Conditions |
|---|---|
| **Critical** | A hardcoded private key or secret that the **backend trusts**: it signs or authenticates requests, mints licences or tokens the server accepts, authenticates an mTLS client with access to other users' data, or grants admin or high-cost access to a paid service. No device access is needed — the IPA/APK is enough — and the impact spans all users. |
| **High** | A hardcoded symmetric key protecting **sensitive user data** (credentials, tokens, health or financial data) at rest or in transit, where ciphertext is reachable by an attacker (backups, cloud sync, shared storage, intercepted traffic). Also: a hardcoded key used to verify integrity or entitlements client-side, allowing forgery; and a plaintext-imported long-term key for a high-value function. |
| **Medium** | A generated key stored in app storage (`SharedPreferences`, DataStore, `NSUserDefaults`, plist, DB) next to the data it protects, so root/jailbreak/backup access recovers both. A hardcoded key protecting moderately sensitive local data with no remote path to the ciphertext. A Keychain key with `kSecAttrAccessibleAlways*`. |
| **Low** | Keys in the keystore/Keychain but configured weaker than the design requires: software-backed where hardware was claimed, missing auth binding for a key the design says is user-gated, non-`ThisDeviceOnly` or synchronisable Keychain classes for device-bound keys, StrongBox/Secure Enclave available but unused for a high-assurance key. Hardcoded keys that only obfuscate non-sensitive data. |
| **Info** | Public keys and certificates in the bundle (pinning, signature verification); test keys in unreachable SDK code; correct envelope encryption flagged by the static rule. |

When you report, include the extracted key (redacted to the first and last bytes), the exact file and offset or class and line, a one-line proof of impact (for example, decrypting a sample record or producing a valid signature), and whether the key is identical across installs. That last fact usually decides between Critical/High and Medium.

## References

- OWASP MASWE — [MASWE-0003: Cryptographic Keys Stored Outside of Platform Keystore](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0003/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0012: Key Generation](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0012/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0043: Android KeyStore](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0043/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0044: Key Attestation](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0044/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0045: Secure Key Import into Keystore](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0045/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0047: Cryptographic Key Storage](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0047/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0057: Keychain Services](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-AUTH/MASTG-KNOW-0057/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0066: CryptoKit](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0066/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0069: Key Management](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0069/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0126: Keychain Access Groups](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0126/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0212: Use of Hardcoded Cryptographic Keys in Code](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0212/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0213: Use of Hardcoded Cryptographic Keys in Code](https://mas.owasp.org/MASTG/tests/ios/MASVS-CRYPTO/MASTG-TEST-0213/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0214: Hardcoded Cryptographic Keys in Files](https://mas.owasp.org/MASTG/tests/ios/MASVS-CRYPTO/MASTG-TEST-0214/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-DEMO-0017](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0017/), [MASTG-DEMO-0013](https://mas.owasp.org/MASTG/demos/ios/MASVS-CRYPTO/MASTG-DEMO-0013/), [MASTG-DEMO-0014](https://mas.owasp.org/MASTG/demos/ios/MASVS-CRYPTO/MASTG-DEMO-0014/) (CC BY-SA 4.0)
- OWASP MASTG — techniques [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/); tools [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/), [radare2 (MASTG-TOOL-0073)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/) (CC BY-SA 4.0)
- [Android Developers — Android Keystore system](https://developer.android.com/privacy-and-security/keystore) (including [StrongBox](https://developer.android.com/privacy-and-security/keystore#StrongBoxKeyMint) and [importing encrypted keys](https://developer.android.com/privacy-and-security/keystore#ImportingEncryptedKeys))
- [Android Developers — Verifying hardware-backed key pairs with key attestation](https://developer.android.com/privacy-and-security/security-key-attestation)
- [Android Developers — `WrappedKeyEntry`](https://developer.android.com/reference/android/security/keystore/WrappedKeyEntry), [`KeyGenParameterSpec.Builder`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder), [`KeyInfo`](https://developer.android.com/reference/android/security/keystore/KeyInfo)
- [Android Developers — Cryptography (Jetpack Security deprecation)](https://developer.android.com/privacy-and-security/cryptography)
- [AOSP — Hardware-backed Keystore](https://source.android.com/docs/security/features/keystore)
- [Apple — Keychain services](https://developer.apple.com/documentation/security/keychain_services) and [Storing keys as data](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/storing_keys_as_data)
- [Apple — Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave) and [`kSecAttrTokenIDSecureEnclave`](https://developer.apple.com/documentation/security/ksecattrtokenidsecureenclave)
- [Apple — CryptoKit `SecureEnclave`](https://developer.apple.com/documentation/cryptokit/secureenclave) and [Storing CryptoKit keys in the keychain](https://developer.apple.com/documentation/cryptokit/storing-cryptokit-keys-in-the-keychain)
- [Apple Platform Security Guide — Keychain data protection](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [NIST SP 800-57 Part 1 Rev. 5 — Recommendation for Key Management](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf)
- [NIST SP 800-175B Rev. 1 — Guideline for Using Cryptographic Standards](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-175Br1.pdf)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) and [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [CWE-321: Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
