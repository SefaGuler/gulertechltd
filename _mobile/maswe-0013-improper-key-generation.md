---
title: "Improper Cryptographic Key Generation (MASWE-0013)"
date: 2026-11-09 09:04:00 +0000
subcategory: crypto
summary: "How to find mobile keys generated too short, from weak randomness or outside secure hardware, with Android and iOS tests, demos and NIST key-size guidance."
refs: [MASWE-0013, MASVS-CRYPTO-2, CWE-326, CWE-331, CWE-337, CWE-338, CWE-522]
tags: [android, ios, masvs-crypto, key-generation, key-size, strongbox]
---

This note is part of our [MASVS-CRYPTO guide](/mobile/masvs-crypto-cryptography-guide/) and covers OWASP [MASWE-0013](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0013/): cryptographic keys that are generated badly. "Badly" has three meanings here — the key is too short for its algorithm, the bits came from a source an attacker can predict, or the key was created somewhere (app heap, server, build machine) that exposes it before it is ever protected. Each of these undermines every mechanism built on the key, however carefully the cipher, mode and storage are chosen. You will find NIST key-size guidance mapped to the Android and iOS APIs that set key sizes, the two OWASP static tests with their demos worked through, a runtime check of our own that catches what static analysis misses, working Kotlin and Swift for correct generation, and severity guidance. Key storage itself is covered in [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/), random number generation in [MASWE-0012](/mobile/maswe-0012-improper-random-number-generation/), and keys derived from passwords in [MASWE-0014](/mobile/maswe-0014-improper-key-derivation/); this note links to them rather than repeating them.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: Key Generation (MASTG-KNOW-0012)](#android-key-generation-mastg-know-0012)
  - [Both platforms: key sizes and security strength (supplementary)](#both-platforms-key-sizes-and-security-strength-supplementary)
  - [Both platforms: where the key bits come from (supplementary)](#both-platforms-where-the-key-bits-come-from-supplementary)
  - [Android: key generation APIs and size parameters (supplementary)](#android-key-generation-apis-and-size-parameters-supplementary)
  - [iOS: key generation APIs and size parameters (supplementary)](#ios-key-generation-apis-and-size-parameters-supplementary)
- [Tests](#tests)
  - [MASTG-TEST-0208 (Android)](#mastg-test-0208-insufficient-key-sizes-android)
  - [MASTG-TEST-0209 (iOS)](#mastg-test-0209-insufficient-key-sizes-ios)
  - [Supplementary: runtime key-size and provenance check](#supplementary-runtime-key-size-and-provenance-check-android-and-ios)
- [Secure implementation](#secure-implementation)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

A key has one job: to be unguessable for as long as the data or the identity it protects matters. Three properties decide whether it can do that job:

1. **Length relative to the algorithm.** The best known attack on AES is still exhaustive search, so a 128-bit AES key gives about 128 bits of security. RSA and elliptic-curve keys are attacked with mathematics (factoring, discrete logarithms), so their keys must be much longer for the same strength: a 3072-bit RSA modulus and a 256-bit elliptic-curve key both give roughly 128 bits. "Key size" means nothing without the algorithm next to it.
2. **Entropy of the generation process.** A 256-bit key produced from a timestamp seed has the entropy of the timestamp — perhaps 30 bits. The length is a ceiling, never a guarantee.
3. **Where generation happens.** A key generated in the app process, on a server, or at build time exists as plain bytes somewhere before it reaches protected storage. A key generated inside the Android Keystore, StrongBox or the Secure Enclave never does.

MASWE-0013 covers failures of all three, plus two related generation-time decisions: exporting a key in plaintext after it has been generated, and giving a key broader properties (purposes, storage, access rules) than it needs. The OWASP tests linked to the weakness only check the first property, key length, statically. The rest of this note gives you the knowledge and the commands to check the others.

The weakness is mapped to MASVS-CRYPTO-2 (key management) and to CWE-326 (Inadequate Encryption Strength), CWE-331 (Insufficient Entropy), CWE-337 (Predictable Seed in PRNG), CWE-338 (Use of Cryptographically Weak PRNG) and CWE-522 (Insufficiently Protected Credentials).

## Modes of Introduction

**Insufficient key length.** The app asks for a key that is shorter than current standards allow: `KeyPairGenerator.initialize(1024)` for RSA, `kSecAttrKeySizeInBits: 1024` on iOS, `secp192r1` for EC, a 64-bit HMAC key. This is usually inherited: a code sample from 2012, a backend protocol that predates the app, a hardware token or payment scheme that only accepted 1024-bit RSA, or a "smaller keys are faster" decision made for an old device.

**Risky or broken algorithms.** Some algorithms only come in weak sizes. DES is 56 bits, two-key Triple DES (2TDEA) about 80, RC4 and Blowfish are obsolete for other reasons, and three-key Triple DES (3TDEA) is no longer approved for new encryption. If the app generates a `DESede` key, the key-size question is already answered.

**Insufficient entropy.** The key bits come from `java.util.Random`, `kotlin.random.Random`, `Math.random()`, `arc4random`-style code paths ported from elsewhere, a `SecureRandom` given a fixed seed, `rand()`/`srand(time(NULL))` in native code, or a UUID, timestamp, device identifier or hash of one. These keys may have the right length and be completely predictable. The RNG side is covered in depth in [MASWE-0012](/mobile/maswe-0012-improper-random-number-generation/).

**Keys made instead of generated.** A key built from a string, a constant byte array, or a hash of the package name is not "generated" at all. If it is a constant, it is a hardcoded key ([MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/)); if it is derived from a password, PIN or device value, its strength is the strength of that input and the KDF ([MASWE-0014](/mobile/maswe-0014-improper-key-derivation/)).

**Insecure key export.** The key leaves the environment it was generated in as plain bytes: `getEncoded()` on a software key sent to a server, `SecKeyCopyExternalRepresentation` on a private key, a key written to a log, a backup or a QR code. NIST SP 800-175B Rev. 1 (section 5.3.5) expects keys that must be transported to be wrapped — encrypted under another key — even when the channel is already protected, because the channel protects the transfer, not the endpoints.

**Insecure key properties.** The key is generated with every purpose enabled (encrypt, decrypt, sign, verify), no user-authentication requirement where the design needs one, in software when secure hardware is available, or as a permanent Keychain item with a broad accessibility class. These choices are fixed at generation time on Android and largely so on iOS. Access restrictions have their own weakness, [MASWE-0016](/mobile/maswe-0016-key-access-not-restricted/).

**Generated outside, then imported.** A backend or the app's own code generates a key with a JCA software provider, CommonCrypto or CryptoKit, and then imports the raw bytes into the Android Keystore or Keychain. The key ends up in the right place but was exposed on the way. This is the "insecure key import" mode in [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/#android-secure-key-import-into-keystore-mastg-know-0045); generating the key in the keystore in the first place removes the problem.

## Impact

- **Compromise of sensitive data.** A key that can be recovered by search, by factoring, or by reproducing the RNG output decrypts everything it protected, including ciphertext captured long ago. Data with a long confidentiality life (health records, identity documents, archives) is exposed to whatever becomes feasible during that life, not just today.
- **Authentication or authorisation bypass.** A recovered signing key lets an attacker produce signatures the backend accepts: device binding, transaction signing, licence tokens, FIDO-style assertions. A weak key in a challenge-response scheme turns impersonation into a computation.
- **Loss of non-repudiation.** If a key could have been generated or recovered by someone other than its owner, signatures made with it no longer prove who made them — a serious problem for regulated signing flows (eIDAS, payments, the EUDI wallet profile that MASWE-0013 is tagged with).

## Mitigations

- **Generate keys inside the platform keystore**, so the raw key material never exists in the app process. On Android use `KeyGenerator`/`KeyPairGenerator` with the `AndroidKeyStore` provider and a `KeyGenParameterSpec`; on iOS use `SecKeyCreateRandomKey` with Keychain storage, the Secure Enclave for P-256, or CryptoKit keys stored in the Keychain. See [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/) for the storage side.
- **Use sufficient key lengths, explicitly.** AES-128 or AES-256 (AES-256 for long-lived data or where a policy demands it), RSA 2048 at the very least and RSA 3072 for keys whose protection must extend beyond 2030, EC P-256 or stronger. Set the size in code rather than trusting a provider default, so the choice is visible in review. NIST SP 800-57 Part 1 Rev. 5 and SP 800-131A Rev. 2 are the references; [keylength.com](https://www.keylength.com/) compares them with other national recommendations.
- **Use the platform CSPRNG only.** `SecureRandom()` with no seed on Android, `SecRandomCopyBytes` or CryptoKit on iOS. Never pass your own seed or `Random` instance into a key generator. OWASP [MASTG-BEST-0001](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0001/) (Android) and [MASTG-BEST-0025](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0025/) (iOS) describe the right APIs.
- **Prefer secure hardware**, and handle its limits: StrongBox supports a narrower set of algorithms and sizes than the TEE, and the Secure Enclave only creates P-256 keys.
- **Wrap keys before export.** If a key really must leave the device (backup, multi-device sync, escrow), encrypt it under a key-encryption key with AES Key Wrap or an AEAD such as AES-GCM, never as raw bytes.
- **Use key attestation** where the backend relies on the key's properties. An Android attestation certificate records the key's algorithm, size, curve, purposes and security level, so the server can check them instead of trusting the app.

## Knowledge

MASWE-0013 has no Knowledge pages linked on the MASWE site. Its Android test, MASTG-TEST-0208, references MASTG-KNOW-0012 (Key Generation), which we cover in full in our MASWE-0003 note; the first section below summarises what matters here and links there. The sections after it are **supplementary** knowledge written by us, because neither OWASP test explains what a sufficient key size is, how sizes are expressed in each API, or where entropy comes from.

### Android: Key Generation (MASTG-KNOW-0012)

Source: [MASTG-KNOW-0012](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0012/). Our full treatment, including corrections to the OWASP code samples, is in [MASWE-0003: Android Key Generation](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/#android-key-generation-mastg-know-0012).

The points from KNOW-0012 that bear on key *generation* rather than storage:

- Since Android 6.0 (API 23), keystore keys are described by a `KeyGenParameterSpec`, which becomes the key's enforced authorisation list. The key size you set there (`setKeySize`) is part of that list and cannot be changed later; a weak key stays weak until it is replaced.
- Passing `"AndroidKeyStore"` as the provider is what makes the key a keystore key. `KeyGenerator.getInstance("AES")` without it gives a properly random software key whose bytes are on the Java heap, which the app must then store or import — the start of most MASWE-0003 findings.
- Before API 23, many apps generated RSA key pairs with `KeyPairGeneratorSpec` (deprecated) or AES keys with `SecureRandom`. You will still find these code paths in apps with a low `minSdkVersion`; check whether they are reachable on supported devices.
- The KNOW-0012 sample generates a 4096-bit RSA key. That is a sound size, but note that RSA generation time grows steeply with modulus size and that StrongBox does not support it (see below).
- KNOW-0012 also shows a PBKDF2 derivation. Its 10,000 iterations are far below current guidance; password-derived keys are the subject of [MASWE-0014](/mobile/maswe-0014-improper-key-derivation/).

### Both platforms: key sizes and security strength (supplementary)

Supplementary. Sources: NIST SP 800-57 Part 1 Rev. 5 (Table 2 and Table 4), NIST SP 800-131A Rev. 2, FIPS 186-5, and the NIST IR 8547 initial public draft.

NIST expresses strength as **bits of security**: the base-2 logarithm of the work needed to break the key with the best known classical attack. The comparable key sizes, from SP 800-57 Part 1 Rev. 5 Table 2:

| Security strength | Symmetric | RSA modulus | DSA / DH (L, N) | ECC key (field size) |
|---|---|---|---|---|
| ≤ 80 bits | 2TDEA | 1024 | L = 1024, N = 160 | 160–223 |
| 112 bits | 3TDEA | 2048 | L = 2048, N = 224 | 224–255 |
| 128 bits | AES-128 | 3072 | L = 3072, N = 256 | 256–383 |
| 192 bits | AES-192 | 7680 | L = 7680, N = 384 | 384–511 |
| 256 bits | AES-256 | 15360 | L = 15360, N = 512 | 512+ |

And the lifetimes NIST assigns to them (SP 800-57 Part 1 Rev. 5 Table 4, SP 800-131A Rev. 2):

| Security strength | Applying protection (encrypt, sign, generate) | Processing existing data (decrypt, verify) |
|---|---|---|
| < 112 bits | Disallowed | Legacy use only |
| 112 bits | Acceptable through 2030 | Legacy use after 2030 |
| ≥ 128 bits | Acceptable through 2031 and beyond | Acceptable |

What this means for the algorithms you will meet in mobile apps:

| Algorithm | Fails | Acceptable today | What to recommend |
|---|---|---|---|
| AES | n/a (AES has no size below 128) | 128, 192, 256 | 256 for long-lived data, or where a policy (for example CNSA 2.0) requires it |
| DES | Always (56-bit key) | — | AES |
| Triple DES | 2TDEA always; 3TDEA for new encryption since 2023 (SP 800-131A Rev. 2) | Decrypting legacy data only | AES |
| RSA | 512, 768, 1024, anything below 2048 | 2048 (through 2030) | 3072 or larger for keys that must remain secure beyond 2030 |
| DSA | Below 2048; FIPS 186-5 no longer approves DSA for signature generation at all | Verification of old signatures | ECDSA P-256 or Ed25519 |
| DH (finite field) | Below 2048 | 2048 (through 2030) | ECDH P-256, or 3072+ |
| ECDSA / ECDH | Curves below 224 bits (for example P-192, `secp160r1`) | P-224 (through 2030), P-256, P-384, P-521 | P-256 (P-384 for CNSA 2.0) |
| EdDSA | — | Ed25519, Ed448 (approved in FIPS 186-5) | Ed25519 |
| HMAC | Keys shorter than the security strength required (under 112 bits) | ≥ 112 bits | A key as long as the hash output (256 bits for HMAC-SHA256) |
| ChaCha20 | — | 256 (the only size) | 256 |

Three things to understand before you apply these tables in a report:

- **Factoring records give practical context.** The largest RSA challenge number publicly factored is RSA-250 (829 bits, 2020). 512-bit RSA has been factorable on rented cloud machines in hours, for well under a hundred dollars, since the "Factoring as a Service" work published in 2015. 1024-bit RSA has not been publicly factored, but NIST has disallowed it for generating signatures since 2013 because the margin is gone.
- **Quantum computing changes the asymmetric side completely and the symmetric side modestly.** Shor's algorithm breaks RSA, DH and elliptic-curve cryptography of every size, so no RSA modulus is "quantum safe" — making a 2048-bit key 4096 bits buys classical margin, not quantum resistance. Grover's algorithm gives at best a square-root speed-up against symmetric keys, which is why AES-256 is the conservative choice for data that must stay confidential for decades. The NIST IR 8547 initial public draft proposes deprecating 112-bit quantum-vulnerable algorithms after 2030 and disallowing all quantum-vulnerable public-key algorithms after 2035; treat these dates as direction of travel, not yet as final policy.
- **The OWASP evaluation is stricter than NIST on AES.** MASTG-TEST-0208 and MASTG-TEST-0209 both state that a 128-bit AES key is insufficient "considering quantum computing attacks", and the Android demo fails on `init(128)`. NIST still approves AES-128 and lists it as the reference point for its lowest post-quantum security category. We report AES-128 as an observation, not a vulnerability, unless the client's own policy requires 256 bits or the data must stay confidential for decades. Similarly, the MASWE-0013 mitigation text pairs 2048-bit RSA with "considering quantum computing attacks"; as explained above, RSA size has no bearing on quantum resistance.

### Both platforms: where the key bits come from (supplementary)

Supplementary. Sources: OWASP [MASTG-BEST-0001](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0001/) and [MASTG-BEST-0025](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0025/), Android "Weak PRNG" risk guidance, Apple `SecRandomCopyBytes` documentation.

A key generator is only as good as its random source. The full treatment of random number generation is in [MASWE-0012](/mobile/maswe-0012-improper-random-number-generation/); what matters for key generation is this:

**Key generators take an RNG argument, and apps sometimes supply a bad one.** On Android, `KeyGenerator.init(int, SecureRandom)`, `KeyGenerator.init(SecureRandom)` and `KeyPairGenerator.initialize(int, SecureRandom)` all accept a caller-supplied RNG. A default `SecureRandom()` is correct, and so is omitting it (the provider uses its own). A `SecureRandom` seeded with a constant (`SecureRandom(seedBytes)`, or `SHA1PRNG` with `setSeed` before first use on old providers) can make the generated key reproducible. The infamous case is the 2013 Android `SecureRandom` initialisation bug in the Apache Harmony-derived `SHA1PRNG`, which led to private keys being recovered from Bitcoin wallet apps. The `Crypto` provider that served `SHA1PRNG` was deprecated in Android 7.0 and removed in Android 9, but code written against it survives in old libraries. Keystore keys are different: for `AndroidKeyStore` the key is generated inside the keystore with its own RNG, and any `SecureRandom` you pass is ignored for key material.

**Hand-rolled generation bypasses the generator altogether.** Code that fills a byte array and wraps it in `SecretKeySpec` (Android) or `SymmetricKey(data:)` (iOS) is generating a key, whatever it is called. The key is only as good as the code that filled the array. `SecureRandom().nextBytes(bytes)` and `SecRandomCopyBytes(kSecRandomDefault, count, &bytes)` are acceptable (though the key is still a software key); `Random().nextBytes`, `UUID().uuidString`, `System.currentTimeMillis()`, `Date().timeIntervalSince1970`, `ANDROID_ID` or `identifierForVendor` are not.

**Check the return value.** `SecRandomCopyBytes` returns `errSecSuccess` (0) or an error; code that ignores the status and proceeds with a zero-filled buffer has generated an all-zero key on failure. The same applies to native `getrandom()` and to OpenSSL `RAND_bytes`, which returns 1 on success.

**Cross-platform frameworks have their own RNGs.** Dart's `Random()` is not cryptographically secure, `Random.secure()` is; in JavaScript, `Math.random()` is not, `crypto.getRandomValues` (or a native module that calls the platform CSPRNG) is. A Flutter or React Native app that generates keys in Dart or JS must be checked at that layer, not only in the platform code.

### Android: key generation APIs and size parameters (supplementary)

Supplementary. Sources: Android Developers reference for `KeyGenerator`, `KeyPairGenerator`, `KeyGenParameterSpec.Builder`, `KeyInfo`, and "Android Keystore system" (StrongBox section).

**Where the size is set.** The key size can reach a key generator in five ways, and a static review has to look for all of them:

| API | How the size is expressed | Notes |
|---|---|---|
| `KeyGenerator.init(int keysize)` / `init(int, SecureRandom)` | Bits of key material | Software providers. For `AndroidKeyStore` you initialise with a `KeyGenParameterSpec` instead. |
| `KeyPairGenerator.initialize(int keysize)` / `initialize(int, SecureRandom)` | RSA: modulus bits. EC: field size, which selects a curve (256 → P-256) | Software providers. |
| `KeyPairGenerator.initialize(AlgorithmParameterSpec)` with `RSAKeyGenParameterSpec(bits, exponent)` or `ECGenParameterSpec("secp256r1")` | Explicit modulus or named curve | Works for software providers and, inside a `KeyGenParameterSpec`, for the keystore. |
| `KeyGenParameterSpec.Builder.setKeySize(int)` | As above, for keystore keys | Default if unset: AES 128, HMAC the digest length, RSA 2048, EC 256 (P-256). |
| `KeyGenParameterSpec.Builder.setAlgorithmParameterSpec(...)` | `RSAKeyGenParameterSpec` or `ECGenParameterSpec` | Overrides the default; must agree with `setKeySize` if both are set. |

Provider defaults for software key generators are provider-specific and have changed across Android versions; do not assume them, and treat code that never sets a size as "unknown until verified at runtime".

**Algorithm names to recognise.** `KeyProperties` constants are inlined by the compiler, so in decompiled code you see the string: `"AES"`, `"HmacSHA256"` (and SHA-1/224/384/512 variants), `"DESede"` (3DES), `"RSA"`, `"EC"`. In software providers you may also find `"DES"`, `"Blowfish"`, `"ARC4"`/`"RC4"`, `"DSA"`, `"DH"`/`"DiffieHellman"` and `"ChaCha20"` (API 28+). Each of the legacy ones is a finding on its own.

**The EC curve is the key size.** For `"EC"`, size 224 means P-224, 256 means P-256, 384 P-384 and 521 P-521. With `ECGenParameterSpec` look at the curve name: `secp256r1`/`prime256v1`/`P-256` are the same curve; anything with 112, 128, 160 or 192 in the name is weak.

**RSA public exponent.** `RSAKeyGenParameterSpec.F4` (65537) is the default and the right choice. An exponent of 3 is not broken in itself but makes padding mistakes fatal; note it if you see it.

**StrongBox limits.** StrongBox KeyMint (Android 9+, requested with `setIsStrongBoxBacked(true)`) supports only RSA 2048, AES 128 and 256, EC P-256 (ECDSA and ECDH), HMAC-SHA256 with keys of 8 to 64 bytes, and Triple DES. Ask it for RSA 3072, P-384 or AES-192 and `generateKey` throws `StrongBoxUnavailableException`. Two consequences for testers:

- An app that needs StrongBox *and* a 128-bit security level should use EC P-256 or AES-256, not RSA. RSA 2048 in StrongBox is a reasonable trade-off today, but it has a 2030 horizon.
- Many apps catch `StrongBoxUnavailableException` and silently retry in the TEE with the same or different parameters. Read the fallback path: if the fallback lowers the key size, changes algorithm, or drops to a software provider, that is the configuration most devices will actually run.

**The TEE accepts weak sizes too.** The Android Keystore enforces what the app asks for, not what is safe. A `KeyGenParameterSpec` with `setKeySize(1024)` for RSA is accepted on most hardware; nothing in the platform stops it. Hardware backing protects the key from extraction, not from being too short.

**Triple DES in the keystore.** `KeyProperties.KEY_ALGORITHM_3DES` exists (API 28+) mainly for payment and legacy interoperability. Treat a newly generated 3DES key as a finding unless there is a documented external constraint.

**Verifying what was generated.** For a keystore key, `KeyInfo` (from `SecretKeyFactory.getInstance(alg, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java)` or the `KeyFactory` equivalent for private keys) reports `getKeySize()`, `getPurposes()`, `getSecurityLevel()` (API 31+; `isInsideSecureHardware()` before that) and more. For any RSA public key, `(publicKey as RSAPublicKey).modulus.bitLength()` gives the real size. Our [runtime check](#supplementary-runtime-key-size-and-provenance-check-android-and-ios) uses both.

**Generated in software, then imported.** `KeyStore.setEntry(alias, SecretKeyEntry(key), KeyProtection.Builder(...).build())` imports a key that already existed in the process. If that key came from `KeyGenerator.getInstance("AES")` a few lines earlier, there was no reason not to generate it in the keystore; report it under [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/). If it came from a server, the right pattern is wrapped import (`WrappedKeyEntry`, Android 9+), also described there.

**Attestation records the size.** The Android attestation extension's authorisation list includes `algorithm` (tag 2), `keySize` (tag 3) and `ecCurve` (tag 10). A server that relies on device-generated keys should check these fields rather than trusting the public key it is sent. Attestation itself is covered in [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/#android-key-attestation-mastg-know-0044).

### iOS: key generation APIs and size parameters (supplementary)

Supplementary. Sources: Apple documentation for `SecKeyCreateRandomKey`, "Key Generation Attributes", `kSecAttrKeySizeInBits`, CryptoKit `SymmetricKey` and `SymmetricKeySize`, and the CommonCrypto `CCCrypt` man page.

iOS has three generation paths, and they express size differently.

**Security framework (asymmetric keys).** `SecKeyCreateRandomKey(_:_:)` takes an attributes dictionary. The two attributes that decide strength are `kSecAttrKeyType` (`kSecAttrKeyTypeRSA` or `kSecAttrKeyTypeECSECPrimeRandom`) and `kSecAttrKeySizeInBits` (RSA modulus size, or 256/384/521 for the P-curves). Further attributes control storage: `kSecAttrIsPermanent` and `kSecAttrApplicationTag` in `kSecPrivateKeyAttrs` make it a Keychain item, `kSecAttrTokenID: kSecAttrTokenIDSecureEnclave` puts it in the Secure Enclave, and `kSecAttrAccessControl` adds user-presence rules. `SecKeyGeneratePair` takes the same dictionary and is deprecated (iOS 16 SDK); treat it as equivalent when you find it in older code.

At the binary level these attribute names are `CFString` constants with short values. When you print a dictionary at runtime you will see them as `type` (key type; `42` is RSA, `73` is EC), `bsiz` (key size in bits), `perm`, `atag`, `tkid` (`com.apple.setoken` for the Secure Enclave) and `private` (the private-key attributes sub-dictionary). Knowing these makes Frida output readable; if in doubt, resolve the constant at runtime as shown in the supplementary test.

**Secure Enclave.** Only 256-bit EC keys on P-256 can be generated in the Secure Enclave. A request for RSA or for another curve with `kSecAttrTokenIDSecureEnclave` fails. That is a hardware constraint, not a weakness: P-256 provides 128-bit security. If an app needs RSA it cannot have Secure Enclave protection, and you should ask why it needs RSA.

**CryptoKit.** CryptoKit generates keys for you and mostly hides size decisions:

- `SymmetricKey(size: .bits128)`, `.bits192`, `.bits256`, or `SymmetricKeySize(bitCount: n)` for anything else. `AES.GCM` accepts 128, 192 and 256-bit keys and throws `CryptoKitError.incorrectKeySize` otherwise; `ChaChaPoly` requires 256. `HMAC` accepts a key of any length — so `SymmetricKey(size: SymmetricKeySize(bitCount: 64))` used as an HMAC key compiles, runs, and is weak.
- `P256`, `P384`, `P521` and `Curve25519` private keys created with their no-argument initialisers (for example `P256.Signing.PrivateKey()`) are random keys of the curve's fixed size. The curve name is the key size.
- `SecureEnclave.P256.Signing.PrivateKey()` and `SecureEnclave.P256.KeyAgreement.PrivateKey()` generate inside the Enclave.

This is why MASTG-TEST-0209 does not test CryptoKit: there is little room to choose a short key. The CryptoKit generation risk is different — keys created with `SymmetricKey(data:)` from bytes the app produced itself, which takes you back to entropy and to MASWE-0003/MASWE-0014.

**CommonCrypto (symmetric keys).** CommonCrypto has no key generator. A CommonCrypto key is a buffer the app filled, ideally with `SecRandomCopyBytes`, and its length is passed to `CCCrypt` (fifth argument, `keyLength`) or `CCCryptorCreate`. The size constants are `kCCKeySizeAES128` (16), `kCCKeySizeAES192` (24), `kCCKeySizeAES256` (32), `kCCKeySizeDES` (8) and `kCCKeySize3DES` (24); the algorithm constants include `kCCAlgorithmAES` (0), `kCCAlgorithmDES` (1), `kCCAlgorithm3DES` (2), `kCCAlgorithmCAST` (3), `kCCAlgorithmRC4` (4), `kCCAlgorithmRC2` (5) and `kCCAlgorithmBlowfish` (6). Note that `kCCAlgorithmAES128` is the same value as `kCCAlgorithmAES`: the "128" refers to the block size, and the key size is set by `keyLength`. Developers misread this both ways.

A classic CommonCrypto pattern you will still meet is a category such as `AES256EncryptWithKey:` that copies an `NSString` password into a zero-padded 33-byte buffer and passes it as a 256-bit key. The key length is right, but the key is a password — a [MASWE-0014](/mobile/maswe-0014-improper-key-derivation/) finding, not a key-size one.

**Exporting what you generated.** `SecKeyCopyExternalRepresentation` returns the raw key (PKCS#1 for RSA, ANSI X9.63 for EC). On a public key that is harmless. On a private key it means the key is now app data. Secure Enclave keys cannot be exported at all; for other Keychain keys, the protection against export is simply that the app never calls this function on the private key, so that is what you check. CryptoKit offers `AES.KeyWrap.wrap(_:using:)` (RFC 3394, iOS 15+) to wrap a symmetric key under another before it leaves the device.

## Tests

OWASP links two tests to MASWE-0013, one per platform. Both are static and both focus on key length. After them we add a [supplementary runtime check](#supplementary-runtime-key-size-and-provenance-check-android-and-ios) that verifies the size of keys as they are actually generated and also catches weak entropy and plaintext export, which neither OWASP test covers.

### MASTG-TEST-0208: Insufficient Key Sizes (Android)

Source: [MASTG-TEST-0208](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0208/). Platform: Android. Type: static (code). Related knowledge: MASTG-KNOW-0012.

#### Overview

The test finds every place where the app generates a key and checks the size it requests against current guidance. The relevant APIs are the JCA classes `KeyGenerator` (symmetric and HMAC keys, sized with `init(int)`) and `KeyPairGenerator` (RSA, EC, DSA, DH, sized with `initialize(int)`), plus the keystore-specific `KeyGenParameterSpec.Builder.setKeySize` and the `RSAKeyGenParameterSpec`/`ECGenParameterSpec` classes, which the OWASP test text does not mention but which you must include.

#### Prerequisites

- The APK, or all split APKs, for the build under test: `adb shell pm path com.example.app`, then `adb pull` each path.
- `jadx` for decompilation (OWASP technique MASTG-TECH-0013, "Reverse Engineering Android Apps", which in practice means decompiling DEX to Java) and `semgrep` (MASTG-TOOL-0110) plus `grep` for the code search (MASTG-TECH-0014, "Static Analysis on Android").
- Optional: `radare2` or Ghidra for native libraries, and a rooted device or emulator with `frida-server` for the runtime check later in this note.

#### Steps

1. **Decompile the app.** jadx output is Java even when the source was Kotlin, which is why the rules below target Java.

   ```bash
   jadx --deobf -d out/ app.apk
   ```

2. **Run the OWASP rule.** This is the rule MASTG-DEMO-0012 uses:

   ```yaml
   rules:
     - id: mastg-android-key-generation-with-insufficient-key-length
       severity: WARNING
       languages:
         - java
       metadata:
         summary: This rule looks for methods that create keys with insufficient length in encryption algorithms.
       message: "[MASVS-CRYPTO] Make sure that the key size is according to security best practices"
       pattern-either:
         - pattern: |
             $K = $G.getInstance("RSA");
             ...
             $K.initialize(1024, new SecureRandom());
         - pattern: |
             $K = $G.getInstance("RSA");
             ...
             $K.initialize(512, new SecureRandom());
         - pattern: |
             $K = $G.getInstance("AES");
             ...
             $K.init(128);
   ```

   ```bash
   semgrep -c mastg-android-key-generation-with-insufficient-key-length.yml out/sources/
   ```

   Understand its limits before you rely on it: it only matches RSA sizes of exactly 512 or 1024 and only when a `new SecureRandom()` is passed (so `initialize(1024)` alone is missed), it does not look at `KeyGenParameterSpec`, EC curves, DES/3DES or HMAC keys, and it flags AES-128, which we treat as an observation (see [key sizes](#both-platforms-key-sizes-and-security-strength-supplementary)).

3. **Run a wider rule set.** These rules use semgrep's `metavariable-comparison`, which works because the compiler and jadx turn constants into literals:

   ```yaml
   rules:
     - id: gt-weak-asymmetric-keysize
       languages: [java]
       severity: WARNING
       message: RSA/DSA/DH key generated with fewer than 2048 bits
       patterns:
         - pattern: |
             $G = KeyPairGenerator.getInstance($ALG, ...);
             ...
             $G.initialize($N, ...);
         - metavariable-regex:
             metavariable: $ALG
             regex: (RSA|DSA|DH|DiffieHellman)
         - metavariable-comparison:
             metavariable: $N
             comparison: $N < 2048
     - id: gt-weak-rsa-spec
       languages: [java]
       severity: WARNING
       message: RSAKeyGenParameterSpec with a modulus below 2048 bits
       patterns:
         - pattern: new RSAKeyGenParameterSpec($N, ...)
         - metavariable-comparison:
             metavariable: $N
             comparison: $N < 2048
     - id: gt-weak-ec-curve
       languages: [java]
       severity: WARNING
       message: Weak elliptic curve requested
       patterns:
         - pattern: new ECGenParameterSpec($CURVE)
         - metavariable-regex:
             metavariable: $CURVE
             regex: (112|128|160|192|239)
     - id: gt-legacy-symmetric-keygen
       languages: [java]
       severity: WARNING
       message: Key generated for a legacy symmetric algorithm
       patterns:
         - pattern: KeyGenerator.getInstance($ALG, ...)
         - metavariable-regex:
             metavariable: $ALG
             regex: (DES|DESede|TripleDES|Blowfish|RC2|RC4|ARC4)
     - id: gt-keystore-keysize-inventory
       languages: [java]
       severity: INFO
       message: Explicit key size in KeyGenParameterSpec - check against the algorithm
       pattern: $B.setKeySize($N)
   ```

   ```bash
   semgrep -c gt-keysize.yml out/sources/ --exclude 'androidx' --exclude 'kotlin' --exclude 'com/google'
   ```

   The last rule is an inventory, not a verdict: `setKeySize(256)` is correct for AES and EC and badly wrong if the algorithm turns out to be RSA. Read the builder chain or the surrounding `getInstance` call for each hit.

4. **Grep for what the rules cannot see.** Sizes passed through a variable, sizes in Kotlin `companion object` constants that were not inlined, and generation in third-party SDKs:

   ```bash
   grep -rnE '(KeyGenerator|KeyPairGenerator)\.getInstance|\.(init|initialize|setKeySize)\(|RSAKeyGenParameterSpec|ECGenParameterSpec' out/sources/ \
     | grep -vE '^out/sources/(androidx|kotlin|kotlinx)/' > keygen-candidates.txt
   grep -nE '\((512|768|1024|56|64|80|112|168)[,)]' keygen-candidates.txt
   ```

5. **Check native code.** If the app ships OpenSSL, BoringSSL or its own crypto in `lib/`, look for key generation there:

   ```bash
   unzip -o app.apk 'lib/arm64-v8a/*' -d native/
   for so in native/lib/arm64-v8a/*.so; do
     hits=$(nm -D "$so" 2>/dev/null | grep -E 'RSA_generate_key_ex|EVP_PKEY_CTX_set_rsa_keygen_bits|EVP_PKEY_keygen|EC_KEY_generate_key|DES_set_key')
     [ -n "$hits" ] && printf '== %s\n%s\n' "$so" "$hits"
   done
   ```

   For a library that calls `EVP_PKEY_CTX_set_rsa_keygen_bits` (OpenSSL 3; in OpenSSL 1.1 it is a macro over `EVP_PKEY_CTX_ctrl`, so look for that instead), open it in radare2 (`r2 -A libfoo.so`, `axt @ sym.imp.EVP_PKEY_CTX_set_rsa_keygen_bits`) and read the immediate loaded into `w1` before the call.

6. **Trace each hit to its use.** Note what the key protects (follow it to `Cipher.init`, `Signature.initSign`, `Mac.init`, or to the network if the public key is registered with a server) and whether the code path is reachable in the release build. A weak key in an unused SDK sample is not the same finding as a weak device-binding key.

#### Observation

A list of key-generation sites, each with: class and method, decompiled line, algorithm, requested size or curve, provider (`AndroidKeyStore` or software), whether StrongBox is requested and what the fallback does, and what the key is used for. Keep the semgrep output as evidence.

#### Evaluation

The test **fails** if the app generates, for a security-relevant purpose, any of:

- an RSA, DSA or finite-field DH key smaller than 2048 bits;
- an EC key on a curve smaller than 224 bits;
- a DES or two-key Triple DES key, or a three-key Triple DES key used to encrypt new data;
- an HMAC key shorter than 112 bits (we recommend reporting anything shorter than 128 bits);
- a key whose size is chosen at runtime from a value that can drop below these limits, for example a StrongBox fallback that lowers the size.

Report as **observations** (not failures) under our methodology: AES-128 (which OWASP's evaluation fails on quantum grounds), RSA-2048 or P-224 keys whose protection must last beyond 2030, and key generation with no explicit size where the resulting default is adequate. If the client applies OWASP's evaluation literally, say so and fail AES-128 too.

The test **passes** when every security-relevant key meets the sizes above. Common false positives: test and sample code in SDKs that is never called, key generation in debug-only classes, and `setKeySize(256)` on AES or EC keys flagged by an over-broad rule.

#### Demo

From [MASTG-DEMO-0012](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0012/MASTG-DEMO-0012/). The vulnerable Kotlin generates one RSA key pair and two AES keys:

```kotlin
val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA)
generator.initialize(1024, SecureRandom())      // 1024-bit RSA: insufficient
val keypair = generator.genKeyPair()

val keyGen1 = KeyGenerator.getInstance("AES")
keyGen1.init(128)                                // AES-128: OWASP fails this
val secretKey1: SecretKey = keyGen1.generateKey()

val keyGen2 = KeyGenerator.getInstance("AES")
keyGen2.init(256)                                // AES-256: fine
val secretKey2: SecretKey = keyGen2.generateKey()
```

After jadx, `KeyProperties.KEY_ALGORITHM_RSA` has been inlined to `"RSA"` and the sizes are plain literals:

```java
KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
generator.initialize(1024, new SecureRandom());
KeyPair keypair = generator.genKeyPair();
KeyGenerator keyGen1 = KeyGenerator.getInstance("AES");
keyGen1.init(128);
SecretKey secretKey1 = keyGen1.generateKey();
```

Running `semgrep -c ../../../../rules/mastg-android-key-generation-with-insufficient-key-length.yml ./MastgTest_reversed.java`:

```text
┌─────────────────┐
│ 2 Code Findings │
└─────────────────┘

    MastgTest_reversed.java
    ❯❱ rules.mastg-android-key-generation-with-insufficient-key-length
          [MASVS-CRYPTO] Make sure that the key size is according to security best practices

           27┆ KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
           28┆ generator.initialize(1024, new SecureRandom());
            ⋮┆----------------------------------------
           31┆ KeyGenerator keyGen1 = KeyGenerator.getInstance("AES");
           32┆ keyGen1.init(128);
```

OWASP fails the test on both hits. Under our methodology the RSA-1024 key on lines 27–28 is the vulnerability and the AES-128 key on lines 31–32 is an observation. Our `gt-weak-asymmetric-keysize` rule also catches lines 27–28, and would still catch them if the `SecureRandom` argument were removed, which the OWASP rule would not. Two further points the demo illustrates without stating: all three keys are generated by software providers, so their bytes sit on the Java heap (a [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/) concern if they are kept), and the demo logs the RSA public key — harmless for a public key, but the same `Log.d` pattern around `secretKey1.encoded` would be a plaintext export.

### MASTG-TEST-0209: Insufficient Key Sizes (iOS)

Source: [MASTG-TEST-0209](https://mas.owasp.org/MASTG/tests/ios/MASVS-CRYPTO/MASTG-TEST-0209/). Platform: iOS. Type: static (code).

#### Overview

The test finds calls that generate or size keys in the app binary and reads the size they use. Without source code that means disassembly. The OWASP test concentrates on the Security framework (`SecKeyCreateRandomKey` and the deprecated `SecKeyGeneratePair`, sized by `kSecAttrKeySizeInBits`) and CommonCrypto (`CCCrypt`, sized by its `keyLength` argument), and leaves CryptoKit aside because CryptoKit generates fixed-size keys for you. We add a CryptoKit symbol check because `SymmetricKeySize(bitCount:)` does allow short keys.

#### Prerequisites

- A **decrypted** IPA. App Store binaries are FairPlay-encrypted; `otool -l Payload/App.app/App | grep -A4 LC_ENCRYPTION_INFO` showing `cryptid 1` means you must decrypt it first on a jailbroken device. Builds supplied directly by the developer are usually not encrypted.
- radare2 (MASTG-TOOL-0073), and on macOS `nm`, `otool` and `xcrun swift-demangle`.
- Optional: a jailbroken device with `frida-server` for the runtime check later in this note.

#### Steps

1. **Extract the binaries** (MASTG-TECH-0058, "Exploring the App Package"). The main executable has the bundle name without `.app`; embedded frameworks and app extensions need the same treatment.

   ```bash
   unzip -q App.ipa -d ipa/
   BIN=ipa/Payload/App.app/App
   ls ipa/Payload/App.app/Frameworks/ ipa/Payload/App.app/PlugIns/ 2>/dev/null
   ```

2. **Check which key APIs are imported.**

   ```bash
   nm -u "$BIN" | grep -E 'SecKeyCreateRandomKey|SecKeyGeneratePair|SecRandomCopyBytes|CCCrypt|CCCryptorCreate|CCHmac'
   nm -u "$BIN" | grep -E 'kSecAttrKeySizeInBits|kSecAttrKeyType|kSecAttrTokenIDSecureEnclave'
   nm -u "$BIN" | xcrun swift-demangle | grep -E 'SymmetricKeySize|SymmetricKey\.init\(size' | sort -u
   ```

   An imported `kSecAttrKeySizeInBits` with `SecKeyCreateRandomKey` means the app sets an explicit size somewhere; `SymmetricKeySize.init(bitCount:)` means a non-standard CryptoKit key size is in play.

3. **Find the call sites in radare2** (MASTG-TECH-0066, "Static Analysis on iOS"): list the import stub, then its cross-references.

   ```text
   r2 -A ipa/Payload/App.app/App
   [0x...]> afl~SecKeyCreateRandomKey
   [0x...]> axt @ sym.imp.SecKeyCreateRandomKey
   [0x...]> pdf @ <calling function>
   ```

4. **Read the size.** In the calling function, find where `kSecAttrKeySizeInBits` is loaded (radare2 shows it as `reloc.kSecAttrKeySizeInBits`, a relocation resolved by the dynamic linker) and the immediate stored next to it. Sizes you will see as immediates:

   | Bits | Immediate | Typical instruction |
   |---|---|---|
   | 256 | `0x100` | `mov w8, 0x100` |
   | 1024 | `0x400` | `mov w8, 0x400` |
   | 2048 | `0x800` | `mov w8, 0x800` |
   | 3072 | `0xc00` | `mov w8, 0xc00` |
   | 4096 | `0x1000` | `mov w8, 0x1000` |

   Also find the `kSecAttrKeyType` value (`reloc.kSecAttrKeyTypeRSA` or `reloc.kSecAttrKeyTypeECSECPrimeRandom`) to know which table the size belongs to. In Objective-C code the size often arrives as an `NSNumber`, either from `numberWithInt:` (look for the size loaded into the argument register before the `objc_msgSend`) or from a boxed literal such as `@2048`.

5. **For CommonCrypto**, find `CCCrypt` call sites and read the second argument (algorithm, `w1`) and the fifth (`keyLength`, `x4`): `mov w1, 1` is DES, `mov w1, 2` is 3DES, `mov x4, 0x10` is a 16-byte key. Then follow the key pointer (`x3`) back to see how the buffer was filled — `SecRandomCopyBytes`, a constant in `__const`, or a password string.

   ```text
   [0x...]> axt @ sym.imp.CCCrypt
   [0x...]> pd-- 20 @ <call address>
   ```

6. **For CryptoKit**, if step 2 showed `SymmetricKeySize.init(bitCount:)`, find its call sites the same way and read the integer passed in `x0`.

7. **Repeat for every framework and extension** in the bundle. Third-party SDKs in `Frameworks/` generate their own keys.

#### Observation

The disassembly around each key-generation call, showing the key type and size, with the function address. For CommonCrypto, the algorithm and `keyLength` values and where the key buffer came from.

#### Evaluation

The test **fails** if a security-relevant key is generated with an RSA modulus below 2048 bits, an EC size below 224 bits (iOS does not normally offer these, but third-party libraries can), a DES or 2TDEA key, a 3TDEA key for new encryption, or an HMAC key below 112 bits. As on Android, we report AES-128 (`kCCKeySizeAES128`, `.bits128`) as an observation unless the client requires OWASP's stricter reading, and RSA-2048 as an observation for keys with a protection horizon beyond 2030.

Inspect each hit by reviewing the disassembly (MASTG-TECH-0076) to confirm that the call is reached and that the value really is the size used — Swift dictionaries are built through several helper calls and the immediate is not always adjacent to the key it belongs to.

#### Demo

From [MASTG-DEMO-0011](https://mas.owasp.org/MASTG/demos/ios/MASVS-CRYPTO/MASTG-DEMO-0011/MASTG-DEMO-0011/). The sample generates a permanent 1024-bit RSA key pair in the Keychain, exports both halves, and signs a message:

```swift
let tag = "org.owasp.mas.rsa-1014".data(using: .utf8)!
let keyAttributes: [String: Any] = [
    kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
    kSecAttrKeySizeInBits as String: 1024,            // insufficient
    kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: tag
    ]
]
var error: Unmanaged<CFError>?
guard let privateKey = SecKeyCreateRandomKey(keyAttributes as CFDictionary, &error) else { return }
let privateKeyData = SecKeyCopyExternalRepresentation(privateKey, &error) as Data?   // exports the private key
```

The radare2 script, run with `r2 -q -i security_keysize.r2 -A MASTestApp`:

```text
?e Uses of SecKeyCreateRandomKey:
afl~SecKeyCreateRandomKey
?e xrefs to SecKeyCreateRandomKey:
axt @ 0x1000078ac
?e Use of reloc.kSecAttrKeySizeInBits as input for SecKeyCreateRandomKey:
pd 1 @ sym.func.1000046f8
pd 9 @ 0x10000484c
pd-- 2 @ 0x1000049a0
```

Relevant output:

```text
Uses of SecKeyCreateRandomKey:
0x1000078ac    1     12 sym.imp.SecKeyCreateRandomKey

xrefs to SecKeyCreateRandomKey:
sym.func.1000046f8 0x1000049a0 [CALL:--x] bl sym.imp.SecKeyCreateRandomKey

│   0x10000484c      080942f9       ldr x8, reloc.kSecAttrKeySizeInBits ; 0x10000c410
│   0x100004850      000140f9       ldr x0, [x8]
│   0x100004854      e30b0094       bl fcn.1000077e0
│   0x100004858      800605a9       stp x0, x1, [x20, 0x50]
│   0x10000485c      48000090       adrp x8, reloc.Foundation.__DataStorage._bytes.allocator__UnsafeMutableRawPointer______ ; 0x10000c000
│   0x100004860      089d41f9       ldr x8, reloc.Swift.Int    ; 0x10000c338
│   0x100004864      883e00f9       str x8, [x20, 0x78]
│   0x100004868      08808052       mov w8, 0x400
│   0x10000486c      883200f9       str x8, [x20, 0x60]
...
│   0x1000049a0      c30b0094       bl sym.imp.SecKeyCreateRandomKey
```

Reading it: the binary has one call to `SecKeyCreateRandomKey`, inside `sym.func.1000046f8`. At `0x10000484c` the code loads the `kSecAttrKeySizeInBits` constant through its relocation and converts it to a Swift dictionary key (`bl fcn.1000077e0`, stored at `[x20, 0x50]`). It then stores the type metadata for `Swift.Int` (`[x20, 0x78]`) and the value `0x400` (`[x20, 0x60]`) — the dictionary's value slot holding the integer 1024. That dictionary is what reaches `SecKeyCreateRandomKey` at `0x1000049a0`. The test fails: 1024-bit RSA is below the 2048-bit minimum.

The demo also contains a second MASWE-0013 problem that the OWASP test does not call out: `SecKeyCopyExternalRepresentation` on the private key, whose hex is then returned to the UI. A Keychain key that the app exports and displays is no longer protected by the Keychain. Searching for `SecKeyCopyExternalRepresentation` call sites, and checking whether their argument is a private key, is part of our supplementary check below.

### Supplementary: runtime key-size and provenance check (Android and iOS)

Guler Tech methodology. Not an OWASP test. It complements MASTG-TEST-0208 and MASTG-TEST-0209.

#### Overview

Static rules miss sizes computed at runtime, keys generated in native code or obfuscated SDKs, and fallbacks that only run on some devices. This check hooks the key-generation APIs while you use the app, records the algorithm, size, provider and RNG for each key actually created, and verifies the result (modulus length, `KeyInfo`, `SecKeyGetBlockSize`). It also flags two generation-time problems the OWASP tests do not cover: caller-supplied RNGs, and plaintext export of private or secret keys.

#### Prerequisites

- Android: a rooted device or emulator with `frida-server` matching your Frida version (the scripts use Frida 17 syntax), the app installed. Run the test on a device **with** StrongBox (for example a recent Pixel) and one **without**, so you see both branches of any fallback.
- iOS: a jailbroken device with `frida-server` and the app installed.
- A list of the app's key-dependent features from the static tests, so you know what to exercise (login, device registration, enabling biometrics, creating a vault, first launch after install).

#### Steps

1. **Android: hook the generators.** Save as `keygen-android.js`:

   ```javascript
   // keygen-android.js - log key generation parameters and results (Frida 17)
   Java.perform(function () {
     const Log = Java.use('android.util.Log');
     const Exc = Java.use('java.lang.Exception');
     const RSAPub = Java.use('java.security.interfaces.RSAPublicKey');
     const ECPub = Java.use('java.security.interfaces.ECPublicKey');
     const where = function () {
       return Log.getStackTraceString(Exc.$new()).split('\n').slice(2, 6).join(' | ');
     };

     // Symmetric keys: KeyGenerator is a concrete class, so hooking it catches every provider
     const KG = Java.use('javax.crypto.KeyGenerator');
     KG.init.overload('int').implementation = function (n) {
       console.log('[KeyGenerator.init] ' + this.getAlgorithm() + ' size=' + n + ' provider=' + this.getProvider().getName());
       return this.init(n);
     };
     KG.init.overload('int', 'java.security.SecureRandom').implementation = function (n, rng) {
       console.log('[KeyGenerator.init] ' + this.getAlgorithm() + ' size=' + n + ' rng=' + rng.$className + ' (' + rng.getAlgorithm() + ')');
       return this.init(n, rng);
     };
     KG.generateKey.implementation = function () {
       const k = this.generateKey();
       const enc = k.getEncoded();
       console.log('[KeyGenerator.generateKey] ' + k.getAlgorithm() + ' provider=' + this.getProvider().getName() +
         (enc ? ' SOFTWARE key, ' + enc.length * 8 + ' bits' : ' keystore key (no encoded form)') + '\n    at ' + where());
       return k;
     };

     // Keystore specs: what the app asked the keystore for
     const B = Java.use('android.security.keystore.KeyGenParameterSpec$Builder');
     B.build.implementation = function () {
       const s = this.build();
       let sb = 'n/a';
       try { sb = s.isStrongBoxBacked(); } catch (e) {}
       console.log('[KeyGenParameterSpec] alias=' + s.getKeystoreAlias() + ' keySize=' + s.getKeySize() +
         ' params=' + s.getAlgorithmParameterSpec() + ' purposes=' + s.getPurposes() + ' strongBox=' + sb);
       return s;
     };

     // Key pairs: getInstance returns a subclass, so hook the subclass that does the work
     ['java.security.KeyPairGenerator$Delegate', 'java.security.KeyPairGenerator'].forEach(function (cn) {
       let C;
       try { C = Java.use(cn); } catch (e) { return; }
       try {
         C.initialize.overload('int', 'java.security.SecureRandom').implementation = function (n, rng) {
           console.log('[' + cn + '.initialize] ' + this.getAlgorithm() + ' size=' + n + ' rng=' + (rng ? rng.$className : 'null'));
           return this.initialize(n, rng);
         };
       } catch (e) {}
       try {
         C.generateKeyPair.implementation = function () {
           const kp = this.generateKeyPair();
           const pub = kp.getPublic();
           let bits = '?';
           if (RSAPub.class.isInstance(pub)) bits = Java.cast(pub, RSAPub).getModulus().bitLength() + '-bit RSA';
           else if (ECPub.class.isInstance(pub)) bits = Java.cast(pub, ECPub).getParams().getCurve().getField().getFieldSize() + '-bit EC';
           console.log('[' + cn + '.generateKeyPair] ' + this.getAlgorithm() + ' ' + bits +
             ' provider=' + this.getProvider().getName() + '\n    at ' + where());
           return kp;
         };
       } catch (e) {}
     });

     // Seeded SecureRandom: a fixed seed can make keys reproducible
     const SR = Java.use('java.security.SecureRandom');
     SR.$init.overload('[B').implementation = function (seed) {
       console.log('[SecureRandom(seed)] seed length=' + seed.length + '\n    at ' + where());
       return this.$init(seed);
     };
     SR.setSeed.overload('[B').implementation = function (seed) {
       console.log('[SecureRandom.setSeed] length=' + seed.length + '\n    at ' + where());
       return this.setSeed(seed);
     };
   });
   ```

   ```bash
   adb shell pm clear com.example.app
   frida -U -f com.example.app -l keygen-android.js
   ```

   Exercise every key-dependent feature. Then clear data and repeat, so you capture first-run generation twice.

   The `KeyPairGenerator` hooks cover providers that are wrapped by the JDK's internal `Delegate` class (Conscrypt, `AndroidKeyStore`). A provider that subclasses `KeyPairGenerator` directly — Bouncy Castle's bundled copies do — is not wrapped; if you see key pairs used but no log lines, print `generator.$className` from a `getInstance` hook and add that class to the list.

2. **Android: verify the keys that ended up in the keystore.** With the app running, attach and enumerate its aliases (keystore aliases are per app UID, so this must run inside the app):

   ```javascript
   // keystore-inventory.js
   Java.perform(function () {
     const KS = Java.use('java.security.KeyStore');
     const KeyInfo = Java.use('android.security.keystore.KeyInfo');
     const SecretKey = Java.use('javax.crypto.SecretKey');
     const SKF = Java.use('javax.crypto.SecretKeyFactory');
     const KF = Java.use('java.security.KeyFactory');
     const ks = KS.getInstance('AndroidKeyStore');
     ks.load.overload('java.security.KeyStore$LoadStoreParameter').call(ks, null);
     const aliases = ks.aliases();
     while (aliases.hasMoreElements()) {
       const alias = aliases.nextElement().toString();
       const key = ks.getKey(alias, null);
       if (key === null) { console.log(alias + ': certificate only'); continue; }
       const spec = SecretKey.class.isInstance(key)
         ? SKF.getInstance(key.getAlgorithm(), 'AndroidKeyStore').getKeySpec(key, KeyInfo.class)
         : KF.getInstance(key.getAlgorithm(), 'AndroidKeyStore').getKeySpec(key, KeyInfo.class);
       const info = Java.cast(spec, KeyInfo);
       let level = 'n/a';
       try { level = info.getSecurityLevel(); } catch (e) { level = 'secureHw=' + info.isInsideSecureHardware(); }
       console.log(alias + ': ' + key.getAlgorithm() + ' ' + info.getKeySize() + ' bits, purposes=' +
         info.getPurposes() + ', securityLevel=' + level + ', origin=' + info.getOrigin());
     }
   });
   ```

   ```bash
   frida -U -p "$(adb shell pidof com.example.app)" -l keystore-inventory.js
   ```

   `getSecurityLevel()` returns 0 (software), 1 (TEE) or 2 (StrongBox). `getOrigin()` returns 1 (`ORIGIN_GENERATED`) for keys generated in the keystore and 2 (`ORIGIN_IMPORTED`) for keys imported in plaintext; 8 (`ORIGIN_SECURELY_IMPORTED`) means wrapped import and 4 means unknown. An `ORIGIN_IMPORTED` key is your evidence for the "generated outside, then imported" mode.

3. **iOS: hook the generators and exporters.** Save as `keygen-ios.js`:

   ```javascript
   // keygen-ios.js - log SecKey generation, export, random bytes and CCCrypt key lengths (Frida 17)
   const sec = Process.getModuleByName('Security');
   const cc = Process.getModuleByName('libcommonCrypto.dylib');
   const blockSize = new NativeFunction(sec.getExportByName('SecKeyGetBlockSize'), 'size_t', ['pointer']);
   const cfstr = function (name) { return new ObjC.Object(sec.getExportByName(name).readPointer()).toString(); };
   console.log('kSecAttrKeySizeInBits=' + cfstr('kSecAttrKeySizeInBits') + ' kSecAttrKeyType=' + cfstr('kSecAttrKeyType') +
     ' RSA=' + cfstr('kSecAttrKeyTypeRSA') + ' EC=' + cfstr('kSecAttrKeyTypeECSECPrimeRandom'));

   Interceptor.attach(sec.getExportByName('SecKeyCreateRandomKey'), {
     onEnter(args) { console.log('[SecKeyCreateRandomKey] ' + new ObjC.Object(args[0]).toString()); },
     onLeave(ret) {
       if (!ret.isNull()) console.log('    -> block size ' + blockSize(ret) + ' bytes');
     }
   });
   Interceptor.attach(sec.getExportByName('SecKeyCopyExternalRepresentation'), {
     onEnter(args) {
       const attrs = new NativeFunction(sec.getExportByName('SecKeyCopyAttributes'), 'pointer', ['pointer'])(args[0]);
       console.log('[SecKeyCopyExternalRepresentation] key attrs: ' + new ObjC.Object(attrs).toString());
       console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).slice(0, 5).join('\n'));
     }
   });
   Interceptor.attach(sec.getExportByName('SecRandomCopyBytes'), {
     onEnter(args) { this.n = args[1].toUInt32(); },
     onLeave(ret) { console.log('[SecRandomCopyBytes] ' + this.n + ' bytes, status=' + ret.toInt32()); }
   });
   Interceptor.attach(cc.getExportByName('CCCrypt'), {
     onEnter(args) {
       console.log('[CCCrypt] op=' + args[0].toInt32() + ' alg=' + args[1].toInt32() + ' keyLength=' + args[4].toUInt32());
     }
   });
   ```

   ```bash
   frida -U -f com.example.app -l keygen-ios.js
   ```

   In the `SecKeyCopyExternalRepresentation` output, the attributes dictionary contains `kcls` (key class): `1` is a private key, `0` a public key. A private-key export is what you are looking for. The `SecRandomCopyBytes` hook shows how many bytes the app requests for keys it builds itself (16 or 32 for AES keys) and whether it checks the status.

4. **Correlate.** For each key logged, match it to a feature and to its later use. For a software key on Android, the `generateKey` log line also says so explicitly; follow its bytes (MASWE-0003 tests) to see if they are stored or sent anywhere.

5. **Compare runs.** For keys built from app-filled buffers, record the bytes from two fresh installs (the MASWE-0003 `SecretKeySpec` and `CCCrypt` hooks print them). Identical or similar values across installs mean the "random" key is not random.

#### Observation

A table of every key generated during the session: platform, feature, algorithm, requested and actual size, provider or token (software, TEE, StrongBox, Keychain, Secure Enclave), origin (generated or imported), RNG passed in (if any), and whether the key was exported and in what form. Keep the Frida logs with timestamps.

#### Evaluation

The check **fails** if any security-relevant key generated at runtime:

- is smaller than the sizes in the MASTG-TEST-0208/0209 evaluations, including on a fallback path that only some devices take;
- was generated with a seeded or non-cryptographic RNG, or from a buffer filled by anything other than the platform CSPRNG;
- is a private or secret key exported in plaintext (`getEncoded()` bytes sent, logged or stored; `SecKeyCopyExternalRepresentation` on a private key) when the design does not require export, or without wrapping when it does;
- shows `ORIGIN_IMPORTED` on Android, or is created on iOS with `SecKeyCreateWithData`/`SymmetricKey(data:)` from locally generated bytes, when it could have been generated in the keystore (report under MASWE-0003 and reference it here).

It **passes** if every key is generated by the platform keystore or CryptoKit with adequate size, no custom RNG is involved, and no private or secret key leaves its protected store in plaintext. A software-generated key is not a failure of *this* check by itself if it is immediately wrapped or used only in memory, but note it for MASWE-0003.

#### Demo

Running `keygen-android.js` against the MASTG-DEMO-0012 sample gives output of this shape (illustrative and abridged; provider names and stack frames vary by Android version):

```text
[java.security.KeyPairGenerator$Delegate.initialize] RSA size=1024 rng=java.security.SecureRandom
[java.security.KeyPairGenerator$Delegate.generateKeyPair] RSA 1024-bit RSA provider=AndroidOpenSSL
    at org.owasp.mastestapp.MastgTest.mastgTest(MastgTest.kt:18) | ...
[KeyGenerator.init] AES size=128 provider=BC
[KeyGenerator.generateKey] AES provider=BC SOFTWARE key, 128 bits
    at org.owasp.mastestapp.MastgTest.mastgTest(MastgTest.kt:23) | ...
[KeyGenerator.init] AES size=256 provider=BC
[KeyGenerator.generateKey] AES provider=BC SOFTWARE key, 256 bits
    at org.owasp.mastestapp.MastgTest.mastgTest(MastgTest.kt:27) | ...
```

Whatever the provider names, the verdict is the same: one 1024-bit RSA key (fail), and two software AES keys (the 128-bit one is an observation; both are MASWE-0003 candidates if they are kept). On iOS, the MASTG-DEMO-0011 sample should log a dictionary containing `bsiz = 1024; type = 42;`, a block size of 128 bytes (1024 bits), and then two `SecKeyCopyExternalRepresentation` calls, the first with `kcls = 1` — the private key being exported.

## Secure implementation

These patterns generate keys of adequate size, inside secure hardware where available, without the app ever holding the key bytes. They complement the storage patterns in [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/#secure-implementation). OWASP's related best practices are [MASTG-BEST-0001](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0001/) and [MASTG-BEST-0025](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0025/) (use the platform CSPRNG) and [MASTG-BEST-0009](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0009/) (use secure encryption algorithms).

### Android: AES-256 and EC P-256 in the keystore, StrongBox first

```kotlin
import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

private const val KEYSTORE = "AndroidKeyStore"

fun generateAesKey(context: Context, alias: String): SecretKey {
    fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(
        alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    )
        .setKeySize(256)                                   // explicit, StrongBox supports it
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setIsStrongBoxBacked(strongBox)
        .build()

    val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
    val hasStrongBox = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
    if (hasStrongBox) {
        try {
            kg.init(spec(strongBox = true))
            return kg.generateKey()
        } catch (e: StrongBoxUnavailableException) {
            // fall through to the TEE with the SAME parameters
        }
    }
    kg.init(spec(strongBox = false))
    return kg.generateKey()
}

fun generateSigningKey(alias: String, strongBox: Boolean) {
    val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))   // P-256, 128-bit security
        .setDigests(KeyProperties.DIGEST_SHA256)
        .setIsStrongBoxBacked(strongBox)
        .build()
    KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE).run {
        initialize(spec)
        generateKeyPair()
    }
}
```

Points that matter for review: the size is stated, the fallback keeps the same parameters, there is no `SecureRandom` argument, and no `getEncoded()` call (it would return `null` anyway). If you need RSA, use `setKeySize(3072)` in the TEE, or accept `2048` in StrongBox with a documented 2030 horizon. To let the server check what was generated, add `setAttestationChallenge(serverNonce)` to the signing key and send `KeyStore.getCertificateChain(alias)`.

### Android: a software key you cannot avoid

When a key must exist outside the keystore (for example a data key shared with a server), generate it with the platform CSPRNG and an explicit size, wrap it immediately under a keystore key, and keep only the wrapped form:

```kotlin
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

fun newWrappedDataKey(kek: SecretKey): Pair<ByteArray, ByteArray> {
    val raw = ByteArray(32).also { SecureRandom().nextBytes(it) }   // 256-bit DEK, no seed
    try {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, kek)                        // kek lives in AndroidKeyStore
        return cipher.iv to cipher.doFinal(raw)                      // persist iv + wrapped DEK
    } finally {
        raw.fill(0)
    }
}

fun unwrapDataKey(kek: SecretKey, iv: ByteArray, wrapped: ByteArray): SecretKey {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.DECRYPT_MODE, kek, GCMParameterSpec(128, iv))
    return SecretKeySpec(cipher.doFinal(wrapped), "AES")
}
```

### iOS: Secure Enclave P-256, and RSA where it is unavoidable

```swift
import Security

func makeEnclaveSigningKey(tag: Data) throws -> SecKey {
    var error: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage], &error
    ) else { throw error!.takeRetainedValue() as Error }

    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,                       // the only Enclave size
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: tag,
            kSecAttrAccessControl as String: access
        ]
    ]
    guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        throw error!.takeRetainedValue() as Error
    }
    return key
}

func makeRsaKey(tag: Data) throws -> SecKey {
    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
        kSecAttrKeySizeInBits as String: 3072,                      // 128-bit security, past 2030
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: tag,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
    ]
    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        throw error!.takeRetainedValue() as Error
    }
    return key
}
```

Send the server `SecKeyCopyExternalRepresentation(SecKeyCopyPublicKey(key)!, &error)` — the **public** key — never the private one.

### iOS: CryptoKit symmetric keys and wrapping for export

```swift
import CryptoKit

let dataKey = SymmetricKey(size: .bits256)          // CSPRNG-backed, explicit size

// If the key must leave the device (backup, second device), wrap it first.
func exportWrapped(_ key: SymmetricKey, kek: SymmetricKey) throws -> Data {
    try AES.KeyWrap.wrap(key, using: kek)           // RFC 3394; kek itself stays protected
}

func importWrapped(_ blob: Data, kek: SymmetricKey) throws -> SymmetricKey {
    try AES.KeyWrap.unwrap(blob, using: kek)
}
```

Where does the KEK come from? On a single device, from a Secure Enclave key via ECIES (the envelope pattern in [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/#ios-envelope-encryption-with-a-secure-enclave-kek)); across devices, from a key agreement with the receiving device's attested key, or from a user passphrase run through a proper KDF ([MASWE-0014](/mobile/maswe-0014-improper-key-derivation/)).

### Both platforms: a review checklist for key generation

- Algorithm and size stated explicitly in code, and meeting the [tables above](#both-platforms-key-sizes-and-security-strength-supplementary).
- No caller-supplied RNG; no key bytes from anything but the platform CSPRNG or the keystore.
- Generated inside the keystore, StrongBox or Secure Enclave unless there is a written reason not to; fallbacks keep the same strength.
- Purposes limited to what the key does; access control set at generation time.
- No plaintext export of private or secret keys; wrapping where export is required.
- Attestation checked server-side where the backend trusts the key's properties.
- A plan for replacing keys with a 2030 horizon (RSA-2048, P-224) and for post-quantum migration of long-lived asymmetric keys.

## Rating findings

Rate on what the key protects, how the attacker gets material to attack (ciphertext, signatures, public key), and how much work the weakness actually saves them. Use these as starting points and adjust for context.

| Rating | Conditions |
|---|---|
| **Critical** | A key that can be reproduced or recovered cheaply and protects something the backend trusts or data at scale: keys from a seeded, time-based or non-cryptographic RNG; RSA-512 or RSA-768 keys used for signing, authentication or key transport; DES keys protecting credentials or tokens in transit or in shared storage. The attacker needs only the public key, a signature or captured ciphertext. |
| **High** | RSA-1024, DSA-1024 or EC keys under 224 bits used for device binding, transaction signing, licence verification or protecting sensitive data; a private key generated and then exported in plaintext (sent, logged or stored in app data); two-key Triple DES for sensitive data. |
| **Medium** | Three-key Triple DES generated for new encryption; HMAC keys between 64 and 111 bits; a StrongBox fallback that lowers the key size or switches to a software provider; a key generated in software and imported in plaintext when it could have been generated in the keystore (cross-reference MASWE-0003). |
| **Low** | RSA-2048 or P-224 keys whose protection must extend beyond 2030 (long-term archives, identity keys, root signing keys) with no replacement plan; key purposes broader than needed; RSA public exponent 3; keys of adequate size whose size depends on an unpinned provider default. |
| **Info** | AES-128 (fails OWASP's evaluation; approved by NIST); RSA-2048 short-lived keys; adequate keys generated in software and used only in memory; weak sizes in unreachable SDK or test code. |

In the report, give the exact call site (class and line, or function address), the requested and observed sizes, the standard that sets the minimum (SP 800-57 Part 1 Rev. 5 / SP 800-131A Rev. 2), what the key protects, and how the attacker obtains the material needed to attack it. For RSA, include the public modulus length from runtime evidence rather than only the static value. For RNG-based findings, the strongest evidence is two installs producing the same or predictably related keys.

## References

- OWASP MASWE — [MASWE-0013: Improper Cryptographic Key Generation](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0013/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0208: Insufficient Key Sizes (Android)](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0208/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0209: Insufficient Key Sizes (iOS)](https://mas.owasp.org/MASTG/tests/ios/MASVS-CRYPTO/MASTG-TEST-0209/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-DEMO-0012](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0012/MASTG-DEMO-0012/) and [MASTG-DEMO-0011](https://mas.owasp.org/MASTG/demos/ios/MASVS-CRYPTO/MASTG-DEMO-0011/MASTG-DEMO-0011/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0012: Key Generation](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0012/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-BEST-0001](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0001/), [MASTG-BEST-0009](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0009/), [MASTG-BEST-0025](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0025/) (CC BY-SA 4.0)
- OWASP MASTG — techniques [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/); tools [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/), [radare2 (MASTG-TOOL-0073)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/) (CC BY-SA 4.0)
- [NIST SP 800-57 Part 1 Rev. 5 — Recommendation for Key Management: Part 1 – General](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf)
- [NIST SP 800-131A Rev. 2 — Transitioning the Use of Cryptographic Algorithms and Key Lengths](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf)
- [NIST SP 800-175B Rev. 1 — Guideline for Using Cryptographic Standards in the Federal Government](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-175Br1.pdf)
- [NIST FIPS 186-5 — Digital Signature Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf)
- [NIST IR 8547 (initial public draft) — Transition to Post-Quantum Cryptography Standards](https://csrc.nist.gov/pubs/ir/8547/ipd)
- [BlueKrypt — Cryptographic Key Length Recommendation](https://www.keylength.com/)
- [Android Developers — Cryptography](https://developer.android.com/privacy-and-security/cryptography) and [Android Keystore system](https://developer.android.com/privacy-and-security/keystore)
- [Android Developers — `KeyGenerator`](https://developer.android.com/reference/javax/crypto/KeyGenerator), [`KeyPairGenerator`](https://developer.android.com/reference/java/security/KeyPairGenerator), [`KeyGenParameterSpec.Builder`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder), [`KeyInfo`](https://developer.android.com/reference/android/security/keystore/KeyInfo), [`KeyProtection`](https://developer.android.com/reference/kotlin/android/security/keystore/KeyProtection)
- [Android Developers — Weak PRNG](https://developer.android.com/privacy-and-security/risks/weak-prng)
- [Apple — `SecKeyCreateRandomKey`](https://developer.apple.com/documentation/security/1823694-seckeycreaterandomkey), [`kSecAttrKeySizeInBits`](https://developer.apple.com/documentation/security/ksecattrkeysizeinbits) and [Key generation attributes](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/key_generation_attributes)
- [Apple — CryptoKit `SymmetricKey`](https://developer.apple.com/documentation/cryptokit/symmetrickey) and [`AES.KeyWrap`](https://developer.apple.com/documentation/cryptokit/aes/keywrap)
- [Apple — `CCCrypt` man page](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/CCCrypt.3cc.html)
- [CWE-326](https://cwe.mitre.org/data/definitions/326.html), [CWE-331](https://cwe.mitre.org/data/definitions/331.html), [CWE-337](https://cwe.mitre.org/data/definitions/337.html), [CWE-338](https://cwe.mitre.org/data/definitions/338.html), [CWE-522](https://cwe.mitre.org/data/definitions/522.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
