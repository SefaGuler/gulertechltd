---
title: "MASVS-CRYPTO: Testing Cryptography and Key Management in Android and iOS Apps"
date: 2026-11-09 09:11:00 +0000
subcategory: crypto
summary: "Hub for the MASVS-CRYPTO series: all eleven MASWE weaknesses, their MASTG Knowledge and Tests, an algorithm reference, a test plan and a hook cheat sheet."
refs: [MASVS-CRYPTO-1, MASVS-CRYPTO-2, MASWE-0007, MASWE-0017]
tags: [android, ios, masvs-crypto, cryptography, methodology]
---

This is the entry point to our series on **OWASP MASVS-CRYPTO**. The control group has two requirements:

- **MASVS-CRYPTO-1:** "The app employs current strong cryptography and uses it according to industry best practices."
- **MASVS-CRYPTO-2:** "The app performs key management according to industry best practices."

Each note in the series covers one weakness from the [MASWE](https://mas.owasp.org/MASWE/) catalogue, with its **Knowledge** (how the platform crypto works) and its **Tests** (how to prove the weakness is or is not present). This page maps the area, gives you an algorithm reference to rate findings against, and collects the hooks and greps you will use on every crypto review.

## Contents

- [What MASVS-CRYPTO covers](#what-masvs-crypto-covers)
- [The eleven weaknesses](#the-eleven-weaknesses)
- [Knowledge and Tests map](#knowledge-and-tests-map)
- [Algorithm and parameter reference](#algorithm-and-parameter-reference)
- [The crypto stack on each platform](#the-crypto-stack-on-each-platform)
- [Test plan](#test-plan)
- [Command and hook cheat sheet](#command-and-hook-cheat-sheet)
- [Reporting crypto findings](#reporting-crypto-findings)
- [References](#references)

## What MASVS-CRYPTO covers

Mobile apps run on devices that get lost, stolen, rooted and instrumented. Cryptography is what protects data once the device or the app itself is in an attacker's hands, which makes the details matter. AES is a good choice, but AES in ECB mode, or AES-GCM with a reused nonce, gives you almost nothing.

- **CRYPTO-1** is about **using primitives correctly**. That means choosing current algorithms, modes, padding, hash functions, MACs and signature schemes, and feeding them proper randomness. In practice, most CRYPTO-1 findings are not exotic attacks. They are a constant IV, `Cipher.getInstance("AES")` (which silently means ECB), MD5 used for integrity, or `java.util.Random` used to generate a token.
- **CRYPTO-2** is about **the life of the keys**: how keys are generated and derived, how long they live, who and what can use them, and whether the device is protected well enough to make hardware-backed keys meaningful.

The two overlap with storage. Where a key *lives* (inside or outside the Keystore/Keychain, or hardcoded in the package) is covered in the storage series under [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/), which OWASP also maps to MASVS-CRYPTO-2. This series links to it rather than repeating it.

The standards MASVS points to for "industry best practices" are NIST [SP 800-175B](https://csrc.nist.gov/pubs/sp/800/175/b/r1/final) (guidance on using cryptographic standards) and [SP 800-57 Part 1](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final) (key management). In findings, cite those, or the specific SP 800-38D / 800-131A / 800-132 section.

## The eleven weaknesses

| ID | Weakness | Control | Profiles | Linked tests | Note |
|----|----------|---------|----------|--------------|------|
| MASWE-0007 | Improper Encryption | CRYPTO-1, CRYPTO-2 | L1, L2, EUDIW | 10 | [Read](/mobile/maswe-0007-improper-encryption/) |
| MASWE-0008 | Improper Hashing | CRYPTO-1 | L1, L2, EUDIW | 1 | [Read](/mobile/maswe-0008-improper-hashing/) |
| MASWE-0009 | Improper Use of Message Authentication Code (MAC) | CRYPTO-1, CRYPTO-2 | L1, L2, EUDIW | 0 | [Read](/mobile/maswe-0009-improper-use-of-mac/) |
| MASWE-0010 | Improper Generation of Cryptographic Signatures | CRYPTO-1, CRYPTO-2 | L1, L2, EUDIW | 0 | [Read](/mobile/maswe-0010-improper-signature-generation/) |
| MASWE-0011 | Improper Verification of Cryptographic Signature | CRYPTO-1 | L1, L2, EUDIW | 0 | [Read](/mobile/maswe-0011-improper-signature-verification/) |
| MASWE-0012 | Improper Random Number Generation | CRYPTO-1 | L1, L2, EUDIW | 4 | [Read](/mobile/maswe-0012-improper-random-number-generation/) |
| MASWE-0013 | Improper Cryptographic Key Generation | CRYPTO-2 | L1, L2, EUDIW | 2 | [Read](/mobile/maswe-0013-improper-key-generation/) |
| MASWE-0014 | Improper Cryptographic Key Derivation | CRYPTO-2 | L1, L2, EUDIW | 0 | [Read](/mobile/maswe-0014-improper-key-derivation/) |
| MASWE-0015 | Cryptographic Key Rotation Not Implemented | CRYPTO-2 | L2, EUDIW | 0 | [Read](/mobile/maswe-0015-key-rotation-not-implemented/) |
| MASWE-0016 | Cryptographic Key Access Not Restricted | CRYPTO-2 (+ AUTH-2, AUTH-3) | L2, EUDIW | 0 | [Read](/mobile/maswe-0016-key-access-not-restricted/) |
| MASWE-0017 | Device Secure Lock Not Enforced | CRYPTO-2 | L2, EUDIW | 4 | [Read](/mobile/maswe-0017-device-secure-lock-not-enforced/) |

Six of the eleven weaknesses have no OWASP tests yet. Those notes give our own test procedures, marked as **Guler Tech methodology**, alongside any related OWASP material that exists.

The **profiles** column tells you when a weakness applies. **L1** is the baseline for every app. **L2** is defence-in-depth for apps handling highly sensitive data. **EUDIW** is the EU Digital Identity Wallet profile. Key rotation (MASWE-0015), restricted key access (MASWE-0016) and enforcing a device lock (MASWE-0017) are L2 requirements. Everything about using primitives correctly applies to every app.

## Knowledge and Tests map

Every OWASP item linked from the eleven weaknesses on the live MASWE site. Weaknesses not listed here have no linked items yet.

### MASWE-0007 — Improper Encryption

| Type | ID | Title | Platform |
|------|----|-------|----------|
| Knowledge | MASTG-KNOW-0011 | Security Provider | Android |
| Knowledge | MASTG-KNOW-0012 | Key Generation | Android |
| Test | MASTG-TEST-0221 | Broken Symmetric Encryption Algorithms | Android |
| Test | MASTG-TEST-0232 | Broken Symmetric Encryption Modes | Android |
| Test | MASTG-TEST-0350 | Runtime Use of Broken Symmetric Encryption Modes | Android |
| Test | MASTG-TEST-0309 | References to Reused Initialization Vectors in Symmetric Encryption | Android |
| Test | MASTG-TEST-0310 | Runtime Use of Reused Initialization Vectors in Symmetric Encryption | Android |
| Test | MASTG-TEST-0307 | References to Asymmetric Key Pairs Used For Multiple Purposes | Android |
| Test | MASTG-TEST-0308 | Runtime Use of Asymmetric Key Pairs Used For Multiple Purposes | Android |
| Test | MASTG-TEST-0312 | References to Explicit Security Provider in Cryptographic APIs | Android |
| Test | MASTG-TEST-0210 | Broken Symmetric Encryption Algorithms | iOS |
| Test | MASTG-TEST-0317 | Broken Symmetric Encryption Modes | iOS |
| Best practice | MASTG-BEST-0005 | Use Secure Encryption Modes | — |
| Best practice | MASTG-BEST-0009 | Use Secure Encryption Algorithms | — |
| Best practice | MASTG-BEST-0020 | Update the GMS Security Provider | Android |

### MASWE-0008 — Improper Hashing

| Type | ID | Title | Platform |
|------|----|-------|----------|
| Test | MASTG-TEST-0211 | Broken Hashing Algorithms | iOS |

### MASWE-0012 — Improper Random Number Generation

| Type | ID | Title | Platform |
|------|----|-------|----------|
| Knowledge | MASTG-KNOW-0013 | Random Number Generation | Android |
| Knowledge | MASTG-KNOW-0070 | Random Number Generator | iOS |
| Test | MASTG-TEST-0204 | Insecure Random API Usage | Android |
| Test | MASTG-TEST-0205 | Non-random Sources Usage | Android |
| Test | MASTG-TEST-0311 | Insecure Random API Usage | iOS |
| Test | MASTG-TEST-0349 | Runtime Use of Insecure Random APIs | iOS |
| Best practice | MASTG-BEST-0001 | Use Secure Random Number Generator APIs | Android |
| Best practice | MASTG-BEST-0025 | Use Secure Random Number Generator APIs | iOS |

### MASWE-0013 — Improper Cryptographic Key Generation

| Type | ID | Title | Platform |
|------|----|-------|----------|
| Test | MASTG-TEST-0208 | Insufficient Key Sizes | Android |
| Test | MASTG-TEST-0209 | Insufficient Key Sizes | iOS |

### MASWE-0017 — Device Secure Lock Not Enforced

| Type | ID | Title | Platform |
|------|----|-------|----------|
| Knowledge | MASTG-KNOW-0001 | Biometric Authentication | Android |
| Knowledge | MASTG-KNOW-0056 | Local Authentication Framework | iOS |
| Test | MASTG-TEST-0247 | References to APIs for Detecting Secure Screen Lock | Android |
| Test | MASTG-TEST-0249 | Runtime Use of Secure Screen Lock Detection APIs | Android |
| Test | MASTG-TEST-0248 | References to APIs for Detecting Secure Screen Lock | iOS |
| Test | MASTG-TEST-0246 | Runtime Use of Secure Screen Lock Detection APIs | iOS |

## Algorithm and parameter reference

Use this table to rate what you find. It reflects NIST SP 800-131A Rev. 2, SP 800-57 Part 1 Rev. 5 and the OWASP cheat sheets as of writing. Where a primitive is weak only in some uses, the table says which.

| Purpose | Use | Acceptable with care | Do not use |
|---------|-----|----------------------|------------|
| Symmetric encryption | AES-GCM (96-bit random or counter nonce, never reused per key), ChaCha20-Poly1305 | AES-CBC or AES-CTR **with** a separate HMAC (encrypt-then-MAC) and a fresh random IV | AES-ECB, any mode with a constant IV/nonce, DES, 3DES/TDEA, RC4, Blowfish, RC2 |
| Asymmetric encryption | RSA-OAEP (SHA-256), ECIES/HPKE | RSA-OAEP with SHA-1 inside MGF1 (still sound, but prefer SHA-256 throughout) | RSA PKCS#1 v1.5 encryption for new designs, "textbook" RSA (`RSA/ECB/NoPadding`) |
| Hashing (integrity) | SHA-256, SHA-384, SHA-512, SHA-3 | SHA-1 only for non-security uses (cache keys, legacy checksums) | MD5 or SHA-1 for anything an attacker can influence: signatures, integrity, deduplication of untrusted data |
| Password hashing / key derivation from passwords | Argon2id, scrypt, PBKDF2-HMAC-SHA256 ≥ 600,000 iterations (OWASP) | bcrypt (for server-side password storage) | Plain or salted single hash, PBKDF2 with low iteration counts, static salt |
| Key derivation from keys | HKDF with a distinct `info` per derived key | — | Hashing key material together ad hoc, reusing one key for several purposes |
| MAC | HMAC-SHA256/384/512, AES-GCM / Poly1305 tags (as part of AEAD) | Truncated HMAC tags ≥ 128 bits | `hash(key ‖ message)`, CBC-MAC on variable-length messages, non-constant-time tag comparison |
| Signatures | ECDSA P-256 (or deterministic nonces, RFC 6979), Ed25519, RSA-PSS ≥ 2048-bit | RSA PKCS#1 v1.5 signatures ≥ 2048-bit (still widely deployed; not broken as a signature scheme) | RSA < 2048, DSA, any scheme over SHA-1, ECDSA with a weak or reused nonce |
| Key sizes | AES-256 (AES-128 also acceptable), RSA ≥ 3072 for data protected beyond 2030, P-256/P-384, X25519/Ed25519 | RSA-2048 (acceptable through 2030 per SP 800-57) | RSA-1024, 112-bit-or-weaker symmetric keys, ECC curves below 224 bits |
| Randomness | `SecureRandom` (default constructor), `SecRandomCopyBytes`, `SystemRandomNumberGenerator`, CryptoKit key/nonce generation | `SecureRandom.getInstanceStrong()` (correct, but may block) | `java.util.Random`, `Math.random`, `kotlin.random.Random`, `rand()`/`random()`, seeding with time, `SHA1PRNG` with a fixed seed |

Two rules cover most real findings:

1. **An AEAD is the default.** If the app uses AES, ask "where is the authentication tag?" If it is CBC or CTR with no MAC, ciphertexts can be modified, and padding-oracle behaviour may be reachable.
2. **Nonces and IVs must never repeat under the same key.** A constant IV in CBC leaks which messages share a prefix. A repeated nonce in CTR or GCM leaks the XOR of the plaintexts, and in GCM it also lets an attacker forge tags.

## The crypto stack on each platform

### Android

- **JCA/JCE** is the API surface (`Cipher`, `MessageDigest`, `Mac`, `Signature`, `KeyGenerator`, `KeyPairGenerator`, `SecretKeyFactory`, `SecureRandom`). The implementation comes from a **provider**. On modern Android that is **Conscrypt** (`AndroidOpenSSL`, BoringSSL underneath) for most algorithms, and **AndroidKeyStore** for operations on Keystore keys. The Bouncy Castle provider is legacy. Requesting a provider explicitly (`Cipher.getInstance("AES/GCM/NoPadding", "BC")`) is a finding in its own right (MASTG-TEST-0312).
- **Transformation strings** decide the mode and padding. `"AES"` alone resolves to `AES/ECB/PKCS5Padding` on the default providers, which is why it is one of the most common findings on Android.
- **Android Keystore** keys enforce what they can be used for: purposes, block modes, paddings, digests, user authentication and randomised encryption. Read the `KeyGenParameterSpec` to see what the app actually asked for. See [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/) and [MASWE-0016](/mobile/maswe-0016-key-access-not-restricted/).
- **Tink** (Google) is a higher-level, misuse-resistant library. Its presence is usually a good sign, and its keysets handle nonces and rotation for you.
- **Native crypto** in `.so` files (OpenSSL, BoringSSL, mbedTLS, or hand-rolled code) does not show up in Java hooks. Check `lib/*/` and hook the native exports.

### iOS

- **CryptoKit** (Swift, iOS 13+) is the modern API. It offers `AES.GCM`, `ChaChaPoly`, `SHA256/384/512`, `HMAC`, `HKDF`, `P256/P384/P521`, `Curve25519`, `SecureEnclave.P256`, plus an explicit `Insecure` namespace for `MD5` and `SHA1`. Its API makes many mistakes hard to make, though not impossible: you can still pass a fixed nonce.
- **CommonCrypto** (C) is still everywhere: `CCCrypt`, `CCCryptorCreate`, `CC_MD5`, `CC_SHA1`, `CCHmac`, `CCKeyDerivationPBKDF`. Its defaults are dangerous: `CCCrypt` with `kCCOptionECBMode` gives you ECB, and passing a `NULL` IV in CBC mode means an all-zero IV.
- **Security framework** (`SecKey*`): asymmetric keys, Keychain-backed keys, Secure Enclave keys (`kSecAttrTokenIDSecureEnclave`), `SecKeyCreateSignature` / `SecKeyVerifySignature` / `SecKeyCreateEncryptedData`, and `SecRandomCopyBytes`.
- **Third-party libraries** (CryptoSwift, OpenSSL builds, libsodium) are linked into the binary or frameworks. List the imports and frameworks to find them.

## Test plan

### 1. Inventory (static)

Decompile the app and list every crypto call site with its parameters: algorithm, mode, padding, key size, IV/nonce source, provider, and where the key comes from. On Android, grep the jadx output. On iOS, list imported symbols and look for CryptoKit types in the Swift metadata.

This inventory drives everything else. Most CRYPTO-1 findings (MASWE-0007, 0008, 0012, 0013) can be spotted here, and it is what the "References to…" tests formalise.

### 2. Runtime confirmation (dynamic)

Static analysis tells you which APIs the code *could* call. Hooks tell you what the app actually calls, with which parameters, how often, and with which keys and IVs. Exercise every flow that touches protected data: login, token refresh, local data encryption, request signing, licence checks and backups. Record:

- each `Cipher.init` / `CCCrypt` call with mode, key identity (alias or hash) and IV (to detect reuse: MASTG-TEST-0310);
- each `Signature`, `Mac` and `MessageDigest` instance with its algorithm;
- every `SecureRandom` / `SecRandomCopyBytes` call, and the *absence* of one where randomness should be (constant IVs, salts, tokens).

### 3. Key management review (CRYPTO-2)

For every key in the inventory, establish:

- **Origin:** generated, derived or imported.
- **Size.**
- **Storage:** Keystore/Keychain/Secure Enclave or not (see MASWE-0003).
- **Usage restrictions:** purposes, user authentication, unlocked-device requirement.
- **Lifetime:** rotation, and invalidation on logout or biometric change.
- **Whether a secure lock screen is required for it to mean anything.**

MASWE-0013 to 0017 each cover one of these questions.

### 4. Verification paths (MASWE-0011)

Anything the app verifies (signed configs, licences, JWTs, update manifests, receipts) is a target. Tamper with the signed data and check whether the app notices.

### 5. Correlate and rate

Tie each finding to the MASWE, the test, the exact call site, and a concrete consequence: decryptable data, forgeable token, predictable value, or usable key. Use the algorithm reference above and the "Rating findings" section of each note.

## Command and hook cheat sheet

### Android — static

```bash
jadx -d out/ app.apk

# Algorithms, modes and padding (look for ECB, DES, RC4, MD5, SHA1, NoPadding)
grep -rnE 'Cipher\.getInstance\(|MessageDigest\.getInstance\(|Mac\.getInstance\(|Signature\.getInstance\(' out/sources/
grep -rnE '"(AES|DES|DESede|RC4|ARCFOUR|Blowfish)(/[A-Z0-9]+/[A-Za-z0-9]+)?"' out/sources/

# IVs, keys and randomness
grep -rnE 'IvParameterSpec\(|GCMParameterSpec\(|SecretKeySpec\(' out/sources/
grep -rnE 'new Random\(|Math\.random\(|SHA1PRNG|setSeed\(' out/sources/

# Key sizes and Keystore specs
grep -rnE '\.initialize\([0-9]+|\.init\([0-9]+|setKeySize\(|KeyGenParameterSpec\.Builder' out/sources/

# Explicit providers
grep -rnE 'getInstance\("[^"]+", *"(BC|SC|AndroidOpenSSL|Conscrypt)"' out/sources/
```

### Android — dynamic

```bash
# Trace the JCA entry points (Frida 16+/17)
frida-trace -U -f <package> \
  -j 'javax.crypto.Cipher!getInstance' -j 'javax.crypto.Cipher!init' \
  -j 'java.security.MessageDigest!getInstance' -j 'javax.crypto.Mac!getInstance' \
  -j 'java.security.Signature!getInstance' -j 'java.security.SecureRandom!$init'

# objection: watch a class and dump arguments
objection -g <package> explore
#   android hooking watch class_method javax.crypto.Cipher.init --dump-args --dump-backtrace
#   android keystore list
```

### iOS — static

```bash
# Imported crypto symbols (decrypted binary)
rabin2 -i Payload/App.app/App | grep -E 'CCCrypt|CC_MD5|CC_SHA1|CCHmac|CCKeyDerivationPBKDF|SecKey|SecRandomCopyBytes|arc4random|rand$|random$'
# CryptoKit usage shows up as Swift symbols
rabin2 -s Payload/App.app/App | grep -iE 'CryptoKit|Insecure|AES.GCM|ChaChaPoly'
otool -L Payload/App.app/App            # linked frameworks (CryptoKit, CryptoSwift, OpenSSL...)
```

### iOS — dynamic

```bash
frida-trace -U -f <bundle-id> -i 'CCCrypt*' -i 'CC_MD5' -i 'CC_SHA1' -i 'CCHmac*' \
  -i 'CCKeyDerivationPBKDF' -i 'SecKeyCreate*' -i 'SecRandomCopyBytes'
```

The individual notes contain complete Frida scripts that log parameters such as mode, IV and key size, and flag reuse automatically.

## Reporting crypto findings

- **Show the call site and the runtime evidence.** "`Cipher.getInstance("AES")` in `com.example.vault.Crypto.encrypt()` resolves to `AES/ECB/PKCS5Padding`, and is called for every note body (Frida log attached)" is reviewable. "Weak crypto" is not.
- **State the consequence, not just the rule.** ECB on short random tokens is low impact. ECB on structured records such as card numbers or chat messages leaks patterns and equality. A constant GCM nonce is high impact. Prove it if you can: decrypt something, forge a tag, predict a value.
- **Separate primitive choice from key management.** A perfect AES-GCM implementation with a hardcoded key is a MASWE-0003 finding, not a MASWE-0007 one. Report both when both apply.
- **Do not over-rate deprecated-but-harmless uses.** MD5 for a cache key, or SHA-1 inside HMAC, is at most Informational. Explain why, so the client does not waste effort on it.
- **Recommend concrete replacements.** For example: `AES/GCM/NoPadding` with a Keystore-generated key and a random 12-byte IV prepended to the ciphertext, or Tink's `Aead`, or CryptoKit `AES.GCM.seal` (it generates the nonce for you).

## References

- OWASP MASVS — [MASVS-CRYPTO-1](https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-1/), [MASVS-CRYPTO-2](https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-2/) (CC BY-SA 4.0)
- OWASP MASWE — [Weakness index](https://mas.owasp.org/MASWE/) (CC BY-SA 4.0)
- OWASP MASTG — [Knowledge](https://mas.owasp.org/MASTG/knowledge/), [Tests](https://mas.owasp.org/MASTG/tests/), [Best Practices](https://mas.owasp.org/MASTG/best-practices/) (CC BY-SA 4.0)
- [NIST SP 800-175B Rev. 1 — Guideline for Using Cryptographic Standards](https://csrc.nist.gov/pubs/sp/800/175/b/r1/final)
- [NIST SP 800-57 Part 1 Rev. 5 — Recommendation for Key Management](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final)
- [NIST SP 800-131A Rev. 2 — Transitioning the Use of Cryptographic Algorithms and Key Lengths](https://csrc.nist.gov/pubs/sp/800/131/a/r2/final)
- [NIST SP 800-38D — Galois/Counter Mode (GCM)](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [OWASP Cheat Sheet — Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP Cheat Sheet — Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [Android Developers — Cryptography](https://developer.android.com/privacy-and-security/cryptography)
- [Apple — CryptoKit](https://developer.apple.com/documentation/cryptokit)

> Adapted and extended from the OWASP MASVS, MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
