---
title: "Improper Cryptographic Key Derivation (MASWE-0014)"
date: 2026-11-09 12:22:00 +0000
subcategory: crypto
summary: "Testing mobile key derivation: PBKDF2, scrypt and Argon2id parameters, salts, PIN-derived keys, HKDF misuse, Frida hooks and offline cracking cost."
refs: [MASWE-0014, MASVS-CRYPTO-2, CWE-326, CWE-327, CWE-759, CWE-760, CWE-916]
tags: [android, ios, masvs-crypto, kdf, pbkdf2, argon2]
---

This note is part of our [MASVS-CRYPTO guide](/mobile/masvs-crypto-cryptography-guide/) and covers OWASP [MASWE-0014](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0014/): keys derived from passwords, PINs or other secrets with a key derivation function (KDF) that is missing, unsuitable or misconfigured. It is the weakness behind "the vault is encrypted with AES-256" claims that collapse once you notice the key is `SHA-256(pin)`. You will find how password-based and key-based KDFs work and what parameters current guidance requires, why a PIN cannot be protected by any KDF on its own, the Android and iOS APIs and their pitfalls, a complete static and dynamic test procedure with Frida hooks, a method for putting a defensible cracking-cost estimate in a report, working Kotlin and Swift, and severity guidance. Keys that are *generated* rather than derived are in [MASWE-0013](/mobile/maswe-0013-improper-key-generation/), and keys stored outside the keystore in [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/).

> **Note:** At the time of writing, MASWE-0014 has **no Knowledge pages and no tests** linked on the OWASP MASWE site. The Knowledge and Testing sections below are our own (Guler Tech methodology), structured like OWASP tests. Where related OWASP material exists in the MASTG — the PBKDF2 examples in MASTG-KNOW-0012 and MASTG-KNOW-0069, the key storage ranking in MASTG-KNOW-0047, and the legacy (MASTG v1) tests MASTG-TEST-0013, MASTG-TEST-0014, MASTG-TEST-0061 and MASTG-TEST-0062 — we cite it and say where its guidance is out of date.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Both platforms: password-based KDFs and current parameters (Guler Tech)](#both-platforms-password-based-kdfs-and-current-parameters-guler-tech)
  - [Both platforms: salts (Guler Tech)](#both-platforms-salts-guler-tech)
  - [Both platforms: PINs and other low-entropy inputs (Guler Tech)](#both-platforms-pins-and-other-low-entropy-inputs-guler-tech)
  - [Both platforms: HKDF, key expansion and domain separation (Guler Tech)](#both-platforms-hkdf-key-expansion-and-domain-separation-guler-tech)
  - [Android: key derivation APIs (Guler Tech)](#android-key-derivation-apis-guler-tech)
  - [iOS: key derivation APIs (Guler Tech)](#ios-key-derivation-apis-guler-tech)
  - [Related OWASP material](#related-owasp-material)
- [Testing](#testing)
  - [Static: locate key derivation and its parameters (Android)](#static-locate-key-derivation-and-its-parameters-android)
  - [Static: locate key derivation and its parameters (iOS)](#static-locate-key-derivation-and-its-parameters-ios)
  - [Dynamic: capture KDF inputs and parameters at runtime (Android)](#dynamic-capture-kdf-inputs-and-parameters-at-runtime-android)
  - [Dynamic: capture KDF inputs and parameters at runtime (iOS)](#dynamic-capture-kdf-inputs-and-parameters-at-runtime-ios)
  - [Estimating offline cracking cost for the report](#estimating-offline-cracking-cost-for-the-report)
- [Secure implementation](#secure-implementation)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

A key derivation function turns some input into one or more keys. There are two families, and confusing them is the root of most findings:

| Input | Right tool | Purpose of the KDF | Examples |
|---|---|---|---|
| Low-entropy secret a human chose or can remember (password, passphrase, PIN) | **Password-based KDF** | Make every guess expensive and stop precomputation | PBKDF2, scrypt, Argon2id |
| High-entropy secret that is not yet a uniform key of the right length (ECDH shared secret, a master key, a KEM output) | **Key-based KDF** | Extract uniform randomness and expand it into several independent keys | HKDF (RFC 5869), NIST SP 800-108 KBKDF, SP 800-56C |

A password-based KDF has two defences. The **salt** — a random, per-derivation value stored next to the result — makes the derivation unique, so the attacker cannot precompute a table of password-to-key mappings or attack many users at once. The **work factor** — iterations, memory, parallelism — makes each guess cost real time or money. Neither adds entropy: a KDF cannot make a 6-digit PIN have more than a million possible values. It only multiplies the cost of trying each one.

A key-based KDF has no work factor at all, because its input is assumed to be unguessable already. Running HKDF on a password is just a fast hash with extra steps.

When the wrong family is used, or the right one is misconfigured, the derived key has the length of an AES-256 key and the strength of the input divided by very little work. The attacker's path is always the same: get something that lets them test a guess (ciphertext with an authentication tag, a stored verifier hash, a known plaintext header), get the salt and parameters (usually stored in the clear next to it, which is fine *if* the KDF is strong), and search the input space offline, on GPUs, with no attempt limit.

The weakness is mapped to MASVS-CRYPTO-2 and to CWE-326 (Inadequate Encryption Strength), CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), CWE-759 (Use of a One-Way Hash without a Salt), CWE-760 (Use of a One-Way Hash with a Predictable Salt) and CWE-916 (Use of Password Hash With Insufficient Computational Effort).

## Modes of Introduction

**Plain hash instead of a KDF.** `SecretKeySpec(MessageDigest.getInstance("SHA-256").digest(password.toByteArray()), "AES")` on Android, `SHA256.hash(data: Data(password.utf8))` turned into a `SymmetricKey` on iOS, `CC_SHA256` or `CC_MD5` in older Objective-C. One fast hash costs a GPU a fraction of a nanosecond; billions of guesses per second are routine. Iterating the hash yourself (`for (i in 1..1000) h = sha256(h)`) is an improvised, unsalted PBKDF with a low count.

**Password used directly as the key.** The password bytes are padded or truncated to 16 or 32 bytes and passed straight to the cipher. The classic Objective-C `AES256EncryptWithKey:` category copies the `NSString` into a zero-filled 33-byte buffer and calls `CCCrypt` with `kCCKeySizeAES256`. The effective key space is the password space, not 2^256 — and most of the key bytes are zero.

**Insufficient work factor.** PBKDF2 with 1,000 or 10,000 iterations (the second figure still appears in the MASTG's own example code), scrypt with N = 2^10, or Argon2 with a few hundred KiB of memory. Often the parameters were picked years ago for older hardware, or lowered after a "login is slow" bug report and never raised again.

**Missing, static or reused salt.** `PBEKeySpec(password, ByteArray(16), ...)` (a zero salt), a salt string in code (`"com.example.app".toByteArray()`), the same salt for every user, a salt derived from the username or device ID, or one salt reused for several purposes. A static salt shared across installs lets an attacker build one table and apply it to every user; a salt equal to a public value such as the email address has the same effect for a targeted attack.

**Low-entropy input.** A 4- or 6-digit PIN, a pattern lock reproduced in the app, a security-question answer, or "secret" device values (`ANDROID_ID`, `identifierForVendor`, serial number, MAC address, package name, install timestamp). The device values are not secret at all to code running on the device, and often not to the backend either. No work factor helps when the whole input space can be enumerated.

**Key-based KDF used on a password.** HKDF or SP 800-108 KBKDF applied to a passphrase. These KDFs do one or two HMAC calls; they are designed for inputs that already have full entropy.

**No domain separation.** One derived key is used for encryption *and* for authentication, or for two different files, users or protocol versions, or two keys are derived with the same HKDF `info`. Compromise or misuse in one context carries over to the other. A related mistake is to store the KDF output as a "password check" and also use it as the encryption key: the stored verifier *is* the key.

**Requesting more output than the PRF produces.** PBKDF2 computes each output block (20 bytes for SHA-1, 32 for SHA-256, 64 for SHA-512) with a separate full set of iterations. An app that asks PBKDF2-HMAC-SHA1 for 64 bytes and splits them into an encryption key and a MAC key pays four times the cost; an attacker who can test a guess against one block — for example, the MAC key against a stored tag — pays once. Derive one PRF-length master key, then expand it with HKDF.

**Raw shared secrets used as keys.** The output of ECDH (`KeyAgreement.generateSecret()`, `SecKeyCopyKeyExchangeResult` without a KDF, CryptoKit `SharedSecret` bytes) used directly as an AES key. The shared secret is a curve point coordinate, not a uniformly random string; NIST SP 800-56A requires a KDF step, and CryptoKit deliberately makes you call `hkdfDerivedSymmetricKey` or `x963DerivedSymmetricKey`.

## Impact

- **Compromise of sensitive data.** An attacker with ciphertext and the salt (from a backup, a rooted or jailbroken device, a forensic image, cloud sync, or a breached backend) recovers the password or PIN offline and decrypts the data — and everything else protected by the same password.
- **Authentication or authorisation bypass.** A recovered password or derived credential lets the attacker log in as the user, unlock app-level locks, or authorise transactions the derived key gates.
- **Credential reuse beyond the app.** Users reuse passwords. Recovering a password from an app vault can unlock the user's email, bank or work accounts, which is why a weak KDF in a "low-sensitivity" app can still be a serious finding.
- **Scale.** With a static salt or no salt, one precomputation applies to every user of the app. With a fast hash, cracking a whole breached dataset is a GPU-hours problem.

## Mitigations

- **Use a password-based KDF for password-derived keys** — Argon2id, scrypt or PBKDF2 — following [NIST SP 800-132](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf) and the current [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html). Never a plain or iterated hash, never the password itself.
- **Use an adequate work factor**: at least PBKDF2-HMAC-SHA256 with 600,000 iterations, PBKDF2-HMAC-SHA512 with 210,000, scrypt N = 2^17, r = 8, p = 1, or Argon2id with 19 MiB of memory and 2 iterations. Store the parameters with the output so they can be raised later, and raise them.
- **Use a unique random salt** of at least 128 bits from the platform CSPRNG for every derivation; store it next to the result. Never hardcode it, derive it from public values, or share it across users or purposes.
- **Do not let low-entropy inputs stand alone.** Combine a PIN-derived value with a non-exportable key held in the Android Keystore or the Secure Enclave, bind keys to the device credential so the hardware enforces attempt limits, or verify the PIN server-side with a lockout before releasing a key share.
- **Use HKDF for key expansion, not for passwords.** Derive one master key with the password-based KDF, then derive each purpose-specific key with HKDF and a distinct `info` string. Always run shared secrets from key agreement through a KDF.

## Knowledge

All sections here are Guler Tech material. They explain the mechanisms you need to test MASWE-0014 and are written to be read in order; the last section lists the related OWASP pages and their status.

### Both platforms: password-based KDFs and current parameters (Guler Tech)

Sources: NIST SP 800-132, RFC 8018 (PKCS #5 v2.1), RFC 7914 (scrypt), RFC 9106 (Argon2), OWASP Password Storage Cheat Sheet.

**PBKDF2** (RFC 8018, NIST SP 800-132) runs HMAC with the password as the key, `c` times, XOR-ing the intermediate results, once per output block. It is CPU-bound: every iteration is two hash compressions, so GPUs and ASICs that compute hashes in massive parallel run it very efficiently. Its strength is purely the iteration count. It is the only one of the three with a platform API on both Android and iOS, which is why most apps use it.

**scrypt** (RFC 7914) adds memory hardness: each guess must fill and randomly read a buffer of `128 × r × N` bytes. Parallel hardware then needs that much memory per concurrent guess, which raises the attacker's cost far more than the defender's. Parameters are `N` (CPU/memory cost, a power of two), `r` (block size) and `p` (parallelism).

**Argon2id** (RFC 9106), winner of the Password Hashing Competition, is memory-hard with tunable memory `m` (KiB), passes `t` and lanes `p`; the `id` variant combines resistance to GPU attacks and to side channels. It is the first choice of both the OWASP cheat sheet and RFC 9106.

**bcrypt** appears in mobile code occasionally. It is a password *hashing* function with a 72-byte input limit and a fixed 192-bit output, not a general KDF; if an app uses it to derive keys, check how the output is turned into a key.

Current parameters from the OWASP Password Storage Cheat Sheet. These are minimums for password storage; they are a sensible minimum for on-device key derivation too.

| KDF | Minimum configuration | Equivalent alternatives listed by OWASP |
|---|---|---|
| Argon2id | m = 19 MiB (19,456 KiB), t = 2, p = 1 | m = 46 MiB t = 1; m = 12 MiB t = 3; m = 9 MiB t = 4; m = 7 MiB t = 5 (all p = 1) |
| scrypt | N = 2^17 (128 MiB), r = 8, p = 1 | N = 2^16 r = 8 p = 2; N = 2^15 r = 8 p = 3; N = 2^14 r = 8 p = 5; N = 2^13 r = 8 p = 10 |
| PBKDF2-HMAC-SHA256 | 600,000 iterations | — |
| PBKDF2-HMAC-SHA512 | 210,000 iterations | — |
| PBKDF2-HMAC-SHA1 | 1,300,000 iterations | — |

RFC 9106 is more generous: its "first recommended option" for Argon2id is t = 1, p = 4, m = 2 GiB, and its second, for memory-constrained environments, t = 3, p = 4, m = 64 MiB. On current phones 64 MiB is usually affordable for a one-off unlock.

NIST SP 800-132 (2010) is older and lower: at least 1,000 PBKDF2 iterations, with 10,000,000 suggested for critical keys where the user can wait. It is still the reference for *how* PBKDF2 must be used — random salt of at least 128 bits, approved HMAC PRF — and it limits PBKDF2-derived keys to protecting stored data, not transport. Older MASTG text cites "at least 10,000 iterations" from NIST SP 800-63B; that figure is obsolete for key derivation, and you should not accept it as a pass.

How to choose, and what to expect to see in apps:

- **Argon2id** where the app can ship a library (libsodium, Bouncy Castle, a vetted native build). Best resistance per millisecond of user wait.
- **PBKDF2-HMAC-SHA256 or -SHA512** where the app wants only platform APIs. Acceptable at the counts above; PBKDF2-SHA512 is somewhat more GPU-resistant per unit of work, which is why its required count is lower.
- **PBKDF2-HMAC-SHA1** is not broken for this purpose (HMAC-SHA1 remains a sound PRF), but needs the highest count and is a sign of old code. We report it as low severity at adequate counts, mainly because NIST is phasing SHA-1 out entirely.

On a device the unlock budget is typically 200–1000 ms. Calibrate parameters on the slowest supported device so that the derivation takes about that long, and never go below the table.

### Both platforms: salts (Guler Tech)

Sources: NIST SP 800-132 section 5.1, OWASP Password Storage Cheat Sheet.

A salt is not secret. Its job is uniqueness. What it must be:

- **Random**, from the platform CSPRNG (`SecureRandom`, `SecRandomCopyBytes`). SP 800-132 requires at least 128 bits of randomly generated salt; 16 bytes is the usual choice.
- **Unique per derivation** — per user, per vault, per install. When the user changes their password, generate a new salt.
- **Stored with the output**, together with the algorithm and parameters, so that the derivation can be repeated and upgraded. A small versioned header (`v1 | kdf=pbkdf2-sha256 | iters=600000 | salt`) in front of the ciphertext is the simplest robust design.

What goes wrong, and what each mistake gives an attacker:

| Salt mistake | Typical code | Effect |
|---|---|---|
| No salt / empty | `PBEKeySpec(pw, ByteArray(0), ...)` (rejected by the Android provider, so developers switch to the next row) | Precomputed tables work across all users |
| Zero salt | `val salt = ByteArray(16)` never filled with random data | Same as no salt; very common, because it looks right |
| Constant salt | `"MySalt123".toByteArray()`, a `byte[]` literal, a resource | One table or one GPU run attacks every install |
| Public-value salt | Username, email, `ANDROID_ID`, bundle ID | Precomputation per target; same salt on every reinstall |
| Salt reused across purposes | Same salt for the vault key and the login verifier | Two outputs from one derivation; verifier may leak the key (see the Modes section) |
| Short salt | 4 or 8 bytes | Collisions across a large user base; below SP 800-132 |

A stored salt in `SharedPreferences` or a plist is **not** a finding by itself. The OWASP MASTG suggests excluding it from backups and, for higher-risk data, encrypting it under a keystore key; that adds a little defence in depth but does not substitute for a strong KDF.

### Both platforms: PINs and other low-entropy inputs (Guler Tech)

Sources: NIST SP 800-132; Android Keystore and Gatekeeper documentation; Apple Platform Security Guide (passcode and Secure Enclave sections).

This is the most important section of the note, because it is where good intentions fail most often.

**A PIN cannot be protected by a KDF.** A 6-digit PIN has 10^6 values (about 20 bits); a 4-digit PIN 10^4. Even with Argon2id or PBKDF2 at 600,000 iterations, an attacker who has the salt and something to test against can try all of them in minutes to hours on one GPU — the [cracking-cost section](#estimating-offline-cracking-cost-for-the-report) shows the arithmetic. A KDF multiplies cost per guess by a constant; it cannot fix an input space that small. Raising the iteration count to make a PIN safe would make unlocking take hours for the user.

**What actually protects a PIN is an attempt limit enforced somewhere the attacker cannot reset or bypass.** An app-level "10 attempts then wipe" counter in `SharedPreferences` or `NSUserDefaults` is not that: offline, the attacker never runs the app; online, they reset the counter. The options that work:

1. **Use the device credential instead of an app PIN.** On Android, generate a keystore key with `setUserAuthenticationRequired(true)` and `setUserAuthenticationParameters(timeout, KeyProperties.AUTH_DEVICE_CREDENTIAL or KeyProperties.AUTH_BIOMETRIC_STRONG)`. The lock-screen credential is verified by Gatekeeper in the TEE (or Weaver in a secure element on devices that have one), which enforces escalating timeouts that the OS cannot bypass. On iOS, protect a Keychain item or Secure Enclave key with `SecAccessControl` flags such as `.devicePasscode` or `.userPresence`; passcode attempts are rate-limited by the Secure Enclave. This is the strongest option and usually the simplest.
2. **Verify the PIN on a server that enforces the limit.** The app derives a value from the PIN and the server releases a key share (or the key) only after a correct value, locking the account after a few failures. The ciphertext on the device is useless without the server share, so offline guessing is impossible. Done properly this needs care so that the server itself cannot run the guessing attack (hardware security modules, or augmented PAKE protocols such as OPAQUE).
3. **Mix the PIN with a non-exportable hardware key.** Derive `K = HKDF(HMAC_keystoreKey(PBKDF2(PIN, salt)))`, where the HMAC key lives in the Android Keystore or the computation involves a Secure Enclave key. Offline attack becomes impossible: copying the ciphertext and the salt off the device is no longer enough. But an attacker with code execution on the unlocked device can still ask the keystore to compute the HMAC for each guess; the only limit is the speed of the TEE or secure element. This is the mitigation MASWE-0014 itself describes ("combine the derived key with additional secret material"), and it is a real improvement, but on its own it does not give a hard attempt limit.

Our evaluation therefore treats a key derived from a PIN alone as a failure regardless of the KDF, option 3 alone as a pass with an observation for high-value data, and options 1 and 2 as passes.

**Device identifiers are not secrets.** `Settings.Secure.ANDROID_ID` (scoped per signing key, user and device since Android 8.0, but readable by any code in the app), `identifierForVendor`, serial numbers, IMEI on old Android versions, Wi-Fi MAC addresses, the package name and install time are all available to anyone who can run code in the app's context and often to the backend or analytics providers. A key derived from them is obfuscation; report it under MASWE-0014 and, if it is effectively constant, under [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/) as well.

### Both platforms: HKDF, key expansion and domain separation (Guler Tech)

Sources: RFC 5869, NIST SP 800-56C Rev. 2, NIST SP 800-108 Rev. 1.

**HKDF** (RFC 5869) has two steps:

- **Extract**: `PRK = HMAC-Hash(salt, IKM)`. Concentrates the entropy of the input keying material (IKM) — for example an ECDH shared secret — into a uniform pseudorandom key. The salt is optional (a string of zero bytes the length of the hash is used if omitted) and, unlike a password salt, may be a fixed application constant; a random salt strengthens the extraction.
- **Expand**: `OKM = T(1) | T(2) | ...`, where `T(i) = HMAC-Hash(PRK, T(i-1) | info | i)`. Produces as many output bytes as needed (up to 255 hash lengths). The `info` parameter binds the output to a context.

HKDF matches the two-step KDF in NIST SP 800-56C Rev. 2, which is the approved way to turn a key-agreement shared secret into keys. NIST SP 800-108 Rev. 1 defines related KBKDFs (counter, feedback and double-pipeline modes over HMAC, CMAC or KMAC) for deriving keys from an existing key.

**Domain separation with `info`.** Every distinct key should come from a distinct `info` value that names its purpose and version, for example `"com.example.vault/v1/file-enc"`, `"com.example.vault/v1/index-mac"`, `"com.example.sync/v2/aes-gcm"`. Including the user or vault ID in `info` (or in the salt) prevents cross-user key reuse. Two keys derived with the same `info` from the same PRK are the same key, whatever the developer intended.

**The misuse to look for:**

- HKDF on a password or PIN (fast; equivalent to a plain hash).
- HKDF-Expand alone on a non-uniform input (skipping Extract on an ECDH secret).
- Raw ECDH output used as a key with no KDF at all.
- Identical or empty `info` for keys that serve different purposes.
- One derived key used for both AES and HMAC, or for both encryption and signing.
- Splitting a long PBKDF2 output into several keys instead of expanding a PRF-length master with HKDF (see Modes of Introduction).

**The correct composition for passwords** is: password-based KDF once → 256-bit master key → HKDF-Expand with a distinct `info` per purpose. The work factor is paid once, and each purpose gets an independent key.

### Android: key derivation APIs (Guler Tech)

Sources: Android Developers reference for `SecretKeyFactory`, `PBEKeySpec`, `PBEParameterSpec`; Android Developers Blog, "Changes to the SecretKeyFactory API in Android 4.4"; Bouncy Castle and Tink API documentation.

**PBKDF2 with the platform provider.** `SecretKeyFactory.getInstance(alg)` with:

| Algorithm name | Available from |
|---|---|
| `PBKDF2WithHmacSHA1` | API 10 |
| `PBKDF2WithHmacSHA1And8bit` | API 19 (compatibility only; see below) |
| `PBKDF2WithHmacSHA224`, `PBKDF2WithHmacSHA256`, `PBKDF2WithHmacSHA384`, `PBKDF2WithHmacSHA512` | API 26 |

The parameters go in a `PBEKeySpec(char[] password, byte[] salt, int iterationCount, int keyLength)`. `keyLength` is in **bits**: 256 for an AES-256 key. `generateSecret(spec).getEncoded()` returns the derived bytes, which the app wraps in `SecretKeySpec(bytes, "AES")`. `PBEKeySpec` copies the password; call `clearPassword()` when done and zero your own `CharArray`. Keeping the password in a `String` (immutable, interned, garbage-collected at an unknown time) is a minor finding in itself.

`PBKDF2WithHmacSHA1And8bit` exists because before Android 4.4 the PBKDF2 implementation used only the low 8 bits of each password character; it was fixed to use the full UTF-16 value, and the old behaviour was kept under this name so existing data could still be decrypted. Seeing it means the app is carrying legacy derivations; check that it migrates them.

**Password-based encryption ciphers.** `Cipher.getInstance("PBEWithMD5AndDES")` and other `PBEWith...` names derive the key and run the cipher in one step, with the iteration count in a `PBEParameterSpec(salt, iterations)`. The MD5/DES and SHA-1/DES/RC2/RC4 variants combine an obsolete KDF (PBKDF1 or the PKCS #12 KDF) with a broken cipher; any of them is a finding. Many Bouncy Castle-provided algorithms were removed from the platform in Android 12, so apps that still rely on `...-BC` algorithm names either bundle their own Bouncy Castle or fail on newer devices.

**No platform Argon2, scrypt or HKDF.** Apps that use them ship a library. Names to grep for:

- Bouncy Castle (`org.bouncycastle` or a repackaged copy): `Argon2BytesGenerator`, `Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)`, `SCrypt.generate(password, salt, N, r, p, dkLen)`, `HKDFBytesGenerator`, `PKCS5S2ParametersGenerator` (PBKDF2).
- Tink: `com.google.crypto.tink.subtle.Hkdf.computeHkdf("HMACSHA256", ikm, salt, info, size)`.
- libsodium bindings (lazysodium and others): `crypto_pwhash` (Argon2id by default in current libsodium), `crypto_kdf_derive_from_key`.
- Hand-rolled HKDF built from `Mac.getInstance("HmacSHA256")` — check it against RFC 5869 (the counter byte starts at 1, `info` is included in every block).

**Native and cross-platform code.** OpenSSL and BoringSSL expose `PKCS5_PBKDF2_HMAC`, `EVP_PBE_scrypt` and `HKDF`; Flutter apps often use Dart packages (`pointycastle`'s `PBKDF2KeyDerivator`, the `cryptography` package's `Pbkdf2` and `Argon2id`), and React Native apps call native modules for `pbkdf2`. In those apps, the parameters are in the Dart snapshot (`libapp.so`) or the JS bundle (`assets/index.android.bundle`), so search there too.

**Where KDF material lives on disk.** The salt, iteration count and (sometimes) a verifier hash are usually in `SharedPreferences` (`/data/data/<package>/shared_prefs/*.xml`), a DataStore file under `files/datastore/`, or a SQLite table. On a rooted device or debuggable build:

```bash
adb shell "su -c 'grep -riE \"salt|iter|kdf|pbkdf|verifier|pin_hash\" /data/data/com.example.app/shared_prefs/'"
```

### iOS: key derivation APIs (Guler Tech)

Sources: CommonCrypto header `CommonKeyDerivation.h`; Apple CryptoKit documentation for `HKDF` and `SharedSecret`.

**PBKDF2 with CommonCrypto.** The only platform password-based KDF on iOS:

```text
int CCKeyDerivationPBKDF(CCPBKDFAlgorithm algorithm,       // kCCPBKDF2 (2)
                         const char *password, size_t passwordLen,
                         const uint8_t *salt, size_t saltLen,
                         CCPseudoRandomAlgorithm prf,      // kCCPRFHmacAlgSHA1 (1) ... SHA512 (5)
                         unsigned rounds,
                         uint8_t *derivedKey, size_t derivedKeyLen);
```

PRF constants: `kCCPRFHmacAlgSHA1` = 1, `kCCPRFHmacAlgSHA224` = 2, `kCCPRFHmacAlgSHA256` = 3, `kCCPRFHmacAlgSHA384` = 4, `kCCPRFHmacAlgSHA512` = 5. On arm64 the first eight arguments are in `x0`–`x7`, so `rounds` is in `w6` and `derivedKeyLen` is on the stack. Those are the values you read in a disassembler or a Frida hook.

`CCCalibratePBKDF(algorithm, passwordLen, saltLen, prf, derivedKeyLen, msec)` returns the number of rounds that takes `msec` milliseconds *on the current device*. Two pitfalls: a small `msec` (say 10–50) gives a low count on old devices, and an app that calibrates on every derivation without storing the result cannot reproduce the key on a later run. Check that the round count is calibrated once, floored at a minimum (600,000 for SHA-256), and stored with the salt.

**CryptoKit has HKDF, not a password-based KDF.** `HKDF<SHA256>.deriveKey(inputKeyMaterial:salt:info:outputByteCount:)` (iOS 14+), plus `HKDF.extract` and `HKDF.expand`. Key agreement results come back as a `SharedSecret`, which must be turned into a key with `hkdfDerivedSymmetricKey(using:salt:sharedInfo:outputByteCount:)` or `x963DerivedSymmetricKey(using:sharedInfo:outputByteCount:)`. If you find `HKDF<...>.deriveKey(inputKeyMaterial: SymmetricKey(data: Data(password.utf8)), ...)`, that is HKDF on a password — the finding described above. If you find a `SharedSecret` turned into a key with `withUnsafeBytes`, that is a raw shared secret used as a key.

**Third-party Swift libraries.** CryptoSwift (`PKCS5.PBKDF2(password:salt:iterations:keyLength:variant:)`, `Scrypt`, `HKDF`) is pure Swift and noticeably slower than CommonCrypto, which tempts developers into low iteration counts; it also does not go through CommonCrypto, so the CommonCrypto Frida hooks below will not see it. libsodium via swift-sodium provides Argon2id (`crypto_pwhash`). RNCryptor's data format v3 uses PBKDF2-HMAC-SHA1 with 10,000 iterations for password-based mode — acceptable when it was designed, below current guidance now.

**Where KDF material lives.** Salts and parameters usually sit in `NSUserDefaults` (`Library/Preferences/<bundle-id>.plist`), a file in `Library/Application Support/`, or a Keychain item. On a jailbroken device:

```bash
plutil -p /var/mobile/Containers/Data/Application/<UUID>/Library/Preferences/com.example.app.plist | grep -iE 'salt|iter|kdf|pin'
```

and `objection -g com.example.app explore` followed by `ios keychain dump` for Keychain-held values.

### Related OWASP material

These pages are not linked to MASWE-0014 on the MASWE site but cover parts of it. Use them as background; where they conflict with the parameters above, the parameters above are current.

- [MASTG-KNOW-0012: Key Generation (Android)](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0012/) — includes a PBKDF2 example with a random salt and **10,000 iterations** of `PBKDF2WithHmacSHA1`; raise to current counts and prefer SHA-256. Our discussion is in the [MASWE-0003 note](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/#android-key-generation-mastg-know-0012).
- [MASTG-KNOW-0069: Key Management (iOS)](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0069/) — a `CCKeyDerivationPBKDF` wrapper for SHA-1/256/512 and the advice that deriving a key from a password avoids storing it; also warns against predictable KDFs based on stable device attributes.
- [MASTG-KNOW-0047: Cryptographic Key Storage (Android)](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0047/) — ranks "key derived from a strong user passphrase with a proper salt and KDF" fourth among storage options and "predictable key derivation from stable attributes" as not recommended.
- MASTG chapter "Mobile App Cryptography", section [Improper Key Derivation Functions](https://mas.owasp.org/MASTG/0x04g-Testing-Cryptography/) — explains why passwords must not be used as keys directly; its iteration figures (10,000 from SP 800-63B) are outdated.
- Legacy (MASTG v1) tests, all deprecated: [MASTG-TEST-0013: Testing Symmetric Cryptography](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0013/) (keys must not be "derived from known values"), [MASTG-TEST-0014: Testing the Configuration of Cryptographic Standard Algorithms](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0014/), [MASTG-TEST-0061: Verifying the Configuration of Cryptographic Standard Algorithms](https://mas.owasp.org/MASTG/tests/ios/MASVS-CRYPTO/MASTG-TEST-0061/) (keys must come from a KDF or a random generator) and [MASTG-TEST-0062: Testing Key Management](https://mas.owasp.org/MASTG/tests/ios/MASVS-CRYPTO/MASTG-TEST-0062/) (keys must not be derived from stable device features).

## Testing

Guler Tech methodology. There are no OWASP tests for MASWE-0014; the five procedures below are ours and are structured like OWASP tests. Run both static procedures for the platforms in scope, confirm with the dynamic ones, and finish with the cracking-cost estimate for anything that fails.

### Static: locate key derivation and its parameters (Android)

Platform: Android. Type: static (code).

#### Overview

Find every place the app turns a password, PIN, passphrase, device value or shared secret into a key, and record the KDF, PRF, work factor, salt source, output length and the purpose of the result.

#### Prerequisites

- The APK or split APKs (`adb shell pm path com.example.app`, then `adb pull` each).
- `jadx`, `apktool`, `semgrep`, `grep`; `radare2` or Ghidra for native libraries.
- For hybrid apps: the JS bundle (`assets/index.android.bundle`) or Flutter `libapp.so`.

#### Steps

1. **Decompile.**

   ```bash
   jadx -d out/ app.apk
   apktool d app.apk -o res_out/
   ```

2. **Inventory KDF and hash-to-key call sites.**

   ```bash
   grep -rnE 'SecretKeyFactory\.getInstance|PBEKeySpec|PBEParameterSpec|PBKDF2|PBEWith|Argon2|SCrypt|scrypt|HKDF|Hkdf|crypto_pwhash|PKCS5S2' out/sources/ \
     | grep -vE '^out/sources/(androidx|kotlin|kotlinx)/' > kdf-sites.txt
   grep -rnE 'MessageDigest\.getInstance' out/sources/ | grep -vE '^out/sources/(androidx|kotlin|kotlinx|okhttp3|okio)/' > digest-sites.txt
   grep -rnE 'ANDROID_ID|Build\.SERIAL|getSerial\(|getMacAddress|getPackageName\(\)' out/sources/ | grep -iE 'key|secret|crypt|salt' > deviceid-kdf.txt
   ```

3. **Run targeted rules.** Constants are inlined by the compiler, so iteration counts and salt literals appear as literals in jadx output:

   ```yaml
   rules:
     - id: gt-pbkdf2-low-iterations
       languages: [java]
       severity: WARNING
       message: PBEKeySpec iteration count below 600,000 - check the PRF (SHA-512 needs 210,000)
       patterns:
         - pattern: new PBEKeySpec($PW, $SALT, $ITER, ...)
         - metavariable-comparison:
             metavariable: $ITER
             comparison: $ITER < 600000
     - id: gt-kdf-constant-salt
       languages: [java]
       severity: WARNING
       message: KDF salt built from a constant
       pattern-either:
         - pattern: new PBEKeySpec($PW, "...".getBytes(...), ...)
         - pattern: |
             byte[] $S = {...};
             ...
             new PBEKeySpec($PW, $S, ...);
         - pattern: |
             byte[] $S = "...".getBytes(...);
             ...
             new PBEKeySpec($PW, $S, ...);
     - id: gt-kdf-zero-salt
       languages: [java]
       severity: WARNING
       message: Salt array allocated but possibly never filled with random bytes
       patterns:
         - pattern: |
             byte[] $S = new byte[$N];
             ...
             new PBEKeySpec($PW, $S, ...);
         - pattern-not: |
             byte[] $S = new byte[$N];
             ...
             $R.nextBytes($S);
             ...
             new PBEKeySpec($PW, $S, ...);
     - id: gt-hash-as-key
       languages: [java]
       severity: WARNING
       message: Key built directly from a message digest
       pattern-either:
         - pattern: new SecretKeySpec($MD.digest(...), ...)
         - pattern: |
             byte[] $H = $MD.digest(...);
             ...
             new SecretKeySpec($H, ...);
         - pattern: new SecretKeySpec(Arrays.copyOf($MD.digest(...), $N), ...)
     - id: gt-legacy-pbe
       languages: [java]
       severity: WARNING
       message: Legacy password-based encryption algorithm
       patterns:
         - pattern-either:
             - pattern: SecretKeyFactory.getInstance($ALG, ...)
             - pattern: Cipher.getInstance($ALG, ...)
         - metavariable-regex:
             metavariable: $ALG
             regex: PBEWith(MD5|SHA1And(DES|RC2|RC4|40|128))
   ```

   ```bash
   semgrep -c gt-kdf.yml out/sources/ --exclude androidx --exclude kotlin
   ```

   The zero-salt rule only sees the case where the array and its use are in the same method; when the salt comes from a field or a helper, follow it by hand.

4. **Triage each site.** For every hit, answer these questions from the decompiled code:

   - What is the input? A user-entered password, a PIN (look at the UI: `inputType="numberPassword"`, a 4–6 digit keypad), a server-provided value, a device identifier, a constant?
   - Which KDF and PRF? Read the string passed to `SecretKeyFactory.getInstance` or the library call.
   - What work factor? The iteration count or Argon2/scrypt parameters, and whether they are fixed, calibrated or read from storage.
   - Where does the salt come from, and where is it stored? Follow the variable to `SecureRandom().nextBytes`, to a constant, or to a preference read.
   - How long is the output, and how is it split? A `keyLength` of 512 split into two keys with PBKDF2-SHA256 is the "more output than the PRF" mode.
   - What is the result used for? Follow it to `Cipher.init`, `Mac.init`, a stored "verifier", or a network request. A verifier stored next to the ciphertext gives an attacker a direct hashcat target.
   - Is there an attempt limit, and where is it enforced? An app-side counter in preferences does not count.

5. **Check native and hybrid layers.**

   ```bash
   for so in $(find res_out/lib -name '*.so'); do
     hits=$(nm -D "$so" 2>/dev/null | grep -E 'PKCS5_PBKDF2_HMAC|EVP_PBE_scrypt|HKDF|crypto_pwhash|argon2')
     [ -n "$hits" ] && printf '== %s\n%s\n' "$so" "$hits"
   done
   grep -oE 'pbkdf2[A-Za-z]*\([^)]{0,120}\)' res_out/assets/index.android.bundle 2>/dev/null | head
   strings -n 6 res_out/lib/arm64-v8a/libapp.so 2>/dev/null | grep -iE 'pbkdf2|argon2|scrypt|hkdf' | head
   ```

#### Observation

For each derivation: file and line, input type, KDF and PRF, work factor, salt source and length, output length and split, purpose of the key, where salt/parameters/verifier are stored, and any attempt limit. A table works best.

#### Evaluation

The test **fails** if any security-relevant key is:

- the password itself, or a plain or self-iterated hash of it (`MessageDigest`, HKDF, or a loop);
- derived with PBKDF2 below 600,000 iterations (SHA-256), 210,000 (SHA-512) or 1,300,000 (SHA-1), scrypt below N = 2^17/r = 8/p = 1 or its equivalents, or Argon2id below 19 MiB/t = 2/p = 1 or its equivalents;
- derived with no salt, a zero, constant or public-value salt, or a salt shared across users or installs;
- derived from a PIN or other enumerable input with no hardware-enforced or server-enforced attempt limit;
- derived from device identifiers or other values available to code on the device;
- derived with a legacy `PBEWith...` algorithm;
- a raw key-agreement output used without a KDF.

Report as observations: PBKDF2-HMAC-SHA1 at an adequate count; salts shorter than 128 bits but random and unique; parameters not stored or not upgradeable; missing domain separation where keys are not yet used across purposes; the password kept in a `String`.

The test **passes** when every derivation uses a password-based KDF at or above the table, with a random unique salt, for inputs of adequate entropy (or with a hardware or server attempt limit for PINs), and keys for different purposes are separated.

#### Demo

A pattern we see regularly in "PIN-protected vault" features, written in Kotlin:

```kotlin
// Vulnerable: PIN, static salt, low count, one key for everything, verifier stored next to it
private val SALT = "vault-salt-2019".toByteArray()

fun unlock(pin: String): SecretKey {
    val spec = PBEKeySpec(pin.toCharArray(), SALT, 10_000, 256)
    val bytes = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1").generateSecret(spec).encoded
    prefs.edit().putString("pin_check", Base64.encodeToString(bytes, Base64.NO_WRAP)).apply()
    return SecretKeySpec(bytes, "AES")
}
```

After jadx (abridged):

```java
public Vault(SharedPreferences prefs) {
    byte[] bytes = "vault-salt-2019".getBytes(Charsets.UTF_8);
    Intrinsics.checkNotNullExpressionValue(bytes, "getBytes(...)");
    this.SALT = bytes;
}

public final SecretKey unlock(String pin) {
    char[] charArray = pin.toCharArray();
    PBEKeySpec spec = new PBEKeySpec(charArray, this.SALT, 10000, 256);
    byte[] bytes = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1").generateSecret(spec).getEncoded();
    // ...
}
```

`gt-pbkdf2-low-iterations` reports the `PBEKeySpec` line (`10000 < 600000`). The salt is a field initialised from a literal, so `gt-kdf-constant-salt` does not match inside `unlock`; the grep inventory finds the literal, and reading the field initialiser confirms it. Triage adds what no rule sees: the input is a PIN, the 256-bit output is computed as two PBKDF2-SHA1 blocks, and the full derived key is stored in `SharedPreferences` as `pin_check` — so an attacker with the preferences file does not need to crack anything at all. Verdict: fail on every count (plain stored key, PIN, constant salt, low count, SHA-1 with output longer than the PRF).

### Static: locate key derivation and its parameters (iOS)

Platform: iOS. Type: static (binary).

#### Overview

Same goal as the Android procedure, working on the decrypted Mach-O binary and its frameworks with symbol tables and radare2.

#### Prerequisites

- A decrypted IPA (check `cryptid` with `otool -l <binary> | grep -A4 LC_ENCRYPTION_INFO`; `cryptid 1` means you must decrypt it first).
- radare2, `nm`, `otool`, `strings`, `xcrun swift-demangle`.

#### Steps

1. **Extract and list imports.**

   ```bash
   unzip -q App.ipa -d ipa/
   BIN=ipa/Payload/App.app/App
   nm -u "$BIN" | grep -E 'CCKeyDerivationPBKDF|CCCalibratePBKDF|CC_SHA(1|256|512)$|CC_MD5$|CCHmac|SecKeyCopyKeyExchangeResult|crypto_pwhash'
   nm -u "$BIN" | xcrun swift-demangle | grep -E 'CryptoKit\.(HKDF|SharedSecret|SHA256\.hash|SHA512\.hash)' | sort -u
   nm "$BIN" | xcrun swift-demangle | grep -E 'CryptoSwift\.(PKCS5|Scrypt|HKDF)' | sort -u
   ```

   Repeat for each binary in `Frameworks/` and `PlugIns/`.

2. **Read `CCKeyDerivationPBKDF` arguments at each call site.**

   ```text
   r2 -A ipa/Payload/App.app/App
   [0x...]> axt @ sym.imp.CCKeyDerivationPBKDF
   [0x...]> pd-- 30 @ <call address>
   ```

   Look for the immediates loaded into `w5` (PRF: 1 = SHA-1, 3 = SHA-256, 5 = SHA-512) and `w6` (rounds) before the `bl`. Counts above 65,535 need two instructions: 600,000 (`0x927c0`) typically appears as `mov w6, 0x27c0` followed by `movk w6, 0x9, lsl 16`; 10,000 is a single `mov w6, 0x2710`. If `w6` comes from a load rather than an immediate, the count is stored or calibrated — follow it to `CCCalibratePBKDF` or a preferences read. Then follow `x3`/`x4` (salt pointer and length): an `adrp`/`add` into `__TEXT,__cstring` or `__DATA,__const` is a constant salt; dump it with `ps @ <addr>` or `px <len> @ <addr>`.

3. **Find plain-hash keys.** For each `CC_SHA256` or CryptoKit `SHA256.hash` call site, check whether the output flows into `CCCrypt`, `SymmetricKey(data:)` or `HKDF` as key material. For `CCCrypt`, the key pointer is `x3` and its length `x4`; a key buffer filled by `CC_SHA256` or `getCString:maxLength:` from an `NSString` is a hash-as-key or password-as-key finding.

4. **Find HKDF misuse.** For each CryptoKit `HKDF` call, check the `inputKeyMaterial` source (password-derived `SymmetricKey(data:)` is a finding) and read the `info` strings (`iz~vault` or `izz` filtered on likely prefixes). Identical `info` at different call sites, or empty `info`, needs review. For `SharedSecret`, confirm the app calls `hkdfDerivedSymmetricKey` or `x963DerivedSymmetricKey` rather than reading raw bytes.

5. **Look for device-identifier inputs.** `identifierForVendor`, `UIDevice` properties or the bundle identifier near key-derivation code:

   ```text
   [0x...]> iz~identifierForVendor
   [0x...]> axt @ <string address>
   ```

#### Observation

Per call site: function address, PRF, rounds (immediate or source), salt source and bytes, output length, input source, and where the key goes.

#### Evaluation

As for Android: fail on password-as-key, hash-as-key, HKDF on a password, raw shared secrets as keys, rounds below the table for the PRF, constant/missing/shared salts, unprotected PIN-derived keys, and device-identifier inputs. Note a calibrated count as a pass only if it has a floor at the minimum and is stored.

#### Demo

The Objective-C pattern we still meet in older iOS codebases and SDKs:

```objectivec
// Vulnerable: the password IS the key (zero-padded to 32 bytes), no KDF, no IV
- (NSData *)AES256EncryptWithKey:(NSString *)key {
    char keyPtr[kCCKeySizeAES256 + 1];
    bzero(keyPtr, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    size_t bufferSize = self.length + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesEncrypted = 0;
    CCCryptorStatus status = CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
                                     keyPtr, kCCKeySizeAES256, NULL,
                                     self.bytes, self.length, buffer, bufferSize, &numBytesEncrypted);
    // ...
}
```

In radare2, the `CCCrypt` call site typically shows `mov x4, 0x20` (32-byte key length) and `x3` pointing at a stack buffer that was zeroed with `bzero` and filled by `getCString:maxLength:encoding:` — no `CCKeyDerivationPBKDF`, no `CC_SHA256`, nothing between the string and the cipher. Verdict: fail (password used directly as key). The `kCCAlgorithmAES128` constant here does *not* mean a 128-bit key; it names AES, and the key length comes from `x4`. The NULL IV is a separate [MASWE-0007](/mobile/maswe-0007-improper-encryption/) finding.

### Dynamic: capture KDF inputs and parameters at runtime (Android)

Platform: Android. Type: dynamic.

#### Overview

Hook the KDF APIs while you use the app, to record the actual parameters, salt and timing for every derivation — including those in obfuscated code, libraries and runtime-calculated configurations that static review misses — and to compare salts across installs and users.

#### Prerequisites

- A rooted device or emulator with `frida-server` (Frida 17 syntax below), the app installed.
- Two test accounts, if the app has accounts. Use test credentials only: the script can print the password, and that output belongs in your evidence store, not in a shared report.

#### Steps

1. **Save the hook script** as `kdf-android.js`:

   ```javascript
   // kdf-android.js - PBEKeySpec, SecretKeyFactory, PBE ciphers and hash-as-key (Frida 17)
   const SHOW_SECRETS = false;   // true only with test credentials
   Java.perform(function () {
     const Log = Java.use('android.util.Log');
     const Exc = Java.use('java.lang.Exception');
     const JString = Java.use('java.lang.String');
     const hex = function (a) {
       return a ? Array.from(a, function (b) { return ('0' + (b & 0xff).toString(16)).slice(-2); }).join('') : 'null';
     };
     const where = function () {
       return Log.getStackTraceString(Exc.$new()).split('\n').slice(2, 6).join(' | ');
     };

     const PBE = Java.use('javax.crypto.spec.PBEKeySpec');
     PBE.$init.overload('[C', '[B', 'int', 'int').implementation = function (pw, salt, iter, bits) {
       console.log('[PBEKeySpec] pwLen=' + (pw ? pw.length : 0) +
         (SHOW_SECRETS && pw ? ' pw=' + JString.$new(pw) : '') +
         ' saltLen=' + (salt ? salt.length : 0) + ' salt=' + hex(salt) +
         ' iterations=' + iter + ' keyBits=' + bits + '\n    at ' + where());
       return this.$init(pw, salt, iter, bits);
     };
     PBE.$init.overload('[C', '[B', 'int').implementation = function (pw, salt, iter) {
       console.log('[PBEKeySpec] (no key length) pwLen=' + (pw ? pw.length : 0) +
         ' salt=' + hex(salt) + ' iterations=' + iter + '\n    at ' + where());
       return this.$init(pw, salt, iter);
     };
     PBE.$init.overload('[C').implementation = function (pw) {
       console.log('[PBEKeySpec] password only - legacy PBE cipher? pwLen=' + (pw ? pw.length : 0) + '\n    at ' + where());
       return this.$init(pw);
     };

     const PBEParam = Java.use('javax.crypto.spec.PBEParameterSpec');
     PBEParam.$init.overload('[B', 'int').implementation = function (salt, iter) {
       console.log('[PBEParameterSpec] salt=' + hex(salt) + ' iterations=' + iter);
       return this.$init(salt, iter);
     };

     const SKF = Java.use('javax.crypto.SecretKeyFactory');
     SKF.generateSecret.implementation = function (spec) {
       const t0 = Date.now();
       const k = this.generateSecret(spec);
       const enc = k.getEncoded();
       console.log('[SecretKeyFactory.generateSecret] ' + this.getAlgorithm() + ' took ' + (Date.now() - t0) + ' ms, ' +
         (enc ? enc.length * 8 : '?') + ' bits' + (SHOW_SECRETS ? ' key=' + hex(enc) : ''));
       return k;
     };

     // Hash-as-key: remember the last digest, flag a SecretKeySpec whose bytes start with it
     let last = null;
     const MD = Java.use('java.security.MessageDigest');
     MD.digest.overload('[B').implementation = function (input) {
       const out = this.digest(input);
       last = { alg: this.getAlgorithm(), out: hex(out), inLen: input.length };
       return out;
     };
     const SKS = Java.use('javax.crypto.spec.SecretKeySpec');
     SKS.$init.overload('[B', 'java.lang.String').implementation = function (key, alg) {
       const h = hex(key);
       if (last && last.out.indexOf(h) === 0) {
         console.log('[SecretKeySpec] ' + alg + ' ' + key.length * 8 + '-bit key = ' + last.alg +
           '(' + last.inLen + ' bytes) - plain hash used as key\n    at ' + where());
       }
       return this.$init(key, alg);
     };
   });
   ```

2. **Run it from a clean state** and exercise every feature that might derive a key: account creation, login, setting and entering an app PIN, creating, locking and unlocking a vault, exporting or backing up data, changing the password.

   ```bash
   adb shell pm clear com.example.app
   frida -U -f com.example.app -l kdf-android.js -o run1.log
   ```

3. **Repeat for comparison**: clear data and run again with the same account (`run2.log`), then with a second account (`run3.log`). Compare salts:

   ```bash
   grep -ho 'salt=[0-9a-f]*' run1.log run2.log run3.log | sort | uniq -c
   ```

   The same salt in all three runs is a constant salt. The same salt for the same account on a fresh install, but different across accounts, is a salt derived from the account (often the username or email); check whether it is a hash of a public value.

4. **Check the work factor against timing.** `generateSecret` taking under ~20 ms on a modern phone for PBKDF2 means an iteration count far below 600,000; at 600,000 SHA-256 iterations expect several hundred milliseconds on mid-range hardware.

5. **Look for verifiers and PIN gates.** After setting a PIN, pull the app's preferences and look for anything that is a function of the PIN alone (a "pin_hash", "check", or the derived key itself):

   ```bash
   adb shell "su -c 'cat /data/data/com.example.app/shared_prefs/*.xml'" | grep -iE 'pin|hash|check|verif|salt|iter'
   ```

   If the app enforces an attempt limit, find where the counter lives. A counter in preferences or a local database is resettable; confirm by editing it (or clearing it) and trying again.

6. **Library KDFs.** If static analysis found Argon2 or scrypt in Bouncy Castle, add hooks on the parameter builder, for example `org.bouncycastle.crypto.params.Argon2Parameters$Builder.build`, printing `getMemory()`, `getIterations()`, `getLanes()` and `getSalt()` from the result. In obfuscated apps, find the class name in jadx first.

#### Observation

The log lines for each derivation (algorithm, iterations or memory/passes, salt, key length, timing, call stack), the salt comparison across runs and accounts, any stored verifier or derived key, and the location and behaviour of attempt counters.

#### Evaluation

Apply the static evaluation criteria to the runtime values; they take precedence where the two differ (for example a count read from remote configuration). Additionally, the test **fails** if the derived key or a PIN-only verifier is stored on the device, or if an attempt limit is enforced only by resettable app state for a PIN-derived key.

#### Demo

Running `kdf-android.js` against the vulnerable `unlock` function from the static demo, then repeating on a fresh install with a different PIN, gives output of this shape (abridged and illustrative):

```text
[PBEKeySpec] pwLen=6 saltLen=15 salt=7661756c742d73616c742d32303139 iterations=10000 keyBits=256
    at ...Vault.unlock(Vault.kt:6) | ...
[SecretKeyFactory.generateSecret] PBKDF2WithHmacSHA1 took 21 ms, 256 bits
---- second install ----
[PBEKeySpec] pwLen=6 saltLen=15 salt=7661756c742d73616c742d32303139 iterations=10000 keyBits=256
```

The salt is the same on both installs and decodes to the ASCII string `vault-salt-2019`; the input is 6 characters long and numeric in the UI; 10,000 iterations of SHA-1 take a few tens of milliseconds. Fail — and, as the cracking-cost estimate below shows, the whole PIN space falls in seconds on a single GPU.

### Dynamic: capture KDF inputs and parameters at runtime (iOS)

Platform: iOS. Type: dynamic.

#### Overview

The iOS counterpart: hook CommonCrypto's PBKDF2 and calibration functions and the plain-hash functions, filtering hashes to those called from the app's own code.

#### Prerequisites

- A jailbroken device with `frida-server`, the app installed, test credentials.
- Results of the static procedure, so you know whether CommonCrypto, CryptoKit or a third-party library is in use. CryptoKit and CryptoSwift do not go through CommonCrypto and will not show up in these hooks.

#### Steps

1. **Save the hook script** as `kdf-ios.js`:

   ```javascript
   // kdf-ios.js - CCKeyDerivationPBKDF, CCCalibratePBKDF and app-called hashes (Frida 17)
   const SHOW_SECRETS = false;
   const cc = Process.getModuleByName('libcommonCrypto.dylib');
   const app = Process.mainModule;
   const PRF = { 1: 'HMAC-SHA1', 2: 'HMAC-SHA224', 3: 'HMAC-SHA256', 4: 'HMAC-SHA384', 5: 'HMAC-SHA512' };
   const fromApp = function (addr) {
     const m = Process.findModuleByAddress(addr);
     return m !== null && m.name === app.name;
   };

   Interceptor.attach(cc.getExportByName('CCKeyDerivationPBKDF'), {
     onEnter(args) {
       const pwLen = args[2].toUInt32();
       const saltLen = args[4].toUInt32();
       this.t0 = Date.now();
       console.log('[CCKeyDerivationPBKDF] prf=' + (PRF[args[5].toInt32()] || args[5].toInt32()) +
         ' rounds=' + args[6].toUInt32() + ' pwLen=' + pwLen + ' saltLen=' + saltLen +
         ' outLen=' + args[8].toUInt32());
       if (SHOW_SECRETS) console.log('    password=' + args[1].readUtf8String(pwLen));
       if (saltLen > 0) console.log(hexdump(args[3], { length: saltLen, header: false, ansi: false }));
       console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).slice(0, 4).join('\n'));
     },
     onLeave(ret) {
       console.log('    status=' + ret.toInt32() + ', took ' + (Date.now() - this.t0) + ' ms');
     }
   });

   Interceptor.attach(cc.getExportByName('CCCalibratePBKDF'), {
     onEnter(args) { this.ms = args[5].toUInt32(); },
     onLeave(ret) { console.log('[CCCalibratePBKDF] target ' + this.ms + ' ms -> ' + ret.toUInt32() + ' rounds'); }
   });

   ['CC_MD5', 'CC_SHA1', 'CC_SHA256', 'CC_SHA512'].forEach(function (name) {
     Interceptor.attach(cc.getExportByName(name), {
       onEnter(args) {
         this.show = fromApp(this.returnAddress);
         if (this.show) {
           this.len = args[1].toUInt32();
           this.md = args[2];
         }
       },
       onLeave(ret) {
         if (this.show) {
           console.log('[' + name + '] called from app, input ' + this.len + ' bytes, digest:');
           console.log(hexdump(this.md, { length: 16, header: false, ansi: false }));
         }
       }
     });
   });

   Interceptor.attach(cc.getExportByName('CCCrypt'), {
     onEnter(args) {
       if (!fromApp(this.returnAddress)) return;
       const keyLen = args[4].toUInt32();
       console.log('[CCCrypt] alg=' + args[1].toInt32() + ' keyLength=' + keyLen + ' key:');
       console.log(hexdump(args[3], { length: keyLen, header: false, ansi: false }));
     }
   });
   ```

2. **Run it from a clean install** and exercise the same features as on Android:

   ```bash
   frida -U -f com.example.app -l kdf-ios.js -o ios-run1.log
   ```

   Then delete and reinstall the app (and, because Keychain items survive deletion, also remove the app's Keychain items with objection's `ios keychain clear` if you want a genuinely fresh state), and run again with the same and with a different account.

3. **Correlate.** A `CC_SHA256` digest whose bytes reappear as the key in a following `CCCrypt` line is hash-as-key. A `CCCrypt` key that is visibly ASCII followed by zero bytes is a password used as key. A `CCKeyDerivationPBKDF` salt that is identical across installs is a constant salt.

4. **Check storage and attempt limits** as on Android: inspect the app's preferences plist and Keychain items for PIN verifiers or derived keys, and find where any attempt counter lives.

#### Observation

The log lines for each derivation, the salt comparison, any hash-to-key or password-to-key correlations, stored verifiers, and attempt-counter behaviour.

#### Evaluation

As for the Android dynamic procedure.

#### Demo

Hooking the `AES256EncryptWithKey:` category from the static demo, called with the test password `hunter2`, the `CCCrypt` hook prints:

```text
[CCCrypt] alg=0 keyLength=32 key:
00000000  68 75 6e 74 65 72 32 00 00 00 00 00 00 00 00 00  hunter2.........
00000010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
```

No `CCKeyDerivationPBKDF` or hash line precedes it. The "256-bit key" is seven ASCII characters and 25 zero bytes. Fail.

### Estimating offline cracking cost for the report

Guler Tech methodology. Use this to turn a KDF finding into a concrete statement of attacker effort, which is what decides severity and what developers find persuasive.

#### Overview

Offline cost depends on three numbers: the size of the input space the attacker must search, the cost of one guess under the app's KDF, and the attacker's hardware throughput. The salt does not change the per-target cost; it prevents the attacker from sharing work across targets.

```text
expected time  ≈  (search space / 2)  ×  cost per guess  /  attacker throughput
cloud cost     ≈  GPU-hours needed  ×  price per GPU-hour
```

#### Prerequisites

- The KDF parameters from the static or dynamic procedures.
- Something to test guesses against, and a note of how the attacker obtains it: a stored verifier, ciphertext with an authentication tag (AES-GCM, or AES-CBC with an HMAC), or ciphertext with a known plaintext structure (a file header, JSON). Write down the access needed — backup, root/jailbreak, physical device, server breach — because that is half of the severity.
- A GPU machine with `hashcat` if you want to measure rather than estimate.

#### Steps

1. **Size the search space.**

   | Input | Space | Bits |
   |---|---|---|
   | 4-digit PIN | 10^4 | 13.3 |
   | 6-digit PIN | 10^6 | 19.9 |
   | 8 lowercase letters | 26^8 ≈ 2.1 × 10^11 | 37.6 |
   | 8 characters, letters and digits | 62^8 ≈ 2.2 × 10^14 | 47.6 |
   | 4 random diceware words | 7776^4 ≈ 3.7 × 10^15 | 51.7 |

   Human-chosen passwords do not have the entropy their length suggests. For them, model a wordlist-and-rules attack of a stated size (for example 10^10 or 10^12 guesses) rather than the character-set maths, and say that is what you did.

2. **Measure attacker throughput.** Benchmark the closest hashcat mode on a current GPU:

   ```bash
   hashcat -b -m 10900     # PBKDF2-HMAC-SHA256
   hashcat -b -m 12100     # PBKDF2-HMAC-SHA512
   hashcat -b -m 12000     # PBKDF2-HMAC-SHA1
   hashcat -b -m 8900      # scrypt
   hashcat -b -m 1400      # plain SHA-256
   ```

   Hashcat benchmarks PBKDF2 modes at a fixed, low iteration count that it prints with the result (999 for the PBKDF2 modes in current versions). Convert to iterations per second (`rate × benchmark iterations`), then divide by the app's iteration count to get guesses per second for the app. For Argon2id, check whether your hashcat version supports it (`hashcat --help | grep -i argon`); if not, time single derivations with the reference `argon2` CLI on a CPU to get a per-guess lower bound.

   If you cannot benchmark, use an order-of-magnitude planning figure and label it as such. Ours: a current high-end consumer GPU computes roughly 10^10 PBKDF2-HMAC-SHA256 iterations per second, and about 2 × 10^10 single SHA-256 hashes of short inputs.

3. **Compute.** With those planning figures, the time for **one GPU** to exhaust each space:

   | KDF (SHA-256) | Guesses/s per GPU | 6-digit PIN | 8 lowercase | 10^10 wordlist + rules |
   |---|---|---|---|---|
   | Plain SHA-256 | ~2 × 10^10 | < 1 ms | ~10 s | ~0.5 s |
   | PBKDF2, 1,000 iterations | ~10^7 | ~0.1 s | ~6 h | ~17 min |
   | PBKDF2, 10,000 iterations | ~10^6 | ~1 s | ~2.4 days | ~2.8 h |
   | PBKDF2, 100,000 iterations | ~10^5 | ~10 s | ~24 days | ~28 h |
   | PBKDF2, 600,000 iterations | ~1.7 × 10^4 | ~1 min | ~145 days | ~7 days |

   Divide by the number of GPUs the attacker is assumed to have, and halve for the expected (average) case. At an assumed cloud price of $2 per GPU-hour, the 145-day figure is about 3,500 GPU-hours, roughly $7,000 — affordable for a targeted attack on one high-value user, expensive across many users *only if each has a unique salt*.

   Two conclusions hold regardless of the exact figures: **every PIN falls in minutes**, and **every plain-hash derivation of a human password falls quickly**. Use the table to show the client the difference that the work factor makes for real passwords, and to show that it makes none for PINs.

4. **Optional: demonstrate.** If the app stores a PBKDF2-HMAC-SHA256 verifier (mode 12000 with a `sha1:` prefix for SHA-1, 12100 with `sha512:` for SHA-512), put it in hashcat's format and crack a test PIN you set yourself:

   ```bash
   # mode 10900 (PBKDF2-HMAC-SHA256) format: sha256:<iterations>:<base64 salt>:<base64 derived bytes>
   echo 'sha256:<iterations>:<base64 salt>:<base64 verifier>' > pin.hash
   hashcat -m 10900 -a 3 pin.hash '?d?d?d?d?d?d'
   ```

   For ciphertext without a verifier, a short script that derives the key and tries an authenticated decryption is enough; AES-GCM's tag check is a perfect oracle:

   ```text
   # pin_poc.py - demonstrate PIN recovery against a PBKDF2 + AES-GCM blob (test data only)
   import hashlib, sys
   from cryptography.hazmat.primitives.ciphers.aead import AESGCM
   from cryptography.exceptions import InvalidTag

   salt, iters = bytes.fromhex(sys.argv[1]), int(sys.argv[2])
   nonce, ct = bytes.fromhex(sys.argv[3]), bytes.fromhex(sys.argv[4])
   for pin in range(10**6):
       key = hashlib.pbkdf2_hmac('sha256', f'{pin:06d}'.encode(), salt, iters, dklen=32)
       try:
           print('PIN', f'{pin:06d}', AESGCM(key).decrypt(nonce, ct, None)[:32])
           break
       except InvalidTag:
           pass
   ```

   Python on a CPU is slow; for the report, run it over a small range around the PIN you set to prove the method, and use the GPU figures for the full-space estimate.

#### Observation

The search space, the KDF cost, the throughput figure and whether it was measured or assumed, the resulting time and cost for one GPU and for a stated attacker budget, and what the attacker needs to obtain first.

#### Evaluation

A KDF configuration is adequate when the expected cost to recover a realistic user secret, for the attacker your threat model assumes, exceeds the value of what it protects for as long as it needs protecting — and, for PINs, when there is a hardware or server attempt limit, because no offline cost will be adequate. Put the numbers in the finding.

#### Demo

Report wording we use, adapted per finding:

> The vault key is derived from the user's 6-digit PIN with PBKDF2-HMAC-SHA1, 10,000 iterations, and a salt that is identical on every installation. The salt and an encrypted vault can be obtained from an unencrypted device backup. With a single current consumer GPU, all 10^6 possible PINs can be tested in a few seconds; one precomputed table recovers the PIN for any user's backup. Increasing the iteration count would not fix this: even at 600,000 iterations the full PIN space falls in about a minute. The key must be bound to hardware with an enforced attempt limit (device credential) or to a server-held share released after server-side PIN verification.

## Secure implementation

### Android: passphrase → PBKDF2 → HKDF, with stored parameters

```kotlin
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

data class KdfParams(val version: Int, val iterations: Int, val salt: ByteArray)

object PassphraseKdf {
    const val MIN_ITERATIONS = 600_000

    fun newParams(): KdfParams =
        KdfParams(version = 1, iterations = MIN_ITERATIONS, salt = ByteArray(16).also { SecureRandom().nextBytes(it) })

    fun masterKey(passphrase: CharArray, p: KdfParams): ByteArray {
        require(p.iterations >= MIN_ITERATIONS && p.salt.size >= 16)
        val spec = PBEKeySpec(passphrase, p.salt, p.iterations, 256)   // one SHA-256 block
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
    }

    // RFC 5869 HKDF-SHA256. Prefer Tink's Hkdf.computeHkdf in production code.
    fun hkdf(ikm: ByteArray, salt: ByteArray?, info: ByteArray, length: Int): ByteArray {
        require(length in 1..255 * 32)
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(salt?.takeIf { it.isNotEmpty() } ?: ByteArray(32), "HmacSHA256"))
        val prk = mac.doFinal(ikm)
        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        val out = ByteArrayOutputStream()
        var t = ByteArray(0)
        var counter = 1
        while (out.size() < length) {
            mac.update(t); mac.update(info); mac.update(counter.toByte())
            t = mac.doFinal()
            out.write(t)
            counter++
        }
        return out.toByteArray().copyOf(length)
    }

    fun purposeKey(master: ByteArray, purpose: String): SecretKey =
        SecretKeySpec(hkdf(master, null, "com.example.vault/v1/$purpose".toByteArray(), 32), "AES")
}

// Usage: derive once per unlock, separate keys per purpose, zero the master afterwards.
// val master = PassphraseKdf.masterKey(chars, params)
// val encKey = PassphraseKdf.purposeKey(master, "file-enc")
// val idxKey = PassphraseKdf.purposeKey(master, "index-enc")
// master.fill(0); chars.fill('\u0000')
```

Store `version`, `iterations` and `salt` in a header in front of the ciphertext. On each successful unlock, if `iterations` is below the current target, re-derive with new parameters and re-wrap the data key. Never store the master key or a verifier derived from the same output; if you need a fast "wrong password" check, rely on the AES-GCM tag of the encrypted data key.

For Argon2id with Bouncy Castle, the master-key step becomes:

```kotlin
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters

fun argon2idMaster(passphrase: CharArray, salt: ByteArray): ByteArray {
    val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
        .withVersion(Argon2Parameters.ARGON2_VERSION_13)
        .withMemoryAsKB(64 * 1024)      // 64 MiB, above the OWASP minimum
        .withIterations(3)
        .withParallelism(1)
        .withSalt(salt)
        .build()
    val out = ByteArray(32)
    Argon2BytesGenerator().apply { init(params) }.generateBytes(passphrase, out)
    return out
}
```

### Android: a PIN that cannot be attacked offline

The PIN is stretched, then mixed with an HMAC computed by a non-exportable keystore key, so a copy of the app's files is not enough. Prefer device-credential binding (`setUserAuthenticationRequired`) when the product allows it; this pattern is for when an app-specific PIN is a requirement.

```kotlin
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

const val PEPPER_ALIAS = "pin-pepper-v1"

fun ensurePepperKey() {
    val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    if (ks.containsAlias(PEPPER_ALIAS)) return
    KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore").apply {
        init(KeyGenParameterSpec.Builder(PEPPER_ALIAS, KeyProperties.PURPOSE_SIGN).build())
        generateKey()
    }
}

fun pinKek(pin: CharArray, params: KdfParams): SecretKey {
    val stretched = PassphraseKdf.masterKey(pin, params)          // brute-forceable on its own
    val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val pepper = ks.getKey(PEPPER_ALIAS, null) as SecretKey      // never leaves the TEE/StrongBox
    val ikm = Mac.getInstance("HmacSHA256").run { init(pepper); doFinal(stretched) }
    stretched.fill(0)
    return SecretKeySpec(PassphraseKdf.hkdf(ikm, null, "com.example.vault/v1/pin-kek".toByteArray(), 32), "AES")
}
```

An attacker with code execution on the device can still drive the keystore HMAC once per guess, so for high-value data add a server-side component or use the device credential.

### iOS: passphrase → PBKDF2 (CommonCrypto) → HKDF (CryptoKit)

```swift
import CommonCrypto
import CryptoKit
import Foundation
import Security

enum KdfError: Error { case derivationFailed(Int32) }

let minimumRounds: UInt32 = 600_000

func newSalt() -> Data {
    var bytes = [UInt8](repeating: 0, count: 16)
    precondition(SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess)
    return Data(bytes)
}

func masterKey(password: String, salt: Data, rounds: UInt32 = minimumRounds) throws -> SymmetricKey {
    precondition(rounds >= minimumRounds && salt.count >= 16)
    var derived = [UInt8](repeating: 0, count: 32)
    let status = salt.withUnsafeBytes { saltPtr in
        CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                             password, password.utf8.count,
                             saltPtr.bindMemory(to: UInt8.self).baseAddress, salt.count,
                             CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                             rounds,
                             &derived, derived.count)
    }
    guard status == Int32(kCCSuccess) else { throw KdfError.derivationFailed(status) }
    defer { derived.withUnsafeMutableBytes { _ = memset($0.baseAddress!, 0, $0.count) } }
    return SymmetricKey(data: derived)
}

func purposeKey(_ master: SymmetricKey, purpose: String) -> SymmetricKey {
    HKDF<SHA256>.deriveKey(inputKeyMaterial: master,
                           salt: Data(),
                           info: Data("com.example.vault/v1/\(purpose)".utf8),
                           outputByteCount: 32)
}
```

Persist the salt and round count with the ciphertext, as on Android. For Argon2id on iOS, use libsodium's `crypto_pwhash` with `crypto_pwhash_ALG_ARGON2ID13` (through a maintained wrapper such as swift-sodium) and the parameters from the table.

### iOS: a PIN bound to the Secure Enclave

The Secure Enclave cannot compute an HMAC for apps, but it can perform ECDH. A key-agreement private key generated in the Enclave, combined with a fixed peer public key stored by the app, yields a device-bound secret that only this device's Enclave can reproduce:

```swift
import CryptoKit
import Foundation

// Once: create the Enclave key and a peer key; persist enclaveKey.dataRepresentation
// and peerPublic.rawRepresentation (neither is secret outside this device). Discard the peer private key.
// let enclaveKey = try SecureEnclave.P256.KeyAgreement.PrivateKey()
// let peerPublic = P256.KeyAgreement.PrivateKey().publicKey

func pinKek(pin: String, salt: Data,
            enclaveKey: SecureEnclave.P256.KeyAgreement.PrivateKey,
            peerPublic: P256.KeyAgreement.PublicKey) throws -> SymmetricKey {
    let stretched = try masterKey(password: pin, salt: salt)                  // PBKDF2 as above
    let deviceSecret = try enclaveKey.sharedSecretFromKeyAgreement(with: peerPublic)
    var ikm = deviceSecret.withUnsafeBytes { Data($0) }
    stretched.withUnsafeBytes { ikm.append(contentsOf: $0) }
    defer { ikm.resetBytes(in: 0..<ikm.count) }
    return HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: ikm),
                                  salt: salt,
                                  info: Data("com.example.vault/v1/pin-kek".utf8),
                                  outputByteCount: 32)
}
```

The same caveat applies as on Android: this stops offline attacks, not an attacker who controls the running app on the unlocked device. Protecting the Enclave key with an access control that requires `.devicePasscode` or `.userPresence` puts the device passcode's hardware attempt limits in front of it.

### Both platforms: review checklist

- A password-based KDF for every human-memorable input; a key-based KDF only for full-entropy inputs.
- Work factor at or above the OWASP table; parameters stored and upgradeable.
- Random, unique, 128-bit or longer salt per derivation.
- PINs protected by a hardware or server attempt limit, not by the KDF.
- One master derivation, then HKDF with distinct `info` per purpose; no output longer than the PRF from PBKDF2.
- No stored verifier equal to (or derived from the same output as) the key.
- Key-agreement outputs always passed through HKDF or the X9.63 KDF.
- Passwords in `CharArray`/`[UInt8]` buffers, zeroed after use; `PBEKeySpec.clearPassword()` called.

## Rating findings

Rate on what the derived key protects, how the attacker obtains the material needed to test guesses, and the cracking cost you computed. Use these as starting points.

| Rating | Conditions |
|---|---|
| **Critical** | Key derived only from constants or device identifiers (effectively a hardcoded key) protecting credentials, tokens or sensitive data at scale; or a password-derived key using a plain hash or the password itself, where the ciphertext or verifier is held server-side or synced to the cloud, so a single breach exposes all users' passwords to fast cracking. |
| **High** | PIN-derived key with no hardware or server attempt limit protecting sensitive data obtainable from a backup, a rooted or jailbroken device, or shared storage; plain-hash or HKDF-on-password derivation for on-device data; PBKDF2 below 10,000 iterations; a constant or shared salt combined with a weak work factor; the derived key or a PIN-only verifier stored on the device. |
| **Medium** | PBKDF2 between 10,000 and the recommended count (or scrypt/Argon2 parameters well below the table) for a password-protected key; a constant or public-value salt with an otherwise adequate work factor; PBKDF2 output longer than the PRF split into several keys; one derived key used for several purposes; raw ECDH output used as a key; legacy `PBEWith...` algorithms. |
| **Low** | PBKDF2-HMAC-SHA1 at an adequate count; salt shorter than 128 bits but random and unique; parameters not stored or not upgradeable; a PIN mixed with a keystore or Secure Enclave secret but with no hard attempt limit, for moderately sensitive data; passwords kept in `String`. |
| **Info** | Argon2id or scrypt slightly below one OWASP configuration but above an equivalent one; HKDF `info` values that could be more specific; calibration targets that are adequate on current devices but have no floor. |

In the report, state the KDF, PRF, work factor and salt behaviour with evidence (decompiled line or Frida log), what the attacker must obtain and how, the search space, and the cracking estimate with its assumptions. A one-line comparison — "at the current setting all 6-digit PINs fall in about one second on one GPU; at the recommended setting, about one minute; with device-credential binding, offline guessing is not possible" — makes the recommendation self-evident.

## References

- OWASP MASWE — [MASWE-0014: Improper Cryptographic Key Derivation](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0014/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0012: Key Generation](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0012/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0047: Cryptographic Key Storage](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0047/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0069: Key Management](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0069/) (CC BY-SA 4.0)
- OWASP MASTG — [Mobile App Cryptography (Improper Key Derivation Functions)](https://mas.owasp.org/MASTG/0x04g-Testing-Cryptography/) (CC BY-SA 4.0)
- OWASP MASTG — legacy (MASTG v1) tests [MASTG-TEST-0013](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0013/), [MASTG-TEST-0014](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0014/), [MASTG-TEST-0061](https://mas.owasp.org/MASTG/tests/ios/MASVS-CRYPTO/MASTG-TEST-0061/), [MASTG-TEST-0062](https://mas.owasp.org/MASTG/tests/ios/MASVS-CRYPTO/MASTG-TEST-0062/) (CC BY-SA 4.0)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [NIST SP 800-132 — Recommendation for Password-Based Key Derivation, Part 1: Storage Applications](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf)
- [NIST SP 800-57 Part 1 Rev. 5 — Recommendation for Key Management](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf)
- [NIST SP 800-56C Rev. 2 — Recommendation for Key-Derivation Methods in Key-Establishment Schemes](https://csrc.nist.gov/pubs/sp/800/56/c/r2/final)
- [NIST SP 800-108 Rev. 1 — Recommendation for Key Derivation Using Pseudorandom Functions](https://csrc.nist.gov/pubs/sp/800/108/r1/upd1/final)
- [RFC 8018 — PKCS #5: Password-Based Cryptography Specification Version 2.1](https://www.rfc-editor.org/rfc/rfc8018)
- [RFC 7914 — The scrypt Password-Based Key Derivation Function](https://www.rfc-editor.org/rfc/rfc7914)
- [RFC 9106 — Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications](https://www.rfc-editor.org/rfc/rfc9106)
- [RFC 5869 — HMAC-based Extract-and-Expand Key Derivation Function (HKDF)](https://www.rfc-editor.org/rfc/rfc5869)
- [Android Developers — `SecretKeyFactory`](https://developer.android.com/reference/javax/crypto/SecretKeyFactory), [`PBEKeySpec`](https://developer.android.com/reference/javax/crypto/spec/PBEKeySpec), [`KeyGenParameterSpec.Builder`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder)
- [Android Developers Blog — Changes to the SecretKeyFactory API in Android 4.4](https://android-developers.googleblog.com/2013/12/changes-to-secretkeyfactory-api-in.html)
- [AOSP — Gatekeeper](https://source.android.com/docs/security/features/authentication/gatekeeper)
- [Apple — CryptoKit `HKDF`](https://developer.apple.com/documentation/cryptokit/hkdf) and [`SharedSecret`](https://developer.apple.com/documentation/cryptokit/sharedsecret)
- [Apple Platform Security Guide](https://support.apple.com/guide/security/welcome/web) (passcodes and the Secure Enclave)
- [hashcat — example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [CWE-326](https://cwe.mitre.org/data/definitions/326.html), [CWE-327](https://cwe.mitre.org/data/definitions/327.html), [CWE-759](https://cwe.mitre.org/data/definitions/759.html), [CWE-760](https://cwe.mitre.org/data/definitions/760.html), [CWE-916](https://cwe.mitre.org/data/definitions/916.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
