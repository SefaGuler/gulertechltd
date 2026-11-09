---
title: "Improper Hashing (MASWE-0008)"
date: 2026-11-09 09:09:00 +0000
subcategory: crypto
summary: "Finding MD5, SHA-1, fast and unsalted hashes in Android and iOS apps, judging whether each use matters, and what to replace them with."
refs: [MASWE-0008, MASVS-CRYPTO-1, CWE-328, CWE-759, CWE-916]
tags: [android, ios, masvs-crypto, hashing, md5, sha-1]
---

This note is part of our [MASVS-CRYPTO guide](/mobile/masvs-crypto-cryptography-guide/) and covers OWASP [MASWE-0008](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0008/): an app uses a hash function that is broken, or uses a sound hash function for a job it was never meant to do. Hashes are everywhere in mobile code, and most uses are harmless, so the real skill in this test is not finding `MD5` in a binary — any `grep` does that — but deciding which of the dozens of hits actually protect something. You will find the background you need to make that call (collision versus preimage resistance, the real status of MD5 and SHA-1, length extension, why password hashing is a separate problem, and why hashing a phone number does not anonymise it), the OWASP iOS test with both of its demos, an Android test procedure of our own (OWASP links no Android test to this weakness), supplementary runtime and privacy checks, replacement code in Kotlin and Swift, and severity guidance.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [General: hash properties and security strength (Guler Tech methodology)](#general-hash-properties-and-security-strength-guler-tech-methodology)
  - [General: MD5 and SHA-1 today (Guler Tech methodology)](#general-md5-and-sha-1-today-guler-tech-methodology)
  - [General: SHA-2, SHA-3 and truncated digests (Guler Tech methodology)](#general-sha-2-sha-3-and-truncated-digests-guler-tech-methodology)
  - [General: length extension and secret-prefix hashing (Guler Tech methodology)](#general-length-extension-and-secret-prefix-hashing-guler-tech-methodology)
  - [General: password hashing is a different problem (Guler Tech methodology)](#general-password-hashing-is-a-different-problem-guler-tech-methodology)
  - [General: unsalted hashes of low-entropy data (Guler Tech methodology)](#general-unsalted-hashes-of-low-entropy-data-guler-tech-methodology)
  - [Android: MessageDigest and friends (Guler Tech methodology)](#android-messagedigest-and-friends-guler-tech-methodology)
  - [iOS: CryptoKit hash functions (MASTG-KNOW-0066)](#ios-cryptokit-hash-functions-mastg-know-0066)
  - [iOS: CommonCrypto digests and third-party libraries (MASTG-KNOW-0067, MASTG-KNOW-0068)](#ios-commoncrypto-digests-and-third-party-libraries-mastg-know-0067-mastg-know-0068)
- [Tests](#tests)
  - [MASTG-TEST-0211: Broken Hashing Algorithms (iOS)](#mastg-test-0211-broken-hashing-algorithms-ios)
  - [Android: Broken Hashing Algorithms (Guler Tech methodology)](#android-broken-hashing-algorithms-guler-tech-methodology)
  - [Supplementary checks (Guler Tech methodology)](#supplementary-checks-guler-tech-methodology)
- [Secure implementation](#secure-implementation)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

A cryptographic hash function maps input of any length to a fixed-length digest. Security depends on three properties — collision resistance, second-preimage resistance and preimage resistance — and on the hash being used in a design that only relies on the properties it actually has. MASWE-0008 is about the two ways that goes wrong:

- **The algorithm is broken for the property the design relies on.** MD5 and SHA-1 no longer provide collision resistance. Anything whose security rests on "nobody can produce two inputs with the same hash" — digital signatures, certificate signatures, content-addressed deduplication across users, commitment schemes — is weakened or broken when it uses them. NIST has deprecated both for security use (see [NIST SP 800-131A Rev. 2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf)).
- **The primitive is wrong for the job.** A plain hash is not a MAC (it has no key, so anyone can recompute it), not a password-storage function (it is designed to be fast, which is exactly what an attacker wants), not a KDF, and not an anonymiser. A non-cryptographic checksum such as CRC-32 is not even a hash in the security sense. Using SHA-256 does not help in any of these cases.

The weakness maps to MASVS-CRYPTO-1 (strong cryptography used according to best practice) and CWE-328 (Use of Weak Hash). Its MASVS v1 ancestor is MSTG-CRYPTO-4, and it applies to the L1, L2 and EUDIW (EU Digital Identity Wallet) profiles. When you write up the wrong-tool cases, CWE-759 (Use of a One-Way Hash without a Salt) and CWE-916 (Use of Password Hash With Insufficient Computational Effort) describe them more precisely than CWE-328.

For every hash you find, answer three questions in order. The answers decide whether you have a finding at all, and they map directly onto the rating table at the end:

1. **What does the hash protect, and against whom?** A cache file name protects nothing. A digest that a server signs, or that the app checks before loading code, protects integrity against whoever can supply the input.
2. **Which property does that use rely on?** Collision resistance (attacker controls *both* inputs), second-preimage resistance (attacker must match a digest *you* produced), preimage resistance (attacker must invert a digest), or none of them (a hash used as a *keyed* function or anonymiser is the wrong tool whatever the algorithm).
3. **Can the attacker guess the input?** If the input is a PIN, phone number, email address or date of birth, the hash is reversible by enumeration no matter how strong the function is.

## Modes of Introduction

**Broken hash algorithms.** MD5 or SHA-1 used where an attacker benefits from producing colliding inputs. On mobile this is rarer than the number of `MD5` hits suggests; the classic cases are signatures over data the attacker can partly choose (signed documents, signed requests that include attacker text), certificate or token formats that sign a SHA-1 digest, and deduplication or caching keyed on a digest of attacker-controlled content shared between users.

**Wrong hash for the job.**

- Passwords or PINs hashed with a single round of MD5, SHA-1 or SHA-256 and stored on the device, sent to the server as the credential, or used as an encryption key. See [MASWE-0014](/mobile/maswe-0014-improper-key-derivation/) for the key-derivation side.
- A plain hash used as a "signature" or integrity check where the attacker can simply recompute it: `SHA-256(data)` stored next to the data in `SharedPreferences`, `SHA-256(secret + params)` as an API request signature. The first needs a MAC or signature ([MASWE-0009](/mobile/maswe-0009-improper-use-of-mac/), [MASWE-0010](/mobile/maswe-0010-improper-signature-generation/)); the second is open to length extension.
- Hashing low-entropy personal data (phone numbers, email addresses, IMEIs, names, dates of birth) and treating the result as anonymous, for analytics, contact discovery, ad matching or crash reports.
- Non-cryptographic checksums (CRC-32, Adler-32, `String.hashCode()`, MurmurHash, xxHash, Luhn) used where an attacker, not a flaky network, is the threat.

**Truncated digests.** The app keeps only part of a digest — the first 8 hex characters of a SHA-256 as an integrity tag, a 4-byte prefix as an identifier, a short hash as a "verification code". Truncating to *n* bits leaves *n*/2 bits of collision resistance: 32 bits becomes a 16-bit birthday bound, about 65,000 attempts.

## Impact

- **Undetected modification of data.** Where a weak or unkeyed hash is the only integrity control, an attacker who can change the data can change the digest too (unkeyed) or craft a colliding pair (broken algorithm), and the app or backend accepts the modified data as genuine.
- **Forgery and authentication bypass.** Signatures or certificates over MD5/SHA-1 digests can be forged with chosen-prefix collisions; secret-prefix "signatures" can be extended to authenticate requests the key holder never made.
- **Credential and secret recovery.** Fast, unsalted password and PIN hashes are cracked offline at billions of guesses per second on a single GPU; a recovered password is then reused against the backend and other services.
- **De-anonymisation and regulatory exposure.** Hashed identifiers are reversed by enumeration, so an analytics or advertising feed of "anonymous" hashes is in fact a feed of personal data. Under UK GDPR a hashed identifier is at best pseudonymised personal data, not anonymous data.

## Mitigations

- **Use approved hash functions for security purposes**: SHA-256, SHA-384 or SHA-512 (FIPS 180-4) or SHA3-256 and above (FIPS 202), in line with NIST SP 800-131A. Prefer 256-bit or larger outputs for anything long-lived, which also covers the post-quantum guidance in [NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/ipd).
- **Use the right primitive.** Keyed integrity needs HMAC or an AEAD ([MASWE-0009](/mobile/maswe-0009-improper-use-of-mac/)); third-party-verifiable integrity needs a signature ([MASWE-0010](/mobile/maswe-0010-improper-signature-generation/), [MASWE-0011](/mobile/maswe-0011-improper-signature-verification/)); passwords need Argon2id, scrypt, bcrypt or PBKDF2 with current parameters ([MASWE-0014](/mobile/maswe-0014-improper-key-derivation/)).
- **Never treat a hash of guessable data as anonymous.** Do not compute it on the client at all if you can avoid it; if pseudonymisation is needed, do it on the server with a keyed function whose key never reaches the app.
- **Do not truncate digests below the security level the use needs**: at least 128 bits of output for collision-sensitive uses, more for long-term ones.
- **Leave MD5 and SHA-1 only where no security depends on them** (cache keys, change detection, interoperability with fixed external formats), and say so in a code comment so the next reviewer does not have to rediscover it.

## Knowledge

OWASP links no Knowledge page directly to MASWE-0008, and its only test (MASTG-TEST-0211) is iOS-only. The general sections below are our own background material, marked **Guler Tech methodology**. The two iOS sections build on the MASTG Knowledge pages that list the platform's hash APIs.

### General: hash properties and security strength (Guler Tech methodology)

For an ideal *n*-bit hash:

| Property | What the attacker must do | Generic cost |
|---|---|---|
| Preimage resistance | Given a digest *h*, find any *m* with H(*m*) = *h* | 2^*n* |
| Second-preimage resistance | Given *m*1, find a different *m*2 with the same digest | 2^*n* |
| Collision resistance | Find any pair *m*1 ≠ *m*2 with the same digest | 2^(*n*/2) (birthday bound) |

The asymmetry matters in triage. A **collision** attack only helps when the attacker controls or influences both inputs: they prepare a benign and a malicious document with the same digest, get the benign one signed or approved, then swap. A **second-preimage** attack is what you need to substitute a file that *someone else* produced and hashed, and no practical second-preimage attack exists for MD5 or SHA-1. So "the app verifies a vendor-built download against an MD5 checksum shipped in the app" is not broken *by collisions* (the attacker did not make the original), although it is still non-compliant and should be fixed. Conversely, "the app hashes user-supplied content with SHA-1 and the server signs the digest" is exactly the collision case.

NIST expresses this as security strength (SP 800-107 Rev. 1 and SP 800-57 Part 1): collision strength is half the output length, preimage strength is the full length. Security strengths below 112 bits are disallowed for new use; 112 bits is acceptable until the end of 2030; 128 bits and above has no announced end date.

| Function | Output | Collision strength | Status for security use |
|---|---|---|---|
| MD5 | 128 | Broken (seconds) | Do not use |
| SHA-1 | 160 | Broken (about 2^63 work) | Disallowed for signature generation; NIST plans to retire it by end of 2030 |
| SHA-224, SHA-512/224, SHA3-224 | 224 | 112 | Acceptable now; the SP 800-131A Rev. 3 draft proposes retiring 112-bit options after 2030 |
| SHA-256, SHA-512/256, SHA3-256 | 256 | 128 | Approved |
| SHA-384, SHA3-384 | 384 | 192 | Approved |
| SHA-512, SHA3-512 | 512 | 256 | Approved |
| SHAKE128 / SHAKE256 | variable | min(*d*/2, 128 / 256) | Approved extendable-output functions (FIPS 202) |
| BLAKE2, BLAKE3 | 256 typical | 128 | Cryptographically sound but not NIST-approved; fine outside FIPS contexts |
| CRC-32, Adler-32, `hashCode()`, MurmurHash, xxHash | 32–128 | None | Not cryptographic; detect accidents only |

A quantum computer running Grover's algorithm halves preimage strength, and quantum collision search gives no practical advantage over classical birthday attacks at these sizes. That is why post-quantum guidance such as NIST IR 8547 concentrates on public-key algorithms and leaves SHA-256 and SHA-3 in place; the practical takeaway is to prefer outputs of 256 bits or more.

### General: MD5 and SHA-1 today (Guler Tech methodology)

**MD5.** Wang and Yu published practical collisions in 2004–2005; today an identical-prefix collision takes seconds on a laptop with public tools such as HashClash. Chosen-prefix collisions — two *different, meaningful* prefixes extended to the same digest — followed in 2007 (Stevens, Lenstra and de Weger) and were used to create a rogue CA certificate in 2008. The Flame malware (2012) used an MD5 chosen-prefix collision to forge a Microsoft code-signing certificate. Preimage attacks remain theoretical (around 2^123 work), which is why MD5 still "works" as a checksum.

**SHA-1.** The SHAttered attack (Stevens, Bursztein, Karpman, Albertini and Markov, 2017) produced the first public SHA-1 collision, two different PDFs, at roughly 2^63 SHA-1 computations. "SHA-1 is a Shambles" (Leurent and Peyrin, 2020) brought chosen-prefix collisions into practical range — tens of thousands of US dollars of rented GPU time — and demonstrated an impersonation attack on the PGP web of trust. Browsers and public CAs stopped accepting SHA-1 TLS certificates years ago. NIST SP 800-131A Rev. 2 disallows SHA-1 for digital signature generation and allows signature *verification* only for legacy data; NIST announced in December 2022 that SHA-1 should be phased out completely by 31 December 2030.

**Where they remain acceptable.** Everything below is a use where no security depends on collision resistance. Record it as informational, or not at all:

- **Non-security checksums and identifiers**: detecting accidental corruption of a download over TLS, cache file names derived from URLs (image loaders and HTTP caches do this constantly), ETags, change detection, Git object IDs, UUIDv5 (which is defined over SHA-1).
- **HMAC-SHA1 and HMAC-MD5.** HMAC's security rests on the compression function behaving as a pseudorandom function, not on collision resistance, so collision attacks do not translate into MAC forgeries. RFC 6151 concludes that the known attacks do not make HMAC-MD5 practically vulnerable as a MAC but that it should not be used in new protocols; SP 800-131A Rev. 2 still lists HMAC with SHA-1 as acceptable. You will meet HMAC-SHA1 legitimately in TOTP/HOTP (RFC 6238 and RFC 4226 default to it, and most authenticator apps only support it), in PBKDF2-HMAC-SHA1 (fine as a construction, but it needs 1,300,000 iterations by today's OWASP guidance), and in older protocols. Treat these as Low or Info with a migration note; see [MASWE-0009](/mobile/maswe-0009-improper-use-of-mac/).
- **Interoperability with external formats you cannot change**: the SHA-1 fingerprint of the app signing certificate that Google APIs and some SDKs use to restrict API keys, the SHA-1 in legacy `CERT.SF`/`MANIFEST.MF` v1 APK signatures, or SHA-1 k-anonymity prefixes used to query the Have I Been Pwned Pwned Passwords range API (a deliberate privacy design, not an integrity check).

The test is never "is MD5 present" but "does anything break if an attacker produces a collision".

### General: SHA-2, SHA-3 and truncated digests (Guler Tech methodology)

**SHA-2** (FIPS 180-4) is the default answer: SHA-256 for general use, SHA-384 or SHA-512 where you want a larger margin or a 64-bit-friendly implementation. SHA-512/256 is SHA-512 truncated to 256 bits with different initial values; it is faster than SHA-256 on 64-bit CPUs and, like SHA-384, resists length extension because part of the internal state is never output. Both Android and iOS provide SHA-256, SHA-384 and SHA-512 natively.

**SHA-3** (FIPS 202) is built on the Keccak sponge, a completely different design from SHA-2. It is not "stronger SHA-2"; it is a hedge in case SHA-2 is ever broken, and it is immune to length extension by construction. SHAKE128 and SHAKE256 are its extendable-output variants. Platform support on mobile is newer and less uniform than for SHA-2, so check the API level or SDK before recommending it; SHA-256 is never a wrong recommendation.

**Truncation.** NIST permits truncating approved digests (SP 800-107 Rev. 1, section 5.1) as long as the remaining length meets the security strength the use requires. In practice:

- A truncated digest used as an **integrity check against an active attacker** needs at least 128 bits for collision-sensitive uses, and arguably the full digest; there is no performance reason to keep less.
- A truncated digest used as an **identifier** collides by accident at about 2^(*n*/2) items. Eight hex characters (32 bits) collide after roughly 65,000 items, which is a real bug in a busy system even without an attacker.
- Watch for `substring(0, 8)`, `prefix(4)`, `Arrays.copyOf(digest, 8)` and `digest.take(…)` after a hash call; these are where truncation hides in decompiled code.

### General: length extension and secret-prefix hashing (Guler Tech methodology)

MD5, SHA-1, SHA-256 and SHA-512 are Merkle–Damgård constructions: the digest *is* the internal state after the last block. If you know H(*secret* ‖ *message*) and the length of *secret* ‖ *message*, you can resume hashing from that state and compute H(*secret* ‖ *message* ‖ *padding* ‖ *extension*) for any extension you like, **without knowing the secret**. The padding is deterministic (a `0x80` byte, zeros, and the 64- or 128-bit message length), so you can construct the extended message exactly.

Why this matters on mobile: request-signing schemes of the form

```text
sig = SHA-256(APP_SECRET + "amount=10&to=alice")
```

are common in apps that "sign" API calls. An attacker who captures one signed request can append `&to=mallory` (preceded by the padding bytes) and compute a valid signature for it. Whether the server then acts on the duplicated parameter depends on its parser — many take the last occurrence — but the signature check itself is defeated. The Flickr API signature forgery (Duong and Rizzo, 2009) was exactly this, with MD5. The secret length is unknown but small, so the attacker simply tries every length from 1 to 64.

What is and is not vulnerable:

| Construction | Length extension? |
|---|---|
| MD5, SHA-1, SHA-256, SHA-512 as H(secret ‖ msg) | Yes |
| SHA-224 | Partially (only 32 bits of state are hidden; guessable) |
| SHA-384, SHA-512/256 | No (128+ bits of state are never output) |
| SHA-3, SHAKE, BLAKE2, BLAKE3 | No |
| HMAC with any of the above | No |

The fix is not "switch to SHA-384". It is to use the primitive designed for keyed integrity — HMAC — which is covered in depth in [MASWE-0009](/mobile/maswe-0009-improper-use-of-mac/). The other ad-hoc variants are no better: H(*msg* ‖ *secret*) is not extendable but inherits every collision in H, so with MD5 or SHA-1 an attacker who can get one of two colliding messages signed can reuse the tag for the other. And a secret-prefix scheme also means the secret is in the app, which is [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/) territory.

### General: password hashing is a different problem (Guler Tech methodology)

General-purpose hashes are engineered to be fast. A single current high-end GPU computes on the order of tens of billions of SHA-256 hashes per second, and more than that for MD5. Every eight-character lowercase-plus-digit password (about 2.8 × 10^12 candidates) falls in minutes, and a six-digit PIN (10^6) falls instantly. Salting stops precomputed tables and forces per-user work; it does nothing about speed.

Password hashing functions are deliberately slow and, in the better ones, memory-hard. The [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) currently recommends, in order of preference:

| Function | Minimum parameters (OWASP) | Mobile availability |
|---|---|---|
| Argon2id | 19 MiB memory, 2 iterations, 1 degree of parallelism (or equivalent trade-offs) | Libraries: libsodium (`crypto_pwhash`), Bouncy Castle `Argon2BytesGenerator` |
| scrypt | N = 2^17, r = 8, p = 1 | Libraries: libsodium, Bouncy Castle, CryptoSwift |
| bcrypt | Work factor 10 or more; 72-byte input limit | Libraries |
| PBKDF2 | 600,000 iterations with HMAC-SHA-256 (1,300,000 with HMAC-SHA-1, 210,000 with HMAC-SHA-512) | Built in: `SecretKeyFactory` `PBKDF2WithHmacSHA256` (Android API 26+), `CCKeyDerivationPBKDF` (iOS) |

PBKDF2 is the one in NIST SP 800-132; it is the only option built into both platforms and the one to expect where FIPS alignment matters.

In a mobile app, password hashing usually belongs on the server: the app sends the password over TLS and the backend stores an Argon2id hash. The client-side cases you need to look at are:

- **Local verification of a password or PIN** — "offline login", an app lock, a vault unlock. Any hash stored on the device can be brute-forced offline once extracted. A slow function raises the cost for passwords, but for a 4- or 6-digit PIN no KDF is slow enough: 10^6 guesses at one second each is under twelve days on a single core and trivially parallel. PINs need a hardware-enforced attempt limit: a Keystore or Keychain key bound to user authentication, a key that mixes the PIN with a hardware-held secret so guessing must happen on the device, or server-side verification with lockout.
- **Client-side pre-hashing** — the app sends `SHA-256(password)` instead of the password. This is not a vulnerability by itself, but it is not a protection either: the hash *is* the password as far as the server is concerned (anyone who obtains it can replay it), and it gives a false sense of security if TLS is weak. If the backend then stores that value with a fast hash, report the backend design, not the client.
- **Password-derived encryption keys** — a key derived from a password with a single SHA-256 round. That is improper key derivation and belongs to [MASWE-0014](/mobile/maswe-0014-improper-key-derivation/).

### General: unsalted hashes of low-entropy data (Guler Tech methodology)

A hash hides its input only if the input is hard to guess. Personal identifiers rarely are:

| Input | Approximate candidate space | Time to enumerate all SHA-256 hashes at ~10^10/s |
|---|---|---|
| 4-digit PIN | 10^4 | Instant |
| Date of birth (100 years) | 3.7 × 10^4 | Instant |
| UK postcode | 1.8 × 10^6 | Instant |
| UK mobile number (+44 7 and nine digits) | 10^9 | Well under a second |
| Every E.164 phone number worldwide | roughly 10^12 or fewer valid numbers | Minutes |
| IMEI for a known device model (fixed TAC, Luhn digit) | 10^6 | Instant |
| Email addresses | Billions known from breach corpora | Minutes, by dictionary |

So `SHA-256("+447700900123")` sent to an analytics SDK, uploaded for contact discovery, or used as a "privacy-safe" user key is reversible by anyone who sees it. The same applies to MD5 of an email address (the long-standing Gravatar URL scheme is the textbook example) and to hashed emails used for advertising audience matching. A **per-record salt** stored next to the hash does not help much: the attacker enumerates the same small space once per record, which for a phone number still takes a fraction of a second each. A **keyed hash** (HMAC with a secret pepper) does prevent enumeration, but only if the key stays secret — and a key shipped in the app is not secret.

Regulators say the same thing. The UK ICO's guidance on anonymisation and pseudonymisation and GDPR Recital 26 treat hashed identifiers as pseudonymised personal data while re-identification remains reasonably likely; the Spanish AEPD and the EDPS published a joint note on hash functions as a pseudonymisation technique that works through exactly these enumeration attacks; and the US FTC's 2024 post "No, hashing still doesn't make your data anonymous" is blunter still.

What a safe design looks like:

- **Do not send the identifier** if the feature does not need it.
- **Pseudonymise on the server** with HMAC-SHA-256 under a key held in a KMS, and keep that key away from the analytics vendor.
- **For contact discovery**, use a rate-limited, authenticated lookup service or a private set intersection protocol, not "upload hashes of the address book". Signal's use of secure enclaves for contact discovery exists precisely because hashing was not enough.

### Android: MessageDigest and friends (Guler Tech methodology)

OWASP has no Knowledge page for hashing on Android. The legacy (MASTG v1) test [MASTG-TEST-0014](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0014/), now deprecated and covered by MASTG-TEST-0312, lists `MessageDigest` among the classes to search for, and the resilience test [MASTG-TEST-0338](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0338/) references it as a storage-integrity API. The rest of this section is our own.

**The platform API.** `java.security.MessageDigest.getInstance(String algorithm)` returns a digest object from the first provider that supports the algorithm. On current Android that provider is Conscrypt (`AndroidOpenSSL`), backed by BoringSSL. Supported names include `MD5`, `SHA-1` (with `SHA1` and `SHA` accepted as aliases), `SHA-224`, `SHA-256`, `SHA-384` and `SHA-512`. Usage is `update(...)` any number of times, then `digest()`, or `digest(input)` in one call. Kotlin compiles to the same calls.

**Where else hashes come from.** You will not catch everything by searching for `MessageDigest`:

| Source | APIs to search for |
|---|---|
| Apache Commons Codec | `DigestUtils.md5`, `md5Hex`, `sha1`, `sha1Hex`, `sha256Hex` |
| Guava | `Hashing.md5()`, `Hashing.sha1()` (both deprecated in Guava), `Hashing.sha256()`, `Hashing.crc32()` |
| Okio / OkHttp | `ByteString.md5()`, `.sha1()`, `.sha256()`; OkHttp `CertificatePinner` uses `sha256/` SPKI pins |
| Bouncy Castle | `MD5Digest`, `SHA1Digest`, `SHA256Digest`, `SHA3Digest` (lightweight API) |
| JDK checksums | `java.util.zip.CRC32`, `CRC32C`, `Adler32` |
| Kotlin/Java | `String.hashCode()`, `Arrays.hashCode()`, `Objects.hash()` (never cryptographic) |
| Native code (`.so`) | OpenSSL/BoringSSL `MD5`, `SHA1`, `EVP_md5`, `EVP_sha1`, `MD5_Init`; bundled implementations with names like `md5_update` |
| Hybrid frameworks | React Native bundles (`assets/index.android.bundle`): `CryptoJS.MD5`, `CryptoJS.SHA1`, the `md5` npm package; Flutter (`libapp.so`): `package:crypto` `md5.convert`, `sha1.convert` |

**Platform features that hash for you, correctly.** Network Security Configuration pins (`<pin digest="SHA-256">`) accept only SHA-256. APK Signature Scheme v2 and later sign SHA-256 or SHA-512 digests; v1 (JAR) signatures may contain SHA-1 digests for old `minSdkVersion` values, which `apksigner verify -v --print-certs app.apk` will show. These are build-time concerns, not app-code findings.

**Decompiled-code tells.** R8 normally inlines `const val` and `static final` strings, so jadx usually shows the literal algorithm name at the call site even in a minified build. When it does not, the name arrives as a parameter or from a field: follow the callers (jadx "Find usage") until you reach the literal, or confirm at runtime with the hook in the test below. Hex-encoding helpers next to a digest call (`String.format("%02x", ...)`, `BigInteger(1, digest).toString(16)`) are a good sign you are looking at a hash that leaves the app as text — in a request, a file name or an analytics event.

### iOS: CryptoKit hash functions (MASTG-KNOW-0066)

Source: [MASTG-KNOW-0066](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0066/).

CryptoKit (iOS 13+) is Apple's Swift cryptography framework, built on the corecrypto library that Apple submits for FIPS 140 validation. Its hash API is the `HashFunction` protocol, implemented by `SHA256`, `SHA384` and `SHA512`, plus two types that Apple deliberately put in a namespace called `Insecure`:

```swift
import CryptoKit

let data = Data("example".utf8)
let good = SHA256.hash(data: data)          // SHA256Digest, 32 bytes
let md5  = Insecure.MD5.hash(data: data)    // Insecure.MD5Digest, 16 bytes
let sha1 = Insecure.SHA1.hash(data: data)   // Insecure.SHA1Digest, 20 bytes

var hasher = SHA256()                       // incremental form
hasher.update(data: data)
let digest = hasher.finalize()
```

The `Insecure` namespace is Apple saying in the type system that these exist for compatibility only. That is useful for you as a tester: in a CryptoKit app every MD5 or SHA-1 call has `Insecure` in its symbol name (`CryptoKit.Insecure.MD5`), which survives into the import table even when the app binary is stripped. Newer SDKs add further hash types, including SHA-3; check the CryptoKit documentation for availability against the app's deployment target before recommending them.

Two smaller points about the source page. Its `String(describing: hash)` example prints a description such as `SHA512 digest: …` rather than plain hex; production code should hex- or Base64-encode the digest bytes explicitly. And its list of key-agreement curves says "P-512"; the NIST curve is P-521.

### iOS: CommonCrypto digests and third-party libraries (MASTG-KNOW-0067, MASTG-KNOW-0068)

Sources: [MASTG-KNOW-0067](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0067/) and [MASTG-KNOW-0068](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0068/).

**CommonCrypto** is the C API in `libcommonCrypto.dylib`, usable from Objective-C and Swift (`import CommonCrypto`) and the only system option for apps that still support iOS 12 or earlier. `CommonDigest.h` defines one-shot and incremental functions for each algorithm:

| Algorithm | One-shot | Incremental | Digest length constant |
|---|---|---|---|
| MD2, MD4, MD5 | `CC_MD2`, `CC_MD4`, `CC_MD5` | `CC_MD5_Init` / `_Update` / `_Final` | `CC_MD5_DIGEST_LENGTH` (16) |
| SHA-1 | `CC_SHA1` | `CC_SHA1_Init` / `_Update` / `_Final` | `CC_SHA1_DIGEST_LENGTH` (20) |
| SHA-224 … SHA-512 | `CC_SHA224`, `CC_SHA256`, `CC_SHA384`, `CC_SHA512` | `CC_SHA256_Init` etc. | `CC_SHA256_DIGEST_LENGTH` (32) etc. |

The one-shot signature is `unsigned char *CC_MD5(const void *data, CC_LONG len, unsigned char *md)`; the incremental `Update` functions take the context first, then the data and length. That ordering matters when you hook them (see the test below).

Since the iOS 13 SDK, `CC_MD2`, `CC_MD4` and `CC_MD5` carry deprecation attributes, and compiling a call produces the warning that the function "is cryptographically broken and should not be used in security contexts. Clients should migrate to SHA256 (or stronger)." `CC_SHA1` is not marked deprecated in the header, but it has the same collision weakness and Apple files SHA-1 under `Insecure` in CryptoKit. Deprecated functions still link and run, so the warning only helps the developer, not you.

**CommonCrypto HMAC and KDFs** (`CommonHMAC.h`, `CommonKeyDerivation.h`) also take a digest choice — `kCCHmacAlgMD5`, `kCCHmacAlgSHA1`, `kCCPRFHmacAlgSHA1` — which are MAC and KDF questions covered in [MASWE-0009](/mobile/maswe-0009-improper-use-of-mac/) and [MASWE-0014](/mobile/maswe-0014-improper-key-derivation/).

**Third-party libraries** listed in KNOW-0068 that matter for hashing: **CryptoSwift** implements MD5, SHA-1, SHA-2, SHA-3, CRC-16/32 and more in pure Swift, with convenience extensions such as `"text".md5()` and `data.sha1()`; because it is a full reimplementation rather than a wrapper, its calls never reach CommonCrypto and will not show up in a CommonCrypto search. **OpenSSL** builds (often bundled for TLS or legacy code) expose `MD5`, `SHA1` and `EVP_md5`. **libsodium** provides `crypto_generichash` (BLAKE2b) and `crypto_pwhash` (Argon2id). Older Objective-C pods frequently add `NSString`/`NSData` categories such as `md5String` built on `CC_MD5`. Search for all of these, not just the system APIs.

## Tests

OWASP maps one test to MASWE-0008, MASTG-TEST-0211 for iOS. There is no Android test linked to this weakness on the MASWE site, and no Android hashing test in the beta test set, so the Android section is our own procedure, built the same way. Both tests answer the "broken algorithm" question; the [supplementary checks](#supplementary-checks-guler-tech-methodology) cover runtime confirmation and the wrong-tool cases (low-entropy inputs, secret-prefix signatures, password and PIN hashes) on both platforms.

### MASTG-TEST-0211: Broken Hashing Algorithms (iOS)

Source: [MASTG-TEST-0211](https://mas.owasp.org/MASTG/tests/ios/MASVS-CRYPTO/MASTG-TEST-0211/). Type: static (code), manual review. Platform: iOS.

#### Overview

The test looks for calls to broken hash functions in the app's binaries and then asks whether each call protects anything. The APIs in scope are the CommonCrypto digests (`CC_MD2`, `CC_MD4`, `CC_MD5`, `CC_SHA1`, and their `_Init`/`_Update`/`_Final` forms) and CryptoKit's `Insecure.MD5` and `Insecure.SHA1`. The Security framework only does asymmetric operations and is out of scope here; its digest choices (for example `.rsaSignatureMessagePKCS1v15SHA1`) belong to the signature notes ([MASWE-0010](/mobile/maswe-0010-improper-signature-generation/), [MASWE-0011](/mobile/maswe-0011-improper-signature-verification/)). We add third-party implementations (CryptoSwift, OpenSSL, Objective-C categories) to the sweep, because they bypass the system APIs entirely.

#### Prerequisites

- A **decrypted** IPA. App Store binaries are FairPlay-encrypted: `otool -l Payload/App.app/App | grep -A4 LC_ENCRYPTION_INFO` showing `cryptid 1` means you must decrypt it on a jailbroken device first. Builds supplied directly for testing (development, ad hoc, enterprise) are normally unencrypted.
- radare2 (MASTG-TOOL-0073), and on macOS the Xcode command-line tools for `nm`, `otool` and `xcrun swift-demangle`.
- For the optional runtime confirmation: a jailbroken device with `frida-server`, or a re-signed build with Frida Gadget.

#### Steps

1. **Extract the app package** (MASTG-TECH-0058, "Exploring the App Package"). An IPA is a ZIP; the executable inside `Payload/<Name>.app/` has the bundle name without `.app`. Do not stop at the main binary: frameworks and app extensions are separate Mach-O files.

   ```bash
   unzip -q App.ipa -d ipa/
   find ipa/Payload -type f -exec file {} + | grep 'Mach-O' | cut -d: -f1 > binaries.txt
   cat binaries.txt
   ```

2. **Check the import tables** for the APIs in scope. This is fast and tells you which binary to open:

   ```bash
   while read -r b; do
     echo "== $b"
     nm -u "$b" 2>/dev/null | grep -E '_CC_(MD2|MD4|MD5|SHA1)(_Init|_Update|_Final)?$'
     nm -u "$b" 2>/dev/null | xcrun swift-demangle | grep -E 'CryptoKit\.Insecure\.(MD5|SHA1)' | sort -u
     nm "$b" 2>/dev/null | xcrun swift-demangle | grep -iE 'CryptoSwift\.(MD5|SHA1)|md5String|EVP_md5|EVP_sha1' | sort -u
   done < binaries.txt
   ```

   The first two commands list *imports* (functions the binary calls in a system library). The third looks at *defined* symbols for statically linked third-party code. Stripped binaries may hide the third category; `strings -a "$b" | grep -iE 'cryptoswift|md5|sha1'` is a cruder fallback.

3. **Locate the call sites in radare2** (MASTG-TECH-0066, "Static Analysis on iOS"). The OWASP demos use a script run with `r2 -q -i script.r2 -A <binary>`. This version uses symbol names rather than the demo's fixed addresses, so it works on any binary:

   ```text
   ?e Uses of CommonCrypto hash functions:
   afl~CC_
   ?e xrefs to CC_MD5:
   axt @ sym.imp.CC_MD5
   ?e xrefs to CC_SHA1:
   axt @ sym.imp.CC_SHA1
   ?e Uses of CryptoKit.Insecure:
   afl~Insecure.
   ```

   ```bash
   r2 -q -i cchash.r2 -A ipa/Payload/App.app/App
   ```

   `afl~CC_` lists the import stubs (`sym.imp.CC_MD5` and so on); `axt` lists every instruction that calls one. For CryptoKit, the flag names contain punctuation from the demangled Swift name, so copy the stub address from the `afl~Insecure.` output and run `axt @ <address>` on it, as the demo does.

4. **Read each call site in context** (MASTG-TECH-0076, "Reviewing Disassembled Objective-C and Swift Code"). For each `axt` hit, print the surrounding instructions and the whole calling function, then walk one level up:

   ```text
   pd-- 5 @ 0x1000048c4        # five instructions either side of the call
   afi @ 0x1000048c4           # which function contains it
   pdf @ <function address>    # whole function
   axt @ <function address>    # who calls that function
   ```

   You are looking for what goes *in* (on arm64 the first three arguments of `CC_MD5(data, len, md)` are in `x0`, `w1` and `x2`) and where the digest goes *out*: compared with a stored value, sent in a request, written to a file name, used as a key. Strings referenced nearby are the quickest clue: `iz~password`, `iz~signature`, `iz~Content-MD5`, `iz~cache` and then `axt` on the string address. With the r2ghidra plugin, `pdg @ <function>` gives pseudo-C that is much faster to read.

5. **Optional, recommended: confirm at runtime** (Guler Tech addition). Static analysis cannot tell you what data reaches the hash or whether the code path runs. Hook the CommonCrypto functions and exercise the app (log in, sync, open the features that touch the hits):

   ```javascript
   // hook-ios-weak-hash.js (Frida 17 syntax)
   const cc = Process.getModuleByName('libcommonCrypto.dylib');
   function show(name, data, len) {
     const n = Math.min(len, 64);
     console.log('[' + name + '] len=' + len);
     console.log(hexdump(data, { length: n, ansi: false }));
   }
   function bt(ctx) {
     return Thread.backtrace(ctx, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n');
   }
   ['CC_MD5', 'CC_SHA1'].forEach(function (name) {
     Interceptor.attach(cc.getExportByName(name), {
       onEnter(args) {                     // CC_MD5(const void *data, CC_LONG len, unsigned char *md)
         show(name, args[0], args[1].toUInt32());
         console.log(bt(this.context));
       }
     });
   });
   ['CC_MD5_Update', 'CC_SHA1_Update'].forEach(function (name) {
     Interceptor.attach(cc.getExportByName(name), {
       onEnter(args) {                     // CC_MD5_Update(CC_MD5_CTX *c, const void *data, CC_LONG len)
         show(name, args[1], args[2].toUInt32());
       }
     });
   });
   ```

   ```bash
   frida -U -f com.example.app -l hook-ios-weak-hash.js
   frida-trace -U -f com.example.app -i 'CryptoKit!*Insecure*'
   ```

   CryptoKit does not go through CommonCrypto, so the second command traces its exported `Insecure` functions by their mangled names (the type name `Insecure` appears literally in them). If nothing shows although static analysis found calls, the code path did not run or the call was specialised into the app binary; rely on the static trace for those.

#### Observation

For every hit, record: the binary (main app, framework or extension) and address, the API and algorithm, the calling function and its role (from symbols, strings or pseudo-code), what the input is (and an example from the hook if you ran it), and where the output goes. A short table per hit is enough and makes the evaluation auditable.

#### Evaluation

The test **fails** if MD5 or SHA-1 (or MD2/MD4) is used in a **security-relevant context**. OWASP's evaluation requires you to establish that context for each hit by reviewing the disassembly; use this decision table:

| Use of the digest | Verdict |
|---|---|
| Input to a signature, certificate, token or commitment that someone relies on, where the attacker can influence the signed data | Fail |
| Integrity check of data or code an attacker can supply, compared against an expected value | Fail (and check where the expected value comes from — if it arrives with the data, there is no integrity check at all, see [MASWE-0009](/mobile/maswe-0009-improper-use-of-mac/)) |
| Password, PIN or secret hashed for storage, comparison or transmission | Fail (and see the password check below; a SHA-256 version also fails, for different reasons) |
| Hash of a personal identifier used as an "anonymous" ID | Fail for privacy regardless of algorithm (see the low-entropy check below) |
| Inside HMAC (`CCHmac` with `kCCHmacAlgSHA1`), PBKDF2 PRF, or TOTP/HOTP | Not a MASWE-0008 failure; record under MASWE-0009 or MASWE-0014 as Low/Info |
| Cache key, file name, ETag, de-duplication of the app's own data, accidental-corruption checksum over TLS | Pass (Info at most) |

It **passes** when no broken algorithm is used, or every remaining use falls in the last two rows. Keep the "stay up to date" caveat from the source in mind: the list of broken algorithms is not fixed, and for data that must stay protected for many years you should apply the most conservative current guidance (NIST SP 800-131A, BSI TR-02102-1, NIST IR 8547) rather than the minimum.

Common false positives: third-party SDKs (analytics, crash reporting, image caching) that MD5 a URL or file name; the app's own code computing a SHA-1 of a bundled asset to detect changes; and `Insecure.SHA1` used to talk to a legacy server protocol where the digest is not a security control. Always check whether the code is reachable — SDKs ship many paths an app never calls.

#### Demo

Two OWASP demos cover this test. Both contain an MD5 and a SHA-1 call over the same sample string, which is exactly the "found but context unknown" situation you start from in a real app.

**[MASTG-DEMO-0015](https://mas.owasp.org/MASTG/demos/ios/MASVS-CRYPTO/MASTG-DEMO-0015/MASTG-DEMO-0015/): CommonCrypto with r2.** The sample (abridged):

```swift
import CommonCrypto

static func generateMD5Hash(data: Data) -> String {
    var hash = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
    data.withUnsafeBytes {
        _ = CC_MD5($0.baseAddress, CC_LONG(data.count), &hash)
    }
    return hash.map { String(format: "%02hhx", $0) }.joined()
}
// generateSHA1Hash is identical with CC_SHA1 / CC_SHA1_DIGEST_LENGTH
```

Running the demo's r2 script produces:

```text
Uses of CommonCrypto hash function:
0x1000071a8    1     12 sym.imp.CC_MD5
0x1000071b4    1     12 sym.imp.CC_SHA1

xrefs to CC_MD5:
(nofunc) 0x1000048c4 [CALL:--x] bl sym.imp.CC_MD5
xrefs to CC_SHA1:
(nofunc) 0x10000456c [CALL:--x] bl sym.imp.CC_SHA1

Use of MD5:
            0x1000048bc      e0630091       add x0, sp, 0x18
            0x1000048c0      01008052       mov w1, 0
            0x1000048c4      390a0094       bl sym.imp.CC_MD5
            0x1000048c8      e00316aa       mov x0, x22
```

**[MASTG-DEMO-0016](https://mas.owasp.org/MASTG/demos/ios/MASVS-CRYPTO/MASTG-DEMO-0016/MASTG-DEMO-0016/): CryptoKit with r2.** The same sample written with `Insecure.MD5.hash(data:)` and `Insecure.SHA1.hash(data:)`. Filtering functions with `afl~Insecure.` finds four import stubs (the two hash types and their two digest types), and `axt` resolves each hash call to its calling function:

```text
Uses of CryptoKit.Insecure functions:
0x100007274    1     12 sym.imp.CryptoKit.Insecure.SHA1Digest.
0x100007280    1     12 sym.imp.CryptoKit.Insecure.MD5.
0x10000728c    1     12 sym.imp.CryptoKit.Insecure.SHA1.
0x100007298    1     12 sym.imp.CryptoKit.Insecure.MD5Digest.

xrefs to CryptoKit.Insecure.MD5:
sym.func.10000469c 0x1000046d8 [CALL:--x] bl sym.imp.CryptoKit.Insecure.MD5.
xrefs to CryptoKit.Insecure.SHA1:
sym.func.1000041d8 0x100004214 [CALL:--x] bl sym.imp.CryptoKit.Insecure.SHA1.
```

Both demos **fail** the test because MD5 and SHA-1 are present, and OWASP's own evaluation adds the caveat that matters: you have to analyse the reverse-engineered code to learn what the digests are for. Two things worth noticing in the output. First, in DEMO-0015 radare2 reports `(nofunc)` for the call sites — analysis did not attribute them to a function — so `afi` will not help. The full output carries a `CODE XREF from sym.func.100004728` comment next to the MD5 call; that is the function that jumps into the block, and the place to start your `pdf`. Second, the five-instruction window confirms the call but tells you nothing about the data: `x0` is set to a stack buffer and `w1` to a constant inside the compiler-generated handling of `Data.withUnsafeBytes`, with no visible link to the sample string. That is normal for Swift, and it is why step 4 tells you to read the whole function and step 5 to watch the data at runtime.

### Android: Broken Hashing Algorithms (Guler Tech methodology)

Our test, structured like the OWASP beta tests. Type: static (code), manual review, with optional dynamic confirmation. Platform: Android. Related OWASP material: legacy (MASTG v1) [MASTG-TEST-0014](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0014/) (which includes `MessageDigest` in its static search) and techniques MASTG-TECH-0013 (reverse engineering), MASTG-TECH-0014 (static analysis), MASTG-TECH-0023 (reviewing decompiled Java code) and MASTG-TECH-0033 (method tracing).

#### Overview

The test finds every use of a broken or non-cryptographic hash in the app's DEX code, native libraries and hybrid-framework bundles, and decides which uses are security-relevant. The main API is `java.security.MessageDigest.getInstance(...)` with `MD5`, `SHA-1`, `SHA1` or `SHA` (and `MD2`/`MD4` where a bundled provider such as Bouncy Castle supplies them), followed by the library wrappers listed in the [Android knowledge section](#android-messagedigest-and-friends-guler-tech-methodology).

#### Prerequisites

- The APK, including splits: `adb shell pm path com.example.app`, then `adb pull` each path.
- jadx (MASTG-TOOL-0018), semgrep (MASTG-TOOL-0110), `unzip`, binutils (`nm`, `strings`) or radare2 for native code.
- For runtime confirmation: a rooted device or emulator with `frida-server` matching your Frida version.

#### Steps

1. **Decompile.**

   ```bash
   jadx -d out/ app.apk
   ```

2. **Quick sweep with grep**, excluding the most common library paths so you see the app's own code first (look at the libraries afterwards; SDK code is code the app ships):

   ```bash
   grep -rnE 'MessageDigest\.getInstance\(|DigestUtils\.(md5|sha1)|Hashing\.(md5|sha1|crc32)|\.md5\(\)|\.sha1\(\)|new (CRC32|Adler32)\(' out/sources/ \
     | grep -vE '^out/sources/(androidx|kotlin|kotlinx|com/google|okhttp3|okio)/'
   grep -rnE '"(MD2|MD5|SHA-?1|SHA)"' out/sources/ | grep -vE '^out/sources/(androidx|kotlin)/'
   ```

3. **Run a semgrep rule** for the structured cases, including algorithm names passed as constants:

   ```yaml
   rules:
     - id: gt-android-broken-hash
       languages: [java]
       severity: WARNING
       message: "[MASVS-CRYPTO-1] Broken hash algorithm $ALG requested. Check the context."
       patterns:
         - pattern-either:
             - pattern: MessageDigest.getInstance($ALG)
             - pattern: MessageDigest.getInstance($ALG, $PROV)
             - pattern: java.security.MessageDigest.getInstance($ALG)
         - metavariable-regex:
             metavariable: $ALG
             regex: (?i).*"(MD2|MD4|MD5|SHA-?1|SHA)"
     - id: gt-android-noncrypto-checksum
       languages: [java]
       severity: INFO
       message: "Non-cryptographic checksum. Fine for corruption, not for tampering."
       pattern-either:
         - pattern: new java.util.zip.CRC32()
         - pattern: new java.util.zip.Adler32()
   ```

   ```bash
   semgrep -c gt-android-broken-hash.yml out/sources/
   ```

   The regex is applied to the source text of the argument, quotes included, so `"SHA-256"` does not match `"SHA"`. If the argument is a field or parameter, the rule will not fire; the grep in step 2 and the hook in step 7 cover that case.

4. **Check native libraries.** Statically linked OpenSSL/BoringSSL exports or contains the digest functions; a library that imports them from another `.so` shows them as undefined (`U`):

   ```bash
   unzip -o -q app.apk 'lib/*' -d native/
   for so in native/lib/arm64-v8a/*.so; do
     echo "== $so"
     nm -D "$so" 2>/dev/null | grep -E ' (MD5|MD5_Init|MD5_Update|SHA1|SHA1_Init|EVP_md5|EVP_sha1)$'
   done
   ```

   For a hit, open the library with `r2 -A` and use `axt @ sym.<name>` (or `sym.imp.<name>` for imports) to find the JNI function that calls it, exactly as on iOS.

5. **Check hybrid bundles.** React Native and Cordova JavaScript is in `assets/`; Flutter AOT code is in `lib/<abi>/libapp.so`, where Dart symbol names survive as strings:

   ```bash
   unzip -o -q app.apk 'assets/*' -d assets_out/
   grep -rnoE 'CryptoJS\.(MD5|SHA1)|md5\(|sha1\(' assets_out/ | head -50
   strings -a native/lib/arm64-v8a/libapp.so | grep -E 'package:crypto|md5|sha1' | head
   ```

6. **Triage each hit** by reading the decompiled code (MASTG-TECH-0023). For every call, find what is hashed (follow the argument of `update`/`digest` back) and where the result goes (follow the return value forward). Use the decision table in the [iOS test's evaluation](#mastg-test-0211-broken-hashing-algorithms-ios); it applies unchanged.

7. **Confirm at runtime** (MASTG-TECH-0033, method tracing). This catches algorithm names that are not literals and shows you the real inputs:

   ```javascript
   // hook-android-hash.js
   Java.perform(function () {
     const MD = Java.use('java.security.MessageDigest');
     const Log = Java.use('android.util.Log');
     const Exc = Java.use('java.lang.Exception');
     const WEAK = /^(MD2|MD4|MD5|SHA|SHA-?1)$/i;
     function printable(a) {
       return Array.from(a, function (b) {
         const c = b & 0xff;
         return (c >= 0x20 && c < 0x7f) ? String.fromCharCode(c) : '.';
       }).join('').slice(0, 120);
     }
     MD.getInstance.overload('java.lang.String').implementation = function (alg) {
       if (WEAK.test(alg)) {
         console.log('[MessageDigest.getInstance] ' + alg);
         console.log(Log.getStackTraceString(Exc.$new()));
       }
       return this.getInstance(alg);
     };
     const updBytes = MD.update.overload('[B');               // update has several 1-argument overloads
     updBytes.implementation = function (input) {
       if (WEAK.test(this.getAlgorithm())) {
         console.log('[update ' + this.getAlgorithm() + '] "' + printable(input) + '"');
       }
       return updBytes.call(this, input);
     };
     MD.digest.overload('[B').implementation = function (input) {
       if (WEAK.test(this.getAlgorithm())) {
         console.log('[digest ' + this.getAlgorithm() + '] "' + printable(input) + '"');
       }
       return this.digest(input);
     };
   });
   ```

   ```bash
   frida -U -f com.example.app -l hook-android-hash.js
   ```

   `MessageDigest` has further overloads (`update(byte)`, `update([B, int, int)`, `update(ByteBuffer)`, `digest([B, int, int)`); add them if the app's code uses them. Exercise login, registration, sync, contact import, purchases and any "verify" feature while the hook runs.

#### Observation

The same per-hit record as on iOS: class and method, line in the decompiled source, algorithm, input (with a sample from the hook), output destination, and whether the code is the app's own or a library's (and if a library's, whether the app calls that path).

#### Evaluation

The test **fails** if MD5, SHA-1, MD2 or MD4 is used in a security-relevant context as defined in the decision table above, or if a CRC/Adler checksum is the only protection against deliberate modification of security-relevant data. It **passes** if no such use exists. Library code that is present but unreachable is not a failure; note it for the developer if it is easy to remove.

#### Demo

A minimal vulnerable sample (ours, for illustration):

```kotlin
import java.security.MessageDigest

class PinStore(private val prefs: android.content.SharedPreferences) {
    // Bad: fast, unsalted SHA-1 of a 6-digit PIN stored on the device
    fun savePin(pin: String) {
        val h = MessageDigest.getInstance("SHA-1").digest(pin.toByteArray())
        prefs.edit().putString("pin_hash", h.joinToString("") { "%02x".format(it) }).apply()
    }
}

// Bad: MD5 of a phone number used as an "anonymous" analytics ID
fun contactKey(phone: String): String =
    MessageDigest.getInstance("MD5").digest(phone.toByteArray())
        .joinToString("") { "%02x".format(it) }
```

After jadx, the relevant lines read:

```java
byte[] h = MessageDigest.getInstance("SHA-1").digest(bytes);
...
byte[] digest = MessageDigest.getInstance("MD5").digest(bytes);
```

and the semgrep rule reports both:

```text
    PinStore.java
    ❯❱ gt-android-broken-hash
          [MASVS-CRYPTO-1] Broken hash algorithm "SHA-1" requested. Check the context.

           21┆ byte[] h = MessageDigest.getInstance("SHA-1").digest(bytes);

    PinStoreKt.java
    ❯❱ gt-android-broken-hash
          [MASVS-CRYPTO-1] Broken hash algorithm "MD5" requested. Check the context.

           14┆ byte[] digest = MessageDigest.getInstance("MD5").digest(bytes);
```

Both hits **fail**, but notice that switching each to SHA-256 would not make either of them pass. The PIN hash fails because any fast hash of a six-digit value is reversed instantly (`hashcat -m 100 -a 3 pin.txt '?d?d?d?d?d?d'` for the SHA-1 version, `-m 1400` for SHA-256), and the phone-number hash fails because the input space is enumerable. The algorithm is the visible symptom; the design is the finding. Write the report that way, or the developer will "fix" it by changing a string.

### Supplementary checks (Guler Tech methodology)

These cover the parts of MASWE-0008 that an algorithm search cannot: whether guessable data is hashed, whether a hash is standing in for a MAC, and whether passwords and PINs are hashed properly. Run them on both platforms.

#### Hashes of low-entropy identifiers

**Overview.** Look for digests of phone numbers, emails, device identifiers or other personal data that leave the device or are used as user keys.

**Prerequisites.** An intercepting proxy (Burp Suite or mitmproxy) with the app's TLS traffic visible (see the network notes for pinning bypass), `hashcat`, and the Frida hooks from the tests above.

**Steps.**

1. With the hooks running, use features that touch personal data: registration, contact sync, invite-a-friend, analytics consent, ad attribution. Note every hash whose input is an identifier.
2. In the proxy, search requests for 32, 40 and 64 hex-character values (MD5, SHA-1, SHA-256) and their Base64 forms. Match them against the hook output.
3. For each candidate, try to reverse it. For a UK mobile number in E.164 form without the plus sign:

   ```bash
   hashcat -m 1400 -a 3 captured.txt '447?d?d?d?d?d?d?d?d?d'
   ```

   Try the normalisation variants the app might use (`+44…`, `07…`, with spaces). Mode 0 is MD5, 100 is SHA-1, 1400 is SHA-256; modes 1410 and 1420 handle `sha256($pass.$salt)` and `sha256($salt.$pass)` if a known salt is involved.

**Observation.** The hashed value, its input, the destination (first-party API, which third party), and the time hashcat needed.

**Evaluation.** Fails if a hash of a personal identifier is sent to a third party or stored as an "anonymous" value and you can reverse it. Passes if identifiers are not hashed on the client at all, or the client sends them over TLS to a first-party backend that pseudonymises them with a server-held key.

#### Secret-prefix hashes and length extension

**Overview.** Find "signatures" computed as H(secret ‖ data) with a Merkle–Damgård hash and show they can be extended.

**Steps.**

1. Statically, look for a digest whose first `update` is a constant or a value loaded from resources, followed by request data — or a string concatenation of a constant and parameters passed to `digest`. The hooks above show this directly: the first `update` contains the secret.
2. In the proxy, identify the signature parameter or header and the exact bytes it covers (often the sorted query string, sometimes with a timestamp).
3. Use `hash_extender` to produce an extended message and signature for each plausible secret length:

   ```bash
   for n in $(seq 8 64); do
     ./hash_extender --data 'amount=10&to=alice' --secret "$n" --append '&to=mallory' \
       --signature '<captured hex signature>' --format sha256
   done
   ```

   Each run prints a new signature and the new message (hex, including the padding bytes). Send them, percent-encoding the padding, and see which one the server accepts.

**Evaluation.** Fails if the app signs requests with H(secret ‖ message) using MD5, SHA-1, SHA-256 or SHA-512, whether or not the server's parser lets you weaponise the extension; demonstrating acceptance raises the severity. Report the fix as HMAC, and report the embedded secret separately under [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/).

#### Fast hashes used for passwords and PINs

**Overview.** Find passwords, passphrases or PINs that are hashed with a general-purpose hash and stored, compared or sent.

**Steps.**

1. Statically, follow the password field (`EditText` with `inputType="textPassword"`, `UITextField` with `isSecureTextEntry`) to the code that processes it; note any digest, KDF or comparison on the way.
2. At runtime, enter a recognisable value (for example `Probe-1234`) and watch the hooks for it reaching `MessageDigest`, `CC_SHA256`, `CC_MD5` or CryptoKit. Also hook `SecretKeyFactory.getInstance` and `PBEKeySpec` on Android and `CCKeyDerivationPBKDF` on iOS to see whether a KDF is used and with how many iterations.
3. On a rooted or jailbroken device, look for the stored result: `adb shell "run-as com.example.app sh -c 'cat shared_prefs/*.xml'"` (debuggable builds) or `adb shell "su -c 'cat /data/data/com.example.app/shared_prefs/*.xml'"`; on iOS, the app's `Library/Preferences/<bundle-id>.plist` (`plutil -p`) and the Keychain (`objection -g <bundle-id> explore` then `ios keychain dump`).
4. Crack a sample: `hashcat -m 1400 -a 3 pin.txt '?d?d?d?d?d?d'` for a 6-digit PIN under SHA-256, or a dictionary attack for a password.

**Evaluation.** Fails if a password or PIN is stored, compared or transmitted as a fast hash (any of MD5, SHA-1, SHA-2 or SHA-3, salted or not) and the result is reachable by an attacker (device storage, backups, logs, network). Fails if a locally verifiable PIN has no hardware-enforced or server-enforced attempt limit, whatever KDF protects it. Passes if passwords are sent over TLS to the server for verification, or derived with Argon2id, scrypt, bcrypt or PBKDF2 at the OWASP parameters, and PINs are protected by a hardware-backed or server-side attempt limit. Key-derivation parameter details are tested in [MASWE-0014](/mobile/maswe-0014-improper-key-derivation/).

#### Unkeyed hashes standing in for integrity protection

**Overview.** A digest stored next to data (`value` and `value_sha256` in preferences, a checksum field in a cached JSON config) gives no protection against an attacker who can edit the data, because they recompute the digest. This is the "missing MAC" case and is tested properly in [MASWE-0009](/mobile/maswe-0009-improper-use-of-mac/); flag it here when you find it during the hash sweep and hand it over.

## Secure implementation

OWASP has no Best Practice page for hashing, so this section is ours. Start from what the hash is for, because that decides the replacement:

| The app uses a hash to… | Use instead |
|---|---|
| Fingerprint or check data where nothing is secret (download checksum against a value shipped in the app, content-addressed cache, change detection) | SHA-256 (or SHA-512/SHA-3-256) |
| Prove data came from you and was not modified, where the verifier also holds the key | HMAC-SHA-256 with a keystore-held key, or an AEAD — see [MASWE-0009](/mobile/maswe-0009-improper-use-of-mac/) |
| Prove data came from your server, verified by the app | A digital signature (Ed25519, ECDSA P-256 with SHA-256) with the public key in the app — see [MASWE-0011](/mobile/maswe-0011-improper-signature-verification/) |
| Store or check a password | Send it over TLS to the server, which stores Argon2id; locally, Argon2id/scrypt/PBKDF2 at OWASP parameters — see [MASWE-0014](/mobile/maswe-0014-improper-key-derivation/) |
| Check a PIN locally | A Keystore/Keychain key bound to user authentication, or server-side verification with lockout |
| Pseudonymise a personal identifier | Server-side HMAC with a KMS-held key, or do not collect it |
| Talk to a legacy system that demands MD5/SHA-1 | Keep it, isolate it, name it, and make sure no security decision depends on it |

### Android

A plain SHA-256 helper, and a download check against a digest that is part of the app package (or of a signed manifest). The expected digest is public, so the comparison does not need to be constant-time; `MessageDigest.isEqual` is used because it is the clearest way to compare two byte arrays and it is constant-time anyway.

```kotlin
import java.io.File
import java.security.MessageDigest

fun sha256(data: ByteArray): ByteArray =
    MessageDigest.getInstance("SHA-256").digest(data)

fun verifyDownload(file: File, expectedSha256: ByteArray): Boolean {
    val md = MessageDigest.getInstance("SHA-256")
    file.inputStream().use { input ->
        val buf = ByteArray(64 * 1024)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            md.update(buf, 0, n)
        }
    }
    return MessageDigest.isEqual(md.digest(), expectedSha256)
}
```

If the expected digest is downloaded from the same server as the file, this check adds nothing beyond TLS: an attacker who can replace the file can replace the digest. Sign a manifest of digests instead and verify the signature in the app.

For a password that genuinely has to be verified or turned into key material on the device (API 26+ for the SHA-256 variant):

```kotlin
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

fun newSalt(): ByteArray = ByteArray(16).also { SecureRandom().nextBytes(it) }

fun passwordHash(password: CharArray, salt: ByteArray, iterations: Int = 600_000): ByteArray {
    val spec = PBEKeySpec(password, salt, iterations, 256)
    try {
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
    } finally {
        spec.clearPassword()
    }
}
```

Store the salt, the iteration count and an algorithm version alongside the hash so you can raise the parameters later. Six hundred thousand iterations is slow on low-end phones; measure, and if it is unacceptable, prefer moving verification to the server over lowering the count. For PINs, do not do this at all: bind a Keystore key to the device credential with `setUserAuthenticationRequired(true)` and let the platform enforce attempt limits (see [MASWE-0016](/mobile/maswe-0016-key-access-not-restricted/) and [MASWE-0017](/mobile/maswe-0017-device-secure-lock-not-enforced/)).

### iOS

CryptoKit replacements for the two OWASP demos:

```swift
import CryptoKit
import Foundation

func sha256Hex(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

func verifyDownload(_ data: Data, expected: SHA256Digest) -> Bool {
    SHA256.hash(data: data) == expected
}
```

For deployment targets below iOS 13, the CommonCrypto equivalent:

```swift
import CommonCrypto
import Foundation

func sha256(_ data: Data) -> Data {
    var out = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
    data.withUnsafeBytes { buf in
        _ = CC_SHA256(buf.baseAddress, CC_LONG(buf.count), &out)
    }
    return Data(out)
}
```

When interoperability forces MD5 or SHA-1, make the intent explicit so the next reviewer can close the finding in seconds:

```swift
// Interop only: legacy CDN cache key. Not a security control; collisions are harmless here.
let cacheKey = Insecure.MD5.hash(data: Data(url.absoluteString.utf8))
```

Passwords on iOS: `CCKeyDerivationPBKDF` with `kCCPRFHmacAlgSHA256` and at least 600,000 rounds, or Argon2id through libsodium (`crypto_pwhash`). PINs: a Keychain item or Secure Enclave key protected by `SecAccessControlCreateWithFlags` with `.userPresence` or `.devicePasscode`, so the OS enforces attempt limits.

### Both platforms

- Replace `SHA-256(secret + params)` request signing with HMAC-SHA-256 over a canonical request, using a per-user key issued after login rather than an app-wide secret ([MASWE-0009](/mobile/maswe-0009-improper-use-of-mac/)).
- Stop hashing personal identifiers on the client. If an SDK requires a hashed email or phone number, document the data flow as personal data in your privacy notice and DPIA; do not describe it as anonymous.
- Do not truncate digests used for integrity. If you need a short code for humans, derive it from a server-side MAC, not a bare hash, and rate-limit verification.

## Rating findings

Rate on what breaks if the hash fails and on what the attacker needs. The algorithm name alone is never the rating.

| Rating | Conditions |
|---|---|
| **Critical** | A hash-based scheme is the authentication for backend actions and you demonstrated a forgery the server accepts: for example a length-extended H(secret ‖ request) that performs a transaction, or an MD5/SHA-1 signature over attacker-influenced data forged with a collision. Also: code the app executes (downloaded JS bundles, plugins, DEX, scripts) whose only integrity check is a hash delivered with the payload over a channel an attacker can influence. |
| **High** | Passwords or long-term secrets stored, logged or transmitted as fast hashes that an attacker can reach (device storage, backups, network); a locally verified PIN with no attempt limit protecting sensitive data; personal identifiers (phone, email, IMEI) hashed and sent to third parties as "anonymous" data, reversed in testing; secret-prefix request signing that is extendable but whose server-side exploitation you could not demonstrate; MD5/SHA-1 in a collision-sensitive design where the attacker influences the input. |
| **Medium** | MD5/SHA-1 in a security-relevant integrity check where only second-preimage resistance is needed (vendor-produced data, digest from a trusted source) — not exploitable today, but non-compliant; truncated digests of 64 bits or fewer used in a security decision; hashed identifiers that stay on the device but are treated as anonymous in logs or exports. |
| **Low** | SHA-1 inside HMAC, PBKDF2 or TOTP/HOTP where a migration path exists; SHA-224 or other 112-bit options for data that must stay protected beyond 2030; PBKDF2 used correctly but with iterations below current guidance (rate under [MASWE-0014](/mobile/maswe-0014-improper-key-derivation/) if that is the main issue). |
| **Info** | MD5/SHA-1/CRC for cache keys, ETags, file names, change detection or accidental-corruption checks; signing-certificate fingerprints required by SDKs; HIBP-style k-anonymity prefixes; broken-hash code in libraries that the app never calls. |

In the report, give the code location, the algorithm, the input (with a redacted sample), what the output is used for, and the one-line demonstration that justifies the rating — the hashcat command and time, the forged request and the server's response, or the collision scenario. A finding that says only "MD5 detected" will be closed as a false positive, often correctly.

## References

- OWASP MASWE — [MASWE-0008: Improper Hashing](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0008/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0211: Broken Hashing Algorithms](https://mas.owasp.org/MASTG/tests/ios/MASVS-CRYPTO/MASTG-TEST-0211/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-DEMO-0015: Uses of Broken Hashing Algorithms in CommonCrypto with r2](https://mas.owasp.org/MASTG/demos/ios/MASVS-CRYPTO/MASTG-DEMO-0015/MASTG-DEMO-0015/) and [MASTG-DEMO-0016: Uses of Broken Hashing Algorithms in CryptoKit with r2](https://mas.owasp.org/MASTG/demos/ios/MASVS-CRYPTO/MASTG-DEMO-0016/MASTG-DEMO-0016/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0066: CryptoKit](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0066/), [MASTG-KNOW-0067: CommonCrypto, SecKey and Wrapper libraries](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0067/), [MASTG-KNOW-0068: Cryptographic Third-Party libraries](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0068/) (CC BY-SA 4.0)
- OWASP MASTG — legacy (MASTG v1) [MASTG-TEST-0014: Testing the Configuration of Cryptographic Standard Algorithms](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0014/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0338: References to Storage Integrity Check APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0338/) (CC BY-SA 4.0)
- OWASP MASTG — techniques [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/), [MASTG-TECH-0033](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0033/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/); tools [radare2 (MASTG-TOOL-0073)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/), [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/) (CC BY-SA 4.0)
- OWASP MASTG — [Mobile App Cryptography](https://mas.owasp.org/MASTG/0x04g-Testing-Cryptography/) ("Improper Hashing") and the MASTG prerequisite page "Identify Security-Relevant Contexts in Code" (CC BY-SA 4.0)
- [NIST SP 800-131A Rev. 2 — Transitioning the Use of Cryptographic Algorithms and Key Lengths](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf) and the [Rev. 3 initial public draft](https://csrc.nist.gov/pubs/sp/800/131/a/r3/ipd)
- [NIST IR 8547 (initial public draft) — Transition to Post-Quantum Cryptography Standards](https://csrc.nist.gov/pubs/ir/8547/ipd)
- [NIST — "NIST Retires SHA-1 Cryptographic Algorithm" (December 2022)](https://www.nist.gov/news-events/news/2022/12/nist-retires-sha-1-cryptographic-algorithm)
- [FIPS 180-4 — Secure Hash Standard](https://csrc.nist.gov/pubs/fips/180-4/upd1/final), [FIPS 202 — SHA-3 Standard](https://csrc.nist.gov/pubs/fips/202/final), [NIST SP 800-107 Rev. 1 — Recommendation for Applications Using Approved Hash Algorithms](https://csrc.nist.gov/pubs/sp/800/107/r1/final), [NIST SP 800-132 — Recommendation for Password-Based Key Derivation](https://csrc.nist.gov/pubs/sp/800/132/final)
- [RFC 6151 — Updated Security Considerations for the MD5 Message-Digest and the HMAC-MD5 Algorithms](https://datatracker.ietf.org/doc/html/rfc6151)
- Stevens et al., ["The first collision for full SHA-1"](https://shattered.io/) (2017); Leurent and Peyrin, ["SHA-1 is a Shambles"](https://sha-mbles.github.io/) (2020); Duong and Rizzo, "Flickr's API Signature Forgery Vulnerability" (2009)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Android Developers — Cryptography](https://developer.android.com/privacy-and-security/cryptography) (supported algorithms and deprecated functionality) and [`MessageDigest`](https://developer.android.com/reference/java/security/MessageDigest)
- [Apple — CryptoKit](https://developer.apple.com/documentation/cryptokit), [`Insecure`](https://developer.apple.com/documentation/cryptokit/insecure) and [CommonDigest.h (archived)](https://web.archive.org/web/20240606000312/https://opensource.apple.com/source/CommonCrypto/CommonCrypto-36064/CommonCrypto/CommonDigest.h)
- [AEPD and EDPS — Introduction to the hash function as a personal data pseudonymisation technique (2019)](https://edps.europa.eu/data-protection/our-work/publications/papers/introduction-hash-function-personal-data_en); [US FTC — "No, hashing still doesn't make your data anonymous" (2024)](https://www.ftc.gov/policy/advocacy-research/tech-at-ftc/2024/07/no-hashing-still-doesnt-make-your-data-anonymous)
- [hashcat](https://hashcat.net/hashcat/) and [hash_extender](https://github.com/iagox86/hash_extender)
- [CWE-328: Use of Weak Hash](https://cwe.mitre.org/data/definitions/328.html), [CWE-759: Use of a One-Way Hash without a Salt](https://cwe.mitre.org/data/definitions/759.html), [CWE-916: Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
