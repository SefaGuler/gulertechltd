---
title: "Improper Use of Message Authentication Code (MAC) (MASWE-0009)"
date: 2026-11-09 12:27:00 +0000
subcategory: crypto
summary: "How MACs fail in mobile apps (naive keyed hashes, short tags, timing leaks, bad composition, exposed keys) and how to test them on Android and iOS."
refs: [MASWE-0009, MASVS-CRYPTO-1, MASVS-CRYPTO-2, CWE-208, CWE-323, CWE-327, CWE-354, CWE-807]
tags: [android, ios, masvs-crypto, hmac, mac, integrity]
---

This note is part of our [MASVS-CRYPTO guide](/mobile/masvs-crypto-cryptography-guide/) and covers OWASP [MASWE-0009](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0009/): a message authentication code that is missing, built from the wrong parts, verified carelessly or keyed with a key the attacker can get. MACs are the quiet half of symmetric cryptography. Developers reach for them to protect stored settings, sign API requests, check downloaded configuration or pair with CBC encryption, and the HMAC call itself is almost always fine. What goes wrong is everything around it: `SHA-256(secret + message)` instead of HMAC, a tag cut down to eight hex characters, a `==` comparison, the same key for encryption and authentication, a key sitting in the APK, and — most often in mobile apps — a MAC used to "prove" something to a device whose owner holds the key. You will find the background for all of those, five test procedures (static and dynamic for each platform, plus a protocol-level tampering and replay test), secure Kotlin, Swift and Objective-C, and severity guidance.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [General: what a MAC gives you and what it does not (Guler Tech methodology)](#general-what-a-mac-gives-you-and-what-it-does-not-guler-tech-methodology)
  - [General: HMAC versus naive keyed hashes (Guler Tech methodology)](#general-hmac-versus-naive-keyed-hashes-guler-tech-methodology)
  - [General: tag length and truncation (Guler Tech methodology)](#general-tag-length-and-truncation-guler-tech-methodology)
  - [General: constant-time verification and error oracles (Guler Tech methodology)](#general-constant-time-verification-and-error-oracles-guler-tech-methodology)
  - [General: combining encryption and authentication (Guler Tech methodology)](#general-combining-encryption-and-authentication-guler-tech-methodology)
  - [General: MAC keys, separation and storage (Guler Tech methodology)](#general-mac-keys-separation-and-storage-guler-tech-methodology)
  - [General: replay protection and canonical encoding (Guler Tech methodology)](#general-replay-protection-and-canonical-encoding-guler-tech-methodology)
  - [General: MACs over server data verified on the device (Guler Tech methodology)](#general-macs-over-server-data-verified-on-the-device-guler-tech-methodology)
  - [Android: javax.crypto.Mac and Keystore HMAC keys (Guler Tech methodology)](#android-javaxcryptomac-and-keystore-hmac-keys-guler-tech-methodology)
  - [iOS: CryptoKit HMAC and CommonCrypto CCHmac (MASTG-KNOW-0066, MASTG-KNOW-0067)](#ios-cryptokit-hmac-and-commoncrypto-cchmac-mastg-know-0066-mastg-know-0067)
  - [Related OWASP material: storage integrity checks (MASTG-KNOW-0086, MASTG-BEST-0065, MASTG-BEST-0066)](#related-owasp-material-storage-integrity-checks-mastg-know-0086-mastg-best-0065-mastg-best-0066)
- [Testing](#testing)
  - [Android: MAC Construction and Verification in Code (Guler Tech methodology)](#android-mac-construction-and-verification-in-code-guler-tech-methodology)
  - [Android: Runtime Use of MACs (Guler Tech methodology)](#android-runtime-use-of-macs-guler-tech-methodology)
  - [iOS: MAC Construction and Verification in Code (Guler Tech methodology)](#ios-mac-construction-and-verification-in-code-guler-tech-methodology)
  - [iOS: Runtime Use of MACs (Guler Tech methodology)](#ios-runtime-use-of-macs-guler-tech-methodology)
  - [Both platforms: Tampering and Replay of MAC-Protected Data (Guler Tech methodology)](#both-platforms-tampering-and-replay-of-mac-protected-data-guler-tech-methodology)
- [Secure implementation](#secure-implementation)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

> **Note:** At the time of writing, the MASWE page for this weakness links **no Knowledge pages and no Tests**. Everything under [Knowledge](#knowledge) and [Testing](#testing) below is **Guler Tech methodology** unless it cites an OWASP ID. The OWASP material that genuinely relates to MACs lives under other weaknesses, and we cite it where it helps: the storage-integrity best practices [MASTG-BEST-0065](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0065/) (iOS) and [MASTG-BEST-0066](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0066/) (Android), the iOS knowledge page [MASTG-KNOW-0086](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0086/), the resilience tests [MASTG-TEST-0338](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0338/) and [MASTG-TEST-0387](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0387/) with their demos (both mapped to MASWE-0057), the crypto knowledge pages [MASTG-KNOW-0012](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0012/), [MASTG-KNOW-0066](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0066/), [MASTG-KNOW-0067](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0067/) and [MASTG-KNOW-0068](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0068/), and the legacy (MASTG v1) tests [MASTG-TEST-0014](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0014/) and [MASTG-TEST-0015](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0015/).

A MAC takes a secret key and a message and produces a short tag. Anyone holding the key can compute the tag; anyone without it cannot produce a valid tag for a message they have not seen tagged, even after seeing many valid pairs. That gives you **integrity** (the message was not changed) and **authenticity** (it came from a key holder). MASWE-0009 applies when one of the conditions that make those guarantees true is missing:

- the algorithm is a sound MAC, not a checksum, a bare hash or a home-made construction;
- the key is random, long enough, used for nothing else, and out of the attacker's reach;
- the tag is long enough;
- verification happens before the data is used, compares in constant time, and fails the same way whatever went wrong;
- the protocol stops a captured valid message from being accepted again.

The weakness maps to MASVS-CRYPTO-1 and MASVS-CRYPTO-2 (the key-management half), to MASVS v1 MSTG-CRYPTO-4 and MSTG-CRYPTO-5, and to CWE-208 (Observable Timing Discrepancy), CWE-323 (Reusing a Nonce, Key Pair in Encryption), CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), CWE-354 (Improper Validation of Integrity Check Value) and CWE-807 (Reliance on Untrusted Inputs in a Security Decision). It applies to the L1, L2 and EUDIW profiles.

One question frames every MAC finding on mobile, so ask it first: **who holds the key, and who is the attacker?** A MAC can only protect against parties who do not have the key. If the key is in the app (hardcoded, or stored where the device owner can read it), the MAC protects against network attackers, other apps and other devices — never against the person holding the phone. Many "integrity" features fail that test before you look at a single line of crypto.

## Modes of Introduction

- **Non-cryptographic checksums.** CRC-32, Adler-32, `hashCode()`, XOR sums or Luhn digits over data an attacker may modify. They detect line noise; an attacker recomputes them in microseconds.
- **Unkeyed hashes as MACs.** `value` stored next to `SHA-256(value)`. The attacker edits both.
- **Naive keyed hashes.** `H(key ‖ message)` (length-extendable with MD5, SHA-1, SHA-256, SHA-512), `H(message ‖ key)` (inherits every collision in H), or bespoke mixes of hashing and XOR, instead of HMAC.
- **MACs on weak primitives.** HMAC-MD5 or HMAC-SHA1 in new designs; raw CBC-MAC over variable-length messages; CBC-MAC keyed with the CBC encryption key.
- **Weak or misused keys.** Keys that are short, derived from device identifiers or the package name, generated with `java.util.Random`, hardcoded ([MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/)), shared by every install, or reused for encryption, for other MAC purposes or across users.
- **Fragile composition of encryption and authentication.** MAC-then-encrypt or encrypt-and-MAC instead of encrypt-then-MAC or an AEAD; decrypting before verifying; a MAC that covers the ciphertext but not the IV, header or key version.
- **Truncated tags.** HMAC output cut to 4–8 bytes; GCM tags shorter than 128 bits without a reason.
- **Missing replay protection.** Signed requests without timestamp, nonce or sequence number; stored data protected by a MAC but open to rollback to an older valid copy.
- **Observable verification.** Byte-by-byte comparison (`==`, `equals`, `Arrays.equals`, `memcmp`, `isEqual:`) and distinct error messages for "bad MAC", "bad padding" and "bad format".
- **Verification that can be skipped.** A missing tag treated as "first run, accept and re-tag"; verification only on some code paths; a failure that is logged but not acted on.

## Impact

- **Undetected manipulation of data.** Stored entitlements, feature flags, prices, user roles, cached server configuration or transaction parameters are modified and accepted as genuine.
- **Forgery and replay of authenticated actions.** Signed requests are forged (with the key or by length extension) or replayed, so the backend executes actions the user never requested — transfers, purchases, account changes.
- **Decryption oracles.** Where authentication is composed badly with CBC encryption, the verification behaviour leaks plaintext through padding-oracle attacks, turning an integrity bug into a confidentiality one.
- **Key recovery and lateral impact.** A MAC key reused as an encryption key, or an app-wide key shared by every user, turns one extraction into the ability to forge for everyone.

## Mitigations

- **Use a standard MAC**: HMAC with SHA-256 or stronger ([RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104), FIPS 198-1, and the NIST SP 800-224 draft that will replace them), or an AEAD mode (AES-GCM, ChaCha20-Poly1305) when you are also encrypting. Use CMAC rather than raw CBC-MAC if you need a block-cipher MAC. Never use checksums for security.
- **Use strong, single-purpose keys**: 256-bit keys from a CSPRNG, generated inside the Android Keystore (`KEY_ALGORITHM_HMAC_SHA256`) or kept in the iOS Keychain, one key per purpose, per user where the backend verifies.
- **Prefer AEAD; otherwise encrypt-then-MAC** with independent keys, covering IV, header and associated data, and verify before decrypting.
- **Keep full-length tags**: at least 128 bits, and the full HMAC output unless bandwidth genuinely matters.
- **Add replay protection**: timestamp plus nonce (or a sequence number) inside the authenticated data, checked by the verifier; versioning for stored data that must not roll back.
- **Verify in constant time with uniform errors**: `MessageDigest.isEqual`, CryptoKit `isValidAuthenticationCode`, `timingsafe_bcmp`; one generic failure for every verification error.
- **Use signatures, not MACs, when the verifier must not be able to forge** — in particular for data a server sends to the app ([MASWE-0010](/mobile/maswe-0010-improper-signature-generation/), [MASWE-0011](/mobile/maswe-0011-improper-signature-verification/)).

## Knowledge

None of these sections comes from a Knowledge page linked to MASWE-0009, because there is none. They are our own explanations, with OWASP and vendor sources cited where they exist.

### General: what a MAC gives you and what it does not (Guler Tech methodology)

A MAC is a symmetric primitive: the same key creates and checks tags. Three consequences follow, and most MAC findings in mobile apps come from forgetting one of them.

1. **Every verifier can forge.** There is no "verify-only" HMAC key. If the app can check a tag, the app (and whoever controls the device) can create one. Where you need a party that can verify but not create — the app checking data from your server, one user checking another's message — you need a digital signature.
2. **No non-repudiation.** A valid tag proves "someone with the key". With a key shared by every install, it proves nothing about which install or user.
3. **Integrity is not freshness.** A MAC says the message is one a key holder produced, not that it was produced *now* or only once. Freshness needs a timestamp, nonce or counter inside the authenticated data.

The most common mobile designs and what a correctly implemented MAC achieves in each:

| Design | Key holder(s) | Protects against | Does not protect against |
|---|---|---|---|
| Stored settings tagged with a Keystore/Keychain key | The app on this device | Offline edits, backups restored to another device, other apps | Root or jailbreak with code execution in the app (the attacker uses the key through the app); rollback to an older tagged copy |
| Stored settings tagged with a hardcoded key | Everyone with the APK/IPA | Accidental corruption | Anyone who reverse-engineers the app once |
| Requests signed with a per-user key issued at login | The user's app and the server | Network tampering, replay (with nonce/timestamp), other users | The user themselves (who can sign anything they like as themselves) |
| Requests signed with an app-wide embedded key | Every install and the server | Casual tampering | Anyone who extracts the key: they can sign requests as any user |
| Config or licence from the server, HMAC-verified by the app | Server and every install | Network/CDN tampering by someone who lacks the key | Anyone who extracts the key, who can mint valid configs or licences |

### General: HMAC versus naive keyed hashes (Guler Tech methodology)

HMAC ([RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104), FIPS 198-1) wraps a hash function in two keyed passes:

```text
HMAC(K, m) = H( (K' XOR opad) || H( (K' XOR ipad) || m ) )
```

where `K'` is the key padded to the hash block size (64 bytes for SHA-256, 128 bytes for SHA-512) or, if longer than a block, hashed first. The outer hash hides the inner hash's state, which is what defeats length extension, and HMAC's security proof relies on the hash's compression function behaving as a pseudorandom function rather than on collision resistance. That is why HMAC-SHA1 is still considered secure as a MAC ([NIST SP 800-131A Rev. 2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf) lists it as acceptable) and why [RFC 6151](https://datatracker.ietf.org/doc/html/rfc6151) finds no practical attack on HMAC-MD5 as a MAC — while still advising against HMAC-MD5 in new protocols. For new work use HMAC-SHA-256; treat HMAC-SHA1 as a migration item and HMAC-MD5 as a stronger one.

The ad-hoc alternatives fail in specific, testable ways:

| Construction | Problem |
|---|---|
| `H(key ‖ msg)` with MD5, SHA-1, SHA-256, SHA-512 | Length extension: from one valid (msg, tag) pair an attacker computes a valid tag for `msg ‖ padding ‖ anything`. See [MASWE-0008](/mobile/maswe-0008-improper-hashing/#general-length-extension-and-secret-prefix-hashing-guler-tech-methodology). |
| `H(msg ‖ key)` | No length extension, but any collision `H(m1) = H(m2)` (computable offline for MD5 and SHA-1, without the key) gives `tag(m1) = tag(m2)`. |
| `H(key ‖ msg ‖ key)` and other "envelopes" | Better than either, but with no reason to exist when HMAC is one call away, and with weaker analysis behind it. |
| Encrypt the hash: `AES(key, SHA-256(msg))` | Malleable or forgeable depending on the mode; with ECB/CBC under a static IV it is a deterministic function an attacker can sometimes splice. |
| Raw CBC-MAC (last ciphertext block of AES-CBC with a zero IV) | Secure only for fixed-length messages; for variable lengths, tags can be spliced to forge new messages. Broken outright if the same key also encrypts. Use CMAC ([NIST SP 800-38B](https://csrc.nist.gov/pubs/sp/800/38/b/upd1/final)). |
| SHA-3/KMAC, BLAKE2 keyed mode, Poly1305 (one-time key) | Sound when used as specified. KMAC is the NIST-approved SHA-3 MAC (SP 800-185). Poly1305 is only safe with a fresh key per message, which is why it appears inside ChaCha20-Poly1305 rather than on its own. |

### General: tag length and truncation (Guler Tech methodology)

A *t*-bit tag can be guessed with probability 2^-*t* per attempt, regardless of how strong the key is. The question is how many attempts the attacker gets:

| Tag length | Guesses for a 50% chance | Practical meaning |
|---|---|---|
| 32 bits | about 3 × 10^9 | Feasible against any verifier without strict rate limiting |
| 64 bits | about 1.3 × 10^19 | Out of reach online; NIST SP 800-38B's general guidance for CMAC is at least 64 bits |
| 96 bits | 2^95 | Minimum for general-purpose GCM per NIST SP 800-38D (32- and 64-bit GCM tags only under strict conditions in its Appendix C) |
| 128 bits | 2^127 | What you should expect to see |
| 256 bits | 2^255 | Full HMAC-SHA-256 |

NIST permits truncating HMAC output (SP 800-107 Rev. 1), but nothing in a mobile app needs a short tag: a 32-byte tag in a header or a preferences file is free. When you find truncation, look at how it is done as well as how short it is. The dangerous variant is the verifier that compares only as many bytes as the *attacker supplied* (`expected.startsWith(provided)`, `memcmp(expected, provided, provided_len)`): an empty or one-character tag then passes. GCM has its own version: `GCMParameterSpec(64, iv)` on Android silently halves the tag.

### General: constant-time verification and error oracles (Guler Tech methodology)

A comparison that returns at the first differing byte (`String.equals`, `Arrays.equals`, Kotlin `==` on strings and `contentEquals` on arrays, Swift `Data ==`, `memcmp`, `-[NSData isEqual:]`) takes slightly longer the more leading bytes are right. An attacker who can submit tags and measure response times can recover a valid tag byte by byte: at most 256 × *n* attempts for an *n*-byte tag instead of 2^(8*n*). Remote timing attacks are noisy but have been demonstrated repeatedly, from the Xbox 360 boot-loader HMAC check to the Keyczar library's verification (2009).

On mobile, be precise about when this is exploitable:

- **The verifier is your server** (signed requests, webhook-style callbacks) — the classic case; check the server code if it is in scope.
- **The verifier is the app, and the tag comes from somewhere the attacker controls but the key does not**: an exported component or deep link carrying a signed parameter, a push payload, a local-network peer, another app via IPC. The attacker has no key and only the timing channel.
- **The verifier is the app checking its own storage** — timing is irrelevant, because an attacker able to edit the sandbox can usually use the key directly. Report a non-constant-time comparison here as Low (code quality), not as a timing attack.

The constant-time options per platform:

| Platform | Use | Avoid |
|---|---|---|
| Android/Java | `MessageDigest.isEqual(a, b)` (constant-time for equal lengths on current Android), Tink `Mac.verifyMac` | `Arrays.equals`, `contentEquals`, `String.equals` or Kotlin `==` on hex/Base64 tags (Kotlin `==` on two `ByteArray`s is a reference check and always fails) |
| iOS CryptoKit | `HMAC<H>.isValidAuthenticationCode(_:authenticating:using:)`, or `==` between two `HashedAuthenticationCode` values (both use a constant-time compare in Apple's open-source swift-crypto implementation) | Converting to `Data` and using `==` |
| iOS C/Objective-C | `timingsafe_bcmp` (Darwin libc), or a manual XOR-accumulate loop | `memcmp`, `-[NSData isEqual:]`, `-[NSString isEqualToString:]` |

**Error oracles** are the other side-channel. If decryption and verification can fail in distinguishable ways — different exception types surfacing as different HTTP status codes or error messages, a "bad padding" path that is faster than a "bad MAC" path — an attacker gets an oracle. With CBC and PKCS#7 padding that oracle decrypts data (the padding-oracle attack; Lucky Thirteen showed that even timing differences in MAC-then-encrypt TLS were enough). The fix is structural: verify the MAC over the ciphertext *first*, and on any failure return one generic error.

### General: combining encryption and authentication (Guler Tech methodology)

There are three generic ways to combine a cipher and a MAC (Bellare and Namprempre, 2000):

| Composition | What is sent | Verdict |
|---|---|---|
| **Encrypt-and-MAC** (E&M) | `Enc(m)`, `MAC(m)` | Leaks: the MAC is computed over plaintext and is deterministic, so equal plaintexts produce equal tags. Not generically secure. |
| **MAC-then-encrypt** (MtE) | `Enc(m ‖ MAC(m))` | The receiver must decrypt before it can verify, which is exactly what padding-oracle and Lucky Thirteen-style attacks exploit with CBC. Secure only with specific modes and careful implementation. |
| **Encrypt-then-MAC** (EtM) | `c = Enc(m)`, `MAC(c)` | Generically secure: tampered ciphertext is rejected before any decryption. The one to use if you compose by hand. |
| **AEAD** | `Seal(m, aad)` | Encryption and authentication in one primitive (AES-GCM, ChaCha20-Poly1305, AES-CCM). The default choice on both platforms. |

Encrypt-then-MAC has details that matter in review:

- The MAC must cover **everything the decryptor uses**: version byte, key identifier, IV/nonce, ciphertext, and any associated context (record ID, user ID). A MAC over the ciphertext alone lets an attacker swap the IV, which in CBC flips bits of the first plaintext block at will.
- Use **independent keys** for encryption and MAC. Derive both from a master key with HKDF (`info = "enc"` / `"mac"`), or generate two keystore keys.
- **Verify before decrypting**, and do not decrypt at all if verification fails.

AEAD modes have their own failure modes, covered with encryption in [MASWE-0007](/mobile/maswe-0007-improper-encryption/): a reused GCM nonce under the same key leaks the authentication subkey and allows forgeries, and code that catches `AEADBadTagException` and carries on (or "falls back" to unauthenticated decryption) throws the authentication away. The OWASP source [MASTG-KNOW-0012](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0012/) makes the same recommendation: prefer GCM, which integrates authentication, over CBC, which needs a separate HMAC.

### General: MAC keys, separation and storage (Guler Tech methodology)

**Strength.** An HMAC key should have at least as many random bits as the security level you want: 256 bits from a CSPRNG for HMAC-SHA-256 is the norm. NIST SP 800-131A requires at least 112 bits for HMAC keys. Keys longer than the hash block size are hashed down, so a 1 KB "key" is no stronger than a 32-byte one, and a key derived from a password, the package name, `ANDROID_ID`, `identifierForVendor` or a timestamp has only the entropy of its source. A password-derived MAC key needs a proper KDF ([MASWE-0014](/mobile/maswe-0014-improper-key-derivation/)); a key from `java.util.Random` or `arc4random` misuse is [MASWE-0012](/mobile/maswe-0012-improper-random-number-generation/).

**Separation.** One key, one purpose, one algorithm ([NIST SP 800-57 Part 1 Rev. 5](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf), section 5.2). The cases you will see:

- the same bytes used as an AES key and an HMAC key (`SecretKeySpec(k, "AES")` and `SecretKeySpec(k, "HmacSHA256")`) — interactions are often not exploitable with AES and HMAC, but nobody has proved they are safe, and with CBC-MAC plus CBC encryption it is a known break;
- one HMAC key for several message types (session tokens and storage tags, say), so a tag minted in one context is valid in another;
- one key for every user, so a tag from user A's request is valid for user B's.

The Android Keystore enforces part of this for you: a key created for `KEY_ALGORITHM_AES` cannot initialise a `Mac`, and an HMAC key is bound to its digest. Raw keys get no such help, and neither does an iOS `SymmetricKey`.

**Storage.** A MAC key belongs in the platform keystore, and on Android it can be *generated* there and never leave secure hardware. On iOS, CryptoKit HMAC keys are `SymmetricKey` values; the Secure Enclave does not compute HMACs for apps, so store the key in the Keychain with a `ThisDeviceOnly` accessibility class. Everything else about key storage — hardcoded keys, keys in preferences, wrapped import — is covered in [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/); for MACs the only extra point is that a hardcoded MAC key is worse than a hardcoded encryption key in one respect, because it lets the attacker *create* data the app or server will trust.

### General: replay protection and canonical encoding (Guler Tech methodology)

**Replay.** For requests, put a timestamp and a random nonce (or a per-session sequence number) inside the authenticated string, and have the server reject anything outside a short window (minutes) or with a nonce it has already seen in that window. Bind the tag to the context it is valid for — HTTP method, path, user or session — so it cannot be moved. For stored data, replay means **rollback**: an attacker restores an older copy of a tagged file (a trial counter before it ran out, an entitlement before it was revoked). A MAC cannot detect that on its own; you need a monotonic counter or version held somewhere the attacker cannot roll back (in practice, the server).

**Canonical encoding.** A MAC authenticates bytes, not meaning. If the app builds the authenticated string by concatenating fields — `userId + amount`, `"a=" + a + "&b=" + b` — two different requests can produce the same bytes: user `12` sending `3` and user `1` sending `23` both authenticate `"123"`. Use an unambiguous encoding: length-prefixed fields, a fixed-order list with a separator that cannot occur in the fields, or a canonical serialisation, and make the verifier rebuild the string from the parsed values, not from the raw request. Duplicate parameters, parameters moved between query and body, and different URL-encodings of the same value are all canonicalisation tests (see the protocol test below).

### General: MACs over server data verified on the device (Guler Tech methodology)

Apps often need to trust data that arrives from a server or a CDN and sits on the device for a while: remote configuration, feature flags, a licence or entitlement blob, an offline voucher, a downloaded ruleset. A MAC is the wrong tool for this. To verify an HMAC the app needs the key; the key is therefore in every install; anyone who extracts it can produce valid configs and licences for themselves and publish a "key generator" for everyone else.

Use a signature instead: the server signs with a private key that never leaves it (ideally in a KMS or HSM), and the app verifies with a public key embedded in the package. Extracting a public key gains an attacker nothing. Ed25519 or ECDSA P-256 with SHA-256 are the usual choices; see [MASWE-0010](/mobile/maswe-0010-improper-signature-generation/) and [MASWE-0011](/mobile/maswe-0011-improper-signature-verification/).

Two caveats belong in the report. First, any client-side check can be patched out on a device the attacker controls, so a signature on a licence protects against forged licences being distributed and against network tampering, not against a determined user who modifies their own app; entitlements that matter must be enforced on the server. Second, signed data still needs freshness (an expiry, a version) or old valid blobs can be replayed.

### Android: javax.crypto.Mac and Keystore HMAC keys (Guler Tech methodology)

There is no Android Knowledge page for MACs. The legacy (MASTG v1) tests [MASTG-TEST-0014](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0014/) and [MASTG-TEST-0015](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0015/) include the `Mac` class in their static search and ask whether symmetric keys are used for more than one purpose; MASTG-KNOW-0012 covers `KeyGenParameterSpec` purposes; BEST-0066 shows an HMAC example. The rest is ours.

**The JCA API.** `javax.crypto.Mac.getInstance(algorithm)` returns a MAC engine, by default from Conscrypt. Standard names are `HmacMD5`, `HmacSHA1`, `HmacSHA224`, `HmacSHA256`, `HmacSHA384` and `HmacSHA512`. The life cycle is `init(key)`, `update(...)` any number of times, then `doFinal()` (or `doFinal(input)` in one step), which returns the tag and resets the engine for reuse with the same key. There is no `verify` method: the app computes the expected tag and compares it, which is precisely where the constant-time mistakes happen. Any `SecretKey` whose algorithm matches works, including `SecretKeySpec(rawBytes, "HmacSHA256")` — the path by which raw, hardcoded or reused keys enter.

**Keystore HMAC keys.** Since Android 6.0 (API 23) the Keystore can generate HMAC keys that never leave it:

```kotlin
val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore")
kg.init(KeyGenParameterSpec.Builder("storage_mac_v1", KeyProperties.PURPOSE_SIGN).build())
val key = kg.generateKey()                          // an AndroidKeyStoreSecretKey; getEncoded() returns null

val tag = Mac.getInstance("HmacSHA256").run { init(key); doFinal(data) }
```

Constants exist for SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512 (`KEY_ALGORITHM_HMAC_SHA1` … `KEY_ALGORITHM_HMAC_SHA512`); the digest is fixed by the algorithm. Computing a MAC is a `PURPOSE_SIGN` operation, as in the platform documentation's example. The usual authorisations apply — `setUserAuthenticationRequired`, `setUnlockedDeviceRequired` (API 28+), and `setIsStrongBoxBacked(true)` (API 28+; StrongBox supports HMAC-SHA256). From a tester's point of view the giveaway is the key class in `Mac.init`: `android.security.keystore.AndroidKeyStoreSecretKey` (or a similarly named keystore class) with `getEncoded()` returning `null` means the key is in the Keystore; `javax.crypto.spec.SecretKeySpec` means the raw bytes are in the app's memory and came from somewhere you need to find.

**Libraries.** Tink's `Mac` primitive (`computeMac`, `verifyMac`) uses HMAC-SHA256 or AES-CMAC with tags of at least 128 bits and constant-time verification, and its `AndroidKeysetManager` can keep the keyset encrypted under a Keystore master key. Bouncy Castle offers `HMac`, `CMac` and `CBCBlockCipherMac` (raw CBC-MAC — look closely if you see it). Apache Commons Codec's `HmacUtils` is a thin wrapper over `Mac`. OkHttp and Retrofit interceptors are where request-signing code usually lives; search for interceptors that add headers such as `X-Signature`, `X-Hmac` or `Authorization: HMAC …`.

**Encrypted Jetpack storage.** `EncryptedSharedPreferences` and `EncryptedFile` (Jetpack Security, via Tink) use AEAD and therefore already authenticate their contents. The library is deprecated; existing use is not a MAC finding, but do not recommend it for new code.

### iOS: CryptoKit HMAC and CommonCrypto CCHmac (MASTG-KNOW-0066, MASTG-KNOW-0067)

Sources: [MASTG-KNOW-0066](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0066/) lists HMAC among CryptoKit's symmetric-key algorithms; [MASTG-KNOW-0067](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0067/) points to `CommonHMAC.h`; [MASTG-KNOW-0068](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0068/) notes that CryptoSwift implements MAC functions (and CRCs) itself. The API detail below is ours.

**CryptoKit (iOS 13+).** `HMAC<H>` is generic over the hash function, so the algorithm is in the type:

```swift
import CryptoKit

let key = SymmetricKey(size: .bits256)
let tag = HMAC<SHA256>.authenticationCode(for: message, using: key)    // HashedAuthenticationCode<SHA256>
let ok  = HMAC<SHA256>.isValidAuthenticationCode(tag, authenticating: message, using: key)

var h = HMAC<SHA256>(key: key)                                          // incremental form
h.update(data: part1)
h.update(data: part2)
let tag2 = h.finalize()
```

`isValidAuthenticationCode` has overloads that accept either a `HashedAuthenticationCode` or raw bytes (any `ContiguousBytes`, such as `Data` read from disk), and both compare in constant time. `HMAC<Insecure.SHA1>` and `HMAC<Insecure.MD5>` compile, which is how weak HMACs appear in CryptoKit code. `HKDF<SHA256>` (iOS 14+) derives separate keys from a master key. For authenticated encryption, `AES.GCM` and `ChaChaPoly` produce a 16-byte tag automatically.

**CommonCrypto.** `CommonHMAC.h` declares a one-shot and an incremental API:

```objectivec
void CCHmac(CCHmacAlgorithm algorithm, const void *key, size_t keyLength,
            const void *data, size_t dataLength, void *macOut);
void CCHmacInit(CCHmacContext *ctx, CCHmacAlgorithm algorithm, const void *key, size_t keyLength);
void CCHmacUpdate(CCHmacContext *ctx, const void *data, size_t dataLength);
void CCHmacFinal(CCHmacContext *ctx, void *macOut);
```

The `CCHmacAlgorithm` enum values are `kCCHmacAlgSHA1` (0), `kCCHmacAlgMD5` (1), `kCCHmacAlgSHA256` (2), `kCCHmacAlgSHA384` (3), `kCCHmacAlgSHA512` (4) and `kCCHmacAlgSHA224` (5). Those integers are what you see in disassembly (`mov w0, #2` before `bl CCHmac`) and in a Frida hook's first argument. `CCHmac` takes the key as a raw pointer, so it is also where hardcoded keys surface ([MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/)). CommonCrypto has no comparison helper; the app's own code decides how the tag is compared.

### Related OWASP material: storage integrity checks (MASTG-KNOW-0086, MASTG-BEST-0065, MASTG-BEST-0066)

Sources: [MASTG-KNOW-0086 Storage Integrity Checks](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0086/), [MASTG-BEST-0065 Implementing Storage Integrity Checks on iOS](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0065/), [MASTG-BEST-0066 Implementing Storage Integrity Checks on Android](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0066/). These pages belong to MASVS-RESILIENCE and MASWE-0057, but they are the closest thing OWASP has to MAC guidance for mobile, and their tests ([MASTG-TEST-0338](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0338/), [MASTG-TEST-0387](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0387/)) find HMAC code you then evaluate here.

Their advice, condensed: compute an HMAC over data before writing it to local storage and verify it before trusting the data; keep the key in the Keychain (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`) or the Android Keystore; if the data is also encrypted, use encrypt-then-MAC; and treat the whole mechanism as defence in depth, because a rooted or jailbroken attacker can extract or use the key, or hook the check.

When you use those pages as reference code, correct three details, all of which are MASWE-0009 issues in their own right:

- **The comparisons are not constant-time.** BEST-0065 verifies with `Data(expected) == mac`, KNOW-0086 with `[hmac isEqual: digestBuffer]`, and BEST-0066 with Kotlin `contentEquals`. For local storage this is low-impact, as explained above, but it is the pattern developers copy into network code. Use `isValidAuthenticationCode`, `timingsafe_bcmp` and `MessageDigest.isEqual`.
- **BEST-0066's Android sample takes the key as a raw `ByteArray`** and wraps it in `SecretKeySpec`, while its prose recommends the Keystore. With a Keystore HMAC key the code is the same minus the `SecretKeySpec` line, and the key never exists in app memory (see [Secure implementation](#secure-implementation)).
- **Neither page addresses rollback.** An attacker can restore an older file with its valid tag. If the stored value is a counter or an entitlement, the authoritative copy must live on the server.

The two demos are useful practice targets for the tests below. [MASTG-DEMO-0101](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0101/MASTG-DEMO-0101/) stores a role in `SharedPreferences` with an HMAC-SHA256 tag, but the key is the hardcoded string `this-is-a-very-secret-key-for-the-demo` and the tags are compared as hex strings with Kotlin `==`; the demo itself shows forging a valid tag for `admin` with one line of Python. [MASTG-DEMO-0150](https://mas.owasp.org/MASTG/demos/ios/MASVS-RESILIENCE/MASTG-DEMO-0150/MASTG-DEMO-0150/) shows the iOS pattern done better: `HMAC<SHA256>.authenticationCode` on write and `isValidAuthenticationCode` on read, visible as two CryptoKit imports in radare2 (with an in-memory key, which a real app would keep in the Keychain).

## Testing

All five tests in this section are **Guler Tech methodology**, written in the shape of the OWASP beta tests. Run the static test first to find the MAC code, the dynamic test to see keys, tags and comparisons at runtime, and the protocol test to prove what an attacker can actually do with what you found. The OWASP resilience tests MASTG-TEST-0338 (Android) and MASTG-TEST-0387 (iOS) are a good complement: they ask *whether* stored data is integrity-checked; these tests ask whether the check is built correctly.

### Android: MAC Construction and Verification in Code (Guler Tech methodology)

Type: static (code), manual review. Platform: Android.

#### Overview

The test locates every place the app computes or verifies a MAC (or something pretending to be one) and checks it against the conditions in the [Overview](#overview): algorithm, construction, key origin, tag length, comparison, composition with encryption, and replay protection. Entry points are `javax.crypto.Mac`, `KeyGenerator` with HMAC algorithms, `SecretKeySpec` with an `Hmac*` algorithm name, `MessageDigest` used with a secret, `java.util.zip.CRC32`/`Adler32`, `GCMParameterSpec`, and library wrappers (Tink `Mac`, Bouncy Castle `HMac`/`CMac`/`CBCBlockCipherMac`, Commons Codec `HmacUtils`).

#### Prerequisites

- The APK and any splits (`adb shell pm path <package>`, `adb pull`).
- jadx (MASTG-TOOL-0018), semgrep (MASTG-TOOL-0110), grep. These implement the OWASP techniques MASTG-TECH-0013 (reverse engineering) and MASTG-TECH-0014 (static analysis); reading the results is MASTG-TECH-0023 (reviewing decompiled Java code).
- radare2 for native libraries, if the app has any.

#### Steps

1. **Decompile** with `jadx -d out/ app.apk`.

2. **Find the MAC code and its relatives:**

   ```bash
   SRC=out/sources
   EXCL='^out/sources/(androidx|kotlin|kotlinx|com/google/android/gms)/'
   grep -rnE 'Mac\.getInstance\(|KEY_ALGORITHM_HMAC|"Hmac(MD5|SHA1|SHA224|SHA256|SHA384|SHA512)"|HmacUtils|CBCBlockCipherMac|new (HMac|CMac)\(' $SRC | grep -vE "$EXCL"
   grep -rnE 'new (CRC32|Adler32)\(' $SRC | grep -vE "$EXCL"
   grep -rniE '"x-(signature|sign|hmac|auth-signature|request-signature)"|addHeader\("(sign|signature)' $SRC | grep -vE "$EXCL"
   grep -rnE 'new GCMParameterSpec\(' $SRC | grep -vE "$EXCL"
   ```

   The third command finds request-signing interceptors by header name, which is often the quickest route to the code that matters.

3. **Run the semgrep rules** below. They are candidate finders; each hit needs reading.

   ```yaml
   rules:
     - id: gt-android-weak-mac-algorithm
       languages: [java]
       severity: WARNING
       message: "[MASVS-CRYPTO-1] Legacy HMAC algorithm $ALG"
       patterns:
         - pattern-either:
             - pattern: Mac.getInstance($ALG)
             - pattern: Mac.getInstance($ALG, $P)
             - pattern: KeyGenerator.getInstance($ALG, $P)
             - pattern: new SecretKeySpec($K, $ALG)
         - metavariable-regex:
             metavariable: $ALG
             regex: (?i).*"hmac(md5|sha1)"
     - id: gt-android-mac-raw-key
       languages: [java]
       severity: INFO
       message: "HMAC key built from raw bytes; find where $K comes from"
       patterns:
         - pattern: new SecretKeySpec($K, $ALG)
         - metavariable-regex:
             metavariable: $ALG
             regex: (?i).*hmac.*
     - id: gt-android-mac-nonconstant-compare
       languages: [java]
       severity: WARNING
       message: "[MASVS-CRYPTO-1] Possible MAC or tag comparison that is not constant-time"
       pattern-either:
         - patterns:
             - pattern-either:
                 - pattern: Arrays.equals($A, $B)
                 - pattern: Intrinsics.areEqual($A, $B)
                 - pattern: $A.equals($B)
                 - pattern: $A.equalsIgnoreCase($B)
             - metavariable-regex:
                 metavariable: $A
                 regex: (?i).*(hmac|mac|sig|tag|digest|hash).*
         - patterns:
             - pattern-either:
                 - pattern: Arrays.equals($A, $B)
                 - pattern: Intrinsics.areEqual($A, $B)
                 - pattern: $A.equals($B)
                 - pattern: $A.equalsIgnoreCase($B)
             - metavariable-regex:
                 metavariable: $B
                 regex: (?i).*(hmac|mac|sig|tag|digest|hash).*
     - id: gt-android-mac-truncation
       languages: [java]
       severity: WARNING
       message: "[MASVS-CRYPTO-1] MAC output truncated"
       pattern-either:
         - pattern: Arrays.copyOf($MAC.doFinal(...), $N)
         - pattern: Arrays.copyOfRange($MAC.doFinal(...), $S, $E)
         - pattern: |
             byte[] $T = $MAC.doFinal(...);
             ...
             Arrays.copyOf($T, $N);
         - pattern: |
             byte[] $T = $MAC.doFinal(...);
             ...
             Arrays.copyOfRange($T, $S, $E);
     - id: gt-android-gcm-short-tag
       languages: [java]
       severity: WARNING
       message: "[MASVS-CRYPTO-1] GCM tag length $LEN bits is below 128"
       patterns:
         - pattern: new GCMParameterSpec($LEN, ...)
         - metavariable-comparison:
             metavariable: $LEN
             comparison: $LEN < 128
   ```

   ```bash
   semgrep -c gt-android-mac.yml out/sources/
   ```

   The comparison rule matches on variable and expression names, so it will catch `storedHmac.equals(calculated)` and `Intrinsics.areEqual(storedHmac, calculatedHmac)` (Kotlin's `==` on strings) and will also produce noise such as `machine.equals(...)`. That is deliberate: a name-based filter is the only practical static signal, and the noise is quick to discard.

4. **Look for hashes standing in for MACs.** Open each class that uses `MessageDigest` together with a secret-looking value:

   ```bash
   grep -rlE 'MessageDigest\.getInstance' $SRC | grep -vE "$EXCL" \
     | xargs grep -liE 'secret|signature|sign\(|apikey|api_key|app_key|salt'
   ```

   In each file, check whether a constant or key is fed into the digest before or after the message (`md.update(SECRET); md.update(body)`, or `digest((SECRET + params).getBytes())`). That is `H(key ‖ msg)` or `H(msg ‖ key)`, not a MAC.

5. **Trace each MAC's key to its origin.** For every `Mac.init(key)`, follow `key` back: a Keystore lookup (`KeyStore.getInstance("AndroidKeyStore")` … `getKey(alias, null)`) is good; `SecretKeySpec` over a literal, a resource, a `BuildConfig` field, a native method's return value, a value from `SharedPreferences`, or a digest of `ANDROID_ID` or the package name is a finding. The hardcoded-key test from [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/) (MASTG-TEST-0212) covers the literal cases in depth. Note whether the same key or key bytes also reach a `Cipher.init`.

6. **Check composition.** Find methods that use both `Cipher` and `Mac`. In the decrypt path, confirm the tag is checked (and checked in constant time) *before* `Cipher.doFinal` runs, that the MAC input includes the IV and any header, and that encryption and MAC use different keys. Also look for `catch (AEADBadTagException ...)` or `catch (BadPaddingException ...)` blocks that do anything other than fail.

7. **Check verification logic.** Read every verify path for: a missing tag treated as acceptable ("first run") or silently re-tagged; comparisons against only part of the tag (`startsWith`, `regionMatches`, `substring` of the expected value to the provided length); failures that are logged but not acted on; and different error responses for different failures.

8. **Check replay protection** in request-signing code: is a timestamp, nonce or sequence number part of the signed string, and is the signed string built from unambiguous fields? Server-side enforcement is tested in the [protocol test](#both-platforms-tampering-and-replay-of-mac-protected-data-guler-tech-methodology).

9. **Native code.** If MAC code lives in a `.so` (common for "hidden" request signing), look for imports or symbols such as `HMAC`, `HMAC_Init_ex`, `EVP_sha1`, `EVP_sha256`, `CRYPTO_memcmp` (constant-time) and `memcmp` (not), then use `axt` in radare2 to find the JNI function that calls them:

   ```bash
   for so in native/lib/arm64-v8a/*.so; do
     echo "== $so"; nm -D "$so" 2>/dev/null | grep -E ' (HMAC|HMAC_Init_ex|HMAC_Final|EVP_md5|EVP_sha1|EVP_sha256|CRYPTO_memcmp|memcmp)$'
   done
   ```

#### Observation

For each MAC use, a row with: location (class and method), purpose (what it protects, who verifies), algorithm and construction, key origin and storage, key reuse, tag length as stored or sent, comparison method, composition order (if encryption is involved), replay elements, and behaviour on failure.

#### Evaluation

The test **fails** for a MAC use that protects security-relevant data and has any of the following:

- a checksum, unkeyed hash, `H(key ‖ msg)` or `H(msg ‖ key)` construction in place of a MAC;
- HMAC-MD5, or raw CBC-MAC over variable-length data (HMAC-SHA1 is a Low finding with a migration note, not a failure on its own);
- a key that is hardcoded, derived from non-secret or low-entropy values, stored outside the Keystore when the attacker model includes device access, shared by all users where the server verifies, or reused for encryption or another MAC purpose;
- a tag shorter than 128 bits (or a GCM tag below 128 bits without a documented constraint), or verification that accepts partial or missing tags;
- a non-constant-time comparison where the tag comes from a source the attacker controls but the key does not;
- MAC-then-encrypt, encrypt-and-MAC, decrypt-before-verify, or a MAC that does not cover the IV and header;
- no replay protection on authenticated requests;
- a MAC used for data from the server that the app verifies (use a signature).

It **passes** when each security-relevant MAC is HMAC-SHA-256 or stronger (or an AEAD), keyed with a single-purpose key generated in the Keystore (or, for server-verified request signing, a per-user key issued after authentication), with full-length tags, constant-time verification before use, encrypt-then-MAC or AEAD composition, and replay protection where messages travel. Uses that protect nothing (cache validation, non-adversarial corruption checks) are not findings.

#### Demo

A deliberately bad request signer (ours, for illustration):

```kotlin
object RequestSigner {
    private const val SECRET = "0123456789abcdef"            // hardcoded, app-wide

    // Bad: HMAC-SHA1, truncated to 8 bytes, hex string, no timestamp or nonce
    fun sign(body: String): String {
        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(SECRET.toByteArray(), "HmacSHA1"))
        return mac.doFinal(body.toByteArray()).copyOf(8).joinToString("") { "%02x".format(it) }
    }

    // Bad: early-exit string comparison
    fun verify(body: String, sigHeader: String): Boolean = sign(body) == sigHeader
}
```

jadx renders the important lines as:

```java
Mac mac = Mac.getInstance("HmacSHA1");
byte[] bytes = SECRET.getBytes(Charsets.UTF_8);
mac.init(new SecretKeySpec(bytes, "HmacSHA1"));
...
byte[] bArrCopyOf = Arrays.copyOf(mac.doFinal(bytes2), 8);
...
return Intrinsics.areEqual(sign(body), sigHeader);
```

and the rules report:

```text
    RequestSigner.java
    ❯❱ gt-android-weak-mac-algorithm
          [MASVS-CRYPTO-1] Legacy HMAC algorithm "HmacSHA1"
           18┆ Mac mac = Mac.getInstance("HmacSHA1");
           20┆ mac.init(new SecretKeySpec(bytes, "HmacSHA1"));
    ❯❱ gt-android-mac-raw-key
          HMAC key built from raw bytes; find where bytes comes from
           20┆ mac.init(new SecretKeySpec(bytes, "HmacSHA1"));
    ❯❱ gt-android-mac-truncation
          [MASVS-CRYPTO-1] MAC output truncated
           22┆ byte[] bArrCopyOf = Arrays.copyOf(mac.doFinal(bytes2), 8);
    ❯❱ gt-android-mac-nonconstant-compare
          [MASVS-CRYPTO-1] Possible MAC or tag comparison that is not constant-time
           31┆ return Intrinsics.areEqual(sign(body), sigHeader);
```

The test **fails** on four counts. The one that decides the severity is not in the rule output at all: `SECRET` is a constant shared by every install, so anyone who decompiles the app can sign any request as anyone. Following the key (step 5) is the part of this test that you cannot automate. The comparison hit also illustrates the name-based rule: it matched only because `sign(...)` and `sigHeader` happen to contain `sig`. Had the variables been called `a` and `b` (as R8 sometimes leaves them), only steps 5–7 would have found it.

### Android: Runtime Use of MACs (Guler Tech methodology)

Type: dynamic. Platform: Android. Related OWASP technique: MASTG-TECH-0033 (method tracing) and MASTG-TECH-0043 (method hooking).

#### Overview

Static analysis misses keys assembled at runtime, MAC code in obfuscated or native layers, and the actual comparison that runs. This test hooks the JCA at runtime to record, for every MAC the app computes: the algorithm, the key class (Keystore or raw) and raw key bytes where exportable, the tag and its length, whether the same key bytes are also used for encryption, and how the tag is compared afterwards.

#### Prerequisites

- A rooted device or emulator with `frida-server` (or a repackaged APK with Frida Gadget), and Frida tools on the host.
- The app installed, and an account you can use to exercise its features.

#### Steps

1. **Save the hook script.** It tracks recent tags (as lower-case hex, upper-case hex and Base64) so that a later comparison involving one of them can be flagged:

   ```javascript
   // hook-android-mac.js
   Java.perform(function () {
     const Mac = Java.use('javax.crypto.Mac');
     const Cipher = Java.use('javax.crypto.Cipher');
     const MD = Java.use('java.security.MessageDigest');
     const Arrays = Java.use('java.util.Arrays');
     const JString = Java.use('java.lang.String');
     const KeyIface = Java.use('java.security.Key');
     const B64 = Java.use('android.util.Base64');
     const Log = Java.use('android.util.Log');
     const Exc = Java.use('java.lang.Exception');

     const tags = new Set();
     const macKeys = new Set();
     const cipherKeys = new Set();

     function hex(a) {
       return Array.from(a, function (b) { return ('0' + (b & 0xff).toString(16)).slice(-2); }).join('');
     }
     function trace() { return Log.getStackTraceString(Exc.$new()); }
     function remember(t) {
       const h = hex(t);
       tags.add(h);
       tags.add(h.toUpperCase());
       tags.add(B64.encodeToString(t, 2));            // 2 = Base64.NO_WRAP
     }

     Mac.init.overload('java.security.Key').implementation = function (k) {
       const enc = k.getEncoded();
       console.log('[Mac.init] ' + this.getAlgorithm() + ' keyClass=' + k.getClass().getName() +
         (enc ? ' raw=' + hex(enc) + ' (' + enc.length * 8 + ' bits)' : ' raw=<not exportable>'));
       if (enc) {
         macKeys.add(hex(enc));
         if (cipherKeys.has(hex(enc))) console.log('  !! these key bytes were already used with Cipher');
       }
       return this.init(k);
     };

     // doFinal(byte[]) calls doFinal() internally, so this one hook sees both forms.
     Mac.doFinal.overload().implementation = function () {
       const t = this.doFinal();
       console.log('[Mac.doFinal] ' + this.getAlgorithm() + ' tag ' + t.length * 8 + ' bits: ' + hex(t));
       remember(t);
       return t;
     };

     Cipher.init.overloads.forEach(function (ov) {
       ov.implementation = function () {
         const k = arguments[1];
         if (k !== null && KeyIface.class.isInstance(k)) {
           const enc = Java.cast(k, KeyIface).getEncoded();
           if (enc) {
             cipherKeys.add(hex(enc));
             if (macKeys.has(hex(enc))) console.log('[Cipher.init] !! key bytes also used for a MAC\n' + trace());
           }
         }
         return ov.apply(this, arguments);
       };
     });

     MD.isEqual.implementation = function (a, b) {
       console.log('[MessageDigest.isEqual] constant-time comparison, ' + (a ? a.length : 0) + ' bytes');
       return this.isEqual(a, b);
     };

     const eqBytes = Arrays.equals.overload('[B', '[B');      // equals has many 2-argument overloads
     eqBytes.implementation = function (a, b) {
       if (tags.size > 0 && a !== null && b !== null && (tags.has(hex(a)) || tags.has(hex(b)))) {
         console.log('[Arrays.equals] NON-constant-time comparison of a MAC tag\n' + trace());
       }
       return eqBytes.call(this, a, b);
     };

     // Heavy: String.equals runs constantly. Keep it enabled only while you exercise the feature.
     JString.equals.implementation = function (o) {
       if (tags.size > 0 && (tags.has(this.toString()) || (o !== null && tags.has(o.toString())))) {
         console.log('[String.equals] NON-constant-time comparison of a MAC tag string\n' + trace());
       }
       return this.equals(o);
     };
   });
   ```

2. **Run it from a cold start** so you see initialisation:

   ```bash
   frida -U -f com.example.app -l hook-android-mac.js
   ```

3. **Exercise every feature that might authenticate data**: login, any signed API call (watch the proxy for signature headers at the same time), purchase and entitlement checks, settings changes, offline data sync, and relaunches (which trigger verification of stored data).

4. **Repeat across a reinstall and on a second device** (`adb shell pm clear com.example.app` between runs). Keep the logged raw keys. A key that is identical across installs or devices is hardcoded or derived from public values.

5. **Optional order check.** If the app also encrypts the same data, add `Cipher.doFinal` logging (all overloads) and look at the order of `Mac.doFinal` and `Cipher.doFinal` on the decrypt path: verify-then-decrypt is what you want to see.

#### Observation

The log gives you, per MAC: algorithm, key class, key bytes (or `<not exportable>`), tag length, the stack trace of the comparison and which comparison was used, and any key overlap with `Cipher`. Save the raw output; redact keys to the first and last bytes in the report.

#### Evaluation

The test **fails** if any security-relevant MAC: uses `HmacMD5` (or `HmacSHA1` for new designs, as a Low finding); is keyed with a `SecretKeySpec` whose bytes are constant across installs; shares key bytes with a `Cipher`; produces or is checked against fewer than 128 bits of tag; or is compared with `Arrays.equals` or `String.equals` where the tag comes from an attacker-controlled source without the key. It **passes** when MAC keys are Keystore keys (`raw=<not exportable>`) or per-user server-issued keys, tags are full length, and comparisons go through `MessageDigest.isEqual` (or a library equivalent).

Watch for one false negative: an app that compares tags with its own loop, or with `Intrinsics.areEqual` on a type other than `String`, will not trigger the comparison hooks. Absence of a `[NON-constant-time]` line is not proof of a constant-time comparison; a `[MessageDigest.isEqual]` line next to the `doFinal` is.

#### Demo

Running the hook against the OWASP sample app built from [MASTG-DEMO-0101](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0101/MASTG-DEMO-0101/) and tapping **Start** twice gives output of this shape (key shortened here):

```text
[Mac.init] HmacSHA256 keyClass=javax.crypto.spec.SecretKeySpec raw=746869732d69732d61...2d64656d6f (304 bits)
[Mac.doFinal] HmacSHA256 tag 256 bits: <64 hex characters>
[String.equals] NON-constant-time comparison of a MAC tag string
java.lang.Exception
    at java.lang.String.equals(Native Method)
    at kotlin.jvm.internal.Intrinsics.areEqual(...)
    at org.owasp.mastestapp.MastgTest.loadProtected(...)
```

The raw key decodes to the ASCII string `this-is-a-very-secret-key-for-the-demo`, the same on every install. The HMAC algorithm and tag length are fine; the hardcoded key fails the test (and lets you forge a tag for `admin`, exactly as the demo shows), and the hex-string comparison is a Low code-quality issue here because the verifier is local.

### iOS: MAC Construction and Verification in Code (Guler Tech methodology)

Type: static (code), manual review. Platform: iOS. Related OWASP techniques: MASTG-TECH-0058 (exploring the app package), MASTG-TECH-0066 (static analysis on iOS) and MASTG-TECH-0076 (reviewing disassembled code).

#### Overview

The iOS version of the static test. MAC entry points are CryptoKit `HMAC<H>` (`authenticationCode(for:using:)`, `isValidAuthenticationCode`, the incremental `update`/`finalize`), CommonCrypto `CCHmac` and `CCHmacInit`/`Update`/`Final`, third-party code (CryptoSwift `HMAC`, `CBCMAC`, `CMAC`, `Poly1305`; OpenSSL `HMAC`), and hashes or CRCs used in their place. The comparison primitives to look for are `memcmp`, `bcmp`, `-[NSData isEqual:]`/`isEqualToData:` and Swift `==` (bad) against `timingsafe_bcmp` and `isValidAuthenticationCode` (good).

#### Prerequisites

- A decrypted IPA (check `cryptid` with `otool -l` as in [MASWE-0008](/mobile/maswe-0008-improper-hashing/#mastg-test-0211-broken-hashing-algorithms-ios)).
- radare2, and on macOS `nm`, `otool` and `xcrun swift-demangle`.

#### Steps

1. **Extract all Mach-O binaries** (main executable, frameworks, extensions):

   ```bash
   unzip -q App.ipa -d ipa/
   find ipa/Payload -type f -exec file {} + | grep 'Mach-O' | cut -d: -f1 > binaries.txt
   ```

2. **Import check** for MAC and comparison APIs:

   ```bash
   while read -r b; do
     echo "== $b"
     nm -u "$b" 2>/dev/null | grep -E '_CC(Hmac|HmacInit|HmacUpdate|HmacFinal)$|_(memcmp|bcmp|timingsafe_bcmp)$'
     nm -u "$b" 2>/dev/null | xcrun swift-demangle | grep -E 'CryptoKit\.(HMAC|HashedAuthenticationCode)' | sort -u
     nm "$b" 2>/dev/null | xcrun swift-demangle | grep -E 'CryptoSwift\.(HMAC|CBCMAC|CMAC|Poly1305)' | sort -u
   done < binaries.txt
   ```

   The CryptoKit lines name the hash type inside the generic (`HMAC<CryptoKit.Insecure.SHA1>` is the weak case). Swift's `Data ==` is normally inlined into the app and ends in a `memcmp` or `bcmp` call, so it does not appear as its own import; look for those primitives near the MAC call sites instead.

3. **Locate and read the call sites** with an r2 script (run with `r2 -q -i mac.r2 -A <binary>`):

   ```text
   ?e HMAC-related imports:
   ii~CCHmac,HMAC,AuthenticationCode
   ?e Comparison primitives:
   ii~memcmp,bcmp,timingsafe_bcmp
   ?e Callers of CCHmac:
   axt @ sym.imp.CCHmac
   ?e Objective-C equality selectors present:
   izz~isEqualToData
   ```

   For each `CCHmac` call site, print the instructions before it (`pd-- 8 @ <address>`) and read the algorithm in `w0`: `mov w0, 0` is SHA-1, `1` MD5, `2` SHA-256, `3` SHA-384, `4` SHA-512, `5` SHA-224. The key pointer and length are in `x1` and `x2`; an `adrp`/`add` pair pointing into `__TEXT,__const` or `__DATA` means a key embedded in the binary (dump it with `px <len> @ <addr>`). For CryptoKit, follow the `HMAC.authenticationCode` and `isValidAuthenticationCode` imports with `axt` on the stub addresses from the `ii` output, as in MASTG-DEMO-0150.

4. **Read the verification path.** In the function that consumes the tag, check what happens after the HMAC is computed: a `bl` to `memcmp`/`bcmp`, a `objc_msgSend` with the `isEqual:` or `isEqualToData:` selector, or a short byte loop that exits early is a non-constant-time comparison; `timingsafe_bcmp` or `isValidAuthenticationCode` is correct. Check, too, what the function does on mismatch, and whether a missing tag is treated as valid.

5. **Trace the key.** For CryptoKit, find where the `SymmetricKey` passed to HMAC is created: `SymmetricKey(size:)` followed by a Keychain write is good; `SymmetricKey(data:)` over constant bytes, a string literal, `identifierForVendor` or a value from `UserDefaults` is a finding. For `CCHmac`, follow `x1`. Note any key also passed to `AES.GCM`, `CCCrypt` or `ChaChaPoly`.

6. **Check composition and replay** as in steps 6–8 of the Android test: verify-before-decrypt, MAC over IV and header, separate keys, timestamps or nonces in signed requests. Look for strings that reveal request-signing schemes: `izz~X-Signature`, `izz~HMAC`, `izz~timestamp`.

#### Observation

The same per-use table as on Android: binary and address, purpose, algorithm, key origin, tag length, comparison primitive, composition, replay elements, and failure behaviour.

#### Evaluation

Identical criteria to the [Android static test](#android-mac-construction-and-verification-in-code-guler-tech-methodology), with the iOS equivalents: `kCCHmacAlgMD5` or `HMAC<Insecure.MD5>` fails; `kCCHmacAlgSHA1` or `HMAC<Insecure.SHA1>` is Low; keys from constants, non-secret identifiers or `UserDefaults` fail; `memcmp`, `bcmp`, `isEqual:` or `Data ==` on tags from an attacker-controlled source fail; `isValidAuthenticationCode` or `timingsafe_bcmp` passes the comparison criterion.

#### Demo

A vulnerable Objective-C verifier for a signed deep-link parameter (ours, for illustration). The tag arrives from a URL any web page can open, and the key is in the binary:

```objectivec
#import <CommonCrypto/CommonHMAC.h>

static const unsigned char kLinkKey[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

BOOL LinkIsAuthentic(NSData *payload, NSData *tag) {
    unsigned char mac[CC_SHA1_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA1, kLinkKey, sizeof(kLinkKey), payload.bytes, payload.length, mac);
    return memcmp(mac, tag.bytes, tag.length) == 0;     // compares only what the caller sent
}
```

In radare2 the call site shows the algorithm, the embedded key and the comparison directly (abridged; addresses illustrative):

```text
mov   w0, 0                         ; kCCHmacAlgSHA1
adrp  x1, 0x100008000
add   x1, x1, 0x3a0                 ; kLinkKey in __TEXT,__const
mov   w2, 0x10                      ; keyLength = 16
...
bl    sym.imp.CCHmac
...
bl    sym.imp.memcmp                ; length taken from tag.length
```

It **fails** on four counts: an embedded key, HMAC-SHA1, a non-constant-time comparison against an attacker-supplied tag (exactly the case where timing matters), and — worst — `memcmp` uses the *attacker's* length, so an empty tag passes and the check is bypassed outright. The fix is a server-side signature over the link parameters, verified with a public key, or no trust in link parameters at all.

### iOS: Runtime Use of MACs (Guler Tech methodology)

Type: dynamic. Platform: iOS. Related OWASP techniques: MASTG-TECH-0086 (method tracing) and MASTG-TECH-0095 (method hooking).

#### Overview

The iOS counterpart of the Android runtime test: hook CommonCrypto's HMAC functions to record algorithm, key and tag; trace CryptoKit's HMAC entry points; and watch the C comparison primitives for comparisons that involve a recently computed tag.

#### Prerequisites

- A jailbroken device with `frida-server`, or a re-signed build with Frida Gadget.
- Frida 17 or later on the host (the script uses the Frida 17 module API).

#### Steps

1. **Save the hook script:**

   ```javascript
   // hook-ios-mac.js (Frida 17 syntax)
   const cc = Process.getModuleByName('libcommonCrypto.dylib');
   const ALG = ['SHA1', 'MD5', 'SHA256', 'SHA384', 'SHA512', 'SHA224'];   // CCHmacAlgorithm values 0..5
   const TAGLEN = [20, 16, 32, 48, 64, 28];
   const recent = [];

   function hex(p, n) {
     try {
       return Array.from(new Uint8Array(p.readByteArray(n)), function (b) {
         return ('0' + b.toString(16)).slice(-2);
       }).join('');
     } catch (e) {
       return '';
     }
   }
   function bt(ctx) {
     return Thread.backtrace(ctx, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n');
   }
   function remember(t) {
     recent.push(t);
     if (recent.length > 32) recent.shift();
   }

   Interceptor.attach(cc.getExportByName('CCHmac'), {
     onEnter(args) {   // CCHmac(alg, key, keyLength, data, dataLength, macOut)
       this.alg = args[0].toInt32();
       const keyLen = args[2].toUInt32();
       console.log('[CCHmac] HMAC-' + (ALG[this.alg] || this.alg) + ' key ' + keyLen * 8 + ' bits: ' +
         hex(args[1], Math.min(keyLen, 64)) + ', data ' + args[4].toUInt32() + ' bytes');
       console.log(bt(this.context));
       this.out = args[5];
     },
     onLeave() {
       const t = hex(this.out, TAGLEN[this.alg] || 32);
       console.log('  tag: ' + t);
       remember(t);
     }
   });

   Interceptor.attach(cc.getExportByName('CCHmacInit'), {
     onEnter(args) {   // CCHmacInit(ctx, alg, key, keyLength)
       const alg = args[1].toInt32();
       const keyLen = args[3].toUInt32();
       console.log('[CCHmacInit] HMAC-' + (ALG[alg] || alg) + ' key ' + keyLen * 8 + ' bits: ' +
         hex(args[2], Math.min(keyLen, 64)));
     }
   });

   Interceptor.attach(cc.getExportByName('CCHmacFinal'), {
     onEnter(args) { this.out = args[1]; },
     onLeave() {
       const t = hex(this.out, 32);   // read 32 bytes; for SHA-1 only the first 20 are the tag
       console.log('[CCHmacFinal] ' + t);
       remember(t);
       remember(t.slice(0, 40));
     }
   });

   ['memcmp', 'bcmp', 'timingsafe_bcmp'].forEach(function (name) {
     const f = Module.findGlobalExportByName(name);
     if (f === null) return;
     Interceptor.attach(f, {
       onEnter(args) {
         const n = args[2].toUInt32();
         if (recent.length === 0 || n === 0 || n > 64) return;
         const a = hex(args[0], n);
         const b = hex(args[1], n);
         if (a === '' || b === '') return;
         const hit = recent.some(function (t) { return t.startsWith(a) || t.startsWith(b); });
         if (hit) {
           console.log('[' + name + '] compares ' + n + ' bytes of a MAC tag' +
             (name === 'timingsafe_bcmp' ? ' (constant-time)' : ' (NOT constant-time)'));
           console.log(bt(this.context));
         }
       }
     });
   });
   ```

2. **Run it and trace CryptoKit in parallel.** CryptoKit does not use CommonCrypto, but its HMAC functions are exported from the framework with mangled names that contain `HMAC` and `isValidAuthenticationCode` literally:

   ```bash
   frida -U -f com.example.app -l hook-ios-mac.js
   frida-trace -U -f com.example.app -i 'CryptoKit!*HMAC*' -i 'CryptoKit!*isValidAuthenticationCode*'
   ```

   frida-trace generates one handler per matched function under `__handlers__/`; edit those to print arguments if you need more than call counts and backtraces.

3. **Exercise the app** as in the Android test: login, signed requests, purchases, deep links with signed parameters, relaunch to trigger stored-data verification.

4. **Check key stability** across reinstall and a second device. For CryptoKit keys, which the hooks above do not print, find the key's origin statically or dump the Keychain on a jailbroken device (`objection -g <bundle-id> explore`, then `ios keychain dump`) and look for the 32-byte generic-password item.

#### Observation

Per MAC: algorithm, key bytes (CommonCrypto) and whether they are stable across installs, tag length, backtrace of the computation, and the comparison primitive with its backtrace — or, for CryptoKit, whether `isValidAuthenticationCode` is called on the verify path.

#### Evaluation

As for the [Android runtime test](#android-runtime-use-of-macs-guler-tech-methodology). A `memcmp` or `bcmp` hit on a tag that came from outside the app's trust boundary fails; a `timingsafe_bcmp` hit or a call to `isValidAuthenticationCode` passes. If CryptoKit's `authenticationCode` is traced but `isValidAuthenticationCode` never is, the app is comparing tags itself: go back to the disassembly of the verify path. The `memcmp` hook matches by content, so a comparison of a tag the hook never saw being computed (for example one computed by CryptoKit) will not be flagged — absence of a hit is not proof.

#### Demo

Against the Objective-C deep-link verifier from the static demo, opening `example://open?p=...&t=` (empty tag) produces:

```text
[CCHmac] HMAC-SHA1 key 128 bits: 000102030405060708090a0b0c0d0e0f, data 24 bytes
  tag: <40 hex characters>
```

and no `memcmp` line, because a zero-length comparison is skipped by the hook — and returns "equal" in the app. The link is accepted. Supplying the first byte of the real tag and timing many requests is unnecessary when an empty tag works; that is the whole finding.

### Both platforms: Tampering and Replay of MAC-Protected Data (Guler Tech methodology)

Type: dynamic (network) and filesystem. Platforms: Android and iOS.

#### Overview

The code-level tests tell you how the MAC is built. This test shows what an attacker can do with it, against the two places MAC-protected data lives: requests to the backend (verified by the server) and data stored on the device (verified by the app). It is the evidence that turns a "Low: HMAC-SHA1" into a "High: signed transfer requests can be replayed" or vice versa.

#### Prerequisites

- An intercepting proxy (Burp Suite or mitmproxy) with the app's TLS traffic visible; pinning bypass if needed (see the network notes).
- A rooted or jailbroken device for the storage half, plus whatever key you recovered in the earlier tests.
- `hash_extender` if the app uses a hash-based signature ([MASWE-0008](/mobile/maswe-0008-improper-hashing/#secret-prefix-hashes-and-length-extension)).
- Written authorisation that covers replaying state-changing requests against the test backend.

#### Steps

**Requests verified by the server.** Pick a state-changing signed request (a transfer, a purchase, a profile change) and send it to Burp Repeater. Then run this matrix, one change at a time:

| # | Change | A correct server |
|---|---|---|
| 1 | Resend unchanged immediately | Accepts once; rejects the second time if nonces are enforced |
| 2 | Resend unchanged after 10+ minutes | Rejects (timestamp window) |
| 3 | Change one parameter value, keep the tag | Rejects |
| 4 | Flip the last character of the tag | Rejects |
| 5 | Send the first half of the tag, one character, or an empty tag | Rejects |
| 6 | Remove the signature header or parameter entirely | Rejects (not "unsigned is allowed") |
| 7 | Duplicate a parameter, move it from body to query, or change its URL-encoding | Rejects, or verifies the exact bytes it acts on |
| 8 | Replay user A's signed request with user B's session | Rejects (key or signed string bound to the user) |
| 9 | If the signature is H(secret ‖ data): length-extend it | Rejects |
| 10 | Time the server on tags that share 0, 4, 8 … leading bytes with the valid one | No measurable difference (only worth trying if code review showed an early-exit comparison on the server) |

If you recovered the signing key earlier, also sign a request of your own choosing (a different amount, another account ID) and send it. That single request is usually the proof of impact.

**Data verified by the app.** On Android, with the app stopped:

```bash
PKG=com.example.app
adb shell "su -c 'cp -r /data/data/$PKG/shared_prefs /data/local/tmp/snap_prefs'"   # snapshot for rollback
adb shell "su -c 'cat /data/data/$PKG/shared_prefs/*.xml'"
```

Then, one at a time, relaunching in between and observing what the app does:

1. **Tamper with a protected value** and leave its tag. The app should detect it (OWASP's MASTG-DEMO-0101 does this with `sed` on `app_settings.xml`).
2. **Delete the tag** and leave the value. The app should treat this as tampering, not as a first run.
3. **Forge a tag** with the recovered key and write both. If the key is hardcoded, this succeeds by construction; demonstrate it once:

   ```bash
   python3 -c 'import hmac,hashlib; print(hmac.new(b"<recovered key>", b"admin", hashlib.sha256).hexdigest())'
   ```

4. **Roll back**: use the app until a protected value changes (a counter decreases, an entitlement expires), then restore the snapshot and relaunch:

   ```bash
   adb shell am force-stop $PKG
   adb shell "su -c 'cp /data/local/tmp/snap_prefs/*.xml /data/data/$PKG/shared_prefs/'"
   ```

   Fix ownership if the app refuses to read the files (`chown` to the app's UID, shown by `adb shell "su -c 'ls -ln /data/data/$PKG'"`). On iOS, do the same with the files under the app's data container (find it with `objection`'s `env` command, or under `/var/mobile/Containers/Data/Application/` on a jailbroken device) and `Library/Preferences/<bundle-id>.plist`.

#### Observation

For each matrix row and storage step: the request or file change, the response or app behaviour, and screenshots or Burp entries. For a successful forgery, keep the forged request and the server's response, or the before/after app screen.

#### Evaluation

For requests, the test **fails** if any of rows 2–9 is accepted, and fails on row 1 if the request is state-changing and can be replayed. Row 10 fails only with a reproducible timing difference. For stored data, the test **fails** if tampering (step 1), tag removal (step 2) or rollback (step 4) of a security-relevant value goes undetected, or if a forged tag (step 3) is accepted because the key is recoverable from the package or ordinary storage. A forged tag accepted on a rooted device when the key is in the Keystore is expected behaviour of any client-side check: report it as a resilience limitation, not as a MASWE-0009 failure.

#### Demo

A signed transfer request of the kind this test targets:

```text
POST /api/v1/transfers HTTP/2
Host: api.example.com
Authorization: Bearer <session token>
X-Timestamp: 1762690000
X-Nonce: 9f2c4e1a7b3d5f60
X-Signature: 5c1e…(64 hex characters)
Content-Type: application/json

{"to":"GB00TEST00000000000001","amount":"10.00"}
```

A typical failing result: rows 1 and 2 are accepted (the server checks the tag but never looks at `X-Timestamp` or `X-Nonce`), so a captured transfer can be repeated indefinitely, and row 8 is accepted because the signature key is one constant shared by all installs. Correctly built HMAC-SHA256, unexploitable algorithm, and still a High finding — which is why this test exists.

## Secure implementation

OWASP's storage-integrity best practices (MASTG-BEST-0065, MASTG-BEST-0066) cover the basic pattern; the code below adds the corrections described in the [related OWASP material](#related-owasp-material-storage-integrity-checks-mastg-know-0086-mastg-best-0065-mastg-best-0066) section and covers request signing and composition. If you are encrypting anyway, the simplest correct answer is an AEAD (AES-GCM or ChaCha20-Poly1305) — see [MASWE-0007](/mobile/maswe-0007-improper-encryption/) — and you do not need a separate MAC.

### Android: HMAC with a Keystore key

```kotlin
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey

private const val ANDROID_KEYSTORE = "AndroidKeyStore"

fun macKey(alias: String = "storage_mac_v1"): SecretKey {
    val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    (ks.getKey(alias, null) as? SecretKey)?.let { return it }
    val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, ANDROID_KEYSTORE)
    kg.init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN).build())
    return kg.generateKey()                     // never leaves the Keystore
}

fun tag(key: SecretKey, data: ByteArray): ByteArray =
    Mac.getInstance("HmacSHA256").run { init(key); doFinal(data) }

fun verify(key: SecretKey, data: ByteArray, received: ByteArray?): Boolean {
    if (received == null || received.size != 32) return false     // missing or short tag = tampering
    return MessageDigest.isEqual(tag(key, data), received)         // constant-time
}
```

Bind each stored value to its context so a valid (value, tag) pair cannot be moved to another key or record: tag `canonical("pref", name, value)` rather than `value` alone, using the helper in the request-signing section below. Store the tag as Base64 next to the value, and on failure discard the value and fall back to a server refresh rather than to a default that grants anything.

### Android: encrypt-then-MAC when you cannot use GCM

Use this only if a constraint rules out AES-GCM (an existing CBC format you must keep reading, for instance). Two separate Keystore keys, MAC over version, IV and ciphertext, verify before decrypt:

```kotlin
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec

private const val VERSION: Byte = 1

// encKey: AES key generated with BLOCK_MODE_CBC and ENCRYPTION_PADDING_PKCS7
// macKey: separate HMAC-SHA256 key from macKey("etm_mac_v1")
fun sealEtM(encKey: SecretKey, macKey: SecretKey, plaintext: ByteArray): ByteArray {
    val c = Cipher.getInstance("AES/CBC/PKCS7Padding")
    c.init(Cipher.ENCRYPT_MODE, encKey)                          // Keystore generates the IV
    val body = byteArrayOf(VERSION) + c.iv + c.doFinal(plaintext)
    return body + tag(macKey, body)                              // tag covers version || iv || ciphertext
}

fun openEtM(encKey: SecretKey, macKey: SecretKey, blob: ByteArray): ByteArray? {
    if (blob.size < 1 + 16 + 16 + 32 || blob[0] != VERSION) return null
    val body = blob.copyOfRange(0, blob.size - 32)
    val received = blob.copyOfRange(blob.size - 32, blob.size)
    if (!verify(macKey, body, received)) return null              // verify first, decrypt only if valid
    val c = Cipher.getInstance("AES/CBC/PKCS7Padding")
    c.init(Cipher.DECRYPT_MODE, encKey, IvParameterSpec(body, 1, 16))
    return try { c.doFinal(body, 17, body.size - 17) } catch (e: Exception) { null }   // one generic failure
}
```

### Both platforms: signing API requests

The client side of a request-signing scheme that survives the protocol test. The key is per user (issued by the server after login over TLS and stored in the Keystore or Keychain, or replaced by a device key pair and a signature scheme such as DPoP, RFC 9449, which avoids shared secrets altogether):

```kotlin
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.SecureRandom

fun canonical(vararg fields: ByteArray): ByteArray {
    val out = ByteArrayOutputStream()
    DataOutputStream(out).use { d ->
        for (f in fields) { d.writeInt(f.size); d.write(f) }     // length-prefixed: no ambiguity
    }
    return out.toByteArray()
}

fun signRequest(key: SecretKey, method: String, path: String, body: ByteArray): Map<String, String> {
    val ts = (System.currentTimeMillis() / 1000).toString()
    val nonce = ByteArray(16).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }
    val bodyHash = MessageDigest.getInstance("SHA-256").digest(body)
    val msg = canonical(method.toByteArray(), path.toByteArray(), bodyHash, ts.toByteArray(), nonce.toByteArray())
    val sig = android.util.Base64.encodeToString(tag(key, msg), android.util.Base64.NO_WRAP)
    return mapOf("X-Timestamp" to ts, "X-Nonce" to nonce, "X-Signature" to sig)
}
```

The server rebuilds `msg` from the parsed request, rejects timestamps more than a few minutes from its clock, keeps seen nonces for that window, looks up the key for the authenticated user, and compares in constant time. Without those server checks the client code above is decoration.

### iOS: CryptoKit HMAC with a Keychain-held key

```swift
import CryptoKit
import Foundation

// Load or create the key with the Keychain helpers from the MASWE-0003 note
// (kSecAttrAccessibleWhenUnlockedThisDeviceOnly).
func makeMACKey() -> SymmetricKey { SymmetricKey(size: .bits256) }

func tag(_ data: Data, key: SymmetricKey) -> Data {
    Data(HMAC<SHA256>.authenticationCode(for: data, using: key))
}

func verify(_ data: Data, tag received: Data?, key: SymmetricKey) -> Bool {
    guard let received, received.count == 32 else { return false }        // HMAC-SHA256 tag length
    return HMAC<SHA256>.isValidAuthenticationCode(received, authenticating: data, using: key)  // constant-time
}

// Separate keys for separate purposes, derived from one master key (iOS 14+).
func subkey(_ master: SymmetricKey, purpose: String) -> SymmetricKey {
    HKDF<SHA256>.deriveKey(inputKeyMaterial: master,
                           salt: Data("com.example.app.v1".utf8),
                           info: Data(purpose.utf8),
                           outputByteCount: 32)
}
```

Use `subkey(master, purpose: "storage-mac")` and `subkey(master, purpose: "request-mac")` rather than one key for both. If you also encrypt, `AES.GCM.seal(_:using:authenticating:)` with the context as associated data replaces the MAC entirely.

### iOS: Objective-C with CCHmac

The corrected version of the static demo's verifier, for code that cannot use CryptoKit:

```objectivec
#import <CommonCrypto/CommonHMAC.h>
#include <string.h>   // timingsafe_bcmp

BOOL TagIsValid(NSData *key, NSData *message, NSData *tag) {
    if (key.length < 32 || tag.length != CC_SHA256_DIGEST_LENGTH) {
        return NO;                                      // wrong length is a failure, never a shortcut
    }
    unsigned char expected[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, key.bytes, key.length, message.bytes, message.length, expected);
    return timingsafe_bcmp(expected, tag.bytes, sizeof(expected)) == 0;
}
```

The key comes from the Keychain, not from a constant.

### Data from the server: sign, do not MAC

For licences, remote configuration and anything else the app must trust from the server, replace the HMAC with a signature: the server signs with a private key held in a KMS or HSM, the app verifies with the embedded public key (`Signature.getInstance("SHA256withECDSA")` on Android, `P256.Signing.PublicKey.isValidSignature(_:for:)` or `Curve25519.Signing.PublicKey.isValidSignature(_:for:)` in CryptoKit), and the signed payload includes an expiry and a version. Verification details and pitfalls are in [MASWE-0011](/mobile/maswe-0011-improper-signature-verification/). Enforce anything with monetary or security value on the server as well.

## Rating findings

Rate on what the MAC protects, who can forge or replay, and whether you demonstrated it. Use these as starting points.

| Rating | Conditions |
|---|---|
| **Critical** | You forged or replayed authenticated requests the **backend** accepts with impact on other users, money or privileged functions: an app-wide MAC key extracted from the package used to sign requests as any user; length extension of an H(secret ‖ request) scheme; replay of state-changing financial requests with no nonce or timestamp checking; a verifier that accepts empty or partial tags on server-verified requests. |
| **High** | A MAC key in the package that lets anyone mint licences, entitlements, vouchers or configuration the app or server trusts; replayable signed requests whose impact is limited to the attacker's own account but bypasses a business control; MAC-then-encrypt or decrypt-before-verify with distinguishable errors (padding oracle) on data an attacker can submit; key reuse between encryption and MAC on such data; an app-side verifier for attacker-controlled input (deep link, IPC, push) that accepts partial tags or compares in non-constant time. |
| **Medium** | Security-relevant stored data protected by a checksum, unkeyed hash or hardcoded-key HMAC (forgeable with device access); rollback of MAC-protected stored state (counters, trials) that goes undetected; tags of 64 bits or fewer; HMAC-MD5 in security-relevant use; MAC keys from low-entropy or public sources. |
| **Low** | HMAC-SHA1 with a sound design (migration note); non-constant-time comparison where the verifier holds data only the device owner could tamper with; Keystore/Keychain-held MAC key but missing context binding; MAC key stored in the Keychain with a broader accessibility class than needed. |
| **Info** | CRC/hash used only to detect accidental corruption; HMAC-SHA1 in TOTP/HOTP for authenticator compatibility; correct HMAC whose only limitation is the generic bypass on a rooted or jailbroken device. |

In the report, state who holds the key and who the attacker is in one sentence; that framing is what developers most often miss. Include the location of the MAC code, the key origin (redacted), the algorithm and tag length, the comparison primitive, and the proof: a forged or replayed request with the server's response, or the before/after state of the app.

## References

- OWASP MASWE — [MASWE-0009: Improper Use of Message Authentication Code (MAC)](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0009/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-BEST-0065: Implementing Storage Integrity Checks on iOS](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0065/) and [MASTG-BEST-0066: Implementing Storage Integrity Checks on Android](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0066/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0086: Storage Integrity Checks](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0086/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0012: Key Generation](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0012/), [MASTG-KNOW-0066: CryptoKit](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0066/), [MASTG-KNOW-0067: CommonCrypto, SecKey and Wrapper libraries](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0067/), [MASTG-KNOW-0068: Cryptographic Third-Party libraries](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0068/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0338: References to Storage Integrity Check APIs (Android)](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0338/) and [MASTG-TEST-0387: References to Storage Integrity Check APIs (iOS)](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0387/), with [MASTG-DEMO-0101](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0101/MASTG-DEMO-0101/) and [MASTG-DEMO-0150](https://mas.owasp.org/MASTG/demos/ios/MASVS-RESILIENCE/MASTG-DEMO-0150/MASTG-DEMO-0150/) (CC BY-SA 4.0)
- OWASP MASTG — legacy (MASTG v1) [MASTG-TEST-0014: Testing the Configuration of Cryptographic Standard Algorithms](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0014/) and [MASTG-TEST-0015: Testing the Purposes of Keys](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0015/) (CC BY-SA 4.0)
- OWASP MASTG — [Mobile App Cryptography](https://mas.owasp.org/MASTG/0x04g-Testing-Cryptography/) (CBC-MAC key reuse, padding oracles, encrypt-then-MAC) (CC BY-SA 4.0)
- OWASP MASTG — techniques [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/), [MASTG-TECH-0033](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0033/), [MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/), [MASTG-TECH-0086](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0086/), [MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/); tools [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/), [radare2 (MASTG-TOOL-0073)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/), [Frida (MASTG-TOOL-0001)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0001/), [Frida for iOS (MASTG-TOOL-0039)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/) (CC BY-SA 4.0)
- [RFC 2104 — HMAC: Keyed-Hashing for Message Authentication](https://datatracker.ietf.org/doc/html/rfc2104) and [RFC 6151 — Updated Security Considerations for MD5 and HMAC-MD5](https://datatracker.ietf.org/doc/html/rfc6151)
- [FIPS 198-1 — The Keyed-Hash Message Authentication Code (HMAC)](https://csrc.nist.gov/pubs/fips/198-1/final) and [NIST SP 800-224 (initial public draft) — Keyed-Hash Message Authentication Code (HMAC)](https://csrc.nist.gov/pubs/sp/800/224/ipd)
- [NIST SP 800-131A Rev. 2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf), [NIST SP 800-107 Rev. 1](https://csrc.nist.gov/pubs/sp/800/107/r1/final), [NIST SP 800-38B (CMAC)](https://csrc.nist.gov/pubs/sp/800/38/b/upd1/final), [NIST SP 800-38D (GCM)](https://csrc.nist.gov/pubs/sp/800/38/d/final), [NIST SP 800-185 (KMAC)](https://csrc.nist.gov/pubs/sp/800/185/final), [NIST SP 800-57 Part 1 Rev. 5](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf)
- Bellare and Namprempre, ["Authenticated Encryption: Relations among notions and analysis of the generic composition paradigm"](https://web.archive.org/web/20210804035343/https://cseweb.ucsd.edu/~mihir/papers/oem.html); AlFardan and Paterson, "Lucky Thirteen: Breaking the TLS and DTLS Record Protocols" (2013)
- [RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
- [Android Developers — Android Keystore system](https://developer.android.com/privacy-and-security/keystore), [`KeyGenParameterSpec`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec), [`KeyProperties`](https://developer.android.com/reference/android/security/keystore/KeyProperties), [`javax.crypto.Mac`](https://developer.android.com/reference/javax/crypto/Mac), [`MessageDigest`](https://developer.android.com/reference/java/security/MessageDigest), and [Cryptography](https://developer.android.com/privacy-and-security/cryptography)
- [Apple — CryptoKit `HMAC`](https://developer.apple.com/documentation/cryptokit/hmac), [`HKDF`](https://developer.apple.com/documentation/cryptokit/hkdf), and the open-source [swift-crypto](https://github.com/apple/swift-crypto) implementation; `CommonHMAC.h` in the iOS SDK's CommonCrypto headers
- [Google Tink — MAC primitive](https://developers.google.com/tink/mac)
- [CWE-208](https://cwe.mitre.org/data/definitions/208.html), [CWE-323](https://cwe.mitre.org/data/definitions/323.html), [CWE-327](https://cwe.mitre.org/data/definitions/327.html), [CWE-354](https://cwe.mitre.org/data/definitions/354.html), [CWE-807](https://cwe.mitre.org/data/definitions/807.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
