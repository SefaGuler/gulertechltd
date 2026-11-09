---
title: "Improper Generation of Cryptographic Signatures (MASWE-0010)"
date: 2026-11-09 09:07:00 +0000
subcategory: crypto
summary: "Weak signature schemes, short keys, ECDSA nonce reuse, misplaced or multi-purpose signing keys and signing oracles: how to test Android and iOS apps."
refs: [MASWE-0010, MASVS-CRYPTO-1, MASVS-CRYPTO-2, CWE-323, CWE-326, CWE-327, CWE-330]
tags: [android, ios, masvs-crypto, digital-signatures, ecdsa, keystore]
---

This note is part of our [MASVS-CRYPTO guide](/mobile/masvs-crypto-cryptography-guide/) and covers OWASP [MASWE-0010](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0010/): an app that *produces* digital signatures in a way that lets someone else produce them too. That happens when the scheme or digest is broken (SHA1withRSA, DSA), when the key is too short, when an ECDSA nonce repeats or is predictable (which hands over the private key itself), when the signing key lives somewhere it can be copied, when one key signs and decrypts, or when a high-value key will sign whatever an attacker feeds it. The receiving end of the same problem — accepting signatures that should have been rejected — is [MASWE-0011](/mobile/maswe-0011-improper-signature-verification/). Here you will find how signing works on each platform (JCA and the Android Keystore, `SecKey`, CryptoKit and the Secure Enclave), seven tests you can run on a real build, reference implementations, and severity guidance.

> **Note:** At the time of writing, the live MASWE page for MASWE-0010 links no Knowledge, Tests or Best Practices. Everything under [Knowledge](#knowledge) and [Testing](#testing) is **Guler Tech methodology**, structured like an OWASP test. Where the MASTG repository has genuinely related material we cite it by ID: the Knowledge pages MASTG-KNOW-0012, 0044, 0066, 0067 and 0069; the beta tests MASTG-TEST-0307 and 0308 with demos MASTG-DEMO-0071 and 0072 (key purposes, which OWASP maps to [MASWE-0007](/mobile/maswe-0007-improper-encryption/)); and the legacy (MASTG v1) tests MASTG-TEST-0014, 0015 and 0061.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Generic: Signature schemes, parameters and their status (Guler Tech)](#generic-signature-schemes-parameters-and-their-status-guler-tech)
  - [Generic: RSA PKCS#1 v1.5 versus RSA-PSS (Guler Tech)](#generic-rsa-pkcs1-v15-versus-rsa-pss-guler-tech)
  - [Generic: ECDSA nonces, RFC 6979 and EdDSA (Guler Tech)](#generic-ecdsa-nonces-rfc-6979-and-eddsa-guler-tech)
  - [Android: Signature API and Keystore signing keys (MASTG-KNOW-0012)](#android-signature-api-and-keystore-signing-keys-mastg-know-0012)
  - [Android: Attestation of signing keys (MASTG-KNOW-0044)](#android-attestation-of-signing-keys-mastg-know-0044)
  - [iOS: SecKey signature algorithms (MASTG-KNOW-0067)](#ios-seckey-signature-algorithms-mastg-know-0067)
  - [iOS: CryptoKit signing and the Secure Enclave (MASTG-KNOW-0066, MASTG-KNOW-0069)](#ios-cryptokit-signing-and-the-secure-enclave-mastg-know-0066-mastg-know-0069)
  - [Generic: Key separation and signing oracles (MASTG-KNOW-0069)](#generic-key-separation-and-signing-oracles-mastg-know-0069)
- [Testing](#testing)
  - [Test 1: References to weak signature schemes and key parameters (Android)](#test-1-references-to-weak-signature-schemes-and-key-parameters-android)
  - [Test 2: Runtime signing operations and signing-key properties (Android)](#test-2-runtime-signing-operations-and-signing-key-properties-android)
  - [Test 3: References to weak signature algorithms and key parameters (iOS)](#test-3-references-to-weak-signature-algorithms-and-key-parameters-ios)
  - [Test 4: Runtime signing operations and signing-key properties (iOS)](#test-4-runtime-signing-operations-and-signing-key-properties-ios)
  - [Test 5: Signing keys used for multiple purposes (Android, iOS)](#test-5-signing-keys-used-for-multiple-purposes-android-ios)
  - [Test 6: ECDSA nonce reuse in collected signatures (Android, iOS)](#test-6-ecdsa-nonce-reuse-in-collected-signatures-android-ios)
  - [Test 7: High-value keys signing attacker-influenced data (Android, iOS)](#test-7-high-value-keys-signing-attacker-influenced-data-android-ios)
- [Secure implementation](#secure-implementation)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

A digital signature lets anyone holding the public key check that a message came from the holder of the private key and was not changed. Mobile apps generate signatures more often than people expect:

- **Device binding and request signing.** The app creates a key pair at enrolment, registers the public key with the backend, and signs a server challenge or each API request so the server knows the call came from *this* installation.
- **Transaction signing and strong customer authentication.** Banking and payment apps sign the transaction details (payee, amount) with a key that is gated by biometrics, so that a valid signature means "the user approved exactly this".
- **Wallets.** Cryptocurrency wallets sign transactions with secp256k1 or Ed25519 keys; identity wallets, including those following the EU Digital Identity Wallet (EUDIW) profile that MASWE lists for this weakness, sign credential presentations and device-authentication structures.
- **Offline artefacts.** Signed QR codes, tickets, receipts, documents and logs produced on the device for someone else to check later.

In every case the backend or a third party treats a valid signature as proof. MASWE-0010 is about the ways that proof can be produced by someone other than the legitimate signer. OWASP frames the threat as "attackers can forge signatures or recover signing keys" (MAS-THREAT-0010), reached through brute-forcing material of insufficient length (MAS-ATTACK-0018), cryptanalysis of broken algorithms or parameters (MAS-ATTACK-0021) and recovering private keys from predictable or reused nonces (MAS-ATTACK-0030). The weakness applies to the L1, L2 and EUDIW profiles and is mapped to MASVS-CRYPTO-1 and MASVS-CRYPTO-2, and to CWE-323 (Reusing a Nonce, Key Pair in Encryption), CWE-326 (Inadequate Encryption Strength), CWE-327 (Use of a Broken or Risky Cryptographic Algorithm) and CWE-330 (Use of Insufficiently Random Values).

Keep the boundaries with neighbouring weaknesses clear when you write the report:

| Problem | Where it belongs |
|---|---|
| The app signs with a weak scheme, short key, bad nonce, multi-purpose key, or acts as a signing oracle | **MASWE-0010 (this note)** |
| The app accepts signatures it should reject | [MASWE-0011](/mobile/maswe-0011-improper-signature-verification/) |
| The signing key is hardcoded or stored outside the keystore | [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/) (report the signing consequence here, the storage cause there) |
| The "signature" is really an HMAC or a keyed hash | [MASWE-0009](/mobile/maswe-0009-improper-use-of-mac/) |
| The random number generator behind the key or nonce is weak | [MASWE-0012](/mobile/maswe-0012-improper-random-number-generation/) and [MASWE-0013](/mobile/maswe-0013-improper-key-generation/) |
| The APK or IPA is code-signed with a weak scheme or key | MASVS-RESILIENCE (MASTG-TEST-0224, 0225 and 0220), not this weakness |

## Modes of Introduction

**Weak or deprecated signature schemes.** `SHA1withRSA`, `MD5withRSA`, `SHA1withECDSA` and anything with DSA. SHA-1 is disallowed for signature generation by NIST SP 800-131A Rev. 2, and chosen-prefix SHA-1 collisions have been practical since 2020, so a signature over attacker-influenced data can be transplanted onto a different message with the same hash. DSA is no longer approved for generating signatures in FIPS 186-5. These usually survive from old sample code (the classic in-app billing verifier used `SHA1withRSA`), from a backend protocol designed a decade ago, or from a third-party SDK.

**Insufficient key length.** RSA keys below 2048 bits (`setKeySize(1024)`, `initialize(1024)`, `kSecAttrKeySizeInBits: 1024`), or elliptic curves below 224 bits. A 512-bit RSA key can be factored in hours on rented compute; 768 bits has been publicly factored; 1024 bits is within reach of well-resourced attackers and is disallowed for new signatures.

**Predictable or reused signature nonces.** ECDSA and DSA need a fresh, secret, uniformly random value *k* for every signature. Reuse it once and anyone with the two signatures can compute the private key; leak a few bits of it consistently and lattice attacks recover the key from enough signatures. This only arises when the app (or a library it bundles) generates *k* itself: custom ECDSA, BouncyCastle low-level classes with a weak `SecureRandom`, wallet code, or native libraries. Platform keystores and Apple's frameworks do it correctly.

**Key reuse across purposes.** One key pair that both signs and decrypts (or does key agreement) violates key separation (NIST SP 800-57 Part 1 Rev. 5, section 5.2). With RSA it can turn a decryption feature into a signing oracle, or vice versa, because both operations apply the same private-key permutation.

**Signing keys outside the platform keystore.** A private key generated with `KeyPairGenerator.getInstance("EC")` and no keystore provider, saved as PKCS#8 in preferences; a `P256.Signing.PrivateKey` whose `rawRepresentation` sits in `UserDefaults`; or a private key in the package. The scheme can be perfect and the signature still worthless, because whoever copies the key signs as the user. The storage side is [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/); the consequence for every signature the backend trusts belongs here.

**Signing attacker-controlled data with a high-value key.** The app exposes a path — a WebView JavaScript bridge, a deep link, an exported component, a server message relayed without checks — through which someone else chooses the bytes that the device key signs. If the same key also authorises logins or payments, and the signed formats are not separated, the attacker obtains a valid signature for something the user never approved.

**Raw and unpadded primitives.** `NONEwithRSA`, `NONEwithECDSA`, keystore keys authorised for `DIGEST_NONE`, `.rsaSignatureRaw`, or "signing" by calling `Cipher` in encrypt mode with a private key. These let the caller choose the exact value that gets exponentiated, which removes the protection the hash-and-pad construction provides.

## Impact

- **Authentication or authorisation bypass.** A forged or reproduced device signature lets an attacker log in as the user, bind a new device, or call APIs that rely on the signature to identify the installation.
- **Unauthorised transactions.** A recovered or oracle-obtained transaction-signing signature is, by design, the strongest evidence of user consent the backend has. Its forgery moves money or changes account settings with no further check.
- **Persistent compromise.** A private key recovered from nonce reuse or a short modulus is valid until it is revoked. Unlike a stolen session, it works offline and for every future signature.
- **Integrity loss for downstream parties.** Tickets, receipts, credentials and documents signed by the app can be fabricated, and the app's signatures lose their value as evidence (non-repudiation).

## Mitigations

- **Use an approved scheme with an approved digest**: ECDSA over P-256 or P-384 with SHA-256 or SHA-384, Ed25519, or RSA-PSS with SHA-256 and at least 2048 bits (3072 bits for keys that must stay valid beyond 2030). These are approved in [FIPS 186-5](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf); key-length rules are in [SP 800-131A Rev. 2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf). RSA PKCS#1 v1.5 with SHA-256 remains approved and is acceptable where a protocol requires it (for example JWS `RS256`).
- **Let the platform generate the nonce**, or use a deterministic scheme: Ed25519, or ECDSA with [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979) nonces in any library that asks you for *k*.
- **Generate signing keys in the platform keystore** — the Android Keystore (StrongBox where available) or the Secure Enclave — and never export them. Bind high-value keys to user authentication and prove their origin to the server with key attestation.
- **One key, one purpose.** Signing keys are created with `PURPOSE_SIGN` only (or `kSecAttrCanSign` only), and separate keys are used for decryption, key agreement and wrapping.
- **Control what gets signed.** Sign structured, canonical data that includes a context label, a version and the fields the user saw; never sign opaque bytes supplied by a third party with a key that authorises anything else.
- **Plan for post-quantum migration.** [NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/ipd) (initial public draft) proposes deprecating 112-bit-security RSA and ECDSA after 2030 and disallowing quantum-vulnerable signatures after 2035, with ML-DSA ([FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)) and SLH-DSA ([FIPS 205](https://csrc.nist.gov/pubs/fips/205/final)) as replacements. Design signed formats with an algorithm identifier so you can switch.

## Knowledge

There is no OWASP Knowledge linked to MASWE-0010. The generic sections below are ours. The platform sections build on the MASTG Knowledge pages named in their headings, which describe key generation, attestation, `SecKey` and CryptoKit in general terms; the signing-specific detail is Guler Tech methodology drawn from the Android, Apple and NIST documentation cited in each section.

### Generic: Signature schemes, parameters and their status (Guler Tech)

What you see in code, and how to read it against current guidance (FIPS 186-5, SP 800-131A Rev. 2, SP 800-57 Part 1 Rev. 5 and the NIST IR 8547 draft):

| Scheme as it appears in code | Status for generating new signatures | Notes |
|---|---|---|
| `MD5withRSA`, `MD2withRSA` | Disallowed | Collisions are trivial. Always a finding. |
| `SHA1withRSA`, `SHA1withECDSA`, `.rsaSignatureMessagePKCS1v15SHA1`, `.ecdsaSignatureMessageX962SHA1`, JWS with SHA-1 | Disallowed (SP 800-131A Rev. 2) | Verifying old SHA-1 signatures is "legacy use"; generating new ones is not allowed. |
| `SHA256withDSA` and any DSA | Not approved for generation (FIPS 186-5) | Same nonce fragility as ECDSA, with larger keys. |
| RSA with a modulus below 2048 bits | Disallowed | 1024-bit keys are a finding regardless of digest. |
| `SHA256withRSA` (PKCS#1 v1.5), JWS `RS256` | Approved | Acceptable, especially for interoperability. Prefer PSS for new designs. |
| `SHA256withRSA/PSS`, `.rsaSignatureMessagePSSSHA256`, JWS `PS256` | Approved | 2048 bits gives 112-bit security, acceptable until 2030; use 3072 bits for longer-lived keys. |
| `SHA256withECDSA` on P-256, `SHA384withECDSA` on P-384, JWS `ES256`/`ES384` | Approved | P-256 is the only curve StrongBox and the Secure Enclave support. |
| Ed25519 (`Curve25519.Signing`, Tink `ED25519`, BouncyCastle `Ed25519Signer`) | Approved (FIPS 186-5) | Deterministic by design, so no nonce to get wrong. |
| ECDSA on secp256k1 | Outside the NIST curves recommended for general use | Fine where a blockchain protocol mandates it. Neither the Android Keystore nor the Secure Enclave supports it, so the key is always software-held, and the nonce is the library's responsibility. |
| `NONEwithRSA`, `NONEwithECDSA`, `DIGEST_NONE`, `.rsaSignatureRaw`, `.rsaSignatureDigestPKCS1v15Raw` | Primitive, not a scheme | Acceptable only when the code hashes and encodes the input itself, correctly, from data it controls. Treat as a finding until shown otherwise. |
| ML-DSA (FIPS 204), SLH-DSA (FIPS 205) | Approved (post-quantum) | Arriving in platform APIs (Apple added ML-DSA to CryptoKit in iOS 26). Not yet a baseline expectation for mobile apps. |

Two practical points matter more than the table. First, the digest and the key size are separate parameters and both must be right: `SHA256withRSA` with a 1024-bit key fails, and so does `SHA1withECDSA` on P-256. Second, look at the scheme the *backend* expects. The app may sign correctly while the server also accepts a weaker variant, and that belongs in your report as well (see [MASWE-0011](/mobile/maswe-0011-improper-signature-verification/)).

### Generic: RSA PKCS#1 v1.5 versus RSA-PSS (Guler Tech)

Both are defined in [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017) and both are approved in FIPS 186-5. They differ in how the hash is encoded before the RSA private-key operation:

- **PKCS#1 v1.5 (RSASSA-PKCS1-v1_5)** builds `00 01 FF…FF 00 || DigestInfo(hash)`. It is deterministic: the same message and key always give the same signature. It has no security proof, and its history is a history of *verifier* bugs — Bleichenbacher's 2006 forgery against lax parsers with public exponent 3, and BERserk (2014) — where the verifier accepted malformed padding. Generating v1.5 signatures is not itself broken.
- **PSS (RSASSA-PSS)** mixes a random salt into the encoding through MGF1. It has a tight security proof, and two signatures over the same message differ. The parameters (hash, MGF1 hash, salt length) must match between signer and verifier, and mismatches are a common source of "verification randomly fails" bugs that developers then fix by switching verification off.

How to rate it: PKCS#1 v1.5 with SHA-256 and a 2048-bit or larger key is not a finding in its own right; mention it as Info with a recommendation to prefer PSS or ECDSA for new formats. It becomes relevant when combined with something else, such as a raw `NONEwithRSA` path or a key that also decrypts.

### Generic: ECDSA nonces, RFC 6979 and EdDSA (Guler Tech)

An ECDSA signature over message hash *z* with private key *d* is the pair (*r*, *s*), where *k* is the per-signature nonce, *r* is the x-coordinate of *k*·G modulo the group order *n*, and *s* = *k*⁻¹(*z* + *r*·*d*) mod *n*. Everything except *k* and *d* is public. That has two consequences you can test for:

1. **Reuse.** Two signatures with the same *k* have the same *r*. From (*r*, *s₁*, *z₁*) and (*r*, *s₂*, *z₂*), *k* = (*z₁* − *z₂*)/(*s₁* − *s₂*) and *d* = (*s₁*·*k* − *z₁*)/*r*, all mod *n*. Two signatures are enough; no cryptanalysis is involved. This is how the PlayStation 3 firmware signing key was recovered in 2010 (a constant *k*), and how funds were stolen from Android Bitcoin wallets in 2013, when a seeding flaw in Android's `SecureRandom` produced repeated nonces.
2. **Bias.** If *k* is not uniform — a few leading bits are always zero, or *k* comes from a weak PRNG — lattice techniques (the "hidden number problem") recover *d* from a few hundred to a few thousand signatures. Timing leaks during signing have the same effect (Minerva and TPM-Fail, both 2019).

There are two robust ways to remove the problem:

- **Deterministic nonces ([RFC 6979](https://www.rfc-editor.org/rfc/rfc6979)).** *k* is derived with HMAC-DRBG from *d* and *z*, so it is unique per message and needs no RNG at signing time. The same message gives the same signature, which is expected behaviour, not a finding. BouncyCastle exposes this as `ECDSASigner(HMacDSAKCalculator(SHA256Digest()))`; libsecp256k1 uses it by default when `secp256k1_ecdsa_sign` is called with a `NULL` nonce function. Implementations that also mix in fresh randomness ("hedged" signatures) keep the benefit and resist fault attacks.
- **EdDSA (Ed25519, [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)).** The nonce is a hash of a secret prefix and the message. There is no *k* for application code to supply.

Where you actually find nonce bugs on mobile: hand-written ECDSA in Kotlin, Swift, JavaScript (React Native) or Dart (Flutter); BouncyCastle `ECDSASigner()` constructed without a `DSAKCalculator`, so it draws *k* from whatever `SecureRandom` the code passes in `ParametersWithRandom` — sometimes `java.util.Random`, sometimes a `SHA1PRNG` seeded with a constant; native code calling OpenSSL's low-level `ECDSA_do_sign_ex` with a caller-supplied *k*; and wallet libraries with their own curve arithmetic. Signatures from the Android Keystore, Conscrypt (BoringSSL), the Security framework and CryptoKit use nonces generated inside the platform; their signatures differ between calls, which is also expected.

### Android: Signature API and Keystore signing keys (MASTG-KNOW-0012)

Related source: [MASTG-KNOW-0012 Key Generation](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0012/), which explains `KeyGenParameterSpec` and notes that EC keys in the Android Keystore can only sign. The signing detail below is ours, from the Android developer documentation.

**The JCA `Signature` class.** Every Java or Kotlin signing operation goes through `java.security.Signature`:

```kotlin
val s = Signature.getInstance("SHA256withECDSA")  // algorithm string = digest + scheme
s.initSign(privateKey)                            // provider chosen here for keystore keys
s.update(message)
val der = s.sign()                                // ECDSA output is DER-encoded (r, s)
```

The algorithm strings you will meet are `SHA256withECDSA`, `SHA384withECDSA`, `SHA512withECDSA`, `SHA256withRSA` (PKCS#1 v1.5), `SHA256withRSA/PSS` (the Android Keystore's name for PSS), the weak `SHA1with…`/`MD5withRSA`, and the raw `NONEwithRSA`/`NONEwithECDSA`. Without an explicit provider, `Signature` uses delayed provider selection: for a keystore key the operation is routed to the Android Keystore provider at `initSign`; for a software key it goes to Conscrypt (`AndroidOpenSSL`). If an app names `"BC"` explicitly, note that for apps targeting Android 9 (API 28) or later most algorithms requested from the platform's bundled `BC` provider throw `NoSuchAlgorithmException`, which is often why apps ship their own BouncyCastle or Spongy Castle copy — and why you should check that library's version.

**Keystore signing keys.** The `KeyGenParameterSpec` becomes the key's authorisation list, enforced inside the keystore (and inside the TEE or StrongBox when the key is hardware-backed). For a signing key, the setters that matter are:

| Setter | What it controls | What to look for |
|---|---|---|
| `Builder(alias, purposes)` | Allowed operations, as a bitmask | `PURPOSE_SIGN` (4), optionally `PURPOSE_VERIFY` (8). Anything combined with `PURPOSE_ENCRYPT` (1), `PURPOSE_DECRYPT` (2), `PURPOSE_WRAP_KEY` (32) or `PURPOSE_AGREE_KEY` (64) is multi-purpose. |
| `setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))` | EC curve | P-256 (default), P-384 or P-521. StrongBox supports only P-256. |
| `setKeySize(n)` | RSA modulus size (or EC field size) | RSA below 2048 is a finding. The default RSA size is 2048. |
| `setDigests(...)` | Digests the key may be used with | `DIGEST_SHA256` or stronger. `DIGEST_SHA1` and `DIGEST_MD5` are weak; `DIGEST_NONE` permits raw input. |
| `setSignaturePaddings(...)` | RSA signature padding | `SIGNATURE_PADDING_RSA_PSS` preferred; `SIGNATURE_PADDING_RSA_PKCS1` acceptable. Must be set for RSA signing keys. |
| `setUserAuthenticationRequired(true)` and `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)` (API 30+) | User presence per signature | Expected for transaction-signing keys; use with `BiometricPrompt.CryptoObject(signature)`. |
| `setIsStrongBoxBacked(true)` (API 28+) | Secure element instead of TEE | Expected where the app claims hardware-grade protection and the device has StrongBox. |
| `setAttestationChallenge(challenge)` (API 24+) | Produces an attestation chain | See the next section. |

In decompiled code these constants are inlined, because they are compile-time `String` and `int` constants: `KeyProperties.DIGEST_SHA1` appears as `"SHA-1"`, `DIGEST_NONE` as `"NONE"`, `SIGNATURE_PADDING_RSA_PKCS1` as `"PKCS1"`, `SIGNATURE_PADDING_RSA_PSS` as `"PSS"`, `KEY_ALGORITHM_EC` as `"EC"`, and the purposes as an integer such as `4` or `12`. Grep for the literal values, not the constant names.

Two Keystore details that trip testers up. Public-key operations (verification) on keystore keys run in software, so `PURPOSE_VERIFY` on its own is meaningless for security; what matters is the private key's purposes. And the keystore rejects an `initSign` whose algorithm string does not match the authorised digest and padding (an `InvalidKeyException`), so a key restricted to `DIGEST_SHA256` cannot be coaxed into signing with SHA-1 even by a hooked app. That is why reading the spec, or querying `KeyInfo` at runtime, tells you the worst the key can do.

**Older and software paths.** `KeyPairGeneratorSpec` (pre-API 23) is deprecated and cannot express digests or paddings; any app with `minSdkVersion` 23 or above should use `KeyGenParameterSpec`. `KeyPairGenerator.getInstance("EC")` with no `"AndroidKeyStore"` provider produces a software key on the Java heap, which the app must then store somewhere (see [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/)). Ed25519 in apps is usually provided by Tink (`PublicKeySign` with the `ED25519` template) or BouncyCastle (`Ed25519Signer`) in software; platform and Keystore support for Curve25519 is newer and device-dependent, so check `Signature.getInstance("Ed25519")` availability at your `minSdkVersion` before relying on it.

The legacy (MASTG v1) tests [MASTG-TEST-0014](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0014/) and [MASTG-TEST-0015](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0015/) list `Signature` among the classes to inventory and ask whether "the private key [is] being exclusively used for signing"; TEST-0015 is deprecated and covered by MASTG-TEST-0307 and 0308.

### Android: Attestation of signing keys (MASTG-KNOW-0044)

Related source: [MASTG-KNOW-0044 Key Attestation](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0044/). The general mechanism, the certificate chain and the server-side checks are covered in our [MASWE-0003 note](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/#android-key-attestation-mastg-know-0044); this section only adds what matters for signing keys.

A device signature is evidence only if the server knows the key could not have been copied. Attestation gives it that knowledge: the app generates the signing key with `setAttestationChallenge(serverChallenge)` and sends `KeyStore.getCertificateChain(alias)` with the public key at registration. For a signing key, the server should check in the attestation extension that:

- `purpose` contains `SIGN` and nothing in the encryption, decryption, wrapping or agreement groups;
- `digest` lists only SHA-256 or stronger, and `padding` (RSA) lists only PSS or PKCS#1 v1.5;
- `origin` is `GENERATED` (not imported);
- the attestation and KeyMint security levels are `TrustedEnvironment` or `StrongBox`;
- user authentication is required where the design relies on it (`userAuthType`, `noAuthRequired` absent); and
- the challenge matches and the root-of-trust fields show a locked bootloader and verified boot.

Since Android 12 (API 31) a key generated with `PURPOSE_ATTEST_KEY` (128) can sign other keys' attestation certificates (`setAttestKeyAlias`), which is useful on devices whose factory attestation keys are rate-limited. For testers, the point is simple: a backend that registers a device public key without verifying attestation cannot distinguish a keystore key from one generated in an emulator or extracted from a script, and every finding about client-side key protection is then weaker than it looks.

### iOS: SecKey signature algorithms (MASTG-KNOW-0067)

Related source: [MASTG-KNOW-0067 CommonCrypto, SecKey and Wrapper libraries](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0067/), which introduces `SecKey` as Apple's asymmetric API and lists wrapper libraries such as SwiftyRSA and Heimdall. The detail below is ours, from Apple's Security framework documentation.

Signing with the Security framework is one call:

```swift
var error: Unmanaged<CFError>?
let alg: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256
guard SecKeyIsAlgorithmSupported(privateKey, .sign, alg),
      let sig = SecKeyCreateSignature(privateKey, alg, message as CFData, &error) as Data? else {
    throw error!.takeRetainedValue() as Error
}
```

The algorithm constant carries the whole scheme. The naming is systematic: `Message` variants hash the input for you, `Digest` variants expect the caller to pass a digest, and the rest names padding and hash.

| `SecKeyAlgorithm` | Scheme | Verdict |
|---|---|---|
| `.ecdsaSignatureMessageX962SHA256` / `SHA384` / `SHA512` | ECDSA, DER output | Good |
| `.ecdsaSignatureDigestX962SHA256` | ECDSA over a caller-supplied SHA-256 digest | Good if the caller really hashes with SHA-256 |
| `.ecdsaSignatureRFC4754` | ECDSA over a digest, raw *r*‖*s* output | Fine; check where the digest comes from |
| `.ecdsaSignatureMessageX962SHA1`, `.ecdsaSignatureDigestX962SHA1` | ECDSA with SHA-1 | Weak |
| `.rsaSignatureMessagePSSSHA256` / `SHA384` / `SHA512` | RSA-PSS | Good (iOS 11+) |
| `.rsaSignatureMessagePKCS1v15SHA256` / `SHA384` / `SHA512` | RSA PKCS#1 v1.5 | Acceptable |
| `.rsaSignatureMessagePKCS1v15SHA1`, `.rsaSignatureDigestPKCS1v15SHA1` | RSA PKCS#1 v1.5 with SHA-1 | Weak |
| `.rsaSignatureDigestPKCS1v15Raw` | PKCS#1 v1.5 padding without `DigestInfo` | Raw; finding unless justified |
| `.rsaSignatureRaw` | Textbook RSA, no padding | Raw; finding |

Key size and type are set at generation in the attributes passed to `SecKeyCreateRandomKey`: `kSecAttrKeyType` (`kSecAttrKeyTypeRSA` or `kSecAttrKeyTypeECSECPrimeRandom`) and `kSecAttrKeySizeInBits` (RSA modulus, or 256/384/521 for EC). Usage flags — `kSecAttrCanSign`, `kSecAttrCanVerify`, `kSecAttrCanDecrypt`, `kSecAttrCanEncrypt`, `kSecAttrCanDerive` — restrict what a stored key may be used for and are your iOS equivalent of Android's purposes. When you dump attributes at runtime (`SecKeyCopyAttributes`) they appear under their short names: `type` (`42` for RSA, `73` for EC), `bsiz` (key size), `tkid` (`com.apple.setoken` for Secure Enclave keys) and `kcls` (`1` for a private key).

### iOS: CryptoKit signing and the Secure Enclave (MASTG-KNOW-0066, MASTG-KNOW-0069)

Related sources: [MASTG-KNOW-0066 CryptoKit](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0066/) and [MASTG-KNOW-0069 Key Management](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0069/). KNOW-0066 lists CryptoKit's public-key algorithms under "Key Agreement" only; CryptoKit also provides signing for the same curves, which is what this section covers. The Secure Enclave storage model is described in our [MASWE-0003 note](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/#ios-secure-enclave-keys-and-cryptokit-mastg-know-0066); here we focus on signing.

CryptoKit separates signing keys from key-agreement keys at the type level, so a misuse has to be explicit:

| Type | Scheme | Key held |
|---|---|---|
| `P256.Signing.PrivateKey`, `P384.Signing.PrivateKey`, `P521.Signing.PrivateKey` | ECDSA with SHA-256/384/512 | In the app process (software) |
| `Curve25519.Signing.PrivateKey` | Ed25519 | In the app process (software) |
| `SecureEnclave.P256.Signing.PrivateKey` | ECDSA P-256 with SHA-256 | Inside the Secure Enclave; the app holds an encrypted, device-bound blob |

`signature(for: data)` hashes the input with the curve's matching SHA-2 function; an overload takes a `Digest` you computed yourself. Because any `Digest` conforms, `signature(for: Insecure.SHA1.hash(data: m))` compiles and produces an ECDSA-with-SHA-1 signature — so `Insecure.SHA1` or `Insecure.MD5` near a signing call is worth a look. ECDSA signatures expose `derRepresentation` (X9.62, what Java and most servers expect) and `rawRepresentation` (64 bytes *r*‖*s* for P-256, what JWS `ES256` expects); mixing them up causes verification failures rather than weaknesses. Ed25519 signatures are 64 bytes. You will see different signature values for the same input from CryptoKit; that is expected.

The Secure Enclave signs only with P-256. `SecureEnclave.P256.Signing.PrivateKey(accessControl:)` with `.privateKeyUsage` (plus `.biometryCurrentSet` or `.userPresence` for user-gated keys) creates a key that never leaves the Enclave; its `dataRepresentation` is useless on any other device. The Security-framework equivalent is `SecKeyCreateRandomKey` with `kSecAttrTokenID = kSecAttrTokenIDSecureEnclave`. Check `SecureEnclave.isAvailable`; the Simulator has none.

Apple has no general-purpose attestation for arbitrary Secure Enclave keys. The supported route is App Attest (`DCAppAttestService` in the DeviceCheck framework): it creates its own Enclave key, has Apple attest it, and lets the app generate assertions. To vouch for your *own* signing key, include its public key in the `clientDataHash` you pass to `attestKey(_:clientDataHash:)` at registration, so the attestation binds the two.

KNOW-0069 states the two rules that this weakness is built on: "always encrypt/verify with the public key and always decrypt/sign with the private key", and "never reuse the key(pair) for another purpose", keeping a separate pair for signing and for encryption. The legacy (MASTG v1) test [MASTG-TEST-0061](https://mas.owasp.org/MASTG/tests/ios/MASVS-CRYPTO/MASTG-TEST-0061/) asks you to verify the algorithms and configurations of every cryptographic library the app uses, which for signing means the table in the previous section.

### Generic: Key separation and signing oracles (MASTG-KNOW-0069)

Related sources: MASTG-KNOW-0069 (above) and the key-purpose tests [MASTG-TEST-0307](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0307/) and [MASTG-TEST-0308](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0308/), which OWASP maps to MASWE-0007 and which we cover in full in the [MASWE-0007 note](/mobile/maswe-0007-improper-encryption/). The signing-oracle material is ours.

NIST SP 800-57 Part 1 Rev. 5, section 5.2, assigns each key one use. For signing keys the reasons are concrete:

- **RSA sign/decrypt duality.** Raw RSA decryption and raw RSA signing are the same operation, *m^d mod N*. If one RSA key both decrypts (especially with PKCS#1 v1.5 encryption, which has a padding oracle history) and signs, a weakness in one path becomes a forgery or decryption capability in the other. The Android Keystore can prevent this through purposes; it does not if the app asked for `PURPOSE_SIGN or PURPOSE_DECRYPT` (MASTG-DEMO-0071's purpose value `15` combines sign, verify, encrypt and decrypt).
- **Cross-protocol signatures.** If one key signs both "login challenge" and "transaction" messages, a signature collected in one context may be valid in the other unless the formats cannot collide. A server challenge that is 32 random bytes and a transaction that happens to serialise to 32 bytes is enough.
- **Signing oracles.** A key that signs whatever bytes reach a particular entry point is a service for whoever can reach that entry point. On mobile, the entry points that let a third party choose the bytes are WebView JavaScript bridges (`@JavascriptInterface`, `WKScriptMessageHandler`), deep links and app links, exported activities, services, broadcast receivers and content providers, push payloads, and server messages relayed by a compromised or spoofed backend. The defence is not to "validate the input" in general but to fix the signed format: a constant context label and version, structured fields that the app itself fills in, and (for consent) the exact values shown to the user.

## Testing

OWASP has no tests for MASWE-0010. The seven tests below are **Guler Tech methodology**. The closest OWASP tests are [MASTG-TEST-0307](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0307/) (static: asymmetric key pairs created for multiple purposes) and [MASTG-TEST-0308](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0308/) (dynamic: the same key used in `Cipher` and `Signature` operations), with [MASTG-DEMO-0071](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0071/MASTG-DEMO-0071/) and [MASTG-DEMO-0072](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0072/MASTG-DEMO-0072/). They belong to MASWE-0007 and are written up in full in our [MASWE-0007 note](/mobile/maswe-0007-improper-encryption/); Test 5 below summarises them and adds the iOS side.

Common prerequisites for all tests: the APK (`adb shell pm path <package>`, then `adb pull` each split) or a decrypted IPA; `jadx` and `apktool` for Android (MASTG-TECH-0013 "Reverse Engineering Android Apps" and MASTG-TECH-0014 "Static Analysis on Android"); `semgrep`; on iOS, the main binary from `Payload/<App>.app/` (MASTG-TECH-0058 "Exploring the App Package") and radare2 or `nm`/`otool` (MASTG-TECH-0066 "Static Analysis on iOS", MASTG-TECH-0076 "Reviewing Disassembled Objective-C and Swift Code"); and for dynamic tests a rooted Android device or jailbroken iOS device with `frida-server` matching your `frida` client (MASTG-TECH-0043 and MASTG-TECH-0095, "Method Hooking").

### Test 1: References to weak signature schemes and key parameters (Android)

Guler Tech methodology. Platform: Android. Type: static (code).

#### Overview

Inventory every place the app creates a signing key or a `Signature` object, and check the scheme, digest, padding and key size against the [status table](#generic-signature-schemes-parameters-and-their-status-guler-tech). This catches SHA-1 and MD5 signatures, DSA, short RSA keys, raw `NONEwith…` signing, Keystore keys authorised for weak digests or `DIGEST_NONE`, software signing keys, and BouncyCastle ECDSA set up with a caller-supplied random source.

#### Prerequisites

- Decompiled sources: `jadx -d out/ app.apk`.
- `semgrep` and the rules below.
- If the app bundles native code, `unzip` and `strings` (or radare2) for `lib/*/*.so`.

#### Steps

1. **Inventory signature algorithms and key generators.**

   ```bash
   grep -rhoE 'Signature\.getInstance\("[^"]+"' out/sources | sort | uniq -c | sort -rn
   grep -rnE 'KeyPairGenerator\.getInstance\("(RSA|EC|DSA|Ed25519)"' out/sources \
     | grep -vE '^out/sources/(androidx|kotlin|kotlinx)/'
   grep -rnE '"(MD5|MD2|SHA1|SHA-1|NONE)with(RSA|ECDSA|DSA)|withDSA"' out/sources
   ```

   A `KeyPairGenerator.getInstance("EC")` without `"AndroidKeyStore"` as the second argument is a software key; follow it to see where the private key ends up (MASWE-0003).

2. **Read the Keystore specs of signing keys.** Remember the constants are inlined:

   ```bash
   grep -rnE 'KeyGenParameterSpec\.Builder\(' out/sources
   grep -rnE 'setDigests\(|setSignaturePaddings\(|setKeySize\(|setAlgorithmParameterSpec\(|setIsStrongBoxBacked|setUserAuthentication|setAttestationChallenge' out/sources
   grep -rnE '"(SHA-1|MD5|NONE)"' out/sources | grep -E 'setDigests'
   ```

   For each `Builder(alias, N)`, decode `N` (4 = sign, 8 = verify, 12 = both; anything with 1, 2, 32 or 64 set is multi-purpose and goes to Test 5).

3. **Run the semgrep rules** against the decompiled Java:

   ```yaml
   rules:
     - id: gt-android-weak-signature-algorithm
       languages: [java]
       severity: WARNING
       message: "Weak, raw or deprecated signature algorithm: $ALG"
       patterns:
         - pattern: Signature.getInstance($ALG, ...)
         - metavariable-regex:
             metavariable: $ALG
             regex: '(?i)"(md5|md2|sha1|sha-1|none)with.*"|".*withdsa"'
     - id: gt-android-weak-keystore-signing-params
       languages: [java]
       severity: WARNING
       message: Keystore key authorised for a weak digest, raw input or PKCS#1 v1.5 padding
       pattern-either:
         - pattern: $B.setDigests(..., "SHA-1", ...)
         - pattern: $B.setDigests(..., "MD5", ...)
         - pattern: $B.setDigests(..., "NONE", ...)
         - pattern: $B.setSignaturePaddings(..., "PKCS1", ...)
     - id: gt-android-short-asymmetric-key
       languages: [java]
       severity: WARNING
       message: Asymmetric key size $N is below 2048 bits
       patterns:
         - pattern-either:
             - pattern: $X.setKeySize($N)
             - pattern: $X.initialize($N)
             - pattern: $X.initialize($N, $R)
         - metavariable-comparison:
             metavariable: $N
             comparison: ($N > 521 and $N < 2048) or $N == 512
     - id: gt-android-bc-ecdsa-random-k
       languages: [java]
       severity: INFO
       message: BouncyCastle ECDSA/DSA signer without a deterministic k calculator; check the SecureRandom passed to init()
       pattern-either:
         - pattern: new ECDSASigner()
         - pattern: new DSASigner()
         - pattern: new ECDSASigner(new RandomDSAKCalculator())
   ```

   ```bash
   semgrep -c gt-android-signing.yml out/sources/
   ```

   The key-size comparison skips 224–521 so that EC sizes and AES sizes do not flood the output. The PKCS#1 rule is informational: v1.5 padding is acceptable, but you want to know where it is used.

4. **Check bundled crypto libraries and native code.** Note the BouncyCastle, Tink, web3j, Trust Wallet Core or libsodium versions present (`ls out/sources/org/bouncycastle` and the `META-INF/*.version` files in the APK), then look for signing primitives in native libraries:

   ```bash
   unzip -o app.apk 'lib/*' -d native/ >/dev/null
   for so in native/lib/arm64-v8a/*.so; do
     echo "== $so"
     strings -a "$so" | grep -E '^(ECDSA_do_sign|ECDSA_do_sign_ex|ECDSA_sign|RSA_sign|DSA_do_sign|EVP_DigestSign|secp256k1_ecdsa_sign|crypto_sign_detached)$'
   done
   ```

   `ECDSA_do_sign_ex` takes caller-supplied nonce material (OpenSSL; deprecated since 3.0); `secp256k1_ecdsa_sign` is safe with a `NULL` nonce function and worth reading if it is passed anything else.

#### Observation

A list of signing sites with: class and method, algorithm string, provider (explicit or implied), key origin (Keystore alias, software generator, imported bytes), Keystore authorisations (purposes, digests, paddings, size, StrongBox, user authentication, attestation), and for each, the business function (device binding, transaction signing, ticket, log). Native and third-party signing functions with library versions.

#### Evaluation

The test **fails** if any signature used for a security decision is generated with:

- an MD5 or SHA-1 digest, DSA, or a raw `NONEwith…` algorithm on data the app does not fully construct itself;
- an RSA key below 2048 bits or an EC key below 224 bits;
- a Keystore key authorised for `DIGEST_SHA1`, `DIGEST_MD5` or `DIGEST_NONE` that signs anything a third party can influence; or
- ECDSA or DSA with a caller-controlled nonce source (BouncyCastle signer with an explicit `SecureRandom` you cannot show is the platform CSPRNG, `ECDSA_do_sign_ex`, custom curve code).

Software signing keys are a finding for MASWE-0003 and a rating factor here. RSA PKCS#1 v1.5 with SHA-256 and at least 2048 bits passes, with an Info note. Common false positives: weak algorithms used only to *verify* legacy data (MASWE-0011's territory); code in unreachable SDK classes; `KeyPairGenerator.initialize(1024)` for DH or for test fixtures; and `NONEwithECDSA` where the code demonstrably hashes with SHA-256 first.

#### Demo

Vulnerable Kotlin (Guler Tech sample, modelled on the structure of MASTG-DEMO-0071):

```kotlin
val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
kpg.initialize(
    KeyGenParameterSpec.Builder("txn_signing", KeyProperties.PURPOSE_SIGN)
        .setKeySize(1024)
        .setDigests(KeyProperties.DIGEST_SHA1, KeyProperties.DIGEST_NONE)
        .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
        .build()
)
kpg.generateKeyPair()

val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
val signer = Signature.getInstance("SHA1withRSA")
signer.initSign(ks.getKey("txn_signing", null) as PrivateKey)
signer.update(transactionJson.toByteArray())
val signature = signer.sign()
```

What jadx shows (constants inlined):

```java
KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
kpg.initialize(new KeyGenParameterSpec.Builder("txn_signing", 4).setKeySize(1024)
        .setDigests("SHA-1", "NONE").setSignaturePaddings("PKCS1").build());
kpg.generateKeyPair();
...
Signature signer = Signature.getInstance("SHA1withRSA");
```

Expected semgrep result (abridged):

```text
    MastgTest_reversed.java
    ❯❱ gt-android-short-asymmetric-key
          Asymmetric key size 1024 is below 2048 bits
           31┆ kpg.initialize(new KeyGenParameterSpec.Builder("txn_signing", 4).setKeySize(1024)
    ❯❱ gt-android-weak-keystore-signing-params
          Keystore key authorised for a weak digest, raw input or PKCS#1 v1.5 padding
           32┆ .setDigests("SHA-1", "NONE").setSignaturePaddings("PKCS1").build());
    ❯❱ gt-android-weak-signature-algorithm
          Weak, raw or deprecated signature algorithm: "SHA1withRSA"
           36┆ Signature signer = Signature.getInstance("SHA1withRSA");
```

The test fails three times over: a 1024-bit modulus, SHA-1 as the signing digest, and `DIGEST_NONE` authorised on a transaction key. The purpose value `4` is correct, which shows why a key-purpose check alone (Test 5) is not enough.

### Test 2: Runtime signing operations and signing-key properties (Android)

Guler Tech methodology. Platform: Android. Type: dynamic (hooks).

#### Overview

Static analysis misses algorithms assembled at runtime, keys created by SDKs, and the real Keystore authorisations on the device. Hooking `java.security.Signature` shows every signing operation the app performs, which key it uses, where that key lives, and what bytes it signs. The output also feeds Test 6 (nonce reuse) and Test 7 (signing oracles).

#### Prerequisites

- Rooted device or emulator with `frida-server`; the app installed (MASTG-TECH-0005 "Installing Apps").
- A test account that can reach the signing flows (enrolment, login, transaction approval).

#### Steps

1. Save the script:

   ```javascript
   // gt-android-sign.js
   Java.perform(function () {
     const Sig = Java.use('java.security.Signature');
     const KeyFactory = Java.use('java.security.KeyFactory');
     const KeyInfo = Java.use('android.security.keystore.KeyInfo');
     const RSAKey = Java.use('java.security.interfaces.RSAKey');
     const ECKey = Java.use('java.security.interfaces.ECKey');
     const Log = Java.use('android.util.Log');
     const Exc = Java.use('java.lang.Exception');
     const pending = {};

     function hex(a, off, len) {
       let s = '';
       for (let i = off; i < off + len; i++) s += ('0' + (a[i] & 0xff).toString(16)).slice(-2);
       return s;
     }
     function list(a) {
       const o = [];
       for (let i = 0; i < a.length; i++) o.push('' + a[i]);
       return o.join(',');
     }
     function describe(k) {
       const cls = k.getClass().getName();
       if (cls.indexOf('android.security.keystore') !== -1) {
         try {
           const ki = Java.cast(KeyFactory.getInstance(k.getAlgorithm(), 'AndroidKeyStore')
             .getKeySpec(k, KeyInfo.class), KeyInfo);
           let level;
           try { level = ki.getSecurityLevel(); } catch (e) { level = ki.isInsideSecureHardware() ? 'secure-hw' : 'software'; }
           return 'KEYSTORE size=' + ki.getKeySize() + ' purposes=' + ki.getPurposes() +
             ' digests=' + list(ki.getDigests()) + ' paddings=' + list(ki.getSignaturePaddings()) +
             ' userAuth=' + ki.isUserAuthenticationRequired() + ' securityLevel=' + level;
         } catch (e) { return 'KEYSTORE ' + cls + ' (KeyInfo failed: ' + e + ')'; }
       }
       let bits = '?';
       try { bits = Java.cast(k, RSAKey).getModulus().bitLength(); } catch (e) {
         try { bits = Java.cast(k, ECKey).getParams().getOrder().bitLength(); } catch (e2) { }
       }
       return 'SOFTWARE KEY IN APP PROCESS ' + cls + ' ' + k.getAlgorithm() + ' ' + bits + ' bits';
     }

     Sig.initSign.overload('java.security.PrivateKey').implementation = function (k) {
       this.initSign(k);   // initialise first: calling getProvider() earlier can lock in the wrong provider
       console.log('\n[initSign] ' + this.getAlgorithm() + ' via ' + this.getProvider().getName() + '\n  ' + describe(k));
       console.log(Log.getStackTraceString(Exc.$new()));
     };
     Sig.initSign.overload('java.security.PrivateKey', 'java.security.SecureRandom').implementation = function (k, r) {
       this.initSign(k, r);
       console.log('\n[initSign+random] ' + this.getAlgorithm() + ' random=' + r.getClass().getName() +
         '/' + r.getAlgorithm() + '\n  ' + describe(k));
     };
     // update(byte[]) delegates to update(byte[], int, int), so hooking the 3-arg form avoids double counting
     Sig.update.overload('[B', 'int', 'int').implementation = function (b, off, len) {
       const id = this.hashCode();
       pending[id] = (pending[id] || '') + hex(b, off, len);
       return this.update(b, off, len);
     };
     Sig.sign.overload().implementation = function () {
       const out = this.sign();
       const id = this.hashCode();
       const msg = pending[id] || '';
       delete pending[id];
       console.log('[sign] ' + this.getAlgorithm() + ' msg(' + msg.length / 2 + ' bytes)=' + msg.slice(0, 160));
       console.log('SIGLINE ' + hex(out, 0, out.length) + ' ' + msg);
       return out;
     };
   });
   ```

2. Run it and exercise every flow that might sign: enrolment, login, step-up, payment approval, QR or ticket generation.

   ```bash
   frida -U -f com.example.app -l gt-android-sign.js -o sign-log.txt
   ```

3. Decode what you see. `purposes` is the bitmask from the Knowledge section; `securityLevel` is `0` (software), `1` (TEE) or `2` (StrongBox) on API 31+. Apps that sign through `update(ByteBuffer)` will show an empty `msg`; add a hook for that overload if you need the data.

4. If you find a software key, hook `KeyFactory.generatePrivate` and `PKCS8EncodedKeySpec.$init` the same way to see where its bytes come from, and hand that to the MASWE-0003 tests.

#### Observation

`sign-log.txt` with, for each signing operation: algorithm, provider, key location and authorisations, signed bytes, signature, and a stack trace that ties it to app code. Keep the `SIGLINE` lines for Test 6.

#### Evaluation

The test **fails** if, for a signature the backend or another party relies on:

- the algorithm or key size is weak as defined in Test 1;
- the key is a software key in the app process (`SOFTWARE KEY IN APP PROCESS`), or a Keystore key at `securityLevel=0` on a device that has a TEE, where the design claims hardware protection;
- a transaction or consent signature is produced with `userAuth=false`;
- `initSign` receives an explicit `SecureRandom` that is not the platform default (for example a seeded `SHA1PRNG`) for ECDSA or DSA; or
- the signed bytes contain data the user or app did not produce (carry this into Test 7).

Note that the `Signature` hook sees only JCA signing. Signing in Tink, BouncyCastle low-level classes, JavaScript (React Native, WebViews), Dart or native code needs its own hooks.

#### Demo

Output for the Test 1 sample, followed by a software-key signer from a second flow (abridged, stack traces trimmed):

```text
[initSign] SHA1withRSA via AndroidKeyStoreBCWorkaround
  KEYSTORE size=1024 purposes=4 digests=SHA-1,NONE paddings=PKCS1 userAuth=false securityLevel=1
    at java.security.Signature.initSign(Native Method)
    at com.example.app.txn.TxnSigner.sign(TxnSigner.kt:41)
[sign] SHA1withRSA msg(58 bytes)=7b22616d6f756e74223a223130302e3030222c2270617965...
SIGLINE 3b9f...c1 7b22616d6f756e74223a223130302e3030222c...

[initSign] SHA256withECDSA via AndroidOpenSSL
  SOFTWARE KEY IN APP PROCESS com.android.org.conscrypt.OpenSSLECPrivateKey EC 256 bits
    at com.example.app.device.DeviceBinding.signChallenge(DeviceBinding.kt:77)
```

The first operation fails on algorithm, key size and missing user authentication even though the key is in the TEE. The second uses a sound scheme with a key that is not in the keystore at all, so its signatures prove only that someone had a copy of the key.

### Test 3: References to weak signature algorithms and key parameters (iOS)

Guler Tech methodology. Platform: iOS. Type: static (binary).

#### Overview

On iOS the signing scheme is selected by a `SecKeyAlgorithm` constant or by a CryptoKit type. The constants are global `CFString` symbols exported by the Security framework, so the binary's import table tells you which schemes the app can use. CryptoKit types appear as Swift mangled symbols. Third-party libraries (OpenSSL, libsodium, libsecp256k1, wallet SDKs) show up as frameworks or as statically linked functions.

#### Prerequisites

- Decrypted IPA and the main binary, plus every binary under `Frameworks/`.
- macOS with Xcode command-line tools (`nm`, `otool`, `xcrun swift-demangle`), or radare2.

#### Steps

1. **List signing-related imports** of the main binary and each embedded framework:

   ```bash
   BIN=Payload/App.app/App
   nm -um "$BIN" | grep -E 'SecKeyCreateSignature|SecKeyCreateRandomKey|SecKeyCreateWithData|kSecKeyAlgorithm(RSA|ECDSA)Signature'
   nm -um "$BIN" | xcrun swift-demangle | grep -oE 'CryptoKit\.(P256|P384|P521|Curve25519|SecureEnclave\.P256|Insecure)\.[A-Za-z.]+' | sort -u
   otool -L "$BIN" | grep -iE 'crypto|ssl|sodium|secp256k1|wallet'
   ls Payload/App.app/Frameworks/
   ```

   With radare2 the equivalent is `r2 -A "$BIN"` followed by `ii~SecKey,kSecKeyAlgorithm,CryptoKit` and `axt @ <address>` for each import to find the call sites.

2. **Classify the algorithm constants** against the [SecKey table](#ios-seckey-signature-algorithms-mastg-know-0067). Imports such as `_kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1`, `_kSecKeyAlgorithmECDSASignatureMessageX962SHA1` or `_kSecKeyAlgorithmRSASignatureRaw` show the app can sign with a weak or raw scheme. An import is not yet a use: find its cross-references and confirm it is passed to `SecKeyCreateSignature` rather than `SecKeyVerifySignature`.

3. **Find key generation parameters.** At each `SecKeyCreateRandomKey` call site, read the attribute dictionary built before it: `kSecAttrKeyType`, `kSecAttrKeySizeInBits` (look for a literal `0x400` = 1024), `kSecAttrTokenID` and the `kSecAttrCan…` flags. Swift often builds these dictionaries in helper functions; decompile the caller in r2 (`pdf @ <fcn>`) or Ghidra.

4. **Look for weak digests next to CryptoKit signing**: `Insecure.SHA1` or `Insecure.MD5` in the same function as `Signing.PrivateKey.signature(for:)`.

5. **Check third-party signers.** For OpenSSL (`RSA_sign`, `ECDSA_do_sign_ex`, `EVP_DigestSign*`), libsodium (`crypto_sign_detached`, Ed25519) and libsecp256k1 (`secp256k1_ecdsa_sign`), note the library version and read how the nonce function and digest are chosen.

#### Observation

A table of call sites with: algorithm constant or CryptoKit type, key type and size, whether the key is a Secure Enclave key (`kSecAttrTokenIDSecureEnclave`, `SecureEnclave.P256`), usage flags, and third-party libraries with versions.

#### Evaluation

The test **fails** if a signature used for a security decision is generated with a SHA-1 or MD5 digest, a raw RSA algorithm, an RSA key below 2048 bits, or a custom ECDSA implementation with a caller-supplied nonce. It also fails, as a MASWE-0003 finding with consequences here, if a high-value signing key is a software key (`P256.Signing.PrivateKey` or a non-Enclave `SecKey`) whose raw representation is persisted outside the Keychain. Secure Enclave P-256 signing with `.ecdsaSignatureMessageX962SHA256` passes. False positives: SHA-1 constants imported for verifying legacy signatures, and algorithms referenced by a wrapper library but never called.

#### Demo

Vulnerable Swift (Guler Tech sample):

```swift
let attrs: [String: Any] = [
    kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
    kSecAttrKeySizeInBits as String: 1024,
    kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: true,
                                    kSecAttrApplicationTag as String: Data("txn".utf8)] as [String: Any]
]
var error: Unmanaged<CFError>?
let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error)!
let sig = SecKeyCreateSignature(key, .rsaSignatureMessagePKCS1v15SHA1, payload as CFData, &error)
```

Import listing for the compiled sample:

```text
$ nm -um Payload/MASTestApp.app/MASTestApp | grep -E 'SecKeyCreate|kSecKeyAlgorithm'
                 (undefined) external _SecKeyCreateRandomKey (from Security)
                 (undefined) external _SecKeyCreateSignature (from Security)
                 (undefined) external _kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1 (from Security)
```

The test fails: the only signature algorithm the binary imports is PKCS#1 v1.5 with SHA-1, and the key-generation helper passes `0x400` (1024) as `kSecAttrKeySizeInBits`.

### Test 4: Runtime signing operations and signing-key properties (iOS)

Guler Tech methodology. Platform: iOS. Type: dynamic (hooks).

#### Overview

Hook `SecKeyCreateSignature` (and `SecKeyCreateRandomKey` for key creation) to see each signing operation with its algorithm, key attributes and data. CryptoKit Secure Enclave operations may also surface here, because CryptoKit reaches the Enclave through lower-level system frameworks, but do not rely on it; software CryptoKit keys never do, and need a Swift-level trace.

#### Prerequisites

- Jailbroken device with `frida-server`; the app installed.
- Optional: `frida-trace` for CryptoKit symbols.

#### Steps

1. Save the script:

   ```javascript
   // gt-ios-sign.js
   function hex(p, n) {
     const u = new Uint8Array(p.readByteArray(n));
     return Array.from(u, b => ('0' + b.toString(16)).slice(-2)).join('');
   }
   const ns = s => ObjC.classes.NSString.stringWithString_(s);
   const sec = Process.getModuleByName('Security');
   const copyAttrs = new NativeFunction(sec.getExportByName('SecKeyCopyAttributes'), 'pointer', ['pointer']);

   Interceptor.attach(sec.getExportByName('SecKeyCreateRandomKey'), {
     onEnter(args) { console.log('\n[SecKeyCreateRandomKey] ' + new ObjC.Object(args[0]).toString()); }
   });
   Interceptor.attach(sec.getExportByName('SecKeyCreateSignature'), {
     onEnter(args) {
       const attrs = new ObjC.Object(copyAttrs(args[0]));
       this.alg = new ObjC.Object(args[1]).toString();
       const d = new ObjC.Object(args[2]);
       this.msg = hex(d.bytes(), d.length());
       console.log('\n[SecKeyCreateSignature] ' + this.alg +
         ' type=' + attrs.objectForKey_(ns('type')) + ' bsiz=' + attrs.objectForKey_(ns('bsiz')) +
         ' tkid=' + attrs.objectForKey_(ns('tkid')) + ' msg(' + d.length() + ')=' + this.msg.slice(0, 160));
       console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).slice(0, 8).join('\n'));
     },
     onLeave(ret) {
       if (ret.isNull()) { console.log('  -> failed'); return; }
       const s = new ObjC.Object(ret);
       console.log('SIGLINE ' + hex(s.bytes(), s.length()) + ' ' + this.msg);
     }
   });
   ```

   `SecKeyCopyAttributes` returns a retained dictionary; the small leak is irrelevant for a test session.

2. Run it and exercise the signing flows:

   ```bash
   frida -U -f com.example.app -l gt-ios-sign.js -o sign-log-ios.txt
   ```

3. For software CryptoKit keys, trace the Swift entry points. Mangled names contain the type and method names, so a glob works:

   ```bash
   frida-trace -U -f com.example.app -i 'CryptoKit!*Signing*PrivateKey*signature*'
   ```

   If nothing appears, the call may be specialised into the app binary; repeat with `-i 'App!*signature*'` (the app's module name) or set the trace on the call sites found in Test 3.

#### Observation

`sign-log-ios.txt` with, for each operation: algorithm constant, key type (`42` RSA, `73` EC), size, token (`com.apple.setoken` for Secure Enclave), signed bytes, signature, and the calling function. Keep the `SIGLINE` lines for Test 6.

#### Evaluation

As for Test 2: the test **fails** if a relied-upon signature uses a weak or raw algorithm or a short key, if a high-value signing key is not in the Secure Enclave where the design claims hardware protection (`tkid` absent), or if the signed bytes include third-party-controlled data (Test 7). For Secure Enclave keys, also confirm in the creation dictionary that the access control includes a user-presence flag when the signature represents user consent.

#### Demo

Output for the Test 3 sample next to a correctly configured Secure Enclave signer:

```text
[SecKeyCreateSignature] algid:sign:RSA:message-PKCS1v15:SHA1 type=42 bsiz=1024 tkid=null msg(61)=7b22...
SIGLINE 5c0e...9a 7b22...

[SecKeyCreateSignature] algid:sign:ECDSA:message-X962:SHA256 type=73 bsiz=256 tkid=com.apple.setoken msg(48)=636f...
SIGLINE 3045022100...0220... 636f...
```

The algorithm constants print as their string values (`algid:sign:RSA:…`). The first operation fails (SHA-1, 1024-bit RSA, software key); the second passes.

### Test 5: Signing keys used for multiple purposes (Android, iOS)

Guler Tech methodology, building on OWASP MASTG-TEST-0307 and MASTG-TEST-0308. Platform: Android and iOS. Type: static and dynamic.

#### Overview

A signing key must do nothing but sign. On Android, OWASP's beta tests cover this for asymmetric Keystore keys: [MASTG-TEST-0307](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0307/) flags `KeyGenParameterSpec.Builder(alias, purposes)` calls whose purposes span more than one of the groups encrypt/decrypt (1, 2, 3), sign/verify (4, 8, 12) and wrap (32), and [MASTG-TEST-0308](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0308/) hooks `Cipher.init`, `Signature.initSign` and `Signature.initVerify` to catch one key appearing in more than one group. Run them as written; the procedure, the semgrep rule and the Frida script from MASTG-DEMO-0071/0072 are in our [MASWE-0007 note](/mobile/maswe-0007-improper-encryption/). Two additions matter for signing keys: `PURPOSE_AGREE_KEY` (64, API 31+) on a signing key is also multi-purpose, and software keys (no `KeyGenParameterSpec` at all) have no enforced purpose, so only the runtime check finds their misuse. iOS has no OWASP test for this; the steps below are ours.

#### Prerequisites

As for Tests 1–4.

#### Steps

1. **Android, static and dynamic:** run MASTG-TEST-0307 and 0308. To triage many keys quickly, decode every literal purpose value and flag those that combine sign (4) with encrypt, decrypt, wrap or agree (1 + 2 + 32 + 64 = 99):

   ```bash
   grep -rhoE 'KeyGenParameterSpec\.Builder\([^,]+, *[0-9]+\)' out/sources | grep -oE '[0-9]+\)$' | tr -d ')' | sort -un |
     while read p; do echo "purposes=$p sign=$(( p & 4 ? 1 : 0 )) other=$(( p & 99 ? 1 : 0 ))"; done
   ```

   Any line with `sign=1 other=1` is a multi-purpose signing key; find its alias in the source.

2. **iOS, static:** in the attribute dictionaries found in Test 3, look for a private key created with both `kSecAttrCanSign` and `kSecAttrCanDecrypt` (or `kSecAttrCanDerive`), and for one application tag being used in both `SecKeyCreateSignature` and `SecKeyCreateDecryptedData` or `SecKeyCopyKeyExchangeResult` paths. In CryptoKit, look for conversions that move one key across types, for example `P256.KeyAgreement.PrivateKey(rawRepresentation: signingKey.rawRepresentation)`.

3. **iOS, dynamic:** fingerprint the public key behind every private-key operation and look for the same fingerprint in more than one group:

   ```javascript
   // gt-ios-key-purpose.js
   const sec = Process.getModuleByName('Security');
   const copyPub = new NativeFunction(sec.getExportByName('SecKeyCopyPublicKey'), 'pointer', ['pointer']);
   const copyExt = new NativeFunction(sec.getExportByName('SecKeyCopyExternalRepresentation'), 'pointer', ['pointer', 'pointer']);
   const seen = {};
   function fp(key) {
     const pub = copyPub(key);
     if (pub.isNull()) return 'no-public-key';
     const d = copyExt(pub, NULL);
     if (d.isNull()) return 'not-exportable';
     const o = new ObjC.Object(d);
     const u = new Uint8Array(o.bytes().readByteArray(o.length()));
     let h = 0x811c9dc5;
     for (const b of u) { h ^= b; h = Math.imul(h, 0x01000193) >>> 0; }
     return h.toString(16);
   }
   function watch(name, group) {
     Interceptor.attach(sec.getExportByName(name), {
       onEnter(args) {
         const id = fp(args[0]);
         console.log('[' + name + '] key=' + id + ' alg=' + new ObjC.Object(args[1]).toString());
         if (seen[id] && seen[id] !== group) console.log('!!! key ' + id + ' used for ' + seen[id] + ' and ' + group);
         seen[id] = seen[id] || group;
       }
     });
   }
   watch('SecKeyCreateSignature', 'sign');
   watch('SecKeyCreateDecryptedData', 'decrypt');
   watch('SecKeyCopyKeyExchangeResult', 'key-agreement');
   ```

   ```bash
   frida -U -f com.example.app -l gt-ios-key-purpose.js
   ```

#### Observation

For each asymmetric private key: its identifier (alias, application tag or public-key fingerprint), the purposes it was created with, and the operations it was actually used for.

#### Evaluation

The test **fails** if any private key that produces signatures is also authorised for, or used for, decryption, key agreement or key wrapping. On Android, a purpose value of `12` (sign and verify) passes; `13`, `14` or `15` fail. On iOS, a Secure Enclave key used for both ECDSA signing and ECIES decryption fails even though each operation is individually sound.

#### Demo

OWASP's MASTG-DEMO-0071 shows the Android case: an RSA key generated with `PURPOSE_SIGN or PURPOSE_VERIFY or PURPOSE_DECRYPT or PURPOSE_ENCRYPT`, which jadx renders as `new KeyGenParameterSpec.Builder(this.KEY_ALIAS, 15)` and which the OWASP semgrep rule reports at that line. MASTG-DEMO-0072's Frida output then shows the same `AndroidKeyStoreRSAPrivateKey` instance in `Cipher.init` (decryption) and `Signature.initSign`, with the warning `This key is used for multiple, conflicting purposes: encryption/decryption and sign/verify`. The iOS script above prints the equivalent:

```text
[SecKeyCreateSignature] key=5f1c03ab alg=algid:sign:ECDSA:message-X962:SHA256
[SecKeyCreateDecryptedData] key=5f1c03ab alg=algid:encrypt:ECIES:ECDHE:KDFX963:SHA256:AESGCM
!!! key 5f1c03ab used for sign and decrypt
```

### Test 6: ECDSA nonce reuse in collected signatures (Android, iOS)

Guler Tech methodology. Platform: Android and iOS (and any traffic the app sends). Type: dynamic, with offline analysis.

#### Overview

If two ECDSA signatures from one key share the value *r*, they share the nonce *k*, and the private key falls out of two lines of modular arithmetic (see [Knowledge](#generic-ecdsa-nonces-rfc-6979-and-eddsa-guler-tech)). This test collects signatures and their messages, looks for repeated *r* values, and when it finds one, recovers the key to prove it. It is essential when Tests 1–4 found custom or third-party ECDSA (wallets, BouncyCastle low-level classes, JavaScript or Dart crypto, native libraries), and cheap enough to run on any app that sends signatures.

#### Prerequisites

- Signatures and the exact bytes signed: the `SIGLINE` output of Tests 2 and 4, or signatures captured from traffic (request headers, JSON bodies, QR codes) together with the canonical bytes they cover.
- The curve and hash (P-256 with SHA-256 in most apps; adjust the script's order *N* and hash for P-384 or secp256k1).
- Python 3.8 or later (no third-party packages).

#### Steps

1. **Collect at least a few dozen signatures** from the same key, over different messages. Repeat the signing flow many times; where the UI makes that slow, call the signing method directly from Frida (`Java.choose` on the signer class, or a call to the Swift/Objective-C method) in a loop.

2. **Write them as `sig_hex msg_hex` lines:**

   ```bash
   grep '^SIGLINE ' sign-log.txt | cut -d' ' -f2,3 > sigs.txt
   ```

3. **Run the analysis:**

   ```python
   #!/usr/bin/env python3
   """Flag repeated ECDSA nonces in collected signatures.
   Input: one line per signature, "<sig_hex> <msg_hex>"; sig is DER (X9.62) or raw r||s.
   Pass --digest if msg_hex is already the SHA-256 digest (e.g. *Digest* SecKey algorithms)."""
   import hashlib, sys
   from collections import defaultdict

   N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551  # P-256 order

   def der_rs(b):
       is_der = b[0] == 0x30 and (b[1] == len(b) - 2 or (b[1] == 0x81 and b[2] == len(b) - 3))
       if not is_der:                        # raw r||s (CryptoKit rawRepresentation, RFC 4754, JOSE)
           h = len(b) // 2
           return int.from_bytes(b[:h], "big"), int.from_bytes(b[h:], "big")
       i = 3 if b[1] == 0x81 else 2          # skip SEQUENCE header
       out = []
       for _ in range(2):
           assert b[i] == 0x02; ln = b[i + 1]
           out.append(int.from_bytes(b[i + 2:i + 2 + ln], "big")); i += 2 + ln
       return tuple(out)

   seen = defaultdict(list)
   prehashed = "--digest" in sys.argv
   for line in open(sys.argv[1]):
       if not line.strip():
           continue
       sig_hex, msg_hex = line.split()
       r, s = der_rs(bytes.fromhex(sig_hex))
       m = bytes.fromhex(msg_hex)
       z = int.from_bytes(m if prehashed else hashlib.sha256(m).digest(), "big")
       seen[r].append((s, z))

   for r, uses in seen.items():
       pairs = [(a, b) for i, a in enumerate(uses) for b in uses[i + 1:] if a[0] != b[0]]
       if not pairs:
           continue                           # unique r, or the same message signed twice
       (s1, z1), (s2, z2) = pairs[0]
       k = ((z1 - z2) * pow(s1 - s2, -1, N)) % N
       d = ((s1 * k - z1) * pow(r, -1, N)) % N
       print(f"REUSED NONCE r={r:064x}\n  recovered private key d={d:064x}")
   print(f"{sum(len(v) for v in seen.values())} signatures, {len(seen)} distinct r values")
   ```

   ```bash
   python3 -I find_reuse.py sigs.txt
   ```

4. **Prove the recovery.** Derive the public key from the recovered *d* (for example with `openssl` after wrapping *d* in a PKCS#8 structure, or any EC library) and compare it with the public key the app registered, or simply sign a new message with *d* and have the app's verifier or backend accept it in a test environment. If the library normalises *s* to the lower half of the range (common with secp256k1), retry with *s₂* replaced by *N* − *s₂* when the recovered key does not match.

5. **Check determinism.** Sign the *same* message twice. Identical signatures mean a deterministic scheme (RFC 6979 or Ed25519), which is fine; confirm it is a standard one by checking the library. Different signatures over the same message mean randomised nonces; reuse then points to an RNG fault.

#### Observation

The number of signatures, the number of distinct *r* values, any repeated *r* with the message pairs, and — for a repeat — the recovered private key (redacted in the report) with proof that it matches the app's public key.

#### Evaluation

The test **fails** if two signatures over different messages share *r*, or if the recovered key verifies. It also fails if static review shows *k* derived from public data (a timestamp, a counter, a hash of the message alone), even when no repeat has been observed yet, because such a *k* is computable and gives the key from one signature. All-distinct *r* values over a few dozen signatures do not prove the nonces are unbiased; for custom implementations, report the construction and recommend RFC 6979 or Ed25519 regardless.

#### Demo

Vulnerable Kotlin (Guler Tech sample): a hand-rolled ticket signer that "optimises" by creating the nonce once.

```kotlin
class TicketSigner(private val d: BigInteger) {
    private val k = BigInteger(256, SecureRandom()).mod(N)     // generated once, reused for every ticket
    private val r = G.multiply(k).normalize().affineXCoord.toBigInteger().mod(N)

    fun sign(ticket: ByteArray): Pair<BigInteger, BigInteger> {
        val z = BigInteger(1, MessageDigest.getInstance("SHA-256").digest(ticket))
        val s = k.modInverse(N).multiply(z.add(r.multiply(d))).mod(N)
        return r to s
    }
}
```

Running the script on three captured tickets:

```text
$ python3 -I find_reuse.py sigs.txt
REUSED NONCE r=806bfa2eb93be94d2ee03a20cbced1a346fcf67c2a694b2f6840407e5acea102
  recovered private key d=ff5be313a5d94bd124047dcf413c233d0d0aeb34b179d93abe75101a10f7ef74
3 signatures, 2 distinct r values
```

The recovered *d* matches the key that signed the tickets, so anyone holding two tickets can mint new ones. (The key above is from our synthetic test run.)

### Test 7: High-value keys signing attacker-influenced data (Android, iOS)

Guler Tech methodology. Platform: Android and iOS. Type: static and dynamic.

#### Overview

A well-protected key is still a liability if someone else chooses what it signs. This test traces the data flowing into each signing call found in Tests 2 and 4 back to its source, identifies entry points through which a third party can supply those bytes, and checks whether the signed format separates one use from another. The classic mobile instance is a WebView JavaScript bridge that exposes "sign this" to whatever page is loaded.

#### Prerequisites

- Results of Tests 1–4 (call sites, stack traces, signed bytes).
- `apktool` output for the manifest; `plutil` for `Info.plist` and the entitlements (`codesign -d --entitlements :- Payload/App.app`).
- Ability to load content into the app's WebViews (a test page you control, a deep link that takes a URL) and, for Android, Chrome remote debugging; for iOS, Safari Web Inspector on an inspectable `WKWebView`.

#### Steps

1. **Map entry points that can reach signing code.**

   ```bash
   grep -rnE '@JavascriptInterface|addJavascriptInterface\(' out/sources
   grep -nE 'android:exported="true"|<intent-filter|android:scheme=' apktool_out/AndroidManifest.xml
   plutil -p Payload/App.app/Info.plist | grep -A5 CFBundleURLTypes
   codesign -d --entitlements :- Payload/App.app | grep -A5 associated-domains
   nm -um Payload/App.app/App | xcrun swift-demangle | grep -E 'WKScriptMessageHandler|userContentController'
   ```

2. **Trace the bytes.** For each signing call site, follow the argument of `update`/`SecKeyCreateSignature`/`signature(for:)` backwards in jadx ("Find usage") or in the disassembly. Classify the source: built by the app from its own state; received from the authenticated backend; or reachable by a third party (JavaScript, intent extras, URL parameters, push payloads, files from shared storage, clipboard).

3. **Check the signed format.** Does the signed message begin with a constant context label and version? Are the fields the app fills in (user, device, timestamp, nonce, purpose) present and in fixed positions? Can a payload supplied for one feature parse as a payload for another? Is the same key used for more than one of login, transaction approval and data signing?

4. **Exercise reachable paths dynamically.** For a JavaScript bridge, enable WebView debugging (via Frida if the build does not, by calling `android.webkit.WebView.setWebContentsDebuggingEnabled(true)` on the UI thread), open `chrome://inspect`, and call the bridge from the console with bytes you choose. On iOS, use Safari's Web Inspector and `window.webkit.messageHandlers.<name>.postMessage(...)`. For deep links: `adb shell am start -a android.intent.action.VIEW -d '<scheme>://<path>?<param>=<value>'` or `xcrun simctl openurl booted '<url>'` on a simulator build. Watch the Test 2/4 hooks to confirm your bytes reach `sign`.

5. **Check what the signature is good for.** Within your test accounts and agreed scope, submit the obtained signature to the backend endpoint for another feature (for example, present a challenge-response signature as a transaction approval). Acceptance proves the oracle is exploitable rather than theoretical.

#### Observation

For each signing key: its business purpose, the entry points that reach it, whether a third party controls any part of the signed bytes, the signed format (with or without context separation), and whether a signature obtained through one path was accepted for another.

#### Evaluation

The test **fails** if a key that authenticates the user or device, approves transactions, or signs artefacts others rely on will sign bytes chosen wholly or partly by a third party without a fixed, feature-specific context; or if a signature obtained in one context is accepted in another. It also fails if the signature produced for third-party input is returned to that third party (for example as the bridge method's return value). It passes when the third party can only influence fields inside a structured, context-labelled message that the app builds and the backend parses strictly, and the key is not shared with higher-value functions.

#### Demo

Vulnerable Kotlin (Guler Tech sample): the device-binding key, which the backend also accepts for login challenges, is exposed to every page loaded in the in-app browser.

```kotlin
class SigningBridge(private val deviceKey: PrivateKey) {
    @JavascriptInterface
    fun sign(payloadB64: String): String {
        val s = Signature.getInstance("SHA256withECDSA")
        s.initSign(deviceKey)
        s.update(Base64.decode(payloadB64, Base64.NO_WRAP))   // caller chooses every byte
        return Base64.encodeToString(s.sign(), Base64.NO_WRAP)
    }
}
webView.addJavascriptInterface(SigningBridge(deviceKey), "Native")
webView.loadUrl(intent.getStringExtra("url")!!)              // URL comes from a deep link
```

A page under the attacker's control, opened through the deep link, calls `Native.sign(...)` with the base64 of a login challenge it fetched from the backend for the victim's account and posts the result back to itself. The Test 2 hook shows the device key signing the challenge bytes, with `SigningBridge.sign` in the stack trace, and the backend accepts the signature as a login. The fix is to remove the bridge method, or to sign only a structure the app builds itself under a separate key whose context label cannot collide with the login format.

## Secure implementation

MASWE-0010 links no OWASP Best Practices, so this section is ours. The examples target current SDKs (Android API 23+ with the version checks shown, iOS 14+ for the async App Attest calls) and are meant as a reference for review and remediation. Key storage, StrongBox fallback and Keychain handling are covered in depth in the [MASWE-0003 note](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/#secure-implementation); here the focus is the signing itself.

### Android: a single-purpose, attested ECDSA signing key

```kotlin
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.ECGenParameterSpec

private const val ANDROID_KEYSTORE = "AndroidKeyStore"

/** Creates a P-256 signing key and returns its attestation chain for the server to verify. */
fun createTxnSigningKey(alias: String, serverChallenge: ByteArray, strongBox: Boolean): List<ByteArray> {
    val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)   // sign only
        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
        .setDigests(KeyProperties.DIGEST_SHA256)                                  // no SHA-1, no NONE
        .setUserAuthenticationRequired(true)
        .setAttestationChallenge(serverChallenge)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG) // every signature
    }
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && strongBox) {
        builder.setIsStrongBoxBacked(true)   // catch StrongBoxUnavailableException and retry without it
    }
    KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE).apply {
        initialize(builder.build())
        generateKeyPair()
    }
    val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    return ks.getCertificateChain(alias).map { it.encoded }
}
```

The server verifies the chain as described in [Attestation of signing keys](#android-attestation-of-signing-keys-mastg-know-0044) and stores the public key against the user and device. Below API 30, `setUserAuthenticationValidityDurationSeconds(-1)` is the deprecated way to require authentication per operation.

### Android: sign a structured, context-labelled transaction

```kotlin
import androidx.biometric.BiometricPrompt
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.PrivateKey
import java.security.Signature

private val TXN_CONTEXT = "com.example.bank/txn-approval/v1".toByteArray()

fun canonicalTxn(payee: String, amountMinor: Long, currency: String, serverNonce: ByteArray): ByteArray =
    ByteArrayOutputStream().use { bos ->
        DataOutputStream(bos).use { out ->
            out.writeShort(TXN_CONTEXT.size); out.write(TXN_CONTEXT)       // domain separation
            out.writeUTF(payee); out.writeLong(amountMinor); out.writeUTF(currency)
            out.writeShort(serverNonce.size); out.write(serverNonce)       // freshness, set by the server
        }
        bos.toByteArray()
    }

fun startApproval(prompt: BiometricPrompt, info: BiometricPrompt.PromptInfo, key: PrivateKey) {
    val sig = Signature.getInstance("SHA256withECDSA").apply { initSign(key) }
    prompt.authenticate(info, BiometricPrompt.CryptoObject(sig))
}

// In AuthenticationCallback.onAuthenticationSucceeded(result):
fun finishApproval(result: BiometricPrompt.AuthenticationResult, txnBytes: ByteArray): ByteArray {
    val sig = requireNotNull(result.cryptoObject?.signature)
    sig.update(txnBytes)
    return sig.sign()            // DER-encoded ECDSA signature; send with txnBytes
}
```

The values in `canonicalTxn` must be the ones displayed in the prompt (`setTitle`/`setDescription`), and the server must rebuild the same bytes from its own record of the transaction and verify against them, rather than trusting fields the app sends alongside the signature. If RSA is required, use `KeyProperties.KEY_ALGORITHM_RSA`, `setKeySize(3072)`, `setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)` and `Signature.getInstance("SHA256withRSA/PSS")`, and confirm the MGF1 digest and salt length your server expects by verifying a test signature with explicit parameters.

### Android: Ed25519 or ECDSA in software, done safely

When a protocol requires a curve the Keystore does not support (secp256k1, or Ed25519 on older devices), the key is necessarily software-held. Wrap its storage with a Keystore key (MASWE-0003) and use a library that handles nonces for you. With Tink:

```kotlin
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.PublicKeySign
import com.google.crypto.tink.signature.SignatureConfig
import com.google.crypto.tink.KeyTemplates

SignatureConfig.register()
val handle = KeysetHandle.generateNew(KeyTemplates.get("ED25519"))   // persist via AndroidKeysetManager
val signer = handle.getPrimitive(PublicKeySign::class.java)
val signature = signer.sign(TXN_CONTEXT + payload)
```

With BouncyCastle low-level ECDSA, always construct the signer as `ECDSASigner(HMacDSAKCalculator(SHA256Digest()))` (RFC 6979) so no caller-supplied random source is involved.

### iOS: Secure Enclave signing with CryptoKit

```swift
import CryptoKit
import Foundation
import Security

enum SigningError: Error { case noEnclave, accessControl }

let txnContext = Data("com.example.bank/txn-approval/v1".utf8)

func makeTxnSigningKey() throws -> SecureEnclave.P256.Signing.PrivateKey {
    guard SecureEnclave.isAvailable else { throw SigningError.noEnclave }
    guard let access = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage, .biometryCurrentSet], nil
    ) else { throw SigningError.accessControl }
    return try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
    // Persist key.dataRepresentation in the Keychain; it only works on this device's Enclave.
}

func signTransaction(_ canonicalTxn: Data, with key: SecureEnclave.P256.Signing.PrivateKey) throws -> Data {
    var message = Data()
    message.append(UInt8(txnContext.count)); message.append(txnContext)   // domain separation
    message.append(canonicalTxn)
    return try key.signature(for: message).derRepresentation                 // ECDSA P-256 / SHA-256
}
```

With the Security framework, the equivalent is a key from `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave` and `.privateKeyUsage`, signed with `SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, message as CFData, &error)` after checking `SecKeyIsAlgorithmSupported`. For software keys where the Enclave is not needed, `Curve25519.Signing.PrivateKey()` gives Ed25519 with nothing to configure; store its `rawRepresentation` in the Keychain with a `ThisDeviceOnly` accessibility class.

### iOS: bind your signing key to App Attest

```swift
import CryptoKit
import DeviceCheck

func attestSigningKey(publicKey: P256.Signing.PublicKey, serverChallenge: Data) async throws -> (String, Data) {
    let service = DCAppAttestService.shared
    guard service.isSupported else { throw SigningError.noEnclave }
    let keyId = try await service.generateKey()
    var clientData = serverChallenge
    clientData.append(publicKey.derRepresentation)          // binds your signing key to the attestation
    let attestation = try await service.attestKey(keyId, clientDataHash: Data(SHA256.hash(data: clientData)))
    return (keyId, attestation)                             // server verifies with Apple's App Attest root
}
```

The server validates the attestation object (certificate chain to Apple's App Attest root, the nonce derived from `clientDataHash`, the app ID and the counter) and only then trusts the signing public key it received with it.

### Both platforms: design rules for signed data

- **One key per function.** Device authentication, transaction approval and artefact signing get separate keys with separate aliases and server-side records.
- **Context label first, then structured fields.** A fixed, versioned label at the start of every signed message makes cross-protocol reuse impossible; length-prefix variable fields so concatenations cannot be ambiguous.
- **The server rebuilds what was signed.** It should never accept "here are the fields, and here is a signature over them" without recomputing the canonical bytes from its own state.
- **Algorithm agility, not negotiation.** Carry an algorithm identifier and key version in the signed format so you can migrate (to 3072-bit RSA, or ML-DSA when platforms support it), but let the server decide which algorithms it accepts.
- **Rotation and revocation.** Signing keys need an expiry and a way to be revoked from the server when a device is lost or a key is found to be weak; see [MASWE-0015](/mobile/maswe-0015-key-rotation-not-implemented/).

## Rating findings

Rate on what a forged signature buys an attacker, what they need to obtain it, and how many users are affected.

| Rating | Conditions |
|---|---|
| **Critical** | The private key can be recovered from public material: ECDSA nonce reuse or computable nonces (Test 6), or an RSA key of 512–768 bits, for a key the backend trusts for authentication, transactions or artefacts that affect other users. A shared signing key (one key for all installs) with any of these defects. A signing oracle (Test 7) reachable remotely, without user interaction beyond opening a link, that yields signatures the backend accepts for login or payment. |
| **High** | 1024-bit RSA or SHA-1 signatures on transaction, device-binding or credential signatures, where the attacker can influence the signed data (chosen-prefix collisions make SHA-1 forgeable). A per-user signing key held in software in app storage, so anyone with a backup, root or malware on the device can sign as the user (rate with MASWE-0003). A signing oracle reachable only through local interaction (another app on the device, a crafted file). Transaction-signing keys not bound to user authentication where the backend treats the signature as proof of consent. |
| **Medium** | Signing keys also used for decryption or key agreement (Test 5) with no demonstrated cross-use exploit. DSA, or SHA-1 signatures over data the attacker cannot influence. Keystore keys authorised for `DIGEST_NONE` or raw RSA on data the app constructs. Custom ECDSA without demonstrated nonce reuse but with a non-standard nonce construction. High-value keys software-backed on devices that offer a TEE or Secure Enclave. |
| **Low** | RSA 2048 for keys expected to remain valid well beyond 2030. Hardware-backed signing keys without attestation, so the backend cannot tell them from software keys. StrongBox available but unused for a high-assurance key. Signed formats without a context label where no cross-use is currently possible. |
| **Info** | RSA PKCS#1 v1.5 with SHA-256 and at least 2048 bits (recommend PSS or ECDSA for new formats). Randomised ECDSA signatures that differ between calls (expected). Deterministic signatures from RFC 6979 or Ed25519 (expected). No post-quantum migration plan. |

When reporting, give the algorithm string or constant, key size, key location (alias and security level, or software class), the exact call site, and a proof appropriate to the defect: a recovered key that verifies against the registered public key, a signature obtained through the oracle and accepted by the test backend, or the `KeyInfo`/attribute dump showing the weak authorisation. Redact recovered private keys to their first and last bytes.

## References

- OWASP MASWE — [MASWE-0010: Improper Generation of Cryptographic Signatures](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0010/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0012: Key Generation](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0012/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0044: Key Attestation](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0044/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0066: CryptoKit](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0066/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0067: CommonCrypto, SecKey and Wrapper libraries](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0067/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0069: Key Management](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0069/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0307: References to Asymmetric Key Pairs Used For Multiple Purposes](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0307/) and [MASTG-TEST-0308: Runtime Use of Asymmetric Key Pairs Used For Multiple Purposes](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0308/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-DEMO-0071](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0071/MASTG-DEMO-0071/) and [MASTG-DEMO-0072](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0072/MASTG-DEMO-0072/) (CC BY-SA 4.0)
- OWASP MASTG — legacy (MASTG v1) tests [MASTG-TEST-0014](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0014/), [MASTG-TEST-0015](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0015/) (deprecated) and [MASTG-TEST-0061](https://mas.owasp.org/MASTG/tests/ios/MASVS-CRYPTO/MASTG-TEST-0061/) (CC BY-SA 4.0)
- OWASP MASTG — techniques [MASTG-TECH-0005](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/), [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/), [MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/) (CC BY-SA 4.0)
- [NIST FIPS 186-5 — Digital Signature Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf)
- [NIST SP 800-131A Rev. 2 — Transitioning the Use of Cryptographic Algorithms and Key Lengths](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf)
- [NIST SP 800-57 Part 1 Rev. 5 — Recommendation for Key Management](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf)
- [NIST IR 8547 (initial public draft) — Transition to Post-Quantum Cryptography Standards](https://csrc.nist.gov/pubs/ir/8547/ipd)
- [NIST FIPS 204 — ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) and [FIPS 205 — SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [RFC 6979 — Deterministic Usage of DSA and ECDSA](https://www.rfc-editor.org/rfc/rfc6979), [RFC 8017 — PKCS #1 v2.2](https://www.rfc-editor.org/rfc/rfc8017), [RFC 8032 — EdDSA](https://www.rfc-editor.org/rfc/rfc8032)
- [Android Developers — Cryptography (deprecated functionality)](https://developer.android.com/privacy-and-security/cryptography#deprecated-functionality)
- [Android Developers — Android Keystore system](https://developer.android.com/privacy-and-security/keystore), [`KeyGenParameterSpec.Builder`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder), [`KeyProperties`](https://developer.android.com/reference/android/security/keystore/KeyProperties), [`KeyInfo`](https://developer.android.com/reference/android/security/keystore/KeyInfo)
- [Android Developers — Verifying hardware-backed key pairs with key attestation](https://developer.android.com/privacy-and-security/security-key-attestation)
- [Android Developers — `java.security.Signature`](https://developer.android.com/reference/java/security/Signature)
- [Apple — `SecKeyCreateSignature`](https://developer.apple.com/documentation/security/seckeycreatesignature%28_:_:_:_:%29) and [`SecKeyAlgorithm`](https://developer.apple.com/documentation/security/seckeyalgorithm)
- [Apple — CryptoKit](https://developer.apple.com/documentation/cryptokit) and [`SecureEnclave.P256.Signing.PrivateKey`](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/signing/privatekey)
- [Apple — Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
- [Apple — Establishing your app's integrity (App Attest)](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity)
- [Google Tink — Digital signatures](https://developers.google.com/tink/digital-signature)
- [CWE-323](https://cwe.mitre.org/data/definitions/323.html), [CWE-326](https://cwe.mitre.org/data/definitions/326.html), [CWE-327](https://cwe.mitre.org/data/definitions/327.html), [CWE-330](https://cwe.mitre.org/data/definitions/330.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
