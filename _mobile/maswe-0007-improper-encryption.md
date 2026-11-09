---
title: "Improper Encryption (MASWE-0007)"
date: 2026-11-09 12:29:00 +0000
subcategory: crypto
summary: "Testing mobile encryption for broken ciphers, ECB, reused IVs and nonces, weak padding, multi-purpose keys and stale providers: tests, demos and fixes."
refs: [MASWE-0007, MASVS-CRYPTO-1, MASVS-CRYPTO-2, CWE-208, CWE-323, CWE-325, CWE-326, CWE-327, CWE-329, CWE-780]
tags: [android, ios, masvs-crypto, aes-gcm, cipher-modes, initialization-vectors]
---

This note is part of our [MASVS-CRYPTO cryptography guide](/mobile/masvs-crypto-cryptography-guide/) and covers OWASP [MASWE-0007](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0007/): encryption that is present but does not do its job. The app calls a real cipher, the data on disk or on the wire looks random, and yet an attacker can read it, change it or forge it without the key, because the algorithm is obsolete, the mode leaks structure, the IV or nonce repeats, the padding gives the game away, or one key is doing several jobs. It is the largest weakness in the CRYPTO series and the one you will report most often. You will find a working background on algorithms, modes, padding and nonces; the Android JCA, Android Keystore, CommonCrypto, CryptoKit and Tink mechanisms; all ten OWASP tests (two of which are still placeholders upstream, so we supply the procedure); supplementary checks for the modes of introduction that OWASP does not yet test; secure Kotlin and Swift; and severity guidance. Key storage is covered in [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/) and is not repeated here.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Background: algorithms, modes, padding and nonces (Guler Tech)](#background-algorithms-modes-padding-and-nonces-guler-tech)
  - [Android: Security Provider (MASTG-KNOW-0011)](#android-security-provider-mastg-know-0011)
  - [Android: Key Generation and Cipher Configuration (MASTG-KNOW-0012)](#android-key-generation-and-cipher-configuration-mastg-know-0012)
  - [iOS: CryptoKit (MASTG-KNOW-0066)](#ios-cryptokit-mastg-know-0066)
  - [iOS: CommonCrypto, SecKey and Wrapper Libraries (MASTG-KNOW-0067)](#ios-commoncrypto-seckey-and-wrapper-libraries-mastg-know-0067)
  - [Both platforms: Third-Party Libraries and Tink (MASTG-KNOW-0068)](#both-platforms-third-party-libraries-and-tink-mastg-know-0068)
- [Tests](#tests)
  - [MASTG-TEST-0221: Broken Symmetric Encryption Algorithms (Android)](#mastg-test-0221-broken-symmetric-encryption-algorithms-android)
  - [MASTG-TEST-0232: Broken Symmetric Encryption Modes (Android)](#mastg-test-0232-broken-symmetric-encryption-modes-android)
  - [MASTG-TEST-0350: Runtime Use of Broken Symmetric Encryption Modes (Android)](#mastg-test-0350-runtime-use-of-broken-symmetric-encryption-modes-android)
  - [MASTG-TEST-0309: References to Reused Initialization Vectors in Symmetric Encryption (Android)](#mastg-test-0309-references-to-reused-initialization-vectors-in-symmetric-encryption-android)
  - [MASTG-TEST-0310: Runtime Use of Reused Initialization Vectors in Symmetric Encryption (Android)](#mastg-test-0310-runtime-use-of-reused-initialization-vectors-in-symmetric-encryption-android)
  - [MASTG-TEST-0307: References to Asymmetric Key Pairs Used For Multiple Purposes (Android)](#mastg-test-0307-references-to-asymmetric-key-pairs-used-for-multiple-purposes-android)
  - [MASTG-TEST-0308: Runtime Use of Asymmetric Key Pairs Used For Multiple Purposes (Android)](#mastg-test-0308-runtime-use-of-asymmetric-key-pairs-used-for-multiple-purposes-android)
  - [MASTG-TEST-0312: References to Explicit Security Provider in Cryptographic APIs (Android)](#mastg-test-0312-references-to-explicit-security-provider-in-cryptographic-apis-android)
  - [MASTG-TEST-0210: Broken Symmetric Encryption Algorithms (iOS)](#mastg-test-0210-broken-symmetric-encryption-algorithms-ios)
  - [MASTG-TEST-0317: Broken Symmetric Encryption Modes (iOS)](#mastg-test-0317-broken-symmetric-encryption-modes-ios)
  - [Supplementary checks (Guler Tech methodology)](#supplementary-checks-guler-tech-methodology)
- [Best practices](#best-practices)
  - [MASTG-BEST-0005: Use Secure Encryption Modes](#mastg-best-0005-use-secure-encryption-modes)
  - [MASTG-BEST-0009: Use Secure Encryption Algorithms](#mastg-best-0009-use-secure-encryption-algorithms)
  - [MASTG-BEST-0020: Update the GMS Security Provider](#mastg-best-0020-update-the-gms-security-provider)
  - [Secure implementation](#secure-implementation)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

MASWE-0007 applies when data is encrypted in a way that leaves it recoverable or forgeable without the key. The OWASP requirement is short — "the app properly encrypts sensitive data" — but "properly" covers every parameter of the operation, and the ciphertext is only as strong as the weakest of them:

| Component | Weak choices you will meet | What breaks | Where this note tests it |
|---|---|---|---|
| Algorithm | DES, 3DES (TDEA), RC4, RC2, Blowfish, CAST5 | Exhaustive key search, birthday collisions on 64-bit blocks, keystream biases | TEST-0221, TEST-0210 |
| Mode of operation | ECB; CBC or CTR without a MAC | Pattern leakage, block cut-and-paste, bit flipping, padding oracles | TEST-0232, TEST-0350, TEST-0317, supplementary S2 |
| IV or nonce | Constant, all-zero, derived from the key, predictable, repeated | Keystream reuse, equal-prefix leakage, GCM authentication-key recovery | TEST-0309, TEST-0310, supplementary S1 |
| Padding | PKCS#7 on unauthenticated CBC; RSA PKCS#1 v1.5 or no padding | Vaudenay and Bleichenbacher oracles, deterministic and malleable RSA | Supplementary S2, S3 |
| Key length | Symmetric keys under 128 bits, RSA under 2048 bits | Brute force, factoring | Supplementary S5; generation in [MASWE-0013](/mobile/maswe-0013-improper-key-generation/) |
| Key usage | One key pair for encryption and signing | Cross-protocol attacks: a decryption oracle becomes a signing oracle | TEST-0307, TEST-0308 |
| Implementation | Removed, outdated or home-made security providers; XOR or Base64 as "encryption" | Known implementation bugs; no security at all | TEST-0312, supplementary S4 |

The weakness is mapped to MASVS-CRYPTO-1 (strong cryptography used according to best practice) and MASVS-CRYPTO-2 (key management, through the key-separation tests), to the L1, L2 and EUDIW profiles, and to seven CWEs:

- CWE-327 Use of a Broken or Risky Cryptographic Algorithm, and CWE-326 Inadequate Encryption Strength.
- CWE-329 Generation of Predictable IV with CBC Mode, and CWE-323 Reusing a Nonce, Key Pair in Encryption.
- CWE-325 Missing Cryptographic Step (typically the missing MAC).
- CWE-780 Use of RSA Algorithm without OAEP.
- CWE-208 Observable Timing Discrepancy (timing-based padding and MAC oracles).

Two things make this weakness different from most others in MASVS. First, a static hit is rarely enough on its own: `Cipher.getInstance("AES")` in a third-party SDK that never runs, or 3DES in an ICAO e-passport reader where the protocol mandates it, is not the same finding as ECB on a session token. Every OWASP test here ends with "further validation required", and you should take that literally. Second, the exploit often lives on the other side of the app: a padding oracle is usually the **backend** decrypting what the app sent, and a forged ECB token is accepted by the **server**. When you find broken encryption in the app, ask where the ciphertext goes and who decrypts it.

## Modes of Introduction

**Broken algorithms.** DES, 3DES, RC4, RC2 and Blowfish survive in mobile code because they are still accepted by the platform APIs (`Cipher.getInstance("DESede")`, `kCCAlgorithm3DES`), because a backend or a hardware partner was built around them, and because tutorials and Stack Overflow answers written a decade ago still rank well. The OWASP page lists them as "deprecated or disallowed by NIST or other standards", which is accurate for all of them; the [background section](#background-algorithms-modes-padding-and-nonces-guler-tech) gives the exact status of each.

**Predictable or reused IVs and nonces.** The IV is the parameter developers most often get wrong because the API lets them pass anything. Typical patterns: `IvParameterSpec(ByteArray(16))` (all zero), an IV string copied from a blog post, the first 16 bytes of the key, a timestamp, a counter kept in memory that resets when the app restarts, or a correct random IV generated once at install time and reused for every message. On iOS, `CCCrypt` with a `NULL` IV silently uses an all-zero IV in CBC mode. For AEAD modes, the related mistake is a truncated authentication tag (`GCMParameterSpec(32, iv)`).

**Risky padding.** PKCS#7 padding on AES-CBC is harmless if the ciphertext is authenticated before it is decrypted, and dangerous if it is not and the decrypting party reveals — by an error code, an exception message or a timing difference — whether the padding was valid. RSA PKCS#1 v1.5 encryption padding has the same structural problem (Bleichenbacher), and RSA with no padding is deterministic and malleable.

**Broken modes of operation.** ECB encrypts every 16-byte block independently, so equal plaintext blocks give equal ciphertext blocks. The MASWE page says NIST disallows AES-ECB; strictly, ECB is still in SP 800-38A, but NIST announced in 2023 that it would revise SP 800-38A and its analysis in NIST IR 8459 singles out ECB as unsuitable for general-purpose confidentiality. In practice no current guidance accepts ECB for encrypting data. On Android the most common way to get ECB is not to ask for it but to ask for `"AES"` with no mode, which defaults to ECB.

**Insufficient key length.** AES keys are always at least 128 bits, so this mode mostly concerns DES (56 effective bits), two-key 3DES, short Blowfish or RC4 keys, and RSA moduli below 2048 bits. Key generation itself is the subject of [MASWE-0013](/mobile/maswe-0013-improper-key-generation/).

**Insecure or wrong key usage.** One key, one purpose (NIST SP 800-57 Part 1 Rev. 5, section 5.2). The mobile pattern is an Android Keystore RSA key generated with `PURPOSE_ENCRYPT | PURPOSE_DECRYPT | PURPOSE_SIGN | PURPOSE_VERIFY` "to keep things simple", or a single symmetric key used both for AES-CBC and for the HMAC that protects it.

**Non-cryptographic operations.** XOR with a constant, Base64, ROT-n, byte shuffling, or a home-made cipher. These are reversible by anyone who reads the code, so they provide no confidentiality. Treat a method called `encrypt` that contains no call to a real cipher as a finding until proven otherwise.

## Impact

- **Compromise of sensitive data.** Plaintext recovery from DES by brute force, from RC4 or reused CTR/GCM keystreams by XOR, from ECB by pattern analysis or dictionary matching on short values (PINs, account numbers), and from unauthenticated CBC through a padding oracle. Data at rest in backups or synced storage and data in transit to the backend are both in scope.
- **Undetected modification.** Without integrity, an attacker flips bits in CBC or CTR ciphertext to change the plaintext predictably (for example `role=user` to `role=adm` in a token), or rearranges ECB blocks.
- **Authentication or authorisation bypass.** Forged ciphertexts, tokens or licence blobs accepted by the app or its backend; GCM forgeries after a nonce repeat; signatures forged through a decryption oracle on a multi-purpose RSA key.
- **Compliance failure.** Use of disallowed algorithms (DES, 3DES for encryption after 2023, PKCS#1 v1.5 key transport after 2023) is itself a failure against NIST SP 800-131A Rev. 2, PCI DSS "strong cryptography" requirements and similar regimes, even where practical exploitation is hard.

## Mitigations

- **Use authenticated encryption.** AES-GCM (`AES/GCM/NoPadding` with a 128-bit tag) or ChaCha20-Poly1305. If CBC is unavoidable for compatibility, apply encrypt-then-MAC with an independent HMAC key and verify the MAC in constant time before decrypting. For RSA, use OAEP, and use RSA only to transport a symmetric key.
- **Manage IVs and nonces properly.** A fresh IV from a CSPRNG for every CBC encryption; a nonce that never repeats under the same key for CTR, GCM and ChaCha20-Poly1305. The simplest way to get this right is to never pass an IV on encryption: let the Android Keystore or CryptoKit generate it, and store it with the ciphertext. On Android use `GCMParameterSpec` (not `IvParameterSpec`) for GCM.
- **Use sufficiently long keys.** AES-128 at minimum (AES-256 for long-lived data is cheap), RSA 2048 at minimum and 3072 for data or keys that must stay protected beyond 2030.
- **Use each key for one purpose.** Separate keys (or key pairs) for encryption, MAC, signing and key wrapping; enforce it with Keystore purposes so the hardware refuses misuse.
- **Do not expose cryptographic errors.** Return one generic failure for every decryption problem, and make the decryption path take the same time whether the padding, the MAC or the plaintext was wrong.
- **Rely on vetted, maintained implementations.** The platform default provider (Conscrypt on Android), CryptoKit on iOS, or a misuse-resistant library such as Tink. Signature verification is covered in [MASWE-0011](/mobile/maswe-0011-improper-signature-verification/).

## Knowledge

The live MASWE-0007 page links two Knowledge items, both Android: MASTG-KNOW-0011 (Security Provider) and MASTG-KNOW-0012 (Key Generation). We add three iOS Knowledge pages from the same MASTG category (KNOW-0066, KNOW-0067 and KNOW-0068) because the iOS tests depend on them, and we open with a background section of our own, because you cannot evaluate a mode or a nonce finding without knowing what breaks and why. Sections marked **supplementary** are not linked from the MASWE page.

### Background: algorithms, modes, padding and nonces (Guler Tech)

Supplementary, Guler Tech methodology. Sources are named inline.

#### Algorithm status

| Algorithm | Block and key size | Status | Why it is weak |
|---|---|---|---|
| DES | 64-bit block, 56-bit effective key | FIPS 46-3 withdrawn by NIST in 2005 | Exhaustive key search has been practical since the EFF's dedicated DES cracker in 1998; today it is a commodity service |
| Two-key 3DES (TDEA) | 64-bit block, 112-bit key | Disallowed for encryption after 2015 (SP 800-131A) | Roughly 80-bit security against known attacks, plus the 64-bit block problem below |
| Three-key 3DES (TDEA) | 64-bit block, 168-bit key (about 112-bit security) | SP 800-67 Rev. 2 withdrawn 1 January 2024; encryption disallowed after 2023, decryption allowed only for legacy data (SP 800-131A Rev. 2) | 64-bit block: birthday collisions after about 2^32 blocks (Sweet32, 2016); SP 800-67 Rev. 2 had already limited a key to 2^20 blocks |
| RC4 | Stream cipher, 40–2048-bit key, no IV | Never NIST-approved; prohibited in TLS by RFC 7465 (2015) | Statistical biases in the keystream allow plaintext recovery (AlFardan et al. 2013; RC4 NOMORE 2015). With no IV, the same key always produces the same keystream |
| RC2 | 64-bit block | Never approved; obsolete | Small block, related-key weaknesses, exportable 40-bit variants |
| Blowfish | 64-bit block, 32–448-bit key | Never FIPS-approved | Sweet32 applies; its designer recommends successors |
| CAST5 (CAST-128) | 64-bit block | Not approved | Small block |
| AES | 128-bit block, 128/192/256-bit key | FIPS 197; approved | No practical attack on the cipher; the risk is in how it is used |
| ChaCha20-Poly1305 | Stream cipher plus MAC, 256-bit key, 96-bit nonce | RFC 8439; not a NIST algorithm but standard in TLS 1.3 and widely recommended | Fast in software, constant-time by design; nonce rules as for GCM |

Two practical notes for rating. Sweet32 needs tens of gigabytes encrypted under one key before collisions become likely, which local mobile storage rarely approaches; 3DES on a phone is therefore mostly a compliance and hygiene finding unless the same key encrypts a high-volume stream. DES and RC4 are different: DES falls to brute force regardless of volume, and RC4 with a fixed key (which is how mobile code tends to use it, since the JCA has no RC4 IV) reuses its keystream on every message.

On key length and quantum computing: MASTG-TEST-0210 says AES-128 "is insufficient in the face of quantum computing attacks". NIST does not take that position. Its transition draft, NIST IR 8547, keeps AES-128, AES-192 and AES-256 approved; the quantum threat it addresses is to RSA and elliptic-curve cryptography. Choosing AES-256 for data that must stay confidential for decades is reasonable margin, not a requirement, and AES-128 is not a finding.

#### Modes of operation

**ECB** encrypts each block on its own: `C_i = E_K(P_i)`. Equal plaintext blocks give equal ciphertext blocks, so structure leaks (the classic illustration is an ECB-encrypted bitmap in which the image is still visible). ECB also has no integrity and no binding between blocks: an attacker can delete, repeat or swap 16-byte blocks, which matters for any token whose fields align to block boundaries. If the attacker can get the app or server to encrypt chosen data alongside a secret (an "ECB oracle"), the secret can be recovered one byte at a time. The one defensible use — encrypting a single block of random data, such as wrapping one random key — is better done with AES Key Wrap (RFC 3394, SP 800-38F).

**CBC** chains blocks: `C_i = E_K(P_i XOR C_(i-1))`, with `C_0` the IV. SP 800-38A (Appendix C) requires the IV to be **unpredictable** for each encryption, not merely unique. A fixed IV makes equal plaintext prefixes produce equal ciphertext prefixes; a predictable IV enables chosen-plaintext attacks (the BEAST attack on TLS 1.0 exploited exactly this). CBC has no integrity: flipping a bit in `C_(i-1)` flips the same bit in `P_i` (and garbles `P_(i-1)`), and flipping a bit in the IV changes the first plaintext block with no collateral damage at all. Worst of all is the **padding oracle** (Vaudenay, 2002; made practical against web frameworks by Rizzo and Duong, 2010): if the decrypting party reveals whether PKCS#7 padding was valid, an attacker can decrypt any ciphertext with at most 256 queries per byte, and can also encrypt chosen plaintext. The signal can be a distinct error message, a different HTTP status, a `BadPaddingException` mapped to a different response, or a timing difference.

**CTR** turns the block cipher into a stream cipher: `C_i = P_i XOR E_K(nonce || counter_i)`. Every counter block must be unique across all messages under the key (SP 800-38A, section 6.5). If two messages share a nonce, `C1 XOR C2 = P1 XOR P2`; anyone who knows or guesses one plaintext gets the other, and short structured messages can be separated by crib-dragging. CTR is fully malleable: flipping ciphertext bits flips exactly those plaintext bits.

**GCM** (SP 800-38D) is CTR encryption plus a GHASH-based MAC keyed with `H = E_K(0^128)`. It is the default you should expect in a modern app, and its rules are strict:

- **IV length.** 96 bits (12 bytes) is the recommended and efficient length. Other lengths are processed through GHASH, which weakens the uniqueness guarantees; there is no reason to use them.
- **Uniqueness.** The probability that any IV repeats under one key must not exceed 2^-32. With the deterministic construction (a fixed field plus an invocation counter) that means the counter must never repeat, across restarts, reinstalls and restored backups. With random 96-bit IVs (the "RBG-based construction") it means **no more than 2^32 invocations per key** (SP 800-38D, section 8.3). For a mobile app that is rarely a practical limit, but it is the reason long-lived high-volume keys need rotation.
- **Per-invocation limit.** At most 2^39 − 256 bits (about 64 GiB) of plaintext per encryption.
- **Tag length.** 128, 120, 112, 104 or 96 bits; 64- and 32-bit tags only under the restrictions in Appendix C. In Java the tag length is the first argument of `GCMParameterSpec(tLen, iv)` and is in **bits**: use 128.
- **Nonce reuse is catastrophic, not just bad.** A repeated nonce leaks the XOR of the plaintexts as with CTR, and in addition two tags under the same nonce give a polynomial equation in `H` whose roots an attacker can compute (Joux's "forbidden attack", 2006). With `H` known, the attacker can forge valid tags for any ciphertext under any nonce for which they have seen one valid message. Böck et al. (2016) found TLS servers in the wild doing exactly this. A GCM nonce repeat therefore destroys confidentiality **and** integrity.

**ChaCha20-Poly1305** (RFC 8439) uses a 256-bit key and a 96-bit nonce. Poly1305 is a one-time MAC whose key is derived from the nonce, so a nonce repeat leaks the keystream and the Poly1305 key, allowing forgeries — the same consequence as GCM. The random-nonce budget is also comparable. XChaCha20-Poly1305 (libsodium, 192-bit nonce) makes random nonces safe for practically unlimited messages, which is why libsodium-based code favours it. On Android, Conscrypt exposes `ChaCha20/Poly1305/NoPadding` from API 28; it is not available for Android Keystore keys. On iOS it is CryptoKit's `ChaChaPoly`.

**Nonce-misuse-resistant AEADs** such as AES-GCM-SIV (RFC 8452) and AES-SIV (RFC 5297) degrade gracefully on a nonce repeat: they leak only whether two messages were identical. Tink offers them as key templates, and AES-SIV is what Tink's deterministic AEAD uses. They are the right answer when a design cannot guarantee unique nonces.

#### Padding

**PKCS#7** (called `PKCS5Padding` in the JCA for historical reasons — for AES it is PKCS#7) is only dangerous when combined with unauthenticated CBC and an oracle, as above. GCM, CTR and ChaCha20 need no padding (`NoPadding`).

**RSA encryption** has three padding options in practice:

- **No padding ("textbook RSA", `RSA/ECB/NoPadding`, `.rsaEncryptionRaw`).** Deterministic (equal plaintexts give equal ciphertexts, so small value spaces can be brute-forced with the public key) and multiplicatively malleable. Never acceptable for encryption.
- **PKCS#1 v1.5 (`PKCS1Padding`, `.rsaEncryptionPKCS1`).** Vulnerable to Bleichenbacher's adaptive chosen-ciphertext attack (1998) whenever the decrypting side reveals padding validity; the attack keeps returning (ROBOT, 2017, found it in major TLS stacks). NIST SP 800-131A Rev. 2 disallows PKCS#1 v1.5 for key transport after 2023. CWE-780 covers RSA without OAEP.
- **OAEP (`OAEPWithSHA-256AndMGF1Padding`, `.rsaEncryptionOAEPSHA256`).** The scheme specified for RSA key transport in NIST SP 800-56B Rev. 2. Implementations must still avoid distinguishable errors (Manger's attack, 2001), but OAEP is the correct choice. RSA can only encrypt a short message (190 bytes for a 2048-bit key with SHA-256 OAEP), so use it to wrap a random AES key, or use a hybrid scheme such as ECIES or HPKE.

In mobile apps, the RSA decryption usually happens on the server: the app encrypts a session key or a credential to a backend public key. The device holding PKCS#1 v1.5 code is then the *client* of the vulnerable operation, and the oracle (if any) is the backend. Test the backend's error behaviour, with authorisation, before rating.

#### Integrity and key separation

Encryption without authentication is the root cause of most of the attacks above. When CBC or CTR must be used, the construction is **encrypt-then-MAC**: encrypt, compute HMAC-SHA256 over the IV and ciphertext (and any associated data) with a **separate** key, verify the MAC first with a constant-time comparison, and only then decrypt. MAC-then-encrypt and encrypt-and-MAC are both weaker. Reusing the encryption key as the MAC key, particularly AES-CBC with CBC-MAC under one key, breaks the MAC.

Key separation applies equally to asymmetric keys. With raw RSA, signing and decrypting are the same operation (`m^d mod n`), so a service that decrypts arbitrary input for you is also signing arbitrary input for you; with padded RSA the attack is less direct but well documented — ROBOT showed that a Bleichenbacher decryption oracle can be used to forge signatures under the same key. NIST SP 800-57 Part 1 Rev. 5 (section 5.2) requires a key to be used for a single purpose.

### Android: Security Provider (MASTG-KNOW-0011)

Source: [MASTG-KNOW-0011](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0011/), extended with the Android documentation.

**What it is.** The Java Cryptography Architecture separates the API (`Cipher`, `Mac`, `Signature`, `KeyGenerator`, `SecureRandom`) from the implementation, which is supplied by a `java.security.Provider`. When you call `Cipher.getInstance("AES/GCM/NoPadding")` without naming a provider, the JCA walks the registered providers in priority order and takes the first one that implements the transformation. On Android that is normally **AndroidOpenSSL**, the Conscrypt provider backed by BoringSSL, which Google maintains and (from Android 10) ships as an updatable APEX module.

**What a device has.** The MASTG page lists the providers on an Android 9 emulator: `AndroidNSSP`, `AndroidOpenSSL`, `CertPathProvider`, `AndroidKeyStoreBCWorkaround`, `BC` (Bouncy Castle 1.57), `HarmonyJSSE`, `AndroidKeyStore`. Lists differ between Android versions and OEM builds. You can print them on the device under test with Frida:

```javascript
// list-providers.js
Java.perform(function () {
  const Security = Java.use('java.security.Security');
  const providers = Security.getProviders();
  for (let i = 0; i < providers.length; i++) {
    console.log((i + 1) + ': ' + providers[i].getName() + ' - ' + providers[i].getInfo());
  }
});
```

```bash
frida -U -f com.example.app -l list-providers.js
```

On a device with Google Play services where the app has called `ProviderInstaller`, you will see `GmsCore_OpenSSL` at position 1: that is the updated provider from MASTG-BEST-0020.

**How providers have changed.** These are the changes that turn an explicit provider name into a bug (they are the background to MASTG-TEST-0312):

| Android version | Change |
|---|---|
| 7.0 (API 24) | The `Crypto` provider (whose main use was the `SHA1PRNG` seeding anti-pattern) deprecated |
| 9 (API 28) | `Crypto` provider removed. Bouncy Castle implementations of algorithms that Conscrypt also provides deprecated: apps targeting API 28+ that request them with `getInstance(..., "BC")` get `NoSuchAlgorithmException` |
| 10 (API 29) | Conscrypt delivered as a Mainline module, so the default provider is patched through Google Play system updates on supported devices |
| 12 (API 31) | Most of those deprecated Bouncy Castle algorithms removed altogether |

The point for testers: an app that names a provider either pins itself to an implementation that may be missing, unmaintained or vulnerable on the device, or bypasses the patched default. An app that **inserts** its own provider at position 1 (`Security.insertProviderAt(BouncyCastleProvider(), 1)`) changes every unnamed `getInstance` call in the process, including those in third-party SDKs, without naming a provider anywhere — a pattern TEST-0312's rule does not catch.

**Older devices.** For apps that must support very old Android versions, the MASTG suggests bundling Conscrypt (`org.conscrypt:conscrypt-android`) and registering it with `Security.addProvider(Conscrypt.newProvider())` (or `insertProviderAt(..., 1)` to make it the default), rather than bundling the much larger Bouncy Castle. The MASTG page also recalls that since July 2016 Google Play has rejected apps that ship vulnerable OpenSSL versions; the same scrutiny applies to any native crypto library you find in `lib/`.

### Android: Key Generation and Cipher Configuration (MASTG-KNOW-0012)

Source: [MASTG-KNOW-0012](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0012/). We cover this page in depth, including its errata, in the [MASWE-0003 note](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/#android-key-generation-mastg-know-0012), together with the Keystore, StrongBox and attestation material. Here we keep only what decides whether **encryption** is configured correctly.

**Transformation strings.** `Cipher.getInstance` takes `"Algorithm/Mode/Padding"`. The algorithm alone is accepted, and the provider then fills in its defaults:

| What the code asks for | What it gets | Verdict |
|---|---|---|
| `"AES"` | `AES/ECB/PKCS5Padding` (documented by Android; flagged by Android Lint's `GetInstance` check) | ECB: finding |
| `"DES"`, `"DESede"`, `"Blowfish"` | The algorithm with the provider's default mode, ECB in the common providers | Broken algorithm and mode |
| `"RSA"` | Provider-dependent padding; on Android the default has historically been no padding at all, unlike desktop Java | Never acceptable: always specify OAEP |
| `"AES/CBC/PKCS5Padding"` | CBC; if `init(ENCRYPT_MODE, key)` is called without an IV, the provider generates a random IV, which you must read with `getIV()` | Acceptable only with a MAC (S2) |
| `"AES/GCM/NoPadding"` | GCM; without parameters on encryption the provider generates a random 12-byte IV and uses a 128-bit tag | Correct |
| `"RSA/ECB/OAEPWithSHA-256AndMGF1Padding"` | OAEP; the `ECB` is a placeholder (RSA has no block mode) | Correct; see the MGF1 note in [Secure implementation](#secure-implementation) |

Algorithm names are case-insensitive (`"desede"` works), and jadx inlines `static final String` constants, so a `KeyProperties.BLOCK_MODE_ECB` reference appears as the literal `"ECB"` in decompiled code. Transformations held in instance fields (Kotlin `private val TRANSFORMATION = "..."`) are not inlined, which is why regex-only searches miss them.

**IV handling.** On encryption you should normally *not* supply an IV: call `init(ENCRYPT_MODE, key)`, read `cipher.iv`, and store it with the ciphertext. On decryption you must supply it: `IvParameterSpec(iv)` for CBC and CTR, `GCMParameterSpec(128, iv)` for GCM. Conscrypt still accepts `IvParameterSpec` for GCM for backward compatibility (assuming a 128-bit tag), but the MASWE mitigations rightly ask for `GCMParameterSpec`. Some providers refuse to re-initialise the **same** `Cipher` object for GCM encryption with the same key and IV; nothing stops a fresh `Cipher` instance from doing it, so that check does not protect against a hardcoded nonce. Android's password-based (`PBEWith...`) ciphers assume an all-zero IV if neither the key nor the parameters provide one; the Android cryptography guide tells you to always pass an explicit IV.

**Keystore enforcement.** For keys in the Android Keystore, the `KeyGenParameterSpec` (or `KeyProtection` for imported keys) is an authorisation list enforced by the keystore and, on hardware-backed devices, by the TEE or StrongBox. Four properties matter for encryption:

- **Purposes** (`PURPOSE_ENCRYPT = 1`, `PURPOSE_DECRYPT = 2`, `PURPOSE_SIGN = 4`, `PURPOSE_VERIFY = 8`, `PURPOSE_WRAP_KEY = 32`, plus `PURPOSE_AGREE_KEY = 64` and `PURPOSE_ATTEST_KEY = 128` from API 31). Using a key outside its purposes throws at `init`.
- **Block modes and paddings** (`setBlockModes`, `setEncryptionPaddings`). A key restricted to `BLOCK_MODE_GCM` cannot be used with CBC or ECB.
- **`setRandomizedEncryptionRequired`** (default `true`). Android requires the encryption to be IND-CPA — the same plaintext must give a different ciphertext each time. Concretely: an AES key that allows ECB cannot be generated or imported for `PURPOSE_ENCRYPT`; the Keystore **generates the IV itself** on encryption and rejects a caller-provided one; and RSA encryption without padding is refused. Decryption is not restricted, so an ECB key for `PURPOSE_DECRYPT` only is accepted. MASTG-DEMO-0058 shows all three behaviours. When you find `setRandomizedEncryptionRequired(false)` in an app, you have almost certainly found ECB, a fixed or derived IV, or textbook RSA — follow it.
- **Supported transformations.** AES keys support `AES/GCM/NoPadding`, `AES/CBC/NoPadding`, `AES/CBC/PKCS7Padding`, `AES/CTR/NoPadding` and `AES/ECB/NoPadding` or `PKCS7Padding` (note the Keystore uses the name `PKCS7Padding`); RSA keys support `NoPadding`, `PKCS1Padding` and the OAEP variants. From API 28 the Keystore also accepts 3DES keys (`KeyProperties.KEY_ALGORITHM_3DES`) for legacy interoperability. "It is in the Keystore" does not mean "it is configured well".

**Legacy RSA keys.** Keys created with the deprecated `KeyPairGeneratorSpec` (the pre-API-23 mechanism shown on the MASTG page) are created with permissive authorisations for backward compatibility — all purposes and paddings, no randomised-encryption requirement. Treat any use of `KeyPairGeneratorSpec` as a multi-purpose key for TEST-0307. EC keys in the Keystore cannot encrypt at all; they sign and, from API 31, agree keys.

**Jetpack Security.** `EncryptedFile` and `EncryptedSharedPreferences` (`androidx.security:security-crypto`) used Tink with AES-256-GCM (and AES-256-SIV for preference keys) under a Keystore master key; the cryptography was sound. The library has since been deprecated. Existing use is not a MASWE-0007 finding, but new code should use Tink directly or the Keystore with AES-GCM, and you should note the deprecation in the report.

### iOS: CryptoKit (MASTG-KNOW-0066)

Supplementary. Source: [MASTG-KNOW-0066](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0066/), extended with Apple's CryptoKit documentation.

CryptoKit (iOS 13+) is Apple's Swift framework over corecrypto, the FIPS-validated library used across Apple's platforms. For encryption it offers exactly two algorithms, both AEAD: `AES.GCM` (128-, 192- or 256-bit `SymmetricKey`) and `ChaChaPoly` (256-bit key). There is no ECB, no CBC, no unauthenticated CTR, no DES and no RC4, which is why MASTG-TEST-0210 and MASTG-TEST-0317 note that CryptoKit "is not vulnerable" to them. It also offers HMAC, SHA-2 (with MD5 and SHA-1 under `Insecure`), key agreement on Curve25519 and NIST P-256/P-384/P-521 (KNOW-0066 writes "P-512"; the curve is P-521), ECDSA and Ed25519 signatures, HKDF, `AES.KeyWrap` (iOS 15+) and HPKE (iOS 17+). CryptoKit does not do RSA; that is the Security framework (`SecKey`).

The API makes the safe path the default:

- `AES.GCM.seal(plaintext, using: key)` and `ChaChaPoly.seal(...)` generate a fresh random 96-bit nonce when you do not pass one, and always produce a 128-bit tag.
- The result is a `SealedBox` with `nonce`, `ciphertext` and `tag`. `combined` gives `nonce || ciphertext || tag` (it is optional for `AES.GCM` because it is only defined for the standard 12-byte nonce; for `ChaChaPoly` it is not optional).
- `AES.GCM.open(box, using: key)` verifies the tag before returning any plaintext and throws `CryptoKitError.authenticationFailure` otherwise.
- Associated data is passed with `authenticating:`.

What can still go wrong is what the developer supplies, and that is what you look for in a CryptoKit app:

- **An explicit nonce.** `AES.GCM.Nonce(data: someConstant)` or a nonce built from a counter, timestamp or the key, passed via `nonce:`. Any explicit nonce deserves a look; a constant one is a nonce-reuse finding with the GCM consequences above.
- **Where the key comes from.** `SymmetricKey(data:)` with constant bytes is a hardcoded key (MASWE-0003); `SymmetricKey(data: SHA256.hash(data: password))` is an unsalted, unstretched password-derived key ([MASWE-0014](/mobile/maswe-0014-improper-key-derivation/)).
- **`swift-crypto` extras.** Apple's open-source `swift-crypto` package mirrors the CryptoKit API, but its `_CryptoExtras` module adds lower-level primitives outside CryptoKit's safe defaults (including unauthenticated AES modes and RSA). Review those calls with the same scrutiny as CommonCrypto.

### iOS: CommonCrypto, SecKey and Wrapper Libraries (MASTG-KNOW-0067)

Supplementary. Source: [MASTG-KNOW-0067](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0067/), extended with the `CommonCryptor.h` header documentation.

**CommonCrypto** is the C library in `libcommonCrypto.dylib`. Its symmetric API is in `CommonCryptor.h`, and it is where nearly all iOS findings for this weakness come from because it exposes the broken options that CryptoKit removed.

The one-shot function:

```c
CCCryptorStatus CCCrypt(
    CCOperation op,         /* kCCEncrypt = 0, kCCDecrypt = 1 */
    CCAlgorithm alg,        /* see table */
    CCOptions options,      /* bitmask: kCCOptionPKCS7Padding = 1, kCCOptionECBMode = 2 */
    const void *key, size_t keyLength,
    const void *iv,         /* optional initialization vector */
    const void *dataIn, size_t dataInLength,
    void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved);
```

| `CCAlgorithm` | Value | Verdict |
|---|---|---|
| `kCCAlgorithmAES128` / `kCCAlgorithmAES` | 0 | AES (the "128" is the block size; the key size comes from `keyLength`: 16, 24 or 32) |
| `kCCAlgorithmDES` | 1 | Broken |
| `kCCAlgorithm3DES` | 2 | Disallowed for encryption |
| `kCCAlgorithmCAST` | 3 | Not approved, 64-bit block |
| `kCCAlgorithmRC4` | 4 | Broken |
| `kCCAlgorithmRC2` | 5 | Broken |
| `kCCAlgorithmBlowfish` | 6 | Not approved, 64-bit block |

Two behaviours of `CCCrypt` are worth memorising:

1. **The mode is CBC unless `kCCOptionECBMode` is set.** There is no other mode in `CCCrypt`. So `CCCrypt` gives you either ECB or unauthenticated CBC.
2. **A `NULL` IV in CBC mode means an all-zero IV.** The header says so explicitly: if CBC is selected and no IV is present, a NULL (all zeroes) IV is used. Code that passes `nil` "because the IV is optional" encrypts deterministically under a fixed IV. MASTG-TEST-0317 calls CBC "more secure when used with a proper IV" — the qualification is the whole point.

The lower-level `CCCryptorCreateWithMode(op, mode, alg, padding, iv, key, keyLength, tweak, tweakLength, numRounds, options, &ref)` exposes more modes through `CCMode`: `kCCModeECB = 1`, `kCCModeCBC = 2`, `kCCModeCFB = 3`, `kCCModeCTR = 4`, `kCCModeOFB = 7`, `kCCModeXTS = 8`, `kCCModeRC4 = 9`, `kCCModeCFB8 = 10`. None of them is authenticated. As KNOW-0067 notes, GCM exists only in CommonCrypto's private SPI (`CommonCryptorSPI.h`), which App Store apps should not call; seeing `CCCryptorGCM*` symbols means the app uses a private API.

**SecKey** (Security framework) handles asymmetric encryption. `SecKeyCreateEncryptedData(publicKey, algorithm, plaintext, &error)` takes a `SecKeyAlgorithm`:

| Algorithm | Verdict |
|---|---|
| `.rsaEncryptionRaw` | Textbook RSA: finding |
| `.rsaEncryptionPKCS1` | PKCS#1 v1.5: finding (CWE-780) |
| `.rsaEncryptionOAEPSHA1` … `.rsaEncryptionOAEPSHA512` | OAEP: acceptable (prefer SHA-256 or above) |
| `.rsaEncryptionOAEPSHA256AESGCM` and siblings | Hybrid RSA-OAEP plus AES-GCM: good |
| `.eciesEncryptionCofactorVariableIVX963SHA256AESGCM` and siblings | ECIES with AES-GCM: good; the "VariableIV" variants are the ones Apple recommends |

The legacy `SecKeyEncrypt` / `SecKeyDecrypt` functions (deprecated) take a `SecPadding` instead: `kSecPaddingNone` and `kSecPaddingPKCS1` are findings, `kSecPaddingOAEP` is OAEP with SHA-1. Check support with `SecKeyIsAlgorithmSupported` before relying on an algorithm.

**Wrapper libraries.** KNOW-0067 lists IDZSwiftCommonCrypto, Heimdall, SwiftyRSA, RNCryptor and Arcane. Wrappers inherit the options of what they wrap, so evaluate the configuration they are called with: IDZSwiftCommonCrypto exposes every CommonCrypto algorithm and mode; SwiftyRSA's padding is selectable (check for PKCS#1); RNCryptor uses AES-256-CBC with HMAC-SHA256 (encrypt-then-MAC), which is sound for MASWE-0007, though its password mode uses PBKDF2 with 10,000 iterations, which is a [MASWE-0014](/mobile/maswe-0014-improper-key-derivation/) finding.

### Both platforms: Third-Party Libraries and Tink (MASTG-KNOW-0068)

Supplementary. Source: [MASTG-KNOW-0068](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0068/) (an iOS page; the same libraries appear in Android, Flutter and React Native apps).

KNOW-0068 lists CJOSE, CryptoSwift, OpenSSL (and wrappers), libsodium, Tink and Themis, and warns against unmaintained libraries and do-it-yourself cryptography. What matters for this weakness:

- **CryptoSwift** is a pure-Swift reimplementation, not a wrapper. It supports AES in ECB, CBC, CTR, GCM and other modes, plus Blowfish, Rabbit and ChaCha20. Its API makes the mode explicit — `AES(key:blockMode:padding:)` with `ECB()`, `CBC(iv:)` or `GCM(iv:mode:)` — so search for those. As the MASTG says, verify the implementation: a pure-software AES is not constant-time on all hardware.
- **OpenSSL, BoringSSL and LibreSSL**, often statically linked inside a framework or `.so`, expose every legacy cipher through `EVP_des_ede3_cbc`, `EVP_rc4`, `EVP_bf_cbc`, `EVP_aes_128_ecb` and the low-level `DES_*`, `RC4_*`, `BF_*` functions. Check the version string too (`strings libcrypto.so | grep -E '^OpenSSL [0-9]'`).
- **libsodium** (and Swift-Sodium, the libsodium JNI wrappers) is misuse-resistant by design: `crypto_secretbox` (XSalsa20-Poly1305), `crypto_aead_xchacha20poly1305_ietf_*` and `crypto_box`. The thing to check is that nonces come from `randombytes_buf` (or are generated by the "easy" API) rather than being constant.
- **Cross-platform frameworks.** In React Native and Cordova bundles, crypto-js is common: `CryptoJS.DES`, `CryptoJS.TripleDES`, `CryptoJS.RC4` and `mode: CryptoJS.mode.ECB` are direct findings, and `CryptoJS.AES.encrypt(data, "passphrase")` derives the key and IV with OpenSSL's MD5-based `EVP_BytesToKey`, which is a key-derivation finding. In Flutter, the `encrypt` package's `AESMode.ecb` is the equivalent signal.
- **Tink** (Google) is the misuse-resistant option we recommend on Android. It exposes *primitives* (AEAD, deterministic AEAD, streaming AEAD, MAC, hybrid encryption, signatures) rather than algorithms and modes, so the developer never chooses a mode, an IV or a padding. Keys live in keysets that support rotation, Tink generates the nonce for every encryption, the ciphertext carries a key-ID prefix so old data stays decryptable after rotation, and on Android `AndroidKeysetManager` keeps the keyset encrypted under an Android Keystore master key. The `AES256_GCM` template is the default choice; `AES256_GCM_SIV` (nonce-misuse resistant) and `AES256_SIV` (deterministic) cover special cases. On iOS, CryptoKit already gives you equivalent safe defaults, so Tink is less common there.
- **Themis** offers "Secure Cell" (AES-256-GCM by default) and "Secure Message" primitives across platforms; check that the default seal mode is used rather than the unauthenticated "context imprint" mode for anything that needs integrity.

## Tests

OWASP maps ten beta tests to MASWE-0007: eight for Android and two for iOS. Two of them (TEST-0309 and TEST-0310, IV reuse) are **placeholders** upstream — they have a title and a note but no procedure — so the procedures in those two sections are ours and labelled as such. The modes of introduction that no OWASP test covers yet (iOS IV and nonce reuse, CBC without integrity, RSA padding, non-cryptographic "encryption", key and tag lengths) are handled in [Supplementary checks](#supplementary-checks-guler-tech-methodology).

| Test | Platform | Type | Mode of introduction |
|---|---|---|---|
| MASTG-TEST-0221 | Android | Static | Broken algorithms |
| MASTG-TEST-0232 | Android | Static | Broken modes (ECB) |
| MASTG-TEST-0350 | Android | Dynamic | Broken modes (ECB) at runtime, including Keystore keys |
| MASTG-TEST-0309 | Android | Static (placeholder upstream) | Reused or predictable IVs |
| MASTG-TEST-0310 | Android | Dynamic (placeholder upstream) | Reused IVs at runtime |
| MASTG-TEST-0307 | Android | Static | Key pairs with multiple purposes |
| MASTG-TEST-0308 | Android | Dynamic | Key pairs used for multiple purposes at runtime |
| MASTG-TEST-0312 | Android | Static | Explicit security provider |
| MASTG-TEST-0210 | iOS | Static | Broken algorithms |
| MASTG-TEST-0317 | iOS | Static | Broken modes (ECB) |

Common prerequisites for the Android tests, so they are not repeated in every section:

- **The APK of the build under test.** `adb shell pm path com.example.app` lists the base and split APKs; `adb pull` each one. Test the release build where you can: R8 may remove dead crypto code from it, and debug-only code paths can produce false positives.
- **Decompilation** (MASTG-TECH-0013, reverse engineering Android apps; MASTG-TECH-0017, decompiling Java code): `jadx -d out/ app.apk` gives you Java sources even for Kotlin apps, which is why the OWASP semgrep rules target Java. Use `jadx-gui` for triage ("Find Usage" on a method is the fastest way to follow data flow, which is MASTG-TECH-0023, reviewing decompiled Java code).
- **Static search** (MASTG-TECH-0014): `semgrep` (MASTG-TOOL-0110) and `grep`. Exclude framework packages from noisy searches: `--exclude-dir` with semgrep or `grep -v '^out/sources/(androidx|kotlin|kotlinx|com/google/android)/'`.
- **Dynamic tests:** a rooted device or emulator with a matching `frida-server` (MASTG-TOOL-0001), the app installed with `adb install` (MASTG-TECH-0005), and hooks applied as in MASTG-TECH-0043 (method hooking). OWASP's newer demos use **frooky** (MASTG-TOOL-0145), a Frida-based tool that takes JSON hook definitions and writes NDJSON; install it with `pip install frooky`. On a non-rootable device, repackage the app with the Frida gadget instead.

### MASTG-TEST-0221: Broken Symmetric Encryption Algorithms (Android)

Source: [MASTG-TEST-0221](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0221/). Type: static (code), manual review. Best practice: MASTG-BEST-0009.

#### Overview

The test looks for symmetric encryption with DES, 3DES, RC4, Blowfish and their relatives. On Android those are selected by name through three JCA factories:

- `Cipher.getInstance(transformation)` — the operation itself.
- `SecretKeyFactory.getInstance(algorithm)` — converting key material, for example `DESKeySpec` or `DESedeKeySpec` into a `SecretKey`.
- `KeyGenerator.getInstance(algorithm)` — generating a key for the algorithm.

Any of the three naming a broken algorithm is a candidate. The status of each algorithm is in the [background table](#algorithm-status); Android's own guidance on [broken or risky cryptographic algorithms](https://developer.android.com/privacy-and-security/risks/broken-cryptographic-algorithm) says the same.

#### Prerequisites

The common Android prerequisites above. Optional: `readelf` or `nm` from the Android NDK or binutils for native libraries.

#### Steps

1. **Decompile** the app: `jadx -d out/ app.apk`.

2. **Run the OWASP semgrep rule** (`mastg-android-broken-encryption-algorithms.yaml`):

   ```yaml
   rules:
     - id: mastg-android-broken-encryption-algorithms
       languages:
         - java
       severity: WARNING
       metadata:
         summary: This rule looks for broken encryption algorithms.
       message: "[MASVS-CRYPTO-1] Broken encryption algorithms found in use."
       pattern-regex: Cipher\.getInstance\("?(DES|DESede|RC4|Blowfish)(/[A-Za-z0-9]+(/[A-Za-z0-9]+)?)?"?\)
   ```

   ```bash
   semgrep -c mastg-android-broken-encryption-algorithms.yaml out/sources/
   ```

   The rule is a regular expression over `Cipher.getInstance` with a string literal. It misses lower-case names, `RC2`, `ARCFOUR`, `PBEWith...` ciphers built on DES, RC2 or RC4, `SecretKeyFactory` and `KeyGenerator` calls, and transformations held in fields or variables.

3. **Widen the sweep** to all three factories, all spellings and the key-spec classes:

   ```bash
   SRC=out/sources
   grep -rniE '"(DES|DESede|TripleDES|3DES|RC2|RC4|ARCFOUR|ARC4|Blowfish|CAST5|IDEA)(/[^"]*)?"' "$SRC" \
     | grep -vE "^$SRC/(androidx|kotlin|kotlinx)/"
   grep -rniE '"PBEWith[A-Za-z0-9]*(DES|RC2|RC4)[^"]*"' "$SRC"
   grep -rnE 'new (DESKeySpec|DESedeKeySpec)\(' "$SRC"
   ```

   The first command matches the literal anywhere (field initialisers, constants, `KeyGenerator` and `SecretKeyFactory` calls), not just inside `Cipher.getInstance`.

4. **Check native code and cross-platform bundles.** Statically linked OpenSSL or BoringSSL exposes legacy ciphers by symbol name:

   ```bash
   unzip -o -q app.apk 'lib/*' 'assets/*' -d apk/
   for so in apk/lib/arm64-v8a/*.so; do
     echo "== $so"
     readelf -Ws --dyn-syms "$so" | grep -E 'EVP_(des|rc4|rc2|bf|cast5)_|DES_(ecb|ede3|set_key)|RC4_set_key|BF_set_key'
     strings -a "$so" | grep -E '^OpenSSL [0-9]|^(DES-EDE3-CBC|DES-ECB|BF-CBC|RC2-CBC)$'   # stripped builds keep cipher names
   done
   # React Native / Cordova bundles
   grep -oE 'CryptoJS\.(DES|TripleDES|RC4|RC4Drop|Rabbit)' apk/assets/index.android.bundle | sort | uniq -c
   ```

   A symbol being present only proves the library was linked; follow up with `r2 -A libfoo.so`, then `axt @ sym.EVP_des_ede3_cbc` to see whether anything calls it.

5. **Triage each hit** (MASTG-TECH-0023). Open the method in jadx-gui, use "Find Usage" to walk back to the caller, and answer three questions: is the code reachable from the app (not dead SDK code); what data goes into `doFinal` (credentials, tokens, personal data, keys); and where does the output go (a file, a preference, the network). Encryption and decryption both count: decryption-only use of 3DES to read legacy data is weaker evidence than new data being encrypted with it.

6. **Optional runtime confirmation.** The hook in [MASTG-TEST-0350](#mastg-test-0350-runtime-use-of-broken-symmetric-encryption-modes-android) logs every `Cipher.getInstance` call with a backtrace and catches algorithms selected dynamically (from a server configuration, for example).

#### Observation

For each location: the class, method and line in the decompiled source; the exact algorithm string (and the mode and padding, which are frequently also wrong — DES is usually used with ECB); how the key is built (often an 8- or 24-byte constant, which is a separate MASWE-0003 finding); what data is protected and where the output goes.

#### Evaluation

The test **fails** if a broken or disallowed symmetric algorithm — DES, two- or three-key 3DES, RC4, RC2, Blowfish, CAST5, or a `PBEWith...` cipher based on them — is used to encrypt or decrypt sensitive data in reachable code.

It **passes** if no such use exists, or if every hit is in unreachable code or protects nothing of value. Common false positives and context to weigh:

- Algorithm names in provider registration or capability tables inside libraries (Bouncy Castle, JSch, Apache Commons) that the app never invokes.
- **Protocol-mandated legacy algorithms.** E-passport readers implementing ICAO 9303 Basic Access Control must use 3DES; EMV and some payment-terminal protocols use 3DES keys. Record them, explain that the algorithm is dictated by the protocol, and check whether the stronger protocol variant (PACE for ICAO) is supported and preferred.
- Decryption of legacy data during a one-off migration to AES-GCM. Verify that the migration re-encrypts and deletes the old data.

#### Demo

From [MASTG-DEMO-0022](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0022/MASTG-DEMO-0022/). The sample encrypts the same string with four broken algorithms. Abridged:

```kotlin
// DES: 8-byte key, provider default mode (ECB)
val keySpec = DESKeySpec(keyBytes)
val secretKey = SecretKeyFactory.getInstance("DES").generateSecret(keySpec)
val cipher = Cipher.getInstance("DES")
cipher.init(Cipher.ENCRYPT_MODE, secretKey)

// 3DES
val tdesKey = SecretKeyFactory.getInstance("DESede").generateSecret(DESedeKeySpec(keyBytes24))
Cipher.getInstance("DESede").init(Cipher.ENCRYPT_MODE, tdesKey)

// RC4 and Blowfish (64-bit Blowfish key)
Cipher.getInstance("RC4").init(Cipher.ENCRYPT_MODE, SecretKeySpec(keyBytes16, "RC4"))
Cipher.getInstance("Blowfish").init(Cipher.ENCRYPT_MODE, SecretKeySpec(keyBytes8, "Blowfish"))
```

Running `semgrep -c ../../../../rules/mastg-android-broken-encryption-algorithms.yaml ./MastgTest_reversed.java` against the jadx output:

```text
┌─────────────────┐
│ 4 Code Findings │
└─────────────────┘

    MastgTest_reversed.java
    ❯❱ rules.mastg-android-broken-encryption-algorithms
          [MASVS-CRYPTO-1] Broken encryption algorithms found in use.

           39┆ Cipher cipher = Cipher.getInstance("DES");
            ⋮┆----------------------------------------
           62┆ Cipher cipher = Cipher.getInstance("DESede");
            ⋮┆----------------------------------------
           81┆ Cipher cipher = Cipher.getInstance("RC4");
            ⋮┆----------------------------------------
          100┆ Cipher cipher = Cipher.getInstance("Blowfish");
```

The test fails on all four. Notice what the rule does not report: the `SecretKeyFactory.getInstance("DES")` and `("DESede")` calls, which the wider grep in step 3 catches, and the fact that every one of these ciphers is also running in ECB, because no mode was given. The keys here come from `SecureRandom`, so there is no MASWE-0003 finding in the demo; in real apps there often is.

### MASTG-TEST-0232: Broken Symmetric Encryption Modes (Android)

Source: [MASTG-TEST-0232](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0232/). Type: static (code), manual review. Best practice: MASTG-BEST-0005.

#### Overview

The test looks for symmetric encryption in ECB mode. In the JCA the mode is the middle part of the transformation string passed to `Cipher.getInstance`, and ECB arrives in two ways: explicitly (`"AES/ECB/PKCS5Padding"`, `"AES/ECB/NoPadding"`, `"AES/ECB/ISO10126Padding"`) or implicitly through a bare `"AES"`, which Android resolves to `AES/ECB/PKCS5Padding`. Google Play's app security guidance treats all of these as vulnerable. For Android Keystore keys there is a third route: `setBlockModes(KeyProperties.BLOCK_MODE_ECB)` on the key spec, which the dynamic test TEST-0350 targets.

**Out of scope:** RSA transformations such as `"RSA/ECB/OAEPPadding"` and `"RSA/ECB/PKCS1Padding"`. RSA has no block mode; the `ECB` is a placeholder in the JCA naming scheme. Do not report it as ECB. (Do look at the padding — see supplementary check S3.)

#### Prerequisites

The common Android prerequisites above.

#### Steps

1. **Decompile**: `jadx -d out/ app.apk`.

2. **Run the OWASP semgrep rule** (`mastg-android-broken-encryption-modes.yaml`):

   ```yaml
   rules:
     - id: mastg-android-broken-encryption-modes
       languages:
         - java
       severity: WARNING
       metadata:
         summary: This rule looks for broken encryption modes.
       message: "[MASVS-CRYPTO-1] Broken encryption modes found in use."
       pattern-either:
         - pattern: Cipher.getInstance("AES")
         - pattern-regex: Cipher\.getInstance\("?[A-Za-z0-9]+/ECB(/[A-Za-z0-9]+)?"?\)
   ```

   ```bash
   semgrep -c mastg-android-broken-encryption-modes.yaml out/sources/
   ```

   Be aware of the rule's edges. The regex matches `"RSA/ECB/PKCS1Padding"` and `"RSA/ECB/NoPadding"` (false positives by the test's own scoping), but not `"RSA/ECB/OAEPWithSHA-256AndMGF1Padding"` because of the hyphens. It misses bare `"DES"`, `"DESede"` and `"Blowfish"` (which are also ECB), lower-case `"aes"`, and transformations built from constants or concatenation.

3. **Widen the sweep:**

   ```bash
   SRC=out/sources
   # ECB in any string, excluding RSA
   grep -rnE '"[A-Za-z0-9]+/ECB/[^"]*"' "$SRC" | grep -viE '"RSA/ECB'
   # bare algorithm names given to Cipher.getInstance (provider default mode)
   grep -rniE 'Cipher\.getInstance\("(AES|DES|DESede|Blowfish)"' "$SRC"
   # Keystore keys that allow ECB, and the switch that makes ECB encryption possible
   grep -rnE 'setBlockModes\([^)]*"ECB"|setRandomizedEncryptionRequired\(false\)' "$SRC"
   # concatenated transformations: look for the pieces
   grep -rnE '"/ECB/?"|"ECB"' "$SRC" | grep -vE "^$SRC/(androidx|kotlin)/"
   ```

   In cross-platform apps, search the JavaScript bundle for `mode: CryptoJS.mode.ECB` (or `CryptoJS.mode.ECB`) and Dart code (in Flutter, usually only visible through `blutter` or strings in `libapp.so`) for `AESMode.ecb`.

4. **Resolve each hit to a transformation and a purpose** in jadx-gui. If the transformation is a field (`this.TRANSFORMATION`), find where the field is assigned. Then follow the `Cipher` object to `doFinal` and determine what it encrypts (MASTG-TECH-0023).

5. **Assess exploitability.** ECB leaks equality of 16-byte blocks. Ask: is the plaintext longer than one block and structured (JSON, tokens, records with fixed fields)? Is the space of plaintexts small (PINs, card numbers, booleans), so an attacker can build a dictionary? Can an attacker get chosen data encrypted alongside a secret? Does the server accept the ciphertext as a token, so block swapping changes its meaning?

#### Observation

The list of locations where ECB is used (explicitly or by default), with the full transformation, the key source, the plaintext type and the destination of the ciphertext.

#### Evaluation

The test **fails** if ECB (explicit or implied by a bare algorithm name) is used to encrypt or decrypt sensitive data.

It **passes** if no symmetric ECB use exists in reachable code. Report as informational only: `RSA/ECB/...` transformations (judge their padding separately), and ECB applied to exactly one block of uniformly random data (for example wrapping one random AES key), while recommending AES Key Wrap or GCM instead.

#### Demo

From [MASTG-DEMO-0023](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0023/MASTG-DEMO-0023/). The sample contains six ECB transformations: four AES variants (one implicit) and DES and 3DES with explicit ECB:

```kotlin
val cipher = Cipher.getInstance("AES")                     // implicit ECB
val cipher = Cipher.getInstance("AES/ECB/NoPadding")
val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
val cipher = Cipher.getInstance("AES/ECB/ISO10126Padding")
val cipher = Cipher.getInstance("DES/ECB/PKCS5Padding")
val cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding")
```

Running the rule against the decompiled code:

```text
┌─────────────────┐
│ 6 Code Findings │
└─────────────────┘

    MastgTest_reversed.java
    ❯❱ rules.mastg-android-broken-encryption-modes
          [MASVS-CRYPTO-1] Broken encryption modes found in use.

           36┆ Cipher cipher = Cipher.getInstance("AES");
            ⋮┆----------------------------------------
           55┆ Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            ⋮┆----------------------------------------
           76┆ Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            ⋮┆----------------------------------------
           95┆ Cipher cipher = Cipher.getInstance("AES/ECB/ISO10126Padding");
            ⋮┆----------------------------------------
          118┆ Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            ⋮┆----------------------------------------
          141┆ Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
```

The test fails. The last two lines are also TEST-0221 failures (broken algorithms), and `AES/ECB/NoPadding` will throw on any input that is not a multiple of 16 bytes, which is why it tends to appear with home-made padding — worth a look in its own right. To see why ECB matters, encrypt two identical blocks and compare:

```bash
printf 'role=user;id=01|role=user;id=01|' | \
  openssl enc -aes-128-ecb -K 000102030405060708090a0b0c0d0e0f -nopad | xxd -c 16
```

Both 16-byte input blocks produce the same 16-byte ciphertext block on the two output lines — that equality is exactly what ECB leaks.

### MASTG-TEST-0350: Runtime Use of Broken Symmetric Encryption Modes (Android)

Source: [MASTG-TEST-0350](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0350/). Type: dynamic (hooks), manual review. Best practice: MASTG-BEST-0005.

#### Overview

The dynamic counterpart to TEST-0232. Static analysis misses transformations assembled at runtime, delivered by a remote configuration, hidden in obfuscated code or native libraries that call back into Java, and Keystore keys whose ECB authorisation is set through `KeyGenParameterSpec.Builder` or `KeyProtection.Builder`. Hooking the APIs while the app runs shows what is actually configured, with a backtrace that tells you where.

Two families of APIs are relevant:

- `Cipher.getInstance(...)` — every overload; the transformation is the first argument.
- `KeyGenParameterSpec.Builder.setBlockModes(...)` and `KeyProtection.Builder.setBlockModes(...)` — the block modes a Keystore key is authorised for; with `setRandomizedEncryptionRequired(...)` on the same builders, which decides whether ECB encryption is allowed at all.

#### Prerequisites

The common dynamic prerequisites above (rooted device or emulator, `frida-server`, frida or frooky on the host).

#### Steps

1. **Install the app** (MASTG-TECH-0005): `adb install -r app.apk` (or `adb install-multiple` for split APKs).

2. **Hook the Keystore builders** with frooky, using OWASP's hook file from MASTG-DEMO-0058:

   ```json
   {
     "category": "CRYPTO",
     "hooks": [
       {
         "class": "android.security.keystore.KeyGenParameterSpec$Builder",
         "methods": ["setBlockModes", "setRandomizedEncryptionRequired"]
       },
       {
         "class": "android.security.keystore.KeyProtection$Builder",
         "methods": ["setBlockModes", "setRandomizedEncryptionRequired"]
       }
     ]
   }
   ```

   ```bash
   frooky -U -f com.example.app --platform android hooks.json > output.json
   ```

3. **Hook `Cipher.getInstance` as well**, which OWASP's demo does not, with plain Frida. This script logs every transformation, flags ECB and bare names, records the resolved provider, and includes the builder hooks so one script covers the whole test:

   ```javascript
   // hook-cipher-modes.js
   Java.perform(function () {
     const Cipher = Java.use('javax.crypto.Cipher');
     const Log = Java.use('android.util.Log');
     const Exception = Java.use('java.lang.Exception');
     const trace = function () { return Log.getStackTraceString(Exception.$new()); };
     const BARE = ['AES', 'DES', 'DESEDE', 'BLOWFISH'];

     Cipher.getInstance.overloads.forEach(function (ov) {
       ov.implementation = function () {
         const c = ov.apply(this, arguments);
         const t = String(arguments[0]);
         const up = t.toUpperCase();
         const ecb = (up.indexOf('/ECB') !== -1 && !up.startsWith('RSA')) || BARE.indexOf(up) !== -1;
         console.log((ecb ? '[!] ECB ' : '[ ] ') + 'Cipher.getInstance("' + t + '") provider=' +
                     c.getProvider().getName() + (ecb ? '\n' + trace() : ''));
         return c;
       };
     });

     ['android.security.keystore.KeyGenParameterSpec$Builder',
      'android.security.keystore.KeyProtection$Builder'].forEach(function (name) {
       const B = Java.use(name);
       B.setBlockModes.implementation = function (modes) {
         const list = [];
         for (let i = 0; i < modes.length; i++) list.push(String(modes[i]));
         console.log((list.indexOf('ECB') !== -1 ? '[!] ' : '[ ] ') + name + '.setBlockModes(' + list.join(', ') + ')\n' + trace());
         return this.setBlockModes(modes);
       };
       B.setRandomizedEncryptionRequired.implementation = function (required) {
         console.log((required ? '[ ] ' : '[!] ') + name + '.setRandomizedEncryptionRequired(' + required + ')\n' + trace());
         return this.setRandomizedEncryptionRequired(required);
       };
     });
   });
   ```

   ```bash
   frida -U -f com.example.app -l hook-cipher-modes.js -o cipher-modes.log
   ```

4. **Exercise the app thoroughly.** Log in and out, create and view the sensitive records the app stores, trigger offline mode and sync, export and import, change settings, and restart the app (key generation often happens only on first run, so also run once after `adb shell pm clear com.example.app`). Enter recognisable sensitive values so you can correlate later.

5. **Extract the hits.** For the frooky NDJSON output, OWASP's evaluation filter:

   ```bash
   jq -r -s '
     flatten
     | .[]
     | select(.method=="setBlockModes" and any(.inputParameters[]?.value[]?; . == "ECB"))
     | "Class: \(.class), Method: \(.method), Block modes: \([.inputParameters[]?.value[]?] | join(", "))"
   ' output.json
   ```

   For the Frida log, `grep -A12 '^\[!\]' cipher-modes.log`.

6. **Validate each hit** with the backtrace: open the calling method in jadx (MASTG-TECH-0023) and determine what data the cipher processes — personal data, authentication tokens, cryptographic keys, session identifiers.

#### Observation

A list of calls to the encryption-configuration APIs, each with its arguments (the transformation string or the block-mode array, and the randomised-encryption flag) and the backtrace.

#### Evaluation

The test **fails** if ECB is configured for a security-relevant cryptographic operation: a `Cipher` created with an ECB transformation (explicit or bare) that processes sensitive data, or a Keystore key authorised for ECB that is used for such data. A `setRandomizedEncryptionRequired(false)` call is not by itself an ECB finding, but it is a strong lead: it is also what enables fixed IVs (TEST-0309) and textbook RSA (S3), so trace that key's use.

It **passes** if every observed transformation uses an appropriate mode (GCM, or CBC/CTR with a MAC) and no Keystore key allows ECB. Remember that dynamic coverage is only as good as the flows you exercised; state in the report which features you covered.

#### Demo

From [MASTG-DEMO-0058](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0058/MASTG-DEMO-0058/). The sample exercises the Keystore's IND-CPA enforcement in three scenarios:

```kotlin
// 1. Import a raw AES key for DECRYPT only, ECB: allowed (decryption is never restricted)
KeyProtection.Builder(KeyProperties.PURPOSE_DECRYPT)
    .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
    .build()

// 2. Import for ENCRYPT, ECB, with randomised encryption explicitly disabled: allowed (bad practice)
KeyProtection.Builder(KeyProperties.PURPOSE_ENCRYPT)
    .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
    .setRandomizedEncryptionRequired(false)
    .build()

// 3. Generate a key for ENCRYPT | DECRYPT with ECB, default randomisation: refused
KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
    .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
    .build()
```

Scenario 1 decrypts a ciphertext produced elsewhere with AES-ECB; scenario 2 encrypts with ECB because the developer opted out of randomisation; scenario 3 fails in `KeyGenerator.init` with:

```text
Randomized encryption (IND-CPA) required but may be violated by block mode: ECB.
See android.security.keystore.KeyGenParameterSpec documentation
```

The frooky output contains one JSON record per call (abridged here), with the stack trace pointing at the source line:

```json
{
  "type": "hook",
  "category": "CRYPTO",
  "class": "android.security.keystore.KeyProtection$Builder",
  "method": "setBlockModes",
  "stackTrace": [
    "android.security.keystore.KeyProtection$Builder.setBlockModes(Native Method)",
    "org.owasp.mastestapp.MastgTest.mastgTest(MastgTest.kt:38)"
  ],
  "inputParameters": [
    { "declaredType": "[Ljava.lang.String;", "value": ["ECB"] }
  ]
}
```

and the `jq` filter reduces the run to:

```text
Class: android.security.keystore.KeyProtection$Builder, Method: setBlockModes, Block modes: ECB
Class: android.security.keystore.KeyProtection$Builder, Method: setBlockModes, Block modes: ECB
Class: android.security.keystore.KeyGenParameterSpec$Builder, Method: setBlockModes, Block modes: ECB
```

The test fails: all three builders were configured with ECB, regardless of whether the Keystore then allowed the operation. The same run also records `setRandomizedEncryptionRequired(false)` at `MastgTest.kt:65` (scenario 2), which is the line that turned a refused configuration into a working ECB encryption. Scenario 1 also tells you something about the wider system: if the app receives ECB ciphertext, something on the server side is producing it.

### MASTG-TEST-0309: References to Reused Initialization Vectors in Symmetric Encryption (Android)

Source: [MASTG-TEST-0309](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0309/). Type: static (code). **Status upstream: placeholder.** OWASP publishes the title and this note only: reusing a key is fine when IVs and nonces follow the rules of the mode — a fresh, unpredictable IV for every CBC encryption (SP 800-38A) and a nonce that never repeats under the same key for counter-based modes — and repeating a key/IV pair "defeats confidentiality and can also undermine integrity". (The note attributes the counter-mode rule to SP 800-38D; that document covers GCM, and the CTR rule is in SP 800-38A, section 6.5. Both say the same thing.) The procedure below is **Guler Tech methodology**.

#### Overview

You are looking for encryption call sites where the IV or nonce is not freshly generated per message: constant, all-zero, derived from the key or from other stable data, predictable (timestamps, `java.util.Random`, simple counters for CBC), or generated once and cached. The relevant constructors are `IvParameterSpec(byte[])` and `IvParameterSpec(byte[], int, int)`, `GCMParameterSpec(int tLen, byte[])` and its offset variant, `ChaCha20ParameterSpec` where used, and `PBEParameterSpec(salt, iterations, ivSpec)`. A Keystore key generated with `setRandomizedEncryptionRequired(false)` is the Keystore-side signal, because that is the only way the Keystore will accept a caller-supplied IV.

The hard part is not finding `IvParameterSpec`; it is telling the **encryption** path, where a constant IV is a vulnerability, from the **decryption** path, where building an `IvParameterSpec` from the bytes stored alongside the ciphertext is exactly right.

#### Prerequisites

The common Android prerequisites above.

#### Steps

1. **Decompile**: `jadx -d out/ app.apk`.

2. **Run a candidate rule** (ours, not OWASP's):

   ```yaml
   rules:
     - id: gt-android-static-or-zero-iv
       languages: [java]
       severity: WARNING
       message: IV or nonce built from constant data; check whether it is used for encryption under one key
       pattern-either:
         - pattern: new IvParameterSpec(new byte[$N])
         - pattern: new GCMParameterSpec($T, new byte[$N])
         - pattern: new IvParameterSpec("...".getBytes(...))
         - pattern: new IvParameterSpec(Base64.decode("...", $F))
         - pattern: |
             byte[] $IV = {...};
             ...
             new IvParameterSpec($IV, ...);
         - pattern: |
             byte[] $IV = {...};
             ...
             new GCMParameterSpec($T, $IV, ...);
         - pattern: $B.setRandomizedEncryptionRequired(false)
   ```

   ```bash
   semgrep -c gt-android-static-or-zero-iv.yaml out/sources/
   ```

3. **List every IV and nonce construction** and every IV-like field, because constants are often hoisted into static fields that a same-method pattern does not see:

   ```bash
   SRC=out/sources
   grep -rnE 'new (IvParameterSpec|GCMParameterSpec|ChaCha20ParameterSpec|PBEParameterSpec)\(' "$SRC" \
     | grep -vE "^$SRC/(androidx|kotlin|kotlinx|com/google/crypto/tink)/"
   grep -rnE 'static final byte\[\] [A-Za-z_]*([Ii][Vv]|[Nn]once|NONCE)' "$SRC"
   grep -rnE '(Arrays\.copyOf|copyOfRange)\([^)]*[Kk]ey' "$SRC"     # IV sliced from key material
   ```

4. **Classify each construction** by walking to the `Cipher.init` that consumes it (jadx-gui "Find Usage"):
   - `init(Cipher.ENCRYPT_MODE, ...)` (decompiled as `init(1, ...)`) with a constant, zero, key-derived or cached IV: **reuse**.
   - CBC encryption with an IV from `System.currentTimeMillis()`, `java.util.Random`, a sequence number or a hash of the plaintext: **predictable** (fails for CBC; for CTR and GCM, a correctly managed counter is acceptable, see below).
   - `init(Cipher.DECRYPT_MODE, ...)` (`init(2, ...)`) with an IV parsed from the stored ciphertext: correct.
   - `init(ENCRYPT_MODE, key)` with no IV, followed by `cipher.getIV()` being stored: correct.
   - A `SecureRandom().nextBytes(iv)` per call: correct. Generated once into a field, or in an `object`/singleton initialiser and reused: **reuse**.

5. **Check counter-based designs.** If GCM or CTR nonces come from a counter, find where the counter lives. A counter in memory resets on restart; a counter in `SharedPreferences` resets on "clear data" and can be rolled back by restoring a backup, while the key in the Keystore survives neither or both depending on configuration. Unless the key is regenerated whenever the counter could reset, treat the design as nonce reuse.

6. **Check PBE ciphers.** `Cipher.getInstance("PBEWith...")` initialised with a `PBEKeySpec`-derived key and no `PBEParameterSpec` carrying an `IvParameterSpec` runs with an all-zero IV on Android.

#### Observation

For each encryption call site: the transformation, the IV source (constant value, field name, derivation), whether the same key is used for more than one message, and what the ciphertext protects.

#### Evaluation

The test **fails** if, for any key, encryption uses an IV or nonce that is constant, zero, derived from stable data or reused across messages; or if CBC encryption uses a predictable IV. Severity depends on the mode (the GCM and CTR consequences are worse than CBC's equal-prefix leak; see [Rating findings](#rating-findings)) and on whether an attacker can obtain two ciphertexts under the same key and IV.

It **passes** if every encryption IV is either generated by the provider or the Keystore and read back with `getIV()`, or drawn from `SecureRandom` per message, or (for CTR/GCM only) produced by a counter construction that provably cannot repeat for the key's lifetime. Decryption-side constructions are not findings.

#### Demo

Guler Tech demo (illustrative). A typical vulnerable helper in Kotlin:

```kotlin
object TokenCrypto {
    private val IV = "0102030405060708".toByteArray()          // constant 16-byte CBC IV

    fun encryptCbc(key: SecretKey, data: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/CBC/PKCS5Padding")
        c.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(IV))
        return c.doFinal(data)
    }

    fun encryptGcm(key: SecretKey, data: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, ByteArray(12)))  // all-zero nonce
        return c.doFinal(data)
    }
}
```

jadx turns the GCM call into `new GCMParameterSpec(128, new byte[12])`, which the rule's second pattern reports. The CBC IV becomes a `private static final byte[] IV` initialised in a `static {}` block from `"0102030405060708".getBytes(Charsets.UTF_8)`, and `new IvParameterSpec(IV)` in the method — no same-method pattern matches it, but the `static final byte[] ...IV` grep in step 3 does. That is the reason step 3 exists.

What a repeated nonce costs, shown with AES-CTR (GCM's encryption layer) and two messages under one key and nonce. Knowing one plaintext recovers the other without the key:

```bash
K=000102030405060708090a0b0c0d0e0f
IV=00000000000000000000000000000000
printf 'PIN=4821;user=alice' | openssl enc -aes-128-ctr -K $K -iv $IV | xxd -p > c1.hex
printf 'PIN=9135;user=bobby' | openssl enc -aes-128-ctr -K $K -iv $IV | xxd -p > c2.hex
python3 - <<'PY'
c1 = bytes.fromhex(open('c1.hex').read().strip())
c2 = bytes.fromhex(open('c2.hex').read().strip())
known = b'PIN=4821;user=alice'
keystream = bytes(a ^ b for a, b in zip(c1, known))
print(bytes(a ^ b for a, b in zip(c2, keystream)))
PY
```

The script prints `b'PIN=9135;user=bobby'`. With GCM the same keystream reuse happens, and the attacker can additionally recover the authentication key from the two tags.

### MASTG-TEST-0310: Runtime Use of Reused Initialization Vectors in Symmetric Encryption (Android)

Source: [MASTG-TEST-0310](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0310/). Type: dynamic (hooks). **Status upstream: placeholder**, with the same note as TEST-0309. The procedure below is **Guler Tech methodology**.

#### Overview

Static analysis cannot always tell whether an IV repeats: the IV may come from a cache, a server, native code, or a counter whose persistence you cannot see. At runtime you can simply record every (key, IV) pair used for encryption and look for duplicates. The script below hooks every `Cipher.init` overload to learn the mode and key of each `Cipher` object, and every `doFinal` overload to read the IV actually used — including IVs generated by the provider or the Keystore, which never appear as an argument.

#### Prerequisites

The common dynamic prerequisites above.

#### Steps

1. **Install the app** (MASTG-TECH-0005).

2. **Load the IV-tracking hook:**

   ```javascript
   // hook-iv-reuse.js
   Java.perform(function () {
     const Cipher = Java.use('javax.crypto.Cipher');
     const KeyStore = Java.use('java.security.KeyStore');
     const System = Java.use('java.lang.System');
     const MessageDigest = Java.use('java.security.MessageDigest');
     const Log = Java.use('android.util.Log');
     const Exception = Java.use('java.lang.Exception');
     const state = {};    // Cipher identity -> { mode, keyId }
     const seen = {};     // keyId|iv -> true
     const aliases = {};  // Keystore key identity -> alias

     function hex(a) {
       if (a === null) return null;
       let s = '';
       for (let i = 0; i < a.length; i++) s += ('0' + (a[i] & 0xff).toString(16)).slice(-2);
       return s;
     }
     function keyId(key) {
       const enc = key.getEncoded();                       // null for Keystore keys
       if (enc === null) {
         const h = System.identityHashCode(key);
         return 'keystore:' + (aliases[h] || ('@' + h));
       }
       return 'sha256:' + hex(MessageDigest.getInstance('SHA-256').digest(enc)).slice(0, 16);
     }

     KeyStore.getKey.implementation = function (alias, password) {
       const k = this.getKey(alias, password);
       if (k !== null) aliases[System.identityHashCode(k)] = alias;
       return k;
     };

     Cipher.init.overloads.forEach(function (ov) {
       ov.implementation = function () {
         const ret = ov.apply(this, arguments);
         if (ov.argumentTypes[1].className === 'java.security.Key') {
           state[System.identityHashCode(this)] = { mode: arguments[0], keyId: keyId(arguments[1]) };
         }
         return ret;
       };
     });

     Cipher.doFinal.overloads.forEach(function (ov) {
       ov.implementation = function () {
         const st = state[System.identityHashCode(this)];
         const iv = hex(this.getIV());
         if (st && st.mode === 1 && iv !== null) {          // 1 = Cipher.ENCRYPT_MODE
           const id = st.keyId + '|' + iv;
           if (seen[id]) {
             console.log('[!] IV REUSE ' + this.getAlgorithm() + ' key=' + st.keyId + ' iv=' + iv + '\n' +
                         Log.getStackTraceString(Exception.$new()));
           } else {
             seen[id] = true;
             console.log('[ ] ' + this.getAlgorithm() + ' key=' + st.keyId + ' iv=' + iv);
           }
         }
         return ov.apply(this, arguments);
       };
     });
   });
   ```

   ```bash
   frida -U -f com.example.app -l hook-iv-reuse.js -o iv.log
   ```

   Raw keys are identified by a truncated SHA-256 of their bytes (so the log does not contain the key), and Keystore keys by the alias they were loaded under.

3. **Exercise every flow that encrypts**, and repeat each one at least twice (save the same record twice, log in twice, sync twice). Many reuse bugs only show on the second message.

4. **Restart and repeat.** Save each run's log separately (`-o iv-run1.log`, `-o iv-run2.log`, ...). Force-stop the app (`adb shell am force-stop com.example.app`), relaunch with the hook, and repeat the flows. Then clear data (`adb shell pm clear com.example.app`) and repeat once more. A counter-based nonce that resets on restart only shows up as a reuse across runs, so concatenate the logs and look for duplicate `key|iv` pairs:

   ```bash
   grep -h '^\[ \]' iv-run1.log iv-run2.log | grep -oE 'key=[^ ]+ iv=[^ ]+' | sort | uniq -d
   ```

   (Keystore keys are tracked by alias, so this cross-run comparison works for them; raw keys are tracked by hash, which is also stable across runs.)

5. **Inspect the IV values** themselves, even without a repeat: an all-zero IV, ASCII text, or IVs that increment by one between CBC messages are findings in their own right.

#### Observation

The log of every encryption with algorithm, key identifier and IV, the `[!] IV REUSE` lines with backtraces, and the cross-run duplicate list.

#### Evaluation

The test **fails** if any (key, IV) pair repeats for encryption of security-relevant data — within a run, across restarts, or across a data clear where the key survives — or if CBC IVs are visibly predictable. Use the backtrace to confirm what was encrypted (MASTG-TECH-0023).

It **passes** if no repeats occur across the exercised flows and restarts and the IVs look random. As with every dynamic test, a pass covers only what you exercised.

#### Demo

Guler Tech demo (illustrative output, values shortened). Running the hook against the `TokenCrypto` sample from TEST-0309 and saving the same record twice:

```text
[ ] AES/CBC/PKCS5Padding key=sha256:3f1c9a0e5b7d2c44 iv=30313032303330343035303630373038
[!] IV REUSE AES/CBC/PKCS5Padding key=sha256:3f1c9a0e5b7d2c44 iv=30313032303330343035303630373038
java.lang.Exception
    at javax.crypto.Cipher.doFinal(Native Method)
    at com.example.app.TokenCrypto.encryptCbc(TokenCrypto.kt:9)
[ ] AES/GCM/NoPadding key=sha256:3f1c9a0e5b7d2c44 iv=000000000000000000000000
[!] IV REUSE AES/GCM/NoPadding key=sha256:3f1c9a0e5b7d2c44 iv=000000000000000000000000
```

The CBC IV is the ASCII string `0102030405060708` and the GCM nonce is all zeros; both repeat. The same hook against a correctly written Keystore AES-GCM helper shows a different 12-byte IV on every line for `keystore:data-key-v1`, because the Keystore generates it. Note also that the hook shows the same raw key (`3f1c9a0e…`) used for both CBC and GCM, which is a key-separation smell worth recording.

### MASTG-TEST-0307: References to Asymmetric Key Pairs Used For Multiple Purposes (Android)

Source: [MASTG-TEST-0307](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0307/). Type: static (code). Knowledge: MASTG-KNOW-0012.

#### Overview

NIST SP 800-57 Part 1 Rev. 5, section 5.2 ("Key Usage"), requires each key to have one purpose: encryption, integrity authentication, key wrapping, random bit generation or digital signatures. On Android, Keystore key pairs are created with `KeyPairGenerator` configured by a `KeyGenParameterSpec`, and the `KeyGenParameterSpec.Builder(keystoreAlias, purposes)` constructor takes the allowed purposes as a bitmask of `KeyProperties` constants. The test reads that bitmask. The reason it matters for encryption is the cross-protocol risk in the [background section](#integrity-and-key-separation): a key that both decrypts and signs lets a weakness in one operation compromise the other.

#### Prerequisites

The common Android prerequisites above.

#### Steps

1. **Decompile**: `jadx -d out/ app.apk`.

2. **Run the OWASP semgrep rule** (`mastg-android-asymmetric-key-pair-used-for-multiple-purposes.yml`), which simply finds every builder construction and captures the purposes:

   ```yaml
   rules:
     - id: mastg-android-asymmetric-key-pair-used-for-multiple-purposes
       severity: WARNING
       languages:
         - java
       metadata:
         summary: Detects usage of KeyGenParameterSpec.Builder to collect observations for key-purposes evaluation.
       message: |
         [MASVS-CRYPTO-1] Detected usage of KeyGenParameterSpec.Builder. Review the configured purposes to ensure key separation (avoid mixing encryption/decryption with signing/verification or wrapping).
       pattern: |
         new KeyGenParameterSpec.Builder($ALIAS, $PURPOSES)
   ```

   ```bash
   semgrep -c mastg-android-asymmetric-key-pair-used-for-multiple-purposes.yml out/sources/
   ```

3. **Decode the bitmask.** The Kotlin `or` and Java `|` expressions are constant-folded by the compiler, so jadx shows a plain integer:

   | Constant | Value |
   |---|---|
   | `PURPOSE_ENCRYPT` | 1 |
   | `PURPOSE_DECRYPT` | 2 |
   | `PURPOSE_SIGN` | 4 |
   | `PURPOSE_VERIFY` | 8 |
   | `PURPOSE_WRAP_KEY` | 32 |
   | `PURPOSE_AGREE_KEY` (API 31) | 64 |
   | `PURPOSE_ATTEST_KEY` (API 31) | 128 |

   Acceptable values for one key are 1, 2, 3 (encryption), 4, 8, 12 (signing) and 32 (wrapping). Anything that combines groups — 5, 6, 7, 9, 10, 11, 13, 14, 15, 33, 35 and so on — fails. If the purposes come from a variable or parameter, trace it.

4. **Find keys the rule cannot see:**

   ```bash
   SRC=out/sources
   grep -rn 'KeyPairGeneratorSpec' "$SRC"                         # legacy spec: permissive, all purposes
   grep -rn 'new KeyProtection.Builder(' "$SRC"                    # imported keys carry purposes too
   grep -rlE 'setSignaturePaddings' "$SRC" | xargs grep -lE 'setEncryptionPaddings'   # both kinds on one key
   ```

   Also review symmetric keys outside the Keystore: the same `SecretKeySpec` bytes passed to both `Cipher` (AES) and `Mac` (HMAC) is the symmetric version of this weakness.

5. **Confirm the key is actually used in more than one role** by following the alias to `Cipher.init` and `Signature.initSign`/`initVerify` calls. Authorisation for several purposes is the static finding; use in several roles (TEST-0308) makes it concrete.

#### Observation

Every `KeyGenParameterSpec.Builder` (and `KeyProtection.Builder`) construction with its alias, the decoded purposes, the algorithm (`KeyPairGenerator.getInstance(...)`), and the paddings and digests configured.

#### Evaluation

The test **fails** if any key pair is authorised for more than one role: encryption/decryption (`PURPOSE_ENCRYPT`, `PURPOSE_DECRYPT`), signing/verification (`PURPOSE_SIGN`, `PURPOSE_VERIFY`), or key wrapping (`PURPOSE_WRAP_KEY`). Keys created through the deprecated `KeyPairGeneratorSpec` fail by default.

It **passes** if each key's purposes stay within one role.

#### Demo

From [MASTG-DEMO-0071](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0071/MASTG-DEMO-0071/). The sample creates one RSA key pair for everything:

```kotlin
val parameterSpec = KeyGenParameterSpec.Builder(
    KEY_ALIAS,
    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY or
        KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_ENCRYPT
).run {
    setDigests(KeyProperties.DIGEST_SHA256)
    setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
    setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
    build()
}
```

The rule's output against the decompiled code:

```text
┌────────────────┐
│ 1 Code Finding │
└────────────────┘

    MastgTest_reversed.java
    ❯❱ rules.mastg-android-asymmetric-key-pair-used-for-multiple-purposes
          [MASVS-CRYPTO-1] Detected usage of KeyGenParameterSpec.Builder. Review the configured purposes to
          ensure key separation (avoid mixing encryption/decryption with signing/verification or wrapping).

           83┆ KeyGenParameterSpec.Builder $this$generateKey_u24lambda_u242 = new
               KeyGenParameterSpec.Builder(this.KEY_ALIAS, 15);
```

`15` is `1 | 2 | 4 | 8`: the test fails. The same key also uses PKCS#1 v1.5 for encryption (`RSA/ECB/PKCS1Padding`), which is a separate finding under supplementary check S3 — and the combination is the textbook setting for a Bleichenbacher-style oracle being turned into a signing capability.

### MASTG-TEST-0308: Runtime Use of Asymmetric Key Pairs Used For Multiple Purposes (Android)

Source: [MASTG-TEST-0308](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0308/). Type: dynamic (hooks). Knowledge: MASTG-KNOW-0012.

#### Overview

The dynamic counterpart to TEST-0307: instead of reading how keys were generated, it watches how they are used. The relevant APIs are `Cipher.init` (with `ENCRYPT_MODE`, `DECRYPT_MODE`, `WRAP_MODE` or `UNWRAP_MODE`), `Signature.initSign(PrivateKey)` and `Signature.initVerify(PublicKey)` (or `initVerify(Certificate)`). A key that shows up in more than one group of operations fails. This also catches keys the static test cannot see — imported keys, keys from bundled keystores, keys created in native code — and it shows real use rather than mere authorisation.

The difficulty is identity: the private half lives in the Keystore and the public half is an ordinary Java object, so you need a way to recognise both halves as one key pair.

#### Prerequisites

The common dynamic prerequisites above.

#### Steps

1. **Install the app** (MASTG-TECH-0005).

2. **Hook all relevant overloads.** OWASP's script in MASTG-DEMO-0072 hooks `Cipher.init(int, Key)` and `Cipher.init(int, Certificate)` and identifies keys by their `toString()`. That misses `Cipher.init` calls with parameters — which is every OAEP call that passes an `OAEPParameterSpec` — and treats the two halves of a pair as different keys unless you match them by eye. This version hooks every overload and identifies RSA key pairs by their modulus, which both halves share (Keystore RSA private keys implement `RSAKey`):

   ```javascript
   // hook-key-purposes.js
   Java.perform(function () {
     const Cipher = Java.use('javax.crypto.Cipher');
     const Signature = Java.use('java.security.Signature');
     const KeyStore = Java.use('java.security.KeyStore');
     const RSAKey = Java.use('java.security.interfaces.RSAKey');
     const System = Java.use('java.lang.System');
     const Log = Java.use('android.util.Log');
     const Exception = Java.use('java.lang.Exception');
     const aliases = {};
     const roles = {};

     function keyId(key) {
       try {
         return 'rsa:' + Java.cast(key, RSAKey).getModulus().toString(16).slice(0, 16);
       } catch (e) {
         const h = System.identityHashCode(key);
         return aliases[h] ? 'alias:' + aliases[h] : key.$className + '@' + h;
       }
     }
     function record(key, role, api) {
       const id = keyId(key);
       roles[id] = roles[id] || {};
       roles[id][role] = true;
       const all = Object.keys(roles[id]);
       console.log('[' + api + '] ' + role + ' key=' + id);
       if (all.length > 1) {
         console.log('!!! MULTIPLE ROLES for ' + id + ': ' + all.join(', ') + '\n' +
                     Log.getStackTraceString(Exception.$new()));
       }
     }

     KeyStore.getKey.implementation = function (alias, password) {
       const k = this.getKey(alias, password);
       if (k !== null) aliases[System.identityHashCode(k)] = alias;
       return k;
     };
     Cipher.init.overloads.forEach(function (ov) {
       ov.implementation = function () {
         const mode = arguments[0];
         const role = (mode === 3 || mode === 4) ? 'key-wrapping' : 'encryption';
         const isKey = ov.argumentTypes[1].className === 'java.security.Key';
         record(isKey ? arguments[1] : arguments[1].getPublicKey(), role, 'Cipher.init');
         return ov.apply(this, arguments);
       };
     });
     Signature.initSign.overloads.forEach(function (ov) {
       ov.implementation = function () {
         record(arguments[0], 'signature', 'Signature.initSign');
         return ov.apply(this, arguments);
       };
     });
     Signature.initVerify.overloads.forEach(function (ov) {
       ov.implementation = function () {
         const a = arguments[0];
         const k = ov.argumentTypes[0].className === 'java.security.PublicKey' ? a : a.getPublicKey();
         record(k, 'signature', 'Signature.initVerify');
         return ov.apply(this, arguments);
       };
     });
   });
   ```

   ```bash
   frida -U -f com.example.app -l hook-key-purposes.js -o key-purposes.log
   ```

   For EC keys (which cannot encrypt in the Keystore but can sign and agree keys), the alias is the identifier.

3. **Exercise the app**, in particular registration, login, request signing and any end-to-end-encryption or secure-messaging features.

4. **Filter noise.** Symmetric keys appear too (with `encryption` only); system components occasionally use `Signature` in-process; and `Cipher.init` overloads that delegate to each other log the same operation twice. Use the backtraces to keep only the app's own operations.

#### Observation

Every cryptographic operation with its role and key identifier, and the `MULTIPLE ROLES` lines with backtraces.

#### Evaluation

The test **fails** if the same key or key pair is used in more than one of: encryption/decryption (`Cipher` with `ENCRYPT_MODE`/`DECRYPT_MODE`), signing/verification (`Signature`), key wrapping (`Cipher` with `WRAP_MODE`/`UNWRAP_MODE`).

It **passes** if each key stays in one group across all exercised flows.

#### Demo

From [MASTG-DEMO-0072](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0072/MASTG-DEMO-0072/), which runs the DEMO-0071 app under OWASP's script. Abridged output:

```text
🔒 *** Cipher.init(Key) HOOKED ***
  encryption/decryption with key: "OpenSSLRSAPublicKey{modulus=a41226cf3ca5b7cc...,publicExponent=10001}"
    org.owasp.mastestapp.MastgTest.encrypt(MastgTest.kt:126)

🔒 *** Cipher.init(Key) HOOKED ***
  encryption/decryption with key: "android.security.keystore2.AndroidKeyStoreRSAPrivateKey@3818961"
    org.owasp.mastestapp.MastgTest.decrypt(MastgTest.kt:145)

✍️ *** Signature.initSign(PrivateKey) HOOKED ***
  sign/verify with key: "android.security.keystore2.AndroidKeyStoreRSAPrivateKey@3818961"
!!! WARNING: This key is used for multiple, conflicting purposes: encryption/decryption and sign/verify
    org.owasp.mastestapp.MastgTest.sign(MastgTest.kt:163)

✅ *** Signature.initVerify(PublicKey) HOOKED ***
  sign/verify with key: "OpenSSLRSAPublicKey{modulus=a41226cf3ca5b7cc...,publicExponent=10001}"
!!! WARNING: This key is used for multiple, conflicting purposes: encryption/decryption and sign/verify
    org.owasp.mastestapp.MastgTest.verify(MastgTest.kt:177)
```

The private key (`AndroidKeyStoreRSAPrivateKey@3818961`) decrypts and then signs; the public key with modulus `a41226cf3ca5b…` encrypts and then verifies. They are two halves of one pair, so the test fails. With the modulus-based identifier above, all four lines collapse onto `rsa:a41226cf3ca5b7cc`, which makes the pairing explicit instead of something you infer.

### MASTG-TEST-0312: References to Explicit Security Provider in Cryptographic APIs (Android)

Source: [MASTG-TEST-0312](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0312/). Type: static (code). Knowledge: MASTG-KNOW-0011. Best practice: MASTG-BEST-0020.

#### Overview

Every JCA `getInstance` method has overloads that take a provider, by name (`"BC"`) or as a `Provider` object. Naming a provider overrides Android's choice of the maintained default (`AndroidOpenSSL`, i.e. Conscrypt) and ties the app to an implementation that may be deprecated, removed, unpatched or home-made. The [provider history](#android-security-provider-mastg-know-0011) shows the consequences: the `Crypto` provider is gone, Bouncy Castle algorithms that Conscrypt provides are refused for apps targeting API 28+ and mostly removed in API 31. The legitimate exception is the Android Keystore, which must be named.

#### Prerequisites

The common Android prerequisites above.

#### Steps

1. **Decompile**: `jadx -d out/ app.apk`.

2. **Run the OWASP semgrep rule** (`mastg-android-hardcoded-security-provider.yaml`):

   ```yaml
   rules:
     - id: mastg-android-hardcoded-security-provider
       languages:
         - java
       severity: WARNING
       metadata:
         summary: This rule looks for explicitly specified security providers in getInstance calls.
       message: "[MASVS-CRYPTO-1] Explicitly specified security provider found. Do not hardcode a provider unless using AndroidKeyStore."
       patterns:
         - pattern-either:
             - pattern: $X.getInstance($ALGO, $PROVIDER)
             - pattern: $X.getInstance($ALGO, (String $PROVIDER))
             - pattern: $X.getInstance($ALGO, (java.security.Provider $PROVIDER))
         - pattern-not: KeyStore.getInstance("AndroidKeyStore")
         - metavariable-regex:
             metavariable: $X
             regex: (Cipher|KeyGenerator|KeyPairGenerator|MessageDigest|Signature|Mac|SecretKeyFactory|KeyFactory|SecureRandom|KeyAgreement|AlgorithmParameters|AlgorithmParameterGenerator|CertificateFactory|CertPathBuilder|CertPathValidator|CertStore|KeyStore)
   ```

   ```bash
   semgrep -c mastg-android-hardcoded-security-provider.yaml out/sources/
   ```

   The rule excludes only `KeyStore.getInstance("AndroidKeyStore")`. It will therefore also report `KeyGenerator.getInstance("AES", "AndroidKeyStore")`, `KeyPairGenerator.getInstance("RSA", "AndroidKeyStore")` and `SecretKeyFactory`/`KeyFactory.getInstance(..., "AndroidKeyStore")` (used to obtain `KeyInfo`). Those are required for Keystore keys; discard them during triage.

3. **Find provider changes the rule cannot see.** Inserting a provider changes the default for every unnamed call:

   ```bash
   SRC=out/sources
   grep -rnE 'Security\.(insertProviderAt|addProvider|removeProvider)\(' "$SRC"
   grep -rnE 'BouncyCastleProvider|org\.spongycastle|Conscrypt\.newProvider' "$SRC" | grep -v "^$SRC/org/" | head
   grep -rhoE 'BouncyCastle Security Provider v[0-9.]+' "$SRC" | sort -u    # bundled BC version
   ```

   Spongy Castle (`org.spongycastle`) is an Android repackaging of Bouncy Castle that has not been maintained for years; finding it is a vulnerable-dependency issue as much as a crypto one.

4. **Confirm at runtime** which provider serves each call. Add `c.getProvider().getName()` logging (the TEST-0350 hook already does this for `Cipher`) and list the provider order with `list-providers.js` from the [KNOW-0011 section](#android-security-provider-mastg-know-0011). A third-party provider at position 1 means every default lookup goes to it.

#### Observation

The list of `getInstance` calls with an explicit provider, any `Security.addProvider`/`insertProviderAt` calls, the bundled provider library and version, and (from the runtime check) the provider that actually serves each operation.

#### Evaluation

Per OWASP, the test **fails** if any `getInstance` call names a provider other than `AndroidKeyStore` for Keystore operations. We apply that with judgement:

- `"BC"`, `"Crypto"`, `"SC"` or a home-made provider for any operation: fail.
- A third-party provider inserted at high priority, or a bundled Bouncy Castle or Spongy Castle with known vulnerabilities: fail (rate with the dependency finding).
- `"AndroidKeyStore"` with `KeyStore`, `KeyGenerator`, `KeyPairGenerator`, `SecretKeyFactory` or `KeyFactory`: pass.
- A bundled, current Conscrypt named explicitly on old devices, or a current Bouncy Castle used only for an algorithm the platform lacks: technically a failure of the OWASP criterion; report as informational with the rationale.

#### Demo

From [MASTG-DEMO-0075](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0075/MASTG-DEMO-0075/). The sample mixes correct and incorrect calls, and registers a deliberately broken provider whose "AES" returns zeros:

```kotlin
Security.addProvider(CustomProvider())                              // registers "Cipher.AES" -> CustomAesCipherSpi

val keyStore = KeyStore.getInstance("AndroidKeyStore")             // PASS: required
val keyGen = KeyGenerator.getInstance("AES")                       // PASS: default provider
val cipher = Cipher.getInstance("AES/GCM/NoPadding")               // PASS: default provider
val cipherBC = Cipher.getInstance("AES/GCM/NoPadding", "BC")       // FAIL: deprecated / removed provider
val cipherCustom = Cipher.getInstance("AES/CBC/PKCS5Padding", "CustomProvider")  // FAIL: custom provider
```

Rule output:

```text
┌─────────────────┐
│ 2 Code Findings │
└─────────────────┘

    MastgTest_reversed.java
    ❯❱ rules.mastg-android-hardcoded-security-provider
          [MASVS-CRYPTO-1] Explicitly specified security provider found. Do not hardcode a provider unless
          using AndroidKeyStore.

           71┆ Cipher cipherBC = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            ⋮┆----------------------------------------
           85┆ Cipher cipherCustom = Cipher.getInstance("AES/CBC/PKCS5Padding", "CustomProvider");
```

Line 71 names Bouncy Castle, deprecated since Android 9 and removed for this algorithm in Android 12 — on a current device it throws `NoSuchAlgorithmException`. Line 85 names the custom provider, whose cipher ignores the key and the mode and returns zero bytes: a vivid illustration of why an unknown provider is a finding. The test fails. Note that `Security.addProvider(CustomProvider())` itself is not reported; step 3 is what catches it.

### MASTG-TEST-0210: Broken Symmetric Encryption Algorithms (iOS)

Source: [MASTG-TEST-0210](https://mas.owasp.org/MASTG/tests/ios/MASVS-CRYPTO/MASTG-TEST-0210/). Type: static (code), manual review.

#### Overview

On iOS, broken symmetric algorithms come almost exclusively from CommonCrypto, where `CCCrypt` (and `CCCryptorCreate`, `CCCryptorCreateWithMode`) takes a `CCAlgorithm` constant: `kCCAlgorithmDES` (1), `kCCAlgorithm3DES` (2), `kCCAlgorithmCAST` (3), `kCCAlgorithmRC4` (4), `kCCAlgorithmRC2` (5) and `kCCAlgorithmBlowfish` (6) are the ones to find. CryptoKit supports only AES-GCM and ChaCha20-Poly1305 and is out of scope. The Security framework handles only asymmetric keys and is also out of scope for this test (RSA padding is covered by supplementary check S3). Third-party code — OpenSSL or BoringSSL builds inside frameworks, CryptoSwift, libsodium, crypto-js in a web view or React Native bundle, or a hand-written DES — is in scope.

In a compiled binary the constants are just small integers in registers, so the test is done in the disassembler: find the calls, then read the argument registers.

#### Prerequisites

- The IPA, **decrypted** if it came from the App Store (`otool -l Payload/App.app/App | grep -A4 LC_ENCRYPTION_INFO`; `cryptid 1` means it is still FairPlay-encrypted). See the MASWE-0003 note for details.
- radare2 (MASTG-TOOL-0073); on macOS also `nm`, `otool` and `xcrun swift-demangle`.
- Optional: a jailbroken device with `frida-server` for runtime confirmation.

#### Steps

1. **Extract the binaries** (MASTG-TECH-0058, exploring the app package):

   ```bash
   unzip -q App.ipa -d ipa/
   APP=ipa/Payload/App.app
   BIN="$APP/$(plutil -extract CFBundleExecutable raw "$APP/Info.plist")"
   ls "$APP/Frameworks/"          # each framework binary needs the same checks
   ```

2. **Check the imports** to see which APIs are linked:

   ```bash
   nm -u "$BIN" | grep -E '_CCCrypt|_CCCryptorCreate'
   nm "$BIN" | xcrun swift-demangle | grep -E 'CryptoSwift\.(Blowfish|AES|Rabbit|ChaCha20)' | sort -u | head
   for f in "$APP"/Frameworks/*.framework; do
     b="$f/$(basename "$f" .framework)"
     nm "$b" 2>/dev/null | grep -qE 'EVP_(des|rc4|bf|rc2)_|_DES_ecb|_RC4_set_key|_BF_set_key' && echo "legacy cipher symbols: $b"
   done
   ```

3. **Locate the call sites in radare2** (MASTG-TECH-0066, static analysis on iOS). OWASP's demo script, adapted:

   ```text
   e asm.bytes=false
   e scr.color=false
   e asm.var=false
   ?e Uses of the CCCrypt function:
   afl~CCCrypt
   ?e xrefs to CCCrypt:
   axt @ sym.imp.CCCrypt
   ```

   ```bash
   r2 -q -i cccrypt.r2 -A "$BIN"
   ```

   For each cross-reference, print the instructions just before the call, for example `pd-- 9 @ 0x1000040e0`.

4. **Decode the arguments.** On arm64 the first eight integer and pointer arguments are in `x0`–`x7` (`w0`–`w7` for 32-bit values):

   | Register | `CCCrypt` | `CCCryptorCreate` | `CCCryptorCreateWithMode` |
   |---|---|---|---|
   | `w0` | `op` (0 encrypt, 1 decrypt) | `op` | `op` |
   | `w1` | **`alg`** | **`alg`** | `mode` |
   | `w2` | `options` | `options` | **`alg`** |
   | `x3` | key | key | `padding` |
   | `x4` | keyLength | keyLength | iv |
   | `x5` | iv | iv | key |
   | `x6` | dataIn | cryptorRef | keyLength |
   | `x7` | dataInLength | — | tweak |

   A `mov w1, 2` before `bl sym.imp.CCCrypt` is 3DES. When the value is not an immediate (computed or loaded from memory), follow the register back or confirm at runtime.

5. **Confirm at runtime (optional, recommended for computed arguments)** on a jailbroken device:

   ```javascript
   // hook-cccrypt.js (Frida 17 syntax)
   const cc = Process.getModuleByName('libcommonCrypto.dylib');
   const ALG = ['AES', 'DES', '3DES', 'CAST', 'RC4', 'RC2', 'Blowfish'];
   Interceptor.attach(cc.getExportByName('CCCrypt'), {
     onEnter(args) {
       const op = args[0].toInt32(), alg = args[1].toInt32(), opt = args[2].toInt32();
       const ivPtr = args[5];
       const mode = (opt & 2) ? 'ECB' : 'CBC';
       const iv = ivPtr.isNull() ? 'NULL (all-zero IV in CBC)' : hexdump(ivPtr, { length: 16, header: false, ansi: false });
       console.log('CCCrypt ' + (op === 0 ? 'encrypt' : 'decrypt') + ' alg=' + (ALG[alg] || alg) +
                   ' mode=' + mode + ' pkcs7=' + ((opt & 1) === 1) + ' keyLen=' + args[4].toInt32() + '\n  iv=' + iv);
       console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n'));
     }
   });
   ```

   ```bash
   frida -U -f com.example.app -l hook-cccrypt.js
   ```

6. **Validate each hit** by reviewing the surrounding disassembly (MASTG-TECH-0076, reviewing disassembled Objective-C and Swift code): what data flows into `dataIn`, and where `dataOut` goes.

#### Observation

The disassembly around each call to the relevant cryptographic functions, with the decoded algorithm, options, key length and IV argument, and the purpose of the operation.

#### Evaluation

The test **fails** if DES, 3DES, RC2, RC4, Blowfish or CAST is used to protect sensitive data — through CommonCrypto, a third-party library, or a custom implementation of the same algorithms. The same protocol-mandated exceptions apply as on Android (ICAO BAC, legacy payment protocols). OWASP also asks you to note "risky configurations" — ECB, short keys, IVs not from a CSPRNG — which the next test and supplementary check S1 cover. Do not apply OWASP's remark that AES-128 is insufficient against quantum attacks; NIST does not share it (see the [background](#algorithm-status)).

It **passes** if no broken algorithm protects sensitive data.

#### Demo

From [MASTG-DEMO-0018](https://mas.owasp.org/MASTG/demos/ios/MASVS-CRYPTO/MASTG-DEMO-0018/MASTG-DEMO-0018/):

```swift
let key = "0123456789abcdef01234567"            // 24-byte key for 3DES
CCCrypt(
    CCOperation(kCCEncrypt),
    CCAlgorithm(kCCAlgorithm3DES),               // 3DES
    CCOptions(kCCOptionPKCS7Padding),            // no ECB flag: CBC mode
    keyBytes, kCCKeySize3DES,
    nil,                                         // IV: NULL
    dataBytes.baseAddress, data.count,
    &encryptedBytes, encryptedBytes.count,
    &numBytesEncrypted)
```

The r2 output (`r2 -q -i cccrypt.r2 -A MASTestApp`):

```text
Uses of the CCCrypt function:
0x1000076c4    1     12 sym.imp.CCCrypt

xrefs to CCCrypt:
sym.func.100004000 0x1000040e0 [CALL:--x] bl sym.imp.CCCrypt

Use of CCCrypt:
│           0x1000040c0      mov w0, 0
│           0x1000040c4      mov w1, 2
│           0x1000040c8      mov w2, 1
│           0x1000040cc      mov x3, x23
│           0x1000040d0      mov w4, 0x18
│           0x1000040d4      mov x5, 0
│           0x1000040d8      mov x6, x22
│           0x1000040dc      mov x7, x25
│           0x1000040e0      bl sym.imp.CCCrypt
```

Decoded: `w0 = 0` encrypt; `w1 = 2` is `kCCAlgorithm3DES`; `w2 = 1` is `kCCOptionPKCS7Padding` only; `w4 = 0x18` is a 24-byte key; `x5 = 0` is a NULL IV. The test fails on the algorithm. Two corrections to the demo's annotations: the NULL IV does not mean "no IV" or ECB (the demo's AI-generated decompilation says `// IV (nil for ECB mode)`) — without `kCCOptionECBMode` this is **CBC with an all-zero IV**, which is a second finding (S1); and `x7` is `dataInLength`, not `dataOut` — the output buffer is passed on the stack (the `str x8, [sp]` a few instructions earlier). The key is also a string literal, a MASWE-0003 finding. As with the other iOS demos, treat the AI-decompiled Swift as a reading aid, not as evidence.

### MASTG-TEST-0317: Broken Symmetric Encryption Modes (iOS)

Source: [MASTG-TEST-0317](https://mas.owasp.org/MASTG/tests/ios/MASVS-CRYPTO/MASTG-TEST-0317/). Type: static (code), manual review. Best practice: MASTG-BEST-0005.

#### Overview

The iOS counterpart to TEST-0232. CryptoKit has no ECB. In CommonCrypto, ECB is enabled by the `kCCOptionECBMode` bit (`0x0002`) in the `options` argument of `CCCrypt` or `CCCryptorCreate`, or by `mode = kCCModeECB` (1) in `CCCryptorCreateWithMode`. Because `options` is a **bitmask**, the register value must be decomposed: `2` is ECB without padding, `3` (`0b11`) is ECB with PKCS#7 padding, `1` is CBC with PKCS#7, `0` is CBC with no padding. Third-party libraries (CryptoSwift `ECB()`, OpenSSL `EVP_aes_*_ecb`, crypto-js `CryptoJS.mode.ECB`) are in scope too.

#### Prerequisites

As for TEST-0210.

#### Steps

1. **Extract the binaries** (MASTG-TECH-0058), as in TEST-0210 step 1.

2. **Find the calls** (MASTG-TECH-0066):

   ```text
   afl~CCCrypt
   axt @ sym.imp.CCCrypt
   axt @ sym.imp.CCCryptorCreate
   axt @ sym.imp.CCCryptorCreateWithMode
   ```

3. **Read the mode argument** at each call site: bit 1 of `w2` for `CCCrypt`/`CCCryptorCreate` (`(value & 2) != 0` means ECB), or `w1 == 1` for `CCCryptorCreateWithMode`.

4. **Check third-party ECB:**

   ```bash
   nm "$BIN" | xcrun swift-demangle | grep -E 'CryptoSwift\.ECB' | sort -u
   strings -a "$BIN" | grep -E 'EVP_aes_(128|192|256)_ecb'
   find "$APP" -name '*.jsbundle' -o -name 'main.jsbundle' | xargs grep -l 'mode.ECB' 2>/dev/null
   ```

5. **Confirm at runtime** with `hook-cccrypt.js` from TEST-0210, which prints `mode=ECB` or `mode=CBC` for every call.

6. **Validate** what the ECB-encrypted data is (MASTG-TECH-0076).

#### Observation

The uses of symmetric encryption with their decoded modes and options, and the data they protect.

#### Evaluation

The test **fails** if ECB is used on sensitive data: `CCCrypt`/`CCCryptorCreate` with `kCCOptionECBMode` set in `options`, `CCCryptorCreateWithMode` with `kCCModeECB`, or ECB in a third-party library.

It **passes** if no ECB use exists for sensitive data. A pass here does **not** mean the CBC that replaces it is sound: check its IV (S1) and its integrity (S2).

#### Demo

From [MASTG-DEMO-0080](https://mas.owasp.org/MASTG/demos/ios/MASVS-CRYPTO/MASTG-DEMO-0080/MASTG-DEMO-0080/):

```swift
let key = "0123456789abcdef"                     // 16-byte key for AES-128
CCCrypt(
    CCOperation(kCCEncrypt),
    CCAlgorithm(kCCAlgorithmAES),
    CCOptions(kCCOptionECBMode | kCCOptionPKCS7Padding),   // ECB
    keyBytes, kCCKeySizeAES128,
    nil,
    dataBytes.baseAddress, data.count,
    &encryptedBytes, encryptedBytes.count,
    &numBytesEncrypted)
```

The r2 script finds two call sites (the binary also contains the 3DES function from DEMO-0018) and prints the second:

```text
xrefs to CCCrypt:
sym.func.100004000 0x1000040e0 [CALL:--x] bl sym.imp.CCCrypt
sym.func.10000469c 0x100004824 [CALL:--x] bl sym.imp.CCCrypt

Use of CCCrypt with ECB mode:
│           0x100004808      mov w0, 0
│           0x10000480c      mov w1, 0
│           0x100004810      mov w2, 3
│           0x100004814      mov w4, 0x10
│           0x100004818      mov x5, 0
│           0x10000481c      mov x6, x20
│           0x100004820      mov x7, x24
│           0x100004824      bl sym.imp.CCCrypt
```

`w0 = 0` encrypt, `w1 = 0` AES, `w2 = 3` is `kCCOptionPKCS7Padding | kCCOptionECBMode`, `w4 = 0x10` a 16-byte key, `x5 = 0` no IV (irrelevant for ECB). The test fails: AES-128 in ECB mode with PKCS#7 padding. The sample's 43-byte plaintext spans three blocks, so any repeated 16-byte block in real data would be visible in the output.

### Supplementary checks (Guler Tech methodology)

These checks cover modes of introduction listed on the MASWE page that no OWASP test addresses yet. Run them on every assessment where the app encrypts anything. Each follows the same structure as the OWASP tests in compressed form.

#### S1: IV and nonce reuse on iOS

**Overview.** The iOS equivalent of TEST-0309/0310. Signals: `CCCrypt` in CBC mode with `iv = NULL` (an all-zero IV) or a constant IV; `CCCryptorCreateWithMode` in CTR mode with a constant IV; CryptoKit `AES.GCM.Nonce(data:)` or `ChaChaPoly.Nonce(data:)` built from constants or counters; CryptoSwift `CBC(iv:)`, `CTR(iv:)` or `GCM(iv:mode:)` with constant arrays; libsodium nonces that are not from `randombytes_buf`.

**Prerequisites.** As for TEST-0210.

**Steps.**

1. At every `CCCrypt` call site found in TEST-0210, read `x5`: `mov x5, 0` with ECB bit clear means a zero IV; an `adrp x5, ...` / `add x5, x5, ...` pair pointing into `__TEXT,__const` or `__DATA` means a constant IV — dump it with `px 16 @ <address>`.
2. Find explicit CryptoKit nonces: `nm "$BIN" | xcrun swift-demangle | grep -E '(AES\.GCM|ChaChaPoly)\.Nonce' | sort -u`. An import of the `Nonce(data:)` initialiser means the app supplies its own nonces; find the callers with `axt` and see where the bytes come from.
3. Run `hook-cccrypt.js` and repeat each flow twice, then restart the app; identical non-NULL IVs for the same key, or `NULL` in CBC mode, confirm the finding. For CryptoKit, hook the nonce initialiser by its mangled symbol (list them with `nm "$BIN" | grep Nonce`) or simply compare the first 12 bytes of two `combined` outputs captured from storage or traffic: they are the nonce.

**Observation.** Each encryption site with its mode, IV or nonce source and value, and whether it repeats.

**Evaluation.** Fails on a zero, constant or repeating IV for CBC under one key, or any repeated nonce for CTR, GCM or ChaCha20-Poly1305. Passes when IVs and nonces come from `SecRandomCopyBytes`, CryptoKit's default (no `nonce:` argument), or a counter that provably cannot repeat for the key's lifetime.

**Demo.** The DEMO-0018 call above: `CCCrypt` with `kCCOptionPKCS7Padding` and `nil` IV is 3DES-CBC with a zero IV, so equal messages produce equal ciphertexts. In CryptoKit, the vulnerable pattern looks like this:

```swift
let fixedNonce = try AES.GCM.Nonce(data: Data(repeating: 0, count: 12))   // reused for every message
let box = try AES.GCM.seal(record, using: key, nonce: fixedNonce)
```

The fix is to delete the `nonce:` argument.

#### S2: CBC without integrity, and padding oracles

**Overview.** AES-CBC (or CTR) with no MAC lets an attacker modify ciphertext undetected; with PKCS#7 padding and an observable padding error it lets them decrypt it. On mobile, check both sides: the app decrypting attacker-controllable input (data from an exported component, a deep link, a shared file, a push payload, a server response an attacker can influence), and the backend decrypting what the app sends (encrypted request bodies, "encrypted tokens", custom session blobs).

**Prerequisites.** Decompiled app or disassembled binary; for the backend part, written authorisation for the API in scope and an intercepting proxy (Burp Suite or similar).

**Steps.**

1. Find CBC and CTR use: on Android `grep -rnE '"AES/(CBC|CTR)/' out/sources/` and Keystore keys with `BLOCK_MODE_CBC` or `BLOCK_MODE_CTR`; on iOS every `CCCrypt` without the ECB bit.
2. For each, look for a MAC over the IV and ciphertext — `Mac.getInstance("HmacSHA256")` or `CCHmac` near the cipher — and check the order: the MAC must be **verified before decryption**, with `MessageDigest.isEqual` (Java) or a constant-time comparison (not `Arrays.equals` or `==` on `Data`), and with a key different from the encryption key.
3. On the decryption side, look at error handling: `catch (BadPaddingException e)` returning a different result from other failures is an oracle in the making.
4. For server-side decryption of app-supplied ciphertext, with authorisation: capture a request in the proxy, flip one bit in the last byte of the second-to-last ciphertext block, and compare responses with an unmodified request and with a request whose ciphertext is truncated. Different status codes, messages or consistent timing differences between "bad padding" and "bad data" indicate an oracle. PadBuster can then automate confirmation (`padbuster <URL> <ciphertext> 16 -encoding 0` for Base64 ciphertexts, plus `-cookies` or `-post` as needed) — keep request volume within the rules of engagement.

**Observation.** The CBC/CTR sites, whether and how a MAC is applied and checked, the error-handling behaviour, and (for the backend) the differential responses.

**Evaluation.** Fails if CBC or CTR protects data whose integrity matters without encrypt-then-MAC (or equivalent), or if a padding or MAC error is distinguishable by an attacker. A confirmed padding oracle is a high-severity finding by itself. Passes if an AEAD mode is used, or CBC/CTR is wrapped in a correctly ordered, constant-time, separately keyed MAC.

**Demo.** The classic pattern on Android:

```kotlin
fun decrypt(blob: ByteArray): String? = try {
    val c = Cipher.getInstance("AES/CBC/PKCS5Padding")
    c.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(blob.copyOfRange(0, 16)))
    String(c.doFinal(blob, 16, blob.size - 16))
} catch (e: BadPaddingException) {
    null                                    // "padding_error" in the API response
} catch (e: Exception) {
    ""                                      // a different signal for everything else
}
```

No MAC, and two distinguishable failure modes: the precondition for a padding oracle wherever this result reaches an attacker.

#### S3: RSA encryption padding

**Overview.** Textbook RSA and PKCS#1 v1.5 encryption (CWE-780). Signals on Android: `"RSA"` alone, `"RSA/ECB/NoPadding"`, `"RSA/NONE/NoPadding"`, `"RSA/ECB/PKCS1Padding"`, `KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1` in a Keystore spec. On iOS: `.rsaEncryptionRaw`, `.rsaEncryptionPKCS1`, `kSecPaddingNone`, `kSecPaddingPKCS1`, and the same choices inside SwiftyRSA or OpenSSL (`RSA_PKCS1_PADDING`, `RSA_NO_PADDING`).

**Steps.** On Android: `grep -rnE '"RSA(/[A-Za-z]+/(NoPadding|PKCS1Padding))?"' out/sources/` and `grep -rn 'ENCRYPTION_PADDING_RSA_PKCS1\|"PKCS1Padding"' out/sources/`. On iOS: `nm -u "$BIN" | grep -E '_SecKeyCreateEncryptedData|_SecKeyEncrypt'`, then read the algorithm argument at each call site (`x1` for `SecKeyCreateEncryptedData`) — the `SecKeyAlgorithm` values are `CFString` constants, so r2 shows a load from a symbol such as `kSecKeyAlgorithmRSAEncryptionPKCS1`. At runtime, hook `Cipher.init` (Android) or `SecKeyCreateEncryptedData` (iOS) and log the algorithm.

**Evaluation.** Fails on textbook RSA in any context, and on PKCS#1 v1.5 encryption for new data (disallowed for key transport after 2023 by SP 800-131A Rev. 2). Rate PKCS#1 v1.5 higher where you can show a decryption oracle — usually a backend that reports decryption failures differently — and lower where the app only encrypts to a server that fails uniformly. Passes with OAEP (SHA-256 or above preferred) or a hybrid scheme (ECIES, HPKE, `.rsaEncryptionOAEPSHA256AESGCM`).

**Demo.** MASTG-DEMO-0071 (TEST-0307) encrypts with `RSA/ECB/PKCS1Padding` under a multi-purpose key, so it fails here too.

#### S4: Non-cryptographic "encryption"

**Overview.** XOR with a constant or a repeating key, Base64 or hex encoding, ROT-n, byte reversal and custom substitution tables, presented as encryption.

**Steps.** In jadx output, list methods named like `encrypt`, `decrypt`, `cipher`, `obfuscate`, `scramble`, `encode` and inspect those that never reach `Cipher`, `Mac` or a crypto library:

```bash
grep -rnE '(byte|char)\) ?\([^)]*\^ ' out/sources/ | grep -vE '^out/sources/(androidx|kotlin|okio|okhttp3)/' | head -50
grep -rnlE '(encrypt|decrypt|obfuscat|scramble)[A-Za-z]*\(' out/sources/ | xargs grep -L 'javax\.crypto' | head
```

On iOS, look for Swift and Objective-C methods with the same names (`nm "$BIN" | xcrun swift-demangle | grep -iE 'encrypt|obfuscat'`) and read them in r2 for `eor` loops. Confirm by reversing the transformation on stored data (for example `base64 -d`, or XOR with the recovered constant).

**Evaluation.** Fails if any such transformation is relied on to protect sensitive data. Passes if every "encrypt" path reaches a real cipher. Obfuscation for anti-tamper purposes is not in scope here unless it is presented as data protection.

#### S5: Key and tag lengths

**Overview and steps.** Check RSA moduli (`KeyPairGenerator.initialize(1024)`, `setKeySize(1024)`, `kSecAttrKeySizeInBits: 1024`), Blowfish and RC4 key sizes (TEST-0221 demo uses a 64-bit Blowfish key), and GCM tag lengths (`GCMParameterSpec(64, iv)` or smaller; the first argument is in bits). Key generation itself is covered in [MASWE-0013](/mobile/maswe-0013-improper-key-generation/).

**Evaluation.** Fails on RSA below 2048 bits, symmetric keys below 112 bits of effective strength, and GCM tags below 96 bits; flag 96- to 120-bit tags as informational unless the design justifies them.

## Best practices

### MASTG-BEST-0005: Use Secure Encryption Modes

Source: [MASTG-BEST-0005](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0005/). Platform: Android (applies equally to iOS).

Replace ECB and unauthenticated modes with an authenticated mode: AES-GCM or AES-CCM (SP 800-38D, SP 800-38C), which provide confidentiality, integrity and authenticity in one operation. OWASP recommends avoiding CBC: it is better than ECB, but incorrect padding handling leads to padding oracles. In practice on Android that means `AES/GCM/NoPadding` with a Keystore key restricted to `BLOCK_MODE_GCM`, and on iOS `AES.GCM` or `ChaChaPoly` from CryptoKit. CCM is not offered by Conscrypt or CryptoKit, so GCM (or ChaCha20-Poly1305) is the practical choice. If an existing format forces CBC, wrap it in encrypt-then-MAC as described in the [background](#integrity-and-key-separation) and plan a migration. The Android reference is the [Cryptography](https://developer.android.com/privacy-and-security/cryptography) guide.

### MASTG-BEST-0009: Use Secure Encryption Algorithms

Source: [MASTG-BEST-0009](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0009/). Platform: Android (applies equally to iOS).

Replace DES, 3DES, RC4, Blowfish and similar with AES (OWASP suggests AES-256, preferably in GCM mode) or ChaCha20 (in its authenticated ChaCha20-Poly1305 form). AES-128-GCM is also acceptable under current NIST guidance; choose 256-bit keys where data must stay confidential for a long time or a policy requires it. Migration matters as much as the new algorithm: decrypt legacy data once with the old algorithm, re-encrypt it with the new one under a new key, delete the old ciphertext and key, and remove the legacy decryption path in a later release. Android's ["Broken or risky cryptographic algorithm"](https://developer.android.com/privacy-and-security/risks/broken-cryptographic-algorithm) page gives the same advice.

### MASTG-BEST-0020: Update the GMS Security Provider

Source: [MASTG-BEST-0020](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0020/). Platform: Android. Knowledge: MASTG-KNOW-0011.

Google Play services ships an updatable security provider that patches the device's OpenSSL/BoringSSL-based provider and `TrustManager` independently of OS updates. Install it early in app start-up, before the first TLS connection:

```kotlin
// requires Google Play services, e.g. implementation("com.google.android.gms:play-services-base:<current version>")
try {
    ProviderInstaller.installIfNeeded(applicationContext)          // blocking: call off the main thread
} catch (e: GooglePlayServicesRepairableException) {
    GoogleApiAvailability.getInstance().showErrorNotification(applicationContext, e.connectionStatusCode)
} catch (e: GooglePlayServicesNotAvailableException) {
    // No Play services: rely on the platform or a bundled Conscrypt
}
```

`ProviderInstaller.installIfNeededAsync(context, listener)` is the non-blocking alternative. After installation, `Security.getProviders()[0].name` is `GmsCore_OpenSSL`, which you can confirm with the provider-listing hook. For devices without Google Play services (Huawei, Amazon, AOSP builds), detect the absence at runtime and bundle Conscrypt (`Security.insertProviderAt(Conscrypt.newProvider(), 1)`) so that cryptography and TLS behave consistently across the fleet. This practice mainly protects network communication; for MASWE-0007 its relevance is that the default provider — which you should be using — is kept current, rather than an app-pinned provider.

### Secure implementation

Guler Tech reference code. Adapt the key aliases, associated data and error handling to the app.

**Android: AES-256-GCM with a Keystore key.** The Keystore picks the IV; the key cannot be used for anything else.

```kotlin
private const val ALIAS = "data-key-v1"
private const val TRANSFORMATION = "AES/GCM/NoPadding"
private const val IV_LEN = 12

fun getOrCreateKey(): SecretKey {
    val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
    val spec = KeyGenParameterSpec.Builder(
            ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)          // GCM only
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setKeySize(256)
        // setRandomizedEncryptionRequired(true) is the default: never switch it off
        .build()
    return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        .apply { init(spec) }
        .generateKey()
}

fun encrypt(plaintext: ByteArray, aad: ByteArray): ByteArray {
    val cipher = Cipher.getInstance(TRANSFORMATION)
    cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())        // no IV: the Keystore generates one
    cipher.updateAAD(aad)                                     // bind context, e.g. record ID + version
    return cipher.iv + cipher.doFinal(plaintext)              // IV (12) || ciphertext || tag (16)
}

fun decrypt(blob: ByteArray, aad: ByteArray): ByteArray {
    val cipher = Cipher.getInstance(TRANSFORMATION)
    cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(),
        GCMParameterSpec(128, blob, 0, IV_LEN))
    cipher.updateAAD(aad)
    return cipher.doFinal(blob, IV_LEN, blob.size - IV_LEN)  // AEADBadTagException if tampered
}
```

**Android: Tink AEAD** (keyset encrypted under a Keystore master key; nonces, format and rotation handled by Tink):

```kotlin
// build.gradle: implementation("com.google.crypto.tink:tink-android:<current version>")
AeadConfig.register()
val keysetHandle = AndroidKeysetManager.Builder()
    .withSharedPref(context, "app_keyset", "app_keyset_prefs")
    .withKeyTemplate(KeyTemplates.get("AES256_GCM"))
    .withMasterKeyUri("android-keystore://app_master_key")
    .build()
    .keysetHandle
val aead = keysetHandle.getPrimitive(Aead::class.java)  // newer Tink versions also offer an overload taking a configuration
val ciphertext = aead.encrypt(plaintext, associatedData)
val decrypted = aead.decrypt(ciphertext, associatedData)
```

**Android: RSA-OAEP for key transport.** Pass the OAEP parameters explicitly: providers disagree on the MGF1 digest for `OAEPWithSHA-256AndMGF1Padding` (desktop Java's SunJCE uses SHA-1 for MGF1 by default, others use SHA-256), and a mismatch with the server fails decryption.

```kotlin
val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey,
    OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT))
val wrappedKey = cipher.doFinal(randomAesKey.encoded)       // encrypt a symmetric key, not the data
```

For RSA private keys held in the Android Keystore, check which MGF1 digests the Keystore supports for your `minSdk` before choosing the parameters; MGF1 with SHA-1 inside OAEP is not a weakness.

**Android: encrypt-then-MAC, only when CBC is forced on you.**

```kotlin
// encKey and macKey are independent keys
fun seal(pt: ByteArray): ByteArray {
    val c = Cipher.getInstance("AES/CBC/PKCS5Padding").apply { init(Cipher.ENCRYPT_MODE, encKey) }
    val body = c.iv + c.doFinal(pt)                         // random IV from the provider
    val tag = Mac.getInstance("HmacSHA256").apply { init(macKey) }.doFinal(body)
    return body + tag
}

fun open(blob: ByteArray): ByteArray {
    val body = blob.copyOfRange(0, blob.size - 32)
    val tag = blob.copyOfRange(blob.size - 32, blob.size)
    val expected = Mac.getInstance("HmacSHA256").apply { init(macKey) }.doFinal(body)
    if (!MessageDigest.isEqual(tag, expected)) throw GeneralSecurityException("decryption failed")
    val c = Cipher.getInstance("AES/CBC/PKCS5Padding")
    c.init(Cipher.DECRYPT_MODE, encKey, IvParameterSpec(body, 0, 16))
    return c.doFinal(body, 16, body.size - 16)
}
```

Use one generic error for every failure path, as above.

**iOS: CryptoKit AES-GCM** (or `ChaChaPoly` with the same shape). Do not pass `nonce:`.

```swift
import CryptoKit

enum SealError: Error { case badNonceSize }

func seal(_ plaintext: Data, key: SymmetricKey, context: Data) throws -> Data {
    let box = try AES.GCM.seal(plaintext, using: key, authenticating: context)   // random 96-bit nonce
    guard let combined = box.combined else { throw SealError.badNonceSize }
    return combined                                                              // nonce || ciphertext || tag
}

func open(_ combined: Data, key: SymmetricKey, context: Data) throws -> Data {
    let box = try AES.GCM.SealedBox(combined: combined)
    return try AES.GCM.open(box, using: key, authenticating: context)           // throws on tampering
}
```

Store the `SymmetricKey` in the Keychain or wrap it with a Secure Enclave key; the pattern is in the [MASWE-0003 note](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/#secure-implementation).

**iOS: RSA when you must.** Use `SecKeyCreateEncryptedData(publicKey, .rsaEncryptionOAEPSHA256AESGCM, data as CFData, &error)`, which does hybrid RSA-OAEP plus AES-GCM for you, after checking `SecKeyIsAlgorithmSupported(publicKey, .encrypt, .rsaEncryptionOAEPSHA256AESGCM)`. For new designs prefer ECIES with a P-256 key (`.eciesEncryptionCofactorVariableIVX963SHA256AESGCM`) or HPKE.

**Both platforms: design rules that prevent the findings in this note.**

- Never pass an IV or nonce on encryption unless you can prove uniqueness; let the Keystore, the provider, CryptoKit or Tink generate it.
- Use associated data to bind ciphertext to its context (user ID, record ID, schema version), so ciphertext cannot be moved between records.
- One key per purpose and per data class, enforced through Keystore purposes; rotate long-lived high-volume keys well before the 2^32 random-nonce limit.
- Return a single, generic error from every decryption failure, and make server APIs do the same.
- Add Android Lint (`GetInstance`, `DeletedProvider`, `DeprecatedProvider`) and semgrep rules like the ones above to CI so regressions are caught before release.

## Rating findings

Rate on what the encryption protects, whether the attacker can obtain the ciphertext (and, for oracle and forgery attacks, submit it), and whether the weakness is practically exploitable or a compliance gap. Use these as starting points.

| Rating | Conditions |
|---|---|
| **Critical** | Broken encryption on data or tokens the **backend trusts**, exploitable remotely and across users: a confirmed padding oracle on an API that decrypts app-supplied ciphertext; ECB or unauthenticated CBC/CTR tokens whose blocks or bits can be changed to escalate privileges or impersonate users; a GCM nonce reused under a server-side key, enabling forgery; DES or RC4 protecting credentials or session secrets in transit. |
| **High** | Practical plaintext recovery or tampering of sensitive user data where the attacker can reach the ciphertext (backups, cloud sync, shared storage, intercepted traffic): DES or RC4; ECB on structured or low-entropy sensitive values; CTR, GCM or ChaCha20-Poly1305 nonce reuse; textbook RSA; PKCS#1 v1.5 with a demonstrated oracle; XOR or Base64 presented as encryption of sensitive data. |
| **Medium** | Weaknesses that need local access or a further condition: 3DES or Blowfish protecting sensitive data at rest (non-compliant, rarely exploitable at mobile volumes); ECB or zero/static-IV CBC on local data reachable only with root, jailbreak or backup access; CBC without a MAC where no oracle is reachable but tampering matters; a key pair authorised and used for both encryption and signing; `setRandomizedEncryptionRequired(false)` on a key protecting sensitive data. |
| **Low** | Defence-in-depth gaps: an explicitly named deprecated or custom provider; PKCS#1 v1.5 encryption to a server that fails uniformly; a multi-purpose key authorisation with only one role used; GCM tags shorter than 128 bits but at least 96; broken algorithms used only to decrypt legacy data during a migration; deprecated Jetpack Security still in use. |
| **Info** | Protocol-mandated legacy algorithms (ICAO BAC 3DES, EMV) with the stronger variant preferred; `RSA/ECB/...` naming flagged by the ECB rule; algorithms registered but never used in third-party SDKs; ECB on a single block of random data; `AndroidKeyStore` provider names reported by the provider rule. |

In the report, give the exact call site (class and line, or binary and address), the decoded parameters (algorithm, mode, padding, IV source, key identity), what the ciphertext protects, and a proof: two identical ECB blocks, two ciphertexts with the same IV, the XOR recovery above, or the differential responses of an oracle. Proof of exploitability is what separates High from Medium in most of these findings.

## References

- OWASP MASWE — [MASWE-0007: Improper Encryption](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0007/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0011: Security Provider](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0011/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0012: Key Generation](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0012/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0066: CryptoKit](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0066/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0067: CommonCrypto, SecKey and Wrapper libraries](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0067/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0068: Cryptographic Third-Party libraries](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0068/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0221: Broken Symmetric Encryption Algorithms](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0221/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0232: Broken Symmetric Encryption Modes](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0232/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0350: Runtime Use of Broken Symmetric Encryption Modes](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0350/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0309: References to Reused Initialization Vectors in Symmetric Encryption](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0309/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0310: Runtime Use of Reused Initialization Vectors in Symmetric Encryption](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0310/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0307: References to Asymmetric Key Pairs Used For Multiple Purposes](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0307/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0308: Runtime Use of Asymmetric Key Pairs Used For Multiple Purposes](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0308/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0312: References to Explicit Security Provider in Cryptographic APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0312/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0210: Broken Symmetric Encryption Algorithms](https://mas.owasp.org/MASTG/tests/ios/MASVS-CRYPTO/MASTG-TEST-0210/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0317: Broken Symmetric Encryption Modes](https://mas.owasp.org/MASTG/tests/ios/MASVS-CRYPTO/MASTG-TEST-0317/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-BEST-0005: Use Secure Encryption Modes](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0005/), [MASTG-BEST-0009: Use Secure Encryption Algorithms](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0009/), [MASTG-BEST-0020: Update the GMS Security Provider](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0020/) (CC BY-SA 4.0)
- OWASP MASTG — demos [MASTG-DEMO-0022](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0022/MASTG-DEMO-0022/), [MASTG-DEMO-0023](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0023/MASTG-DEMO-0023/), [MASTG-DEMO-0058](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0058/MASTG-DEMO-0058/), [MASTG-DEMO-0071](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0071/MASTG-DEMO-0071/), [MASTG-DEMO-0072](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0072/MASTG-DEMO-0072/), [MASTG-DEMO-0075](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0075/MASTG-DEMO-0075/), [MASTG-DEMO-0018](https://mas.owasp.org/MASTG/demos/ios/MASVS-CRYPTO/MASTG-DEMO-0018/MASTG-DEMO-0018/), [MASTG-DEMO-0080](https://mas.owasp.org/MASTG/demos/ios/MASVS-CRYPTO/MASTG-DEMO-0080/MASTG-DEMO-0080/) (CC BY-SA 4.0)
- OWASP MASTG — techniques [MASTG-TECH-0005](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/), [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/), [MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/); tools [Frida (MASTG-TOOL-0001)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0001/), [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [radare2 (MASTG-TOOL-0073)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/), [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/), [frooky (MASTG-TOOL-0145)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0145/) (CC BY-SA 4.0)
- OWASP MASTG — legacy (MASTG v1) tests superseded by the above: [MASTG-TEST-0013](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0013/), [MASTG-TEST-0014](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0014/), [MASTG-TEST-0015](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0015/), [MASTG-TEST-0061](https://mas.owasp.org/MASTG/tests/ios/MASVS-CRYPTO/MASTG-TEST-0061/) (CC BY-SA 4.0)
- [Android Developers — Cryptography](https://developer.android.com/privacy-and-security/cryptography) (including deprecated functionality and PBE ciphers without an IV)
- [Android Developers — Broken or risky cryptographic algorithm](https://developer.android.com/privacy-and-security/risks/broken-cryptographic-algorithm)
- [Android Developers — Android Keystore system](https://developer.android.com/privacy-and-security/keystore), [`KeyGenParameterSpec.Builder`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder), [`KeyProtection.Builder`](https://developer.android.com/reference/android/security/keystore/KeyProtection.Builder), [`KeyProperties`](https://developer.android.com/reference/android/security/keystore/KeyProperties)
- [Android Developers — Update your security provider to protect against SSL exploits](https://developer.android.com/privacy-and-security/security-gms-provider)
- [Android Developers Blog — Cryptography changes in Android P](https://android-developers.googleblog.com/2018/03/cryptography-changes-in-android-p.html) and [Android 12 behaviour changes: Bouncy Castle](https://developer.android.com/about/versions/12/behavior-changes-all#bouncy-castle)
- [Google Play Console Help — app security improvement guidance on unsafe encryption](https://support.google.com/faqs/answer/10046138) and [related remediation guidance](https://support.google.com/faqs/answer/9450925)
- [Apple — CryptoKit](https://developer.apple.com/documentation/cryptokit), [`AES.GCM`](https://developer.apple.com/documentation/cryptokit/aes/gcm), [`ChaChaPoly`](https://developer.apple.com/documentation/cryptokit/chachapoly)
- [Apple — `SecKeyCreateEncryptedData`](https://developer.apple.com/documentation/security/seckeycreateencrypteddata%28_:_:_:_:%29) and [Using keys for encryption](https://developer.apple.com/documentation/security/using-keys-for-encryption)
- [Apple — `CommonCryptor.h` (CCCrypt man page)](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/CCCrypt.3cc.html)
- [Google Tink — documentation](https://developers.google.com/tink) and [tink-java](https://github.com/tink-crypto/tink-java)
- [NIST SP 800-38A — Block Cipher Modes of Operation](https://csrc.nist.gov/pubs/sp/800/38/a/final), [Decision to revise SP 800-38A (2023)](https://csrc.nist.gov/news/2023/decision-to-revise-nist-sp-800-38a), [NIST IR 8459](https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8459.pdf)
- [NIST SP 800-38D — Galois/Counter Mode (GCM) and GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [NIST SP 800-131A Rev. 2 — Transitioning the Use of Cryptographic Algorithms and Key Lengths](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf)
- [NIST SP 800-67 Rev. 2 — TDEA (withdrawn 2024)](https://csrc.nist.gov/pubs/sp/800/67/r2/final) and [FIPS 46-3 — DES (withdrawn 2005)](https://csrc.nist.gov/pubs/fips/46-3/final)
- [NIST SP 800-56B Rev. 2 — Key establishment using integer factorization cryptography](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Br2.pdf)
- [NIST SP 800-57 Part 1 Rev. 5 — Recommendation for Key Management](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf)
- [NIST IR 8547 (initial public draft) — Transition to Post-Quantum Cryptography Standards](https://csrc.nist.gov/pubs/ir/8547/ipd)
- [RFC 8439 — ChaCha20 and Poly1305](https://www.rfc-editor.org/rfc/rfc8439), [RFC 8452 — AES-GCM-SIV](https://www.rfc-editor.org/rfc/rfc8452), [RFC 7465 — Prohibiting RC4 Cipher Suites](https://www.rfc-editor.org/rfc/rfc7465), [RFC 8017 — PKCS #1 v2.2](https://www.rfc-editor.org/rfc/rfc8017)
- [Sweet32: Birthday attacks on 64-bit block ciphers](https://sweet32.info/), [RC4 NOMORE](https://www.rc4nomore.com/), [ROBOT attack](https://robotattack.org/)
- Rizzo and Duong, [Practical Padding Oracle Attacks (USENIX WOOT 2010)](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Rizzo.pdf); Böck et al., [Nonce-Disrespecting Adversaries: Practical Forgery Attacks on GCM in TLS (USENIX WOOT 2016)](https://eprint.iacr.org/2016/475)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- CWE: [208](https://cwe.mitre.org/data/definitions/208.html), [323](https://cwe.mitre.org/data/definitions/323.html), [325](https://cwe.mitre.org/data/definitions/325.html), [326](https://cwe.mitre.org/data/definitions/326.html), [327](https://cwe.mitre.org/data/definitions/327.html), [329](https://cwe.mitre.org/data/definitions/329.html), [780](https://cwe.mitre.org/data/definitions/780.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
