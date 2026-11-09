---
title: "Improper Verification of Cryptographic Signature (MASWE-0011)"
date: 2026-11-09 09:06:00 +0000
subcategory: crypto
summary: "Skipped or ignored checks, alg:none and key confusion, untrusted keys, partial payloads: how to test and prove signature-verification bypasses on mobile."
refs: [MASWE-0011, MASVS-CRYPTO-1, CWE-295, CWE-347]
tags: [android, ios, masvs-crypto, signature-verification, jwt, frida]
---

This note is part of our [MASVS-CRYPTO guide](/mobile/masvs-crypto-cryptography-guide/) and covers OWASP [MASWE-0011](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0011/): an app that accepts forged or tampered data as authentic because it checks a signature badly, or not at all. The scheme can be flawless and the keys perfectly stored; none of it matters if the result of `verify()` is ignored, an exception handler turns failure into success, the token tells the app which algorithm and key to use, or the public key arrives in the same download as the data it is supposed to vouch for. Signing problems are covered separately in [MASWE-0010](/mobile/maswe-0010-improper-signature-generation/). Here you will find what a correct verification has to check, the failure patterns we see in mobile apps (including JWTs, updates, licences, in-app purchases and downloaded models), eight tests with Frida and static procedures, a tampering method that turns a suspicion into a demonstrated bypass, reference implementations, and severity guidance.

> **Note:** At the time of writing, the live MASWE page for MASWE-0011 links no Knowledge, Tests or Best Practices. The Knowledge and Testing sections below are **Guler Tech methodology**, structured like OWASP tests. Related MASTG material we found and cite: the storage-integrity tests MASTG-TEST-0338 (Android) and MASTG-TEST-0387 (iOS) with MASTG-DEMO-0150, Knowledge pages MASTG-KNOW-0029, 0067 and 0086, and Best Practices MASTG-BEST-0065 and 0066. OWASP maps those tests to MASWE-0057 (app resources integrity), and both MASWE-0057 and MASWE-0049 (unsafe dynamic code loading) refer to MASWE-0011 for the signature check itself.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Generic: What a correct verification checks (Guler Tech)](#generic-what-a-correct-verification-checks-guler-tech)
  - [Generic: Verifier failure patterns (Guler Tech)](#generic-verifier-failure-patterns-guler-tech)
  - [Generic: JWS and JWT verification on the client (Guler Tech)](#generic-jws-and-jwt-verification-on-the-client-guler-tech)
  - [Generic: Trust anchors for the signer's key (Guler Tech)](#generic-trust-anchors-for-the-signers-key-guler-tech)
  - [Android: Verification APIs and integrity checks (MASTG-KNOW-0029)](#android-verification-apis-and-integrity-checks-mastg-know-0029)
  - [iOS: SecKey, CryptoKit and storage integrity checks (MASTG-KNOW-0067, MASTG-KNOW-0086)](#ios-seckey-cryptokit-and-storage-integrity-checks-mastg-know-0067-mastg-know-0086)
  - [Generic: Where mobile apps verify signatures (Guler Tech)](#generic-where-mobile-apps-verify-signatures-guler-tech)
- [Testing](#testing)
  - [Test 1: Inventory of verification sites and trust anchors (Android)](#test-1-inventory-of-verification-sites-and-trust-anchors-android)
  - [Test 2: Inventory of verification sites and trust anchors (iOS)](#test-2-inventory-of-verification-sites-and-trust-anchors-ios)
  - [Test 3: Runtime verification results and their handling (Android)](#test-3-runtime-verification-results-and-their-handling-android)
  - [Test 4: Runtime verification results and their handling (iOS)](#test-4-runtime-verification-results-and-their-handling-ios)
  - [Test 5: Proving a bypass by tampering signed data (Android, iOS)](#test-5-proving-a-bypass-by-tampering-signed-data-android-ios)
  - [Test 6: JWT and JWS handling on the client (Android, iOS)](#test-6-jwt-and-jws-handling-on-the-client-android-ios)
  - [Test 7: Purchases, licences and entitlements verified on the device (Android, iOS)](#test-7-purchases-licences-and-entitlements-verified-on-the-device-android-ios)
  - [Test 8: Downloaded code, updates and ML models (Android, iOS)](#test-8-downloaded-code-updates-and-ml-models-android-ios)
- [Secure implementation](#secure-implementation)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

Signature verification answers one question: *did the holder of a key I already trust produce exactly these bytes?* Apps ask it about remote configuration, feature flags, over-the-air JavaScript bundles, plugins and scripts, machine-learning models, licence files, purchase receipts and transactions, identity tokens, QR codes and tickets, and data they wrote to local storage themselves. Wherever the answer gates a decision, an attacker who can make the app answer "yes" wrongly can substitute their own data for the authentic data.

OWASP frames the threat as "attackers can present forged or tampered data as authentic" (MAS-THREAT-0011), carried out by "presenting data with invalid, stripped, or attacker-signed signatures that the app accepts" (MAS-ATTACK-0031). The weakness applies to the L1, L2 and EUDIW profiles (identity wallets verify issuer signatures on credentials and relying-party signatures on requests), and is mapped to MASVS-CRYPTO-1, CWE-347 (Improper Verification of Cryptographic Signature) and CWE-295 (Improper Certificate Validation) — the latter because a signer's key usually arrives inside a certificate whose chain must also be validated.

Two framing points make reports on this weakness much more accurate:

- **Who is the attacker?** A verification bug matters when someone *other than the app's own user* can supply the data: a network attacker on a cleartext or unpinned channel, a compromised CDN or third-party host, a malicious server in a federated protocol, another app writing to shared storage, or anyone who can hand the user a QR code, link or file. When the only party able to tamper is the device owner (licences, purchases, local entitlements), client-side verification is a *design* weakness: it will be bypassed by instrumentation however well it is written, and the fix is server-side verification.
- **Bypassing a correct check is not this weakness.** Hooking `Signature.verify` to return `true` proves that a rooted user can patch the app, which is a resilience topic (MASVS-RESILIENCE). MASWE-0011 is about verification that fails *without* instrumentation: tampered data accepted by the unmodified app. Use forced-true hooks only to learn what the app does after a successful check (see [Test 5](#test-5-proving-a-bypass-by-tampering-signed-data-android-ios)).

## Modes of Introduction

**Verification skipped.** The data has a signature field, and nothing ever checks it; or verification exists behind a debug flag, a remote kill switch, or a "first launch" shortcut. This is the most common finding, and the hardest to see in code review because absent code does not stand out.

**Verification result ignored.** `Signature.verify()` returns `false` for a bad signature rather than throwing; code written as if it throws calls it and carries on. Swift equivalents: discarding the `Bool` from `isValidSignature`, or wrapping the check in `assert()`, which is not evaluated in optimised builds. Kotlin's `assert` is equally inert because JVM assertions are disabled on Android; `require()` and `check()` are always evaluated.

**Catch-all exception handlers.** Tink's `PublicKeyVerify.verify` and most JWT libraries signal failure by throwing. `try { verify() } catch (e: Exception) { log(e) }` followed by using the data — or `runCatching { verify() }.getOrDefault(true)`, or Swift's `try?` with the result discarded — converts every failure into success.

**Untrusted or unpinned signer keys.** The verification key is taken from the data itself (a JWK in a JWT header, a certificate inside the signed archive, a `publicKey` field in the JSON), fetched from a URL the data names (`jku`, `x5u`), downloaded over the same channel as the data, or read from a writable location. An attacker who can replace the data can then replace the key and sign with their own.

**Algorithm confusion.** The verifier lets the data choose the algorithm: JWT `alg: none`, `HS256` with the RSA public key used as an HMAC secret, or a weak or deprecated algorithm the verifier still accepts.

**Comparing instead of verifying.** Recomputing a hash and comparing it with a "signature" field (anyone can recompute an unkeyed hash), comparing binary signatures with `strcmp`/`strncmp` (stops at the first zero byte), with `memcmp` and an attacker-supplied length, or after converting bytes to a `String` (invalid UTF-8 collapses to the same replacement characters).

**Verifying part of the payload.** The signature covers the `data` field but the app also reads an unsigned `url` next to it; the app verifies a re-serialised object instead of the received bytes; parsers disagree about duplicate keys; an archive's manifest is signed but the files are not checked against it; or the app verifies one copy of a file and then loads another (time-of-check to time-of-use).

**Missing semantic checks.** A genuine signature over the wrong thing: an expired token, a configuration for another app or environment, a licence for another user or device, an older but validly signed update (rollback), or a replayed one-time message.

## Impact

- **Execution of unauthorised code.** Tampered JavaScript bundles, scripts, plugins, DEX files or native libraries run with the app's identity, permissions and data.
- **Authentication or authorisation bypass.** Forged tokens, assertions or QR codes are accepted as genuine, letting an attacker in as another user or unlock restricted functions.
- **Security controls switched off remotely.** Tampered configuration or feature flags disable certificate pinning, redirect API endpoints, lower authentication requirements or enable debug features.
- **Financial loss.** Forged purchase receipts and licences unlock paid content; at scale, through patching tools, this is a revenue problem.
- **Compromise of data integrity.** Tampered ML models, rules, price lists, transaction details or stored state are processed and shown as authentic.

## Mitigations

- **Verify every security-relevant input, and fail closed.** Treat `false`, an exception and a missing signature identically: reject the data and do not use any part of it.
- **Anchor the key in the app.** Ship the expected public key (or a hash of it, or a private CA certificate) in the app package and verify against that. Never verify with a key taken from the data, a URL in the data, or an unauthenticated download. Plan rotation by shipping the next key in advance.
- **Fix the algorithm in the verifier.** Allow-list exactly the algorithms you sign with; reject `none`, HMAC algorithms where asymmetric ones are expected, and anything deprecated.
- **Verify the exact bytes you will use, then parse.** Verify the raw received bytes before deserialising, and use only what the signature covered. For archives and bundles, check every file's hash against the signed manifest and reject unlisted files.
- **Check what the signature means.** Type or purpose, audience or app ID, user and device binding, issue and expiry times, version (to prevent rollback) and a nonce where replay matters.
- **Move trust decisions to the server where the user is the attacker.** Purchases, licences, entitlements and integrity verdicts are verified by your backend, which then grants access; the app displays the result.
- **Use approved schemes and maintained libraries**, as listed in [FIPS 186-5](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf), and keep JWT/JOSE libraries current.

## Knowledge

OWASP links no Knowledge to MASWE-0011. The generic sections below are ours. The two platform sections start from the MASTG Knowledge pages named in their headings, which describe HMAC- and signature-based integrity checks on stored data, and extend them with the verification APIs and pitfalls from the Android, Apple and IETF documentation cited.

### Generic: What a correct verification checks (Guler Tech)

A verification is correct when all of the following hold. Use the list as a review checklist; most findings are one missing line.

1. **The key comes from a trust anchor the app already has.** A public key or CA certificate compiled into the app, or a key delivered under a signature that chains to one. Not a key in the message, not a key fetched from a URL the message names.
2. **The algorithm is fixed by the verifier.** The code decides "ES256" or `SHA256withECDSA`; the message's header may be checked against it but never selects it.
3. **The signature is verified over the exact received bytes,** before parsing, and the code uses only what those bytes contain.
4. **Every failure is fatal.** A `false` return, an exception, a missing or empty signature, an unknown key ID and an unsupported algorithm all lead to rejection, and no partial result is used.
5. **The meaning is checked.** Type or purpose, issuer, audience or app identifier, subject (user, device), validity period, version or sequence number, and nonce where applicable.
6. **The comparison, if any, is constant-length and binary-safe.** Where the code compares digests (for example, a file hash against a signed manifest), it uses `MessageDigest.isEqual` or a constant-time equivalent on the raw bytes.

### Generic: Verifier failure patterns (Guler Tech)

What these look like in code you will review, decompiled:

```kotlin
// 1. Result ignored: verify() returns false, it does not throw
val s = Signature.getInstance("SHA256withECDSA")
s.initVerify(pinnedKey); s.update(body)
s.verify(sig)                                   // return value dropped
applyConfig(body)

// 2. Catch-all: Tink throws GeneralSecurityException on failure
try { verifier.verify(sig, body) } catch (e: Exception) { Log.w(TAG, "sig check failed", e) }
applyConfig(body)

// 3. Failure defaults to success
val ok = runCatching { checkSignature(body, sig) }.getOrDefault(true)

// 4. Debug or remote kill switch
if (BuildConfig.DEBUG || !remoteFlags.enforceSignatures || verify(body, sig)) applyConfig(body)

// 5. Lossy comparison: different byte arrays can produce equal strings
if (String(expectedDigest) == String(manifestDigest)) loadBundle(file)
```

```swift
// 6. Discarded result, or an assert() that is compiled out with -O
_ = publicKey.isValidSignature(signature, for: payload)
assert(publicKey.isValidSignature(signature, for: payload))

// 7. try? swallows the throw from a verifying JOSE library
let _ = try? jws.validate(using: verifier)
```

```text
// 8. Native: strcmp/strncmp stop at the first 0x00 byte, so two different
//    signatures or hashes that both start with 00 compare equal
if (strncmp(computed_hash, signed_hash, 32) == 0) { /* accept */ }
```

Pattern 8 is not hypothetical: a signature check built on `strncmp` was the root of a widely exploited console-signing bypass in 2008, and the same mistake still appears in hand-written native integrity checks.

Partial-coverage patterns are harder to spot because the verification call itself is correct:

- **Envelope fields outside the signature.** `{"payload": "...", "signature": "...", "download_url": "..."}` where only `payload` is signed.
- **Verify the object, use the bytes (or the reverse).** The app parses JSON, re-serialises it to verify, and then uses fields from the original text; or verifies the text and then parses with a library that resolves duplicate keys differently from the backend that signed it.
- **Signed manifest, unchecked files.** A JavaScript bundle or model archive ships a signed list of file hashes, but the loader does not hash each file, or loads files that are not in the list. The 2013 Android "Master Key" vulnerability (CVE-2013-4787) is the canonical example of a verifier and a loader disagreeing about which ZIP entry they were looking at.
- **Time-of-check to time-of-use.** The app verifies a file in shared or external storage and then reads it again to load it, giving another app a window to swap it.

### Generic: JWS and JWT verification on the client (Guler Tech)

A JWS compact token is `base64url(header).base64url(payload).base64url(signature)`, and the signature covers the ASCII bytes of the first two parts joined by a dot ([RFC 7515](https://www.rfc-editor.org/rfc/rfc7515)). The header carries `alg` and optionally `kid`, `jwk`, `jku`, `x5c` and `x5u`. Each of those header fields is attacker-controlled input, and each has caused real vulnerabilities when a verifier trusted it:

| Header abuse | What a vulnerable verifier does | Notes |
|---|---|---|
| `"alg": "none"` | Accepts an unsigned token | RFC 7518 defines `none`; libraries must not accept it unless explicitly configured to. |
| `"alg": "HS256"` on an RS256/ES256 system | Uses the RSA/EC *public* key as an HMAC secret, so anyone can sign | The 2015 algorithm-confusion class (for example CVE-2015-9235 in the Node.js `jsonwebtoken` package). |
| `"jwk": {...}` | Verifies with the key embedded in the header | CVE-2018-0114 (node-jose) is the reference case. |
| `"jku"` / `"x5u"` | Fetches the key set or certificate from a URL in the header | The attacker hosts their own key set. |
| `"x5c"` | Trusts a certificate chain in the header without validating it to a pinned root | A self-signed chain is accepted. |
| `"kid"` | Uses `kid` to build a file path or query | Path traversal to a known file used as an HMAC key, or injection. |

On mobile there is an additional, very common failure: **decode-only libraries used for decisions.** `com.auth0.android:jwtdecode` (`JWT(token)`), the iOS `JWTDecode.swift` package (`decode(jwt:)`), JavaScript's `jwt-decode`, and `JWT.decode()` in Auth0's `java-jwt` parse a token without checking the signature. That is fine for displaying a name or pre-emptively refreshing an expiring access token, because the server checks the token on every call. It is a finding when the app uses the decoded claims for a local decision — unlocking premium features, choosing an admin UI, accepting an offline login, or trusting a token received from a QR code or deep link.

Verifying libraries and their safe forms:

- **jjwt (`io.jsonwebtoken`)**: `Jwts.parser().verifyWith(publicKey).build().parseSignedClaims(token)` in 0.12; `Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token)` in 0.11. `parseClaimsJwt` (no "s") parses *unsigned* tokens in 0.11; 0.12 rejects unsecured tokens unless the builder calls `unsecured()`.
- **Auth0 `java-jwt`**: `JWT.require(Algorithm.ECDSA256(publicKey, null)).withIssuer(iss).withAudience(aud).build().verify(token)`. The `Algorithm` object fixes the algorithm; `JWT.decode` does not verify.
- **Nimbus JOSE + JWT**: `SignedJWT.parse(token)`, check `header.algorithm == JWSAlgorithm.ES256`, then `verify(ECDSAVerifier(publicKey))` and check the result; a `DefaultJWTProcessor` with a `JWSVerificationKeySelector` does the algorithm pinning for you.
- **iOS**: there is no Apple JWT API. Apps use JOSESwift (`validate(using:)` throws, `isValid(for:)` returns `Bool`) or verify by hand with CryptoKit, which is short and easy to review (see [Secure implementation](#secure-implementation)).
- **Cross-platform frameworks**: in React Native, `jsonwebtoken` depends on Node.js built-ins and does not run in the app without polyfills, so apps that genuinely verify tend to use a native module or a pure-JavaScript JOSE library, while many only decode with `jwt-decode`. In Flutter, `dart_jsonwebtoken` distinguishes `JWT.verify(token, key)` from `JWT.decode(token)`.

ECDSA has its own verifier bug class: Java 15–18's ECDSA implementation accepted signatures with *r* = *s* = 0 for any message and key ("Psychic Signatures", CVE-2022-21449). Android was not affected, because its ECDSA goes through Conscrypt and BoringSSL, but backends running affected Java versions were, as are hand-written verifiers that do not check 0 < *r*, *s* < *n*. An all-zero signature is a cheap test case.

### Generic: Trust anchors for the signer's key (Guler Tech)

Everything above assumes the verifier has the right public key. Where it comes from decides whether verification means anything:

| Key source | Verdict |
|---|---|
| Public key or its SHA-256 hash compiled into the app (code, `res/raw`, bundle resource) | Good. The app package is code-signed, so the key is as trustworthy as the app. |
| Private CA certificate compiled into the app; signer certificate delivered with the data and validated to that CA (path validation, validity dates, key usage, revocation policy) | Good, and supports rotation. |
| Key set fetched over TLS from your own domain, **with** certificate pinning, cached with a version | Acceptable; strength equals the pinning. |
| Key set fetched over TLS without pinning, from the same host as the data | Weak: anyone able to intercept TLS (a corporate proxy, a user-installed CA on old Android versions, a compromised CDN) can replace both. |
| Key in the signed data, in a header, or at a URL the data names | Broken: the attacker supplies their own key. |
| Key read from app storage, shared storage, `NSUserDefaults` or a downloaded file | Broken for any attacker who can write there. |

The certificate case is where CWE-295 enters. On Android, validating a signer certificate against an app-shipped root means a `CertPathValidator` with `PKIXParameters` built from a `KeyStore` containing only your root (and an explicit revocation decision), or `TrustManagerFactory` initialised from that `KeyStore`. On iOS it means `SecTrustCreateWithCertificates` with a basic X.509 policy (`SecPolicyCreateBasicX509`), `SecTrustSetAnchorCertificates` with your root, `SecTrustSetAnchorCertificatesOnly(trust, true)`, and `SecTrustEvaluateWithError` — whose `Bool` result is ignored as often as `verify()`'s. Checking only that "a certificate is present", or comparing its subject name, is not validation.

### Android: Verification APIs and integrity checks (MASTG-KNOW-0029)

Related sources: [MASTG-KNOW-0029 File Integrity Checks](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0029/), which describes HMAC-protecting stored data and notes that "another way to provide integrity is to sign the byte array"; [MASTG-BEST-0066](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0066/), which recommends an HMAC with a Keystore key over stored data, mentions `java.security.Signature` as the asymmetric alternative, and warns that such checks are defence in depth because a rooted attacker can intercept them. The API detail below is ours.

**`java.security.Signature`** is the standard verifier:

```kotlin
fun verifyConfig(body: ByteArray, sig: ByteArray, pinned: PublicKey): Boolean {
    val v = Signature.getInstance("SHA256withECDSA")   // fixed by the app
    v.initVerify(pinned)                               // key from the app package
    v.update(body)                                     // exact received bytes
    return try { v.verify(sig) } catch (e: SignatureException) { false }  // malformed = invalid
}
```

`verify` returns `false` for a signature that does not match and may throw `SignatureException` for a malformed one (behaviour differs between providers), so robust code maps both to rejection. `initVerify(Certificate)` uses the certificate's public key but does **not** validate the certificate: no chain, no expiry, no trust anchor. The only certificate field it looks at is a critical key-usage extension that forbids signing.

**Tink's `PublicKeyVerify`** (`verify(signature, data)`) returns nothing and throws `GeneralSecurityException` on failure; it is excellent when the exception propagates, and dangerous inside a catch-all. Tink keysets carry the algorithm, so algorithm confusion is not possible, but the public keyset still has to come from a trust anchor.

**BouncyCastle** low-level verifiers (`ECDSASigner.verifySignature`, `Ed25519Signer.verifySignature`, `PSSSigner.verifySignature`) return `Boolean`. Apps that bundle BouncyCastle for Ed25519 or secp256k1 should be on a current version.

**APK and app-signing verification by the OS** (`apksigner`, v2/v3/v4 schemes, covered by MASTG-KNOW-0003 and the legacy test MASTG-TEST-0038) protects the installed package, not data the app downloads afterwards. Comparing `PackageInfo.signingInfo` with an expected certificate hash is a tamper-detection control (MASVS-RESILIENCE), not a substitute for verifying downloaded content.

### iOS: SecKey, CryptoKit and storage integrity checks (MASTG-KNOW-0067, MASTG-KNOW-0086)

Related sources: [MASTG-KNOW-0067](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0067/) introduces `SecKey` for asymmetric operations; [MASTG-KNOW-0086 Storage Integrity Checks](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0086/) and [MASTG-BEST-0065](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0065/) describe protecting stored data with an HMAC (`CCHmac`, CryptoKit `HMAC`) or with `SecKeyCreateSignature`/`SecKeyVerifySignature`, and note that the checks can be bypassed on jailbroken devices by extracting the key or intercepting the function. The API detail below is ours.

**`SecKeyVerifySignature(key, algorithm, signedData, signature, &error)`** returns a `Boolean` and fills `error` (typically `errSecVerifyFailed`) on failure. The algorithm constant fixes scheme and digest — use the `Message` variants (`.ecdsaSignatureMessageX962SHA256`, `.rsaSignatureMessagePSSSHA256`) unless you hash yourself — and `SecKeyIsAlgorithmSupported(key, .verify, alg)` should be checked first. The public key usually comes from `SecKeyCreateWithData` on bytes shipped in the bundle, or from `SecCertificateCopyKey` on a certificate that has first been validated with `SecTrustEvaluateWithError`.

**CryptoKit** verification is a method on the public key and returns `Bool`:

```swift
let key = try P256.Signing.PublicKey(derRepresentation: pinnedKeyDER)    // from the bundle
let sig = try P256.Signing.ECDSASignature(derRepresentation: sigBytes)    // or rawRepresentation:
guard key.isValidSignature(sig, for: body) else { throw ConfigError.badSignature }
```

`Curve25519.Signing.PublicKey.isValidSignature(_:for:)` does the same for Ed25519. Constructing the signature object throws on malformed input, which is another failure path that must reject rather than fall through.

**StoreKit 2** verifies App Store-signed JWS transactions for you and reports the outcome as `VerificationResult<Transaction>`: `.verified(transaction)` or `.unverified(transaction, error)`. `payloadValue` throws for unverified results; `unsafePayloadValue` returns the transaction regardless. Unlocking content in the `.unverified` branch, or via `unsafePayloadValue`, is the StoreKit 2 form of this weakness.

The MASTG storage-integrity tests apply this to local data: [MASTG-TEST-0387](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0387/) (iOS) and [MASTG-TEST-0338](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0338/) (Android) list references to `HMAC`, `CCHmac`, `SecKeyCreateSignature`, `javax.crypto.Mac`, `java.security.Signature` and `MessageDigest`, and fail the app when security-relevant data read from storage is used without an integrity check. Their demo, [MASTG-DEMO-0150](https://mas.owasp.org/MASTG/demos/ios/MASVS-RESILIENCE/MASTG-DEMO-0150/MASTG-DEMO-0150/), uses radare2 to show one storage flow that writes and reads `user_profile.json` with no HMAC and a second that calls `HMAC.authenticationCode` before writing and `HMAC.isValidAuthenticationCode` after reading. Those tests prove a check *exists*; the tests below establish whether it *works*.

### Generic: Where mobile apps verify signatures (Guler Tech)

| Artefact | Typical mechanism | What usually goes wrong |
|---|---|---|
| Remote configuration and feature flags | JSON plus detached signature, or JWS | Unsigned fields alongside the signed payload; key fetched with the config; verification behind a flag that the config itself controls |
| Over-the-air JavaScript bundles (React Native CodePush, Expo Updates), Lua or other scripts | Signed manifest or bundle hash; CodePush and Expo both offer optional code signing | Signing never enabled; manifest signed but files unchecked; rollback to an older signed bundle |
| Native plugins, DEX or `.so` downloaded at runtime (Android) | Rare and discouraged; sometimes a hash list | No signature at all; file stored in writable location (MASWE-0049) |
| ML models (`.tflite`, Core ML) | Hash from a manifest, or none | Model swapped on CDN or in storage; manifest unsigned |
| Licences and entitlements | Signed licence file or token | Verified only on the device, so the owner patches the check; licence not bound to user or device |
| In-app purchases | Google Play `Purchase.originalJson` + `signature` (RSA); Apple StoreKit 2 JWS; legacy App Store receipt (PKCS#7) | Verification only on the device; `.unverified` accepted; PKCS#7 checked with `PKCS7_NOVERIFY` or not at all |
| Identity tokens and credentials | JWS/JWT, SD-JWT, mdoc (COSE) | Decode-only library; `alg`/`jwk` trusted; issuer key not anchored; expiry not checked |
| QR codes, tickets, vouchers | Compact signed payload | Verifier accepts unsigned variant; no expiry or replay protection |
| Local storage integrity | HMAC or signature over stored data | Covered by MASTG-TEST-0338/0387 under MASWE-0057; key extractable on rooted devices |

## Testing

OWASP has no tests for MASWE-0011; the eight tests below are **Guler Tech methodology**. The nearest OWASP tests are [MASTG-TEST-0338](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0338/) and [MASTG-TEST-0387](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0387/) ("References to Storage Integrity Check APIs", mapped to MASWE-0057). Run them when the app stores security-relevant state locally: they find whether an HMAC or signature check exists, after which Tests 3–5 here tell you whether it can be bypassed without instrumentation.

The order matters. Tests 1 and 2 find every place the app verifies, and the key each place trusts. Tests 3 and 4 watch those checks at runtime. Test 5 is the proof: you change signed data, leave the app unmodified, and observe whether it accepts the change. Tests 6–8 apply the same method to JWTs, purchases and licences, and downloaded code and models.

Common prerequisites: the APK (all splits) or decrypted IPA; `jadx`, `apktool` and `semgrep` (MASTG-TECH-0013, MASTG-TECH-0014); for iOS, the main binary and frameworks from `Payload/<App>.app/` with `nm`, `otool`, `xcrun swift-demangle` or radare2 (MASTG-TECH-0058, MASTG-TECH-0066, MASTG-TECH-0076); a rooted or jailbroken device with `frida-server` (MASTG-TECH-0043, MASTG-TECH-0095); an intercepting proxy such as Burp Suite or mitmproxy, with TLS pinning bypassed where necessary, to modify traffic; and access to the app's data directories (MASTG-TECH-0008 on Android, MASTG-TECH-0059 on iOS).

### Test 1: Inventory of verification sites and trust anchors (Android)

Guler Tech methodology. Platform: Android. Type: static (code).

#### Overview

Find every signature verification in the app, the key it uses and where that key comes from, the algorithm and who chooses it, and what the code does with the result. In parallel, find signed artefacts the app consumes (anything with a `signature`, `sig` or `jws` field, signed tokens, manifests) and check that each one actually reaches a verifier.

#### Prerequisites

- `jadx -d out/ app.apk` and `apktool d app.apk -o apktool_out/`.
- `semgrep` and the rules below.

#### Steps

1. **Find verifiers.**

   ```bash
   grep -rnE 'initVerify\(|\.verify\(|verifySignature\(|PublicKeyVerify|JWTVerifier|parseSignedClaims|parseClaimsJws|JWSVerifier' out/sources \
     | grep -vE '^out/sources/(androidx|kotlin|kotlinx|com/google/android/gms)/'
   ```

2. **Find signed artefacts and the code that consumes them.**

   ```bash
   grep -rnE '"(signature|sig|signed_payload|jws|x-signature)"' out/sources
   grep -rnE 'JWT\.decode\(|new JWT\(|parseClaimsJwt\(|parseUnsecuredClaims\(|SignedJWT\.parse\(|JWTParser\.parse\(' out/sources
   ```

   For each artefact, follow the parsed data forward to its use and backwards to a verifier. An artefact with a signature field and no verifier on its path is the "verification skipped" mode.

3. **Find the trust anchors.** Embedded RSA-2048 and P-256 public keys have fixed Base64 prefixes, which makes them easy to grep (these are public keys, not secrets):

   ```bash
   grep -rnoE 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA[A-Za-z0-9+/=]{20,}|MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE[A-Za-z0-9+/=]{20,}' out/ apktool_out/
   grep -rlE 'BEGIN (PUBLIC KEY|CERTIFICATE)' apktool_out/
   grep -rnE 'X509EncodedKeySpec|CertificateFactory\.getInstance|CertPathValidator|PKIXParameters|getJWK\(|getJWKURL\(|getX509CertURL\(' out/sources
   ```

   Then trace each `X509EncodedKeySpec` or `generatePublic` back to its bytes: a resource or constant is an anchor; a field of the downloaded data, a header, a URL or a preference is not.

4. **Run the semgrep rules:**

   ```yaml
   rules:
     - id: gt-android-verify-result-ignored
       languages: [java]
       severity: ERROR
       message: Signature.verify() called as a statement; its boolean result is discarded
       pattern: (Signature $S).verify(...);
     - id: gt-android-verify-failure-swallowed
       languages: [java]
       severity: WARNING
       message: Verification inside try/catch whose handler neither throws nor returns; check whether execution continues
       patterns:
         - pattern: |
             try { ... $V.verify(...); ... } catch ($T $E) { ... }
         - pattern-not: |
             try { ... } catch ($T $E) { ... throw $X; }
         - pattern-not: |
             try { ... } catch ($T $E) { ... return $R; }
     - id: gt-android-jwt-decoded-not-verified
       languages: [java]
       severity: INFO
       message: JWT parsed without signature verification; check whether its claims drive a local decision
       pattern-either:
         - pattern: com.auth0.jwt.JWT.decode(...)
         - pattern: new com.auth0.android.jwt.JWT(...)
         - pattern: $P.parseClaimsJwt(...)
         - pattern: $P.parseUnsecuredClaims(...)
     - id: gt-android-key-from-token-header
       languages: [java]
       severity: WARNING
       message: Verification key or key URL taken from the token header
       pattern-either:
         - pattern: $H.getJWK()
         - pattern: $H.getJWKURL()
         - pattern: $H.getX509CertURL()
         - pattern: $H.getX509CertChain()
   ```

   ```bash
   semgrep -c gt-android-verify.yml out/sources/
   ```

5. **Check gating conditions** around each verifier: `BuildConfig.DEBUG`, remote-config flags, `if (signature != null)` (so a missing signature skips the check), and environment switches.

#### Observation

A table of verification sites with: artefact, algorithm (and who chooses it), key source, result handling (returned, ignored, caught), gating conditions, and the code that consumes the verified data. A list of signed artefacts with no verifier on their path.

#### Evaluation

The test **fails** if, for any security-relevant artefact: there is no verification on the path from receipt to use; the result is discarded or a failure falls through a handler; verification is skipped when the signature is absent or when a debug or remote flag says so; the key comes from the data, a header, a URL in the data or writable storage; the algorithm is taken from the data; or a decode-only parser feeds a local trust decision. Findings from static analysis alone are strong evidence; confirm the impact with Test 5. Common false positives: `verify` on unrelated classes (Mockito, view validators), JWT decoding used only to schedule token refresh, and pinned certificate hashes used for TLS (MASWE-0028's territory).

#### Demo

Vulnerable Kotlin (Guler Tech sample): a remote-config loader.

```kotlin
fun onConfig(json: JSONObject) {
    val payload = json.getString("payload").toByteArray()
    val sig = Base64.decode(json.getString("signature"), Base64.NO_WRAP)
    val key = KeyFactory.getInstance("EC").generatePublic(            // key shipped with the data
        X509EncodedKeySpec(Base64.decode(json.getString("publicKey"), Base64.NO_WRAP)))
    val v = Signature.getInstance("SHA256withECDSA")
    v.initVerify(key)
    v.update(payload)
    v.verify(sig)                                                     // result ignored
    applyConfig(JSONObject(String(payload)), json.optString("update_url"))  // unsigned field used
}
```

Expected semgrep result on the jadx output (abridged):

```text
    RemoteConfigLoader.java
    ❯❱ gt-android-verify-result-ignored
          Signature.verify() called as a statement; its boolean result is discarded
           47┆ signature.verify(sig);
```

The rule finds one of three defects. Manual tracing of `generatePublic` shows the key comes from the `publicKey` field of the same response, and following `applyConfig` shows `update_url` is read from outside `payload`. Any one of the three is enough to fail the test.

### Test 2: Inventory of verification sites and trust anchors (iOS)

Guler Tech methodology. Platform: iOS. Type: static (binary).

#### Overview

The iOS equivalent of Test 1. Verifiers are calls to `SecKeyVerifySignature`, CryptoKit `isValidSignature`, trust evaluation for signer certificates, OpenSSL `PKCS7_verify` or `EVP_DigestVerify*` in bundled libraries, and JOSE libraries. Because you usually work from the binary, the key question for each call site is what happens to the return value.

#### Prerequisites

- Decrypted IPA; main binary and `Frameworks/`.
- `nm`, `otool`, `strings`, `xcrun swift-demangle`; radare2 for call-site inspection.

#### Steps

1. **List verification imports and libraries.**

   ```bash
   BIN=Payload/App.app/App
   nm -um "$BIN" | grep -E 'SecKeyVerifySignature|SecKeyCreateWithData|SecCertificateCopyKey|SecTrustEvaluateWithError|SecTrustSetAnchorCertificates|SecPolicyCreateBasicX509|kSecKeyAlgorithm.*Signature'
   nm -um "$BIN" | xcrun swift-demangle | grep -oE 'CryptoKit\.[A-Za-z0-9.]*isValidSignature[^(]*|StoreKit\.VerificationResult[^ ]*|JWTDecode[^ ]*|JOSESwift[^ ]*' | sort -u
   ls Payload/App.app/Frameworks/
   for f in Payload/App.app/Frameworks/*.framework; do n=$(basename "$f" .framework); nm -gU "$f/$n" 2>/dev/null | grep -E 'PKCS7_verify|EVP_DigestVerify|crypto_sign_verify_detached' | sed "s|^|$n: |"; done
   ```

2. **Find the trust anchors.**

   ```bash
   strings -a "$BIN" | grep -E 'BEGIN PUBLIC KEY|BEGIN CERTIFICATE|MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE|MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A|verifyReceipt|jwks'
   find Payload/App.app \( -name '*.pem' -o -name '*.der' -o -name '*.cer' -o -name '*.crt' -o -name '*jwks*' \)
   ```

3. **Inspect each call site's result handling** in radare2:

   ```text
   r2 -A Payload/App.app/App
   [0x...]> axt @ sym.imp.SecKeyVerifySignature
   [0x...]> pd 8 @ <call-site address>
   ```

   On arm64 the result comes back in `w0`. A checked result is followed promptly by a test on it (`tbz w0, 0, <fail>`, `tbnz`, `cbz w0`, `and w0, w0, 1` then a branch). A result that is overwritten (another `bl`, a `mov w0, …`) before any such test is ignored. Do the same for `SecTrustEvaluateWithError` and for the CryptoKit `isValidSignature` symbols.

4. **Check StoreKit and JWT usage.** If `StoreKit.VerificationResult` appears, decompile its users (Ghidra or r2 `pdf`) and check the `.unverified` branch; search for `unsafePayloadValue` (it may be inlined, so absence from the symbol list is not proof). If `JWTDecode` is linked, find what the decoded claims are used for.

#### Observation

As for Test 1: verification sites with algorithm, key source, result handling and gating; artefacts with no verifier.

#### Evaluation

As for Test 1. In addition, the test fails if `SecTrustEvaluateWithError` on a signer certificate is called without your own anchors set (`SecTrustSetAnchorCertificates` plus `SecTrustSetAnchorCertificatesOnly`), so any certificate from a system-trusted CA would be accepted as the signer, or if OpenSSL `PKCS7_verify` is called with `PKCS7_NOVERIFY` (signer certificate not verified) or `PKCS7_NOSIGS` (signatures not verified).

#### Demo

Vulnerable Swift (Guler Tech sample):

```swift
func loadLicence(_ licence: Data, signature: Data) -> Licence? {
    var error: Unmanaged<CFError>?
    _ = SecKeyVerifySignature(pinnedKey, .ecdsaSignatureMessageX962SHA256,
                              licence as CFData, signature as CFData, &error)
    return try? JSONDecoder().decode(Licence.self, from: licence)
}
```

radare2 around the call site (illustrative, release build):

```text
[0x100004f20]> pd 6 @ 0x100004f6c
│  0x100004f6c   bl sym.imp.SecKeyVerifySignature
│  0x100004f70   adrp x8, 0x10000c000
│  0x100004f74   ldr x0, [x8, 0x3a8]          ; JSONDecoder
│  0x100004f78   bl sym.imp.swift_allocObject
│  0x100004f7c   bl sym.imp.Foundation.JSONDecoder.init
│  0x100004f80   mov x20, x0
```

`w0` from `SecKeyVerifySignature` is overwritten two instructions later without any test, so the result is never consulted. The test fails.

### Test 3: Runtime verification results and their handling (Android)

Guler Tech methodology. Platform: Android. Type: dynamic (hooks).

#### Overview

Hook the verifiers found in Test 1 (and common ones you did not find statically, because SDKs and obfuscated code hide them), log the key, algorithm, data and *result* of every verification, and correlate that with what the app does next. A verification that returns `false` followed by the app using the data is a confirmed "result ignored" or "failure swallowed" defect. A signed artefact that is loaded with no verification event at all is "verification skipped".

#### Prerequisites

- Rooted device or emulator with `frida-server`; the app installed.
- The pinned key fingerprints from Test 1 (SHA-256 of the encoded public key), to compare with the keys used at runtime.

#### Steps

1. Save the script. `FORCE` stays `false` for this test; Test 5 explains when to set it.

   ```javascript
   // gt-android-verify.js
   const FORCE = false;
   Java.perform(function () {
     const Sig = Java.use('java.security.Signature');
     const MD = Java.use('java.security.MessageDigest');
     const Log = Java.use('android.util.Log');
     const Exc = Java.use('java.lang.Exception');
     const pending = {};
     function hex(a, off, len) {
       let s = '';
       for (let i = off; i < off + len; i++) s += ('0' + (a[i] & 0xff).toString(16)).slice(-2);
       return s;
     }
     function fp(key) {
       const d = MD.getInstance('SHA-256').digest(key.getEncoded());
       return hex(d, 0, d.length).slice(0, 16);
     }
     Sig.initVerify.overload('java.security.PublicKey').implementation = function (k) {
       this.initVerify(k);
       pending[this.hashCode()] = { key: k.getAlgorithm() + ':' + fp(k), data: '' };
     };
     Sig.initVerify.overload('java.security.cert.Certificate').implementation = function (c) {
       this.initVerify(c);
       pending[this.hashCode()] = { key: 'cert:' + fp(c.getPublicKey()), data: '' };
     };
     Sig.update.overload('[B', 'int', 'int').implementation = function (b, off, len) {
       const p = pending[this.hashCode()];
       if (p && p.data.length < 512) p.data += hex(b, off, Math.min(len, 128));
       return this.update(b, off, len);
     };
     function report(self, ok) {
       const p = pending[self.hashCode()] || { key: '?', data: '' };
       console.log('\n[verify] ' + self.getAlgorithm() + ' key=' + p.key + ' -> ' + ok + ' data=' + p.data.slice(0, 96));
       console.log(Log.getStackTraceString(Exc.$new()).split('\n').slice(1, 7).join('\n'));
     }
     Sig.verify.overload('[B').implementation = function (s) {
       const ok = this.verify(s);
       report(this, ok);
       return FORCE ? true : ok;
     };
     Sig.verify.overload('[B', 'int', 'int').implementation = function (s, off, len) {
       const ok = this.verify(s, off, len);
       report(this, ok);
       return FORCE ? true : ok;
     };
     // JWT libraries, if present under their original names
     [['com.auth0.jwt.JWT', 'decode'], ['com.auth0.jwt.JWTVerifier', 'verify'],
      ['com.auth0.android.jwt.JWT', '$init'], ['io.jsonwebtoken.impl.DefaultJwtParser', 'parse'],
      ['com.nimbusds.jose.JWSObject', 'verify']].forEach(function (t) {
       try {
         Java.use(t[0])[t[1]].overloads.forEach(function (o) {
           o.implementation = function () {
             const r = o.apply(this, arguments);
             console.log('[jwt] ' + t[0] + '.' + t[1] + ' -> ' + (r === undefined ? 'void' : r));
             return r;
           };
         });
         console.log('hooked ' + t[0] + '.' + t[1]);
       } catch (e) { /* class not present or renamed */ }
     });
   });
   ```

2. Run it, exercise every flow that loads a signed artefact, then repeat while applying the tampering from Test 5:

   ```bash
   frida -U -f com.example.app -l gt-android-verify.js -o verify-log.txt
   ```

3. If the app uses Tink, add hooks for the `verify` method of its `PublicKeyVerify` implementations (for example `com.google.crypto.tink.subtle.EcdsaVerifyJce` and `Ed25519Verify`) and log whether they throw. For obfuscated JWT libraries, find the class by a string it contains (Auth0's `java-jwt` raises "The Token's Signature resulted invalid when verified using the Algorithm: …") and hook it by its renamed name.

#### Observation

`verify-log.txt` with every verification: algorithm, key fingerprint, data preview, result, and call stack; JWT library calls; and your notes of what the app did after each one (UI change, network request, file written).

#### Evaluation

The test **fails** if a verification returns `false` (or throws) and the app nevertheless uses the data; if a signed artefact is consumed with no verification event; if the key fingerprint at runtime does not match a pinned key from Test 1 (the key came from somewhere else); or if decode-only JWT calls (`JWT.decode`, `com.auth0.android.jwt.JWT.<init>`) precede a local trust decision. It passes for an artefact when tampered input produces `false` and the app rejects it visibly (error, fallback to cached signed data, refusal to proceed).

#### Demo

Output from the Test 1 sample with a tampered config (the payload was changed, the signature left as it was):

```text
[verify] SHA256withECDSA key=EC:9a41c07de2b81f3c -> false data=7b22666561747572655f707265...
    at java.security.Signature.verify(Native Method)
    at com.example.app.config.RemoteConfigLoader.onConfig(RemoteConfigLoader.kt:47)
    at com.example.app.config.RemoteConfigLoader$fetch$1.invokeSuspend(RemoteConfigLoader.kt:31)
```

The verification fails, and the premium feature flag from the tampered payload still appears in the app. The fingerprint `9a41c07d…` also matches the `publicKey` field of the response rather than any key in the APK.

### Test 4: Runtime verification results and their handling (iOS)

Guler Tech methodology. Platform: iOS. Type: dynamic (hooks).

#### Overview

The iOS equivalent of Test 3: hook `SecKeyVerifySignature`, CryptoKit's `isValidSignature` exports, `SecTrustEvaluateWithError`, and JWT decoding, and correlate results with behaviour.

#### Prerequisites

- Jailbroken device with `frida-server`; the app installed.

#### Steps

1. Save the script:

   ```javascript
   // gt-ios-verify.js
   const FORCE = false;
   function hex(p, n) {
     const u = new Uint8Array(p.readByteArray(Math.min(n, 48)));
     return Array.from(u, b => ('0' + b.toString(16)).slice(-2)).join('');
   }
   function bt(ctx) {
     return Thread.backtrace(ctx, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).slice(0, 6).join('\n    ');
   }
   const sec = Process.getModuleByName('Security');
   Interceptor.attach(sec.getExportByName('SecKeyVerifySignature'), {
     onEnter(args) {
       const d = new ObjC.Object(args[2]);
       this.info = new ObjC.Object(args[1]).toString() + ' data(' + d.length() + ')=' + hex(d.bytes(), d.length());
       this.where = bt(this.context);
     },
     onLeave(ret) {
       const ok = ret.toInt32() & 0xff;
       console.log('\n[SecKeyVerifySignature] ' + this.info + ' -> ' + ok + '\n    ' + this.where);
       if (FORCE && !ok) ret.replace(ptr(1));
     }
   });
   Interceptor.attach(sec.getExportByName('SecTrustEvaluateWithError'), {
     onEnter() { this.where = bt(this.context); },
     onLeave(ret) { console.log('\n[SecTrustEvaluateWithError] -> ' + (ret.toInt32() & 0xff) + '\n    ' + this.where); }
   });
   const ck = Process.findModuleByName('CryptoKit');
   if (ck) {
     ck.enumerateExports().filter(e => e.type === 'function' && e.name.indexOf('isValidSignature') !== -1)
       .forEach(e => Interceptor.attach(e.address, {
         onEnter() { this.where = bt(this.context); },
         onLeave(ret) {
           const ok = ret.toInt32() & 1;
           console.log('\n[CryptoKit] ' + e.name + ' -> ' + ok + '\n    ' + this.where);
           if (FORCE && !ok) ret.replace(ptr(1));
         }
       }));
   }
   ```

   `SecTrustEvaluateWithError` also fires for TLS; the backtrace tells you whether the caller is the app's signer-certificate code or the networking stack.

2. Run it and exercise the flows, then repeat with tampered inputs (Test 5):

   ```bash
   frida -U -f com.example.app -l gt-ios-verify.js -o verify-log-ios.txt
   ```

3. For JWT decoding and Swift-level verifiers, use `frida-trace` with globs on the mangled names, for example `frida-trace -U -f com.example.app -i '*JWTDecode*decode*' -i '*JOSESwift*valid*'`. If the CryptoKit hook stays silent although Test 2 found `isValidSignature`, the generic function may have been specialised into the app binary; trace the app module (`-i 'App!*isValidSignature*'`) instead.

#### Observation

`verify-log-ios.txt` with algorithm, data preview, result and caller for each verification, plus notes on the app's behaviour after each.

#### Evaluation

As for Test 3: the test **fails** if a verification returns `0` and the app uses the data, if a signed artefact is consumed with no verification event, if a JWT is only decoded before a local trust decision, or if signer-certificate trust is evaluated without app-specific anchors (check the anchors set before the `SecTrustEvaluateWithError` call in the code found by the backtrace).

#### Demo

Output for the Test 2 sample with a licence whose `"plan"` field was changed from `"basic"` to `"pro"`:

```text
[SecKeyVerifySignature] algid:sign:ECDSA:message-X962:SHA256 data(74)=7b226c6963656e6365223a7b22706c616e223a2270726f22 -> 0
    0x100004f70 App!LicenceStore.loadLicence(_:signature:)
    0x100005a18 App!LicenceStore.refresh()
```

The verification returns `0` and the app shows the Pro plan. The test fails; Test 5 turns this into a reportable proof.

### Test 5: Proving a bypass by tampering signed data (Android, iOS)

Guler Tech methodology. Platform: Android and iOS. Type: dynamic (traffic, filesystem).

#### Overview

This is the test that produces the evidence for a MASWE-0011 finding. You alter signed data in the way a real attacker could — in transit, in storage, or at its source — leave the app **unmodified**, and observe whether it accepts the change. Tests 3 and 4 run alongside to explain *why* it was accepted (no verification, ignored result, wrong key, partial coverage). Each mutation in the matrix below targets one failure mode, so the set of accepted mutations tells you precisely what is broken.

#### Prerequisites

- An artefact identified in Tests 1–2 and the channel through which an attacker could alter it: traffic (Burp Suite or mitmproxy, with pinning bypassed for the test), a file in the app's data directory or shared storage, or content the attacker can host (a QR code, a link, a CDN object in a test environment).
- A field whose change is visible: a feature flag that shows a menu, a displayed price or name, a plan level, a script that changes a label.
- Hooks from Test 3 or 4 running, with `FORCE = false`.
- A P-256 key pair you control, for the "attacker-signed" mutations:

  ```bash
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out attacker.pem
  openssl pkey -in attacker.pem -pubout -out attacker_pub.pem
  openssl dgst -sha256 -sign attacker.pem -out attacker.sig payload.json   # DER-encoded ECDSA signature
  ```

#### Steps

1. **Record a baseline.** Capture the genuine artefact, confirm the app accepts it, and save it unchanged.

2. **Apply one mutation at a time**, reload the artefact (restart the app, pull to refresh, clear the cache), and record the app's behaviour and the hook output:

   | # | Mutation | Failure mode it detects | Correct behaviour |
   |---|---|---|---|
   | M1 | Change one byte of the signed payload, keep the signature | Verification skipped or result ignored | Reject |
   | M2 | Flip one bit of the signature, keep the payload | As M1 (confirms the check runs at all) | Reject |
   | M3 | Empty the signature; then remove the field entirely | "Verify only if present" logic | Reject |
   | M4 | Change a field outside the signed part (envelope field, HTTP header, file next to the manifest) | Partial coverage | Ignore the field or reject |
   | M5 | Sign the modified payload with your key; then also replace any key, certificate, `jwk` or key URL that travels with the data | Key taken from the data or the channel | Reject |
   | M6 | Replay a genuine, older artefact (previous config version, earlier bundle, expired licence) | No version, expiry or replay check | Reject |
   | M7 | Replay a genuine artefact meant for another context (other user, device, app, environment) | No audience or subject binding | Reject |
   | M8 | Re-encode the signature (DER ↔ raw *r*‖*s*, base64 ↔ base64url, add trailing bytes) and send an all-zero signature | Lenient or hand-written parser | Reject (encoding variants may legitimately be accepted if the payload is untouched) |
   | M9 | Duplicate a JSON key inside the signed payload with a different value | Parser differential between signer and app | Reject or use the signed value |

3. **Use the right tool for the channel.** In transit, a mitmproxy addon keeps the edit reproducible:

   ```python
   # tamper_config.py — M1: change a signed field, keep the signature
   import json
   from mitmproxy import http

   def response(flow: http.HTTPFlow) -> None:
       if flow.request.path.startswith("/v1/config"):
           body = json.loads(flow.response.get_text())
           inner = json.loads(body["payload"])
           inner["feature_premium"] = True
           body["payload"] = json.dumps(inner)
           flow.response.set_text(json.dumps(body))
   ```

   ```bash
   mitmdump -s tamper_config.py --listen-port 8080
   ```

   On the device, for stored artefacts:

   ```bash
   # Android (root, or run-as on a debuggable build)
   adb shell su -c "cp /data/data/com.example.app/files/licence.json /data/local/tmp/licence.orig"
   adb shell su -c "sed -i 's/\"plan\":\"basic\"/\"plan\":\"pro\"/' /data/data/com.example.app/files/licence.json"
   adb shell am force-stop com.example.app
   ```

   ```bash
   # iOS (jailbroken): find the container with objection's "env" command, then edit over SSH
   ssh root@<device> "sed -i '' 's/\"plan\":\"basic\"/\"plan\":\"pro\"/' '/var/mobile/Containers/Data/Application/<UUID>/Library/licence.json'"
   ```

   For JWS artefacts, generate the variants with a short script:

   ```python
   #!/usr/bin/env python3
   """Print tampered variants of a compact JWS: tamper_jws.py <token> <claim> <json-value>"""
   import base64, json, sys

   def b64d(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
   def b64e(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

   h, p, s = sys.argv[1].split(".")
   claims = json.loads(b64d(p))
   claims[sys.argv[2]] = json.loads(sys.argv[3])
   p2 = b64e(json.dumps(claims, separators=(",", ":")).encode())
   sig = bytearray(b64d(s)); sig[-1] ^= 1
   none_hdr = b64e(json.dumps({"alg": "none", "typ": "JWT"}).encode())
   print("payload-changed  ", f"{h}.{p2}.{s}")
   print("signature-flipped", f"{h}.{p}.{b64e(bytes(sig))}")
   print("signature-empty  ", f"{h}.{p}.")
   print("alg-none         ", f"{none_hdr}.{p2}.")
   print("zero-signature   ", f"{h}.{p2}.{b64e(bytes(len(sig)))}")
   ```

   ```bash
   python3 -I tamper_jws.py "$TOKEN" plan '"pro"'
   ```

4. **Explain the result** with the hook output: no verification event (skipped), `false`/`0` followed by acceptance (ignored or swallowed), a key fingerprint that matches your key (key from the data), or `true` with the modified field outside the signed bytes (partial coverage).

5. **Optional what-if, for impact only.** If every mutation is rejected, set `FORCE = true` and repeat M1 to see what a successful verification would unlock. This shows the value of the protected data (useful for rating related resilience findings) but is **not** a MASWE-0011 finding, because it needs instrumentation of the app.

6. **Restore** the saved originals and clear any tampered caches.

#### Observation

For each mutation: the artefact before and after (a diff), how it was delivered, the hook output, the app's behaviour (screenshot or log line), and whether the effect persisted after restart.

#### Evaluation

The test **fails** if the unmodified app accepts any of M1–M5 or M9 for security-relevant data, or M6–M7 where the artefact's meaning depends on version, recipience or freshness (licences, configs that relax security, one-time tokens). M8 encoding variants that leave the payload untouched are informational unless the all-zero signature is accepted, which is a failure. The test **passes** when every mutation is rejected and the app falls back safely (keeps the last valid artefact, or refuses the operation) rather than crashing into an undefined state.

Rate the result with the attacker in mind: who could have performed the mutation without the device owner's cooperation? M1 accepted on a config fetched over pinned TLS from your own server is a latent defect; the same over cleartext, from a third-party CDN, or from shared storage is directly exploitable.

#### Demo

For the Android sample in Test 1, with `tamper_config.py` active:

| Mutation | Hook output | App behaviour | Result |
|---|---|---|---|
| M1 payload changed | `[verify] … -> false` | Premium menu appears | Fail |
| M2 signature bit flipped | `[verify] … -> false` | Premium menu appears | Fail |
| M4 `update_url` changed | `[verify] … -> true` | App downloads from the changed URL | Fail |
| M5 payload signed with `attacker.pem`, `publicKey` replaced with `attacker_pub.pem` | `[verify] … key=EC:<attacker fingerprint> -> true` | Premium menu appears | Fail |

Four independent failures. M5 alone shows that fixing the ignored result would not be enough: the key must come from the APK.

### Test 6: JWT and JWS handling on the client (Android, iOS)

Guler Tech methodology. Platform: Android and iOS. Type: static and dynamic.

#### Overview

Many apps never verify JWTs, which is correct when only the server relies on them. This test identifies the tokens the *app* relies on — for offline access, feature gating, deep-link or QR-code login, credential presentation, or configuration — and checks that the client verifies them with a fixed algorithm and an anchored key, and enforces their claims.

#### Prerequisites

- Tokens observed in traffic, storage or QR codes, and the code that consumes them (Tests 1–4).
- `tamper_jws.py` from Test 5; optionally `jwt_tool` or Burp Suite's JWT Editor extension.

#### Steps

1. **Classify each token.** For every JWT the app handles, decide from the code and the hook output whether the client merely forwards it (server relies on it), decodes it for display or refresh timing, or makes a local decision with its claims. Only the last group is in scope.

2. **Identify the library and its configuration** (Test 1/2 output): decode-only (`JWT.decode`, `com.auth0.android.jwt.JWT`, `JWTDecode.swift`, `jwt-decode`), verifying with a fixed algorithm (`JWT.require(Algorithm.ES256(...))`, `verifyWith(key)`), or verifying with the header's `alg` and key fields.

3. **Run the mutations** against each in-scope token, delivering it through the same path the app uses (intercepted response, stored value, deep link, QR code):

   ```bash
   python3 -I tamper_jws.py "$TOKEN" plan '"pro"'          # payload change, flipped/empty/zero signature, alg none
   python3 jwt_tool.py "$TOKEN" -X a                        # alg:none variants
   python3 jwt_tool.py "$TOKEN" -X k -pk server_pub.pem     # RS/ES -> HS256 key confusion with the public key
   python3 jwt_tool.py "$TOKEN" -X i                        # inject an attacker JWK in the header
   ```

   Key confusion can also be produced without tools, using the server's public key exactly as the app holds it (try the PEM file with and without its trailing newline, and the DER form):

   ```bash
   b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
   h=$(printf '{"alg":"HS256","typ":"JWT"}' | b64url)
   p=$(printf '{"sub":"test-user","plan":"pro"}' | b64url)
   s=$(printf '%s.%s' "$h" "$p" | openssl dgst -sha256 -mac HMAC -macopt hexkey:$(xxd -p server_pub.pem | tr -d '\n') -binary | b64url)
   echo "$h.$p.$s"
   ```

   Then test claim enforcement with *genuine* tokens: an expired one (wait for, or capture, a token past its `exp`), one for another audience or environment, and one for another test user.

4. **Watch the hooks** (Tests 3/4) to see whether verification runs and what it returns for each variant.

#### Observation

For each in-scope token: library and configuration, the variants delivered, hook output, and app behaviour.

#### Evaluation

The test **fails** if a token whose claims drive a local decision is decoded without verification; if any of the unsigned, `none`, key-confusion, embedded-key or zero-signature variants is accepted; if the verification key comes from the token or a URL in it; or if expired, wrong-audience or other-user tokens are accepted where the decision depends on those claims. Decode-only use for display or refresh scheduling passes (note it as Info). The test also fails, in the server's column, if the backend accepts any of these variants; report that as a server-side CWE-347 finding alongside.

#### Demo

Vulnerable Kotlin (Guler Tech sample): an offline "pro mode" check.

```kotlin
fun isPro(token: String): Boolean {
    val jwt = com.auth0.android.jwt.JWT(token)            // decodes only; no signature check
    return jwt.getClaim("plan").asString() == "pro" && !jwt.isExpired(0)
}
```

Delivering the `payload-changed` variant from `tamper_jws.py` (plan changed to `"pro"`, original signature kept) through the intercepted login response:

```text
[jwt] com.auth0.android.jwt.JWT.$init -> void
```

No verification event follows, and the app switches to Pro mode offline. The `alg-none` and `signature-empty` variants are accepted too, because nothing ever looks at the signature. The test fails.

### Test 7: Purchases, licences and entitlements verified on the device (Android, iOS)

Guler Tech methodology. Platform: Android and iOS. Type: static and dynamic.

#### Overview

For purchases and licences the attacker is usually the device owner, so the right question is not "is the on-device verification correct?" but "is the decision made on the device at all?". Google Play signs purchase data with the app's licence key, StoreKit 2 transactions are JWS signed by the App Store, and legacy App Store receipts are PKCS#7; all of these can be verified on the device, and all of those verifications can be patched out. Google and Apple both recommend verifying purchases on your server and granting entitlements from there.

#### Prerequisites

- Test purchases enabled: a Google Play licence-tester account, or the App Store sandbox or StoreKit testing.
- Tests 1–4 tooling and an intercepting proxy.

#### Steps

1. **Find the purchase and licence code.**

   ```bash
   # Android
   grep -rnE 'getOriginalJson\(\)|getSignature\(\)|getPurchaseToken\(\)|verifyPurchase|SHA1withRSA|onPurchasesUpdated|acknowledgePurchase' out/sources
   grep -rnE 'com\.google\.android\.vending\.licensing|LicenseChecker|ServerManagedPolicy|requestIntegrityToken|decodeIntegrityToken' out/sources
   ```

   ```bash
   # iOS
   nm -um Payload/App.app/App | xcrun swift-demangle | grep -oE 'StoreKit\.(VerificationResult|Transaction|AppTransaction)[A-Za-z.]*' | sort -u
   nm -um Payload/App.app/App | xcrun swift-demangle | grep -c unsafePayloadValue   # may be inlined; 0 is not proof
   strings -a Payload/App.app/App | grep -E 'verifyReceipt|appStoreReceiptURL'
   nm -um Payload/App.app/App | grep -E 'PKCS7_verify|SKReceiptRefreshRequest'
   ```

2. **Trace where the entitlement is granted.** Follow the success path of the purchase flow to the code that unlocks content. Does it send `purchaseToken` (Android) or the transaction's `jwsRepresentation` or `originalID` (iOS) to your backend and wait for an answer, or does it set a local flag?

3. **Check the on-device verifier, if there is one**: `Signature.getInstance("SHA1withRSA")` over `originalJson` with an embedded Base64 public key (the classic Play sample); StoreKit 2 code that unlocks in the `.unverified` case or uses `unsafePayloadValue`; OpenSSL `PKCS7_verify` called with `PKCS7_NOVERIFY` or `PKCS7_NOSIGS`; a call from the device to Apple's deprecated `verifyReceipt` endpoint (which also exposes the app's shared secret, a [MASWE-0004](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/) finding).

4. **Exercise it.** Make a test purchase while the proxy blocks requests to your own backend; if content unlocks, the decision is local. Then apply Test 5 mutations to any cached entitlement (a stored purchase JSON, a licence file, a `UserDefaults` flag) and restart the app. For Play Integrity, confirm the token is sent to the backend unmodified and that the app does not hold decryption or verification keys for it.

#### Observation

Where the entitlement decision is made, which verification (if any) runs on the device and how, what the backend receives, and the result of the blocked-backend and cached-entitlement experiments.

#### Evaluation

The test **fails** if paid content or features are unlocked on the basis of on-device verification alone (or none), if StoreKit 2 `.unverified` results unlock content, if receipt validation uses `PKCS7_NOVERIFY`/`PKCS7_NOSIGS`, or if a cached entitlement can be edited (Test 5 M1) without a server-signed record being re-checked. It passes when the backend verifies the purchase with Google (Play Developer API) or Apple (App Store Server API) and grants the entitlement, and the app treats its local copy as a cache that the server can revoke. A server-signed entitlement cache verified on the device is acceptable defence in depth; note that a rooted user can still patch it.

#### Demo

Vulnerable Swift (Guler Tech sample):

```swift
func handle(_ result: VerificationResult<Transaction>) async {
    switch result {
    case .verified(let t), .unverified(let t, _):         // both branches unlock
        Entitlements.shared.unlock(t.productID)
        await t.finish()
    }
}
```

`xcrun swift-demangle` of the imports shows `StoreKit.VerificationResult` and no network call to the app's backend in the purchase path; static review of `handle` shows the `.unverified` case falling into the same unlock. The test fails. The Android equivalent is `onPurchasesUpdated` calling `unlockPremium()` immediately after a local `SHA1withRSA` check over `getOriginalJson()`, with no `purchaseToken` sent to the server.

### Test 8: Downloaded code, updates and ML models (Android, iOS)

Guler Tech methodology. Platform: Android and iOS. Type: static and dynamic.

#### Overview

Code and models fetched after installation are not covered by the platform's code signing. This test finds what the app downloads and loads at runtime — DEX files, native libraries, JavaScript bundles, scripts, Core ML or TensorFlow Lite models — and checks that each is verified against an anchored key before it is written to its final location and loaded, and that an older valid version cannot be substituted. It complements [MASWE-0049](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0049/) (where the code is loaded from) and MASWE-0057 (resource integrity).

#### Prerequisites

- Tests 1–4 tooling and an intercepting proxy; the ability to host a modified artefact on the proxy.

#### Steps

1. **Find runtime loading.**

   ```bash
   # Android
   grep -rnE 'DexClassLoader|InMemoryDexClassLoader|PathClassLoader\(|System\.load\(|createPackageContext\(|CONTEXT_INCLUDE_CODE' out/sources
   grep -rnE 'com\.microsoft\.codepush|expo\.modules\.updates|org\.tensorflow\.lite\.Interpreter|FirebaseModelDownloader|ai\.onnxruntime' out/sources
   grep -rn 'CodePushPublicKey' apktool_out/res/values/strings.xml
   ```

   ```bash
   # iOS
   nm -um Payload/App.app/App | xcrun swift-demangle | grep -E 'MLModel\.compileModel|MLModel\.init\(contentsOf|JSContext|evaluateScript' | sort -u
   plutil -p Payload/App.app/Info.plist | grep -iE 'CodePush'
   ls Payload/App.app/ | grep -iE 'Expo.plist|main.jsbundle'
   ```

   For CodePush, the presence of `CodePushPublicKey` means bundle signing is enabled; its absence means bundles are trusted on TLS alone. For Expo Updates, check the embedded configuration for a code-signing certificate.

2. **Trace the download-to-load path.** Where is the file written (private storage, cache, external storage)? Is a hash or signature checked, against what key, and before or after it is moved into place? Is the version compared with the installed one?

3. **Watch loading at runtime** (Android):

   ```javascript
   // gt-android-loaders.js
   Java.perform(function () {
     ['dalvik.system.DexClassLoader', 'dalvik.system.PathClassLoader'].forEach(function (c) {
       Java.use(c).$init.overloads.forEach(function (o) {
         o.implementation = function () {
           console.log('[' + c + '] ' + arguments[0]);
           return o.apply(this, arguments);
         };
       });
     });
   });
   // native libraries: watch the linker rather than System.load, which is sensitive to its caller
   Interceptor.attach(Process.getModuleByName('libdl.so').getExportByName('android_dlopen_ext'), {
     onEnter(args) { console.log('[dlopen] ' + args[0].readCString()); }
   });
   ```

   On iOS, trace model compilation and script evaluation with `frida-trace -U -f com.example.app -m '-[JSContext evaluateScript:*]' -i '*MLModel*compileModel*'`, and run the Test 4 script to see whether any verification precedes them.

4. **Substitute the artefact.** Modify it so the change is visible and harmless (a JavaScript bundle with one changed UI string; a model with altered weights that changes an output; a script that logs a marker), serve it in place of the original through the proxy, and restart the app. Then serve an older genuine version (rollback) and, where the manifest is signed separately, a genuine manifest with a modified file.

#### Observation

The list of runtime-loaded artefacts with download URL, storage path, verification step and key, and the outcome of each substitution.

#### Evaluation

The test **fails** if a modified artefact is loaded; if verification uses a key from the download or an unpinned fetch; if files are checked after being placed where they are loaded from, or loaded from storage other apps can write; if a signed manifest's per-file hashes are not enforced; or if an older signed artefact is accepted when the app has seen a newer one. For JavaScript bundles and scripts, transport security alone (TLS without bundle signing) is a Medium finding at least, because a compromise of the update server or CDN becomes code execution on every device.

#### Demo

A React Native app using CodePush without `CodePushPublicKey`. A modified `index.android.bundle` with one changed string is served by the proxy for the update check response's download URL:

```text
[mitmdump] GET https://<update-host>/<bundle-path>  -> served modified index.android.bundle
[Test 3 hooks] no [verify] events during download or install
$ adb shell su -c 'ls /data/data/com.example.app/files/CodePush'
codepush.json
<package-hash>
```

The app installs the modified bundle on the next restart and shows the changed string; no verification event appears in the Test 3 hook output. With `CodePushPublicKey` set and the bundle signed by the release pipeline, the same substitution is rejected and the app keeps the previous bundle. The test fails for the unsigned configuration.

## Secure implementation

MASWE-0011 links no OWASP Best Practices, so this section is ours; [MASTG-BEST-0065](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0065/) and [MASTG-BEST-0066](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0066/) cover the related case of HMAC-protecting local storage. The code below is deliberately small and fails closed; adapt the claim checks to your format.

### Android: verify a signed configuration against a pinned key

```kotlin
import android.content.Context
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import org.json.JSONObject

class SignedConfigVerifier(context: Context) {
    // SubjectPublicKeyInfo (DER) shipped in res/raw; the next key is shipped alongside for rotation
    private val trusted: Map<String, PublicKey> = mapOf(
        "cfg-2026" to load(context, R.raw.config_key_2026),
        "cfg-2027" to load(context, R.raw.config_key_2027),
    )

    private fun load(ctx: Context, id: Int): PublicKey =
        KeyFactory.getInstance("EC").generatePublic(
            X509EncodedKeySpec(ctx.resources.openRawResource(id).use { it.readBytes() }))

    /** Returns the verified config, or throws. Never returns unverified data. */
    fun verify(payload: ByteArray, signature: ByteArray, keyId: String, minVersion: Long): JSONObject {
        val key = trusted[keyId] ?: throw SecurityException("unknown key id")
        val ok = try {
            Signature.getInstance("SHA256withECDSA").run {   // algorithm fixed here, not by the data
                initVerify(key); update(payload); verify(signature)
            }
        } catch (e: java.security.GeneralSecurityException) { false }
        if (!ok) throw SecurityException("bad signature")

        val cfg = JSONObject(String(payload, Charsets.UTF_8))  // parse only after verifying
        if (cfg.getString("app") != BuildConfig.APPLICATION_ID) throw SecurityException("wrong app")
        if (cfg.getLong("version") < minVersion) throw SecurityException("rollback")
        if (cfg.getLong("expires") * 1000 < System.currentTimeMillis()) throw SecurityException("expired")
        return cfg                                            // use only fields inside payload
    }
}
```

The caller persists the highest accepted `version` and passes it as `minVersion`, and keeps using the last verified config if `verify` throws. `GeneralSecurityException` covers `SignatureException` and `InvalidKeyException`; a malformed signature is simply a bad signature. Tink's `PublicKeyVerify` with a public keyset in `res/raw` is an equally good choice: let its exception propagate.

### Android: verify a JWS with a fixed algorithm and claims

```kotlin
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import java.security.interfaces.ECPublicKey
import java.util.Date

fun verifyToken(token: String, issuerKey: ECPublicKey, expectedAud: String): JWTClaimsSet {
    val jwt = SignedJWT.parse(token)                                     // rejects unsigned tokens
    if (jwt.header.algorithm != JWSAlgorithm.ES256) throw SecurityException("unexpected alg")
    if (!jwt.verify(ECDSAVerifier(issuerKey))) throw SecurityException("bad signature")  // key from the app
    val c = jwt.jwtClaimsSet
    if (c.issuer != "https://id.example.com") throw SecurityException("issuer")
    if (expectedAud !in c.audience) throw SecurityException("audience")
    if (c.expirationTime?.before(Date()) != false) throw SecurityException("expired")
    return c
}
```

The header's `jwk`, `jku`, `x5c` and `kid` are never used to pick the key. If several issuer keys are valid during rotation, look `kid` up in a map the app ships, as in the previous example.

### Android: verify downloaded code or models before they are loadable

Download to a temporary file in `cacheDir`, verify the signed manifest (as above), compare the SHA-256 of every file with the manifest using `MessageDigest.isEqual`, reject files not listed, and only then move the files into a private directory under `filesDir` from which they are loaded. Never load from external storage, and record the installed version so an older manifest is refused.

### iOS: verify a signed payload with CryptoKit

```swift
import CryptoKit
import Foundation

enum VerificationError: Error { case unknownKey, badSignature, claims }

struct SignedPayloadVerifier {
    // DER SubjectPublicKeyInfo files shipped in the app bundle
    private let keys: [String: P256.Signing.PublicKey]

    init(bundle: Bundle = .main) throws {
        var k: [String: P256.Signing.PublicKey] = [:]
        for id in ["cfg-2026", "cfg-2027"] {
            guard let url = bundle.url(forResource: id, withExtension: "der") else { continue }
            k[id] = try P256.Signing.PublicKey(derRepresentation: Data(contentsOf: url))
        }
        keys = k
    }

    func verify(payload: Data, signature: Data, keyId: String) throws -> Data {
        guard let key = keys[keyId] else { throw VerificationError.unknownKey }
        guard let sig = try? P256.Signing.ECDSASignature(derRepresentation: signature),
              key.isValidSignature(sig, for: payload) else { throw VerificationError.badSignature }
        return payload                    // decode and check app, version and expiry next
    }
}
```

### iOS: verify an ES256 JWS without a third-party library

```swift
func base64URLDecode<S: StringProtocol>(_ s: S) -> Data? {
    var t = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    while t.count % 4 != 0 { t += "=" }
    return Data(base64Encoded: t)
}

func verifyES256(_ token: String, key: P256.Signing.PublicKey) throws -> [String: Any] {
    let parts = token.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 3,
          let headerData = base64URLDecode(parts[0]),
          let header = try JSONSerialization.jsonObject(with: headerData) as? [String: Any],
          header["alg"] as? String == "ES256",                       // checked, never used to choose
          let payloadData = base64URLDecode(parts[1]),
          let sigData = base64URLDecode(parts[2]), sigData.count == 64 else {
        throw VerificationError.badSignature
    }
    let signingInput = Data("\(parts[0]).\(parts[1])".utf8)
    let sig = try P256.Signing.ECDSASignature(rawRepresentation: sigData)   // JWS uses raw r||s
    guard key.isValidSignature(sig, for: signingInput) else { throw VerificationError.badSignature }
    guard let claims = try JSONSerialization.jsonObject(with: payloadData) as? [String: Any],
          let exp = claims["exp"] as? TimeInterval, exp > Date().timeIntervalSince1970 else {
        throw VerificationError.claims
    }
    return claims                         // then check iss, aud and sub against expected values
}
```

### iOS: validate a signer certificate against your own root

```swift
func signerKey(leaf: SecCertificate, intermediates: [SecCertificate], root: SecCertificate) throws -> SecKey {
    var trust: SecTrust?
    let policy = SecPolicyCreateBasicX509()
    guard SecTrustCreateWithCertificates(([leaf] + intermediates) as CFArray, policy, &trust) == errSecSuccess,
          let t = trust else { throw VerificationError.unknownKey }
    SecTrustSetAnchorCertificates(t, [root] as CFArray)
    SecTrustSetAnchorCertificatesOnly(t, true)                         // ignore the system trust store
    var error: CFError?
    guard SecTrustEvaluateWithError(t, &error), let key = SecCertificateCopyKey(leaf) else {
        throw VerificationError.unknownKey
    }
    return key            // then SecKeyVerifySignature(key, .ecdsaSignatureMessageX962SHA256, ...)
}
```

### Purchases and licences: verify on the server

- **Google Play:** send `purchaseToken` and product ID to your backend; the backend calls the Google Play Developer API (`purchases.products.get` for one-time products, `purchases.subscriptionsv2.get` for subscriptions), checks the state, grants the entitlement and acknowledges the purchase. Play Integrity tokens are likewise decoded and checked on the server.
- **Apple:** with StoreKit 2, unlock only on `.verified` and send `jwsRepresentation` (or the transaction ID) to your backend, which validates it with the App Store Server API or Apple's App Store Server Library and grants the entitlement. Do not call `verifyReceipt` from the device.
- **Licences:** issue them from the server, signed with a key that never ships in the app, bound to the user and device, with an expiry; the app verifies them as above for offline use and re-validates with the server when online.

```swift
for await result in Transaction.currentEntitlements {
    guard case .verified(let transaction) = result else { continue }   // ignore unverified
    await backend.register(jws: result.jwsRepresentation, productID: transaction.productID)
}
```

## Rating findings

Rate on who can supply the tampered data, what accepting it achieves, and how many users it reaches.

| Rating | Conditions |
|---|---|
| **Critical** | An attacker without access to the victim's device can get the app to **run code** (scripts, bundles, plugins, native libraries) or **accept forged authentication data** (tokens, QR or deep-link logins, credentials) because verification is skipped, ignored, uses a key from the data, or accepts `none`/key-confused/unsigned tokens — including when the artefact travels over cleartext, a third-party CDN or shared storage. |
| **High** | The same defects on configuration or models that change security behaviour (pinning, endpoints, authentication requirements, fraud rules) or financial values. Verification against a key fetched over the same unpinned channel as the data. OTA JavaScript bundles protected by TLS only, with no bundle signing. Paid content or licences unlocked solely by on-device verification, where patching tools make the bypass available to any user. |
| **Medium** | Defects exploitable only by someone who can write the app's private storage (root, backup restore, another vulnerability) on data that affects the user's own security. Missing expiry, audience, version or replay checks on otherwise verified artefacts. Weak algorithms (SHA-1) accepted by the verifier. StoreKit 2 `.unverified` transactions honoured. |
| **Low** | Correct verification, but the signer key cannot be rotated without an app update and has no expiry. Lenient signature encodings accepted with the payload intact. A server-signed entitlement cache verified only on the device, with server re-validation. |
| **Info** | Decode-only JWT use for display or refresh timing. A correct client-side check that can be bypassed only by instrumenting or repackaging the app (report under MASVS-RESILIENCE). |

Raise the rating when the affected data reaches other users (shared content, peer-to-peer verification of tickets or credentials) or when the app has elevated privileges; lower it when the backend independently re-verifies the same artefact before acting. In the report, name the artefact, the delivery channel and who controls it, the mutation that was accepted (Test 5 table), the hook output that explains why, and before/after evidence of the effect.

## References

- OWASP MASWE — [MASWE-0011: Improper Verification of Cryptographic Signature](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0011/) (CC BY-SA 4.0)
- OWASP MASWE — [MASWE-0049: Unsafe Dynamic Code Loading](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0049/) and [MASWE-0057: App Resources Integrity Not Verified](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0057/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0029: File Integrity Checks](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0029/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0067: CommonCrypto, SecKey and Wrapper libraries](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0067/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0086: Storage Integrity Checks](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0086/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0338: References to Storage Integrity Check APIs (Android)](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0338/) and [MASTG-TEST-0387: References to Storage Integrity Check APIs (iOS)](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0387/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-DEMO-0150: References to Storage Integrity Check APIs with radare2](https://mas.owasp.org/MASTG/demos/ios/MASVS-RESILIENCE/MASTG-DEMO-0150/MASTG-DEMO-0150/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-BEST-0065: Implementing Storage Integrity Checks on iOS](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0065/) and [MASTG-BEST-0066: Implementing Storage Integrity Checks on Android](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0066/) (CC BY-SA 4.0)
- OWASP MASTG — techniques [MASTG-TECH-0008](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0008/), [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0059](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0059/), [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/), [MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/) (CC BY-SA 4.0)
- [NIST FIPS 186-5 — Digital Signature Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf)
- [RFC 7515 — JSON Web Signature](https://www.rfc-editor.org/rfc/rfc7515), [RFC 7518 — JSON Web Algorithms](https://www.rfc-editor.org/rfc/rfc7518), [RFC 8725 — JSON Web Token Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725)
- [OWASP JSON Web Token Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html)
- [Android Developers — `java.security.Signature`](https://developer.android.com/reference/java/security/Signature) and [`CertPathValidator`](https://developer.android.com/reference/java/security/cert/CertPathValidator)
- [Android Developers — Fight fraud and abuse: verify purchases](https://developer.android.com/google/play/billing/security) and [Play Integrity API](https://developer.android.com/google/play/integrity)
- [Apple — `SecKeyVerifySignature`](https://developer.apple.com/documentation/security/seckeyverifysignature%28_:_:_:_:_:%29), [`SecTrustEvaluateWithError`](https://developer.apple.com/documentation/security/sectrustevaluatewitherror%28_:_:%29) and [`SecTrustSetAnchorCertificates`](https://developer.apple.com/documentation/security/sectrustsetanchorcertificates%28_:_:%29)
- [Apple — CryptoKit `P256.Signing.PublicKey`](https://developer.apple.com/documentation/cryptokit/p256/signing/publickey)
- [Apple — StoreKit `VerificationResult`](https://developer.apple.com/documentation/storekit/verificationresult) and [App Store Server API](https://developer.apple.com/documentation/appstoreserverapi)
- [Google Tink — Digital signatures](https://developers.google.com/tink/digital-signature)
- [CVE-2013-4787](https://nvd.nist.gov/vuln/detail/CVE-2013-4787), [CVE-2015-9235](https://nvd.nist.gov/vuln/detail/CVE-2015-9235), [CVE-2018-0114](https://nvd.nist.gov/vuln/detail/CVE-2018-0114), [CVE-2022-21449](https://nvd.nist.gov/vuln/detail/CVE-2022-21449)
- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html) and [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
