---
title: "Improper Random Number Generation (MASWE-0012)"
date: 2026-11-09 12:24:00 +0000
subcategory: crypto
summary: "Testing Android and iOS apps for predictable randomness: java.util.Random, seeded SecureRandom, rand/drand48, time-based tokens, Frida hooks, fixes."
refs: [MASWE-0012, MASVS-CRYPTO-1, CWE-332, CWE-337, CWE-338]
tags: [android, ios, masvs-crypto, prng, securerandom, frida]
---

This note is part of our [MASVS-CRYPTO guide](/mobile/masvs-crypto-cryptography-guide/) and covers OWASP [MASWE-0012](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0012/): security-relevant values produced by a generator an attacker can predict. Almost every other control in the series assumes good randomness. Keys, IVs, nonces, salts, session identifiers, OTPs, PKCE verifiers and password-reset codes are only as strong as the generator behind them, and a 256-bit AES key drawn from `java.util.Random` has at most 2^48 possible values, however long it looks. Below you will find how the platform generators actually work (`java.util.Random`, `SecureRandom` and Conscrypt on Android; the kernel CSPRNG, `SecRandomCopyBytes`, `arc4random` and the libc PRNGs on iOS), the four OWASP tests with their demos, Frida scripts for runtime confirmation, working proof-of-concept code that predicts `java.util.Random` output for a report, secure Kotlin and Swift patterns, and severity guidance.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: Random Number Generation (MASTG-KNOW-0013)](#android-random-number-generation-mastg-know-0013)
  - [iOS: Random Number Generator (MASTG-KNOW-0070)](#ios-random-number-generator-mastg-know-0070)
  - [Both platforms: where unpredictability is required (supplementary)](#both-platforms-where-unpredictability-is-required-supplementary)
  - [Both platforms: non-random sources, seeding and modulo bias (supplementary)](#both-platforms-non-random-sources-seeding-and-modulo-bias-supplementary)
- [Tests](#tests)
  - [MASTG-TEST-0204: Insecure Random API Usage (Android)](#mastg-test-0204-insecure-random-api-usage-android)
  - [MASTG-TEST-0205: Non-random Sources Usage (Android)](#mastg-test-0205-non-random-sources-usage-android)
  - [MASTG-TEST-0311: Insecure Random API Usage (iOS)](#mastg-test-0311-insecure-random-api-usage-ios)
  - [MASTG-TEST-0349: Runtime Use of Insecure Random APIs (iOS)](#mastg-test-0349-runtime-use-of-insecure-random-apis-ios)
  - [Supplementary checks (not OWASP tests)](#supplementary-checks-not-owasp-tests)
  - [Proving predictability in a report](#proving-predictability-in-a-report)
- [Best practices](#best-practices)
  - [MASTG-BEST-0001: Use Secure Random Number Generator APIs (Android)](#mastg-best-0001-use-secure-random-number-generator-apis-android)
  - [MASTG-BEST-0025: Use Secure Random Number Generator APIs (iOS)](#mastg-best-0025-use-secure-random-number-generator-apis-ios)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

A pseudorandom number generator (PRNG) is a deterministic function. It holds some internal state, and each call advances the state and returns a value derived from it. Two properties decide whether a PRNG is acceptable for security work:

- **State size and seeding.** If the state, or the seed it started from, is small or guessable, an attacker can enumerate it. `java.util.Random` has 48 bits of state. libc `rand()` seeded with `time(nil)` has as many possibilities as there are seconds in the window the attacker cares about.
- **Forward unpredictability.** A *statistical* PRNG only promises that its output looks uniformly distributed. Nothing stops you working backwards from outputs to the state. A *cryptographically secure* PRNG (CSPRNG) adds the guarantee that seeing any amount of output does not let you compute other outputs, past or future, any faster than brute force over its full seed space.

Statistical quality and security are different properties. `java.util.Random` passes most statistical batteries you are likely to run against it. As the [proof section](#proving-predictability-in-a-report) shows, you can still recover its state from two `nextInt()` values in milliseconds, and from a 16-character password it generated in about five seconds on a laptop. This is why "the tokens look random" is never evidence, and why a statistical tool such as Burp Sequencer cannot clear a finding of this kind.

Both mobile platforms ship a good CSPRNG. On Android it is `java.security.SecureRandom`, which on every current version ends up in BoringSSL's DRBG (via Conscrypt) seeded from the Linux kernel. On iOS it is the kernel's Fortuna-based generator, reached through `SecRandomCopyBytes`, `SystemRandomNumberGenerator`, CryptoKit and, on Apple platforms, `arc4random`. MASWE-0012 is therefore almost never about a platform shortcoming. It is about apps that:

1. call a general-purpose generator (`java.util.Random`, `Math.random()`, Kotlin `Random`, `ThreadLocalRandom`, `rand()`, `random()`, `drand48()`, GameplayKit, a home-made Swift `RandomNumberGenerator`) where a CSPRNG was needed;
2. make a value "random" out of something that is not random at all: the clock, a device identifier, a `hashCode()`, a counter; or
3. take a good generator and make it deterministic: a hardcoded seed, a seed derived from public values, or `SecureRandom` misused as a key-derivation function.

The weakness maps to MASVS-CRYPTO-1 and to CWE-332 (Insufficient Entropy in PRNG), CWE-337 (Predictable Seed in PRNG) and CWE-338 (Use of Cryptographically Weak PRNG). In MASVS v1 it was MSTG-CRYPTO-6, and the OWASP profiles are L1, L2 and EUDIW (the EU Digital Identity Wallet profile).

## Modes of Introduction

**Risky random APIs.** The developer reaches for the convenient API. `Random().nextInt(…)` for a six-digit OTP, `Math.random()` for a nonce, `(1..16).map { chars.random() }` for a temporary password, `arc4random()` (fine on Apple) next to `rand()` (not fine) in shared C code, or `Int.random(in:using:)` with a seedable generator someone wrote for unit tests. These APIs are not documented as cryptographically secure. Some are documented as explicitly *not* secure: the Javadoc for `java.util.Random`, `ThreadLocalRandom` and `SplittableRandom` all say so.

**Non-random sources.** "Random" values built from `System.currentTimeMillis()`, `Date().time`, `Calendar.MILLISECOND`, `System.nanoTime()`, `CFAbsoluteTimeGetCurrent()`, `ANDROID_ID`, `identifierForVendor`, `Build.SERIAL`, a user ID, a `hashCode()` or a combination of them, often run through a hash so they *look* random. Hashing does not add entropy. SHA-256 of a millisecond timestamp still has about as many possible values as there are milliseconds in the attacker's search window.

**Hardcoded or predictable seeds.** `Random(42)`, `srand(1234)`, `GKMersenneTwisterRandomSource(seed: 0xC0FFEE)`, `SecureRandom(seedBytes)` with a constant, or a seed from public data (package name, install time, device ID). A hardcoded seed is recoverable from the package with `jadx` or `strings`, and it makes the output identical on every install. A special and still common case is **SecureRandom as a KDF**: seeding `SHA1PRNG` with a password and passing it to `KeyGenerator.init` to "derive" an AES key. This only ever worked because the old provider was deterministic after `setSeed`. Android 9 removed that provider, and key derivation belongs in a real KDF ([MASWE-0014](/mobile/maswe-0014-improper-key-derivation/)).

## Impact

- **Authentication or authorisation bypass.** If an attacker can predict or enumerate a session identifier, an OTP or a password-reset code, they can take over the account without the credential. The same applies to an OAuth `state` or PKCE `code_verifier` generated client-side, a device-binding secret, or a pairing code. A predictable PKCE verifier defeats the protection PKCE adds against authorisation-code interception.
- **Compromise of sensitive data.** Keys, IVs and salts derived from a weak generator can be reproduced. A local database key from `Random(seed)` with a constant seed is in effect a hardcoded key (see [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/)). A key from an unseeded `java.util.Random` is a 48-bit key that can be brute-forced given one known plaintext block.
- **Private-key recovery from signatures.** ECDSA and DSA need a fresh, secret, uniformly random nonce *k* for every signature. Reuse or predictability of *k* leaks the private key from two signatures. This is how Android Bitcoin wallets were drained in 2013 (see the [Android knowledge section](#android-random-number-generation-mastg-know-0013)). It is mostly a concern for apps that implement signing in their own code or bundle an old library; platform and Keystore signing are not affected. See [MASWE-0010](/mobile/maswe-0010-improper-signature-generation/).
- **Loss of encryption guarantees.** GCM with a repeated nonce under the same key loses confidentiality for the affected messages and lets an attacker forge authentication tags. CBC with a predictable IV is open to chosen-plaintext attacks. See [MASWE-0007](/mobile/maswe-0007-improper-encryption/).

## Mitigations

- **Use the platform CSPRNG for every security-relevant value.** On Android that is `SecureRandom()` with the default constructor. On iOS it is `SecRandomCopyBytes`, CryptoKit (`SymmetricKey(size:)`, `AES.GCM.Nonce()`), or the Swift standard library `random` APIs with the default `SystemRandomNumberGenerator`. Better still, let the platform generate the value for you: Android Keystore and CryptoKit generate keys and IVs internally.
- **Never seed deterministically.** Do not pass a seed to `SecureRandom`, do not call `setSeed` "to add entropy", and never use a hardcoded seed in any generator whose output matters. Seeded, reproducible generators belong in tests and game replays only.
- **Use enough entropy and a uniform mapping.** Use at least 128 bits for anything an attacker can attack offline: keys, tokens, salts and reset links (NIST SP 800-132 requires at least 128 random bits in a PBKDF salt). Use at least 64 bits for session identifiers (NIST SP 800-63B and the OWASP Session Management Cheat Sheet). Use short numeric codes only behind server-side rate limiting and expiry. Map random bits into a range with `nextInt(bound)`, `arc4random_uniform(n)` or `Int.random(in:)`, not `% n`.
- **Prefer server generation for server-trusted secrets.** Session tokens, reset codes and OTPs should be minted by the backend's CSPRNG. If the client generates something the server will trust (PKCE verifier, OAuth `state`, a device secret), apply the same standard as the server would.
- **Follow established guidance**: [RFC 4086](https://datatracker.ietf.org/doc/html/rfc4086) (Randomness Requirements for Security), NIST SP 800-90A Rev. 1 (DRBG constructions), and the [OWASP Cryptographic Storage Cheat Sheet, "Secure Random Number Generation"](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#secure-random-number-generation).

## Knowledge

### Android: Random Number Generation (MASTG-KNOW-0013)

Source: [MASTG-KNOW-0013](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0013/), extended with the OpenJDK/libcore, Conscrypt and Kotlin standard-library sources and the Android Developers ["Weak PRNG" risk page](https://developer.android.com/privacy-and-security/risks/weak-prng).

The OWASP page is short: use `SecureRandom` with the default constructor, never `java.util.Random`, and be aware of the 2013 PRNG bug. What follows is the mechanism a tester needs in order to reason about each hit.

#### java.util.Random: a 48-bit LCG

`java.util.Random` is a linear congruential generator (LCG), and its algorithm is fixed by its specification. Every conforming Java implementation, Android's libcore included, must produce the same sequence for the same seed:

```text
state  = (state * 0x5DEECE66D + 0xB) mod 2^48
next(bits) = state >>> (48 - bits)          // top bits of the new state
```

- `Random(seed)` sets `state = (seed XOR 0x5DEECE66D) mod 2^48`. Same seed, same sequence, on every device and every JVM.
- `Random()` (no argument) seeds from `seedUniquifier() XOR System.nanoTime()` in the OpenJDK-based libcore that Android uses. `nanoTime` is a monotonic clock since boot, and the uniquifier is a fixed sequence of constants. The seed is not secret in principle, but in practice you never need it: the 48-bit *state* is the real bound, and outputs leak it directly.
- `nextInt()` returns `next(32)`: the top 32 of the 48 state bits. Two consecutive values leave only 16 unknown bits to brute-force, which takes milliseconds.
- `nextLong()` is `(next(32) << 32) + next(32)`, so one `nextLong()` hands you two consecutive outputs.
- `nextDouble()` is `((next(26) << 27) + next(27)) * 2^-53`. One double leaks 53 bits across two states, leaving 22 unknown bits (four million candidates, under a second).
- `nextInt(bound)` uses `next(31)` and either a multiply-shift (when `bound` is a power of two) or `r % bound` with rejection. Even when each output reveals only about six bits (`bound = 62`), the generator is still only 48 bits. The low *k* bits of an LCG modulo 2^*k* form their own smaller LCG, so the low 18 bits can be solved separately from the parity of the outputs and the remaining 30 brute-forced. We use this in the [password PoC](#proving-predictability-in-a-report).
- `nextBytes(n)` fills the buffer from `nextInt()` four bytes at a time. Sixteen "random" key bytes are four consecutive outputs of the same 48-bit state.

**`Math.random()`** calls `nextDouble()` on a single process-wide `java.util.Random` created on first use. Every `Math.random()` call in the app and in every library it loads draws from the same sequence. If one value from that sequence is ever visible to an attacker (an analytics sampling value, a jitter delay, a request ID), every later `Math.random()` value in that process is predictable.

#### Other non-cryptographic generators you will meet

| API | What it is | Why it is not acceptable for secrets |
|---|---|---|
| `java.util.concurrent.ThreadLocalRandom` | Per-thread 64-bit generator (SplitMix-style), API 21+ | Javadoc: "not cryptographically secure". Its seeding has also been unreliable on some Android versions (below) |
| `java.util.SplittableRandom` | 64-bit SplitMix, API 24+ | Javadoc: "not cryptographically secure" |
| `kotlin.random.Random` (`Random.Default`, `Random(seed)`) | `Random(seed)` is XorWow. `Random.Default` delegates to a platform generator | Not specified as cryptographically secure. On Android below API 34, `Random.Default` is a per-thread `java.util.Random` |
| Kotlin collection helpers: `list.random()`, `shuffled()`, `IntRange.random()`, `"…".random()` | Use `Random.Default` unless you pass a generator | Same as above |
| Apache Commons Lang `RandomStringUtils` / `RandomUtils` | Static helpers; older releases use a shared `java.util.Random` | Check the bundled version and which instance (`secure()` or `insecure()` in recent releases) is used |
| Dart `Random()`, JavaScript `Math.random()` (Flutter, React Native) | Statistical PRNGs in the framework runtime | Use `Random.secure()` / `crypto.getRandomValues` instead |

The Kotlin detail is worth knowing because Kotlin code rarely names `java.util.Random`. The JDK 8 platform implementation in the Kotlin standard library only uses `ThreadLocalRandom` for `Random.Default` when the Android SDK level is 34 or higher. Its source comments say `ThreadLocalRandom` seeding is broken on Android API 25–33. Below 34 it falls back to a thread-local `java.util.Random`. Either way `Random.Default` is not a CSPRNG. The secure Kotlin idiom is `SecureRandom().asKotlinRandom()`, passed explicitly to `shuffled(…)`, `random(…)` and friends.

#### SecureRandom on Android

`java.security.SecureRandom` is the JCA's CSPRNG interface, and the implementation you get depends on the provider. On every Android version you will test today:

- `new SecureRandom()` takes the first provider that offers a `SecureRandom` service. That is Conscrypt, registered as `AndroidOpenSSL`, under the algorithm name `SHA1PRNG`. The OWASP page states this, and `getAlgorithm()` will print `SHA1PRNG`. Do not let the name mislead you: Conscrypt maps it to `OpenSSLRandom`, which calls BoringSSL's `RAND_bytes`, a CTR-DRBG seeded from the kernel (`getrandom`/`/dev/urandom`). It has nothing in common with the SHA-1-based "SHA1PRNG" of the old Harmony and Sun providers.
- `SecureRandom.getInstance("SHA1PRNG")` on Android 9+ resolves to the same Conscrypt implementation.
- `setSeed(…)` and the `SecureRandom(byte[] seed)` constructor reach `OpenSSLRandom.engineSetSeed`. In current Conscrypt this checks the argument for `null` and otherwise ignores it. So on modern Android a seed does not make the output deterministic. It just does nothing.
- `setSeed(long)` is called with `0` by `java.util.Random`'s constructor during every `SecureRandom` construction, because `SecureRandom extends Random`. `SecureRandom` ignores that call. This matters when you hook `setSeed` (see below).

So why does OWASP still say "default constructor only", and why do we still flag seeded or provider-pinned `SecureRandom`?

- **History and portability.** Until Android 9 the platform also shipped the Apache Harmony `Crypto` provider, whose `SHA1PRNG` *replaced* its state with your seed if you called `setSeed` before the first `nextBytes`. Its output was then fully deterministic. This is what made the "derive an AES key by seeding SHA1PRNG with the password" Stack Overflow pattern "work". Google deprecated the provider in Android 7.0 (it threw `NoSuchProviderException` for apps targeting API 24+) and removed it in Android 9 (API 28). The same code in a shared Kotlin/JVM module running on a server JDK still gets Sun's `SHA1PRNG`, where seeding before first use is documented to make it deterministic.
- **Third-party providers.** An app that calls `SecureRandom.getInstance(alg, provider)` against a bundled provider, or uses a deterministic test helper such as Bouncy Castle's `org.bouncycastle.util.test.FixedSecureRandom` outside tests, gets whatever that provider does.
- **Intent.** A constant seed tells you the developer expected reproducible output. That expectation is the bug, even when today's provider quietly discards the seed.

**`SecureRandom.getInstanceStrong()`** (Java 8, Android API 26) returns the implementation named in the `securerandom.strongAlgorithms` security property. On server JDKs on Linux this is `NativePRNGBlocking`, which reads `/dev/random`. Before Linux 5.6 that could block for a long time when the kernel's entropy estimate was low, hence the well-known "my server hangs on startup" problem. On Android every platform `SecureRandom` ends in the same BoringSSL generator, so `getInstanceStrong()` gives you no extra strength. It can throw `NoSuchAlgorithmException` if the property names something unavailable, and on a JVM backend it may block. Treat it as unnecessary on Android. Recommend the default constructor.

**`UUID.randomUUID()`** draws 122 bits from `SecureRandom` (version 4). That is fine as an unguessable identifier. `UUID.nameUUIDFromBytes(…)` is a version 3 UUID (an MD5 of its input) and is entirely deterministic.

#### The 2013 Android PRNG bug (history)

In August 2013 a Bitcoin.org advisory warned that every Android Bitcoin wallet was exposed to theft. Wallets had produced ECDSA signatures with repeated nonces, and the private keys were computed from the blockchain. Google's ["Some SecureRandom Thoughts"](https://android-developers.googleblog.com/2013/08/some-securerandom-thoughts.html) confirmed that the JCA's PRNG was not properly initialised on some devices. The OWASP page names Android 4.1–4.3 (API 16–18). Google published a `PRNGFixes` class that seeded OpenSSL's PRNG from `/dev/urandom` and installed a `/dev/urandom`-backed `SecureRandom` provider at the highest priority. Earlier academic work had already found entropy weaknesses in the Harmony `SHA1PRNG` used on Android (Michaelis, Meyer and Schwenk, "Randomly Failed!", CT-RSA 2013).

For testing today this is history. No supported app should have a `minSdkVersion` below 19. If you find `PRNGFixes` in a modern APK it is dead code: report it as Info at most and move on. The lesson is the useful part: correct high-level code was still broken by the provider underneath it. That is why OWASP's best practice tells you to rely on a current, maintained provider.

### iOS: Random Number Generator (MASTG-KNOW-0070)

Source: [MASTG-KNOW-0070](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0070/), extended with Apple's Platform Security Guide, the Darwin man pages and SE-0202.

#### The system CSPRNG

Apple platforms have one kernel CSPRNG, based on Fortuna (Apple Platform Security Guide, "Random number generation"). It is seeded at boot and continuously reseeded from the Secure Enclave's hardware TRNG, interrupt timing jitter and other sources. User space reaches it through `/dev/random` and `/dev/urandom`, which are equivalent on Darwin and do not block the way Linux's `/dev/random` historically did, through `getentropy(2)` (at most 256 bytes per call, intended for seeding), and through the higher-level APIs below. For an app, everything in the "secure" column of the table ultimately draws from this generator.

| API | Backed by | Verdict for security use |
|---|---|---|
| `SecRandomCopyBytes(kSecRandomDefault, n, buf)` | `CCRandomCopyBytes` → `CCRandomGenerateBytes` → system CSPRNG | **Preferred.** Check the `OSStatus` |
| CryptoKit `SymmetricKey(size:)`, `AES.GCM.Nonce()`, `ChaChaPoly.Nonce()`, `P256…PrivateKey()` | System CSPRNG | **Preferred** for keys and nonces: you never handle raw randomness |
| `Int.random(in:)`, `UInt8.random(in:)`, `Bool.random()`, `shuffled()`, `randomElement()` with the default generator | `SystemRandomNumberGenerator` → `arc4random_buf` | Secure on Apple platforms |
| `CCRandomGenerateBytes`, `CCRandomCopyBytes` | System CSPRNG | Secure, lower level |
| `arc4random()`, `arc4random_buf()`, `arc4random_uniform(n)` | System CSPRNG on current Apple platforms | Secure on Apple, but legacy C style (see below) |
| `/dev/random`, `/dev/urandom`, `getentropy` | Kernel CSPRNG directly | Secure, but discouraged: easy to mishandle short reads and errors |
| `rand()`, `srand()`, `rand_r()` | Small-state libc PRNG | **Insecure** |
| `random()`, `srandom()` | Additive feedback generator, 31 words of state by default | **Insecure** |
| `drand48()`, `erand48()`, `lrand48()`, `nrand48()`, `mrand48()`, `jrand48()`, `srand48()`, `seed48()`, `lcong48()` | 48-bit LCG, same multiplier and increment as `java.util.Random` | **Insecure** |
| GameplayKit `GKARC4RandomSource`, `GKLinearCongruentialRandomSource`, `GKMersenneTwisterRandomSource`, `GKRandomDistribution` | Seedable, deterministic game PRNGs | **Insecure** (Apple positions them for gameplay, not cryptography) |
| A custom type conforming to `RandomNumberGenerator`, passed with `using: &rng` | Whatever it implements (often SplitMix64 or xorshift for reproducible tests) | **Insecure** unless it wraps the system CSPRNG |
| C++ `std::rand`, `std::mt19937`, Unity `UnityEngine.Random`, .NET `System.Random` | Statistical PRNGs | **Insecure** |

#### The arc4random nuance

The name comes from RC4 (the "Alleged RC4" cipher) used by the original BSD implementation, and many testers still flag `arc4random` on reflex. Do not. On current Apple platforms the `arc4random` family is backed by the same system CSPRNG as `SecRandomCopyBytes`. The macOS man page describes it as a cryptographic pseudo-random number generator, and OWASP's knowledge page and demos treat it as secure. The reasons to prefer other APIs are about misuse, not strength:

- **`arc4random() % n` has modulo bias** whenever *n* does not divide 2^32. With `% 256`, as in the OWASP demo, there is no bias (2^32 is a multiple of 256). With `% 10` or `% 62` there is. `arc4random_uniform(n)` rejection-samples and is always uniform.
- **Portability.** The same C file compiled for another platform may get a different implementation. Glibc only gained `arc4random` in version 2.36, and other libcs have shipped RC4- or ChaCha-based versions with different guarantees. That matters for shared native code, not for the iOS build itself.

`rand()`/`random()` are a different story: they are deterministic by design and their state is tiny. `srand(time(nil))` makes the whole sequence a function of a 32-bit Unix timestamp. An attacker who knows roughly when the value was generated needs to try only a few thousand seeds. The OWASP demo's trace shows exactly this: the seed `0x691a0327` is the Unix time 1763312423, or 2025-11-16 17:00:23 UTC, the moment the demo ran. `drand48()` without any `srand48` call is worse still. POSIX fixes its initial state (`0x1234ABCD330E`), so an unseeded `drand48` produces **the same sequence on every launch of every install**. We compiled the demo's `drand48` token loop against the macOS libc and got `65d75a7251e203952862b00fe6292888` on every run.

#### Swift standard library and custom generators

SE-0202 (Swift 4.2) added `random(in:)`, `random(in:using:)`, `shuffled()`, `randomElement()` and the `RandomNumberGenerator` protocol. With no `using:` argument these APIs use `SystemRandomNumberGenerator`, which Apple documents as using a cryptographically secure algorithm on all its platforms. A trace shows it ending in `arc4random_buf`. The risk is the `using:` overload. Developers write a seedable generator for deterministic tests or procedural content, and it leaks into production code that generates codes or IDs. Any type conforming to `RandomNumberGenerator` in the app is worth a look.

Swift also blocks the most obvious mistake. The Darwin headers mark `rand`, `srand`, `random`, `rand_r` and several `*rand48` functions `__swift_unavailable`, so Swift code cannot call them directly. Some `*rand48` functions such as `drand48()` remain callable. When you find `rand`/`random` imports in a Swift app, they come from Objective-C or C/C++ code, a third-party SDK or engine, or deliberate `@_silgen_name` bindings like the ones the OWASP demo uses to reach them.

### Both platforms: where unpredictability is required (supplementary)

Our methodology: OWASP's tests both end in "determine whether the value is security-relevant". This table is how we make that call and what we expect to see.

| Value | Requirement | Minimum we accept | Notes |
|---|---|---|---|
| Symmetric keys, HMAC keys | Secret, uniform | 128 bits from a CSPRNG (256 preferred), ideally generated *inside* Keystore/Secure Enclave/CryptoKit | Key generation: [MASWE-0013](/mobile/maswe-0013-improper-key-generation/) |
| AES-GCM / ChaCha20-Poly1305 nonce | **Unique** per key | 96-bit random nonce from a CSPRNG, or a counter. NIST SP 800-38D caps random-IV GCM at 2^32 messages per key | Reuse is catastrophic: [MASWE-0007](/mobile/maswe-0007-improper-encryption/) |
| AES-CBC IV | **Unpredictable** | 128 bits from a CSPRNG per message (NIST SP 800-38A, Appendix C) | A counter or timestamp IV is a finding even if unique |
| ECDSA/DSA nonce *k* | Secret, uniform, never reused | Leave it to the platform, or use RFC 6979 deterministic nonces | Own-code signing only: [MASWE-0010](/mobile/maswe-0010-improper-signature-generation/) |
| Salts (PBKDF2, Argon2, scrypt) | Unique, not secret | At least 128 random bits (NIST SP 800-132) | [MASWE-0014](/mobile/maswe-0014-improper-key-derivation/) |
| Session IDs, refresh tokens, API tokens | Unguessable | At least 64 bits of entropy (NIST SP 800-63B; OWASP Session Management Cheat Sheet). We expect 128+ | Should be server-generated |
| Password-reset tokens/links | Unguessable, single use, short-lived | 128 bits for links. Short codes only with rate limiting and expiry | OWASP Forgot Password Cheat Sheet |
| OTPs, PINs, pairing codes | Uniform over the code space | CSPRNG + `nextInt(10^n)`. Security comes from attempt limits | Server-generated by preference |
| PKCE `code_verifier`, OAuth `state`, OIDC `nonce` | Unguessable | RFC 7636 recommends 32 random octets base64url-encoded for the verifier | Client-generated by design: test these |
| UUIDs used as capabilities (share links, file names) | Unguessable | UUID v4 from a CSPRNG (122 bits) at minimum | RFC 9562 warns not to assume UUIDs are hard to guess |
| Temporary passwords | Unguessable | CSPRNG + uniform alphabet mapping, 16+ characters | |

Values that do **not** need a CSPRNG, and should not be reported: UI animation and colours, shuffle order of non-sensitive content, game mechanics, retry back-off jitter, A/B bucketing and analytics sampling (unless the bucket gates a security feature), test fixtures. Be careful with "jitter is harmless" when the same `Math.random()` instance also feeds a token: as explained above, the harmless value leaks the state.

### Both platforms: non-random sources, seeding and modulo bias (supplementary)

Our methodology. These cases need no PRNG to go wrong.

**Non-random sources and how much they are worth to an attacker**

| Source | Effective entropy | Typical misuse |
|---|---|---|
| `System.currentTimeMillis()`, `Date().time`, `Instant.now()`, `Date().timeIntervalSince1970`, `CFAbsoluteTimeGetCurrent()` | About log2 of the attacker's time window in ms: about 22 bits for one hour, often far less, because request timestamps or `Date` headers narrow it | Tokens, file names, IVs, "random" seeds |
| `Calendar.MILLISECOND`, `Calendar.SECOND` | Under 10 bits (0–999) or 6 bits | "Random" PINs and codes, as in MASTG-DEMO-0008 |
| `System.nanoTime()`, `SystemClock.elapsedRealtime()`, `uptimeMillis()`, `mach_absolute_time()` | Time since boot. Guessable to within the device's uptime range | Seeds |
| `ANDROID_ID`, `Build.SERIAL`, IMEI, MAC, `identifierForVendor`, advertising ID, Firebase installation ID | 0 bits against anyone who can read them: they are identifiers, not secrets | Device "secrets", key material, encryption passwords |
| `hashCode()`, `System.identityHashCode`, `Object.toString()` | 32 bits at most, often deterministic (`String.hashCode` is a fixed polynomial) | Request signatures, "unique" IDs |
| Counters, `Process.myPid()`, `getpid()` | A handful of bits | Nonces |
| `ProcessInfo.processInfo.globallyUniqueString` | Documented as unique (host name, process ID and timestamp), not as unpredictable | Tokens |
| UUID v1/v6 (time + node), v3/v5 (`UUID.nameUUIDFromBytes`, name-based hashes) | Time-based or fully deterministic | Share links, reset tokens |
| A hash (MD5/SHA-1/SHA-256) of any of the above | The same entropy as the input | Everything above, "made random" |

**Seeding.** A generator is never stronger than its seed. `Random(seed)` with a constant gives identical output on every install. `Random(System.currentTimeMillis())` has as many possible states as the attacker's time window has milliseconds, not 2^48. A secure generator seeded deterministically is just as bad if the provider honours the seed (Harmony `SHA1PRNG`, Sun `SHA1PRNG` before first use, any seeded DRBG in a third-party library). When you see a seed, ask two questions: does this implementation honour it, and where does the seed come from?

**Modulo bias.** Mapping a uniform value from a range of size *N* into *n* buckets with `% n` makes the first `N mod n` buckets slightly more likely. Two worked examples:

- `bytes[i] % 62` for an alphanumeric token: 256 mod 62 = 8, so the first 8 characters of the alphabet each occur with probability 5/256 and the other 54 with 4/256. The first 8 characters are 25% more likely than the rest. The entropy loss is small (about 5.950 bits per character instead of 5.954), so on its own this is a Low finding. It is still worth fixing, and it shows the developer is hand-rolling the mapping.
- `abs(secureRandom.nextInt()) % 1_000_000` for an OTP: 2^31 mod 10^6 = 483,648, so codes below 483,648 are more likely by about 1 in 2,147 (negligible). The real bug is `Math.abs(Integer.MIN_VALUE)`, which is still negative and produces a malformed code once in about 4 billion draws. `nextInt(1_000_000)` avoids both problems.

Bias becomes material when *n* is a large fraction of *N*, for example `UInt16 % 40000`, where the first 25,536 values are twice as likely as the rest. Report bias for what it costs in entropy, not as a predictability finding.

## Tests

OWASP maps four tests to MASWE-0012: two static tests for Android (insecure APIs, non-random sources) and a static and a dynamic test for iOS. All four share the same structure. Find the API, then prove the value is security-relevant. They also share the same blind spots: seeded `SecureRandom`, Kotlin `Random`, custom Swift generators, GameplayKit and cross-platform frameworks are not covered. We close those gaps in the [supplementary checks](#supplementary-checks-not-owasp-tests), and the [proof section](#proving-predictability-in-a-report) shows how to turn a hit into evidence.

The two Android tests list the prerequisites "identify sensitive data" and "identify security-relevant contexts". In practice that means doing the threat modelling first: list the app's authentication, session, recovery, pairing and encryption flows, so that when the scan returns 40 `Random` hits you know which call sites sit on those paths.

### MASTG-TEST-0204: Insecure Random API Usage (Android)

Source: [MASTG-TEST-0204](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0204/). Type: static (code), manual review. Related knowledge: MASTG-KNOW-0013. Best practice: MASTG-BEST-0001. Supersedes the legacy (MASTG v1) test MASTG-TEST-0016 "Testing Random Number Generation".

#### Overview

The test looks for general-purpose PRNGs, `java.util.Random` and `Math.random()` in OWASP's rule, at call sites that produce security-relevant values. OWASP's principle is the one to quote in a report: if a PRNG is not explicitly documented as cryptographically secure, it must not be used where unpredictability is required. We widen the API list to `ThreadLocalRandom`, `SplittableRandom`, Kotlin `Random` and common helper libraries, and we include seeded or provider-pinned `SecureRandom` in the same sweep. That case has no dedicated OWASP test, but OWASP's static-analysis technique page uses exactly this example.

#### Prerequisites

- The APK(s) of the build under test: `adb shell pm path com.example.app`, then `adb pull` each path (base and splits).
- `jadx` for decompilation (MASTG-TECH-0013, reverse engineering Android apps) and `semgrep` and `grep` for the search (MASTG-TECH-0014, static analysis on Android, with MASTG-TOOL-0110).
- The list of security-relevant flows from your threat model (see above).
- Optional, for confirmation: a rooted device or emulator with `frida-server` ([supplementary runtime check](#android-runtime-confirmation-of-prng-use)).

#### Steps

1. **Decompile.** jadx emits Java even for Kotlin sources, which is why the OWASP rules target Java:

   ```bash
   jadx --deobf -d out/ base.apk
   ```

   Keep a non-deobfuscated copy too (`jadx -d out-raw/ base.apk`) if the app is minified. R8 often keeps the names of `java.*` and `kotlin.*` classes, so the APIs remain searchable even when the app's own classes are renamed.

2. **Run the OWASP rule** (`mastg-android-random-apis-insufficient-entropy.yml`, adapted by OWASP from the mindedsecurity Android semgrep rules):

   ```yaml
   rules:
     - id: mastg-android-random-apis-insufficient-entropy
       severity: WARNING
       languages:
         - java
       message: "[MASVS-CRYPTO-1] The application makes use of random number generators with insufficient entropy."
       pattern-either:
         - patterns:
             - pattern-inside: $M(...){ ... }
             - pattern-either:
                 - pattern: Math.random(...)
                 - pattern: (java.util.Random $X).$Y(...)
   ```

   ```bash
   semgrep -c mastg-android-random-apis-insufficient-entropy.yml out/sources/
   ```

   The typed pattern `(java.util.Random $X).$Y(...)` matches any method call on a value semgrep can infer to be a `java.util.Random`. It does not match the constructor on its own, `ThreadLocalRandom`, Kotlin's `Random`, or calls where the type cannot be inferred (fields declared as a supertype, obfuscated code). Treat it as a starting point.

3. **Widen the sweep** with our rule set:

   ```yaml
   rules:
     - id: gt-android-noncrypto-prng
       languages: [java]
       severity: WARNING
       message: Non-cryptographic PRNG - check whether the value is security-relevant
       pattern-either:
         - pattern: new java.util.Random(...)
         - pattern: Math.random()
         - pattern: java.util.concurrent.ThreadLocalRandom.current()
         - pattern: new java.util.SplittableRandom(...)
         - pattern: kotlin.random.Random.Default
         - pattern: kotlin.random.RandomKt.Random(...)
         - pattern: org.apache.commons.lang3.RandomStringUtils.$M(...)
     - id: gt-android-securerandom-misuse
       languages: [java]
       severity: WARNING
       message: SecureRandom seeded, or obtained with an explicit algorithm or provider
       pattern-either:
         - pattern: new java.security.SecureRandom($SEED)
         - pattern: (java.security.SecureRandom $SR).setSeed(...)
         - pattern: java.security.SecureRandom.getInstance(...)
         - pattern: java.security.SecureRandom.getInstanceStrong()
   ```

   ```bash
   semgrep -c gt-android-random.yml out/sources/
   ```

   And a grep pass that is robust to type-inference failures. It also catches Kotlin helpers, which jadx renders as calls into `CollectionsKt`, `RangesKt` or `StringsKt` with `Random.Default` as an argument:

   ```bash
   grep -rnE 'new Random\(|java\.util\.Random|Math\.random\(|ThreadLocalRandom|SplittableRandom|kotlin\.random|Random\.Default|RandomKt\.Random\(|RandomStringUtils|FixedSecureRandom' out/sources/ \
     | grep -vE '^out/sources/(androidx|kotlin|kotlinx|com/google/(android|common|protobuf))/'
   grep -rnE 'new SecureRandom\([^)]+\)|\.setSeed\(|SecureRandom\.getInstance(Strong)?\(' out/sources/ \
     | grep -vE '^out/sources/(androidx|kotlin|kotlinx)/'
   ```

4. **Check native code**, where `rand()`/`srand()` and C++ `<random>` engines appear in bundled libraries and game engines:

   ```bash
   unzip -o base.apk 'lib/*' -d native/
   for so in native/lib/arm64-v8a/*.so; do
     echo "== $so"
     nm -D --undefined-only "$so" 2>/dev/null | grep -wE 'rand|srand|random|srandom|drand48|lrand48|mrand48|srand48'
     nm -DC --defined-only "$so" 2>/dev/null | grep -E 'mersenne_twister_engine|linear_congruential_engine' | head -3
   done
   ```

   For a hit, open the library with `r2 -A libfoo.so` and run `axt @ sym.imp.rand` to find the calling functions.

5. **Triage every hit** by reviewing the decompiled code (MASTG-TECH-0023). In jadx-gui, right-click the method and choose *Find Usage* (shortcut `x`) to walk from the PRNG call to the sink. You are looking for the value reaching `SecretKeySpec`, `IvParameterSpec`, `GCMParameterSpec`, `PBEKeySpec` (as a salt), `KeyGenerator.init(…, random)`, `Signature.initSign(key, random)`, an HTTP request body or header (token, `state`, `code_verifier`, OTP), a preference that stores a credential, or a user-visible code.

#### Observation

A list of call sites: class, method and decompiled line, the API (`new Random()`, `Random(seed)` with the seed value, `Math.random()`, `Random.Default`, seeded `SecureRandom`), the variable it feeds, and the sink you traced it to. For seeded generators, record the seed and where it comes from (literal, time, device identifier).

#### Evaluation

The test **fails** if a value from a non-cryptographic PRNG, or from a deterministically seeded generator, is used in a security-relevant context: keys, IVs or nonces, salts, authentication or session tokens, OTPs, PINs, passwords, reset codes, PKCE verifiers, OAuth `state`/`nonce`, or any identifier whose possession grants access.

It **passes** for a call site if the value is used only for non-security purposes (UI, animation, gameplay, back-off jitter, sampling), and that generator instance is not shared with a security-relevant use. Watch `Math.random()` in particular here, because its instance is shared process-wide.

Treat these separately:

- `new SecureRandom()` and `SecureRandom.getInstance("SHA1PRNG")` with no seed on a current Android version are **not** findings.
- `SecureRandom` with a constant seed, or used as a password-to-key derivation, is a finding even though Conscrypt ignores the seed today. Rate it Low if the output is provably unaffected on all supported versions, and higher if the code also runs on a JVM or uses a provider that honours the seed. The KDF misuse itself belongs under [MASWE-0014](/mobile/maswe-0014-improper-key-derivation/).
- Common false positives: third-party SDK code that is never reached from the app, Kotlin/AndroidX internals, test helpers shipped in the APK but unreachable, and `Random` used to pick a server from a list.

#### Demo

From [MASTG-DEMO-0007](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0007/MASTG-DEMO-0007/), "Common Uses of Insecure Random APIs". The Kotlin sample:

```kotlin
// FAIL: authentication token from java.util.Random
val random1 = Random().nextDouble()

// FAIL: unclear use; trace callers
val random2 = 1 + Math.random()

// FAIL: password generated with java.util.Random
val characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
val random = Random()
val password = StringBuilder(16)
for (i in 0 until 16) {
    password.append(characters[random.nextInt(characters.length)])
}

// PASS: SecureRandom
val random4 = SecureRandom().nextInt(21)
```

The jadx output that the rule runs against:

```java
double random1 = new Random().nextDouble();
double random2 = 1 + Math.random();
Random random = new Random();
StringBuilder password = new StringBuilder(16);
for (int i = 0; i < 16; i++) {
    password.append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".charAt(random.nextInt("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".length())));
}
String random3 = password.toString();
int random4 = new SecureRandom().nextInt(21);
```

`semgrep -c ../../../../rules/mastg-android-random-apis-insufficient-entropy.yml ./MastgTest_reversed.java`:

```text
┌─────────────────┐
│ 3 Code Findings │
└─────────────────┘

    MastgTest_reversed.java
    ❯❱ rules.mastg-android-random-apis-insufficient-entropy
          [MASVS-CRYPTO-1] The application makes use of random number generators with insufficient entropy.

           22┆ double random1 = new Random().nextDouble();
            ⋮┆----------------------------------------
           23┆ double random2 = 1 + Math.random();
            ⋮┆----------------------------------------
           27┆ password.append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".charAt(ran
               dom.nextInt("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".length())));
```

The test fails. Line 22 produces an authentication token from `java.util.Random`, and line 27 generates a password with it. Line 23 (`Math.random()`) needs its callers traced before you can decide. `SecureRandom().nextInt(21)` is correctly not reported. If you reproduce the demo, note that the OWASP text says "five instances" while the output shows three, and that the line numbers refer to the reversed Java file, not the Kotlin source. Line 27 is exactly the pattern our [password PoC](#proving-predictability-in-a-report) breaks: from one generated password we recover the generator state and print the next password the app will produce.

### MASTG-TEST-0205: Non-random Sources Usage (Android)

Source: [MASTG-TEST-0205](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0205/). Type: static (code), manual review. Related knowledge: MASTG-KNOW-0013. Best practice: MASTG-BEST-0001.

#### Overview

The test looks for values that are meant to be unpredictable but are computed from something that is not random: in OWASP's examples, the current time via `Date().getTime()` and `Calendar.MILLISECOND`. We extend the source list to the monotonic clocks, device identifiers, `hashCode()` and name-based UUIDs (see the [table above](#both-platforms-non-random-sources-seeding-and-modulo-bias-supplementary)), and to PRNG seeds derived from these. A time-seeded `java.util.Random` is caught by both Android tests, and you should report it once.

#### Prerequisites

As for MASTG-TEST-0204: decompiled sources (`jadx`), `semgrep`/`grep`, and the security-relevant flows from your threat model.

#### Steps

1. **Decompile** as in TEST-0204 (MASTG-TECH-0013).

2. **Run the OWASP rule** (`mastg-android-non-random-use.yml`):

   ```yaml
   rules:
     - id: mastg-android-non-random-use
       severity: WARNING
       languages:
         - java
       message: "[MASVS-CRYPTO-1] The application makes use of non-random sources."
       pattern-either:
         - patterns:
             - pattern-inside: $M(...){ ... }
             - pattern-either:
                 - pattern: new Date()
                 - pattern: System.currentTimeMillis()
                 - pattern: (Calendar $C).get(...)
   ```

   ```bash
   semgrep -c mastg-android-non-random-use.yml out/sources/
   ```

   Expect a lot of noise. Every log timestamp, cache expiry and date picker matches. The rule tells you where time is read, not where it is misused.

3. **Search for the sources the rule misses** and for hashes and seeds built from them:

   ```bash
   grep -rnE 'System\.nanoTime\(|SystemClock\.(elapsedRealtime|uptimeMillis)|Instant\.now\(|Settings\.Secure\.ANDROID_ID|"android_id"|Build\.SERIAL|getSerial\(|getImei\(|getDeviceId\(|nameUUIDFromBytes|identityHashCode' out/sources/ \
     | grep -vE '^out/sources/(androidx|kotlin|kotlinx|com/google/(android|common))/'
   grep -rnE 'new Random\((System\.(currentTimeMillis|nanoTime)|new Date|.*hashCode)' out/sources/
   ```

4. **Trace each candidate to its sink** (MASTG-TECH-0023). The dangerous shapes are a time or identifier value reaching a token, a key or IV, a salt, a file name that acts as a capability, or a seed. Look for intermediate hashing: `MessageDigest.getInstance("MD5").digest((androidId + System.currentTimeMillis()).toByteArray())` is a non-random source even though the output looks random.

5. **Optional runtime check.** Hook the sink rather than the source (time is read constantly). For example, hook `IvParameterSpec.$init` or the token-building method you identified and run the flow twice in quick succession. Values that differ only in a few low-order digits, or that track the clock, confirm the finding.

#### Observation

For each candidate: the source (time API, identifier, hash), the transformation applied (truncation, hash, concatenation), the sink, and an estimate of the attacker's search space: for example, "milliseconds within the minute before the reset request was sent: 60,000 candidates".

#### Evaluation

The test **fails** if a security-relevant value (token, password, PIN, OTP, key, IV, nonce, salt, session identifier, seed for any of these) is derived from a non-random source, with or without hashing. It **passes** if time and identifiers are used only as what they are: timestamps, expiry checks, non-secret identifiers or log fields.

Precise boundaries:

- A timestamp *included alongside* a CSPRNG value (for example in a signed token's `iat` claim) is fine. A timestamp *instead of* one is not.
- A device identifier used to *identify* a device to the server is not this weakness (it may be a privacy matter). The same identifier used as a key, password or secret is.
- `UUID.randomUUID()` is a CSPRNG source and passes. `UUID.nameUUIDFromBytes` does not.

#### Demo

From [MASTG-DEMO-0008](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0008/MASTG-DEMO-0008/), "Uses of Non-random Sources":

```kotlin
// FAIL: Date().time used for an authentication token
val random1 = Date().time.toInt()

// FAIL: Calendar millisecond field used for an authentication token
val c = Calendar.getInstance()
val random2 = c.get(Calendar.MILLISECOND)
```

jadx renders `Calendar.MILLISECOND` as its constant value, `14`. That is one reason the OWASP rule matches any `Calendar.get(...)` rather than the field name:

```java
int random1 = (int) new Date().getTime();
Calendar c = Calendar.getInstance();
int random2 = c.get(14);
```

```text
┌─────────────────┐
│ 2 Code Findings │
└─────────────────┘

    MastgTest_reversed.java
    ❯❱ rules.mastg-android-non-random-use
          [MASVS-CRYPTO-1] The application makes use of non-random sources.

           22┆ int random1 = (int) new Date().getTime();
            ⋮┆----------------------------------------
           24┆ int random2 = c.get(14);
```

The test fails on both lines. `random1` is the low 32 bits of the epoch milliseconds. Anyone who knows the time to within a second has 1,000 candidates. `random2` has at most 1,000 possible values whatever the attacker knows. The demo is a good reminder for jadx triage: `Calendar.get(1)` is `YEAR`, `get(13)` is `SECOND`, and `get(14)` is `MILLISECOND`.

### MASTG-TEST-0311: Insecure Random API Usage (iOS)

Source: [MASTG-TEST-0311](https://mas.owasp.org/MASTG/tests/ios/MASVS-CRYPTO/MASTG-TEST-0311/). Type: static (code), manual review. Related knowledge: MASTG-KNOW-0070. Best practice: MASTG-BEST-0025. Supersedes the legacy (MASTG v1) test MASTG-TEST-0063 "Testing Random Number Generation".

#### Overview

The test finds calls to the libc PRNGs (`rand`, `random`, and the `*rand48` family) in the app's binaries and decides whether their output is security-relevant. OWASP's demo searches imports for anything containing `rand`, which also returns the secure APIs (`arc4random*`, `SecRandomCopyBytes`, `CCRandomGenerateBytes`, Swift `random`). Those appear for contrast, and you should not report them. We add custom `RandomNumberGenerator` conformances and GameplayKit, which the import search cannot classify on its own.

#### Prerequisites

- A **decrypted** IPA. App Store binaries are FairPlay-encrypted. Check with `otool -l Payload/App.app/App | grep -A4 LC_ENCRYPTION_INFO`: `cryptid 1` means you must dump it from a jailbroken device first. Development, ad hoc and enterprise builds usually arrive unencrypted.
- radare2 (MASTG-TOOL-0073), `jq`, and on macOS `nm`, `otool` and `xcrun swift-demangle`.

#### Steps

1. **Extract the binaries** (MASTG-TECH-0058, exploring the app package):

   ```bash
   unzip -q App.ipa -d ipa/
   BIN=ipa/Payload/App.app/App
   ls ipa/Payload/App.app/Frameworks/   # each embedded framework and dylib gets the same treatment
   ```

2. **Quick import check** for the insecure functions and for GameplayKit:

   ```bash
   nm -u "$BIN" | grep -E '^ *_(rand|srand|rand_r|random|srandom|[delmnj]rand48|srand48|seed48|lcong48)$'
   otool -L "$BIN" | grep -i GameplayKit
   ```

   The anchored regex matters. A plain `grep rand` also returns `_arc4random`, `_SecRandomCopyBytes` and dozens of unrelated symbols.

3. **List call sites with radare2** (MASTG-TECH-0066, static analysis on iOS). OWASP's script, `insecure_random.r2`, is a single line:

   ```text
   axtj @@=`ii~+rand[1]`
   ```

   `ii` lists imports, `~+rand` filters them case-insensitively for `rand`, `[1]` keeps the address column, and `axtj @@=…` prints the cross-references to each address as JSON. Run it and keep only the insecure functions:

   ```bash
   r2 -q -i insecure_random.r2 -A "$BIN" > output.json
   jq -s 'add | map(select(.refname | test("^sym[.]imp[.](rand|srand|rand_r|random|srandom|[delmnj]rand48|srand48|seed48|lcong48)$")))' \
     output.json > evaluation.json
   ```

   OWASP's own filter is `test("^sym[.]imp[.](rand|srand|drand48)")`. It has no end anchor, so it would also match a symbol such as `randomize`. Ours adds the rest of the family and anchors both ends.

4. **Look for custom generators and GameplayKit use**, which never show up as libc imports:

   ```bash
   nm "$BIN" | xcrun swift-demangle | grep -E 'conformance descriptor for .* : Swift\.RandomNumberGenerator'
   nm "$BIN" | xcrun swift-demangle | grep -E 'random\(in: .*using:|shuffled\(using:|randomElement\(using:' | sort -u | head
   nm -u "$BIN" | grep -E 'OBJC_CLASS_\$_GK(ARC4|LinearCongruential|MersenneTwister)RandomSource|OBJC_CLASS_\$_GK(Random|Gaussian|Shuffled)Distribution'
   ```

   A conformance to `RandomNumberGenerator` defined in the app (not in the Swift runtime) means someone wrote a generator. Find its `next()` implementation and check whether it wraps `SystemRandomNumberGenerator`/`SecRandomCopyBytes` or implements an algorithm such as SplitMix64 or xorshift with a stored seed.

5. **Confirm security relevance** by reviewing the disassembly of each calling function (MASTG-TECH-0076):

   ```text
   r2 -A ipa/Payload/App.app/App
   [0x...]> pdf @ sym.MASTestApp.MastgTest.generateRandomTokenDrand48_...yFZ_
   [0x...]> axt @ sym.MASTestApp.MastgTest.generateRandomTokenDrand48_...yFZ_
   [0x...]> pdf @ <caller>
   ```

   Iterate up the call chain until you reach a sink you can name: a Keychain write, a request builder, `CCCrypt`, a CryptoKit call, a UI label showing a code. For `srand`/`srandom`/`srand48` call sites, find the seed argument (`w0`/`x0` just before the `bl`). A `bl sym.imp.time` feeding it is the classic time seed. A `mov w0, #imm` is a hardcoded one.

#### Observation

A list of insecure-PRNG call sites with the function name and address, the API, the seed (if a seeding call exists) and its origin, and the sink the output reaches. Add any custom `RandomNumberGenerator` types or GameplayKit sources, with the place they are used.

#### Evaluation

The test **fails** if output from `rand`, `random`, the `*rand48` family, a deterministic custom generator or a GameplayKit source is used in a security-relevant context: keys, IVs, nonces, tokens, session identifiers, passwords, PINs, OTPs, PKCE verifiers.

It **passes** for uses unrelated to security, which OWASP lists explicitly: random delays, non-security identifiers, game mechanics. It also passes for the secure APIs the import search returns: `arc4random`, `arc4random_buf`, `arc4random_uniform`, `SecRandomCopyBytes`, `CCRandomGenerateBytes`, `SystemRandomNumberGenerator` and Swift's `FixedWidthInteger.random`. If `arc4random() % n` is used for a code with *n* not a power of two, note the modulo bias as a separate Low finding. It does not fail this test.

#### Demo

From [MASTG-DEMO-0073](https://mas.owasp.org/MASTG/demos/ios/MASVS-CRYPTO/MASTG-DEMO-0073/MASTG-DEMO-0073/), "Uses of Insecure Random Number Generation with r2". The sample builds a 16-byte hex token in nine ways. The insecure ones:

```swift
// Unsafe bindings to libc srand and rand (not callable from Swift otherwise)
@_silgen_name("srand") func c_srand(_ seed: UInt32)
@_silgen_name("rand")  func c_rand() -> Int32

static func generateRandomTokenRand() -> String {
    var token = ""
    for _ in 0..<16 { token += String(format: "%02x", c_rand() % 256) }
    return token
}

static func generateRandomTokenDrand48() -> String {
    var token = ""
    for _ in 0..<16 { token += String(format: "%02x", Int(drand48() * 256.0) % 256) }
    return token
}

// in mastgTest(): seed libc rand with the current time
c_srand(UInt32(time(nil)))
```

…alongside secure versions using `UInt8.random(in:)`, `/dev/random`, `arc4random_uniform`, `arc4random`, `SystemRandomNumberGenerator`, `CCRandomGenerateBytes` and the recommended `SecRandomCopyBytes`.

The r2 script returns cross-references for all of them. After filtering, `evaluation.json` holds the three insecure call sites:

```json
[
  { "from": 12444, "opcode": "bl sym.imp.drand48",
    "fcn_name": "sym.MASTestApp.MastgTest.generateRandomTokenDrand48_...yFZ_", "refname": "sym.imp.drand48" },
  { "from": 5228, "opcode": "bl sym.imp.rand",
    "fcn_name": "sym.MASTestApp.MastgTest.generateRandomTokenRand_...yFZ_", "refname": "sym.imp.rand" },
  { "from": 16004, "opcode": "bl sym.imp.srand",
    "fcn_name": "sym.MASTestApp.MastgTest.mastg.completion_...FZ_", "refname": "sym.imp.srand" }
]
```

The test fails. `rand` is seeded with `time(nil)` in `mastgTest`, so the token is a function of the second it was generated. `drand48` is never seeded at all (the sample's `srand48(time(nil))` is commented out), so its token is the same on every launch. In the unfiltered output you will also see `bl sym.imp.arc4random`, `arc4random_uniform`, `SecRandomCopyBytes`, `CCRandomGenerateBytes` and the Swift `FixedWidthInteger.random` and `SystemRandomNumberGenerator` stubs. Those are the secure contrasts and are not findings. In OWASP's published `output.json` some function names (`generateInsecureRandomTokenArc4…`) differ from the Swift source, apparently from an earlier build of the sample. The addresses and imports are what matter.

### MASTG-TEST-0349: Runtime Use of Insecure Random APIs (iOS)

Source: [MASTG-TEST-0349](https://mas.owasp.org/MASTG/tests/ios/MASVS-CRYPTO/MASTG-TEST-0349/). Type: dynamic (hooks), manual review. Related knowledge: MASTG-KNOW-0070. Best practice: MASTG-BEST-0025.

#### Overview

The dynamic counterpart of TEST-0311. Hook the insecure libc PRNGs in the running app, exercise every flow, and collect calls with backtraces. Runtime evidence catches PRNG use in frameworks you did not statically analyse and code paths that are hard to follow in disassembly. It also gives you the actual seeds and outputs, which you need to prove predictability. The limitation is coverage: a flow you do not trigger produces no output.

#### Prerequisites

- The app installed on a device (MASTG-TECH-0056, installing apps): on a jailbroken device, or a re-signed IPA with the Frida Gadget for non-jailbroken testing.
- Frida (MASTG-TOOL-0039) on the host, matching `frida-server` (or Gadget) on the device. Check with `frida-ps -Uai`.
- A test account and the list of flows to exercise: registration, login, MFA enrolment, password reset, device pairing, anything that encrypts.

#### Steps

1. **Install and identify the app** (MASTG-TECH-0056):

   ```bash
   frida-ps -Uai | grep -i example      # note the bundle ID and process name
   ```

2. **Trace the relevant APIs** (MASTG-TECH-0095, method hooking). OWASP's demo uses `frida-trace`, including the secure APIs for contrast:

   ```bash
   frida-trace -U -f com.example.app \
     -i "*FixedWidthInteger*random*" -i "*rand" -i "*rand48" -i "arc4random*" \
     -i "*SystemRandomNumberGenerator*" -i "CCRandom*" -i "SecRandomCopyBytes"
   ```

   (`-U` selects the USB device. The OWASP `run.sh` attaches by name with `-n 'MASTestApp'`.) `frida-trace` writes one handler per function under `__handlers__/`. Edit the `onLeave` of `rand.js`, `random.js` and friends to log `retval`, so you capture outputs as well as calls.

3. **For evidence, use a targeted script** that logs seeds, return values and one backtrace per call site:

   ```javascript
   // hook-ios-prng.js (Frida 17 syntax)
   const seeders = ['srand', 'srandom', 'srand48', 'seed48', 'lcong48'];
   const generators = ['rand', 'rand_r', 'random', 'drand48', 'erand48', 'lrand48', 'nrand48', 'mrand48', 'jrand48'];
   const seenCallers = new Set();

   function caller(ctx, ret) {
     const key = DebugSymbol.fromAddress(ret).toString();
     if (seenCallers.has(key)) return null;
     seenCallers.add(key);
     return Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, 8).map(DebugSymbol.fromAddress).join('\n    ');
   }

   for (const name of seeders.concat(generators)) {
     const addr = Module.findGlobalExportByName(name);
     if (addr === null) continue;
     Interceptor.attach(addr, {
       onEnter(args) {
         if (name === 'srand' || name === 'srandom') {
           const seed = args[0].toUInt32();
           const now = Math.floor(Date.now() / 1000);
           console.log(`[${name}] seed=${seed} (0x${seed.toString(16)})  host time=${now}  delta=${now - seed}s`);
         } else if (name === 'srand48') {
           console.log(`[srand48] seed=${args[0].toString()}`);
         } else if (seeders.includes(name)) {
           console.log(`[${name}] called`);
         }
         const bt = caller(this.context, this.returnAddress);
         if (bt) console.log(`[${name}] first call from:\n    ${bt}`);
       },
       onLeave(retval) {
         if (name === 'rand' || name === 'random' || name === 'lrand48' || name === 'mrand48')
           console.log(`[${name}] -> ${retval.toInt32()}`);
       }
     });
   }

   // GameplayKit sources: log seeds when they are created explicitly
   if (ObjC.available) {
     for (const cls of ['GKMersenneTwisterRandomSource', 'GKLinearCongruentialRandomSource']) {
       const c = ObjC.classes[cls];
       if (!c) continue;
       Interceptor.attach(c['- initWithSeed:'].implementation, {
         onEnter(args) { console.log(`[${cls} initWithSeed:] ${args[2].toString()}`); }
       });
     }
     const arc4 = ObjC.classes.GKARC4RandomSource;
     if (arc4) {
       Interceptor.attach(arc4['- initWithSeed:'].implementation, {
         onEnter(args) { console.log(`[GKARC4RandomSource initWithSeed:] ${new ObjC.Object(args[2]).toString()}`); }
       });
     }
   }
   ```

   ```bash
   frida -U -f com.example.app -l hook-ios-prng.js
   ```

   `drand48` returns a `double` in register `d0`, not `x0`, so the script logs the call and caller rather than a meaningless `retval`. Compare `delta` to the clock offset between host and device (check with `ideviceinfo -k TimeIntervalSince1970` if you have libimobiledevice). A delta of a few seconds means `srand(time(nil))`.

4. **Exercise the app** extensively. Go through every flow on your list, enter data wherever you can, and repeat security-relevant flows twice. Then kill and relaunch the app and repeat once more: identical outputs across launches mean a fixed seed or an unseeded `drand48`.

5. **Map backtraces to code** (MASTG-TECH-0076). Open the binary in r2 at the reported caller (`pdf @ <symbol>`) and confirm what the value is used for, exactly as in TEST-0311 step 5.

#### Observation

Runtime calls to insecure PRNGs with function names, seeds (and their relation to the clock), sample return values, and a backtrace per call site, linked to the user action that triggered them.

#### Evaluation

The test **fails** if random values produced by insecure APIs at runtime are used in a security-relevant context, confirmed through the backtrace and code review. It passes if the only insecure-PRNG calls come from non-security code. Hits from system frameworks such as UIKit animations or audio, which you can see in the backtrace, are not app findings. The secure APIs in the trace (`arc4random*`, `SecRandomCopyBytes`, `CCRandomGenerateBytes`, `SystemRandomNumberGenerator`) are not findings.

#### Demo

From [MASTG-DEMO-0074](https://mas.owasp.org/MASTG/demos/ios/MASVS-CRYPTO/MASTG-DEMO-0074/MASTG-DEMO-0074/), which runs the same sample as DEMO-0073 under the `frida-trace` command above and presses the app's **Start** button:

```text
  2959 ms  srand(seed=0x691a0327)
  2959 ms  rand()
           ... x 16
  2959 ms  $ss17FixedWidthIntegerPsE6random2inxSNyxG_tFZ()
  2959 ms     | arc4random_buf(buf=0x16ef965a8, nbytes=0x8)
           ... x 16
  2959 ms  open(path="/dev/random", oflag=0x0, ...)
  2960 ms  arc4random_uniform(upper_bound=0x100)
           ... x 16
  2960 ms  arc4random()
           ... x 16
  2960 ms  $ss27SystemRandomNumberGeneratorVABycfC()
  2960 ms  $ss17FixedWidthIntegerPsE6random2in5usingxSNyxG_qd__ztSGRd__lFZ()
  2960 ms     | $ss17FixedWidthIntegerPsE7_random5usingxqd__z_tSGRd__lFZ()
  2960 ms     |    | arc4random_buf(buf=0x16ef964d8, nbytes=0x8)
           ... x 16
  2960 ms  drand48()
           ... x 16
  2960 ms  CCRandomGenerateBytes()
  2960 ms  SecRandomCopyBytes()
  2960 ms     | CCRandomCopyBytes()
  2960 ms     |    | CCRandomGenerateBytes()
```

The test fails on `srand`/`rand` and `drand48`. The trace makes the predictability concrete: `seed=0x691a0327` is the Unix timestamp 1763312423, the second the button was pressed. Anyone who can bracket that moment regenerates the token by calling `srand(t); rand()…` for each candidate `t`. The rest of the trace documents the secure paths. Swift's `UInt8.random(in:)` and `SystemRandomNumberGenerator` both end in `arc4random_buf`, and `SecRandomCopyBytes` wraps `CCRandomCopyBytes` → `CCRandomGenerateBytes`. That is useful when a developer asks you whether their Swift `random` call is safe.

### Supplementary checks (not OWASP tests)

Our methodology. These close the gaps the four OWASP tests leave: there is no Android dynamic test, and seeded `SecureRandom`, Kotlin, custom Swift generators and cross-platform frameworks are outside the OWASP rules.

#### Android: runtime confirmation of PRNG use

Overview: hook the non-cryptographic generators and `SecureRandom`'s seeding paths, run the security-relevant flows, and collect values with stack traces. This is the Android equivalent of TEST-0349, built on OWASP's Android method-hooking technique (MASTG-TECH-0043) with Frida (MASTG-TOOL-0001).

Prerequisites: a rooted device or emulator with `frida-server`, or a Gadget-injected APK. You also need the flows from your threat model.

Steps:

```javascript
// hook-android-prng.js
Java.perform(() => {
  const Log = Java.use('android.util.Log');
  const Exception = Java.use('java.lang.Exception');
  const seen = new Set();

  function stack() {
    return Log.getStackTraceString(Exception.$new()).split('\n').slice(2, 9).join('\n');
  }
  function report(tag, detail) {
    const st = stack();
    const where = st.split('\n')[0];
    console.log(`[${tag}] ${detail}  @ ${where.trim()}`);
    if (!seen.has(tag + where)) { seen.add(tag + where); console.log(st); }
  }
  const isSecure = (obj) => obj.$className.indexOf('SecureRandom') !== -1;

  // java.util.Random construction: log the seed (SecureRandom's super(0) call is skipped)
  const Random = Java.use('java.util.Random');
  Random.$init.overload('long').implementation = function (seed) {
    this.$init(seed);
    if (!isSecure(this)) report('Random.<init>', `class=${this.$className} seed=${seed}`);
  };
  Random.setSeed.implementation = function (seed) {
    this.setSeed(seed);
    if (!isSecure(this) && seed != 0) report('Random.setSeed', `seed=${seed}`);
  };
  for (const m of ['nextInt', 'nextLong', 'nextDouble']) {
    Random[m].overloads.forEach((ov) => {
      ov.implementation = function () {
        const r = ov.apply(this, arguments);
        if (!isSecure(this)) report(`Random.${m}`, `-> ${r}`);
        return r;
      };
    });
  }
  Java.use('java.lang.Math').random.implementation = function () {
    const r = this.random();
    report('Math.random', `-> ${r}`);
    return r;
  };
  try {
    Java.use('java.util.concurrent.ThreadLocalRandom').current.implementation = function () {
      report('ThreadLocalRandom.current', '');
      return this.current();
    };
  } catch (e) {}
  try {
    Java.use('kotlin.random.XorWowRandom').$init.overloads.forEach((ov) => {
      ov.implementation = function () {
        report('kotlin XorWowRandom.<init>', `args=${Array.from(arguments).join(',')}`);
        return ov.apply(this, arguments);
      };
    });
  } catch (e) { console.log('kotlin.random not found under its original name (minified?)'); }

  // SecureRandom: explicit seeds, explicit algorithms/providers
  const SR = Java.use('java.security.SecureRandom');
  SR.$init.overload('[B').implementation = function (seed) {
    report('SecureRandom(byte[])', `seedLen=${seed.length}`);
    return this.$init(seed);
  };
  SR.setSeed.overload('[B').implementation = function (seed) {
    report('SecureRandom.setSeed([B)', `seedLen=${seed.length}`);
    return this.setSeed(seed);
  };
  SR.setSeed.overload('long').implementation = function (seed) {
    if (seed != 0) report('SecureRandom.setSeed(long)', `seed=${seed}`);  // 0 comes from Random's constructor
    return this.setSeed(seed);
  };
  SR.getInstance.overloads.forEach((ov) => {
    ov.implementation = function () {
      const r = ov.apply(this, arguments);
      report('SecureRandom.getInstance', `alg=${arguments[0]} -> provider=${r.getProvider().getName()}`);
      return r;
    };
  });
});
```

```bash
frida -U -f com.example.app -l hook-android-prng.js
```

Two implementation details matter. `SecureRandom` extends `java.util.Random`, so its constructor runs `Random(long)` with seed `0` and calls `setSeed(0)`. Without the filters above, every `SecureRandom` would show up as a seeded `Random`. Second, Kotlin's `Random.Default` on Android below API 34 is a thread-local `java.util.Random`, so its calls appear as `Random.nextInt` with a Kotlin frame in the stack.

Observation: the seed values (does `Random.<init>` show the same constant on every launch?), sample outputs, and the first stack trace per call site. Clear data with `adb shell pm clear com.example.app` and repeat once. Identical seeds or outputs across fresh starts prove a fixed seed.

Evaluation: as for MASTG-TEST-0204. A non-crypto generator on a security-relevant path fails. So does a constant seed reaching any generator used for secrets. `SecureRandom.getInstance` returning `AndroidOpenSSL` with no seed passes.

#### Cross-platform frameworks

Overview: Flutter, React Native, .NET MAUI and Unity apps generate randomness in the framework runtime, so the native-API tests above may see nothing.

Steps:

```bash
# Flutter: Dart code is AOT-compiled into libapp.so (Android) / App.framework/App (iOS); look for the APIs by name
strings -a libapp.so | grep -E 'Random\.secure|dart:math' | head
# React Native: the JS bundle (or Hermes bytecode after hermes-dec/hbctool disassembly)
grep -oE 'Math\.random\(\)|crypto\.getRandomValues|react-native-get-random-values|uuid\.v4|nanoid' \
  assets/index.android.bundle | sort | uniq -c
# Unity / .NET: managed assemblies (Mono) or IL2CPP metadata
strings -a global-metadata.dat | grep -E 'System\.Random|RandomNumberGenerator|UnityEngine\.Random' | sort -u
```

Evaluation: Dart `Random()` (without `.secure()`), JavaScript `Math.random()`, .NET `System.Random` and `UnityEngine.Random` fail on a security-relevant path. Dart `Random.secure()`, `crypto.getRandomValues` (polyfilled by `react-native-get-random-values`, which calls `SecRandomCopyBytes` on iOS and `SecureRandom` on Android) and .NET `RandomNumberGenerator` pass. JavaScript `uuid` v4 and `nanoid` are only as good as the `getRandomValues` polyfill behind them: confirm it is installed and imported before the library.

#### iOS: SecRandomCopyBytes result handling

A low-severity robustness check. `SecRandomCopyBytes` returns an `OSStatus`. Code that ignores it, for example `_ = SecRandomCopyBytes(…)`, or has no comparison to `errSecSuccess` near the call, would use an all-zero buffer if the call ever failed. Failure is extremely rare, so this is a Low or Info code-quality finding, but it is cheap to spot during the TEST-0311 disassembly review: look for the return value in `w0` being discarded after `bl sym.imp.SecRandomCopyBytes`.

### Proving predictability in a report

"Uses `java.util.Random`" plus a code path to a token is a valid finding. A demonstration of predictability is what moves it from "theoretical" to "fix this sprint", and on a disputed report it ends the argument. Pick the cheapest proof that fits the case.

**1. Fixed seed: show determinism.** Run the flow on two fresh installs, or two devices, and show the identical value, either from the app's own output or from the Frida log (`Random.<init> seed=42`). Include the seed's location in jadx (class, method, line) or in r2 (`mov w0, #0x2a` before `bl sym.imp.srand`). This is the strongest and simplest proof, and it also shows the value is the same for every user.

**2. Time seed: regenerate offline.** Bracket the generation time (request timestamp in the proxy, `Date` header, log line), then enumerate. For libc `rand` on Darwin, a host-side C loop is enough, because the macOS libc has the same `rand`/`srand` implementation the device uses (confirm against one captured value):

```objectivec
// regen.c: find the srand(time) seed that produced an observed token
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {          // ./regen <token-hex> <unix-time-guess>
    const char *want = argv[1];
    long guess = strtol(argv[2], NULL, 10);
    char got[33];
    for (long t = guess - 3600; t <= guess + 3600; t++) {
        srand((unsigned)t);
        for (int i = 0; i < 16; i++) sprintf(got + 2 * i, "%02x", rand() % 256);
        if (strcmp(got, want) == 0) { printf("seed = %ld\n", t); return 0; }
    }
    puts("not found in window");
    return 1;
}
```

For Java time seeds (`Random(System.currentTimeMillis())`), do the same in Java over a millisecond window: `new Random(t)` for each candidate `t`. One hour is 3.6 million candidates, which takes seconds.

**3. Unseeded LCG: recover the state from outputs.** This is the case developers dispute ("it's seeded from nanoTime, you can't guess that"). You do not need the seed. The outputs reveal the state. Three PoCs we use, all verified against Java 19 and compatible with Android's libcore, because the algorithm is fixed by the specification:

*Two `nextInt()` values → all future values.* The first output is the top 32 bits of the state, so 2^16 candidates remain:

```java
import java.util.Random;

public class PredictRandom {
    static final long MULT = 0x5DEECE66DL, ADD = 0xBL, MASK = (1L << 48) - 1;
    static long step(long s) { return (s * MULT + ADD) & MASK; }

    // Recover the state after two consecutive nextInt() outputs
    static long recover(int first, int second) {
        long upper = ((long) first & 0xFFFFFFFFL) << 16;
        for (long low = 0; low < (1 << 16); low++) {
            long next = step(upper | low);
            if ((int) (next >>> 16) == second) return next;
        }
        throw new IllegalStateException("no candidate");
    }

    public static void main(String[] a) {
        Random victim = new Random();                       // unknown seed
        long s = recover(victim.nextInt(), victim.nextInt()); // two observed values
        for (int i = 0; i < 3; i++) {
            s = step(s);
            System.out.printf("predicted %11d  actual %11d%n", (int) (s >>> 16), victim.nextInt());
        }
    }
}
```

```text
predicted  1572502194  actual  1572502194
predicted -1029516057  actual -1029516057
predicted   561443558  actual   561443558
```

*One `Math.random()` value → all future `Math.random()` values.* One double carries 26 bits of one state and 27 bits of the next, so 2^22 candidates remain:

```java
static long recoverFromDouble(double observed) {
    long bits = (long) (observed * (1L << 53));
    long hi26 = bits >>> 27, lo27 = bits & ((1L << 27) - 1);
    for (long low = 0; low < (1L << 22); low++) {
        long s2 = step((hi26 << 22) | low);
        if ((s2 >>> 21) == lo27) return s2;                 // state after the observed double
    }
    throw new IllegalStateException();
}
// next value: s = step(s); a = s >>> 22; s = step(s); b = s >>> 21; ((a << 27) + b) * 0x1.0p-53
```

*One generated password → the next password.* This is the MASTG-DEMO-0007 pattern: 16 characters from `random.nextInt(62)`. Each character reveals only about six bits, but two LCG properties make this fast. The low 18 bits of the state evolve independently of the rest, and because 62 is even, each character's index parity equals bit 17 of the state. So you solve the low 18 bits from the parities (2^18 work), then brute-force the upper 30 bits (2^30 work) against the full characters:

```java
// idx[i] = alphabet.indexOf(password.charAt(i)) for the observed password
for (long low = 0; low < (1 << 18); low++) {
    long s = low; boolean ok = true;
    for (int i = 0; i < 16 && ok; i++) {
        s = (s * MULT + ADD) & ((1 << 18) - 1);
        ok = ((s >>> 17) & 1) == (idx[i] & 1);
    }
    if (!ok) continue;
    for (long hi = 0; hi < (1L << 30); hi++) {
        long st = (hi << 18) | low; boolean m = true;
        for (int i = 0; i < 16 && m; i++) {
            st = (st * MULT + ADD) & MASK;
            m = ((int) (st >>> 17)) % 62 == idx[i];
        }
        if (m) { /* (hi << 18) | low is the state before the first character: replay to predict */ }
    }
}
```

```text
observed password: 6wWgaz17a9u0fYku
state before first char: c7968e618ecc  (5.4 s)
predicted next: WdOf5puXYPkkMcaT
actual next:    WdOf5puXYPkkMcaT
```

Single-threaded on a laptop, about five seconds. In the report, the before-and-after pair of passwords is the evidence.

*Keys from `java.util.Random.nextBytes`.* The key space is at most 2^48, whatever the key length. You rarely need to run that search to make the point. State it, with the arithmetic, and offer the demonstration if challenged.

**4. libc `drand48` without a seed.** Show the same token on two launches and two devices, and quote the POSIX default state. We reproduced the OWASP demo's token loop with the macOS libc and got `65d75a7251e203952862b00fe6292888` on every run.

**What not to rely on.** Burp Sequencer and similar statistical tests (FIPS 140-2 batteries, NIST SP 800-22) measure distribution, not unpredictability. They will flag a raw timestamp or a counter, and that is a useful screen for *server-issued* tokens. A `java.util.Random` or `drand48` output passes them comfortably, so a good Sequencer score never clears a finding found in code. And where the token is minted by the backend, its generator is a server-side issue. Report it as such, outside the mobile weakness.

## Best practices

### MASTG-BEST-0001: Use Secure Random Number Generator APIs (Android)

Source: [MASTG-BEST-0001](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0001/). Platform: Android. Knowledge: MASTG-KNOW-0013.

OWASP's guidance, in short: use `java.security.SecureRandom` with the **default constructor**. It meets the statistical tests of FIPS 140-2 §4.9.1 and the strength requirements of RFC 4086, and it seeds itself from system entropy. Do not supply a seed. Android's documentation discourages it because it risks deterministic output. The `setSeed` documentation says a seed supplements rather than replaces existing entropy, but that guarantee depends on the provider, and the old `Crypto` provider broke it. So target a modern Android version and leave the provider to the platform (AndroidOpenSSL/Conscrypt). For other languages and frameworks, use the API that exposes the OS CSPRNG, and check it has no known weaknesses. OWASP cites a Zellic write-up on Dart/Flutter as a reminder that framework generators need checking.

What that looks like in Kotlin:

```kotlin
import android.util.Base64
import java.security.SecureRandom
import kotlin.random.asKotlinRandom

object Rng {
    // One shared instance is fine: SecureRandom is thread-safe. No seed, no algorithm, no provider.
    private val secure = SecureRandom()
    val kotlinRandom = secure.asKotlinRandom()   // for shuffled(), random(), Random-taking APIs

    fun bytes(n: Int): ByteArray = ByteArray(n).also { secure.nextBytes(it) }

    // 256-bit URL-safe token: share links, client nonces, PKCE code_verifier (43 chars)
    fun token(): String =
        Base64.encodeToString(bytes(32), Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    // Uniform n-digit code: nextInt(bound) rejection-samples, so no modulo bias
    fun numericCode(digits: Int = 6): String {
        var bound = 1
        repeat(digits) { bound *= 10 }
        return secure.nextInt(bound).toString().padStart(digits, '0')
    }

    // Unambiguous alphabet, uniform selection
    private const val ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    fun password(length: Int = 20): String =
        buildString(length) { repeat(length) { append(ALPHABET[secure.nextInt(ALPHABET.length)]) } }
}

// Kotlin helpers default to Random.Default; pass the secure generator explicitly
val pinPadOrder = (0..9).shuffled(Rng.kotlinRandom)
```

And the things not to write:

```kotlin
val bad1 = Random().nextInt(1_000_000)               // java.util.Random: 48-bit, predictable
val bad2 = (1..6).map { ('0'..'9').random() }        // Random.Default: not a CSPRNG
val bad3 = SecureRandom("seed".toByteArray())        // seeded: deterministic intent, provider-dependent
val bad4 = SecureRandom.getInstance("SHA1PRNG", "Crypto")  // provider removed in Android 9
```

Better than generating randomness yourself:

- **Keys**: generate them in the Android Keystore (`KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")`). The key is created from the secure hardware's RNG and never enters the app. See [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/) and [MASWE-0013](/mobile/maswe-0013-improper-key-generation/).
- **IVs**: with a Keystore AES-GCM key and randomised encryption required (the default), do not supply an IV. Call `cipher.init(Cipher.ENCRYPT_MODE, key)` and read `cipher.iv` afterwards. For software keys, use 12 bytes from `SecureRandom` per message.
- **Tokens and codes the server trusts**: mint them on the server.
- **Cross-platform**: Flutter `Random.secure()`; React Native `crypto.getRandomValues` via `react-native-get-random-values`, imported before any library that needs it.

### MASTG-BEST-0025: Use Secure Random Number Generator APIs (iOS)

Source: [MASTG-BEST-0025](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0025/). Platform: iOS. Knowledge: MASTG-KNOW-0070.

OWASP's guidance: use APIs backed by the OS CSPRNG and never build your own PRNG. In order of preference: `SecRandomCopyBytes` (Security framework); `CCRandomCopyBytes`/`CCRandomGenerateBytes` (CommonCrypto, secure but lower level and not documented on Apple's developer site); the Swift standard library `random` APIs with the default `SystemRandomNumberGenerator` (make sure no custom generator is passed); and CryptoKit, which has no raw-bytes API but generates keys (`SymmetricKey`) and nonces (`AES.GCM.Nonce`) from the system CSPRNG for you. For hybrid apps: Flutter/Dart `Random.secure()`, which reaches `SecRandomCopyBytes` through Dart's platform layer, and in React Native a library such as `react-native-get-random-values` or `react-native-securerandom`, both of which call `SecRandomCopyBytes`.

Swift:

```swift
import Foundation
import Security
import CryptoKit

enum RandomError: Error { case failed(OSStatus) }

func secureRandomBytes(_ count: Int) throws -> Data {
    var bytes = [UInt8](repeating: 0, count: count)
    let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
    guard status == errSecSuccess else { throw RandomError.failed(status) }   // fail closed
    return Data(bytes)
}

// 256-bit URL-safe token (PKCE code_verifier, share links, client nonces)
func secureToken() throws -> String {
    try secureRandomBytes(32).base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

// Uniform 6-digit code: Int.random(in:) uses SystemRandomNumberGenerator and is unbiased
func numericCode() -> String {
    String(format: "%06d", Int.random(in: 0..<1_000_000))
}

// Let CryptoKit generate keys and nonces
let key = SymmetricKey(size: .bits256)
let sealed = try AES.GCM.seal(Data("payload".utf8), using: key)   // random 96-bit nonce generated internally
```

Objective-C and C:

```objectivec
uint8_t buf[32];
if (SecRandomCopyBytes(kSecRandomDefault, sizeof(buf), buf) != errSecSuccess) {
    // fail closed: do not continue with an uninitialised or zeroed buffer
}
uint32_t digit = arc4random_uniform(10);   // uniform in [0, 10); never arc4random() % 10
```

What to avoid, and what to tell developers who ask about each:

- `rand()`, `random()`, `drand48()` and the rest of the `*rand48` family: never for anything security-relevant, whatever the seed.
- GameplayKit sources and custom `RandomNumberGenerator` types: fine for gameplay and deterministic tests. Keep them out of code paths that produce secrets. Code review can enforce this with a lint rule banning `using:` outside test targets.
- `arc4random` family: secure on Apple platforms. Prefer `SecRandomCopyBytes` or Swift's APIs in new code, and replace `arc4random() % n` with `arc4random_uniform(n)`.
- `/dev/random` directly: secure but discouraged. There is no reason to handle file descriptors and short reads yourself.

## Rating findings

Rate on what the value protects, how much effort the attacker needs to predict or enumerate it, and whether that can happen remotely. Use these as starting points and adjust for context.

| Rating | Conditions |
|---|---|
| **Critical** | A predictable value directly grants access to **other users' accounts or data, remotely**: client-generated authentication or session tokens, reset codes or device-binding secrets that the backend accepts, produced by a fixed-seed or time-seeded generator, or by an LCG whose outputs an attacker can observe. Also: a hardcoded seed for key generation, giving the same key on every install, for data an attacker can reach (backups, sync, network). Also: own-code ECDSA/DSA signing with nonces from a weak generator, for a key the backend trusts. |
| **High** | Weak or non-random generation of **keys, IVs/nonces or salts protecting sensitive data**, where reproducing them is feasible: `java.util.Random`/`drand48`-derived keys (at most 48 bits), time-derived keys or IVs, a GCM nonce that can repeat. Also: a PKCE `code_verifier`, OAuth `state` or OIDC `nonce` from a non-CSPRNG source, and a predictable OTP or PIN used as a second factor. |
| **Medium** | A non-cryptographic PRNG on a security-relevant path where exploitation needs extra conditions: the attacker must observe several outputs from the same instance, needs on-device access, or the value is short-lived and also server-validated with rate limiting. Also: a predictable CBC IV under an otherwise sound key, and capability URLs or file names from time or name-based UUIDs. |
| **Low** | `SecureRandom` seeded or provider-pinned where output is provably unaffected on all supported Android versions (Conscrypt ignores the seed), but the code shows deterministic intent or also runs on a JVM. Modulo bias with small entropy loss (`byte % 62`). Unchecked `SecRandomCopyBytes` status. `arc4random() % n` for codes. |
| **Info** | Non-cryptographic PRNGs used only for non-security purposes (UI, games, jitter, sampling) on instances not shared with security uses. `arc4random`/`SystemRandomNumberGenerator` flagged by a tool. `PRNGFixes` dead code in an app with `minSdkVersion` 19 or higher. Unreachable third-party SDK code. |

When you report, include: the call site (class/method/line from jadx, or function/address from r2); the generator and its seed and the seed's origin; the sink and what the value protects; the attacker's search space in numbers ("48-bit state", "about 3,600 candidate seeds for a one-hour window"); and the cheapest proof from the [section above](#proving-predictability-in-a-report). Whether the value is identical across installs, or recoverable from observed outputs, is usually what decides between Critical/High and Medium.

## References

- OWASP MASWE — [MASWE-0012: Improper Random Number Generation](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0012/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0013: Random Number Generation](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0013/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0070: Random Number Generator](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0070/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0204: Insecure Random API Usage](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0204/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0205: Non-random Sources Usage](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0205/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0311: Insecure Random API Usage](https://mas.owasp.org/MASTG/tests/ios/MASVS-CRYPTO/MASTG-TEST-0311/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0349: Runtime Use of Insecure Random APIs](https://mas.owasp.org/MASTG/tests/ios/MASVS-CRYPTO/MASTG-TEST-0349/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-BEST-0001: Use Secure Random Number Generator APIs (Android)](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0001/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-BEST-0025: Use Secure Random Number Generator APIs (iOS)](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0025/) (CC BY-SA 4.0)
- OWASP MASTG — demos [MASTG-DEMO-0007](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0007/MASTG-DEMO-0007/), [MASTG-DEMO-0008](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0008/MASTG-DEMO-0008/), [MASTG-DEMO-0073](https://mas.owasp.org/MASTG/demos/ios/MASVS-CRYPTO/MASTG-DEMO-0073/MASTG-DEMO-0073/), [MASTG-DEMO-0074](https://mas.owasp.org/MASTG/demos/ios/MASVS-CRYPTO/MASTG-DEMO-0074/MASTG-DEMO-0074/) (CC BY-SA 4.0)
- OWASP MASTG — legacy (MASTG v1) tests [MASTG-TEST-0016](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0016/) and [MASTG-TEST-0063](https://mas.owasp.org/MASTG/tests/ios/MASVS-CRYPTO/MASTG-TEST-0063/) (CC BY-SA 4.0)
- OWASP MASTG — techniques [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/), [MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/), [MASTG-TECH-0056](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0056/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/), [MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/); tools [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/), [radare2 (MASTG-TOOL-0073)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/), [Frida for iOS (MASTG-TOOL-0039)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/), [Frida for Android (MASTG-TOOL-0001)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0001/) (CC BY-SA 4.0)
- [Android Developers — Weak PRNG](https://developer.android.com/privacy-and-security/risks/weak-prng) and [`SecureRandom`](https://developer.android.com/reference/java/security/SecureRandom), [`java.util.Random`](https://developer.android.com/reference/java/util/Random)
- [Android Developers Blog — Some SecureRandom Thoughts (2013)](https://android-developers.googleblog.com/2013/08/some-securerandom-thoughts.html), [Security "Crypto" provider deprecated in Android N (2016)](https://android-developers.googleblog.com/2016/06/security-crypto-provider-deprecated-in.html), [Cryptography changes in Android P (2018)](https://android-developers.googleblog.com/2018/03/cryptography-changes-in-android-p.html)
- [Android Developers — Cryptography](https://developer.android.com/privacy-and-security/cryptography)
- [Conscrypt — `OpenSSLRandom`](https://github.com/google/conscrypt/blob/master/common/src/main/java/org/conscrypt/OpenSSLRandom.java) and [Kotlin stdlib — `JDK8PlatformImplementations`](https://github.com/JetBrains/kotlin/blob/master/libraries/stdlib/jdk8/src/kotlin/internal/jdk8/JDK8PlatformImplementations.kt)
- [Apple — `SecRandomCopyBytes`](https://developer.apple.com/documentation/security/secrandomcopybytes%28_:_:_:%29), [Randomization Services](https://developer.apple.com/documentation/security/randomization-services), [`SystemRandomNumberGenerator`](https://developer.apple.com/documentation/swift/systemrandomnumbergenerator), [GameplayKit `GKRandomSource`](https://developer.apple.com/documentation/gameplaykit/gkrandomsource)
- [Apple Platform Security Guide — Random number generation](https://support.apple.com/en-us/guide/security/seca0c73a75b/web)
- [Swift Evolution SE-0202 — Random Unification](https://github.com/swiftlang/swift-evolution/blob/main/proposals/0202-random-unification.md)
- Darwin man pages: [random(4)](https://keith.github.io/xcode-man-pages/random.4.html), [rand(3)/random(3)](https://www.manpagez.com/man/3/random/), [drand48(3)](https://www.manpagez.com/man/3/drand48/)
- [RFC 4086 — Randomness Requirements for Security](https://datatracker.ietf.org/doc/html/rfc4086), [RFC 7636 — PKCE](https://datatracker.ietf.org/doc/html/rfc7636), [RFC 6979 — Deterministic DSA and ECDSA](https://datatracker.ietf.org/doc/html/rfc6979), [RFC 9562 — UUIDs](https://datatracker.ietf.org/doc/html/rfc9562)
- [NIST SP 800-90A Rev. 1 — Deterministic Random Bit Generators](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final), [SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final), [SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final), [SP 800-132](https://csrc.nist.gov/pubs/sp/800/132/final), [SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html)
- OWASP Cheat Sheets: [Cryptographic Storage — Secure Random Number Generation](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#secure-random-number-generation), [Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), [Forgot Password](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- [Predicting the next Math.random() in Java (Franklin Ta)](https://franklinta.com/2014/08/31/predicting-the-next-math-random-in-java/)
- K. Michaelis, C. Meyer, J. Schwenk, "Randomly Failed! The State of Randomness in Current Java Implementations", CT-RSA 2013
- [CWE-332](https://cwe.mitre.org/data/definitions/332.html), [CWE-337](https://cwe.mitre.org/data/definitions/337.html), [CWE-338](https://cwe.mitre.org/data/definitions/338.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
