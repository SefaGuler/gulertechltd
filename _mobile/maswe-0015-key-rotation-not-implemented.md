---
title: "Cryptographic Key Rotation Not Implemented (MASWE-0015)"
date: 2026-11-09 12:21:00 +0000
subcategory: crypto
summary: "Cryptoperiods, key versioning and rotation for mobile apps: how to tell whether keys are ever rotated, and how to build rotation without losing data."
refs: [MASWE-0015, MASVS-CRYPTO-2, CWE-324]
tags: [android, ios, masvs-crypto, key-rotation, key-management, tink]
---

This note is part of our [MASVS-CRYPTO guide](/mobile/masvs-crypto-cryptography-guide/) and covers OWASP [MASWE-0015](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0015/): cryptographic keys that are never rotated. It is the lifecycle companion to two neighbouring notes: [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/) asks *where* a key lives, [MASWE-0016](/mobile/maswe-0016-key-access-not-restricted/) asks *who may use it*, and this one asks *for how long, and what happens when it has to go*. You will find the theory you need to argue the finding (cryptoperiods and key states from NIST SP 800-57), what rotation means for each kind of key a mobile app touches — keys it generates, keys it shares with every install, and server keys it trusts — the platform mechanisms (Android Keystore aliases and validity dates, Tink keysets, APK signing lineage, Keychain versioning, pin sets), a set of practical tests, Kotlin and Swift for rotation that does not lose data, and severity guidance.

> **Note:** At the time of writing, MASWE-0015 has no linked Knowledge pages or Tests on mas.owasp.org; the weakness page says "No Tests Yet". Everything under [Knowledge](#knowledge) and [Testing](#testing) below is **Guler Tech methodology**. Where the MASTG contains genuinely related material (app signing, certificate pinning, keystore storage) we cite it by ID; we have not invented any OWASP IDs.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Both platforms: cryptoperiods and key states](#both-platforms-cryptoperiods-and-key-states)
  - [Both platforms: rotating client-side keys versus server keys the app trusts](#both-platforms-rotating-client-side-keys-versus-server-keys-the-app-trusts)
  - [Both platforms: key identifiers and versioned ciphertext](#both-platforms-key-identifiers-and-versioned-ciphertext)
  - [Both platforms: envelope encryption and re-encryption strategies](#both-platforms-envelope-encryption-and-re-encryption-strategies)
  - [Both platforms: event-driven rotation](#both-platforms-event-driven-rotation)
  - [Android: Keystore alias versioning and key validity dates](#android-keystore-alias-versioning-and-key-validity-dates)
  - [Android: Tink keysets as built-in rotation](#android-tink-keysets-as-built-in-rotation)
  - [Android: APK signing key rotation (MASTG-KNOW-0003)](#android-apk-signing-key-rotation-mastg-know-0003)
  - [iOS: Keychain and Secure Enclave key versioning](#ios-keychain-and-secure-enclave-key-versioning)
  - [Both platforms: certificate pin rotation (MASTG-KNOW-0015, MASTG-KNOW-0072)](#both-platforms-certificate-pin-rotation-mastg-know-0015-mastg-know-0072)
  - [Both platforms: signing keys for config, updates and tokens](#both-platforms-signing-keys-for-config-updates-and-tokens)
- [Testing](#testing)
  - [Related OWASP material](#related-owasp-material)
  - [GT-0015-1: Key inventory and rotation capability (Android, iOS)](#gt-0015-1-key-inventory-and-rotation-capability-android-ios)
  - [GT-0015-2: Key identifiers in stored ciphertext (Android, iOS)](#gt-0015-2-key-identifiers-in-stored-ciphertext-android-ios)
  - [GT-0015-3: Key lifecycle at runtime (Android)](#gt-0015-3-key-lifecycle-at-runtime-android)
  - [GT-0015-4: Key lifecycle at runtime (iOS)](#gt-0015-4-key-lifecycle-at-runtime-ios)
  - [GT-0015-5: Rotation readiness of server keys the app trusts (Android, iOS)](#gt-0015-5-rotation-readiness-of-server-keys-the-app-trusts-android-ios)
  - [GT-0015-6: APK signing key lineage (Android)](#gt-0015-6-apk-signing-key-lineage-android)
  - [GT-0015-7: Key management policy and process evidence](#gt-0015-7-key-management-policy-and-process-evidence)
- [Secure implementation](#secure-implementation)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

MASWE-0015 applies when an app keeps using a cryptographic key beyond the period it should be used — or, more often on mobile, when the app is designed in a way that makes replacing a key impossible without breaking it. The OWASP requirement is short: *"The app rotates cryptographic keys regularly."* Behind that sentence sit three distinct capabilities, and an app can fail any of them:

1. **A defined lifetime.** Every key has a cryptoperiod — a time span, a usage budget, or a set of events — after which it must stop protecting new data.
2. **A mechanism to replace it.** The storage formats, protocols and code can introduce a new key while data and signatures made under the old one remain readable or verifiable during migration. That needs key identifiers and versioning.
3. **Retirement.** Superseded keys are restricted to decrypting or verifying existing material and are eventually destroyed.

Rotation here means *rekeying*: generating a new, independent key. Deriving the "new" key from the old one (hashing it, incrementing a counter into a KDF with the old key as input) does not bound a compromise, because whoever holds the old key can compute the new one. Treat that pattern as no rotation at all.

Rotation looks different depending on which key you are looking at. A mobile app typically touches five classes:

| Key class | Typical example | Who must rotate it | What "never rotated" looks like in a test |
|---|---|---|---|
| Generated on the device, scoped to it | Keystore KEK for a local database; Secure Enclave key for device binding | The app | One constant alias or tag since first install; nothing deletes it on logout |
| Shared by every install | Hardcoded AES key; HMAC request-signing secret in the APK | In practice, nobody | The same bytes in every app version for years |
| Provisioned by the server to the device | Per-user data key; session MAC key; wrapped key import | Backend and app together | Delivered once at registration; no version field; never refreshed |
| Server keys the app trusts | TLS pins; public key that verifies remote config or OTA bundles; JWT verification key | Backend, but the app must allow it | A single hardcoded public key, no key ID, no backup pin |
| Platform signing keys | APK signing key; Play App Signing upload key | The developer | Release key generated a decade ago; no v3 lineage |

**Why it matters more on mobile than people expect.**

- **Old app versions live forever.** You cannot force every user to update. A key embedded in, or trusted by, version 1.0 stays in use on every device that never upgrades. Rotation therefore has to be designed into the first release, not bolted on when you need it.
- **Hardcoded keys turn a device secret into a population secret.** A static symmetric key shared across all installs cannot be rotated without shipping a new build, and the old build keeps the old key. It is also the one place mobile apps realistically hit cryptographic usage limits: NIST SP 800-38D (section 8.3) caps AES-GCM with random 96-bit IVs at 2^32 invocations per key, and a key shared by a few million installs encrypting every request or telemetry event gets there collectively. Once IVs collide, GCM loses both confidentiality and integrity. See [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/) and [MASWE-0004](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/) for finding the key; this note is about the consequence that it can never be replaced.
- **Devices change hands and accounts change on devices.** Logout, account switching, resale and reinstall are all events where a key bound to the previous context should die. On iOS, Keychain items survive app deletion, so a "fresh install" can silently pick up the previous install's keys.
- **Compromise recovery.** If there is no version field and no second key, the only response to a leaked or suspect key is a forced update and, for locally encrypted data, data loss. Teams that know this tend not to rotate even when they should.

**Profiles: L2 and EUDIW.** MASWE-0015 is tagged with the [MAS-L2](https://mas.owasp.org/Profiles/MAS-L2/) and [MAS-EUDIW](https://mas.owasp.org/Profiles/MAS-EUDIW/) profiles and not with L1. MAS-L2 ("Advanced Security") is the profile for apps where a compromise has serious consequences — banking, payments, health, government, enterprise access — and defence in depth is expected on top of the L1 baseline. MAS-EUDIW is the OWASP MAS profile for European Digital Identity Wallet apps under the revised eIDAS framework (Regulation (EU) 2024/1183); OWASP describes it as drawing on the other profiles and extending beyond their union. In practice: if your engagement is scoped to L1 only, report rotation gaps as observations; for L2 apps and identity wallets, where long-lived device keys, credential keys and issuer trust anchors are central to the security model, they are in-scope findings.

The weakness maps to MASVS-CRYPTO-2 ("The app performs key management according to industry best practices") and to [CWE-324: Use of a Key Past its Expiration Date](https://cwe.mitre.org/data/definitions/324.html). OWASP links it to threat MAS-THREAT-0015 ("Attackers can decrypt or forge all data ever protected with a compromised key"), reached through reverse engineering the package (MAS-ATTACK-0001) or reading device storage on a compromised device (MAS-ATTACK-0005).

## Modes of Introduction

**No rotation mechanism.** The storage format or protocol is designed around exactly one key. Ciphertext is `IV || ciphertext || tag` with nothing that says which key produced it; the Keystore alias is a constant such as `"db_key"`; the request-signing secret is a `const val`; the app verifies remote config against one embedded public key. Replacing the key means either re-encrypting everything in one shot (and hoping nothing is interrupted) or breaking existing installs, so nobody does it.

**Unbounded cryptoperiods.** Keys are created once — on first launch, at registration, at build time — and nothing in the code, the backend or the policy ever retires them. Typical evidence: no `setKeyValidity*` calls, no key version in any API, a Keychain item whose creation date matches the original install from years ago, a release signing certificate valid until 2049 and never rotated.

**Superseded keys not retired.** A new key exists, but the old one is still used for new operations (both versions encrypt, or the "primary" pointer was never moved), or it is kept indefinitely after all data has been migrated. An old key that still decrypts is a liability for as long as it exists; an old key that still *encrypts or signs* means the rotation achieved nothing.

Mobile-specific variants you will meet in practice:

- **Static keys shared across installs** (hardcoded or derived from the package name, signing certificate or other public constants). Rotation requires an app release, and the previous release keeps the previous key.
- **Single trust anchors.** One pinned SPKI hash with no backup; one embedded public key for config, update or licence verification; a JWT verification key compiled in rather than fetched by key ID.
- **User-scoped keys that outlive the user.** Logout clears tokens but not the Keystore or Keychain key that encrypts the user's cache, so the next account on the device inherits it.
- **Reinstall does not reset keys (iOS).** Keychain items persist after deletion of the app, so a new install reuses a key the previous install created — including one an attacker obtained.
- **No compromise lever.** The backend has no way to tell installed apps "key version N is revoked, re-key now".

## Impact

- **Compromise of sensitive data.** One compromised key decrypts the entire history it ever protected rather than a bounded window. For a static key shared across installs, that history spans every user.
- **Authentication or authorisation bypass.** A compromised signing or MAC key keeps producing values the app or backend accepts — forged requests, licences, configuration or tokens — for as long as the key is trusted, with no expiry to cut it off.
- **Integrity of code and configuration.** If the key that verifies OTA bundles, remote configuration or feature flags cannot be rotated, its compromise lets an attacker push trusted content to every install until each one is manually updated, and indefinitely to installs that never update.
- **Availability (the forgotten side).** Apps with no rotation path break when rotation is forced on them: a pinned certificate is re-keyed by the CDN, a CA is distrusted, a signing key must be replaced after an incident. The fear of that outage is a common reason organisations keep using keys they know they should retire.
- **Compliance.** Standards that apply to many L2 apps require defined cryptoperiods and key changes at their end, for example PCI DSS v4.0 requirement 3.7.4. "We never rotate" is a finding in that context irrespective of exploitability.

## Mitigations

- **Define a cryptoperiod for every key** — by time, by usage, and by event — using NIST SP 800-57 Part 1 Rev. 5 (section 5.3) as the baseline, and write it down in a key inventory.
- **Make every ciphertext, signature and wrapped key self-describing.** Carry a key identifier or version in a header, bound into the AEAD associated data, or use a library that does it for you (Tink keysets).
- **Use envelope encryption for anything that persists.** Data is encrypted under data encryption keys (DEKs); DEKs are wrapped by a key encryption key (KEK) in the Keystore, Keychain or Secure Enclave. Rotating the KEK then means rewrapping a handful of DEKs, not re-encrypting the data.
- **Rotate on events, not only on dates.** Logout, account switch, re-enrolment, password change, reinstall, and any suspicion of compromise should create new keys and destroy old ones.
- **Trust key sets, not single keys.** Ship at least one backup pin; verify server signatures against a set of keys selected by key ID; fetch JWT verification keys from a JWKS endpoint; give the backend a way to revoke a key version and to require clients to re-key.
- **Retire properly.** After rotation, restrict superseded keys to decrypt/verify, migrate, then delete them (`KeyStore.deleteEntry`, `SecItemDelete`, Tink `disable`/`destroy`).
- **Remove static shared keys.** No amount of rotation discipline fixes a key compiled into the package; move the function server-side or derive per-install keys.
- **Plan for the platform keys too.** Use Play App Signing or HSM custody for APK signing keys and sign with APK Signature Scheme v3 so the key can be rotated with a lineage.

## Knowledge

None of the sections below has a dedicated MASTG Knowledge page; they are our own write-ups. Where the MASTG has a related page we name it in the heading.

### Both platforms: cryptoperiods and key states

A **cryptoperiod** is the time span during which a key is authorised for use. NIST SP 800-57 Part 1 Rev. 5 (section 5.3) splits it into two parts for keys that protect stored data:

- the **originator-usage period (OUP)** — when the key may *apply* protection (encrypt, sign, wrap, compute a MAC), and
- the **recipient-usage period (RUP)** — when it may still *process* protected data (decrypt, verify, unwrap). The RUP can extend beyond the OUP so that data protected late in the OUP stays readable.

SP 800-57 lists factors that shorten or lengthen a cryptoperiod: the strength of the algorithm, the operating environment (a phone that may be lost, rooted or resold is not a locked machine room), the volume of data protected, the lifetime of that data, the security function, the re-keying method, the number of places the key exists, and the threat. Table 1 in section 5.3.6 gives suggested ranges. The ones you will cite most often in mobile reports:

| Key type (SP 800-57 terminology) | Suggested cryptoperiod |
|---|---|
| Symmetric data-encryption key | OUP up to 2 years; RUP up to OUP + 3 years |
| Symmetric key-wrapping key (a KEK) | OUP up to 2 years; RUP up to OUP + 3 years |
| Symmetric authentication key (HMAC) | OUP up to 2 years; RUP up to OUP + 3 years |
| Private signature key | 1 to 3 years |
| Public signature-verification key | Several years, depending on key size |
| Private and public authentication keys | 1 to 2 years |
| Ephemeral key-agreement keys | One key-agreement transaction |

Treat these as defensible defaults, not law; NIST is explicit that the right period depends on the risk factors. What you can always insist on is that a period *exists* and that the system can honour it.

Usage-based limits are part of the cryptoperiod too. The one that matters in practice is AES-GCM: with random 96-bit IVs, SP 800-38D section 8.3 limits a single key to 2^32 invocations of the encryption function so that the probability of an IV collision stays negligible. A per-install key encrypting local records will never get near that. A key shared by every install, or a server key used for every client response, can.

SP 800-57 section 7 also defines **key states**, which give you precise language for the "superseded keys not retired" mode:

| State | What the key may do |
|---|---|
| Pre-activation | Nothing yet (generated, distributed, not in use) |
| Active | Apply and process protection |
| Suspended | Temporarily nothing (for example during an investigation) |
| Deactivated | Process only: decrypt, verify, unwrap existing material — never apply new protection |
| Compromised | Process only, under controlled conditions, to recover data; never apply protection |
| Destroyed | Key material gone; metadata may remain |

A correctly rotated key moves from *active* to *deactivated* when its successor becomes active, and to *destroyed* once nothing protected under it remains. Tink's key statuses (`ENABLED`, `DISABLED`, `DESTROYED`) plus its "primary" pointer map directly onto these states; hand-rolled schemes need the same distinctions in code.

### Both platforms: rotating client-side keys versus server keys the app trusts

Rotation is implemented in different places depending on who owns the key, and your test has to look in the right place.

**Keys the app generates and uses itself** (Keystore and Keychain KEKs, Secure Enclave signing keys, per-install DEKs). The app owns the whole lifecycle. Rotation is entirely client-side: generate a successor under a new identifier, migrate (rewrap or re-encrypt), switch the "current" pointer, destroy the old key. If the key is registered with the backend — a device-binding public key, an App Attest key, a FIDO-style credential — the backend must accept a re-registration and revoke the old public key, otherwise the old private key, if extracted or still usable on a stolen device, keeps working.

**Keys the backend provisions to the app** (per-user content keys, session keys, keys imported with `WrappedKeyEntry` or via Keychain). The backend decides when a key is superseded; the app must be able to receive a new version, keep the old one for decryption while it migrates, and report which version it holds. Look for a version or key ID in the provisioning API and in the app's storage.

**Server keys the app trusts** (TLS certificate pins, public keys that verify remote configuration, OTA bundles, licences or push payloads, JWT verification keys, a server public key used for end-to-end encryption). The private key never touches the app, so the app cannot "rotate" it — but it can make rotation *impossible* by trusting exactly one key with no way to add another. The client-side requirements are: trust a *set* of keys selected by key ID, ship the next key before it is needed (backup pins, pre-distributed verification keys), accept authenticated updates to the trust set, and honour revocation.

**Static symmetric keys shared across installs** sit in the worst position: the app both uses the key and is the only distribution channel for it, and the key is equally available to every attacker who downloads the package. A rotation would need a new build plus server-side support for both keys for as long as old builds exist. Expect the answer "we can't rotate it" and report it as such, together with the underlying MASWE-0003/MASWE-0004 finding.

### Both platforms: key identifiers and versioned ciphertext

Rotation needs every protected object to say which key protects it. Without that, the decrypting side has to guess (try every key), which is slow, error-prone, and makes it tempting to keep only one key.

Common self-describing formats you will see:

| Format | Where the key identifier lives |
|---|---|
| Tink AEAD with the default `TINK` output prefix | First 5 bytes: version byte `0x01` followed by the 4-byte key ID (big-endian) |
| JWS / JWE (JOSE) | `kid` in the protected header |
| COSE (used by mdoc credentials, WebAuthn) | `kid` header parameter |
| Custom app formats | A version byte and key ID or DEK ID in a fixed header |

A reasonable custom layout looks like this, with the whole header bound into the AEAD associated data so it cannot be swapped:

```text
+---------+-------------+----------------+------------------------+
| ver (1) | key id (4)  | nonce (12)     | ciphertext || tag (16) |
+---------+-------------+----------------+------------------------+
  AAD = ver || key id || context (e.g. record id, table name)
```

The identifier does not have to be inline. A database may store `kek_version` in a column next to the wrapped DEK; a file store may encode it in the file name. When testing, absence of a header is a reason to look further, not a finding on its own.

Two pitfalls when reviewing custom formats: the version or key ID is *not* authenticated (an attacker who can write the file can point the reader at an older, weaker or compromised key), and the reader silently falls back to "try the other keys" when the identified key fails, which reintroduces the guessing.

### Both platforms: envelope encryption and re-encryption strategies

Envelope encryption is what makes rotation affordable. Data is encrypted under one or more **DEKs**; each DEK is encrypted ("wrapped") under a **KEK** that never leaves the Keystore, Keychain or Secure Enclave; only wrapped DEKs are persisted. The pattern and its Keystore/Secure Enclave implementation are in our [MASWE-0003 note](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/#secure-implementation); here is why it matters for rotation:

- **Rotating the KEK** means generating `kek.v(N+1)`, unwrapping each DEK with `kek.vN` and rewrapping it with `kek.v(N+1)`, then deleting `kek.vN`. The cost is proportional to the number of DEKs (often one to a few hundred), not the gigabytes of data.
- **Rotating a DEK** means re-encrypting the data it protects. You only need to do this when the DEK itself might be compromised, or when it approaches a usage limit.
- **Crypto-shredding.** Deleting a KEK makes everything under it unrecoverable instantly, which is the cleanest way to implement "logout wipes local data" for large caches.

Strategies for re-encrypting data when you do need to:

| Strategy | How it works | Trade-off |
|---|---|---|
| Rewrap only | New KEK, rewrap DEKs, data untouched | Cheap; does not help if a DEK leaked |
| Lazy re-encryption | Decrypt with the old key on read, write back under the new key | No big migration; old key must live until every record has been touched |
| Background batch | Re-encrypt in a resumable job (`WorkManager` on Android, `BGProcessingTask` on iOS) with a per-record version marker | Bounded migration window; needs crash-safe progress tracking |
| Re-provision | Discard local data and re-download it under new keys | Simplest for caches of server data; not possible for data that exists only on the device |

Whatever the strategy, the per-record key identifier is what makes it safe to interrupt and resume.

### Both platforms: event-driven rotation

Time-based cryptoperiods are only half the story on mobile. These events should rotate or destroy keys:

| Event | What should happen |
|---|---|
| Logout or account switch | Destroy user-scoped keys (or crypto-shred via the KEK); the next user gets fresh keys and cannot decrypt leftovers |
| Re-enrolment or device re-registration | Generate a new device-binding key pair; backend revokes the old public key |
| Password or PIN change (for password-derived KEKs) | Derive a new KEK with a new salt and rewrap the DEKs |
| Biometric enrolment change or lock-screen removal | Android invalidates auth-bound keys (`KeyPermanentlyInvalidatedException`); iOS makes `.biometryCurrentSet` items unreadable. The app must re-create keys and re-enrol cleanly rather than fall back to a weaker key. See [MASWE-0016](/mobile/maswe-0016-key-access-not-restricted/) |
| Reinstall (iOS) | Purge Keychain items left by a previous install on first launch |
| Suspected compromise | Backend marks key version N revoked; clients re-key on next contact; servers stop accepting material from version N |
| Key or library migration | Move to a stronger algorithm or larger key size under a new identifier |

When you test, these events are your levers: trigger each one and observe whether key identifiers change.

### Android: Keystore alias versioning and key validity dates

The Android Keystore has no "rotate" operation. A key is created under an **alias**, its authorisation list is fixed at generation, and rotation is the app's job: create a key under a new alias, migrate, delete the old alias. Apps that rotate therefore use versioned aliases (`vault.kek.v3`) or keep a mapping from logical key to current alias. `KeyStore.aliases()` enumerates all aliases owned by the app's UID; `deleteEntry(alias)` removes one; `getCreationDate(alias)` returns when the entry was created. Keystore keys are deleted when the app is uninstalled (unlike iOS Keychain items).

`KeyGenParameterSpec.Builder` and `KeyProtection.Builder` can also encode a cryptoperiod into the key itself, mapping neatly onto SP 800-57:

| Setter (API 23+) | Effect | SP 800-57 equivalent |
|---|---|---|
| `setKeyValidityStart(Date)` | Key unusable before this date | Pre-activation |
| `setKeyValidityForOriginationEnd(Date)` | No encryption or signing after this date | End of OUP |
| `setKeyValidityForConsumptionEnd(Date)` | No decryption or verification after this date | End of RUP |
| `setKeyValidityEnd(Date)` | Sets both of the above | End of the cryptoperiod |

Using a key outside its window throws `KeyNotYetValidException` or `KeyExpiredException` (both `InvalidKeyException` subclasses) at `Cipher.init`/`Signature.init`. Two caveats: time-based restrictions depend on a trustworthy clock and are enforced by the Keystore service rather than necessarily inside secure hardware, so they are a lifecycle tool, not a security boundary against a rooted device; and an app that catches `KeyExpiredException` and generates a fresh key *without migrating* has turned expiry into data loss. The certificate validity dates on asymmetric keys (`setCertificateNotBefore`/`setCertificateNotAfter`) are something else entirely: they describe the self-signed certificate the Keystore wraps around the public key and are not enforced on key use.

`KeyInfo` (obtained through `SecretKeyFactory` or `KeyFactory` for the `AndroidKeyStore` provider; the mechanics are in our [MASWE-0003 note](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/#android-android-keystore-tee-and-strongbox-mastg-know-0043)) exposes `getKeyValidityStart()`, `getKeyValidityForOriginationEnd()` and `getKeyValidityForConsumptionEnd()`, which is how you read a key's configured lifetime at runtime.

Authentication-bound keys add a forced-rotation path the app must handle: they are permanently invalidated when the user removes the secure lock screen, and by default when a new biometric is enrolled. Correct apps catch `KeyPermanentlyInvalidatedException`, delete the alias, and run the enrolment flow again. Incorrect ones fall back to an unprotected key.

### Android: Tink keysets as built-in rotation

[Tink](https://developers.google.com/tink) is Google's cryptography library and the most direct way to get rotation on Android without writing a scheme. Its unit of key management is the **keyset**, not the key:

- A keyset holds one or more keys. Each has a 32-bit **key ID**, a **status** (`ENABLED`, `DISABLED`, `DESTROYED`) and an **output prefix type**.
- Exactly one enabled key is **primary**. New ciphertexts and signatures are produced with the primary key.
- With the default `TINK` prefix, every output starts with `0x01` and the 4-byte key ID of the key that produced it. On decryption Tink uses the prefix to select the key, and also tries keys with the `RAW` prefix (no header).
- Rotation is the documented [Tink key rotation](https://developers.google.com/tink/managing-key-rotation) procedure: add a new key, distribute the keyset, promote the new key to primary, disable the old key once nothing needs it, and destroy it later.

On Android, `AndroidKeysetManager` stores the keyset in `SharedPreferences`, encrypted under a master key in the Android Keystore (the URI passed to `withMasterKeyUri`, such as `android-keystore://my_master_key`). The stored value is a hex-encoded `EncryptedKeyset` protobuf, which normally also contains a plaintext `KeysetInfo` — primary key ID, and for each key its type URL, status, key ID and prefix type, but no key material. That metadata is a gift to a tester: decode it and you can see whether the keyset has ever contained more than one key.

Two related libraries you will meet:

- **Jetpack Security** (`EncryptedSharedPreferences`, `EncryptedFile`) uses Tink keysets internally, stored in the app's preferences under names beginning `__androidx_security_crypto_encrypted_prefs_`. It exposes no rotation API, and the library is deprecated by Google. Its use is not a MASWE-0015 finding by itself, but it means the app has no practical way to rotate those keys.
- **DataStore with Tink** (`androidx.datastore:datastore-tink`, `AeadSerializer`) wraps a DataStore serializer with a Tink `Aead`; OWASP mentions it in [MASTG-BEST-0050](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0050/). Rotation then follows the keyset you pass in.

The Tink master key in the Keystore is itself a KEK; rotating it means re-encrypting the keyset under a new master key URI, which Tink does not do automatically.

### Android: APK signing key rotation (MASTG-KNOW-0003)

Related: [MASTG-KNOW-0003](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0003/) and [MASTG-BEST-0006](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0006/). We cover signing schemes in depth in our [app signing note](/mobile/mastg-know-0003-app-signing/); this section is only about rotation.

Before Android 9 an app could never change its signing key: updates signed with a different key are rejected, so a compromised or weak signing key was permanent. **APK Signature Scheme v3** (Android 9, API 28) adds a **signing-certificate lineage**: a chain of certificates, each entry signed by the previous key, proving that the new key is the legitimate successor. The platform accepts an update signed with the new key if the installed app's key appears earlier in the lineage. Each older signer in the lineage carries capabilities that let the developer decide how much trust the old key keeps (for example, whether it may still be used for signature-protected permissions or a shared UID). Android 13 added **v3.1**, which lets a rotated signer target only newer platform versions while older devices keep seeing the original signer.

Practical consequences for an assessment:

- With rotation, the v1/v2 signatures are typically made with the **original** key (so older Android versions keep accepting updates) and the v3 block with the **new** key plus lineage. `apksigner verify -v --print-certs` shows the signers per scheme.
- For apps using **Play App Signing**, Google holds the app signing key and the developer holds an upload key. Google offers a key upgrade for app signing, and the upload key can be reset if lost or compromised. Ask which applies.
- Apps that verify their own signature at runtime (an anti-tampering check comparing the signing certificate with a hardcoded hash) must handle a lineage. `PackageManager.GET_SIGNING_CERTIFICATES` returns a `SigningInfo` with `getSigningCertificateHistory()`, `getApkContentsSigners()` and `hasPastSigningCertificates()`, and `PackageManager.hasSigningCertificate(packageName, certSha256, PackageManager.CERT_INPUT_SHA256)` (API 28) checks the whole lineage. A check that only knows one hash will break the day the key is rotated, which in practice prevents the rotation.

Signing-key rotation is a resilience and supply-chain control more than a data-protection one. Report its absence as a finding only when there is a reason to rotate (a key held insecurely, a known exposure, a weak legacy key); otherwise record it as an observation.

### iOS: Keychain and Secure Enclave key versioning

iOS has no rotation API either. Rotation is done by naming:

- Generic-password items (where CryptoKit `SymmetricKey`s are usually stored) are identified by `kSecAttrService` + `kSecAttrAccount`; a versioned scheme uses accounts such as `kek.v3`.
- Key items (`kSecClassKey`, including Secure Enclave key references) are identified by `kSecAttrApplicationTag`, which is `Data`, and optionally `kSecAttrLabel`.
- Every item carries `kSecAttrCreationDate` and `kSecAttrModificationDate`, which `objection`'s `ios keychain dump` shows in its *Created* column. They are the quickest runtime evidence of a key's age.

Secure Enclave private keys can never be exported, so the only way to rotate one is to generate a new Secure Enclave key, rewrap whatever the old one protected (or re-register the new public key with the backend), and delete the old reference. The envelope pattern with a Secure Enclave KEK is in our [MASWE-0003 note](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/#ios-envelope-encryption-with-a-secure-enclave-kek).

Lifecycle facts that matter for testing:

- **Keychain items survive app deletion.** Apple's documentation does not promise this either way and it has been stable in practice for years. A new install sees items from the previous install unless the app purges them on first launch (a `UserDefaults` flag works, because `UserDefaults` are deleted with the app).
- **Items in shared access groups** are visible to every app and extension in the group; rotating a shared key needs coordination across all of them.
- **App Attest keys** (`DCAppAttestService.generateKey()`) are per install and must be regenerated after reinstall; the backend should treat a new attested key for the same user as a re-enrolment and retire the old one.
- **Code signing** is managed through Apple certificates and provisioning profiles; certificate renewal is routine and is not what MASWE-0015 is about.

### Both platforms: certificate pin rotation (MASTG-KNOW-0015, MASTG-KNOW-0072)

Pinning belongs to MASVS-NETWORK and its weakness is [MASWE-0028: Insecure Identity Pinning](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0028/); we touch it here only because a pin is a server key the app trusts, and pinning without a rotation plan is the classic way to make key rotation impossible. The MASTG background is in [MASTG-KNOW-0015](https://mas.owasp.org/MASTG/knowledge/android/MASVS-NETWORK/MASTG-KNOW-0015/) (Android) and [MASTG-KNOW-0072](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-NETWORK/MASTG-KNOW-0072/) (iOS).

- **Pin the public key (SPKI hash), not the certificate.** A certificate renewal that keeps the same key pair then needs no app change.
- **Always ship a backup pin** for a key that is *not currently deployed* — a spare key pair held offline, or a second CA's key. When the primary key must be rotated (or is compromised), the server switches to the backup key and installed apps keep working. Pinning only the current leaf key plus its own issuing CA is not a backup if the CA itself rotates its intermediate.
- **Android Network Security Configuration** supports `<pin-set expiration="YYYY-MM-DD">`. After that date Android stops enforcing the pins and falls back to the configured trust anchors, so old app versions do not brick themselves. That is a deliberate availability trade-off: an expired pin set means pinning is silently off (OWASP [MASTG-TEST-0243](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0243/) checks for it).
- **iOS `NSPinnedDomains`** (ATS) has no expiry; the developer must rotate pins through app updates and backup pins. Pinning in code (`URLSessionDelegate`, TrustKit, OkHttp `CertificatePinner` on Android) has whatever rotation behaviour the code gives it.
- **Remotely updated pins** must be delivered in a signed bundle whose signing key is itself rotatable; otherwise the pin update channel becomes the weakest key in the system.

### Both platforms: signing keys for config, updates and tokens

Apps frequently embed a public key to verify something the server signs: remote configuration and feature flags, OTA JavaScript or asset bundles, licences and entitlements, push payloads, QR-code or offline tokens. The private key never leaves the server, but the app decides whether that key can ever change. What good looks like:

- **Verification against a key set, selected by key ID.** The signed object carries `kid`; the app holds a small map of trusted keys, including the *next* key, shipped before it is used.
- **Authenticated trust-list updates.** New keys arrive in a structure signed by a long-term root key that lives offline, or through an app update.
- **Revocation.** A key ID can be removed from the trust set or listed as revoked, and the app refuses objects signed with it.
- **Expiry.** Signed objects carry an issue time and expiry so a compromised old key cannot be used to replay ancient but valid content indefinitely.

**JWT verification keys** deserve a specific mention. An app that verifies ID tokens or offline tokens locally should obtain the issuer's keys from the issuer's JWKS endpoint (`jwks_uri` in the OpenID Provider metadata), select the key by the token's `kid`, cache it, and refresh when it sees an unknown `kid` (rate-limited). A public key compiled into the app breaks on the issuer's next rotation, and a symmetric `HS256` secret compiled into the app is worse: it cannot be rotated without a release and lets anyone forge tokens (see [MASWE-0011](/mobile/maswe-0011-improper-signature-verification/)).

## Testing

All tests in this section are **Guler Tech methodology**. Static analysis can prove that a rotation *capability* exists or is missing; runtime testing can show whether lifecycle events actually change keys; and because rotation is partly a process control, the last test is about evidence you request from the client.

### Related OWASP material

We searched the MASTG knowledge, tests, beta tests, techniques, best practices and demos for material related to key rotation. What genuinely exists:

| ID | Type | Relevance |
|---|---|---|
| [MASTG-KNOW-0003](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0003/) App Signing | Knowledge | APK signing schemes; v3 enables key rotation |
| [MASTG-BEST-0006](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0006/) Use Up-to-Date APK Signing Schemes | Best practice | Recommends v3 "which also supports key rotation" |
| [MASTG-TEST-0224](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0224/) Usage of Insecure APK Signature Version | Test (v2 beta) | Signing scheme check; prerequisite for GT-0015-6 |
| [MASTG-TEST-0038](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0038/) Making Sure that the App is Properly Signed | Test, legacy (MASTG v1) | Notes that v3 supports key rotation after compromise |
| [MASTG-KNOW-0015](https://mas.owasp.org/MASTG/knowledge/android/MASVS-NETWORK/MASTG-KNOW-0015/) Certificate Pinning (Android) | Knowledge | Backup pins and pin expiration |
| [MASTG-KNOW-0072](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-NETWORK/MASTG-KNOW-0072/) Server Trust Evaluation (iOS) | Knowledge | Backup pins; no expiry in `NSPinnedDomains` |
| [MASTG-TEST-0242](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0242/), [MASTG-TEST-0243](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0243/) | Tests (v2 beta) | Missing pinning, expired pins in the NSC |
| [MASTG-TEST-0385](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0385/) Missing Certificate Pinning in ATS | Test (v2 beta) | iOS pin presence |
| [MASTG-KNOW-0043](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0043/), [MASTG-KNOW-0047](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0047/) | Knowledge | Keystore and envelope encryption, the basis of cheap rotation |
| [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0061](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0061/), [MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/) | Techniques | Reverse engineering, static analysis, method hooking, IPA extraction, Keychain dumping |

The MASTG Android cryptography chapter lists "key rotation" among the key management functions to verify, but no test, demo or rule implements it.

### GT-0015-1: Key inventory and rotation capability (Android, iOS)

Guler Tech methodology. Platform: Android and iOS. Type: static (code).

#### Overview

You cannot judge rotation without knowing what keys exist. This test builds a **key inventory** from the binary — every key the app generates, loads, imports, derives or trusts — and, for each, answers four questions: how is it identified (alias, tag, account, key ID), is that identifier versioned, is there code that creates a successor and migrates data, and is there code that destroys it (on rotation, logout or reset). A key with a constant identifier and no creation-of-successor or deletion path cannot be rotated by this build of the app.

#### Prerequisites

- The APK (all splits) or a decrypted IPA of the build under test.
- `jadx` (decompilation, [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)), `apktool` for resources, and `semgrep` for pattern searches (static analysis, [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)).
- For iOS: `unzip`, `rabin2`/`radare2`, and a disassembler of your choice ([MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/) for extracting the binary).
- The results of the hardcoded-key tests from our [MASWE-0003 note](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/#tests) (MASTG-TEST-0212/0213/0214). A hardcoded key is unrotatable by definition; carry those findings into the inventory.

#### Steps

1. **Decompile the Android app.**

   ```bash
   jadx -d out/ app.apk
   apktool d app.apk -o res_out/
   APP=out/sources/com/example   # the app's own packages; keep library code out of the noise
   ```

2. **List every Keystore key and every lifecycle operation.** The alias is the first argument to `KeyGenParameterSpec.Builder`/`KeyProtection.Builder` and the argument to `getKey`, `getEntry`, `containsAlias` and `deleteEntry`.

   ```yaml
   rules:
     - id: gt-keystore-key-created
       languages: [java]
       severity: INFO
       message: Keystore key created - alias $ALIAS, purposes $P
       pattern: new KeyGenParameterSpec.Builder($ALIAS, $P)
     - id: gt-keystore-key-imported
       languages: [java]
       severity: INFO
       message: Key imported into the Keystore - alias $ALIAS
       pattern: $KS.setEntry($ALIAS, $ENTRY, new KeyProtection.Builder(...). ... .build())
     - id: gt-keystore-key-deleted
       languages: [java]
       severity: INFO
       message: Keystore entry deleted - alias $ALIAS
       pattern: $KS.deleteEntry($ALIAS)
     - id: gt-keystore-key-validity
       languages: [java]
       severity: INFO
       message: Key validity period configured
       pattern-either:
         - pattern: $B.setKeyValidityEnd(...)
         - pattern: $B.setKeyValidityForOriginationEnd(...)
         - pattern: $B.setKeyValidityForConsumptionEnd(...)
   ```

   ```bash
   semgrep -c gt-key-lifecycle.yml out/sources/ --text
   grep -rnE 'getKey\(|getEntry\(|containsAlias\(|deleteEntry\(' "$APP"
   ```

3. **Resolve the aliases.** jadx usually inlines string constants, but aliases built at runtime (`"kek_" + version`, `"${userId}_key"`) need you to read the method. Write down each alias and whether it contains a version number, a user identifier, or neither.

4. **Search for versioning and key-ID handling.**

   ```bash
   grep -rniE '"[a-z0-9_.-]*(_v|\.v|-v)[0-9]+"|keyVersion|key_version|kekVersion|keyId|"kid"|primaryKeyId' "$APP"
   grep -rnE 'AndroidKeysetManager|KeysetHandle|KeysetManager|withMasterKeyUri|setPrimary\(|\.rotate\(|\.disable\(|\.destroy\(' "$APP"
   grep -rnE 'EncryptedSharedPreferences|EncryptedFile|MasterKey' "$APP"
   ```

   Tink with `setPrimary` or rotation code is a strong positive signal; Tink with only `withKeyTemplate` and no rotation code means the keyset will hold exactly one key forever.

5. **Follow the logout and reset paths.** Find the logout, account-switch, "delete account" and "reset app" handlers (search for `logout`, `signOut`, `clearSession`, `deleteAccount`, or the strings on those buttons in `res_out/res/values/strings.xml`) and check whether they delete keys, destroy keysets or wipe wrapped DEKs, or only clear tokens.

6. **Inventory server-side trust anchors** (pins, embedded public keys, JWKS URLs). These are covered in detail by [GT-0015-5](#gt-0015-5-rotation-readiness-of-server-keys-the-app-trusts-android-ios); for the inventory, just record them.

7. **iOS: list Keychain and key APIs, then the identifiers.**

   ```bash
   unzip -q app.ipa -d ipa/
   BIN="ipa/Payload/App.app/App"
   rabin2 -i "$BIN" | grep -E 'SecItem(Add|Update|Delete|CopyMatching)|SecKeyCreateRandomKey|SecKeyCreateWithData|kSecAttr(ApplicationTag|Account|Service|TokenIDSecureEnclave)'
   rabin2 -zz "$BIN" | grep -iE 'kek|dek|key[._-]?v[0-9]|keyversion|kid' | head -50
   ```

   Then cross-reference each `SecItemDelete` call (`axt @ sym.imp.SecItemDelete` in `r2 -A`) to see whether it is reachable from a logout or rotation path.

   > **Warning:** Swift stores string literals of up to 15 UTF-8 bytes inline in instructions rather than as C strings, so short tags such as `"kek.v1"` often do not appear in `strings` or `rabin2 -zz` output. Absence of a hit is not evidence of absence; read the disassembly around `SecItemAdd`, or confirm at runtime with [GT-0015-4](#gt-0015-4-key-lifecycle-at-runtime-ios).

#### Observation

A key inventory table, one row per key:

| Key | Purpose / protects | Identifier | Versioned? | Successor created by | Destroyed by | Validity set? |
|---|---|---|---|---|---|---|
| … | … | alias / tag / account / kid | yes / no | method or "none" | method or "none" | dates or "none" |

Attach the semgrep output and the decompiled methods that create and delete each key.

#### Evaluation

The test **fails** for a key if it protects sensitive data or something the backend trusts and any of the following holds:

- its identifier is constant and no code path creates a successor key and migrates data or registrations to it;
- a successor exists but the superseded key remains in use for new operations (both versions encrypt or sign);
- it is user-scoped and nothing destroys it on logout or account switch;
- it is hardcoded or derived from public constants (inherently unrotatable).

It **passes** for a key if identifiers are versioned (or a Tink keyset is used with rotation code), there is a migration path, and superseded keys are deleted or demoted to decrypt/verify-only. Static analysis shows capability, not practice: a pass here still needs [GT-0015-3](#gt-0015-3-key-lifecycle-at-runtime-android)/[GT-0015-4](#gt-0015-4-key-lifecycle-at-runtime-ios) and the policy evidence from [GT-0015-7](#gt-0015-7-key-management-policy-and-process-evidence).

Common false positives: aliases that look constant but are used for genuinely ephemeral keys (deleted and regenerated per operation); third-party SDK keys outside the app's control (record them, but report against the SDK); and keys whose only function is non-sensitive (for example, a cache of public images).

#### Demo

A typical unrotatable design — a single Keystore key used directly for every record, never deleted:

```kotlin
private const val KEY_ALIAS = "local_db_key"

fun dbKey(): SecretKey {
    val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    (ks.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
    val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
    gen.init(
        KeyGenParameterSpec.Builder(KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .build()
    )
    return gen.generateKey()
}

fun logout(prefs: SharedPreferences) {
    prefs.edit().remove("access_token").remove("refresh_token").apply()   // key untouched
}
```

Running the lifecycle rules over the jadx output of a lab build:

```text
┌─────────────────┐
│ 1 Code Finding  │
└─────────────────┘

    com/example/vault/DbKeyProvider.java
    ❯❱ gt-keystore-key-created
          Keystore key created - alias "local_db_key", purposes 3

           31┆ keyGenerator.init(new KeyGenParameterSpec.Builder("local_db_key", 3).setBlockModes("GCM")
               .setEncryptionPaddings("NoPadding").build());
```

No `gt-keystore-key-deleted` or `gt-keystore-key-validity` hits, a constant alias, and a logout handler that only removes tokens: the test fails. The local database key lives as long as the app is installed, survives every logout, and the next account on the device decrypts with the same key.

### GT-0015-2: Key identifiers in stored ciphertext (Android, iOS)

Guler Tech methodology. Platform: Android and iOS. Type: filesystem and dynamic.

#### Overview

A design that supports rotation leaves visible traces in its data: ciphertexts with a version or key-ID header, a `kek_version` column next to wrapped keys, a Tink keyset with several keys. This test pulls the app's stored data and reads those traces. It answers two questions static analysis struggles with: *is a key identifier actually written*, and *has more than one key ever been used*.

#### Prerequisites

- A rooted Android device or emulator, or a debuggable build (for `run-as`); a jailbroken iPhone, or an iPhone with an objection-patched app for file access.
- The app used realistically for a while (logged in, data synced, ideally across an app update), so storage is populated.
- `xxd`, `base64`, `sqlite3`, and optionally `protoc` (for `--decode_raw`) on your workstation.

#### Steps

1. **Pull the app's data.**

   ```bash
   # Android, rooted
   adb shell su -c 'tar -C /data/data -cf /sdcard/app.tar com.example.app'
   adb pull /sdcard/app.tar && mkdir appdata && tar -xf app.tar -C appdata
   # Android, debuggable build
   adb exec-out run-as com.example.app tar -cf - . > app.tar
   ```

   On iOS, find the data container with `objection -n com.example.app start` and `env`, then copy `Documents/`, `Library/` and the app's preferences plist over SSH (jailbroken) or with objection's `file download`.

2. **Find encrypted blobs.** Look for high-entropy files, Base64 values in `shared_prefs/*.xml` or `Library/Preferences/*.plist`, and BLOB or long text columns in SQLite databases:

   ```bash
   find appdata -type f -size +64c -exec sh -c 'printf "%s  " "$1"; head -c 4096 "$1" | gzip -c | wc -c' _ {} \; | sort -k2 -n | tail -20
   sqlite3 appdata/com.example.app/databases/app.db '.schema'
   ```

   Compressibility is a quick entropy proxy: encrypted data barely compresses.

3. **Compare the leading bytes of several blobs.** Random IVs make the first bytes of headerless ciphertext differ every time; a fixed prefix means a header.

   ```bash
   for f in appdata/com.example.app/files/records/*.bin; do xxd -l 8 "$f"; done
   grep -o '"[A-Za-z0-9+/=]\{40,\}"' appdata/com.example.app/shared_prefs/vault.xml | tr -d '"' | head -5 \
     | while read b; do echo "$b" | base64 -d | xxd -l 8; done
   ```

4. **Check for Tink keysets and decode their metadata.** `AndroidKeysetManager` writes a hex string into the preference file you configured; Jetpack Security uses names beginning `__androidx_security_crypto_encrypted_prefs_`.

   ```bash
   grep -rl 'keyset' appdata/com.example.app/shared_prefs/
   # copy the hex value of the keyset entry into keyset.hex, then:
   xxd -r -p keyset.hex | protoc --decode_raw
   ```

   In the decoded `EncryptedKeyset`, field `2` is the encrypted keyset and field `3` the plaintext `KeysetInfo`: field `1` is the primary key ID, and each repeated field `2` describes one key (`1` type URL, `2` status where 1 = enabled, 2 = disabled, 3 = destroyed, `3` key ID, `4` output prefix type where 1 = TINK, 3 = RAW). One `KeyInfo` entry means the keyset has never been rotated.

5. **Check for version columns and versioned wrapped keys.** In the database schema, look for `key_id`, `kek_version`, `key_version` or similar columns, and query their distinct values:

   ```bash
   sqlite3 appdata/com.example.app/databases/app.db 'SELECT kek_version, COUNT(*) FROM wrapped_keys GROUP BY 1;'
   ```

6. **Confirm at runtime what the app writes.** Hook encryption and print the first bytes of each output, together with the key object, to tie headers to keys:

   ```javascript
   // gt-cipher-prefix.js
   Java.perform(function () {
     const Cipher = Java.use('javax.crypto.Cipher');
     function hex(a, n) {
       let s = '';
       for (let i = 0; i < Math.min(n, a.length); i++) s += ('0' + (a[i] & 0xff).toString(16)).slice(-2);
       return s;
     }
     const keys = new Map();
     Cipher.init.overload('int', 'java.security.Key').implementation = function (mode, key) {
       keys.set(this.hashCode(), mode + ' ' + key.getAlgorithm() + ' ' + key.toString());
       return this.init(mode, key);
     };
     Cipher.doFinal.overload('[B').implementation = function (input) {
       const out = this.doFinal(input);
       console.log('[doFinal] ' + (keys.get(this.hashCode()) || '?') + ' -> ' + out.length + ' bytes, head=' + hex(out, 8));
       return out;
     };
   });
   ```

   ```bash
   frida -U -f com.example.app -l gt-cipher-prefix.js
   ```

   Keystore keys generate the IV inside the Keystore, so the `doFinal` output is ciphertext and tag only; the app's own header (if any) is prepended afterwards, so also compare against the bytes that reach disk.

#### Observation

For each data store: whether ciphertexts carry a version or key ID (and where), whether that identifier is authenticated (look for `updateAAD` covering the header in the code), and how many distinct key identifiers or keyset entries exist on a device that has been in use.

#### Evaluation

The test **fails** (as supporting evidence for MASWE-0015) if persistent encrypted data, wrapped keys or signed objects carry no key identifier anywhere — inline, in a column, or via a keyset — so that a second key could not be introduced without guessing. It is a stronger failure if an identifier exists but is not authenticated, or if the reader falls back to trying other keys when the identified one fails.

It **passes** if every persistent ciphertext or wrapped key is tied to an authenticated key identifier, or the app uses a Tink keyset. Seeing more than one identifier on a long-lived install is positive evidence that rotation has actually happened.

False positives: data that is re-downloaded from the server and never needs to be decrypted with an old key (a cache that is simply wiped on rotation) does not need identifiers.

#### Demo

Two record files from a lab app, one written before and one after a rotation:

```text
$ xxd -l 8 records/0001.bin
00000000: 0100 0000 0129 a1f4                      .....)..
$ xxd -l 8 records/0412.bin
00000000: 0100 0000 029c 5e07                      ......^.
```

The first byte (`01`) is a format version; the next four bytes are the key ID (`00000001`, then `00000002`); then the nonce begins. This app passes. The vulnerable counterpart shows nothing constant across files:

```text
$ for f in records/*.bin; do xxd -l 8 "$f"; done
00000000: 5be0 13c9 7a44 0e81                      [...zD..
00000000: e2a7 0b55 9d10 c3f2                      ...U....
00000000: 0c71 ee38 41b9 6d2a                      .q.8A.m*
```

That is `nonce || ciphertext || tag` with nothing identifying the key; together with a constant alias from GT-0015-1 it confirms a single-key design.

### GT-0015-3: Key lifecycle at runtime (Android)

Guler Tech methodology. Platform: Android. Type: dynamic.

#### Overview

This test drives the app through the lifecycle events that should rotate or destroy keys and records what actually happens in the Android Keystore. It turns "the code has a `deleteEntry` somewhere" into "logging out deletes key X and logging in as another user creates key Y".

#### Prerequisites

- A rooted device or emulator with `frida-server` (Frida, [MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/) for method hooking), or a build with the Frida gadget.
- `objection` (optional; it has `android keystore list` and `android keystore watch`).
- Two test accounts, and if the client can provide it, the previous release of the app to test upgrade behaviour.

#### Steps

1. **Load an inventory-and-watch script.** It logs key creation and deletion as they happen and can print the full inventory with creation and validity dates on demand.

   ```javascript
   // gt-keystore-lifecycle.js
   Java.perform(function () {
     const KeyStore = Java.use('java.security.KeyStore');
     const KeyInfo = Java.use('android.security.keystore.KeyInfo');
     const SecretKey = Java.use('javax.crypto.SecretKey');
     const SecretKeyFactory = Java.use('javax.crypto.SecretKeyFactory');
     const KeyFactory = Java.use('java.security.KeyFactory');
     const Builder = Java.use('android.security.keystore.KeyGenParameterSpec$Builder');

     Builder.$init.overload('java.lang.String', 'int').implementation = function (alias, purposes) {
       console.log('[create] alias=' + alias + ' purposes=' + purposes);
       return this.$init(alias, purposes);
     };
     KeyStore.deleteEntry.implementation = function (alias) {
       console.log('[delete] alias=' + alias);
       return this.deleteEntry(alias);
     };

     globalThis.inventory = function () {
       Java.perform(function () {
         const ks = KeyStore.getInstance('AndroidKeyStore');
         ks.load(null, null);
         const e = ks.aliases();
         while (e.hasMoreElements()) {
           const alias = e.nextElement().toString();
           const created = ks.getCreationDate(alias);
           let line = alias + ' created=' + (created ? created.toString() : '?');
           try {
             const key = ks.getKey(alias, null);
             if (key !== null) {
               const alg = key.getAlgorithm();
               const info = SecretKey.class.isInstance(key)
                 ? Java.cast(SecretKeyFactory.getInstance(alg, 'AndroidKeyStore').getKeySpec(Java.cast(key, SecretKey), KeyInfo.class), KeyInfo)
                 : Java.cast(KeyFactory.getInstance(alg, 'AndroidKeyStore').getKeySpec(key, KeyInfo.class), KeyInfo);
               line += ' alg=' + alg +
                 ' validFrom=' + info.getKeyValidityStart() +
                 ' originationEnd=' + info.getKeyValidityForOriginationEnd() +
                 ' consumptionEnd=' + info.getKeyValidityForConsumptionEnd();
             }
           } catch (err) { line += ' (' + err + ')'; }
           console.log(line);
         }
       });
     };
   });
   ```

   ```bash
   frida -U -f com.example.app -l gt-keystore-lifecycle.js
   # in the Frida REPL, after each event:
   inventory()
   ```

   Calling `getKey` on an authentication-bound key does not trigger authentication; only using it does, so the inventory is safe to run.

2. **Run the lifecycle script**, calling `inventory()` after each step and noting `[create]`/`[delete]` lines:

   | Step | Action |
   |---|---|
   | 1 | Fresh install (`adb shell pm clear com.example.app`), first launch |
   | 2 | Log in as user A, use the features that store data |
   | 3 | Log out |
   | 4 | Log in as user B |
   | 5 | Change the password or PIN (if the app has its own) |
   | 6 | Enrol an additional fingerprint in Settings, return to the app |
   | 7 | Upgrade from the previous release (install old build, use it, `adb install -r` the new build) |
   | 8 | Use any "reset", "re-register device" or "delete account" feature |

3. **Check who can still decrypt what.** After step 4, look in storage (GT-0015-2) for user A's encrypted data. If it is still there and user B's session can decrypt it with the same key, the key was not rotated on account switch.

4. **Optional: exercise validity dates.** If keys have `originationEnd` set, move the device clock past it (emulator or test device only) and observe whether the app rotates gracefully, fails with `KeyExpiredException`, or silently generates a new key and loses data.

#### Observation

A timeline: event → aliases created, aliases deleted, inventory after the event (alias, creation date, validity). Keep the Frida log.

#### Evaluation

The test **fails** if:

- user-scoped keys survive logout and are reused for the next account (same alias and creation date after step 4);
- password or PIN change does not produce a new KEK or rewrap (for password-derived designs);
- after biometric enrolment change, the app replaces an invalidated auth-bound key with one that is *not* auth-bound, or keeps working without re-creating the key;
- a server-provisioned key is never refreshed across re-registration or reset;
- validity dates exist but expiry leads to silent key replacement and data loss.

It **passes** if user-scoped keys are destroyed on logout, lifecycle events produce new keys (new alias or version), and old keys are deleted once migration completes.

#### Demo

Frida output from a vulnerable lab app across steps 1 to 4:

```text
[create] alias=local_db_key purposes=3
# inventory() after login as A
local_db_key created=Mon Mar 03 09:14:22 GMT 2025 alg=AES validFrom=null originationEnd=null consumptionEnd=null
# logout: no [delete] line
# inventory() after login as B
local_db_key created=Mon Mar 03 09:14:22 GMT 2025 alg=AES validFrom=null originationEnd=null consumptionEnd=null
```

One key, created on first launch, no validity period, no deletion on logout, shared by both accounts: the test fails. A passing app shows `[delete] alias=vault.kek.u1842.v1` at logout and `[create] alias=vault.kek.u2071.v1` at the next login.

### GT-0015-4: Key lifecycle at runtime (iOS)

Guler Tech methodology. Platform: iOS. Type: dynamic.

#### Overview

The iOS counterpart of GT-0015-3. It adds one check Android does not need: whether keys survive a delete-and-reinstall cycle, because Keychain items do.

#### Prerequisites

- A jailbroken device with `frida-server`, or the app repackaged with the Frida gadget ([MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/) for method hooking).
- `objection` for Keychain dumping ([MASTG-TECH-0061](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0061/)); it only shows items in the app's own access groups.
- Two test accounts.

#### Steps

1. **Dump the Keychain after each lifecycle event** (same table as GT-0015-3, plus reinstall):

   ```bash
   objection -n com.example.app start
   # in the objection REPL:
   ios keychain dump --json keychain-after-login-A.json
   ```

   Older objection releases use `objection -g <bundle-id> explore`. The *Created* column (from `kSecAttrCreationDate`) is the key's age.

2. **Log Keychain writes and deletes** to tie items to code paths:

   ```javascript
   // gt-keychain-lifecycle.js (Frida 17; on older Frida use Module.findExportByName(null, name))
   const exp = (n) => Module.getGlobalExportByName(n);
   ['SecItemAdd', 'SecItemDelete', 'SecItemUpdate'].forEach(function (name) {
     Interceptor.attach(exp(name), {
       onEnter(args) {
         const q = new ObjC.Object(args[0]);
         const pick = ['class', 'svce', 'acct', 'atag', 'labl', 'pdmn', 'agrp', 'tkid'];
         const out = [];
         pick.forEach(function (k) {
           const v = q.objectForKey_(k);
           if (v !== null) out.push(k + '=' + v.toString());
         });
         console.log('[' + name + '] ' + out.join(' '));
       }
     });
   });
   Interceptor.attach(exp('SecKeyCreateRandomKey'), {
     onEnter(args) { console.log('[SecKeyCreateRandomKey] ' + new ObjC.Object(args[0]).toString()); }
   });
   ```

   ```bash
   frida -U -f com.example.app -l gt-keychain-lifecycle.js
   ```

   The short keys are the raw values of the Security constants (`svce` = `kSecAttrService`, `acct` = `kSecAttrAccount`, `atag` = `kSecAttrApplicationTag`, `pdmn` = `kSecAttrAccessible`, `agrp` = `kSecAttrAccessGroup`, `tkid` = `kSecAttrTokenID`). Application tags are `Data` and print as hex.

3. **Reinstall test.** Note the creation dates of the app's key items, delete the app, reinstall the same build, log in, and dump again. Items whose *Created* date predates the reinstall were inherited from the previous install.

4. **Account switch.** As on Android, check whether user A's encrypted data remains readable after user B logs in.

#### Observation

Per event: Keychain items added, updated, deleted (service/account or tag), creation dates before and after, and the reinstall result.

#### Evaluation

The test **fails** if key items survive logout and are reused by the next account, if a reinstall reuses key items from the previous install without the app deliberately migrating them, or if Secure Enclave keys registered with the backend are never replaced on re-registration. It **passes** if the app purges stale items on first launch after install, destroys user-scoped keys on logout, and creates new, versioned items on lifecycle events.

#### Demo

Vulnerable Swift: the key is created once and nothing deletes it on logout or reinstall.

```swift
func storageKey() throws -> SymmetricKey {
    if let data = try? keychainRead(service: "com.example.vault", account: "storage-key") {
        return SymmetricKey(data: data)
    }
    let key = SymmetricKey(size: .bits256)
    try keychainWrite(service: "com.example.vault", account: "storage-key",
                      data: key.withUnsafeBytes { Data($0) })
    return key
}
```

objection after deleting and reinstalling the app on 9 November 2026:

```text
Created                    Accessible      ACL    Type      Account      Service            Data
-------------------------  --------------  -----  --------  -----------  -----------------  ----------------
2024-02-11 18:02:37 +0000  AfterFirstUnlock  None   Password  storage-key  com.example.vault  (failed to decode)
```

The storage key was created in February 2024, has survived at least one reinstall, carries no version, and uses a migratable accessibility class: the test fails (the accessibility class itself is a [MASWE-0016](/mobile/maswe-0016-key-access-not-restricted/) issue).

### GT-0015-5: Rotation readiness of server keys the app trusts (Android, iOS)

Guler Tech methodology. Platform: Android and iOS. Type: static and network.

#### Overview

This test checks whether the backend *could* rotate the keys the app trusts without breaking installed apps: TLS pins, embedded public keys for signed content, and JWT verification keys. The test does not need the server's private keys; it inspects how many keys the app trusts, how it selects them, and whether the set can change.

#### Prerequisites

- Decompiled app (jadx/apktool, or the extracted IPA and its `Info.plist`).
- An interception proxy (mitmproxy or Burp) with the app's pinning disabled for the network part, used only to observe signed payloads.
- `openssl` for computing SPKI hashes; `plutil` on macOS for plists.

#### Steps

1. **Collect pins.**

   ```bash
   # Android: Network Security Configuration and OkHttp CertificatePinner
   grep -o 'networkSecurityConfig="[^"]*"' res_out/AndroidManifest.xml
   cat res_out/res/xml/network_security_config.xml
   grep -rn 'sha256/' out/sources/ | grep -v '^out/sources/okhttp3/'
   # iOS: ATS pinning and TrustKit
   plutil -p ipa/Payload/App.app/Info.plist | grep -A20 -E 'NSPinnedDomains|TSKConfiguration'
   ```

2. **Compare pins with what the servers present.** Compute the SPKI hash of each first-party server's leaf and intermediates:

   ```bash
   H=api.example.com
   openssl s_client -connect $H:443 -servername $H -showcerts </dev/null 2>/dev/null \
     | awk '/BEGIN CERT/{n++} {print > ("cert" n ".pem")}'
   for c in cert*.pem; do
     printf '%s  ' "$c"
     openssl x509 -in "$c" -pubkey -noout | openssl pkey -pubin -outform der \
       | openssl dgst -sha256 -binary | base64
   done
   ```

   For each pinned domain, record which pins match a certificate currently served, and how many pins match *nothing* currently served — those are the backup pins. Check any `expiration` date in the NSC against today (that part is OWASP [MASTG-TEST-0243](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0243/)).

3. **Find embedded verification keys.**

   ```bash
   grep -rnE 'BEGIN PUBLIC KEY|X509EncodedKeySpec|"kty"\s*:|jwks|\.well-known/' out/sources/ res_out/ | grep -vE '/(androidx|kotlin|okhttp3)/'
   grep -rnE 'Signature\.getInstance|initVerify\(' out/sources/com/example
   rabin2 -i "$BIN" | grep -E 'SecKeyCreateWithData|SecKeyVerifySignature'
   rabin2 -zz "$BIN" | grep -E 'BEGIN PUBLIC KEY|jwks|well-known'
   ```

   For each key, read the verification code: does it select a key by `kid` from a set, or verify against one constant? Is there any mechanism to add or revoke keys? For JWTs, does the app use a JWKS endpoint, a single embedded public key, or a shared HMAC secret?

4. **Observe signed payloads in traffic.** With interception set up, capture the remote config, OTA bundle manifest or other signed objects. Note whether they carry a key ID and expiry. If they carry a `kid`, modify it to an unknown value (leaving the signature intact) and check that the app rejects the object rather than falling back to a default key.

#### Observation

Per trust anchor: number of trusted keys, whether a backup exists that is not currently deployed, key selection method (`kid` lookup or single key), update and revocation mechanism, and expiry handling.

#### Evaluation

The test **fails** if any first-party trust anchor that protects something security-relevant is a single key with no backup and no authenticated update path — one pinned key per domain with no backup, one embedded public key verifying config or code with no `kid` support, a JWT verification key compiled in, or a shared HMAC secret. It also fails if the app ignores `kid` and falls back to any key that verifies. Pins without backups are primarily a MASWE-0028 availability issue; report them here only where they demonstrably block key rotation.

It **passes** if each trust anchor is a set with at least one undeployed backup or pre-distributed successor, keys are selected by identifier, and the set can be updated or revoked through an authenticated channel or app update.

#### Demo

A Network Security Configuration that pins only the current leaf key:

```xml
<network-security-config>
  <domain-config cleartextTrafficPermitted="false">
    <domain includeSubdomains="true">api.example.com</domain>
    <pin-set>
      <pin digest="SHA-256">LEAF_SPKI_SHA256_BASE64</pin>
    </pin-set>
  </domain-config>
</network-security-config>
```

And config verification against one constant key:

```kotlin
private val CONFIG_KEY: PublicKey = KeyFactory.getInstance("EC")
    .generatePublic(X509EncodedKeySpec(Base64.decode(BuildConfig.CONFIG_PUBKEY, Base64.DEFAULT)))

fun verifyConfig(payload: ByteArray, sig: ByteArray): Boolean =
    Signature.getInstance("SHA256withECDSA").run { initVerify(CONFIG_KEY); update(payload); verify(sig) }
```

Step 2 output for the pinned domain:

```text
cert1.pem  LEAF_SPKI_SHA256_BASE64          <- matches the only pin
cert2.pem  INTERMEDIATE_SPKI_SHA256_BASE64   <- not pinned
```

One pin, matching the currently deployed leaf, no backup; one config-signing key with no identifier and no update path. If either key is compromised or must be replaced, every installed version breaks or keeps trusting the old key until users update: the test fails.

### GT-0015-6: APK signing key lineage (Android)

Guler Tech methodology, building on OWASP [MASTG-TEST-0224](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0224/) and [MASTG-KNOW-0003](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0003/). Platform: Android. Type: static.

#### Overview

Checks whether the app is signed in a way that permits signing-key rotation (v3), whether it has ever rotated, and whether the app's own signature checks would survive a rotation.

#### Prerequisites

- The release APK as distributed (from the store or the client), Android SDK build-tools (`apksigner`), and the jadx output.

#### Steps

1. **List schemes and signers.**

   ```bash
   apksigner verify -v --print-certs app.apk
   ```

   Look at the "Verified using v1/v2/v3/v3.1 scheme" lines and the signer certificate digests. If the v3 signer differs from the v1/v2 signer, the app has rotated and carries a lineage.

2. **Record the signing certificate's age and key type** from the `apksigner` output (certificate DN, digests, key algorithm and size); an RSA 1024 or very old certificate is a reason to want rotation.

3. **Check the app's own signature verification**, if it has one:

   ```bash
   grep -rnE 'GET_SIGNATURES|GET_SIGNING_CERTIFICATES|signingInfo|getSigningCertificateHistory|getApkContentsSigners|hasSigningCertificate' out/sources/com/example
   ```

   A comparison of `signatures[0]` or `apkContentsSigners[0]` with one hardcoded hash will fail after rotation; a check against `getSigningCertificateHistory()` or `hasSigningCertificate` will not.

4. **Ask** whether the app uses Play App Signing (and who holds the upload key), or where the release key is held.

#### Observation

Schemes present, signer certificates per scheme, certificate dates and key type, presence of a lineage, and how the app's runtime signature check (if any) handles lineage.

#### Evaluation

This is usually an observation rather than a finding. Report it as a **finding** when there is a reason the key should be rotatable and is not: the APK is signed only with v1/v2 and the signing key is weak (for example RSA 1024 or SHA-1 based), held insecurely, or known to be exposed; or the app's runtime signature check pins a single certificate in a way that blocks rotation. It **passes** if the app is signed with v2 and v3 (and v3.1 where relevant), the key is held under Play App Signing or equivalent custody, and any runtime check is lineage-aware.

#### Demo

A runtime tamper check that prevents rotation:

```kotlin
val expected = "3f1c...e29a"   // SHA-256 of the 2016 release certificate, truncated here
val info = pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
val cert = info.signingInfo.apkContentsSigners[0].toByteArray()
if (sha256Hex(cert) != expected) killApp()
```

`apksigner verify -v --print-certs` on the same build shows v1, v2 and v3 verified with a single signer and no lineage. The certificate cannot be rotated without first shipping a version whose check accepts both keys; record it, and raise its severity only if the key's custody is in doubt.

### GT-0015-7: Key management policy and process evidence

Guler Tech methodology. Platform: both, and the backend. Type: documentation review and interview.

#### Overview

Rotation is partly a process control: someone has to decide cryptoperiods, run the rotation, and respond to compromise. A tester can see the mechanisms in the app but not whether anybody ever pulls the lever. This test collects evidence from the client so that the finding (or the pass) does not rest on assumption.

#### Prerequisites

- A point of contact on the client side who owns cryptography or platform security, ideally with backend access.
- Your key inventory from GT-0015-1 and GT-0015-5, so the questions are specific.

#### Steps

1. **Request the key management policy** (or the relevant section of the security standard) and check that it defines, per key type: owner, purpose, algorithm and size, storage, cryptoperiod (OUP/RUP or equivalent), rotation triggers, and destruction.
2. **Request the key inventory** and reconcile it with yours. Keys you found that are not in their inventory are usually the ones nobody rotates.
3. **Ask for rotation evidence** for the keys that matter: date of the last rotation of the config-signing key, the TLS keys behind pinned domains, any server-provisioned client keys. Ask for configuration evidence for KMS-held keys, for example:

   ```bash
   aws kms get-key-rotation-status --key-id <key-id>
   gcloud kms keys describe <key> --keyring <ring> --location <loc> --format='value(rotationPeriod,nextRotationTime)'
   az keyvault key rotation-policy show --vault-name <vault> --name <key>
   ```

4. **Walk through the compromise playbook** for one client-relevant key: how would they revoke it, how do installed apps learn about it, what is the minimum supported app version mechanism, and how long would old versions keep trusting it?
5. **Pins and signing keys:** who holds the backup pin's private key, where, and when the pin set was last reviewed; whether Play App Signing is used and who holds the upload key.

#### Observation

Documents received (titles, versions, dates), answers per question, and gaps between the client's inventory and yours.

#### Evaluation

The test **fails** if there are no defined cryptoperiods or rotation procedures for keys in scope, if the client cannot show that a key with a defined cryptoperiod has ever been rotated, or if there is no way to revoke and replace a compromised client-trusted key short of an app release. It **passes** if cryptoperiods are defined and evidenced, and the compromise playbook covers the mobile client.

#### Demo

Example wording for a report when the mechanisms exist but the process does not:

```text
Finding: Cryptoperiods not defined for client-trusted keys (MASWE-0015)
The application verifies remote configuration with an ECDSA P-256 key selected by
key ID and ships a backup pin for api.example.com, so rotation is technically
possible (GT-0015-1, GT-0015-5: pass). However, the client confirmed that the
configuration-signing key has not been rotated since it was created in 2021, that no
cryptoperiod is defined for it, and that the backup pin's private key location is
unknown (GT-0015-7: fail). Recommendation: define cryptoperiods per NIST SP 800-57
Part 1 Rev. 5, record custody of backup keys, and rehearse a rotation.
```

## Secure implementation

The patterns below are deliberately small. They show the moving parts of rotation — versioned identifiers, rewrapping, retirement, trust sets — and assume you already store keys correctly as described in our [MASWE-0003 note](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/#secure-implementation).

### Android: versioned KEKs with rewrapping

KEKs live in the Keystore under `vault.kek.v<N>`. DEKs are wrapped with AES-GCM and the wrapped record stores the KEK version, which is also bound into the associated data. Rotation creates `v<N+1>`, rewraps every DEK, and deletes the old versions only when nothing references them.

```kotlin
class KekRing(private val prefix: String = "vault.kek.v") {
    private val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun versions(): List<Int> =
        ks.aliases().toList().filter { it.startsWith(prefix) }
            .mapNotNull { it.removePrefix(prefix).toIntOrNull() }.sorted()

    fun current(): Int = versions().lastOrNull() ?: create(1)

    fun create(version: Int, originationDays: Long = 365): Int {
        val originationEnd = Date(System.currentTimeMillis() + originationDays * 86_400_000L)
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder("$prefix$version",
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeyValidityForOriginationEnd(originationEnd)   // no new wrapping after this date
                .build()
        )
        gen.generateKey()
        return version
    }

    fun key(version: Int): SecretKey = ks.getKey("$prefix$version", null) as SecretKey
    fun destroy(version: Int) = ks.deleteEntry("$prefix$version")
}

data class WrappedDek(val dekId: String, val kekVersion: Int, val blob: ByteArray)  // blob = iv || ct || tag

private fun aad(dekId: String, v: Int) = "dek:$dekId:kek:$v".toByteArray()

fun wrap(ring: KekRing, dekId: String, dek: ByteArray): WrappedDek {
    val v = ring.current()
    val c = Cipher.getInstance("AES/GCM/NoPadding")
    c.init(Cipher.ENCRYPT_MODE, ring.key(v))
    c.updateAAD(aad(dekId, v))
    return WrappedDek(dekId, v, c.iv + c.doFinal(dek))
}

fun unwrap(ring: KekRing, w: WrappedDek): ByteArray {
    val c = Cipher.getInstance("AES/GCM/NoPadding")
    c.init(Cipher.DECRYPT_MODE, ring.key(w.kekVersion), GCMParameterSpec(128, w.blob, 0, 12))
    c.updateAAD(aad(w.dekId, w.kekVersion))
    return c.doFinal(w.blob, 12, w.blob.size - 12)
}

fun rotateKek(ring: KekRing, store: DekStore) {
    val next = ring.create(ring.current() + 1)
    for (w in store.all()) {
        if (w.kekVersion == next) continue
        val dek = unwrap(ring, w)
        try { store.put(wrap(ring, w.dekId, dek)) } finally { dek.fill(0) }
    }
    if (store.all().all { it.kekVersion == next }) {
        ring.versions().filter { it < next }.forEach(ring::destroy)   // retire superseded KEKs
    }
}
```

`DekStore` is whatever persists wrapped DEKs (a small table or file); its `put` must be atomic per record so an interrupted rotation can resume. Run `rotateKek` when the current KEK's origination period ends (catch `KeyExpiredException` on wrap and rotate, never just regenerate), on a schedule, or when the backend signals a key-version revocation. Add `setUserAuthenticationRequired`/`setUnlockedDeviceRequired` as your access policy demands — see [MASWE-0016](/mobile/maswe-0016-key-access-not-restricted/).

### Android: Tink keyset rotation

If you can use Tink, let the keyset carry versions for you. API names below are from Tink Java 1.x; they have shifted between releases, so check them against your version.

```kotlin
AeadConfig.register()

val manager = AndroidKeysetManager.Builder()
    .withSharedPref(context, "vault_keyset", "vault_keyset_prefs")
    .withKeyTemplate(KeyTemplates.get("AES256_GCM"))
    .withMasterKeyUri("android-keystore://vault_master_key")
    .build()

fun aead(): Aead = manager.keysetHandle.getPrimitive(RegistryConfiguration.get(), Aead::class.java)
// aead().encrypt(plaintext, associatedData) -> 0x01 || 4-byte key id || iv || ciphertext || tag

private fun keyIds(h: KeysetHandle): Set<Int> = (0 until h.size()).map { h.getAt(it).id }.toSet()

fun rotate(): Int {
    val before = keyIds(manager.keysetHandle)
    manager.add(KeyTemplates.get("AES256_GCM"))
    val added = (keyIds(manager.keysetHandle) - before).single()
    manager.setPrimary(added)          // new data now uses the new key; old keys still decrypt
    return added
}

fun retire(oldKeyId: Int) {
    manager.disable(oldKeyId)          // after re-encryption: old ciphertexts no longer accepted
    // later, once you are sure nothing needs it:
    // manager.destroy(oldKeyId)
}
```

Re-encrypt lazily (decrypt and write back on read) or in a resumable background job before disabling the old key. Remember that the Keystore master key protecting the keyset is a separate KEK with its own lifecycle.

### iOS: versioned Keychain KEK and rewrapping

The same pattern with CryptoKit and the Keychain. For high-assurance keys, replace the Keychain-stored `SymmetricKey` KEK with a Secure Enclave KEK as shown in our [MASWE-0003 note](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/#ios-envelope-encryption-with-a-secure-enclave-kek); the versioning logic does not change.

```swift
import CryptoKit
import Foundation
import Security

enum KekRing {
    static let service = "com.example.vault.kek"
    static func account(_ v: Int) -> String { "kek.v\(v)" }

    static func create(version v: Int) throws -> SymmetricKey {
        let key = SymmetricKey(size: .bits256)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account(v),
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String: key.withUnsafeBytes { Data($0) }
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(status)) }
        return key
    }

    static func load(version v: Int) throws -> SymmetricKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account(v),
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var out: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &out)
        guard status == errSecSuccess, let data = out as? Data else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
        return SymmetricKey(data: data)
    }

    static func destroy(version v: Int) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account(v)
        ]
        SecItemDelete(query as CFDictionary)
    }
}

struct WrappedDek: Codable { let dekId: String; let kekVersion: Int; let box: Data }

func wrap(_ dek: SymmetricKey, id: String, version v: Int) throws -> WrappedDek {
    let kek = try KekRing.load(version: v)
    let aad = Data("dek:\(id):kek:\(v)".utf8)
    let sealed = try AES.GCM.seal(dek.withUnsafeBytes { Data($0) }, using: kek, authenticating: aad)
    return WrappedDek(dekId: id, kekVersion: v, box: sealed.combined!)   // non-nil with the default 12-byte nonce
}

func unwrap(_ w: WrappedDek) throws -> SymmetricKey {
    let kek = try KekRing.load(version: w.kekVersion)
    let aad = Data("dek:\(w.dekId):kek:\(w.kekVersion)".utf8)
    return SymmetricKey(data: try AES.GCM.open(AES.GCM.SealedBox(combined: w.box), using: kek, authenticating: aad))
}

func rotate(from old: Int, deks: [WrappedDek], save: (WrappedDek) throws -> Void) throws {
    let next = old + 1
    _ = try KekRing.create(version: next)
    for w in deks where w.kekVersion != next {
        try save(try wrap(try unwrap(w), id: w.dekId, version: next))
    }
    for v in 1...old { KekRing.destroy(version: v) }   // only after every DEK has been saved
}
```

Purge Keychain items left by a previous install on first launch, before creating any keys:

```swift
let purgedFlag = "keychainPurgedForThisInstall"
if !UserDefaults.standard.bool(forKey: purgedFlag) {
    for cls in [kSecClassGenericPassword, kSecClassKey] {
        SecItemDelete([kSecClass as String: cls] as CFDictionary)   // app's own access groups only
    }
    UserDefaults.standard.set(true, forKey: purgedFlag)
}
```

If the app shares a Keychain access group with other apps or extensions, scope the delete with `kSecAttrAccessGroup` and `kSecAttrService` so you do not wipe items you do not own.

### Both platforms: trusting a rotating set of server keys

Verify signed content against a set of keys selected by identifier, ship the next key before it is used, and treat an unknown identifier as a failure, not a reason to try other keys.

```kotlin
class TrustedKeys(private val keys: Map<String, PublicKey>, private val revoked: Set<String>) {
    fun verify(kid: String, payload: ByteArray, sig: ByteArray): Boolean {
        if (kid in revoked) return false
        val key = keys[kid] ?: return false
        return Signature.getInstance("SHA256withECDSA").run { initVerify(key); update(payload); verify(sig) }
    }
}

// Shipped in the app: the active key and its pre-distributed successor.
val configKeys = TrustedKeys(
    keys = mapOf("cfg-2026a" to loadKey(R.raw.cfg_2026a), "cfg-2027a" to loadKey(R.raw.cfg_2027a)),
    revoked = emptySet()
)
```

For TLS pins, pin SPKI hashes and include at least one backup key that is not deployed:

```xml
<network-security-config>
  <domain-config cleartextTrafficPermitted="false">
    <domain includeSubdomains="true">api.example.com</domain>
    <pin-set expiration="2027-12-31">
      <pin digest="SHA-256">CURRENT_SPKI_SHA256_BASE64</pin>
      <pin digest="SHA-256">BACKUP_SPKI_SHA256_BASE64</pin>
    </pin-set>
  </domain-config>
</network-security-config>
```

Decide deliberately what the `expiration` should be: it protects old app versions from bricking, at the cost of silently disabling pinning after that date. On iOS, `NSPinnedDomains` takes the same two-pin approach without an expiry. For JWTs, fetch keys from the issuer's `jwks_uri`, cache them, select by `kid`, and refresh on an unknown `kid` at most every few minutes.

### Both platforms: rotation on logout and compromise

- **Logout and account switch:** delete user-scoped Keystore aliases or Keychain items (or the KEK, crypto-shredding the data), delete wrapped DEKs, and destroy Tink keysets scoped to the user. Re-create on next login.
- **Device re-registration:** generate a new device-binding key pair, register the new public key, and have the backend revoke the old one in the same transaction.
- **Compromise lever:** include a key version in authenticated API responses (or a "minimum key version" in signed config). When the backend raises it, the app rotates its local keys and fetches new server-provisioned keys; the backend stops accepting material from revoked versions.
- **Record cryptoperiods in code and policy:** a constant such as `KEK_ORIGINATION_DAYS` next to the key definition, matching the key management policy, makes the period reviewable.

## Rating findings

Rate on what the unrotatable key protects, how widely it is shared, and how hard it would be to recover from its compromise. Rotation findings are about blast radius and recoverability; they rarely stand alone as an exploit, so a concrete exposure path (an extracted key, a leaked backup, a rooted device) should drive the higher ratings.

| Rating | Conditions |
|---|---|
| **Critical** | A key that verifies **code or security-relevant configuration** (OTA bundles, remote config controlling security features, update manifests) or that the backend trusts for authentication, with no rotation or revocation path, **and** evidence or a credible path to its compromise (key in the package, key exposed in a public repository, a known incident). Also: a key known or suspected to be compromised that is still active. |
| **High** | A **static key shared by every install** (hardcoded or derived from public values) protecting sensitive data or backend trust, so rotation needs a release and old versions keep the key indefinitely. A single trust anchor (one config-signing key, a compiled-in JWT key, an HMAC secret) for a security-relevant function with no `kid` support or update path. |
| **Medium** | Device-scoped keys protecting sensitive data with no versioning and no rotation on logout or account switch, so the next user inherits the key and any leftover ciphertext. iOS keys reused across reinstall. Server-provisioned client keys never refreshed. No defined cryptoperiods or rotation evidence for client-trusted keys in an L2 or EUDIW scope (GT-0015-7). |
| **Low** | Per-install, Keystore- or Keychain-held keys with no version identifier in the ciphertext format but a feasible migration path; superseded keys kept longer than necessary but no longer used for new operations; a single pin with no backup where pinning is a defence-in-depth control only; v3 signing absent with a well-protected key. |
| **Info** | Rotation implemented but the cryptoperiod undocumented; a Tink keyset that has never been rotated in a young app; APK signing key never rotated with no reason to rotate it; a lineage-unaware runtime signature check (note for the developers' rotation planning). |

When you report, state the key, what it protects, how long it has been in use (creation date from the Keystore or Keychain, certificate dates, or the client's answer), whether it is shared across installs, and what a compromise would require to recover from — a server switch, a forced update, or data loss. That last point is usually what persuades a client to fund rotation.

## References

- OWASP MASWE — [MASWE-0015: Cryptographic Key Rotation Not Implemented](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0015/) (CC BY-SA 4.0)
- OWASP MASWE — [MASWE-0028: Insecure Identity Pinning](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0028/) (CC BY-SA 4.0)
- OWASP MAS Profiles — [MAS-L2](https://mas.owasp.org/Profiles/MAS-L2/) and [MAS-EUDIW](https://mas.owasp.org/Profiles/MAS-EUDIW/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0003: App Signing](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0003/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0015: Certificate Pinning](https://mas.owasp.org/MASTG/knowledge/android/MASVS-NETWORK/MASTG-KNOW-0015/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0043: Android KeyStore](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0043/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0047: Cryptographic Key Storage](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0047/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0072: Server Trust Evaluation](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-NETWORK/MASTG-KNOW-0072/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-BEST-0006: Use Up-to-Date APK Signing Schemes](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0006/) and [MASTG-BEST-0050: Store Data Encrypted in App Sandbox Directory](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0050/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-TEST-0224](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0224/), [MASTG-TEST-0242](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0242/), [MASTG-TEST-0243](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0243/), [MASTG-TEST-0385](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0385/), and legacy (MASTG v1) [MASTG-TEST-0038](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0038/) (CC BY-SA 4.0)
- OWASP MASTG — techniques [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0061](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0061/), [MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/) (CC BY-SA 4.0)
- [NIST SP 800-57 Part 1 Rev. 5 — Recommendation for Key Management: Part 1 – General](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf) (cryptoperiods, section 5.3; key states, section 7)
- [NIST SP 800-38D — Recommendation for Block Cipher Modes of Operation: GCM and GMAC](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf) (invocation limits, section 8.3)
- [Google Tink — Key rotation](https://developers.google.com/tink/managing-key-rotation) and [Tink documentation](https://developers.google.com/tink)
- [Android Developers — `KeyGenParameterSpec.Builder`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder), [`KeyInfo`](https://developer.android.com/reference/android/security/keystore/KeyInfo), [`SigningInfo`](https://developer.android.com/reference/android/content/pm/SigningInfo)
- [Android Developers — APK Signature Scheme v3](https://source.android.com/docs/security/features/apksigning/v3) and [`apksigner`](https://developer.android.com/tools/apksigner)
- [Android Developers — Network security configuration: certificate pinning](https://developer.android.com/privacy-and-security/security-config#CertificatePinning)
- [Apple — Keychain services](https://developer.apple.com/documentation/security/keychain_services), [Storing CryptoKit keys in the keychain](https://developer.apple.com/documentation/cryptokit/storing-cryptokit-keys-in-the-keychain)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) (`jwks_uri`) and [RFC 7517 — JSON Web Key](https://www.rfc-editor.org/rfc/rfc7517)
- [OWASP Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html)
- [CWE-324: Use of a Key Past its Expiration Date](https://cwe.mitre.org/data/definitions/324.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
