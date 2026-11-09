---
title: "Lack of Non-Repudiation for Critical Actions (MASWE-0025)"
date: 2026-11-09 08:31:00 +0000
subcategory: auth
summary: "Transaction signing with attested, user-authenticated keys, Protected Confirmation, what to sign, server checks and audit logs: testing non-repudiation."
refs: [MASWE-0025, MASVS-AUTH-3, CWE-451, CWE-778]
tags: [android, ios, masvs-auth, non-repudiation, transaction-signing, key-attestation]
---

This note is part of our [MASVS-AUTH guide](/mobile/masvs-auth-authentication-guide/) and covers OWASP [MASWE-0025](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0025/): critical actions — a payment, a high-value transfer, a signature in an identity wallet — approved in a way that leaves no reliable evidence of *who* approved *what*. When such an action is later disputed, the service provider has a bearer token in a log, a "confirmed" flag in a database and the user's word against theirs. When it is abused, the user approved one thing on screen while the app, an overlay or a compromised OS sent another. Non-repudiation answers both problems with the same mechanism: the user's approval produces a signature, made with a key only the user can use, over exactly the transaction they were shown, which the server verifies and keeps. Below you will find what non-repudiation means technically and (modestly) legally, why MACs and tokens do not provide it, how to sign with Android Keystore keys, Android Protected Confirmation and Secure Enclave keys, what to sign, what the server and its audit log must do, eight tests, and severity guidance.

> **Note:** At the time of writing, MASWE-0025 has no linked Knowledge pages or Tests on mas.owasp.org; the weakness page says "No Tests Yet". We searched the MASTG knowledge, tests, beta tests, techniques, best practices and demos; there is no MASTG material on Android Protected Confirmation, and the related items are listed in [Related OWASP material](#related-owasp-material). The Knowledge and Testing sections below are **Guler Tech methodology**, citing OWASP IDs only where the material exists. We are not lawyers: the legal remarks below describe the regulatory landscape at a high level and are not legal advice.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Generic: Non-repudiation, technically and legally (Guler Tech)](#generic-non-repudiation-technically-and-legally-guler-tech)
  - [Generic: Why MACs, bearer tokens and DPoP are not enough (Guler Tech)](#generic-why-macs-bearer-tokens-and-dpop-are-not-enough-guler-tech)
  - [Generic: eIDAS, qualified signatures and the EUDI Wallet (Guler Tech)](#generic-eidas-qualified-signatures-and-the-eudi-wallet-guler-tech)
  - [Generic: What you see is what you sign (MASTG-KNOW-0022)](#generic-what-you-see-is-what-you-sign-mastg-know-0022)
  - [Generic: What to sign (Guler Tech)](#generic-what-to-sign-guler-tech)
  - [Android: User-authenticated signing keys and key attestation (MASTG-KNOW-0043, MASTG-KNOW-0044)](#android-user-authenticated-signing-keys-and-key-attestation-mastg-know-0043-mastg-know-0044)
  - [Android: Protected Confirmation (Guler Tech)](#android-protected-confirmation-guler-tech)
  - [iOS: Secure Enclave signing keys and App Attest (MASTG-KNOW-0057, MASTG-KNOW-0066)](#ios-secure-enclave-signing-keys-and-app-attest-mastg-know-0057-mastg-know-0066)
  - [Generic: Server-side verification and the evidence record (Guler Tech)](#generic-server-side-verification-and-the-evidence-record-guler-tech)
- [Testing](#testing)
  - [Related OWASP material](#related-owasp-material)
  - [What you can prove from the client](#what-you-can-prove-from-the-client)
  - [GT-0025-1: Critical-action inventory and evidence map (Android, iOS)](#gt-0025-1-critical-action-inventory-and-evidence-map-android-ios)
  - [GT-0025-2: Does the request carry a user signature (Android, iOS)](#gt-0025-2-does-the-request-carry-a-user-signature-android-ios)
  - [GT-0025-3: Signing-key properties and attestation (Android)](#gt-0025-3-signing-key-properties-and-attestation-android)
  - [GT-0025-4: Signing-key properties (iOS)](#gt-0025-4-signing-key-properties-ios)
  - [GT-0025-5: What is signed versus what is shown (Android, iOS)](#gt-0025-5-what-is-signed-versus-what-is-shown-android-ios)
  - [GT-0025-6: Server rejects altered, unsigned, replayed and foreign signatures (Android, iOS)](#gt-0025-6-server-rejects-altered-unsigned-replayed-and-foreign-signatures-android-ios)
  - [GT-0025-7: Use of Android Protected Confirmation (Android)](#gt-0025-7-use-of-android-protected-confirmation-android)
  - [GT-0025-8: Evidence retention and audit logging (Android, iOS)](#gt-0025-8-evidence-retention-and-audit-logging-android-ios)
- [Secure implementation](#secure-implementation)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

MASWE-0025 applies when a critical action can be approved without a confirmation path that produces cryptographic evidence of what the user saw and approved. The OWASP requirement is *"The app ensures non-repudiation for critical actions."* OWASP describes the target state as two properties:

1. **A trusted confirmation path.** The user is shown exactly what they are approving through a path that a tampered app, an overlay or a compromised operating system cannot alter.
2. **Cryptographic evidence of the approval.** The confirmation produces a signature, with an attested hardware-backed key, over the message that was shown, which the server verifies and retains.

On Android, Android Protected Confirmation was designed to provide both: a prompt rendered by a trusted UI in the Trusted Execution Environment (TEE), and a Keystore key that will only sign the exact message the user confirmed there. OWASP's weakness page warns that its interface definition has been deprecated and that it is not guaranteed to work on current devices; we look at what that means [below](#android-protected-confirmation-guler-tech). iOS offers no equivalent trusted-UI API to third-party apps. For most apps, then, the realistic target is OWASP's second mitigation, "the strongest available alternative": **transaction signing with a hardware-backed, user-authenticated, attested key over the exact transaction shown in the app**, verified and stored by the server.

The attacks OWASP lists for MASWE-0025 are both about the gap between what the user sees and what is executed:

- **MAS-ATTACK-0036:** displaying overlays or tampering with the UI to alter what the user sees while approving an action — banking malware drawing over the app on Android, or a repackaged app showing one payee and paying another.
- **MAS-ATTACK-0037:** manipulating a compromised OS to alter or fabricate the confirmation flow — root-level malware or instrumentation changing the transaction between the screen and the signing call, or calling the signing key directly.

OWASP's threat is MAS-THREAT-0025: *"Attackers can obtain user approval for actions different from what the user intended."* The mirror-image risk is the user who approved an action and later denies it. Both are addressed by evidence that binds a specific user, a specific transaction and a specific moment.

The weakness maps to MASVS-AUTH-3 ("The app secures sensitive operations with additional authentication") and to two CWEs: [CWE-451: User Interface (UI) Misrepresentation of Critical Information](https://cwe.mitre.org/data/definitions/451.html), for the "what you see" half, and [CWE-778: Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html), for the evidence half. It is tagged with the [MAS-L2](https://mas.owasp.org/Profiles/MAS-L2/) and [MAS-EUDIW](https://mas.owasp.org/Profiles/MAS-EUDIW/) profiles: banking and payment apps, and European Digital Identity Wallets, where signatures and credential presentations are the product.

MASWE-0025 builds on its neighbours, and this note links rather than repeats them. Requiring authentication for the action at all is [MASWE-0023](/mobile/maswe-0023-step-up-authentication-not-implemented/). Restricting the signing key to authenticated use is [MASWE-0016](/mobile/maswe-0016-key-access-not-restricted/). Signing correctly (algorithms, nonces, key separation) is [MASWE-0010](/mobile/maswe-0010-improper-signature-generation/), and verifying correctly is [MASWE-0011](/mobile/maswe-0011-improper-signature-verification/). The biometric prompt mechanics are in [MASWE-0020](/mobile/maswe-0020-local-authentication-bypass/), [MASWE-0021](/mobile/maswe-0021-non-biometric-fallback-for-sensitive-transactions/) and [MASWE-0022](/mobile/maswe-0022-keys-not-invalidated-on-biometric-enrollment/). What MASWE-0025 adds is the question: *if this action were disputed tomorrow, what could the service provider prove, and could the user have been shown something else?*

## Modes of Introduction

OWASP lists two modes of introduction:

**No trusted confirmation path.** Critical actions are confirmed through the ordinary app UI. On a healthy device that is usually fine; on a device with overlay malware, a repackaged app or a compromised OS, the screen can say "£25 to Alice" while the request says "£2,500 to Mallory". Without a trusted UI, the app cannot prove which one the user saw.

**No cryptographic evidence of approval.** The action completes with no hardware-backed signature binding the message to the user's approval. The app owner holds an access token, an IP address and a timestamp, none of which prove that the user, rather than someone with their session or their unlocked phone, approved this specific transaction.

The concrete shapes we find in mobile apps:

- **Bearer token only.** The "confirm" call is an authenticated `POST` with the same token every other call uses. Whoever had the token could have made it.
- **Shared-secret MAC.** The app "signs" requests with an HMAC key that the server also holds (or that is hardcoded in the app). Either side could have produced the tag, so it proves nothing to a third party ([MASWE-0009](/mobile/maswe-0009-improper-use-of-mac/) covers MAC misuse in general).
- **Signature without user authentication.** A Keystore or Secure Enclave key signs transactions, but it is usable without the user (no `setUserAuthenticationRequired`, no `.biometryCurrentSet`), or only behind an event-bound prompt. Malware or a person holding the unlocked phone produces valid signatures ([MASWE-0016](/mobile/maswe-0016-key-access-not-restricted/)).
- **Signature over the wrong data.** The signature covers a server nonce, a session ID or a transaction ID, but not the amount and payee; or it covers fields the server then ignores in favour of unsigned fields elsewhere in the request.
- **Blind signing.** The server sends an opaque blob to sign; the app signs it without parsing it, and displays transaction details from a *different* field. What is shown and what is signed are not tied together.
- **Display and signed data diverge.** Rounding, currency formatting, truncated IBANs, a payee *nickname* shown while the signed data has the account number, a time zone shift on a scheduled payment.
- **Unattested keys.** The server accepts any public key the app registers, so it cannot tell a hardware-backed, user-authenticated key from a key generated in software by a script.
- **Verify-and-forget.** The server verifies the signature and discards it; or it logs it in a store anyone with database access can edit. When the dispute comes, the evidence is gone or worthless.

## Impact

- **Financial loss.** Users are tricked into approving altered payments, or approvals are fabricated on compromised devices, and funds go to attacker-controlled destinations.
- **Disputes the provider cannot win.** Without evidence of what was approved, the provider cannot contest a chargeback or a claim that a payment was unauthorised. In EU and UK payments law the burden of proving that a disputed transaction was authenticated and correctly recorded sits with the payment service provider (PSD2 Article 72; in the UK, regulation 75 of the Payment Services Regulations 2017), and the use of a payment instrument as recorded by the provider is not in itself necessarily enough to prove the user authorised it.
- **Undetectable abuse.** Without a tamper-evident record, an insider or an attacker with database access can alter or delete the trail of who approved what.
- **Regulatory and contractual exposure.** For identity wallets and signature services, a signature or presentation the user cannot be shown to have approved undermines the legal effect the service exists to provide.

## Mitigations

- **Bind cryptographic evidence to the action.** The user's approval produces a signature over the exact transaction shown, made with a hardware-backed key that is usable only after the user authenticates (per operation, strong biometrics); the server verifies it and keeps it.
- **Use a trusted confirmation path where one exists.** Android Protected Confirmation where `ConfirmationPrompt.isSupported()` is true and the server can verify it; otherwise the strongest alternative above, and accept and document the residual risk of a compromised OS.
- **Verify the key, not just the signature.** On Android, verify the key attestation chain at enrolment and check that the key is hardware-backed, sign-only, user-authenticated per operation and (with Protected Confirmation) requires trusted confirmation. On iOS, bind the Secure Enclave key to a genuine app instance with App Attest.
- **Sign what the user saw, canonically.** A versioned, unambiguous encoding of the human-relevant fields, plus a server nonce, a timestamp and the key ID, rebuilt and checked by the server from its own record.
- **Keep the evidence.** Store the signed bytes, the signature, the public key or certificate chain, the verification result and the server's own context in an append-only, tamper-evident log with synchronised time.

## Knowledge

None of the sections below is an OWASP Knowledge page dedicated to MASWE-0025. Where a MASTG Knowledge page covers a building block we name it in the heading.

### Generic: Non-repudiation, technically and legally (Guler Tech)

**Technically**, non-repudiation is a property of *evidence*: a third party, looking at the evidence later, can establish that a particular entity performed a particular action, and the entity cannot credibly claim otherwise. For a mobile approval that requires:

| Property | What provides it | What breaks it |
|---|---|---|
| **Origin** — only the user could have produced the evidence | An asymmetric private key that never leaves secure hardware and is usable only after the user authenticates | Shared keys (MAC), extractable keys, keys usable without authentication |
| **Integrity** — the evidence covers exactly this transaction | A signature over a canonical encoding of the transaction | Signing a subset, signing an ID, ambiguous encodings |
| **Intent** — the user saw and agreed to this transaction | A trusted display of the transaction, or at least the transaction in the app UI immediately before an explicit, per-operation authentication | Blind signing, passive biometrics, overlays, display/sign divergence |
| **Freshness and uniqueness** — this approval is not a replay | A server nonce and a timestamp inside the signed data | Signing static data; nonces reused or unchecked |
| **Identity binding** — the key belongs to this user | A registration step, itself strongly authenticated, linking the public key to the account; attestation of the key's properties | Keys enrolled on a plain session; unattested keys |
| **Preservation** — the evidence still exists and is trustworthy later | Retained signed data, signature, certificate chain and verification context in tamper-evident storage | Discarding signatures; mutable logs; no time source |

The last row is often forgotten. A perfectly generated signature that nobody stored provides no non-repudiation at all. Conversely, a well-kept log of bearer-token requests provides a record of *what happened* but not of *who approved it*.

**Legally**, "non-repudiation" is not a switch. Courts and dispute processes weigh evidence; a cryptographic signature with a sound key-management story is strong evidence, a log entry is weaker evidence, and neither is conclusive by itself. What the technology can do is give the service provider evidence that is hard to dispute and hard to forge. Be careful in reports not to claim that an implementation "guarantees" or "provides legal non-repudiation"; say instead what evidence it produces and how strong that evidence is.

### Generic: Why MACs, bearer tokens and DPoP are not enough (Guler Tech)

- **MACs** (HMAC, AES-CMAC) use a symmetric key. The verifier holds the same key as the signer, so the verifier could have produced any tag it holds. A MAC proves to the server that *someone with the key* sent the message; it cannot prove to a third party that it was the user and not the server. If the key is derived from or shared with the server, or hardcoded in the app, the tag is worth nothing as evidence.
- **Bearer tokens** (session cookies, OAuth access tokens) prove that the request was made by someone holding the token. Tokens leak (logs, backups, proxies, malicious SDKs), are refreshed silently, and carry no information about the specific transaction or about the user being present.
- **Sender-constrained tokens** — DPoP (RFC 9449) or mutual-TLS-bound tokens (RFC 8705) — prove possession of a key by the client instance. That is valuable against token theft, but the DPoP key is normally not bound to user authentication, and the proof covers the HTTP method, URL and a timestamp rather than the transaction's business content. It shows *which installation* sent the request, not that *the user approved this payment*.
- **App integrity signals** — Play Integrity verdicts, App Attest assertions — prove that a genuine app on a genuine device made the request. An App Attest assertion does sign a client data hash you choose, so it can cover the transaction, but its key is not bound to the user's biometrics. Useful as a complement, not as user evidence.

Only an asymmetric key that is (a) under the user's sole control by being hardware-bound and user-authenticated, and (b) used to sign the transaction content, gives evidence of origin, integrity and intent at once.

### Generic: eIDAS, qualified signatures and the EUDI Wallet (Guler Tech)

For the MAS-EUDIW profile, the legal frame is the EU eIDAS Regulation (Regulation (EU) No 910/2014, amended by Regulation (EU) 2024/1183). Three levels of electronic signature exist:

- An **electronic signature** — any data in electronic form logically associated with other data and used to sign. Article 25 says it may not be denied legal effect or admissibility as evidence *solely* because it is electronic or not qualified.
- An **advanced electronic signature (AdES)**, Article 26: uniquely linked to and capable of identifying the signatory, created using signature-creation data the signatory can use, with a high level of confidence, under their sole control, and linked to the signed data so that any subsequent change is detectable. These are essentially the technical properties in the table above.
- A **qualified electronic signature (QES)**: an AdES created by a qualified signature creation device (QSCD) and based on a qualified certificate. Article 25 gives a QES the equivalent legal effect of a handwritten signature.

The amended regulation requires EUDI Wallets to let users sign with qualified electronic signatures. In most architectures the QSCD is not the phone: the signing key lives in a remote QSCD operated by a qualified trust service provider, and the wallet's job is to authenticate the user to that service strongly enough to meet the "sole control" requirement (the CEN standard EN 419 241-1 describes this as Sole Control Assurance Level 2, SCAL2). The phone's own device keys — the ones a mobile tester can examine — then secure the wallet's authentication and credential presentations, and the user's view of what is being signed.

Two consequences for testing. First, a mobile app's device-key signature is generally *not* a QES; do not describe it as one. It can still be strong evidence and may meet AdES-like properties, but that is for the provider's legal advisers. Second, for wallets, the "what you see" question applies to the document or data being signed remotely: the wallet must show the user what will be signed (or a reliable representation of it) and bind the authorisation to the hash of that document, so that a different document cannot be signed under the same approval.

In payments, PSD2 strong customer authentication with dynamic linking (Commission Delegated Regulation (EU) 2018/389, Article 5) and the evidential burden in PSD2 Article 72 push in the same direction without using the word "non-repudiation". In the UK, electronic signatures are admissible in evidence under the Electronic Communications Act 2000, alongside the retained UK eIDAS rules.

### Generic: What you see is what you sign (MASTG-KNOW-0022)

Related: [MASTG-KNOW-0022: Overlay Attacks](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0022/) and [MASTG-BEST-0040: Preventing Overlay Attacks](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0040/).

"What you see is what you sign" (WYSIWYS) is the requirement that the data presented to the user for approval and the data that is signed are the same. It fails in three ways, in decreasing order of how often we find them:

1. **By design**: the app signs something other than what it displays — a nonce, an ID, a server blob — or displays a transformed version that does not correspond one-to-one to the signed data.
2. **By UI attack** (MAS-ATTACK-0036): an overlay on Android covers the transaction details or the Confirm button; a repackaged app shows altered details. App-side overlay defences (`setHideOverlayWindows`, `filterTouchesWhenObscured`, `FLAG_WINDOW_IS_OBSCURED`) reduce this; MASTG-TEST-0340 checks for them.
3. **By OS compromise** (MAS-ATTACK-0037): root-level malware or instrumentation changes the data between the screen and the `Signature.update` call, or asks the key to sign while the user believes they are authenticating for something else.

A biometric prompt does not fix WYSIWYS. `BiometricPrompt` and the Face ID/Touch ID sheet are system UI, but their title, description and `localizedReason` are text the app supplies, and the prompt has no idea what the `CryptoObject` will sign after it returns. On a compromised device, the per-operation, user-authenticated key guarantees that *the user authenticated for one signature*; it does not guarantee *which* data was signed. That is the residual risk OWASP accepts when it calls biometric-bound transaction signing the strongest available alternative.

Only a confirmation path outside the reach of the OS fixes the third failure: Android Protected Confirmation's TEE-rendered prompt, a separate hardware token with its own display (the classic banking "card reader" or a display-equipped security key), or a second device. For the first two failures — which are the common ones — careful design is enough: sign exactly the displayed fields, and defend the UI.

### Generic: What to sign (Guler Tech)

Sign a canonical, versioned structure that contains everything a third party would need to understand what was approved:

| Field | Why |
|---|---|
| Context label and version, e.g. `com.example.bank/payment-approval/v2` | Domain separation: a signature for a payment cannot be reinterpreted as a login or another message type |
| Operation type | "payment", "add-payee", "change-email", "sign-document" |
| Human-relevant fields, exactly as displayed | Amount in minor units and currency, payee name **and** account identifier, reference, execution date; for a document, its hash and title |
| Server nonce | Freshness and single use; also ties the signature to the pending operation the server created |
| Server operation ID | Lets the server find the exact pending record and rebuild the bytes |
| Client timestamp | Corroborates the server's own time; never trusted on its own |
| Key ID and user ID | Removes ambiguity if a user has several devices |
| Display text or locale (if the display is generated) | Lets a reviewer reconstruct what the user saw |

Use an encoding with exactly one byte representation per value: deterministic CBOR (RFC 8949, section 4.2), the JSON Canonicalization Scheme (RFC 8785), or a length-prefixed binary layout like the one in our [MASWE-0010 note](/mobile/maswe-0010-improper-signature-generation/#android-sign-a-structured-context-labelled-transaction). Do not sign "the JSON body as serialised by the client" and then let the server parse a re-serialised copy; whitespace, key order and number formatting differences make verification brittle, and parser differentials make it unsafe.

The server should **rebuild** the signed bytes from its own record of the pending operation and verify the signature against those, rather than verifying a client-supplied blob and then reading business fields from elsewhere in the request. Algorithm choice, key sizes and ECDSA nonce handling are covered in [MASWE-0010](/mobile/maswe-0010-improper-signature-generation/); verification pitfalls (algorithm confusion, unchecked results, DER parsing) in [MASWE-0011](/mobile/maswe-0011-improper-signature-verification/).

### Android: User-authenticated signing keys and key attestation (MASTG-KNOW-0043, MASTG-KNOW-0044)

Related: [MASTG-KNOW-0043: Android KeyStore](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0043/), [MASTG-KNOW-0044: Key Attestation](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0044/) and [MASTG-KNOW-0001: Biometric Authentication](https://mas.owasp.org/MASTG/knowledge/android/MASVS-AUTH/MASTG-KNOW-0001/).

The signing key for non-repudiation on Android is an EC P-256 (or RSA) key pair in the Android Keystore, created with `PURPOSE_SIGN` only, `setUserAuthenticationRequired(true)`, `setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)` (per operation, Class 3 biometrics), `setInvalidatedByBiometricEnrollment(true)`, `setUnlockedDeviceRequired(true)`, preferably StrongBox-backed, and with an attestation challenge from the server. It is used only through `BiometricPrompt` with a `CryptoObject` wrapping the `Signature`. Our [MASWE-0016 note](/mobile/maswe-0016-key-access-not-restricted/#secure-implementation) has the full builder and explains each restriction; we do not repeat it here.

What MASWE-0025 adds is that **the server must be able to check those properties**, because evidence is only as good as the server's knowledge of the key that produced it. That is what key attestation is for. When a key is generated with `setAttestationChallenge(challenge)`, `KeyStore.getCertificateChain(alias)` returns a chain whose leaf certificate contains the attestation extension (OID `1.3.6.1.4.1.11129.2.1.17`), signed by an attestation key that chains to a Google root. The extension is an ASN.1 `KeyDescription` with:

- `attestationSecurityLevel` and `keyMintSecurityLevel` (older: `keymasterSecurityLevel`): `0` Software, `1` TrustedEnvironment, `2` StrongBox;
- `attestationChallenge`: must equal the server's challenge (freshness of the enrolment);
- two authorisation lists, `softwareEnforced` and `hardwareEnforced`, with tagged fields. The ones that matter here:

| Tag | Field | Expect for a non-repudiation key |
|---|---|---|
| `[1]` | `purpose` | Sign (`2`) only |
| `[503]` | `noAuthRequired` | **Absent** |
| `[504]` | `userAuthType` | Biometric (`2`) for biometric-only; `3` means password or biometric |
| `[505]` | `authTimeout` | Absent (per-operation authentication) |
| `[508]` | `trustedConfirmationRequired` | Present if Protected Confirmation is used |
| `[509]` | `unlockedDeviceRequired` | Present |
| `[704]` | `rootOfTrust` | Verified boot state `Verified`, locked bootloader |
| `[709]` | `attestationApplicationId` | Your package name and signing-certificate digest |

These fields must appear in `hardwareEnforced`; the same values in `softwareEnforced` only say what Android promised, not what the TEE enforces. MASTG-KNOW-0044 lists the server-side checks — random challenge, chain to the Google root, revocation status list, security level, root of trust — and warns against attestation verified only on the client.

Attestation happens once, at key enrolment. After that, the server associates the public key with the user and the attested properties, and every later signature from that key inherits them. A server that skips attestation cannot distinguish a properly restricted key from a key a script generated in software and registered through the same API.

### Android: Protected Confirmation (Guler Tech)

There is no MASTG Knowledge page for Android Protected Confirmation (APC); this section draws on the Android developer and AOSP documentation.

**What it is.** Introduced in Android 9 (API level 28), APC lets an app show a short confirmation text ("Send £25.00 to Alice Smith?") in a full-screen prompt rendered by a trusted UI running in the TEE, not by Android. The user confirms with a physical button press. The TEE's ConfirmationUI app then produces a confirmation token that allows KeyMint to sign — and the Keystore will only let a key created with `setUserConfirmationRequired(true)` sign — the exact message that was confirmed. Because the prompt and the token are produced outside Android, a compromised OS cannot change the text the user sees or obtain a signature over a different text. It is the only API that addresses MAS-ATTACK-0037 directly.

**The API.**

- `ConfirmationPrompt.isSupported(context)` — whether the device has the trusted UI.
- `ConfirmationPrompt.Builder(context).setPromptText(text).setExtraData(bytes).build()`, then `presentPrompt(executor, callback)`; `cancelPrompt()` to dismiss.
- `ConfirmationCallback.onConfirmed(dataThatWasConfirmed)`, `onDismissed()`, `onCanceled()`, `onError(e)`.
- `dataThatWasConfirmed` is a CBOR structure that contains the prompt text the user saw and the extra data the app passed in. The app signs it with the confirmation-bound key and sends the blob and the signature to the server.

**What the server must check** (from the Android developer guide): the signature and the key's attestation chain; that the attestation shows `TRUSTED_CONFIRMATION_REQUIRED` (`trustedConfirmationRequired`, tag `[508]`); that `extraData` contains a fresh nonce from the server, for replay protection; and that the transaction it executes is the one in `promptText`. The guide is explicit that `promptText` is the only part the user actually confirmed: if `extraData` contains the transaction too, the server must not assume it matches the prompt. APC also does not provide a confidential channel, so the prompt must not display information that would not ordinarily be shown on the device.

**Status.** The public SDK classes are not marked deprecated, but in early 2024 AOSP deprecated the Keystore 2.0 AIDL interfaces for APC (commit `07fec0ff` in `platform/system/security`, "Deprecating the aidl for Android Protected Confirmation"), citing the support and maintenance cost for device makers and low developer adoption, and describing the change as sunsetting the API. Device support was always limited to some devices with a TEE trusted UI. In practice, expect `isSupported()` to return `false` on most devices you test, check it on each target device rather than assuming, and treat APC as an enhancement where available, never as the only path. Apps that use it need a fallback — the biometric-bound signing described above — and the server needs to know which path produced each signature, because the evidential strength differs.

### iOS: Secure Enclave signing keys and App Attest (MASTG-KNOW-0057, MASTG-KNOW-0066)

Related: [MASTG-KNOW-0057: Keychain Services](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-AUTH/MASTG-KNOW-0057/), [MASTG-KNOW-0066: CryptoKit](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0066/), [MASTG-KNOW-0069: Key Management](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0069/) and, for App Attest, [MASTG-KNOW-0135](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0135/).

The iOS equivalent of the Android key is a P-256 key generated in the Secure Enclave with an access control created from `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` and the flags `[.privateKeyUsage, .biometryCurrentSet]`: the private key never leaves the Secure Enclave, and every signature requires Face ID or Touch ID with the biometrics enrolled when the key was made. With CryptoKit this is `SecureEnclave.P256.Signing.PrivateKey(accessControl:)`; with the Security framework, `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave`, then `SecKeyCreateSignature` with `.ecdsaSignatureMessageX962SHA256`. Creation code is in our [MASWE-0016 note](/mobile/maswe-0016-key-access-not-restricted/#ios-secure-enclave-signing-key-with-current-set-biometrics). The traps: CryptoKit's `SecureEnclave.P256.Signing.PrivateKey()` with no access control needs only an unlocked device; `.userPresence` allows passcode fallback (MASWE-0021); `.biometryAny` survives new enrolments (MASWE-0022).

Two iOS limitations shape what you can expect:

- **No trusted confirmation UI for third-party apps.** Apple's hardware-backed confirmation (the side-button double-click that Apple Pay uses) is not exposed for arbitrary transaction signing. The app UI is the display, with the residual risk discussed under [WYSIWYS](#generic-what-you-see-is-what-you-sign-mastg-know-0022).
- **No attestation of arbitrary Secure Enclave keys.** The server cannot obtain a certificate saying "this P-256 key is in the Secure Enclave and requires current-set biometrics". The usual compensation is App Attest: at enrolment, the app generates an App Attest key and has Apple attest it with a `clientDataHash` that includes the new signing public key (see [MASWE-0010](/mobile/maswe-0010-improper-signature-generation/#ios-bind-your-signing-key-to-app-attest)). The server then knows the signing key was registered by a genuine instance of the app — whose code creates keys with the right access control — but the access control itself is established by code review and testing (GT-0025-4), not by the server.

### Generic: Server-side verification and the evidence record (Guler Tech)

Evidence is created on the server. For each critical action, the server should:

1. Create the pending operation and a nonce; send the client the display data and the nonce.
2. Receive the signature (and, for APC, the confirmed CBOR); look up the user's active key by key ID; reject revoked or unknown keys.
3. Rebuild the canonical signed bytes from the pending record (or, for APC, parse the CBOR and compare `promptText` and the nonce in `extraData` with the pending record).
4. Verify the signature with the registered public key and the expected algorithm, rejecting anything else.
5. Mark the nonce as used, atomically with executing the operation.
6. Write an **evidence record** and execute the operation.

A useful evidence record contains: the operation ID and type; the canonical signed bytes (or the APC CBOR); the signature; the key ID, the public key and a reference to its enrolment record (attestation chain, App Attest attestation, the authentication used to enrol it); the confirmation path (APC, biometric-bound, other); the verification result and the verifier's version; server receive and execute times from a synchronised clock; and the session and device context.

The store must make tampering evident. OWASP ASVS 5.0 requires that logs include when, where, who and what (16.2.1), use synchronised time sources (16.2.2), log authentication operations with the factor used (16.3.1), and be protected from unauthorised access and modification (16.4.2) and sent to a logically separate system (16.4.3). For evidence that may be used in disputes, providers commonly add one or more of: write-once (WORM) object storage with retention locks; hash chaining, where each record includes the hash of the previous one, with the chain head periodically signed or anchored elsewhere; RFC 3161 trusted timestamps over batches; or a Merkle-tree transparency log of the kind Certificate Transparency uses (RFC 9162). Retention periods are a legal and regulatory decision; they need to cover the dispute window for the product.

Note the tension with privacy: the evidence record contains personal data. Minimise it (store what the user saw, not their whole profile), protect it like any other sensitive store, and follow the provider's retention policy.

## Testing

The tests below are **Guler Tech methodology**. The sequence is: find the critical actions (GT-0025-1); see whether the requests carry a user signature at all (GT-0025-2); establish what the signing key really is (GT-0025-3, GT-0025-4); compare what is signed with what is shown (GT-0025-5); attack the server's verification (GT-0025-6); check the trusted-UI path where it exists (GT-0025-7); and find out what evidence survives (GT-0025-8).

### Related OWASP material

No OWASP test is mapped to MASWE-0025. These items cover building blocks; all IDs were found in the MASTG repository.

| ID | Platform | What it checks | Mapped weakness | Relevance to MASWE-0025 |
|---|---|---|---|---|
| [MASTG-TEST-0327](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0327/), [MASTG-TEST-0266](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0266/), [MASTG-TEST-0267](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0267/) | Android, iOS | Event-bound biometrics; keys without user authentication | MASWE-0020 | A signing key usable without the user produces no evidence of the user; see [our MASWE-0020 note](/mobile/maswe-0020-local-authentication-bypass/) |
| [MASTG-TEST-0326](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0326/), [MASTG-TEST-0268](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0268/), [MASTG-TEST-0269](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0269/) | Android, iOS | Device-credential fallback | MASWE-0021 | A shoulder-surfed PIN signs as well as the user's biometric; see [our MASWE-0021 note](/mobile/maswe-0021-non-biometric-fallback-for-sensitive-transactions/) |
| [MASTG-TEST-0328](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0328/), [MASTG-TEST-0270](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0270/), [MASTG-TEST-0271](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0271/) | Android, iOS | Keys not invalidated on new enrolment | MASWE-0022 | Someone else's fingerprint can sign; see [our MASWE-0022 note](/mobile/maswe-0022-keys-not-invalidated-on-biometric-enrollment/) |
| [MASTG-TEST-0329](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0329/) | Android | `setConfirmationRequired(false)` | MASWE-0020 | Passive face unlock approves without an explicit action: weak evidence of intent |
| [MASTG-TEST-0330](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0330/) | Android | Extended key validity duration | MASWE-0020 | One authentication, many signatures |
| [MASTG-TEST-0307](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0307/), [MASTG-TEST-0308](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0308/) | Android | Asymmetric keys with multiple purposes | MASWE-0007 | A signing key that also decrypts or is reused for login weakens the evidence |
| [MASTG-TEST-0340](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0340/) | Android | References to overlay protections | MASWE-0036 in the repository | MAS-ATTACK-0036 on the approval screen |
| [MASTG-TEST-0018](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0018/), [MASTG-TEST-0064](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0064/), [MASTG-TEST-0035](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0035/) | Android, iOS | Legacy (MASTG v1): biometric authentication; overlay attacks | — | Superseded by the beta tests above |

The MASTG chapter [Mobile App Authentication Architectures](https://mas.owasp.org/MASTG/0x04e-Testing-Authentication-and-Session-Management/) describes "Transaction Signing with Push Notifications and PKI" — a key pair generated at sign-up, the public key registered on the backend, the transaction delivered by push, confirmed, signed after user authentication and verified with the public key — and says that "non-repudiation mechanisms should be applied to sensitive transactions" to prove that a transaction was performed (integrity) and by whom (authentication). Techniques used below: [MASTG-TECH-0120](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0120/) (interception proxy), [MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/) and [MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/) (method hooking).

### What you can prove from the client

| You can prove from the client | You need the backend (or its documentation) for |
|---|---|
| Whether critical requests carry a signature, and over what (GT-0025-2, GT-0025-5) | Whether the server stores the signature and the signed data |
| The signing key's configuration and, on Android, its attestation (GT-0025-3, GT-0025-4) | Whether the server verifies the attestation at enrolment |
| That the server accepts unsigned, altered, replayed or foreign-key requests (GT-0025-6) — conclusive | The log's integrity protections and retention |
| Whether APC is used and supported on a given device (GT-0025-7) | How evidence would be produced in a dispute |
| What evidence the service returns to you (receipts, history, data-subject access exports) (GT-0025-8) | Clock synchronisation and access control on the evidence store |

When the backend is out of scope, GT-0025-6 still gives conclusive results, and GT-0025-8 becomes a short list of questions in the report with whatever client-observable evidence you found. When it is in scope, test against ASVS 5.0 V16 and the server-side verification steps above, and for the web equivalent use OWASP WSTG "Test Integrity Checks" (WSTG-BUSL-03) and "Test Ability to Forge Requests" (WSTG-BUSL-02).

### GT-0025-1: Critical-action inventory and evidence map (Android, iOS)

Guler Tech methodology. Platform: Android, iOS. Type: static (code) and dynamic (network, manual).

#### Overview

List the critical actions — the subset of sensitive actions whose approval may later be disputed or must be proven — and for each, what evidence the app produces. This overlaps with the step-up map in [GT-0023-1](/mobile/maswe-0023-step-up-authentication-not-implemented/#gt-0023-1-sensitive-action-inventory-and-step-up-map-android-ios); if you have it, add the evidence columns to it.

#### Prerequisites

- Decompiled app (jadx; a decrypted IPA with radare2 or another disassembler), an interception proxy, a test account with payments or signing enabled.

#### Steps

1. **Identify critical actions.** Typical candidates: payments and transfers, payee management, loan or credit agreements, consent to terms (where consent matters legally), trades, crypto withdrawals, in a wallet: credential presentations and qualified signatures, and in enterprise apps: approvals in workflows (expenses, purchase orders, access grants).

2. **Find signing code.** Android:

   ```bash
   grep -rnE "Signature\.getInstance|initSign\(|\.sign\(\)|KeyProperties\.PURPOSE_SIGN|setUserConfirmationRequired|ConfirmationPrompt|setAttestationChallenge|getCertificateChain" out/sources | grep -v "/androidx/\|/kotlin/\|/org/bouncycastle/" | head -60
   grep -rnE "Mac\.getInstance|HmacSHA256|\"X-[A-Za-z-]*(Signature|Sig|Hmac|Mac)\"" out/sources | head -40
   ```

   iOS:

   ```bash
   r2 -qc "ii~SecKeyCreateSignature,SecKeyCreateRandomKey,SecAccessControlCreateWithFlags,CCHmac,DCAppAttestService" "$BIN"
   strings -a "$BIN" | grep -E "SecureEnclave|Signing\.PrivateKey|X-[A-Za-z-]*(Signature|Sig|Hmac)|biometryCurrentSet" | sort -u | head -40
   ```

   HMAC hits on the critical request path are candidates for the "shared-secret MAC" mode.

3. **Perform each critical action** with the proxy recording and note: signature-like fields (headers such as `X-Signature`, body fields such as `signature`, `sig`, `jws`, `assertion`, base64 blobs of 64–72 bytes for ECDSA or 256–512 bytes for RSA), detached JWS (`header..signature`), and any enrolment request that registered a public key or certificate chain (often at onboarding or "activate this device").

4. **Record what the user saw**: screenshot each approval screen and system prompt.

#### Observation

A table: action, request, signature present (where), signing API from the code, enrolment request found, screenshots of the approval UI.

#### Evaluation

Record a provisional **fail** for each critical action whose request carries no asymmetric signature (only a token, or an HMAC). Actions with a signature go on to GT-0025-3 to GT-0025-6.

#### Demo

```text
Action               Request                          Signature                       Signing API              Enrolment
-------------------  -------------------------------  ------------------------------  -----------------------  -----------------------------
Pay (any payee)      POST /api/v2/payments/{id}/conf  X-Sig: 71-byte base64 (ECDSA)   Signature SHA256withECDSA POST /api/v2/devices (pubkey, no chain)
Add payee            POST /api/v2/payees              none                            —                        —
Accept loan terms    POST /api/v2/loans/{id}/accept   X-Mac: 32-byte hex              Mac HmacSHA256           —
```

Adding a payee produces no evidence at all; loan acceptance carries an HMAC whose key ships in the app (found in GT-0025-2), so it proves nothing about the user; payments carry an ECDSA signature, but the key was registered without an attestation chain. Each row continues in the tests below.

### GT-0025-2: Does the request carry a user signature (Android, iOS)

Guler Tech methodology. Platform: Android, iOS. Type: static (code) and dynamic (network, hooks).

#### Overview

Establish what kind of evidence each critical request carries: none, a bearer token, a MAC, an app-integrity signal, or an asymmetric signature — and for signatures, whether the key that produced it is plausibly under the user's sole control.

#### Prerequisites

- GT-0025-1 completed; Frida on a rooted Android device or jailbroken iOS device.

#### Steps

1. **For MAC-like fields**, find the key. In jadx, follow `Mac.init(key)` back to a `SecretKeySpec` built from a constant, a resource, a string decoded at runtime, or a value received from the server at login. Confirm at runtime:

   ```javascript
   // gt-mac-key.js (Android)
   Java.perform(function () {
     const Spec = Java.use('javax.crypto.spec.SecretKeySpec');
     Spec.$init.overload('[B', 'java.lang.String').implementation = function (k, alg) {
       if (alg.indexOf('Hmac') === 0) {
         let h = ''; for (let i = 0; i < k.length; i++) h += ('0' + (k[i] & 0xff).toString(16)).slice(-2);
         console.log('[*] ' + alg + ' key: ' + h);
       }
       return this.$init(k, alg);
     };
   });
   ```

   Whether the key is hardcoded, server-provided or stored in the Keystore, a MAC is symmetric: the server can produce it too.

2. **For signatures**, hook the signing call to tie the request field to a key ([MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/)):

   ```javascript
   // gt-sign-trace.js (Android)
   Java.perform(function () {
     const Sig = Java.use('java.security.Signature');
     Sig.initSign.overload('java.security.PrivateKey').implementation = function (k) {
       console.log('[*] initSign ' + this.getAlgorithm() + ' key class=' + k.$className);
       return this.initSign(k);
     };
     Sig.sign.overload().implementation = function () {
       const out = this.sign();
       console.log('[*] sign() -> ' + out.length + ' bytes');
       return out;
     };
   });
   ```

   A key class such as `android.security.keystore2.AndroidKeyStoreECPrivateKey` (names vary by Android version) indicates a Keystore key; `org.bouncycastle...` or `java.security.interfaces.ECPrivateKey` implementations from a software provider indicate a key in app memory, possibly stored on disk.

   On iOS ([MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/)):

   ```javascript
   // gt-sign-trace-ios.js
   const sec = Process.getModuleByName('Security');
   const SecKeyCopyAttributes = new NativeFunction(
     sec.getExportByName('SecKeyCopyAttributes'), 'pointer', ['pointer']);
   Interceptor.attach(sec.getExportByName('SecKeyCreateSignature'), {
     onEnter(args) {
       const attrs = new ObjC.Object(SecKeyCopyAttributes(args[0]));   // CFDictionary of key attributes
       console.log('[*] SecKeyCreateSignature alg=' + new ObjC.Object(args[1]) +
                   ' tokenID=' + attrs.objectForKey_('tkid'));
     }
   });
   ```

   `tkid` is the dictionary key behind `kSecAttrTokenID`; the value `com.apple.setoken` means the key is in the Secure Enclave. CryptoKit's `SecureEnclave` signing may not pass through this export on every iOS version; if nothing fires, trace with `frida-trace -U -f <bundle> -i 'SecKey*'` and fall back to the code review in GT-0025-4.

3. **Correlate**: perform the action and match the hook output with the signature field in the proxy.

#### Observation

For each critical request: evidence type (none, token, MAC with key origin, app-integrity assertion, asymmetric signature), key location (Keystore/Secure Enclave or software), and the hook output.

#### Evaluation

The test **fails** for a critical action if the request carries no asymmetric signature from a device-held key — only a bearer token, a sender-constrained token, an app-integrity assertion, or a MAC — or if the signature is made with a software key held in app memory or storage.

It **passes** if every critical request carries an asymmetric signature made inside the Android Keystore or the Secure Enclave. Whether that key is user-authenticated and attested is GT-0025-3 and GT-0025-4.

#### Demo

```kotlin
// Vulnerable: "signing" loan acceptance with an HMAC key shipped in the app.
private val LOAN_KEY = SecretKeySpec("0123456789abcdef0123456789abcdef".toByteArray(), "HmacSHA256")

fun acceptHeader(body: ByteArray): String =
    Mac.getInstance("HmacSHA256").run { init(LOAN_KEY); doFinal(body) }.toHex()
```

```text
[*] HmacSHA256 key: 3031323334353637383961626364656630313233343536373839616263646566
POST /api/v2/loans/L-2291/accept   X-Mac: 5f1d…a90c   -> 200 {"status":"ACCEPTED"}
```

Anyone with the APK can compute valid `X-Mac` values, and the server holds the same key. The loan acceptance has no evidence of the user's approval; the test fails.

### GT-0025-3: Signing-key properties and attestation (Android)

Guler Tech methodology. Platform: Android. Type: static (code) and dynamic (hooks, attestation analysis).

#### Overview

For the transaction-signing key, establish three things: that it is hardware-backed, that it is usable only after per-operation strong user authentication, and that the server can know both through attestation. Our [MASWE-0016 note](/mobile/maswe-0016-key-access-not-restricted/) has the general key-restriction tests — GT-0016-1 (builder calls), GT-0016-2 (`KeyInfo`) and GT-0016-3 (using the key without authentication). Run those on the signing key first; this test adds attestation and the enrolment request.

#### Prerequisites

- Rooted device with Frida; the signing key alias (from GT-0016-1 or a `KeyStore.aliases()` probe); the enrolment request from GT-0025-1; `openssl`.

#### Steps

1. **Check the configuration** with GT-0016-1 and GT-0016-2: `PURPOSE_SIGN` only, `setUserAuthenticationRequired(true)`, timeout `0` with `AUTH_BIOMETRIC_STRONG` (or `setUserAuthenticationValidityDurationSeconds(-1)` on older code), `setInvalidatedByBiometricEnrollment` not `false`, `setUnlockedDeviceRequired(true)`, `setAttestationChallenge(...)` present, and `isInsideSecureHardware()`/`getSecurityLevel()` reporting TEE or StrongBox.

2. **Prove use without authentication** with the GT-0016-3 probe. A signing key that signs without a prompt fails this test outright: anything signed with it is not evidence of the user.

3. **Dump the certificate chain**:

   ```javascript
   // gt-chain.js
   Java.perform(function () {
     const KeyStore = Java.use('java.security.KeyStore');
     const B64 = Java.use('android.util.Base64');
     globalThis.dumpChain = function (alias) {
       Java.perform(function () {
         const ks = KeyStore.getInstance('AndroidKeyStore');
         ks.load(null, null);
         const chain = ks.getCertificateChain(alias);
         if (chain === null) { console.log('no chain for ' + alias); return; }
         console.log('chain length: ' + chain.length);
         for (let i = 0; i < chain.length; i++) {
           console.log('-----BEGIN CERTIFICATE-----\n' +
             B64.encodeToString(chain[i].getEncoded(), 0).trim() + '\n-----END CERTIFICATE-----');
         }
       });
     };
   });
   ```

   ```bash
   frida -U -F -l gt-chain.js
   # in the REPL:
   dumpChain('tx_signing_key')
   ```

   A chain of length 1 (a self-signed certificate) means the key was generated without an attestation challenge: the server cannot have verified anything about it.

4. **Decode the attestation extension** of the leaf certificate. Save the first PEM block as `leaf.pem`, then:

   ```bash
   openssl x509 -in leaf.pem -noout -text | grep -A2 '1.3.6.1.4.1.11129.2.1.17'
   openssl asn1parse -in leaf.pem -i | grep -n -A1 '1.3.6.1.4.1.11129.2.1.17'
   # take the offset of the OCTET STRING on the line after the OID, then:
   openssl asn1parse -in leaf.pem -i -strparse <offset>
   ```

   In the `strparse` output, the two authorisation lists appear as SEQUENCEs of context-specific tags (`cont [ 1 ]`, `cont [ 504 ]`, and so on). Compare the hardware-enforced list with the [table above](#android-user-authenticated-signing-keys-and-key-attestation-mastg-know-0043-mastg-know-0044). Google's `android-key-attestation` sample parser gives a readable dump if you prefer.

5. **Check the enrolment request** in the proxy history: does the app send the whole certificate chain, or only the public key? If only the public key, the server cannot verify attestation. Optionally, replay the enrolment with a public key from a software key you generated (`openssl ecparam -name prime256v1 -genkey -noout -out sw.pem; openssl ec -in sw.pem -pubout -out sw.pub`) on a test account: if the server accepts it, it does not verify attestation, and every signature from enrolled keys inherits that uncertainty. Enrolment should itself require step-up (GT-0023-7).

#### Observation

The key configuration, the GT-0016-3 probe result, the chain length, the decoded authorisation lists and security levels, the enrolment request, and the result of the software-key enrolment attempt.

#### Evaluation

The test **fails** if the signing key: is usable without user authentication or with a validity window; allows device-credential authentication for high-value actions without a documented decision; is not hardware-backed; has no attestation chain; or if the server accepts enrolment of a key with no or invalid attestation.

It **passes** if the key is hardware-backed, sign-only, per-operation `BIOMETRIC_STRONG`, invalidated on enrolment, attested with these properties in `hardwareEnforced`, and the server rejects keys without a valid chain.

#### Demo

Lab app key generation (decompiled) and enrolment:

```java
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder("tx_signing_key", KeyProperties.PURPOSE_SIGN)
        .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
        .setDigests(KeyProperties.DIGEST_SHA256)
        .setUserAuthenticationRequired(true)
        .setUserAuthenticationParameters(600, KeyProperties.AUTH_BIOMETRIC_STRONG
                | KeyProperties.AUTH_DEVICE_CREDENTIAL)
        .build();                                              // no attestation challenge
```

```text
dumpChain('tx_signing_key')
chain length: 1
POST /api/v2/devices  {"publicKey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE…"}   -> 201
(software key enrolled on a test account) -> 201
```

The key is usable for ten minutes after any unlock with the device PIN, it is not attested, and the server accepts a software key in its place. Payment signatures from this app are evidence that *some* key registered to the account signed, not that the user approved. The test fails.

### GT-0025-4: Signing-key properties (iOS)

Guler Tech methodology. Platform: iOS. Type: static (code) and dynamic (hooks).

#### Overview

The iOS counterpart: confirm that the transaction-signing key lives in the Secure Enclave, requires current-set biometrics for each signature, never leaves the device, and was enrolled in a way the server can trust. The key-restriction tests GT-0016-4 (access control in the binary), GT-0016-5 (Keychain attributes at runtime) and GT-0016-6 (using items and Secure Enclave keys without authentication) in our [MASWE-0016 note](/mobile/maswe-0016-key-access-not-restricted/) do most of the work; run them on the signing key.

#### Prerequisites

- Jailbroken device with Frida, or a re-signed IPA with the gadget; the decrypted binary; the enrolment request from GT-0025-1.

#### Steps

1. **Run GT-0016-4 to GT-0016-6** on the signing key. Expect `kSecAttrTokenIDSecureEnclave` (or CryptoKit `SecureEnclave.P256.Signing.PrivateKey(accessControl:)`), an access control with `.privateKeyUsage` and `.biometryCurrentSet`, and a `...ThisDeviceOnly` protection class. A CryptoKit key created with the default initialiser, `.userPresence`, `.devicePasscode` or `.biometryAny` is a weaker finding (MASWE-0016, MASWE-0021, MASWE-0022).

2. **Prove the prompt is enforced by the Secure Enclave.** With `ios ui biometrics_bypass` active in objection, attempt the approval: if the signature is still produced only after a real Face ID/Touch ID, the prompt is enforced by the key's access control; if the approval completes with the bypass, the signature does not depend on the user.

3. **Check the enrolment.** In the proxy, look for an App Attest attestation object sent with the signing public key (a CBOR blob with `fmt` `apple-appattest`), and check whether the server accepts a public key registered without one (replay the enrolment with a key generated off-device on a test account, as in GT-0025-3 step 5).

#### Observation

Access-control flags and protection class (from code and runtime), the bypass result, and the enrolment request and replay result.

#### Evaluation

The test **fails** if the signing key is not in the Secure Enclave, can sign without biometric authentication or with the biometric bypass active, accepts passcode fallback or any-biometry for high-value actions without a documented decision, is synchronisable or migratable, or if the server accepts signing keys that are not bound to a genuine app instance (no App Attest or equivalent).

It **passes** if the key is a Secure Enclave key with `.privateKeyUsage` and `.biometryCurrentSet` in a `ThisDeviceOnly` class, each signature requires real biometrics, and the server binds the public key to an App Attest attestation at enrolment.

#### Demo

```swift
// Vulnerable: Secure Enclave key with no user-presence requirement.
let key = try SecureEnclave.P256.Signing.PrivateKey()        // device unlocked is enough
let sig = try key.signature(for: payload)                     // no prompt, ever
```

With this key, GT-0016-6 signs a test payload from a Frida REPL without any prompt. The key is hardware-backed but not user-authenticated, so its signatures prove the device, not the user. The test fails.

### GT-0025-5: What is signed versus what is shown (Android, iOS)

Guler Tech methodology. Platform: Android, iOS. Type: dynamic (hooks, manual).

#### Overview

Capture the exact bytes the app signs and compare them with what the approval screen displayed and with what the request asks the server to do. This finds the common WYSIWYS failures by design (signing a nonce or an ID, blind signing, display/sign divergence), and demonstrates the residual risk on a compromised device.

#### Prerequisites

- Frida on a rooted or jailbroken device; GT-0025-2 shows which signing call is used; a test payee and small amounts.

#### Steps

1. **Log the data being signed.** Android:

   ```javascript
   // gt-signed-data.js
   Java.perform(function () {
     const Sig = Java.use('java.security.Signature');
     const Str = Java.use('java.lang.String');
     function show(b) {
       let h = ''; for (let i = 0; i < b.length; i++) h += ('0' + (b[i] & 0xff).toString(16)).slice(-2);
       console.log('[*] Signature.update ' + b.length + ' bytes\n    hex:  ' + h +
                   '\n    utf8: ' + Str.$new(b, 'UTF-8'));
     }
     Sig.update.overload('[B').implementation = function (b) { show(b); return this.update(b); };
     Sig.update.overload('[B', 'int', 'int').implementation = function (b, off, len) {
       show(Java.array('byte', Array.prototype.slice.call(b, off, off + len)));
       return this.update(b, off, len);
     };
   });
   ```

   iOS:

   ```javascript
   // gt-signed-data-ios.js
   Interceptor.attach(Process.getModuleByName('Security').getExportByName('SecKeyCreateSignature'), {
     onEnter(args) {
       const data = new ObjC.Object(args[2]);                 // CFDataRef dataToSign
       console.log('[*] SecKeyCreateSignature ' + new ObjC.Object(args[1]) + ', ' + data.length() + ' bytes');
       console.log(hexdump(data.bytes(), { length: Math.min(data.length(), 512), ansi: false }));
     }
   });
   ```

2. **Approve a transaction** and compare three things side by side: the approval screen (screenshot), the signed bytes (hook output), and the request body (proxy). Check each human-relevant field: amount and currency, payee name *and* account identifier, reference, date, and for documents, the document hash.

3. **Look for divergence by design:** fields displayed but not signed; signed fields not displayed (opaque server blobs); different representations (displayed "£1,000.00", signed `100000` minor units is fine; displayed "Alice (savings)", signed account number of a different payee is not); and server-chosen data the app signs without parsing.

4. **Demonstrate the residual risk.** On a test account, change the data in the hook before it reaches `Signature.update` (for example, replace the payee identifier or amount in the signed bytes and request body), while the screen shows the original. Complete the real biometric prompt. If the server executes the altered transaction, you have shown that on a compromised device the user can be made to sign something other than what they saw — MAS-ATTACK-0037. This is expected without a trusted UI; record it as the residual risk, and check whether APC (GT-0025-7) is available and used.

#### Observation

For each critical action: screenshot, signed bytes, request body, and a field-by-field comparison; the result of the alteration in step 4.

#### Evaluation

The test **fails** if any human-relevant field shown on the approval screen is not covered by the signature, if the app signs data it does not display or parse (blind signing), or if displayed and signed values do not correspond. Step 4 succeeding is a **fail** for apps that claim a trusted confirmation path, and a documented residual risk (not a fail on its own) for apps using biometric-bound signing as the strongest available alternative.

It **passes** if the signed bytes contain every displayed field in a canonical form, plus a server nonce and context label, and nothing the user was not shown.

#### Demo

```text
Screen:    "Pay £25.00 to Alice Smith, sort code 00-00-00, account ••••1234, ref RENT"
Signed:    [*] Signature.update 32 bytes
              hex:  6b3f…e1a0
              utf8: (binary)          -> SHA-256 of the server nonce only
Request:   {"paymentId":"pay-77810","amountMinor":2500,"payee":{"account":"00001234",...},"sig":"MEUCIQ…"}
```

The signature covers only the nonce. The payment ID ties it to a pending record, but GT-0025-6 shows the server accepts a changed `amountMinor` with the same signature, because nothing in the signed data constrains it. The test fails.

### GT-0025-6: Server rejects altered, unsigned, replayed and foreign signatures (Android, iOS)

Guler Tech methodology. Platform: Android, iOS (network). Type: dynamic (network).

#### Overview

The decisive test for the server. A signature is only evidence if the server refuses everything that is not a fresh signature, by the user's registered key, over exactly the operation being executed.

#### Prerequisites

- A legitimate signed request captured in the proxy (held, not yet forwarded, for the replay cases); two test accounts with enrolled keys; Burp Repeater.

#### Steps

Run each case against a fresh pending operation and check the effect in the account:

| Case | Procedure | Expected secure result |
|---|---|---|
| Unsigned | Remove the signature field or header | Refused |
| Empty or garbage | Empty string; 64 zero bytes; a truncated signature | Refused (verification errors handled as failures; see [MASWE-0011](/mobile/maswe-0011-improper-signature-verification/)) |
| Altered business data | Change amount, payee, reference or date in the body, keep the signature | Refused |
| Altered unsigned fields | Change fields outside the signed structure that still affect execution (a second `amount`, a `currency` header, a query parameter) | Refused, or the field has no effect |
| Replay | Forward the original; then resend it | Second refused |
| Cross-operation | Use a signature from operation A on pending operation B | Refused |
| Foreign key | Sign with account B's enrolled key (hook the app on B's device) and send for account A, with A's key ID or B's | Refused |
| Unknown key | Sign with a software key and send its key ID or public key inline | Refused |
| Algorithm downgrade | If the request names an algorithm (`"alg":"ES256"`), change it (`none`, `HS256`) | Refused |
| Stale | Hold a valid signed request beyond the nonce lifetime, then forward | Refused |

For the "altered" and "cross-operation" cases you do not need to forge a signature: you reuse a real one with different data. For "foreign key", the easiest route is to run the app on a second device logged in as account B, hook `Signature.update` (GT-0025-5) to substitute account A's pending-operation bytes, and approve with B's biometrics.

#### Observation

For each case: the request, the response and the effect.

#### Evaluation

The test **fails** if the server executes any operation in any case above. Acceptance of altered business data or of a signature by a key not registered to the user is the most serious result: the server's "signed" transactions are not evidence of anything.

It **passes** if every case is refused and nothing takes effect, while the original request succeeds once.

#### Demo

```text
POST /api/v2/payments/pay-77810/confirm
{"amountMinor":250000,"payee":{"account":"99990000"},"sig":"MEUCIQ… (from the £25 approval)"}

HTTP/2 200 OK   {"status":"EXECUTED"}
```

The server verified the signature over the nonce, and then executed the amount and payee from the request body. The approval of £25 to Alice became £2,500 to another account. The test fails, and the evidence the server keeps for this payment shows a valid signature on a transaction the user never saw.

### GT-0025-7: Use of Android Protected Confirmation (Android)

Guler Tech methodology. Platform: Android. Type: static (code) and dynamic (hooks, device).

#### Overview

If the app uses Android Protected Confirmation, check that it is used correctly and that the server gets its benefit; if it does not, record whether it would be available on the target devices. There is no MASTG test for APC.

#### Prerequisites

- Decompiled APK; one or more test devices on Android 9 or higher; Frida.

#### Steps

1. **Find the API:**

   ```bash
   grep -rnE "android\.security\.ConfirmationPrompt|ConfirmationCallback|setPromptText|setExtraData|presentPrompt|isSupported\(|setUserConfirmationRequired" out/sources | grep -v "/androidx/" | head -30
   ```

2. **Check support on each test device** and trace use at runtime:

   ```javascript
   // gt-apc.js
   Java.perform(function () {
     const CP = Java.use('android.security.ConfirmationPrompt');
     CP.isSupported.implementation = function (ctx) {
       const r = this.isSupported(ctx);
       console.log('[*] ConfirmationPrompt.isSupported -> ' + r);
       return r;
     };
     const B = Java.use('android.security.ConfirmationPrompt$Builder');
     B.setPromptText.implementation = function (t) {
       console.log('[*] promptText: ' + t);
       return this.setPromptText(t);
     };
     B.setExtraData.implementation = function (d) {
       console.log('[*] extraData: ' + (d === null ? 'null' : d.length + ' bytes'));
       return this.setExtraData(d);
     };
   });
   ```

   If the app never calls `isSupported`, call it yourself from the REPL to learn whether the device could have used APC:

   ```javascript
   Java.perform(function () {
     const ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
     console.log(Java.use('android.security.ConfirmationPrompt').isSupported(ctx));
   });
   ```

3. **If APC is used**, check: the key is created with `setUserConfirmationRequired(true)` and an attestation challenge (attestation shows `trustedConfirmationRequired`, tag `[508]`, in GT-0025-3); the prompt text contains the human-relevant fields (amount, currency, payee and account); the extra data contains a server nonce; the app signs `dataThatWasConfirmed` exactly; the request sends the CBOR and the signature; and the server rejects the fallback path for operations that require APC on capable devices. Run GT-0025-6 against the APC request, adding one case: change the transaction in `extraData` but not in the prompt text, and confirm the server executes only what the prompt said.

4. **Check the fallback.** On a device where `isSupported()` returns `false`, perform the same action and check that the app falls back to biometric-bound signing (not to no signature) and that the request tells the server which path was used.

#### Observation

`isSupported` results per device, the prompt text and extra data, the signing call, the request, and the fallback behaviour.

#### Evaluation

When APC is used, the test **fails** if the key is not confirmation-bound, the prompt omits key transaction fields, the extra data lacks a server nonce, the server trusts transaction data from `extraData` over the prompt text, or the fallback produces no user-authenticated signature.

When APC is not used, this test has no pass/fail of its own; record whether `isSupported()` was `true` on any target device, and treat its absence as part of the residual-risk statement in GT-0025-5. Given the API's deprecated interface and limited support, we do not report the absence of APC as a finding by itself.

#### Demo

Correct use, in outline (Kotlin):

```kotlin
if (ConfirmationPrompt.isSupported(context)) {
    ConfirmationPrompt.Builder(context)
        .setPromptText("Pay £25.00 to Alice Smith, account ••••1234?")
        .setExtraData(serverNonce)                                  // freshness only
        .build()
        .presentPrompt(ContextCompat.getMainExecutor(context), object : ConfirmationCallback() {
            override fun onConfirmed(dataThatWasConfirmed: ByteArray) {
                val s = Signature.getInstance("SHA256withECDSA")
                s.initSign(confirmationKey)                         // setUserConfirmationRequired(true)
                s.update(dataThatWasConfirmed)
                api.confirm(opId, dataThatWasConfirmed, s.sign())
            }
        })
} else {
    signWithBiometric(opId, canonicalBytes)                         // strongest available alternative
}
```

```text
[*] ConfirmationPrompt.isSupported -> false     (test device A)
[*] ConfirmationPrompt.isSupported -> false     (test device B)
```

On both test devices APC was unavailable and the app used the biometric fallback, which passed GT-0025-3 to GT-0025-6. No APC finding; the residual risk is noted.

### GT-0025-8: Evidence retention and audit logging (Android, iOS)

Guler Tech methodology. Platform: Android, iOS (client-observable and backend). Type: dynamic (network, manual) and review.

#### Overview

Non-repudiation is decided after the fact, from what the provider kept. A mobile tester usually cannot inspect the evidence store, but can collect what the client exposes, verify a real evidence record independently when the provider supplies one, and put precise questions in the report.

#### Prerequisites

- Completed critical actions on a test account; where possible, a contact on the backend team.

#### Steps

1. **Collect client-observable evidence.** Transaction history and receipts (do they show the device, time and approval method?); responses to the confirm request (an evidence or receipt ID, a server timestamp); notification of the approval to another channel; a data-subject access request export for the test account, if the engagement allows it.

2. **Request an evidence record** for one of your test transactions and verify it yourself. Given the signed bytes, the signature and the public key (or attestation leaf certificate):

   ```bash
   openssl x509 -in leaf.pem -pubkey -noout > pub.pem          # if you were given the certificate
   openssl dgst -sha256 -verify pub.pem -signature sig.der signed.bin
   ```

   `Verified OK` means the record is internally consistent. Then check that `signed.bin` decodes to the transaction you approved (amount, payee, nonce, time), and that the public key matches the key enrolled from your test device (compare with the GT-0025-3 chain or the enrolment request).

3. **Ask, and record the answers:** Is the signed data, signature, key and certificate chain stored for every critical action? For how long? In what store, and who can modify or delete entries? Is there hash chaining, WORM storage, trusted timestamping or a separate log system (ASVS 5.0 16.4.2, 16.4.3)? Are times from a synchronised source and recorded in UTC (16.2.2)? Are authentication and approval events logged with the factor used (16.3.1)? Are verification failures logged and alerted on (16.3.2, 16.3.3)? Are evidence records protected as personal data?

4. **Check the client does not leak the evidence.** Signed payloads and signatures in Logcat or the unified log, or stored unencrypted on the device, are a storage finding (see the [STORAGE guide](/mobile/masvs-storage-1-secure-storage-guide/)), not evidence.

#### Observation

Screenshots of receipts and history, the evidence record and your verification output, and the backend team's answers (or the fact that none were available).

#### Evaluation

The test **fails** if the provider does not retain the signed data and signature for critical actions, if the retained record cannot be verified independently (your step 2 fails or the data does not match the transaction), or if the evidence store is modifiable by application operators without detection. Record it as **not verified** — not as a pass — if no backend information was available.

It **passes** if a sample record verifies, matches the approved transaction and the enrolled key, and the provider documents tamper-evident, access-controlled retention with synchronised time.

#### Demo

```text
$ openssl dgst -sha256 -verify pub.pem -signature sig.der signed.bin
Verified OK
$ xxd signed.bin | head -3
00000000: 0024 636f 6d2e 6578 616d 706c 652e 6261  .$com.example.ba
00000010: 6e6b 2f70 6179 6d65 6e74 2d61 7070 726f  nk/payment-appro
00000020: 7661 6c2f 7632 0009 7061 792d 3737 3831  val/v2..pay-7781
00000030: 3000 0770 6179 6d65 6e74 0000 0000 0000  0..payment......
```

The record verifies, carries the context label and the operation ID, and the rest decodes to the £25.00 (`2500` minor units) test payment, the payee and the server nonce. The backend team confirmed records are written to a separate, write-once store with daily signed chain heads; the test passes.

## Secure implementation

A design that holds up in a dispute has the same shape on both platforms:

1. **Enrol** a signing key per device, behind step-up ([MASWE-0023](/mobile/maswe-0023-step-up-authentication-not-implemented/)): hardware-backed, sign-only, per-operation strong biometrics, invalidated on enrolment change. On Android send the attestation chain; on iOS send an App Attest attestation over the public key. The server verifies and stores both.
2. **Create** each critical operation on the server, with a nonce and a canonical representation.
3. **Display** the human-relevant fields in the app (and, where supported, in APC's trusted UI), defended against overlays.
4. **Sign** the canonical bytes (or APC's `dataThatWasConfirmed`) after per-operation user authentication.
5. **Verify** on the server against the stored key, rebuilding the bytes; consume the nonce; execute.
6. **Retain** an evidence record in tamper-evident storage.

### Android: canonical approval bytes and biometric-bound signing

Key creation and the `BiometricPrompt` flow are in [MASWE-0016](/mobile/maswe-0016-key-access-not-restricted/#android-transaction-signing-key-bound-to-strong-biometrics); a length-prefixed canonical encoding is in [MASWE-0010](/mobile/maswe-0010-improper-signature-generation/#android-sign-a-structured-context-labelled-transaction). The pieces specific to non-repudiation are what goes into the bytes and the fact that the screen is built from the same object:

```kotlin
data class Approval(
    val opId: String, val type: String, val amountMinor: Long, val currency: String,
    val payeeName: String, val payeeAccount: String, val reference: String,
    val serverNonce: ByteArray, val keyId: String, val clientTime: Long
) {
    fun displayText(): String =                                     // shown on screen and in the prompt
        "Pay ${formatMinor(amountMinor, currency)} to $payeeName, account ${mask(payeeAccount)}, ref $reference"

    fun canonicalBytes(): ByteArray = ByteArrayOutputStream().use { bos ->
        DataOutputStream(bos).use { out ->
            out.writeUTF("com.example.bank/payment-approval/v2")    // context label
            out.writeUTF(opId); out.writeUTF(type)
            out.writeLong(amountMinor); out.writeUTF(currency)
            out.writeUTF(payeeName); out.writeUTF(payeeAccount); out.writeUTF(reference)
            out.writeShort(serverNonce.size); out.write(serverNonce)
            out.writeUTF(keyId); out.writeLong(clientTime)
        }
        bos.toByteArray()
    }
}
```

Build the approval screen, the `BiometricPrompt` description and the signed bytes from the same `Approval` instance, received from the server's pending operation, and send only `opId`, `keyId`, `clientTime` and the signature: the server already has the rest. Add `setHideOverlayWindows(true)` (with the `HIDE_OVERLAY_WINDOWS` permission) to the approval activity and `filterTouchesWhenObscured` to the Confirm button (MASTG-BEST-0040). Where `ConfirmationPrompt.isSupported()` is true, use APC as in the [GT-0025-7 demo](#gt-0025-7-use-of-android-protected-confirmation-android) with a separate confirmation-bound key, and tell the server which path you used.

### iOS: Secure Enclave approval

```swift
import CryptoKit
import LocalAuthentication

struct Approval {
    let opId: String, type: String, amountMinor: Int64, currency: String
    let payeeName: String, payeeAccount: String, reference: String
    let serverNonce: Data, keyId: String, clientTime: Int64

    func canonicalBytes() -> Data {
        var d = Data()
        func put(_ s: String) { let b = Data(s.utf8); d.append(UInt16(b.count).bigEndianData); d.append(b) }
        put("com.example.bank/payment-approval/v2")
        put(opId); put(type)
        d.append(amountMinor.bigEndianData); put(currency)
        put(payeeName); put(payeeAccount); put(reference)
        d.append(UInt16(serverNonce.count).bigEndianData); d.append(serverNonce)
        put(keyId); d.append(clientTime.bigEndianData)
        return d
    }
}

extension FixedWidthInteger {
    var bigEndianData: Data { withUnsafeBytes(of: self.bigEndian) { Data($0) } }
}

func sign(_ approval: Approval, keyData: Data, displayText: String) throws -> Data {
    let context = LAContext()
    context.touchIDAuthenticationAllowableReuseDuration = 0         // a recent unlock does not count
    context.localizedReason = displayText
    let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: keyData,
                                                        authenticationContext: context)
    return try key.signature(for: approval.canonicalBytes()).derRepresentation
}
```

The key is created with `[.privateKeyUsage, .biometryCurrentSet]` and `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` ([MASWE-0016](/mobile/maswe-0016-key-access-not-restricted/#ios-secure-enclave-signing-key-with-current-set-biometrics)) and its public key is registered with an App Attest attestation ([MASWE-0010](/mobile/maswe-0010-improper-signature-generation/#ios-bind-your-signing-key-to-app-attest)). The server encodes the integers big-endian and the strings as 16-bit length plus UTF-8, exactly as here; Java's `writeUTF` uses modified UTF-8, which differs from standard UTF-8 only for NUL and supplementary characters, so if you share one format across platforms, define it once and test both against the server with non-ASCII payee names.

### Server: verify and record

```javascript
// approve.js — illustrative
const crypto = require('crypto');

async function confirmApproval(req, res) {
  const op = await ops.getPending(req.params.opId, req.user.id);
  const key = await keys.active(req.user.id, req.body.keyId);         // enrolled with verified attestation
  if (!op || !key) return res.status(403).json({ error: 'invalid' });

  const signed = canonicalBytes(op, key.keyId, req.body.clientTime);  // rebuilt from server state
  const sig = Buffer.from(req.body.signature, 'base64');
  const valid = crypto.verify('sha256', signed, key.publicKeyPem, sig);
  if (!valid || !(await ops.consumeNonce(op.id))) {
    await evidence.append({ opId: op.id, result: 'rejected', keyId: key.keyId, at: new Date().toISOString() });
    return res.status(403).json({ error: 'invalid' });
  }

  await evidence.append({                                             // append-only, hash-chained store
    opId: op.id, type: op.type, userId: req.user.id, keyId: key.keyId,
    path: req.body.path,                                              // "apc" or "biometric"
    signedBytes: signed.toString('base64'), signature: req.body.signature,
    enrolmentRef: key.enrolmentId, result: 'verified',
    receivedAt: new Date().toISOString()
  });
  await ops.execute(op.id);                                           // exactly what was signed
  res.json({ status: 'EXECUTED', evidenceId: op.id });
}
```

The `evidence.append` implementation should include the previous record's hash in each new record and write to storage the application cannot rewrite; periodically sign or externally anchor the chain head. Reject client clocks that differ wildly from the server's, but record both.

### Design checklist

- One key per device and purpose; enrolment behind step-up; revocation on device loss.
- Per-operation strong biometrics; no device-credential fallback for high-value approvals unless documented (MASWE-0021).
- Every displayed field in the signed data; nothing signed that is not displayed; server nonce and context label always present.
- Server rebuilds, verifies, consumes the nonce and executes in one transaction.
- Attestation (Android) or App Attest binding (iOS) checked at enrolment and stored with the key.
- APC where supported, with a recorded path; overlay defences on Android approval screens.
- Evidence records retained, tamper-evident, time-synchronised and access-controlled.

## Rating findings

Rate on what the action is worth, whether the gap lets an attacker *change* what is executed (fraud) or only weakens the provider's *evidence* (dispute risk), and what the attacker needs.

| Rating | Conditions |
|---|---|
| **Critical** | The server executes a high-value critical action with business data that is **not covered by the user's signature** (GT-0025-6 "altered business data" succeeds), or accepts signatures from keys not registered to the user, so a token thief, a tampered app or a network attacker inside the app can change amount or payee while the user approves something else. |
| **High** | Critical actions (payments, payee changes, contract acceptance, wallet signatures or presentations) carry **no user evidence**: only a bearer token or a MAC, or a signature from a key usable without user authentication (proved with GT-0016-3/GT-0016-6), or a software key. Also: the server accepts enrolment of unattested or software keys for transaction signing; blind signing of server-supplied data the app does not display. |
| **Medium** | Signatures cover the transaction, but with weaknesses that reduce their evidential value: authorisation windows instead of per-operation, device-credential fallback or any-biometry for high-value actions, displayed fields missing from the signed data (references, dates), no evidence retention or a mutable evidence store (GT-0025-8 fails), approval screens without overlay protection on Android. |
| **Low** | Sound biometric-bound signing with residual WYSIWYS risk on compromised devices documented (GT-0025-5 step 4) but APC available and unused on a significant share of the user base; missing context label or client timestamp; evidence retention undocumented. |
| **Info** | APC unavailable on target devices and the strongest alternative implemented correctly; evidence controls could not be verified because the backend was out of scope (state "not verified"). |

When you report, separate the two kinds of impact. "An attacker can change what is executed" is a fraud finding and is rated by the money or data at stake. "The provider cannot prove what the user approved" is an evidence finding and is rated by the dispute exposure. For both, give the action, the request, what was signed (hook output), what was shown (screenshot), the server's response to the GT-0025-6 cases, and the key's attestation or access-control evidence. Avoid legal conclusions; describe what evidence exists and how strong it is.

## References

- OWASP MASWE — [MASWE-0025: Lack of Non-Repudiation for Critical Actions](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0025/) (CC BY-SA 4.0)
- OWASP MASWE — [MASWE-0016](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0016/), [MASWE-0010](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0010/), [MASWE-0011](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0011/), [MASWE-0020](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0020/), [MASWE-0021](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0021/), [MASWE-0022](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0022/), [MASWE-0023](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0023/), [MASWE-0039](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0039/) (CC BY-SA 4.0)
- OWASP MAS Profiles — [MAS-L2](https://mas.owasp.org/Profiles/MAS-L2/) and [MAS-EUDIW](https://mas.owasp.org/Profiles/MAS-EUDIW/) (CC BY-SA 4.0)
- OWASP MASTG — [Mobile App Authentication Architectures](https://mas.owasp.org/MASTG/0x04e-Testing-Authentication-and-Session-Management/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0001: Biometric Authentication](https://mas.owasp.org/MASTG/knowledge/android/MASVS-AUTH/MASTG-KNOW-0001/), [MASTG-KNOW-0043: Android KeyStore](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0043/), [MASTG-KNOW-0044: Key Attestation](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0044/), [MASTG-KNOW-0022: Overlay Attacks](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0022/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0057: Keychain Services](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-AUTH/MASTG-KNOW-0057/), [MASTG-KNOW-0066: CryptoKit](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0066/), [MASTG-KNOW-0069: Key Management](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0069/), [MASTG-KNOW-0135: Virtual Devices Detection](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0135/) (App Attest validation) (CC BY-SA 4.0)
- OWASP MASTG — beta tests [MASTG-TEST-0266](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0266/), [MASTG-TEST-0267](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0267/), [MASTG-TEST-0268](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0268/), [MASTG-TEST-0269](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0269/), [MASTG-TEST-0270](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0270/), [MASTG-TEST-0271](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0271/), [MASTG-TEST-0326](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0326/), [MASTG-TEST-0327](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0327/), [MASTG-TEST-0328](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0328/), [MASTG-TEST-0329](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0329/), [MASTG-TEST-0330](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0330/), [MASTG-TEST-0307](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0307/), [MASTG-TEST-0308](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0308/), [MASTG-TEST-0340](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0340/) (CC BY-SA 4.0)
- OWASP MASTG — legacy (MASTG v1) tests [MASTG-TEST-0018](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0018/), [MASTG-TEST-0064](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0064/), [MASTG-TEST-0035](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0035/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-BEST-0040: Preventing Overlay Attacks](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0040/); techniques [MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/), [MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/), [MASTG-TECH-0120](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0120/); tools [Frida (MASTG-TOOL-0031)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/), [objection (MASTG-TOOL-0038)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0038/), [Burp Suite (MASTG-TOOL-0077)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0077/) (CC BY-SA 4.0)
- OWASP ASVS 5.0 — [V16 Security Logging and Error Handling](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md)
- OWASP WSTG — [Test Ability to Forge Requests (WSTG-BUSL-02)](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/02-Test_Ability_to_Forge_Requests) and [Test Integrity Checks (WSTG-BUSL-03)](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/03-Test_Integrity_Checks)
- [Android Developers — Android Protected Confirmation](https://developer.android.com/privacy-and-security/security-android-protected-confirmation), [`ConfirmationPrompt`](https://developer.android.com/reference/android/security/ConfirmationPrompt), [`ConfirmationCallback`](https://developer.android.com/reference/android/security/ConfirmationCallback), [`setUserConfirmationRequired`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setUserConfirmationRequired(boolean))
- [Android Open Source Project — Protected Confirmation](https://source.android.com/docs/security/features/protected-confirmation) and [commit 07fec0ff, "Deprecating the aidl for Android Protected Confirmation"](https://android.googlesource.com/platform/system/security/+/07fec0ff)
- [Android Developers — Verifying hardware-backed key pairs with key attestation](https://developer.android.com/privacy-and-security/security-key-attestation) and [Google — android-key-attestation sample](https://github.com/google/android-key-attestation)
- [Android Developers Blog — Android Protected Confirmation: Taking transaction security to the next level (2018)](https://android-developers.googleblog.com/2018/10/android-protected-confirmation.html)
- [Apple — Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave), [`SecAccessControlCreateFlags`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags), [CryptoKit `SecureEnclave`](https://developer.apple.com/documentation/cryptokit/secureenclave), [Validating apps that connect to your server](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server)
- [Regulation (EU) No 910/2014 (eIDAS)](https://eur-lex.europa.eu/eli/reg/2014/910/oj) and [Regulation (EU) 2024/1183 (European Digital Identity Framework)](https://eur-lex.europa.eu/eli/reg/2024/1183/oj)
- [Directive (EU) 2015/2366 (PSD2)](https://eur-lex.europa.eu/eli/dir/2015/2366/oj) (Article 72) and [Commission Delegated Regulation (EU) 2018/389](https://eur-lex.europa.eu/eli/reg_del/2018/389/oj) (Article 5); [The Payment Services Regulations 2017 (UK)](https://www.legislation.gov.uk/uksi/2017/752/contents) (regulation 75)
- [RFC 8949: CBOR](https://www.rfc-editor.org/rfc/rfc8949) (section 4.2, deterministic encoding), [RFC 8785: JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785), [RFC 3161: Time-Stamp Protocol](https://www.rfc-editor.org/rfc/rfc3161), [RFC 9162: Certificate Transparency 2.0](https://www.rfc-editor.org/rfc/rfc9162), [RFC 9449: DPoP](https://www.rfc-editor.org/rfc/rfc9449), [RFC 8705: OAuth 2.0 Mutual-TLS](https://www.rfc-editor.org/rfc/rfc8705)
- [CWE-451: User Interface (UI) Misrepresentation of Critical Information](https://cwe.mitre.org/data/definitions/451.html) and [CWE-778: Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
