---
title: "Step-Up Authentication Not Implemented for Sensitive Actions (MASWE-0023)"
date: 2026-11-09 08:33:00 +0000
subcategory: auth
summary: "Which mobile actions need step-up authentication, how the server must enforce, bind and expire it, and how to prove client-only step-up can be bypassed."
refs: [MASWE-0023, MASVS-AUTH-3, MASVS-PLATFORM-3, CWE-306]
tags: [android, ios, masvs-auth, step-up, session-management, frida]
---

This note is part of our [MASVS-AUTH guide](/mobile/masvs-auth-authentication-guide/) and covers OWASP [MASWE-0023](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0023/): sensitive actions that can be performed with nothing more than an existing session. The login at the start of the session tells the backend that someone knew the password, or had the device, at some point. It says nothing about whether the person holding the phone *now* is the account owner, or whether a request carrying a valid token came from the app at all. Step-up authentication closes that gap for the operations that matter: paying a new payee, changing the email address or the MFA settings, revealing a card number, binding a new device. Below you will find which actions need it, the mechanisms that can provide it, how the server must enforce it (step-up tokens, `acr`/`amr`/`auth_time`, RFC 9470), how to bind it to the one transaction it approves, and seven tests that show whether the backend actually demands fresh authentication or merely trusts the app's screen flow.

> **Note:** At the time of writing, MASWE-0023 has no linked Knowledge pages or Tests on mas.owasp.org; the weakness page says "No Tests Yet". We searched the MASTG knowledge, tests, beta tests, techniques, best practices and demos; the genuinely related items are listed in [Related OWASP material](#related-owasp-material). The Knowledge and Testing sections below are **Guler Tech methodology**, citing OWASP IDs only where the material exists.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Generic: Which actions need step-up (Guler Tech)](#generic-which-actions-need-step-up-guler-tech)
  - [Generic: Step-up mechanisms and what they prove (Guler Tech)](#generic-step-up-mechanisms-and-what-they-prove-guler-tech)
  - [Generic: Server-side enforcement, step-up tokens and RFC 9470 (Guler Tech)](#generic-server-side-enforcement-step-up-tokens-and-rfc-9470-guler-tech)
  - [Generic: Freshness and binding the step-up to the action (Guler Tech)](#generic-freshness-and-binding-the-step-up-to-the-action-guler-tech)
  - [Android: Step-up building blocks (MASTG-KNOW-0001)](#android-step-up-building-blocks-mastg-know-0001)
  - [iOS: Step-up building blocks (MASTG-KNOW-0056, MASTG-KNOW-0057)](#ios-step-up-building-blocks-mastg-know-0056-mastg-know-0057)
  - [Both platforms: Entry points that skip the gate (MASTG-KNOW-0019, MASTG-KNOW-0079, MASTG-KNOW-0080)](#both-platforms-entry-points-that-skip-the-gate-mastg-know-0019-mastg-know-0079-mastg-know-0080)
  - [Android: Overlays on the step-up screen (MASTG-KNOW-0022)](#android-overlays-on-the-step-up-screen-mastg-know-0022)
- [Testing](#testing)
  - [Related OWASP material](#related-owasp-material)
  - [What you can prove from the client](#what-you-can-prove-from-the-client)
  - [GT-0023-1: Sensitive action inventory and step-up map (Android, iOS)](#gt-0023-1-sensitive-action-inventory-and-step-up-map-android-ios)
  - [GT-0023-2: Replaying sensitive requests without step-up evidence (Android, iOS)](#gt-0023-2-replaying-sensitive-requests-without-step-up-evidence-android-ios)
  - [GT-0023-3: Bypassing a client-side step-up gate (Android)](#gt-0023-3-bypassing-a-client-side-step-up-gate-android)
  - [GT-0023-4: Bypassing a client-side step-up gate (iOS)](#gt-0023-4-bypassing-a-client-side-step-up-gate-ios)
  - [GT-0023-5: Step-up binding, freshness and reuse (Android, iOS)](#gt-0023-5-step-up-binding-freshness-and-reuse-android-ios)
  - [GT-0023-6: Entry points that skip the step-up (Android, iOS)](#gt-0023-6-entry-points-that-skip-the-step-up-android-ios)
  - [GT-0023-7: Strength of the step-up mechanism itself (Android, iOS)](#gt-0023-7-strength-of-the-step-up-mechanism-itself-android-ios)
- [Secure implementation](#secure-implementation)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

MASWE-0023 applies when an app lets a user perform a sensitive action within an authenticated session without re-confirming who they are. The OWASP requirement is *"The app enforces step-up authentication before granting access to sensitive functionality."* Step-up means that, even inside a valid session, the backend demands a fresh authentication event — a password, a second factor, a crypto-bound biometric, a passkey assertion — before it executes one particular operation, and that it checks the evidence of that event itself.

Two attacker models drive this weakness, matching OWASP's attack list for it:

- **Someone with the device and the session** (MAS-ATTACK-0032): the unlocked phone left on the desk, the phone taken from a user's hand, the partner or colleague who knows the device PIN, the stolen phone whose app session is still alive. For them the app's long-lived session is an open door, and the only thing standing between them and a payment or an email change is whatever the app asks for at that moment.
- **Someone with the tokens but not the device** (MAS-ATTACK-0033): an access or refresh token stolen through a log, a backup, a malicious SDK, a proxy on a rooted device or any other weakness in this series. They never see the app's UI. If step-up only exists as a screen in the app, it does not exist for them.

OWASP's threat for MASWE-0023 sums both up as MAS-THREAT-0023: *"Attackers can perform sensitive actions in a victim's authenticated session."*

The second model is the reason MASVS-AUTH insists that enforcement happen on the remote endpoint. A biometric prompt, a PIN pad or a "confirm with your password" dialog in the app is useful UI; it is a security control only if the backend refuses the operation without proof that the step-up happened, recently, for this user and for this action. Most of the testing in this note is therefore about the API, not the app. The app is where you find the sensitive actions and capture the requests; the backend is where you prove whether step-up is real.

**MASVS-PLATFORM-3.** OWASP also maps MASWE-0023 to MASVS-PLATFORM-3 ("The app uses the user interface securely"). Step-up is often implemented as a UI flow — a screen that must be passed before another screen is shown — and some of the most sensitive actions are *displays*: a card PAN, a CVV, recovery codes, an IBAN with the full account holder's details. If the gate lives in the navigation rather than in the API, any other way of reaching the screen (a deep link, an exported activity, an App Shortcut, a restored back stack, a notification) skips it; and if the step-up screen itself accepts input, it is a target for overlays. We cover both, linking to the dedicated PLATFORM weaknesses rather than repeating them.

**Profiles: L2 and EUDIW.** MASWE-0023 is tagged with the [MAS-L2](https://mas.owasp.org/Profiles/MAS-L2/) and [MAS-EUDIW](https://mas.owasp.org/Profiles/MAS-EUDIW/) profiles. MAS-L2 covers apps where compromise has serious consequences — banking, payments, health, government, enterprise access. MAS-EUDIW is the profile for European Digital Identity Wallet apps under the revised eIDAS framework (Regulation (EU) 2024/1183). For a wallet, presenting a credential to a relying party, signing with a qualified signature and adding or removing credentials are the sensitive actions; for a banking app regulated under PSD2, strong customer authentication for payments and for "actions through a remote channel which may imply a risk of payment fraud" is a legal requirement, not a hardening option. If your engagement is scoped to L1, report missing step-up as a recommendation unless the action is plainly dangerous (account takeover through an email change is dangerous at any level).

The weakness maps to [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html) and to MSTG-AUTH-10 in MASVS v1 ("Sensitive transactions require step-up authentication"). OWASP also maps it to the Android Core App Quality guideline *Biometric_Authentication*. The general web guidance is in OWASP ASVS 5.0, V7.5 "Defenses Against Session Abuse": 7.5.1 (L2) requires full re-authentication before changing sensitive account attributes such as email, phone number or MFA configuration; 7.5.3 (L3) requires further authentication with at least one factor before highly sensitive transactions. NIST SP 800-63B-4 defines reauthentication timeouts per assurance level (for AAL2, an overall timeout that should be no more than 24 hours and an inactivity timeout that should be no more than one hour) and explicitly allows an authentication process to "provide step-up authentication to raise the session's AAL".

## Modes of Introduction

OWASP lists four modes of introduction. Each has a recognisable shape in mobile apps.

**No re-authentication for sensitive actions.** The app logs in once — often with a long-lived refresh token and a "stay signed in" default — and every operation, including payments to new payees, card reveals and credential changes, rides on that session. The biometric "app unlock" at launch is sometimes mistaken for step-up; it is not. It happens before the user has chosen an action, it is usually event-bound (see [MASWE-0020](/mobile/maswe-0020-local-authentication-bypass/)), and the backend rarely knows it happened.

**Step-up not bound to the action.** A re-authentication challenge exists but proves only that "the user authenticated recently". The result is a session flag (`stepped_up = true` for 15 minutes) or a bearer token that the client can attach to any request. One approval — perhaps for a small, harmless-looking action — then authorises a different, larger or modified one. In payments this is exactly what PSD2 "dynamic linking" forbids.

**Step-up not enforced server-side.** The app shows a biometric prompt or a PIN pad, and on success calls the same API it would have called anyway. Sometimes the app sends a flag (`"biometricVerified": true`, `X-Auth-Level: 2`) that the server trusts. Sometimes the server enforces step-up on the mobile endpoint but not on the equivalent web, legacy (`/v1/`) or GraphQL endpoint.

**Uniform assurance level.** Every API operation sits behind the same token check. There is no classification of actions by risk, so the developers had nowhere to attach a step-up requirement even if they wanted one.

Further variants we see regularly:

- **Thresholds computed by the client.** "Step-up above £500" is decided in the app, so a request for £5,000 with the step-up skipped is accepted; or the server threshold can be avoided by splitting a payment, by currency choice, or by scheduling.
- **The factor protects itself badly.** The phone number that receives the step-up OTP, or the device key that signs approvals, can be changed or re-enrolled without step-up — and once the attacker controls the factor, every later step-up succeeds.
- **Weak fallback.** A crypto-bound biometric step-up that falls back to an SMS OTP, or to "answer your security question", when the biometric "fails" (see [MASWE-0021](/mobile/maswe-0021-non-biometric-fallback-for-sensitive-transactions/) for the device-credential variant).
- **Step-up state on the client.** The app caches "authenticated within the last five minutes" in memory or `SharedPreferences`/`UserDefaults` and decides locally whether to prompt again.
- **Entry points that bypass the flow.** A deep link, exported activity, notification, widget or restored screen lands directly on the sensitive screen, past the step-up gate (MASVS-PLATFORM-3).

## Impact

- **Financial loss.** Whoever holds the session — the person with the unlocked phone, or the holder of a stolen token — can initiate transfers, add payees, buy goods or redeem balances.
- **Compromise of sensitive data.** Card numbers, CVVs, recovery codes, identity documents, health records or full account statements can be revealed or exported without the legitimate user's involvement.
- **Persistent account takeover.** Changing the email address, phone number or password, disabling MFA, or enrolling an attacker-controlled device turns a short window of access into permanent control, and usually locks the real user out of recovery.
- **Loss of evidence.** Without step-up, the backend cannot distinguish an action by the user from an action by someone holding the user's session, which weakens fraud handling and dispute resolution (see [MASWE-0025](/mobile/maswe-0025-lack-of-non-repudiation/)).

## Mitigations

- **Classify actions by risk** and write the classification down: which operations require step-up, with which mechanism, and how fresh the authentication must be.
- **Require step-up for sensitive actions** with a mechanism matched to the risk: a crypto-bound biometric over a Keystore or Secure Enclave key, a passkey assertion with user verification, or a second factor — not just the app-unlock biometric from launch.
- **Enforce on the server.** The backend decides that step-up is needed, issues the challenge, verifies the evidence and refuses the operation without it. Nothing the client says about its own state counts.
- **Bind the step-up to the action.** The evidence covers this specific transaction (amount, payee, the field being changed) and a server nonce, so it cannot be replayed or applied to a different operation.
- **Keep it fresh and single-use.** Short maximum age (minutes, not hours), one operation per approval for high-risk actions, invalidated when the session ends.
- **Protect every entry point.** Enforce the requirement in the API, and in the app check it at the point of use rather than in the navigation flow.
- **Protect the factors.** Changing a factor, the recovery channel or the device binding is itself a step-up action, ideally using the *existing* factor.

## Knowledge

None of the sections below is an OWASP Knowledge page dedicated to MASWE-0023. Where a MASTG Knowledge page covers a building block we name it in the heading; the step-up material is ours. Biometric mechanics are covered in our [MASTG-KNOW-0001 note](/mobile/mastg-know-0001-biometric-authentication/) and key restrictions in [MASWE-0016](/mobile/maswe-0016-key-access-not-restricted/); we summarise and link.

### Generic: Which actions need step-up (Guler Tech)

Step-up is a business decision expressed as a security control, so start with the list of actions, not with the mechanisms. The table below is the baseline we use for L2 apps; adjust it to the app's domain.

| Action class | Examples | Why it needs step-up | Typical requirement |
|---|---|---|---|
| Moving money | Payment to a **new** payee, adding or editing a payee, raising limits, international transfers, standing orders, direct debit mandates, crypto withdrawals | Direct, often irreversible loss | Per transaction, bound to amount and payee (PSD2 dynamic linking in the EU and UK) |
| Changing credentials and recovery | Email address, phone number, password, PIN, security questions, recovery codes | Converts temporary access into permanent takeover | Full re-authentication (ASVS 5.0 7.5.1), ideally with the existing factor; notify the old channel |
| Changing MFA | Disabling MFA, adding a TOTP seed, enrolling a new phone for push, removing a passkey | Removes or replaces the factor that protects everything else | Re-authentication with an existing factor |
| Device binding | Activating the app on a new device, registering a new transaction-signing key, re-enrolling biometrics in the app | The new device becomes a trusted authenticator | Strong step-up plus out-of-band confirmation on the old device or channel |
| Revealing secrets | Full PAN, CVV, PIN reveal, recovery codes, API keys, private keys, QR codes for TOTP seeds | Data that enables fraud elsewhere | Per reveal, short-lived display, no caching |
| Exporting data | Full statements, health records, identity documents, "download my data" | Bulk disclosure | Step-up; deliver to a verified channel |
| Account lifecycle | Account deletion, closing products, adding an authorised user, role elevation | Destructive or privilege-changing | Step-up, with a confirmation that names the action |
| Wallet operations (EUDIW) | Presenting a credential, qualified signature creation, adding or deleting a credential, changing the wallet PIN | Identity is the asset | User authentication per presentation or signature as the wallet's design specifies |
| Session and device management | Listing and terminating other sessions, trusting a device ("remember me") | Lets an attacker evict the real user or entrench themselves | Re-authentication with at least one factor (ASVS 5.0 7.5.2) |

Not every action deserves the same friction. Viewing the balance does not; a £5 transfer to a payee used last week may be exempt under a risk-based policy. That is acceptable, as long as the exemption is decided **on the server** with information the client cannot forge, and as long as the exemption cannot be used to dodge step-up for the dangerous variant (splitting one large payment into many small ones, for example).

### Generic: Step-up mechanisms and what they prove (Guler Tech)

Each step-up mechanism proves something different to the server. Rate them by what the server can verify, not by what the user sees.

| Mechanism | What the server can verify | Resists | Main weaknesses |
|---|---|---|---|
| Re-enter account password | User knows the password, now | Unattended unlocked device | Phishable; shoulder-surfing; useless if the attacker phished the password in the first place |
| SMS or email OTP | Control of a phone number or mailbox, now | Unattended device (if the OTP goes elsewhere) | SIM swap, SMS interception, OTP forwarding, the OTP often arrives on the same phone; NIST SP 800-63B-4 restricts SMS/PSTN as an authenticator |
| TOTP (authenticator app) | Possession of the seed | Token theft without the seed | Seed often on the same device; phishable in real time |
| Push approval in the app | The approving device holds the session or key the server associates with the user | Remote token theft | Approval fatigue ("MFA bombing"); unbound "Approve?" prompts; weak if the approval call is just an authenticated API request |
| In-app PIN verified by the server | Knowledge of the app PIN | Unattended device | Brute force without server-side limits; PIN pad overlays |
| Local biometric, event-bound | Nothing; the server sees an ordinary request | Nothing beyond the UI | One Frida hook bypasses it ([MASWE-0020](/mobile/maswe-0020-local-authentication-bypass/)) |
| Local biometric, crypto-bound (Keystore or Secure Enclave key, per-operation) | A signature from a device-bound key that only works after user authentication | Unattended device, token theft, instrumentation without the user's biometric | Only as strong as the key's restrictions ([MASWE-0016](/mobile/maswe-0016-key-access-not-restricted/)) and the enrolment step |
| Passkey or WebAuthn assertion with user verification | A signature over the server's challenge from a credential registered for the user, with the UV flag set | Phishing (origin- or app-bound), token theft | UV flag must be checked; synced passkeys live in the user's cloud account, not only this device |
| Transaction signing with a device key | A signature over the transaction itself | All of the above, plus tampering with the transaction between approval and execution | Requires careful canonicalisation; WYSIWYS is still only as good as the app UI ([MASWE-0025](/mobile/maswe-0025-lack-of-non-repudiation/)) |

Three rules follow from the table:

1. **The evidence must reach the server.** A local check that produces a boolean is not step-up. The output that matters is something the server can verify: a password it checks, an OTP it issued, a signature with a key it registered, a passkey assertion over its challenge, or a token its authorisation server minted after one of those.
2. **The factor should be independent of the session.** An SMS OTP that arrives on the same phone that is already unlocked and logged in adds little against MAS-ATTACK-0032. A crypto-bound biometric does, because it needs the user's finger or face, not just the device.
3. **The factor must protect itself.** If enrolling a new signing key requires only a valid session, a token thief enrols their own key and passes every subsequent "biometric" step-up.

Push approvals deserve a special mention because they are often the default mobile step-up for web logins and for transactions initiated elsewhere. A push that says "Approve sign-in?" with Approve and Deny buttons is vulnerable to approval fatigue: the attacker triggers it repeatedly until the user taps Approve. Number matching (the user types a code shown on the initiating screen), showing the transaction details and location in the approval, rate-limiting prompts, and making the approval a signature over the request (not just an authenticated `POST /approve`) all help. The OpenID Foundation's Client-Initiated Backchannel Authentication (CIBA) specification formalises decoupled approvals of this kind and includes a `binding_message` shown on both devices for the same reason.

### Generic: Server-side enforcement, step-up tokens and RFC 9470 (Guler Tech)

A server-enforced step-up has four parts: a **policy** that says which operations need which authentication, a **challenge** that tells the client what is missing, **evidence** that the client returns, and a **check** at the point of execution. There are two common designs.

**Design A: the authorisation server raises the session's assurance.** In an OAuth 2.0 / OpenID Connect architecture, the access token records how and when the user authenticated:

| Claim | Meaning | Source |
|---|---|---|
| `auth_time` | Time of the last active user authentication | OpenID Connect Core; RFC 9068 for JWT access tokens |
| `acr` | Authentication Context Class Reference — the assurance level satisfied | OpenID Connect Core; RFC 9068 |
| `amr` | Authentication Methods References — the methods used (`pwd`, `otp`, `hwk`, `face`, `fpt`, `mfa`, `user`, ...) | OpenID Connect Core; values registered in RFC 8176 |

When the resource server receives a request for a sensitive operation, it checks those claims against its policy. If they are insufficient it answers with the standard challenge defined in **RFC 9470, "OAuth 2.0 Step Up Authentication Challenge Protocol"** (Bertocci and Campbell, September 2023):

```text
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="insufficient_user_authentication",
  error_description="A more recent authentication is required",
  acr_values="urn:example:acr:mfa", max_age="300"
```

`acr_values` lists the acceptable authentication contexts in order of preference; `max_age` is the number of seconds allowed since the last active authentication. The client then sends the user back through the authorisation server — in a native app, through the system browser (`ASWebAuthenticationSession` on iOS, Custom Tabs on Android, as RFC 8252 requires) — with the same `acr_values` and `max_age` in the authorisation request (OpenID Connect also defines `prompt=login` to force re-authentication). It receives a new access token with a fresh `auth_time` and the higher `acr`, and retries. RFC 9470 also says that the resource server learns these values from the JWT access token (`acr`, `auth_time`, per RFC 9068) or from token introspection (RFC 7662), where they appear as top-level members.

Two things go wrong in practice. The resource server never checks the claims (the challenge exists in the documentation and nowhere else), or the claims are checked but the new token is a general-purpose token valid for an hour, so one step-up unlocks every sensitive operation for that hour.

**Design B: an action-specific step-up token or signature.** The backend issues a challenge for one pending operation — "transfer 4f1c… needs approval, nonce N" — and accepts only evidence bound to it: an OTP the server associated with that operation, a device-key signature over the operation and nonce, or a short-lived, single-use step-up token whose claims name the operation. This is the design most mobile banking APIs use, and it is the one that satisfies dynamic linking. A minimal step-up token, if you issue one, looks like this:

```json
{
  "sub": "user-7781",
  "sid": "session-2a9e",
  "purpose": "payment",
  "txn": "sha256:3b1f…c09a",
  "amr": ["hwk", "face"],
  "auth_time": 1793952000,
  "iat": 1793952001,
  "exp": 1793952121,
  "jti": "7f3c2d0e-1c55-4d8a-9a51-0f8b6c1d2e44"
}
```

The executing endpoint verifies the signature on the token, that `sub` and `sid` match the caller's session, that `purpose` and `txn` match *this* request (recomputing the hash from the request it is about to execute), that it has not expired, and that `jti` has not been seen before.

Whatever the design, these are not acceptable evidence:

- a header or body field the client sets (`X-Step-Up: true`, `"authLevel": 2`, `"biometric": "SUCCESS"`);
- a token the client could have minted, or one signed with a key shipped in the app;
- a session flag that survives the operation it was raised for, without expiry or scope;
- the fact that the request arrived through "the confirm endpoint" rather than "the create endpoint", when nothing ties the two together.

### Generic: Freshness and binding the step-up to the action (Guler Tech)

**Freshness.** "Recently authenticated" needs a number. For the most sensitive operations — new payees, credential changes, device binding — use a per-operation approval (effectively `max_age=0`). For lower-risk operations that still need step-up, a window of a few minutes is defensible; an hour is not, and "since login" is not step-up at all. NIST SP 800-63B-4 reauthentication timeouts (AAL2: overall no more than 24 hours, inactivity no more than one hour; AAL3: overall no more than 12 hours, inactivity no more than 15 minutes) are *session* limits; step-up windows for individual actions should be much shorter. The client cannot be trusted to measure freshness: the server compares `auth_time` or the step-up token's `iat` with its own clock.

**Binding.** A step-up proves the user approved *something*. Binding makes sure it was *this*. In the EU and UK, payment services under PSD2 are subject to the regulatory technical standards on strong customer authentication — Commission Delegated Regulation (EU) 2018/389 and its UK onshored equivalent. Article 5, "dynamic linking", requires that the payer is made aware of the amount and the payee, that the authentication code is specific to that amount and payee, that the code accepted corresponds to the original amount and payee, and that any change to either invalidates the code. Outside payments, the same principle protects credential changes: the approval for "change email to a@example.com" must not be usable for "change email to attacker@example.net".

Ways to achieve binding, from strongest to weakest:

1. **Transaction signing.** The client signs a canonical representation of the operation plus a server nonce with a user-authenticated device key (Android Keystore key bound to `BIOMETRIC_STRONG`, iOS Secure Enclave key with `.biometryCurrentSet`). The server rebuilds the canonical bytes from its own record of the pending operation and verifies. Signature generation pitfalls are in [MASWE-0010](/mobile/maswe-0010-improper-signature-generation/); the evidential side is in [MASWE-0025](/mobile/maswe-0025-lack-of-non-repudiation/).
2. **Challenge derived from the operation.** For passkeys, the server can derive the WebAuthn challenge from the pending operation (for example, a hash over a random nonce and the operation's canonical bytes). The authenticator signs the challenge inside `clientDataJSON`, so the assertion is bound to the operation — but the passkey sheet does not show the operation to the user, so binding exists while "what you see is what you approve" depends entirely on the app UI.
3. **OTP associated with the operation on the server.** The server generates an OTP for pending operation X, and only accepts it for X. The SMS text should name the amount and payee so the user can notice a swap.
4. **Rich authorisation requests.** In OAuth deployments, RFC 9396 (Rich Authorization Requests) lets the client request authorisation for structured `authorization_details` — for example a payment with amount and creditor — so the resulting token is scoped to that operation. This is the approach Open Banking and FAPI profiles use.

A step-up that is fresh but unbound still fails the "Step-Up Not Bound to the Action" mode: one approval for a £10 transfer can be reused, by a token thief or by a tampered app, for a £10,000 one.

### Android: Step-up building blocks (MASTG-KNOW-0001)

Related: [MASTG-KNOW-0001](https://mas.owasp.org/MASTG/knowledge/android/MASVS-AUTH/MASTG-KNOW-0001/); our walkthrough is in the [MASTG-KNOW-0001 note](/mobile/mastg-know-0001-biometric-authentication/) and the legacy API in the [MASTG-KNOW-0002 note](/mobile/mastg-know-0002-fingerprintmanager/).

The Android pieces you will see in a step-up flow:

- **`BiometricPrompt` with a `CryptoObject`** (`androidx.biometric`). The only form of biometric step-up a server can rely on: the prompt authorises one `Signature` operation with a Keystore key created with `setUserAuthenticationRequired(true)` and `setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)`. The signature over the server's challenge is the step-up evidence. Without a `CryptoObject`, `onAuthenticationSucceeded` is just a callback (MASTG-TEST-0327 finds this; see MASWE-0020). Allowing `DEVICE_CREDENTIAL` is a policy decision for high-value operations (MASTG-TEST-0326, MASWE-0021); `setConfirmationRequired(false)` lets passive face unlock approve without an explicit tap (MASTG-TEST-0329).
- **Key restrictions.** Per-operation authorisation, invalidation on biometric enrolment (`setInvalidatedByBiometricEnrollment(true)`, MASWE-0022), `setUnlockedDeviceRequired(true)`, and server-side verification through key attestation. These are covered in depth in [MASWE-0016](/mobile/maswe-0016-key-access-not-restricted/). A step-up key with a 300-second validity window is satisfied by the user unlocking the phone; that is not step-up.
- **Credential Manager and passkeys.** `androidx.credentials.CredentialManager` with a `GetPublicKeyCredentialOption` carrying the server's WebAuthn request JSON (`"userVerification": "required"`); the result's `PublicKeyCredential.authenticationResponseJson` goes to the server, which verifies the assertion and the UV flag.
- **`KeyguardManager.createConfirmDeviceCredentialIntent`.** The old way to re-prompt for the device PIN (legacy MASTG-TEST-0017 covered it). It was deprecated in API level 29 in favour of `BiometricPrompt` with `DEVICE_CREDENTIAL`, and like any prompt it is event-bound unless the result is used to unlock a key.
- **Custom Tabs for OIDC step-up.** For Design A, the app opens the authorisation endpoint with `acr_values`/`max_age`/`prompt=login` in a Custom Tab (typically via AppAuth) and receives the new tokens through a verified App Link or a custom scheme redirect, with PKCE.

### iOS: Step-up building blocks (MASTG-KNOW-0056, MASTG-KNOW-0057)

Related: [MASTG-KNOW-0056](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-AUTH/MASTG-KNOW-0056/) and [MASTG-KNOW-0057](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-AUTH/MASTG-KNOW-0057/).

- **`LAContext.evaluatePolicy`.** Returns a Boolean to the app. On its own it is event-bound, bypassable with a single hook (objection's `ios ui biometrics_bypass`, MASTG-TEST-0266/0267, MASWE-0020), and invisible to the server.
- **Keychain items and Secure Enclave keys with access control.** A `SecAccessControl` created with `.biometryCurrentSet` (plus `.privateKeyUsage` for a Secure Enclave key) makes the system require Face ID or Touch ID for each use. Signing a server challenge with such a key — `SecKeyCreateSignature` or CryptoKit's `SecureEnclave.P256.Signing.PrivateKey.signature(for:)` — produces step-up evidence. Use a fresh `LAContext` per operation and keep `touchIDAuthenticationAllowableReuseDuration` at `0`, or a recent unlock can satisfy the prompt. `.userPresence` or `.devicePasscode` allow passcode fallback (MASTG-TEST-0268/0269, MASWE-0021); `.biometryAny` survives enrolment changes (MASTG-TEST-0270/0271, MASWE-0022).
- **Passkeys.** `ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier:)` and `createCredentialAssertionRequest(challenge:)` with `userVerificationPreference = .required`; the `ASAuthorizationPlatformPublicKeyCredentialAssertion` gives you `rawAuthenticatorData`, `rawClientDataJSON` and `signature` for the server to verify.
- **`ASWebAuthenticationSession` for OIDC step-up.** Opens the authorisation server with `acr_values`/`max_age`; set `prefersEphemeralWebBrowserSession` deliberately, since an ephemeral session cannot reuse the browser's login cookie (which is sometimes exactly what you want for a forced re-authentication).

A detail that matters for testing: on both platforms, the text in the biometric prompt (`setTitle`/`setDescription` on Android, `localizedReason` on iOS) comes from the app. The prompt is system UI, but it does not tell the user, or prove to the server, what is being approved. Binding comes from what is signed, not from what the prompt says.

### Both platforms: Entry points that skip the gate (MASTG-KNOW-0019, MASTG-KNOW-0079, MASTG-KNOW-0080)

Related: [MASTG-KNOW-0019: Deep Links](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0019/), [MASTG-KNOW-0132: Android Activities](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0132/), [MASTG-KNOW-0079: Custom URL Schemes](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0079/) and [MASTG-KNOW-0080: Universal Links](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0080/).

When step-up is implemented as navigation — "the Settings screen pushes the PIN screen, which on success pushes the Change Email screen" — the gate exists only on that one path. Every other route to the sensitive screen is a potential bypass:

- **Deep links, App Links and Universal Links** routed by a central router (`examplebank://settings/email`, `https://www.example.com/app/cards/reveal`). Routers frequently map a path straight to a destination screen without re-running the guards the normal path applies. Insecure deep links in general are [MASWE-0029](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0029/).
- **Exported Android activities** that host the sensitive screen, startable by any app with an explicit intent (MASTG-TEST-0364; [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/)).
- **Notifications, App Shortcuts, widgets, Siri Shortcuts and App Intents**, which often launch the destination directly.
- **State restoration.** Android re-creates the back stack after process death; iOS state restoration and SwiftUI scene storage can bring the user back to the screen they left. If the gate ran only on forward navigation, the restored screen appears without it.
- **Back navigation and timeouts.** After the step-up window expires, the screen is still in the back stack; pressing Back returns to it, often with the secret still rendered.

None of these matter if the API enforces step-up: the screen opens, but the request it makes is refused. They become findings when the screen displays data that was fetched without step-up (a PAN cached from an earlier call), or calls an API that does not enforce it. Test them anyway, because they are the easiest way to demonstrate to a client that their "step-up" is a UI convention.

### Android: Overlays on the step-up screen (MASTG-KNOW-0022)

Related: [MASTG-KNOW-0022: Overlay Attacks](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0022/), [MASTG-BEST-0040: Preventing Overlay Attacks](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0040/) and [MASWE-0039: App Vulnerable to Overlay Attacks](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0039/).

A step-up screen asks the user to type something (a password, an app PIN) or to tap a confirmation. On Android, a malicious app with the "display over other apps" permission or an accessibility service can draw over it to capture the PIN, or trick the user into tapping Confirm on an action they cannot see. Banking malware families have done this for years. The app-side defences are `setHideOverlayWindows(true)` with the `HIDE_OVERLAY_WINDOWS` permission (API level 31+), `filterTouchesWhenObscured` on confirmation controls, and checking `FLAG_WINDOW_IS_OBSCURED`/`FLAG_WINDOW_IS_PARTIALLY_OBSCURED`; MASTG-TEST-0340 checks for them. Overlays are a secondary concern for MASWE-0023 — they attack a step-up that exists — but a PIN-pad step-up with no overlay protection on an L2 banking app is worth a line in the report. iOS does not allow third-party apps to draw over other apps, so the equivalent risk there is limited to a tampered app or a compromised OS (MASWE-0025).

## Testing

The tests below are **Guler Tech methodology**. They follow one principle: find every sensitive action, capture the request that performs it, and then prove — with the request, not the screen — whether the backend demands fresh, bound authentication. GT-0023-1 builds the map; GT-0023-2 and GT-0023-5 are the decisive network tests; GT-0023-3 and GT-0023-4 show what a client-only gate is worth; GT-0023-6 and GT-0023-7 cover the routes around the gate and the strength of the gate itself.

### Related OWASP material

No OWASP test is mapped to MASWE-0023. These existing items cover building blocks of a step-up flow or the routes around it; all IDs were found in the MASTG repository.

| ID | Platform | What it checks | Mapped weakness | Relevance to MASWE-0023 |
|---|---|---|---|---|
| [MASTG-TEST-0327](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0327/), [MASTG-TEST-0266](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0266/), [MASTG-TEST-0267](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0267/) | Android, iOS | Event-bound biometric authentication | MASWE-0020 | A biometric step-up that is event-bound gives the server nothing; see [our MASWE-0020 note](/mobile/maswe-0020-local-authentication-bypass/) |
| [MASTG-TEST-0326](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0326/), [MASTG-TEST-0268](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0268/), [MASTG-TEST-0269](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0269/) | Android, iOS | Fallback to device credential | MASWE-0021 | Step-up strength; see [our MASWE-0021 note](/mobile/maswe-0021-non-biometric-fallback-for-sensitive-transactions/) |
| [MASTG-TEST-0328](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0328/), [MASTG-TEST-0270](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0270/), [MASTG-TEST-0271](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0271/) | Android, iOS | Keys not invalidated on enrolment | MASWE-0022 | An attacker who adds their fingerprint passes biometric step-up; see [our MASWE-0022 note](/mobile/maswe-0022-keys-not-invalidated-on-biometric-enrollment/) |
| [MASTG-TEST-0329](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0329/), [MASTG-TEST-0330](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0330/) | Android | No explicit confirmation; extended key validity | MASWE-0020 | A step-up satisfied passively or by a recent unlock |
| [MASTG-TEST-0364](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0364/) | Android | Exported, unprotected activities exposing sensitive functionality | MASWE-0018 | Entry points past the gate (GT-0023-6) |
| [MASTG-TEST-0393](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0393/), [MASTG-TEST-0394](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0394/) | Android | Unverified App Links; custom URL scheme input validation | MASWE-0029 | Entry points past the gate (GT-0023-6) |
| [MASTG-TEST-0370](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0370/), [MASTG-TEST-0371](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0371/), [MASTG-TEST-0395](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0395/) | iOS | URL scheme and Universal Link handler validation | MASWE-0029 | Entry points past the gate (GT-0023-6) |
| [MASTG-TEST-0340](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0340/) | Android | References to overlay protections | MASWE-0036 in the repository | PIN-pad and confirmation screens (GT-0023-7) |
| [MASTG-TEST-0017](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0017/), [MASTG-TEST-0018](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0018/), [MASTG-TEST-0064](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0064/) | Android, iOS | Legacy (MASTG v1): confirm credentials, biometric authentication; the iOS test explicitly asks you to verify that "re-authenticating a user performing a payment transaction" uses Keychain access control | — | Historical guidance for local step-up |
| [MASTG-TEST-0028](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0028/), [MASTG-TEST-0035](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0035/), [MASTG-TEST-0070](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0070/), [MASTG-TEST-0075](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0075/) | Android, iOS | Legacy (MASTG v1): deep links, overlay attacks, Universal Links, custom URL schemes | — | Superseded by the beta tests above |

The MASTG chapter [Mobile App Authentication Architectures](https://mas.owasp.org/MASTG/0x04e-Testing-Authentication-and-Session-Management/) describes step-up in the context of 2FA ("Once the user attempts to execute a bank transfer, the second factor ... must be presented") and insists that it be enforced and verified on the server. Its "Transaction Signing with Push Notifications and PKI" section is the pattern GT-0023-5 tests for. Techniques used below: [MASTG-TECH-0120](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0120/) (interception proxy), [MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/) and [MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/) (method hooking), [MASTG-TECH-0172](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0172/) and [MASTG-TECH-0173](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0173/) (listing and monitoring deep links), [MASTG-TECH-0166](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0166/) and [MASTG-TECH-0169](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0169/) (URL scheme registrations and opening deep links).

### What you can prove from the client

Be explicit in the report about which side of the line each result sits on.

| You can prove from the client | You need the backend (or its documentation) for |
|---|---|
| That a sensitive request succeeds without any step-up evidence (GT-0023-2): this is conclusive — the server executed it | Whether a risk engine *would* have demanded step-up for a different user, device or amount |
| That step-up evidence is reusable, unbound or long-lived (GT-0023-5) | The exact step-up policy and its thresholds |
| That the app's gate is client-side only (GT-0023-3, GT-0023-4) — strong evidence, conclusive once combined with GT-0023-2 | Whether the server logs the missing step-up and alerts on it |
| That the factor can be replaced without step-up (GT-0023-7) | Whether fraud controls would later reverse the transaction |
| What the access token claims (`acr`, `amr`, `auth_time`) say | Whether the resource server actually reads them |

When the backend is in scope, pair the mobile tests with the corresponding web tests: OWASP WSTG "Testing for Bypassing Authentication Schema" (WSTG-ATHN-04), "Testing for Weaker Authentication in Alternative Channel" (WSTG-ATHN-10) and "Testing for the Circumvention of Work Flows" (WSTG-BUSL-06), and verify against ASVS 5.0 V7.5. When it is not, say so: a successful replay in GT-0023-2 is still a finding, because the server is the thing that executed the action.

Use test accounts you control, with small amounts and test payees. For credential-change tests, use a second mailbox and phone number you own, and agree in advance how accounts will be recovered.

### GT-0023-1: Sensitive action inventory and step-up map (Android, iOS)

Guler Tech methodology. Platform: Android, iOS. Type: static (code) and dynamic (network, manual).

#### Overview

Build the list of sensitive actions the app offers, the API request behind each, and what step-up (if any) the app and the server apply. Every later test works from this table, and the table itself often shows the finding: an action list with nothing in the "server demands" column.

#### Prerequisites

- The APK/IPA, decompiled: jadx for Android ([MASTG-TOOL-0018](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/)); for iOS a decrypted IPA analysed with radare2 ([MASTG-TOOL-0073](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/)) or your disassembler of choice.
- An interception proxy, such as Burp Suite ([MASTG-TOOL-0077](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0077/)), with the device configured to trust it and certificate pinning bypassed where necessary.
- A test account with the features enabled (payees, cards, MFA) and, if possible, the API documentation or OpenAPI specification.

#### Steps

1. **Walk the app.** With the proxy recording, use every feature on the [action classes](#generic-which-actions-need-step-up-guler-tech) list: add a payee, pay a new and an existing payee, reveal card details, change email, phone, password and PIN, enable and disable MFA or biometrics, export statements, manage devices and sessions, delete the account (on a throwaway account last). Note where the app prompts for anything.

2. **Collect step-up vocabulary from the code.** On Android:

   ```bash
   jadx -d out app.apk
   grep -rnE -i "step.?up|reauth|re-auth|elevat|acr_values|max_age|insufficient_user_authentication|\bamr\b|auth_time|otp|challenge|confirm(ation)?Token|X-[A-Za-z-]*(Auth|OTP|Step|Verify)" out/sources | grep -v "/androidx/\|/kotlin/" | head -100
   grep -rn "BiometricPrompt\|CryptoObject\|createConfirmDeviceCredentialIntent\|GetPublicKeyCredentialOption" out/sources | head -50
   ```

   Look for Retrofit or OkHttp interfaces (`@POST`, `@Header`) that carry step-up headers, interceptors that react to `401`/`403` with a step-up flow, and router configuration (Navigation graphs in `res/navigation/*.xml`, Compose `NavHost` routes) that shows which destinations sit behind a PIN or biometric screen.

   On iOS:

   ```bash
   unzip -q App.ipa -d ipa && BIN=ipa/Payload/App.app/App
   strings -a "$BIN" | grep -E -i "step.?up|reauth|acr_values|max_age|insufficient_user_authentication|auth_time|otp|challenge|X-[A-Za-z-]*(Auth|OTP|Step|Verify)" | sort -u | head -100
   r2 -qc "izz~+evaluatePolicy,SecAccessControlCreateWithFlags,biometryCurrentSet,createCredentialAssertionRequest" "$BIN"
   ```

3. **Map each action to its request.** In the proxy history, find the request that performs each action (not the one that loads the screen). Record method, path, body fields and any header that appears only on that request.

4. **Classify the step-up you observed.** For each action: nothing; client-only prompt (prompt appears, request has no extra evidence); evidence sent (OTP, signature, step-up token, new access token); and whether the server ever returned a challenge (`401` with `WWW-Authenticate: ... insufficient_user_authentication`, a `403` with a custom code such as `STEP_UP_REQUIRED`, or a "pending, confirm with OTP" response).

5. **Decode the access token** if it is a JWT, to see what the server records about the authentication:

   ```bash
   python3 -c 'import sys,base64,json;p=sys.argv[1].split(".")[1];print(json.dumps(json.loads(base64.urlsafe_b64decode(p+"="*(-len(p)%4))),indent=2))' "$ACCESS_TOKEN"
   ```

   Note `acr`, `amr`, `auth_time`, `exp`, `scope` and any custom assurance claim. Repeat after a step-up to see whether anything changes.

#### Observation

A table with one row per sensitive action: screen, request, client-side prompt, evidence in the request, server challenge seen, token claims before and after.

#### Evaluation

This test is a map, not a verdict, but record a provisional **fail** for any action in the high-risk classes (money, credentials, MFA, device binding, secret reveal, export, deletion) where no step-up evidence is sent and no server challenge was ever observed. Rows with a client-side prompt but no evidence in the request go straight to GT-0023-2 and GT-0023-3/4. Rows with evidence go to GT-0023-5.

#### Demo

Excerpt from a lab app's step-up map:

```text
Action                 Request                              Client prompt          Evidence in request          Server challenge
---------------------  -----------------------------------  ---------------------  ---------------------------  ----------------
Add payee              POST /api/v2/payees                  BiometricPrompt        none                         never
Pay new payee          POST /api/v2/payments                BiometricPrompt        X-Biometric-Verified: true   never
Reveal card PAN        GET  /api/v2/cards/{id}/details      6-digit app PIN        none (PIN checked locally)   never
Change email           PUT  /api/v2/profile/email           password dialog        "password" in body           400 if wrong
Disable MFA            DELETE /api/v2/mfa/totp              none                   none                         never
Token claims           acr: "urn:example:acr:password", amr: ["pwd"], auth_time = login time, unchanged after prompts
```

Only the email change sends evidence the server checks. Everything else is client-side or absent, and `X-Biometric-Verified: true` is a client assertion, not evidence. GT-0023-2 will confirm.

### GT-0023-2: Replaying sensitive requests without step-up evidence (Android, iOS)

Guler Tech methodology. Platform: Android, iOS (network). Type: dynamic (network).

#### Overview

The decisive test. Take each sensitive request from GT-0023-1, remove or falsify the step-up evidence, and send it with an ordinary session token. If the server executes it, step-up is not enforced server-side, whatever the app shows. This is the MAS-ATTACK-0033 scenario (a stolen token, no device) and it is the cleanest evidence you can put in a report.

#### Prerequisites

- GT-0023-1 completed; the proxy history contains each sensitive request.
- A valid session obtained by a normal login *without* any later step-up. Log in, then perform no sensitive action in the app, and take the access token from the next ordinary request.
- Agreed test amounts, payees and recovery arrangements.

#### Steps

1. **Send each sensitive request to Burp Repeater** and replace the `Authorization` header with the plain-login token from the prerequisites.

2. **Strip the evidence, one variation at a time:**

   | Variation | What to change |
   |---|---|
   | A. Remove | Delete the step-up header, body field or token entirely |
   | B. Falsify | Set client-asserted flags to the "success" value: `X-Biometric-Verified: true`, `"authLevel": 2`, `"stepUp": "DONE"` |
   | C. Empty or malformed | Empty OTP, `000000`, an empty or truncated signature, a step-up token with an altered payload and the original signature |
   | D. Skip the confirm step | For two-step flows (create pending operation, then confirm with OTP), call only the create step, or call the "execute" endpoint directly with the pending ID |
   | E. Other channels | Send the same operation to the web API, an older version (`/api/v1/`), a GraphQL mutation or a batch endpoint, if the app or its web counterpart uses one |

   A `curl` equivalent is useful for the report:

   ```bash
   curl -sk -X POST https://api.example.com/api/v2/payees \
     -H "Authorization: Bearer $LOGIN_ONLY_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"name":"GT Test Payee","sortCode":"000000","account":"00000000"}' -i
   ```

3. **Verify the effect** in the app or account: the payee exists, the email changed, the card details came back, MFA is off. A `200` with no effect is not a pass — some APIs accept and silently queue for manual review — so check the outcome.

4. **For Design A (OIDC/`acr`)**, also send the request with a token whose `auth_time` is old (log in, wait past the policy window, replay). If the server accepts it, freshness is not checked.

#### Observation

For each action and variation: the request (redacted), the response status and body, and the observed effect in the account.

#### Evaluation

The test **fails** for an action if any variation results in the server executing it — the operation takes effect, or the secret is returned — without valid, fresh step-up evidence. Variation B succeeding is the worst case: the server trusts a client assertion.

The test **passes** for an action if every variation is refused with a step-up challenge or an error and nothing takes effect, and the original flow (with real evidence) still works.

Note any variation that returns a challenge but still has an effect (for example, a payee created in a "pending" state that later activates without approval) and follow up with the backend team.

#### Demo

A vulnerable lab backend. The Kotlin client attaches a header after an event-bound prompt:

```kotlin
// Vulnerable: the "step-up" is a header the client sets after a local prompt.
override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
    api.createPayment(
        body = paymentRequest,
        biometricVerified = "true"          // @Header("X-Biometric-Verified")
    )
}
```

Variation A, header removed, login-only token:

```text
POST /api/v2/payments HTTP/2
Host: api.example.com
Authorization: Bearer <login-only access token>
Content-Type: application/json

{"payeeId":"p-90121","amountMinor":2500,"currency":"GBP","reference":"GT-0023-2"}

HTTP/2 201 Created
{"paymentId":"pay-55120","status":"ACCEPTED"}
```

The payment appears in the account history. The header was never checked; the test fails for "Pay new payee". On the same backend, `PUT /api/v2/profile/email` without the `password` field returned `400 {"error":"password_required"}` and the email did not change: that action passes variation A, and goes on to GT-0023-5 to check what else the password check is bound to.

### GT-0023-3: Bypassing a client-side step-up gate (Android)

Guler Tech methodology. Platform: Android. Type: dynamic (hooks).

#### Overview

Show that the app's step-up decision can be flipped from inside the process: the sensitive screen opens, or the sensitive request is sent, without the user passing the gate. On its own this proves that the gate is client-side; combined with GT-0023-2 (the request succeeds without evidence) it is the complete story for the MAS-ATTACK-0032 scenario: someone with the unlocked phone, plus instrumentation, or a tampered build. If GT-0023-2 already passed (the server refuses without evidence), this test shows only that the UI can be bypassed and the request will then fail — record that as a pass with a note.

#### Prerequisites

- Rooted device or emulator with frida-server ([MASTG-TOOL-0001](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0001/)), or a repackaged APK with the Frida gadget; objection ([MASTG-TOOL-0029](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0029/)) optional.
- The gate's location from GT-0023-1: the method that decides whether to show the step-up, or the callback that proceeds after it.

#### Steps

1. **Find the decision point.** Typical shapes in jadx output: a policy method returning a Boolean (`isStepUpRequired(action)`, `needsReauth()`, `hasRecentAuth()`), a timestamp compared with `System.currentTimeMillis()` (`lastAuthAt + 300_000 > now`), or a callback that runs the action (`onAuthenticationSucceeded`, `onPinVerified`). Confirm with tracing:

   ```bash
   frida-trace -U -f com.example.bank -j '*StepUp*!*' -j '*Reauth*!*' -j '*!*verifyPin*'
   ```

   (`-j` takes a `class!method` glob for Java methods: the first two match any method of classes whose names contain `StepUp` or `Reauth`, the third any method named like `verifyPin`. Adjust them to the names you found.)

2. **Flip the decision.** With objection:

   ```bash
   objection -g com.example.bank explore
   # in the objection REPL:
   android hooking set return_value com.example.bank.security.StepUpPolicy.isStepUpRequired false
   ```

   Or with a Frida script when the gate is a timestamp or a callback:

   ```javascript
   // gt-stepup-gate.js — lab app names; replace with the classes you found
   Java.perform(function () {
     const Policy = Java.use('com.example.bank.security.StepUpPolicy');
     Policy.isStepUpRequired.overload('java.lang.String').implementation = function (action) {
       console.log('[*] isStepUpRequired(' + action + ') -> false');
       return false;
     };
     const Session = Java.use('com.example.bank.session.SessionState');
     Session.getLastStrongAuthAt.implementation = function () {
       return Java.use('java.lang.System').currentTimeMillis();   // "authenticated just now"
     };
   });
   ```

   ```bash
   frida -U -f com.example.bank -l gt-stepup-gate.js
   ```

   For a biometric gate, the event-bound bypass from [our MASWE-0020 note](/mobile/maswe-0020-local-authentication-bypass/) (calling `onAuthenticationSucceeded` with a null `CryptoObject`) does the same job. If that bypass throws because the app dereferences `result.cryptoObject.signature`, the gate is crypto-bound: good, and a pass for this test.

3. **Perform the sensitive action** with the hook active and watch the proxy: is the request sent, does it carry evidence, and does the server accept it?

4. **For PIN gates verified locally**, look at where the PIN is compared. A PIN hash in `SharedPreferences` checked in app code is both a step-up bypass and a brute-force target (GT-0023-7).

#### Observation

The hook output, a screen recording or screenshots showing the sensitive screen or action without passing the gate, and the resulting request and response from the proxy.

#### Evaluation

The test **fails** if flipping the client-side decision lets the user complete the sensitive action — the request is sent and the server executes it. It also fails for display actions if the sensitive data is shown (fetched without step-up, or served from a cache).

It **passes** if the gate cannot be bypassed in a way that produces an executed action: either the gate is crypto-bound (the action needs a signature only an authenticated key can produce), or the server refuses the request that the bypassed app sends.

#### Demo

Vulnerable gate in a lab app (decompiled):

```java
public final boolean isStepUpRequired(String action) {
    long age = System.currentTimeMillis() - this.session.getLastStrongAuthAt();
    return SENSITIVE.contains(action) && age > 300_000L;   // decided on the device
}
```

Hook output and the request it led to:

```text
[*] isStepUpRequired(reveal_card) -> false
GET /api/v2/cards/c-1182/details HTTP/2
Authorization: Bearer <login-only access token>

HTTP/2 200 OK
{"pan":"5555 55•• •••• 4444","expiry":"09/29","cvv":"•••"}     (redacted in the report)
```

The card details screen opened without the PIN pad and the backend returned full card details on a plain session token. The test fails, and GT-0023-2 for the same request fails as well.

### GT-0023-4: Bypassing a client-side step-up gate (iOS)

Guler Tech methodology. Platform: iOS. Type: dynamic (hooks).

#### Overview

The iOS counterpart of GT-0023-3: show that the step-up decision or its result can be changed in the process, and whether the server cares.

#### Prerequisites

- Jailbroken device with frida-server ([MASTG-TOOL-0039](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/)), or an IPA re-signed with the Frida gadget ([MASTG-TECH-0090](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0090/)); objection ([MASTG-TOOL-0074](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0074/)) optional.
- Candidate class and method names from GT-0023-1.

#### Steps

1. **Trace the gate.** For Objective-C or `@objc`-exposed Swift classes:

   ```bash
   frida-trace -U -f com.example.bank -m '*[*StepUp* *]' -m '*[*Reauth* *]' -m '-[LAContext evaluatePolicy:localizedReason:reply:]'
   ```

   Pure Swift classes do not appear to `-m`; trace their mangled symbols with `-i` instead (find them with `r2 -qc 'is~StepUp' "$BIN"` or `nm`), or work from the network side.

2. **Bypass the biometric result** where step-up is `LAContext`-based:

   ```bash
   objection -g com.example.bank explore
   # in the objection REPL:
   ios ui biometrics_bypass
   ```

   This hooks `evaluatePolicy:localizedReason:reply:` and reports success regardless of the real result (the technique used by legacy MASTG-TEST-0064 and MASTG-TEST-0267). If the app uses a Keychain item or Secure Enclave key with access control, the bypass has no effect: the system still demands Face ID or Touch ID to release the item or sign. Note the difference — that is the crypto-bound case.

3. **Flip a Boolean policy method** where the gate is app logic:

   ```javascript
   // gt-stepup-gate-ios.js
   const cls = ObjC.classes.StepUpPolicy;           // lab app name
   Interceptor.attach(cls['- isStepUpRequiredFor:'].implementation, {
     onLeave(retval) {
       console.log('[*] isStepUpRequiredFor: -> NO');
       retval.replace(ptr(0));
     }
   });
   ```

   ```bash
   frida -U -f com.example.bank -l gt-stepup-gate-ios.js
   ```

4. **Perform the sensitive action** and capture the request and response in the proxy.

#### Observation

Hook output, a recording of the bypassed flow, and the request and response.

#### Evaluation

As GT-0023-3: **fail** if the bypass leads to an executed action or a revealed secret; **pass** if the action needs a user-authenticated key operation or the server refuses the request.

#### Demo

Vulnerable Swift gate:

```swift
func confirmNewPayee(_ payee: Payee) {
    let context = LAContext()
    context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                           localizedReason: "Confirm new payee") { success, _ in
        guard success else { return }
        self.api.addPayee(payee)        // same request as without the prompt
    }
}
```

objection output:

```text
(agent) [x1q8] Localized Reason for auth requirement: Confirm new payee
(agent) [x1q8] OS authentication response: false
(agent) [x1q8] Marking OS response as True instead
(agent) [x1q8] Biometrics bypass hook complete
```

The proxy shows `POST /api/v2/payees` with no extra evidence and a `201 Created`. The test fails; the root cause is the same as GT-0023-2 (no server-side requirement), with an event-bound prompt on top.

### GT-0023-5: Step-up binding, freshness and reuse (Android, iOS)

Guler Tech methodology. Platform: Android, iOS (network). Type: dynamic (network).

#### Overview

For actions where the server *does* demand evidence, check what the evidence is bound to: the user, the session, the specific operation, a time window and a single use. This is the "Step-Up Not Bound to the Action" mode of introduction, and PSD2 dynamic linking for payments.

#### Prerequisites

- Actions that passed GT-0023-2 (the server refuses without evidence).
- Two test accounts (A and B), ideally on two devices, and the ability to complete the real step-up for each.
- The proxy configured to intercept and hold requests (Burp's Intercept, or a breakpoint in mitmproxy).

#### Steps

1. **Capture a legitimate step-up.** Perform the action on account A, completing the step-up, but intercept the final request. Save the evidence: OTP, signature and signed payload, step-up token, or the post-step-up access token. Drop or let through the request as each case below requires.

2. **Run the binding checks:**

   | Check | Procedure | Expected secure result |
   |---|---|---|
   | Operation binding | Approve a payment of £1 to payee X; in the held request change the amount to £100 or the payee to Y; forward | Refused: evidence does not match |
   | Cross-operation reuse | Approve an "add payee" step-up; replay its token or signature on "change email" or "disable MFA" | Refused: wrong purpose |
   | Replay | Forward the original request, then send it again (Repeater) with the same evidence | Second request refused (single use) |
   | Freshness | Hold the evidence for longer than the claimed window (or 15 minutes, if unknown), then forward | Refused: too old |
   | Session binding | Log out and in again (new session) on account A; reuse the evidence from the old session | Refused |
   | User binding | Use account A's evidence with account B's session | Refused |
   | Scope creep | After one successful step-up, perform a *different* sensitive action without a new step-up within the window | Refused for high-risk actions; any accepted window should be short and documented |
   | Threshold games | If step-up applies only above a threshold, try the amount just below it repeatedly, in other currencies, as a scheduled payment, or as a standing order | Cumulative or per-payee limits trigger step-up |

3. **For transaction signatures**, compare what is signed with the request: decode the signed payload (or hook the signing call — see GT-0025-5 in [our MASWE-0025 note](/mobile/maswe-0025-lack-of-non-repudiation/)) and confirm that it contains the amount, the payee, a server nonce and an operation identifier. A signature over the nonce alone is bound to the challenge, not to the transaction, unless the server tied the nonce to the transaction when it issued it — which the operation-binding check above verifies.

4. **For Design A tokens**, check the lifetime and reuse of the stepped-up access token: decode it, note `exp` and `auth_time`, and see whether the same token performs several sensitive actions in a row.

#### Observation

For each check: the modified request, the response, and whether the action took effect.

#### Evaluation

The test **fails** if the server accepts step-up evidence for a different amount, payee, operation, session or user than it was issued for; accepts it twice for an operation that should be single-use; accepts it after an unjustified period (for high-risk actions, anything beyond a few minutes); or if threshold-based step-up can be routinely avoided.

It **passes** if every modification is refused and the original, unmodified request succeeds once.

#### Demo

A lab backend issues a step-up token after OTP verification and accepts it for any sensitive call for 30 minutes:

```text
POST /api/v2/stepup/verify   {"otp":"493021"}
200 {"stepUpToken":"<opaque>","expiresIn":1800}

POST /api/v2/payments   X-Step-Up-Token: <opaque>   {"payeeId":"p-90121","amountMinor":100,...}
201 {"paymentId":"pay-55130"}

POST /api/v2/payments   X-Step-Up-Token: <same>     {"payeeId":"p-90777","amountMinor":250000,...}
201 {"paymentId":"pay-55131"}

DELETE /api/v2/mfa/totp X-Step-Up-Token: <same>
204
```

One OTP authorised a £1 payment, a £2,500 payment to a different payee and the removal of MFA. The step-up is server-enforced but unbound and reusable; the test fails, and for the payments it does not meet dynamic linking.

### GT-0023-6: Entry points that skip the step-up (Android, iOS)

Guler Tech methodology. Platform: Android, iOS. Type: static (manifest, Info.plist) and dynamic (manual).

#### Overview

Reach each sensitive screen by every route other than the normal one and check whether the step-up gate still appears, and whether the screen shows or does anything without it. This is the MASVS-PLATFORM-3 side of MASWE-0023: the UI flow is the gate, so routes around the flow are bypasses.

#### Prerequisites

- The list of sensitive screens from GT-0023-1.
- Android: `adb` ([MASTG-TOOL-0004](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0004/)) and the decoded manifest. iOS: the `Info.plist` and entitlements, and `xcrun devicectl` (device) or `xcrun simctl` (simulator).

#### Steps

1. **List entry points.** Android ([MASTG-TECH-0172](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0172/)):

   ```bash
   apktool d -o app_src app.apk
   grep -nE 'android:exported="true"|<data |android:scheme|android:host|android:pathPrefix|android:pathPattern' app_src/AndroidManifest.xml
   adb shell dumpsys package com.example.bank | sed -n '/Activity Resolver Table/,/Receiver Resolver Table/p'
   grep -rn '<deepLink' app_src/res/navigation/ 2>/dev/null
   ```

   iOS ([MASTG-TECH-0166](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0166/)):

   ```bash
   plutil -extract CFBundleURLTypes json -o - ipa/Payload/App.app/Info.plist
   codesign -d --entitlements - ipa/Payload/App.app 2>/dev/null | grep -A5 associated-domains
   plutil -extract UIApplicationShortcutItems json -o - ipa/Payload/App.app/Info.plist 2>/dev/null
   ```

   Then grep the decompiled code for the router: route tables mapping paths to screens (`"cards/{id}/reveal"`, `"settings/email"`, `"security/mfa"`).

2. **Invoke each route to a sensitive screen**, logged in but without a recent step-up. Android ([MASTG-TECH-0173](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0173/)):

   ```bash
   adb shell am start -W -a android.intent.action.VIEW -d "examplebank://cards/c-1182/reveal" com.example.bank
   adb shell am start -W -n com.example.bank/.ui.settings.ChangeEmailActivity      # exported activity
   ```

   iOS ([MASTG-TECH-0169](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0169/)):

   ```bash
   xcrun simctl openurl booted "examplebank://cards/c-1182/reveal"
   xcrun devicectl device process launch --device <device-id> \
     --payload-url 'examplebank://settings/email' com.example.bank
   ```

3. **Test the non-link routes manually:** tap notifications that point to sensitive screens; use App Shortcuts or home-screen quick actions; on Android, open the sensitive screen after a step-up, then force process death (`adb shell am kill com.example.bank` with the app in the background) and return to it from Recents; on iOS, leave the app on the screen, let the step-up window expire, and return; on both, wait out the window and press Back into the sensitive screen.

4. **For non-exported Android activities**, starting them from a root shell (`adb shell su -c 'am start -n com.example.bank/.ui.cards.CardDetailsActivity'`) is not an external attack, but it quickly shows whether the activity itself enforces the gate or relies on its caller. Report it as defence-in-depth evidence, not as an exploitable entry point.

5. **Watch the proxy** for each route: does the screen make the sensitive request, and is it accepted?

#### Observation

For each route: the command or action, whether the step-up appeared, what the screen displayed, and any sensitive request and response.

#### Evaluation

The test **fails** if any externally reachable route (deep link, App Link or Universal Link, exported activity, notification, shortcut, restored state) shows sensitive data or completes a sensitive action without the step-up — either because the API does not enforce step-up, or because the data was cached from an earlier call. If the screen opens but its API calls are refused, record a **pass** with a low-severity UI observation (the gate is in the navigation rather than at the point of use).

#### Demo

A lab app's router maps the card reveal path directly to the details fragment; the PIN gate lives only in the "Cards" list screen:

```kotlin
// Vulnerable: deep link router bypasses the PIN gate the list screen applies.
when (uri.pathSegments.firstOrNull()) {
    "cards" -> navController.navigate(R.id.cardDetailsFragment,
                   bundleOf("cardId" to uri.pathSegments[1], "reveal" to true))
}
```

```text
$ adb shell am start -W -a android.intent.action.VIEW -d "examplebank://cards/c-1182/reveal" com.example.bank
Status: ok
Activity: com.example.bank/.ui.MainActivity
-> Card details displayed with full PAN; proxy: GET /api/v2/cards/c-1182/details 200
```

Any app, or any web page that can trigger the custom scheme, can open the full card details on an unlocked phone without the PIN. Because the API also returned the PAN on a plain session token, GT-0023-2 fails for the same action.

### GT-0023-7: Strength of the step-up mechanism itself (Android, iOS)

Guler Tech methodology. Platform: Android, iOS. Type: dynamic (network, hooks) and static.

#### Overview

A server-enforced, bound step-up can still be weak: the factor can be replaced without step-up, the OTP can be brute-forced, the biometric falls back to something easier, approvals can be spammed, or the PIN pad can be overlaid. This test checks the gate rather than the route.

#### Prerequisites

- GT-0023-1 and GT-0023-5 completed; two test accounts; an agreed rate for automated requests.

#### Steps

1. **Factor replacement.** Using a session without step-up, try to change each factor the step-up relies on: the phone number for OTPs, the TOTP seed, the push-approval device, the registered signing key or passkey, the app PIN. Capture the requests (GT-0023-1) and replay them without evidence (GT-0023-2). Also try the enrolment API directly: a device-binding endpoint that registers a new public key on a plain session lets a token thief enrol their own key.

2. **OTP brute force.** Send wrong OTPs to the step-up verification endpoint with Burp Intruder at a modest rate. Record after how many attempts the server locks, slows down or invalidates the OTP, and whether a new OTP request resets the counter. A six-digit OTP with no attempt limit is a step-up that can be guessed.

3. **Fallbacks.** Cancel or fail the strong step-up (biometric) repeatedly and note what the app offers next: device credential (MASWE-0021), SMS OTP, email link, security questions, or "skip". Check whether the server accepts the weaker evidence for the same high-risk action.

4. **Push approval fatigue.** If step-up for web or other-device actions uses push approval, trigger several approvals in a row from account A's other channel and check for rate limiting, number matching, and whether the approval shows the action details.

5. **Local PIN verification.** If the app PIN is verified on the device, find where its verifier is stored (`SharedPreferences`, a database, the Keychain) and whether a hash can be brute-forced offline; a four- or six-digit PIN hashed with SHA-256 falls in milliseconds. See [MASWE-0001](/mobile/maswe-0001-sensitive-data-unencrypted-private-storage/) for storage.

6. **Overlays (Android).** For PIN-pad and confirmation screens, run the MASTG-TEST-0340 checks: grep the decompiled code and layouts for `setHideOverlayWindows`, `filterTouchesWhenObscured`, `FLAG_WINDOW_IS_OBSCURED` and `FLAG_WINDOW_IS_PARTIALLY_OBSCURED`:

   ```bash
   grep -rnE "setHideOverlayWindows|HIDE_OVERLAY_WINDOWS|filterTouchesWhenObscured|setFilterTouchesWhenObscured|FLAG_WINDOW_IS(_PARTIALLY)?_OBSCURED|onFilterTouchEventForSecurity" out/ app_src/res/layout app_src/AndroidManifest.xml
   ```

#### Observation

For each check: the requests and responses, attempt counts, the fallback chain offered, and the overlay-protection grep output.

#### Evaluation

The test **fails** if: a step-up factor (OTP phone number, TOTP seed, push device, signing key, passkey, PIN) can be changed or enrolled without step-up using an existing factor; the step-up OTP or PIN can be attempted without an effective server-side limit; the server accepts a weaker fallback for a high-risk action; or approvals can be triggered repeatedly with no number matching or rate limit. Missing overlay protection on a PIN-pad or confirmation screen is a separate, lower-rated observation (MASWE-0039).

#### Demo

```text
PUT /api/v2/profile/phone   Authorization: Bearer <login-only token>   {"phone":"+44 7700 900123"}
200 {"status":"UPDATED"}

POST /api/v2/stepup/otp/send       -> SMS sent to +44 7700 900123 (tester's number)
POST /api/v2/stepup/verify  {"otp":"…"}  -> 200 {"stepUpToken":"<opaque>"}
```

The OTP step-up is enforced and bound (GT-0023-5 passed), but the phone number it goes to can be changed with a plain session token, so a token thief redirects the OTP to their own phone and passes every later step-up. The test fails; rate this with the impact of the strongest action the step-up protects.

## Secure implementation

Start with a policy the server owns. A compact form:

| Action | Mechanism | Max age | Bound to | Single use |
|---|---|---|---|---|
| Pay new payee, add payee, raise limit | Transaction signature with biometric-bound device key (or OTP naming amount and payee) | Per operation | Amount, payee, operation ID, nonce | Yes |
| Change email, phone, password, MFA, recovery | Existing strong factor (device-key signature or passkey with UV), plus notification to the old channel | Per operation | Field and new value | Yes |
| Bind new device or signing key | Existing factor on the old device, or out-of-band verification; key attestation on Android | Per operation | New public key | Yes |
| Reveal PAN, CVV, recovery codes | Biometric-bound signature or passkey with UV | Per reveal | Resource ID | Yes |
| Export data, delete account | Re-authentication | Few minutes | Operation | Yes |

### Server: challenge, verify, execute

A minimal Express-style middleware for Design B. The server owns the pending operation; the client never sends the fields that are signed, only the signature.

```javascript
// stepup.js — illustrative; use your framework's equivalents
const crypto = require('crypto');

async function requireStepUp(req, res, next) {
  const op = await pendingOps.get(req.params.opId);                  // created by the server earlier
  if (!op || op.userId !== req.user.id || op.sessionId !== req.session.id) {
    return res.status(404).end();
  }
  const evidence = req.get('X-Step-Up-Signature');
  if (!evidence) {
    const nonce = crypto.randomBytes(32).toString('base64url');
    await pendingOps.setNonce(op.id, nonce, Date.now() + 120000);    // 2-minute validity
    return res.status(401)
      .set('WWW-Authenticate', 'Bearer error="insufficient_user_authentication", max_age="0"')
      .json({ opId: op.id, nonce, display: op.displayText });
  }
  const key = await deviceKeys.activeKeyFor(req.user.id, req.get('X-Device-Key-Id'));
  const signed = canonicalBytes(op, await pendingOps.nonce(op.id));    // rebuilt from server state
  const ok = key && crypto.verify('sha256', signed, key.publicKeyPem, Buffer.from(evidence, 'base64'));
  if (!ok || !(await pendingOps.consumeNonce(op.id))) {              // expired or already used
    return res.status(403).json({ error: 'step_up_failed' });
  }
  next();                                                            // execute exactly this operation
}
```

`deviceKeys` contains only keys enrolled through a step-up-protected flow and, on Android, keys whose attestation shows per-operation strong-biometric authentication (see [MASWE-0016](/mobile/maswe-0016-key-access-not-restricted/#both-platforms-let-the-server-check)). `canonicalBytes` is the same versioned, context-labelled encoding the app uses (see [MASWE-0010](/mobile/maswe-0010-improper-signature-generation/#android-sign-a-structured-context-labelled-transaction)). Log every challenge, success and failure with the operation ID (ASVS 5.0 16.3.1).

For Design A (OIDC), the resource server checks `acr` against the action's required value, `auth_time` against `max_age`, and returns the RFC 9470 challenge otherwise; issue stepped-up tokens with a short lifetime or narrowly scoped `authorization_details` (RFC 9396) so one step-up does not unlock everything.

### Android: answer the challenge with a biometric-bound signature

```kotlin
class StepUpSigner(private val activity: FragmentActivity) {

    fun approve(challenge: StepUpChallenge, onEvidence: (String) -> Unit) {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val key = ks.getKey(TX_KEY_ALIAS, null) as PrivateKey   // created with per-operation BIOMETRIC_STRONG
        val sig = Signature.getInstance("SHA256withECDSA").apply { initSign(key) }

        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Approve payment")
            .setDescription(challenge.display)                     // e.g. "£25.00 to GT Test Payee"
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setNegativeButtonText("Cancel")
            .setConfirmationRequired(true)
            .build()

        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                val s = result.cryptoObject?.signature ?: return
                s.update(canonicalBytes(challenge))                // same encoding the server rebuilds
                onEvidence(Base64.encodeToString(s.sign(), Base64.NO_WRAP))
            }
        }
        BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), callback)
            .authenticate(info, BiometricPrompt.CryptoObject(sig))
    }
}
```

Key creation (per-operation `AUTH_BIOMETRIC_STRONG`, `setInvalidatedByBiometricEnrollment(true)`, `setUnlockedDeviceRequired(true)`, attestation challenge) is in [MASWE-0016](/mobile/maswe-0016-key-access-not-restricted/#android-transaction-signing-key-bound-to-strong-biometrics). Handle `KeyPermanentlyInvalidatedException` by re-enrolling through a step-up-protected flow, never by silently falling back. In the networking layer, treat a `401` with `insufficient_user_authentication` as "run step-up and retry once", not as "log out".

### iOS: answer the challenge with a Secure Enclave key

```swift
import CryptoKit
import LocalAuthentication

func approve(_ challenge: StepUpChallenge,
             key: SecureEnclave.P256.Signing.PrivateKey) throws -> String {
    // The key was created with [.privateKeyUsage, .biometryCurrentSet] and
    // kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly; each signature prompts.
    let signature = try key.signature(for: canonicalBytes(challenge))
    return signature.derRepresentation.base64EncodedString()
}

// Restore the key with a fresh context per approval, so a recent unlock does not count:
func loadKey(_ data: Data, reason: String) throws -> SecureEnclave.P256.Signing.PrivateKey {
    let context = LAContext()
    context.touchIDAuthenticationAllowableReuseDuration = 0
    context.localizedReason = reason                         // e.g. "Approve £25.00 to GT Test Payee"
    return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data,
                                                     authenticationContext: context)
}
```

Key creation is in [MASWE-0016](/mobile/maswe-0016-key-access-not-restricted/#ios-secure-enclave-signing-key-with-current-set-biometrics). Bind the public key to a genuine app instance at enrolment with App Attest ([MASWE-0010](/mobile/maswe-0010-improper-signature-generation/#ios-bind-your-signing-key-to-app-attest)).

### Passkeys as step-up

If the app already uses passkeys, a passkey assertion with user verification is a good step-up. Have the server issue a fresh challenge tied to the pending operation, request `"userVerification": "required"`, and on the server check the signature, the challenge, the RP ID hash, and that the UV bit (`0x04`) in the flags byte of `authenticatorData` is set. Remember that synced passkeys are not device-bound: they prove the user and their passkey provider account, not this phone.

### App-side rules

- Check step-up at the point of use: the screen or view model that performs the action asks the server, rather than trusting that the previous screen ran the gate.
- Do not cache revealed secrets; fetch them per reveal, clear them when the screen leaves the foreground, and protect the screen from screenshots (MASWE-0038).
- Route deep links, shortcuts, notifications and restored states through the same guard; on Android avoid exporting activities that host sensitive screens.
- Protect PIN pads and confirmation buttons from overlays on Android (MASTG-BEST-0040).

## Rating findings

Rate on what the unprotected action does, who can exploit it (a token thief remotely, or someone with the unlocked device), and how much the step-up that does exist reduces that.

| Rating | Conditions |
|---|---|
| **Critical** | The server executes a high-impact action — payment or transfer to a new payee, adding a payee, changing email/phone/password, disabling or replacing MFA, enrolling a new device or signing key — with **only a session token**, demonstrated with GT-0023-2 or GT-0023-7, so a stolen token or a short moment with an unlocked phone leads to financial loss or permanent account takeover. Also: the server trusts a client-asserted step-up flag (`X-Biometric-Verified: true`) for these actions. |
| **High** | Step-up is enforced but **unbound or reusable** for high-impact actions (one approval authorises other amounts, payees or operations, or lasts tens of minutes), or the step-up factor itself can be replaced without step-up. Also: full PAN/CVV, recovery codes or bulk personal data revealed or exported on a plain session token. Also: a deep link or exported component reaches a high-impact action without step-up and the API accepts it (GT-0023-6). For an EUDIW wallet: credential presentation or signature creation without per-use user authentication. |
| **Medium** | Server-enforced step-up with weaknesses that need extra conditions: windows of several minutes where per-operation was required, an OTP verification endpoint with weak rate limiting, push approvals without number matching or details, a weaker fallback accepted for high-value actions, thresholds avoidable by splitting. Also: lower-impact sensitive actions (session management, partial data export) without step-up. |
| **Low** | The API enforces step-up correctly, but the client gate is navigation-based and can be bypassed to show an empty or failing screen; missing overlay protection on a PIN-pad or confirmation screen; event-bound biometric used as an *extra* layer on top of a server-verified factor; step-up policy undocumented. |
| **Info** | Risk-based exemptions decided server-side and documented; step-up present but with UX issues (unclear prompt text); no backend access, so freshness limits could only be estimated. |

When you report, give the action, the request (redacted), the variation that succeeded, the server's response and the effect in the account, plus the token claims (`acr`, `amr`, `auth_time`) that show what the server knew. State whether the finding is exploitable remotely with a stolen token (MAS-ATTACK-0033) or needs the device (MAS-ATTACK-0032), and map it to ASVS 5.0 7.5.1 or 7.5.3 and, for EU payment apps, to the PSD2 SCA dynamic-linking requirement.

## References

- OWASP MASWE — [MASWE-0023: Step-Up Authentication Not Implemented for Sensitive Actions](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0023/) (CC BY-SA 4.0)
- OWASP MASWE — [MASWE-0020](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0020/), [MASWE-0021](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0021/), [MASWE-0022](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0022/), [MASWE-0025](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0025/), [MASWE-0029: Insecure Deep Links](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0029/), [MASWE-0039: App Vulnerable to Overlay Attacks](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0039/) (CC BY-SA 4.0)
- OWASP MAS Profiles — [MAS-L2](https://mas.owasp.org/Profiles/MAS-L2/) and [MAS-EUDIW](https://mas.owasp.org/Profiles/MAS-EUDIW/) (CC BY-SA 4.0)
- OWASP MASTG — [Mobile App Authentication Architectures](https://mas.owasp.org/MASTG/0x04e-Testing-Authentication-and-Session-Management/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0001: Biometric Authentication](https://mas.owasp.org/MASTG/knowledge/android/MASVS-AUTH/MASTG-KNOW-0001/), [MASTG-KNOW-0056: Local Authentication Framework](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-AUTH/MASTG-KNOW-0056/), [MASTG-KNOW-0057: Keychain Services](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-AUTH/MASTG-KNOW-0057/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-KNOW-0019: Deep Links](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0019/), [MASTG-KNOW-0022: Overlay Attacks](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0022/), [MASTG-KNOW-0132: Android Activities](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0132/), [MASTG-KNOW-0079: Custom URL Schemes](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0079/), [MASTG-KNOW-0080: Universal Links](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0080/) (CC BY-SA 4.0)
- OWASP MASTG — beta tests [MASTG-TEST-0266](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0266/), [MASTG-TEST-0267](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0267/), [MASTG-TEST-0268](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0268/), [MASTG-TEST-0269](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0269/), [MASTG-TEST-0270](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0270/), [MASTG-TEST-0271](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0271/), [MASTG-TEST-0326](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0326/), [MASTG-TEST-0327](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0327/), [MASTG-TEST-0328](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0328/), [MASTG-TEST-0329](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0329/), [MASTG-TEST-0330](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0330/), [MASTG-TEST-0340](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0340/), [MASTG-TEST-0364](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0364/), [MASTG-TEST-0393](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0393/), [MASTG-TEST-0394](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0394/), [MASTG-TEST-0370](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0370/), [MASTG-TEST-0371](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0371/), [MASTG-TEST-0395](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0395/) (CC BY-SA 4.0)
- OWASP MASTG — legacy (MASTG v1) tests [MASTG-TEST-0017](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0017/), [MASTG-TEST-0018](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0018/), [MASTG-TEST-0064](https://mas.owasp.org/MASTG/tests/ios/MASVS-AUTH/MASTG-TEST-0064/), [MASTG-TEST-0028](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0028/), [MASTG-TEST-0035](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0035/), [MASTG-TEST-0070](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0070/), [MASTG-TEST-0075](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0075/) (CC BY-SA 4.0)
- OWASP MASTG — [MASTG-BEST-0040: Preventing Overlay Attacks](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0040/) (CC BY-SA 4.0)
- OWASP MASTG — techniques [MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/), [MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/), [MASTG-TECH-0090](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0090/), [MASTG-TECH-0120](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0120/), [MASTG-TECH-0166](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0166/), [MASTG-TECH-0169](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0169/), [MASTG-TECH-0172](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0172/), [MASTG-TECH-0173](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0173/); tools [Frida for Android (MASTG-TOOL-0001)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0001/), [adb (MASTG-TOOL-0004)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0004/), [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [objection for Android (MASTG-TOOL-0029)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0029/), [Frida for iOS (MASTG-TOOL-0039)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/), [radare2 for iOS (MASTG-TOOL-0073)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/), [objection for iOS (MASTG-TOOL-0074)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0074/), [Burp Suite (MASTG-TOOL-0077)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0077/) (CC BY-SA 4.0)
- OWASP ASVS 5.0 — [V7 Session Management (7.5 Defenses Against Session Abuse)](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x16-V7-Session-Management.md) and [V16 Security Logging and Error Handling](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md)
- OWASP WSTG — [Testing for Bypassing Authentication Schema (WSTG-ATHN-04)](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema), [Testing for Weaker Authentication in Alternative Channel (WSTG-ATHN-10)](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/04-Authentication_Testing/10-Testing_for_Weaker_Authentication_in_Alternative_Channel), [Testing for the Circumvention of Work Flows (WSTG-BUSL-06)](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/06-Testing_for_the_Circumvention_of_Work_Flows)
- [NIST SP 800-63B-4: Digital Identity Guidelines — Authentication and Authenticator Management](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [RFC 9470: OAuth 2.0 Step Up Authentication Challenge Protocol](https://www.rfc-editor.org/rfc/rfc9470), [RFC 9068: JWT Profile for OAuth 2.0 Access Tokens](https://www.rfc-editor.org/rfc/rfc9068), [RFC 8176: Authentication Method Reference Values](https://www.rfc-editor.org/rfc/rfc8176), [RFC 9396: OAuth 2.0 Rich Authorization Requests](https://www.rfc-editor.org/rfc/rfc9396), [RFC 7662: OAuth 2.0 Token Introspection](https://www.rfc-editor.org/rfc/rfc7662), [RFC 8252: OAuth 2.0 for Native Apps](https://www.rfc-editor.org/rfc/rfc8252), [RFC 9700: Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/rfc/rfc9700)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) (`acr_values`, `max_age`, `prompt`, `auth_time`, `amr`) and [OpenID Connect Client-Initiated Backchannel Authentication (CIBA) Core 1.0](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html)
- [Commission Delegated Regulation (EU) 2018/389 — RTS on strong customer authentication and common and secure communication](https://eur-lex.europa.eu/eli/reg_del/2018/389/oj) (Article 5, dynamic linking)
- [W3C Web Authentication Level 2](https://www.w3.org/TR/webauthn-2/) and [passkeys.dev](https://passkeys.dev/)
- [Android Developers — Show a biometric authentication dialog](https://developer.android.com/identity/sign-in/biometric-auth), [Credential Manager](https://developer.android.com/identity/sign-in/credential-manager), [Tapjacking](https://developer.android.com/privacy-and-security/risks/tapjacking)
- [Apple — Accessing keychain items with Face ID or Touch ID](https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id), [Supporting passkeys](https://developer.apple.com/documentation/authenticationservices/supporting-passkeys), [`ASWebAuthenticationSession`](https://developer.apple.com/documentation/authenticationservices/aswebauthenticationsession)
- [Auth0 — What is step-up authentication?](https://auth0.com/blog/what-is-step-up-authentication-when-to-use-it/)
- [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
