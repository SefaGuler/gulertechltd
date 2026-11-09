---
title: "MASVS-AUTH: Testing Authentication and Authorisation in Android and iOS Apps"
date: 2026-11-09 08:39:00 +0000
subcategory: auth
summary: "Hub for the MASVS-AUTH series: the eight MASWE weaknesses, their MASTG Knowledge and Tests, client-vs-server boundaries, a test plan and a cheat sheet."
refs: [MASVS-AUTH-1, MASVS-AUTH-2, MASVS-AUTH-3, MASWE-0018, MASWE-0025]
tags: [android, ios, masvs-auth, authentication, methodology]
---

This is the entry point to our series on **OWASP MASVS-AUTH**. The control group has three requirements:

- **MASVS-AUTH-1:** "The app uses secure authentication and authorization protocols and follows the relevant best practices."
- **MASVS-AUTH-2:** "The app performs local authentication securely according to the platform best practices."
- **MASVS-AUTH-3:** "The app secures sensitive operations with additional authentication."

Each note in the series covers one weakness from the [MASWE](https://mas.owasp.org/MASWE/) catalogue, with its **Knowledge** and **Tests**. This page maps the area, draws the line between what a mobile test can prove and what needs backend testing, and collects the commands you will reach for on every authentication review.

## Contents

- [What MASVS-AUTH covers](#what-masvs-auth-covers)
- [The eight weaknesses](#the-eight-weaknesses)
- [Knowledge and Tests map](#knowledge-and-tests-map)
- [Client or server: what a mobile test can prove](#client-or-server-what-a-mobile-test-can-prove)
- [Authentication building blocks on mobile](#authentication-building-blocks-on-mobile)
- [Test plan](#test-plan)
- [Command and hook cheat sheet](#command-and-hook-cheat-sheet)
- [Reporting authentication findings](#reporting-authentication-findings)
- [References](#references)

## What MASVS-AUTH covers

MASVS says it plainly: authentication and authorisation **must be enforced on the remote endpoint**. The app's job is to:

- use the protocols correctly;
- authenticate the user locally in a way that cannot be switched off with a hook;
- ask for fresh authentication before anything sensitive;
- not leave the door open afterwards.

In practice the three controls break down like this:

- **AUTH-1 (protocols and authorisation):** how the app logs in and keeps a session, and whether its own components (activities, services, receivers, providers) let other apps act without authorisation. On the MASWE list: **MASWE-0018** (unprotected app components) and **MASWE-0019** (no autofill support, which drives users towards weak passwords).
- **AUTH-2 (local authentication):** biometrics and app PINs. Is the check bound to cryptography or is it a boolean in the UI? Can it fall back to a weaker credential? Does a newly enrolled fingerprint inherit access? That is **MASWE-0020**, **0021** and **0022**.
- **AUTH-3 (sensitive operations):** step-up before payments and account changes (**MASWE-0023**), sessions that really end (**MASWE-0024**), and evidence of who approved what (**MASWE-0025**).

Two neighbouring notes from the [CRYPTO series](/mobile/masvs-crypto-cryptography-guide/) are prerequisites for AUTH-2:

- [MASWE-0016](/mobile/maswe-0016-key-access-not-restricted/): keys that require user authentication to use.
- [MASWE-0017](/mobile/maswe-0017-device-secure-lock-not-enforced/): a device passcode, without which none of that works.

Our older notes on [Android biometric authentication](/mobile/mastg-know-0001-biometric-authentication/) and [FingerprintManager](/mobile/mastg-know-0002-fingerprintmanager/) also belong to this group.

## The eight weaknesses

| ID | Weakness | Controls | Profiles | Linked tests | Note |
|----|----------|----------|----------|--------------|------|
| MASWE-0018 | Lack of Authentication or Authorization on App Components | AUTH-1, PLATFORM-1, STORAGE-2 | L1, L2, EUDIW | 6 | [Read](/mobile/maswe-0018-missing-auth-on-app-components/) |
| MASWE-0019 | Lack of Auto-fill Support for Credential Providers | AUTH-1, AUTH-3 | L1, L2, EUDIW | 0 | [Read](/mobile/maswe-0019-no-autofill-support-for-credential-providers/) |
| MASWE-0020 | Local Authentication Can Be Bypassed | AUTH-2, CRYPTO-2 | L2, EUDIW | 5 | [Read](/mobile/maswe-0020-local-authentication-bypass/) |
| MASWE-0021 | Fallback to Non-biometric Credentials Allowed for Sensitive Transactions | AUTH-2 | L2, EUDIW | 3 | [Read](/mobile/maswe-0021-non-biometric-fallback-for-sensitive-transactions/) |
| MASWE-0022 | Crypto Keys Not Invalidated on New Biometric Enrollment | AUTH-2, CRYPTO-2 | L2, EUDIW | 3 | [Read](/mobile/maswe-0022-keys-not-invalidated-on-biometric-enrollment/) |
| MASWE-0023 | Step-Up Authentication Not Implemented for Sensitive Actions | AUTH-3, PLATFORM-3 | L2, EUDIW | 0 | [Read](/mobile/maswe-0023-step-up-authentication-not-implemented/) |
| MASWE-0024 | Sensitive Data Accessible After Session Termination | AUTH-3 | L2, EUDIW | 0 | [Read](/mobile/maswe-0024-sensitive-data-accessible-after-session-termination/) |
| MASWE-0025 | Lack of Non-Repudiation for Critical Actions | AUTH-3 | L2, EUDIW | 0 | [Read](/mobile/maswe-0025-lack-of-non-repudiation/) |

Four of the eight weaknesses have no OWASP tests yet. Their notes give our own procedures, marked **Guler Tech methodology**.

The **profiles** column tells you when a weakness applies. **L1** applies to every app: unprotected components and missing autofill support. Everything about biometrics, step-up, session termination and non-repudiation is **L2/EUDIW**, the profiles for banking, health, identity and the EU Digital Identity Wallet. For an L1 app these are still worth raising as observations, but they should not be reported as failures of the profile.

## Knowledge and Tests map

Every OWASP item linked from the eight weaknesses on the live MASWE site. Weaknesses not listed here have no linked items yet.

### MASWE-0018 — Lack of Authentication or Authorization on App Components

| Type | ID | Title | Platform |
|------|----|-------|----------|
| Knowledge | MASTG-KNOW-0020 | Inter-Process Communication (IPC) Mechanisms | Android |
| Knowledge | MASTG-KNOW-0132 | Android Activities | Android |
| Knowledge | MASTG-KNOW-0133 | Android Services | Android |
| Knowledge | MASTG-KNOW-0134 | Android Broadcast Receivers | Android |
| Knowledge | MASTG-KNOW-0117 | Android ContentProvider | Android |
| Knowledge | MASTG-KNOW-0017 | App Permissions | Android |
| Test | MASTG-TEST-0364 | Exported And Unprotected Activities That Expose Sensitive Functionality | Android |
| Test | MASTG-TEST-0365 | Exported And Unprotected Services That Expose Sensitive Functionality | Android |
| Test | MASTG-TEST-0366 | Exported And Unprotected Broadcast Receivers That Expose Sensitive Functionality | Android |
| Test | MASTG-TEST-0355 | References to Unauthorized Database Access through Content Providers | Android |
| Test | MASTG-TEST-0356 | Runtime Verification of Unauthorized Database Access through Content Providers | Android |
| Test | MASTG-TEST-0357 | References to Oversharing of File-Based Content Providers | Android |
| Best practice | MASTG-BEST-0052 | Restrict Access to Android App Components | Android |
| Best practice | MASTG-BEST-0049 | Restrict and Validate Access to Exported Content Providers | Android |

### MASWE-0020 — Local Authentication Can Be Bypassed

| Type | ID | Title | Platform |
|------|----|-------|----------|
| Knowledge | MASTG-KNOW-0001 | Biometric Authentication | Android |
| Knowledge | MASTG-KNOW-0043 | Android KeyStore | Android |
| Knowledge | MASTG-KNOW-0047 | Cryptographic Key Storage | Android |
| Knowledge | MASTG-KNOW-0012 | Key Generation | Android |
| Knowledge | MASTG-KNOW-0056 | Local Authentication Framework | iOS |
| Knowledge | MASTG-KNOW-0057 | Keychain Services | iOS |
| Test | MASTG-TEST-0327 | References to APIs for Event-Bound Biometric Authentication | Android |
| Test | MASTG-TEST-0329 | References to APIs Enforcing Authentication without Explicit User Action | Android |
| Test | MASTG-TEST-0330 | References to APIs for Keys used in Biometric Authentication with Extended Validity | Android |
| Test | MASTG-TEST-0266 | References to APIs for Event-Bound Biometric Authentication | iOS |
| Test | MASTG-TEST-0267 | Runtime Use Of Event-Bound Biometric Authentication | iOS |
| Best practice | MASTG-BEST-0036 | Use Cryptographic Binding for Biometric Authentication | — |
| Best practice | MASTG-BEST-0038 | Require Explicit User Confirmation for Biometric Authentication | Android |

### MASWE-0021 — Fallback to Non-biometric Credentials Allowed for Sensitive Transactions

| Type | ID | Title | Platform |
|------|----|-------|----------|
| Test | MASTG-TEST-0326 | References to APIs Allowing Fallback to Non-Biometric Authentication | Android |
| Test | MASTG-TEST-0268 | References to APIs Allowing Fallback to Non-Biometric Authentication | iOS |
| Test | MASTG-TEST-0269 | Runtime Use Of APIs Allowing Fallback to Non-Biometric Authentication | iOS |
| Best practice | MASTG-BEST-0031 | Enforce Strong Biometrics for Sensitive Operations | — |

### MASWE-0022 — Crypto Keys Not Invalidated on New Biometric Enrollment

| Type | ID | Title | Platform |
|------|----|-------|----------|
| Test | MASTG-TEST-0328 | References to APIs Detecting Biometric Enrollment Changes | Android |
| Test | MASTG-TEST-0270 | References to APIs Detecting Biometric Enrollment Changes | iOS |
| Test | MASTG-TEST-0271 | Runtime Use Of APIs Detecting Biometric Enrollment Changes | iOS |
| Best practice | MASTG-BEST-0037 | Invalidate Biometric Keys on Enrollment Changes | — |

## Client or server: what a mobile test can prove

Authentication findings are where mobile reports are most often over- or under-rated. The test is always the same question: **does the server's decision depend on something the client controls?**

| You observe on the device | What it proves | What you still need |
|---------------------------|----------------|---------------------|
| Biometric prompt is a UI gate, and hooking `onAuthenticationSucceeded` or `evaluatePolicy` unlocks the screen | The *local* control is bypassable (MASWE-0020) | Whether the unlocked screen can do anything the session token could not already do. If the API accepts the same token with or without the prompt, the biometric adds no server-side assurance. |
| Sensitive API call succeeds after you remove a step-up header or replay it without a fresh OTP | Server does not enforce step-up (MASWE-0023) | Nothing more: this is a server-side finding proven from the client. |
| Old access or refresh token still works after logout | Server does not revoke on logout (MASWE-0024) | Token lifetimes, to rate it. |
| Exported component performs an action when called by `adb` or a test app | Missing component authorisation (MASWE-0018) | Whether the action reaches the backend with the user's session (usually yes, which raises severity). |
| Request carries no signature, or a signature from a key that is not auth-bound | No non-repudiation (MASWE-0025) | Client's audit/logging design. Ask for it; you cannot see it. |

Where the finding is really a backend issue (broken object-level authorisation, weak password policy, missing lockout), report it against the API using [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) / [WSTG](https://owasp.org/www-project-web-security-testing-guide/) references, and mention the mobile flow only as the route you used to reach it.

## Authentication building blocks on mobile

A quick reference for what "follows the relevant best practices" means in 2026.

- **Login via OAuth 2.0 / OIDC in the system browser, not an embedded WebView.** Use Custom Tabs on Android and `ASWebAuthenticationSession` on iOS, with **PKCE** ([RFC 7636](https://www.rfc-editor.org/rfc/rfc7636)) and a claimed HTTPS redirect (App Links / Universal Links), or at least a private-use scheme ([RFC 8252](https://www.rfc-editor.org/rfc/rfc8252)). Do not ship a client secret in the app (see [MASWE-0004](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/)). The current security baseline is [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700), the OAuth 2.0 Security Best Current Practice.
- **Passkeys** (WebAuthn/FIDO2) via Android Credential Manager and iOS `ASAuthorizationController` are now the strongest mainstream option for both sign-in and step-up: phishing-resistant, device-bound or synced, with user verification built in.
- **Tokens:** short-lived access tokens and rotating refresh tokens with reuse detection, held in Keystore-encrypted storage or the Keychain ([MASWE-0001](/mobile/maswe-0001-sensitive-data-unencrypted-private-storage/)) and revoked server-side on logout ([RFC 7009](https://www.rfc-editor.org/rfc/rfc7009)).
- **Biometrics:** only meaningful when **crypto-bound**. The biometric unlocks a Keystore/Keychain key, which signs a server challenge or decrypts a secret. A biometric that only returns `true` to the app is a convenience feature, not a security control.
- **Step-up and transaction confirmation:** the server asks for fresh authentication (or a signature from an auth-bound key) for each sensitive action, and binds it to the specific transaction. In the EU this is also the PSD2 "dynamic linking" requirement for payments.
- **Device binding:** an attested, hardware-backed key generated at enrolment identifies the app instance. Many of the controls above build on it.

## Test plan

### 1. Map the authentication surface

List:

- every way to log in: password, social/OIDC, magic link, passkey, SMS OTP;
- every way the app stays logged in: tokens, cookies, refresh;
- every place a local check appears: app PIN, biometric prompt, "unlock with Face ID";
- every action that should require more than a session: payments, payee changes, contact detail changes, secret reveal, device binding, data export, account deletion.

Note which side enforces each.

### 2. Static review

- **Android manifest:** exported components, permissions and protection levels, `grantUriPermissions`, provider paths (MASWE-0018).
- **`BiometricPrompt` usage:** `CryptoObject` present? Allowed authenticators? `setConfirmationRequired`? (MASWE-0020/0021).
- **`KeyGenParameterSpec`:** user-authentication parameters, invalidation on enrolment (MASWE-0021/0022).
- **iOS:** `LAContext.evaluatePolicy` vs Keychain items with `SecAccessControl`; policy and flags such as `.biometryCurrentSet` vs `.biometryAny` (MASWE-0020/0021/0022).
- **Login flow:** WebView vs system browser, PKCE, client secrets.
- **Password fields:** autofill hints and content types (MASWE-0019).

### 3. Dynamic review

- Intercept the whole flow in Burp. For each sensitive action, replay it without the step-up artefact, with an old one, and for a different transaction (MASWE-0023).
- Hook the local authentication callbacks and confirm whether bypassing them gives you access to anything new (MASWE-0020).
- Call exported components from `adb` or a test app (MASWE-0018).
- On a test device: change the biometric enrolment and check whether protected actions still work (MASWE-0022). Try the passcode fallback on a sensitive action (MASWE-0021).

### 4. Session termination

Log out, expire and revoke. Then:

- replay the old tokens;
- diff the sandbox for leftover data;
- navigate back and open deep links into authenticated screens (MASWE-0024).

### 5. Evidence for critical actions

Check whether critical requests carry a signature from a hardware-backed, user-authenticated key, and whether the server rejects altered, unsigned or replayed requests (MASWE-0025).

## Command and hook cheat sheet

### Android components

```bash
adb shell dumpsys package <package> | sed -n '/Activity Resolver Table/,/^$/p'
adb shell am start -n <package>/.SecretActivity --es token test
adb shell am startservice -n <package>/.SyncService   # use start-foreground-service on API 26+ where needed
adb shell am broadcast -a <package>.ACTION_RESET -n <package>/.ResetReceiver
adb shell content query --uri content://<authority>/users
adb shell content read --uri content://<authority>/files/../shared_prefs/auth.xml
```

### Local authentication

```bash
# Android: watch BiometricPrompt callbacks and whether a CryptoObject is passed
frida-trace -U -f <package> \
  -j 'androidx.biometric.BiometricPrompt!authenticate' \
  -j 'androidx.biometric.BiometricPrompt$AuthenticationCallback!onAuthenticationSucceeded'

# iOS: LocalAuthentication and Keychain access-control usage
frida-trace -U -f <bundle-id> -m '-[LAContext evaluatePolicy:localizedReason:reply:]' \
  -i 'SecAccessControlCreateWithFlags' -i 'SecItemCopyMatching'

# iOS: objection's built-in event-bound bypass (proves the check is not crypto-bound)
objection -g <bundle-id> explore
#   ios ui biometrics_bypass
```

### Tokens and sessions

```bash
# Decode a JWT payload without verifying it, to read exp / acr / amr / scope
cut -d. -f2 <<<"$JWT" | tr '_-' '/+' | base64 -d 2>/dev/null; echo

# Replay an old access token after logout (expect 401)
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $OLD_TOKEN" https://api.example.com/v1/me
```

The individual notes contain complete scripts: Frida hooks that print the `CryptoObject` and key parameters, attacker apps for exported components, and replay matrices for step-up and logout.

## Reporting authentication findings

- **Lead with the server's behaviour.** "The transfer API accepts requests without the step-up token" is a High-severity finding with a one-line proof. "The biometric prompt can be bypassed with Frida" needs the second half of the sentence: "…and the bypassed screen can then approve transfers the plain session cannot."
- **Separate local from remote impact.** A hookable app PIN on an app whose tokens are already in plaintext storage adds little. On an app that keeps tokens Keystore-encrypted behind an auth-bound key, the same hook is the whole attack.
- **Quote the platform rule.** For example: `BiometricPrompt.authenticate(info)` without a `CryptoObject` (MASTG-TEST-0327), `.deviceOwnerAuthentication` where only biometrics should be allowed (MASTG-TEST-0268), or `.biometryAny` where `.biometryCurrentSet` is needed (MASTG-TEST-0270).
- **Give the backend fix as well as the client fix.** For local authentication that usually means: generate an auth-bound key at enrolment, register its public key, and have the server verify a signature over a server challenge for each sensitive action.

## References

- OWASP MASVS — [MASVS-AUTH-1](https://mas.owasp.org/MASVS/controls/MASVS-AUTH-1/), [MASVS-AUTH-2](https://mas.owasp.org/MASVS/controls/MASVS-AUTH-2/), [MASVS-AUTH-3](https://mas.owasp.org/MASVS/controls/MASVS-AUTH-3/) (CC BY-SA 4.0)
- OWASP MASWE — [Weakness index](https://mas.owasp.org/MASWE/) (CC BY-SA 4.0)
- OWASP MASTG — [Knowledge](https://mas.owasp.org/MASTG/knowledge/), [Tests](https://mas.owasp.org/MASTG/tests/), [Best Practices](https://mas.owasp.org/MASTG/best-practices/) (CC BY-SA 4.0)
- [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [RFC 8252 — OAuth 2.0 for Native Apps](https://www.rfc-editor.org/rfc/rfc8252)
- [RFC 7636 — Proof Key for Code Exchange (PKCE)](https://www.rfc-editor.org/rfc/rfc7636)
- [RFC 9700 — Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/rfc/rfc9700)
- [RFC 7009 — OAuth 2.0 Token Revocation](https://www.rfc-editor.org/rfc/rfc7009)
- [NIST SP 800-63B-4 — Authentication and Authenticator Management](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [Android Developers — Show a biometric authentication dialog](https://developer.android.com/identity/sign-in/biometric-auth)
- [Android Developers — Credential Manager](https://developer.android.com/identity/sign-in/credential-manager)
- [Apple — LocalAuthentication](https://developer.apple.com/documentation/localauthentication)
- [Apple — Supporting passkeys](https://developer.apple.com/documentation/authenticationservices/supporting-passkeys)

> Adapted and extended from the OWASP MASVS, MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
