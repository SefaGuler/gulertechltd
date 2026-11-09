---
title: "Lack of Auto-fill Support for Credential Providers (MASWE-0019)"
date: 2026-11-09 08:37:00 +0000
subcategory: auth
summary: "Why apps must work with password managers and passkeys: Android Autofill, Credential Manager, iOS Password AutoFill, associated domains, and tests."
refs: [MASWE-0019, MASVS-AUTH-1, MASVS-AUTH-3, CWE-287, CWE-522]
tags: [android, ios, masvs-auth, autofill, passkeys, password-managers]
---

This note is part of our [MASVS-AUTH guide](/mobile/masvs-auth-authentication-guide/) and covers OWASP [MASWE-0019](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0019/): apps that do not work with the platform's credential providers. It is the security case *for* password managers. An app that blocks paste, hides its login fields from autofill or draws its own keypad for the account password does not make users more careful; it makes them choose passwords short enough to type on a phone, reuse them, keep them in a notes app, and copy them through the clipboard. Below you will find how credential filling actually works on both platforms (the Android Autofill Framework, Credential Manager, Digital Asset Links, iOS Password AutoFill, associated domains, passkeys and credential provider extensions), the anti-patterns that break it, the opposite risk of sensitive fields that should *not* be filled or learned, our static and dynamic tests, secure Kotlin and Swift, and severity guidance.

> **Note:** At the time of writing, MASWE-0019 has no linked Knowledge pages or Tests on mas.owasp.org; the weakness page says "No Tests Yet". The MASTG does contain material on neighbouring topics — keyboard caching, text field masking, custom keyboards, accessibility data sensitivity, App Link and Universal Link domain verification — which we list in [Related OWASP material](#related-owasp-material) and cite where it applies. The Knowledge and Testing sections below are **Guler Tech methodology**.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Both platforms: why credential filling is a security control](#both-platforms-why-credential-filling-is-a-security-control)
  - [Android: the Autofill Framework](#android-the-autofill-framework)
  - [Android: Credential Manager and passkeys](#android-credential-manager-and-passkeys)
  - [Android: Digital Asset Links for credential sharing (MASTG-KNOW-0019)](#android-digital-asset-links-for-credential-sharing-mastg-know-0019)
  - [Android: input types, keyboard learning and accessibility (MASTG-KNOW-0055, MASTG-KNOW-0143)](#android-input-types-keyboard-learning-and-accessibility-mastg-know-0055-mastg-know-0143)
  - [iOS: Password AutoFill and text content types (MASTG-KNOW-0121, MASTG-KNOW-0100)](#ios-password-autofill-and-text-content-types-mastg-know-0121-mastg-know-0100)
  - [iOS: associated domains and webcredentials (MASTG-KNOW-0080)](#ios-associated-domains-and-webcredentials-mastg-know-0080)
  - [iOS: passkeys, ASAuthorizationController and credential providers (MASTG-KNOW-0082, MASTG-KNOW-0141)](#ios-passkeys-asauthorizationcontroller-and-credential-providers-mastg-know-0082-mastg-know-0141)
  - [Both platforms: one-time codes](#both-platforms-one-time-codes)
  - [Both platforms: system authentication sessions for third-party login](#both-platforms-system-authentication-sessions-for-third-party-login)
  - [Both platforms: anti-patterns that break credential filling](#both-platforms-anti-patterns-that-break-credential-filling)
  - [Both platforms: the inverse risk](#both-platforms-the-inverse-risk)
- [Testing](#testing)
  - [Related OWASP material](#related-owasp-material)
  - [GT-0019-1: Credential field configuration in code and layouts (Android)](#gt-0019-1-credential-field-configuration-in-code-and-layouts-android)
  - [GT-0019-2: Credential field configuration in the binary (iOS)](#gt-0019-2-credential-field-configuration-in-the-binary-ios)
  - [GT-0019-3: App-to-website association files (Android and iOS)](#gt-0019-3-app-to-website-association-files-android-and-ios)
  - [GT-0019-4: Fill, save, paste and one-time codes on a device (Android)](#gt-0019-4-fill-save-paste-and-one-time-codes-on-a-device-android)
  - [GT-0019-5: Fill, save, paste and one-time codes on a device (iOS)](#gt-0019-5-fill-save-paste-and-one-time-codes-on-a-device-ios)
  - [GT-0019-6: Third-party login in embedded views (Android and iOS)](#gt-0019-6-third-party-login-in-embedded-views-android-and-ios)
  - [GT-0019-7: Sensitive non-credential fields offered to autofill or keyboard learning (Android and iOS)](#gt-0019-7-sensitive-non-credential-fields-offered-to-autofill-or-keyboard-learning-android-and-ios)
- [Secure implementation](#secure-implementation)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

MASWE-0019 applies when an app does not support the mechanisms the platform provides for supplying credentials: password and one-time-code autofill, Password AutoFill tied to an associated domain, credential sharing between the app and its website, system authentication sessions for third-party sign-in, and passkeys. The OWASP requirement is *"The app enables auto-fill support for credential providers."* It maps to MASVS-AUTH-1 (secure authentication protocols and best practices) and MASVS-AUTH-3 (sensitive operations secured with additional authentication), to [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html) and [CWE-522: Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html), and it is tagged with all three profiles: [MAS-L1](https://mas.owasp.org/Profiles/MAS-L1/), [MAS-L2](https://mas.owasp.org/Profiles/MAS-L2/) and [MAS-EUDIW](https://mas.owasp.org/Profiles/MAS-EUDIW/). Unlike most AUTH weaknesses, it is a baseline (L1) expectation: every app with a login should get this right.

OWASP's threat for this weakness is MAS-THREAT-0019, *"Attackers can capture credentials that users handle manually."* The two attacks it lists explain why:

- **MAS-ATTACK-0041 — reading sensitive data from the clipboard when users copy it between apps.** If the app cannot be filled, the user who has a password manager copies the password out of it and pastes it in. Every app that reads the clipboard in that window — and on iOS, every nearby device sharing the Universal Clipboard — can see it. OWASP's clipboard weakness, [MASWE-0030](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0030/), points back to this one as its mitigation: "provide secure alternatives such as auto-fill … so users never need to copy secrets."
- **MAS-ATTACK-0042 — phishing credentials through lookalike apps or pages when users must type them manually.** A password manager fills credentials only into the app or site it has verified as belonging to the account's domain. A user who types the password from memory will type it into a lookalike just as readily. Passkeys go further: the credential is bound to the relying party and cannot be phished at all.

What a mobile tester can prove here is unusually client-side. The configuration lives in the app (field types, hints, content types, entitlements) and on the website (`assetlinks.json`, `apple-app-site-association`), and both can be checked from outside. The backend matters in two places: whether it accepts pasted and long passwords (a server that truncates or rejects 64-character generated passwords defeats the client), and whether passkey assertions are verified correctly — the latter is a server test in its own right ([OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) V6 Authentication, WebAuthn sections).

## Modes of Introduction

OWASP lists five; we see each regularly, plus a handful of variants.

**Credential fields not recognised by the autofill framework.** Login fields built as plain text inputs, custom views or canvas-drawn controls (game engines, some cross-platform toolkits), Jetpack Compose text fields before Compose 1.8 without the experimental autofill APIs, or fields explicitly excluded with `importantForAutofill="no"`. iOS fields without `textContentType` usually still work through heuristics, but fields that are not `UITextField`/`SecureField` at all do not.

**No one-time-code autofill.** OTP fields that are plain numeric inputs with no `smsOTPCode` hint, no SMS Retriever or User Consent integration on Android, and no `.oneTimeCode` content type on iOS. The user reads the code from a notification and retypes or copies it.

**Missing website association.** No `delegate_permission/common.get_login_creds` statement in `assetlinks.json` for the production signing certificate; no `webcredentials:` entry in the iOS Associated Domains entitlement, or an `apple-app-site-association` file that does not list the app. Without it, the password manager cannot tell that `com.example.bank` and `https://example.com` are the same account, so it either offers nothing or offers everything and leaves the user to pick — exactly the condition in which a lookalike app gets filled.

**Embedded custom login instead of system flows.** Third-party sign-in (Google, Microsoft, Apple, a bank's IdP) inside the app's own `WebView` or `WKWebView`. The host app can read everything typed, the user cannot see the real URL, and the browser's password manager and passkeys are unavailable. Several identity providers block this outright.

**No passwordless option.** No passkeys where they could replace or supplement the password.

Variants:

- **Active obstruction:** paste disabled in credential fields; long-press disabled; a scrambled in-app keypad for the account password; the `.oneTimeCode` content type set on a password field to suppress iOS's "Save Password" and "Strong Password" prompts.
- **Save never offered:** the Android login lives in a single-activity app and never calls `AutofillManager.commit()`; the iOS login view is never removed from the hierarchy after sign-in. Users can fill but never save, so new accounts never reach the manager.
- **Masking done by hand:** a password field implemented as a text field with a custom transformation or custom bullet rendering, which also means the keyboard learns the password (see [the inverse risk](#both-platforms-the-inverse-risk)).
- **Generated passwords rejected:** client-side rules that forbid characters password managers generate, or a maximum length of 12 or 16.

## Impact

- **Credential exposure through workarounds.** Passwords and one-time codes cross the clipboard, land in keyboard dictionaries and cloud-synced notes, and are visible to clipboard-reading apps and other devices.
- **Weaker and reused passwords.** If the password has to be typed on a phone, it will be short, memorable and reused. Reuse turns every third-party breach into a credential-stuffing risk for this app.
- **Loss of phishing resistance.** Domain-matched autofill, and passkeys above all, stop the user from handing credentials to a lookalike. An app that cannot be filled trains its users to type credentials whenever asked.
- **Credential capture by the host app.** Third-party credentials typed into an embedded WebView are available to the app (and to any compromised SDK inside it).
- **Account takeover.** The end result of the above, which is how OWASP phrases it: captured credentials or one-time codes are reused for unauthorised access.

## Mitigations

- **Annotate credential fields** so the platform recognises them: `android:autofillHints` (`username`, `password`, `newPassword`, `smsOTPCode`) or Compose `ContentType` semantics on Android; `textContentType` (`.username`, `.password`, `.newPassword`, `.oneTimeCode`) on iOS. Use real password input types.
- **Let users paste** into every credential and code field. NIST SP 800-63B-4 requires verifiers to allow password managers and recommends permitting paste; the UK NCSC has made the same point for years ("Let them paste passwords").
- **Trigger the save flow**: call `AutofillManager.commit()` (or the Compose `LocalAutofillManager`'s `commit()`) after a successful login on Android; remove the login UI from the hierarchy on iOS, or save explicitly through Credential Manager.
- **Associate the app with its website**: `get_login_creds` in `assetlinks.json` for the release signing certificate; `webcredentials:` in Associated Domains plus an `apple-app-site-association` file that lists the app.
- **Support one-time-code autofill**: `smsOTPCode` hint or the SMS Retriever / User Consent APIs on Android, `.oneTimeCode` on iOS, and domain-bound SMS formats where you control the message.
- **Use system authentication sessions** — Custom Tabs on Android, `ASWebAuthenticationSession` on iOS — for any browser-based or third-party sign-in.
- **Offer passkeys** through Credential Manager and `ASAuthorizationController`.
- **Do the opposite for non-credential secrets**: exclude card PINs, CVVs, recovery codes and transaction approval codes from autofill saving and from keyboard learning, deliberately and per field.

## Knowledge

None of the sections below is an OWASP Knowledge page dedicated to MASWE-0019. Where a MASTG Knowledge page covers part of the mechanism (keyboard caching, masking, universal links, custom keyboards, accessibility), we name it in the heading and build on it.

### Both platforms: why credential filling is a security control

Security teams sometimes ask for paste and autofill to be disabled "so credentials are not stored on the phone". The argument does not survive contact with how people use phones:

| What the app does | What users actually do | Result |
|---|---|---|
| Blocks autofill and paste | Pick a password they can type with thumbs, or reuse one | Short, reused, guessable passwords; credential stuffing works |
| Blocks autofill, allows paste | Copy from the password manager or a notes app, paste in | Password on the clipboard; readable by other foreground apps, synced via Universal Clipboard, kept in clipboard history on some keyboards |
| Allows filling, no domain association | Choose a credential manually from a list | Works, but the manager cannot warn when the app is a lookalike |
| Fills, domain-associated | Tap a suggestion | Long unique password, never typed, never on the clipboard, only offered to the right app |
| Passkey | Confirm with biometrics | No shared secret to phish, replay or leak from the server |

Current guidance agrees. **NIST SP 800-63B-4** (2025) states that verifiers shall allow password managers and should permit paste for passwords, and it recommends against composition rules and forced periodic changes — both of which push users away from generated passwords. **OWASP ASVS** has long required that "paste functionality, browser password helpers, and external password managers are permitted" (2.1.11 in ASVS 4.0.3; the requirement carries over to the password-security section of V6 Authentication in ASVS 5.0). The **UK NCSC** published "Let them paste passwords" in 2017 for the same reason. Google's Android core app quality guidelines include autofill hints and Credential Manager support, which is where OWASP's mapping to `Autofill_Hints` and `Credential_Manager` comes from.

What the password manager stores is not your concern as an app developer: it is the user's encrypted vault, protected by the device lock and the manager's own key hierarchy. What *is* your concern is everything that happens when the manager cannot be used.

### Android: the Autofill Framework

The [Autofill Framework](https://developer.android.com/identity/autofill/autofill-optimize) (Android 8.0, API 26) lets one system-selected **autofill service** — Google Password Manager by default on most devices, or a third-party manager the user picks in *Settings › Passwords, passkeys & accounts* (wording varies by version and OEM) — read the structure of the focused screen and offer datasets for its fields. The app does not talk to the service; it describes its views and the framework does the rest. The current service is stored in a secure setting you can read with `adb shell settings get secure autofill_service`.

How the service decides what a field is:

1. **Autofill hints.** `android:autofillHints` in XML or `View.setAutofillHints(...)` in code. Hints are strings; the platform constants on `View` (`AUTOFILL_HINT_USERNAME` = `"username"`, `AUTOFILL_HINT_PASSWORD` = `"password"`, `AUTOFILL_HINT_EMAIL_ADDRESS`, `AUTOFILL_HINT_PHONE`, card hints) are complemented by `androidx.autofill.HintConstants`, which adds `AUTOFILL_HINT_NEW_USERNAME` (`"newUsername"`), `AUTOFILL_HINT_NEW_PASSWORD` (`"newPassword"`), `AUTOFILL_HINT_SMS_OTP` (`"smsOTPCode"`) and other OTP hints. `newPassword` tells the manager to *generate* rather than fill.
2. **Input type.** `textPassword`, `textWebPassword`, `numberPassword` and `textVisiblePassword` are strong signals. A password field that is `inputType="text"` with a `PasswordTransformationMethod` applied in code looks masked to the user but not like a password to most heuristics — or to the keyboard (see [below](#android-input-types-keyboard-learning-and-accessibility-mastg-know-0055-mastg-know-0143)).
3. **Heuristics** on resource IDs, hint text and surrounding labels. They differ per service, which is why a login that "works with Google" may fail with another manager. Hints remove the guesswork.

**`importantForAutofill`** decides whether a view is reported at all:

| XML value | Constant (`View.IMPORTANT_FOR_AUTOFILL_*`) | Int | Meaning |
|---|---|---|---|
| `auto` (default) | `AUTO` | 0 | The system decides |
| `yes` | `YES` | 1 | Report this view |
| `no` | `NO` | 2 | Do not report this view; children may still be reported |
| `yesExcludeDescendants` | `YES_EXCLUDE_DESCENDANTS` | 4 | Report this view, not its children |
| `noExcludeDescendants` | `NO_EXCLUDE_DESCENDANTS` | 8 | Report neither this view nor its children |

The integers are what you see in decompiled code (`setImportantForAutofill(8)`). `noExcludeDescendants` on a root layout silently removes the whole login form from autofill — a common copy-paste from Stack Overflow answers to "how do I stop the autofill popup". `View.isImportantForAutofill()` returns the effective result after parents are considered, which is what the dynamic test checks.

**The save flow.** The service asks to save when the *autofill context* ends with changed values: by default when the activity finishes, or when all relevant views become invisible if the service asked for that. Single-activity apps that swap fragments or Compose destinations never finish the login activity, so they must call `AutofillManager.commit()` after a successful login (and `cancel()` when the user abandons the form). Missing `commit()` is the usual reason for "fill works but save never appears".

**Custom views** that are not `EditText` must implement the autofill contract themselves — `getAutofillType()`, `getAutofillValue()`, `autofill(AutofillValue)`, and `AutofillManager.notifyValueChanged()` — or expose a virtual structure through `onProvideAutofillVirtualStructure()`. Game engines and canvas-based toolkits usually do neither.

**Jetpack Compose.** Compose UI 1.8 added first-class autofill: `Modifier.semantics { contentType = ContentType.Username }` (also `Password`, `NewPassword`, `NewUsername`, `EmailAddress`, `SmsOtpCode` and others) and `LocalAutofillManager.current?.commit()`. Earlier versions offered only an experimental `Modifier.autofill`/`AutofillNode` API that few apps adopted, so Compose login screens built before 2025 are frequently invisible to password managers.

**WebView.** Android's WebView participates in autofill for HTML forms; it honours the HTML `autocomplete` attribute (`username`, `current-password`, `new-password`, `one-time-code`). Hybrid apps should set those attributes on their own login pages.

**Testing aids.** `adb shell cmd autofill set log_level verbose` turns on framework logging, and `adb shell dumpsys autofill` prints the service and active sessions. Both are developer tools and their output changes between releases; use them to confirm what the framework saw, not as evidence on their own.

### Android: Credential Manager and passkeys

[Credential Manager](https://developer.android.com/identity/sign-in/credential-manager) (`androidx.credentials`) is the Jetpack API Google now recommends for sign-in. It presents one system sheet that offers the user's saved **passwords**, **passkeys** and federated **Sign in with Google** credentials, and it saves new ones. It replaces Smart Lock for Passwords (the `com.google.android.gms.auth.api.credentials` Credentials API), the legacy Google Sign-In for Android client and One Tap, all of which are deprecated. On Android 14 (API 34) and later, Credential Manager is a platform service and third-party password managers plug into it as credential providers; on Android 9 to 13 it is backed by Google Play services.

The calls you will recognise in decompiled code:

| Purpose | API |
|---|---|
| Entry point | `CredentialManager.create(context)` |
| Sign in | `getCredential(context, GetCredentialRequest(listOf(GetPasswordOption(), GetPublicKeyCredentialOption(requestJson))))` |
| Result types | `PasswordCredential` (`id`, `password`), `PublicKeyCredential` (`authenticationResponseJson`), `CustomCredential` (for example a Google ID token) |
| Save a password | `createCredential(context, CreatePasswordRequest(id, password))` |
| Create a passkey | `createCredential(context, CreatePublicKeyCredentialRequest(requestJson))` → `registrationResponseJson` |
| Sign out | `clearCredentialState(ClearCredentialStateRequest())` |

Credential Manager complements the Autofill Framework rather than replacing it: autofill still handles the fields of a classic login form, while Credential Manager drives the sheet that appears when the screen opens or the user taps "Sign in". Recent library versions can attach a pending Credential Manager request to an input field so that passkeys appear alongside autofill suggestions.

**Passkeys on Android** are WebAuthn credentials synchronised by the credential provider. Two things link them to your website. First, the relying party ID (RP ID) in the request JSON must be your web domain. Second, that domain must publish a Digital Asset Links statement granting the app `get_login_creds` (next section). The server must also accept the app's origin, which for Android apps is not `https://…` but `android:apk-key-hash:<base64url SHA-256 of the signing certificate>` in `clientDataJSON`. A backend that accepts only web origins fails Android passkeys; one that accepts *any* `android:apk-key-hash` value accepts assertions from any app the user is tricked into installing — a server-side finding worth checking when you have backend scope.

### Android: Digital Asset Links for credential sharing (MASTG-KNOW-0019)

Related: [MASTG-KNOW-0019](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0019/) (Deep Links), [MASTG-TECH-0174](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0174/) and [MASTG-BEST-0070](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0070/).

The same [Digital Asset Links](https://developers.google.com/digital-asset-links/v1/getting-started) file that verifies App Links (`https://<domain>/.well-known/assetlinks.json`) also tells credential providers that an app and a website share accounts. The relation differs:

| Relation | Used for |
|---|---|
| `delegate_permission/common.handle_all_urls` | App Links verification (MASTG-KNOW-0019) |
| `delegate_permission/common.get_login_creds` | Sharing passwords and passkeys between the site and the app |

A statement names the app by **package name** and **SHA-256 fingerprint of the signing certificate**. With Play App Signing, that is the *app signing key* held by Google, not the upload key the developer signs with — the single most common reason the association works in debug and fails in production. Every host that serves a login form needs a file (subdomains are not covered by the apex), and it must be served over HTTPS without redirects, as MASTG-TECH-0174 describes for App Links. Google's [Digital Asset Links API](https://developers.google.com/digital-asset-links/reference/rest) can evaluate a statement for you (`v1/assetlinks:check` and `v1/statements:list`).

Older guidance also had the app declare the association in its manifest through an `asset_statements` `<meta-data>` resource that includes the website's statements. You will still see it in apps that used Smart Lock; it is harmless, but the website file is what current providers rely on.

### Android: input types, keyboard learning and accessibility (MASTG-KNOW-0055, MASTG-KNOW-0143)

Related: [MASTG-KNOW-0055](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0055/) (Keyboard Cache) and [MASTG-KNOW-0143](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0143/) (Accessibility Data Sensitivity).

Field type is where autofill support and keyboard caching meet. MASTG-KNOW-0055 explains that the password input types (`textPassword`, `textWebPassword`, `numberPassword`, `textVisiblePassword`) and `textNoSuggestions` stop the keyboard from offering suggestions and learning what is typed, and how to decode `inputType` integers (`129` = `TYPE_CLASS_TEXT | TYPE_TEXT_VARIATION_PASSWORD`; `18` = number password; `225` = web password; `145` = visible password). The same input types are among the strongest signals the autofill service uses. A password field built as plain text therefore fails twice: password managers may not recognise it, and the keyboard may store the password in its learning database — MASTG-KNOW-0055 shows it turning up in Gboard's `trainingcachev3.db`. OWASP now tracks keyboard caching under [MASWE-0036](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0036/) (with the storage angle covered by MASVS-STORAGE-2); our [MASWE-0001 note](/mobile/maswe-0001-sensitive-data-unencrypted-private-storage/) covers where such data ends up on disk.

For sensitive fields that are not passwords, `android:imeOptions="flagNoPersonalizedLearning"` (`EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING`, API 26) asks the keyboard not to update its personalised model from that field. It is a request to the IME, honoured by mainstream keyboards, not an enforcement mechanism.

**Accessibility.** Some password managers fall back to an accessibility service when an app does not support autofill. Android 14 added `android:accessibilityDataSensitive`, which hides marked views from accessibility services that are not declared accessibility tools — a good defence against malware, and OWASP recommends it for login fields ([MASTG-BEST-0075](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0075/)). The same best practice notes the side effect: accessibility-based password managers lose access too, so the app must support the Autofill Framework to keep them working. Treat "login marked accessibility-sensitive but not autofill-ready" as a MASWE-0019 finding.

**`FLAG_SECURE` is not an autofill switch.** `WindowManager.LayoutParams.FLAG_SECURE` blocks screenshots, screen recording and non-secure displays; it does not disable the Autofill Framework, and secure login screens can be filled and saved normally. Do not accept "we use `FLAG_SECURE`, so autofill is off" as a design rationale, and do not report `FLAG_SECURE` as breaking autofill without evidence.

### iOS: Password AutoFill and text content types (MASTG-KNOW-0121, MASTG-KNOW-0100)

Related: [MASTG-KNOW-0121](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0121/) (Text Input Field Masking) and [MASTG-KNOW-0100](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0100/) (Keyboard Cache).

[Password AutoFill](https://developer.apple.com/documentation/security/password-autofill) is part of the system keyboard: when a credential field gets focus, the QuickType bar above the keyboard offers the best-matching credential from the user's credential provider (Apple's Passwords app and iCloud Keychain, or a third-party manager enabled in Settings), and a key button opens the full list. After a successful sign-in the system offers to save or update the credential. The app influences this through `UITextInputTraits`:

| Property / modifier | Values that matter | Raw value | Effect |
|---|---|---|---|
| `textContentType` | `.username` | `username` | Field receives the account name; with passkeys, enables AutoFill-assisted passkey sign-in |
| | `.password` | `password` | Existing password; offered and saved |
| | `.newPassword` | `new-password` | Registration or change; offers "Use Strong Password" |
| | `.oneTimeCode` | `one-time-code` | Offers codes from Messages (and Mail on recent iOS) or a manager's verification codes |
| `isSecureTextEntry` | `true` | — | Masks input, disables copy and keyboard learning, forces the system keyboard; also a heuristic for "password" |
| `passwordRules` | `UITextInputPasswordRules(descriptor:)` | — | Tells the generator your policy so generated passwords are accepted |

SwiftUI exposes the same through `.textContentType(...)` on `TextField` and `SecureField`. MASTG-KNOW-0121 covers masking; MASTG-KNOW-0100 covers what `autocorrectionType`, `spellCheckingType` and `isSecureTextEntry` do for keyboard caching.

iOS also infers credential fields heuristically, so a login without content types often still works. Two things it cannot infer: that a field is a **new** password (no generator without `.newPassword`), and which **domain** the app belongs to (that is the associated domain). The save prompt appears when the system sees that the filled username and password fields have gone away after the user submitted — typically because the login view controller was dismissed or replaced. Logins that stay on screen, or that clear the fields before navigating, never prompt.

### iOS: associated domains and webcredentials (MASTG-KNOW-0080)

Related: [MASTG-KNOW-0080](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0080/) (Universal Links) and [MASTG-TECH-0175](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0175/).

The `com.apple.developer.associated-domains` entitlement that holds `applinks:` entries for universal links (MASTG-KNOW-0080) also holds **`webcredentials:`** entries for credential sharing:

```xml
<key>com.apple.developer.associated-domains</key>
<array>
    <string>webcredentials:example.com</string>
    <string>applinks:example.com</string>
</array>
```

The website confirms the link with an [`apple-app-site-association`](https://developer.apple.com/documentation/xcode/supporting-associated-domains) (AASA) file at `https://example.com/.well-known/apple-app-site-association`:

```json
{
  "webcredentials": {
    "apps": ["ABCDE12345.com.example.app"]
  }
}
```

The identifier is the Team ID (App ID prefix) followed by the bundle ID. Modern iOS fetches AASA files through Apple's CDN (`https://app-site-association.cdn-apple.com/a/v1/<domain>`) when the app is installed or updated, not directly from the site; MASTG-TECH-0175 shows how to query both and lists the usual failures (redirects, wrong content type, identifier mismatch, missing subdomain files). An entry with `?mode=developer` or `?mode=managed` changes how the file is fetched; developer mode only works for development-signed builds, so seeing it in a production entitlement means the association is broken in release.

With the association in place, Password AutoFill suggests the site's credentials first, third-party credential providers receive the domain as the service identifier, and passkeys created on the website work in the app. Without it, users can still pick a credential manually, but nothing protects them from picking it for the wrong app.

### iOS: passkeys, ASAuthorizationController and credential providers (MASTG-KNOW-0082, MASTG-KNOW-0141)

Related: [MASTG-KNOW-0082](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0082/) (App Extensions) and [MASTG-KNOW-0141](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0141/) (Custom Keyboards).

The [AuthenticationServices](https://developer.apple.com/documentation/authenticationservices) framework gives apps a single controller for system credential UI:

- `ASAuthorizationPasswordProvider().createRequest()` asks for a saved password and returns an `ASPasswordCredential` (`user`, `password`). It replaces `SecRequestSharedWebCredential`, which is deprecated.
- `ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier:)` creates [passkey](https://developer.apple.com/documentation/authenticationservices/supporting-passkeys) registration (`createCredentialRegistrationRequest(challenge:name:userID:)`) and assertion (`createCredentialAssertionRequest(challenge:)`) requests (iOS 16+). The relying party identifier must be a domain listed under `webcredentials:`.
- `ASAuthorizationController(authorizationRequests:)` runs one or several requests: `performRequests()` shows the sheet, `performAutoFillAssistedRequests()` offers passkeys in the QuickType bar of a `.username` field instead.

**Credential provider extensions** are how third-party password managers integrate: an app extension with the `com.apple.authentication-services-credential-provider-ui` extension point, built on `ASCredentialProviderViewController` and entitled with `com.apple.developer.authentication-services.autofill-credential-provider`. Since iOS 17 they can provide passkeys as well as passwords. The app under test does not need any code for this; it needs content types and associated domains, because those are what the provider receives (as `ASCredentialServiceIdentifier` values) to choose a credential. If you are testing a password manager itself, its extension is a separate attack surface covered by MASTG-KNOW-0082.

**Keyboards.** AutoFill is part of the *system* keyboard. MASTG-KNOW-0141 and [MASTG-BEST-0069](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0069/) explain that secure fields always use the system keyboard and that apps can reject third-party keyboard extensions app-wide; neither affects AutoFill. What *does* defeat it is an app replacing the keyboard with its own input view (`inputView`) or on-screen keypad for the account password: no keyboard, no QuickType bar, no AutoFill.

### Both platforms: one-time codes

One-time codes delivered by SMS or email are the credentials users most often copy by hand.

**Android** has three routes: the `smsOTPCode` autofill hint (the autofill service or keyboard offers the code), the [SMS Retriever API](https://developers.google.com/identity/sms-retriever/overview) (Play services delivers a message containing the app's 11-character hash to the app without any permission), and the [SMS User Consent API](https://developers.google.com/identity/sms-retriever/user-consent/overview) (the user approves sharing one message). Avoid `READ_SMS`, which Google Play restricts and which grants far more than one code.

**iOS** offers codes received in Messages (and, on recent iOS, Mail) above the keyboard for any field with `.oneTimeCode`. Password managers can also store TOTP seeds and fill generated codes into the same field.

**Domain-bound codes.** Both Safari/iOS and Chrome's WebOTP recognise SMS messages whose last line is `@example.com #123456`: the code is only offered to that origin (and, on iOS, to apps associated with it). If you control the SMS template, this is a cheap phishing defence — a code requested by a lookalike app is not filled there.

**A caveat for transaction codes.** Strong customer authentication schemes such as PSD2 require *dynamic linking*: the code is bound to the amount and payee, and the message shows both. Auto-filling such a code lets the user skip reading what they approve. That is a reason to show the transaction details prominently next to the code field, not a reason to block autofill for login codes. We return to it under [the inverse risk](#both-platforms-the-inverse-risk).

### Both platforms: system authentication sessions for third-party login

OAuth and OpenID Connect sign-in from a native app belongs in an **external user agent**, as [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252) (OAuth 2.0 for Native Apps) requires and the [OAuth 2.0 Security BCP, RFC 9700](https://www.rfc-editor.org/rfc/rfc9700), reinforces:

- **Android:** [Custom Tabs](https://developer.chrome.com/docs/android/custom-tabs/overview/) (`androidx.browser.customtabs.CustomTabsIntent`), usually through AppAuth for Android (`net.openid.appauth`). OWASP's [MASTG-BEST-0012](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0012/) notes that Android recommends Custom Tabs for sign-in because the host app cannot inspect the content.
- **iOS:** [`ASWebAuthenticationSession`](https://developer.apple.com/documentation/authenticationservices/aswebauthenticationsession), which shows a system consent alert ("'App' Wants to Use 'example.com' to Sign In"), runs the page out of process, and returns the redirect to the app. `SFSafariViewController` is also out of process — MASTG-KNOW-0076 notes the app cannot access its AutoFill data — but is meant for browsing, not authentication.

In both, the browser's password manager and passkeys work, the user sees the real URL, and the app never sees the password. In an embedded `WebView`/`WKWebView`, the app can inject JavaScript, read the DOM, observe every request and capture what is typed; the user cannot verify the page; and credential filling is limited. Google blocks its OAuth endpoints in embedded WebViews (`disallowed_useragent`), and several other identity providers detect and refuse them. OWASP's [MASTG-TEST-0378](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0378/) and [MASTG-BEST-0060](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0060/) address the related case of *first-party* password fields inside a `WKWebView`; if you adopt their native-overlay pattern, give the native field the right `textContentType` so AutoFill still works.

### Both platforms: anti-patterns that break credential filling

| Anti-pattern | Android form | iOS form | Why it is a finding |
|---|---|---|---|
| Paste blocked | `onTextContextMenuItem` returning `false` for `android.R.id.paste` (`16908322`), `isLongClickable = false`, selection action-mode callbacks returning `false` | `canPerformAction(_:withSender:)` returning `false` for `paste(_:)` | Forces typing; users choose weaker passwords |
| Fields hidden from autofill | `importantForAutofill="no"` / `noExcludeDescendants`; Compose field without content type (pre-1.8 without experimental API) | Custom control instead of `UITextField`; `textContentType` deliberately wrong | Password managers cannot fill |
| Prompt suppression hack | Autofill cancelled on every focus (`AutofillManager.cancel()`) | `.oneTimeCode` (or another non-credential type) on the password field to stop "Save Password" | Save never offered; generator disabled |
| Hand-made masking | `inputType="text"` + `PasswordTransformationMethod` in code | Custom bullet rendering, `isSecureTextEntry = false` | Not recognised as password; keyboard learns the password |
| In-app keypad for the account password | Custom `View` grid, scrambled keypad | Custom `inputView` or on-screen keypad | No keyboard, no autofill. Acceptable only for a local app PIN that is not an account credential |
| Generator-hostile rules | `maxLength` 12/16, banned symbols | Same, plus no `passwordRules` | Generated passwords rejected; users fall back to typing |
| Login in an embedded WebView | `WebView` loads IdP `/authorize` | `WKWebView` loads IdP | Host app sees credentials; no system manager or passkeys |

Some of these appear in apps with a justification ("anti-keylogger keypad", "regulator asked us to block paste"). Record the justification, and explain in the report that current NIST, NCSC and ASVS guidance points the other way. A scrambled keypad is a reasonable control for a short *local* PIN that unlocks the app; it is not a substitute for supporting a password manager on the account password.

### Both platforms: the inverse risk

Credential filling is for credentials. Other secrets entered into an app should not be saved by a password manager as if they were passwords, nor learned by the keyboard:

- **Card PINs, CVV/CVC codes, card numbers outside a checkout context**: if marked or detected as a password, the manager may offer to save them against the app's domain, sometimes overwriting the real account password. Card data belongs in the platform's payment autofill, if anywhere, not in the password entry.
- **Transaction approval codes and signing PINs**: auto-filling a dynamic-linking code skips the user's review of amount and payee (see [one-time codes](#both-platforms-one-time-codes)). For high-value approvals, consider keeping the code field fillable but showing the transaction details next to it, or using an in-app confirmation instead of an SMS code.
- **Recovery codes, security answers, national identity numbers, account numbers**: should not be learned by the keyboard or offered back in suggestions to other apps.

On Android, exclude such fields with `importantForAutofill="no"` and prevent learning with a non-caching input type or `flagNoPersonalizedLearning`. On iOS there is no per-field "do not autofill" switch; keep such fields out of username/password pairs, do not mark them `.password`, disable autocorrection and spell checking (or use `isSecureTextEntry`), and verify on a device that no save prompt appears. OWASP's keyboard-caching tests ([MASTG-TEST-0258](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0258/), [MASTG-TEST-0313](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0313/), [MASTG-TEST-0314](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0314/)) cover the keyboard side; [GT-0019-7](#gt-0019-7-sensitive-non-credential-fields-offered-to-autofill-or-keyboard-learning-android-and-ios) covers the autofill side.

## Testing

The tests below are **Guler Tech methodology**. The order matters: map every credential entry point first (login, registration, password change, re-authentication prompts, OTP and recovery screens, third-party sign-in), then check how each is built (GT-0019-1, GT-0019-2), whether the website vouches for the app (GT-0019-3), and finally what actually happens with a real password manager on a real device (GT-0019-4, GT-0019-5). The dynamic tests are the ones that settle arguments: a screenshot of a password manager offering nothing, or of a paste that does nothing, is better evidence than any decompiled attribute.

Use a password manager the client's users are likely to have (Google Password Manager on Android and Apple Passwords on iOS at minimum) and at least one third-party manager, because heuristics differ.

### Related OWASP material

No OWASP test is mapped to MASWE-0019. These existing items cover neighbouring checks; we searched the MASTG knowledge, tests (v1 and beta), techniques, best practices and demos, and all IDs below exist.

| ID | Platform | What it covers | Relevance to MASWE-0019 |
|---|---|---|---|
| [MASTG-TEST-0258](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0258/) | Android | Keyboard caching attributes (`inputType`) in UI elements | Password input types are also autofill signals |
| [MASTG-TEST-0316](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0316/) | Android | Passwords, PINs and OTPs unmasked in text fields | Hand-made masking anti-pattern |
| [MASTG-TEST-0313](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0313/), [MASTG-TEST-0314](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0314/) | iOS | Keyboard caching traits, static (r2) and runtime (Frida) | Our iOS tests extend their method to `textContentType` |
| [MASTG-TEST-0346](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0346/), [MASTG-TEST-0347](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0347/) | iOS | `isSecureTextEntry` / `SecureField` usage | Secure entry is an AutoFill heuristic |
| [MASTG-TEST-0389](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0389/) | iOS | App-wide rejection of custom keyboards | Does not affect AutoFill; do not confuse with in-app keypads |
| [MASTG-TEST-0378](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0378/) | iOS | Password fields in WebView-loaded HTML | Embedded-login mode of introduction |
| [MASTG-TEST-0276](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0276/) to [MASTG-TEST-0280](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0280/) | iOS | General pasteboard use, clearing, expiry, local-only | The clipboard exposure MASWE-0019 exists to prevent |
| [MASTG-TEST-0006](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0006/), [MASTG-TEST-0055](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0055/) | Android, iOS | Legacy (MASTG v1): keyboard cache | Superseded by the beta tests above |
| [MASTG-TEST-0028](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0028/) | Android | Legacy (MASTG v1): deep links, including `assetlinks.json` checks | Same file, different relation |
| [MASTG-TEST-0057](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0057/) | iOS | Legacy (MASTG v1): sensitive data disclosed through the UI | Secure text entry |
| [MASTG-BEST-0019](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0019/), [MASTG-BEST-0026](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0026/) | Android, iOS | Non-caching input types; preventing keyboard caching (both placeholders at the time of writing) | Inverse risk |
| [MASTG-BEST-0069](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0069/), [MASTG-BEST-0075](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0075/) | iOS, Android | System keyboard for secrets; accessibility data sensitivity (explicitly says to support autofill) | Keyboards and accessibility managers |
| [MASTG-BEST-0070](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0070/), [MASTG-BEST-0012](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0012/), [MASTG-BEST-0060](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0060/) | Android, iOS | Digital Asset Links; Custom Tabs for sign-in; native secure entry over WebViews | Association and system sessions |
| [MASTG-TECH-0174](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0174/), [MASTG-TECH-0175](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0175/), [MASTG-TECH-0177](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0177/) | Android, iOS | Verifying App Link / Universal Link association; inspecting the UI hierarchy | Used in GT-0019-3 and GT-0019-4 |

### GT-0019-1: Credential field configuration in code and layouts (Android)

Guler Tech methodology. Platform: Android. Type: static (code and resources).

#### Overview

Inventory every input field on every credential screen and record how it presents itself to the Autofill Framework and to the keyboard: input type, autofill hints, `importantForAutofill` (including on parent layouts), Compose content types, paste suppression, and whether the app calls `AutofillManager.commit()` or uses Credential Manager. Decompiled code shows constants as integers, so decode them as you go.

#### Prerequisites

- The APK and any splits; jadx ([MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)) and semgrep ([MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TOOL-0110](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/)).
- A list of credential screens, ideally with their layout or composable names (from a walkthrough with `adb shell dumpsys activity top` or [MASTG-TECH-0177](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0177/)).

#### Steps

1. **Decompile code and resources.** jadx decodes layouts to readable XML under `resources/res/`.

   ```bash
   jadx -d out/ app.apk
   LAYOUTS=out/resources/res
   ```

2. **List every autofill and input-type attribute in layouts.**

   ```bash
   grep -rnE 'android:(inputType|autofillHints|importantForAutofill|imeOptions)=' "$LAYOUTS"/layout*/ \
     | sort > fields.txt
   grep -rnE 'importantForAutofill="(no|noExcludeDescendants)"' "$LAYOUTS"/layout*/
   ```

   Then open the layouts of the credential screens and check each field together with its parents: an `EditText` with a perfect `autofillHints` inside a `LinearLayout` with `noExcludeDescendants` is excluded.

3. **Search code for the same settings and for paste suppression.**

   ```bash
   grep -rnE 'setAutofillHints|setImportantForAutofill|setInputType|PasswordTransformationMethod|AutofillManager|onTextContextMenuItem|setLongClickable\(false\)|setCustomSelectionActionModeCallback|setCustomInsertionActionModeCallback|16908322' \
     out/sources/ | grep -vE '^out/sources/(androidx|com/google/android/material)/'
   ```

   `16908322` is `android.R.id.paste` as jadx renders it.

4. **Run rules that encode the anti-patterns.**

   ```yaml
   rules:
     - id: gt-autofill-excluded
       languages: [java]
       severity: WARNING
       message: View excluded from autofill (2 = NO, 8 = NO_EXCLUDE_DESCENDANTS)
       pattern-either:
         - pattern: $V.setImportantForAutofill(2)
         - pattern: $V.setImportantForAutofill(8)
     - id: gt-paste-suppressed
       languages: [java]
       severity: WARNING
       message: Text field subclass intercepts paste
       patterns:
         - pattern: |
             public boolean onTextContextMenuItem(int $ID) { ... }
         - pattern-inside: |
             class $C extends $P { ... }
     - id: gt-manual-password-masking
       languages: [java]
       severity: INFO
       message: Masking applied in code; check the field's inputType is a password type
       pattern: $V.setTransformationMethod(PasswordTransformationMethod.getInstance())
     - id: gt-autofill-cancelled
       languages: [java]
       severity: INFO
       message: Autofill context cancelled; check it is not called on every focus
       patterns:
         - pattern: $M.cancel()
         - pattern-inside: |
             AutofillManager $M = ...;
             ...
   ```

   ```bash
   semgrep -c gt-autofill.yml out/sources/ --text
   ```

   The `cancel()` rule only matches when jadx keeps a typed local; if it finds nothing, fall back to the grep in step 3.

5. **Check Compose screens.** Compose fields do not appear in layouts. Look for content-type semantics and password keyboards:

   ```bash
   grep -rnE 'ContentType\.(Companion\.)?(get)?(Username|Password|NewPassword|NewUsername|EmailAddress|SmsOtpCode)|KeyboardType\.(Companion\.)?(get)?Password|PasswordVisualTransformation|SecureTextField|LocalAutofillManager' \
     out/sources/ | grep -v '^out/sources/androidx/'
   ```

   A Compose login that uses `PasswordVisualTransformation` but no `ContentType` and no `LocalAutofillManager` was probably written for Compose before 1.8: verify dynamically, since heuristics may still pick up some fields.

6. **Check the sign-in APIs.**

   ```bash
   grep -rlE 'androidx/credentials|androidx\.credentials' out/sources/ | grep -v '^out/sources/androidx/' | head
   grep -rnE 'GetPasswordOption|GetPublicKeyCredentialOption|CreatePasswordRequest|CreatePublicKeyCredentialRequest|clearCredentialState' out/sources/ | grep -v '^out/sources/androidx/'
   grep -rnE 'com\.google\.android\.gms\.auth\.api\.credentials|GoogleSignInClient' out/sources/ | grep -v '^out/sources/com/google/' | head
   grep -n 'asset_statements' out/resources/AndroidManifest.xml
   ```

   The third line finds the deprecated Smart Lock and Google Sign-In clients.

7. **Record the decoded result per field** in a table: screen, field, input type (decoded), hints, effective `importantForAutofill`, paste handling, and whether the screen commits.

#### Observation

For each credential and code field: decoded `inputType`, autofill hints or Compose content type, own and inherited `importantForAutofill`, paste handling, masking method; per screen: `commit()`/Credential Manager save calls; app-wide: Credential Manager, passkey and legacy API usage.

#### Evaluation

The test **fails** if any account credential or login code field:

- is excluded from autofill (`no`/`noExcludeDescendants` on the field or a parent, or `setImportantForAutofill(2|8)`);
- suppresses paste or long-press;
- is a password field with a non-password `inputType` (masking by transformation only);
- is a custom view or Compose field with no autofill support (no hints/content type and no autofill implementation) — confirm with GT-0019-4 before reporting.

It is a **weaker finding** (hardening) if fields are recognisable but lack explicit hints, registration and change-password screens lack `newPassword`, single-activity logins never call `commit()`, or the app still uses deprecated Smart Lock / Google Sign-In APIs. Passkey absence is an observation at L1 and a recommendation at L2.

It **passes** when every credential field has a password-appropriate input type and explicit hints or content types, nothing excludes them, paste works, and the save flow is triggered.

#### Demo

A pattern we see in apps that "hardened" their login: the whole form excluded from autofill, and a custom field that masks in code and swallows paste.

```xml
<LinearLayout
    android:id="@+id/login_form"
    android:importantForAutofill="noExcludeDescendants"
    android:orientation="vertical">
    <EditText android:id="@+id/login_user" android:inputType="text" />
    <com.example.app.ui.NoPasteEditText
        android:id="@+id/login_pass"
        android:inputType="text" />
</LinearLayout>
```

```kotlin
class NoPasteEditText(ctx: Context, attrs: AttributeSet?) : AppCompatEditText(ctx, attrs) {
    init {
        transformationMethod = PasswordTransformationMethod.getInstance()
        isLongClickable = false
    }
    override fun onTextContextMenuItem(id: Int): Boolean =
        if (id == android.R.id.paste) false else super.onTextContextMenuItem(id)
}
```

Detection (abridged):

```text
$ grep -rnE 'importantForAutofill="(no|noExcludeDescendants)"' out/resources/res/layout*/
out/resources/res/layout/activity_login.xml:7:    android:importantForAutofill="noExcludeDescendants"

$ semgrep -c gt-autofill.yml out/sources/ --text
  out/sources/com/example/app/ui/NoPasteEditText.java
    gt-paste-suppressed: Text field subclass intercepts paste
     21┆ public boolean onTextContextMenuItem(int id) {
     22┆     if (id == 16908322) {
     23┆         return false;
    gt-manual-password-masking: Masking applied in code; check the field's inputType is a password type
     15┆ setTransformationMethod(PasswordTransformationMethod.getInstance());
```

Three failures: the form is invisible to autofill, paste is blocked, and the password field is `inputType="text"`, so the keyboard may learn it.

### GT-0019-2: Credential field configuration in the binary (iOS)

Guler Tech methodology. Platform: iOS. Type: static (binary, resources, entitlements).

#### Overview

Establish which content types the app uses, where secure entry and password rules are set, whether any text field class overrides `canPerformAction(_:withSender:)` to block paste, whether the AuthenticationServices APIs are linked, and which domains the app claims for `webcredentials`. The approach extends OWASP's keyboard-caching static test ([MASTG-TEST-0313](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0313/), demo [MASTG-DEMO-0076](https://mas.owasp.org/MASTG/demos/ios/MASVS-STORAGE/MASTG-DEMO-0076/MASTG-DEMO-0076/)): Swift code that touches UIKit compiles to `objc_msgSend` calls with selectors you can find, and the content-type constants are imported symbols.

#### Prerequisites

- A decrypted IPA ([MASTG-TECH-0054](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0054/)) explored as in [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/).
- macOS with Xcode command-line tools (`nm`, `codesign`, `plutil`, `swift-demangle`) and radare2 ([MASTG-TOOL-0073](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/)).

#### Steps

1. **Locate the binaries.**

   ```bash
   unzip -q app.ipa -d ipa
   APP=$(ls -d ipa/Payload/*.app)
   BIN="$APP/$(plutil -extract CFBundleExecutable raw "$APP/Info.plist")"
   ```

   Repeat the following steps for frameworks under `$APP/Frameworks/` that contain UI (login SDKs often live there).

2. **Find content-type constants and AuthenticationServices classes.**

   ```bash
   nm -u "$BIN" | grep -E '_UITextContentType' | sort -u
   nm -u "$BIN" | grep -E '_OBJC_CLASS_\$_(ASAuthorization|ASWebAuthenticationSession|ASPasswordCredential|SFSafariViewController|WKWebView)' | sort -u
   ```

   The first command lists imported constants such as `_UITextContentTypeUsername`, `_UITextContentTypePassword`, `_UITextContentTypeNewPassword` and `_UITextContentTypeOneTimeCode`. Swift's `.password` and SwiftUI's `.textContentType(.password)` both resolve to these constants.

3. **Find the relevant selectors and their call sites.**

   ```bash
   strings -a "$BIN" | grep -xE 'setTextContentType:|setSecureTextEntry:|setPasswordRules:|canPerformAction:withSender:|paste:|setInputView:' | sort -u
   r2 -q -c 'f~+setTextContentType,setSecureTextEntry,setPasswordRules' "$BIN"
   r2 -A -q -c 'axt @ 0x100010118' "$BIN"   # address of a reloc.fixup.* flag from the previous command
   ```

   As in MASTG-DEMO-0076, follow each `axt` result and read the `mov x2, …` before the `objc_msgSend`. For `setTextContentType:` the argument is loaded from the imported constant, so the instruction before the call references `UITextContentTypePassword` (or another constant) rather than an immediate. A selector that only appears inside third-party code can be ignored.

4. **Find classes that override `canPerformAction:withSender:`.**

   ```bash
   r2 -q -c 'ic' "$BIN" | grep -B30 'canPerformAction:withSender:' | grep -E '^\[|class|canPerformAction'
   ```

   Then disassemble the override and look for a comparison against the `paste:` selector followed by returning `0`.

5. **Check storyboards and nibs.** Interface Builder settings are not in code. Compiled nibs are binary archives, but string values such as content-type raw values are stored as plain text:

   ```bash
   find "$APP" \( -name '*.nib' -o -name '*.storyboardc' \) | while read -r f; do
     grep -rlaE 'one-time-code|new-password|username|password' "$f" 2>/dev/null
   done
   ```

   A login nib that contains neither `username` nor `password` as content types relies on heuristics.

6. **Check SwiftUI modifiers.**

   ```bash
   nm -u "$BIN" | xcrun swift-demangle | grep -E 'textContentType|SecureField' | sort -u
   ```

7. **Extract entitlements** ([MASTG-TECH-0111](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0111/)) and list the associated domains.

   ```bash
   codesign -d --entitlements :- "$APP" 2>/dev/null | plutil -convert json -o - - \
     | jq -r '."com.apple.developer.associated-domains"[]?'
   ```

   Record the `webcredentials:` domains and any `?mode=` suffix. GT-0019-3 checks the website side.

#### Observation

Imported content-type constants; call sites and values of `setTextContentType:`, `setSecureTextEntry:` and `setPasswordRules:` for the credential screens; classes overriding `canPerformAction:withSender:` and what they do for `paste:`; content types in nibs; SwiftUI modifiers; AuthenticationServices, Safari and WebKit classes in use; associated domains.

#### Evaluation

The test **fails** if:

- a password field has a non-credential content type (`.oneTimeCode` on a password is the typical hack) or is not secure entry and not marked `.password`;
- a text field subclass used for credentials or codes returns `false` for `paste:`;
- credential entry uses a custom input view or keypad for the account password;
- the app has no `webcredentials:` entry although it shares an account system with a website, or the entry carries `?mode=developer` in a production build.

It is a **weaker finding** if content types are missing but heuristics work in GT-0019-5, registration lacks `.newPassword` or `passwordRules`, or the OTP field lacks `.oneTimeCode`. It **passes** when credential fields carry the right content types, paste is not suppressed and the associated domain is declared.

#### Demo

Adapted from the OWASP sample in MASTG-DEMO-0076, with the problems this weakness is about:

```swift
alert.addTextField { tf in
    tf.placeholder = "E-Mail"
    tf.autocorrectionType = .no              // no .username: domain matching relies on heuristics
}
alert.addTextField { tf in
    tf.placeholder = "Password"
    tf.isSecureTextEntry = true
    tf.textContentType = .oneTimeCode        // suppresses "Save Password" and "Strong Password"
}
```

```swift
final class NoPasteTextField: UITextField {
    override func canPerformAction(_ action: Selector, withSender sender: Any?) -> Bool {
        action == #selector(paste(_:)) ? false : super.canPerformAction(action, withSender: sender)
    }
}
```

Detection (abridged):

```text
$ nm -u "$BIN" | grep _UITextContentType
                 U _UITextContentTypeOneTimeCode
$ strings -a "$BIN" | grep -xE 'canPerformAction:withSender:|paste:'
canPerformAction:withSender:
paste:
$ r2 -q -c 'ic' "$BIN" | grep -B2 canPerformAction
... class 12 _TtC10MASTestApp16NoPasteTextField :: UITextField
... method 0 canPerformAction:withSender:
```

Swift classes appear under their mangled Objective-C runtime names (`_TtC<len><module><len><class>`); `xcrun swift-demangle` turns them back into `MASTestApp.NoPasteTextField`.

The only content type imported is `oneTimeCode`, used on a password field, and a text field subclass overrides `canPerformAction:withSender:`; disassembling it shows the `paste:` comparison. Both fail.

### GT-0019-3: App-to-website association files (Android and iOS)

Guler Tech methodology. Platforms: Android and iOS. Type: static (network resources).

#### Overview

Check that every domain on which users sign in vouches for the production app: a `get_login_creds` statement for the release signing certificate in `assetlinks.json`, and a `webcredentials` entry listing `<TeamID>.<bundleID>` in the AASA file. This is the configuration that lets password managers and passkeys treat app and website as one account — and refuse to fill a lookalike. As MASTG-TECH-0175 points out, these files are the website's responsibility, so findings here often go to a different team; say so in the report.

#### Prerequisites

- The release APK (or the Play-distributed one, so the certificate is Google's app signing key) and the production IPA.
- The sign-in domains: from the app's traffic, its strings, its App Link hosts and its `webcredentials:` entitlement.
- `curl`, `jq`, `apksigner` (Android SDK build-tools).

#### Steps

1. **Get the Android package name and signing certificate fingerprint.**

   ```bash
   PKG=$(aapt2 dump packagename app.apk)
   FP=$(apksigner verify --print-certs app.apk | grep -m1 'SHA-256 digest' \
        | awk '{print toupper($NF)}' | sed 's/../&:/g; s/:$//')
   echo "$PKG $FP"
   ```

2. **Fetch `assetlinks.json` from each sign-in host** and check status, content type and redirects (no `-L`: a redirect is itself a failure).

   ```bash
   curl -sS -o assetlinks.json -w '%{http_code} %{content_type} %{redirect_url}\n' \
     https://example.com/.well-known/assetlinks.json
   jq '.[] | select(.relation | index("delegate_permission/common.get_login_creds"))
           | .target | select(.namespace == "android_app")' assetlinks.json
   ```

3. **Ask Google's Digital Asset Links API** whether the relation holds for this exact app.

   ```bash
   curl -sS "https://digitalassetlinks.googleapis.com/v1/assetlinks:check?\
   source.web.site=https://example.com&\
   relation=delegate_permission/common.get_login_creds&\
   target.android_app.package_name=$PKG&\
   target.android_app.certificate.sha256_fingerprint=$FP" | jq .
   ```

   Look for `"linked": true`.

4. **Fetch the AASA file** from the site and from Apple's CDN ([MASTG-TECH-0175](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0175/)) for each `webcredentials:` domain.

   ```bash
   curl -sS -o aasa.json -w '%{http_code} %{content_type} %{redirect_url}\n' \
     https://example.com/.well-known/apple-app-site-association
   curl -sS https://app-site-association.cdn-apple.com/a/v1/example.com | jq '.webcredentials'
   jq -r '.webcredentials.apps[]?' aasa.json
   ```

5. **Compare the AASA app list** with the IPA's Team ID and bundle ID (from the entitlements in GT-0019-2: `application-identifier` is `<TeamID>.<bundleID>`).

6. **If passkeys are offered**, note the RP ID the app uses (from the request JSON in traffic) and confirm it is a domain covered by both files.

#### Observation

Per domain: HTTP status, content type, redirects, the `get_login_creds` statements and fingerprints, the API's `linked` result, the AASA `webcredentials.apps` list from the site and from the CDN, and the app identifiers they should match.

#### Evaluation

The test **fails** for a domain on which users sign in if `assetlinks.json` has no `get_login_creds` statement for the production package and fingerprint (including the common case of the upload key instead of the Play app signing key), the AASA file does not list the app under `webcredentials`, the files are missing, redirect, or are served with the wrong type, or the app's entitlement uses `?mode=developer` in production.

It **passes** when both files associate the production app with every sign-in domain and the CDN copy matches. If the app and website deliberately use separate account systems, record that and treat the result as informational.

#### Demo

A typical partial configuration: App Links were set up, credential sharing was not.

```json
[{
  "relation": ["delegate_permission/common.handle_all_urls"],
  "target": {
    "namespace": "android_app",
    "package_name": "com.example.app",
    "sha256_cert_fingerprints": ["00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF"]
  }
}]
```

```text
$ jq '.[] | select(.relation | index("delegate_permission/common.get_login_creds"))' assetlinks.json
$ curl -sS ".../v1/assetlinks:check?...relation=delegate_permission/common.get_login_creds..." | jq .linked
null
```

No statement and no link: Android password managers cannot associate the app with `example.com`, and passkeys created on the website cannot be used in the app. The fix is to add `"delegate_permission/common.get_login_creds"` to the same statement's relation list.

### GT-0019-4: Fill, save, paste and one-time codes on a device (Android)

Guler Tech methodology. Platform: Android. Type: dynamic (manual, with optional hooks).

#### Overview

Use a real password manager against every credential screen and record what it offers, what it saves and what the app lets you paste. Back the observations with a UI hierarchy dump and a Frida inventory of each field's effective autofill properties, which also catches fields created at runtime.

#### Prerequisites

- A device or emulator with Google Play services, Android 9+ (Android 14+ to see Credential Manager with third-party providers).
- Google Password Manager and one third-party manager installed; a test account whose credentials are *not* yet saved.
- Optionally frida-server ([MASTG-TOOL-0001](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0001/)) for steps 6–7 ([MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/)).

#### Steps

1. **Confirm the active autofill service** and turn on framework logging.

   ```bash
   adb shell settings get secure autofill_service
   adb shell cmd autofill set log_level verbose
   adb logcat -c && adb logcat | grep -iE 'autofill' > autofill.log &
   ```

2. **Save flow.** Log in by typing the test credentials. A "Save password?" (or the provider's equivalent) prompt should appear after the login succeeds. If it does not, note whether the app stays in the same activity (`adb shell dumpsys activity top | grep ACTIVITY`) — a hint that `commit()` is missing.

3. **Fill flow.** Save the credentials manually in the manager if step 2 failed. Log out, return to the login screen, tap the username field: suggestions should appear in a dropdown or the keyboard's inline suggestion strip. If nothing appears, long-press the field and check the overflow menu for **Autofill**. Repeat with the third-party manager.

4. **Registration and password change.** On fields that set a new password, the manager should offer to generate one. Note any rejection of the generated password by the app (length limits, banned characters) or by the server.

5. **Hierarchy check** ([MASTG-TECH-0177](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0177/)).

   ```bash
   adb shell uiautomator dump /sdcard/ui.xml && adb pull /sdcard/ui.xml
   grep -oE '<node [^>]*(EditText|password="true")[^>]*>' ui.xml \
     | grep -oE '(resource-id|class|password)="[^"]*"' | paste - - -
   ```

   A field the user perceives as a password with `password="false"` is masked by hand.

6. **Inventory autofill properties at runtime.**

   ```javascript
   // gt-autofill-fields.js — run with: frida -U -n <process> -l gt-autofill-fields.js
   Java.perform(() => {
     const IMP = { 0: 'auto', 1: 'yes', 2: 'no', 4: 'yesExcludeDescendants', 8: 'noExcludeDescendants' };
     Java.choose('android.widget.EditText', {
       onMatch(et) {
         if (!et.isShown()) return;
         let id = 'no-id';
         try { id = et.getResources().getResourceEntryName(et.getId()); } catch (e) {}
         const raw = et.getAutofillHints();
         const hints = [];
         if (raw) { for (let i = 0; i < raw.length; i++) hints.push(raw[i]); }
         console.log(`${et.getClass().getName()} id=${id} inputType=${et.getInputType()} ` +
           `hints=${hints.join(',') || 'none'} own=${IMP[et.getImportantForAutofill()]} ` +
           `effective=${et.isImportantForAutofill()} longClick=${et.isLongClickable()}`);
       },
       onComplete() {}
     });
   });
   ```

   Run it while each credential screen is visible. `effective=false` means the field is not reported to the autofill service, whatever its own setting says. Compose fields are not `EditText`s and will not appear; rely on steps 3 and 5 for them.

7. **Paste.** Copy a canary string (`GT-PASTE-CANARY-19`) in another app, long-press the field and choose **Paste**; also try `adb shell input keyevent 279` (`KEYCODE_PASTE`) with the field focused. To see what the app does with the request:

   ```javascript
   Java.perform(() => {
     const TextView = Java.use('android.widget.TextView');
     TextView.onTextContextMenuItem.implementation = function (id) {
       const r = this.onTextContextMenuItem(id);
       if (id === 16908322) console.log(`paste -> ${r} on ${this.getClass().getName()}`);
       return r;
     };
   });
   ```

   A subclass that overrides the method and returns early never reaches `TextView`'s implementation; hook the subclass found in GT-0019-1 the same way.

8. **One-time codes.** Trigger an SMS code. On an emulator you can inject one with `adb emu sms send 5551234 "Your example.com code is 482913"`; for the SMS Retriever API the message must end with the app's hash, which you can recover from traffic or from a real message. Check whether the code is offered above the keyboard or filled automatically, and whether paste works in the OTP field.

9. **Passkeys and Credential Manager.** If the app offers them, create a passkey, sign out, and sign in with it; note which provider sheet appears and whether the server accepts the assertion.

#### Observation

Per screen: screenshots of save prompts and fill suggestions (or their absence) for each manager, the hierarchy dump, the Frida field inventory, paste results with hook output, OTP behaviour, generated-password acceptance, and passkey behaviour.

#### Evaluation

The test **fails** if, on any account credential or login-code screen, no supported password manager can fill the fields, paste is blocked, a perceived password field is not a password type, or saving is never offered after a successful login *and* no Credential Manager save exists. It **passes** when both managers fill and save, paste works, OTP fields accept fills or paste, and generated passwords are accepted.

#### Demo

Frida output for the vulnerable layout from GT-0019-1:

```text
android.widget.EditText id=login_user inputType=1 hints=none own=auto effective=false longClick=true
com.example.app.ui.NoPasteEditText id=login_pass inputType=1 hints=none own=auto effective=false longClick=false
paste -> false on com.example.app.ui.NoPasteEditText
```

Both fields are effectively excluded (inherited from the parent's `noExcludeDescendants`), the password field is plain text (`inputType=1`) and paste returns `false`. The device showed no suggestion from either manager.

### GT-0019-5: Fill, save, paste and one-time codes on a device (iOS)

Guler Tech methodology. Platform: iOS. Type: dynamic (manual, with optional hooks).

#### Overview

The iOS counterpart of GT-0019-4. AutoFill behaviour is visible in the QuickType bar and the save sheet; a Frida script modelled on OWASP's [MASTG-DEMO-0077](https://mas.owasp.org/MASTG/demos/ios/MASVS-STORAGE/MASTG-DEMO-0077/MASTG-DEMO-0077/) records each field's content type, secure entry, password rules and paste capability as it gains focus.

#### Prerequisites

- A device on a current iOS version with a passcode, Apple Passwords/iCloud Keychain enabled, and one third-party credential provider enabled under *Settings › General › AutoFill & Passwords* (iOS 18; earlier versions put this under *Settings › Passwords*).
- A test account not yet saved.
- Optionally Frida ([MASTG-TOOL-0039](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/)) on a jailbroken device or a Gadget-injected build ([MASTG-TECH-0090](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0090/)) for step 5 ([MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/)).

#### Steps

1. **Save flow.** Sign in by typing. A "Save Password?" sheet should appear once the login screen goes away. On registration, the new-password field should offer "Use Strong Password".
2. **Fill flow.** Log out and tap the username field. With a working association, the QuickType bar shows the matching credential with the website's domain; without one, only the key button appears. Repeat with the third-party provider.
3. **One-time codes.** Trigger an SMS code; the code should appear above the keyboard ("From Messages") when the OTP field is focused.
4. **Paste.** Copy `GT-PASTE-CANARY-19` in Notes, long-press each credential and code field, and check that **Paste** is offered and works.
5. **Field inventory with Frida.**

   ```javascript
   // gt-autofill-traits.js — frida -U -n <process> -l gt-autofill-traits.js
   const tfClass = ObjC.classes.UITextField;
   const pasteSel = ObjC.selector('paste:');
   Interceptor.attach(tfClass['- becomeFirstResponder'].implementation, {
     onEnter(args) {
       const tf = new ObjC.Object(args[0]);
       const ct = tf.textContentType();
       const rules = tf.passwordRules();
       const canPaste = tf.canPerformAction_withSender_(pasteSel, NULL);
       console.log(`${tf.$className} aid=${tf.accessibilityIdentifier()} placeholder=${tf.placeholder()} ` +
         `textContentType=${ct ? ct.toString() : 'nil'} secure=${tf.isSecureTextEntry()} ` +
         `passwordRules=${rules ? rules.passwordRulesDescriptor() : 'nil'} canPaste=${canPaste}`);
     }
   });
   ```

   Make sure the pasteboard holds text before you focus the fields: `UIResponder` reports `paste:` as unavailable when there is nothing to paste, which would look like a false positive. SwiftUI fields appear as private `UITextField` subclasses in our experience; custom controls that do not inherit from `UITextField` will not appear at all, which is itself worth recording.

6. **Associated domain status.** If AutoFill does not show the domain, use the checks in [MASTG-TECH-0175](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0175/) to see whether the device verified the association, and compare with GT-0019-3.

7. **Passkeys.** If offered, create a passkey, sign out, and sign in with it from the sheet and, if implemented, from the QuickType bar of the username field.

#### Observation

Screenshots of QuickType suggestions, save sheets and strong-password offers per provider; paste results; OTP behaviour; the Frida trait log per field; passkey behaviour.

#### Evaluation

The test **fails** if no provider can fill an account credential screen, the save sheet never appears and no explicit save exists, paste is not offered in credential or code fields (with text on the pasteboard), the password field reports a non-credential content type, or credential entry uses an in-app keypad. It **passes** when fill, save and paste work with both providers and the trait log shows `.username`/`.password`/`.newPassword`/`.oneTimeCode` where expected.

#### Demo

Frida output for the vulnerable sample from GT-0019-2:

```text
_UIAlertControllerTextField aid=nil placeholder=E-Mail textContentType=nil secure=false passwordRules=nil canPaste=true
_TtC10MASTestApp16NoPasteTextField aid=nil placeholder=Password textContentType=one-time-code secure=true passwordRules=nil canPaste=false
```

The password field advertises itself as a one-time-code field and refuses paste. On the device, no "Save Password?" sheet appeared after sign-in, and Notes-copied text could not be pasted.

### GT-0019-6: Third-party login in embedded views (Android and iOS)

Guler Tech methodology. Platforms: Android and iOS. Type: static and dynamic.

#### Overview

Find every browser-based sign-in — third-party identity providers, social login, the app's own web login — and determine whether it runs in a system authentication session (Custom Tabs, `ASWebAuthenticationSession`) or in an embedded web view the app controls.

#### Prerequisites

- Decompiled app (GT-0019-1/2), an interception proxy ([MASTG-TECH-0120](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0120/)), and a device.

#### Steps

1. **Static.** Search for authorisation endpoints and the APIs that would load them.

   ```bash
   # Android
   grep -rnE '/authorize|/oauth2?/|accounts\.google\.com|login\.microsoftonline\.com|appleid\.apple\.com' out/sources/ | grep -v '^out/sources/androidx/' | head
   grep -rlE 'CustomTabsIntent|net/openid/appauth|net\.openid\.appauth' out/sources/ | head
   # iOS
   strings -a "$BIN" | grep -E 'https://[^ ]*(authorize|oauth|login)' | sort -u | head
   nm -u "$BIN" | grep -E '_OBJC_CLASS_\$_(ASWebAuthenticationSession|SFSafariViewController|WKWebView)'
   ```

2. **Dynamic.** Start each sign-in option. On Android, check which activity is in front:

   ```bash
   adb shell dumpsys activity top | grep -E 'ACTIVITY'
   ```

   A Custom Tab shows as the browser's activity (for Chrome, `org.chromium.chrome.browser.customtabs.CustomTabActivity`); an embedded view shows the app's own activity. On iOS, `ASWebAuthenticationSession` displays the system "Wants to Use … to Sign In" alert first and a Safari-style sheet; a `WKWebView` login looks like part of the app.

3. **Confirm in traffic** that the `/authorize` request carries the browser's user agent and cookies (system session) rather than the app's WebView user agent.

4. **For embedded views, show what the app can see.** Hook `WebView.evaluateJavascript` / `addJavascriptInterface` (Android) or `WKUserContentController` script messages (iOS) during sign-in, or simply demonstrate that password managers and passkeys are unavailable in the view.

#### Observation

Per sign-in option: the user agent (system browser or embedded view), the identity provider and URL, evidence of JavaScript injection or bridges in embedded views, and password manager/passkey availability.

#### Evaluation

The test **fails** if credentials for a **third-party** identity provider are entered into an embedded web view. A **first-party** web login in an embedded view is a weaker finding when the view is locked to the app's own origin, the fields carry `autocomplete` attributes and autofill works; it fails if autofill does not work there either. It **passes** when every browser-based sign-in uses Custom Tabs or `ASWebAuthenticationSession`.

#### Demo

```text
$ adb shell dumpsys activity top | grep ACTIVITY
  ACTIVITY com.example.app/.auth.SocialLoginActivity 9f3c2d1 pid=12345
$ grep -rn 'accounts.google.com' out/sources/com/example/app/auth/
out/sources/com/example/app/auth/SocialLoginActivity.java:58:  this.webView.loadUrl("https://accounts.google.com/o/oauth2/v2/auth?client_id=...
```

The Google sign-in page loads inside the app's own activity. Google returns `disallowed_useragent` for this in production; apps work around it by spoofing the user agent, which is itself a finding.

### GT-0019-7: Sensitive non-credential fields offered to autofill or keyboard learning (Android and iOS)

Guler Tech methodology. Platforms: Android and iOS. Type: static and dynamic.

#### Overview

The inverse of the tests above: confirm that secrets which are not account credentials — card PINs, CVVs, recovery codes, transaction approval codes, security answers, identity numbers — are not presented to password managers as credentials and are not learned by the keyboard.

#### Prerequisites

- The field inventory from GT-0019-1/2 and the dynamic setup from GT-0019-4/5.

#### Steps

1. **Classify fields.** Mark every non-credential secret field in the inventory.
2. **Static (Android).** For those fields, check for `importantForAutofill="no"`, a non-caching input type or `textNoSuggestions`, and `flagNoPersonalizedLearning`; flag any that carry `password`/`username` hints. Run OWASP's [MASTG-TEST-0258](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0258/) on them.
3. **Static (iOS).** Check that none is marked `.password`/`.username`, and run [MASTG-TEST-0313](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0313/) for autocorrection and spell checking.
4. **Dynamic.** Enter canary values and complete the flow. Note any password-manager save prompt. Then, in another app, type the first characters of the canary and see whether the keyboard suggests the rest ([MASTG-TEST-0314](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0314/) on iOS; on a rooted Android device, `adb shell su -c "strings /data/data/com.google.android.inputmethod.latin/databases/trainingcachev3.db" | grep GT-` as in MASTG-KNOW-0055).
5. **Transaction codes.** For approval codes, check whether the amount and payee are visible on the screen where the code is filled.

#### Observation

Per field: autofill exclusion, input type and learning flags, content type, any save prompts, keyboard suggestions of canaries, and the transaction context shown next to approval codes.

#### Evaluation

The test **fails** if a non-credential secret is offered to the password manager as a password or username (save prompt for a card PIN, a recovery code saved as the account password), or if it is learned and suggested by the keyboard. Auto-filled transaction approval codes with no transaction details on screen are a weaker finding. It **passes** when these fields are excluded from credential saving and keyboard learning.

#### Demo

```xml
<!-- vulnerable: card PIN looks like an account password to autofill services -->
<EditText android:id="@+id/card_pin"
    android:inputType="numberPassword"
    android:autofillHints="password" />
```

After entering the PIN on the "Activate card" screen, Google Password Manager offered to save it as the password for the app — and would have replaced the user's real saved password if accepted.

## Secure implementation

### Android: XML login with autofill and save

```xml
<LinearLayout android:orientation="vertical" android:layout_width="match_parent" android:layout_height="wrap_content">
    <EditText android:id="@+id/username"
        android:inputType="textEmailAddress"
        android:autofillHints="username" />
    <EditText android:id="@+id/password"
        android:inputType="textPassword"
        android:autofillHints="password" />
</LinearLayout>
```

```kotlin
private fun onLoginSucceeded() {
    // Single-activity apps must end the autofill context explicitly so the save prompt appears.
    requireContext().getSystemService(AutofillManager::class.java)?.commit()
    findNavController().navigate(R.id.action_login_to_home)
}
```

Use `android:autofillHints="newPassword"` (and `newUsername` where relevant) on registration and change-password screens, and do not set a `maxLength` below 64.

### Android: Compose login (Compose UI 1.8+)

```kotlin
@Composable
fun LoginForm(onLogin: (String, String) -> Unit) {
    var user by remember { mutableStateOf("") }
    var pass by remember { mutableStateOf("") }
    val autofill = LocalAutofillManager.current
    OutlinedTextField(
        value = user, onValueChange = { user = it }, label = { Text("Email") },
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email, autoCorrectEnabled = false),
        modifier = Modifier.semantics { contentType = ContentType.Username }
    )
    OutlinedTextField(
        value = pass, onValueChange = { pass = it }, label = { Text("Password") },
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        modifier = Modifier.semantics { contentType = ContentType.Password }
    )
    Button(onClick = { autofill?.commit(); onLogin(user, pass) }) { Text("Sign in") }
}
```

### Android: Credential Manager for passwords and passkeys

```kotlin
suspend fun signIn(activity: Activity, passkeyRequestJson: String): SignInResult {
    val cm = CredentialManager.create(activity)
    val request = GetCredentialRequest(listOf(
        GetPasswordOption(),
        GetPublicKeyCredentialOption(passkeyRequestJson)   // from your server: challenge, rpId, allowCredentials
    ))
    return when (val c = cm.getCredential(activity, request).credential) {
        is PasswordCredential -> api.passwordLogin(c.id, c.password)
        is PublicKeyCredential -> api.verifyPasskey(c.authenticationResponseJson)
        else -> SignInResult.Unsupported
    }
}

suspend fun offerSave(activity: Activity, user: String, password: String) {
    CredentialManager.create(activity).createCredential(activity, CreatePasswordRequest(user, password))
}
```

Catch `GetCredentialCancellationException` and `NoCredentialException` and fall back to the form; never treat a cancelled sheet as a failed login attempt for lockout purposes.

On the website, publish one statement covering both App Links and credential sharing for the **Play app signing** certificate:

```json
[{
  "relation": ["delegate_permission/common.handle_all_urls",
               "delegate_permission/common.get_login_creds"],
  "target": {
    "namespace": "android_app",
    "package_name": "com.example.app",
    "sha256_cert_fingerprints": ["<Play app signing SHA-256>"]
  }
}]
```

### iOS: UIKit and SwiftUI login

```swift
usernameField.textContentType = .username
usernameField.keyboardType = .emailAddress
usernameField.autocorrectionType = .no
passwordField.textContentType = .password
passwordField.isSecureTextEntry = true

// Registration / change password
newPasswordField.textContentType = .newPassword
newPasswordField.isSecureTextEntry = true
newPasswordField.passwordRules = UITextInputPasswordRules(
    descriptor: "minlength: 12; required: lower; required: upper; required: digit;")

otpField.textContentType = .oneTimeCode
otpField.keyboardType = .numberPad
```

```swift
TextField("Email", text: $email)
    .textContentType(.username)
    .keyboardType(.emailAddress)
    .textInputAutocapitalization(.never)
    .autocorrectionDisabled()
SecureField("Password", text: $password)
    .textContentType(.password)
```

After a successful sign-in, dismiss or replace the login view so the system can offer to save. Add `webcredentials:example.com` to Associated Domains and publish the matching AASA file.

### iOS: passwords and passkeys through ASAuthorizationController

```swift
final class SignInController: NSObject, ASAuthorizationControllerDelegate,
                              ASAuthorizationControllerPresentationContextProviding {
    private var anchor: ASPresentationAnchor?

    func signIn(challenge: Data, anchor: ASPresentationAnchor) {
        self.anchor = anchor
        let passkey = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: "example.com")
            .createCredentialAssertionRequest(challenge: challenge)
        let password = ASAuthorizationPasswordProvider().createRequest()
        let controller = ASAuthorizationController(authorizationRequests: [passkey, password])
        controller.delegate = self
        controller.presentationContextProvider = self
        controller.performRequests()
    }

    func authorizationController(controller: ASAuthorizationController,
                                 didCompleteWithAuthorization authorization: ASAuthorization) {
        switch authorization.credential {
        case let assertion as ASAuthorizationPlatformPublicKeyCredentialAssertion:
            api.verifyPasskey(credentialID: assertion.credentialID,
                              clientDataJSON: assertion.rawClientDataJSON,
                              authenticatorData: assertion.rawAuthenticatorData,
                              signature: assertion.signature,
                              userID: assertion.userID)
        case let credential as ASPasswordCredential:
            api.passwordLogin(user: credential.user, password: credential.password)
        default:
            break
        }
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        // ASAuthorizationError.canceled: show the normal form.
    }

    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        anchor ?? ASPresentationAnchor()
    }
}
```

The challenge must come from the server and be single-use; the server verifies the assertion against the stored public key, the RP ID hash and the origin.

### Both platforms: third-party sign-in and non-credential secrets

- Run OAuth/OIDC in Custom Tabs (AppAuth for Android) or `ASWebAuthenticationSession` (AppAuth for iOS or the API directly), with PKCE ([RFC 7636](https://www.rfc-editor.org/rfc/rfc7636)) and claimed HTTPS redirect URIs where possible.
- For card PINs, recovery codes and approval codes on Android:

  ```xml
  <EditText android:id="@+id/card_pin"
      android:inputType="numberPassword"
      android:importantForAutofill="no"
      android:imeOptions="flagNoPersonalizedLearning" />
  ```

  On iOS, use `isSecureTextEntry = true` or disable autocorrection and spell checking, never mark these fields `.password`, and keep them out of username/password pairs.
- Show the amount and payee next to any transaction approval code field.

## Rating findings

Rate on what the user is pushed into (clipboard, typing, reuse), how valuable the account is (profile), whether the app actively obstructs credential managers or merely fails to help them, and whether credentials cross into a component the app controls.

| Rating | Conditions |
|---|---|
| **Critical** | Not normally used for MASWE-0019 on its own. If an embedded login demonstrably captures third-party credentials and sends them anywhere other than the identity provider, rate that under the weakness it chains into. |
| **High** | Third-party identity-provider credentials entered into an embedded web view the app controls (GT-0019-6). An L2 or EUDIW app whose primary login cannot be filled by any password manager **and** blocks paste, leaving typing as the only option; or a password field that is not a password type and is shown to be learned by the keyboard (canary suggested in another app). |
| **Medium** | Primary login not fillable by password managers (excluded from autofill, custom keypad, non-`UITextField` control) but paste works; paste blocked but autofill works; login OTP fields that block both autofill and paste; no website association for an app that shares accounts with its website, so managers cannot domain-match (phishing resistance lost); non-credential secrets saved as the account password (GT-0019-7). |
| **Low** | Fields fillable only through heuristics (missing hints or content types) with no functional failure; save never offered (missing `commit()` or view lifecycle); no `newPassword`/`passwordRules`, or length and character rules that reject generated passwords; deprecated Smart Lock or Google Sign-In APIs; `?mode=developer` in production entitlements; keyboard learning of non-credential secrets without evidence it reaches other apps. |
| **Info** | No passkey support (raise to Low for L2 apps that offer only passwords and SMS codes); first-party web login in an origin-locked embedded view where autofill works; deliberate separation of app and website accounts. |

When you report, include screenshots from both password managers (or the absence of suggestions), the decoded field configuration, the association file evidence, and a sentence explaining *why* blocking managers is the less secure option, citing NIST SP 800-63B-4 and the NCSC. Clients often believe they are following security advice when they block paste; the report should leave them with the current advice instead.

## References

- OWASP MASWE — [MASWE-0019: Lack of Auto-fill Support for Credential Providers](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0019/) (CC BY-SA 4.0)
- OWASP MASWE — [MASWE-0030: Improper Use of the Clipboard](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0030/) and [MASWE-0036: Unnecessary Exposure of Sensitive Data via the User Interface](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0036/) (CC BY-SA 4.0)
- OWASP MAS Profiles — [MAS-L1](https://mas.owasp.org/Profiles/MAS-L1/), [MAS-L2](https://mas.owasp.org/Profiles/MAS-L2/), [MAS-EUDIW](https://mas.owasp.org/Profiles/MAS-EUDIW/) (CC BY-SA 4.0)
- OWASP MASTG — knowledge [MASTG-KNOW-0019](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0019/), [MASTG-KNOW-0055](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0055/), [MASTG-KNOW-0143](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0143/), [MASTG-KNOW-0076](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0076/), [MASTG-KNOW-0080](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0080/), [MASTG-KNOW-0082](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0082/), [MASTG-KNOW-0083](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0083/), [MASTG-KNOW-0100](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0100/), [MASTG-KNOW-0121](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0121/), [MASTG-KNOW-0141](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0141/) (CC BY-SA 4.0)
- OWASP MASTG — beta tests [MASTG-TEST-0258](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0258/), [MASTG-TEST-0316](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0316/), [MASTG-TEST-0276](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0276/), [MASTG-TEST-0280](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0280/), [MASTG-TEST-0313](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0313/), [MASTG-TEST-0314](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0314/), [MASTG-TEST-0346](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0346/), [MASTG-TEST-0347](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0347/), [MASTG-TEST-0378](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0378/), [MASTG-TEST-0389](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0389/) (CC BY-SA 4.0)
- OWASP MASTG — legacy (MASTG v1) tests [MASTG-TEST-0006](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0006/), [MASTG-TEST-0028](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0028/), [MASTG-TEST-0055](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0055/), [MASTG-TEST-0057](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0057/) (CC BY-SA 4.0)
- OWASP MASTG — best practices [MASTG-BEST-0012](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0012/), [MASTG-BEST-0019](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0019/), [MASTG-BEST-0026](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0026/), [MASTG-BEST-0060](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0060/), [MASTG-BEST-0069](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0069/), [MASTG-BEST-0070](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0070/), [MASTG-BEST-0075](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0075/) (CC BY-SA 4.0)
- OWASP MASTG — demos [MASTG-DEMO-0076](https://mas.owasp.org/MASTG/demos/ios/MASVS-STORAGE/MASTG-DEMO-0076/MASTG-DEMO-0076/) and [MASTG-DEMO-0077](https://mas.owasp.org/MASTG/demos/ios/MASVS-STORAGE/MASTG-DEMO-0077/MASTG-DEMO-0077/) (CC BY-SA 4.0)
- OWASP MASTG — techniques [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/), [MASTG-TECH-0174](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0174/), [MASTG-TECH-0177](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0177/), [MASTG-TECH-0054](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0054/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0090](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0090/), [MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/), [MASTG-TECH-0111](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0111/), [MASTG-TECH-0175](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0175/), [MASTG-TECH-0120](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0120/); tools [MASTG-TOOL-0001](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0001/), [MASTG-TOOL-0039](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/), [MASTG-TOOL-0073](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/), [MASTG-TOOL-0110](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/) (CC BY-SA 4.0)
- [Android Developers — Optimize your app for autofill](https://developer.android.com/identity/autofill/autofill-optimize), [`View` autofill hints](https://developer.android.com/reference/android/view/View#setAutofillHints(java.lang.String...)), [`AutofillManager`](https://developer.android.com/reference/android/view/autofill/AutofillManager), [`HintConstants`](https://developer.android.com/reference/androidx/autofill/HintConstants)
- [Android Developers — Credential Manager](https://developer.android.com/identity/sign-in/credential-manager) and [Sign in your user with Credential Manager: handle sign-out](https://developer.android.com/identity/sign-in/credential-manager-siwg-implementation#handle-sign-out)
- [Google — Digital Asset Links](https://developers.google.com/digital-asset-links/v1/getting-started), [SMS Retriever API](https://developers.google.com/identity/sms-retriever/overview), [SMS User Consent API](https://developers.google.com/identity/sms-retriever/user-consent/overview), [Custom Tabs](https://developer.chrome.com/docs/android/custom-tabs/overview/)
- [Apple — Password AutoFill](https://developer.apple.com/documentation/security/password-autofill), [`UITextContentType`](https://developer.apple.com/documentation/uikit/uitextcontenttype), [`UITextInputPasswordRules`](https://developer.apple.com/documentation/uikit/uitextinputpasswordrules), [Supporting associated domains](https://developer.apple.com/documentation/xcode/supporting-associated-domains)
- [Apple — Supporting passkeys](https://developer.apple.com/documentation/authenticationservices/supporting-passkeys), [`ASAuthorizationController`](https://developer.apple.com/documentation/authenticationservices/asauthorizationcontroller), [`ASWebAuthenticationSession`](https://developer.apple.com/documentation/authenticationservices/aswebauthenticationsession), [`ASCredentialProviderViewController`](https://developer.apple.com/documentation/authenticationservices/ascredentialproviderviewcontroller)
- [NIST SP 800-63B-4: Digital Identity Guidelines — Authentication and Authenticator Management](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [NCSC — Let them paste passwords](https://www.ncsc.gov.uk/blog-post/let-them-paste-passwords)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) (V6 Authentication) and [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [W3C Web Authentication (WebAuthn)](https://www.w3.org/TR/webauthn-3/) and [FIDO Alliance — Passkeys](https://fidoalliance.org/passkeys/)
- [RFC 8252: OAuth 2.0 for Native Apps](https://www.rfc-editor.org/rfc/rfc8252), [RFC 9700: Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/rfc/rfc9700), [RFC 7636: PKCE](https://www.rfc-editor.org/rfc/rfc7636)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html) and [CWE-522: Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
