---
title: "MASWE-0054: Device Attestation Not Implemented"
date: 2026-11-10 20:03:00 +0000
subcategory: resilience
summary: "Testing Play Integrity, key attestation, App Attest and DeviceCheck: backend verification, replay and request binding, verdict policy, device binding."
refs: [MASWE-0054, MASVS-RESILIENCE-1]
tags: [android, ios, masvs-resilience, play-integrity, app-attest, key-attestation]
---

This note is part of our [MASVS-RESILIENCE guide](/mobile/masvs-resilience-resilience-testing-guide/) and covers OWASP [MASWE-0054](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0054/): a backend that cannot tell whether a request comes from a genuine device or from a rooted phone, an emulator, a device farm or a script. Device attestation is the one resilience control in this series that does not live on the device. The phone collects evidence that is signed by hardware or by Google or Apple, and **your backend** decides what to do with it. That changes how you test it. Hooking the app tells you almost nothing; what matters is whether the server verifies the evidence, binds it to the request, refuses replays, and acts on the result when it is bad or missing. Below you get the mechanisms in depth (Play Integrity standard and classic requests and the May 2025 verdict changes, Android hardware key attestation including the 2026 root, App Attest and DeviceCheck, device binding), four tests of our own because OWASP has none for this weakness, the patterns that fix the usual gaps, and how to rate what you find. Local root, jailbreak and emulator checks are covered in [MASWE-0051](/mobile/maswe-0051-root-jailbreak-detection-not-implemented/) and [MASWE-0053](/mobile/maswe-0053-emulator-virtual-device-detection-not-implemented/); proof that the *app* is genuine is [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/); the malware signals that Play Integrity also carries are in [MASWE-0055](/mobile/maswe-0055-malware-detection-not-implemented/).

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: Google Play Integrity API (MASTG-KNOW-0035)](#android-google-play-integrity-api-mastg-know-0035)
  - [Android: Key Attestation (MASTG-KNOW-0119)](#android-key-attestation-mastg-know-0119)
  - [Android: Device Attestation (MASTG-KNOW-0120)](#android-device-attestation-mastg-know-0120)
  - [Android: Device Binding (MASTG-KNOW-0034)](#android-device-binding-mastg-know-0034)
  - [iOS: Device Binding (MASTG-KNOW-0090)](#ios-device-binding-mastg-know-0090)
  - [iOS: DeviceCheck and App Attest (supplementary)](#ios-devicecheck-and-app-attest-supplementary)
- [Tests](#tests)
  - [Before you start: scope, accounts and builds](#before-you-start-scope-accounts-and-builds)
  - [GT-RES-0054-1: Attestation is requested for sensitive operations (Android, iOS)](#gt-res-0054-1-attestation-is-requested-for-sensitive-operations-android-ios)
  - [GT-RES-0054-2: Backend verification of attestation evidence (Android, iOS)](#gt-res-0054-2-backend-verification-of-attestation-evidence-android-ios)
  - [GT-RES-0054-3: Verdict handling policy (Android, iOS)](#gt-res-0054-3-verdict-handling-policy-android-ios)
  - [GT-RES-0054-4: Device binding implementation review (Android, iOS)](#gt-res-0054-4-device-binding-implementation-review-android-ios)
- [Secure implementation](#secure-implementation)
  - [Android: standard request bound to the request content](#android-standard-request-bound-to-the-request-content)
  - [Backend: checking a Play Integrity payload](#backend-checking-a-play-integrity-payload)
  - [Android: key attestation at enrolment](#android-key-attestation-at-enrolment)
  - [iOS: App Attest client flow](#ios-app-attest-client-flow)
  - [Backend checklist](#backend-checklist)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

MASWE-0054 applies when the backend has no cryptographically verifiable evidence about the device a request comes from, or has it and does not use it properly. The OWASP requirement is *"The app implements device attestation."* It maps to MASVS-RESILIENCE-1 ("The app validates the integrity of the platform"), to the v1 requirement MSTG-RESILIENCE-10 (device binding) and to the beta weakness MASWE-0100. OWASP gives no CWE. If your report template needs one, [CWE-693](https://cwe.mitre.org/data/definitions/693.html) (Protection Mechanism Failure) fits a missing control, and [CWE-290](https://cwe.mitre.org/data/definitions/290.html) (Authentication Bypass by Spoofing) fits a backend that trusts a device claim it never verified.

**OWASP has no tests for this weakness.** MASWE-0054 links no MASTG tests and no legacy v1 test covers it, so the four tests below (GT-RES-0054-1 to -4) are our own methodology. OWASP does not link Knowledge pages to weaknesses either; we assign five here by topic. Two of them, MASTG-KNOW-0119 (Key Attestation) and MASTG-KNOW-0120 (Device Attestation), are empty placeholders on the OWASP site, so those sections are written from the vendor documentation.

The weakness carries OWASP's **R** profile (plus EUDIW, the EU Digital Identity Wallet profile). It applies to apps whose threat model includes an attacker who controls the device or who talks to the backend without the real app at all: banking, payments, wallets and identity apps, games with an economy, promotions and sign-up bonuses, DRM. For an app without that threat model, a missing attestation is an observation, not a vulnerability. Even where it applies, attestation is defence in depth. It raises the cost of automation and tampering; it does not replace authentication, authorisation or server-side validation, and it never makes an insecure API secure.

OWASP describes the threat as MAS-THREAT-0054, *"Attackers can interact with the backend from untrusted environments"*, reached through three attacks:

| Attack | Description | What attestation contributes |
|---|---|---|
| MAS-ATTACK-0065 | Running the app on a rooted or jailbroken device they control | Android: hardware-backed boot state (locked bootloader, verified OS image) visible to the server. iOS: nothing about jailbreak state (see below) |
| MAS-ATTACK-0066 | Running the app in an emulator or virtual device | Android: emulators do not get Google-rooted hardware attestation and do not get `MEETS_DEVICE_INTEGRITY`. iOS: App Attest is not available in the Simulator |
| MAS-ATTACK-0068 | Impersonating the app with scripts, bots, or tampered clients when interacting with the backend | A request without fresh, request-bound evidence from a genuine device and app can be rejected or challenged |

What each platform mechanism actually proves:

| Mechanism | Who signs the evidence | What it says about the device | Needs Google/Apple services | Verified by |
|---|---|---|---|---|
| Play Integrity API | Google (token encrypted and signed per app) | Certified device, locked bootloader and certified OS image (Android 13+), patch age for `MEETS_STRONG_INTEGRITY`, plus app and licence verdicts and optional risk signals | Yes: Play Store and Play services | Google's `decodeIntegrityToken` endpoint called by your server (or your server, for classic requests with self-managed keys) |
| Android key attestation | The device's TEE or StrongBox, chaining to a Google root | Boot state, bootloader lock, OS signing key, OS/vendor/boot patch levels, the calling app's package and signing certificate, where the key lives | No | Your server, against Google's roots and revocation list |
| App Attest (`DCAppAttestService`) | Secure Enclave key certified by Apple | That a genuine Apple device and a genuine instance of your app (Team ID + bundle ID) hold the key. **Not** whether iOS is jailbroken | Yes: Apple servers at attestation time | Your server |
| DeviceCheck (`DCDevice`) | Apple | Nothing about integrity. A token that lets your server read and write two bits per device | Yes | Apple's DeviceCheck API called by your server |

The OWASP text makes the central point and we repeat it because almost every finding in this area comes back to it: **the backend must validate the evidence and apply the service-specific binding, freshness and replay rules; a verdict evaluated by the app is just another local check that can be patched out.**

Keep the neighbouring topics apart:

| Question | Where it lives |
|---|---|
| Does the app itself look for root, jailbreak, emulators, hooking frameworks? | [MASWE-0051](/mobile/maswe-0051-root-jailbreak-detection-not-implemented/), [MASWE-0053](/mobile/maswe-0053-emulator-virtual-device-detection-not-implemented/), [MASWE-0065](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/) |
| Is the calling app the unmodified, store-distributed binary (`appIntegrity`, App Attest app identity)? | [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/) |
| Does the backend refuse devices on old Android patch levels? | [MASWE-0041](/mobile/maswe-0041-running-on-recent-platform-version-not-ensured/) |
| Does the backend force users onto a current app version? | [MASWE-0043](/mobile/maswe-0043-enforced-updating-not-implemented/) |
| Does the app require a device lock screen, and can the server know? | [MASWE-0017](/mobile/maswe-0017-device-secure-lock-not-enforced/) |
| Are transaction signatures tied to a hardware key whose properties the server checked? | [MASWE-0025](/mobile/maswe-0025-lack-of-non-repudiation/) |
| Are API keys shipped in the app instead of being protected by App Check or attestation? | [MASWE-0004](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/) |
| Does Play Integrity report Play Protect or screen-capturing apps? | [MASWE-0055](/mobile/maswe-0055-malware-detection-not-implemented/) |

## Modes of Introduction

**No attestation at all.** The API accepts any well-formed request with a valid session. Account creation, login, OTP requests, promotions and payments can be driven by scripts and emulators at scale.

**Client-side evaluation.** The app requests a Play Integrity token or performs App Attest, then decides locally whether to continue. Common variants: the app decrypts a classic Play Integrity token itself with response keys embedded in the APK; the app calls a backend endpoint that returns `{"ok": true}` and only the app enforces it; the app checks `isSupported` and simply skips attestation when it is `false`. All of these collapse to a single return value that can be changed with one hook.

**Token present, not verified.** The backend checks that a header such as `X-Integrity-Token` exists, or forwards it to Google but ignores the result, or logs the verdict for "monitoring mode" that was never switched to enforcement.

**No request binding.** Standard requests without `requestHash`, or with a constant value; classic requests with a nonce generated on the device, never recorded, or not tied to the request content; App Attest assertions over a `clientData` that does not include the server challenge or the request parameters. A valid token can then be lifted from one request and attached to another.

**No freshness or replay control.** `timestampMillis` is not checked, classic nonces are not single-use, App Attest challenges are reusable and the assertion counter is not stored and compared.

**Incomplete validation.** Only `deviceRecognitionVerdict` is checked while `requestPackageName`, `appRecognitionVerdict` and `certificateSha256Digest` are ignored; `UNEVALUATED` or an empty verdict is treated as a pass; key attestation chains are accepted from any root, without revocation checks, with the extension taken from the wrong certificate, or with `attestationSecurityLevel` `Software`; the App Attest `aaguid` is not checked, so development-environment keys work against production.

**Attestation at the wrong moment.** One attestation at app start or login, after which a long-lived session token carries the trust for everything else, including the payment five hours later from a different environment.

**Fail-open error handling.** When Play Integrity returns `TOO_MANY_REQUESTS`, the daily quota runs out, Google or Apple endpoints time out, or the client reports "unsupported", the backend lets the request through without any compensating control. This is often deliberate (to avoid locking out users during an outage) and never documented.

**Device binding with bearer identifiers.** The "device" is a UUID in shared preferences, `ANDROID_ID` or `identifierForVendor` sent in a header. Anyone who copies the value is the device.

## Impact

- **Automation and fraud at scale.** Fake account creation, credential stuffing, promotion and referral abuse, scraping, inventory hoarding and bot traffic in games run from emulators, device farms or scripts without the real app.
- **Account takeover follow-through.** Stolen credentials and OTPs are used from an attacker-controlled environment. Without attestation and device binding the backend cannot tell the onboarding of a new device by the real user from onboarding by the attacker.
- **Bypass of client-side protections.** Root, emulator and tamper checks in the app are bypassed on the attacker's device and the backend never learns that they failed.
- **Financial loss.** Abuse of transaction flows, bonuses, premium content and in-game economies from environments that the business would have refused if it could see them.

## Mitigations

- **Use the platform services.** On Android, Play Integrity standard requests for routine calls and, where you need control over the policy or support devices without Google Play, direct key attestation with a server-side check of `RootOfTrust` and patch levels. On iOS, App Attest for app and device legitimacy, DeviceCheck bits for per-device state across reinstalls.
- **Verify on the server, always.** Decrypt and verify Play Integrity tokens through Google's `decodeIntegrityToken` endpoint from your backend. Verify key attestation chains and App Attest objects on your backend. Never put decryption keys, verification logic or the decision in the app.
- **Bind evidence to the request and to a server challenge.** `requestHash` (standard) or a server-issued, single-use `nonce` that includes a hash of the request (classic); a server challenge in the key attestation; a server challenge plus the request in App Attest `clientData`. Check timestamps and keep replay state.
- **Gate sensitive operations on the result.** Attest at the point of the high-value action (sign-up, login from a new device, adding a payee, payment, promotion redemption), not once per app launch.
- **Respond in tiers and fail safely.** Allow, allow with limits, step-up, deny. Treat errors, empty verdicts and `UNEVALUATED` as "not attested" and route them to a compensating control, not to "allow".
- **Bind devices with non-exportable keys.** A Keystore or Secure Enclave key generated per install, registered to the account under step-up authentication, with requests signed over a server challenge.
- **Layer, measure, and plan for bypass.** Combine attestation with local checks (MASWE-0051, MASWE-0053) and server-side risk signals (velocity, `recentDeviceActivity`, App Attest risk metric). Run in monitor mode first to learn your install base, then enforce. Assume that some attackers will get valid evidence from real devices and design the policy so that this is expensive, not free.

## Knowledge

OWASP links no Knowledge pages to MASWE-0054. We assign five by topic: MASTG-KNOW-0035 (Play Integrity), MASTG-KNOW-0119 (Key Attestation, a placeholder), MASTG-KNOW-0120 (Device Attestation, a placeholder), and the two Device Binding pages, MASTG-KNOW-0034 (Android) and MASTG-KNOW-0090 (iOS). OWASP has no Knowledge page on App Attest and DeviceCheck in the RESILIENCE category, so we add a supplementary section for iOS.

### Android: Google Play Integrity API (MASTG-KNOW-0035)

Source: [MASTG-KNOW-0035](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0035/), extended and corrected from Google's [Play Integrity documentation](https://developer.android.com/google/play/integrity).

#### What the API is and what it replaced

The Play Integrity API returns a signed and encrypted verdict about three things: the **device** (is it a genuine, certified Android device in a trustworthy state), the **app** (is this the binary Google Play distributed, signed with your key) and the **account** (did the user install or buy the app on Google Play). Optional signals add environment information (Play Protect state, apps that can capture or control the screen), request velocity per device and a small amount of per-device storage that survives reinstalls.

It replaced the SafetyNet Attestation API. Google stopped onboarding new SafetyNet Attestation users in January 2023 and fully turned the API down at the end of January 2025; calls to it now fail. If you find `SafetyNetClient.attest()` in an app, the app has **no working attestation**, whatever the code suggests. (Other SafetyNet APIs, such as Verify Apps, still exist; see [MASWE-0055](/mobile/maswe-0055-malware-detection-not-implemented/).)

Play Integrity needs the Google Play Store and Google Play services on the device. Devices without them (Huawei devices without GMS, many Chinese-market devices, custom ROMs without Google apps, some enterprise devices) cannot produce a verdict. That is a design input for your policy, not a reason to fail open for everyone.

#### Standard and classic requests

There are two ways to request a token. The verdict format is the same.

| | Standard request | Classic request |
|---|---|---|
| Client API | `IntegrityManagerFactory.createStandard()` → `StandardIntegrityManager.prepareIntegrityToken(PrepareIntegrityTokenRequest)` once, then `StandardIntegrityTokenProvider.request(StandardIntegrityTokenRequest)` per action | `IntegrityManagerFactory.create()` → `IntegrityManager.requestIntegrityToken(IntegrityTokenRequest)` |
| Warm-up | Required ("prepare the token provider"), a few seconds, up to 5 per app instance per minute | None |
| Latency | A few hundred milliseconds | A few seconds |
| Intended use | Any action or server call, on demand | Occasional one-off for the highest-value actions |
| Request binding | `requestHash` (max 500 characters; put a digest of the request in it) | `nonce` (base64 URL-safe, no wrap, 16 to 500 characters) |
| Replay protection | Automatic, by Google Play | Your server must make the nonce single-use |
| Decryption | Only on Google's servers | Google's servers, or your own server with response keys from Play Console |
| Rate limits | 10,000 requests per app per day by default (raise on request); no public per-instance limit on tokens, but non-public defensive limits apply | Same daily default; 5 tokens per app instance per minute |
| Minimum Android | API 23 with library 1.4.0 or later (older libraries: API 21) | API 23 with library 1.4.0 or later (older libraries: API 19) |

Two details from the documentation matter in reviews. The standard token provider can expire: the next `request()` fails with `INTEGRITY_TOKEN_PROVIDER_INVALID` and the app must prepare a new one. And Google warns against **caching verdicts** with classic requests, because a cached good verdict can be exfiltrated and replayed from another environment; the guidance is to make a standard request on demand instead.

#### Binding a token to a request: requestHash and nonce

A token without request binding proves only that *some* request from a good device happened recently. Google's wording for standard requests is that without `requestHash` "the integrity token will be bound only to the device, but not to the specific request, which opens up the possibility of attack."

- **Standard:** the app computes a digest (for example SHA-256 over a stable serialisation) of the parameters that matter for the action, such as user ID, payee, amount and a client request ID, and passes it with `setRequestHash()`. The server recomputes the digest from the request it actually received and compares it with `requestDetails.requestHash`. Replay is handled by Google: decoding the same token repeatedly returns cleared verdicts (empty device verdict, `UNEVALUATED` app and licence verdicts, cleared optional signals).
- **Classic:** the server issues a unique, unpredictable value (128 bits or more), the app builds the message including that value, hashes it and passes the digest with `setNonce()`. The server recomputes the digest, checks it against `requestDetails.nonce`, and checks that the unique value is one it issued and that it is used for the first time.

Both values are visible in clear to the app and to Google, so never put personal data in them; hash it.

#### Decrypting and verifying the token

The token the app receives is opaque to it. For classic requests Google documents the format: a JWE (key wrap `A256KW`, content encryption `A256GCM`) containing a JWS signed with `ES256`, both in compact serialisation, so you see five base64url segments separated by dots. Standard tokens can only be decoded by Google.

The supported server flow for both request types:

1. Create a service account in the Google Cloud project linked to the app.
2. From your server, obtain an OAuth access token for that service account with the `playintegrity` scope.
3. Call `https://playintegrity.googleapis.com/v1/<PACKAGE_NAME>:decodeIntegrityToken` with `{"integrity_token": "<token>"}`.
4. Read the JSON payload and apply your checks.

For classic requests you may instead let Play Console give you the response encryption key (AES) and verification key (EC public key) and decrypt and verify locally on the server. Google recommends letting Google manage the keys. Either way, **decryption on the client is not supported**, and finding those keys inside an APK means that anyone can decrypt, read and, worse, the logic that trusts the result is in the attacker's hands.

#### The verdict payload

An illustrative payload with all optional signals enabled (values are examples, not from a real app):

```json
{
  "requestDetails": {
    "requestPackageName": "com.example.bank",
    "requestHash": "q8m0Hk4p2n3L5dX1v9b7c6Z0aQwErTyUiOpAsDfGhJk",
    "timestampMillis": "1762790400000"
  },
  "appIntegrity": {
    "appRecognitionVerdict": "PLAY_RECOGNIZED",
    "packageName": "com.example.bank",
    "certificateSha256Digest": ["6a6a1474b5cbbb2b1aa57e0bc3"],
    "versionCode": "4210"
  },
  "deviceIntegrity": {
    "deviceRecognitionVerdict": ["MEETS_BASIC_INTEGRITY", "MEETS_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY"],
    "deviceAttributes": { "sdkVersion": 35 },
    "recentDeviceActivity": { "deviceActivityLevel": "LEVEL_1" }
  },
  "accountDetails": { "appLicensingVerdict": "LICENSED" },
  "environmentDetails": {
    "appAccessRiskVerdict": { "appsDetected": ["KNOWN_INSTALLED"] },
    "playProtectVerdict": "NO_ISSUES"
  }
}
```

What each field means and what your server must do with it:

| Field | Values | Server check |
|---|---|---|
| `requestDetails.requestPackageName` | Package name the token was requested for. Google notes it "might be spoofed in the middle of the request" | Must equal your package name |
| `requestDetails.requestHash` / `nonce` | Exactly what the app passed | Must equal the value you recompute from the received request (and, for classic, a server-issued, unused value) |
| `requestDetails.timestampMillis` | When the token was requested (classic: computed on the server) | Must be within your allowed window, typically seconds to a few minutes |
| `appIntegrity.appRecognitionVerdict` | `PLAY_RECOGNIZED`, `UNRECOGNIZED_VERSION`, `UNEVALUATED` | Expect `PLAY_RECOGNIZED`; optionally check `packageName`, `certificateSha256Digest` and `versionCode` yourself. This is the app-attestation half, see [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/) |
| `deviceIntegrity.deviceRecognitionVerdict` | Zero or more labels (next section). Omitted entirely when the device meets none | Choose the label each action requires; treat a missing field as "no labels" |
| `accountDetails.appLicensingVerdict` | `LICENSED`, `UNLICENSED`, `UNEVALUATED` | Since the 2025 changes, `LICENSED` requires that Google Play installed or updated the app |
| `testingDetails.isTestingResponse` | Present only for test responses configured in Play Console | Log it; never treat it as a real verdict outside the test accounts you configured |

#### Device recognition labels and the May 2025 changes

Google strengthened the verdicts for devices running Android 13 and later (announced December 2024, live for all developers in May 2025). On those devices every device label now depends on hardware-backed key attestation. The labels, as currently documented:

| Label | Returned by default? | Android 13 and later | Android 12 and earlier |
|---|---|---|---|
| `MEETS_DEVICE_INTEGRITY` | Yes | Genuine, certified device with hardware-backed proof that the bootloader is locked and the loaded OS is a certified manufacturer image | Genuine, certified device; hardware-backed attestation where available, software fallback otherwise |
| `MEETS_STRONG_INTEGRITY` | Opt-in | `MEETS_DEVICE_INTEGRITY` plus security updates in the last year for all partitions, including an Android OS patch and a vendor patch | Hardware-backed proof of boot integrity only; **no** patch-age requirement |
| `MEETS_BASIC_INTEGRITY` | Opt-in | Key attestation with a Google root is present; bootloader may be locked or unlocked and boot state verified or unverified. Rooted devices can get this label | Passes basic integrity checks; may not be certified |
| `MEETS_VIRTUAL_INTEGRITY` | Only for apps on Google Play Games for PC | Not affected by the change | Emulator with Google Play services that passes integrity checks |
| *(no labels)* | — | Signs of attack (such as API hooking), system compromise (such as root), or not a physical device | Same |

Further consequences of the 2025 change:

- On Android 13 and later, the optional labels and optional signals (`MEETS_BASIC_INTEGRITY`, `MEETS_STRONG_INTEGRITY`, recent device activity, device recall, app access risk, Play Protect verdict) are only returned when the requesting app was installed or updated by Google Play. `deviceAttributes` is the exception.
- Because `MEETS_STRONG_INTEGRITY` means different things below and above Android 13, Google recommends enabling `deviceAttributes` and deciding per SDK version. Google's own example of keeping the old meaning: require `MEETS_STRONG_INTEGRITY` when `sdkVersion < 33` and `MEETS_DEVICE_INTEGRITY` when `sdkVersion >= 33`.
- A device returns every label whose criteria it meets, so a strong device returns all three. Check for the label you need with an exact element match. A string `contains("INTEGRITY")` check, which we have seen, accepts `MEETS_BASIC_INTEGRITY` as if it were device integrity.
- Google says it now changes device verdicts in more situations, "such as when there is evidence of excessive activity or key compromise", and may fall back to other signals to produce temporary verdicts when hardware-backed signals are unavailable.

The overview recommends a tiered trust model: `MEETS_STRONG_INTEGRITY` on Android 13+ at the top, then `MEETS_DEVICE_INTEGRITY` on 13+ together with `MEETS_STRONG_INTEGRITY` below 13, then `MEETS_DEVICE_INTEGRITY` below 13, then `MEETS_BASIC_INTEGRITY`, then nothing.

#### Optional signals

You switch these on in Play Console (Protected with Play → Play Integrity API settings). They are absent from the payload otherwise.

- **`deviceAttributes.sdkVersion`**: the Android SDK level, from a hardware-backed signal on Android 13+. Empty when not evaluated.
- **`recentDeviceActivity.deviceActivityLevel`**: how many tokens *your app* requested on this device in the last hour. `LEVEL_1` (standard: 10 or fewer; classic: 5 or fewer), `LEVEL_2` (11–25; 6–10), `LEVEL_3` (26–50; 11–15), `LEVEL_4` (more than 50; more than 15) or `UNEVALUATED`. A device minting tokens at a high rate is often a real phone serving tokens to bots elsewhere.
- **`deviceRecall`** (beta): three bits you set server-to-server for a device, returned with their write month (`values.bitFirst`… and `writeDates.yyyymmFirst`…), surviving reinstall and factory reset. Use it to recognise a device you already flagged for abuse or that already redeemed a trial.
- **`environmentDetails.appAccessRiskVerdict`** and **`environmentDetails.playProtectVerdict`**: other apps that can capture, overlay or control the screen, and Play Protect's state. Both are malware signals and are explained in [MASWE-0055](/mobile/maswe-0055-malware-detection-not-implemented/).

#### Errors, quotas and outages

The client library returns error codes instead of a token in many situations: `API_NOT_AVAILABLE`, `PLAY_STORE_NOT_FOUND`, `NETWORK_ERROR`, `APP_NOT_INSTALLED`, `PLAY_SERVICES_NOT_FOUND`, `APP_UID_MISMATCH`, `TOO_MANY_REQUESTS`, `GOOGLE_SERVER_UNAVAILABLE`, `PLAY_STORE_VERSION_OUTDATED`, `PLAY_SERVICES_VERSION_OUTDATED`, `CLOUD_PROJECT_NUMBER_IS_INVALID`, `REQUEST_HASH_TOO_LONG` (standard), the `NONCE_*` errors (classic), `CLIENT_TRANSIENT_ERROR`, `INTEGRITY_TOKEN_PROVIDER_INVALID` (standard) and `INTERNAL_ERROR`. Google classifies `APP_NOT_INSTALLED` and `APP_UID_MISMATCH` as non-actionable and says to treat them "as if the client has failed all integrity checks", and its retry guidance ends the same way: after three retries with exponential backoff, treat the outcome as failed.

That is the design rule a tester checks: **an error is not a pass.** The app may legitimately show a remediation dialog (`GET_INTEGRITY`, `GET_STRONG_INTEGRITY`, `GET_LICENSED`, `CLOSE_UNKNOWN_ACCESS_RISK`, `CLOSE_ALL_ACCESS_RISK`) or fall back to a step-up, but a request that arrives with "error" instead of a token must not be treated like one with a good verdict.

The default quota of 10,000 requests per app per day is small for a popular app. If the backend fails open when the quota is exhausted, an attacker can deliberately burn the quota. Google recommends quota monitoring and alerts in Play Console or Google Cloud Console, and planning in advance how the backend behaves during a Play Integrity outage (the Play status dashboard reports them) and when platform key attestation keys are revoked.

#### How attackers approach Play Integrity

In general terms, and without the specifics (this series does not document attestation bypasses):

- **Hooking the app** to fake a "pass" works only against apps that evaluate the verdict locally. Against a correct server-side integration it gains nothing, because the token is produced by Google Play components and checked by Google's servers.
- **Relaying tokens from genuine devices.** Fraud operations run real, certified phones that generate tokens on demand for bots elsewhere. Request binding (`requestHash` with the real request content), short timestamp windows, `recentDeviceActivity` and server-side velocity limits make this expensive.
- **Spoofing hardware attestation with leaked device keys.** There is an ecosystem of root modules that present attestation from a leaked or extracted factory key so that a rooted device appears locked. Google revokes leaked keys through the attestation revocation list, Remote Key Provisioning removes factory keys from new devices, and `MEETS_STRONG_INTEGRITY` adds the patch-age requirement. This is why your policy should prefer `MEETS_STRONG_INTEGRITY` for the highest-risk actions, and why a direct key attestation verifier must check revocation.
- **Simply not using the app.** Scripts call the API directly. Without any attestation requirement the backend cannot tell.

#### Corrections to the OWASP page

The OWASP Knowledge page is older than the current API and has several errors. We corrected them in the text above:

- It says the API works "starting with Android 4.4 (level 19)". That applied to classic requests with library 1.3.0 and earlier; with library 1.4.0 and later both request types require Android 6.0 (API 23).
- It describes the API in terms of classic requests only and recommends a nonce "generated by the app or server". Google's guidance prefers standard requests with `requestHash`, and for classic requests a server-generated unique value; a device-generated value is described as "simpler and less secure".
- Its description of `MEETS_BASIC_INTEGRITY` ("may not be approved to run Google Play Services") and `MEETS_VIRTUAL_INTEGRITY` predates the 2025 changes, and it does not mention that `MEETS_VIRTUAL_INTEGRITY` is only for Google Play Games for PC.
- It says to "minimize queries to the Play Protect API"; it means the Play Integrity API.
- The example payload has `UNRECOGNIZED_VERSION` together with `MEETS_DEVICE_INTEGRITY` and `UNEVALUATED` licensing, which is a valid combination (a sideloaded build on a good device) but is presented without explanation.

### Android: Key Attestation (MASTG-KNOW-0119)

Source: [MASTG-KNOW-0119](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0119/) is a **placeholder** on the OWASP site that points to Google's [key attestation guide](https://developer.android.com/privacy-and-security/security-key-attestation). This section is written from that guide and from the AOSP [key and ID attestation](https://source.android.com/docs/security/features/keystore/attestation) documentation.

Key attestation lets your server verify that a key pair was generated in the device's secure hardware, and it carries a signed snapshot of the device's boot state at the time the key was created. It is the raw signal that Play Integrity uses on Android 13+, available to you directly, without Google Play services on the device and with your own policy. Google Play devices that launched with Android 7.0 or later should use attestation keys signed by the Google root; attestation became mandatory with Android 8.0.

#### Requesting an attestation

The app generates a key in Android Keystore with an attestation challenge from your server, then sends the certificate chain to your server:

```kotlin
// challenge: fresh, random, single-use bytes from your server
val spec = KeyGenParameterSpec.Builder("device-binding", KeyProperties.PURPOSE_SIGN)
    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
    .setDigests(KeyProperties.DIGEST_SHA256)
    .setAttestationChallenge(challenge)
    .build()
KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").run {
    initialize(spec)
    generateKeyPair()
}
val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
val chain = ks.getCertificateChain("device-binding").map { it.encoded }  // DER, leaf first
// send chain (base64) to the server together with the challenge ID
```

Add `setIsStrongBoxBacked(true)` to request StrongBox (handle `StrongBoxUnavailableException`), and `setDevicePropertiesAttestationIncluded(true)` (API 31+) to ask for device identifiers such as brand, model and product in the attestation. Serial and IMEI attestation require privileged permissions that normal apps do not have.

#### Verifying the certificate chain

Google's steps, rewritten as a server checklist:

1. **Do it on the server.** Google's guide explicitly warns against validating on the same device, because a compromised OS could make the validation trust anything.
2. **Verify the chain**: each certificate signs the next, and the root is one of Google's attestation roots (next section).
3. **Check revocation** of every certificate in the chain against Google's status list.
4. **Find the right extension.** If a provisioning-information extension (OID `1.3.6.1.4.1.11129.2.1.30`, CBOR) is present, the key attestation extension must be in the certificate immediately after it. Use the **first** certificate from the root side that carries the attestation extension (OID `1.3.6.1.4.1.11129.2.1.17`). Google warns: "Only the first occurrence of the extension in the chain can be trusted"; later copies could have been added by an attacker who extends the chain with their own certificate.
5. **Check the content** against your expectations: challenge, security level, root of trust, patch levels, app identity.

Google now publishes a [Kotlin verification library](https://github.com/android/keyattestation) and recommends moving custom verifiers to it, because it "covers edge cases that are often missed by custom verifiers", such as expiry handling.

#### Root certificates and the 2026 root

The trust anchors are listed on the key attestation page and as a JSON array at `https://android.googleapis.com/attestation/root`. As of this writing:

- The long-standing **RSA root** (subject `SERIALNUMBER=f92009e853b6b045`; Google has reissued it several times with the same key).
- A new **ECDSA P-384 root** (subject `CN=Key Attestation CA1, OU=Android, O=Google LLC, C=US`) that, per Google, "will begin signing attestation certificate chains on February 1, 2026". A verifier built before 2026 that pins only the RSA root rejects new chains. Check this in every review.

Two expiry rules that trip up custom verifiers: factory-provisioned keys on devices launched before 2021 have **expired** certificates, and Google says to keep trusting chains to the `f92009e853b6b045` root "regardless of certificate validity period" unless revoked; but certificates issued through **Remote Key Provisioning** (RKP) must have their validity checked, because short lifetimes are part of RKP's design. RKP was optional with Android 15 and is the only supported provisioning method for devices launching with Android 16, which removes factory keys from the picture for new devices.

A chain with any other root is not evidence of secure hardware. Devices that launched before Android 7.0 use **software attestation** signed with a key that is published in the AOSP source code, so anyone can produce such a chain. The guide also notes that a non-Google-Play device maker could use its own root, though Google is not aware of any doing so.

#### Revocation status list

Google publishes revoked and suspended attestation certificates at `https://android.googleapis.com/attestation/status`. The JSON has an `entries` object keyed by certificate serial number in lowercase hex; each entry has a `status` (`REVOKED` or `SUSPENDED`) and optionally `expires`, `reason` (`UNSPECIFIED`, `KEY_COMPROMISE`, `CA_COMPROMISE`, `SUPERSEDED`, `SOFTWARE_FLAW`) and `comment`. Honour the `Cache-Control` header rather than fetching it per request. Leaked factory keys are revoked "typically within several days of discovery", sometimes later when large numbers of devices are affected. A verifier that does not check this list accepts attestations made with keys that are known to be public.

#### The KeyDescription extension

The attestation extension is an ASN.1 `KeyDescription` sequence:

| Field | Meaning | What to check |
|---|---|---|
| `attestationVersion` | Schema version: 1 to 4 for Keymaster 2.0 to 4.1, then 100, 200, 300, 400, 500 for KeyMint 1.0 to 5.0 | Parse according to the version; know which fields exist |
| `attestationSecurityLevel` | `Software` (0), `TrustedEnvironment` (1), `StrongBox` (2) | Reject `Software` for any trust decision |
| `keyMintVersion` / `keyMintSecurityLevel` | Called `keymasterVersion` / `keymasterSecurityLevel` up to version 4 | Informational; security level should match |
| `attestationChallenge` | The bytes the app passed to `setAttestationChallenge()` | Must equal the server-issued, unused challenge |
| `uniqueId` | Only for privileged system apps | Ignore |
| `softwareEnforced` / `hardwareEnforced` | `AuthorizationList`s of key properties and device state | Read device state from `hardwareEnforced` |

Fields of interest in the authorisation lists (tag numbers from the AOSP schema):

| Tag | Field | Notes |
|---|---|---|
| 704 | `rootOfTrust` | `verifiedBootKey` (hash of the key that signed the OS), `deviceLocked` (bootloader locked), `verifiedBootState`, `verifiedBootHash` |
| 705, 706 | `osVersion`, `osPatchLevel` | OS version and patch level as `YYYYMM` |
| 718, 719 | `vendorPatchLevel`, `bootPatchLevel` | `YYYYMMDD`; Play Integrity's strong label requires recent OS **and** vendor patches |
| 709 | `attestationApplicationId` | Package name(s), version and signing certificate digests of the app that created the key, filled in by the OS. Usually in `softwareEnforced`, because the OS rather than the TEE determines it |
| 710–717, 723 | `attestationIdBrand`, `…Device`, `…Product`, `…Serial`, `…Imei`, `…Meid`, `…Manufacturer`, `…Model`, `…SecondImei` | Only with ID attestation |
| 724 | `moduleHash` | KeyMint 4.0 and later |

`verifiedBootState` values: `Verified` (0, green: full chain of trust from hardware to the OS), `SelfSigned` (1, yellow: verified with a user-installed root of trust, as with an alternative OS on a relocked Pixel), `Unverified` (2, orange: bootloader unlocked, `verifiedBootKey` is 32 zero bytes), `Failed` (3, red: the other fields cannot be trusted).

#### Building a policy from the fields

A typical policy for a high-risk action: root is a Google attestation root; no certificate revoked; `attestationSecurityLevel` is `TrustedEnvironment` or `StrongBox`; `attestationChallenge` matches; `deviceLocked` is true; `verifiedBootState` is `Verified`, or `SelfSigned` with a `verifiedBootKey` on an allowlist; `osPatchLevel` and `vendorPatchLevel` within your threshold; `attestationApplicationId` contains your package and your signing certificate digest.

The `SelfSigned` branch is how a direct key attestation policy can support hardened alternative operating systems that Play Integrity does not certify. GrapheneOS, for example, publishes its verified boot key fingerprints and an [attestation compatibility guide](https://grapheneos.org/articles/attestation-compatibility-guide) for apps; MASWE-0054 references it. Whether you accept such devices is a business decision, but you can only make it with direct key attestation.

#### Looking at an attestation as a tester

Capture the chain from the app's own traffic at enrolment (base64 DER certificates, leaf first), then:

```bash
# one certificate per file, leaf first
for i in 0 1 2 3; do jq -r ".chain[$i]" enrol.json | base64 -d > cert$i.der; done
openssl x509 -inform DER -in cert0.der -noout -subject -issuer -dates
openssl x509 -inform DER -in cert0.der -noout -text | grep -A1 '1.3.6.1.4.1.11129.2.1.17'
# root: compare its public key with Google's published roots
openssl x509 -inform DER -in cert3.der -noout -pubkey | openssl pkey -pubin -outform DER | sha256sum
# dump the extension structure (the offset comes from the first asn1parse listing)
openssl asn1parse -inform DER -in cert0.der | grep -n '1.3.6.1.4.1.11129.2.1.17'
```

The JSON field name `chain` is whatever the app uses. For a readable dump of the `KeyDescription`, run the chain through Google's Kotlin library or the [Key Attestation sample](https://github.com/googlesamples/android-key-attestation) in a small JVM test harness. Do this to understand what the backend receives; the backend tests themselves are in GT-RES-0054-2.

### Android: Device Attestation (MASTG-KNOW-0120)

Source: [MASTG-KNOW-0120](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0120/) is a **placeholder** that points to the [device integrity field](https://developer.android.com/google/play/integrity/verdicts#device-integrity-field) of Play Integrity. We use it for the design question that sits above the two APIs: which device attestation should a given app use, and how do they fit together?

| Question | Play Integrity | Direct key attestation |
|---|---|---|
| Who defines "good device"? | Google, as labels | You, from raw fields |
| Works without Google Play? | No | Yes, on any device with hardware attestation and a Google root (or another root you decide to trust) |
| Revocation, RKP, leaked keys | Handled by Google | Your verifier must check the status list and expiry rules |
| App identity | `appIntegrity` (Play-recognised binary and certificate) | `attestationApplicationId` (package and signing certificate as seen by the OS) |
| Licence, Play Protect, screen-access risk, velocity, device recall | Yes (some optional) | No |
| Cost | Google quota (10,000/day default), API call to Google per token | Your own server work; no per-request quota |
| Typical use | Per-request checks on routine and high-value actions | Device enrolment, binding a signing key to an account, supporting non-GMS or alternative-OS devices |

They combine well: key attestation once at device enrolment (proving the binding key is hardware-backed and recording the boot state), Play Integrity standard requests on later sensitive calls, and assertions signed with the enrolled key on each high-value request.

**Wrappers.** Firebase App Check uses Play Integrity on Android and App Attest or DeviceCheck on iOS, and gives your backend a short-lived App Check token to verify. It is a convenient way to require attestation for Firebase services and your own APIs, but the App Check token is the evidence your backend sees; you do not get the full Play Integrity payload or binding to the request content through it (App Check offers limited-use tokens for replay protection on selected endpoints), and App Check enforcement must be switched on for each service. reCAPTCHA Enterprise for mobile includes Play Integrity signals in a risk score. Both are legitimate choices; test them by the same rules (server-side enforcement, fail-safe behaviour, binding to the action where the product supports it).

### Android: Device Binding (MASTG-KNOW-0034)

Source: [MASTG-KNOW-0034](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0034/).

The goal of device binding is that the trust earned by one installation on one device (a completed onboarding, a registered second factor, a remembered device) does not move with the app's data to another device. If an attacker copies the app's files, tokens and preferences from device A to device B, device B must not inherit device A's privileges.

OWASP lists three approaches:

1. **Add device identifiers to the credentials.** For example, the server stores a device identifier with the refresh token and refuses the token from a different identifier. Weak if the identifier is something the client simply reports.
2. **Encrypt local data with keys that cannot leave the device.** Android Keystore keys are non-exportable; data encrypted with them is useless on another device. OWASP's sample generates an RSA key for unwrapping and an AES-GCM key, uses a device identifier as associated data, and wraps the AES key with the RSA public key.
3. **Token-based device authentication** with an instance identifier.

What to know about each in practice:

- **Identifiers.** `Settings.Secure.ANDROID_ID` has been scoped per app signing key, per user and per device since Android 8.0, and changes on factory reset. Hardware identifiers (IMEI, serial) are not available to normal apps since Android 10. A random UUID in `SharedPreferences` identifies an installation and travels with a data copy. None of these proves anything when it is just sent in a header: anyone who reads it can send it.
- **OWASP's sample code has a bug.** In the AES-GCM step it calls `cipher.updateAAD(aad)` and then `cipher.init(Cipher.ENCRYPT_MODE, key)` a second time. Re-initialising resets the cipher, discards the AAD and (with the Keystore) generates a fresh IV, so the associated data is never bound. Initialise once, then call `updateAAD()`, then encrypt. With Android Keystore AES-GCM keys you also normally let the Keystore generate the IV (`cipher.init(ENCRYPT_MODE, key)` and read `cipher.iv`), because caller-provided IVs are rejected unless `setRandomizedEncryptionRequired(false)` is set.
- **"Instance ID" is gone.** The Google/Firebase Instance ID SDKs that OWASP refers to were deprecated and replaced by Firebase Installations. An installation ID is still a bearer identifier.

The pattern that actually binds a device is cryptographic: **a per-install signing key in Android Keystore** (StrongBox where available), generated with an attestation challenge so the server can verify that it is hardware-backed (previous section), registered to the account only after strong authentication or step-up, and used to sign a server challenge (and the request content) on each sensitive request. Copying the app's data copies the key alias, not the key. A server that records the attestation at enrolment also knows the boot state and patch level of the device it bound. [MASWE-0025](/mobile/maswe-0025-lack-of-non-repudiation/) covers signing keys for transactions in depth; [MASWE-0016](/mobile/maswe-0016-key-access-not-restricted/) covers user-authentication requirements on such keys.

Two things that undermine binding in reviews: binding state that is backed up to the cloud and restored onto a new device (check `android:allowBackup`, `android:fullBackupContent` and `android:dataExtractionRules`; Keystore keys are never backed up, but wrapped key blobs and tokens are), and a server that accepts the session token alone after enrolment, so the signature is only checked once.

### iOS: Device Binding (MASTG-KNOW-0090)

Source: [MASTG-KNOW-0090](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0090/).

Same goal on iOS. Apple removed access to hardware identifiers years ago, so OWASP suggests:

- **`identifierForVendor`** (`UIDevice.current.identifierForVendor`): a UUID that is the same for all apps from the same vendor on a device, reset when the user deletes all of the vendor's apps. It can change in other situations, so OWASP suggests combining it with something stored in the Keychain.
- **Something stored in the Keychain** with a `…ThisDeviceOnly` protection class (`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`). `ThisDeviceOnly` items are not included in backups that can be restored to another device and do not migrate to a new device.
- **Access control flags** (`kSecAccessControlDevicePasscode`, `kSecAccessControlUserPresence`, `kSecAccessControlBiometryAny`, `kSecAccessControlBiometryCurrentSet`) so that using the stored secret requires the user.

Corrections and additions: the OWASP page still shows Swift 2 syntax and recommends Google Instance ID, which is deprecated (see the Android section). Keychain items are not reliably deleted when the app is uninstalled; that persistence is not documented behaviour, so do not build security on it either way.

As on Android, the strong pattern is a **non-exportable key**: either a Secure Enclave key created with `kSecAttrTokenIDSecureEnclave` in a `…ThisDeviceOnly` access control, registered with the server under step-up and used to sign server challenges, or the **App Attest key**, which is also a Secure Enclave key, does not survive reinstall, device migration or backup restore, and comes with Apple's attestation that it belongs to your app on genuine hardware. The difference: a plain Secure Enclave key gives the server no third-party proof of where it lives (Apple has no general attestation of arbitrary Secure Enclave keys, see [MASWE-0016](/mobile/maswe-0016-key-access-not-restricted/)); an App Attest key does.

### iOS: DeviceCheck and App Attest (supplementary)

OWASP has no Knowledge page on these services in the RESILIENCE category, but MASWE-0054 names them as the iOS mechanisms. This section is based on Apple's DeviceCheck documentation: [Establishing your app's integrity](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity), [Validating apps that connect to your server](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server), [Assessing fraud risk](https://developer.apple.com/documentation/devicecheck/assessing-fraud-risk) and [Accessing and modifying per-device data](https://developer.apple.com/documentation/devicecheck/accessing-and-modifying-per-device-data).

#### DeviceCheck: two bits per device

`DCDevice.current.generateToken` (iOS 11+, check `isSupported`) returns an ephemeral token. Your server sends it to Apple with a JWT signed by a DeviceCheck key from your developer account (ES256) and can:

- `POST /v1/query_two_bits`: read `bit0`, `bit1` and `last_update_time` (`YYYY-MM`);
- `POST /v1/update_two_bits`: set the bits;
- `POST /v1/validate_device_token`: check that the token came from a genuine Apple device.

Each request carries `device_token`, a unique `transaction_id` and a `timestamp`. Production base URL `https://api.devicecheck.apple.com`, development `https://api.development.devicecheck.apple.com`. The bits are per device and per developer team, and they persist when the app is deleted, so they suit "this device already took the free trial" or "this device was involved in fraud". DeviceCheck says **nothing** about the integrity of the device or the app, and the token itself is not bound to a request.

#### App Attest: keys, attestation and assertions

App Attest (`DCAppAttestService.shared`, iOS 14+) has three client calls:

1. `generateKey(completionHandler:)` creates a P-256 key pair in the Secure Enclave and returns a key identifier. Apple recommends one key per user account per device. Keys survive app updates but not reinstallation, device migration or restore from backup.
2. `attestKey(_:clientDataHash:completionHandler:)` asks Apple to certify the key. `clientDataHash` is the SHA-256 of a one-time server challenge (at least 16 bytes). It returns an **attestation object** that the app sends to the server with the key ID. If the call fails with `serverUnavailable`, retry later with the same key; for other errors discard the key and start again.
3. `generateAssertion(_:clientDataHash:completionHandler:)` signs a hash of request data (which should include a fresh server challenge) and returns an **assertion object** that accompanies sensitive requests.

`isSupported` is false on devices that cannot use the service (and in the Simulator). Among app extensions only action, extensible SSO and watchOS extensions are supported. Apple's guidance is to "gracefully bypass the service" on unsupported devices, which means your server must have a policy for clients that *claim* to be unsupported.

#### Server-side verification of the attestation object

The attestation object is CBOR (`fmt: "apple-appattest"`, `attStmt` with `x5c` and `receipt`, and `authData`, following the WebAuthn authenticator data layout). Apple's steps, condensed:

1. Verify the `x5c` chain: credential certificate first, then the intermediate, up to Apple's App Attestation root CA.
2. `clientDataHash = SHA256(challenge)`; `nonce = SHA256(authData || clientDataHash)`.
3. Extract the octet string from the credential certificate extension `1.2.840.113635.100.8.2` and check that it equals `nonce`.
4. Check that SHA-256 of the credential certificate's public key (X9.62 uncompressed point) equals the key identifier the app sent.
5. Check that the `RP ID` hash in `authData` equals SHA-256 of your App ID (`<TeamID>.<bundle ID>`; for App Clips, the full app's App ID).
6. Check that `counter` is `0`.
7. Check `aaguid`: production keys carry `appattest` followed by seven `0x00` bytes; development keys carry `appattestdevelop`.
8. Check that `credentialId` equals the key identifier.

Apple's current version of the page adds two checks on values in the authenticator data `extensions` CBOR dictionary, `apple_validation_category_01` (how the executable was distributed: App Store, TestFlight, development signing, enterprise/ad hoc, Developer ID and others) and `apple_bundle_version_01` (the app version). These appear to be recent additions that come with App Attest support on macOS; older open-source verifiers do not check them, so treat them as a recommended extra and confirm against Apple's page at the time of your test.

Store the verified public key with the user and device, make sure the key is not already associated with another user, store the receipt, and keep development and production keys apart.

#### Server-side verification of assertions

For each assertion (CBOR with `signature` and `authenticatorData`):

1. `clientDataHash = SHA256(clientData)` where `clientData` is the request as received (including the challenge);
2. `nonce = SHA256(authenticatorData || clientDataHash)`;
3. verify `signature` over `nonce` with the stored public key;
4. check the `RP ID` hash against your App ID;
5. check that `counter` is greater than the stored counter (greater than 0 on first use), then store it;
6. check that the challenge embedded in `clientData` is the one you issued (and mark it used).

The counter check is what defeats replay of a captured assertion; the challenge check is what defeats pre-generation; hashing the actual request content is what stops an assertion from being moved to a different request.

#### Receipts and the fraud risk metric

The attestation statement includes a **receipt** (PKCS #7, similar to an App Store receipt). Your server can POST it, base64-encoded, with an APNs-style provider JWT, to `https://data.appattest.apple.com/v1/attestationData` (development: `https://data-development.appattest.apple.com`) and receives a new receipt of type `RECEIPT` that contains a **risk metric** (field 17): roughly the number of keys attested for your app on that device over the past 30 days. A high count suggests one device minting attestations for many instances of a compromised app. Validate every receipt (signature up to Apple's root, App ID in field 2, creation time in field 12 no more than five minutes old, public key in field 3 matching the stored key), refresh after the "not before" date (field 19) and before expiry (field 21). Reinstalls, restores and device transfers legitimately raise the count, so tune thresholds on your own data.

#### Development and production environments

The entitlement `com.apple.developer.devicecheck.appattest-environment` (`development` or `production`) selects the environment during development; adding the App Attest capability in Xcode sets `development`, and omitting the entitlement also uses the sandbox. **After distribution through TestFlight, the App Store or the Enterprise program, the app ignores the entitlement and always uses production.** Keys and receipts from one environment do not work in the other. The server-side consequence: a production backend must accept only the production `aaguid`. A production backend that also accepts development keys opens a side door: development-signed builds are not distributed through the App Store, can run with a debugger attached, and their keys are counted in the sandbox, away from the device's production risk metric.

Apple's documentation is inconsistent on the development `aaguid`: the validation article says `appattestdevelop`, while "Preparing to use the App Attest service" says `appattestsandbox`. Verifiers in the field check `appattestdevelop`. For a production backend it does not matter: allow only `appattest` + seven zero bytes.

Apple also asks large apps to ramp up gradually (as a rule of thumb no more than 10 million users per day per app, and fewer than about 100 `attestKey` calls per second across all installations), because Apple may throttle attestation. Throttling is another error path where fail-open behaviour hides.

#### What App Attest does not tell you

Apple is explicit that App Attest establishes that the evidence comes from genuine Apple hardware and a legitimate instance of your app, and that "an attacker that modifies the device's operating system might bypass restrictions". Neither DeviceCheck nor App Attest attests that iOS is unmodified. A jailbroken device can still be a genuine Apple device running your genuine app, and its assertions can be used to serve requests for others; the risk metric, per-device velocity and server-side behaviour analysis are the only App Attest-side counters to that. Local jailbreak detection ([MASWE-0051](/mobile/maswe-0051-root-jailbreak-detection-not-implemented/)) remains the main iOS signal for the OS state, with all its limits.

## Tests

OWASP has no tests for MASWE-0054, and no legacy v1 RESILIENCE test covers it, so all tests below are ours. They verify **the app's own integration on your own test accounts**: whether evidence is requested, whether the backend verifies and enforces it, and what the policy does with each result. None of them involves defeating Google's or Apple's attestation; where a test needs a "bad" verdict, it uses a device state you legitimately control (an emulator, an unlocked test device) or Play Console's test responses.

### Before you start: scope, accounts and builds

- **Written authorisation for backend testing.** These are API tests against the production or staging backend. Agree the environment, the endpoints, rate limits and the test accounts.
- **At least two test accounts** (A and B) and, if possible, two devices, to test cross-account and cross-device behaviour.
- **A proxy set-up** with TLS interception and, if the app pins certificates, a way to observe its traffic on a test device; see our [traffic interception lab](/mobile/mobile-traffic-interception-lab/) and [pinning note](/mobile/maswe-0028-insecure-identity-pinning/).
- **Builds**: the Play/App Store build installed from the store on a certified device (baseline), plus any QA, staging or development builds the client can provide. A non-store build is the honest way to produce `UNRECOGNIZED_VERSION`/`UNLICENSED` verdicts and development-environment App Attest keys; you do not need to modify the client's app.
- **Device matrix** (Android): a certified retail device with a locked bootloader and current patches; an emulator image with Google Play; optionally an OEM-unlockable test device that you can unlock and relock; an old device on Android 12 or lower. (iOS): a supported device; the Simulator for the "unsupported" path.
- **Access to the Play Console** (read access to Play Integrity settings and testing) or a contact who has it.
- To see the device verdict that Play Integrity gives a test device, unlock the Play Store's developer options (Play Store → profile → Settings → About → tap **Play Store version** seven times), then Settings → General → Developer options → **Check integrity**. The result contains all default and optional labels, independent of what the app has enabled.

### GT-RES-0054-1: Attestation is requested for sensitive operations (Android, iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Establish whether the app uses device attestation at all, which mechanism, and on which operations. Combine static evidence (libraries and calls) with traffic evidence (which requests carry attestation material). The output is a map of sensitive endpoints to evidence, which drives the next three tests.

#### Prerequisites

The APK/AAB splits or decrypted IPA, jadx or apktool, `strings`/`otool`/`nm` for iOS, a proxy, Frida on a test device, and a list of the app's sensitive operations (registration, login, new-device enrolment, password and PIN reset, OTP requests, adding a payee or card, payments, limit changes, promotions, rewards, in-game purchases).

#### Steps

1. **Android, static.** Decompile and search for the attestation APIs and libraries:

   ```bash
   jadx -d out app.apk
   grep -rnE 'play\.core\.integrity|IntegrityManagerFactory|StandardIntegrity|requestIntegrityToken|setRequestHash|setNonce\(' out/sources | head
   grep -rnE 'setAttestationChallenge|getCertificateChain|setIsStrongBoxBacked|setDevicePropertiesAttestationIncluded' out/sources | head
   grep -rnE 'safetynet|SafetyNetClient|\.attest\(' out/sources | head          # dead API since 2025
   grep -rnE 'appcheck|PlayIntegrityAppCheckProviderFactory|recaptcha' out/sources | head
   grep -rnE 'decryptionKey|verificationKey|JsonWebEncryption|A256KW' out/sources | head   # local decryption in the app?
   ```

   R8 renames app code but the Play Integrity library's public API and the binder interface strings usually survive. Check Gradle metadata in the APK too: `unzip -l app.apk | grep -i integrity` often shows a library version file under `META-INF/` that names the Play Integrity artifact.

2. **iOS, static.** On a decrypted IPA:

   ```bash
   otool -L Payload/App.app/App | grep -i devicecheck
   nm -u Payload/App.app/App | grep -iE 'DCAppAttestService|DCDevice'
   strings -a Payload/App.app/App | grep -E 'generateAssertion|attestKey|generateKey|isSupported' | sort -u | head
   codesign -d --entitlements :- Payload/App.app | grep -A1 appattest-environment
   grep -rl -E 'FIRAppCheck|AppAttestProvider|DeviceCheckProvider' Payload/App.app/Frameworks 2>/dev/null
   ```

   Swift call sites may only show as symbol references to `DCAppAttestService`; the framework link is the reliable first indicator.

3. **Runtime tracing of the app's own calls** (to see *when* evidence is produced):

   ```bash
   # Android: trace Play Integrity and Keystore attestation calls made by the app
   frida-trace -U -f com.example.bank \
     -j '*IntegrityTokenProvider*!request' -j '*IntegrityManager*!requestIntegrityToken' \
     -j 'android.security.keystore.KeyGenParameterSpec$Builder!setAttestationChallenge'
   # iOS: trace App Attest and DeviceCheck
   frida-trace -U -f com.example.bank -m '-[DCAppAttestService *]' -m '-[DCDevice generateTokenWithCompletionHandler:]'
   ```

4. **Traffic mapping.** Exercise every sensitive operation with test account A and record, per request, whether it carries attestation material and where (header, body field). Recognise it:
   - Play Integrity token: a long string of five base64url segments separated by dots (JWE).
   - Key attestation: an array of base64 DER certificates at enrolment, often next to a public key.
   - App Attest attestation object: base64 CBOR that typically starts with `o2NmbXRvYXBwbGUtYXBwYXR0ZXN0` (a map whose first key is `fmt: "apple-appattest"`), sent with a key ID.
   - App Attest assertion: base64 CBOR that typically starts with `omlzaWduYXR1cmU` (a map whose first key is `signature`).
   - DeviceCheck token: a long base64 string from `DCDevice`, often only at registration.
   - App Check: an `X-Firebase-AppCheck` header (a JWT issued by Firebase).
   Also record where the **challenge** comes from (a preceding `GET /challenge`-style call or nothing).

5. **Timing.** Note whether attestation happens per action, per session, or once at install. Check whether a long-lived session token alone is enough for later sensitive calls.

#### Observation

A table of sensitive operations with: evidence type (none / Play Integrity / key attestation / App Attest / DeviceCheck / App Check), where it travels, whether a server challenge precedes it, and whether the request content is bound (`requestHash` present and non-constant across requests; assertion over request data). Static evidence of the mechanism, and any client-side decryption or decision code.

#### Evaluation

- **Fail** for an R-profile app: no attestation on any sensitive operation; only SafetyNet Attestation (dead); attestation only at app start or login while later high-value operations rely on the session alone; Play Integrity token decryption keys or verdict evaluation found in the client.
- **Weak** (continue with GT-RES-0054-2): attestation present but no server challenge, constant `requestHash`, or tokens reused across several requests.
- **Pass**: each high-value operation carries fresh evidence produced for that operation, with a server challenge or request hash.
- **Not applicable / Info**: the app's threat model does not include R. Record what exists.

#### Demo

A typical gap, adapted from a pattern we see in reviews (illustrative):

```kotlin
// Token requested once at start-up and cached for every later call
lateinit var cachedToken: String
fun onAppStart(provider: StandardIntegrityTokenProvider) {
    provider.request(StandardIntegrityTokenRequest.builder().setRequestHash("init").build())
        .addOnSuccessListener { cachedToken = it.token() }
}
fun pay(req: PaymentRequest) = api.pay(req, integrityToken = cachedToken)  // same token, constant hash
```

```text
# illustrative proxy log
POST /v2/session/start       X-Integrity: 5 segments, len 1630
POST /v2/payments            X-Integrity: identical to /session/start
POST /v2/payees              X-Integrity: identical to /session/start
```

With standard requests, Google's replay protection means the second decode of the same token returns cleared verdicts; if `/v2/payments` still succeeds, the backend either does not decode the token or ignores the result. That is the starting point for GT-RES-0054-2.

### GT-RES-0054-2: Backend verification of attestation evidence (Android, iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Check that the backend verifies the evidence cryptographically, binds it to the request and the challenge, rejects replays and stale evidence, and does not accept requests without evidence. Every step modifies **your own** requests to **the app's own API** with **your test accounts**; nothing here touches Google's or Apple's verification.

#### Prerequisites

The endpoint map from GT-RES-0054-1, a proxy with repeater functionality (Burp Suite or mitmproxy), test accounts A and B, the baseline device, and agreement on the allowed request rate (each fresh Play Integrity token counts against the client's quota).

#### Steps

Perform each case on one sensitive endpoint at a time; start with a harmless one (for example a profile update or a small promotion check) before you touch payments.

1. **Missing evidence.** Replay a valid request with the attestation header or field removed, then with it present but empty. Also send the request as the app does when attestation fails on the client (see step 9).
2. **Malformed evidence.** Replace the token or assertion with random base64 of the same length, then with a truncated copy of a real one.
3. **Replay.** Send the same captured request twice, and again after a few minutes.
   - Play Integrity standard: the second decode returns cleared verdicts; the backend must reject.
   - Play Integrity classic: the server-issued nonce must be single-use.
   - App Attest: the counter in the replayed assertion is not greater than the stored one, and the challenge was already used.
   - Key attestation: replay a captured enrolment (chain and challenge ID) after a successful enrolment.
4. **Request substitution.** Keep the evidence and change a bound parameter: amount, payee, account number, promotion code, user ID. With `requestHash`, the server's recomputed digest no longer matches; with App Attest, the signature over `clientData` no longer verifies. If the backend accepts the changed request, find out what is actually in the hash (often nothing request-specific).
5. **Cross-endpoint and cross-account reuse.** Take fresh evidence produced for a low-value call (for example a balance refresh) and attach it to a high-value call. Take evidence produced in account A's session and attach it to a request in account B's session.
6. **Staleness.** Obtain a fresh token or assertion, hold the request for longer than any sensible window (10 minutes, then an hour), then send it. The server should check `timestampMillis` or its own challenge expiry.
7. **Wrong app or environment.**
   - Android: run a non-Play build supplied by the client (QA, staging, internal APK) against the production backend. Expect `UNRECOGNIZED_VERSION` and `UNLICENSED`/`UNEVALUATED`; if the build has a different `applicationId` (for example a `.debug` suffix), `requestPackageName` must not match.
   - iOS: run a development-signed build supplied by the client against the production backend. Its App Attest keys carry the development `aaguid` and must be rejected by production.
   - Key attestation: complete enrolment from an Android emulator. Emulator chains do not chain to a Google root (or come from software attestation) and must not be accepted as hardware-backed.
8. **Unsupported path (iOS).** Run the app in the Simulator (`isSupported` is false) or replay a request with whatever field marks "App Attest unsupported". Observe whether the backend applies a compensating control (step-up, limits, manual review) or treats the client exactly like an attested one.
9. **Client-side failure path (Android).** On the test device, disable the Play Store temporarily (`adb shell pm disable-user --user 0 com.android.vending`; re-enable afterwards with `adb shell pm enable com.android.vending`) or block Google Play endpoints in your proxy so that token requests fail. Record what the app sends and how the backend responds.

#### Observation

For each case: the exact request (redacted), the HTTP status and body, and the business effect (operation executed, step-up requested, blocked). Record whether error responses distinguish "invalid token" from other failures (useful for the client, also useful to an attacker; usually fine). Ask the backend team for the server log line for at least one rejected case, which proves the rejection came from attestation verification.

#### Evaluation

- **Fail (High in an R-profile app with abuse exposure):** a sensitive operation succeeds with missing, malformed or empty evidence (cases 1, 2, 9). The control does not exist on the server.
- **Fail (Medium):** replay accepted (case 3); request substitution accepted (case 4); cross-endpoint or cross-account reuse accepted (case 5); development-environment App Attest keys or non-Google-rooted key attestation accepted in production (case 7).
- **Fail (Low–Medium):** stale evidence accepted well beyond a sensible window (case 6); the unsupported path silently downgrades to "trusted" (case 8).
- **Pass:** every case is rejected or routed to a deliberate compensating control that you can see (step-up, hold, review).

#### Demo

What a backend that "verifies" without binding looks like (Python, illustrative):

```python
def check_integrity(token: str) -> bool:
    payload = play_integrity.decode(PACKAGE, token)          # calls decodeIntegrityToken
    labels = payload["deviceIntegrity"].get("deviceRecognitionVerdict", [])
    return "MEETS_DEVICE_INTEGRITY" in labels                 # nothing else is checked
```

```text
# illustrative results against such a backend
case 3 replay (standard)      -> 403  (cleared verdict on second decode: good, by accident)
case 4 amount 10 -> 9000      -> 200  requestHash never compared
case 5 token from /balance    -> 200  no binding to the action
case 7 QA build (UNRECOGNIZED_VERSION, requestPackageName com.example.bank.qa) -> 200
```

The replay is rejected only because Google clears the verdict on the second decode; everything that depends on the backend's own checks fails.

### GT-RES-0054-3: Verdict handling policy (Android, iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

GT-RES-0054-2 shows whether the backend verifies evidence. This test shows what it **does** with each possible result, including errors, partial verdicts and outages. Most real weaknesses are here: `UNEVALUATED` treated as a pass, optional labels never enabled, the strong label required where it locks out legitimate users (who then get a bypass), or quota exhaustion that switches enforcement off.

#### Prerequisites

Access to the client's Play Console Play Integrity settings (or screenshots from them), a backend contact, the device matrix, and, for Android, Play Console **testing** set up for your test account. In Play Console under Protected with Play → Play Integrity API → Manage → Testing, the client can assign the verdicts or error code that specific Google accounts should receive. Test responses carry `"testingDetails": {"isTestingResponse": true}`.

#### Steps

1. **Collect the configuration.** Which optional labels and signals are enabled (`MEETS_BASIC_INTEGRITY`, `MEETS_STRONG_INTEGRITY`, `deviceAttributes`, `recentDeviceActivity`, `deviceRecall`, `appAccessRiskVerdict`, `playProtectVerdict`)? Standard or classic? Response encryption managed by Google or by the client? Daily quota and alerting? For iOS: is the receipt stored and the risk metric used?
2. **Get the written policy**, or reconstruct it from code if you have backend source access: a table of action × verdict → decision.
3. **Drive each verdict with Play Console test responses** on your test account and the baseline device: no device labels; `MEETS_BASIC_INTEGRITY` only; `MEETS_DEVICE_INTEGRITY` without `MEETS_STRONG_INTEGRITY`; `UNRECOGNIZED_VERSION`; `UNLICENSED`; `UNEVALUATED` for app and licence; and each error code that the console lets you choose. For each, perform a low-value and a high-value operation and record the decision.
4. **Drive real states with real devices**, which also checks that the backend does not special-case test responses: the certified device (baseline), the emulator with Google Play (no device labels), an Android 12 device (check how the policy treats `MEETS_STRONG_INTEGRITY` without `deviceAttributes`), and if available an OEM-unlocked test device (on Android 13+ typically `MEETS_BASIC_INTEGRITY` only). Use the Play Store's **Check integrity** to confirm what each device gets.
5. **Errors and outages.** With the backend team, review what happens when `decodeIntegrityToken` returns HTTP 429 or 5xx or times out, when the client sends an error code instead of a token (GT-RES-0054-2 step 9), and when the daily quota is exhausted. On iOS, the same for Apple's `serverUnavailable` and throttling.
6. **Velocity and recall.** If `recentDeviceActivity` or the App Attest risk metric is enabled, ask what thresholds apply and what happens at `LEVEL_3`/`LEVEL_4` or a high risk metric. If `deviceRecall` is used, ask what the bits mean and when they are set.
7. **Account-level response.** After a bad verdict, check whether anything is recorded against the account (for example a flag that requires step-up on the next new-device login) or only the single request is refused.

#### Observation

The configuration, the policy table, and the decisions you observed for each verdict and error on each operation, with the evidence (requests, responses, screenshots of the app's reaction and of remediation dialogs).

#### Evaluation

- **Fail:** any high-value operation allowed with no device labels, with `UNEVALUATED`, with an error instead of a token, or during quota exhaustion, without a compensating control; `MEETS_BASIC_INTEGRITY` accepted where the policy claims device integrity (often a substring check); `testingDetails.isTestingResponse` honoured for accounts that are not configured testers; "monitor only" in production with no plan to enforce.
- **Weak:** only default labels used for actions where the client's risk assessment calls for the strong label or velocity signals; no `deviceAttributes`, so `MEETS_STRONG_INTEGRITY` is applied identically below and above Android 13; no quota alerting; App Attest receipts discarded.
- **Pass:** a documented, tiered policy where each verdict and each failure maps to a deliberate decision, errors are treated as "not attested", and there is a defined, monitored behaviour for outages.

#### Demo

An illustrative policy table that passes, for a banking app:

```text
action           | strong(13+) | device | basic only | none / UNEVALUATED / error | UNRECOGNIZED_VERSION
-----------------+-------------+--------+------------+----------------------------+---------------------
view balance     | allow       | allow  | allow      | allow + flag session       | prompt GET_INTEGRITY
login new device | allow       | allow  | step-up    | step-up + 24h payee hold   | deny
add payee        | allow       | step-up| deny       | deny                       | deny
payment > 500    | allow       | step-up| deny       | deny                       | deny
decode 429/5xx   | treat as "none"; alert on rate; no global bypass
```

### GT-RES-0054-4: Device binding implementation review (Android, iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Check whether the app's "trusted device" status is bound to the device with a non-exportable key, or to an identifier or token that can be copied. Covers MASTG-KNOW-0034 and MASTG-KNOW-0090.

#### Prerequisites

Two test devices of the same platform (rooted/jailbroken test devices make the data-copy step easier; on iOS an encrypted Finder backup restored to a second device also works), the proxy, objection or Frida, and a test account enrolled as a trusted device.

#### Steps

1. **Identify the binding material.** From GT-RES-0054-1 traffic and the code: what does the server use to recognise the device? Look for `ANDROID_ID`, `identifierForVendor`, a UUID in preferences or the Keychain, a Firebase Installation ID, a public key registered at enrolment, signatures on requests.
2. **Inspect key storage.** Android: in an objection session attached to the app, run `android keystore list` to see the app's Keystore aliases. With Frida you can trace the app's own `KeyGenParameterSpec.Builder` calls to see `setAttestationChallenge`, `setIsStrongBoxBacked` and `setUserAuthenticationRequired`:

   ```bash
   frida-trace -U -f com.example.bank -j 'android.security.keystore.KeyGenParameterSpec$Builder!set*'
   ```

   iOS: in an objection session, `ios keychain dump` lists Keychain items with their accessibility class; look for `…ThisDeviceOnly` classes and Secure Enclave keys (`kSecAttrTokenIDSecureEnclave` in the code).
3. **Header manipulation.** If a device identifier travels in a header or body, change it in the proxy and see whether the server notices (it should, if it is bound to a key; it cannot, if it is just an identifier).
4. **Copy test.** Enrol device A. Copy the app's data to device B:
   - Android (rooted test devices): `adb shell su -c 'tar -czf /data/local/tmp/app.tgz -C /data/data com.example.bank'`, pull, push to device B, extract, restore ownership and SELinux context (`chown -R`, `restorecon -R`) for the app's UID on B.
   - iOS: restore an encrypted backup of device A to device B, or copy the app container between jailbroken test devices.
   Start the app on B. Check whether it is still logged in and trusted, and whether a sensitive operation succeeds without re-enrolment.
5. **Backup path (Android).** Check `android:allowBackup`, `android:fullBackupContent` and `android:dataExtractionRules` (`aapt2 dump xmltree app.apk --file AndroidManifest.xml | grep -iE 'allowBackup|dataExtraction|fullBackup'`). Cloud backup restore to a new device is the realistic, non-root version of the copy test.
6. **Enrolment.** Check what is required to enrol a new device: password only, OTP, step-up on an existing device, cooling-off period, notification to the user. Check that enrolment includes attestation (key attestation chain or App Attest object) and that the server verifies it (GT-RES-0054-2 cases apply).

#### Observation

The binding material, where keys live (security level, `ThisDeviceOnly`), what the server checks per request, and the result of the copy and backup tests.

#### Evaluation

- **Fail:** the copied app on device B keeps trusted status and can perform sensitive operations; the "device ID" is a bearer value that can be changed or replayed; enrolment of a new device needs only the password (credential theft then equals full device trust).
- **Weak:** keys are hardware-backed but the server checks the signature only at login and trusts a session token afterwards; binding material is included in backups.
- **Pass:** a non-exportable, attested key per install, enrolled under strong authentication, used to sign server challenges for sensitive operations; copied data on device B fails and forces re-enrolment.

#### Demo

Illustrative result of the copy test against a bearer-identifier design:

```text
device A: enrolled, X-Device-Id: 7f3c9a2e-...-b41d   (UUID from shared_prefs/device.xml)
device B: data copied, app opens logged in
POST /v1/transfers  X-Device-Id: 7f3c9a2e-...-b41d  -> 200 OK  (no signature, no re-enrolment)
```

## Secure implementation

MASWE-0054 links no OWASP Best Practices, so this section is ours.

### Android: standard request bound to the request content

```kotlin
class Attestor(context: Context, cloudProjectNumber: Long) {
    private val manager = IntegrityManagerFactory.createStandard(context)
    private var provider: StandardIntegrityTokenProvider? = null

    fun warmUp() = manager.prepareIntegrityToken(
        PrepareIntegrityTokenRequest.builder().setCloudProjectNumber(cloudProjectNumber).build()
    ).addOnSuccessListener { provider = it }

    // canonical = the same stable serialisation the server will rebuild, e.g. "transfer|acc=123|to=456|amt=50.00|rid=<uuid>"
    fun tokenFor(canonical: String): Task<StandardIntegrityToken> {
        val hash = Base64.encodeToString(
            MessageDigest.getInstance("SHA-256").digest(canonical.toByteArray()),
            Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        return provider!!.request(StandardIntegrityTokenRequest.builder().setRequestHash(hash).build())
    }
}
```

Handle `INTEGRITY_TOKEN_PROVIDER_INVALID` by calling `warmUp()` again. Send the token with the request; do not cache it.

### Backend: checking a Play Integrity payload

```python
def verify(token, received_request, now_ms, policy):
    p = decode_integrity_token(PACKAGE, token)                  # Google endpoint, service account
    rd = p["requestDetails"]
    if rd["requestPackageName"] != PACKAGE: return deny("package")
    if rd.get("requestHash") != b64url_sha256(canonical(received_request)): return deny("binding")
    if now_ms - int(rd["timestampMillis"]) > 120_000: return deny("stale")
    if p["appIntegrity"]["appRecognitionVerdict"] != "PLAY_RECOGNIZED": return deny("app")
    di = p.get("deviceIntegrity", {})
    labels = set(di.get("deviceRecognitionVerdict", []))       # exact elements, not substrings
    sdk = di.get("deviceAttributes", {}).get("sdkVersion", 0)
    return policy.decide(action=received_request.action, labels=labels, sdk=sdk,
                         activity=di.get("recentDeviceActivity", {}).get("deviceActivityLevel"),
                         licensed=p["accountDetails"]["appLicensingVerdict"] == "LICENSED",
                         env=p.get("environmentDetails", {}))
# any exception, timeout, 429 or 5xx from decode_integrity_token -> policy.decide(..., labels=set())
```

### Android: key attestation at enrolment

Generate the binding key with a server challenge (code in the Key Attestation section), send the chain once at enrolment under step-up authentication, and verify on the server with Google's Kotlin library: both roots trusted, revocation checked, first extension used, `TrustedEnvironment` or `StrongBox`, challenge matched, `deviceLocked` and `Verified` (or allowlisted `SelfSigned`), patch levels within policy, `attestationApplicationId` matching your package and signing digest. Store the public key and the attested properties; require a signature over a fresh challenge with that key on each sensitive request.

### iOS: App Attest client flow

```swift
import DeviceCheck
import CryptoKit

enum AttestError: Error { case unsupported }
let service = DCAppAttestService.shared

func enrol(challenge: Data) async throws -> (keyId: String, attestation: Data) {
    guard service.isSupported else { throw AttestError.unsupported }   // server decides what this means
    let keyId = try await service.generateKey()
    let attestation = try await service.attestKey(keyId, clientDataHash: Data(SHA256.hash(data: challenge)))
    return (keyId, attestation)                                        // send both; persist keyId only
}

func assert(keyId: String, request: [String: String], challenge: String) async throws -> (Data, Data) {
    var body = request; body["challenge"] = challenge
    let clientData = try JSONEncoder().encode(body)
    let assertion = try await service.generateAssertion(keyId, clientDataHash: Data(SHA256.hash(data: clientData)))
    return (clientData, assertion)                                     // server verifies against clientData as sent
}
```

Persist the key ID (for example in the Keychain with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`) and use one key per user account. Ramp up attestation gradually for large user bases.

### Backend checklist

- Evidence is verified on the server; the app never decides.
- Every token/assertion is bound to a server challenge and to the request content, single-use, and fresh.
- Package name, signing certificate (Android) or App ID and production `aaguid` (iOS) are checked.
- Labels are matched exactly; `UNEVALUATED`, empty and errors mean "not attested".
- `deviceAttributes` is used to interpret `MEETS_STRONG_INTEGRITY` per Android version.
- Key attestation verifiers trust both Google roots, check revocation and RKP expiry, use the first extension, and reject `Software`.
- App Attest counters, receipts and risk metric are stored and used.
- There is a tiered policy per action, a monitored quota, and a documented outage mode that does not mean "allow everything".
- Trusted-device status is bound to a non-exportable key enrolled under strong authentication.

## Rating findings

The series rule applies: for an app whose threat model does not include the **R** profile, a missing attestation is **Info**. For an R-profile app, rate by what the gap lets an attacker do against the business, not by the absence of an API call. Attestation is a server-side control, so a broken server-side check is usually worse than a missing client-side one: it gives a false sense of protection and often already sits on the endpoint that matters.

| Rating | Conditions |
|---|---|
| **Critical** | Not used for attestation gaps alone. Rate the underlying flaw (for example an authorisation bypass) and mention the missing attestation as an aggravating factor. |
| **High** | R-profile app where the backend accepts sensitive operations (payments, payee or card management, new-device enrolment, account creation with bonuses) with **missing or invalid** evidence while the client team believes attestation is enforced; evidence of active bot or emulator abuse on an endpoint without attestation; Play Integrity decryption keys and verdict logic shipped in the app as the only check. |
| **Medium** | No attestation on high-value operations of an R-profile app; replay, request substitution or cross-endpoint reuse accepted; fail-open on errors or quota exhaustion; development-environment App Attest keys or non-Google-rooted/`Software` key attestation accepted in production; device binding that survives a data copy for sensitive operations. |
| **Low** | Attestation present and enforced but weakly bound (stale window too long, attestation only at login for medium-value actions); `MEETS_STRONG_INTEGRITY` interpreted without `deviceAttributes`; key attestation verifier without the 2026 root (fails closed: an availability problem that tends to produce bypass requests); App Attest receipts and risk metric unused; no quota alerting. |
| **Info** | Non-R apps; recommendations such as enabling `recentDeviceActivity` or `deviceRecall`, moving from classic to standard requests, or adopting Google's verification library. |

Raise a level when the endpoint is demonstrably abused (client fraud data, public bot tooling for the app) or when the gap combines with weak authentication (for example new-device enrolment with password only and no attestation). Lower a level when strong compensating server-side controls exist (velocity limits, risk engine, manual review) and you can see them working in GT-RES-0054-3. In the report give the endpoint, the evidence type, the exact case from GT-RES-0054-2 or -3 that failed, the request and response pair, and the server-side change that fixes it.

## References

- OWASP MASWE: [MASWE-0054: Device Attestation Not Implemented](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0054/); related [MASWE-0051](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0051/), [MASWE-0053](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0053/), [MASWE-0055](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0055/), [MASWE-0056](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0056/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-RESILIENCE-1](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-1/) (CC BY-SA 4.0)
- OWASP MASTG knowledge: [MASTG-KNOW-0035](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0035/), [MASTG-KNOW-0119](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0119/), [MASTG-KNOW-0120](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0120/), [MASTG-KNOW-0034](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0034/), [MASTG-KNOW-0090](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0090/) (CC BY-SA 4.0)
- OWASP MASTG tools: [Frida (MASTG-TOOL-0031)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/), [objection (MASTG-TOOL-0038)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0038/), [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [adb (MASTG-TOOL-0004)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0004/), [Burp Suite (MASTG-TOOL-0077)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0077/), [mitmproxy (MASTG-TOOL-0097)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0097/) (CC BY-SA 4.0)
- Google Play Integrity: [Overview](https://developer.android.com/google/play/integrity/overview), [Standard requests](https://developer.android.com/google/play/integrity/standard), [Classic requests](https://developer.android.com/google/play/integrity/classic), [Integrity verdicts](https://developer.android.com/google/play/integrity/verdicts), [Improved verdicts in Android 13 and later](https://developer.android.com/google/play/integrity/improvements), [Error codes](https://developer.android.com/google/play/integrity/error-codes), [Additional tools and testing](https://developer.android.com/google/play/integrity/additional-tools), [Remediation dialogs](https://developer.android.com/google/play/integrity/remediation), [Device recall](https://developer.android.com/google/play/integrity/device-recall), [Making Play Integrity API faster, more resilient, and more private (Android Developers Blog, December 2024)](https://android-developers.googleblog.com/2024/12/making-play-integrity-api-faster-resilient-private.html), [SafetyNet Attestation API deprecation](https://developer.android.com/privacy-and-security/safetynet/deprecation-timeline)
- Android key attestation: [Verify hardware-backed key pairs with key attestation](https://developer.android.com/privacy-and-security/security-key-attestation), [Key and ID attestation (AOSP)](https://source.android.com/docs/security/features/keystore/attestation), [Attestation roots (JSON)](https://android.googleapis.com/attestation/root), [Attestation revocation status list](https://android.googleapis.com/attestation/status), [android/keyattestation (Kotlin verification library)](https://github.com/android/keyattestation), [Key Attestation sample](https://github.com/googlesamples/android-key-attestation), [KeyGenParameterSpec.Builder](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder), [GrapheneOS attestation compatibility guide](https://grapheneos.org/articles/attestation-compatibility-guide)
- Apple DeviceCheck: [DeviceCheck](https://developer.apple.com/documentation/devicecheck), [Establishing your app's integrity](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity), [Validating apps that connect to your server](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server), [Assessing fraud risk](https://developer.apple.com/documentation/devicecheck/assessing-fraud-risk), [Preparing to use the App Attest service](https://developer.apple.com/documentation/devicecheck/preparing-to-use-the-app-attest-service), [Accessing and modifying per-device data](https://developer.apple.com/documentation/devicecheck/accessing-and-modifying-per-device-data), [App Attest environment entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.devicecheck.appattest-environment), [DCAppAttestService](https://developer.apple.com/documentation/devicecheck/dcappattestservice), [DCDevice](https://developer.apple.com/documentation/devicecheck/dcdevice)
- Firebase: [App Check](https://firebase.google.com/docs/app-check)
- CWE: [CWE-693](https://cwe.mitre.org/data/definitions/693.html), [CWE-290](https://cwe.mitre.org/data/definitions/290.html) (our mapping; OWASP gives none)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
