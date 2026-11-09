---
title: "MASVS-PLATFORM: Testing IPC, WebViews and the User Interface in Android and iOS Apps"
date: 2026-11-09 21:15:00 +0000
subcategory: platform
summary: "Hub for the MASVS-PLATFORM series: twelve weaknesses, all 48 OWASP tests, where each lives, legacy mapping, attacker positions, test plan, cheat sheet."
refs: [MASVS-PLATFORM-1, MASVS-PLATFORM-2, MASVS-PLATFORM-3, MASWE-0029, MASWE-0040]
tags: [android, ios, masvs-platform, webview, ipc, methodology]
---

This is the entry point to our series on **OWASP MASVS-PLATFORM**, the control group about how an app talks to the rest of the device. It has three requirements:

- **MASVS-PLATFORM-1:** "The app uses IPC mechanisms securely."
- **MASVS-PLATFORM-2:** "The app uses WebViews securely."
- **MASVS-PLATFORM-3:** "The app uses the user interface securely."

The series follows the [MASWE](https://mas.owasp.org/MASWE/) catalogue: one note per weakness, MASWE-0029 to MASWE-0040, each with its **Knowledge**, **Tests**, best practices and a rating table. OWASP files several tests under a weakness that does not match their topic. We document each test where it belongs and say so in both notes; the [placement table](#where-each-test-lives) explains every case. This page maps the area, lists all 48 OWASP tests with a link to the section that covers them, maps the deprecated v1 tests, explains what each attacker position can prove, and collects the commands you will use on every platform review.

One limit to know before you start. The [MASWE-0034 note](/mobile/maswe-0034-webviews-allow-access-to-local-resources/) covers file-read exposure through WebView settings in depth: the settings, the seven tests and how to rate them. It does not include a step-by-step proof of concept that exfiltrates a file. Its tests prove that a WebView has local reach. Proving that attacker script gets into that WebView is done with the entry-point tests in [MASWE-0035](/mobile/maswe-0035-webviews-loading-untrusted-content/) and [MASWE-0029](/mobile/maswe-0029-insecure-deep-links/).

## Contents

- [What MASVS-PLATFORM covers](#what-masvs-platform-covers)
- [The series](#the-series)
- [Where each test lives](#where-each-test-lives)
- [Test matrix](#test-matrix)
- [Legacy v1 tests and their replacements](#legacy-v1-tests-and-their-replacements)
- [What each attacker position can prove](#what-each-attacker-position-can-prove)
- [Test plan](#test-plan)
- [Rating overview](#rating-overview)
- [Command cheat sheet](#command-cheat-sheet)
- [Platform knowledge not tied to a weakness](#platform-knowledge-not-tied-to-a-weakness)
- [Related weaknesses in other categories](#related-weaknesses-in-other-categories)
- [Other series hubs](#other-series-hubs)
- [References](#references)

## What MASVS-PLATFORM covers

Every channel in this group is one the platform provides on purpose. Apps are meant to receive links, send intents, share files, render web content and show data on screen. Findings come from the app trusting those channels more than the platform does. In practice that means one of three mistakes:

1. **Trusting the sender or the receiver.** Deep links, intents, the clipboard and extensions all carry data across a trust boundary. The OS tells you little or nothing about who is on the other side.
2. **Trusting web content with native power.** A WebView runs someone's JavaScript inside your app's identity, with your bridges, your files and your cookies.
3. **Forgetting who else is looking.** The screen, the lock screen, Recents, notification listeners, overlays and accessibility services all see what the app shows.

**PLATFORM-1 (IPC)** has four weaknesses. **MASWE-0029** covers deep links: who receives a link, and what the handler does with it. **MASWE-0030** covers the clipboard. **MASWE-0031** covers app extensions and is iOS only: custom keyboards, share and action extensions, App Groups and keychain groups. **MASWE-0032** covers intents and is Android only: implicit intents, broadcasts, `PendingIntent`s and intent redirection. Exported components that perform actions without authorisation are not in this group. They are [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/), which already covers exported Android components and their permission protection.

**PLATFORM-2 (WebViews)** has three weaknesses. They split one attack into its parts. **MASWE-0035** asks how attacker content gets into the WebView. **MASWE-0033** asks what native functionality that content can call through a bridge. **MASWE-0034** asks what local files and providers that content can read. A WebView finding is rated on all three together, plus the network path ([cleartext](/mobile/maswe-0026-cleartext-network-traffic/), [certificate validation](/mobile/maswe-0027-insecure-certificate-validation/)).

**PLATFORM-3 (UI)** has five weaknesses. **MASWE-0036** covers input masking and the keyboard cache. **MASWE-0037** covers notifications. **MASWE-0038** covers screenshots, Recents and App Switcher snapshots, and screen recording. **MASWE-0039** covers overlays and tapjacking. **MASWE-0040** covers accessibility services.

**Profiles: the L1/L2 split.** MASWE-0029 to MASWE-0035, all of PLATFORM-1 and PLATFORM-2, are tagged **L1, L2 and EUDIW**. They are the baseline for every app. MASWE-0036 to MASWE-0040, all of PLATFORM-3, are tagged **L2 and EUDIW** only. UI protections are expected of banking, payment, health, identity and EU Digital Identity Wallet apps. The screenshot, overlay and accessibility notes rate findings down explicitly for L1 apps. The UI and notification notes rate on the data exposed, so for an L1 app say in the report that the requirement belongs to L2.

**Platform coverage.** OWASP tags MASWE-0039 and MASWE-0040 for both platforms, but every test is Android. Our notes explain [why classic overlays do not apply to iOS](/mobile/maswe-0039-app-vulnerable-to-overlay-attacks/#ios-why-classic-overlay-attacks-do-not-apply-supplementary) and cover the iOS accessibility residue in [GT-0040-3](/mobile/maswe-0040-sensitive-data-leaked-via-accessibility/#gt-0040-3-secrets-in-accessibility-labels-ios). MASWE-0037 has only an Android OWASP test; our [GT-0037-3](/mobile/maswe-0037-sensitive-data-exposed-via-notifications/#gt-0037-3-references-to-notification-content-apis-ios) and [GT-0037-4](/mobile/maswe-0037-sensitive-data-exposed-via-notifications/#gt-0037-4-runtime-capture-and-lock-screen-preview-observation-ios) add iOS. The clipboard has only iOS OWASP tests; [GT-0030-1](/mobile/maswe-0030-improper-use-of-the-clipboard/#gt-0030-1-clipboard-writes-of-sensitive-data-without-the-sensitive-flag-android) and [GT-0030-2](/mobile/maswe-0030-improper-use-of-the-clipboard/#gt-0030-2-sensitive-data-on-the-clipboard-at-runtime-android) add Android.

**What is out of scope.** Sensitive data at rest (snapshot files, App Group containers, WebView caches) is MASVS-STORAGE; we point to the [STORAGE guide](/mobile/masvs-storage-1-secure-storage-guide/) where it matters. Missing authentication on a component or entry point is MASVS-AUTH (MASWE-0018). WebView TLS and cleartext are MASVS-NETWORK.

## The series

| Note | Weakness | Controls | Profiles | OWASP tests documented (filed by OWASP under this weakness) | Our supplementary checks |
|------|----------|----------|----------|------------------------------------------|--------------------------|
| [Insecure Deep Links](/mobile/maswe-0029-insecure-deep-links/) | MASWE-0029 | PLATFORM-1, STORAGE-2, CODE-4 | L1, L2, EUDIW | 5 (5) | GT-0029-1, GT-0029-2 |
| [Improper Use of the Clipboard](/mobile/maswe-0030-improper-use-of-the-clipboard/) | MASWE-0030 | PLATFORM-1, STORAGE-2 | L1, L2, EUDIW | 5 iOS (0) | GT-0030-1 to GT-0030-3 |
| [Allowing Untrusted App Extensions](/mobile/maswe-0031-allowing-untrusted-app-extensions/) (iOS) | MASWE-0031 | PLATFORM-1, STORAGE-2 | L1, L2, EUDIW | 1 (1) | GT-0031-1 to GT-0031-5 |
| [Insecure Intents](/mobile/maswe-0032-insecure-intents/) (Android) | MASWE-0032 | PLATFORM-1, STORAGE-2 | L1, L2, EUDIW | 3 (3) | GT-0032-1 to GT-0032-3 |
| [Sensitive Native Functionality Exposed in WebViews](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/) | MASWE-0033 | PLATFORM-2, STORAGE-2 | L1, L2, EUDIW | 6 (0) | GT-0033-1, GT-0033-2 |
| [WebViews Allow Access to Local Resources](/mobile/maswe-0034-webviews-allow-access-to-local-resources/) | MASWE-0034 | PLATFORM-2, STORAGE-2, CODE-4 | L1, L2, EUDIW | 7 (13) | — |
| [WebViews Loading Untrusted Content](/mobile/maswe-0035-webviews-loading-untrusted-content/) | MASWE-0035 | PLATFORM-2, CODE-4 | L1, L2, EUDIW | 5 (5) | GT-0035-1 |
| [Sensitive Data Exposed via the UI](/mobile/maswe-0036-sensitive-data-exposed-via-ui/) | MASWE-0036 | PLATFORM-3, STORAGE-2 | L2, EUDIW | 6 (12) | GT-0036-1, GT-0036-2 |
| [Sensitive Data Exposed via Notifications](/mobile/maswe-0037-sensitive-data-exposed-via-notifications/) | MASWE-0037 | PLATFORM-3, STORAGE-2 | L2, EUDIW | 1 (1) | GT-0037-1 to GT-0037-4 |
| [Insufficient Screenshot Protection](/mobile/maswe-0038-insufficient-screenshot-protection/) | MASWE-0038 | PLATFORM-3, STORAGE-2 | L2, EUDIW | 6, 3 of them placeholders (6) | GT-0038-1, GT-0038-2 |
| [App Vulnerable to Overlay Attacks](/mobile/maswe-0039-app-vulnerable-to-overlay-attacks/) | MASWE-0039 | PLATFORM-3, CODE-1 | L2, EUDIW | 1 (0) | GT-0039-1, GT-0039-2 |
| [Sensitive Data Leaked via Accessibility Services](/mobile/maswe-0040-sensitive-data-leaked-via-accessibility/) | MASWE-0040 | PLATFORM-3, STORAGE-2 | L2, EUDIW | 2 (3, including the shared TEST-0316) | GT-0040-1 to GT-0040-3 |

Most PLATFORM weaknesses also map to MASVS-STORAGE-2 (preventing data leakage), because the usual outcome is private data leaving the app through a platform channel.

The Knowledge items are spread across the notes. Android's WebView item (MASTG-KNOW-0018) is split three ways: [settings and local access](/mobile/maswe-0034-webviews-allow-access-to-local-resources/#android-webviews-mastg-know-0018), [bridges](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/#android-webview-native-bridges-mastg-know-0018), and [URL loading and Safe Browsing](/mobile/maswe-0035-webviews-loading-untrusted-content/#android-url-loading-navigation-control-and-safe-browsing-mastg-know-0018). iOS WebViews (MASTG-KNOW-0076) are split the same way, and [WKContentWorld](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/#ios-wkcontentworld-mastg-know-0139) sits with the bridges. The Android IPC basics live in the intents note: [IPC mechanisms](/mobile/maswe-0032-insecure-intents/#android-inter-process-communication-ipc-mechanisms-mastg-know-0020), [explicit and implicit intents](/mobile/maswe-0032-insecure-intents/#android-explicit-vs-implicit-intents-mastg-know-0025), [pending intents](/mobile/maswe-0032-insecure-intents/#android-pending-intents-mastg-know-0024), the three component types and [object serialization](/mobile/maswe-0032-insecure-intents/#android-object-serialization-mastg-know-0021). The MASWE-0018 note covers the same components from the authorisation side. Custom keyboards (MASTG-KNOW-0141) appear in both the [extensions note](/mobile/maswe-0031-allowing-untrusted-app-extensions/#ios-custom-keyboards-mastg-know-0141) and the [UI note](/mobile/maswe-0036-sensitive-data-exposed-via-ui/#ios-custom-keyboards-mastg-know-0141). Fifteen PLATFORM Knowledge items belong to no weakness. They are summarised [below](#platform-knowledge-not-tied-to-a-weakness).

## Where each test lives

OWASP links a test to a weakness through the test's `maswe` front-matter field. For most tests that field matches the topic. For the tests below it does not, or the test sits in a different MASVS folder on mas.owasp.org. We document every test in the note where its topic is. The note OWASP files it under has a one-line pointer.

| Tests | OWASP files them under | We document them in | Why |
|-------|------------------------|---------------------|-----|
| iOS MASTG-TEST-0276 to 0280 (pasteboard) | MASWE-0036 | [MASWE-0030](/mobile/maswe-0030-improper-use-of-the-clipboard/#tests) | They test what the app writes to the pasteboard, and whether it clears, expires and keeps it local. That is clipboard handling. MASWE-0036 has a [pointer](/mobile/maswe-0036-sensitive-data-exposed-via-ui/#pointer-pasteboard-tests-mastg-test-0276-to-0280-ios). |
| Android MASTG-TEST-0340 (overlay protections) | MASWE-0036 | [MASWE-0039](/mobile/maswe-0039-app-vulnerable-to-overlay-attacks/#mastg-test-0340-references-to-overlay-attack-protections-android) | It searches for touch filtering and overlay hiding, which are tapjacking defences. MASWE-0036 has a [pointer](/mobile/maswe-0036-sensitive-data-exposed-via-ui/#pointer-mastg-test-0340-references-to-overlay-attack-protections-android). |
| Android MASTG-TEST-0334; iOS MASTG-TEST-0376 to 0380 (bridges) | MASWE-0034 | [MASWE-0033](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/#tests) | They test JavaScript bridges and native-to-page data flows, not file access. MASWE-0034 has a [pointer section](/mobile/maswe-0034-webviews-allow-access-to-local-resources/#bridge-tests-owasp-files-under-maswe-0034). |
| Android MASTG-TEST-0316 (authentication data in text fields) | MASWE-0036 and MASWE-0040 | [MASWE-0036](/mobile/maswe-0036-sensitive-data-exposed-via-ui/#mastg-test-0316-app-exposing-user-authentication-data-in-text-input-fields-android) | It is a masking test. Its accessibility consequence is rated in MASWE-0040, which has a [pointer](/mobile/maswe-0040-sensitive-data-leaked-via-accessibility/#mastg-test-0316-app-exposing-user-authentication-data-in-text-input-fields-android). |
| Android MASTG-TEST-0372, 0374 (intents); 0398, 0399, 0400 (WebView URL loading) | MASWE-0032; MASWE-0035 | The same notes | No mismatch in the weakness. OWASP keeps the files in its MASVS-CODE folder, so their URLs contain `MASVS-CODE`. |
| iOS MASTG-TEST-0313, 0314 (keyboard cache) | MASWE-0036 | The same note | Kept in OWASP's MASVS-STORAGE folder. |

The result is that three weaknesses have **no tests on their own MASWE page**. MASWE-0030's tests sit on the MASWE-0036 page. MASWE-0033's sit on the MASWE-0034 page. MASWE-0039's single test sits on the MASWE-0036 page. If you browse OWASP by weakness, the MASWE-0034 page lists 13 tests and the MASWE-0036 page lists 12. Our notes document 7 and 6 of them respectively.

## Test matrix

All 48 OWASP v2 tests linked to MASWE-0029 to MASWE-0040, grouped by the note that documents them. **Type** is OWASP's own classification. **OWASP files under** gives the weakness in the test's `maswe` field. Three Android screenshot tests are `status: placeholder` on OWASP. For those, the note gives our own procedure, labelled Guler Tech methodology.

| ID | Title (links to our section) | Platform | Type | OWASP files under |
|----|------------------------------|----------|------|-------------------|
| **MASWE-0029: deep links** | | | | |
| [MASTG-TEST-0393](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0393/) | [Use of Unverified App Links](/mobile/maswe-0029-insecure-deep-links/#mastg-test-0393-use-of-unverified-app-links-android) | Android | static, config | 0029 |
| [MASTG-TEST-0394](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0394/) | [Missing Input Validation in Custom URL Scheme Handlers](/mobile/maswe-0029-insecure-deep-links/#mastg-test-0394-missing-input-validation-in-custom-url-scheme-handlers-android) | Android | static, code, manual | 0029 |
| [MASTG-TEST-0370](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0370/) | [Missing Input Validation in Custom URL Scheme Handlers](/mobile/maswe-0029-insecure-deep-links/#mastg-test-0370-missing-input-validation-in-custom-url-scheme-handlers-ios) | iOS | static, code | 0029 |
| [MASTG-TEST-0371](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0371/) | [Missing Source Validation in Custom URL Scheme Handlers](/mobile/maswe-0029-insecure-deep-links/#mastg-test-0371-missing-source-validation-in-custom-url-scheme-handlers-ios) | iOS | static, code | 0029 |
| [MASTG-TEST-0395](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0395/) | [Missing Input Validation in Universal Link Handlers](/mobile/maswe-0029-insecure-deep-links/#mastg-test-0395-missing-input-validation-in-universal-link-handlers-ios) | iOS | static, code, manual | 0029 |
| **MASWE-0030: clipboard** | | | | |
| [MASTG-TEST-0276](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0276/) | [Use of the iOS General Pasteboard](/mobile/maswe-0030-improper-use-of-the-clipboard/#mastg-test-0276-use-of-the-ios-general-pasteboard-ios) | iOS | static, code, manual | 0036 |
| [MASTG-TEST-0277](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0277/) | [Sensitive Data in the iOS General Pasteboard at Runtime](/mobile/maswe-0030-improper-use-of-the-clipboard/#mastg-test-0277-sensitive-data-in-the-ios-general-pasteboard-at-runtime-ios) | iOS | dynamic, hooks | 0036 |
| [MASTG-TEST-0278](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0278/) | [Pasteboard Contents Not Cleared After Use](/mobile/maswe-0030-improper-use-of-the-clipboard/#mastg-test-0278-pasteboard-contents-not-cleared-after-use-ios) | iOS | static, code | 0036 |
| [MASTG-TEST-0279](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0279/) | [Pasteboard Contents Not Expiring](/mobile/maswe-0030-improper-use-of-the-clipboard/#mastg-test-0279-pasteboard-contents-not-expiring-ios) | iOS | static, code | 0036 |
| [MASTG-TEST-0280](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0280/) | [Pasteboard Contents Not Restricted to Local Device](/mobile/maswe-0030-improper-use-of-the-clipboard/#mastg-test-0280-pasteboard-contents-not-restricted-to-local-device-ios) | iOS | static, code | 0036 |
| **MASWE-0031: app extensions** | | | | |
| [MASTG-TEST-0389](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0389/) | [References to the App-Wide Restriction of Custom Keyboards](/mobile/maswe-0031-allowing-untrusted-app-extensions/#mastg-test-0389-references-to-the-app-wide-restriction-of-custom-keyboards-ios) | iOS | static, code, manual | 0031 |
| **MASWE-0032: intents** | | | | |
| [MASTG-TEST-0372](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0372/) | [Implicit Intents Used for Internal App Communication](/mobile/maswe-0032-insecure-intents/#mastg-test-0372-implicit-intents-used-for-internal-app-communication-android) | Android | static, code, manual | 0032 |
| [MASTG-TEST-0374](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0374/) | [References to Implicit Intents Carrying Sensitive Extras](/mobile/maswe-0032-insecure-intents/#mastg-test-0374-references-to-implicit-intents-carrying-sensitive-extras-android) | Android | static, code, manual | 0032 |
| [MASTG-TEST-0381](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0381/) | [References to Insecure PendingIntent Creation](/mobile/maswe-0032-insecure-intents/#mastg-test-0381-references-to-insecure-pendingintent-creation-android) | Android | static | 0032 |
| **MASWE-0033: WebView bridges** | | | | |
| [MASTG-TEST-0334](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0334/) | [Native Code Exposed Through WebViews](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/#mastg-test-0334-native-code-exposed-through-webviews-android) | Android | static, code, manual | 0034 |
| [MASTG-TEST-0376](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0376/) | [References to Native Bridge APIs in WebViews](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/#mastg-test-0376-references-to-native-bridge-apis-in-webviews-ios) | iOS | static, code | 0034 |
| [MASTG-TEST-0377](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0377/) | [References to evaluateJavaScript Used as Bridge Reply in WKScriptMessageHandler](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/#mastg-test-0377-references-to-evaluatejavascript-used-as-bridge-reply-in-wkscriptmessagehandler-ios) | iOS | static, code, manual | 0034 |
| [MASTG-TEST-0378](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0378/) | [References to Password Fields in WebView-Loaded HTML](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/#mastg-test-0378-references-to-password-fields-in-webview-loaded-html-ios) | iOS | static, code, manual | 0034 |
| [MASTG-TEST-0379](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0379/) | [References to evaluateJavaScript Without Content World Isolation](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/#mastg-test-0379-references-to-evaluatejavascript-without-content-world-isolation-ios) | iOS | static, code | 0034 |
| [MASTG-TEST-0380](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0380/) | [References to evaluateJavaScript Writing Sensitive Data into WebView DOM](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/#mastg-test-0380-references-to-evaluatejavascript-writing-sensitive-data-into-webview-dom-ios) | iOS | static, code, manual | 0034 |
| **MASWE-0034: WebView local resources** | | | | |
| [MASTG-TEST-0250](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0250/) | [References to Content Provider Access in WebViews](/mobile/maswe-0034-webviews-allow-access-to-local-resources/#mastg-test-0250-references-to-content-provider-access-in-webviews-android) | Android | static, code | 0034 |
| [MASTG-TEST-0251](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0251/) | [Runtime Use of Content Provider Access APIs in WebViews](/mobile/maswe-0034-webviews-allow-access-to-local-resources/#mastg-test-0251-runtime-use-of-content-provider-access-apis-in-webviews-android) | Android | dynamic, hooks, manual | 0034 |
| [MASTG-TEST-0252](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0252/) | [References to Local File Access in WebViews](/mobile/maswe-0034-webviews-allow-access-to-local-resources/#mastg-test-0252-references-to-local-file-access-in-webviews-android) | Android | static, code | 0034 |
| [MASTG-TEST-0253](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0253/) | [Runtime Use of Local File Access APIs in WebViews](/mobile/maswe-0034-webviews-allow-access-to-local-resources/#mastg-test-0253-runtime-use-of-local-file-access-apis-in-webviews-android) | Android | dynamic, hooks, manual | 0034 |
| [MASTG-TEST-0333](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0333/) | [Overly Broad File Read Access in WebViews](/mobile/maswe-0034-webviews-allow-access-to-local-resources/#mastg-test-0333-overly-broad-file-read-access-in-webviews-ios) | iOS | static, code, manual | 0034 |
| [MASTG-TEST-0335](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0335/) | [WebView File Origin Access Relaxed by Configuration](/mobile/maswe-0034-webviews-allow-access-to-local-resources/#mastg-test-0335-webview-file-origin-access-relaxed-by-configuration-ios) | iOS | static, code, manual | 0034 |
| [MASTG-TEST-0336](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0336/) | [Runtime Setting of Relaxed WebView File Origin Policies](/mobile/maswe-0034-webviews-allow-access-to-local-resources/#mastg-test-0336-runtime-setting-of-relaxed-webview-file-origin-policies-ios) | iOS | dynamic, hooks, manual | 0034 |
| **MASWE-0035: WebView untrusted content** | | | | |
| [MASTG-TEST-0398](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0398/) | [References to WebViewClient URL Loading Handlers](/mobile/maswe-0035-webviews-loading-untrusted-content/#mastg-test-0398-references-to-webviewclient-url-loading-handlers-android) | Android | static, code, manual | 0035 |
| [MASTG-TEST-0399](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0399/) | [SafeBrowsing Disabled](/mobile/maswe-0035-webviews-loading-untrusted-content/#mastg-test-0399-safebrowsing-disabled-android) | Android | static, config, code | 0035 |
| [MASTG-TEST-0400](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0400/) | [Runtime Use of WebViewClient URL Loading Handlers](/mobile/maswe-0035-webviews-loading-untrusted-content/#mastg-test-0400-runtime-use-of-webviewclient-url-loading-handlers-android) | Android | dynamic, hooks, manual | 0035 |
| [MASTG-TEST-0331](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0331/) | [Use of Deprecated WebView APIs](/mobile/maswe-0035-webviews-loading-untrusted-content/#mastg-test-0331-use-of-deprecated-webview-apis-ios) | iOS | static, code | 0035 |
| [MASTG-TEST-0332](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0332/) | [Attacker-Controlled URI in WebViews](/mobile/maswe-0035-webviews-loading-untrusted-content/#mastg-test-0332-attacker-controlled-uri-in-webviews-ios) | iOS | static, code, manual | 0035 |
| **MASWE-0036: sensitive data in the UI** | | | | |
| [MASTG-TEST-0258](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0258/) | [References to Keyboard Caching Attributes in UI Elements](/mobile/maswe-0036-sensitive-data-exposed-via-ui/#mastg-test-0258-references-to-keyboard-caching-attributes-in-ui-elements-android) | Android | static, code | 0036 |
| [MASTG-TEST-0316](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0316/) | [App Exposing User Authentication Data in Text Input Fields](/mobile/maswe-0036-sensitive-data-exposed-via-ui/#mastg-test-0316-app-exposing-user-authentication-data-in-text-input-fields-android) | Android | static, code, manual | 0036, 0040 |
| [MASTG-TEST-0313](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0313/) | [References to APIs for Preventing Keyboard Caching of Text Fields](/mobile/maswe-0036-sensitive-data-exposed-via-ui/#mastg-test-0313-references-to-apis-for-preventing-keyboard-caching-of-text-fields-ios) | iOS | static, code, manual | 0036 |
| [MASTG-TEST-0314](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0314/) | [Runtime Monitoring of Text Fields Eligible for Keyboard Caching](/mobile/maswe-0036-sensitive-data-exposed-via-ui/#mastg-test-0314-runtime-monitoring-of-text-fields-eligible-for-keyboard-caching-ios) | iOS | dynamic, hooks | 0036 |
| [MASTG-TEST-0346](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0346/) | [References to APIs Hiding Sensitive Data in Text Input Fields](/mobile/maswe-0036-sensitive-data-exposed-via-ui/#mastg-test-0346-references-to-apis-hiding-sensitive-data-in-text-input-fields-ios) | iOS | static, code, manual | 0036 |
| [MASTG-TEST-0347](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0347/) | [Runtime Use of APIs Hiding Sensitive Data in Text Input Fields](/mobile/maswe-0036-sensitive-data-exposed-via-ui/#mastg-test-0347-runtime-use-of-apis-hiding-sensitive-data-in-text-input-fields-ios) | iOS | dynamic, hooks | 0036 |
| **MASWE-0037: notifications** | | | | |
| [MASTG-TEST-0315](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0315/) | [Sensitive Data Exposed via Notifications](/mobile/maswe-0037-sensitive-data-exposed-via-notifications/#mastg-test-0315-sensitive-data-exposed-via-notifications-android) | Android | static, code | 0037 |
| **MASWE-0038: screenshots** | | | | |
| [MASTG-TEST-0289](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0289/) | [Runtime Verification of Sensitive Content Exposure in Screenshots During App Backgrounding](/mobile/maswe-0038-insufficient-screenshot-protection/#mastg-test-0289-runtime-verification-of-sensitive-content-exposure-in-screenshots-during-app-backgrounding-android) | Android | dynamic, filesystem, manual | 0038 |
| [MASTG-TEST-0291](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0291/) | [References to Screen Capturing Prevention APIs](/mobile/maswe-0038-insufficient-screenshot-protection/#mastg-test-0291-references-to-screen-capturing-prevention-apis-android) | Android | static, code | 0038 |
| [MASTG-TEST-0292](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0292/) | [setRecentsScreenshotEnabled Not Used to Prevent Screenshots When Backgrounded](/mobile/maswe-0038-insufficient-screenshot-protection/#mastg-test-0292-setrecentsscreenshotenabled-not-used-to-prevent-screenshots-when-backgrounded-android) (placeholder) | Android | static, code | 0038 |
| [MASTG-TEST-0293](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0293/) | [setSecure Not Used to Prevent Screenshots in SurfaceViews](/mobile/maswe-0038-insufficient-screenshot-protection/#mastg-test-0293-setsecure-not-used-to-prevent-screenshots-in-surfaceviews-android) (placeholder) | Android | static, code | 0038 |
| [MASTG-TEST-0294](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0294/) | [SecureOn Not Used to Prevent Screenshots in Compose Dialogs](/mobile/maswe-0038-insufficient-screenshot-protection/#mastg-test-0294-secureon-not-used-to-prevent-screenshots-in-compose-dialogs-android) (placeholder) | Android | static, code | 0038 |
| [MASTG-TEST-0290](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0290/) | [Runtime Verification of Sensitive Content Exposure in Screenshots During App Backgrounding](/mobile/maswe-0038-insufficient-screenshot-protection/#mastg-test-0290-runtime-verification-of-sensitive-content-exposure-in-screenshots-during-app-backgrounding-ios) | iOS | dynamic, filesystem | 0038 |
| **MASWE-0039: overlays** | | | | |
| [MASTG-TEST-0340](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0340/) | [References to Overlay Attack Protections](/mobile/maswe-0039-app-vulnerable-to-overlay-attacks/#mastg-test-0340-references-to-overlay-attack-protections-android) | Android | static, code | 0036 |
| **MASWE-0040: accessibility** | | | | |
| [MASTG-TEST-0403](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0403/) | [References to Accessibility Data Sensitivity APIs](/mobile/maswe-0040-sensitive-data-leaked-via-accessibility/#mastg-test-0403-references-to-accessibility-data-sensitivity-apis-android) | Android | static, code, manual | 0040 |
| [MASTG-TEST-0404](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0404/) | [Runtime Verification of Accessibility Data Sensitivity](/mobile/maswe-0040-sensitive-data-leaked-via-accessibility/#mastg-test-0404-runtime-verification-of-accessibility-data-sensitivity-android) | Android | dynamic, hooks, manual | 0040 |

That is 24 Android and 24 iOS tests. 38 are static and 10 are dynamic. Static tests find candidates: an API call, a flag, a missing attribute. Whether that candidate is reachable and exploitable is left to manual review. That is why most notes add a runtime proof of their own:

- [GT-0029-1](/mobile/maswe-0029-insecure-deep-links/#gt-0029-1-link-hijacking-with-a-competing-handler-android-and-ios) (link hijacking) and [GT-0029-2](/mobile/maswe-0029-insecure-deep-links/#gt-0029-2-exploiting-unvalidated-deep-link-input-android-and-ios) (link exploitation);
- [GT-0033-1](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/#gt-0033-1-enumerating-and-calling-bridges-at-runtime-and-proving-origin-restriction-android-and-ios), which calls bridges from an origin you control;
- [GT-0035-1](/mobile/maswe-0035-webviews-loading-untrusted-content/#gt-0035-1-driving-every-webview-load-input-with-an-attacker-url-android-and-ios), which feeds every WebView load input an attacker URL;
- [GT-0039-1](/mobile/maswe-0039-app-vulnerable-to-overlay-attacks/#gt-0039-1-proving-tapjacking-with-an-attacker-overlay-app-android), an attacker overlay app;
- [GT-0040-2](/mobile/maswe-0040-sensitive-data-leaked-via-accessibility/#gt-0040-2-logging-what-a-malicious-accessibility-service-sees-android), a logging accessibility service;
- [GT-0037-2](/mobile/maswe-0037-sensitive-data-exposed-via-notifications/#gt-0037-2-what-a-notification-listener-receives-android), a notification listener;
- [GT-0038-1](/mobile/maswe-0038-insufficient-screenshot-protection/#gt-0038-1-live-capture-check-with-screenshots-recording-and-casting-android-and-ios), live capture, recording and casting.

MASWE-0034 has no GT check of its own. Its runtime proof is the attacker-content path from MASWE-0035 and MASWE-0029, as noted in the introduction.

## Legacy v1 tests and their replacements

MASTG v1 had 24 tests in the PLATFORM folders, plus five platform-topic tests filed under STORAGE or CODE. All are now `status: deprecated`, with a `covered_by` list. If an older report or a client checklist cites them, map them like this:

| Legacy test | Platform | v1 title | OWASP `covered_by` | Where we cover it |
|-------------|----------|----------|--------------------|-------------------|
| [MASTG-TEST-0005](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0005/) | Android | Determining Whether Sensitive Data Is Shared with Third Parties via Notifications | 0315 | [MASWE-0037](/mobile/maswe-0037-sensitive-data-exposed-via-notifications/#tests) |
| [MASTG-TEST-0006](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0006/) | Android | Determining Whether the Keyboard Cache Is Disabled for Text Input Fields | 0258 | [MASWE-0036](/mobile/maswe-0036-sensitive-data-exposed-via-ui/#mastg-test-0258-references-to-keyboard-caching-attributes-in-ui-elements-android) |
| [MASTG-TEST-0007](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0007/) | Android | Determining Whether Sensitive Stored Data Has Been Exposed via IPC Mechanisms | 0339, 0355, 0356, 0357 | Content providers in [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/#mastg-test-0355-references-to-unauthorized-database-access-through-content-providers-android); 0339 (SQL injection, MASWE-0050) is touched on in [GT-0018-5](/mobile/maswe-0018-missing-auth-on-app-components/#gt-0018-5-content-provider-injection-path-permissions-and-file-access-android) |
| [MASTG-TEST-0008](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0008/) | Android | Checking for Sensitive Data Disclosure Through the User Interface | 0316 | [MASWE-0036](/mobile/maswe-0036-sensitive-data-exposed-via-ui/#mastg-test-0316-app-exposing-user-authentication-data-in-text-input-fields-android); its notification half is TEST-0315 in [MASWE-0037](/mobile/maswe-0037-sensitive-data-exposed-via-notifications/#mastg-test-0315-sensitive-data-exposed-via-notifications-android) |
| [MASTG-TEST-0010](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0010/) | Android | Finding Sensitive Information in Auto-Generated Screenshots | 0289, 0291 | [MASWE-0038](/mobile/maswe-0038-insufficient-screenshot-protection/#tests), plus placeholders 0292 to 0294 |
| [MASTG-TEST-0024](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0024/) | Android | Testing for App Permissions | 0254 | Outside this series: MASWE-0066 (MASVS-PRIVACY). See [App Permissions](#android-app-permissions-mastg-know-0017) |
| [MASTG-TEST-0026](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0026/) | Android | Testing Implicit Intents | 0372, 0374, 0375 | [MASWE-0032](/mobile/maswe-0032-insecure-intents/#tests); 0375 (returned-data validation) is filed under MASWE-0050 |
| [MASTG-TEST-0027](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0027/) | Android | Testing for URL Loading in WebViews | 0398, 0399, 0400 | [MASWE-0035](/mobile/maswe-0035-webviews-loading-untrusted-content/#tests) |
| [MASTG-TEST-0028](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0028/) | Android | Testing Deep Links | 0393, 0394 | [MASWE-0029](/mobile/maswe-0029-insecure-deep-links/#tests), plus GT-0029-1 and GT-0029-2 |
| [MASTG-TEST-0029](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0029/) | Android | Testing for Sensitive Functionality Exposure Through IPC | 0364, 0365, 0366 | [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/#mastg-test-0364-exported-and-unprotected-activities-that-expose-sensitive-functionality-android); broadcast sniffing in [GT-0032-2](/mobile/maswe-0032-insecure-intents/#gt-0032-2-implicit-and-sticky-broadcasts-carrying-sensitive-extras-android) |
| [MASTG-TEST-0030](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0030/) | Android | Testing for Vulnerable Implementation of PendingIntent | 0381 | [MASWE-0032](/mobile/maswe-0032-insecure-intents/#mastg-test-0381-references-to-insecure-pendingintent-creation-android) |
| [MASTG-TEST-0031](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0031/) | Android | Testing JavaScript Execution in WebViews | — (empty) | Enabled JavaScript is now a condition inside 0250 to 0253 in [MASWE-0034](/mobile/maswe-0034-webviews-allow-access-to-local-resources/#tests), not a finding on its own |
| [MASTG-TEST-0032](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0032/) | Android | Testing WebView Protocol Handlers | 0250, 0251, 0252, 0253 | [MASWE-0034](/mobile/maswe-0034-webviews-allow-access-to-local-resources/#tests) |
| [MASTG-TEST-0033](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0033/) | Android | Testing for Java Objects Exposed Through WebViews | 0334 | [MASWE-0033](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/#mastg-test-0334-native-code-exposed-through-webviews-android), plus GT-0033-1 for the dynamic half |
| [MASTG-TEST-0035](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0035/) | Android | Testing for Overlay Attacks | 0340 | [MASWE-0039](/mobile/maswe-0039-app-vulnerable-to-overlay-attacks/#tests), plus GT-0039-1 for the dynamic half |
| [MASTG-TEST-0037](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0037/) | Android | Testing WebViews Cleanup | 0320 | STORAGE: [MASWE-0001](/mobile/maswe-0001-sensitive-data-unencrypted-private-storage/#mastg-test-0320-webviews-not-cleaning-up-sensitive-data-android) |
| [MASTG-TEST-0055](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0055/) | iOS | Finding Sensitive Data in the Keyboard Cache | 0313, 0314 | [MASWE-0036](/mobile/maswe-0036-sensitive-data-exposed-via-ui/#tests) |
| [MASTG-TEST-0056](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0056/) | iOS | Determining Whether Sensitive Data Is Exposed via IPC Mechanisms | — (empty) | No successor. The iOS channels are split across MASWE-0029, 0030 and 0031; see [iOS IPC](#ios-inter-process-communication-mastg-know-0078) |
| [MASTG-TEST-0057](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0057/) | iOS | Checking for Sensitive Data Disclosed Through the User Interface | 0346, 0347 | [MASWE-0036](/mobile/maswe-0036-sensitive-data-exposed-via-ui/#tests) |
| [MASTG-TEST-0059](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0059/) | iOS | Testing Auto-Generated Screenshots for Sensitive Information | 0290 | [MASWE-0038](/mobile/maswe-0038-insufficient-screenshot-protection/#mastg-test-0290-runtime-verification-of-sensitive-content-exposure-in-screenshots-during-app-backgrounding-ios), plus GT-0038-2 |
| [MASTG-TEST-0069](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0069/) | iOS | Testing App Permissions | 0360, 0361, 0362, 0363 | Outside this series: MASWE-0066 (MASVS-PRIVACY). See [App Permissions](#ios-app-permissions-mastg-know-0077) |
| [MASTG-TEST-0070](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0070/) | iOS | Testing Universal Links | 0370, 0371, 0395 | [MASWE-0029](/mobile/maswe-0029-insecure-deep-links/#tests) |
| [MASTG-TEST-0071](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0071/) | iOS | Testing UIActivity Sharing | — (empty) | [GT-0031-5](/mobile/maswe-0031-allowing-untrusted-app-extensions/#gt-0031-5-sensitive-data-offered-through-the-share-sheet-ios) keeps a narrow version |
| [MASTG-TEST-0072](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0072/) | iOS | Testing App Extensions | 0388, 0389, 0299, 0346, 0347 | 0389 in [MASWE-0031](/mobile/maswe-0031-allowing-untrusted-app-extensions/#tests); 0346, 0347 in MASWE-0036; 0388 and 0299 in [MASWE-0001](/mobile/maswe-0001-sensitive-data-unencrypted-private-storage/#mastg-test-0388-references-to-sensitive-data-stored-unprotected-in-shared-app-group-containers-ios) |
| [MASTG-TEST-0073](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0073/) | iOS | Testing UIPasteboard | 0276, 0277, 0278, 0279, 0280 | [MASWE-0030](/mobile/maswe-0030-improper-use-of-the-clipboard/#tests) |
| [MASTG-TEST-0075](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0075/) | iOS | Testing Custom URL Schemes | 0370, 0371 | [MASWE-0029](/mobile/maswe-0029-insecure-deep-links/#tests) |
| [MASTG-TEST-0076](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0076/) | iOS | Testing iOS WebViews | 0331, 0332, 0333 | 0331 and 0332 in [MASWE-0035](/mobile/maswe-0035-webviews-loading-untrusted-content/#tests); 0333 in [MASWE-0034](/mobile/maswe-0034-webviews-allow-access-to-local-resources/#mastg-test-0333-overly-broad-file-read-access-in-webviews-ios) |
| [MASTG-TEST-0077](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0077/) | iOS | Testing WebView Protocol Handlers | 0335, 0336 | [MASWE-0034](/mobile/maswe-0034-webviews-allow-access-to-local-resources/#tests) |
| [MASTG-TEST-0078](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0078/) | iOS | Determining Whether Native Methods Are Exposed Through WebViews | 0376, 0377, 0378, 0379, 0380 | [MASWE-0033](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/#tests) |

Most v1 tests had a dynamic half that the v2 tests dropped. Examples are calling the bridge, running the overlay proof of concept, sniffing the broadcast and tracing the notification. Our GT checks restore those halves. Three legacy tests have an empty `covered_by`: 0031, 0056 and 0071. And OWASP's list for TEST-0008 omits TEST-0315, although the notification part of that v1 test now lives there. In MASVS v1 terms, the weaknesses map to MSTG-PLATFORM-3 (MASWE-0029), -6 (0034), -7 (0033), -9 (0039) and -11 (0031), and to MSTG-STORAGE-7 (0036) and -9 (0038). MASWE-0030, 0032, 0035, 0037 and 0040 have no v1 mapping.

## What each attacker position can prove

A PLATFORM finding without an attacker position is unratable. "The deep link is not validated" means one thing if a web page can deliver it, and another if only `adb` can. Name the position in every finding, and reproduce it in the lab as closely as you can.

| Attacker position | What it needs | Weaknesses it reaches | What a successful test proves | What it cannot prove |
|-------------------|---------------|-----------------------|-------------------------------|----------------------|
| **Malicious web page, link, email or QR code** | The user taps once (sometimes a chooser). Nothing installed. | 0029 (every `BROWSABLE` handler, Android `intent:` URIs), 0035, then 0033 and 0034 once its content runs in a WebView | Link-driven actions without confirmation; attacker content in the app's WebView; bridge calls and local reads from that content | Explicit intents to non-browsable components; anything on screen |
| **Network attacker on WebView content** | Cleartext loads or broken TLS | 0033, 0034, 0035 through the [NETWORK](/mobile/masvs-network-secure-communication-guide/) findings | Injected script in a page that holds a bridge or local reach | Nothing, if WebView traffic is HTTPS and validated |
| **Malicious app, no permissions** | Installed. On Android 10+ it usually has to be in the foreground to start your activities. | 0029 (claims schemes, sends explicit intents), 0032 (receives implicit intents and broadcasts, abuses `PendingIntent`s and results), 0034 and 0035 (intents that choose WebView content, `content://` URIs), 0030 (reads the clipboard when opened; any time on Android 9 and lower), 0031 (hosts your share or action extension), [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/) | Interception and injection through IPC | Other apps' windows or text: that needs one of the next three rows |
| **Malicious app with the overlay permission** | The user grants *Display over other apps* in Special app access | 0039 | Tapjacking and input capture on unprotected screens | Reading view text (that is accessibility); anything on iOS |
| **Malicious app with an accessibility service** | The user enables it past system warnings. Android 13+ adds restricted settings for sideloaded apps. | 0040; it also defeats `FLAG_SECURE` for text (0038) and can press confirmation buttons | Credentials, OTPs and payment controls readable or operable on screens without data-sensitivity protection | Views marked accessibility-sensitive on Android 14+, if the service is not declared as an accessibility tool |
| **Malicious app with notification-listener access** | The user grants Notification access | 0037; also tokens that 0032 exposes through notifications | Full notification content, including OTPs. The note covers the Android 15 change for sensitive notifications. | Anything not posted as a notification |
| **A keyboard the user installed** | iOS: enabled, plus Full Access to send data out. Android: chosen as IME. | 0031, 0036; on Android the IME can also read the clipboard (0030) | Keystrokes in fields that do not force the system keyboard or disable learning | iOS secure text entry fields, which always use the system keyboard |
| **Physical access or a shoulder-surfer** | Proximity, a locked phone, or briefly an unlocked one | 0037 (lock screen), 0038 (Recents and App Switcher), 0036 (unmasked fields, keyboard suggestions), 0030 (copy previews) | What is readable with no tools | IPC and WebView issues |
| **Screen-sharing scam** | Consent to record or share the screen, obtained by social engineering | 0038 (live capture: `FLAG_SECURE` on Android, capture-state redaction on iOS) | Secrets captured live | Recents snapshots (a different path) |
| **Backups and forensic extraction** | A backup, a seized device, or root or jailbreak | 0038 (snapshot files at rest), 0036 (keyboard cache files), 0031 (App Group containers) | Residue the platform keeps on the app's behalf | Whether a file is in a given backup type depends on the OS version. Check it, do not assume. At-rest data is rated in the [STORAGE guide](/mobile/masvs-storage-1-secure-storage-guide/). |
| **Controller of the device** | Your rooted or jailbroken test phone, Frida, `adb` | Every note uses it as methodology | Nothing on its own. `adb am start` proves a path exists. A finding needs one of the rows above to use it. | — |

The rule of thumb: `adb`, `simctl` and Frida are how you find and reproduce a path. The rating depends on the cheapest real attacker who can travel the same path. Several notes give the evidence for that directly: a crafted web page (MASWE-0029), a minimal attacker app (MASWE-0018 and GT-0039-1), a probe accessibility service (GT-0040-2) and a probe listener (GT-0037-2).

## Test plan

Before step 1, write down two lists. The first is the **sensitive data**: credentials, OTPs, tokens, card and bank data, recovery secrets, personal data. OWASP calls this `identify-sensitive-data`. The second is the **sensitive screens**: login, PIN, payment confirmation, payee change, MFA approval, recovery codes. Every UI test is evaluated per screen. Have at least one Android 14+ device, one Android 11 or older device or emulator (for overlay and clipboard behaviour), and an iOS device or Simulator.

### 1. Attack-surface inventory

- **Android manifest** (decoded with apktool, or read with aapt2). Record `minSdkVersion` and `targetSdkVersion`, exported components and their permissions, intent filters (`VIEW`, `BROWSABLE`, `autoVerify`), `<queries>`, and providers with `grantUriPermissions`. Then run `pm get-app-links` and `dumpsys package`. Component authorisation is [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/).
- **iOS Info.plist** of the app and of every `.appex`. Record `CFBundleURLTypes`, `NSUserActivityTypes`, `CFBundleDocumentTypes`, `LSSupportsOpeningDocumentsInPlace`, `NSBonjourServices`, `UIBackgroundModes` and `NSExtension` activation rules.
- **iOS entitlements** of every binary. Record `associated-domains` (including any `?mode=developer`), `application-groups` and `keychain-access-groups` ([GT-0031-1](/mobile/maswe-0031-allowing-untrusted-app-extensions/#gt-0031-1-inventory-of-the-apps-own-extensions-ios)).
- **Code entry points.** List link handlers, `onNewIntent`, `scene(_:continue:)`, App Intents and Siri intents. The [platform knowledge](#platform-knowledge-not-tied-to-a-weakness) section explains the iOS channels that no note covers.

### 2. Deep links and IPC

- Enumerate and fire every link ([how](/mobile/maswe-0029-insecure-deep-links/#before-you-start-enumerating-and-firing-every-deep-link)). Run TEST-0393, 0394, 0370, 0371 and 0395. Then prove hijacking and exploitation with GT-0029-1 and GT-0029-2 from a crafted web page.
- Android intents: run the [static triage](/mobile/maswe-0032-insecure-intents/#before-you-start-static-triage-of-intent-traffic) and TEST-0372, 0374 and 0381. Then run GT-0032-1 (redirection), GT-0032-2 (broadcasts) and GT-0032-3 (results).
- iOS extensions: run TEST-0389 and GT-0031-1 to GT-0031-5. Clipboard: run TEST-0276 to 0280 on iOS and GT-0030-1 to GT-0030-3.

### 3. WebViews

- Inventory every WebView, its settings, its content sources and its bridges ([0035](/mobile/maswe-0035-webviews-loading-untrusted-content/#before-you-start-map-the-webviews-and-their-inputs), [0033](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/#before-you-start-inventory-every-webview-and-bridge), [0034](/mobile/maswe-0034-webviews-allow-access-to-local-resources/#before-you-start-inventory-every-webview)). Enable remote debugging on your test build or with Frida.
- **Entry first.** Run TEST-0398 to 0400, 0331 and 0332, then GT-0035-1. Do any of the inputs from step 2 reach a load API?
- **Then capability.** Run the bridge tests (0334, 0376 to 0380) and GT-0033-1 from your probe origin. Run the local-resource tests (0250 to 0253, 0333, 0335 and 0336) from the same probe content.
- Rate the chain, not the parts. A deep link that loads your page into a WebView with a token bridge is one Critical finding, not three Mediums.

### 4. UI exposure

- **Input.** Run TEST-0258, 0316, 0313, 0314, 0346 and 0347, then GT-0036-1 field by field and GT-0036-2 screen by screen.
- **Notifications.** Run TEST-0315. Trigger every notification ([list](/mobile/maswe-0037-sensitive-data-exposed-via-notifications/#before-you-start-list-every-notification-the-app-can-post)) with the screen locked under the default settings (GT-0037-1 and GT-0037-4). Then run a listener (GT-0037-2).
- **Capture.** Run TEST-0289 and 0290 for Recents and the App Switcher, then TEST-0291 to 0294, then GT-0038-1 with recording and casting.
- **Overlays and accessibility** (Android, L2 apps). Run TEST-0340 and GT-0039-2 per screen, then GT-0039-1 on Android 12+ and on 11 or lower. Run TEST-0403 and 0404 on Android 14+, then GT-0040-2. Treat the two together: the same banking malware usually holds both permissions.

### 5. Report

For every finding, state the attacker position from the table above, the OS versions tested, the profile (L1 or L2), and whether the path was proven at runtime or only found statically.

## Rating overview

The detailed tables are in each note's *Rating findings* section. This is the shape of them, ordered roughly by what the attacker needs. When the same data is at stake, the less the attacker needs, the higher the rating.

| Finding | Attacker needs | Typical rating | Details |
|---------|----------------|----------------|---------|
| Authentication material (reset or magic-login token, OAuth code without PKCE) over a claimable link, shown interceptable | Malicious app with no permissions, or one tap | Critical | [MASWE-0029](/mobile/maswe-0029-insecure-deep-links/#rating-findings) |
| An attacker URL renders in a WebView with a sensitive bridge, local file read or the user's credentials | One tap, or an app with no permissions | Critical | [MASWE-0035](/mobile/maswe-0035-webviews-loading-untrusted-content/#rating-findings), [MASWE-0033](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/#rating-findings), [MASWE-0034](/mobile/maswe-0034-webviews-allow-access-to-local-resources/#rating-findings) |
| Tokens via an implicit intent or broadcast; redirection or a mutable `PendingIntent` that reaches account actions or URI grants to secrets | Any installed app, no interaction | Critical | [MASWE-0032](/mobile/maswe-0032-insecure-intents/#rating-findings) |
| Own share or action extension acts on host content without confirmation, using shared credentials | Any app, plus the user picking the extension | Critical | [MASWE-0031](/mobile/maswe-0031-allowing-untrusted-app-extensions/#rating-findings) |
| A notification that alone grants access (magic link, reset token) on the lock screen by default, or delivered to listeners | A locked phone in hand, or notification access | Critical | [MASWE-0037](/mobile/maswe-0037-sensitive-data-exposed-via-notifications/#rating-findings) |
| Master secrets copied to the clipboard programmatically, never cleared, readable in the background (apps supporting API 28 and lower) | Any installed app | Critical (rare) | [MASWE-0030](/mobile/maswe-0030-improper-use-of-the-clipboard/#rating-findings) |
| One-tap link that changes state without confirmation; attacker content in an authenticated WebView | One tap | High | [MASWE-0029](/mobile/maswe-0029-insecure-deep-links/#rating-findings), [MASWE-0035](/mobile/maswe-0035-webviews-loading-untrusted-content/#rating-findings) |
| OTPs or approval codes in notifications of a finance or identity app, on the lock screen or to listeners | A locked phone, or notification access | High | [MASWE-0037](/mobile/maswe-0037-sensitive-data-exposed-via-notifications/#rating-findings) |
| Credentials in fields a third-party iOS keyboard can serve, with no app-wide restriction | A keyboard the user installed | High | [MASWE-0031](/mobile/maswe-0031-allowing-untrusted-app-extensions/#rating-findings) |
| Unmasked password, PIN or OTP field by default in a high-value app | Shoulder-surfer, recording, keyboard | High | [MASWE-0036](/mobile/maswe-0036-sensitive-data-exposed-via-ui/#rating-findings) |
| Account-takeover secrets in Recents or the App Switcher, or capturable live without `FLAG_SECURE` (L2) | Brief physical access, or a screen-sharing scam | High | [MASWE-0038](/mobile/maswe-0038-insufficient-screenshot-protection/#rating-findings) |
| One-tap irreversible action completed under a pass-through overlay, proven on current Android (L2) | Overlay permission plus the user's tap | High | [MASWE-0039](/mobile/maswe-0039-app-vulnerable-to-overlay-attacks/#rating-findings) |
| Credential, OTP or payment-confirmation views readable or operable by a non-tool accessibility service on Android 14+ (L2) | An enabled accessibility service | High | [MASWE-0040](/mobile/maswe-0040-sensitive-data-leaked-via-accessibility/#rating-findings) |
| Sensitive bridge on first-party content with weak origin checks, one XSS away; local-read settings with no attacker path shown | A second vulnerability | Medium | [MASWE-0033](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/#rating-findings), [MASWE-0034](/mobile/maswe-0034-webviews-allow-access-to-local-resources/#rating-findings) |
| Unverified App Links or universal links carrying personal identifiers; delivery that needs a chooser choice | One tap plus a user choice | Medium | [MASWE-0029](/mobile/maswe-0029-insecure-deep-links/#rating-findings), [MASWE-0032](/mobile/maswe-0032-insecure-intents/#rating-findings) |
| Masked secret fields still eligible for keyboard learning; full card numbers shown where a partial value would do | Device access or a keyboard | Medium | [MASWE-0036](/mobile/maswe-0036-sensitive-data-exposed-via-ui/#rating-findings) |
| Safe Browsing disabled on own-domain WebViews; `allowFileAccess` without either relaxation flag; unverified links that only navigate | — | Low | [MASWE-0035](/mobile/maswe-0035-webviews-loading-untrusted-content/#rating-findings), [MASWE-0034](/mobile/maswe-0034-webviews-allow-access-to-local-resources/#rating-findings), [MASWE-0029](/mobile/maswe-0029-insecure-deep-links/#rating-findings) |
| Overlay or accessibility protections missing in an L1 app; overlays on iOS; detection-only screenshot controls | — | Info to Low | [MASWE-0039](/mobile/maswe-0039-app-vulnerable-to-overlay-attacks/#rating-findings), [MASWE-0040](/mobile/maswe-0040-sensitive-data-leaked-via-accessibility/#rating-findings), [MASWE-0038](/mobile/maswe-0038-insufficient-screenshot-protection/#rating-findings) |

Four rules apply to every row.

- **No Critical for UI weaknesses on their own.** The notes for MASWE-0036, 0038, 0039 and 0040 reserve Critical for a demonstrated chain. Every UI path needs proximity, consent or a permission the user granted.
- **Rate the chain.** A link that loads attacker content (0029, 0035) into a WebView with a bridge (0033) or local reach (0034) is rated once, at the level of the whole path. An exported activity ([MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/)) that lands on an unprotected one-tap approval (0039) is rated the same way.
- **User-granted special access is not exotic.** Banking malware routinely gets accessibility, notification and overlay access. The notes keep it as a precondition that rules out Critical, not one that discounts the finding to Low for L2 apps.
- **Reachability changes the rating.** A static hit in dead code, or in an SDK the app never initialises, is Low. Say whether you proved the path at runtime.

## Command cheat sheet

The most-used commands from the series. Each note has the full procedure, the expected output and how to read it.

### Inventory

```bash
# Android: SDK levels, exported components, intent filters
aapt2 dump badging app.apk | grep -E 'sdkVersion|targetSdkVersion'
apktool d -f -o apk_out app.apk
grep -nE 'android:exported="true"|autoVerify|BROWSABLE|<data |grantUriPermissions|android:permission=' apk_out/AndroidManifest.xml
adb shell pm get-app-links com.example.app                 # Android 12+: App Link verification state per domain
adb shell dumpsys package com.example.app | grep -A30 'Schemes:'

# iOS: schemes, activity types, document types and entitlements of the app and every extension
unzip -q App.ipa -d ipa
find ipa/Payload/App.app -maxdepth 2 -name '*.appex'
plutil -convert json -o - ipa/Payload/App.app/Info.plist \
  | jq '{CFBundleURLTypes, NSUserActivityTypes, CFBundleDocumentTypes, NSBonjourServices, UIBackgroundModes}'
codesign -d --entitlements - ipa/Payload/App.app/App 2>/dev/null \
  | grep -A6 -E 'associated-domains|application-groups|keychain-access-groups'
```

### Deep links and intents

```bash
# Fire a link as a browser would (no package), and to one exported component
adb shell "am start -W -a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d 'myapp://transfer?amount=1&to=TEST'"
adb shell "am start -W -n com.example.app/.DeepLinkActivity -a android.intent.action.VIEW -d 'https://example.com/app/x'"
xcrun simctl openurl booted 'myapp://transfer?amount=1&to=TEST'
xcrun devicectl device process launch --device <UDID> --payload-url 'myapp://transfer?amount=1' com.example.app

# Who else receives an action; sticky broadcasts; send a broadcast to a receiver
adb shell cmd package query-activities --components -a com.example.app.INTERNAL_ACTION
adb shell dumpsys activity broadcasts | sed -n '/Sticky broadcasts/,/^$/p'
adb shell am broadcast -n com.example.app/.SyncReceiver -a com.example.app.SYNC --es mode full
```

### WebViews

```bash
# Android: debuggable WebViews show up in chrome://inspect on the workstation
adb shell cat /proc/net/unix | grep -o 'webview_devtools_remote_[0-9]*'
adb shell dumpsys webviewupdate | grep -E 'Current WebView package|versionName'
# Settings, loaders and bridges in decompiled code
jadx -d jadx_out app.apk
grep -rnE 'setAllowFileAccess|setAllowUniversalAccessFromFileURLs|setAllowFileAccessFromFileURLs|setAllowContentAccess|addJavascriptInterface|addWebMessageListener|shouldOverrideUrlLoading|loadUrl\(' jadx_out/sources
# iOS: WebView APIs and bridges in the binary (Safari Web Inspector needs isInspectable on iOS 16.4+)
rabin2 -zzq ipa/Payload/App.app/App | grep -E 'loadFileURL|allowingReadAccessTo|allowFileAccessFromFileURLs|addScriptMessageHandler|evaluateJavaScript|UIWebView'
```

### UI exposure

```bash
# Screens, Recents and recordings
adb shell dumpsys activity activities | grep -E 'topResumedActivity|mResumedActivity'
adb exec-out screencap -p > screen.png
adb shell input keyevent KEYCODE_APP_SWITCH; sleep 1; adb exec-out screencap -p > recents.png
adb shell screenrecord --time-limit 15 /sdcard/live.mp4 && adb pull /sdcard/live.mp4
# What the view tree exposes (triage only, not proof for accessibility)
adb shell uiautomator dump /sdcard/ui.xml && adb pull /sdcard/ui.xml
# Notifications, listeners, accessibility services, overlay permission
adb shell dumpsys notification --noredact | grep -B2 -A8 com.example.app
adb shell settings get secure enabled_accessibility_services
adb shell appops set com.example.overlaytest SYSTEM_ALERT_WINDOW allow
# iOS Simulator pasteboard after a copy in the app
xcrun simctl pbpaste booted
```

## Platform knowledge not tied to a weakness

OWASP files these MASTG Knowledge items under MASVS-PLATFORM, but no weakness note in this series covers them. Each summary ends with the closest place to report a related finding.

### Android: App Permissions (MASTG-KNOW-0017)

Android apps declare permissions in the manifest. Each permission has a protection level. `normal` permissions are granted at install. `signature` permissions go only to apps signed with the declaring app's certificate. `dangerous` permissions need a runtime prompt (Android 6.0, API 23, and later). Special `appop` permissions need the user to act in *Settings › Apps › Special app access*; overlays and all-files access are examples. Apps can also define custom permissions to protect their own components. For PLATFORM testing, two parts matter. Custom and signature permissions guard exported components. And special access is exactly what the stronger attacker positions above need. Over-requesting is a privacy issue. [OWASP page](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0017/). Closest place to report: component protection is already explained in our [MASWE-0018 note](/mobile/maswe-0018-missing-auth-on-app-components/#android-app-permissions-mastg-know-0017), including [custom permission definitions](/mobile/maswe-0018-missing-auth-on-app-components/#gt-0018-4-custom-permission-definitions-android). Unjustified permissions go under [MASWE-0066](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0066/) (MASVS-PRIVACY, tested by MASTG-TEST-0254).

### Android: Enforced Updating (MASTG-KNOW-0023)

Apps on Google Play can force an update with the Play In-App Updates API. `AppUpdateManager` reports whether an update is available and starts an *immediate* flow (full screen, blocking) or a *flexible* one (background download, then `completeUpdate()`). The API supports Android 5.0 and later, but not apps that use `.obb` expansion files. A mandatory update has to keep blocking: the user can cancel, and the app must re-check in `onResume`. The real control is server-side. The backend should publish a minimum `versionCode` and reject requests from older builds. The Play Console prompt for outdated versions can be dismissed and is no substitute. [OWASP page](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0023/). To test it, block or edit the update-policy response. If an old build keeps working against the API, enforcement is client-only. Closest place to report: [MASWE-0043 (Enforced Updating Not Implemented)](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0043/), MASVS-CODE-2, L2 and EUDIW. It is outside this series.

### iOS: App Permissions (MASTG-KNOW-0077)

Every third-party iOS app runs as the `mobile` user inside a sandbox. Access beyond the sandbox is controlled in three separate layers, and a review has to inspect all three:

- **Purpose strings** in `Info.plist`. These are required before a prompt can be shown. Without one, a request can fail or crash the app.
- **Entitlements**, signed into the binary.
- **Runtime authorization prompts.**

A declared key alone does not prove the app uses the resource, and a referenced API alone does not prove the code path is reachable. Reduced-scope pickers such as `PHPickerViewController` (iOS 14+) avoid broad library access. [OWASP page](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0077/). Closest place to report: [MASWE-0066](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0066/) for unjustified permissions. The entitlements that matter for PLATFORM are associated domains (MASWE-0029), and App Groups and keychain groups (MASWE-0031).

### iOS: Enforced Updating (MASTG-KNOW-0074)

iOS has no public API to force an App Store update. Apps build their own gate. A common one queries the App Store Lookup API (`https://itunes.apple.com/lookup?bundleId=…`) and compares `results[0].version` with `CFBundleShortVersionString`, not `CFBundleVersion`, which is the build number. The app then sends the user to the store through `SKStoreProductViewController` or the `trackViewUrl`. Phased releases, regional differences and empty results make lookups unreliable. For security-critical updates, the source of truth should be a backend minimum version, with the server rejecting old builds. [OWASP page](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0074/). Closest place to report: [MASWE-0043](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0043/), as for Android.

### iOS: Object Serialization (MASTG-KNOW-0075)

iOS persists and exchanges objects through `NSCoding` and `NSSecureCoding`, `NSKeyedArchiver`, `Codable` with JSON or property-list encoders, XML parsers and ORMs such as Core Data and Realm. Realm encryption is off by default. Plain `NSCoding` builds the object before the class can be checked. `NSSecureCoding` (`supportsSecureCoding`, `decodeObject(of:forKey:)`) restricts the class, but adds no integrity and no encryption. Third-party XML libraries differ in how they handle external entities, and Apple's `XMLParser` should not resolve them (`shouldResolveExternalEntities` set to `false`). For PLATFORM this matters when decoded data arrives over a channel: the pasteboard, a URL parameter, an App Group file or a Handoff `userInfo`. [OWASP page](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0075/). Closest place to report: [MASWE-0050 (Unsafe Handling of Untrusted Data)](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0050/) for unsafe decoding. Unprotected serialized secrets at rest belong in [MASWE-0001](/mobile/maswe-0001-sensitive-data-unencrypted-private-storage/). The Android counterpart is in the [intents note](/mobile/maswe-0032-insecure-intents/#android-object-serialization-mastg-know-0021).

### iOS: Inter-Process Communication (MASTG-KNOW-0078)

iOS has no general-purpose channel between third-party apps. Exchange goes through platform-mediated channels in three groups:

- **User-mediated:** pasteboard, URL schemes and universal links, share sheet, document picker, Handoff, Siri and App Intents.
- **Entitlement-scoped:** App Groups, keychain groups, extensions and file coordination.
- **Network-based:** Bonjour, Core Bluetooth and Core NFC.

For each channel, ask five questions. Who can send? Who can receive? Is user interaction needed? How long does the data live? Is the channel limited by an entitlement? [OWASP page](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0078/). This is the map our iOS notes follow. Report findings in [MASWE-0029](/mobile/maswe-0029-insecure-deep-links/) (links), [MASWE-0030](/mobile/maswe-0030-improper-use-of-the-clipboard/) (pasteboard) or [MASWE-0031](/mobile/maswe-0031-allowing-untrusted-app-extensions/) (extensions and groups). The legacy test for this topic, MASTG-TEST-0056, has no successor.

### iOS: Low-Level System IPC Mechanisms (MASTG-KNOW-0104)

XPC (`NSXPCConnection` and the lower-level Swift and C APIs), Mach ports (`NSMachPort`, `CFMachPort`) and `CFMessagePort` are used by Apple frameworks and daemons. They are not a channel between unrelated apps. Apple DTS states that there is no supported way for iOS apps to talk to each other directly over XPC, and the local and remote `CFMessagePort` creation functions return `NULL` on iOS 7 and later. XPC does appear in supported designs: File Provider, BrowserEngineKit, ExtensionFoundation and enhanced security helper extensions. If an App Store binary imports XPC symbols, find out which of those designs it serves, and review the helper's input validation. [OWASP page](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0104/). Closest place to report: [MASWE-0031](/mobile/maswe-0031-allowing-untrusted-app-extensions/) for extension and helper boundaries.

### iOS: Document Picker, Document Interaction, and Open in Place (MASTG-KNOW-0122)

`UIDocumentPickerViewController` imports and exports by copying. For open and move operations it hands over security-scoped URLs, which need `startAccessingSecurityScopedResource()`. `UIDocumentInteractionController` lets the user send a file to another app, which receives a copy, usually in `Documents/Inbox`. Apps that declare `LSSupportsOpeningDocumentsInPlace` or `UISupportsDocumentBrowser` work on the original file where it lives, often through a File Provider. Every declared document type is an input any app can send. Treat received files as untrusted, and note that Inbox copies stay in the sandbox. [OWASP page](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0122/). Closest place to report: [MASWE-0034](/mobile/maswe-0034-webviews-allow-access-to-local-resources/) when a received file is rendered in a WebView (it lists "a file the user receives and opens" as an attacker position); [MASWE-0050](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0050/) for parser bugs; [MASWE-0001](/mobile/maswe-0001-sensitive-data-unencrypted-private-storage/) for sensitive copies left behind.

### iOS: Handoff (MASTG-KNOW-0123)

Handoff advertises an `NSUserActivity` to the user's nearby devices on the same iCloud account. The activity must be declared in `NSUserActivityTypes`, marked `isEligibleForHandoff` and made current with `becomeCurrent()`. The receiving device gets it in `scene(_:continue:)`, the same entry point that universal links use. So `userInfo` is input to validate, and it is data that leaves the device. Apple recommends a payload of about 3 KB or less. `isEligibleForSearch` and `isEligibleForPrediction` also expose the activity to Spotlight and Siri Suggestions. [OWASP page](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0123/). Closest place to report: [MASWE-0029](/mobile/maswe-0029-insecure-deep-links/) for continuation-handler validation. Secrets placed in an activity are data leakage under MASVS-STORAGE-2.

### iOS: SiriKit and Siri Shortcuts (MASTG-KNOW-0124)

SiriKit (iOS 10+) runs an Intents extension (`INExtension`) for Apple-defined domains such as messaging and payments. Since iOS 12, apps also donate shortcuts through `NSUserActivity` (`isEligibleForPrediction`) and `INInteraction`. Intent parameters, donated interactions and shortcut configurations come from outside the app's UI, and some sync across the user's devices. Authorisation and confirmation must therefore happen in the intent handler, not only in the screens. Donations must not carry secrets. [OWASP page](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0124/). Closest place to report: [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/#gt-0018-7-url-schemes-universal-links-and-extensions-that-act-without-authentication-ios) for actions without authentication. The extension's shared App Group belongs in [MASWE-0031](/mobile/maswe-0031-allowing-untrusted-app-extensions/).

### iOS: File Coordination APIs (MASTG-KNOW-0127)

`NSFileCoordinator` and `NSFilePresenter` serialise reads and writes to shared files, usually in an App Group container that an app and its extensions both use. Coordination only binds processes that take part in it. Uncoordinated access bypasses it. `UIDocument` coordinates automatically, and extensions must remove their presenters when they go to the background. For security, coordination is not a channel in itself. Its absence shows up as races and half-written state in shared files. [OWASP page](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0127/). Closest place to report: [MASWE-0031](/mobile/maswe-0031-allowing-untrusted-app-extensions/#gt-0031-2-shared-app-group-container-contents-ios) (shared container contents).

### iOS: Bonjour (MASTG-KNOW-0128)

Bonjour discovers services on the local network over mDNS and DNS-SD. It uses `NWBrowser` and `NWListener`; the older `NetService` API is deprecated. Since iOS 14, an app needs `NSLocalNetworkUsageDescription` and must list the service types it browses in `NSBonjourServices`. Discovery neither authenticates nor encrypts. Anyone on the same network can advertise the same `_name._tcp` service, so the connection that follows needs its own TLS and peer authentication. [OWASP page](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0128/). Closest place to report: [MASWE-0026](/mobile/maswe-0026-cleartext-network-traffic/#gt-0026-3-unencrypted-machine-to-machine-channels-ble-nfc-wi-fi-direct-usb) for a cleartext local channel; [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/) for a local service that acts for unauthenticated peers.

### iOS: App Intents and AI Agent Exposure (MASTG-KNOW-0129)

App Intents (iOS 16+) declare actions (`AppIntent`, `IntentParameter`, `AppEntity`, `AppShortcutsProvider`). The system can surface them in Siri, Shortcuts, Spotlight, widgets, controls, the Action button and Apple Intelligence features. Arbitrary third-party AI agents cannot call them, but every intent is still an entry point outside the app's UI. Its parameters must be validated. Destructive or financial actions need `requestConfirmation()` or an `authenticationPolicy`. Results and dialogs appear in system UI and should not disclose sensitive data. [OWASP page](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0129/). Closest place to report: [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/) for intents that act without authentication. Sensitive data in intent results is UI exposure, reported under [MASWE-0036](/mobile/maswe-0036-sensitive-data-exposed-via-ui/).

### iOS: Core Bluetooth (MASTG-KNOW-0130)

Core Bluetooth handles BLE through `CBCentralManager`, which scans and connects, and `CBPeripheralManager`, which advertises and serves GATT characteristics. Apps linked on iOS 13 and later need `NSBluetoothAlwaysUsageDescription`. Background use needs `UIBackgroundModes` with `bluetooth-central` or `bluetooth-peripheral`. Pairing and link-layer encryption are optional in BLE, so a characteristic that does not require encryption (`.readEncryptionRequired`, `.writeEncryptionRequired`) can be read or written by any nearby central. Sensitive payloads usually need application-layer authentication and encryption as well. [OWASP page](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0130/). Closest place to report: [GT-0026-3](/mobile/maswe-0026-cleartext-network-traffic/#gt-0026-3-unencrypted-machine-to-machine-channels-ble-nfc-wi-fi-direct-usb) in the cleartext note.

### iOS: Core NFC (MASTG-KNOW-0131)

Core NFC reads NDEF tags with `NFCNDEFReaderSession`, which can also write since iOS 13. It reaches ISO 7816, ISO 15693, FeliCa and MIFARE tags with `NFCTagReaderSession` (iOS 13+). That class needs `NFCReaderUsageDescription`, the `com.apple.developer.nfc.readersession.formats` entitlement, and for ISO 7816 and FeliCa the declared identifiers. Anyone can write a tag or stick one over a genuine one. So tag contents are attacker-controlled input, and an NDEF URL record is one more way to deliver a deep link. [OWASP page](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0131/). Closest place to report: [MASWE-0029](/mobile/maswe-0029-insecure-deep-links/) for URL payloads; [MASWE-0050](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0050/) for parsing; [GT-0026-3](/mobile/maswe-0026-cleartext-network-traffic/#gt-0026-3-unencrypted-machine-to-machine-channels-ble-nfc-wi-fi-direct-usb) for unprotected NFC exchanges.

## Related weaknesses in other categories

A PLATFORM review touches these weaknesses from other groups. Where we have a note, the link goes there.

- **[MASWE-0018: Missing authentication on app components](/mobile/maswe-0018-missing-auth-on-app-components/)** (MASVS-AUTH). Exported activities, services, receivers and providers, and iOS entry points that act without authentication. The deep-link, intent and overlay notes all hand over to it.
- **[MASWE-0019: No autofill support for credential providers](/mobile/maswe-0019-no-autofill-support-for-credential-providers/)**. This is usually why users copy passwords. Report it next to clipboard findings.
- **[MASWE-0001](/mobile/maswe-0001-sensitive-data-unencrypted-private-storage/)** and **[MASWE-0024](/mobile/maswe-0024-sensitive-data-accessible-after-session-termination/)** (MASVS-STORAGE and AUTH). WebView cleanup (TEST-0320), App Group storage (TEST-0388), snapshot files at rest, and snapshots that outlive a logout.
- **[MASWE-0026](/mobile/maswe-0026-cleartext-network-traffic/)** and **[MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/)** (MASVS-NETWORK). WebView cleartext, mixed content and `onReceivedSslError`, the network route into every WebView finding.
- **[MASWE-0050](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0050/)**, **[MASWE-0043](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0043/)** and **[MASWE-0066](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0066/)** (MASVS-CODE and PRIVACY). Untrusted data handling (TEST-0339, 0375), enforced updating and permissions. We will cover them in their own series.

## Other series hubs

- [MASVS-STORAGE: secure storage](/mobile/masvs-storage-1-secure-storage-guide/)
- [MASVS-CRYPTO: cryptography and key management](/mobile/masvs-crypto-cryptography-guide/)
- [MASVS-AUTH: authentication and authorisation](/mobile/masvs-auth-authentication-guide/). Most PLATFORM entry points end in an authorisation question.
- [MASVS-NETWORK: secure communication](/mobile/masvs-network-secure-communication-guide/)

## References

- OWASP MASVS: [MASVS-PLATFORM-1](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-1/), [MASVS-PLATFORM-2](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-2/), [MASVS-PLATFORM-3](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-3/) (CC BY-SA 4.0)
- OWASP MASWE: [MASWE-0029](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0029/), [MASWE-0030](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0030/), [MASWE-0031](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0031/), [MASWE-0032](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0032/), [MASWE-0033](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0033/), [MASWE-0034](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0034/), [MASWE-0035](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0035/), [MASWE-0036](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0036/), [MASWE-0037](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0037/), [MASWE-0038](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0038/), [MASWE-0039](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0039/), [MASWE-0040](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0040/), [MASWE-0043](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0043/), [MASWE-0050](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0050/), [MASWE-0066](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0066/) (CC BY-SA 4.0)
- OWASP MASTG Knowledge: Android [MASTG-KNOW-0017](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0017/), [MASTG-KNOW-0023](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0023/); iOS [MASTG-KNOW-0074](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0074/), [MASTG-KNOW-0075](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0075/), [MASTG-KNOW-0077](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0077/), [MASTG-KNOW-0078](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0078/), [MASTG-KNOW-0104](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0104/), [MASTG-KNOW-0122](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0122/), [MASTG-KNOW-0123](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0123/), [MASTG-KNOW-0124](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0124/), [MASTG-KNOW-0127](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0127/), [MASTG-KNOW-0128](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0128/), [MASTG-KNOW-0129](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0129/), [MASTG-KNOW-0130](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0130/), [MASTG-KNOW-0131](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0131/) (CC BY-SA 4.0)
- OWASP MASTG: [Tests](https://mas.owasp.org/MASTG/tests/), [Knowledge](https://mas.owasp.org/MASTG/knowledge/), [Techniques](https://mas.owasp.org/MASTG/techniques/), [Best Practices](https://mas.owasp.org/MASTG/best-practices/) (CC BY-SA 4.0)
- [Android Developers: Permissions on Android](https://developer.android.com/guide/topics/permissions/overview), [In-app updates](https://developer.android.com/guide/playcore/in-app-updates), [Verify Android App Links](https://developer.android.com/training/app-links/verify-android-applinks), [Android security risks catalogue](https://developer.android.com/privacy-and-security/risks)
- [Apple: Requesting access to protected resources](https://developer.apple.com/documentation/uikit/requesting-access-to-protected-resources), [NSUserActivity](https://developer.apple.com/documentation/foundation/nsuseractivity), [App Intents](https://developer.apple.com/documentation/appintents), [UIDocumentPickerViewController](https://developer.apple.com/documentation/uikit/uidocumentpickerviewcontroller), [NSSecureCoding](https://developer.apple.com/documentation/foundation/nssecurecoding), [Core Bluetooth](https://developer.apple.com/documentation/corebluetooth), [Core NFC](https://developer.apple.com/documentation/corenfc), [TN3155: Debugging universal links](https://developer.apple.com/documentation/technotes/tn3155-debugging-universal-links)

> Adapted and extended from the OWASP MASVS, MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
