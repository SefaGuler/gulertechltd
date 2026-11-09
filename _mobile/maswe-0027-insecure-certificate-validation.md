---
title: "Insecure Certificate Validation (MASWE-0027)"
date: 2026-11-09 16:02:00 +0000
subcategory: network
summary: "Testing Android and iOS apps for trust-all TrustManagers, hostname bypasses, WebView SSL errors, user CAs and unsafe URLSession delegates."
refs: [MASWE-0027, MASVS-NETWORK-1, CWE-295, CWE-297]
tags: [android, ios, masvs-network, tls, certificate-validation, mitm]
---

This note is part of our [MASVS-NETWORK guide](/mobile/masvs-network-secure-communication-guide/) and covers OWASP [MASWE-0027](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0027/): apps that encrypt their traffic but do not check who they are encrypting it for. TLS gives you confidentiality and integrity only if the client authenticates the server, and the client does that by validating the certificate chain and matching the certificate to the hostname it meant to reach. Take either check away and anyone on the path can present their own certificate, decrypt everything, and re-encrypt it to the real server, with the padlock still showing. Below you will find what each platform validates by default and where apps switch it off (Android `X509TrustManager`, `HostnameVerifier`, raw `SSLSocket`, `WebViewClient.onReceivedSslError`, user versus system CA stores, the GMS security provider; iOS server trust evaluation, `URLSessionDelegate` and `WKNavigationDelegate` challenge handling), the nine OWASP tests with their demos, our dynamic method for proving a finding with an untrusted CA and a wrong-hostname certificate, secure patterns, and how to rate what you find, including how to tell live code from dead code.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Generic: what certificate validation actually checks (supplementary)](#generic-what-certificate-validation-actually-checks-supplementary)
  - [iOS: Server Trust Evaluation (MASTG-KNOW-0072)](#ios-server-trust-evaluation-mastg-know-0072)
  - [Android: Trust managers, hostname verifiers and CA stores (supplementary)](#android-trust-managers-hostname-verifiers-and-ca-stores-supplementary)
  - [Android: Security Provider (MASTG-KNOW-0011)](#android-security-provider-mastg-know-0011)
- [Tests](#tests)
  - [Before you start: static triage of the whole app](#before-you-start-static-triage-of-the-whole-app)
  - [MASTG-TEST-0282: Unsafe Custom Trust Evaluation (Android)](#mastg-test-0282-unsafe-custom-trust-evaluation-android)
  - [MASTG-TEST-0283: Incorrect Implementation of Server Hostname Verification (Android)](#mastg-test-0283-incorrect-implementation-of-server-hostname-verification-android)
  - [MASTG-TEST-0234: Missing Implementation of Server Hostname Verification with SSLSockets (Android)](#mastg-test-0234-missing-implementation-of-server-hostname-verification-with-sslsockets-android)
  - [MASTG-TEST-0284: Incorrect SSL Error Handling in WebViews (Android)](#mastg-test-0284-incorrect-ssl-error-handling-in-webviews-android)
  - [MASTG-TEST-0286: Network Security Configuration Allowing Trust in User-Provided CAs (Android)](#mastg-test-0286-network-security-configuration-allowing-trust-in-user-provided-cas-android)
  - [MASTG-TEST-0285: Outdated Android Version Allowing Trust in User-Provided CAs (Android)](#mastg-test-0285-outdated-android-version-allowing-trust-in-user-provided-cas-android)
  - [MASTG-TEST-0295: GMS Security Provider Not Updated (Android)](#mastg-test-0295-gms-security-provider-not-updated-android)
  - [MASTG-TEST-0396: References to URLSessionDelegate Bypassing Certificate Validation (iOS)](#mastg-test-0396-references-to-urlsessiondelegate-bypassing-certificate-validation-ios)
  - [MASTG-TEST-0397: References to WKNavigationDelegate Bypassing Certificate Validation (iOS)](#mastg-test-0397-references-to-wknavigationdelegate-bypassing-certificate-validation-ios)
  - [GT-0027-1: Proving it on the wire with an untrusted CA and a wrong-hostname certificate (Android and iOS)](#gt-0027-1-proving-it-on-the-wire-with-an-untrusted-ca-and-a-wrong-hostname-certificate-android-and-ios)
  - [GT-0027-2: Other TLS stacks and cross-platform frameworks (Android and iOS)](#gt-0027-2-other-tls-stacks-and-cross-platform-frameworks-android-and-ios)
- [Best practices](#best-practices)
  - [MASTG-BEST-0073: Properly Validate Server Trust in URLSessionDelegate and WKNavigationDelegate](#mastg-best-0073-properly-validate-server-trust-in-urlsessiondelegate-and-wknavigationdelegate)
  - [MASTG-BEST-0021: Ensure Proper Error and Exception Handling](#mastg-best-0021-ensure-proper-error-and-exception-handling)
  - [MASTG-BEST-0020: Update the GMS Security Provider](#mastg-best-0020-update-the-gms-security-provider)
  - [Secure patterns for Android (Guler Tech)](#secure-patterns-for-android-guler-tech)
- [Rating findings](#rating-findings)
  - [Telling live code from dead code](#telling-live-code-from-dead-code)
- [References](#references)

## Overview

MASWE-0027 applies when an app accepts a server certificate it should have rejected: one that does not chain to a trusted root, has expired or is not yet valid, is self-signed, or was issued for a different hostname. The OWASP requirement is *"The app validates certificates for all network traffic."* It maps to MASVS-NETWORK-1 ("The app secures all network traffic according to the current best practices"), to MASVS v1 MSTG-NETWORK-3, and to two CWEs: [CWE-295](https://cwe.mitre.org/data/definitions/295.html) (Improper Certificate Validation) for chain and validity failures, and [CWE-297](https://cwe.mitre.org/data/definitions/297.html) (Improper Validation of Certificate with Host Mismatch) for the hostname case. Android's own risk catalogue lists the same two problems as *unsafe X509TrustManager* and *unsafe HostnameVerifier*. The weakness is tagged for profiles L1, L2 and EUDIW, which means it is a baseline expectation for every app, not a hardening extra.

OWASP describes the threat as MAS-THREAT-0027, *"Attackers can intercept or modify TLS-protected network traffic"*, reached through two attacks: MAS-ATTACK-0014, a machine-in-the-middle position (ARP poisoning, DNS spoofing, a rogue access point), and MAS-ATTACK-0015, presenting a fraudulent or invalid certificate that the app accepts. The first gives the attacker the path; the second is what this weakness hands them. Neither needs anything on the victim's device: no malware, no root, no installed CA, no user interaction. That is why disabled validation rates higher than almost any other network finding.

Keep three things apart, because they are tested and rated differently:

| Question | Where it lives | Note |
|---|---|---|
| Does the app validate the chain and the hostname at all? | This note (MASWE-0027) | Trust-all trust managers, accept-all hostname verifiers, `proceed()` on WebView errors, delegates that accept any `SecTrust` |
| Which CAs does the app trust? | This note, partly | Trusting user-installed CAs widens the set of roots; it does not switch validation off |
| Does the app restrict trust to *its own* server keys? | [MASWE-0028](/mobile/maswe-0028-insecure-identity-pinning/) | Pinning is hardening layered on top of correct validation; missing pinning is not missing validation |

And keep this note separate from transport choices: an app sending HTTP at all, or allowing TLS 1.0, is [cleartext traffic](/mobile/maswe-0026-cleartext-network-traffic/) or [insecure TLS versions](/mobile/maswe-0026-insecure-tls-protocol-versions/). In particular, `NSAllowsArbitraryLoads` on iOS and `cleartextTrafficPermitted="true"` on Android are not certificate validation findings: with them set, an HTTPS connection is still validated normally.

## Modes of Introduction

**Validation switched off during development and shipped.** The classic: a backend in staging has a self-signed certificate, someone pastes a "trust all certificates" snippet from a forum, and the release build keeps it. On Android it is an `X509TrustManager` whose `checkServerTrusted()` is empty, plus often a `HostnameVerifier` returning `true`; on iOS a `URLSessionDelegate` that answers every server-trust challenge with `.useCredential`.

**Accepting self-signed or untrusted certificates "just for this host".** Code that accepts a certificate when the chain has length one, when the issuer name looks right, or when `X509Certificate.checkValidity()` passes. None of those establishes trust: an attacker can mint a self-signed certificate with any issuer name and any validity period.

**Hostname verification skipped or done wrongly.** A `HostnameVerifier` that returns `true`, compares the requested hostname against an allowlist without looking at the certificate, or matches with `endsWith("example.com")` (which also matches `evilexample.com`). Raw `SSLSocket` use without any verifier, because the socket does not check hostnames by itself. On iOS, replacing the SSL policy on a trust object with a basic X.509 policy, or creating the SSL policy with a `nil` hostname.

**Errors caught and ignored.** A custom trust manager that delegates to the platform one but wraps the call in `try { … } catch (e: CertificateException) { log(e) }`. A WebView client that logs the SSL error and then calls `proceed()`. An iOS delegate that calls `SecTrustEvaluateWithError` and ignores its return value.

**Trust widened instead of disabled.** A Network Security Configuration with `<certificates src="user"/>` in the release build, a `minSdkVersion` that lets the app run on Android 6 or lower (where user CAs are trusted by every app), or a debugging proxy's CA bundled in `res/raw` and referenced as a trust anchor.

**Third-party code.** SDKs, HTTP wrappers and cross-platform plugins that ship their own permissive defaults or expose a "disable SSL verification" flag that the app sets: `NoopHostnameVerifier`, Alamofire's `DisabledTrustEvaluator`, AFNetworking's `allowInvalidCertificates`, Flutter's `badCertificateCallback`, .NET's `DangerousAcceptAnyServerCertificateValidator`. Process-wide overrides such as `HttpsURLConnection.setDefaultSSLSocketFactory()` are especially damaging because they also apply to every SDK in the process that uses `HttpsURLConnection`.

**Outdated TLS implementation.** On Android devices that never receive platform updates, the system TLS provider may carry known bugs; the GMS security provider exists to patch it. OWASP lists this under MASWE-0027 because a broken TLS library can mis-validate as surely as a broken trust manager.

## Impact

- **Compromise of sensitive data.** Everything sent over the affected connections can be read: credentials, session and refresh tokens, personal data, health and financial records, API keys returned by the backend.
- **Authentication and authorisation bypass.** Captured tokens and passwords let the attacker act as the user against the real backend, from anywhere, long after the network attack ends.
- **Integrity of what the app receives.** The attacker can alter responses: change account numbers or amounts shown to the user, inject JavaScript into WebView content, swap a downloaded configuration, feature flag or update, or feed the app data that leads to further client-side bugs.
- **Legal and regulatory exposure.** Interception of personal data is a reportable breach under UK GDPR and similar regimes; financial and health apps carry sector rules on top.

## Mitigations

- **Use the platform's validation.** On Android, the default `TrustManager` and `HostnameVerifier` used by `HttpsURLConnection`, OkHttp and the WebView; on iOS, the URL Loading System's default handling. Do not implement `checkServerTrusted()`, `HostnameVerifier` or authentication-challenge delegates unless you need to tighten trust.
- **Customise trust declaratively.** Private CAs, debug-only proxy CAs and pins go into Android's Network Security Configuration and iOS's `NSPinnedDomains`, not into code.
- **Verify hostnames on every TLS channel**, including raw `SSLSocket` and Network.framework connections where nothing does it for you.
- **Fail closed.** Any validation error ends the connection: `CertificateException` propagates, `handler.cancel()` is called, `.cancelAuthenticationChallenge` is returned. No user prompt; users cannot assess a certificate error.
- **Trust only system CAs in release builds**, keep `user` trust anchors inside `<debug-overrides>`, and do not support Android versions without Network Security Configuration unless you enforce trust yourself.
- **Keep the TLS stack current**: update the GMS security provider early, or bundle Conscrypt on devices without Google Play services.
- **Review third-party code** for its TLS settings, and add lint and CI checks that fail the build on known-bad patterns.

## Knowledge

OWASP links one Knowledge page to MASWE-0027, MASTG-KNOW-0072 (iOS server trust evaluation). Its second half covers pinning, which belongs to [MASWE-0028](/mobile/maswe-0028-insecure-identity-pinning/); we cover the validation half here. The Android tests rely on knowledge spread across several OWASP pages (exception handling, the security provider, the Network Security Configuration), so we add a supplementary Android section that gathers what you need about trust managers, hostname verifiers and CA stores, and a short section on the security provider. The Network Security Configuration file format itself is explained in our [cleartext traffic note](/mobile/maswe-0026-cleartext-network-traffic/); here we only cover its trust-anchor parts.

### Generic: what certificate validation actually checks (supplementary)

When a TLS client receives the server's certificate chain, correct validation answers two separate questions.

**Is this chain trustworthy?** (path validation, [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280))

- The chain builds from the leaf, through any intermediates, to a **trust anchor** the client already holds (the OS root store, plus whatever the app adds).
- Every signature in the chain verifies.
- Every certificate is inside its validity period.
- Intermediates are allowed to act as CAs (basic constraints, key usage) and the leaf is allowed for TLS server authentication (extended key usage `serverAuth`).
- Platform policy on top: minimum key sizes, signature algorithms, and on Apple platforms the App Transport Security requirements (covered in the [TLS versions note](/mobile/maswe-0026-insecure-tls-protocol-versions/)).
- Revocation is checked only partially or soft-fail by default on both platforms; treat it as a bonus, not a control you can rely on.

**Is it the certificate for the server I asked for?** (service identity, [RFC 9525](https://www.rfc-editor.org/rfc/rfc9525), which obsoletes RFC 6125)

- The hostname the client intended to reach must match a `dNSName` (or, for IP literals, an `iPAddress`) in the certificate's Subject Alternative Name. A wildcard covers exactly one left-most label: `*.example.com` matches `api.example.com`, not `example.com` or `a.b.example.com`. Matching against the subject Common Name is legacy behaviour that modern clients no longer rely on.

The two checks are independent and you need both. Path validation without hostname verification accepts any publicly trusted certificate for *any* domain, and anyone can get one of those for a domain they own in minutes through ACME. Hostname verification without path validation accepts a self-signed certificate that simply claims the right name. Either way the attacker wins, which is why "only" hostname verification being off is rated as seriously as trust-all.

Where each check lives matters for testing:

| Platform and API | Chain validation | Hostname verification |
|---|---|---|
| Android `HttpsURLConnection`, OkHttp, WebView | Default `X509TrustManager` (NSC-aware) | Default `HostnameVerifier` (OkHttp's verifier) / Chromium |
| Android raw `SSLSocket` | Default `X509TrustManager` if the default factory is used | **None** unless the app calls a verifier |
| iOS URL Loading System, `WKWebView` | `SecTrust` evaluation with the SSL policy | Same evaluation: the SSL policy carries the hostname |
| iOS Network.framework | `SecTrust` evaluation, unless a verify block overrides it | Same, unless the verify block or policy drops it |

### iOS: Server Trust Evaluation (MASTG-KNOW-0072)

Source: [MASTG-KNOW-0072](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-NETWORK/MASTG-KNOW-0072/). Pinning-specific parts (`NSPinnedDomains`, TrustKit, Alamofire evaluators, pinning in WebViews and native code) are covered in [MASWE-0028](/mobile/maswe-0028-insecure-identity-pinning/).

**The default.** When an app uses `URLSession` (or `WKWebView`) and does nothing special, the system evaluates the server's chain against the iOS trust store, checks the hostname, and applies App Transport Security's extra requirements on top. Apple's position, repeated in [Preventing Insecure Network Connections](https://developer.apple.com/documentation/security/preventing-insecure-network-connections), is that you should fix the server rather than loosen ATS or replace the evaluation. The trust store contains Apple's roots plus any root the user has installed through a configuration profile **and** explicitly enabled under *Settings > General > About > Certificate Trust Settings* ([Apple Support 102390](https://support.apple.com/en-us/102390)). Unlike Android, there is no per-app opt-out of user-enabled roots short of pinning, so iOS has no equivalent of the Android user-CA tests below.

**How an app takes over.** TLS server authentication reaches the app as an authentication challenge, a [`URLAuthenticationChallenge`](https://developer.apple.com/documentation/foundation/urlauthenticationchallenge) whose `protectionSpace.authenticationMethod` is `NSURLAuthenticationMethodServerTrust`. If the app implements one of these methods, the decision is handed to it:

| Method | Scope |
|---|---|
| [`urlSession(_:didReceive:completionHandler:)`](https://developer.apple.com/documentation/foundation/urlsessiondelegate/urlsession%28_:didreceive:completionhandler:%29) on `URLSessionDelegate` | Session-level challenges (server trust, client certificates) for every task in the session |
| `urlSession(_:task:didReceive:completionHandler:)` on `URLSessionTaskDelegate` | Per task; receives server-trust challenges when the session-level method is not implemented |
| [`webView(_:didReceive:completionHandler:)`](https://developer.apple.com/documentation/webkit/wknavigationdelegate/webview%28_:didreceive:completionhandler:%29) on `WKNavigationDelegate` | Challenges raised by a `WKWebView`'s loads |
| `connection(_:willSendRequestFor:)` on the deprecated `NSURLConnectionDelegate` | Legacy apps and old SDKs |

Swift's async variants (`urlSession(_:didReceive:) async`) are the same methods at the Objective-C level and land in the binary under the same selectors. Inside the method, the app reads `challenge.protectionSpace.serverTrust`, a `SecTrust` object that the system has already prepared with the server's chain and an SSL policy for the requested hostname, and it must call the completion handler with one of four dispositions:

| Disposition | Meaning |
|---|---|
| `.performDefaultHandling` | "I am not handling this one." The system evaluates as if the method did not exist. Safe. |
| `.useCredential` with `URLCredential(trust:)` | "I have decided this server is trusted." The connection proceeds on the app's word. Safe **only** after the app has evaluated the trust and it passed. |
| `.cancelAuthenticationChallenge` | Abort the connection. The correct answer to a failed evaluation. |
| `.rejectProtectionSpace` | Reject this protection space and let the system try the next one; rarely used for server trust. |

The important property, stated plainly by OWASP and worth repeating: **as soon as an app implements a challenge method and touches `URLAuthenticationChallenge`, it owns part of the trust decision**, whether or not the implementation is correct. Every such method is a review item.

**Evaluating trust correctly.** The current APIs are [`SecTrustEvaluateWithError`](https://developer.apple.com/documentation/security/sectrustevaluatewitherror%28_:_:%29) (iOS 12+, synchronous, returns `Bool` and a `CFError`) and `SecTrustEvaluateAsyncWithError` (iOS 13+, takes a queue and a callback). The older `SecTrustEvaluate` is deprecated since iOS 13 and is a source of bugs: its `OSStatus` return value only says whether evaluation *ran*; the verdict is in the separate `SecTrustResultType` (`.unspecified` or `.proceed` mean trusted; `.recoverableTrustFailure` and `.fatalTrustFailure` mean not). Code that checks only `== errSecSuccess` accepts everything.

Apple's guide [Performing Manual Server Trust Authentication](https://developer.apple.com/documentation/foundation/performing-manual-server-trust-authentication) describes the legitimate reasons to customise the evaluation: to **tighten** trust (pinning), or to **extend** it to a private CA or a development server's self-signed certificate, by adding anchors with `SecTrustSetAnchorCertificates` and then *still evaluating*. Extending trust correctly looks like this:

```swift
// Trust only our bundled private CA for this host, then evaluate normally
SecTrustSetAnchorCertificates(serverTrust, [internalCA] as CFArray)
SecTrustSetAnchorCertificatesOnly(serverTrust, true)
var error: CFError?
let trusted = SecTrustEvaluateWithError(serverTrust, &error)
completionHandler(trusted ? .useCredential : .cancelAuthenticationChallenge,
                  trusted ? URLCredential(trust: serverTrust) : nil)
```

**Pitfalls to look for in review** (each one is a MASWE-0027 finding when reachable):

- `.useCredential` with no evaluation at all (the OWASP demos for both tests).
- Evaluation performed but the result ignored, or a `do/catch` around it that falls through to `.useCredential`.
- No check of `authenticationMethod`, so the same branch answers server-trust and other challenge types.
- The hostname dropped from the policy: `SecTrustSetPolicies(serverTrust, SecPolicyCreateBasicX509())`, or [`SecPolicyCreateSSL(true, nil)`](https://developer.apple.com/documentation/security/secpolicycreatessl%28_:_:%29) where the hostname argument is `nil`. The chain is still checked, but any certificate from a trusted CA for any domain is accepted (CWE-297).
- "Validation" that compares the leaf's subject summary or common name with a string, or checks only the expiry date.
- Library switches: Alamofire's `DisabledTrustEvaluator`, or `DefaultTrustEvaluator(validateHost: false)`; AFNetworking's `AFSecurityPolicy` with `allowInvalidCertificates = YES` or `validatesDomainName = NO`.
- Lower layers: Network.framework's [`sec_protocol_options_set_verify_block`](https://developer.apple.com/documentation/security/sec_protocol_options_set_verify_block%28_:_:_:%29) whose block calls `complete(true)` unconditionally; CFStream's `kCFStreamSSLValidatesCertificateChain` set to `false`. ATS does not police these lower layers the way it does the URL Loading System, so nothing else will catch them.

### Android: Trust managers, hostname verifiers and CA stores (supplementary)

OWASP has no single Knowledge page for this; the tests link to [MASTG-KNOW-0010 (Exception Handling)](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0010/) and [MASTG-KNOW-0014 (Network Security Configuration)](https://mas.owasp.org/MASTG/knowledge/android/MASVS-NETWORK/MASTG-KNOW-0014/). This section is our own summary of the mechanisms, based on the Android developer documentation ([Security with network protocols](https://developer.android.com/privacy-and-security/security-ssl), [Network security configuration](https://developer.android.com/privacy-and-security/security-config) and the risk pages for [unsafe TrustManagers](https://developer.android.com/privacy-and-security/risks/unsafe-trustmanager) and [unsafe HostnameVerifiers](https://developer.android.com/privacy-and-security/risks/unsafe-hostname)).

#### X509TrustManager and checkServerTrusted

Android uses JSSE. An `SSLContext` is initialised with key managers (client certificates), trust managers (server validation) and a random source; every socket it produces asks its `X509TrustManager` to approve the server's chain during the handshake by calling `checkServerTrusted(chain, authType)`. The contract is simple: **return normally to accept, throw `CertificateException` to reject.** That makes an empty method body a trust-all implementation: nothing throws, so everything is accepted.

The platform's default trust manager comes from `TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())` initialised with a `null` `KeyStore`. On Android 7.0+ it is supplied by the Network Security Configuration provider (it shows up as `AndroidNSSP` at the top of `Security.getProviders()`), so it applies the app's `<trust-anchors>`, domain configs and pins. When an app builds its own `TrustManager`, all of that is bypassed for connections using it, including anything the NSC promised.

Insecure shapes you will meet in decompiled code:

| Pattern | Effect |
|---|---|
| Empty `checkServerTrusted` | Accepts everything |
| Body that only calls `chain[0].checkValidity()` | Accepts any certificate that is in date, self-signed included |
| Delegates to the platform manager inside `try/catch` that logs and continues | Accepts everything; the log line makes it look deliberate |
| Accepts if `chain.size == 1` or issuer DN contains a string | Accepts an attacker's self-signed certificate with that DN |
| `getAcceptedIssuers()` returns `null` or an empty array | Not a bypass on its own (the list mainly matters on the server side, when asking clients for certificates), but it almost always sits next to an empty `checkServerTrusted` |
| `SSLCertificateSocketFactory.getInsecure(...)` (deprecated in API 29) | Factory with all checks disabled |

How the trust manager reaches traffic: `SSLContext.init(null, arrayOf(tm), …)`, then `connection.sslSocketFactory = ctx.socketFactory` for one `HttpsURLConnection`, `HttpsURLConnection.setDefaultSSLSocketFactory(...)` for **every** `HttpsURLConnection` in the process, or `OkHttpClient.Builder().sslSocketFactory(factory, tm)` for an OkHttp client. When you find a bad trust manager, follow it to these calls: the blast radius is the set of clients that receive it.

Google Play scans for unsafe `X509TrustManager` implementations and `onReceivedSslError` handlers and warns or blocks uploads ([Google Play Help 6346016](https://support.google.com/faqs/answer/6346016), [7071387](https://support.google.com/faqs/answer/7071387)). The scan is pattern-based, so obfuscated or reflective variants get through, and apps distributed outside Play are not scanned at all.

#### HostnameVerifier

`javax.net.ssl.HostnameVerifier` has one method, `verify(hostname: String, session: SSLSession): Boolean`. `HttpsURLConnection` calls it after the handshake with the hostname from the URL; the default verifier (`HttpsURLConnection.getDefaultHostnameVerifier()`) checks that hostname against the leaf certificate's SANs. OkHttp has its own `OkHostnameVerifier` with the same semantics. A custom verifier replaces that check.

Insecure verifiers are usually one of these:

- `return true` (or a lambda `{ _, _ -> true }`), Apache's `AllowAllHostnameVerifier` / `SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER`, or `NoopHostnameVerifier` from Apache HttpClient 4.4+.
- An allowlist on the `hostname` parameter (`hostname == "api.example.com"`, `hostname.endsWith("example.com")`). The parameter is the host the app *asked for*, not what the certificate says, so this returns `true` whatever certificate the attacker presents.
- `session.peerHost == hostname`: also compares the request with itself.
- Hand-written wildcard matching that is too broad, or that falls back to `true` when parsing the certificate throws.

`HttpsURLConnection.setDefaultHostnameVerifier(...)` is process-wide, like the default socket factory.

#### SSLSocket does not verify hostnames

Raw `SSLSocket` is used for custom protocols (MQTT, XMPP, proprietary binary protocols, some SDKs' telemetry). The Android documentation [warns explicitly](https://developer.android.com/privacy-and-security/security-ssl#WarningsSslSocket) that `SSLSocket` does **not** perform hostname verification; it is the caller's job to call a `HostnameVerifier` on the session after the handshake and close the socket if it fails.

A nuance OWASP's wording blurs: the OWASP test says the connection succeeds "because `SSLSocket` is not affected by" the Network Security Configuration. A socket from `SSLSocketFactory.getDefault()` is built on the platform's default `SSLContext`, whose trust manager comes from the NSC-aware provider (`AndroidNSSP`), so the chain is still validated. That is also why the OWASP demo uses `wrong.host.badssl.com`, whose chain is valid: the only thing wrong is the name. What the NSC cannot add is hostname verification, because that is not part of the trust manager's job. So the precise statement is: a perfect NSC does not save an `SSLSocket` that never verifies the hostname. Cleartext rules in the NSC, on the other hand, do not apply to raw sockets at all.

#### WebViewClient.onReceivedSslError

A `WebView` validates certificates itself (it is Chromium). When it hits a recoverable certificate error it calls the app's [`WebViewClient.onReceivedSslError(view, handler, error)`](https://developer.android.com/reference/android/webkit/WebViewClient#onReceivedSslError%28android.webkit.WebView,%20android.webkit.SslErrorHandler,%20android.net.http.SslError%29). The default implementation cancels the load. An override must call either `handler.cancel()` or `handler.proceed()`; Android's guidance is that apps should never call `proceed()`, and that prompting the user is not a fix either, because users cannot judge a certificate error. The decision may also be remembered for later errors in the same WebView, so one `proceed()` can cover more than one load.

`SslError` carries a set of errors and a "primary" one: `SSL_NOTYETVALID` (0), `SSL_EXPIRED` (1), `SSL_IDMISMATCH` (2), `SSL_UNTRUSTED` (3), `SSL_DATE_INVALID` (4), `SSL_INVALID` (5). `getPrimaryError()` returns only the most severe; `hasError(code)` tests for a specific one. Logic such as "proceed unless the primary error is `SSL_UNTRUSTED`" lets an attacker's wrong-host or expired certificate through, and "proceed if the primary error is `SSL_IDMISMATCH`" is the WebView equivalent of an accept-all hostname verifier. The legacy MASTG test also notes that older Apache Cordova versions proceeded on SSL errors in debuggable builds, one more reason to check `android:debuggable` in release.

#### User versus system CA stores, and the targetSdk 24 change

Android keeps two root stores:

| Store | Location | Who can change it |
|---|---|---|
| System | `/system/etc/security/cacerts/` up to Android 13; from Android 14 the Conscrypt APEX at `/apex/com.android.conscrypt/cacerts/`, updatable through Google Play system updates | OEM / Google; a rooted user |
| User | `/data/misc/user/0/cacerts-added/` (per Android user) | Any user, through *Settings > Security > Encryption & credentials > Install a certificate* (path varies by OEM); MDM / device owner |

You can see both under *Trusted credentials* (System and User tabs). From code, the `AndroidCAStore` key store lists them with `system:` and `user:` alias prefixes.

Which store an app trusts depends on its **targetSdkVersion** and on the **device's** Android version:

- **Android 7.0 (API 24) and higher, app targets API 24+**: by default the app trusts **system CAs only**. User-installed CAs, including your proxy CA and anything a user was talked into installing, are ignored. This is the change that made interception testing harder in 2016 and closed off "install this profile to use our Wi-Fi" attacks.
- **Android 7.0+, app targets API 23 or lower**: the old default applies and the app trusts system **and** user CAs.
- **Android 6.0 (API 23) and lower, any app**: there is no Network Security Configuration at all; every app trusts system and user CAs unless it enforces its own trust in code.
- **Any app with an NSC that lists `<certificates src="user"/>`** in `<base-config>` or a `<domain-config>`: user CAs are trusted for those connections, overriding the default. Inside `<debug-overrides>` the same element applies only when the app is debuggable, which is the intended way to test with a proxy.

Since Android 11 an app can no longer prompt the user to install a CA certificate through `KeyChain.createInstallIntent()`; the user has to go to Settings and do it manually, behind a screen lock. That raises the bar for social-engineering a malicious CA onto the device, but MDM and device-owner apps can still install CAs silently, and corporate TLS-inspection CAs are common on managed devices.

NSC trust anchors also support `src="@raw/<file>"` for a bundled CA. That is the right way to trust a private CA, and a finding when the bundled file is a debugging proxy's root (check its subject with `openssl x509 -in res/raw/<file> -noout -subject -issuer`). Pins and the `overridePins` attribute are covered in [MASWE-0028](/mobile/maswe-0028-insecure-identity-pinning/); the rest of the file format is in our [cleartext note](/mobile/maswe-0026-cleartext-network-traffic/).

#### Cross-platform and third-party stacks

| Stack | Validation-killer to grep for |
|---|---|
| OkHttp / Retrofit | `.sslSocketFactory(factory, trustAll)`, `.hostnameVerifier { _, _ -> true }`, "unsafe" client builder helpers |
| Apache HttpClient (legacy, or repackaged) | `ALLOW_ALL_HOSTNAME_VERIFIER`, `AllowAllHostnameVerifier`, `NoopHostnameVerifier`, `TrustSelfSignedStrategy`, `TrustAllStrategy` |
| Volley / custom `HurlStack` | Constructor taking an `SSLSocketFactory` built from a trust-all context |
| Flutter (Dart `HttpClient`) | `badCertificateCallback` returning `true`; Dart's stack ignores the NSC and the system proxy |
| React Native | Custom `OkHttpClientFactory` in Java/Kotlin with the OkHttp patterns above |
| .NET MAUI / Xamarin | `ServerCertificateCustomValidationCallback` returning `true`, `HttpClientHandler.DangerousAcceptAnyServerCertificateValidator` |
| Cordova / Ionic plugins | `cordova-plugin-advanced-http` server trust mode `nocheck`; `onReceivedSslError` overrides in plugin code |
| Unity | A `CertificateHandler` subclass whose `ValidateCertificate` returns `true` |

### Android: Security Provider (MASTG-KNOW-0011)

Source: [MASTG-KNOW-0011](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0011/).

Java security services on Android, TLS included, come from `java.security.Provider` implementations registered in priority order; the TLS one is Conscrypt (`AndroidOpenSSL`), backed by BoringSSL. The device's copy is only as current as the device's updates. Two mechanisms keep it fresh independently of OEMs:

- **Google Play services' provider.** [`ProviderInstaller`](https://developer.android.com/privacy-and-security/security-gms-provider) (`com.google.android.gms.security.ProviderInstaller`) installs a Play-services-maintained provider, `GmsCore_OpenSSL`, at the top of the provider list for the calling app's process. `installIfNeeded(context)` is synchronous and throws `GooglePlayServicesRepairableException` (Play services out of date or disabled; the user can fix it) or `GooglePlayServicesNotAvailableException` (cannot be fixed, e.g. no Play services). `installIfNeededAsync(context, listener)` reports through `ProviderInstallListener.onProviderInstalled()` and `onProviderInstallFailed(errorCode, recoveryIntent)`. It must run before the first TLS connection, typically in `Application.onCreate()` or on a background thread at start-up.
- **Conscrypt as a Mainline module.** From Android 10, Conscrypt is an updatable APEX module delivered through Google Play system updates, and from Android 14 the system CA store moved into it as well. On those versions the platform provider is patched without OEM involvement, which reduces (but does not remove) the value of `ProviderInstaller`.

Devices without Google Play services (some regional builds, AOSP-based tablets, Huawei devices) get neither; OWASP's advice for them is to bundle Conscrypt (`org.conscrypt:conscrypt-android`) and register it with `Security.insertProviderAt(Conscrypt.newProvider(), 1)`.

## Tests

OWASP links nine tests to MASWE-0027: seven Android and two iOS, all static. They replace these legacy (MASTG v1) tests:

| Legacy test | Replaced by |
|---|---|
| [MASTG-TEST-0021](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0021/) Testing Endpoint Identify Verification (Android) | MASTG-TEST-0282, 0283, 0284, 0285, 0286 (and 0234, which OWASP does not list but which covers the `SSLSocket` part) |
| [MASTG-TEST-0023](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0023/) Testing the Security Provider (Android) | MASTG-TEST-0295 |
| [MASTG-TEST-0067](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0067/) Testing Endpoint Identity Verification (iOS) | MASTG-TEST-0396, 0397 (and the ATS tests 0322 and 0342, covered in the [cleartext](/mobile/maswe-0026-cleartext-network-traffic/) and [TLS versions](/mobile/maswe-0026-insecure-tls-protocol-versions/) notes) |

The legacy tests had a dynamic half that the new ones dropped. We restore it as [GT-0027-1](#gt-0027-1-proving-it-on-the-wire-with-an-untrusted-ca-and-a-wrong-hostname-certificate-android-and-ios), because a static hit is a candidate and the proxy test is what turns it into a finding you can rate. [GT-0027-2](#gt-0027-2-other-tls-stacks-and-cross-platform-frameworks-android-and-ios) covers stacks the OWASP tests do not reach.

### Before you start: static triage of the whole app

One pass over the decompiled app finds candidates for all the Android tests at once.

```bash
# Pull every split of the installed app (base + config splits)
adb shell pm path com.example.app
adb pull /data/app/~~XXXX/com.example.app-YYYY/base.apk

# Code (jadx) and resources/manifest (apktool)
jadx -d out base.apk
apktool d base.apk -o apk_out

# Everything TLS-related in app code; leave out framework packages you trust
grep -rnE 'X509(Extended)?TrustManager|checkServerTrusted|HostnameVerifier|ALLOW_ALL_HOSTNAME|NoopHostnameVerifier|getInsecure\(|setDefaultSSLSocketFactory|setDefaultHostnameVerifier|sslSocketFactory\(|hostnameVerifier\(|createSocket\(|onReceivedSslError|badCertificateCallback|ProviderInstaller' \
    out/sources/ | grep -vE '^out/sources/(androidx|kotlin|kotlinx)/' > tls-hits.txt
wc -l tls-hits.txt
```

Group the hits by package. Library packages (`okhttp3`, `com.android.volley`, an analytics SDK) tell you which third-party code to look at; your client's own packages are where the decisions are made. If the app is obfuscated, class names will not help, but interface names (`X509TrustManager`), method names inherited from the platform (`checkServerTrusted`, `verify`, `onReceivedSslError`) and string constants survive R8.

For iOS, extract and check the app, then list every Mach-O binary, because SDK frameworks make their own connections:

```bash
unzip -q App.ipa -d ipa
otool -l ipa/Payload/App.app/App | grep -A4 LC_ENCRYPTION_INFO   # cryptid 0 = decrypted
find ipa/Payload/App.app -type f | while read -r f; do
  file "$f" | grep -q 'Mach-O' && echo "$f"
done > macho.txt
```

### MASTG-TEST-0282: Unsafe Custom Trust Evaluation (Android)

Source: [MASTG-TEST-0282](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0282/). Platform: Android. Type: static (code) with manual review. Related knowledge: MASTG-KNOW-0010. Best practice: MASTG-BEST-0021.

#### Overview

The test looks for custom `X509TrustManager` implementations whose `checkServerTrusted(...)` does not properly reject bad chains: empty bodies, `checkValidity()`-only checks, swallowed exceptions, self-signed shortcuts. Any connection built on such a trust manager accepts a certificate the attacker generated themselves. OWASP also flags the use of `checkServerTrusted(...)` at all where an NSC would do: a custom trust manager that *is* correct is still error-prone and bypasses the NSC, so note it even when it passes.

#### Prerequisites

- The APK, decompiled with jadx ([MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0017](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0017/)).
- semgrep ([MASTG-TOOL-0110](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/)) with the OWASP rule, or grep.
- jadx-gui for code review ([MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)) and, for confirmation, a device with Frida.

#### Steps

1. **Find every trust manager** ([MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)):

   ```bash
   grep -rnE 'implements X509TrustManager|extends X509ExtendedTrustManager|new X509TrustManager\(\)|checkServerTrusted\(' out/sources/
   semgrep -c mastg-android-network-checkservertrusted.yml out/sources/
   ```

   The OWASP rule matches every `public void checkServerTrusted(...)` implementation, correct or not; it is a locator, not a verdict.

2. **Read each implementation** in jadx-gui. The questions are: can this method return normally for a chain that does not reach a trusted root? Does every failure path throw? Is anything caught and swallowed? Does it delegate to the platform trust manager, and if so, is that call outside any `try/catch` that continues?

3. **Follow it to the sockets.** Right-click the class, *Find Usage*, and trace to `SSLContext.init(...)`, then to `setSSLSocketFactory`, `setDefaultSSLSocketFactory`, or `OkHttpClient.Builder.sslSocketFactory`. Note which clients and which hosts use it, and whether the path is gated by a build flag, a remote-config value or a debug menu (see [Telling live code from dead code](#telling-live-code-from-dead-code)).

4. **Confirm at runtime** which trust managers the app installs, with a Frida hook on `SSLContext.init`:

   ```javascript
   // tm-trace.js — log every TrustManager passed to SSLContext.init, with a stack trace
   Java.perform(() => {
     const SSLContext = Java.use('javax.net.ssl.SSLContext');
     const Log = Java.use('android.util.Log');
     const Exception = Java.use('java.lang.Exception');
     SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom')
       .implementation = function (km, tms, sr) {
         if (tms !== null) {
           for (let i = 0; i < tms.length; i++) {
             console.log('[SSLContext.init] TrustManager: ' + tms[i].$className);
           }
         }
         console.log(Log.getStackTraceString(Exception.$new()));
         return this.init(km, tms, sr);
       };
   });
   ```

   ```bash
   frida -U -f com.example.app -l tm-trace.js
   ```

   A trust manager from your list appearing here, with a stack trace leading to the app's API client, means the code path is live. Then prove the impact with [GT-0027-1](#gt-0027-1-proving-it-on-the-wire-with-an-untrusted-ca-and-a-wrong-hostname-certificate-android-and-ios), step 1.

#### Observation

The list of `checkServerTrusted` implementations with file and line, the decompiled body of each, the call chain to the HTTP clients that use it, the Frida output showing it installed at runtime, and the proxy evidence.

#### Evaluation

The test **fails** if a custom `X509TrustManager` used for the app's connections can return from `checkServerTrusted(...)` without throwing for a chain that the platform trust manager would reject: empty body, validity-only check, swallowed `CertificateException`, chain-length or DN-string shortcut, or acceptance of self-signed certificates in a release build.

It **passes** if there is no custom trust manager, or if the custom one first calls the platform trust manager (or a correctly initialised one with a private CA keystore), lets its exceptions propagate, and only *adds* checks. A passing custom trust manager that does nothing an NSC could not do is still worth an observation recommending the NSC.

#### Demo

[MASTG-DEMO-0054](https://mas.owasp.org/MASTG/demos/android/MASVS-NETWORK/MASTG-DEMO-0054/MASTG-DEMO-0054/). The sample connects to a host with an expired certificate (OWASP uses `tlsexpired.no`; `expired.badssl.com` from [badssl](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0143/) behaves the same) through a trust-all manager:

```kotlin
val trustAllCerts = arrayOf<TrustManager>(
    object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {} // accepts anything
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }
)
val sslContext = SSLContext.getInstance("TLS")
sslContext.init(null, trustAllCerts, SecureRandom())
connection.sslSocketFactory = sslContext.socketFactory
```

semgrep finds the empty method in the decompiled code:

```text
MastgTest_reversed.java
❯❱ rules.mastg-android-network-checkservertrusted
      Improper Server Certificate verification detected.
       92┆ @Override // javax.net.ssl.X509TrustManager
       93┆ public void checkServerTrusted(X509Certificate[] chain, String authType) {
       94┆ }
```

The request succeeds. Without the custom trust manager the platform rejects it with `java.security.cert.CertPathValidatorException: Trust anchor for certification path not found.` The test fails: the method body never throws.

### MASTG-TEST-0283: Incorrect Implementation of Server Hostname Verification (Android)

Source: [MASTG-TEST-0283](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0283/). Platform: Android. Type: static (code) with manual review.

#### Overview

The test looks for `HostnameVerifier` implementations that do not compare the certificate with the hostname: unconditional `true`, allowlists on the hostname parameter, over-broad wildcard logic, and channels where verification is never invoked. With hostname verification off, any certificate from any publicly trusted CA is accepted, and an attacker can get one for a domain they control.

#### Prerequisites

- Decompiled APK; semgrep with the OWASP rule; jadx-gui.
- For confirmation, a device that trusts your proxy CA in the **system** store (rooted device or emulator; see the [interception lab](/mobile/mobile-traffic-interception-lab/)), so that the wrong-hostname certificate passes chain validation and only hostname verification is tested.

#### Steps

1. **Locate verifiers and the places they are installed:**

   ```bash
   grep -rnE 'implements HostnameVerifier|new HostnameVerifier\(\)|setHostnameVerifier|setDefaultHostnameVerifier|hostnameVerifier\(|ALLOW_ALL_HOSTNAME_VERIFIER|AllowAllHostnameVerifier|NoopHostnameVerifier' out/sources/
   semgrep -c mastg-android-network-hostname-verification.yml out/sources/
   ```

   The OWASP rule matches anonymous `new HostnameVerifier() {...}` classes only. Kotlin lambdas usually decompile to that shape (or to a synthetic `$$ExternalSyntheticLambda` class that implements the interface), but named classes and Apache constants need the grep.

2. **Read each `verify(...)`.** It should end in a call to the default verifier (`HttpsURLConnection.getDefaultHostnameVerifier().verify(hostname, session)` or `OkHostnameVerifier`) or in a comparison against the certificate's SANs (`session.peerCertificates[0]` cast to `X509Certificate`, `subjectAlternativeNames`). Anything that only reads `hostname`, or that returns `true` from a `catch`, fails.

3. **Check coverage**: list every `SSLSocket` and non-HTTP TLS channel (see [MASTG-TEST-0234](#mastg-test-0234-missing-implementation-of-server-hostname-verification-with-sslsockets-android)) and confirm a verifier is invoked on each.

4. **Confirm with a wrong-hostname certificate** ([GT-0027-1](#gt-0027-1-proving-it-on-the-wire-with-an-untrusted-ca-and-a-wrong-hostname-certificate-android-and-ios), step 2). If the app also has a trust-all manager, the untrusted-CA step already succeeds and the hostname bug is a second, separate finding.

#### Observation

Verifier implementations with their code, where each is installed, the hosts it covers, and the proxy evidence from the wrong-hostname run.

#### Evaluation

The test **fails** if any `HostnameVerifier` used by the app can return `true` when the certificate does not match the hostname: unconditional acceptance, decisions based only on the `hostname` argument, wildcard logic that matches unintended names, or exceptions mapped to `true`. It also fails if a TLS channel the app uses has no hostname verification at all.

It **passes** if the app uses the default verifiers, or a custom verifier that delegates to the default one and only adds restrictions.

#### Demo

[MASTG-DEMO-0055](https://mas.owasp.org/MASTG/demos/android/MASVS-NETWORK/MASTG-DEMO-0055/MASTG-DEMO-0055/). The sample connects to a host whose certificate has a non-matching SAN, with a verifier that logs and accepts:

```kotlin
connection.hostnameVerifier = HostnameVerifier { hostname, _ ->
    Log.w("HOSTNAME_VERIFIER", "Insecurely allowing host: $hostname")
    true
}
```

jadx turns the lambda into an anonymous class that calls a synthetic method, which is what the rule reports:

```text
❯❱ rules.mastg-android-network-hostname-verification
      Improper server hostname verification detected
       69┆ connection.setHostnameVerifier(new HostnameVerifier() { // from class:
           org.owasp.mastestapp.MastgTest$$ExternalSyntheticLambda0
       71┆     public final boolean verify(String str, SSLSession sSLSession) {
       72┆         return MastgTest.fetchUrl$lambda$1(str, sSLSession);
```

Following `fetchUrl$lambda$1` shows `return true;` after the log call. The test fails. Note that the OWASP sample *also* installs a trust-all manager (so it can reach its test host), which means the demo connection would succeed even with a correct verifier; in a real app, keep the two findings separate and prove each with its own proxy step.

### MASTG-TEST-0234: Missing Implementation of Server Hostname Verification with SSLSockets (Android)

Source: [MASTG-TEST-0234](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0234/). Platform: Android. Type: static (code).

#### Overview

The test looks for `SSLSocket` connections where the app never calls a `HostnameVerifier`. `SSLSocket` validates the chain with the default trust manager but does not check the hostname, so a certificate from a trusted CA for any other domain is accepted.

#### Prerequisites

- Decompiled APK; semgrep with the OWASP rule; jadx-gui.
- Optionally Frida, to confirm which hosts the sockets connect to.

#### Steps

1. **Find socket creation and verifier calls:**

   ```bash
   grep -rnE 'SSLSocketFactory|createSocket\(|startHandshake\(|getDefaultHostnameVerifier|\.verify\(' out/sources/
   semgrep -c mastg-android-ssl-socket-hostnameverifier.yml out/sources/
   ```

   The OWASP rule reports both sides (`SSLSocketFactory.getDefault()`, `createSocket(...)`, `getDefaultHostnameVerifier()`, `.verify(...)`); the finding is a socket path with no verifier call on it.

2. **For each socket**, read the method in jadx: after `startHandshake()` (or the first read/write, which triggers the handshake), is `verify(host, socket.session)` called, and does a `false` result close the socket and abort before any data is sent?

3. **Check alternatives**: `SSLParameters.setEndpointIdentificationAlgorithm("HTTPS")` set on the socket before the handshake also enables hostname checking in JSSE implementations that support it. If you see it instead of a `HostnameVerifier`, confirm the behaviour on the target Android versions with the wrong-hostname proxy step rather than assuming.

4. **Identify the host and protocol** each socket talks to (Frida on `javax.net.ssl.SSLSocketFactory.createSocket` overloads, or the strings in the code), so you can rate by data sensitivity and intercept it with the [lab's](/mobile/mobile-traffic-interception-lab/) transparent mode; raw sockets ignore the HTTP proxy setting.

#### Observation

Each `SSLSocket` use with its target host, the presence or absence of hostname verification and its result handling, and any wrong-hostname interception evidence.

#### Evaluation

The test **fails** if the app uses `SSLSocket` (directly or through a library) without verifying the hostname, or verifies it but continues when verification returns `false`. It **passes** if every socket path verifies the hostname and aborts on failure. If a `HostnameVerifier` is present, also apply [MASTG-TEST-0283](#mastg-test-0283-incorrect-implementation-of-server-hostname-verification-android) to it.

#### Demo

[MASTG-DEMO-0048](https://mas.owasp.org/MASTG/demos/android/MASVS-NETWORK/MASTG-DEMO-0048/MASTG-DEMO-0048/) (fail) and [MASTG-DEMO-0049](https://mas.owasp.org/MASTG/demos/android/MASVS-NETWORK/MASTG-DEMO-0049/MASTG-DEMO-0049/) (pass). Both connect to `wrong.host.badssl.com`, whose certificate is valid but issued for a different name. The failing one:

```kotlin
val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
val socket = factory.createSocket("wrong.host.badssl.com", 443) as SSLSocket
socket.startHandshake()               // chain is fine, so this succeeds
socket.outputStream.write(request)    // no hostname check: data goes to the wrong server
```

semgrep reports the socket creation and no verifier:

```text
❱ rules.mastg-android-ssl-socket-hostnameverifier
     35┆ SocketFactory socketFactory = SSLSocketFactory.getDefault();
     37┆ SSLSocketFactory sslSocketFactory = (SSLSocketFactory) socketFactory;
     38┆ Socket createSocket = sslSocketFactory.createSocket("wrong.host.badssl.com", 443);
```

The passing demo adds the check after the handshake, and the scan now also reports lines 49 and 61 (`getDefaultHostnameVerifier()` and `verify(...)`):

```kotlin
val verifier = HttpsURLConnection.getDefaultHostnameVerifier()
if (!verifier.verify(host, socket.session)) {
    throw SSLException("Hostname verification failed for host: $host")
}
```

and logcat shows `javax.net.ssl.SSLException: Hostname verification failed for host: wrong.host.badssl.com`. The difference between the two outputs is exactly what you look for in a real app.

### MASTG-TEST-0284: Incorrect SSL Error Handling in WebViews (Android)

Source: [MASTG-TEST-0284](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0284/). Platform: Android. Type: static (code) with manual review. Related knowledge: MASTG-KNOW-0010. Best practice: MASTG-BEST-0021.

#### Overview

The test looks for `WebViewClient.onReceivedSslError(...)` overrides that call `handler.proceed()`, unconditionally or on weak conditions. That turns every certificate error in the WebView into a silent success, and since the WebView often hosts login pages, payment pages or authenticated content with cookies, the impact is usually the same as a trust-all manager.

#### Prerequisites

- Decompiled APK; semgrep with the OWASP rule; jadx-gui.
- A device with the app installed and logcat ([MASTG-TECH-0009](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0009/)), for confirmation.

#### Steps

1. **Find overrides:**

   ```bash
   grep -rn 'onReceivedSslError' out/sources/ | grep -v '^out/sources/android/'
   semgrep -c mastg-android-network-onreceivedsslerror.yml --max-lines-per-finding 15 out/sources/
   ```

2. **Read each override** and classify it:
   - `handler.proceed()` with no condition: fails.
   - `proceed()` gated on `getPrimaryError()` (for example "not `SSL_UNTRUSTED`", or "is `SSL_IDMISMATCH`"): fails; the primary error hides the rest, and each accepted class is attacker-reachable.
   - `proceed()` gated on `BuildConfig.DEBUG` or a debuggable check: check the release manifest (`android:debuggable`) and whether the constant was folded away; a runtime flag is reachable.
   - A dialog asking the user whether to continue: fails (Android guidance and Google Play policy both say cancel).
   - `try { … } catch (…) { }` with no `cancel()` on the exception path: fails if the WebView can continue.
   - `handler.cancel()` only, or `super.onReceivedSslError(...)`: passes.

3. **Check which WebViews use the client**: follow `setWebViewClient(...)` to the activities and the URLs they load, including deep-link-driven loads.

4. **Confirm**: load the WebView through the untrusted-CA proxy ([GT-0027-1](#gt-0027-1-proving-it-on-the-wire-with-an-untrusted-ca-and-a-wrong-hostname-certificate-android-and-ios), step 1) and watch the page render and logcat show the error being overridden.

#### Observation

Each override with its decision logic, the WebViews and URLs it covers, logcat output and proxy evidence.

#### Evaluation

The test **fails** if any reachable `onReceivedSslError` override can call `proceed()` for a certificate error in a release build, whether unconditionally, on a primary-error condition, after a user prompt, or through an exception path that never calls `cancel()`. It **passes** if there is no override or every path calls `cancel()`.

#### Demo

[MASTG-DEMO-0056](https://mas.owasp.org/MASTG/demos/android/MASVS-NETWORK/MASTG-DEMO-0056/MASTG-DEMO-0056/). The WebView loads a site with an expired certificate and the client logs the error, then proceeds:

```kotlin
webViewClient = object : WebViewClient() {
    override fun onReceivedSslError(view: WebView, handler: SslErrorHandler, error: SslError) {
        Log.e("MastgTestWebView", "SSL errors onReceivedSslError: ${getSslErrorMessage(error)}")
        handler.proceed()   // every certificate error accepted
    }
}
```

semgrep shows the whole method, ending in `handler.proceed();` (line 35). Logcat confirms the error was seen and overridden:

```text
[ERROR:ssl_client_socket_impl.cc(877)] handshake failed; returned -1, SSL error code 1, net_error -201
SSL errors onReceivedSslError: The date of the certificate is invalid.
primary error: 4 certificate: Issued to: ... CN=tlsexpired.no; ... on URL: https://tlsexpired.no/
```

`net_error -201` is Chromium's `ERR_CERT_DATE_INVALID` and primary error 4 is `SSL_DATE_INVALID`. The page loads anyway. The test fails.

### MASTG-TEST-0286: Network Security Configuration Allowing Trust in User-Provided CAs (Android)

Source: [MASTG-TEST-0286](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0286/). Platform: Android. Type: static (config). Related knowledge: MASTG-KNOW-0014.

#### Overview

The test checks whether the app's Network Security Configuration explicitly re-enables trust in user-installed CAs with `<certificates src="user"/>`, undoing the protection apps targeting API 24+ get by default. Validation is still performed, but against a larger set of roots that includes anything installed on the device by the user, an MDM, or someone with the unlocked phone.

#### Prerequisites

- The decoded manifest and `res/xml/` from apktool ([MASTG-TECH-0117](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/)).
- semgrep with the OWASP rule; `yq` or `xmllint` optional ([MASTG-TECH-0150](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0150/), [MASTG-TECH-0151](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0151/)).

#### Steps

1. **Find the NSC** and confirm the release build is not debuggable:

   ```bash
   grep -oE 'android:(networkSecurityConfig|debuggable)="[^"]*"' apk_out/AndroidManifest.xml
   # android:networkSecurityConfig="@xml/network_security_config"
   ```

2. **List trust anchors in every scope:**

   ```bash
   NSC=apk_out/res/xml/network_security_config.xml
   grep -nE '<(base-config|domain-config|debug-overrides|domain |certificates|pin-set)' "$NSC"
   semgrep -c mastg-android-network-insecure-trust-anchors.yml "$NSC"
   ```

3. **Work out the effective trust per host.** A `<trust-anchors>` block in a `<domain-config>` *replaces* the inherited one for those domains; it is not merged. So decide, for each API host the app uses: which block applies, does it include `user`, does a `<pin-set>` apply (pins still constrain user CAs unless the `<certificates>` element has `overridePins="true"`), and is the entry inside `<debug-overrides>`?

4. **Check bundled anchors** referenced as `src="@raw/..."`, and identify them:

   ```bash
   openssl x509 -in apk_out/res/raw/extra_ca.pem -noout -subject -issuer -dates
   # (use -inform DER for .der/.cer files)
   ```

   A "PortSwigger CA" or "mitmproxy" subject in a release build is its own finding.

5. **Optional runtime confirmation**: with your proxy CA installed only in the *user* store, run the app through the proxy. If traffic to a host decrypts, user trust is effective for it.

#### Observation

The NSC content, the effective trust anchors for each relevant host, whether the app is debuggable, and any bundled CA identities.

#### Evaluation

The test **fails** if `<certificates src="user"/>` appears in `<base-config>` or in a `<domain-config>` that covers hosts the release app talks to. Scope it in the report: base config (every connection) versus named domains, and whether pinning still constrains it.

It **passes** if `user` appears only inside `<debug-overrides>` and the release build is not debuggable. That is the main false positive: the OWASP semgrep rule matches `<certificates src="user"` anywhere in the file, including inside `<debug-overrides>`, so always read the context of a hit.

#### Demo

[MASTG-DEMO-0057](https://mas.owasp.org/MASTG/demos/android/MASVS-NETWORK/MASTG-DEMO-0057/MASTG-DEMO-0057/). The app (minSdk 29, targetSdk 35) points its manifest at an NSC that adds user CAs to the base config:

```xml
<network-security-config>
    <base-config>
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
```

```text
network_security_config.xml
❯❱ rules.mastg-android-network-insecure-trust-anchors
      The network security config allows certificates imported on the user's behalf
       6┆ <certificates src="user" />
```

With the `mitm-software.badssl.com` root installed under *User credentials*, the app's `HttpsURLConnection` to that host succeeds; without the NSC entry it fails with `Trust anchor for certification path not found`. The test fails.

### MASTG-TEST-0285: Outdated Android Version Allowing Trust in User-Provided CAs (Android)

Source: [MASTG-TEST-0285](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0285/). Platform: Android. Type: static (config). Related knowledge: MASTG-KNOW-0014. OWASP marks it `deprecated_since: 24`: it only matters for apps that still run on Android 6.0 or lower.

#### Overview

The test checks whether the app can be installed on devices running API 23 or lower, where there is no Network Security Configuration and every app trusts user-installed CAs. OWASP reads this from `minSdkVersion`. We add a check OWASP's version leaves out: `targetSdkVersion` below 24 gives the same implicit user-CA trust on *modern* devices, because the default configuration is chosen by target SDK.

#### Prerequisites

- The APK, and `aapt2` or apktool ([MASTG-TECH-0117](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/), [MASTG-TECH-0150](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0150/)).

#### Steps

1. **Read both SDK levels:**

   ```bash
   aapt2 dump badging base.apk | grep -E "^(sdkVersion|targetSdkVersion)"
   # or, after apktool:
   grep -A2 sdkInfo apk_out/apktool.yml
   ```

2. **If `minSdkVersion` < 24**, check whether the app compensates on old devices: a custom trust manager restricted to system anchors (e.g. built from the `AndroidCAStore` aliases starting with `system:`), or pinning in code that does not depend on the NSC. Review any such code with [MASTG-TEST-0282](#mastg-test-0282-unsafe-custom-trust-evaluation-android) in mind.

3. **If `targetSdkVersion` < 24**, the app trusts user CAs on every device. Google Play's target-API requirements make this rare for store apps, but you will see it in enterprise, sideloaded and abandoned apps.

#### Observation

`minSdkVersion`, `targetSdkVersion`, and any compensating trust code.

#### Evaluation

The test **fails** if `minSdkVersion` is below 24 (OWASP's criterion). We also fail it if `targetSdkVersion` is below 24. It passes when both are 24 or higher, or when compensating code enforces system-only trust on older versions (record that as an observation instead).

#### Demo

OWASP has no demo for this test; this is ours. A legacy build:

```text
$ aapt2 dump badging base.apk | grep -E "^(sdkVersion|targetSdkVersion)"
sdkVersion:'21'
targetSdkVersion:'34'
```

The app installs on Android 5.0 to 6.0 devices, where a user-installed CA is trusted for all its HTTPS traffic. The test fails on `minSdkVersion`; on Android 7+ devices the app is protected by its target SDK. Rate it by the share of supported devices on Android 6 or older, which for most apps today is negligible.

### MASTG-TEST-0295: GMS Security Provider Not Updated (Android)

Source: [MASTG-TEST-0295](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0295/). Platform: Android. Type: static (code). Related knowledge: MASTG-KNOW-0011, MASTG-KNOW-0010. Best practice: MASTG-BEST-0020.

#### Overview

The test checks that the app updates the security provider through Google Play services before making TLS connections, and handles failure properly. A provider that is never updated leaves the app relying on whatever TLS library the device shipped with, including on devices that stopped receiving updates years ago.

#### Prerequisites

- Decompiled APK; jadx-gui.
- A device with Google Play services and Frida, for the runtime check.

#### Steps

1. **Find the call** and its error handling:

   ```bash
   grep -rnE 'ProviderInstaller|installIfNeeded(Async)?|ProviderInstallListener|onProviderInstallFailed|GooglePlayServices(Repairable|NotAvailable)Exception' out/sources/
   ```

2. **Read the context** in jadx:
   - Where is it called? `Application.onCreate()`, a start-up initialiser, or the first network layer setup is right; a settings screen is not.
   - Synchronous: are both exceptions caught, and does the catch do something (show the Play services resolution, fall back to bundled Conscrypt, mark the session as degraded), or is it empty?
   - Asynchronous: does `onProviderInstallFailed` handle `errorCode`/`recoveryIntent`, and does the app wait for `onProviderInstalled` before its first connection?

3. **Check at runtime** that the GMS provider is first in the list after start-up:

   ```javascript
   // providers.js
   Java.perform(() => {
     const providers = Java.use('java.security.Security').getProviders();
     for (let i = 0; i < providers.length; i++) {
       console.log(i + ': ' + providers[i].getName() + ' (' + providers[i].getInfo() + ')');
     }
   });
   ```

   ```bash
   frida -U -n "Example App" -l providers.js    # attach after the app has made its first request
   ```

   `0: GmsCore_OpenSSL` means the update ran. If R8 renamed the Play services classes so grep found nothing, this runtime check is your evidence.

#### Observation

The call site(s), the exception or listener handling, the timing relative to the first connection, and the runtime provider list.

#### Evaluation

The test **fails** if the app never calls `ProviderInstaller`, calls it after network connections have started, or ignores its failure (empty catch, no listener handling). It passes when the provider is updated early and failures lead to a defined behaviour. Consider the device population: with `minSdkVersion` 29 or higher, Conscrypt is updated through Mainline anyway and this finding is informational.

#### Demo

OWASP has no demo for this test; this is ours. A failing start-up:

```kotlin
class App : Application() {
    override fun onCreate() {
        super.onCreate()
        try {
            ProviderInstaller.installIfNeeded(this)
        } catch (e: Exception) {
            // ignored: app continues with the device's provider
        }
        ApiClient.init(this)
    }
}
```

The grep shows a single `installIfNeeded` call in `App.onCreate` with a catch-all whose body jadx renders empty. The test fails on error handling; the fix is in [MASTG-BEST-0020](#mastg-best-0020-update-the-gms-security-provider) below.

### MASTG-TEST-0396: References to URLSessionDelegate Bypassing Certificate Validation (iOS)

Source: [MASTG-TEST-0396](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0396/). Platform: iOS. Type: static (code) with manual review. Related knowledge: MASTG-KNOW-0072. Best practice: MASTG-BEST-0073.

#### Overview

The test looks for `URLSessionDelegate` (session-level) and `URLSessionTaskDelegate` (task-level) challenge handlers that call `completionHandler(.useCredential, URLCredential(trust: serverTrust))` without first evaluating the trust successfully. OWASP's heuristic is to list every handler and every caller of `SecTrustEvaluateWithError`, and treat a handler with no cross-reference to it as the prime suspect. The heuristic cuts both ways: a handler that calls the function can still ignore its result, and a handler may legitimately use `SecTrustEvaluateAsyncWithError` instead. Every handler gets read.

#### Prerequisites

- A decrypted IPA ([MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/)).
- radare2 ([MASTG-TOOL-0073](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/)) for the OWASP script ([MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/)); a disassembler with a decompiler view for review ([MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/)).
- For confirmation, a device with Frida and the proxy set-up from the [lab](/mobile/mobile-traffic-interception-lab/).

#### Steps

1. **Quick look across all binaries** (main app and frameworks):

   ```bash
   while read -r b; do
     echo "== $b"
     strings -a "$b" | grep -E 'URLSession:(task:)?didReceiveChallenge:completionHandler:|allowInvalidCertificates|validatesDomainName|DisabledTrustEvaluator' | sort -u
     rabin2 -i "$b" 2>/dev/null | grep -E 'SecTrustEvaluate|SecPolicyCreate(SSL|BasicX509)|SecTrustSetPolicies'
   done < macho.txt
   ```

   A binary containing the delegate selector but importing no `SecTrustEvaluate*` function is your first target.

2. **Run the OWASP radare2 script** on each candidate binary:

   ```text
   e scr.color=false
   e asm.bytes=false
   ?e Custom authentication-challenge handlers:
   is~NSURLAuthenticationChallenge
   ?e Accessors into the protection space:
   is~protectionSpace,serverTrust
   ?e Uses of SecTrustEvaluateWithError:
   is~SecTrustEvaluateWithError
   ?e xrefs to SecTrustEvaluateWithError:
   axt @ sym.imp.SecTrustEvaluateWithError
   ```

   ```bash
   r2 -q -i auth_challenge.r2 -A ipa/Payload/App.app/App > output.txt
   ```

   Swift method symbols are mangled; the demangled names (`InsecureURLSessionDelegate.urlSession(_:didReceive:completionHandler:)`) make the mapping obvious. Stripped binaries will not have them; then work from the Objective-C selector, which survives because the delegate method is called through the runtime.

3. **Review each handler's disassembly** (`pdf @ <address>`) or decompiled view. Answer: is `authenticationMethod` compared to `NSURLAuthenticationMethodServerTrust`; is the trust evaluated; on which branch is `URLCredential(trust:)` created; does a failed evaluation reach `.cancelAuthenticationChallenge`; are policies replaced (`SecTrustSetPolicies`, `SecPolicyCreateBasicX509`, `SecPolicyCreateSSL` with a null hostname)?

4. **Confirm at runtime** that the handler runs for the app's real traffic and whether evaluation happens:

   ```bash
   frida-trace -U -f com.example.app \
     -m '-[* URLSession:didReceiveChallenge:completionHandler:]' \
     -m '-[* URLSession:task:didReceiveChallenge:completionHandler:]' \
     -i 'SecTrustEvaluateWithError' -i 'SecTrustEvaluateAsyncWithError'
   ```

   Then run [GT-0027-1](#gt-0027-1-proving-it-on-the-wire-with-an-untrusted-ca-and-a-wrong-hostname-certificate-android-and-ios). A handler call with no evaluation call, followed by a decrypted request in the untrusted-CA proxy, is the finding proven end to end.

#### Observation

The list of challenge handlers with addresses, the protection-space accessors, the callers of the trust-evaluation APIs, the disassembly or decompiled code of each handler, and the runtime trace and proxy evidence.

#### Evaluation

The test **fails** if a challenge handler can call the completion handler with `.useCredential` and a server-trust credential when trust evaluation has not been performed or has failed, or after replacing the SSL policy with one that drops the hostname. OWASP's static criterion is a handler with no cross-reference to `SecTrustEvaluateWithError`; treat that as a strong indicator to confirm by review, not as the verdict.

It **passes** for handlers that evaluate the trust (possibly after adding anchors or pins), use the credential only on success, cancel on failure, and return `.performDefaultHandling` for challenge types they do not handle.

#### Demo

[MASTG-DEMO-0154](https://mas.owasp.org/MASTG/demos/ios/MASVS-NETWORK/MASTG-DEMO-0154/MASTG-DEMO-0154/). Two delegates connect to `expired.badssl.com`. The insecure one:

```swift
class InsecureURLSessionDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        completionHandler(.useCredential, URLCredential(trust: serverTrust)) // no evaluation
    }
}
```

The secure one checks the method, calls `SecTrustEvaluateWithError`, and cancels on failure. The script output separates them:

```text
Custom authentication-challenge handlers (functions referencing NSURLAuthenticationChallenge):
50   0x00004490 ... MASTestApp.SecureURLSessionDelegate.urlSession...didReceive.completionHandler(...)
58   0x00004000 ... MASTestApp.InsecureURLSessionDelegate.urlSession...didReceive.completionHandler(...)
Accessors into the challenge protection space (protectionSpace / serverTrust):
455  0x000165e0 ... _objc_msgSend$protectionSpace
457  0x00016620 ... _objc_msgSend$serverTrust
Uses of SecTrustEvaluateWithError:
949  0x000161bc ... imp.SecTrustEvaluateWithError
xrefs to SecTrustEvaluateWithError:
sym.MASTestApp.SecureURLSessionDelegate.urlSession...  0x4638 [CALL:--x] bl sym.imp.SecTrustEvaluateWithError
```

Only the secure handler (`0x4490`) calls the evaluation function. In the insecure handler (`0x4000`), `serverTrust` is read at `0x4064`, the only test is a `nil` check (`cbz x0, 0x4120`), and the `NSURLCredential` is created at `0x40d8`. The app shows the insecure request returning HTTP 200 from a server with an expired certificate. The test fails for `InsecureURLSessionDelegate`.

### MASTG-TEST-0397: References to WKNavigationDelegate Bypassing Certificate Validation (iOS)

Source: [MASTG-TEST-0397](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0397/). Platform: iOS. Type: static (code) with manual review. Related knowledge: MASTG-KNOW-0072. Best practice: MASTG-BEST-0073.

#### Overview

The same bug in a `WKWebView`: a `WKNavigationDelegate` that implements `webView(_:didReceive:completionHandler:)` and accepts the server trust without a successful evaluation. Whatever the WebView then shows (a login form, a checkout page, a hybrid app's whole UI) can be read and rewritten by the attacker. Returning `.performDefaultHandling` keeps the WebView's own validation and is fine.

#### Prerequisites

As for [MASTG-TEST-0396](#mastg-test-0396-references-to-urlsessiondelegate-bypassing-certificate-validation-ios).

#### Steps

1. **Find WebView challenge handlers** (the Objective-C selector is `webView:didReceiveAuthenticationChallenge:completionHandler:`):

   ```bash
   while read -r b; do
     strings -a "$b" | grep -q 'webView:didReceiveAuthenticationChallenge:completionHandler:' && echo "handler in: $b"
   done < macho.txt
   ```

2. **Run the OWASP radare2 script**, which adds `SecTrustEvaluateAsyncWithError` to the evaluation APIs it looks for:

   ```text
   ?e Server-trust evaluation calls:
   is~SecTrustEvaluateWithError,SecTrustEvaluateAsyncWithError
   ?e xrefs to SecTrustEvaluateWithError:
   axt @ sym.imp.SecTrustEvaluateWithError
   ?e xrefs to SecTrustEvaluateAsyncWithError:
   axt @ sym.imp.SecTrustEvaluateAsyncWithError
   ```

   ```bash
   r2 -q -i webview_auth_challenge.r2 -A ipa/Payload/App.app/App > output.txt
   ```

3. **Review each handler** with the same questions as for `URLSession`. Hybrid frameworks often implement this delegate in a plugin rather than in app code, so look in the frameworks as well.

4. **Confirm at runtime**: `frida-trace -U -f com.example.app -m '-[* webView:didReceiveAuthenticationChallenge:completionHandler:]' -i 'SecTrustEvaluate*'`, then load the WebView content through the untrusted-CA proxy.

#### Observation

As for MASTG-TEST-0396, for WebView handlers; plus the URLs loaded in the affected WebViews.

#### Evaluation

The test **fails** if a `WKNavigationDelegate` challenge handler accepts a server-trust credential without a successful evaluation, or regardless of its result. The absence of an evaluation API cross-reference marks a candidate; the verdict needs the review. It **passes** for handlers that return `.performDefaultHandling`, or evaluate and cancel on failure.

#### Demo

[MASTG-DEMO-0155](https://mas.owasp.org/MASTG/demos/ios/MASVS-NETWORK/MASTG-DEMO-0155/MASTG-DEMO-0155/). The delegate accepts any non-`nil` trust and the WebView loads `self-signed.badssl.com`:

```swift
class InsecureWKNavigationDelegate: NSObject, WKNavigationDelegate {
    func webView(_ webView: WKWebView, didReceive challenge: URLAuthenticationChallenge,
                 completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        completionHandler(.useCredential, URLCredential(trust: serverTrust))
    }
}
```

```text
Custom authentication-challenge handlers (functions referencing NSURLAuthenticationChallenge):
50   0x00004000 ... MASTestApp.InsecureWKNavigationDelegate.webView...didReceive.completionHandler(...)
Accessors into the challenge protection space (protectionSpace / serverTrust):
451  0x00015980 ... _objc_msgSend$protectionSpace
454  0x000159e0 ... _objc_msgSend$serverTrust
Server-trust evaluation calls:
xrefs to SecTrustEvaluateWithError:
xrefs to SecTrustEvaluateAsyncWithError:
```

The evaluation sections are empty: the binary does not even import the APIs. The handler reads `serverTrust`, checks only for `nil`, and builds the credential. The self-signed page renders. The test fails.

### GT-0027-1: Proving it on the wire with an untrusted CA and a wrong-hostname certificate (Android and iOS)

Guler Tech methodology. Platform: Android and iOS. Type: dynamic (network). This restores and extends the dynamic part of legacy tests MASTG-TEST-0021 and 0067.

#### Overview

Static review tells you a bad trust manager or delegate exists; the proxy tells you whether the app's real traffic is exposed, which hosts and flows are affected, and which of the two checks is broken. The test has two steps that isolate the two checks:

1. **Untrusted CA**: the proxy signs its certificates with a CA the device has never seen. A correct client rejects every connection. Anything you can read was accepted without chain validation (CWE-295).
2. **Wrong hostname**: the proxy serves a certificate signed by a CA the device *does* trust, but issued for a different name. A correct client rejects it. Anything you can read was accepted without hostname verification (CWE-297).

You need a **baseline** as well: with a trusted CA and correct per-host certificates, you must be able to see the traffic. If you cannot, the app pins or ignores the proxy, and a "rejected" result in the two steps tells you nothing.

#### Prerequisites

- The proxy set-up and device configuration from our [interception lab](/mobile/mobile-traffic-interception-lab/): mitmproxy ([MASTG-TOOL-0097](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0097/)) or Burp Suite ([MASTG-TOOL-0077](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0077/)); for Android, your normal proxy CA in the **system** store (rooted device or emulator); for iOS, the CA profile installed and enabled in *Certificate Trust Settings*.
- A transparent or VPN-based capture mode for apps that ignore the system proxy (Flutter, raw sockets, some SDKs).
- **No bypass tooling running.** No objection `sslpinning disable`, no SSL Kill Switch, no "universal" Frida unpinning script. Those scripts disable validation themselves, and a result obtained with them proves nothing about the app.
- A test account and a list of the app's flows: start-up, login, token refresh, main features, payments, file upload, in-app web pages, push registration, and anything a static hit pointed at.

#### Steps

1. **Baseline.** Run your normal proxy and confirm you can see the app's HTTPS traffic for the flows above.

   ```bash
   mitmdump --listen-port 8080 -w baseline.flows
   adb shell settings put global http_proxy 192.168.1.10:8080        # Android; iOS: Wi-Fi > proxy > Manual
   ```

   Note which hosts never appear decrypted (pinned or not proxy-aware). For pinned hosts, see the note in step 3.

2. **Step 1: untrusted CA.** Start mitmproxy with a fresh configuration directory, so it generates a new CA that the device does not trust:

   ```bash
   mitmdump --listen-port 8080 --set confdir="$HOME/.mitmproxy-untrusted" -w untrusted-ca.flows
   ```

   With Burp, the equivalent is *Proxy > Proxy settings > Proxy listeners > Edit > Certificate > Use a self-signed certificate*, or regenerating Burp's CA and not installing it. Exercise every flow, including in-app web pages. A correct app shows network errors, and mitmproxy logs a client TLS handshake failure saying the client does not trust the proxy's certificate for that host. Any request that appears decrypted is a finding.

3. **Step 2: wrong hostname.** Create a leaf certificate for a name the app never uses, signed by the CA the device **does** trust (your normal mitmproxy CA), and serve it for every host:

   ```bash
   cd "$(mktemp -d)"
   openssl req -new -newkey rsa:2048 -nodes -keyout wrong.key \
     -subj "/CN=wrong.example.org" -out wrong.csr
   printf 'subjectAltName=DNS:wrong.example.org\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' > wrong.ext
   openssl x509 -req -in wrong.csr \
     -CA ~/.mitmproxy/mitmproxy-ca-cert.pem -CAkey ~/.mitmproxy/mitmproxy-ca.pem -CAcreateserial \
     -days 30 -sha256 -extfile wrong.ext -out wrong.crt
   openssl verify -CAfile ~/.mitmproxy/mitmproxy-ca-cert.pem -verify_hostname api.example.com wrong.crt
   # -> error 62 at 0 depth lookup: hostname mismatch   (good: chain valid, name wrong)
   cat wrong.crt wrong.key > wrong.pem
   mitmdump --listen-port 8080 --certs '*=wrong.pem' -w wrong-host.flows
   ```

   The certificate has a SAN, `serverAuth`, a 2048-bit key, SHA-256 and a short lifetime, so iOS's certificate requirements do not reject it for reasons other than the name. In Burp, use *Generate a CA-signed certificate with a specific hostname* and enter `wrong.example.org`. Run the same flows. Anything decrypted was accepted without hostname verification.

   For hosts that are pinned, step 2 cannot tell you anything, because the pin check fails first. Either review hostname verification statically for them, or neutralise only the pinning (for example a targeted hook on OkHttp's `CertificatePinner.check`, or removing the NSC `<pin-set>` in a re-signed build) and leave the platform's validation intact. Do not use a blanket "disable SSL" script here: those also replace the hostname verifier.

4. **Optional: other certificate faults.** Expired and not-yet-valid certificates are covered by step 1 in practice (an app that validates chains rejects them; one that does not accepts everything). If the static review found a validity-only or self-signed shortcut, serve a self-signed certificate for the real hostname to show that specific acceptance:

   ```bash
   openssl req -x509 -newkey rsa:2048 -nodes -keyout ss.key -out ss.crt -days 30 \
     -subj "/CN=api.example.com" -addext "subjectAltName=DNS:api.example.com"
   cat ss.crt ss.key > ss.pem
   mitmdump --listen-port 8080 --certs 'api.example.com=ss.pem'
   ```

5. **Collect corroborating evidence.** On Android, rejections appear in logcat:

   ```bash
   adb logcat | grep -E 'SSLHandshakeException|CertPathValidatorException|not verified|onReceivedSslError'
   # Trust anchor for certification path not found.       <- chain rejected
   # Hostname api.example.com not verified                  <- hostname rejected (HttpsURLConnection)
   ```

   On iOS, a correct rejection surfaces in the app as `NSURLErrorServerCertificateUntrusted` (-1202) or `NSURLErrorSecureConnectionFailed` (-1200); you can see the system's TLS messages in Console.app with the device selected. A packet capture shows the client aborting the handshake with an alert:

   ```bash
   tshark -r capture.pcap -Y 'tls.alert_message' -T fields -e ip.dst -e tls.alert_message.desc
   # 48 = unknown_ca, 42 = bad_certificate, 46 = certificate_unknown
   ```

   Capture on the proxy host while using the lab's transparent or VPN mode (`sudo tcpdump -i <iface> -w capture.pcap host <device-ip>`), so the client's TLS goes straight to port 443 and the dissector sees it. No alert and application data flowing to the proxy is the opposite.

6. **Clean up**: `adb shell settings put global http_proxy :0`, remove proxy settings on iOS, and disable trust in your CA on test devices you hand back.

#### Observation

For each step: the proxy flows file, the list of hosts and flows decrypted versus rejected, representative requests showing the sensitive data (credentials and tokens redacted in the report), logcat or app error output, and for each decrypted host the code location from static review that explains it.

#### Evaluation

| Baseline | Step 1 (untrusted CA) | Step 2 (wrong hostname) | Conclusion for that host |
|---|---|---|---|
| Visible | Decrypted | (decrypted too) | **Fail**: no chain validation (CWE-295). Step 2 adds nothing. |
| Visible | Rejected | Decrypted | **Fail**: no hostname verification (CWE-297) |
| Visible | Rejected | Rejected | **Pass** for the flows exercised |
| Not visible | Rejected | Rejected | Inconclusive: pinned or not proxy-aware. Resolve with the lab's transparent mode or targeted pinning neutralisation |
| Not visible | Decrypted | | Fail; and the app is not pinning what you thought |

The test fails for an app if any host carrying user data, authentication material or content the app acts upon fails step 1 or step 2. Record the result per host: often one SDK or one WebView is broken while the main API client is fine.

#### Demo

Illustrative and abridged. An Android app whose analytics SDK installs `HttpsURLConnection.setDefaultSSLSocketFactory()` with a trust-all manager, while the main API uses OkHttp with defaults. Step 1 with a fresh CA:

```text
192.168.1.20:41022: client TLS handshake failed. The client does not trust the proxy's certificate for api.example.com
192.168.1.20:41030: POST https://telemetry.example.net/v2/events
                 << 204 No Content 0b
192.168.1.20:41034: GET https://api.example.com/content/terms.html     (WebView)
                 << 200 OK 18.2k
```

The API client rejects the proxy (good). The telemetry SDK's events are readable and contain the device ID and user email; the WebView page also loads, which points to an `onReceivedSslError` override. Two findings, each tied to its code location: the process-wide trust-all factory (also affecting every other `HttpsURLConnection` user) and the WebView handler.

### GT-0027-2: Other TLS stacks and cross-platform frameworks (Android and iOS)

Guler Tech methodology. Platform: Android and iOS. Type: static (code) and dynamic.

#### Overview

The OWASP tests target the platform APIs. Many apps make some of their connections through other stacks: Network.framework or CFStream on iOS, Dart's `HttpClient` in Flutter, .NET's `HttpClient`, Unity's web requests, native C/C++ libraries with their own OpenSSL or BoringSSL. Each has its own way to disable validation, and none is checked by the OWASP rules or by ATS.

#### Prerequisites

- The decompiled app and the binary list from [Before you start](#before-you-start-static-triage-of-the-whole-app).
- Identification of the framework (Flutter: `libflutter.so` / `Flutter.framework`; .NET: `libmonosgen-2.0.so` or assemblies; Unity: `libunity.so` / `UnityFramework.framework`; React Native: `libreactnativejni.so` / React frameworks).

#### Steps

1. **iOS lower layers**: look for `sec_protocol_options_set_verify_block`, `kCFStreamSSLValidatesCertificateChain`, `kCFStreamSSLPeerName`, `SecPolicyCreateBasicX509` and `SecTrustSetPolicies` imports or strings in each Mach-O:

   ```bash
   while read -r b; do
     rabin2 -i "$b" 2>/dev/null | grep -E 'sec_protocol_options_set_verify_block|SecPolicyCreateBasicX509|SecTrustSetPolicies' | sed "s|^|$b: |"
     strings -a "$b" | grep -E 'kCFStreamSSLValidatesCertificateChain' | sed "s|^|$b: |"
   done < macho.txt
   ```

   Review each verify block: it must evaluate the `sec_trust_t` it receives (via `sec_trust_copy_ref` and `SecTrustEvaluateWithError`) and pass the result to `complete(...)`.

2. **Android native code**: list native libraries and look for OpenSSL/BoringSSL verification switches.

   ```bash
   for so in apk_out/lib/arm64-v8a/*.so; do
     strings -a "$so" | grep -qE 'SSL_CTX_set_verify|X509_verify_cert' && echo "TLS code in: $so"
   done
   ```

   `SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, …)`, or a verify callback that returns 1 unconditionally, disables validation; hostname checking in OpenSSL needs `X509_VERIFY_PARAM_set1_host` (or `SSL_set1_host`). Review in a disassembler; libcurl users with `CURLOPT_SSL_VERIFYPEER` or `CURLOPT_SSL_VERIFYHOST` set to 0 are the common case.

3. **Framework-level switches**: grep decompiled Java/Kotlin for the patterns in the [cross-platform table](#cross-platform-and-third-party-stacks). Flutter's Dart code is compiled ahead of time into `libapp.so` / `App.framework`, and identifiers such as `badCertificateCallback` may not be recoverable; .NET assemblies can be extracted and decompiled with a .NET decompiler. Where static review is impractical, rely on step 4.

4. **Dynamic**: run [GT-0027-1](#gt-0027-1-proving-it-on-the-wire-with-an-untrusted-ca-and-a-wrong-hostname-certificate-android-and-ios) in transparent or VPN mode, so traffic from proxy-unaware stacks reaches the proxy.

#### Observation

The stacks in use, each relevant code location, and per-host proxy results from transparent capture.

#### Evaluation

The test **fails** if any stack disables chain validation or hostname verification for traffic that matters, by the same criteria as the OWASP tests. It passes when every stack uses its platform's or library's default validation, or custom validation that evaluates and fails closed.

#### Demo

A Flutter app with a development override left in:

```text
// Dart (from the source repository; not recoverable from the AOT binary)
final client = HttpClient()
  ..badCertificateCallback = (X509Certificate cert, String host, int port) => true;
```

Static review of the APK finds nothing useful in `libapp.so`. In step 1 with the lab's transparent mode, every API call decrypts with the untrusted CA. The test fails; the code location is supplied by the client's developers from the hint "Dart `HttpClient` with a permissive `badCertificateCallback`".

## Best practices

### MASTG-BEST-0073: Properly Validate Server Trust in URLSessionDelegate and WKNavigationDelegate

Source: [MASTG-BEST-0073](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0073/). Platform: iOS.

The best implementation of the challenge methods is no implementation: without them, the URL Loading System and `WKWebView` perform the full evaluation with ATS on top. For pinning, prefer the declarative `NSPinnedDomains` in `Info.plist` (see [MASWE-0028](/mobile/maswe-0028-insecure-identity-pinning/)). For a server with an untrusted certificate, fix the server. When you must handle the challenge:

1. Handle only `NSURLAuthenticationMethodServerTrust`; for anything else return `.performDefaultHandling`.
2. Take the `SecTrust` from `challenge.protectionSpace.serverTrust`; do not replace its SSL policy.
3. Make your adjustments (extra anchors, pin comparison) and then call `SecTrustEvaluateWithError` (or the async variant) and require `true`.
4. Answer `.useCredential` with `URLCredential(trust:)` only on success.
5. Answer `.cancelAuthenticationChallenge` on failure.

```swift
func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
    guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
          let serverTrust = challenge.protectionSpace.serverTrust else {
        completionHandler(.performDefaultHandling, nil)
        return
    }
    var error: CFError?
    if SecTrustEvaluateWithError(serverTrust, &error) {
        completionHandler(.useCredential, URLCredential(trust: serverTrust))
    } else {
        completionHandler(.cancelAuthenticationChallenge, nil)
    }
}
```

The same structure applies to `webView(_:didReceive:completionHandler:)`. (OWASP's text says to cancel "on any other challenge type"; its own secure demo, and Apple's guidance, return `.performDefaultHandling` for challenge types the method does not handle, which is what we recommend, since cancelling breaks legitimate HTTP or client-certificate authentication without adding security.)

### MASTG-BEST-0021: Ensure Proper Error and Exception Handling

Source: [MASTG-BEST-0021](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0021/). Platform: Android.

The general rule behind both the trust-manager and WebView tests is **fail securely** ([CWE-636](https://cwe.mitre.org/data/definitions/636.html), "not failing securely"): a security check that errors must deny, never fall back to a weaker path. For TLS that means letting `CertificateException` and `SSLException` propagate to the caller and turning them into a user-facing "cannot connect securely" state, never catching them to retry without validation; calling `handler.cancel()` in WebViews; and keeping certificate details out of production logs (they are useful to developers, but logs are not where security decisions get made). User-facing messages stay generic.

### MASTG-BEST-0020: Update the GMS Security Provider

Source: [MASTG-BEST-0020](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0020/). Platform: Android.

Update the provider early, before any TLS connection, and handle both outcomes. On devices without Google Play services, check availability at runtime and bundle Conscrypt instead.

```kotlin
class App : Application() {
    override fun onCreate() {
        super.onCreate()
        ProviderInstaller.installIfNeededAsync(this, object : ProviderInstaller.ProviderInstallListener {
            override fun onProviderInstalled() {
                ApiClient.init(this@App)               // first connections only after the update
            }
            override fun onProviderInstallFailed(errorCode: Int, recoveryIntent: Intent?) {
                val availability = GoogleApiAvailability.getInstance()
                if (availability.isUserResolvableError(errorCode)) {
                    availability.showErrorNotification(this@App, errorCode)
                }
                Security.insertProviderAt(Conscrypt.newProvider(), 1)   // bundled fallback
                ApiClient.init(this@App)
            }
        })
    }
}
```

### Secure patterns for Android (Guler Tech)

**Private CA: use the NSC, not code.** Scope the private root to the hosts that need it and keep proxy trust for debug builds only:

```xml
<network-security-config>
    <domain-config>
        <domain includeSubdomains="true">internal.example.com</domain>
        <trust-anchors>
            <certificates src="@raw/internal_root_ca" />
        </trust-anchors>
    </domain-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>
```

**If a library insists on an explicit `X509TrustManager`, give it the platform one.** OkHttp's `sslSocketFactory(factory, trustManager)` needs both arguments; build them from the default factory so the NSC still applies:

```kotlin
val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
tmf.init(null as KeyStore?)
val platformTm = tmf.trustManagers.filterIsInstance<X509TrustManager>().single()
val ctx = SSLContext.getInstance("TLS").apply { init(null, arrayOf(platformTm), null) }
val client = OkHttpClient.Builder()
    .sslSocketFactory(ctx.socketFactory, platformTm)   // no hostnameVerifier override
    .build()
```

**Raw sockets: verify the hostname and close on failure.**

```kotlin
val socket = SSLSocketFactory.getDefault().createSocket(host, 443) as SSLSocket
socket.startHandshake()
if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(host, socket.session)) {
    socket.close()
    throw SSLPeerUnverifiedException("Certificate does not match $host")
}
```

**WebViews: do not override `onReceivedSslError`**, or override it only to cancel and report:

```kotlin
override fun onReceivedSslError(view: WebView, handler: SslErrorHandler, error: SslError) {
    handler.cancel()
    showConnectionError()   // generic message; no "continue anyway"
}
```

**Debug-only conveniences stay out of release.** Put any development trust code in a `src/debug/` source set so it does not exist in the release APK, rather than behind an `if` that might be reachable. Turn on Android Lint's security checks as errors in CI (`TrustAllX509TrustManager`, `BadHostnameVerifier`, `AllowAllHostnameVerifier`, `SSLCertificateSocketFactoryGetInsecure`, `SSLCertificateSocketFactoryCreateSocket`), and add the OWASP semgrep rules above to the pipeline.

**Release builds**: `minSdkVersion` 24 or higher, no `user` trust anchors outside `<debug-overrides>`, `android:debuggable="false"`.

## Rating findings

Rate on three things: **what crosses the affected connection** (credentials, tokens, payment data, personal data, content the app executes or displays as trusted), **which check is missing and what the attacker needs** (a network position only, or also a CA on the victim's device), and **whether the code path is reached** in the release app during normal use. MAS-ATTACK-0014 (same Wi-Fi, rogue access point, ARP or DNS spoofing) needs no access to the victim's device and no interaction; we do not treat it as a mitigating factor for consumer apps. Missing hostname verification rates the same as missing chain validation, because a publicly trusted certificate for an attacker-owned domain costs nothing.

| Rating | Conditions |
|---|---|
| **Critical** | Chain validation or hostname verification disabled (trust-all manager, accept-all verifier, `SSLSocket` without verification, `proceed()` on WebView errors, iOS delegate accepting unevaluated trust, lower-level stack with verification off), reachable by a same-network attacker without user interaction, on connections carrying **credentials, session or refresh tokens, payment or card data**, or content the app executes or uses for security decisions (code, scripts, configuration, update packages). Proven or provable with GT-0027-1. |
| **High** | The same disabled validation on connections carrying other personal or sensitive data, or allowing tampering with what the user sees (account details, amounts, messages), including WebViews showing authenticated content. Also: a process-wide override (`setDefaultSSLSocketFactory`, `setDefaultHostnameVerifier`) whose reach you cannot fully enumerate. |
| **Medium** | Disabled validation that needs one user action to reach (a specific opt-in flow), or applies only to low-sensitivity traffic that is still security-relevant; a WebView that prompts the user to "continue anyway"; `<certificates src="user"/>` in the release base config or for sensitive API domains without pinning (attacker needs a CA in the victim's user store: MDM, a device owner, or a user persuaded to install it in Settings); `targetSdkVersion` below 24. Disabled validation gated by a runtime flag (remote config, hidden debug menu) that you have shown can be switched on in production. |
| **Low** | `minSdkVersion` below 24 with no compensating trust code; `user` trust anchors scoped to non-sensitive domains, or constrained by a pin-set; `ProviderInstaller` missing or with empty error handling; a debugging proxy CA bundled but unused by release configs; insecure trust code present in the release binary but shown to be unreachable (see below). |
| **Info** | `user` anchors only in `<debug-overrides>` with a non-debuggable release; a correct custom trust manager or delegate that the NSC or `NSPinnedDomains` could replace; `ProviderInstaller` absent with `minSdkVersion` 29 or higher; SDK helper classes for "unsafe" clients that nothing references; results obtained only with bypass tooling running. |

Raise a level when the exposed connection carries data for many users (a shared API key, an admin channel) or when an unauthenticated attacker on public Wi-Fi is realistic for the app's user base (travel, retail, banking). Lower a level when the only affected host carries public, non-personal content that the app does not act on, but do not go below Medium for a *reachable* disabled check in your client's own code: the next feature to use that client will not be so harmless. In the report give the code location (class and method from jadx, or function and address from r2), the clients and hosts it affects, the proxy evidence per host with step 1 or step 2 clearly named, the device and OS version, and the fix at the source.

### Telling live code from dead code

Insecure trust code in a binary is not always used. Google Play's scanner flags it either way, and it should be removed either way, but severity follows reachability. Before rating below High, establish which of these applies:

1. **Referenced?** In jadx, *Find Usage* on the trust-manager class, the verifier, the factory method (`getUnsafeOkHttpClient()`-style helpers), and the `WebViewClient` subclass. No references from app code (only from the library that defines it) means dead in practice. With R8, unreferenced code is usually removed outright, so code that survives into a release build is often referenced from somewhere: follow it.
2. **Gated how?** A branch on `BuildConfig.DEBUG` normally disappears in release builds because the constant is folded at compile time. If the insecure code is still present, the condition is something evaluated at runtime: a build-flavour string, a `SharedPreferences` value, a remote-config flag, an intent extra, a hidden debug screen. Find where that value comes from and whether a production user, another app or a network attacker can set it. A remote-config flag fetched over a properly validated channel, defaulting to off, is a Medium at most; a flag in an exported component or in unvalidated traffic is reachable.
3. **Executed?** Hook the constructor or the method with Frida and use the app through all its flows:

   ```javascript
   // Android: replace with the class you found
   Java.perform(() => {
     const Tm = Java.use('com.example.net.TrustEverythingManager');
     Tm.$init.overloads.forEach(o => {
       o.implementation = function () {
         console.log('[+] TrustEverythingManager constructed');
         return o.apply(this, arguments);
       };
     });
   });
   ```

   On iOS, `frida-trace` the delegate selectors from MASTG-TEST-0396 and 0397. A hook that never fires across a full walkthrough, combined with no references in step 1, supports "unreachable"; a hook that fires once at start-up means every connection through that client is exposed.
4. **Observed on the wire?** GT-0027-1 is the final word for the flows you exercised. If static review says reachable but you could not trigger it, rate on the static evidence and say what condition triggers it.

Dead code is Low (it can be revived by a one-line change and it attracts store warnings); unreachable third-party helper code is Info.

## References

- OWASP MASWE: [MASWE-0027: Insecure Certificate Validation](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0027/); related [MASWE-0026](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0026/) and [MASWE-0028](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0028/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-NETWORK-1](https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-1/) (CC BY-SA 4.0)
- OWASP MASTG knowledge: [MASTG-KNOW-0072: Server Trust Evaluation](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-NETWORK/MASTG-KNOW-0072/), [MASTG-KNOW-0014: Android Network Security Configuration](https://mas.owasp.org/MASTG/knowledge/android/MASVS-NETWORK/MASTG-KNOW-0014/), [MASTG-KNOW-0011: Security Provider](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0011/), [MASTG-KNOW-0010: Exception Handling](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0010/) (CC BY-SA 4.0)
- OWASP MASTG tests: [MASTG-TEST-0234](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0234/), [MASTG-TEST-0282](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0282/), [MASTG-TEST-0283](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0283/), [MASTG-TEST-0284](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0284/), [MASTG-TEST-0285](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0285/), [MASTG-TEST-0286](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0286/), [MASTG-TEST-0295](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0295/), [MASTG-TEST-0396](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0396/), [MASTG-TEST-0397](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0397/); legacy [MASTG-TEST-0021](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0021/), [MASTG-TEST-0023](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0023/), [MASTG-TEST-0067](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0067/) (CC BY-SA 4.0)
- OWASP MASTG demos: [MASTG-DEMO-0048](https://mas.owasp.org/MASTG/demos/android/MASVS-NETWORK/MASTG-DEMO-0048/MASTG-DEMO-0048/), [MASTG-DEMO-0049](https://mas.owasp.org/MASTG/demos/android/MASVS-NETWORK/MASTG-DEMO-0049/MASTG-DEMO-0049/), [MASTG-DEMO-0054](https://mas.owasp.org/MASTG/demos/android/MASVS-NETWORK/MASTG-DEMO-0054/MASTG-DEMO-0054/), [MASTG-DEMO-0055](https://mas.owasp.org/MASTG/demos/android/MASVS-NETWORK/MASTG-DEMO-0055/MASTG-DEMO-0055/), [MASTG-DEMO-0056](https://mas.owasp.org/MASTG/demos/android/MASVS-NETWORK/MASTG-DEMO-0056/MASTG-DEMO-0056/), [MASTG-DEMO-0057](https://mas.owasp.org/MASTG/demos/android/MASVS-NETWORK/MASTG-DEMO-0057/MASTG-DEMO-0057/), [MASTG-DEMO-0154](https://mas.owasp.org/MASTG/demos/ios/MASVS-NETWORK/MASTG-DEMO-0154/MASTG-DEMO-0154/), [MASTG-DEMO-0155](https://mas.owasp.org/MASTG/demos/ios/MASVS-NETWORK/MASTG-DEMO-0155/MASTG-DEMO-0155/) (CC BY-SA 4.0)
- OWASP MASTG best practices: [MASTG-BEST-0073](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0073/), [MASTG-BEST-0021](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0021/), [MASTG-BEST-0020](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0020/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0009](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0009/), [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0017](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0017/), [MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/), [MASTG-TECH-0117](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/), [MASTG-TECH-0150](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0150/), [MASTG-TECH-0151](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0151/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/) (CC BY-SA 4.0)
- OWASP MASTG tools: [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/), [radare2 (MASTG-TOOL-0073)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/), [badssl (MASTG-TOOL-0143)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0143/), [mitmproxy (MASTG-TOOL-0097)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0097/), [Burp Suite (MASTG-TOOL-0077)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0077/), [Frida (MASTG-TOOL-0031)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/), [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [Apktool (MASTG-TOOL-0011)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/) (CC BY-SA 4.0)
- Android Developers: [Security with network protocols](https://developer.android.com/privacy-and-security/security-ssl) (incl. [warnings about using SSLSocket directly](https://developer.android.com/privacy-and-security/security-ssl#WarningsSslSocket)), [Network security configuration](https://developer.android.com/privacy-and-security/security-config), [Unsafe X509TrustManager](https://developer.android.com/privacy-and-security/risks/unsafe-trustmanager), [Unsafe HostnameVerifier](https://developer.android.com/privacy-and-security/risks/unsafe-hostname), [Update your security provider](https://developer.android.com/privacy-and-security/security-gms-provider), [`WebViewClient.onReceivedSslError`](https://developer.android.com/reference/android/webkit/WebViewClient#onReceivedSslError%28android.webkit.WebView,%20android.webkit.SslErrorHandler,%20android.net.http.SslError%29), [`SslError`](https://developer.android.com/reference/android/net/http/SslError), [`X509TrustManager`](https://developer.android.com/reference/javax/net/ssl/X509TrustManager), [`HostnameVerifier`](https://developer.android.com/reference/javax/net/ssl/HostnameVerifier)
- Google Play Help: [unsafe X509TrustManager](https://support.google.com/faqs/answer/6346016), [unsafe WebViewClient.onReceivedSslError](https://support.google.com/faqs/answer/7071387)
- Apple: [Preventing Insecure Network Connections](https://developer.apple.com/documentation/security/preventing-insecure-network-connections), [Performing Manual Server Trust Authentication](https://developer.apple.com/documentation/foundation/performing-manual-server-trust-authentication), [`URLAuthenticationChallenge`](https://developer.apple.com/documentation/foundation/urlauthenticationchallenge), [`urlSession(_:didReceive:completionHandler:)`](https://developer.apple.com/documentation/foundation/urlsessiondelegate/urlsession%28_:didreceive:completionhandler:%29), [`webView(_:didReceive:completionHandler:)`](https://developer.apple.com/documentation/webkit/wknavigationdelegate/webview%28_:didreceive:completionhandler:%29), [`SecTrustEvaluateWithError`](https://developer.apple.com/documentation/security/sectrustevaluatewitherror%28_:_:%29), [`SecPolicyCreateSSL`](https://developer.apple.com/documentation/security/secpolicycreatessl%28_:_:%29), [`sec_protocol_options_set_verify_block`](https://developer.apple.com/documentation/security/sec_protocol_options_set_verify_block%28_:_:_:%29), [Trust manually installed certificate profiles (Apple Support 102390)](https://support.apple.com/en-us/102390), Apple Developer Forums threads [67493](https://developer.apple.com/forums/thread/67493) and [707320](https://developer.apple.com/forums/thread/707320)
- [RFC 5280: Internet X.509 PKI Certificate and CRL Profile](https://www.rfc-editor.org/rfc/rfc5280), [RFC 9525: Service Identity in TLS](https://www.rfc-editor.org/rfc/rfc9525), [RFC 8446: TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446) (alert codes)
- [NIST SP 800-52 Rev. 2: Guidelines for the Selection, Configuration, and Use of TLS Implementations](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf) (server certificate validation and hostname checking requirements for TLS clients)
- [mitmproxy documentation](https://docs.mitmproxy.org/stable/) (certificates and the `--certs` option), [Burp Suite documentation](https://portswigger.net/burp/documentation), [Frida](https://frida.re/docs/home/), [Conscrypt](https://conscrypt.org)
- CWE: [CWE-295](https://cwe.mitre.org/data/definitions/295.html), [CWE-297](https://cwe.mitre.org/data/definitions/297.html), [CWE-636](https://cwe.mitre.org/data/definitions/636.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
