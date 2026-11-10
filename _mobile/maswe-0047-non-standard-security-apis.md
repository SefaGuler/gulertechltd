---
title: "MASWE-0047: Using Non-Standard APIs for Security-Critical Functionality"
date: 2026-11-10 10:06:00 +0000
subcategory: code
summary: "Finding home-made crypto, bundled TLS stacks, custom DNS resolvers and custom login flows in mobile apps, and testing if they bypass platform security."
refs: [MASWE-0047, MASVS-CODE-3, MASVS-AUTH-1, MASVS-CRYPTO-1, MASVS-NETWORK-1, CWE-287, CWE-326, CWE-327, CWE-1240]
tags: [android, ios, masvs-code, custom-crypto, tls-stacks, authentication]
---

This note is part of our [MASVS-CODE guide](/mobile/masvs-code-code-quality-guide/) and covers OWASP [MASWE-0047](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0047/): apps that implement cryptography, TLS, name resolution or authentication themselves, or with components nobody has vetted, when the platform already provides a maintained way to do it. The platform's implementations are not perfect, but they are written by specialists, reviewed by many people, patched through OS and Google Play system updates, and wired into the device's security policy: the trust store, the Network Security Configuration, App Transport Security, Private DNS, the user's password manager. Code the app brings with it gets none of that by default. A home-made cipher is usually broken; a bundled TLS library is usually *correct* but frozen at the version it shipped with and blind to the platform's policy; a custom DNS resolver quietly ignores the user's encrypted DNS; a custom login screen cannot use passkeys or the password manager. Below you will find what counts as "standard", how to recognise each kind of non-standard implementation in a release binary (library fingerprints, native library names, symbol names, crypto constants), four tests of our own (OWASP has none for this weakness yet), secure Kotlin and Swift, and how to rate what you find. Whether the code is *correct* once you have found it is decided by the CRYPTO, NETWORK and AUTH notes linked throughout; this note finds the code and decides whether it should exist at all.

> **Note:** OWASP has not yet published any tests or Knowledge items for MASWE-0047. The tests in this note are Guler Tech methodology, labelled `GT-CODE-0047-x`. The closest OWASP item is the placeholder [MASTG-TEST-0239](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0239/) ("Using low-level APIs (e.g. Socket) to set up a custom HTTP connection"), which OWASP files under MASWE-0026 with a note that it could also belong here; we cover it in our [cleartext traffic note](/mobile/maswe-0026-cleartext-network-traffic/). No MASTG v1 test is replaced by this note.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Background](#background)
  - [Generic: what counts as standard](#generic-what-counts-as-standard)
  - [Android and iOS: cryptography providers and libraries](#android-and-ios-cryptography-providers-and-libraries)
  - [Android and iOS: networking and TLS stacks and the platform policies they skip](#android-and-ios-networking-and-tls-stacks-and-the-platform-policies-they-skip)
  - [Android and iOS: DNS resolution](#android-and-ios-dns-resolution)
  - [Android and iOS: authentication and credential APIs](#android-and-ios-authentication-and-credential-apis)
  - [Generic: recognising non-standard implementations in a binary](#generic-recognising-non-standard-implementations-in-a-binary)
- [Tests](#tests)
  - [GT-CODE-0047-1: Custom or bundled cryptography (Android and iOS)](#gt-code-0047-1-custom-or-bundled-cryptography-android-and-ios)
  - [GT-CODE-0047-2: Custom networking or TLS stack bypassing platform trust (Android and iOS)](#gt-code-0047-2-custom-networking-or-tls-stack-bypassing-platform-trust-android-and-ios)
  - [GT-CODE-0047-3: Custom DNS resolution (Android and iOS)](#gt-code-0047-3-custom-dns-resolution-android-and-ios)
  - [GT-CODE-0047-4: Custom authentication flows instead of platform credential APIs (Android and iOS)](#gt-code-0047-4-custom-authentication-flows-instead-of-platform-credential-apis-android-and-ios)
- [Secure implementation](#secure-implementation)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

MASWE-0047 applies when security-critical functionality (cryptography, networking and TLS, DNS resolution, authentication) is implemented with custom code or unproven components instead of platform APIs or established, peer-reviewed libraries. The OWASP requirement is *"The app uses standard APIs for security-critical functionality."* It maps to four MASVS controls: MASVS-CODE-3 ("The app only uses software components without known vulnerabilities"), MASVS-CRYPTO-1 ("The app employs current strong cryptography and uses it according to industry best practices"), MASVS-NETWORK-1 ("The app secures all network traffic according to the current best practices") and MASVS-AUTH-1 ("The app uses secure authentication and authorization protocols and follows the relevant best practices"). The CWEs are [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html), [CWE-1240: Use of a Cryptographic Primitive with a Risky Implementation](https://cwe.mitre.org/data/definitions/1240.html), [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html) and [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html). Android's risk catalogue covers the DNS part as [Insecure DNS Setup](https://developer.android.com/privacy-and-security/risks/bad-dns), and the Android core app quality guidelines include a cryptographic-algorithms item. The weakness is tagged for L1, L2 and EUDIW, so unlike most CODE weaknesses it is a **baseline** expectation.

Its MASVS v1 ancestors are MSTG-CRYPTO-2 ("The app uses proven implementations of cryptographic primitives") and MSTG-NETWORK-6 ("The app only depends on up-to-date connectivity and security libraries"). In the beta MASWE catalogue the same ground was split across three weaknesses numbered MASWE-0019, MASWE-0032 and MASWE-0049; those numbers now belong to other weaknesses ([autofill](/mobile/maswe-0019-no-autofill-support-for-credential-providers/), [insecure intents](/mobile/maswe-0032-insecure-intents/) and [unsafe dynamic code loading](/mobile/maswe-0049-unsafe-dynamic-code-loading/)), so read old references with care. OWASP's privacy counterpart is [MASWE-0069](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0069/) (*Usage of Non-Privacy-Preserving Functionality*), which makes the same "prefer the platform" argument for system authentication sessions, pickers and on-device processing. The threat is MAS-THREAT-0047 and the referenced attacks are MAS-ATTACK-0001, MAS-ATTACK-0014 and MAS-ATTACK-0021.

Keep the neighbouring weaknesses apart:

| Question | Where it lives |
|---|---|
| Is security functionality implemented in-house or with an unvetted, unmaintained or policy-bypassing component, when a standard one exists? | This note (MASWE-0047) |
| Is a *standard* API used with a weak algorithm, mode, key size or parameter? | [CRYPTO series](/mobile/masvs-crypto-cryptography-guide/) (MASWE-0007 to MASWE-0014) |
| Does a bundled library have a known CVE? | [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/) |
| Is a platform API deprecated, removed or turned down? | [MASWE-0046](/mobile/maswe-0046-use-of-deprecated-apis/) |
| Does a TLS stack (any stack) skip certificate or hostname validation, allow old protocol versions, or fail to pin? | [MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/), [MASWE-0026 TLS versions](/mobile/maswe-0026-insecure-tls-protocol-versions/), [MASWE-0028](/mobile/maswe-0028-insecure-identity-pinning/) |
| Does traffic leave in cleartext, including through raw sockets? | [MASWE-0026 cleartext](/mobile/maswe-0026-cleartext-network-traffic/) |
| Does the login work with password managers and passkeys? | [MASWE-0019](/mobile/maswe-0019-no-autofill-support-for-credential-providers/) |
| Can local authentication (biometrics, PIN) be bypassed? | [MASWE-0020](/mobile/maswe-0020-local-authentication-bypass/) |
| Does the app download and run code? | [MASWE-0049](/mobile/maswe-0049-unsafe-dynamic-code-loading/) |

A typical engagement produces a finding here *and* one in a neighbouring note: "the app bundles its own TLS stack, which ignores the declared certificate pins" (MASWE-0047) and "that stack accepts our proxy certificate for the API host" (MASWE-0028). Report the root cause here and the concrete break there, cross-referenced.

## Modes of Introduction

**Roll-your-own cryptography.** A class called `CryptoUtil`, `Obfuscator` or `SecureStorage` that XORs data with a key string, shuffles bytes, Base64-encodes the result, or implements AES, RC4 or a "simple" stream cipher by hand. Home-made key derivation (`sha256(password + salt)` repeated a few times), home-made MACs (`sha256(key + message)`, which is open to length extension), home-made random number generators. Constructions that combine real primitives into an unreviewed protocol (a custom handshake, an "encrypted" token format) belong here too.

**Unvetted or unmaintained crypto libraries.** Abandoned repackagings such as SpongyCastle, single-maintainer libraries that have never been audited, a statically linked OpenSSL several years old, or a crypto library copied into the source tree and modified. These are not "custom" in the strict sense, but they share its problem: nobody is fixing them.

**Custom networking or TLS stacks.** A native SDK that brings libcurl and OpenSSL; a cross-platform runtime whose HTTP client does its own TLS (Flutter's Dart `HttpClient` is the classic case); raw sockets with `SSLSocket` or a hand-built HTTP layer; a bundled CA file used instead of the device trust store. Even when such stacks validate certificates correctly, they do not read the Network Security Configuration, do not enforce ATS, do not receive the platform's security updates, and often ignore the system proxy.

**Custom DNS resolution.** DNS-over-UDP queries to a hard-coded public resolver, a DNS-over-HTTPS client library, or a vendor "HTTPDNS" service, used instead of the system resolver. All of them bypass Android's Private DNS and any encrypted DNS configured on iOS, and the plain-UDP ones replace an encrypted lookup with a spoofable one.

**Custom authentication.** A username and password form that defeats password managers, passwords verified on the device against a stored hash, third-party sign-in rendered in the app's own WebView, an OAuth flow without PKCE, a home-made device-binding or challenge-response scheme with a key compiled into the app, a biometric "gate" that is just a boolean. In each case the platform offers a standard mechanism: Credential Manager and `AccountManager` on Android, Authentication Services and Password AutoFill on iOS, passkeys on both, and the system browser for OAuth.

## Impact

- **Compromise of sensitive data.** Home-made ciphers are broken by reading the code; an outdated bundled TLS library carries known vulnerabilities the platform has fixed; a stack that ignores pinning or the platform trust policy can be intercepted where the rest of the app cannot.
- **Authentication bypass.** Client-side password checks, embedded-WebView sign-in and custom token schemes give an attacker with the device, a repackaged app or a malicious page a way around the server's authentication, or a way to capture the user's credentials.
- **Silent loss of platform protections.** Security fixes delivered through OS updates, Google Play system updates or the GMS security provider never reach code the app bundled. Policy the developer *thinks* applies (pins in the NSC, ATS, Private DNS) does not apply to that code.
- **Privacy loss.** Custom DNS sends lookups to a third party in cleartext; embedded login exposes credentials and browsing state to the app (see MASWE-0069).

## Mitigations

- **Use platform security APIs**: JCA with the default provider and the Android Keystore, CryptoKit and the Security framework; `HttpsURLConnection`, OkHttp or Cronet with the NSC on Android and `URLSession` with ATS on iOS; the system resolver; Credential Manager, Authentication Services and the system browser for authentication.
- **Where a library is needed, choose a vetted, maintained one** and use its high-level API: Tink, libsodium, Conscrypt, SQLCipher, AppAuth. Prefer components that meet recognised standards (FIPS 140-3 validated modules where required, [BSI TR-02102-1](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.pdf?__blob=publicationFile) algorithm recommendations) and keep them in your dependency scanning ([MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/)).
- **Never design or implement your own cipher, KDF, MAC, random number generator, TLS stack or authentication protocol** for production.
- **Make bundled stacks follow platform policy**: route cross-platform HTTP through the platform client (Flutter `cronet_http`/`cupertino_http`, .NET's platform handlers), replicate pins in code where a native stack cannot read the NSC, and ship no private trust store unless you also maintain it.
- **Leave DNS to the platform**, or opt into encrypted resolution with the platform API (`NWParameters.PrivacyContext` on iOS).
- **Use the platform's credential flows**: passkeys and passwords through Credential Manager / `ASAuthorizationController`, autofill-friendly fields, OAuth 2.0 for native apps (RFC 8252) with PKCE (RFC 7636) in the system browser.

## Background

OWASP has no Knowledge items for this weakness, so this section is ours.

### Generic: what counts as standard

"Standard" is not the same as "came with the OS". We use this decision order:

| Class | Examples | Verdict |
|---|---|---|
| **Platform API** | JCA/Conscrypt, Android Keystore, `HttpsURLConnection`, `DnsResolver`, Credential Manager; CryptoKit, CommonCrypto, Security framework, `URLSession`, Network framework, Authentication Services | Standard |
| **Vetted, maintained library used through its intended API** | Tink, libsodium, Conscrypt bundled as a provider, Bouncy Castle (current `bcprov` release), OkHttp, Cronet, AppAuth, SQLCipher | Standard, provided it is current (MASWE-0044) and does not bypass a platform policy the app relies on |
| **Vetted library, but outdated, forked, modified, or configured around platform policy** | Five-year-old OpenSSL linked into a `.so`; a Bouncy Castle copy with patched classes; a libcurl with its own CA bundle | Non-standard in practice; finding depends on age and on what it bypasses |
| **Unvetted or unmaintained component** | SpongyCastle, single-author crypto libraries without review, a GitHub gist pasted into the project | Non-standard |
| **Home-made** | Own cipher, KDF, MAC, PRNG, TLS layer, token format, login protocol | Non-standard; nearly always a finding |

Two questions decide borderline cases. First, *who maintains it, and how would a security fix reach this app?* For platform code the answer is the OS vendor, through system updates. For a bundled library it is the app team, through a dependency update and a new release, which only happens if somebody is watching. Second, *does it honour the platform's security policy?* A library can be excellent and still be a problem if the app's security design assumes the NSC, ATS or Private DNS applies to it.

### Android and iOS: cryptography providers and libraries

**Android.** The Java Cryptography Architecture dispatches `Cipher.getInstance()`, `MessageDigest.getInstance()` and friends to registered providers. The default is `AndroidOpenSSL`, which is Conscrypt backed by BoringSSL; since Android 10 it is delivered as a Mainline module and updated through Google Play system updates, and the GMS security provider (`ProviderInstaller`, see [MASWE-0046](/mobile/maswe-0046-use-of-deprecated-apis/)) can install an even newer copy on devices with Google Play services. Keys belong in the `AndroidKeyStore` provider. Google's [cryptography guidance](https://developer.android.com/privacy-and-security/cryptography) recommends using the default provider and not naming one, and recommends Tink for higher-level needs. Libraries you will meet:

| Library | Package or file | Notes |
|---|---|---|
| Tink | `com/google/crypto/tink/` | Google's misuse-resistant library; keysets wrapped by a Keystore key on Android. Standard |
| Conscrypt (bundled) | `org/conscrypt/`, `libconscrypt_jni.so` | The same code as the platform provider; legitimate on devices without Google Play services (MASTG-BEST-0020). Check the version |
| Bouncy Castle | `org/bouncycastle/` | Vetted, but large; on Android the platform's internal copy is renamed (`com.android.org.bouncycastle`) and not for apps. A bundled current release is acceptable for algorithms the platform lacks; an old one is a MASWE-0044 issue |
| SpongyCastle | `org/spongycastle/` | A repackaging of Bouncy Castle made for old Android versions and no longer maintained. Non-standard today |
| libsodium | `libsodium.so`, `org/libsodium/jni/`, `com/goterl/lazysodium/` | Vetted; check the binding's maintenance status |
| OpenSSL / BoringSSL (bundled) | `libcrypto.so`, `libssl.so`, or statically linked into another `.so` | Vetted code, but the app owns its updates. Fingerprint the version |
| SQLCipher | `net/zetetic/`, `net/sqlcipher/`, `libsqlcipher.so` | Standard choice for encrypted SQLite |

**iOS.** CryptoKit (iOS 13) offers AES-GCM, ChaChaPoly, HKDF, HMAC, SHA-2 and P-256/P-384/P-521 and Curve25519 keys, with Secure Enclave support for P-256. CommonCrypto (`CCCrypt`, `CCKeyDerivationPBKDF`, `CC_SHA256`) and the Security framework (`SecKey*`, keychain) are the older C APIs. Apple's underlying module, corecrypto, is submitted for FIPS 140 validation; Apple lists its certificates under its platform security certifications. Third-party libraries:

| Library | Where it shows up | Notes |
|---|---|---|
| CryptoSwift | `CryptoSwift.framework`, or Swift symbols containing `11CryptoSwift` when linked statically | Pure-Swift implementations of many algorithms; not Apple's code and not FIPS-validated; acceptable only where CryptoKit genuinely lacks the algorithm, and then with a review |
| OpenSSL / BoringSSL builds | `OpenSSL.framework`, `openssl.framework`, `libcrypto`/`libssl` statically linked into an SDK | App-owned updates; often bundled by VoIP, VPN and video SDKs |
| libsodium (swift-sodium) | `Sodium.framework`, `Clibsodium` | Vetted |
| RNCryptor | `RNCryptor` symbols | A data format built on CommonCrypto; maintained and reviewed, but a custom format: check its version |
| SQLCipher | `SQLCipher.framework` | Standard choice for encrypted SQLite |

**FIPS and BSI.** OWASP's mitigation mentions FIPS 140-2/3 and BSI TR-02102. Only a few engagements require *validated* modules (government, some finance and health contracts); for them, the requirement is that the cryptographic module in use appears on NIST's CMVP list for the relevant version, which a bundled library almost never does. For everyone else the standards are useful as algorithm and parameter guidance; the [CRYPTO series](/mobile/masvs-crypto-cryptography-guide/) applies them.

### Android and iOS: networking and TLS stacks and the platform policies they skip

The platform networking stacks enforce several policies that the developer declares once and the OS applies everywhere: on Android the [Network Security Configuration](https://developer.android.com/privacy-and-security/security-config) (trust anchors, whether user-installed CAs are trusted, certificate pins, cleartext policy) and on iOS [App Transport Security](https://developer.apple.com/documentation/security/preventing-insecure-network-connections) (HTTPS, TLS 1.2+, forward secrecy, exceptions per domain, and `NSPinnedDomains`). Both platforms also apply the system trust store, which the vendor updates when a CA is distrusted, and enterprise configuration pushed by MDM. A stack that does its own TLS skips all of this unless it re-implements it.

| Stack | Platform | Uses platform TLS and trust store? | Honours NSC / ATS? |
|---|---|---|---|
| `HttpsURLConnection`, OkHttp (default `SSLSocketFactory`) | Android | Yes | NSC: yes |
| Raw `SSLSocket` from the default factory | Android | Yes, but hostname verification is the caller's job (MASTG-TEST-0234) | NSC trust settings yes; cleartext policy cannot apply to sockets |
| `java.net.Socket` / `Socket` with a hand-written HTTP layer | Android | No TLS at all unless added | No; Android documents that `usesCleartextTraffic` is honoured "on a best-effort basis" and that the `Socket` API is not expected to honour it |
| React Native `fetch`/`XMLHttpRequest` | Both | Yes (OkHttp on Android, `NSURLSession` on iOS) | Yes |
| Flutter `dart:io` `HttpClient` (and `package:http` on top of it) | Both | No: TLS inside the Flutter engine (BoringSSL), system proxy ignored | No. Flutter's `cronet_http` / `cupertino_http` packages use the platform stacks instead |
| .NET MAUI / Xamarin | Both | Depends on the handler: the platform handlers (`AndroidMessageHandler`, `NSUrlSessionHandler`) use the platform stack; the managed handler does not | Only with the platform handlers |
| Native libraries with libcurl, OpenSSL, BoringSSL, mbedTLS, wolfSSL | Both | No | No |
| `URLSession`, `WKWebView` | iOS | Yes | ATS: yes |
| Network framework (`NWConnection`), CFNetwork streams | iOS | Yes (system trust store) | ATS: **no**. Apple states that ATS does not apply to these lower-level interfaces |

Not every bypass is a vulnerability. A bundled stack that validates certificates properly against a maintained trust store, pins where the app's design requires pinning, and negotiates TLS 1.2+ is acceptable. The finding is one of three things: the declared platform policy does not apply to sensitive traffic (pins in the NSC that the native SDK ignores; ATS assumed but never applied), the bundled trust store or library is stale, or the stack's own validation is broken (rated in MASWE-0027). The [traffic interception lab](/mobile/mobile-traffic-interception-lab/) explains how to see traffic from stacks that ignore the proxy.

### Android and iOS: DNS resolution

**Android.** Lookups through `InetAddress.getByName()`, `Network.getAllByName()`, OkHttp's default `Dns.SYSTEM` and the [`DnsResolver`](https://developer.android.com/reference/android/net/DnsResolver) API (API 29) go to the system resolver. Since Android 9 that resolver supports [Private DNS](https://android-developers.googleblog.com/2018/04/dns-over-tls-support-in-android-p.html), DNS over TLS on port 853, in automatic (opportunistic) mode by default or in strict mode with a user-chosen hostname. Google later added [DNS over HTTP/3](https://security.googleblog.com/2022/07/dns-over-http3-in-android.html) for some well-known providers through the updatable DNS resolver module. Android's risk page states the recommendation plainly: let the OS handle DNS. On a test device the setting is visible as `adb shell settings get global private_dns_mode` (`off`, `opportunistic` or `hostname`) and `private_dns_specifier`.

**iOS.** `URLSession`, Network framework and `getaddrinfo` use the system resolver, which since iOS 14 can be configured for encrypted DNS (DoT or DoH) by a configuration profile or a `NEDNSSettingsManager` app. An app can require encrypted resolution for its own connections with [`NWParameters.PrivacyContext`](https://developer.apple.com/documentation/network/nwparameters/privacycontext) and `requireEncryptedNameResolution(_:fallbackResolver:)` (iOS 14); the `default` privacy context applies to all connections that do not use a custom one. That is the standard way to get encrypted DNS in an iOS app.

**Non-standard resolvers.** dnsjava (`org.xbill.DNS`), MiniDNS (`org.minidns`), OkHttp's `okhttp-dnsoverhttps` (`okhttp3.dnsoverhttps.DnsOverHttps`), custom implementations of OkHttp's `Dns` interface, vendor HTTPDNS SDKs (some of which can be queried over plain HTTP), C code calling `res_query` with a fixed name server, and hard-coded IP addresses for API hosts. Why it matters: a plain-UDP query to a fixed resolver replaces a Private DNS lookup with one any on-path attacker can read and spoof, and it bypasses the resolver an enterprise or VPN configuration expects. TLS certificate validation still protects HTTPS connections from a spoofed answer, so a custom resolver on its own is mostly a privacy, availability and defence-in-depth problem. It becomes serious when something else relies on DNS being trustworthy: cleartext endpoints, broken certificate validation, IP-address allow-lists, or DNS TXT records the app trusts for configuration. A DoH library is not automatically better: it brings its own TLS client (check it as in GT-CODE-0047-2) and its own failure behaviour (a silent fallback to plain DNS).

### Android and iOS: authentication and credential APIs

| Need | Android standard | iOS standard |
|---|---|---|
| Passwords and passkeys for the app's own accounts | [Credential Manager](https://developer.android.com/identity/sign-in/credential-manager) (`androidx.credentials`): `GetPasswordOption`, `GetPublicKeyCredentialOption`; Autofill framework hints on fields | `ASAuthorizationController` with `ASAuthorizationPasswordProvider` and `ASAuthorizationPlatformPublicKeyCredentialProvider` (passkeys, iOS 16); [Password AutoFill](https://developer.apple.com/documentation/security/password_autofill) with `textContentType` and a `webcredentials:` associated domain |
| Sign in with Google / Apple | Credential Manager with `GetGoogleIdOption` / `GetSignInWithGoogleOption`; `AuthorizationClient` for scopes | `ASAuthorizationAppleIDProvider` |
| Third-party OAuth 2.0 / OpenID Connect | System browser through Custom Tabs, typically with AppAuth; PKCE; App Links redirect | `ASWebAuthenticationSession`; PKCE; universal-link or custom-scheme callback |
| Accounts shared across the app's components or sync adapters | `AccountManager` with an authenticator service | Keychain access groups |
| Local user verification | `BiometricPrompt` with a `CryptoObject`, or keys requiring authentication | LocalAuthentication with keychain access control (`SecAccessControl`) |

[RFC 8252](https://www.rfc-editor.org/rfc/rfc8252) (OAuth 2.0 for Native Apps) requires native apps to use an external user agent (the system browser or an in-app browser tab such as Custom Tabs or `ASWebAuthenticationSession`) rather than an embedded WebView, because the app controls an embedded WebView and can read what the user types into it. It also requires [PKCE (RFC 7636)](https://www.rfc-editor.org/rfc/rfc7636) for public clients. Google's OAuth endpoints refuse sign-in from embedded WebViews (the `disallowed_useragent` error). The detailed tests for password managers and passkeys are in [MASWE-0019](/mobile/maswe-0019-no-autofill-support-for-credential-providers/) and for local authentication in [MASWE-0020](/mobile/maswe-0020-local-authentication-bypass/); here the question is whether the app built its own mechanism where these exist.

Custom authentication patterns you will meet, with why each is a problem:

- **Client-side verification.** The app stores a password or PIN hash and compares locally, then uses a long-lived token to talk to the server. Anyone who can patch or hook the app skips the comparison; the stored hash can be brute-forced offline.
- **Embedded WebView for a third-party identity provider.** The app can read credentials and session cookies; the user cannot see the real URL; passkeys and the browser's password manager are unavailable.
- **OAuth without PKCE, or with a custom scheme anyone can register.** Another app can receive the authorisation code.
- **Home-made tokens and device binding.** Tokens signed with a key in the app, device IDs used as secrets, "challenge-response" with a hard-coded key. The key is in the binary; the scheme has never been reviewed.
- **Passwords kept for silent re-login.** The app stores the user's password to log in again later instead of using refresh tokens.

### Generic: recognising non-standard implementations in a binary

You will rarely have source code. These are the signals that survive compilation:

| Signal | Android | iOS |
|---|---|---|
| Library packages and module names | Smali directories such as `org/spongycastle/`, `org/bouncycastle/`, `org/conscrypt/`, `org/xbill/DNS/`, `okhttp3/dnsoverhttps/`, `net/openid/appauth/`, `io/flutter/` | `Frameworks/*.framework` names; Swift module names in mangled symbols (`11CryptoSwift`); Objective-C class names (`class-dump`, `otool -ov`) |
| Native libraries | `lib/<abi>/libcrypto.so`, `libssl.so`, `libcurl.so`, `libsodium.so`, `libconscrypt_jni.so`, `libflutter.so`, `libmonosgen-2.0.so`, `libunity.so` | Framework binaries (`OpenSSL.framework`, `Flutter.framework`, `UnityFramework.framework`) and statically linked code |
| Exported or imported symbols | `llvm-nm -D` shows `T SSL_CTX_new` (the library contains OpenSSL) or `U curl_easy_setopt` (it calls libcurl) | `nm` shows the same names with a leading underscore |
| Version strings | `OpenSSL 1.1.1w  11 Sep 2023`, `BoringSSL`, `mbed TLS 2.28.x`, `wolfSSL`, `libcurl/8.x` | Same |
| Protocol strings | `SSLv3`, `TLSv1`, cipher-suite names, `@SECLEVEL=0` | Same |
| Bundled trust stores | `assets/cacert.pem`, `res/raw/*.bks`, `*.p12`, `*.crt` | `*.pem`, `*.der`, `*.cer` in the bundle |
| Crypto constants | Byte or int arrays in DEX; data in `.so` | Data in `__TEXT,__const` or `__DATA,__const` |

Crypto constants are the most reliable sign of an *implementation* (as opposed to a call to an API). They are present wherever the algorithm is implemented, so finding them in the app's own code, rather than in a recognised library, is a strong hint of home-made or copied crypto:

| Constant | Hex (byte order in memory) | In jadx Java output |
|---|---|---|
| AES S-box, first 8 bytes | `63 7c 77 7b f2 6b 6f c5` | `99, 124, 119, 123, -14, 107, 111, -59` (as `byte[]`) |
| AES inverse S-box, first 4 bytes | `52 09 6a d5` | `82, 9, 106, -43` |
| SHA-256 initial value H0, H1 | `67 e6 09 6a`, `85 ae 67 bb` (little-endian `uint32`) | `1779033703`, `-1150833019` (or `0x6a09e667`, `0xbb67ae85`) |
| SHA-256 first round constant | `98 2f 8a 42` | `1116352408` (`0x428a2f98`) |
| MD5 / SHA-1 initial value A, B | `01 23 45 67`, `89 ab cd ef` | `1732584193`, `-271733879` (`0x67452301`, `0xefcdab89`); SHA-1 adds `0xc3d2e1f0` |
| MD5 first sine constant | `78 a4 6a d7` | `-680876936` (`0xd76aa478`) |
| ChaCha20 / Salsa20 | ASCII `expand 32-byte k` | the same string |

CRC32 tables (`0x77073096`) and Java's own `String.hashCode` multipliers are common false positives; they are not cryptography. Tools such as the FindCrypt plug-ins for IDA and Ghidra, or YARA crypto-signature rules, automate this search across a whole binary.

## Tests

OWASP has no tests linked to MASWE-0047. The four tests below each cover one mode of introduction. They are deliberately about *identification and policy*: they find non-standard components and show whether the platform's protections apply to them. Once a component is found, its correctness is tested with the existing notes: the [CRYPTO series](/mobile/masvs-crypto-cryptography-guide/) for algorithms and modes, [GT-0027-2 in the MASWE-0027 note](/mobile/maswe-0027-insecure-certificate-validation/) for certificate validation in other TLS stacks, [MASTG-TEST-0345 and GT-0026-TLS-3 in the TLS versions note](/mobile/maswe-0026-insecure-tls-protocol-versions/) for protocol configuration of embedded stacks, [MASWE-0028](/mobile/maswe-0028-insecure-identity-pinning/) for pinning, and [MASWE-0019](/mobile/maswe-0019-no-autofill-support-for-credential-providers/) for credential-manager support.

Common preparation for all four:

```bash
# Android
aapt2 dump badging app.apk | grep -E "^(package|sdkVersion|targetSdkVersion)"
jadx -d out-jadx app.apk
apktool d -f -o out-smali app.apk
unzip -o -q app.apk 'lib/*' 'assets/*' 'res/raw/*' -d apk-files
# iOS (decrypted IPA)
unzip -o -q App.ipa -d ipa; APP=$(ls -d ipa/Payload/*.app)
find "$APP" -type f -exec sh -c 'file "$1" | grep -q "Mach-O" && echo "$1"' _ {} \; > macho.txt
```

### GT-CODE-0047-1: Custom or bundled cryptography (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

Platform: Android and iOS. Type: static (code and binary), with optional dynamic confirmation. Tools: jadx, Apktool, ripgrep, `llvm-nm`/`nm`, `strings`, `xxd`, radare2 ([MASTG-TOOL-0073](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/) / [MASTG-TOOL-0028](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0028/)), optionally Frida. Techniques: [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0082](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0082/).

#### Overview

The test inventories every source of cryptography in the app (platform APIs, bundled libraries, and code that implements cryptographic operations itself) and classifies each one using the [decision table](#generic-what-counts-as-standard). It fails on home-made cryptography and on unvetted or unmaintained libraries protecting sensitive data. Bundled vetted libraries are passed on to dependency scanning.

#### Prerequisites

- Decompiled APK and/or decrypted IPA (common preparation above).
- A short list of what the app protects cryptographically, from the CRYPTO tests or the client's design documents: stored data, tokens, request signing, licence checks.

#### Steps

1. **Inventory bundled crypto libraries (Android).**

   ```bash
   ls -d out-smali/smali*/org/bouncycastle out-smali/smali*/org/spongycastle out-smali/smali*/org/conscrypt \
         out-smali/smali*/com/google/crypto/tink out-smali/smali*/org/libsodium out-smali/smali*/com/goterl \
         out-smali/smali*/net/zetetic out-smali/smali*/net/sqlcipher 2>/dev/null
   ls apk-files/lib/*/ | grep -E 'libcrypto|libssl|libsodium|libconscrypt|libsqlcipher|libmbed|libwolfssl'
   for so in apk-files/lib/arm64-v8a/*.so; do
     strings -a "$so" | grep -m1 -oE 'OpenSSL [0-9]\.[0-9.]+[a-z]?|BoringSSL|[Mm]bed ?TLS [0-9.]+|wolfSSL [0-9.]+|libsodium' | sed "s|^|$so: |"
     llvm-nm -D --defined-only "$so" 2>/dev/null | grep -qE ' T (EVP_EncryptInit_ex|AES_set_encrypt_key|crypto_secretbox_easy)$' && echo "$so: defines crypto primitives"
   done
   ```

   A library that *defines* (`T`) `EVP_EncryptInit_ex` contains OpenSSL or BoringSSL, whatever its file name. Obfuscated apps may have renamed the Java packages (`org.bouncycastle` becomes `a.b.c`); the class-name strings Bouncy Castle uses in its provider registration (`"org.bouncycastle.jcajce.provider..."`) and the provider name `"BC"` often survive.

2. **Inventory bundled crypto libraries (iOS).**

   ```bash
   ls "$APP/Frameworks/" | grep -iE 'openssl|crypto|sodium|sqlcipher|rncryptor'
   while read -r b; do
     nm "$b" 2>/dev/null | grep -m1 -q '11CryptoSwift' && echo "$b: CryptoSwift (statically linked or framework)"
     nm "$b" 2>/dev/null | grep -qE ' T _(EVP_EncryptInit_ex|SSL_CTX_new)$' && echo "$b: contains OpenSSL/BoringSSL"
     strings -a "$b" | grep -m1 -oE 'OpenSSL [0-9]\.[0-9.]+[a-z]?' | sed "s|^|$b: |"
   done < macho.txt
   ```

3. **Record versions and maintenance status** of every library found and pass them to [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/) scanning (SBOM via [MASTG-TECH-0130](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0130/) / [MASTG-TECH-0132](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0132/), then `osv-scanner` or `grype`). Note separately whether the project is maintained at all: last release date, archived repository, published security policy.

4. **Find home-made cryptography in first-party code.** Restrict the search to the app's own packages (and to SDK packages you want to assess):

   ```bash
   SRC=out-jadx/sources/com/example
   # Names that promise cryptography
   rg -n -i 'class \w*(crypt|cipher|obfusc|scrambl|secur\w*stor)\w*|fun \w*(encrypt|decrypt|obfuscate)\w*\(|(public|private|static).*\b(encrypt|decrypt|obfuscate)\w*\(' $SRC
   # XOR loops over byte arrays
   rg -n '\^\s*\w+\[\s*\w+\s*%\s*\w+\.(length|size)' $SRC
   rg -n '\(byte\)\s*\(\s*\w+\[\w+\]\s*\^' $SRC
   # Hash-based KDFs and MACs built by hand
   rg -n 'MessageDigest\.getInstance' $SRC | cut -c1-160
   # Crypto constants (see the table in Background)
   rg -n '99, 124, 119, 123, -14|1779033703|0x6a09e667|1732584193|0x67452301|-680876936|0xd76aa478|expand 32-byte k' out-jadx/sources/
   ```

   For each `MessageDigest` hit, read the code: a digest of `key + message` used as an authenticator, or a digest of `password + salt` (iterated or not) used as a key, is a home-made MAC or KDF. On iOS the equivalent is a function that calls `CC_SHA256`/`SHA256.hash` on concatenated key and data, or an `eor` loop in a function whose name contains `encrypt` or `obfuscate`:

   ```bash
   nm "$APP/$(plutil -extract CFBundleExecutable raw "$APP/Info.plist")" | xcrun swift-demangle | grep -iE 'encrypt|decrypt|obfuscat|scrambl' | head -40
   ```

5. **Search raw bytes for constants** in native code and Mach-O binaries, where there is no Java output to read:

   ```bash
   for f in apk-files/lib/arm64-v8a/*.so $(cat macho.txt 2>/dev/null); do
     hex=$(xxd -p "$f" | tr -d '\n')
     for c in 637c777bf26b6fc5:AES-sbox 67e6096a85ae67bb:SHA-256-IV 0123456789abcdef:MD5/SHA1-IV 657870616e642033322d62797465206b:ChaCha; do
       echo "$hex" | grep -q "${c%%:*}" && echo "$f: ${c##*:}"
     done
   done
   ```

   A hit in `libcrypto.so` or `Flutter.framework` is expected. A hit in `libapp-security.so` or in the main executable of an app that should be calling CryptoKit is what you are looking for; open it in radare2 or Ghidra and find the function that references the table.

6. **Classify** each item as platform API, vetted-and-current library, vetted-but-stale library, unvetted/unmaintained library, or home-made, and note what it protects.

7. **Optionally confirm what the home-made code protects** with a Frida hook on the app's own method on a test device. This only observes inputs and outputs:

   ```javascript
   // observe-crypto.js: log the app's own "encrypt" helper (class and method from jadx)
   Java.perform(() => {
     const C = Java.use('com.example.app.util.Obfuscator');
     C.encode.overloads.forEach(ov => {
       ov.implementation = function (...args) {
         const out = ov.apply(this, args);
         console.log('[Obfuscator.encode] in=' + JSON.stringify(String(args[0])).slice(0, 80) +
                     ' out=' + String(out).slice(0, 80));
         return out;
       };
     });
   });
   ```

   Seeing a session token or a password go in tells you the severity.

#### Observation

A table of every cryptographic component: name, location (package, `.so`, framework), version, maintenance status, class (platform / vetted current / vetted stale / unvetted / home-made), and what it protects; code locations and decompiled excerpts for home-made code; Frida output where used.

#### Evaluation

The test **fails** if sensitive data, credentials, keys or a security decision are protected by:

- home-made cryptography: an own cipher, encoding presented as encryption, a hand-written implementation of a standard algorithm, an own KDF, MAC, PRNG or protocol; or
- an unvetted or unmaintained crypto library (for example SpongyCastle, an archived single-maintainer library, a modified copy of a vetted library).

A vetted library that is outdated is reported under MASWE-0044 (and here only if it is unmaintained). The test **passes** when all cryptography uses platform APIs or vetted, maintained libraries through their documented API; whether those calls are *configured* correctly is then the CRYPTO series' job.

#### Demo

A helper copied into many apps:

```kotlin
object Obfuscator {
    private val KEY = "s3cr3t-k3y".toByteArray()
    fun encode(plain: String): String {
        val b = plain.toByteArray()
        for (i in b.indices) b[i] = (b[i].toInt() xor KEY[i % KEY.size].toInt()).toByte()
        return Base64.encodeToString(b, Base64.NO_WRAP)
    }
}
// used as: prefs.edit().putString("rt", Obfuscator.encode(refreshToken)).apply()
```

Step 4 output (jadx renders the loop in Java):

```text
out-jadx/sources/com/example/app/util/Obfuscator.java:14:            bArr[i] = (byte) (bArr[i] ^ KEY[i % KEY.length]);
```

The Frida hook shows the refresh token going in. The "encryption" is reversed by anyone who reads the APK: the key is a string constant and XOR is its own inverse. The test fails; rate as in [MASWE-0007's non-cryptographic "encryption" check](/mobile/maswe-0007-improper-encryption/) (High for a refresh token in a location an attacker can reach, such as a backup). The fix is a Keystore-held AES-GCM key or Tink, shown in [Secure implementation](#secure-implementation).

### GT-CODE-0047-2: Custom networking or TLS stack bypassing platform trust (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

Platform: Android and iOS. Type: static and dynamic. Tools: everything in the [traffic interception lab](/mobile/mobile-traffic-interception-lab/) (Burp Suite or mitmproxy, a rooted Android device or emulator for system CAs, `rvictl` for iOS), `llvm-nm`, `strings`, `openssl`, Frida. Related: [MASTG-TECH-0109](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0109/) and [MASTG-TECH-0110](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0110/) (intercepting Flutter HTTPS traffic).

#### Overview

The test finds every network stack the app uses and checks, per stack and per host, whether the platform's trust policy actually applies: the system trust store, the NSC (user-CA policy, pins, cleartext) on Android, ATS and `NSPinnedDomains` on iOS. The key technique is a differential: change one thing about the device's trust configuration and see which connections change behaviour. A connection that does not react the way the declared policy says it should is handled by a stack that bypasses that policy.

#### Prerequisites

- An interception set-up from the [lab note](/mobile/mobile-traffic-interception-lab/) that can capture traffic from proxy-unaware stacks (transparent mode, a VPN-based capture such as WireGuard into mitmproxy, or a rogue access point).
- Android: one device where you can install your CA as a **user** CA and one (or a rooted emulator) where you can install it as a **system** CA; for Android 14 and later, the APEX method described in the lab note.
- iOS: a device with your CA installed as a profile and trusted in *Certificate Trust Settings*.
- The app's declared policy: `res/xml/<networkSecurityConfig>.xml` from the APK and `NSAppTransportSecurity` from `Info.plist` (`plutil -p "$APP/Info.plist"`).

#### Steps

1. **Identify the stacks statically.**

   ```bash
   # Android: native TLS and HTTP libraries, cross-platform runtimes, bundled trust stores
   ls apk-files/lib/arm64-v8a/ | grep -E 'libssl|libcrypto|libcurl|libflutter|libmonosgen|libunity|libgrpc|libcronet'
   for so in apk-files/lib/arm64-v8a/*.so; do
     llvm-nm -D "$so" 2>/dev/null | grep -qE ' [TU] (SSL_CTX_new|curl_easy_setopt|mbedtls_ssl_setup|wolfSSL_CTX_new)$' && echo "TLS/HTTP code: $so"
   done
   find apk-files/assets apk-files/res -type f \( -name '*.pem' -o -name '*.crt' -o -name '*.cer' -o -name '*.der' -o -name '*.bks' -o -name '*.p12' \) 2>/dev/null
   strings -a apk-files/lib/arm64-v8a/*.so | grep -E 'Certificate data from Mozilla as of|/etc/ssl|/system/etc/security/cacerts' | sort -u
   # iOS: same idea per Mach-O; Network framework and CFNetwork use is also outside ATS
   while read -r b; do
     nm -u "$b" 2>/dev/null | grep -E '_nw_connection_create|_nw_parameters_create_secure_tcp|_CFStreamCreatePairWithSocketToHost|_SSL_CTX_new|_curl_easy_setopt' | sed "s|^|$(basename "$b"): |"
   done < macho.txt
   find "$APP" -type f \( -name '*.pem' -o -name '*.cer' -o -name '*.der' -o -name '*.crt' \)
   ```

   `curl`'s Mozilla-derived `cacert.pem` starts with a `## Certificate data from Mozilla as of:` line, which dates the bundled trust store. Count and inspect a PEM bundle with `grep -c 'BEGIN CERTIFICATE' cacert.pem` and `openssl storeutl -noout -text -certs cacert.pem | grep -E 'Subject:|Not After'`.

2. **Record the declared policy.** From the NSC: `base-config` and `domain-config` trust anchors (is `src="user"` present?), `<pin-set>` entries and their domains, `cleartextTrafficPermitted`. From ATS: `NSAllowsArbitraryLoads`, `NSExceptionDomains`, `NSPinnedDomains`. This is what the platform would enforce; the rest of the test checks whether it does.

3. **Run the differential (Android).** For each run, exercise every feature (login, payments, chat, media, any feature backed by a native SDK) and log, per host, whether the proxy saw decrypted traffic, a TLS failure, or nothing.

   | Run | Device trust configuration | Expected for a platform stack (app targets API 24+) | A deviation means |
   |---|---|---|---|
   | A | Your CA as **user** CA only; NSC does not trust user CAs | TLS failures for every host | A host decrypted here is served by a stack that trusts user CAs despite the NSC |
   | B | Your CA as **system** CA | Decrypted for unpinned hosts; TLS failure for hosts pinned in the NSC | A host pinned in the NSC but decrypted here is served by a stack that ignores NSC pins. A host *not* pinned in the NSC that still fails uses its own trust store or code-level pinning (confirm statically) |
   | C | System CA, transparent capture, NSC with `cleartextTrafficPermitted="false"` | No plain HTTP from the app | Plain HTTP to any host means a stack that ignores the cleartext policy |
   | D | No CA, transparent capture | Hosts appear by SNI with normal handshakes | Hosts that appear only here, never in proxy mode, belong to a proxy-unaware stack |

4. **Run the differential (iOS).**

   | Run | Device configuration | Expected for `URLSession` | A deviation means |
   |---|---|---|---|
   | E | Your CA installed and fully trusted, proxy configured | Decrypted, except hosts in `NSPinnedDomains` or pinned in code | A host in `NSPinnedDomains` that is decrypted is reached through a stack outside ATS. A host that fails without any pinning configured uses its own trust store |
   | F | Transparent capture (rogue AP or `rvictl` passive capture) | No plain HTTP and no TLS below 1.2 unless ATS exceptions allow it | Plain HTTP or TLS 1.0/1.1 with no matching ATS exception means Network framework, CFNetwork, BSD sockets or an embedded stack |

   On iOS you can capture without a proxy using `rvictl -s <UDID>` and `tcpdump -i rvi0 -n -w ios.pcap`; then `tshark -r ios.pcap -Y 'tls.handshake.type == 1' -T fields -e tls.handshake.extensions_server_name -e tls.handshake.extensions.supported_version -e tls.handshake.version` lists the hosts and the versions offered.

5. **Attribute deviations to a stack** with a benign Frida hook that logs, for the app's bundled libraries, how verification is configured. Exported symbols can be hooked by name; in stripped engines such as `libflutter.so` they cannot, which is why the lab note uses reFlutter or pattern scanning there.

   ```javascript
   // tls-config.js: log TLS verification settings in bundled (non-system) libraries
   const isApp = m => m.path.includes('/data/app/') || m.path.includes('/Bundle/Application/') || m.path.includes('.app/');
   for (const m of Process.enumerateModules().filter(isApp)) {
     for (const name of ['SSL_CTX_set_verify', 'SSL_set_verify']) {
       const p = m.findExportByName(name);
       if (p) Interceptor.attach(p, { onEnter(a) { console.log(`[${m.name}] ${name} mode=${a[1].toInt32()}`); } });
     }
     const ce = m.findExportByName('curl_easy_setopt');
     if (ce) Interceptor.attach(ce, { onEnter(a) {
       const opt = a[1].toInt32();
       if (opt === 64 || opt === 81) console.log(`[${m.name}] curl ${opt === 64 ? 'SSL_VERIFYPEER' : 'SSL_VERIFYHOST'}=${a[2].toInt32()}`);
       if (opt === 10065) console.log(`[${m.name}] curl CAINFO=${a[2].readCString()}`);
     } });
   }
   ```

   `SSL_VERIFY_NONE` is `0` and `SSL_VERIFY_PEER` is `1`; in libcurl, `CURLOPT_SSL_VERIFYPEER` is option 64, `CURLOPT_SSL_VERIFYHOST` is 81 (it should be 2) and `CURLOPT_CAINFO` is 10065. Run with `frida -U -f com.example.app -l tls-config.js` early, because many SDKs configure TLS once at start-up. `curl_easy_setopt` is variadic: on Android arm64 the value arrives in a register and `args[2]` works, but on iOS arm64 variadic arguments are passed on the stack, so read the value from `this.context.sp` there or fall back to static review.

6. **Send each stack on to the correctness tests**: certificate validation ([GT-0027-2](/mobile/maswe-0027-insecure-certificate-validation/)), protocol versions ([GT-0026-TLS-3 / MASTG-TEST-0345](/mobile/maswe-0026-insecure-tls-protocol-versions/)), pinning ([MASWE-0028](/mobile/maswe-0028-insecure-identity-pinning/)).

#### Observation

Per host: the stack that serves it, whether it is proxy-aware, its behaviour in each run (decrypted / TLS failure / plain HTTP / not seen), the platform policy declared for it, and the evidence (proxy log, `tshark` output, Frida log). Per stack: library and version, bundled trust store and its date.

#### Evaluation

The test **fails** for a stack that carries sensitive traffic if any of the following holds:

- a policy the app declares for that traffic is not enforced: NSC pins or ATS pinned domains bypassed (run B or E), NSC user-CA restriction bypassed (run A), cleartext despite `cleartextTrafficPermitted="false"` or without an ATS exception (runs C, F);
- the stack uses its own trust store that is stale (we use: not refreshed within the last 12 months of releases, or containing roots that Mozilla or the platform have since distrusted), or its library is outdated (MASWE-0044);
- the stack's own validation is disabled or broken (report the break under MASWE-0027, the cause here).

It **passes** if all sensitive traffic uses platform stacks, or if every non-platform stack validates certificates correctly against the platform store or a maintained bundle, enforces pins equivalent to those declared, and uses TLS 1.2 or later. A proxy-unaware stack that otherwise passes is an Info observation (it complicates testing and ignores enterprise proxies, but it is not a weakness on its own).

#### Demo

An Android app declares a pin for its API host:

```xml
<network-security-config>
    <domain-config>
        <domain includeSubdomains="false">api.example.com</domain>
        <pin-set expiration="2027-06-30">
            <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
            <pin digest="SHA-256">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

The Kotlin code uses OkHttp. A bundled payments SDK, `libpaysdk.so`, statically contains OpenSSL and libcurl and also calls `api.example.com`. Step 1 output:

```text
TLS/HTTP code: apk-files/lib/arm64-v8a/libpaysdk.so
apk-files/assets/paysdk/cacert.pem
## Certificate data from Mozilla as of: Tue Oct 15 03:12:10 2019 GMT
```

Run B, with the proxy CA as a system CA:

```text
api.example.com  GET /v2/accounts       TLS failure (client rejected certificate)    # OkHttp, NSC pin enforced
api.example.com  POST /pay/authorize    decrypted, 200                               # libpaysdk.so
```

The Frida hook shows `[libpaysdk.so] curl CAINFO=/data/data/com.example.app/files/paysdk/cacert.pem` and `SSL_VERIFYPEER=1`. Validation is on, but against a 2019 Mozilla bundle copied into the app's storage, and the NSC pins do not apply. The test fails: the declared pinning is bypassed for payment authorisation, and the trust store is several years out of date. The pinning gap is rated in [MASWE-0028](/mobile/maswe-0028-insecure-identity-pinning/); the fix is to ask the SDK vendor for a build that uses the platform stack (or that accepts the app's pins), and to update or remove the bundled CA file.

### GT-CODE-0047-3: Custom DNS resolution (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

Platform: Android and iOS. Type: static and dynamic (network capture). Tools: jadx, ripgrep, `nm`, PCAPdroid or `tcpdump` on Android, `rvictl` and `tcpdump` on iOS, Wireshark/`tshark`. Related: Android's [Insecure DNS Setup](https://developer.android.com/privacy-and-security/risks/bad-dns) risk page.

#### Overview

The test checks whether the app resolves host names itself instead of through the system resolver, and if so whether its resolver is weaker (plain DNS to a fixed server, HTTPDNS over HTTP, a DoH client with broken TLS) or bypasses policy (Private DNS, enterprise or VPN DNS). It also records whether the app's security depends on DNS answers.

#### Prerequisites

- Decompiled app (common preparation).
- An Android test device whose Private DNS you can set, and a way to capture its traffic per app (PCAPdroid, which works without root through a local VPN, or `tcpdump` on a rooted device or emulator; or a capture on the access point).
- An iOS device connected to a Mac for `rvictl`, or capture at the access point.
- The IP address of the test network's DNS resolver, to tell system lookups from the app's own.

#### Steps

1. **Search for resolver libraries and custom resolvers (Android).**

   ```bash
   ls -d out-smali/smali*/org/xbill/DNS out-smali/smali*/org/minidns out-smali/smali*/okhttp3/dnsoverhttps 2>/dev/null
   rg -n 'implements Dns\b|: Dns\b|\.dns\(|DnsOverHttps\.Builder|SimpleResolver\(|ExtendedResolver\(' out-jadx/sources/ | cut -c1-180
   rg -n -i 'httpdns' out-jadx/sources/ out-jadx/resources/ | cut -c1-160 | head
   # Hard-coded public resolvers and DoH endpoints
   rg -n '"(8\.8\.8\.8|8\.8\.4\.4|1\.1\.1\.1|1\.0\.0\.1|9\.9\.9\.9|208\.67\.222\.222|223\.5\.5\.5|119\.29\.29\.29)"|dns-query|cloudflare-dns\.com|dns\.google' out-jadx/
   ```

   An OkHttp client built with `.dns(SomeDns)` is the usual integration point; open `SomeDns.lookup()` and see what it calls. Also look for hard-coded IP addresses used in place of host names for API endpoints (`https://203.0.113.10/...`), which bypass DNS altogether and usually come with a disabled hostname check.

2. **Search for resolver code (iOS).**

   ```bash
   while read -r b; do
     nm -u "$b" 2>/dev/null | grep -E '_res_(9_)?(query|search|send)$|_res_9_ninit|_dns_open|_nw_privacy_context_require_encrypted_name_resolution' | sed "s|^|$(basename "$b"): |"
     strings -a "$b" | grep -E 'dns-query|cloudflare-dns\.com|dns\.google|^(8\.8\.8\.8|1\.1\.1\.1|9\.9\.9\.9)$' | sort -u | sed "s|^|$(basename "$b"): |"
   done < macho.txt
   ```

   `res_query` and friends (the `res_9_*` names are what `<resolv.h>` maps them to) with an explicitly configured name server are a custom resolver; a call to the privacy-context API that requires encrypted resolution is the *standard* way and is a pass. `DNSServiceQueryRecord` (dns_sd) is a platform API and is fine.

3. **Observe resolution on Android.** Put the test device in strict Private DNS mode so that every system lookup goes over DNS over TLS to one known host:

   ```bash
   adb shell settings put global private_dns_mode hostname
   adb shell settings put global private_dns_specifier dns.google
   ```

   Then capture while you use the app. With strict mode on, system lookups appear as TCP port 853 to the Private DNS server. Anything else that looks like name resolution is the app's own:

   ```bash
   tshark -r android.pcap -Y 'udp.port == 53 || tcp.port == 53 || (tls.handshake.extensions_server_name contains "dns")' \
     -T fields -e ip.dst -e dns.qry.name -e tls.handshake.extensions_server_name
   ```

   PCAPdroid attributes each connection to an app, which removes the guesswork. Restore the setting afterwards (`adb shell settings put global private_dns_mode opportunistic`).

4. **Observe resolution on iOS.** Capture with `rvictl -s <UDID>` and `tcpdump -i rvi0 -n -w ios.pcap 'port 53 or port 853 or port 443'`. System lookups go to the network's resolver (from DHCP) unless an encrypted DNS profile is installed; DNS queries to any *other* address, or DoH requests to a resolver the device is not configured to use, come from the app.

5. **Check what depends on DNS.** For each name the app resolves itself, note whether the connection that follows is HTTPS with correct validation (spoofing then leads to a TLS failure), plain HTTP, a stack with disabled validation, or an IP-based decision. Also check the failure path: block the custom resolver's traffic at the access point and see whether the app falls back to the system resolver, fails, or (worse) to plain DNS when DoH fails.

#### Observation

The resolver components found (library, class, configured servers), the captured queries with destination and transport, the hosts resolved by the app itself, what each of those hosts is used for and over which transport, and the fallback behaviour.

#### Evaluation

The test **fails** if host names used for authentication, API calls, updates or configuration are resolved by an app-specific mechanism that is weaker than the platform's (plain DNS or HTTPDNS over HTTP to a fixed server, a DoH client whose TLS validation is broken, a silent fallback from DoH to plain DNS), or if it bypasses DNS policy the deployment depends on (Private DNS in strict mode, enterprise or VPN split DNS in a managed-device deployment). It **passes** if the app uses the system resolver, or uses an encrypted resolver at least as strong as the platform's with correct validation (on iOS, the privacy-context API). Severity depends heavily on step 5: with properly validated HTTPS on top, a custom plain resolver is usually Low (privacy and defence in depth); it rises when DNS answers decide anything security-relevant.

#### Demo

```kotlin
object FastDns : Dns {                                   // OkHttp's Dns interface
    private val resolver = SimpleResolver("8.8.8.8")     // dnsjava: plain UDP to a fixed server
    override fun lookup(hostname: String): List<InetAddress> {
        val records = Lookup(hostname, Type.A).apply { setResolver(resolver) }.run()
        return records?.filterIsInstance<ARecord>()?.map { it.address } ?: Dns.SYSTEM.lookup(hostname)
    }
}
val client = OkHttpClient.Builder().dns(FastDns).build()
```

With strict Private DNS on the test device, step 3 shows the system's lookups over TCP 853 and, every time the app starts, these:

```text
8.8.8.8    api.example.com
8.8.8.8    auth.example.com
```

The app's API and login host names leave the device in cleartext UDP to a fixed resolver, ignoring the user's Private DNS. Step 5 shows HTTPS with correct validation follows, so a spoofed answer causes a TLS failure, not interception. The test fails; we rate it Low (privacy leak to any on-path observer, loss of Private DNS, a denial-of-service lever) and recommend removing the custom `Dns` or replacing it with the platform resolver.

### GT-CODE-0047-4: Custom authentication flows instead of platform credential APIs (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

Platform: Android and iOS. Type: static, dynamic and manual. Tools: jadx, ripgrep, `nm`, `codesign` (or `ldid -e`) for entitlements, Burp Suite or mitmproxy, `adb`, Frida.

#### Overview

The test inventories how the app authenticates users (its own accounts, federated sign-in, local unlock) and checks each mechanism against the platform standard in the [authentication table](#android-and-ios-authentication-and-credential-apis). It fails on custom mechanisms where the standard one exists and the custom one is weaker: client-side verification, embedded-WebView sign-in, OAuth without PKCE or an external user agent, and home-made token or device-binding schemes. Whether the login works with password managers is tested in depth in [MASWE-0019](/mobile/maswe-0019-no-autofill-support-for-credential-providers/); local authentication bypass in [MASWE-0020](/mobile/maswe-0020-local-authentication-bypass/).

#### Prerequisites

- Decompiled app; for iOS, the entitlements of the main executable.
- Test accounts, an interception set-up, and for Android `adb`.
- The identity providers the app supports (from the login screen).

#### Steps

1. **Inventory authentication components (Android).**

   ```bash
   ls -d out-smali/smali*/androidx/credentials out-smali/smali*/net/openid/appauth out-smali/smali*/androidx/browser/customtabs \
         out-smali/smali*/com/google/android/libraries/identity/googleid out-smali/smali*/com/google/android/gms/auth/api/signin 2>/dev/null
   unzip -l app.apk | grep -E 'META-INF/androidx\.credentials_credentials\.version|play-services-auth\.properties'
   rg -n 'AccountManager|addAccountExplicitly|android\.accounts\.AccountAuthenticator' out-jadx/ | cut -c1-160 | head
   # WebView-based sign-in
   rg -n -i 'loadUrl\(.*(authorize|oauth|login|signin|/auth)|shouldOverrideUrlLoading' out-jadx/sources/com/example | cut -c1-180
   rg -n 'code_challenge|code_verifier|S256' out-jadx/sources/ | cut -c1-160 | head
   ```

2. **Inventory authentication components (iOS).**

   ```bash
   EXE="$APP/$(plutil -extract CFBundleExecutable raw "$APP/Info.plist")"
   nm -u "$EXE" | grep -E 'OBJC_CLASS_\$_(ASAuthorizationController|ASAuthorizationPasswordProvider|ASAuthorizationPlatformPublicKeyCredentialProvider|ASAuthorizationAppleIDProvider|ASWebAuthenticationSession|WKWebView|SFSafariViewController|LAContext)'
   codesign -d --entitlements :- "$APP" 2>/dev/null | grep -A6 'associated-domains'
   strings -a "$EXE" | grep -E 'code_challenge|S256|/authorize|/oauth' | sort -u | head
   ```

   `webcredentials:example.com` in `com.apple.developer.associated-domains` is what Password AutoFill and passkeys need; its absence in an app with its own accounts is a MASWE-0019 lead.

3. **Walk through every sign-in path** with the proxy running and note, for each:
   - **Where credentials are typed.** On Android, `adb shell dumpsys activity activities | grep -E 'topResumedActivity|mResumedActivity'` while the login page is open: the app's own activity means an in-app form or WebView; the browser's package (for example a `CustomTabActivity` in `com.android.chrome`) means a Custom Tab. On iOS, `ASWebAuthenticationSession` shows a system consent alert ("wants to use example.com to sign in") and a browser sheet; an embedded `WKWebView` shows neither.
   - **Whether the system offers saved passwords or passkeys** (the Credential Manager bottom sheet, the iOS keyboard suggestion or passkey sheet).
   - **The authorisation request** for OAuth/OIDC: `code_challenge` with `code_challenge_method=S256`, `state`, and the `redirect_uri` (an `https` App Link or universal link, or a custom scheme).
   - **Where the password is verified.** If the login completes with no request carrying the credential (or a derivative of it) to a server, verification is local. Confirm with a benign trace of the app's digest calls during login:

     ```bash
     frida-trace -U -f com.example.app -j 'java.security.MessageDigest!digest' -j 'javax.crypto.Mac!doFinal'
     ```

4. **Look for home-made token and device-binding schemes.** In the captured traffic, look for request signatures, "device keys" or tokens that the app computes itself (custom headers such as `X-Signature`, `X-Device-Token`). Trace them back in jadx: an HMAC or signature with a key stored as a constant in the app, or a "device secret" derived from `ANDROID_ID` or `identifierForVendor`, is a home-made scheme. Keys bound to the device should come from the Android Keystore or Secure Enclave and be registered with the server; see [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/) and [MASWE-0013](/mobile/maswe-0013-improper-key-generation/).

5. **Check for stored passwords.** After login, inspect the app's private storage on a test device (`adb shell run-as com.example.app ls -R` for debuggable builds, or root; the keychain with objection on iOS) for the user's password. Storing it for silent re-login is a custom substitute for refresh tokens.

#### Observation

A list of authentication paths with, for each: the mechanism (platform API, library, custom), where credentials are entered, PKCE/state/redirect details, where verification happens, any custom token or binding scheme with its key source, and screenshots or proxy entries as evidence.

#### Evaluation

The test **fails** if any of the following holds:

- primary authentication is verified on the device (local hash comparison unlocks server-side data or functions);
- a third-party or federated sign-in runs in an embedded WebView;
- a native OAuth/OIDC flow lacks PKCE, or uses an embedded user agent;
- requests or devices are authenticated by a home-made scheme with a key in the app or a device identifier as a secret;
- the app stores the user's password for re-login.

Findings about password-manager or passkey support go to MASWE-0019, and deprecated authentication libraries (legacy Google Sign-In, `SFAuthenticationSession`) to [MASWE-0046](/mobile/maswe-0046-use-of-deprecated-apis/). The test **passes** if authentication uses platform credential APIs or a standards-based flow (OAuth 2.0/OIDC in an external user agent with PKCE, passkeys/WebAuthn) and is verified on the server.

#### Demo

```kotlin
class PartnerLoginActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val web = WebView(this).also { setContentView(it) }
        web.settings.javaScriptEnabled = true
        web.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(v: WebView, r: WebResourceRequest): Boolean {
                if (r.url.scheme == "exampleapp") { exchangeCode(r.url.getQueryParameter("code")); return true }
                return false
            }
        }
        web.loadUrl("https://idp.example.org/authorize?client_id=app&response_type=code&redirect_uri=exampleapp://cb")
    }
}
```

Step 3: `dumpsys` shows `com.example.app/.PartnerLoginActivity` resumed while the identity provider's password form is displayed; no password manager offer appears; the captured authorisation request has no `code_challenge` and no `state`. The test fails twice over: the partner's credentials are typed into a WebView the app controls, and the authorisation code is not bound to the client by PKCE. The fix is AppAuth (or a plain Custom Tab) with PKCE and an App Link redirect, shown below.

## Secure implementation

OWASP links no best practices to MASWE-0047. These are the patterns we recommend in reports; each replaces one of the custom mechanisms above with the platform or a vetted library.

**Encryption with a platform-held key (Android).** Either use the Keystore directly (see [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/) for a full example) or Tink, whose keyset is wrapped by a Keystore key:

```kotlin
AeadConfig.register()
val keysetHandle = AndroidKeysetManager.Builder()
    .withSharedPref(context, "app_keyset", "app_keyset_prefs")
    .withKeyTemplate(KeyTemplates.get("AES256_GCM"))
    .withMasterKeyUri("android-keystore://app_master_key")
    .build()
    .keysetHandle
val aead = keysetHandle.getPrimitive(Aead::class.java)   // newer Tink releases also take a Configuration argument
val ciphertext = aead.encrypt(plaintext, "refresh_token".toByteArray())   // associated data binds the context
```

**Encryption on iOS with CryptoKit**, with the key kept in the keychain (or derived from a Secure Enclave key agreement):

```swift
import CryptoKit
let key = SymmetricKey(size: .bits256)                       // store with kSecAttrAccessibleWhenUnlockedThisDeviceOnly
let sealed = try AES.GCM.seal(plaintext, using: key, authenticating: Data("refresh_token".utf8))
let blob = sealed.combined!                                  // nonce || ciphertext || tag
let opened = try AES.GCM.open(try AES.GCM.SealedBox(combined: blob), using: key,
                              authenticating: Data("refresh_token".utf8))
```

**Key derivation and MACs.** Use a real KDF (PBKDF2 with a high iteration count via `SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")` or `CCKeyDerivationPBKDF`, HKDF in CryptoKit or Tink for key material) and HMAC (`Mac.getInstance("HmacSHA256")`, CryptoKit `HMAC<SHA256>`), never a hash of concatenated values. Details and parameters are in [MASWE-0014](/mobile/maswe-0014-improper-key-derivation/) and [MASWE-0009](/mobile/maswe-0009-improper-use-of-mac/).

**Networking through the platform stack.** On Android, OkHttp with the default trust manager, and policy in the NSC; on iOS, `URLSession` with ATS. In Flutter, route HTTP through the platform:

```text
// pubspec.yaml: dependencies cronet_http (Android) and cupertino_http (iOS)
// Dart: choose the platform client once and pass it to package:http users
final http.Client client = Platform.isAndroid
    ? CronetClient.defaultCronetEngine()
    : CupertinoClient.defaultSessionConfiguration();
```

If a native SDK must keep its own TLS stack, ask the vendor for: the platform trust store (on Android, the system CA directory or a callback into the platform `X509TrustManager`), pins matching those in the NSC or ATS, TLS 1.2+, and a library version that is tracked in your SBOM. Never ship an unmaintained CA bundle.

**Encrypted DNS the standard way (iOS).** If the app must not depend on the network's resolver, require encrypted resolution for its own connections with the Network framework rather than shipping a resolver:

```swift
import Network
// Apply to every connection that does not use a custom privacy context
NWParameters.PrivacyContext.default.requireEncryptedNameResolution(
    true,
    fallbackResolver: .https(URL(string: "https://dns.example.net/dns-query")!, serverAddresses: [])
)
```

On Android, leave resolution to the system (`Dns.SYSTEM` in OkHttp, `InetAddress`, `DnsResolver`), which follows Private DNS.

**Sign-in with Credential Manager (Android).**

```kotlin
val credentialManager = CredentialManager.create(context)
val request = GetCredentialRequest(listOf(
    GetPasswordOption(),
    GetPublicKeyCredentialOption(requestJson = passkeyRequestJsonFromServer)   // WebAuthn options from your server
))
val result = credentialManager.getCredential(activity, request)               // suspend; shows the system sheet
when (val c = result.credential) {
    is PasswordCredential -> signInWithPassword(c.id, c.password)              // verified by the server
    is PublicKeyCredential -> verifyAssertionOnServer(c.authenticationResponseJson)
}
```

**Sign-in with passkeys and passwords (iOS).**

```swift
let passkey = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: "example.com")
    .createCredentialAssertionRequest(challenge: challengeFromServer)
let password = ASAuthorizationPasswordProvider().createRequest()
let controller = ASAuthorizationController(authorizationRequests: [passkey, password])
controller.delegate = self
controller.presentationContextProvider = self
controller.performRequests()
```

The app needs `webcredentials:example.com` in its associated domains and the matching `apple-app-site-association` file on the server ([MASWE-0019](/mobile/maswe-0019-no-autofill-support-for-credential-providers/)).

**Third-party sign-in in the system browser with PKCE.** On Android, AppAuth (`net.openid:appauth`) builds the request with PKCE by default and opens a Custom Tab; register an App Link (`https`) as the redirect where the identity provider allows it. On iOS:

```swift
let session = ASWebAuthenticationSession(url: authorizeURLWithPKCE,
                                         callbackURLScheme: "com.example.app") { callbackURL, error in
    guard let url = callbackURL, error == nil else { return }
    exchangeCodeOnServerOrWithVerifier(url)    // check state, send code_verifier with the token request
}
session.presentationContextProvider = self
session.start()
```

**Verify on the server.** Passwords, OTPs, passkey assertions and device-bound signatures are verified by the backend. Local unlock (biometrics, app PIN) should release a key from the Keystore or keychain, not flip a boolean ([MASWE-0020](/mobile/maswe-0020-local-authentication-bypass/)).

## Rating findings

Rate on three things: **what the non-standard component protects** (credentials and keys, other sensitive data, an authentication or authorisation decision, nothing sensitive), **how far it falls short of the standard** (broken by reading the code; vetted but stale or bypassing a declared policy; merely different), and **the attacker position** needed to exploit the gap (anyone with the APK or IPA, a network attacker, someone with access to backups or the device, a malicious app or page). Where the gap is a concrete break (a pin not enforced, a certificate accepted, a token readable), rate the break in its own note and cite this note for the cause; use the table below for the non-standard component itself.

| Rating | Conditions |
|---|---|
| **Critical** | Authentication or authorisation can be bypassed by anyone with the app binary because of a custom mechanism: client-side password verification guarding server-side data; a request-signing or device-binding scheme whose key is in the app and that the server trusts as proof of identity. A custom TLS stack carrying credentials that accepts any certificate (the break is rated under MASWE-0027). |
| **High** | Home-made or non-cryptographic "encryption" of credentials, tokens or keys in a location an attacker can reach (backups, shared storage, network); a bundled stack that bypasses declared NSC/ATS pins or user-CA restrictions for authentication or payment traffic; third-party credentials entered in an embedded WebView; OAuth without PKCE where another app can receive the redirect; passwords stored for silent re-login. |
| **Medium** | Unvetted or unmaintained crypto libraries protecting sensitive data without a known break; a bundled stack with a stale trust store or library but correct validation; home-made encryption of non-credential personal data in app-private storage; custom DNS that falls back from DoH to plain DNS for sensitive hosts, or whose answers drive a security decision; custom login that breaks password managers (rated with MASWE-0019). |
| **Low** | Custom plain-DNS or HTTPDNS resolution followed by correctly validated HTTPS; a vetted library bundled where a platform API would do (for example CryptoSwift for SHA-256), used correctly; proxy-unaware but otherwise correct platform-equivalent stacks for non-sensitive traffic. |
| **Info** | Bundled Conscrypt on non-GMS devices per MASTG-BEST-0020; Tink, libsodium or SQLCipher in current versions; proxy-unaware stacks that only complicate testing; recommendations to move cross-platform HTTP onto the platform client. |

Raise a level when the component sits on the login, payment or key-management path, or affects every user at every start; when the same weakness is in an SDK shipped to many apps; or when a declared policy (NSC pins, ATS) gives the client a false sense of protection. Lower a level when exploitation needs a rooted or jailbroken device the attacker controls *and* only affects that attacker's own account. In the report, name the component and version, where it lives (package, `.so`, framework), what it protects, the platform standard it replaces, the evidence (decompiled excerpt, differential test table, capture, Frida log), and the standard replacement.

## References

- OWASP MASWE: [MASWE-0047: Using Non-Standard APIs for Security-Critical Functionality](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0047/); related [MASWE-0069](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0069/), [MASWE-0046](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0046/), [MASWE-0044](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0044/), [MASWE-0019](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0019/), [MASWE-0026](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0026/), [MASWE-0027](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0027/), [MASWE-0028](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0028/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-CODE-3](https://mas.owasp.org/MASVS/controls/MASVS-CODE-3/), [MASVS-AUTH-1](https://mas.owasp.org/MASVS/controls/MASVS-AUTH-1/), [MASVS-CRYPTO-1](https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-1/), [MASVS-NETWORK-1](https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-1/) (CC BY-SA 4.0)
- OWASP MASTG tests referenced: [MASTG-TEST-0239](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0239/) (placeholder), [MASTG-TEST-0234](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0234/), [MASTG-TEST-0345](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0345/) (CC BY-SA 4.0)
- OWASP MASTG best practices and knowledge: [MASTG-BEST-0020](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0020/), [MASTG-KNOW-0011](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0011/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0082](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0082/), [MASTG-TECH-0109](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0109/), [MASTG-TECH-0110](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0110/), [MASTG-TECH-0130](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0130/), [MASTG-TECH-0132](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0132/) (CC BY-SA 4.0)
- OWASP MASTG tools: [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [Apktool (MASTG-TOOL-0011)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/), [radare2 for Android (MASTG-TOOL-0028)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0028/), [radare2 for iOS (MASTG-TOOL-0073)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/), [Frida (MASTG-TOOL-0031)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/), [reFlutter (MASTG-TOOL-0100)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0100/) (CC BY-SA 4.0)
- Android Developers: [Security tips: credentials](https://developer.android.com/privacy-and-security/security-tips#Credentials), [Cryptography (crypto provider guidance)](https://developer.android.com/privacy-and-security/cryptography#crypto_provider), [Network security configuration](https://developer.android.com/privacy-and-security/security-config), [`<application>` element (`usesCleartextTraffic`, best-effort note on `Socket`)](https://developer.android.com/guide/topics/manifest/application-element), [Insecure DNS Setup](https://developer.android.com/privacy-and-security/risks/bad-dns), [`DnsResolver`](https://developer.android.com/reference/android/net/DnsResolver), [Credential Manager](https://developer.android.com/identity/sign-in/credential-manager), [Update your security provider](https://developer.android.com/privacy-and-security/security-gms-provider); Android Developers Blog: [DNS over TLS support in Android P](https://android-developers.googleblog.com/2018/04/dns-over-tls-support-in-android-p.html); Google Security Blog: [DNS-over-HTTP/3 in Android](https://security.googleblog.com/2022/07/dns-over-http3-in-android.html)
- Apple Developer: [Password AutoFill](https://developer.apple.com/documentation/security/password_autofill), [Preventing insecure network connections](https://developer.apple.com/documentation/security/preventing-insecure-network-connections), [`NWParameters.PrivacyContext`](https://developer.apple.com/documentation/network/nwparameters/privacycontext), [`ASAuthorizationController`](https://developer.apple.com/documentation/authenticationservices/asauthorizationcontroller), [`ASWebAuthenticationSession`](https://developer.apple.com/documentation/authenticationservices/aswebauthenticationsession), [CryptoKit](https://developer.apple.com/documentation/cryptokit)
- Standards: [RFC 8252: OAuth 2.0 for Native Apps](https://www.rfc-editor.org/rfc/rfc8252), [RFC 7636: Proof Key for Code Exchange](https://www.rfc-editor.org/rfc/rfc7636), [BSI TR-02102-1: Cryptographic Mechanisms](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.pdf?__blob=publicationFile), [NIST CMVP (FIPS 140-3 validated modules)](https://csrc.nist.gov/projects/cryptographic-module-validation-program)
- Libraries: [Tink](https://developers.google.com/tink), [Conscrypt](https://github.com/google/conscrypt), [AppAuth for Android](https://github.com/openid/AppAuth-Android)
- CWE: [CWE-287](https://cwe.mitre.org/data/definitions/287.html), [CWE-326](https://cwe.mitre.org/data/definitions/326.html), [CWE-327](https://cwe.mitre.org/data/definitions/327.html), [CWE-1240](https://cwe.mitre.org/data/definitions/1240.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
