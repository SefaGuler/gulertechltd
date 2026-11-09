---
title: "Network Traffic Not Encrypted: Cleartext Traffic (MASWE-0026, Part 1)"
date: 2026-11-09 16:00:00 +0000
subcategory: network
summary: "Finding cleartext traffic in Android and iOS apps: NSC and ATS in depth, HTTP URLs, raw sockets, cross-platform frameworks, BLE, capture and Frida."
refs: [MASWE-0026, MASVS-NETWORK-1, CWE-319]
tags: [android, ios, masvs-network, cleartext, network-security-config, app-transport-security]
---

This note is part of our [MASVS-NETWORK guide](/mobile/masvs-network-secure-communication-guide/) and covers the cleartext half of OWASP [MASWE-0026](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0026/): an app that sends or receives data without encrypting it in transit. That means plain HTTP, but also `ws://` WebSockets, MQTT on port 1883, plaintext gRPC, FTP, SMTP without STARTTLS, hand-rolled protocols over raw sockets, and data sent over Bluetooth, NFC or Wi-Fi Direct without encryption. The other half of MASWE-0026, connections that *are* encrypted but with TLS 1.0 or 1.1, is in [Part 2: insecure TLS protocol versions](/mobile/maswe-0026-insecure-tls-protocol-versions/). This note is also where the series explains the platform mechanisms in full: Android's Network Security Configuration and iOS App Transport Security, with their schemas, precedence rules and defaults by `targetSdk` and iOS version. The notes on [certificate validation](/mobile/maswe-0027-insecure-certificate-validation/) and [pinning](/mobile/maswe-0028-insecure-identity-pinning/) refer back here. After that come the nine OWASP tests (three of them OWASP placeholders that we have written ourselves), our supplementary checks for WebViews, SDKs and proximity channels, secure configurations and severity guidance.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: Network Security Configuration (MASTG-KNOW-0014)](#android-network-security-configuration-mastg-know-0014)
  - [iOS: App Transport Security (MASTG-KNOW-0071)](#ios-app-transport-security-mastg-know-0071)
  - [iOS: Network APIs (MASTG-KNOW-0073)](#ios-network-apis-mastg-know-0073)
- [Tests](#tests)
  - [Legacy tests and how to approach this weakness](#legacy-tests-and-how-to-approach-this-weakness)
  - [MASTG-TEST-0233: Hardcoded HTTP URLs (Android)](#mastg-test-0233-hardcoded-http-urls-android)
  - [MASTG-TEST-0235: Android App Configurations Allowing Cleartext Traffic (Android)](#mastg-test-0235-android-app-configurations-allowing-cleartext-traffic-android)
  - [MASTG-TEST-0236: Cleartext Traffic Observed on the Network (Android and iOS)](#mastg-test-0236-cleartext-traffic-observed-on-the-network-android-and-ios)
  - [MASTG-TEST-0237: Cross-Platform Framework Configurations Allowing Cleartext Traffic (Android)](#mastg-test-0237-cross-platform-framework-configurations-allowing-cleartext-traffic-android)
  - [MASTG-TEST-0238: Runtime Use of Network APIs Transmitting Cleartext Traffic (Android)](#mastg-test-0238-runtime-use-of-network-apis-transmitting-cleartext-traffic-android)
  - [MASTG-TEST-0239: Using Low-Level APIs (e.g. Socket) to Set Up a Custom HTTP Connection (Android)](#mastg-test-0239-using-low-level-apis-eg-socket-to-set-up-a-custom-http-connection-android)
  - [MASTG-TEST-0321: Hardcoded HTTP URLs (iOS)](#mastg-test-0321-hardcoded-http-urls-ios)
  - [MASTG-TEST-0322: App Transport Security Configurations Allowing Cleartext Traffic (iOS)](#mastg-test-0322-app-transport-security-configurations-allowing-cleartext-traffic-ios)
  - [MASTG-TEST-0323: Uses of Low-Level Networking APIs for Cleartext Traffic (iOS)](#mastg-test-0323-uses-of-low-level-networking-apis-for-cleartext-traffic-ios)
  - [Supplementary checks (Guler Tech methodology)](#supplementary-checks-guler-tech-methodology)
  - [GT-0026-1: WebView cleartext and mixed content (Android and iOS)](#gt-0026-1-webview-cleartext-and-mixed-content-android-and-ios)
  - [GT-0026-2: Third-party SDKs and native libraries (Android and iOS)](#gt-0026-2-third-party-sdks-and-native-libraries-android-and-ios)
  - [GT-0026-3: Unencrypted machine-to-machine channels (BLE, NFC, Wi-Fi Direct, USB)](#gt-0026-3-unencrypted-machine-to-machine-channels-ble-nfc-wi-fi-direct-usb)
- [Secure implementation](#secure-implementation)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

MASWE-0026 states the requirement plainly: *"The app encrypts all network traffic."* It maps to MASVS-NETWORK-1 ("The app secures all network traffic according to the current best practices") and to CWE-319, Cleartext Transmission of Sensitive Information. OWASP describes the threat as MAS-THREAT-0026, *attackers can intercept or modify cleartext network traffic*, and lists three ways they do it:

- **MAS-ATTACK-0012**: monitoring traffic on the same network, such as public Wi-Fi or a compromised router. This is passive. On an open hotspot anyone in radio range can record every frame. On a WPA2-Personal network, any client that knows the passphrase and captures a victim's four-way handshake can decrypt that victim's frames. WPA3-SAE closes that particular gap, but the router, the ISP and everything upstream still see the plaintext.
- **MAS-ATTACK-0013**: monitoring local or proximity interfaces such as Bluetooth, NFC or USB. The attacker needs to be within radio range (metres for BLE, centimetres for NFC) or to have a sniffer on the link.
- **MAS-ATTACK-0014**: an active machine-in-the-middle, through ARP poisoning, DNS spoofing or a rogue access point. Against cleartext the attacker does not need a trusted certificate, a compromised CA, a rooted device or any cooperation from the user. They just rewrite bytes.

That last point explains why cleartext usually rates higher than the other network weaknesses. Breaking a TLS connection whose certificate validation works needs a CA compromise or a certificate the user installed. Breaking a cleartext connection needs a position on the path and nothing else.

The weakness applies even when the cleartext traffic carries nothing sensitive. Integrity matters as well as confidentiality. An attacker who can modify a plain-HTTP response can change prices, links, phone numbers and images shown in a banking app; replace a JavaScript file loaded into a WebView that has a native bridge; serve a forged "update available" message pointing to a phishing page; or redirect the next request somewhere else. TLS with proper certificate validation gives you confidentiality, integrity and server authentication together; cleartext gives you none of them.

Both platforms now block plain HTTP by default for their standard HTTP stacks: Android for apps targeting API 28 or higher, iOS through ATS since iOS 9. So most findings in this area are not "the developer forgot". They come from one of three places:

1. **A configuration opt-out**: `cleartextTrafficPermitted="true"`, `android:usesCleartextTraffic="true"`, `NSAllowsArbitraryLoads`, `NSExceptionAllowsInsecureHTTPLoads`. These are often added during development and never removed.
2. **A code path the platform policy does not see**: `java.net.Socket`, native code, BSD sockets, Network.framework, CFNetwork, and the bundled networking stacks of Flutter, Unity, .NET, gRPC, MQTT and other libraries.
3. **A platform version or build variant where the default does not apply**: an Android 8.1 device running an app that targets API 34 still allows cleartext unless the app opts out explicitly; a debug-variant NSC that ends up in the release build; a library manifest whose `usesCleartextTraffic="true"` is merged into the app.

The static tests below find all three. The dynamic tests confirm what actually goes over the wire.

## Modes of Introduction

OWASP lists seven ways the weakness gets into an app. Here is what each looks like in a real APK or IPA.

- **Cleartext allowed in platform-provided settings.** On Android: `cleartextTrafficPermitted="true"` on `<base-config>` (all hosts) or on a `<domain-config>` (named hosts), or `android:usesCleartextTraffic="true"` when no NSC is present. On iOS: `NSAllowsArbitraryLoads`, `NSAllowsArbitraryLoadsInWebContent`, `NSAllowsArbitraryLoadsForMedia`, or `NSExceptionAllowsInsecureHTTPLoads` on a domain. A common pattern is a staging-server exception (`dev.example.com`, an IP address, `10.0.2.2`) that ships to production with `includeSubdomains`/`NSIncludesSubdomains` set on the parent domain.
- **Use of HTTP.** `http://` base URLs in Retrofit, `URL`, `URLSession` or a WebView; URLs built at runtime (`Uri.Builder().scheme("http")`, `URLComponents` with `scheme = "http"`); URLs received from a server or remote config; HTTP redirects that the client follows from HTTPS to HTTP.
- **Use of non-HTTP insecure protocols.** `ws://` WebSockets, MQTT on 1883 (`tcp://`) instead of 8883 (`ssl://`), gRPC channels built with `usePlaintext()`, FTP, SMTP/IMAP/XMPP without TLS or STARTTLS, Redis, SIP, RTSP and custom binary protocols.
- **Unencrypted machine-to-machine channels.** BLE characteristics readable or writable without encryption, BLE "Just Works" pairing (which encrypts the link but gives no protection against an active MITM during pairing), classic Bluetooth `createInsecureRfcommSocketToServiceRecord`, raw NFC APDUs carrying secrets, Wi-Fi Direct or local-network sockets with no TLS, `MCSession` created with `encryptionPreference: .none`, unencrypted USB accessory protocols.
- **Low-level network APIs.** `java.net.Socket`, `SocketChannel`, `DatagramSocket` and native `connect()`/`send()` on Android; Network.framework, CFNetwork streams and BSD sockets on iOS. None of these consult Android's cleartext policy or ATS, because they cannot tell whether the bytes they carry are encrypted.
- **Cross-platform framework misconfiguration.** Capacitor `server.cleartext: true`, Cordova `<access origin="*">`, React Native or Expo templates whose debug cleartext settings leak into release builds, .NET MAUI/Xamarin apps using the managed `HttpClientHandler` (which bypasses NSC and ATS), Flutter's `dart:io` stack, which has its own sockets and ignores the system proxy, and Unity's "Allow downloads over HTTP" player setting.
- **Third-party libraries.** Ad, analytics and attribution SDKs, map tiles, crash reporters, chat and video SDKs with their own native stack, or an SDK whose manifest merges `usesCleartextTraffic="true"` into the app.

## Impact

- **Disclosure of sensitive data.** Anyone on the path can read credentials, session and refresh tokens, API keys, personal and health data, location, device identifiers and message content.
- **Authentication and authorisation bypass.** A captured bearer token or session cookie lets the attacker act as the user until the token expires. A captured refresh token or password extends that indefinitely. See the [MASVS-AUTH guide](/mobile/masvs-auth-authentication-guide/) for what a stolen token is worth.
- **Integrity of the app and its content.** Responses can be modified: content injection into native screens and WebViews, JavaScript injection that reaches a WebView bridge, tampered configuration (feature flags, API base URLs, certificate pins delivered from the server), tampered downloads (code-push bundles, ML models, plug-ins). Where a downloaded artefact is executed, the impact can reach code execution inside the app.
- **Phishing and redirection.** The attacker can serve a convincing login page or redirect the user, and the app shows it as trusted content.
- **Regulatory exposure.** Personal data transmitted in cleartext is a failure of "appropriate technical measures" under UK GDPR Article 32, and similar provisions in HIPAA and PCI DSS (which requires strong cryptography for cardholder data over open, public networks).

## Mitigations

- **Use TLS for every connection.** HTTPS and `wss://` for web traffic; TLS or STARTTLS-required variants for other protocols (MQTT over 8883, gRPC with transport security, SFTP or FTPS, SMTPS or SMTP with mandatory STARTTLS). For proximity channels, add encryption at the application layer rather than relying on the link layer alone.
- **Make cleartext impossible in configuration, not just unused.** On Android ship an NSC with `<base-config cleartextTrafficPermitted="false">` and also set `android:usesCleartextTraffic="false"` so that devices on API 23, and devices on API 24–27 where the platform default is still "allowed", are covered. On iOS leave ATS at its defaults; do not add `NSAllowsArbitraryLoads`.
- **Keep exceptions narrow, justified and temporary.** If one legacy host truly cannot do TLS, add a per-domain exception for that exact host, without subdomains, document the reason, and make sure nothing sensitive goes to it. Apple requires a written justification during App Store review for most exceptions.
- **Fix the server, not the client.** An exception in the app is permanent for every installed copy until users update. A certificate on the server fixes the problem for every client at once.
- **Prefer high-level APIs that enforce the policy.** On Android: `HttpURLConnection`/`HttpsURLConnection` and OkHttp, both of which check the cleartext policy. On iOS: `URLSession`, which ATS covers. Use sockets, Network.framework or a bundled stack only when you need them, and then configure TLS yourself.
- **Configure cross-platform frameworks explicitly** and check the compiled output (merged manifest, compiled `Info.plist`, generated config), not just the project's settings file.
- **Vet and pin down third-party components.** Know which SDKs do their own networking, what they send and to which hosts, and keep them updated. See [MASTG-KNOW-0004: Third-party libraries](/mobile/mastg-know-0004-third-party-libraries/).

## Knowledge

The three knowledge items below describe the platform mechanisms that decide whether cleartext is allowed. The other MASVS-NETWORK notes rely on them as well: trust anchors and pinning in the NSC, and ATS's TLS requirements, come up again in [MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/), [MASWE-0028](/mobile/maswe-0028-insecure-identity-pinning/) and [Part 2](/mobile/maswe-0026-insecure-tls-protocol-versions/).

### Android: Network Security Configuration (MASTG-KNOW-0014)

Source: [MASTG-KNOW-0014](https://mas.owasp.org/MASTG/knowledge/android/MASVS-NETWORK/MASTG-KNOW-0014/), extended with the current [Android developer documentation](https://developer.android.com/privacy-and-security/security-config).

The Network Security Configuration (NSC), introduced in Android 7.0 (API 24), is a declarative XML file that controls an app's network security without code changes. It covers five things:

- **Cleartext traffic**: whether HTTP and other unencrypted protocols are permitted, app-wide or per host.
- **Trust anchors**: which CAs the app trusts, such as system CAs, user-installed CAs, or certificates bundled in the APK.
- **Certificate pinning**: SHA-256 hashes of the `SubjectPublicKeyInfo` that a chain must contain.
- **Debug overrides**: extra trust anchors that apply only when the app is debuggable.
- **Certificate transparency** (Android 16, API 36, and later) and **Encrypted Client Hello** (Android 17, API 37, and later).

#### Where the configuration lives

The manifest points to the file:

```xml
<application
    android:networkSecurityConfig="@xml/network_security_config"
    android:usesCleartextTraffic="false"
    ... >
```

After `apktool d` the reference `@xml/network_security_config` resolves to `res/xml/network_security_config.xml`. The name is arbitrary, so always follow the reference rather than looking for the default name. Three pitfalls:

- **Resource qualifiers.** An app can ship more than one version of the file: `res/xml/`, `res/xml-v28/`, `res/xml-v31/` and so on. Android picks the best match for the device's API level. Check every `res/xml*/` directory for a file with that name.
- **Resource references in the manifest.** `android:usesCleartextTraffic="@bool/cleartext"` is legal. Resolve it in `res/values*/bools.xml`.
- **Build variants.** Gradle merges `src/debug/res/xml/network_security_config.xml` only into debug builds. The file you are testing must come from the build that users install. Test the release APK or AAB-derived split, not a debug build the client sent you.

When the app starts, the platform logs which configuration it loaded ([MASTG-TECH-0009](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0009/)):

```bash
adb logcat -s NetworkSecurityConfig
# D NetworkSecurityConfig: Using Network Security Config from resource network_security_config debugBuild: false
# or, when there is none:
# D NetworkSecurityConfig: No Network Security Config specified, using platform default
```

The exact wording differs slightly between Android versions, but the `debugBuild` value is useful: `true` means `<debug-overrides>` is active.

#### File format and schema

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <!-- 0 or 1: applies to every destination not matched by a domain-config -->
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>

    <!-- any number: applies to the listed domains -->
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="false">legacy.example.com</domain>
        <!-- optional: trust-anchors, pin-set, certificateTransparency, domainEncryption,
             and nested domain-config elements -->
    </domain-config>

    <!-- 0 or 1: only honoured when android:debuggable="true" -->
    <debug-overrides>
        <trust-anchors>
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>
```

| Element / attribute | Where | Meaning |
|---|---|---|
| `cleartextTrafficPermitted` | `base-config`, `domain-config` | `true` allows cleartext to the covered destinations. If unset, the value is inherited (see below). |
| `<domain includeSubdomains>` | `domain-config` (one or more) | Host to match. `includeSubdomains="true"` matches the host and every subdomain at any depth; otherwise exact match only. No wildcards, no ports, no schemes. |
| `<trust-anchors>` / `<certificates src>` | `base-config`, `domain-config`, `debug-overrides` | `system`, `user`, or a raw resource (`@raw/my_ca`, PEM or DER). `overridePins="true"` makes chains ending in that source skip pinning; it defaults to `true` inside `debug-overrides`. |
| `<pin-set expiration>` / `<pin digest="SHA-256">` | `domain-config` | SPKI pins. After the `expiration` date (`yyyy-MM-dd`) pinning is **disabled** for that domain, and the app falls back to ordinary CA validation. Details in [MASWE-0028](/mobile/maswe-0028-insecure-identity-pinning/). |
| `<certificateTransparency enabled>` | `base-config`, `domain-config` | API 36+. Off by default on Android 16 and on by default from Android 17 (API 37). It is not applied to chains that end in a `user` or bundled anchor unless forced. |
| `<domainEncryption mode>` | `base-config`, `domain-config` | API 37+. Controls Encrypted Client Hello; `enabled` by default for apps targeting API 37+. |

#### Inheritance and precedence

The NSC resolves a configuration for each destination host:

1. **The most specific matching `domain-config` wins.** If `example.com` (with `includeSubdomains="true"`) and `api.example.com` are both configured, connections to `api.example.com` use the second one, because it is the longest match. A nested `domain-config` is matched in the same way.
2. **Unset values are inherited.** A `domain-config` that does not set `cleartextTrafficPermitted` takes the value from its parent `domain-config` if it is nested, otherwise from `base-config`.
3. **Unset `base-config` values come from the platform defaults** for the app's `targetSdkVersion`, as shown in the next section.
4. **Hosts with no matching `domain-config` use `base-config`.**

Two consequences for testers. First, a secure-looking `base-config` says nothing about the hosts listed in a `domain-config`. You have to read every `domain-config`. Second, `includeSubdomains="true"` on a registrable domain covers every subdomain, including ones created years later and ones that a third party hosts for the client.

The no-argument method `NetworkSecurityPolicy.getInstance().isCleartextTrafficPermitted()` reports the app-wide value, and `isCleartextTrafficPermitted(String hostname)` (API 24) reports the value resolved for one host. You can call both from Frida to confirm the effective policy on a given device (see TEST-0235).

#### Defaults by targetSdk and device version

When the app has no NSC, or its `base-config` leaves something unset, these platform defaults apply:

| App targets | Default `base-config` |
|---|---|
| API 28 (Android 9) and higher | `cleartextTrafficPermitted="false"`, trust `system` only |
| API 24–27 (Android 7.0–8.1) | `cleartextTrafficPermitted="true"`, trust `system` only |
| API 23 (Android 6.0) and lower | `cleartextTrafficPermitted="true"`, trust `system` and `user` |

The table is keyed on `targetSdkVersion`, but the device's Android version decides which rules exist at all. That gives this effective matrix, which OWASP's [MASTG-BEST-0010](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0010/) also highlights:

| Device runs | What decides cleartext |
|---|---|
| Android 5.x and lower (API ≤ 22) | Nothing. There is no platform cleartext policy; every stack may send HTTP. |
| Android 6.0 (API 23) | `android:usesCleartextTraffic` only (default `true`). There is no NSC on this version. |
| Android 7.0–8.1 (API 24–27) | NSC if present; otherwise `usesCleartextTraffic`; otherwise **allowed**. The "blocked by default for target 28+" rule does not exist on these versions, so an app targeting API 35 with `minSdk 24` and no explicit opt-out sends HTTP on an Android 8.1 phone. |
| Android 9 (API 28) and higher | NSC if present (unset values fall back to the `targetSdk`-based defaults); otherwise `usesCleartextTraffic`; otherwise blocked for apps targeting API 28+. |
| Android 17 (API 37) and higher | As above, plus an implicit configuration for `localhost`, `ip6-localhost` and loopback IP literals that allows cleartext and skips CT and pinning, unless the app configures those hosts itself. |

User-installed CAs stopped being trusted by default for apps targeting API 24 and higher. That matters for interception (see the [lab note](/mobile/mobile-traffic-interception-lab/)) and for [MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/), not for cleartext.

#### usesCleartextTraffic versus the NSC

`android:usesCleartextTraffic` was added in API 23. It is a single app-wide flag with no per-host granularity, and its default follows `targetSdkVersion` (true up to 27, false from 28). The rules:

- On Android 7.0 and higher, **the flag is ignored if the app has an NSC.** Even an empty `<network-security-config/>` counts. The NSC's own values, or the `targetSdk` defaults, apply instead. This is why OWASP's TEST-0235 does not fail an app that sets the flag to `true` but also ships an NSC.
- On Android 6.0 the flag is the only control, and the NSC is ignored.
- The flag is being deprecated. Google's manifest reference says it will be ignored for apps targeting API level 38 and above, and recommends the NSC for API 24+ and the flag in addition for apps that still support API 23.
- Library manifests are merged into the app manifest. If the app does not set the attribute and an SDK's manifest sets `usesCleartextTraffic="true"`, the merged manifest contains `true`. Always read the merged manifest from the built APK, never the source `AndroidManifest.xml`.

#### debug-overrides

`<debug-overrides>` applies only when the app is `android:debuggable="true"`. When it is not, the platform ignores the whole section. It can contain **only `<trust-anchors>`**. You cannot enable cleartext in it. Teams that want HTTP in debug builds use a debug-variant NSC file instead, and that is where release builds most often go wrong. A `debug-overrides` section in a release build is harmless as long as the release build really is not debuggable. If `android:debuggable="true"` shipped to production, report that separately; it is a serious finding in its own right.

#### What the NSC does not cover

The cleartext flag is honoured on a best-effort basis by components that ask for it, either through `ApplicationInfo.flags` or through `NetworkSecurityPolicy.isCleartextTrafficPermitted()`:

- **Covered:** the platform `HttpURLConnection`, OkHttp 3 and later (which checks the policy per host before sending a cleartext request), Volley and Retrofit (which sit on top of these), `DownloadManager`, `MediaPlayer`, and WebView for apps targeting API 26 and higher. In practice WebView uses the app-wide value rather than per-host rules, so check its behaviour on the device and do not assume that a per-domain NSC exception applies inside a WebView.
- **Not covered:** `java.net.Socket`, `SocketChannel`, `DatagramSocket` and anything built on them; native code (`libcurl`, custom C/C++ networking, game engines); Flutter's `dart:io` `HttpClient`; .NET's managed `SocketsHttpHandler`; gRPC with `usePlaintext()` (Netty or OkHttp transport); MQTT clients; and any library with its own socket layer. Android's documentation says so directly: a `Socket` cannot know whether its traffic is cleartext.

When the policy blocks a request you will see one of these in logcat or in the app's error handling. Both show that the app *tried* to send cleartext:

```text
java.io.IOException: Cleartext HTTP traffic to api.example.com not permitted
java.net.UnknownServiceException: CLEARTEXT communication to api.example.com not permitted by network security policy
```

The first comes from the platform `HttpURLConnection`, the second from OkHttp.

### iOS: App Transport Security (MASTG-KNOW-0071)

Source: [MASTG-KNOW-0071](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-NETWORK/MASTG-KNOW-0071/), extended with Apple's [`NSAppTransportSecurity`](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity) reference and [Preventing Insecure Network Connections](https://developer.apple.com/documentation/security/preventing-insecure-network-connections).

App Transport Security (ATS) is on by default for apps linked against the iOS 9 SDK or later. If an app is linked against an older SDK, ATS is off whatever iOS version it runs on, though no current app can be built that way. ATS is enforced inside the URL Loading System (`URLSession` and everything built on it) and inside `WKWebView` and AVFoundation media loads. It is configured with the `NSAppTransportSecurity` dictionary in the app's `Info.plist`.

#### What ATS enforces

Without exceptions, a connection must:

- use HTTPS (plain `http://` is refused with `NSURLErrorAppTransportSecurityRequiresSecureConnection`, code −1022);
- negotiate TLS 1.2 or later;
- use a forward-secret ECDHE key exchange with an AES-128 or AES-256 cipher (GCM or CBC);
- present a certificate signed with SHA-256 or stronger and an RSA key of at least 2048 bits or an ECC key of at least 256 bits;
- pass default server trust evaluation: not expired, name matches the host, chain to a trusted root (system or user/MDM-installed and fully trusted), and the revocation and Certificate Transparency policy the OS applies to publicly trusted certificates.

The TLS-version and cipher requirements are covered in [Part 2](/mobile/maswe-0026-insecure-tls-protocol-versions/), and trust evaluation in [MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/). This note is about the first bullet and the keys that remove it.

#### The NSAppTransportSecurity dictionary

```text
NSAppTransportSecurity : Dictionary
    NSAllowsArbitraryLoads               : Boolean   (iOS 9+)
    NSAllowsArbitraryLoadsForMedia       : Boolean   (iOS 10+)
    NSAllowsArbitraryLoadsInWebContent   : Boolean   (iOS 10+)
    NSAllowsLocalNetworking              : Boolean   (iOS 10+)
    NSExceptionDomains : Dictionary
        <domain-name, IP address or CIDR range> : Dictionary
            NSIncludesSubdomains                  : Boolean
            NSExceptionAllowsInsecureHTTPLoads    : Boolean
            NSExceptionMinimumTLSVersion          : String  (TLSv1.0 | TLSv1.1 | TLSv1.2 | TLSv1.3)
            NSExceptionRequiresForwardSecrecy     : Boolean (default YES)
            NSRequiresCertificateTransparency     : Boolean (Apple now marks it obsolete)
    NSPinnedDomains : Dictionary         (iOS 14+, identity pinning, see MASWE-0028)
```

All the Boolean keys default to `NO`, except `NSExceptionRequiresForwardSecrecy`, which defaults to `YES`.

#### Global keys and what each exempts

| Key | What it exempts | Cleartext? |
|---|---|---|
| `NSAllowsArbitraryLoads` | All ATS requirements for every host **not** listed in `NSExceptionDomains`. HTTP is allowed; HTTPS still gets default trust evaluation, but the TLS-version and cipher requirements are dropped, and the app is free to weaken trust evaluation in its delegate. | Yes, for all unlisted hosts, unless it is ignored (see precedence). |
| `NSAllowsArbitraryLoadsInWebContent` | ATS for `WKWebView` loads only; `URLSession` stays protected. Meant for browsers and apps that display arbitrary web content. | Yes, inside web views. |
| `NSAllowsArbitraryLoadsForMedia` | ATS for media loaded through AVFoundation (for example `AVPlayer` streaming HLS). Meant for media whose content is already protected, such as DRM-protected streams. | Yes, for AVFoundation media. |
| `NSAllowsLocalNetworking` | Lets the app reach unqualified host names, `.local` hosts and IP addresses without disabling ATS elsewhere. | Yes, to local hosts. |

#### Per-domain keys

| Key | Effect |
|---|---|
| `NSIncludesSubdomains` | Applies the domain's dictionary to every subdomain. Without it, only the exact host matches. Use it instead of wildcards, which are not supported. |
| `NSExceptionAllowsInsecureHTTPLoads` | Allows `http://` to that host. It also *permits* the app to relax server trust evaluation for HTTPS to that host in its own authentication-challenge handler, but on its own it does not change trust evaluation, the TLS minimum or the forward-secrecy requirement. |
| `NSExceptionMinimumTLSVersion` | Lowers the minimum TLS version for the host. See [Part 2](/mobile/maswe-0026-insecure-tls-protocol-versions/). |
| `NSExceptionRequiresForwardSecrecy` | `NO` allows non-ECDHE cipher suites. See Part 2. |
| `NSRequiresCertificateTransparency` | Historically required CT for the host; Apple now documents it as obsolete. |

Domain names must be lowercase, without port or trailing dot. Since iOS 17 the key can also be an IPv4 or IPv6 address or a CIDR range. Matching is literal: an exception for `api.example.com` does not apply when the app connects to that host's IP address, and the reverse is also true.

You will still find old variants in legacy projects and SDK integration guides: `NSTemporaryExceptionAllowsInsecureHTTPLoads`, `NSTemporaryExceptionMinimumTLSVersion`, `NSThirdPartyException…`. Apple no longer documents them, but OWASP notes that the temporary variants still work. Treat them exactly like their `NSException…` equivalents.

#### Precedence and OS-version behaviour

These rules decide what actually applies. They are also where most mistakes in reports come from:

1. **A domain listed in `NSExceptionDomains` ignores every global key.** That holds even if its dictionary is empty. So `NSAllowsArbitraryLoads = YES` with `secure.example.com: {}` disables ATS everywhere *except* `secure.example.com`, which gets full ATS.
2. **On iOS 10 and later, `NSAllowsArbitraryLoads` is ignored (treated as `NO`) if `NSAllowsArbitraryLoadsInWebContent`, `NSAllowsArbitraryLoadsForMedia` or `NSAllowsLocalNetworking` is present, whatever its value.** Apple designed this so that apps could ship `NSAllowsArbitraryLoads` for iOS 9 and a narrower key for iOS 10+. On iOS 9 the opposite applied, and the narrower keys were ignored. Every supported iOS version now follows the iOS 10 rule, so an `Info.plist` with both `NSAllowsArbitraryLoads = YES` and `NSAllowsArbitraryLoadsInWebContent = YES` does **not** disable ATS for `URLSession`.
3. **The key name must be exact.** ATS ignores unknown keys. OWASP's own demo uses `NSAllowsArbitraryLoadsForLocalNetworking`, which is not an Apple key and has no effect. Only the three real names in rule 2 trigger the "ignore arbitrary loads" behaviour.
4. **Local networking changed in iOS 17.** From iOS 10 to iOS 16, ATS did not restrict unqualified names, `.local` hosts or IP addresses, so `NSAllowsLocalNetworking` was mostly a declaration of intent. From iOS 17, ATS restricts connections to IP addresses by default. Apps now need `NSAllowsLocalNetworking` or an IP/CIDR entry in `NSExceptionDomains` to reach a device such as `http://192.168.1.20`. Unqualified names and `.local` hosts are still allowed. When you read older material, including MASTG-KNOW-0071's statement that ATS does not apply to IP addresses, keep this change in mind.
5. **Code cannot loosen ATS.** `URLSessionConfiguration.tlsMinimumSupportedProtocolVersion` and similar settings apply in addition to ATS. A lower value in code does not get past ATS unless a matching `Info.plist` exception exists. Details in [MASTG-KNOW-0073](#ios-network-apis-mastg-know-0073) below and in Part 2.
6. **Extensions are separate.** Each app extension (share, widget, notification service, and so on) runs in its own process and has its own `Info.plist` with its own ATS dictionary. ATS keys in an embedded framework's `Info.plist` have no effect, because ATS reads the `Info.plist` of the main bundle of the process.

#### Where ATS does not apply

- **Lower-level APIs:** Network.framework (`NWConnection`, `NetworkConnection`), CFNetwork sockets and streams, BSD sockets, and anything built on them: SwiftNIO, gRPC-Swift, CocoaAsyncSocket and MQTT clients that use it, Starscream WebSockets (depending on version and transport), and the bundled stacks of Flutter, .NET (managed handler), Unity and libcurl. Apple's own wording: *"ATS doesn't apply to calls your app makes to lower-level networking interfaces like the Network framework or CFNetwork. In these cases, you take responsibility for ensuring the security of the connection."* See [MASTG-KNOW-0073](#ios-network-apis-mastg-know-0073).
- **Unqualified host names and `.local` hosts** (and IP addresses before iOS 17), as described above.
- **Hosts covered by exceptions.**

#### Justification and App Store review

Apple requires a justification during App Store review for `NSAllowsArbitraryLoads`, `NSAllowsArbitraryLoadsForMedia`, `NSAllowsArbitraryLoadsInWebContent`, `NSExceptionAllowsInsecureHTTPLoads` and `NSExceptionMinimumTLSVersion`. The justification is entered in App Store Connect and is not in the binary, so you can only see it if the client shares it. Review is not a security control. Apps with all of these keys are on the store. A browser that must open arbitrary sites is the textbook acceptable case for `NSAllowsArbitraryLoadsInWebContent`.

### iOS: Network APIs (MASTG-KNOW-0073)

Source: [MASTG-KNOW-0073](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-NETWORK/MASTG-KNOW-0073/). Apple's [TN3151: Choosing the right networking API](https://developer.apple.com/documentation/technotes/tn3151-choosing-the-right-networking-api) is the reference for which layer to use.

iOS offers four layers, from highest to lowest. ATS protects only the first.

#### URL Loading System

`URLSession`, `URLRequest`, `URLSessionWebSocketTask` (iOS 13+), `URLAuthenticationChallenge`, and the deprecated `NSURLConnection`. It supports HTTP/1.1, HTTP/2 and HTTP/3, caching, cookies, redirects, proxies and HSTS. It integrates with system trust evaluation, and **ATS applies**: `http://` and `ws://` URLs fail unless an exception allows them. Most third-party HTTP libraries are wrappers around `URLSession` and inherit ATS: Alamofire, Moya, Apollo iOS, and Firebase's and most analytics SDKs' HTTP layers.

Per-session TLS limits are set with `URLSessionConfiguration.tlsMinimumSupportedProtocolVersion` / `tlsMaximumSupportedProtocolVersion` (type `tls_protocol_version_t`), replacing the deprecated `tlsMinimumSupportedProtocol` / `tlsMaximumSupportedProtocol` (`SSLProtocol`). These apply in addition to ATS and are covered in Part 2.

#### Network framework

Introduced in iOS 12. `NWConnection`, `NWListener`, `NWBrowser`, `NWParameters` and `NWProtocolTLS`, plus the Swift-concurrency `NetworkConnection`, `NetworkListener` and `NetworkBrowser` added in iOS 26. It gives direct TCP, UDP, QUIC and TLS with explicit protocol stacks. **ATS does not apply.** Whether a connection is encrypted depends only on its parameters:

```swift
let plain  = NWConnection(host: "device.example.com", port: 80,  using: .tcp)   // cleartext
let secure = NWConnection(host: "device.example.com", port: 443, using: .tls)   // TLS with default options
let custom = NWConnection(host: "device.example.com", port: 8443,
                          using: NWParameters(tls: NWProtocolTLS.Options(), tcp: .init()))
```

TLS options go through `sec_protocol_options_*` functions on `NWProtocolTLS.Options().securityProtocolOptions`, such as `sec_protocol_options_set_min_tls_protocol_version` and `sec_protocol_options_set_verify_block`.

#### CFNetwork and Core Foundation streams

`CFStreamCreatePairWithSocketToHost`, `CFReadStream`/`CFWriteStream`, `CFSocket`, `CFHTTPMessage`, and the long-deprecated `CFReadStreamCreateForHTTPRequest`. The Foundation equivalents are `Stream.getStreamsToHost(withName:port:inputStream:outputStream:)` and `InputStream`/`OutputStream`. Encryption is turned on per stream with `kCFStreamPropertySSLSettings` or `Stream.PropertyKey.socketSecurityLevelKey`. Without that property, the stream is plaintext. **ATS does not apply.** You still meet these APIs in older SDKs and in libraries that want a C interface.

#### BSD sockets

`socket`, `connect`, `bind`, `listen`, `accept`, `send`, `recv`, `sendto`, `recvfrom` and `getaddrinfo` from libSystem. **ATS does not apply**, and any TLS has to come from a library linked into the app (OpenSSL, BoringSSL, mbedTLS, wolfSSL) or be absent. Flutter's engine, Unity, libcurl and cross-platform C/C++ SDKs all live at this layer. Apple's guidance is to use the URL Loading System for HTTP(S) and to drop to Network.framework only when you need a protocol it cannot handle.

## Tests

### Legacy tests and how to approach this weakness

These tests replace the MASTG v1 tests [MASTG-TEST-0019: Testing Data Encryption on the Network (Android)](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0019/) and [MASTG-TEST-0065: Testing Data Encryption on the Network (iOS)](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0065/). OWASP lists MASTG-TEST-0019 as covered by TEST-0233 to 0239. TEST-0234, hostname verification on `SSLSocket`, is covered in [MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/). MASTG-TEST-0065 is listed as covered by TEST-0321, 0322 and 0236; its section on low-level APIs now corresponds to TEST-0323.

No single test proves the absence of cleartext. Configuration tests show what the platform *would* allow. String and API tests show what the code *could* do. Capture shows what happened during your session. Hooks show which code sent it. We run them in this order on every engagement:

1. **Configuration**: TEST-0235 (Android) or TEST-0322 (iOS), plus TEST-0237 for cross-platform apps. These take minutes and tell you where to look.
2. **Inventory**: TEST-0233 or TEST-0321 for URLs, and TEST-0239 or TEST-0323 for low-level APIs.
3. **Confirmation**: TEST-0236 capture with full app coverage, then TEST-0238 hooks to attribute anything you could not tie to a code location.
4. **Old Android**: if `minSdkVersion` is 27 or lower, repeat the capture on an Android 8.1 (API 27) emulator. That is where the `targetSdk` 28 default stops protecting the app.

### MASTG-TEST-0233: Hardcoded HTTP URLs (Android)

Source: [MASTG-TEST-0233](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0233/). Platform: Android. Type: static (code). Related tests: TEST-0235, TEST-0236, TEST-0238.

#### Overview

The test lists `http://` URLs embedded in the APK: in DEX code, resources, assets and native libraries. Each one is a candidate cleartext endpoint. A URL in the binary is not a finding by itself. What matters is whether the app actually connects to it, and whether the platform would let it. OWASP is explicit about this limitation, so the test is really "find, then trace".

We extend the search to other cleartext schemes and ports (`ws://`, `ftp://`, `mqtt://`, `tcp://`, `:1883`) and to URLs built at runtime, which a simple `http://` grep misses.

#### Prerequisites

- The release APK, or all splits of the release bundle (`adb shell pm path com.example.app` then `adb pull` each one).
- jadx ([MASTG-TOOL-0018](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/)) and Apktool ([MASTG-TOOL-0011](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/)) for reverse engineering ([MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)).
- `strings` or rabin2 ([MASTG-TOOL-0129](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/)) for native libraries ([MASTG-TECH-0019](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0019/)), and optionally semgrep ([MASTG-TOOL-0110](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/)).

#### Steps

1. **Decompile and unpack.**

   ```bash
   jadx -d out_jadx app.apk
   unzip -q -o app.apk -d out_zip
   ```

2. **Search code and resources for cleartext URLs**, filtering out the usual noise: XML namespaces, DTDs, licence texts and specification URIs. None of these are ever fetched.

   ```bash
   NOISE='schemas\.android\.com|www\.w3\.org|xmlpull\.org|apache\.org/licenses|ns\.adobe\.com|purl\.org|xml\.org|schemas\.xmlsoap\.org|java\.sun\.com|opensource\.org|www\.apple\.com/DTDs'
   grep -rnoE "(http|ws|ftp|mqtt|tcp)://[^\"' <>]+" out_jadx/sources out_jadx/resources \
     | grep -vE "$NOISE" | sort -u > http_urls.txt
   wc -l http_urls.txt
   ```

3. **Search assets and native code.** These are where cross-platform code lives: a React Native `index.android.bundle`, Cordova/Capacitor `assets/public` or `assets/www`, the Flutter AOT snapshot `libapp.so`, and .NET assemblies.

   ```bash
   grep -rIoE "(http|ws)://[^\"' <>]+" out_zip/assets | grep -vE "$NOISE" | sort -u
   for so in out_zip/lib/arm64-v8a/*.so; do
     strings -a "$so" | grep -oE "(http|ws|ftp|mqtt)://[^\"' <>]+" | sed "s|^|$(basename "$so"): |"
   done | grep -vE "$NOISE" | sort -u
   ```

4. **Look for URLs built at runtime.** Scheme and host are often concatenated or set separately:

   ```bash
   grep -rnE 'scheme\("http"\)|URL\("http",|"http://" ?\+|"http" ?\+ ?"://' out_jadx/sources | head -50
   grep -rnE ':1883|:8080|:80[^0-9]|usePlaintext\(\)' out_jadx/sources | head -50
   ```

5. **Trace every candidate to a sink.** Open it in jadx-gui and use *Find Usage* (`x`) on the constant or field. Follow it to a networking call: `URL.openConnection`, `Retrofit.Builder().baseUrl`, `Request.Builder().url`, `WebView.loadUrl`, `MediaPlayer.setDataSource`, `DownloadManager.Request`, a WebSocket or MQTT client, or an `Intent(ACTION_VIEW)` that sends the user to a browser. Record what is sent (headers, body, query parameters) and when (login, every launch, a rarely used screen).

6. **Check whether the policy would allow it** (TEST-0235), then **confirm it on the wire** (TEST-0236), in particular on an API 27 device if `minSdk` allows one.

A minimal semgrep rule makes step 2 repeatable across engagements and catches literals that span `+` concatenation in jadx's Java output:

```yaml
rules:
  - id: gt-android-cleartext-url-literal
    languages: [java]
    severity: WARNING
    message: Cleartext URL literal - trace to a network sink and check the NSC
    pattern-regex: '"(http|ws|ftp|mqtt)://(?!schemas\.android\.com|www\.w3\.org)[^"]+"'
```

```bash
semgrep --config gt-cleartext.yml out_jadx/sources --json | jq -r '.results[] | "\(.path):\(.start.line)"'
```

#### Observation

A de-duplicated list of cleartext URLs with their location (class and line, resource file, asset or native library). For each URL record the sink it reaches, the data it carries, and whether it is reachable in normal use.

#### Evaluation

The test **fails** if any cleartext URL is confirmed to be used for communication, either reachable in code and permitted by the effective cleartext policy on a supported Android version, or observed in traffic.

It **passes** for URLs that are:

- not used for network communication (namespaces, licence text, documentation links, log messages);
- blocked by the effective policy on *every* Android version the app supports (`minSdk` and up), and the app degrades safely when blocked. Record the URL as an observation anyway, because it is a latent bug that becomes a vulnerability the day someone adds an exception;
- redirections of the *user* to a public web page in an external browser or Custom Tab that carry no session data. That is the browser's traffic, not the app's. Still mention it, and rate it Low at most.

False positives to watch for: `http://localhost` and `http://10.0.2.2` (the emulator's host loopback) in debug-only code that R8 did not strip, URLs in SDK sample strings, and URLs that are rewritten to `https://` before use (search for `.replace("http://", "https://")`).

#### Demo

OWASP does not publish an Android demo for this test. Ours is a small Kotlin client with one used and one unused cleartext URL:

```kotlin
object ApiConfig {
    const val BASE_URL = "http://api.example.com/v1/"          // FAIL: used for API calls
    const val HELP_URL = "http://www.example.com/help"         // opened in the browser only
    const val SCHEMA = "http://schemas.android.com/apk/res/android" // noise
}

fun fetchProfile(token: String): String {
    val conn = URL(ApiConfig.BASE_URL + "profile").openConnection() as HttpURLConnection
    conn.setRequestProperty("Authorization", "Bearer $token")
    return conn.inputStream.bufferedReader().use { it.readText() }
}
```

```text
$ cat http_urls.txt
out_jadx/sources/com/example/app/ApiConfig.java:http://api.example.com/v1/
out_jadx/sources/com/example/app/ApiConfig.java:http://www.example.com/help
```

Tracing `BASE_URL` in jadx leads to `fetchProfile`, which sends a bearer token. With `targetSdk 34` and no NSC, the request fails on Android 9+ with `Cleartext HTTP traffic to api.example.com not permitted`. With `minSdk 24`, though, the same request goes out in cleartext on Android 7.0–8.1. The test fails. `HELP_URL` is an `ACTION_VIEW` link and is reported as Low.

### MASTG-TEST-0235: Android App Configurations Allowing Cleartext Traffic (Android)

Source: [MASTG-TEST-0235](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0235/). Platform: Android. Type: static (configuration). Knowledge: MASTG-KNOW-0014.

#### Overview

The test reads the two places where an Android app can permit cleartext, the manifest flag `android:usesCleartextTraffic` and the NSC's `cleartextTrafficPermitted`, and works out the effective policy. OWASP's evaluation considers the flag and the NSC. We add two inputs that change the answer: `targetSdkVersion` and `minSdkVersion`.

#### Prerequisites

- The release APK.
- Apktool or jadx to decode resources, and aapt2 ([MASTG-TOOL-0124](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0124/)) for a quick manifest dump ([MASTG-TECH-0117](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/), [MASTG-TECH-0150](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0150/)).
- `xmllint`, `xmlstarlet` or `yq` for NSC queries ([MASTG-TECH-0151](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0151/)).
- Optionally a device with Frida ([MASTG-TOOL-0031](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/)) to confirm the resolved policy.

#### Steps

1. **Read SDK levels and the two manifest attributes** from the built APK. This is the merged manifest, so attributes contributed by libraries are included.

   ```bash

   aapt2 dump xmltree app.apk --file AndroidManifest.xml | grep -iE 'usesCleartextTraffic|networkSecurityConfig|debuggable'
   ```

   Typical output:

   ```text
   sdkVersion:'24'
   targetSdkVersion:'35'
         A: http://schemas.android.com/apk/res/android:usesCleartextTraffic(0x010104ec)=true
         A: http://schemas.android.com/apk/res/android:networkSecurityConfig(0x01010527)=@0x7f150002
   ```

2. **Decode resources and locate the NSC file**, including qualified variants:

   ```bash
   apktool d -f -o out_apktool app.apk
   grep -o 'android:networkSecurityConfig="[^"]*"' out_apktool/AndroidManifest.xml
   # android:networkSecurityConfig="@xml/network_security_config"
   find out_apktool/res -path '*/xml*/network_security_config.xml'
   ```

3. **Extract every cleartext decision in the NSC**, with the domains it applies to:

   ```bash
   NSC=out_apktool/res/xml/network_security_config.xml
   xmlstarlet sel -t -m '//base-config' -o 'base-config cleartext=' -v '@cleartextTrafficPermitted' -n "$NSC"
   xmlstarlet sel -t -m '//domain-config' \
     -o 'domain-config cleartext=' -v '@cleartextTrafficPermitted' -o ' domains=' \
     -m 'domain' -v '.' -o '(sub=' -v '@includeSubdomains' -o ') ' -b -n "$NSC"
   ```

   An empty value means "not set; inherited". Resolve it by walking up to the parent `domain-config`, then to `base-config`, then to the defaults for `targetSdkVersion`.

4. **Resolve the effective policy** for each Android version the app supports, using the matrix in [MASTG-KNOW-0014](#android-network-security-configuration-mastg-know-0014). In short:
   - NSC present: the NSC decides on API 24+, and the manifest flag is ignored. Unset `base-config` cleartext falls back to `targetSdk` defaults on API 28+ devices, and to **allowed** on API 24–27 devices.
   - No NSC: the manifest flag decides. If it is absent, the `targetSdk` default applies on API 28+ devices, and cleartext is **allowed** on API 23–27 devices.
   - `minSdk` 23 or lower: on API 23 only the flag counts; on API ≤ 22 nothing stops cleartext.

5. **Optionally confirm on a device.** Load this into the running app with `frida -U -n <App name> -l nsc-check.js`:

   ```javascript
   Java.perform(() => {
     const Policy = Java.use("android.security.NetworkSecurityPolicy").getInstance();
     console.log("app-wide:", Policy.isCleartextTrafficPermitted());
     for (const h of ["api.example.com", "cdn.example.com", "legacy.example.com"]) {
       console.log(h, Policy.isCleartextTrafficPermitted(h));
     }
   });
   ```

   Run it on an API 27 emulator and on a current device. The results often differ.

#### Observation

For each supported Android version range: the manifest flag value (and where it came from), whether an NSC exists, `base-config` cleartext, and each `domain-config` with its domains, `includeSubdomains` and resolved cleartext value.

#### Evaluation

Following OWASP, the test **fails** if cleartext is permitted, which happens when:

1. the manifest sets `usesCleartextTraffic="true"` and there is no NSC;
2. the NSC sets `cleartextTrafficPermitted="true"` on `<base-config>`; or
3. the NSC sets `cleartextTrafficPermitted="true"` on any `<domain-config>`.

It does not fail on `usesCleartextTraffic="true"` alone when an NSC is present, even an empty one, because the flag is then ignored on API 24+.

We add two conditions that OWASP's list does not capture:

4. **Implicit permission on older devices.** `minSdkVersion` ≤ 27 and nothing explicitly sets cleartext to `false`, neither `base-config` nor the manifest flag. Cleartext is then allowed on every supported device below Android 9, whatever the `targetSdk`. Note the subtle case: an app with an NSC that leaves `base-config` cleartext unset and `minSdk` 24 still allows cleartext on Android 7.0–8.1, and the manifest flag cannot help, because the NSC makes the platform ignore it.
5. **`minSdkVersion` ≤ 22.** There is no platform control at all on those devices. Report it as an observation and rate it by what the app sends.

A `domain-config` exception is acceptable when it names exact hosts the client controls or depends on (no `includeSubdomains` on a registrable domain), nothing sensitive is sent there, and there is a recorded reason. It still fails the test; the rating reflects the context.

#### Demo

OWASP has no demo for this test. Ours shows the two most common real-world patterns at once: a manifest flag that is ignored, and a `domain-config` exception that is not.

```xml
<!-- AndroidManifest.xml (merged) -->
<application
    android:usesCleartextTraffic="true"
    android:networkSecurityConfig="@xml/network_security_config">
```

```xml
<!-- res/xml/network_security_config.xml -->
<network-security-config>
    <base-config cleartextTrafficPermitted="false" />
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">example.com</domain>
    </domain-config>
</network-security-config>
```

```text
$ xmlstarlet sel ... network_security_config.xml
base-config cleartext=false
domain-config cleartext=true domains=example.com(sub=true)
```

Evaluation: the manifest flag is ignored on API 24+, because an NSC exists. `base-config` blocks cleartext. The `domain-config` allows cleartext to `example.com` **and every subdomain**, including `api.example.com`. Combined with the URL found in TEST-0233, this exception is what makes the bearer-token request succeed on every Android version. The test fails.

### MASTG-TEST-0236: Cleartext Traffic Observed on the Network (Android and iOS)

Source: [MASTG-TEST-0236](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0236/). Platform: network (OWASP files it under Android, but it is used for iOS as well, and the legacy iOS test MASTG-TEST-0065 points to it). Type: dynamic (network).

#### Overview

Static tests show *potential* cleartext. This test records what the app actually sends while you use it. It catches everything static analysis misses: URLs from remote config, server-driven redirects, SDK traffic, native stacks and proximity bridges that end in IP traffic. OWASP names three limitations, and they shape the procedure:

- **Attribution.** A packet capture sees the whole device, not one app.
- **Code location.** The capture shows what was sent, not which class sent it.
- **Coverage.** You only see the features you exercised.

#### Prerequisites

- The lab set up as described in our [mobile traffic interception lab](/mobile/mobile-traffic-interception-lab/): an interception proxy (Burp Suite [MASTG-TOOL-0077](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0077/), mitmproxy [MASTG-TOOL-0097](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0097/) or ZAP [MASTG-TOOL-0079](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0079/)) and a packet-capture path: tcpdump ([MASTG-TOOL-0080](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0080/)) or Wireshark/tshark ([MASTG-TOOL-0081](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0081/)) on a rooted device, on a rogue access point or hotspot, or through `rvictl` for iOS. The relevant OWASP techniques are [MASTG-TECH-0010](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0010/) and [MASTG-TECH-0011](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0011/) (Android), and [MASTG-TECH-0062](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0062/) and [MASTG-TECH-0063](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0063/) (iOS).
- A test account, and a list of the app's features so that you can tick them off.
- Ideally a clean test device with as few other apps as possible, and for Android an API 27 emulator if `minSdk` allows one.

You do not need a working TLS interception setup for this test. Cleartext is visible without one. If pinning breaks the app behind the proxy, use raw packet capture rather than spending time on bypasses (those are covered in [MASWE-0028](/mobile/maswe-0028-insecure-identity-pinning/)).

#### Steps

1. **Use two capture paths together.** A proxy shows HTTP in readable form, but only for traffic that honours the proxy setting. Flutter, many game engines, raw sockets and MQTT ignore the system proxy completely. A packet capture sees everything, so run one in parallel:
   - Android without root: PCAPdroid (a VPN-service capture app) can capture **only the target app** and export a pcap. That solves the attribution problem.
   - Android with root: `adb shell su -c 'tcpdump -i any -s 0 -w /data/local/tmp/app.pcap'`, then `adb pull`.
   - Any device on a lab access point: `sudo tcpdump -i <ap-interface> -s 0 -w app.pcap host <device-ip>`.
   - iOS on macOS: `rvictl -s <UDID>`, then `sudo tshark -i rvi0 -w ios.pcap`; stop with `rvictl -x <UDID>`.

2. **Exercise the app completely**: first launch and onboarding, registration, login, logout, password reset, every main screen, settings, payments, messaging, media playback, file upload and download, push notification handling, deep links, background refresh, and every proximity feature. Leave the app in the background for a few minutes to catch periodic SDK beacons. Note the time of each action so that you can match it to the capture.

3. **Find cleartext HTTP in the proxy.** In Burp, filter Proxy HTTP history with a Bambda such as `return !requestResponse.finalRequest().httpService().secure();`. In mitmproxy use the view filter `~u "^http://"`, or headless:

   ```bash
   mitmdump -nr flows.mitm --flow-detail 1 '~u "^http://"'
   ```

4. **Find every cleartext protocol in the capture** with tshark:

   ```bash
   # HTTP requests with host and path
   tshark -r app.pcap -Y 'http.request' -T fields -e frame.time -e ip.dst -e http.host -e http.request.method -e http.request.uri
   # Other well-known cleartext protocols
   tshark -r app.pcap -Y 'mqtt || ftp || smtp || imap || pop || xmpp || websocket || sip || rtsp || telnet'
   # TCP flows with payload that is neither TLS nor recognised HTTP: candidates for custom protocols
   tshark -r app.pcap -Y 'tcp.len > 0 && !tls && !http && !dns' -T fields -e ip.dst -e tcp.dstport | sort | uniq -c | sort -rn
   # UDP other than DNS and QUIC
   tshark -r app.pcap -Y 'udp && !dns && !quic && !mdns && !ssdp' -T fields -e ip.dst -e udp.dstport | sort | uniq -c
   # Map IP addresses back to the names the device resolved
   tshark -r app.pcap -Y 'dns.flags.response == 1 && dns.a' -T fields -e dns.qry.name -e dns.a | sort -u
   ```

   For any unknown flow, use *Follow → TCP Stream* in Wireshark, or `tshark -r app.pcap -q -z follow,tcp,ascii,<stream-index>`, and read what is in it.

5. **Attribute traffic to the app.** Use one or more of: a per-app capture (PCAPdroid); a timestamp match against your action log; a DNS name that belongs to the app's backend or one of its SDKs (from TEST-0233/0321); a host that matches a URL found statically; and finally TEST-0238 hooks, which prove which code sent it.

6. **Repeat on an old Android version** (API 27) if `minSdk` allows. Also check logcat on current devices for `Cleartext HTTP traffic to … not permitted`. Those lines show attempts that were blocked here and would succeed on an older device or under a looser configuration.

#### Observation

The pcap and proxy history, plus a table: destination host and port, protocol, the app action that triggered it, what the payload contains (credentials, tokens, PII, content), and how you attributed it to the app.

#### Evaluation

The test **fails** if any cleartext traffic originates from the app, whether from its own code or from an SDK it ships. Sensitive data in that traffic determines the severity, not the result.

Do not count these as app cleartext:

- DNS lookups (inherently plaintext unless Private DNS/DoT or DoH is used, and a platform matter);
- connectivity checks and captive-portal probes by the OS (`connectivitycheck.gstatic.com`, `captive.apple.com`);
- traffic from other apps and system services. Prove attribution before you report.

An HTTP request that is immediately answered with a redirect to HTTPS still fails. The first request goes out in cleartext with whatever headers and cookies the client attaches, and an active attacker can strip the redirect (SSL stripping). The impact is lower when the request carries nothing sensitive. iOS's URL Loading System supports HSTS, which can upgrade later requests to a host that has sent the header; Android's HTTP stacks do not apply HSTS, so do not count on it on either platform.

#### Demo

OWASP has no demo for this test. Here is a tshark excerpt from the TEST-0233 sample app running on an Android 8.1 emulator:

```text
$ tshark -r app.pcap -Y 'http.request' -T fields -e ip.dst -e http.host -e http.request.uri
203.0.113.10	api.example.com	/v1/profile

$ tshark -r app.pcap -q -z follow,tcp,ascii,3 | head -8
GET /v1/profile HTTP/1.1
Authorization: Bearer <redacted>
User-Agent: Dalvik/2.1.0 (Linux; U; Android 8.1.0; ...)
Host: api.example.com
Connection: Keep-Alive
Accept-Encoding: gzip
```

The bearer token is in cleartext, and the `Dalvik` user agent shows that the platform `HttpURLConnection` sent it. The test fails. On an Android 14 device the same action produces no packet and a `Cleartext HTTP traffic … not permitted` line in logcat, so the TEST-0235 analysis was right.

### MASTG-TEST-0237: Cross-Platform Framework Configurations Allowing Cleartext Traffic (Android)

Source: [MASTG-TEST-0237](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0237/). Platform: Android (we add the iOS equivalent). Type: static (configuration, code).

> **Note:** OWASP marks this test as a placeholder. Its only content is that cross-platform frameworks "typically have their own implementations for HTTP libraries, where cleartext traffic can be allowed." The procedure below is the **Guler Tech methodology**.

#### Overview

Cross-platform frameworks change the cleartext question in two ways. Some generate the platform configuration for you, and their templates allow cleartext for local development servers (Metro, Capacitor live reload, Expo). Others bypass the platform's HTTP stack, so the NSC and ATS do not apply at all (Flutter's `dart:io`, .NET's managed handler, Unity, anything with libcurl). You need to know which framework is in use, then where its configuration ends up in the build, then which stack it actually uses.

#### Prerequisites

- The APK and, where available, the IPA.
- The tools from TEST-0233 and TEST-0235. For Flutter, blutter ([MASTG-TOOL-0116](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0116/)) to recover Dart object pools and strings from `libapp.so`.

#### Steps

1. **Identify the framework.**

   ```bash
   unzip -l app.apk | grep -E 'libflutter\.so|libapp\.so|libreactnativejni\.so|libhermes\.so|index\.android\.bundle|assets/www/|assets/public/|capacitor\.config\.json|libmonodroid\.so|libxamarin-app\.so|assemblies|libunity\.so|libil2cpp\.so' | head
   ```

   On iOS: `Frameworks/Flutter.framework`, `main.jsbundle` (React Native), `public/` plus `capacitor.config.json`, `www/` (Cordova), `Frameworks/UnityFramework.framework`, or `.dll` assemblies or `Microsoft.*`/`Xamarin.*` symbols for .NET.

2. **Check the framework's own configuration**, in the form it takes in the build:

   | Framework | Where to look | Cleartext indicator |
   |---|---|---|
   | **Capacitor** | `assets/capacitor.config.json` (Android), `App.app/capacitor.config.json` (iOS) | `"server": { "cleartext": true }` (Android cleartext), `"androidScheme": "http"`, a `server.url` pointing to `http://…` (a live-reload server left in a release build), `"android": { "allowMixedContent": true }` |
   | **Cordova** | `res/xml/config.xml` (Android), `App.app/config.xml` (iOS) | `<access origin="*" />`, `<allow-navigation href="http://*/*" />`; cordova-ios generates ATS keys from `<access>`/`<allow-navigation>`, so also check the compiled `Info.plist` |
   | **React Native / Expo** | merged manifest, `res/xml/*`, `Info.plist`; `app.json`/`app.config.*` if you have source | `usesCleartextTraffic="true"` in release (the templates set it for debug only, via a debug manifest or manifest placeholder); `NSAllowsArbitraryLoads`; Expo `expo-build-properties` with `android.usesCleartextTraffic: true` |
   | **Flutter** | `libapp.so` / `App.framework/App` strings; `pubspec.lock` if available | `http://` / `ws://` in the AOT snapshot. Flutter's `dart:io` stack does not use the platform HTTP client (see below) |
   | **.NET MAUI / Xamarin** | `[assembly: Application(UsesCleartextTraffic = true)]` ends up in the merged manifest; `libxamarin-app.so` environment strings; assemblies | `XA_HTTP_CLIENT_HANDLER_TYPE` set to a managed handler, or code using `HttpClientHandler`/`SocketsHttpHandler` directly, bypasses the NSC; on iOS a managed handler bypasses ATS (the native `NSUrlSessionHandler` does not) |
   | **Unity** | merged manifest, `Info.plist`, `global-metadata.dat` strings | The player setting "Allow downloads over HTTP" sets platform cleartext flags in the generated project; `UnityWebRequest` to `http://` URLs |

   ```bash
   # Capacitor and Cordova
   jq '.server, .android' out_zip/assets/capacitor.config.json 2>/dev/null
   grep -E '<access|<allow-navigation|<allow-intent' out_apktool/res/xml/config.xml 2>/dev/null
   # Xamarin/.NET Android: handler selection baked into the native app config
   strings -a out_zip/lib/arm64-v8a/libxamarin-app.so 2>/dev/null | grep -A1 XA_HTTP_CLIENT_HANDLER_TYPE
   # Flutter: URLs in the Dart AOT snapshot
   strings -a out_zip/lib/arm64-v8a/libapp.so | grep -oE "(http|ws)://[^\"' <>]+" | sort -u
   ```

3. **Establish which stack carries the traffic.** This is the step that decides whether the TEST-0235 or TEST-0322 result means anything:
   - **React Native**: `fetch` and `XMLHttpRequest` go through OkHttp on Android and `NSURLSession` on iOS, so NSC and ATS apply. Native modules and WebSocket libraries can differ.
   - **Cordova and Capacitor**: the WebView and the native HTTP plug-in (Capacitor's `CapacitorHttp`, `cordova-plugin-advanced-http`) use the platform stacks, so NSC and ATS apply, subject to the WebView caveats in GT-0026-1.
   - **Flutter**: `package:http` and Dio use `dart:io`'s `HttpClient` by default. It has its own sockets and BoringSSL, ignores the system proxy, and does not go through ATS or the platform HTTP client. Flutter 2.0 briefly made `dart:io` refuse cleartext according to the platform policy. Flutter's breaking-change page lists that behaviour as reverted in 2.2 (marked "proposed"), so do not rely on it in either direction. Treat the NSC and ATS as **not** protecting Flutter traffic unless the app uses `cupertino_http` or `cronet_http`, and confirm with capture. Use reFlutter ([MASTG-TOOL-0100](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0100/)) or a transparent capture to see Flutter traffic.
   - **.NET**: `AndroidMessageHandler` (the default in current templates) and `NSUrlSessionHandler` use the platform stacks. `SocketsHttpHandler`/managed `HttpClientHandler` do not.
   - **Unity, Godot, Unreal, C/C++ SDKs**: assume a bundled stack. Policy does not apply.

4. **Confirm dynamically.** Run TEST-0236 with a transparent capture, because Flutter and native stacks ignore the proxy, and TEST-0238 hooks at the libc level, which see every stack.

#### Observation

Framework and version, the framework configuration as compiled into the build, the effective platform cleartext policy, which networking stack each feature uses, and the cleartext endpoints that stack can reach.

#### Evaluation

The test **fails** if a framework setting allows cleartext in the release build (Capacitor `server.cleartext: true`, a release `usesCleartextTraffic="true"` with no NSC, `NSAllowsArbitraryLoads` from a template, Cordova `<access origin="*">` turned into ATS exceptions, a `server.url` with an `http://` live-reload address), **or** if the app uses a stack that bypasses the platform policy and that stack is used with cleartext URLs. A Flutter or managed-.NET app with `http://` endpoints fails even when its NSC and ATS look perfect.

It passes when the framework configuration does not permit cleartext in release builds and every stack in use either enforces the platform policy or is only given `https://`/`wss://` endpoints, confirmed by capture.

#### Demo

A Capacitor release build that still has the developer's live-reload settings:

```json
{
  "appId": "com.example.app",
  "webDir": "dist",
  "server": {
    "url": "http://192.168.1.50:8100",
    "cleartext": true
  }
}
```

```text
$ jq '.server' out_zip/assets/capacitor.config.json
{
  "url": "http://192.168.1.50:8100",
  "cleartext": true
}
```

The app loads its entire UI, including the login form, from an HTTP server on a private address. On the user's own network that address usually leads nowhere and the app shows a blank screen. On a network where an attacker controls `192.168.1.50` or the routing, the attacker serves the whole app. Test fails, and we would rate it High: an attacker with a position on the LAN gets full content control, including of the login page.

### MASTG-TEST-0238: Runtime Use of Network APIs Transmitting Cleartext Traffic (Android)

Source: [MASTG-TEST-0238](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0238/). Platform: Android (the approach also works on iOS). Type: dynamic (hooks).

> **Note:** OWASP marks this test as a placeholder. Its note says only that Frida, with backtraces, can attribute traffic to the app and to an exact code location, and that the new limitation is having to instrument every relevant networking API. The procedure below is the **Guler Tech methodology**.

#### Overview

Hooking runs inside the app's process, so anything you see came from the app. That solves TEST-0236's attribution problem. A backtrace then gives you the code location. The question is which layer to hook. High-level hooks (`URL.openConnection`, OkHttp) give readable URLs but miss native stacks and get lost in obfuscated class names. We therefore hook at libc, where every stack ends: Java sockets, OkHttp, Conscrypt, Flutter's `dart:io`, libcurl and game engines all call `write`/`send`/`sendto` on a socket file descriptor. At that point we classify each outgoing buffer: if it does not start with a TLS record header, it is cleartext.

#### Prerequisites

- A rooted device or emulator with frida-server, or a repackaged app with frida-gadget. Frida ([MASTG-TOOL-0031](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/), [Android setup MASTG-TOOL-0001](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0001/)) 16 or 17.
- If the app detects Frida, deal with that first. Our [MASWE-0020 note](/mobile/maswe-0020-local-authentication-bypass/) covers the common patterns.

#### Steps

1. **Save the native tap** as `cleartext-tap.js`. It works on Frida 16 and 17 and needs no class names:

   ```javascript
   // Guler Tech - flag outgoing socket writes that are not TLS records
   function findExport(name) {
     if (typeof Module.findGlobalExportByName === "function") return Module.findGlobalExportByName(name);
     return Module.findExportByName(null, name);
   }

   const IP_TYPES = ["tcp", "tcp6", "udp", "udp6"];
   const SKIP_PORTS = [53, 443];      // DNS; UDP 443 is QUIC (encrypted, but not TLS-record framed)
   const reported = new Set();

   function isTlsRecord(buf, len) {
     if (len < 3) return false;
     const b = new Uint8Array(buf.readByteArray(3));
     return b[0] >= 0x14 && b[0] <= 0x17 && b[1] === 0x03;   // content type 20-23, version 3.x
   }

   function printable(buf, len) {
     const b = new Uint8Array(buf.readByteArray(Math.min(len, 120)));
     let s = "";
     for (const c of b) s += (c >= 0x20 && c < 0x7f) ? String.fromCharCode(c) : ".";
     return s;
   }

   function javaStack() {
     if (!Java.available) return "";
     let out = "";
     Java.performNow(() => {
       const Log = Java.use("android.util.Log");
       const T = Java.use("java.lang.Throwable");
       out = Log.getStackTraceString(T.$new()).split("\n").slice(1, 12).join("\n");
     });
     return out;
   }

   function tap(name) {
     const addr = findExport(name);
     if (addr === null) return;
     Interceptor.attach(addr, {
       onEnter(args) {
         const fd = args[0].toInt32();
         const type = Socket.type(fd);
         if (type === null || IP_TYPES.indexOf(type) < 0) return;
         const len = args[2].toInt32();
         if (len <= 0 || isTlsRecord(args[1], len)) return;
         const peer = Socket.peerAddress(fd);
         if (peer === null || SKIP_PORTS.indexOf(peer.port) >= 0) return;
         const key = type + " " + peer.ip + ":" + peer.port;
         console.log("\n[cleartext] " + name + " " + key + " len=" + len);
         console.log("  " + printable(args[1], len));
         if (reported.has(key)) return;   // full stacks once per destination
         reported.add(key);
         console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0, 8)
           .map(DebugSymbol.fromAddress).join("\n"));
         const js = javaStack();
         if (js) console.log(js);
       }
     });
   }

   ["write", "send", "sendto"].forEach(tap);
   ```

2. **Add high-level hooks for readable URLs** (`http-hooks.js`). These are optional but useful in reports:

   ```javascript
   Java.perform(() => {
     const URL = Java.use("java.net.URL");
     const Log = Java.use("android.util.Log");
     const T = Java.use("java.lang.Throwable");
     URL.openConnection.overload().implementation = function () {
       if (this.getProtocol() === "http") {
         console.log("[URL] " + this.toString() + "\n" + Log.getStackTraceString(T.$new()));
       }
       return this.openConnection();
     };
     const WebView = Java.use("android.webkit.WebView");
     WebView.loadUrl.overload("java.lang.String").implementation = function (u) {
       if (u.startsWith("http://")) console.log("[WebView] " + u);
       return this.loadUrl(u);
     };
   });
   ```

   For a quick look without writing code: `objection -g com.example.app explore`, then `android hooking watch class_method java.net.URL.openConnection --dump-args --dump-backtrace`, or `frida-trace -U -f com.example.app -i sendto -i connect`.

3. **Spawn the app with both scripts** so that start-up traffic is included, then repeat the feature walk-through from TEST-0236:

   ```bash
   frida -U -f com.example.app -l cleartext-tap.js -l http-hooks.js
   ```

4. **Triage each hit.** The destination tells you where it went, the printable preview tells you the protocol and the data, and the native and Java stacks tell you which library and class sent it. Map native frames to libraries (`libapp.so` means Flutter app code, `libflutter.so` the Flutter engine, `libcurl`, `libil2cpp.so` Unity, `libjavacrypto.so`/`libssl.so` should never appear here) and Java frames to packages (`okhttp3`, `com.android.okhttp` for platform `HttpURLConnection`, SDK package names).

#### Observation

For each cleartext destination: the hooked call, protocol and port, a payload preview, and the native and Java backtrace, with the responsible package or library named.

#### Evaluation

The test **fails** if the app's process writes non-TLS application data to a remote socket (not loopback) during normal use. The backtrace shows whether the app's own code or an SDK is responsible. That affects the remediation, not the result.

Known false positives: STARTTLS protocols, whose first bytes are plaintext until the upgrade (check that the upgrade happens), DTLS and other UDP protocols with their own framing, a TLS record split across two `write` calls (rare with Conscrypt and BoringSSL, but confirm with the pcap), and loopback IPC (filtered out if you add `127.0.0.1`/`::1` to a skip list). `sendmsg` and `writev` are not hooked; add them if a stack uses them and you see traffic in the pcap without hits.

#### Demo

Hits (abridged) from the TEST-0233 app on Android 8.1, and from a Flutter build of the same feature on Android 14 (no NSC exception; Flutter ignores the policy):

```text
[cleartext] sendto tcp 203.0.113.10:80 len=212
  GET /v1/profile HTTP/1.1..Authorization: Bearer <redacted>..User-Agent: Dalvik/2.1.0 ...
0x7a1c2e4b10 libc.so!sendto+0x10
0x7a0f6d22c4 libopenjdk.so!NET_Send+0x54
...
java.net.SocketOutputStream.socketWrite0(Native Method)
com.android.okhttp.internal.http.Http1xStream.writeRequest(Http1xStream.java:...)
com.example.app.ApiClientKt.fetchProfile(ApiClient.kt:12)

[cleartext] write tcp 203.0.113.10:80 len=188
  GET /v1/profile HTTP/1.1..user-agent: Dart/3.5 (dart:io)..authorization: Bearer <redacted>
0x7b33a01f2c libc.so!write+0xc
0x7a7d8e0a14 libflutter.so!0x1c4fa14
0x7a6b012c88 libapp.so!0x3a2c88
```

The first hit names the exact Kotlin function. The second shows that the Flutter engine sent a bearer token in cleartext on a current Android version, where the platform policy would have blocked it.

### MASTG-TEST-0239: Using Low-Level APIs (e.g. Socket) to Set Up a Custom HTTP Connection (Android)

Source: [MASTG-TEST-0239](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0239/). Platform: Android. Type: static (code).

> **Note:** OWASP marks this test as a placeholder. Its note says only that the test could also map to MASWE-0047. The procedure below is the **Guler Tech methodology**.

#### Overview

`java.net.Socket` and its relatives carry whatever bytes you give them, and they never consult the cleartext policy. An app that writes `GET / HTTP/1.1` to a `Socket`, speaks MQTT or a custom binary protocol over a plain TCP socket, or uses native `connect()` sends cleartext whatever its NSC says. The test finds these APIs and decides, for each use, whether TLS is layered on top.

#### Prerequisites

- jadx output and the unzipped APK from TEST-0233.
- rabin2 or `nm`/`readelf` for native imports, and optionally semgrep.

#### Steps

1. **Find Java and Kotlin socket APIs.**

   ```bash
   grep -rnE 'new Socket\(|new java\.net\.Socket\(|SocketChannel\.open|AsynchronousSocketChannel|new DatagramSocket|SocketFactory\.getDefault\(\)|\.createSocket\(' out_jadx/sources \
     | grep -v '^out_jadx/sources/\(okhttp3\|okio\|com/android/okhttp\)/' | head -100
   ```

   Then the libraries that wrap them: gRPC (`ManagedChannelBuilder`, `usePlaintext()`), MQTT (Eclipse Paho `MqttClient` with `tcp://` URIs, HiveMQ `MqttClient.builder()` without `sslWithDefaultConfig()`), WebSocket clients (`ws://`), Ktor sockets (`aSocket(...).tcp()` without `.tls()`), Netty, Apache MINA, Java-WebSocket and XMPP libraries.

   ```bash
   grep -rnE 'usePlaintext\(\)|MqttConnectOptions|MqttClient\(|"tcp://|"ws://|aSocket\(|\.tcp\(\)\.connect|NioEventLoopGroup' out_jadx/sources | head -50
   ```

2. **Look for hand-rolled protocols.** Literal HTTP request lines or headers next to a socket are a strong signal:

   ```bash
   grep -rnE '"(GET|POST|PUT) [^"]* HTTP/1\.[01]|"Host: |\\r\\n\\r\\n' out_jadx/sources | head
   ```

3. **Check native libraries.** Imports show which ones do their own networking, and strings show the protocol:

   ```bash
   for so in out_zip/lib/arm64-v8a/*.so; do
     imp=$(rabin2 -i "$so" 2>/dev/null | grep -wE 'socket|connect|send|sendto|getaddrinfo' | wc -l)
     tls=$(rabin2 -i "$so" 2>/dev/null | grep -cE 'SSL_(connect|write)|mbedtls_ssl|wolfSSL')
     [ "$imp" -gt 0 ] && echo "$(basename "$so"): socket imports=$imp tls imports=$tls"
   done
   strings -a out_zip/lib/arm64-v8a/libnative.so | grep -E 'HTTP/1\.[01]|libcurl|CURLOPT|http://'
   ```

   A library that imports `connect`/`send` but has no TLS imports, and no statically linked TLS (check the strings for `BoringSSL`, `OpenSSL`, `mbed TLS`), can only send cleartext.

4. **Decide TLS or not for each use.** Open each hit in jadx and follow the socket from creation to first write:
   - Plain `Socket(host, port)` or `SocketFactory.getDefault()`, with nothing that wraps the streams: **cleartext**.
   - `SSLSocketFactory.getDefault().createSocket(...)`, `SSLContext.getSocketFactory()`, or `sslFactory.createSocket(plainSocket, host, port, true)` (layered TLS): **TLS**. Hostname verification is then your next problem: `SSLSocket` does not check the hostname. That is TEST-0234 in [MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/).
   - A STARTTLS-style protocol: check that the upgrade is mandatory and happens before any credentials are sent.
   - gRPC: `usePlaintext()` means cleartext; `useTransportSecurity()` or the default for `forTarget` on most transports means TLS.
   - Note the port. A connection to 80, 1883, 5222, 8080 or 9000 with no TLS wrapper is the typical finding.

5. **Confirm** with TEST-0238 (the libc tap catches all of these) and TEST-0236.

#### Observation

Each socket or low-level usage with its class or library, destination (if static), protocol, whether TLS wraps it, and what data passes through it.

#### Evaluation

The test **fails** if the app uses a socket or other low-level API to exchange application data with a remote host without TLS (or equivalent authenticated encryption at the application layer), in its own code or in a bundled library. Sockets bound to loopback for IPC are a different weakness (local exposure, see [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/)) unless they relay traffic outward.

It passes when every low-level connection is wrapped in TLS before any application data is written, or carries only data that is designed to be public and integrity-protected some other way (for example signed payloads). The second case is rare enough that you should ask the client to justify it.

#### Demo

OWASP has no demo for this test. Ours is a Kotlin HTTP request over a raw socket. It works on every Android version, whatever the NSC says:

```kotlin
fun rawGet(token: String): String =
    Socket("api.example.com", 80).use { s ->                 // FAIL: plain TCP, NSC not consulted
        s.getOutputStream().write(
            ("GET /v1/profile HTTP/1.1\r\nHost: api.example.com\r\n" +
             "Authorization: Bearer $token\r\nConnection: close\r\n\r\n").toByteArray()
        )
        s.getInputStream().bufferedReader().readText()
    }
```

```text
$ grep -rnE 'new Socket\(' out_jadx/sources/com/example
out_jadx/sources/com/example/app/RawClientKt.java:14:        Socket socket = new Socket("api.example.com", 80);
$ grep -rnE '"GET [^"]* HTTP/1\.[01]' out_jadx/sources/com/example
out_jadx/sources/com/example/app/RawClientKt.java:17:            ... "GET /v1/profile HTTP/1.1\r\nHost: api.example.com\r\n" ...
```

The socket is not wrapped, the port is 80, and a bearer token is written to it. The test fails. The safe version uses `SSLSocketFactory.getDefault().createSocket("api.example.com", 443)` followed by explicit hostname verification, or simply OkHttp with an `https://` URL.

### MASTG-TEST-0321: Hardcoded HTTP URLs (iOS)

Source: [MASTG-TEST-0321](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0321/). Platform: iOS. Type: static (code).

#### Overview

This is the iOS counterpart of TEST-0233: find `http://` URLs in the app's binaries and resources, then work out whether they are used and whether ATS, or the lack of it, would let the connection through. On iOS that question has two parts. Is the URL used with `URLSession` (ATS applies, so check TEST-0322), or with a lower-level API (ATS does not apply, so check TEST-0323)?

#### Prerequisites

- A decrypted IPA (App Store binaries are FairPlay-encrypted; decrypt them on a jailbroken device or use the client's build). Unzip it ([MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/)).
- radare2 ([MASTG-TOOL-0073](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/)) or rabin2, `strings`, and optionally Ghidra or Hopper for cross-references ([MASTG-TECH-0071](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0071/), [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/)).

#### Steps

1. **Unpack and list every Mach-O in the bundle**: the main binary, embedded frameworks and app extensions all need checking.

   ```bash
   unzip -q -o App.ipa -d ipa && cd ipa/Payload/*.app
   find . -type f -perm -u+x -exec file {} + | grep Mach-O | cut -d: -f1
   ```

2. **Extract cleartext URLs** from binaries and from resources (plists, JSON, JavaScript bundles, Flutter's `App.framework/App`):

   ```bash
   NOISE='www\.apple\.com/DTDs|www\.w3\.org|ns\.adobe\.com|purl\.org|apache\.org/licenses|schemas\.'
   for b in $(find . -type f -perm -u+x -exec file {} + | grep Mach-O | cut -d: -f1); do
     rabin2 -zz "$b" 2>/dev/null | grep -oE "(http|ws)://[^ \"]+" | sed "s|^|$b: |"
   done | grep -vE "$NOISE" | sort -u
   grep -rIoE "(http|ws)://[^\"' <>]+" --include='*.plist' --include='*.json' --include='*.js' --include='*.jsbundle' --include='*.html' . | grep -vE "$NOISE" | sort -u
   ```

3. **Find the code that uses each URL.** With radare2, as in OWASP's demo:

   ```text
   iz~http://            # strings with address
   axt @ <string-addr>   # code references
   pd 20 @ <xref-addr>   # disassemble the use
   ```

   Look for the string flowing into `URL(string:)`/`NSURL URLWithString:` and then `URLSession`, `WKWebView.load`, `AVPlayer`, `NWEndpoint`, `CFStreamCreatePairWithSocketToHost` or a third-party client.

4. **Account for Swift string storage.** Swift stores strings of up to 15 UTF-8 bytes inline as immediate values, not in `__cstring`. A short URL such as `http://10.0.0.1` (15 bytes) will not show up in `strings` at all. It is built from `mov`/`movk` immediates instead, so look in the disassembly for the 16-bit chunks `0x7468`, `0x7074` and `0x2f3a` (the little-endian halves of `http:/`), or rely on the dynamic tests. The compiler also removes unused constants, which is why OWASP's demo shows `http://httpbin.org/get` but not the unused `http://example.com/api` from the same source file.

5. **Check ATS** for the hosts you found (TEST-0322) and **confirm on the wire** (TEST-0236).

#### Observation

URLs with their binary or resource location, the code reference and API they reach, and the ATS exception that applies to the host (if any).

#### Evaluation

The test **fails** if any cleartext URL is confirmed to be used for communication. That means it reaches `URLSession`/`WKWebView`/AVFoundation **and** an ATS exception allows it, or it reaches a lower-level API where ATS does not apply, or it is observed in traffic. OWASP notes the key limitation: a URL alone proves nothing, so evaluate it together with TEST-0322 and TEST-0323.

#### Demo

OWASP's [MASTG-DEMO-0084](https://mas.owasp.org/MASTG/demos/ios/MASVS-NETWORK/MASTG-DEMO-0084/MASTG-DEMO-0084/) uses this Swift code (shortened):

```swift
struct MastgTest {
    static let httpEndpoint = "http://httpbin.org/get"   // FAIL: hardcoded HTTP URL
    static let httpApiUrl   = "http://example.com/api"   // FAIL: but never used
    static let httpsEndpoint = "https://httpbin.org/get" // PASS

    static func mastgTest(completion: @escaping (String) -> Void) {
        guard let url = URL(string: httpEndpoint) else { return }
        URLSession.shared.dataTask(with: url) { _, response, error in
            completion("\(String(describing: response)) \(String(describing: error))")
        }.resume()
    }
}
```

The radare2 script lists the strings, finds the cross-reference and disassembles the use:

```text
Uses of http:// URLs:
3   0x00006c60 0x100006c60 22  23   2.__TEXT.__cstring       ascii http://httpbin.org/get

xrefs to http://httpbin.org/get:
sym.func.100005024 0x100005130 [STRN:r--] add x8, x8, str.http:__httpbin.org_get

│  0x100005130      add x8, x8, 0xc60          ; "http://httpbin.org/get"
│  0x100005158      bl sym.imp.Foundation.URL.string_...cfC_
│  0x100005238      ldr x0, [x8, 0xc8]         ; reloc.NSURLSession
│  0x100005248      bl sym.imp.objc_msgSend    ; sharedSession
```

The URL is loaded at `0x100005130`, turned into a `URL` at `0x100005158` and used with `NSURLSession.sharedSession` at `0x100005238`. Because the app's `Info.plist` has `NSExceptionAllowsInsecureHTTPLoads` for `httpbin.org` (MASTG-DEMO-0083, below), ATS lets the request through. The test fails. `http://example.com/api` does not appear in the binary at all, because the compiler removed it as unused.

### MASTG-TEST-0322: App Transport Security Configurations Allowing Cleartext Traffic (iOS)

Source: [MASTG-TEST-0322](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0322/). Platform: iOS. Type: static (configuration), manual review. Knowledge: MASTG-KNOW-0071.

#### Overview

The test reads the `NSAppTransportSecurity` dictionary of the app (and of each extension) and identifies the keys that allow cleartext: `NSAllowsArbitraryLoads` (when not overridden), `NSAllowsArbitraryLoadsInWebContent`, `NSAllowsArbitraryLoadsForMedia`, `NSAllowsLocalNetworking` and per-domain `NSExceptionAllowsInsecureHTTPLoads`. As OWASP notes, ATS covers only the URL Loading System, so a clean result here says nothing about Network.framework or sockets (TEST-0323).

#### Prerequisites

- The unzipped IPA ([MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/)).
- `plutil` ([MASTG-TOOL-0062](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0062/)) on macOS, or Python's `plistlib` / libplist's `plistutil` elsewhere ([MASTG-TECH-0153](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0153/), [MASTG-TECH-0138](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0138/), [MASTG-TECH-0155](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0155/)).
- `jq`, and optionally `gron`.

#### Steps

1. **Find the `Info.plist` of the app and of every extension.** App Store builds use binary plists.

   ```bash
   cd ipa/Payload
   find . -name Info.plist \( -path '*.app/Info.plist' -o -path '*.appex/Info.plist' \) | grep -v '/Frameworks/'
   ```

2. **Dump the ATS dictionary of each** as JSON:

   ```bash
   plutil -extract NSAppTransportSecurity json -o - MyApp.app/Info.plist 2>/dev/null | jq .
   # Linux / no plutil:
   python3 -c 'import plistlib,sys,json; print(json.dumps(plistlib.load(open(sys.argv[1],"rb")).get("NSAppTransportSecurity"), indent=2))' MyApp.app/Info.plist
   # Or only the keys that matter here, as in OWASP's demo:
   plutil -convert json -o Info.json MyApp.app/Info.plist
   gron Info.json | grep -E 'NSAppTransportSecurity\.(NSAllowsArbitraryLoads|NSAllowsArbitraryLoadsInWebContent|NSAllowsArbitraryLoadsForMedia|NSAllowsLocalNetworking)|AllowsInsecureHTTPLoads'
   ```

   If there is no `NSAppTransportSecurity` key at all, ATS applies with its defaults.

3. **Validate key names and value types.** ATS expects Booleans and ignores unknown keys. Flag misspelt or invented keys (`NSAllowsArbitraryLoadsForLocalNetworking`, `NSAllowArbitraryLoads`) as configuration errors: they show intent, but they have no effect. Do not report them as cleartext, and remember that they do not trigger the iOS 10 "ignore `NSAllowsArbitraryLoads`" rule.

4. **Resolve the effective policy per host and per API**, using the precedence rules in [MASTG-KNOW-0071](#ios-app-transport-security-mastg-know-0071):
   - For each host in `NSExceptionDomains`, only its own dictionary counts. Is `NSExceptionAllowsInsecureHTTPLoads` set? Does `NSIncludesSubdomains` widen it?
   - For other hosts: is any of `NSAllowsArbitraryLoadsInWebContent`, `NSAllowsArbitraryLoadsForMedia` or `NSAllowsLocalNetworking` present (with any value)? If so, `NSAllowsArbitraryLoads` is ignored for `URLSession`, and each narrower key governs its own area (WKWebView, AVFoundation, local hosts). If not, `NSAllowsArbitraryLoads = YES` disables ATS for all unlisted hosts.
   - Check `MinimumOSVersion`. It tells you whether the iOS 17 IP-address change affects every supported version.

5. **Confirm at runtime where it matters.** On a device, watch the Console app (filtered on the app's process) or `idevicesyslog` while you use the feature. A blocked load logs `App Transport Security has blocked a cleartext HTTP (http://) resource load since it is insecure` and returns error −1022. A load that succeeds over HTTP is visible in TEST-0236.

6. **Ask for the justification** of each exception if you are working with the developer. Apple collects it in App Store Connect, not in the binary.

#### Observation

The ATS dictionary of the app and of each extension, the list of keys that allow cleartext, the resolved policy per area (URLSession, WKWebView, AVFoundation, local hosts, each exception domain), and any invalid keys.

#### Evaluation

Following OWASP, the test **fails** if any of these is true:

1. `NSAllowsArbitraryLoads = YES` **and** none of `NSAllowsArbitraryLoadsInWebContent`, `NSAllowsArbitraryLoadsForMedia` or `NSAllowsLocalNetworking` is present (because on iOS 10+ their presence makes ATS ignore it);
2. `NSAllowsArbitraryLoadsInWebContent = YES`;
3. `NSAllowsArbitraryLoadsForMedia = YES`;
4. `NSAllowsLocalNetworking = YES`;
5. any domain in `NSExceptionDomains` has `NSExceptionAllowsInsecureHTTPLoads = YES` (or the legacy `NSTemporaryExceptionAllowsInsecureHTTPLoads`).

Then apply OWASP's "further validation": is the exception needed for the app's core purpose? A browser legitimately needs `NSAllowsArbitraryLoadsInWebContent`. A smart-home app may legitimately need `NSAllowsLocalNetworking` to talk to devices on the LAN, but then what it sends to them must be protected some other way (GT-0026-3). A banking app needs none of these. Our ratings treat a justified, narrowly scoped exception with no sensitive traffic as Low or Info, even though the test result is "fail".

#### Demo

OWASP's [MASTG-DEMO-0083](https://mas.owasp.org/MASTG/demos/ios/MASVS-NETWORK/MASTG-DEMO-0083/MASTG-DEMO-0083/) ships this ATS dictionary (shortened):

```xml
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key><true/>
    <key>NSAllowsArbitraryLoadsInWebContent</key><true/>
    <key>NSAllowsArbitraryLoadsForMedia</key><true/>
    <key>NSAllowsArbitraryLoadsForLocalNetworking</key><true/>
    <key>NSExceptionDomains</key>
    <dict>
        <key>api.example.com</key>
        <dict>
            <key>NSExceptionAllowsInsecureHTTPLoads</key><true/>
            <key>NSExceptionRequiresForwardSecrecy</key><false/>
            <key>NSTemporaryExceptionMinimumTLSVersion</key><string>TLSv1.0</string>
            <key>NSIncludesSubdomains</key><true/>
        </dict>
        <key>httpbin.org</key>
        <dict>
            <key>NSExceptionAllowsInsecureHTTPLoads</key><true/>
            <key>NSExceptionMinimumTLSVersion</key><string>TLSv1.1</string>
            <key>NSIncludesSubdomains</key><true/>
        </dict>
    </dict>
</dict>
```

OWASP's `plutil` + `gron` + `egrep` pipeline outputs:

```text
json.NSAppTransportSecurity.NSAllowsArbitraryLoads = true;
json.NSAppTransportSecurity.NSAllowsArbitraryLoadsForLocalNetworking = true;
json.NSAppTransportSecurity.NSAllowsArbitraryLoadsForMedia = true;
json.NSAppTransportSecurity.NSAllowsArbitraryLoadsInWebContent = true;
json.NSAppTransportSecurity.NSExceptionDomains["api.example.com"].NSExceptionAllowsInsecureHTTPLoads = true;
json.NSAppTransportSecurity.NSExceptionDomains["httpbin.org"].NSExceptionAllowsInsecureHTTPLoads = true;
```

Our resolution of it:

- `NSAllowsArbitraryLoads` is **ignored**, because `NSAllowsArbitraryLoadsInWebContent` and `NSAllowsArbitraryLoadsForMedia` are present. `URLSession` connections to unlisted hosts are still fully protected by ATS.
- `NSAllowsArbitraryLoadsForLocalNetworking` is **not an ATS key** and does nothing. OWASP's demo text treats it as the local-networking exception and as one of the keys that override arbitrary loads; the real key is `NSAllowsLocalNetworking`. The conclusion about `NSAllowsArbitraryLoads` still holds because of the other two keys.
- WKWebView content and AVFoundation media may load over HTTP from any host.
- `api.example.com`, `httpbin.org` and all their subdomains may be reached over HTTP. `http://httpbin.org/get` (TEST-0321) succeeds **because of the domain exception**, not because of the global key. The TLS-related keys on these domains are covered in Part 2.

The test fails, on four valid keys.

### MASTG-TEST-0323: Uses of Low-Level Networking APIs for Cleartext Traffic (iOS)

Source: [MASTG-TEST-0323](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0323/). Platform: iOS. Type: static (code), manual review. Knowledge: MASTG-KNOW-0073.

#### Overview

ATS stops at the URL Loading System. This test looks for the APIs below it: Network.framework, CFNetwork and BSD sockets, in the main binary and in embedded frameworks. For each use, it decides whether TLS is configured. A clean ATS dictionary combined with an `NWConnection(…, using: .tcp)` to port 80 is cleartext.

#### Prerequisites

- The decrypted, unzipped IPA.
- radare2/rabin2, `otool` (Xcode command-line tools) or `nm`, and a disassembler for review ([MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/)).

#### Steps

1. **See which binaries link the relevant frameworks:**

   ```bash
   for b in MyApp.app/MyApp MyApp.app/Frameworks/*.framework/*; do
     [ -f "$b" ] && file "$b" | grep -q 'Mach-O' || continue
     otool -L "$b" | grep -E 'Network\.framework|CFNetwork\.framework' | sed "s|^|$b: |"
   done
   ```

   Linking CFNetwork is normal (Foundation uses it). What matters is which *symbols* each binary imports.

2. **List imported low-level symbols:**

   ```bash
   rabin2 -i MyApp.app/MyApp | grep -E ' (socket|connect|send|sendto|recv|getaddrinfo)$|nw_connection|nw_parameters|NWConnection|NWParameters|NWEndpoint|CFStreamCreatePairWithSocket|CFSocketCreate|CFReadStreamCreateForHTTPRequest|getStreamsToHost'
   ```

   Swift Network symbols are mangled, but rabin2 and radare2 demangle them (`Network.NWConnection…`, `Network.NWEndpoint.Port.integerLiteral…`). Third-party frameworks that commonly appear here: SwiftNIO (`NIOPosix`), gRPC-Swift, CocoaAsyncSocket (`GCDAsyncSocket`), CocoaMQTT, Starscream and SocketRocket.

3. **For each call site, determine the transport parameters:**
   - **Network.framework**: `NWParameters.tcp`/`.udp`, or `nw_parameters_create_secure_tcp` with `NW_PARAMETERS_DISABLE_PROTOCOL`, means **cleartext**. `NWParameters.tls`, `NWParameters(tls:tcp:)`, `.dtls` or `.quic` means **TLS**. Check the port passed to `NWEndpoint.Port` (OWASP's demo recovers `0x50` = 80 from the `mov w0` before the call).
   - **CFNetwork / Foundation streams**: look for `kCFStreamPropertySSLSettings`, `kCFStreamSSLLevel` or `NSStreamSocketSecurityLevelKey` being set before the stream is opened. Without them the stream is plaintext.
   - **BSD sockets**: look for a TLS library in the binary (`SSL_connect`, `mbedtls_ssl_handshake`, `wolfSSL_connect` imports or strings). Without one, `send()` on a TCP socket to a remote host is cleartext. Recover the destination from `getaddrinfo`'s arguments, as in OWASP's demo.

4. **Confirm dynamically.** `frida-trace -U -f com.example.app -i 'nw_connection_create' -i 'connect' -i 'getaddrinfo'` shows when these paths run, and TEST-0236 shows what they send. Our `cleartext-tap.js` from TEST-0238 also runs on iOS for BSD-socket and CFNetwork traffic. Network.framework may not pass through `write`/`send`, so use packet capture for it.

#### Observation

A list of low-level API uses by binary and function, with the destination and port where recoverable, the transport parameters (TLS or not), and the data involved.

#### Evaluation

The test **fails** if the app or one of its frameworks uses Network.framework, CFNetwork or BSD sockets to exchange data with a remote host without TLS. As OWASP puts it, the further validation is to establish whether `.tls` is part of the `NWParameters`, and whether CFNetwork or socket connections have any TLS wrapping. The presence of these APIs is not a failure by itself. A Network.framework connection with `.tls` passes this test. Whether its TLS configuration is any good is then a question for Part 2 and MASWE-0027.

#### Demo

OWASP's [MASTG-DEMO-0085](https://mas.owasp.org/MASTG/demos/ios/MASVS-NETWORK/MASTG-DEMO-0085/MASTG-DEMO-0085/) uses Network.framework without TLS:

```swift
let host = NWEndpoint.Host("httpbin.org")
let port = NWEndpoint.Port(integerLiteral: 80)
let connection = NWConnection(host: host, port: port, using: .tcp)   // FAIL: no TLS, ATS not applied
connection.start(queue: .main)
// ... send("GET /get HTTP/1.1\r\nHost: httpbin.org\r\n...")
```

```text
xrefs to Network.NWEndpoint.Port.integerLiteral:
sym.func.1000046c4 0x1000047f4 [CALL:--x] bl sym.imp.Network.NWEndpoint.Port.integerLiteral.UInt16...V_tcfC

│  0x1000047e8      bl sym.imp.Network.NWEndpoint.Host.stringLiteral.__String_...cfC_
│  0x1000047f0      mov w0, 0x50                              ; 'P'
│  0x1000047f4      bl sym.imp.Network.NWEndpoint.Port.integerLiteral.UInt16...V_tcfC
│  0x1000047fc      bl sym.imp.Network.NWConnection.allocator_...a_
```

Port `0x50` (80) feeds an `NWConnection` with TCP parameters. The app's ATS is at its defaults, yet the connection succeeds. The test fails.

[MASTG-DEMO-0086](https://mas.owasp.org/MASTG/demos/ios/MASVS-NETWORK/MASTG-DEMO-0086/MASTG-DEMO-0086/) does the same with BSD sockets: `rabin2 -i` shows imports of `connect`, `getaddrinfo`, `recv`, `send` and `socket`, and the disassembly before `getaddrinfo` loads `"httpbin.org"` as the node name and a service string built from `0x50`. With no TLS library in the binary, the `send()` that follows is cleartext.

(OWASP's sample sources label both of these with `MASTG-TEST-0322` in their comments, but the demos belong to TEST-0323.)

### Supplementary checks (Guler Tech methodology)

The OWASP tests above concentrate on HTTP stacks and platform configuration. Three areas of MASWE-0026 regularly produce findings without being covered directly. We test them as part of the same engagement.

### GT-0026-1: WebView cleartext and mixed content (Android and iOS)

#### Overview

A WebView that loads `http://` pages, or loads HTTPS pages that pull scripts over HTTP, gives a network attacker the ability to run JavaScript in the app's WebView. Where the WebView has a native bridge (`addJavascriptInterface`, `WKScriptMessageHandler`), that JavaScript can reach native code.

#### Steps

1. **Android**: find `setMixedContentMode` and the value it is given:

   ```bash
   grep -rnE 'setMixedContentMode|MIXED_CONTENT_(ALWAYS_ALLOW|COMPATIBILITY_MODE)|loadUrl\("http://' out_jadx/sources | head
   ```

   `MIXED_CONTENT_ALWAYS_ALLOW` (0) lets HTTPS pages load any HTTP sub-resource. `MIXED_CONTENT_COMPATIBILITY_MODE` (2) allows some (images, media). The default for apps targeting API 21+ is `MIXED_CONTENT_NEVER_ALLOW` (1). Combine this with the NSC result. WebView honours the app-wide cleartext flag for apps targeting API 26+, so check what it does on the device with per-domain exceptions.
2. **iOS**: `NSAllowsArbitraryLoadsInWebContent` (TEST-0322), `loadHTMLString(_:baseURL:)` with an `http://` base URL, and `WKWebViewConfiguration.upgradeKnownHostsToHTTPS` (iOS 14.5+). WKWebView blocks active mixed content (scripts) on HTTPS pages regardless of ATS.
3. **Both**: open every in-app web screen through the proxy and look for `http://` documents and sub-resources.

#### Evaluation

Fails if a WebView loads a document or active content (scripts, iframes) over cleartext, or allows mixed active content. It is at least High if the WebView has a JavaScript bridge or shows a login, payment or account screen.

### GT-0026-2: Third-party SDKs and native libraries (Android and iOS)

#### Overview

An SDK can send cleartext even when the app's own code is clean: an ad network serving creatives over HTTP, an attribution SDK reporting to an HTTP endpoint, a native analytics library with its own sockets, or an SDK whose manifest merges `usesCleartextTraffic="true"`.

#### Steps

1. **Inventory SDKs** by package prefix (Android) and framework name (iOS); see [MASTG-KNOW-0004](/mobile/mastg-know-0004-third-party-libraries/).
2. **Find manifest contributions.** If you have the source, Gradle's merged-manifest report (`app/build/outputs/logs/manifest-merger-release-report.txt`) shows which library added `usesCleartextTraffic`. From the APK alone, compare the attribute with what the app's own source would set, or ask.
3. **Attribute traffic.** Map every host in the TEST-0236 capture to the SDK that owns it (DNS names usually make this obvious), and every TEST-0238 backtrace to an SDK package or `.so`.
4. **Check versions** against the vendor's changelog for known "switched to HTTPS" fixes.

#### Evaluation

Fails for any cleartext traffic from an SDK. The rating depends on what is sent: an advertising ID, location and device fingerprint in cleartext is a privacy finding (Medium), and SDK-delivered HTML or JavaScript over HTTP is a content-injection finding (High if rendered in a privileged WebView).

### GT-0026-3: Unencrypted machine-to-machine channels (BLE, NFC, Wi-Fi Direct, USB)

#### Overview

MASWE-0026 explicitly includes proximity interfaces (MAS-ATTACK-0013). Companion apps for locks, medical devices, wearables, vehicles and payment terminals often move credentials, unlock commands and health data over BLE or a local Wi-Fi link. Link-layer protection is often absent or weak: BLE characteristics without encryption permissions, "Just Works" pairing (encrypted, but unauthenticated against an active MITM during pairing), and LE Legacy Pairing, whose keys a passive sniffer can recover by capturing the pairing.

#### Steps

1. **Static**:
   - Android BLE: `BluetoothGattCharacteristic.PERMISSION_READ`/`PERMISSION_WRITE` (unencrypted) versus `PERMISSION_READ_ENCRYPTED(_MITM)`/`PERMISSION_WRITE_ENCRYPTED(_MITM)` on a GATT server; `writeCharacteristic` payloads built from tokens or PINs on the client side; `createBond()` usage.
   - Android Classic Bluetooth: `createInsecureRfcommSocketToServiceRecord` and `listenUsingInsecureRfcommWithServiceRecord` (no authentication or encryption required).
   - Android NFC: `HostApduService.processCommandApdu` and `IsoDep.transceive` handling secrets in plain APDUs.
   - Android Wi-Fi Direct: `WifiP2pManager` followed by a plain `Socket`/`ServerSocket` (TEST-0239).
   - iOS: `CBAttributePermissions.readable`/`.writeable` versus `.readEncryptionRequired`/`.writeEncryptionRequired`, `CBCharacteristicProperties` `.notifyEncryptionRequired`/`.indicateEncryptionRequired`, `MCSession(peer:securityIdentity:encryptionPreference:)` with `.none` or `.optional`, Network.framework peer-to-peer (`includePeerToPeer = true`) with `.tcp`.
2. **Dynamic, Android BLE**: enable *Developer options → Enable Bluetooth HCI snoop log*, toggle Bluetooth, use the feature, then `adb bugreport bug.zip` and open `FS/data/misc/bluetooth/logs/btsnoop_hci.log` (the path varies by vendor) in Wireshark with the filter `btatt`. Read and write values appear as the app sees them, above the link encryption. If they contain credentials, check whether the link was encrypted (`btsmp` pairing and an encryption-change event in `bthci_evt`) and what pairing method was used.
3. **Dynamic, over the air**: a BLE sniffer (an nRF52-based board with Wireshark, or an Ubertooth) shows whether an outsider sees plaintext ATT values. Hook `BluetoothGatt.writeCharacteristic` with Frida to log payloads with backtraces.

#### Evaluation

Fails if sensitive data or security-relevant commands (unlock, pairing secrets, tokens, health data) travel over a proximity channel without encryption, or with encryption that an attacker in range can defeat (LE Legacy Pairing sniffed during pairing, Just Works for a channel that needs MITM protection), and no application-layer encryption with authenticated keys sits on top.

## Secure implementation

OWASP does not publish a best practice dedicated to cleartext traffic. The relevant ones are [MASTG-BEST-0010: Use Up-to-Date minSdkVersion](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0010/) (which explains the Android 8.1 gap), [MASTG-BEST-0042: Use Strong TLS Settings in ATS Configuration](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0042/) and [MASTG-BEST-0043: Enforce Strong TLS Settings When ATS Doesn't Apply](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0043/). Here is what we recommend in reports.

**Android: block cleartext explicitly, on every supported version.**

```xml
<!-- AndroidManifest.xml -->
<application
    android:networkSecurityConfig="@xml/network_security_config"
    android:usesCleartextTraffic="false"
    ... >
```

```xml
<!-- res/xml/network_security_config.xml -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    <!-- Only if a host genuinely cannot do TLS, nothing sensitive goes there, and the reason is documented:
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="false">legacy-status.example.com</domain>
    </domain-config>
    -->
</network-security-config>
```

The explicit `false` covers Android 7.0–8.1 devices, where the default would allow cleartext. The manifest flag covers Android 6.0, which has no NSC. Raising `minSdkVersion` to 28 or higher removes the problem altogether. Android Lint's `InsecureBaseConfiguration` check warns when `base-config` permits cleartext; keep it as an error in CI.

**Keep developer conveniences out of release builds.** Put any HTTP-allowing NSC in `src/debug/res/xml/`, and add a CI step that runs `aapt2 dump xmltree` on the release artefact and fails the build if `usesCleartextTraffic=true` or `cleartextTrafficPermitted="true"` appears. In debug builds, turn on `StrictMode.VmPolicy.Builder().detectCleartextNetwork()` (API 23+) with `penaltyLog()` or `penaltyDeathOnCleartextNetwork()`. It inspects outgoing traffic, including raw sockets, and flags anything that is not TLS. It can produce false positives for STARTTLS and HTTP proxies.

**Make the HTTP client refuse cleartext as well (defence in depth).**

```kotlin
val client = OkHttpClient.Builder()
    .connectionSpecs(listOf(ConnectionSpec.MODERN_TLS))   // no ConnectionSpec.CLEARTEXT: http:// URLs fail
    .build()
```

**Use TLS with every protocol.** gRPC: `ManagedChannelBuilder.forAddress(host, 443).useTransportSecurity()`, never `usePlaintext()`. MQTT: `ssl://host:8883`. WebSockets: `wss://`. Raw sockets: `SSLSocketFactory` plus explicit hostname verification (see [MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/)). WebViews: leave mixed content at `MIXED_CONTENT_NEVER_ALLOW`.

**iOS: leave ATS alone.** The most secure `NSAppTransportSecurity` dictionary is no dictionary at all. If an exception is unavoidable, scope it to one exact host:

```xml
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSExceptionDomains</key>
    <dict>
        <key>legacy-status.example.com</key>
        <dict>
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <true/>
        </dict>
    </dict>
</dict>
```

Browsers and apps that must display arbitrary web content should use `NSAllowsArbitraryLoadsInWebContent`, not `NSAllowsArbitraryLoads`. Apps that talk to LAN devices should use `NSAllowsLocalNetworking` (or IP/CIDR exceptions on iOS 17+) and protect the data at the application layer.

**iOS: configure TLS where ATS does not reach.**

```swift
let tls = NWProtocolTLS.Options()
sec_protocol_options_set_min_tls_protocol_version(tls.securityProtocolOptions, .TLSv12)
let connection = NWConnection(host: "device.example.com", port: 8443,
                              using: NWParameters(tls: tls, tcp: NWProtocolTCP.Options()))
```

For Multipeer Connectivity, use `MCSession(peer: me, securityIdentity: nil, encryptionPreference: .required)`. For CoreBluetooth peripherals, use `.readEncryptionRequired`/`.writeEncryptionRequired` permissions.

**Cross-platform.** Capacitor: no `server.url` and no `server.cleartext` in release config. Cordova: replace `<access origin="*">` with explicit `https://` origins. React Native and Expo: keep cleartext settings in the debug manifest or placeholder only, and check the release artefact. Flutter: only `https://`/`wss://` URLs; enforce that centrally (a single base-URL constant, an assertion in an HTTP client wrapper), because the platform policy cannot be counted on. .NET: use the native handlers (`AndroidMessageHandler`, `NSUrlSessionHandler`).

**Prefer server fixes.** Every ATS or NSC exception compensates for a server that does not offer TLS. Fix the server, then remove the exception.

## Rating findings

Rate cleartext findings on three things: **what crosses the wire** (credentials and tokens, personal or financial data, executable or security-relevant content, or nothing sensitive), **who can reach it** (passive observer on shared Wi-Fi, active MITM via rogue AP or ARP/DNS spoofing, an attacker within BLE/NFC range), and **how reliably it happens** (every launch, a main flow, a rarely used feature, only on Android ≤ 8.1, only on a LAN). Cleartext needs no certificate, no device compromise and no user mistake, so it rates higher than missing pinning or other TLS weaknesses with the same data at stake.

| Rating | Conditions |
|---|---|
| **Critical** | Credentials, session or refresh tokens, or payment card data sent in cleartext to an internet endpoint in a main flow (login, every API call) on current OS versions, so that a passive observer on public Wi-Fi gets account takeover. Executable or security-controlling content fetched in cleartext and acted on: code-push or JavaScript bundles, plug-ins, update manifests, server-delivered pins or API base URLs. Unlock or authorisation commands for a physical device (lock, vehicle, medical device) over an unauthenticated, unencrypted proximity channel. |
| **High** | The Critical cases when they only occur on supported older versions (Android 7.0–8.1 with `minSdk` ≤ 27), in a secondary flow, or only on a LAN. Sensitive personal, health or financial data in cleartext. A WebView loading a document or scripts over HTTP where it has a JavaScript bridge or shows login, payment or account screens. Capacitor/Cordova apps loading their UI over HTTP. Global cleartext enabled (`base-config cleartextTrafficPermitted="true"`, effective `NSAllowsArbitraryLoads`) **and** at least one sensitive request confirmed over HTTP. |
| **Medium** | Cleartext traffic with low-sensitivity data that an attacker can modify to mislead the user (content, prices, links, images, news), or that leaks device identifiers, location or behaviour (analytics and ad SDKs). HTTP-to-HTTPS redirects on API hosts where the first request carries no secret (SSL stripping is possible). Global cleartext enabled with no sensitive traffic observed. `NSAllowsArbitraryLoadsInWebContent` in an app that is not a browser. |
| **Low** | Per-domain exceptions for hosts the client controls, with no sensitive traffic observed. Unused hardcoded HTTP URLs combined with a permissive configuration. Implicit cleartext permission on Android 7.0–8.1 (`minSdk` ≤ 27, no explicit `false`) with no cleartext use found. External-browser links to HTTP pages. Media over HTTP via `NSAllowsArbitraryLoadsForMedia` for non-sensitive public content. |
| **Info** | HTTP URLs that are never used (namespaces, licences). Blocked cleartext attempts visible in logs with no supported version that would allow them. Justified `NSAllowsLocalNetworking` or a LAN exception where the data is protected at the application layer. A browser's `NSAllowsArbitraryLoadsInWebContent`. Invalid ATS keys with no effect (report as a configuration-hygiene note). |

Adjustments: raise one level if the app targets a high-risk population or context (banking, health, government ID, children, journalists) or is designed for use on public networks (travel, transport, events). Lower one level if the data is independently protected end to end with authenticated encryption, for example signed and encrypted payloads with keys not derived from the traffic. In the report, give the request or packet (with secrets redacted), the configuration lines that allow it, the code location or SDK from the backtrace, the OS versions affected, and the attacker position required.

## References

- OWASP MASWE: [MASWE-0026: Network Traffic Not Encrypted](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0026/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-NETWORK-1](https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-1/) (CC BY-SA 4.0)
- OWASP MASTG, knowledge: [MASTG-KNOW-0014: Android Network Security Configuration](https://mas.owasp.org/MASTG/knowledge/android/MASVS-NETWORK/MASTG-KNOW-0014/), [MASTG-KNOW-0071: iOS App Transport Security](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-NETWORK/MASTG-KNOW-0071/), [MASTG-KNOW-0073: iOS Network APIs](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-NETWORK/MASTG-KNOW-0073/) (CC BY-SA 4.0)
- OWASP MASTG, tests: [MASTG-TEST-0233](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0233/), [MASTG-TEST-0235](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0235/), [MASTG-TEST-0236](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0236/), [MASTG-TEST-0237](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0237/), [MASTG-TEST-0238](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0238/), [MASTG-TEST-0239](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0239/), [MASTG-TEST-0321](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0321/), [MASTG-TEST-0322](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0322/), [MASTG-TEST-0323](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0323/); legacy (MASTG v1) [MASTG-TEST-0019](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0019/), [MASTG-TEST-0065](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0065/) (CC BY-SA 4.0)
- OWASP MASTG, demos: [MASTG-DEMO-0083](https://mas.owasp.org/MASTG/demos/ios/MASVS-NETWORK/MASTG-DEMO-0083/MASTG-DEMO-0083/), [MASTG-DEMO-0084](https://mas.owasp.org/MASTG/demos/ios/MASVS-NETWORK/MASTG-DEMO-0084/MASTG-DEMO-0084/), [MASTG-DEMO-0085](https://mas.owasp.org/MASTG/demos/ios/MASVS-NETWORK/MASTG-DEMO-0085/MASTG-DEMO-0085/), [MASTG-DEMO-0086](https://mas.owasp.org/MASTG/demos/ios/MASVS-NETWORK/MASTG-DEMO-0086/MASTG-DEMO-0086/) (CC BY-SA 4.0)
- OWASP MASTG, best practices: [MASTG-BEST-0010](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0010/), [MASTG-BEST-0042](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0042/), [MASTG-BEST-0043](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0043/) (CC BY-SA 4.0)
- OWASP MASTG, techniques: [MASTG-TECH-0009](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0009/), [MASTG-TECH-0010](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0010/), [MASTG-TECH-0011](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0011/), [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0019](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0019/), [MASTG-TECH-0117](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/), [MASTG-TECH-0150](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0150/), [MASTG-TECH-0151](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0151/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0062](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0062/), [MASTG-TECH-0063](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0063/), [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/), [MASTG-TECH-0138](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0138/), [MASTG-TECH-0153](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0153/), [MASTG-TECH-0155](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0155/), [MASTG-TECH-0071](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0071/) (CC BY-SA 4.0)
- OWASP MASTG, tools: [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [Apktool (MASTG-TOOL-0011)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/), [aapt2 (MASTG-TOOL-0124)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0124/), [blutter (MASTG-TOOL-0116)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0116/), [Frida for Android (MASTG-TOOL-0001)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0001/), [Frida (MASTG-TOOL-0031)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/), [rabin2 (MASTG-TOOL-0129)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/), [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/), [reFlutter (MASTG-TOOL-0100)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0100/), [radare2 for iOS (MASTG-TOOL-0073)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/), [Plutil (MASTG-TOOL-0062)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0062/), [Burp Suite (MASTG-TOOL-0077)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0077/), [ZAP (MASTG-TOOL-0079)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0079/), [mitmproxy (MASTG-TOOL-0097)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0097/), [tcpdump (MASTG-TOOL-0080)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0080/), [Wireshark (MASTG-TOOL-0081)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0081/), [MITM Relay (MASTG-TOOL-0078)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0078/) (CC BY-SA 4.0)
- Android Developers: [Network security configuration](https://developer.android.com/privacy-and-security/security-config), [`<application>`: `android:usesCleartextTraffic` and `android:networkSecurityConfig`](https://developer.android.com/guide/topics/manifest/application-element), [`NetworkSecurityPolicy`](https://developer.android.com/reference/android/security/NetworkSecurityPolicy), [`StrictMode.VmPolicy.Builder.detectCleartextNetwork()`](https://developer.android.com/reference/android/os/StrictMode.VmPolicy.Builder#detectCleartextNetwork()), [Security tips: networking](https://developer.android.com/privacy-and-security/security-tips#networking), [Security best practices: secure communication](https://developer.android.com/privacy-and-security/security-best-practices#secure-communication), [`java.net.Socket`](https://developer.android.com/reference/java/net/Socket), [`SSLSocket`](https://developer.android.com/reference/javax/net/ssl/SSLSocket), [`WebSettings.setMixedContentMode`](https://developer.android.com/reference/android/webkit/WebSettings#setMixedContentMode(int)), [Android cleartext communications risk](https://developer.android.com/privacy-and-security/risks/cleartext-communications), [Insecure machine-to-machine communication setup](https://developer.android.com/privacy-and-security/risks/insecure-machine-to-machine)
- Apple: [`NSAppTransportSecurity`](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity) and its keys [`NSAllowsArbitraryLoads`](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity/nsallowsarbitraryloads), [`NSAllowsArbitraryLoadsInWebContent`](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity/nsallowsarbitraryloadsinwebcontent), [`NSAllowsLocalNetworking`](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity/nsallowslocalnetworking), [`NSExceptionDomains`](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity/nsexceptiondomains); [Preventing Insecure Network Connections](https://developer.apple.com/documentation/security/preventing-insecure-network-connections); [TN3151: Choosing the right networking API](https://developer.apple.com/documentation/technotes/tn3151-choosing-the-right-networking-api); [URL Loading System](https://developer.apple.com/documentation/foundation/url-loading-system); [Network framework](https://developer.apple.com/documentation/network) and [`NWConnection`](https://developer.apple.com/documentation/network/nwconnection); [`sec_protocol_options_set_min_tls_protocol_version`](https://developer.apple.com/documentation/security/sec_protocol_options_set_min_tls_protocol_version%28_:_:%29); [`MCSession`](https://developer.apple.com/documentation/multipeerconnectivity/mcsession); [Apple Developer Forums: ATS and lower-level APIs](https://developer.apple.com/forums/thread/67493)
- Frameworks: [Flutter: insecure HTTP connections disabled by default (breaking change notice)](https://docs.flutter.dev/release/breaking-changes/network-policy-ios-android), [Capacitor configuration](https://capacitorjs.com/docs/config), [Cordova config.xml `<access>`](https://cordova.apache.org/docs/en/latest/config_ref/), [.NET for Android HttpClient handlers](https://learn.microsoft.com/en-us/dotnet/android/)
- Tools: [Frida JavaScript API (`Interceptor`, `Socket`, `Thread.backtrace`)](https://frida.re/docs/javascript-api/), [objection](https://github.com/sensepost/objection), [mitmproxy filter expressions](https://docs.mitmproxy.org/stable/concepts-filters/), [Burp Bambdas](https://portswigger.net/burp/documentation/desktop/extend-burp/bambdas), [PCAPdroid](https://github.com/emanuele-f/PCAPdroid), [tshark](https://www.wireshark.org/docs/man-pages/tshark.html)
- Standards: [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html); [NIST SP 800-52 Rev. 2](https://csrc.nist.gov/pubs/sp/800/52/r2/final) (TLS selection and configuration); [RFC 8996](https://www.rfc-editor.org/rfc/rfc8996) (deprecating TLS 1.0 and 1.1, covered in Part 2); [RFC 6797](https://www.rfc-editor.org/rfc/rfc6797) (HSTS); Bluetooth Core Specification, Vol 3 Part H (Security Manager)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
