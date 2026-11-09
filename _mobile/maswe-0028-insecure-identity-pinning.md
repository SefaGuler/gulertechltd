---
title: "Insecure Identity Pinning (MASWE-0028)"
date: 2026-11-09 16:03:00 +0000
subcategory: network
summary: "Testing certificate and public key pinning on Android and iOS: NSC pin-sets, OkHttp, TrustKit, NSPinnedDomains, SPKI hashes, bypasses and rating."
refs: [MASWE-0028, MASVS-NETWORK-2, CWE-295]
tags: [android, ios, masvs-network, certificate-pinning, tls, frida]
---

This note is part of our [MASVS-NETWORK guide](/mobile/masvs-network-secure-communication-guide/) and covers OWASP [MASWE-0028](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0028/): identity pinning that is missing, incomplete or wired up so that it does not actually restrict anything. Normal TLS validation answers "does this certificate chain to *any* CA the device trusts?". Pinning narrows that to "does it chain to a key *we* chose?", which is what protects the app when the device trusts a CA it should not: a mis-issuing or compromised public CA, a corporate inspection root pushed by MDM, or a CA profile a user was talked into installing. Below you will find what a pin is and how to derive one with `openssl`, the leaf/intermediate/root trade-off, backup pins and dynamic pinning, Android's Network Security Configuration `<pin-set>` and its expiry trap, OkHttp's `CertificatePinner`, TrustKit, iOS `NSPinnedDomains` and custom `SecTrust` code, Flutter and React Native, the four OWASP tests with our supplementary checks, a full section on bypassing pinning so you can see the traffic, secure patterns and severity guidance. Certificate *validation* (trust managers, hostname verification, `SecTrustEvaluateWithError`) belongs to [MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/); the proxy and CA setup is in the [interception lab](/mobile/mobile-traffic-interception-lab/).

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Both platforms: what is pinned and how to derive a pin (supplementary)](#both-platforms-what-is-pinned-and-how-to-derive-a-pin-supplementary)
  - [Both platforms: choosing the pin target, backup pins and dynamic pinning (supplementary)](#both-platforms-choosing-the-pin-target-backup-pins-and-dynamic-pinning-supplementary)
  - [Android: Certificate Pinning (MASTG-KNOW-0015)](#android-certificate-pinning-mastg-know-0015)
  - [iOS: Server Trust Evaluation and pinning (MASTG-KNOW-0072)](#ios-server-trust-evaluation-and-pinning-mastg-know-0072)
  - [Both platforms: pinning in cross-platform frameworks (supplementary)](#both-platforms-pinning-in-cross-platform-frameworks-supplementary)
- [Tests](#tests)
  - [Before you start: which domains must be pinned](#before-you-start-which-domains-must-be-pinned)
  - [MASTG-TEST-0242: Missing Certificate Pinning in Network Security Configuration (Android)](#mastg-test-0242-missing-certificate-pinning-in-network-security-configuration-android)
  - [MASTG-TEST-0243: Expired Certificate Pins in the Network Security Configuration (Android)](#mastg-test-0243-expired-certificate-pins-in-the-network-security-configuration-android)
  - [MASTG-TEST-0244: Missing Certificate Pinning in Network Traffic (Android)](#mastg-test-0244-missing-certificate-pinning-in-network-traffic-android)
  - [MASTG-TEST-0385: Missing Certificate Pinning in ATS (iOS)](#mastg-test-0385-missing-certificate-pinning-in-ats-ios)
  - [Supplementary checks (Guler Tech methodology)](#supplementary-checks-guler-tech-methodology)
  - [GT-0028-1: Code-level pinning on Android (OkHttp, TrustKit, TrustManager)](#gt-0028-1-code-level-pinning-on-android-okhttp-trustkit-trustmanager)
  - [GT-0028-2: Code-level pinning on iOS (SecTrust, TrustKit, Alamofire)](#gt-0028-2-code-level-pinning-on-ios-sectrust-trustkit-alamofire)
  - [GT-0028-3: Runtime pinning check (iOS)](#gt-0028-3-runtime-pinning-check-ios)
  - [GT-0028-4: Dynamic pin delivery and pin-failure handling (both platforms)](#gt-0028-4-dynamic-pin-delivery-and-pin-failure-handling-both-platforms)
- [Bypassing pinning during an assessment](#bypassing-pinning-during-an-assessment)
  - [Why a bypass on your own device is not a finding](#why-a-bypass-on-your-own-device-is-not-a-finding)
  - [Android: objection and Frida](#android-objection-and-frida)
  - [Android: repackaging with a modified NSC](#android-repackaging-with-a-modified-nsc)
  - [iOS: objection, Frida and SSL Kill Switch](#ios-objection-frida-and-ssl-kill-switch)
  - [Flutter apps](#flutter-apps)
  - [Xamarin apps](#xamarin-apps)
  - [When the universal scripts fail](#when-the-universal-scripts-fail)
- [Secure implementation](#secure-implementation)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

MASVS-NETWORK-2 asks that "the app performs identity pinning for all remote endpoints under the developer's control". MASWE-0028 is the weakness behind it: the app does not pin, or pins in a way that does not hold, so it cannot insist on talking only to servers that present a key the operator chose.

It helps to be precise about what pinning adds. A correctly validated TLS connection already defeats the attacker on the same café Wi-Fi, the rogue access point and the ARP spoofer: they cannot produce a certificate for `api.example.com` that chains to a trusted root. Pinning only matters once the attacker *has* such a certificate, which happens when:

- a public CA (or one of the many subordinate CAs that chain to a public root) mis-issues or is compromised;
- the device trusts an extra root: a corporate TLS-inspection CA installed by MDM, a CA profile installed and fully trusted by the user on iOS, a user CA trusted by an Android app that opted into user CAs, or a CA installed into the system store by malware with root;
- a state actor or network operator can obtain certificates from a CA in the device's store.

In each case the forged certificate passes normal validation and fails a pin check. That is the whole value proposition, and it is why missing pinning is a defence-in-depth finding rather than a direct vulnerability (see [Rating findings](#rating-findings)).

Pinning also raises the cost of studying the app's API, because the user's own proxy CA is rejected too. OWASP lists that as a benefit, and many app owners care about it more than about CA compromise. Be honest with them about its limits: anyone who controls a device can remove pinning in minutes ([Bypassing pinning during an assessment](#bypassing-pinning-during-an-assessment)). Pinning is not an API-protection or anti-reverse-engineering control; that is MASVS-RESILIENCE territory.

MASWE-0028 applies to the **L2** and **EUDIW** profiles in the MASWE metadata, and maps to the legacy MSTG-NETWORK-4 requirement and to CWE-295 (Improper Certificate Validation). It also carries a reminder that the browser world gave up on dynamic pinning: HTTP Public Key Pinning (RFC 7469) was removed from Chrome and Firefox because site operators kept locking out their own users with stale pins. Apps can pin safely because the developer ships the pins and the client together, but the failure mode HPKP made famous, self-inflicted outage, is exactly the availability risk you will see in this note.

## Modes of Introduction

- **No pinning at all** for first-party API hosts, leaving them protected only by the device's trust store.
- **Partial coverage.** Pins exist for `api.example.com` but not for `auth.example.com`, the upload host, the WebView origin or a second `OkHttpClient` built by an SDK or image loader. Pinning is only as strong as the least-pinned first-party host that carries tokens.
- **Pins that are present but not enforced.** An expired NSC `<pin-set>` (Android silently turns pinning off), `overridePins="true"` on user CAs in a release build, TrustKit with `enforcePinning` off (report-only), an Alamofire `ServerTrustManager` that does not list the host and does not require every host to be evaluated, `NSPinnedDomains` on an app whose deployment target includes iOS 13 (the key is ignored there).
- **Pins so broad they do not restrict.** A pin-set that lists every major public root, or a pin on a public root that thousands of unrelated subordinate CAs chain to, is technically pinning and practically equivalent to the system store.
- **Improper validation logic.** Custom code that compares something an attacker controls (subject or issuer *names*, a hash of the server-sent chain rather than the validated chain), that accepts the connection when the pin check fails, or that replaces chain validation with a pin check in a way that breaks validation. The last one is often worse than no pinning and is rated under [MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/).
- **Dynamic pinning without integrity.** Pins downloaded from a config endpoint over a channel that is itself not pinned, or not signed, so the attacker who can intercept can also choose the pins.
- **No backup pins.** A single leaf-key pin turns every certificate rotation into an outage, and the pressure that outage creates usually ends with pinning being removed.

## Impact

- **Disclosure and manipulation of traffic** when an attacker holds a certificate the device trusts: credentials, session and refresh tokens, personal and financial data, and the ability to change responses (payee details, update URLs, feature flags).
- **Account takeover** through captured tokens, scaled to every user whose device trusts the rogue CA (a corporate fleet behind an inspection proxy, a population under a hostile CA).
- **API abuse.** Easier inspection and replay of the app's API, which matters to fraud, scraping and bot programmes even though it is not a vulnerability on its own.
- **Availability.** The flip side: badly maintained pins break the app for everyone after a certificate or CA rotation, until users install an update.

## Mitigations

- Prefer the platform mechanism: NSC `<pin-set>` on Android, `NSPinnedDomains` on iOS. Both are declarative, reviewable and enforced by the system for the standard network stack.
- Pin **public keys** (SHA-256 of the SubjectPublicKeyInfo), not whole certificates, and include at least one **backup** key that is not on the server yet.
- Pin every first-party host that carries credentials or sensitive data, in every network stack the app uses (platform client, OkHttp instances, WebViews, native code, Flutter/Dart, SDKs you control). Do not pin third-party hosts whose keys you do not manage.
- If pins must change without an app update, deliver them **signed** with a key baked into the app and keep baked-in bootstrap pins.
- Treat pin rotation as an operational process with an owner: inventory, expiry alerts, a runbook, and a test that compares the shipped pins with the live chains before each release.
- Do not write custom pinning code unless you have to; when you do, compare keys from the *validated* chain and fail closed.

## Knowledge

### Both platforms: what is pinned and how to derive a pin (supplementary)

All mainstream mechanisms (NSC, OkHttp, TrustKit, ATS `NSPinnedDomains`, Alamofire's `PublicKeysTrustEvaluator`) work the same way underneath. During the handshake the platform builds and validates the certificate chain as usual, then takes the **SubjectPublicKeyInfo** (SPKI) of the certificates in that chain, hashes the DER encoding with SHA-256, and checks whether any hash is in the pin set. The SPKI is the `SEQUENCE { algorithm, subjectPublicKey }` structure inside the certificate: it contains the key *and* its algorithm identifier, so an RSA key and an EC key can never collide, and a renewed certificate that reuses the same key keeps the same pin.

The pin is written as base64 of the 32-byte digest, which is always 44 characters ending in `=`. OkHttp prefixes it with `sha256/`; NSC wraps it in `<pin digest="SHA-256">`; ATS calls the key `SPKI-SHA256-BASE64`. They are the same value, so a pin you derive once works in all of them.

Deriving the pin of the leaf certificate a server presents:

```bash
openssl s_client -connect api.example.com:443 -servername api.example.com </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | openssl enc -base64
```

Step by step: `s_client` performs the handshake (`-servername` sends SNI, without which many hosts return a default certificate); `x509 -pubkey -noout` prints the leaf's public key as PEM; `pkey -pubin -outform der` turns it into DER SubjectPublicKeyInfo; `dgst -sha256 -binary` hashes it; `enc -base64` encodes it. Older guides use `openssl rsa -pubin -outform der` in the third step. That only works for RSA keys and fails with "Not an RSA key" on the ECDSA certificates most CDNs now serve; `openssl pkey` handles both.

To pin an intermediate (or see every hash in the chain), dump the chain with `-showcerts`, split it, and hash each certificate:

```bash
openssl s_client -connect api.example.com:443 -servername api.example.com -showcerts </dev/null 2>/dev/null \
  | awk '/BEGIN CERTIFICATE/{n++; f=1} f{print > ("cert" n ".pem")} /END CERTIFICATE/{f=0}'

for c in cert*.pem; do
  subj=$(openssl x509 -in "$c" -noout -subject)
  pin=$(openssl x509 -in "$c" -pubkey -noout | openssl pkey -pubin -outform der \
        | openssl dgst -sha256 -binary | openssl enc -base64)
  echo "$c  $pin  $subj"
done
```

```text
cert1.pem  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=  subject=CN=api.example.com
cert2.pem  BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=  subject=C=US, O=Example Trust, CN=Example Issuing CA 2
```

The server normally does not send the root, so to pin a root you hash the root certificate from the CA's repository or your trust store. For a **backup pin** you hash a key that is not deployed yet, straight from the private key or a CSR held offline:

```bash
# from the backup private key (kept offline, not on the server)
openssl pkey -in backup.key -pubout -outform der | openssl dgst -sha256 -binary | openssl enc -base64
# or from a CSR generated with that key
openssl req -in backup.csr -pubkey -noout | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary | openssl enc -base64
```

As a tester you use the same pipeline in reverse: extract the pins from the app, compute the hashes of the live chain for each first-party host, and match them up. That tells you which certificate each pin targets (leaf, intermediate, root), whether a backup exists, and whether a pin matches nothing at all (dead pin, a rotation waiting to break the app).

Two formats you will meet that are *not* SPKI pins: the hex SHA-256 fingerprint of the whole certificate (`openssl x509 -noout -fingerprint -sha256`, used by some Cordova plugins), which changes at every renewal, and whole certificates bundled as `.cer`/`.crt`/`.pem`/`.bks` files, which are trust-store pinning (see below).

### Both platforms: choosing the pin target, backup pins and dynamic pinning (supplementary)

**What to pin.** Every option is a trade between how much it restricts and how often it breaks:

| Target | Restricts the attacker to | Breaks when | Notes |
|---|---|---|---|
| Leaf key | Your own private key | The server key changes | Strongest. Survives renewals only if the key is reused (most ACME clients generate a new key by default; certbot has `--reuse-key`). Needs a backup key. |
| Intermediate CA key | Certificates from that one issuing CA | The CA switches intermediates | CAs rotate intermediates. Let's Encrypt moved from R3/E1 to R10/R11 and E5/E6 in 2024 and issues from several at random, which broke apps pinned to a single intermediate. Pin several or add a backup. |
| Root CA key | Every certificate under that root, including all its subordinate CAs | You change CA, or the CA re-roots | Apple recommends CA identities for `NSPinnedDomains`. Effective when the root is your own private CA or a CA with a small, well-run hierarchy; weak when the root is shared by a large ecosystem of resellers and sub-CAs. |
| Private CA you operate | Your CA only | Practically never, if you run it well | Strongest long-term option; the server certificate need not be publicly trusted at all, which is fine for API hosts that only the app talks to. |

**Backup pins.** A backup pin is the hash of a key that is not in use yet: a spare leaf key generated and stored offline, or the key of a second CA you have an account with. When the primary key is retired or compromised you deploy the backup key on the server and the shipped app keeps working, then you ship a release with a new backup. Android does not enforce a backup; the [Android documentation](https://developer.android.com/privacy-and-security/security-config#CertificatePinning) and Apple both recommend one. TrustKit on iOS refuses a domain configuration with fewer than two hashes for this reason.

**Dynamic pinning.** Some apps fetch pins at run time so they can rotate without a release. That is legitimate only if the pin payload is authenticated independently of the TLS connection it is meant to protect: signed with a key whose public half is compiled into the app, with a version or expiry to prevent rollback, and with baked-in bootstrap pins used for the very first fetch. Fetching the list over an unpinned connection (trust on first use at best), accepting an unsigned JSON blob, or letting a remote-config value switch pinning off, hands the attacker the controls.

**Trust-store pinning.** An alternative style ships the expected certificates (or a private CA) and builds a `TrustManager`/`SecTrust` anchor set from them alone, so only those anchors are trusted. On Android that is a custom `KeyStore` + `TrustManagerFactory`, or NSC `<trust-anchors>` with `<certificates src="@raw/my_ca"/>` and no `system` entry; on iOS it is `SecTrustSetAnchorCertificates` plus `SecTrustSetAnchorCertificatesOnly`. It restricts trust as well as SPKI pinning does, provided the full chain validation still runs.

### Android: Certificate Pinning (MASTG-KNOW-0015)

Source: [MASTG-KNOW-0015](https://mas.owasp.org/MASTG/knowledge/android/MASVS-NETWORK/MASTG-KNOW-0015/). The general NSC mechanism (trust anchors, cleartext, debug overrides) is covered in [MASTG-KNOW-0014](https://mas.owasp.org/MASTG/knowledge/android/MASVS-NETWORK/MASTG-KNOW-0014/) and in our [MASWE-0027 note](/mobile/maswe-0027-insecure-certificate-validation/); here we look at the pinning parts.

#### Network Security Configuration `<pin-set>` (Android 7.0, API 24+)

The NSC is an XML resource referenced from the manifest (`<application android:networkSecurityConfig="@xml/network_security_config">`) and lives at `res/xml/<name>.xml`. Pinning is declared per `<domain-config>`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config>
        <domain includeSubdomains="true">example.com</domain>
        <pin-set expiration="2027-12-31">
            <!-- issuing CA key currently in use -->
            <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
            <!-- backup: second CA, or an offline spare key -->
            <pin digest="SHA-256">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

The rules that matter when you test it:

- **Where a pin-set can appear.** Only inside `<domain-config>`. `<base-config>` and `<debug-overrides>` cannot contain one, so there is no "pin everything" switch; every pinned host must be named.
- **Matching.** A connection passes if *any* key in the validated chain of trust matches *any* pin. Chain validation against the trust anchors runs first; pinning only narrows it.
- **Digest.** `SHA-256` is the only supported digest. The value is base64 of the SPKI hash, exactly as derived above.
- **Domains.** `<domain>` matches the exact host; `includeSubdomains="true"` extends it to every subdomain. When several `<domain-config>` entries match, the most specific domain wins. A nested `<domain-config>` inherits any setting it does not set itself, including the parent's pin-set.
- **Expiration.** `expiration="yyyy-MM-dd"` is the date at and after which the pin-set is no longer applied. After that the connection is validated against the trust anchors only, exactly as if there were no pins. Android does this deliberately so that apps which stop receiving updates do not lose connectivity. The consequence for you: an expired pin-set looks like pinning in the APK and is not pinning on the device. With no `expiration` attribute, pins never expire.
- **`overridePins`.** Any `<certificates>` trust-anchor source can carry `overridePins="true"`, which means chains ending in a CA from that source skip pin checks. The default is `false`, except inside `<debug-overrides>`, where it defaults to `true`. Two consequences: `<certificates src="user" overridePins="true"/>` in a release `<base-config>` lets any user-installed CA defeat the pins (an ineffective-pin finding); and the debug-overrides trust anchors bypass pins, which is fine because they only apply when `android:debuggable="true"`. Check that the release build is not debuggable.
- **User CAs and pinning.** Since targetSdk 24 apps do not trust user-added CAs unless the NSC says so. If an app does trust user CAs for a domain that also has a pin-set (without `overridePins`), the pins still apply and a user CA is still rejected. Pinning is therefore what separates "the user installed a CA" from "the user's traffic is readable" for apps that opted into user CAs.
- **Scope.** NSC is enforced by the platform's default `TrustManager` (Conscrypt), so it covers `HttpsURLConnection`, OkHttp and Retrofit using the default trust manager, Volley, and `WebView` (Chromium's verifier consults the same configuration, and logs `X509Util: Failed to validate the certificate chain, error: Pin verification failed` when a pin fails). It does *not* cover a client that installs its own `TrustManager` built from its own `KeyStore`, native code using its own TLS library (BoringSSL/OpenSSL in a `.so`, Cronet bundled with its own verifier, game engines), or Flutter's Dart `HttpClient`.
- **Version floor.** NSC is ignored before Android 7.0. If `minSdkVersion` is below 24, devices on 6.0 and older get no NSC pinning at all; TrustKit for Android was written partly to back-port it.

A pin failure surfaces in `HttpsURLConnection`/OkHttp as `javax.net.ssl.SSLHandshakeException: java.security.cert.CertificateException: Pin verification failed`.

#### OkHttp `CertificatePinner`

OkHttp has its own pinner, independent of the NSC, configured on the client:

```kotlin
val pinner = CertificatePinner.Builder()
    .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    .add("api.example.com", "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
    .add("**.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    .build()

val client = OkHttpClient.Builder()
    .certificatePinner(pinner)
    .build()
```

Points to check:

- **Host patterns.** A plain name matches only that host. `*.example.com` matches exactly one extra label (`api.example.com`, not `example.com` and not `a.b.example.com`); `**.example.com` matches the domain and any depth of subdomain. A pinner configured for `example.com` does nothing for `api.example.com`.
- **What is compared.** OkHttp runs the platform trust manager first, then "cleans" the chain down to a trusted root, then compares pins against the cleaned chain. Versions before 2.7.4 / 3.1.2 compared against the raw server-sent chain, which let an attacker with any trusted certificate append the genuine pinned certificate and pass ([CVE-2016-2402](https://nvd.nist.gov/vuln/detail/CVE-2016-2402)). If you see an OkHttp that old, it is a finding in its own right.
- **Per-client.** Pins live on one `OkHttpClient`. `client.newBuilder()` copies them; a fresh `OkHttpClient()` elsewhere (an image loader, a WebSocket client, an SDK's own client, a second Retrofit instance) does not. Pinning coverage is per client instance, not per app.
- **Failure.** A mismatch throws `SSLPeerUnverifiedException: Certificate pinning failure!` followed by the peer chain's `sha256/` hashes and the configured pins. Developers sometimes deliberately configure a wrong pin to read the correct ones from this message; testers can read it from logcat in debug builds too.
- **Both NSC and OkHttp.** They stack: OkHttp's default trust manager enforces NSC pins, and `CertificatePinner` adds its own check.

#### TrustKit for Android

[TrustKit-Android](https://github.com/datatheorem/TrustKit-Android) reads its policy from the NSC file, adding a `<trustkit-config>` element for enforcement and reporting:

```xml
<domain-config>
    <domain includeSubdomains="true">api.example.com</domain>
    <pin-set>
        <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
        <pin digest="SHA-256">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin>
    </pin-set>
    <trustkit-config enforcePinning="true" disableDefaultReportUri="true">
        <report-uri>https://reports.example.com/pin-failures</report-uri>
    </trustkit-config>
</domain-config>
```

The app calls `TrustKit.initializeWithNetworkSecurityConfiguration(context)` and then uses `TrustKit.getInstance().getSSLSocketFactory(host)` / `getTrustManager(host)` on its HTTP clients. When testing, check `enforcePinning`: with it off, TrustKit only reports failures and the connection proceeds. Also check that the factories are actually attached to the clients that talk to the pinned hosts.

#### Custom `TrustManager` pinning

Before the NSC, pinning meant a custom `X509TrustManager`: load the expected certificates into a `KeyStore`, build a `TrustManagerFactory` from it, and give the resulting `SSLContext` to the client. Variants compare `cert.publicKey.encoded` hashes inside `checkServerTrusted`. This is the error-prone route OWASP warns about, and the mistakes are the ones to look for in jadx:

- `checkServerTrusted` that computes a pin, logs a mismatch and returns anyway (fail-open);
- a pin check that replaces the default validation rather than following it, so the chain is never validated or the hostname never checked (`SSLSocket` does not verify hostnames for you);
- comparing against the server-sent `chain` array in a way that lets a pinned certificate appended to an attacker's chain satisfy the check;
- comparing names (`getIssuerDN()`, `getSubjectDN()`) instead of keys. The legacy MASTG WebView example pinned the issuer DN string; anyone can mint a self-signed certificate with any DN, so that "pin" restricts nothing;
- pinning in `WebViewClient.onLoadResource()` or similar callbacks, which run after the resource request has been made.

Where custom code breaks *validation*, rate it under [MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/); the pinning failure is secondary.

#### WebViews and native code

`WebView` honours the NSC, so NSC pins cover first-party pages loaded in it. Code-level pins (OkHttp, TrustKit) do not, unless the app proxies WebView requests through a pinned client in `shouldInterceptRequest`, which only works for simple `GET` loads. Native libraries doing their own TLS bypass all of the above; look for libssl/BoringSSL/mbedTLS symbols and hash-like strings in `lib/*/*.so`.

### iOS: Server Trust Evaluation and pinning (MASTG-KNOW-0072)

Source: [MASTG-KNOW-0072](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-NETWORK/MASTG-KNOW-0072/). The default trust evaluation, ATS and the `URLAuthenticationChallenge` delegate methods are explained in our [MASWE-0027 note](/mobile/maswe-0027-insecure-certificate-validation/), together with [MASTG-BEST-0073](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0073/). This section covers the pinning layer.

#### `NSPinnedDomains` (iOS 14+)

Apple's [Identity Pinning](https://developer.apple.com/news/?id=g9ejcf8y) feature adds an `NSPinnedDomains` dictionary to the ATS configuration in `Info.plist`. Each key is a domain name; each value can contain:

| Key | Type | Meaning |
|---|---|---|
| `NSIncludesSubdomains` | Boolean | Apply the entry to all subdomains as well. Default `NO`. |
| `NSPinnedCAIdentities` | Array of dictionaries | Each dictionary holds `SPKI-SHA256-BASE64`. A CA (intermediate or root) in the evaluated chain must match one of them. |
| `NSPinnedLeafIdentities` | Array of dictionaries | Same format; the leaf certificate's key must match one of them. |

```xml
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSPinnedDomains</key>
    <dict>
        <key>api.example.com</key>
        <dict>
            <key>NSIncludesSubdomains</key>
            <true/>
            <key>NSPinnedCAIdentities</key>
            <array>
                <dict>
                    <key>SPKI-SHA256-BASE64</key>
                    <string>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</string>
                </dict>
                <dict>
                    <key>SPKI-SHA256-BASE64</key>
                    <string>BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</string>
                </dict>
            </array>
        </dict>
    </dict>
</dict>
```

What you need to know as a tester:

- **Availability.** iOS 14, iPadOS 14, macOS 11, watchOS 7 and tvOS 14. Earlier versions ignore the key, so an app whose deployment target is iOS 13 has no ATS pinning on those devices.
- **Scope.** Enforced by ATS for the URL Loading System (`URLSession` and APIs built on it). It does not apply to Network framework connections made directly, `CFStream`/BSD sockets, or third-party TLS stacks (Flutter's BoringSSL, native OpenSSL). Do not assume `WKWebView` content is covered; verify it dynamically.
- **No expiration and no reporting.** Unlike the NSC there is no expiry attribute, so a stale pin breaks connectivity rather than silently disabling pinning. There is no report URI either.
- **Pinning adds to trust, it does not replace it.** The chain still has to pass default evaluation; pins narrow it. A user-installed and fully trusted CA profile therefore fails the pin check, which is the point.
- **Per bundle.** App extensions (`PlugIns/*.appex`) have their own `Info.plist` and their own ATS dictionary. A share extension that uploads to `api.example.com` is unpinned unless its plist pins it too.
- **Backup.** Apple recommends at least one backup identity per domain.

#### Custom server trust evaluation (`SecTrust`)

Apps that need more control implement `urlSession(_:didReceive:completionHandler:)` on their `URLSessionDelegate` and check the key themselves. A correct implementation validates first, then pins against the validated chain, and fails closed:

```swift
func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
    guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
          let trust = challenge.protectionSpace.serverTrust else {
        completionHandler(.performDefaultHandling, nil)
        return
    }
    // 1. Normal chain + hostname evaluation must pass first
    var error: CFError?
    guard SecTrustEvaluateWithError(trust, &error),
          let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate] else {   // iOS 15+
        completionHandler(.cancelAuthenticationChallenge, nil)
        return
    }
    // 2. Any key in the validated chain must match a pin
    let matched = chain.contains { cert in
        guard let key = SecCertificateCopyKey(cert), let hash = spkiSHA256Base64(key) else { return false }
        return pinnedHashes.contains(hash)
    }
    if matched {
        completionHandler(.useCredential, URLCredential(trust: trust))
    } else {
        completionHandler(.cancelAuthenticationChallenge, nil)
    }
}
```

The subtle trap is in `spkiSHA256Base64`. `SecKeyCopyExternalRepresentation` does **not** return the SubjectPublicKeyInfo: for RSA it returns the PKCS#1 `RSAPublicKey`, for EC keys the raw X9.63 point. Hashing that gives a value that never matches the `openssl` pin. Correct implementations prepend the fixed ASN.1 SPKI header for the key type and size (TrustKit does exactly this) before hashing, or hash `SecCertificateCopyData` of a pinned *certificate* instead (certificate pinning, which breaks at every renewal). When you review such code, check which of the two it does, and check that the hardcoded hashes actually match a certificate in the live chain.

The mistakes that turn this into a finding are the ones listed in MASTG-KNOW-0072 and BEST-0073: calling `.useCredential` unconditionally or on mismatch, not calling `.cancelAuthenticationChallenge`, skipping `SecTrustEvaluateWithError` (now a validation flaw, MASWE-0027), using the deprecated `SecTrustEvaluate` and ignoring the result type, and pinning on certificate names.

`WKWebView` offers `webView(_:didReceive:completionHandler:)` on its navigation delegate. As OWASP notes, that challenge covers main-frame navigations, not every sub-resource load, so it gives incomplete pinning for web content.

#### TrustKit, Alamofire and AFNetworking

- **[TrustKit](https://github.com/datatheorem/TrustKit)** is configured with a dictionary (in code or under `TSKConfiguration` in `Info.plist`) containing `kTSKPinnedDomains`, and per domain `kTSKPublicKeyHashes` (at least two required), `kTSKIncludeSubdomains`, `kTSKEnforcePinning`, `kTSKReportUris` and optionally `kTSKExpirationDate`. With `kTSKSwizzleNetworkDelegates` it swizzles `NSURLSession`/`NSURLConnection` delegates to enforce pins automatically; otherwise the app calls `TSKPinningValidator` from its own delegate. As on Android, `kTSKEnforcePinning = NO` means report-only, and an expiration date that has passed disables enforcement for that domain.
- **Alamofire 5** pins with a `ServerTrustManager(evaluators: ["api.example.com": PublicKeysTrustEvaluator()])`. `PublicKeysTrustEvaluator` by default takes the keys of every certificate bundled in the app and also performs default validation and host validation. Look for `DisabledTrustEvaluator` (no evaluation at all) and for `ServerTrustManager(allHostsMustBeEvaluated: false, ...)`, which lets hosts missing from the map fall through to default handling without pins.
- **AFNetworking** (legacy) uses `AFSecurityPolicy policyWithPinningMode:AFSSLPinningModePublicKey`. `allowInvalidCertificates = YES` or `validatesDomainName = NO` weakens it; `AFSSLPinningModeNone` means no pinning.

#### Native code

Pinning can also live in C/Swift code using the lower-level `SecTrust` API or the Network framework's `sec_protocol_options_set_verify_block`, or inside a bundled OpenSSL/BoringSSL. It makes static review harder and does not make bypass meaningfully harder for someone with Frida.

### Both platforms: pinning in cross-platform frameworks (supplementary)

OWASP's knowledge items end with a paragraph on frameworks. In practice this is where pinning most often goes missing, because the framework's network stack is not the one the NSC or ATS governs.

- **Flutter.** Dart's `HttpClient` (and packages built on it, such as `http` and `dio`) uses BoringSSL compiled into the Flutter engine (`libflutter.so` on Android, `Flutter.framework` on iOS). NSC and `NSPinnedDomains` do not apply, the user CA store is not consulted, and the client ignores the system proxy. Pinning is done in Dart: a `SecurityContext(withTrustedRoots: false)` loaded with the expected CA via `setTrustedCertificatesBytes` (trust-store pinning), a `badCertificateCallback` (only called for certificates that *failed* validation; returning `true` there is a validation flaw, not pinning), dio's `validateCertificate` hook on `IOHttpClientAdapter`, or packages such as `http_certificate_pinning`. Pins and PEM files end up in `libapp.so` (AOT snapshot) or under `flutter_assets/`.
- **React Native.** `fetch` and `XMLHttpRequest` go through OkHttp on Android and `NSURLSession` on iOS, so NSC pins and `NSPinnedDomains` *do* apply. Libraries such as `react-native-ssl-public-key-pinning` (TrustKit on iOS, OkHttp `CertificatePinner` on Android) and `react-native-ssl-pinning` add code-level pins; on Android the app can also supply a pinned client through `OkHttpClientProvider.setOkHttpClientFactory`. Check the JS bundle (`assets/index.android.bundle`, `main.jsbundle`; Hermes bytecode needs a disassembler) for pin configuration.
- **Cordova / Ionic.** Requests from JavaScript run in the WebView. On Android the NSC applies to WebView traffic; on iOS `NSPinnedDomains` coverage of `WKWebView` must be verified. Plugins such as the SSL certificate checker plugin compare whole-certificate fingerprints in a separate request, which proves nothing about the WebView's own connections.
- **Xamarin / .NET MAUI.** Pinning usually lives in a `ServicePointManager.ServerCertificateValidationCallback` or `HttpClientHandler.ServerCertificateCustomValidationCallback` that compares the public key string of a chain element. Check which element (`chain.ChainElements[1]` is the intermediate), that `sslPolicyErrors` is still honoured, and that the callback does not simply `return true`. Xamarin reached end of support on 1 May 2024; new code should be on .NET MAUI.

## Tests

OWASP's v2 tests for MASWE-0028 are three Android tests and one iOS test. [MASTG-TEST-0242](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0242/), [MASTG-TEST-0243](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0243/) and [MASTG-TEST-0244](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0244/) replace the legacy Android test [MASTG-TEST-0022](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0022/) (Testing Custom Certificate Stores and Certificate Pinning); [MASTG-TEST-0385](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0385/) replaces the legacy iOS test [MASTG-TEST-0068](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0068/). The v2 set only checks the *declarative* mechanisms statically (NSC, ATS) plus one runtime test on Android, and has no OWASP demos for the Android tests. The legacy tests covered OkHttp, TrustKit, Xamarin and Cordova code, and an iOS runtime check; we keep that coverage in four supplementary checks.

### Before you start: which domains must be pinned

Every test here has the same prerequisite: a list of the **first-party** hosts that carry the app's core or security-sensitive traffic. Third-party hosts (analytics, crash reporting, ad networks, maps, payment SDK endpoints) are not pinned by the app developer and must not be reported as missing pins; their operators rotate keys without telling anyone, and pinning them is how apps break.

Build the list from three sources and reconcile them:

```bash
# 1. Strings in the app (Android): decoded resources, DEX and native libraries
apktool d -f app.apk -o app_apktool
jadx -d app_jadx app.apk
grep -rhoE 'https?://[A-Za-z0-9.-]+' app_jadx app_apktool/res app_apktool/assets 2>/dev/null | sort | uniq -c | sort -rn
for so in app_apktool/lib/*/*.so; do strings -a "$so" | grep -oE 'https?://[A-Za-z0-9.-]+'; done | sort -u

# 1b. Strings in the app (iOS)
unzip -q app.ipa -d ipa
rabin2 -zz ipa/Payload/*.app/$(plutil -extract CFBundleExecutable raw ipa/Payload/*.app/Info.plist) | grep -oE 'https?://[A-Za-z0-9.-]+' | sort -u

# 2. Hosts the app actually contacts, from a capture (TLS SNI), whether or not interception succeeds
tshark -r session.pcapng -Y 'tls.handshake.type == 1' -T fields -e tls.handshake.extensions_server_name | sort | uniq -c | sort -rn
```

The third source is the client: ask which domains they operate. Registrable domain, certificate subject and DNS (`dig +short CNAME api.example.com`) help you guess, but a CNAME to a CDN or an API gateway does not tell you who manages the certificate. When in doubt, list the host as "first-party (assumed)" and say so in the report. See [MASTG-TECH-0022](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0022/) and [MASTG-TECH-0071](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0071/).

A hardcoded URL is not proof of a connection. OWASP's "further validation" applies to all four tests: confirm that the code which uses the URL is reachable (jadx cross-references, [MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/); disassembly on iOS, [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/)) or that the host appears in the capture.

### MASTG-TEST-0242: Missing Certificate Pinning in Network Security Configuration (Android)

Source: [MASTG-TEST-0242](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0242/). Platform: Android. Type: static (config, code). Related knowledge: MASTG-KNOW-0014, MASTG-KNOW-0015. Replaces part of MASTG-TEST-0022.

#### Overview

The test checks whether the NSC declares a `<pin-set>` for each relevant first-party domain. It fails when the app has no NSC, or has one without pins for those domains. It deliberately does not claim the app has *no* pinning: OkHttp, TrustKit or native code may pin the same host, in which case the result is "not covered by NSC pinning" and you move on to [GT-0028-1](#gt-0028-1-code-level-pinning-on-android-okhttp-trustkit-trustmanager) and [MASTG-TEST-0244](#mastg-test-0244-missing-certificate-pinning-in-network-traffic-android).

#### Prerequisites

- The APK (all splits if it is an app bundle; the NSC lives in the base split).
- apktool ([MASTG-TOOL-0011](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/)) or jadx ([MASTG-TOOL-0018](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/)), Python 3 (or yq/jq), `openssl`.
- The first-party domain list.

#### Steps

1. **Decode the app** ([MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)) and read the manifest ([MASTG-TECH-0117](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/), [MASTG-TECH-0150](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0150/)):

   ```bash
   apktool d -f app.apk -o app_apktool
   grep -o 'android:networkSecurityConfig="[^"]*"' app_apktool/AndroidManifest.xml
   grep -oE 'android:(minSdkVersion|targetSdkVersion)="[0-9]+"' app_apktool/apktool.yml app_apktool/AndroidManifest.xml
   grep -o 'android:debuggable="[^"]*"' app_apktool/AndroidManifest.xml
   ```

   No `networkSecurityConfig` attribute means no NSC pinning (and platform defaults for everything else). `@xml/network_security_config` maps to `app_apktool/res/xml/network_security_config.xml` ([MASTG-TECH-0151](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0151/)). Note `minSdkVersion`: below 24, NSC pins do not exist on the oldest supported devices.

2. **List every domain with its effective pin-set.** Nested `<domain-config>` elements inherit their parent's pins, which a flat grep gets wrong. This short script walks the tree, reports expiry and pin count, and prints the trust anchors with their `overridePins` setting:

   ```python
   import sys, datetime
   import xml.etree.ElementTree as ET

   today = datetime.date.today()

   def walk(dc, inherited_pins):
       pins = dc.find("pin-set")
       if pins is None:
           pins = inherited_pins
       for d in dc.findall("domain"):
           sub = d.get("includeSubdomains", "false")
           if pins is None:
               print(f"{d.text.strip():30} sub={sub:5}  NO PINS")
               continue
           exp = pins.get("expiration")
           n = len(pins.findall("pin"))
           state = "no expiry"
           if exp:
               expired = datetime.date.fromisoformat(exp) <= today
               state = f"expires {exp}" + ("  ** EXPIRED: pinning OFF **" if expired else "")
           print(f"{d.text.strip():30} sub={sub:5}  pins={n}  {state}")
       for child in dc.findall("domain-config"):
           walk(child, pins)

   root = ET.parse(sys.argv[1]).getroot()
   for dc in root.findall("domain-config"):
       walk(dc, None)
   for el in root.iter():
       for c in el.findall("trust-anchors/certificates"):
           print(f"{el.tag}: certificates src={c.get('src')} overridePins={c.get('overridePins', 'default')}")
   ```

   ```bash
   python3 -I nsc_pins.py app_apktool/res/xml/network_security_config.xml
   ```

   The yq/jq route from MASTG-TECH-0151 gives you the pinned domains in one line (it does not resolve inheritance):

   ```bash
   yq -p=xml -o=json '.' network_security_config.xml > nsc.json
   jq -r '.["network-security-config"]["domain-config"] | (if type == "array" then .[] else . end)
          | select(.["pin-set"] != null) | .domain | (if type == "array" then .[] else . end)
          | if type == "object" then .["+content"] else . end' nsc.json
   ```

3. **Match each first-party host against the most specific domain entry.** `auth.example.com` is covered by `example.com` only if that entry has `includeSubdomains="true"`, and a more specific entry without pins (for example one added to allow cleartext to a subdomain) takes precedence and carries no pins unless it is nested under the pinned one.

4. **Check that the pins match something.** For each pinned host, derive the live chain's SPKI hashes ([derivation pipeline](#both-platforms-what-is-pinned-and-how-to-derive-a-pin-supplementary)) and match them with the pins. Record which pin is leaf, intermediate, root or backup (matches nothing live: either a planned backup or a dead pin; ask).

5. **Look for other pinning before concluding** ([GT-0028-1](#gt-0028-1-code-level-pinning-on-android-okhttp-trustkit-trustmanager)): `CertificatePinner`, `sha256/` strings, TrustKit, custom trust managers.

#### Observation

The manifest attribute (or its absence), the NSC file, the table of domains with pin count, expiry and `includeSubdomains`, the trust-anchor sources with `overridePins`, the first-party host list with the entry that covers each, and the mapping of pins to live certificates.

#### Evaluation

The test **fails** if the app connects to a relevant first-party host and either no NSC is set, or the NSC sets no pin-set that applies to that host.

It does **not** fail because third-party hosts are unpinned.

If code-level pinning covers the host, record "not covered by NSC" and evaluate that mechanism instead. Report separately, as ineffective pinning, a pin-set that is present but defeated by `<certificates src="user" overridePins="true"/>` (or any other non-system source with `overridePins="true"`) in a release configuration, and a pin-set whose pins match nothing in the live chain and include no plausible backup (that one is an availability issue: the app should already be failing).

#### Demo

OWASP has no demo for this test; this is our own (Guler Tech methodology). The app talks to `api.example.com` and `auth.example.com`; the developer pinned the API but scoped the entry without subdomains:

```xml
<network-security-config>
    <domain-config>
        <domain>api.example.com</domain>
        <pin-set>
            <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
            <pin digest="SHA-256">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin>
        </pin-set>
    </domain-config>
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">example.com</domain>
    </domain-config>
</network-security-config>
```

```text
$ python3 -I nsc_pins.py app_apktool/res/xml/network_security_config.xml
api.example.com                sub=false  pins=2  no expiry
example.com                    sub=true   NO PINS

$ grep -rhoE 'https://[a-z0-9.-]+\.example\.com' app_jadx | sort -u
https://api.example.com
https://auth.example.com
```

`auth.example.com` matches the second entry, which has no pins. That is the host that issues the session and refresh tokens, so the test fails for it even though the "main" API is pinned. The fix is to pin at `example.com` with `includeSubdomains="true"` (or add `auth.example.com` to the pinned entry).

### MASTG-TEST-0243: Expired Certificate Pins in the Network Security Configuration (Android)

Source: [MASTG-TEST-0243](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0243/). Platform: Android. Type: static (config). Related knowledge: MASTG-KNOW-0014, MASTG-KNOW-0015. Replaces part of MASTG-TEST-0022.

#### Overview

An NSC pin-set with an `expiration` date in the past is ignored: Android falls back to the domain's trust anchors as if no pins existed. This keeps abandoned apps online, and it means a pinning control reviewed at release time can quietly disappear while the app is still in users' hands. The test finds expired pin-sets for first-party hosts. OWASP's own example is an app that pinned its private CA: after expiry any certificate valid under the configured anchors is accepted.

#### Prerequisites

As for MASTG-TEST-0242. Know the date the test is run; for a report, also note the app version and its release date (an expiry date that lands a few weeks after release is a planned failure).

#### Steps

1. Decode the app and locate the NSC (steps 1-2 of MASTG-TEST-0242).
2. Extract every pin-set's `expiration` with the domains it applies to, including inherited ones. The script above prints `** EXPIRED: pinning OFF **` for dates on or before today (the platform treats the expiry date itself as expired). A quick grep also works:

   ```bash
   grep -n 'expiration=' app_apktool/res/xml/network_security_config.xml
   ```

3. Map the affected domains to the first-party list.
4. Confirm the effect at run time if you have a rooted device with your proxy CA in the **system** store: an expired pin-set lets the proxy decrypt the traffic without any bypass, and logcat shows no `Pin verification failed`. That turns a static observation into evidence.
5. Note pin-sets that will expire within the app's likely support window (for example within 12 months); they are not failures yet, but worth a Low/Info note.

#### Observation

The list of pin-sets with expiration dates, the domains each applies to (with inheritance), which of those are first-party, and optionally the run-time capture showing decrypted traffic.

#### Evaluation

The test **fails** if any pin-set applying to a relevant first-party domain has an expiration date on or before the test date. It does not fail for expired pins on third-party domains. A pin-set without an `expiration` attribute does not expire; that is a pass for this test (and an availability consideration for the developers, who then need backup pins and a release process).

#### Demo

Our own (Guler Tech methodology), since OWASP publishes none:

```xml
<domain-config>
    <domain includeSubdomains="true">example.com</domain>
    <pin-set expiration="2025-06-30">
        <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
        <pin digest="SHA-256">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin>
    </pin-set>
</domain-config>
```

```text
$ python3 -I nsc_pins.py app_apktool/res/xml/network_security_config.xml
example.com                    sub=true   pins=2  expires 2025-06-30  ** EXPIRED: pinning OFF **
base-config: certificates src=system overridePins=default
```

With the proxy CA installed as a system CA on a rooted emulator, mitmproxy shows decrypted `https://api.example.com/v1/accounts` requests with no hooking. The test fails. Note what an attacker still needs: a certificate trusted by the device's system store (or by the app's anchors). The expired pins remove the defence-in-depth layer, they do not by themselves open the traffic to a Wi-Fi attacker.

### MASTG-TEST-0244: Missing Certificate Pinning in Network Traffic (Android)

Source: [MASTG-TEST-0244](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0244/). Platform: Android (network). Type: dynamic, network. Related knowledge: MASTG-KNOW-0015. Replaces the dynamic part of MASTG-TEST-0022.

#### Overview

The implementation-agnostic test: put a MITM proxy whose CA the *device* trusts between the app and its servers, use the app, and see which first-party hosts you can decrypt without bypassing anything. Any first-party host you can read is not pinned (or not effectively pinned), whatever the code looks like. It catches pinning in NSC, OkHttp, TrustKit, native code or anything else, and it also catches the cases static analysis misses: a second unpinned client, an expired pin-set, an `overridePins` trust anchor.

#### Prerequisites

The test only measures pinning if the *only* thing that can stop the proxy is a pin. Set it up so normal validation succeeds:

- A rooted device or emulator with your proxy's CA in the **system** trust store. A user CA is not enough: apps targeting API 24+ ignore user CAs unless they opt in, so a failed connection would tell you about trust anchors, not pins. On Android 14+ the system store is the Conscrypt APEX (`/apex/com.android.conscrypt/cacerts`), which needs a different injection method from older versions. The [interception lab](/mobile/mobile-traffic-interception-lab/) covers both.
- An interception proxy: Burp Suite ([MASTG-TOOL-0077](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0077/)) or mitmproxy ([MASTG-TOOL-0097](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0097/)), set up as in [MASTG-TECH-0011](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0011/). For apps that ignore the system proxy (Flutter, Xamarin, some native stacks) use transparent redirection (iptables, a VPN-based tool, or a rogue access point) instead.
- A packet capture running alongside (`tcpdump` on the device or `tshark` on the AP) so you can list hosts that *attempted* TLS, including the ones that failed.
- A test account and a list of the app's features to exercise; installed per [MASTG-TECH-0005](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/).

#### Steps

1. Start the capture and the proxy, and watch the logs ([MASTG-TECH-0009](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0009/)):

   ```bash
   mitmdump -p 8080 -w session.mitm
   adb shell settings put global http_proxy 192.168.56.1:8080
   adb logcat -v time | grep -iE 'pin verification|pinning failure|X509Util|SSLHandshakeException|CertPathValidator'
   ```

2. Launch the app cold and exercise every feature that talks to the network: registration, login, MFA, profile, payments, uploads, embedded web content, logout. Pinning is often applied per client, so features that use a different client (uploads, WebSockets, WebViews) must be exercised individually.

3. List what was decrypted and what failed:

   ```bash
   mitmdump -nr session.mitm --set flow_detail=1 | grep -oE 'https://[^/ ]+' | sort | uniq -c
   ```

   In the mitmproxy event log, pinned hosts show up as client TLS handshakes that failed because the client does not trust the proxy's certificate; in Burp, as "The client failed to negotiate a TLS connection" entries in the event log. Combine with the SNI list from the capture.

4. Remove the proxy afterwards: `adb shell settings put global http_proxy :0`.

#### Observation

The proxy capture of decrypted first-party hosts, the list of hosts whose handshakes failed, the SNI list, relevant logcat lines (`Pin verification failed`, `Certificate pinning failure!`), and the device's Android version and the method used to install the CA.

#### Evaluation

The test **fails** if any relevant first-party host appears decrypted in the capture. It does not fail because third-party hosts are decrypted.

A host whose handshake fails is *probably* pinned. Confirm before writing "pinned" in a report: other causes are mutual TLS (the server asks for a client certificate the proxy cannot present), certificate transparency or custom validation in a native stack, HTTP/3 over UDP (QUIC never reaches a TCP proxy; Cronet and some SDKs fall back to TCP only after a failure), and a CA that was not actually installed in the store the app uses. A pinned host should fail consistently, with a pin-related log line, and succeed once you apply a bypass ([Bypassing pinning during an assessment](#bypassing-pinning-during-an-assessment)).

#### Demo

Our own (Guler Tech methodology). Proxy CA in the system store, app exercised through login and an upload:

```text
$ mitmdump -nr session.mitm --set flow_detail=1 | grep -oE 'https://[^/ ]+' | sort | uniq -c
  14 https://api.example.com
   3 https://upload.example.com
  22 https://telemetry.example.net

$ adb logcat | grep -i pin
W/System.err: javax.net.ssl.SSLPeerUnverifiedException: Certificate pinning failure!
```

The pin failures belong to `auth.example.com` (visible in the SNI list, never decrypted): login is pinned. `api.example.com` and `upload.example.com` are first-party and readable, so the test fails for them. `telemetry.example.net` is a third-party SDK and is not reported. In jadx, the cause is a second `OkHttpClient()` built in the API module without the `CertificatePinner` that the auth module uses.

### MASTG-TEST-0385: Missing Certificate Pinning in ATS (iOS)

Source: [MASTG-TEST-0385](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0385/). Platform: iOS. Type: static. Related knowledge: [MASTG-KNOW-0071](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-NETWORK/MASTG-KNOW-0071/), MASTG-KNOW-0072. Demo: [MASTG-DEMO-0148](https://mas.owasp.org/MASTG/demos/ios/MASVS-NETWORK/MASTG-DEMO-0148/MASTG-DEMO-0148/). Replaces MASTG-TEST-0068.

#### Overview

The test checks that `Info.plist` declares `NSPinnedDomains` entries for the relevant first-party hosts the app reaches through the URL Loading System. As with the NSC test, absence of ATS pins is not proof of absence of pinning: custom `URLSessionDelegate` code, TrustKit, Alamofire or a non-URLSession stack may pin. In that case the result is "not covered by ATS pinning" and you continue with [GT-0028-2](#gt-0028-2-code-level-pinning-on-ios-sectrust-trustkit-alamofire) and [GT-0028-3](#gt-0028-3-runtime-pinning-check-ios). OWASP's own limitation note says the same: the test does not cover Network framework, sockets, native TLS or third-party stacks.

#### Prerequisites

- The decrypted IPA ([MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/)); `plutil` (macOS) or `plistutil` (Linux), PlistBuddy ([MASTG-TOOL-0135](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0135/)), `jq`, rabin2 ([MASTG-TOOL-0129](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/)), `otool`.
- The first-party domain list and the app's `MinimumOSVersion`.

#### Steps

1. Unpack the app and convert the main `Info.plist` and every extension's plist to JSON ([MASTG-TECH-0138](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0138/)):

   ```bash
   unzip -q app.ipa -d ipa
   APP=$(ls -d ipa/Payload/*.app)
   plutil -convert json -o Info.json "$APP/Info.plist"
   jq '.MinimumOSVersion, .NSAppTransportSecurity.NSPinnedDomains' Info.json
   for p in "$APP"/PlugIns/*.appex/Info.plist; do
     echo "== $p"; plutil -convert json -o - "$p" | jq '.NSAppTransportSecurity.NSPinnedDomains'
   done
   ```

   PlistBuddy gives the same without conversion: `/usr/libexec/PlistBuddy -c 'Print :NSAppTransportSecurity:NSPinnedDomains' "$APP/Info.plist"`.

2. Check `MinimumOSVersion`: below 14.0, the pins are absent on older devices.

3. Retrieve hardcoded URLs from the binary and frameworks (MASTG-TECH-0071):

   ```bash
   BIN="$APP/$(jq -r .CFBundleExecutable Info.json)"
   rabin2 -zz "$BIN" | grep -oE 'https://[^" ]+' | sort -u
   for f in "$APP"/Frameworks/*.framework; do rabin2 -zz "$f/$(basename "$f" .framework)" 2>/dev/null; done | grep -oE 'https://[^" ]+' | sort -u
   ```

4. Compare: every first-party host reached via `URLSession` should be listed, directly or through `NSIncludesSubdomains`. For each listed host, derive the live chain's SPKI hashes and check that at least one `NSPinnedCAIdentities` entry matches a CA in the chain or one `NSPinnedLeafIdentities` entry matches the leaf.

5. Look for other pinning before concluding: `TSKConfiguration` in `Info.plist`, `otool -L "$BIN" | grep -iE 'trustkit|alamofire|afnetworking'`, imports of `SecTrustEvaluateWithError`, `SecTrustCopyCertificateChain`, `SecCertificateCopyKey` (`rabin2 -i "$BIN"`).

#### Observation

The `NSPinnedDomains` dictionary (main app and each extension), the minimum OS version, the hardcoded first-party URLs, the hosts lacking an entry, and the match between pins and live chains.

#### Evaluation

The test **fails** if the app makes URL Loading System connections to a relevant first-party host and there is no `NSAppTransportSecurity` dictionary, no `NSPinnedDomains` key, or no entry covering that host. It does not fail for third-party hosts. If another pinning mechanism covers the host, record "not covered by ATS pinning" and evaluate that mechanism.

#### Demo

[MASTG-DEMO-0148](https://mas.owasp.org/MASTG/demos/ios/MASVS-NETWORK/MASTG-DEMO-0148/MASTG-DEMO-0148/). The sample app calls three hosts with `URLSession.shared`. Two public test hosts (`sha256.badssl.com`, `rsa2048.badssl.com`) are pinned; `example.com` stands in for the app's own backend and is not:

```swift
struct MastgTest {
    static let pinnedEndpoint = "https://sha256.badssl.com/"        // pinned via NSPinnedDomains
    static let secondPinnedEndpoint = "https://rsa2048.badssl.com/" // pinned via NSPinnedDomains
    static let developerEndpoint = "https://example.com/"           // the app's own backend: NOT pinned

    static func mastgTest(completion: @escaping (String) -> Void) {
        for endpoint in [pinnedEndpoint, secondPinnedEndpoint, developerEndpoint] {
            URLSession.shared.dataTask(with: URL(string: endpoint)!) { _, _, _ in }.resume()
        }
    }
}
```

OWASP's script converts the plist and extracts the pins and URLs:

```bash
plutil -convert json -o Info_reversed.json Info_reversed.plist
jq '.NSAppTransportSecurity.NSPinnedDomains' Info_reversed.json > ats_pinned_domains.json
rabin2 -z MASTestApp | grep http > output.txt
```

```json
{
  "sha256.badssl.com": {
    "NSPinnedCAIdentities": [ { "SPKI-SHA256-BASE64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" } ],
    "NSIncludesSubdomains": true
  },
  "rsa2048.badssl.com": {
    "NSPinnedCAIdentities": [ { "SPKI-SHA256-BASE64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" } ],
    "NSIncludesSubdomains": true
  }
}
```

```text
0   0x000153c0 0x000153c0 26  27   3.__TEXT.__cstring         ascii https://sha256.badssl.com/
1   0x000153e0 0x000153e0 27  28   3.__TEXT.__cstring         ascii https://rsa2048.badssl.com/
2   0x00015400 0x00015400 20  21   3.__TEXT.__cstring         ascii https://example.com/
```

(The demo pins a real CA key; we show a placeholder hash.) The test fails: `example.com`, the backend, has no `NSPinnedDomains` entry, so its connections rely on the system trust store alone. Two more observations a real report would add: each pinned domain has a single identity and no backup, and both domains share one CA pin, so a change of CA breaks both at once.

### Supplementary checks (Guler Tech methodology)

The four OWASP tests check the declarative configuration and the Android runtime result. These checks cover what they leave out: code-level pinning on both platforms, the iOS runtime result, and dynamic pins. They are ours, not OWASP tests.

### GT-0028-1: Code-level pinning on Android (OkHttp, TrustKit, TrustManager)

#### Overview

Find every pinning implementation in code, check that it covers every client that talks to first-party hosts, and check it is not fail-open or comparing the wrong thing.

#### Prerequisites

jadx output (`jadx -d app_jadx app.apk`), apktool output, `strings`, a device for confirmation.

#### Steps

1. Search for pinning APIs and pin material:

   ```bash
   grep -rnE 'CertificatePinner|certificatePinner\(|TrustKit|PinningTrustManager|checkServerTrusted|X509TrustManager|TrustManagerFactory|setSSLSocketFactory|sslSocketFactory\(' app_jadx/sources | grep -v '/okhttp3/internal/'
   grep -rnoE 'sha(1|256)/[A-Za-z0-9+/]{27,43}=' app_jadx/sources
   grep -rnoE '"[A-Za-z0-9+/]{43}="' app_jadx/sources | head
   find app_apktool/res app_apktool/assets -type f \( -iname '*.cer' -o -iname '*.crt' -o -iname '*.pem' -o -iname '*.der' -o -iname '*.bks' -o -iname '*.jks' -o -iname '*.p12' \)
   for so in app_apktool/lib/*/*.so; do strings -a "$so" | grep -E '^[A-Za-z0-9+/]{43}=$|sha256/' | sed "s|^|$so: |"; done
   ```

   With obfuscation, OkHttp class names disappear but the strings `Certificate pinning failure!` and `sha256/` remain; follow them in jadx to the pinner and its `add()` calls (the method that takes a `String` and a `String...` and returns the builder).

2. **Coverage.** Find every place an HTTP client is built (`OkHttpClient.Builder()`, `new OkHttpClient()`, `HttpsURLConnection`, `Retrofit.Builder().client(...)`, WebSocket clients, image loaders such as Glide/Coil OkHttp integrations) and check which ones receive the pinner or the TrustKit socket factory. Map each to the hosts it calls.

3. **Host patterns.** Compare the `add()` patterns with the first-party list (`example.com` vs `*.example.com` vs `**.example.com`).

4. **Correctness of custom trust managers.** Read `checkServerTrusted`: does it call the default trust manager first, compare SPKI hashes from the validated chain, throw `CertificateException` on mismatch, and never swallow the exception? Is hostname verification left intact?

5. **TrustKit settings.** `enforcePinning`, report URIs, and whether `getSSLSocketFactory(host)` is used on the right clients.

6. **Library versions.** OkHttp before 3.1.2 (or 2.7.4) is vulnerable to CVE-2016-2402; the version is usually in `META-INF/okhttp.version` or visible from the package layout.

7. **Confirm at run time** with the setup from MASTG-TEST-0244: hosts using an unpinned client are decrypted.

#### Observation

The list of pinning implementations, the clients and hosts each covers, the pin values mapped to live certificates, and any correctness issues with code references.

#### Evaluation

**Fail** if a first-party host is reached through a client with no pinning; if a pinning check is fail-open, compares names instead of keys, or compares against the unvalidated chain; or if TrustKit runs with enforcement off in a release build. **Pass** if every first-party client enforces pins that match the live chain (plus backup) and failure aborts the connection.

#### Demo

```kotlin
// Auth module: pinned
val authClient = OkHttpClient.Builder()
    .certificatePinner(CertificatePinner.Builder()
        .add("auth.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        .add("auth.example.com", "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
        .build())
    .build()

// API module: a fresh client, no pinner, carries the same bearer token
val apiClient = OkHttpClient.Builder()
    .addInterceptor(BearerTokenInterceptor(tokenStore))
    .build()
```

```text
$ grep -rnE 'OkHttpClient\.Builder\(\)|certificatePinner\(' app_jadx/sources/com/example/
.../auth/AuthModule.java:31:        OkHttpClient.Builder builder = new OkHttpClient.Builder();
.../auth/AuthModule.java:32:        builder.certificatePinner(pinner);
.../api/ApiModule.java:18:        OkHttpClient.Builder builder = new OkHttpClient.Builder();
```

The second builder never gets a pinner. The token obtained over the pinned connection travels to `api.example.com` over an unpinned one. Fail. The fix is to build one base client with the pinner and derive others from it with `newBuilder()`.

### GT-0028-2: Code-level pinning on iOS (SecTrust, TrustKit, Alamofire)

#### Overview

The iOS counterpart of GT-0028-1: find pinning in code or libraries and check coverage and correctness.

#### Prerequisites

Decrypted IPA, rabin2/radare2, `otool`, `nm`, a disassembler (Ghidra, Hopper or r2), `plutil`.

#### Steps

1. Identify libraries and APIs:

   ```bash
   otool -L "$BIN" | grep -iE 'trustkit|alamofire|afnetworking'
   ls "$APP/Frameworks"
   rabin2 -i "$BIN" | grep -E 'SecTrustEvaluate|SecTrustCopyCertificateChain|SecTrustGetCertificateAtIndex|SecCertificateCopyKey|SecKeyCopyExternalRepresentation|SecCertificateCopyData|CC_SHA256|SecTrustSetAnchorCertificates'
   rabin2 -zz "$BIN" | grep -E 'didReceiveChallenge|TSKPinningValidator|ServerTrustManager|PublicKeysTrustEvaluator|PinnedCertificatesTrustEvaluator|DisabledTrustEvaluator|AFSecurityPolicy'
   rabin2 -zz "$BIN" | grep -oE '[A-Za-z0-9+/]{43}=' | sort -u
   plutil -convert json -o - "$APP/Info.plist" | jq '.TSKConfiguration'
   find "$APP" -iname '*.cer' -o -iname '*.der' -o -iname '*.crt' -o -iname '*.pem'
   ```

2. **Delegate review.** In the disassembly of each `urlSession:didReceiveChallenge:completionHandler:` (and `webView:didReceiveAuthenticationChallenge:completionHandler:`), follow the paths to the completion handler. Every path that passes `.useCredential` (disposition 0) must be preceded by a successful `SecTrustEvaluateWithError` and a successful pin comparison; every mismatch path must pass `.cancelAuthenticationChallenge` (disposition 2).

3. **Hash computation.** Check whether the code hashes `SecKeyCopyExternalRepresentation` output directly (no ASN.1 header: pins will never match an `openssl` SPKI pin, so either the app compares something else, or the pins were derived the same wrong way, which still works but is worth noting) or hashes whole certificates (`SecCertificateCopyData`: certificate pinning, breaks at renewal).

4. **Library configuration.** TrustKit: `kTSKEnforcePinning`, `kTSKIncludeSubdomains`, `kTSKExpirationDate`, swizzling on or off. Alamofire: hosts in the `evaluators` map, `allHostsMustBeEvaluated`, any `DisabledTrustEvaluator`. AFNetworking: pinning mode, `allowInvalidCertificates`, `validatesDomainName`.

5. **Coverage.** Which `URLSession` instances use the pinning delegate? `URLSession.shared` has no delegate, so requests made through it get only ATS (and `NSPinnedDomains` if configured).

#### Observation

The mechanisms found, configuration values, code paths in the trust delegate, the hosts each mechanism covers and the pin-to-certificate mapping.

#### Evaluation

**Fail** if a first-party host is reached without any pinning; if the delegate accepts on mismatch or never cancels; if TrustKit enforcement is off or expired; if Alamofire lets the host fall through. A delegate that skips `SecTrustEvaluateWithError` entirely is rated under MASWE-0027.

#### Demo

```swift
// Pins checked, but the mismatch path still accepts the connection
if pinnedHashes.contains(hash) {
    completionHandler(.useCredential, URLCredential(trust: trust))
} else {
    os_log("pin mismatch for %{public}@", challenge.protectionSpace.host)
    completionHandler(.performDefaultHandling, nil)   // falls back to system trust: pinning is decorative
}
```

`.performDefaultHandling` on mismatch hands the decision back to the system, which accepts any trusted CA, including a proxy CA installed by the user. Under GT-0028-3 the host is decrypted and the console shows "pin mismatch" for each request. Fail; the mismatch branch must call `.cancelAuthenticationChallenge`.

### GT-0028-3: Runtime pinning check (iOS)

#### Overview

The iOS equivalent of MASTG-TEST-0244, which OWASP's v2 set does not yet have for iOS. It is implementation-agnostic and the quickest way to see whether ATS pins, delegates and libraries actually hold.

#### Prerequisites

An iOS device with your proxy's CA profile installed **and** enabled under Settings > General > About > Certificate Trust Settings (installing the profile alone does not make the CA trusted for TLS). Proxy configured on the Wi-Fi network ([MASTG-TECH-0063](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0063/)), or transparent redirection for apps that ignore the proxy. A capture on the Mac via a remote virtual interface (`rvictl -s <UDID>`, then `tshark -i rvi0`) for the SNI list. Optionally `idevicesyslog` or Console.app to read the device log.

#### Steps

1. Confirm the setup with Safari against a first-party web page: it must load through the proxy without warnings.
2. Start the proxy and capture; launch the app and exercise every feature, including extensions (share, notification service) and web content.
3. List decrypted hosts, failed handshakes and the SNI list as in MASTG-TEST-0244. In the device log, look for messages from the app's process mentioning trust or pinning failures and `NSURLErrorDomain` errors.

#### Observation

Decrypted first-party hosts, hosts with failed handshakes, SNI list, log lines, iOS version.

#### Evaluation

**Fail** if any relevant first-party host is decrypted. Treat handshake failures with the same caution as on Android (mutual TLS, QUIC, non-URLSession stacks with their own trust store). A Flutter app will typically show *no* traffic at all through the proxy; that is not pinning, it is a proxy-unaware client ([Flutter apps](#flutter-apps)).

#### Demo

```text
$ mitmdump -nr ios-session.mitm --set flow_detail=1 | grep -oE 'https://[^/ ]+' | sort | uniq -c
   9 https://api.example.com
   2 https://media.example.com
```

The developers believed `api.example.com` was pinned, yet it is decrypted. The deployment target is iOS 15 and the test device runs iOS 17, so the version floor is not the cause. The plist entry is `example.com` with `NSIncludesSubdomains` absent (default `NO`), so it only applies to the bare domain. Fail, with a one-line fix.

### GT-0028-4: Dynamic pin delivery and pin-failure handling (both platforms)

#### Overview

Some apps download pins, or a "pinning enabled" flag, at run time; and every app with pinning has some behaviour when pins fail. Both can undo the control.

#### Prerequisites

The interception setup with a working bypass (so you can see and modify the configuration traffic), jadx or a disassembler.

#### Steps

1. Look for pin material or pinning flags in remote configuration: search the code for `pin`, `pinning`, `certificatePinner`, `ssl` near remote-config clients (Firebase Remote Config, an app config endpoint) and capture the configuration responses.
2. With the bypass active, modify the response: replace the pin values with your proxy CA's SPKI hash, or set the pinning flag off. Remove the bypass, restart the app, and see whether the proxy can now decrypt first-party traffic.
3. Check whether the payload is signed (a signature field, a JWS, a detached signature header) and whether a modified payload is rejected.
4. Check the failure path: when a pin fails, does the app retry on an unpinned client, fall back to HTTP, or show an error? Look for `catch (SSLPeerUnverifiedException ...)` blocks that rebuild the client.

#### Observation

The configuration source, its transport, any signature, the effect of tampering, and the failure-handling behaviour.

#### Evaluation

**Fail** if an attacker who can intercept the configuration fetch (or the first fetch) can install pins of their choosing or switch pinning off, or if a pin failure triggers a fallback that completes the request without pins.

#### Demo

```json
{ "net": { "pinning_enabled": false, "pins": [] } }
```

Served from `https://config.example.com/v2/app` over an unpinned connection, unsigned, and honoured on the next launch: `CertificatePinner` is built only if `pinning_enabled` is `true`. An attacker who can intercept one config fetch disables pinning for the life of the install. Fail.

## Bypassing pinning during an assessment

You will bypass pinning on almost every mobile engagement, because you cannot test the API, the session handling or most of MASVS-NETWORK, AUTH and STORAGE without seeing the traffic. This section is based on OWASP's [MASTG-TECH-0012](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0012/) (Android) and [MASTG-TECH-0064](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0064/) (iOS), plus the framework-specific techniques [MASTG-TECH-0109](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0109/), [MASTG-TECH-0110](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0110/) and [MASTG-TECH-0125](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0125/). The goal is visibility: get the app talking through your proxy with as little disturbance as possible, then test what you see.

### Why a bypass on your own device is not a finding

Pinning defends the user against a **network** attacker who holds a trusted certificate. It does not, and cannot, defend an app against the person who controls the device it runs on: that person can attach a debugger, hook the TLS stack, patch the binary or change the configuration, and every one of those steps is outside the threat pinning addresses. So:

- "Pinning was bypassed with objection/Frida on a rooted test device" is **not** a vulnerability, and it does not belong in the findings list. At most it is a line in the methodology section ("pinning was present on hosts X, Y and was bypassed for testing using Z").
- A bypass becomes relevant only if it needs no control of the victim's device: an expired pin-set, an unpinned host, `overridePins` on user CAs, a downloadable pin list an attacker can rewrite. Those are the findings in this note, and you prove them *without* a bypass.
- If the client wants the app to resist instrumentation and repackaging, that is a MASVS-RESILIENCE requirement (root/jailbreak detection, hooking detection, integrity checks), tested and rated there. How long the bypass took can be useful input to that discussion; it is not a pinning result.

Record which method worked; the developers will want to reproduce your traffic captures, and it documents that the observed pinning was real.

### Android: objection and Frida

**objection** ([MASTG-TOOL-0038](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0038/)) is the fastest first attempt. On a rooted device with `frida-server` running:

```bash
frida-ps -Uai | grep -i example          # find the package identifier
objection -g com.example.app explore     # attach (or spawn) and open the REPL
# inside the REPL:
android sslpinning disable
# or apply it at start-up so hooks are in place before the first request:
objection -g com.example.app explore --startup-command "android sslpinning disable"
```

objection's Android pinning module replaces the checks most apps rely on: it supplies an empty `X509TrustManager` when the app calls `SSLContext.init`, neuters OkHttp 3's `CertificatePinner.check`, TrustKit's `OkHostnameVerifier` and `PinningTrustManager`, the Appcelerator pinning trust manager, and Conscrypt's `TrustManagerImpl` verification methods (`verifyChain` and `checkTrustedRecursive` on Android 7+), which is where NSC pins are enforced for the platform stack. Each hook prints a line when it fires, so the output tells you which mechanism the app actually used. On a non-rooted device, patch the APK with the Frida Gadget first (`objection patchapk --source app.apk`, see [MASTG-TECH-0004](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0004/)).

**Frida universal scripts** cover more cases than objection, as OWASP notes. [frida-multiple-unpinning](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0140/) from Frida CodeShare ([MASTG-TOOL-0032](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0032/)):

```bash
frida -U -f com.example.app --codeshare akabe1/frida-multiple-unpinning
```

It hooks the same core points (`SSLContext.init` with a permissive trust manager, Conscrypt `TrustManagerImpl`, OkHttp `CertificatePinner.check` and the Kotlin-mangled `check$okhttp` used by OkHttp 4), plus a long tail: TrustKit, Apache `AbstractVerifier`, `WebViewClient.onReceivedSslError` (calls `proceed()`), the NSC's `NetworkSecurityTrustManager`, Conscrypt `CertPinManager`, Netty, PhoneGap, IBM Worklight, Appmattus CT checks and more. Its most useful trick is dynamic: it hooks the constructor of `SSLPeerUnverifiedException`, walks the stack to the method that threw it, and patches that method to return early, which defeats custom pinners it has never seen.

HTTP Toolkit's [frida-interception-and-unpinning](https://github.com/httptoolkit/frida-interception-and-unpinning) collection is a good alternative: you set your proxy address and CA certificate in its `config.js`, and its Android scripts inject the CA into the system trust store at run time, force the app's traffic to the proxy, and unpin the common libraries plus a fallback for unknown ones. That saves you installing a system CA on Android 14+, where the APEX-based store makes it awkward.

On rooted devices with LSPosed ([MASTG-TOOL-0149](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0149/)), Xposed modules such as TrustMeAlready or SSLUnpinning ([MASTG-TOOL-0025](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0025/)) do the same system-wide, useful for apps with Frida detection.

Frida 17 removed the Java and ObjC bridges from the scripting runtime for scripts loaded through the API; the `frida` CLI and the REPL still provide them, so the commands above work, but if you package your own agent with `frida-compile`, import `frida-java-bridge` explicitly.

### Android: repackaging with a modified NSC

When the app detects Frida or you want a stable, hook-free build for a long test, change the configuration instead of the code.

**By hand** (decode, replace the NSC, rebuild, sign):

```bash
apktool d -f app.apk -o app_src
grep -o 'android:networkSecurityConfig="[^"]*"' app_src/AndroidManifest.xml   # add the attribute if absent
```

Replace (or create) `app_src/res/xml/network_security_config.xml`, dropping every `<pin-set>` and trusting user CAs:

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config>
        <trust-anchors>
            <certificates src="system"/>
            <certificates src="user" overridePins="true"/>
        </trust-anchors>
    </base-config>
</network-security-config>
```

```bash
apktool b app_src -o app-mod.apk
zipalign -p -f 4 app-mod.apk app-mod-aligned.apk
apksigner sign --ks ~/.android/debug.keystore --ks-pass pass:android --out app-mod-signed.apk app-mod-aligned.apk
adb uninstall com.example.app
adb install app-mod-signed.apk
```

For app bundles, sign every split with the same key and install them together with `adb install-multiple`. Removing the pin-sets only defeats NSC pinning; OkHttp or TrustKit pins in code still apply, so combine with a Frida hook or patch the code too.

**apk-mitm** automates the same idea: `npx apk-mitm app.apk` decodes the app, rewrites the NSC to trust user CAs, patches out common pinning code in smali, and re-signs it as `app-patched.apk`. It also accepts `.xapk`/`.apks` bundles. **uber-apk-signer** ([MASTG-TOOL-0103](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0103/)) is a convenient one-step align-and-sign alternative.

**Static pin replacement** (MASTG-TECH-0012) works when the pinning is in code: find the hashes (`grep -ri "sha256" app_src/smali*`) and replace them with your proxy CA's SPKI hash, or change the pinned host string to a non-existent name so the real host is no longer matched (useful against obfuscated OkHttp). Bundled certificates (`.cer`, `.crt`, also files without extension in `res/raw` and `assets`) can be replaced with your CA; a BKS truststore can have your CA added with `keytool -importcert ... -storetype BKS -provider org.bouncycastle.jce.provider.BouncyCastleProvider -providerpath bcprov.jar -storepass <password from the code>`.

Re-signing has side effects you should expect and not report: Google Sign-In, Firebase App Check, Play Integrity and any app-side signature check will notice the new signing key. If the app refuses to run after repackaging, you are looking at a RESILIENCE control, not a pinning one.

### iOS: objection, Frida and SSL Kill Switch

On a jailbroken device with `frida-server` (or a re-signed IPA with the Frida Gadget, [MASTG-TECH-0090](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0090/)):

```bash
frida-ps -Uai | grep -i example
objection -g com.example.app explore --startup-command "ios sslpinning disable"
```

objection's iOS module hooks several layers at once: the Secure Transport functions used by older stacks (`SSLHandshake`, `SSLSetSessionOption`, `SSLCreateContext`), the BoringSSL-based verification used by `URLSession` and Network framework on current iOS (including the custom-verify callback setter in `libboringssl`), the `NSURLSession` challenge delegate methods, AFNetworking's `AFSecurityPolicy`, and TrustKit's validator. As on Android, watch which hooks fire.

**SSL Kill Switch 3** ([MASTG-TOOL-0066](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0066/), the maintained successor of SSL Kill Switch 2 mentioned in the technique) is a jailbreak tweak that disables certificate validation, and therefore pinning, for apps using the system TLS stack, without attaching anything per app. It is the easiest way through apps that detect Frida, provided they do not also detect the jailbreak.

Writing your own hook is straightforward when you know the mechanism. For example, forcing the system evaluation to succeed:

```javascript
const sec = Process.getModuleByName('Security');
const evalWithError = sec.getExportByName('SecTrustEvaluateWithError');
Interceptor.replace(evalWithError, new NativeCallback(function (trust, errorOut) {
  if (!errorOut.isNull()) errorOut.writePointer(NULL);
  return 1;
}, 'bool', ['pointer', 'pointer']));
```

This alone does not defeat an app that compares hashes after evaluation (its own comparison still fails), nor ATS `NSPinnedDomains`, which is enforced inside the URL Loading System. For the former, hook the delegate method or the comparison function; for the latter, the deterministic route is to remove `NSPinnedDomains` from `Info.plist` and re-sign the app ([MASTG-TECH-0092](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0092/)), or rely on a tool that disables verification at the BoringSSL layer.

If the app uses mutual TLS, a bypass gets you nothing until you also extract the client certificate and its password (often in the bundle or Keychain) and load it into the proxy, as the legacy iOS test described.

### Flutter apps

Flutter breaks the usual setup twice over ([MASTG-TECH-0109](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0109/), [MASTG-TECH-0110](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0110/)): Dart's `HttpClient` **ignores the system proxy**, and its TLS is **BoringSSL compiled into the engine** (`libflutter.so`, `Flutter.framework`), so neither user CAs, the NSC nor objection's Java/ObjC hooks touch it. Recognise it first:

```bash
unzip -l app.apk | grep -E 'libflutter\.so|libapp\.so'
ls ipa/Payload/*.app/Frameworks | grep -i flutter
```

You need to solve both problems:

1. **Route the traffic.** Use transparent interception: `iptables` NAT rules on a rooted device (`iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination 192.168.56.1:8080`), ProxyDroid ([MASTG-TOOL-0120](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0120/)), a VPN-based redirector, or a Wi-Fi hotspot/OpenVPN setup for iOS. Enable invisible (transparent) proxying in Burp or run mitmproxy in transparent mode.
2. **Disable verification.** NVISO's [disable-flutter-tls-verification](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0101/) script pattern-matches BoringSSL's `ssl_verify_peer_cert` inside the Flutter engine and forces it to succeed (`frida -U -f com.example.app -l disable-flutter-tls.js`). Alternatively [reFlutter](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0100/) replaces the engine with a patched build that sends traffic to a proxy IP you choose and skips verification; repackage and re-sign the result (`reflutter app.apk`, then sign with uber-apk-signer).

Disabling `ssl_verify_peer_cert` also defeats Dart-level trust-store pinning (`SecurityContext(withTrustedRoots: false)`), because that is enforced in the same verification. Pinning implemented in Dart *after* the handshake (comparing `response.certificate` hashes in app code) is not; you need to find that function in `libapp.so` (Blutter or reFlutter's offset dump help) and hook it.

### Xamarin apps

Xamarin (end of support since May 2024, still common in the field) apps using the managed `HttpClientHandler` do not follow the device proxy ([MASTG-TECH-0125](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0125/)). The options are: patch the app so `WebRequest.DefaultWebProxy` points at your proxy (IL edit with dnSpy, or hook the property with Frida); get a network MITM position with bettercap ([MASTG-TOOL-0076](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0076/)) ARP spoofing and redirect port 443 to the proxy (`pfctl` on macOS, `iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination 127.0.0.1:8080` on Linux); or spoof DNS (an `/etc/hosts` entry on a rooted device). In each case enable invisible proxying and set the listener to redirect to the original host and port with "Force use of TLS".

Pinning in Xamarin lives in the `ServerCertificateValidationCallback`. Decompile the assemblies from `assemblies/` with ILSpy or dnSpy (newer builds pack them into `assemblies.blob` or compress them, which `pyxamstore` can unpack), patch the callback to `return true`, and repack, or hook it at run time.

### When the universal scripts fail

When no off-the-shelf hook works, find the check that fails and hook that.

1. **Find the throw site.** Log the stack every time a TLS or pinning exception is created; the frame below the constructor is the pinning code:

   ```javascript
   Java.perform(function () {
     const Log = Java.use('android.util.Log');
     const Throwable = Java.use('java.lang.Throwable');
     ['javax.net.ssl.SSLPeerUnverifiedException', 'java.security.cert.CertificateException'].forEach(function (name) {
       const Ex = Java.use(name);
       Ex.$init.overload('java.lang.String').implementation = function (msg) {
         console.log('[!] ' + name + ': ' + msg);
         console.log(Log.getStackTraceString(Throwable.$new()));
         return this.$init(msg);
       };
     });
   });
   ```

2. **Obfuscated OkHttp.** Find the pinner by its strings (`Certificate pinning failure!`, `sha256/`) or, as OWASP suggests, by signature: `CertificatePinner.Builder.add(String, String...)` returns the builder, so `grep -ri 'Ljava/lang/String;\[Ljava/lang/String;)L' app_src/smali*` lists candidates. Hook each, print the arguments, and either swap in your own hash or make the `check` method return.

3. **Native pinning.** Look for TLS library symbols in the app's own `.so` files (`SSL_CTX_set_verify`, `SSL_CTX_set_custom_verify`, `X509_verify_cert`, `mbedtls_x509_crt_verify`) and hook the verify callback or the comparison (`memcmp` against a 32-byte hash is a common tell). On iOS, the same applies to bundled OpenSSL and to Network framework's `sec_protocol_options_set_verify_block`.

4. **Configuration first.** Before writing hooks, check whether the pins come from somewhere you can change: a remote config ([GT-0028-4](#gt-0028-4-dynamic-pin-delivery-and-pin-failure-handling-both-platforms)), a file in the app's data directory, a debug menu.

## Secure implementation

OWASP has no Best Practice entry for MASWE-0028 yet ([MASTG-BEST-0073](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0073/) covers trust evaluation in iOS delegates and is discussed in the MASWE-0027 note). These are the patterns we recommend.

**Android: NSC first.** Pin each first-party registrable domain with subdomains, two or more pins of which at least one is a backup, and an expiry policy that is a conscious decision:

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system"/>
        </trust-anchors>
    </base-config>
    <domain-config>
        <domain includeSubdomains="true">example.com</domain>
        <pin-set expiration="2028-06-30">
            <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin> <!-- current issuing CA -->
            <pin digest="SHA-256">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin> <!-- second CA (backup) -->
            <pin digest="SHA-256">CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=</pin> <!-- offline spare leaf key -->
        </pin-set>
    </domain-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="user"/>
        </trust-anchors>
    </debug-overrides>
</network-security-config>
```

The expiry trade-off is real: an expiration date makes abandoned installs fall back to normal validation instead of breaking; no expiration means a pinned app keeps enforcing (and possibly breaking) forever. If you set one, track it like a certificate expiry and ship new pins with a new date well before it. Keep user CAs out of release configurations; the `<debug-overrides>` block gives developers and testers a proxy-friendly debug build.

**OkHttp.** Build one base client with the `CertificatePinner` and derive every other client from it with `newBuilder()`, so new features inherit the pins. Use `**.example.com` deliberately, not by habit. Keep OkHttp current.

**iOS: `NSPinnedDomains`.** Pin CA identities (Apple's recommendation) with a backup for each domain, `NSIncludesSubdomains` where appropriate, repeat the entries in every extension that talks to your hosts, and raise the deployment target to iOS 14 or accept that older devices are unpinned. Do not implement a trust delegate just to pin; if you must, follow the structure in the [SecTrust section](#ios-server-trust-evaluation-and-pinning-mastg-know-0072): evaluate, then compare SPKI hashes of the evaluated chain (with the ASN.1 header), then `.cancelAuthenticationChallenge` on any mismatch.

**Frameworks.** Flutter: trust-store pinning with `SecurityContext(withTrustedRoots: false)` and your CA, or a maintained pinning package, applied to every client including `dio` instances. React Native: NSC and `NSPinnedDomains` already apply to `fetch`; add a library only for older OS versions or reporting.

**Operations.**

- Keep an inventory: host, pinned keys, what each key is (leaf, intermediate, root, backup), where the backup private key is stored.
- Add a release check that derives the live chain's SPKI hashes with the `openssl` pipeline and fails the build if a host's live chain matches none of the shipped pins.
- Coordinate certificate and CA changes with app releases: the new key's pin must be in the field (in an app version most users have) *before* the server changes.
- Collect pin-failure reports (TrustKit's report URI, or your own telemetry); a spike means either an attack or an operational mistake, and you want to know which.
- If you deliver pins dynamically, sign them, version them, and never let remote configuration turn pinning off.

## Rating findings

Rate on three things: **what the pinning gap protects** (credentials and tokens, sensitive personal or financial data, or merely public content), **what the attacker needs** (a certificate trusted by the device — via a compromised or mis-issuing CA, an MDM-installed inspection root, a user-installed CA, or malware with root — versus nothing more than a network position), and **the app's requirement profile** (whether MASVS-NETWORK-2 is in scope: L2, high-risk, EUDIW). Without a trusted certificate, a network attacker gets nothing from a missing pin; with correct validation in place, missing pinning is defence in depth.

| Rating | Conditions |
|---|---|
| **Critical** | Not used for pinning issues on their own. If the "pinning" code breaks certificate validation so that any network attacker can intercept, rate it as MASWE-0027 (typically High or Critical depending on data). |
| **High** | Pinning logic that makes interception *easier* than having no pinning: a check that compares names rather than keys combined with skipped chain validation, or a delegate that accepts any certificate when the pin fails and also bypasses system evaluation. Also: a dynamic pin or kill-switch mechanism that a network attacker without any trusted certificate can use to install their own pins and disable validation. Usually overlaps MASWE-0027. |
| **Medium** | An L2/high-risk app (banking, payments, health, identity wallet) where pinning is required and is missing or ineffective for first-party hosts that carry credentials or sensitive data: no pinning; an expired NSC pin-set; `overridePins="true"` on user CAs in release; pins on a public root shared by a large ecosystem with nothing narrower; a second unpinned client carrying the same tokens; TrustKit in report-only mode; a fail-open mismatch path; unsigned dynamic pins fetched over an unpinned channel. |
| **Low** | Missing pinning for sensitive first-party hosts in an L1 app (or where the client has not adopted MASVS-NETWORK-2), stated as a hardening recommendation (Info if those hosts carry nothing sensitive); ineffective pins for first-party hosts carrying only low-sensitivity data; `NSPinnedDomains` absent on supported iOS 13 devices or NSC absent below API 24; **no backup pin** or pins that match nothing live (an availability risk: one certificate or CA change takes the app offline, and the outage pressure usually ends with pinning removed); pin-sets that expire within the app's support window. |
| **Info** | Pinning bypassed on the tester's own rooted or jailbroken device; third-party hosts not pinned; correct pinning with observations (leaf-only pins with a documented backup, a single CA pin across many hosts); pins confirmed to work. |

Raise one level when the app's documented threat model or regulator explicitly requires pinning against interception by enterprise or state-level CAs, or when the gap covers the authentication host and tokens are long-lived. Lower one level when the affected host is reached only before login and carries nothing sensitive. In the report, state the attacker position explicitly ("an attacker who can obtain a certificate trusted by the device, for example through a CA installed by a device management profile"), list the hosts affected and the hosts correctly pinned, include the configuration excerpt or code reference, the capture showing decrypted first-party traffic *without any bypass*, the device OS version and how the test CA was installed, and the fix.

## References

- OWASP MASWE — [MASWE-0028: Insecure Identity Pinning](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0028/) (CC BY-SA 4.0)
- OWASP MASVS — [MASVS-NETWORK-2](https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-2/) (CC BY-SA 4.0)
- OWASP MASTG — knowledge [MASTG-KNOW-0015: Certificate Pinning (Android)](https://mas.owasp.org/MASTG/knowledge/android/MASVS-NETWORK/MASTG-KNOW-0015/), [MASTG-KNOW-0072: Server Trust Evaluation (iOS)](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-NETWORK/MASTG-KNOW-0072/), [MASTG-KNOW-0014: Android Network Security Configuration](https://mas.owasp.org/MASTG/knowledge/android/MASVS-NETWORK/MASTG-KNOW-0014/), [MASTG-KNOW-0071: iOS App Transport Security](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-NETWORK/MASTG-KNOW-0071/) (CC BY-SA 4.0)
- OWASP MASTG — tests [MASTG-TEST-0242](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0242/), [MASTG-TEST-0243](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0243/), [MASTG-TEST-0244](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0244/), [MASTG-TEST-0385](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0385/); legacy (MASTG v1) tests [MASTG-TEST-0022](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0022/), [MASTG-TEST-0068](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0068/) (CC BY-SA 4.0)
- OWASP MASTG — demo [MASTG-DEMO-0148](https://mas.owasp.org/MASTG/demos/ios/MASVS-NETWORK/MASTG-DEMO-0148/MASTG-DEMO-0148/); best practice [MASTG-BEST-0073](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0073/) (CC BY-SA 4.0)
- OWASP MASTG — techniques [MASTG-TECH-0012](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0012/), [MASTG-TECH-0064](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0064/), [MASTG-TECH-0109](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0109/), [MASTG-TECH-0110](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0110/), [MASTG-TECH-0125](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0125/), [MASTG-TECH-0004](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0004/), [MASTG-TECH-0005](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/), [MASTG-TECH-0009](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0009/), [MASTG-TECH-0011](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0011/), [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0022](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0022/), [MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/), [MASTG-TECH-0117](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/), [MASTG-TECH-0150](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0150/), [MASTG-TECH-0151](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0151/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0063](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0063/), [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/), [MASTG-TECH-0090](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0090/), [MASTG-TECH-0092](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0092/), [MASTG-TECH-0138](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0138/), [MASTG-TECH-0071](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0071/) (CC BY-SA 4.0)
- OWASP MASTG — tools [objection (MASTG-TOOL-0038)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0038/), [Frida (MASTG-TOOL-0031)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/), [Frida CodeShare (MASTG-TOOL-0032)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0032/), [frida-multiple-unpinning (MASTG-TOOL-0140)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0140/), [SSLUnpinning (MASTG-TOOL-0025)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0025/), [LSPosed (MASTG-TOOL-0149)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0149/), [SSL Kill Switch 3 (MASTG-TOOL-0066)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0066/), [reFlutter (MASTG-TOOL-0100)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0100/), [disable-flutter-tls-verification (MASTG-TOOL-0101)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0101/), [uber-apk-signer (MASTG-TOOL-0103)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0103/), [ProxyDroid (MASTG-TOOL-0120)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0120/), [Apktool (MASTG-TOOL-0011)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/), [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [rabin2 (MASTG-TOOL-0129)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/), [PlistBuddy (MASTG-TOOL-0135)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0135/), [Burp Suite (MASTG-TOOL-0077)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0077/), [mitmproxy (MASTG-TOOL-0097)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0097/), [bettercap (MASTG-TOOL-0076)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0076/) (CC BY-SA 4.0)
- OWASP — [Pinning Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Pinning_Cheat_Sheet.html)
- [Android Developers — Network security configuration: certificate pinning, `pin-set`, `overridePins`, debug overrides](https://developer.android.com/privacy-and-security/security-config); [Security with network protocols](https://developer.android.com/privacy-and-security/security-ssl); [Unsafe hostname verification](https://developer.android.com/privacy-and-security/risks/unsafe-hostname)
- [Apple — Identity Pinning: How to configure server certificates for your app](https://developer.apple.com/news/?id=g9ejcf8y); [`NSPinnedDomains`](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity/nspinneddomains); [Performing manual server trust authentication](https://developer.apple.com/documentation/foundation/url_loading_system/handling_an_authentication_challenge/performing_manual_server_trust_authentication); [`SecTrustEvaluateWithError`](https://developer.apple.com/documentation/security/sectrustevaluatewitherror%28_:_:%29); [`SecTrustCopyCertificateChain`](https://developer.apple.com/documentation/security/sectrustcopycertificatechain%28_:%29)
- [OkHttp — `CertificatePinner`](https://lysine.dev/okhttp/5.x/okhttp/okhttp3/-certificate-pinner/) and [HTTPS](https://lysine.dev/okhttp/features/https/); [CVE-2016-2402](https://nvd.nist.gov/vuln/detail/CVE-2016-2402)
- [TrustKit (iOS)](https://github.com/datatheorem/TrustKit), [TrustKit-Android](https://github.com/datatheorem/TrustKit-Android), [Alamofire — Security](https://github.com/Alamofire/Alamofire/blob/master/Documentation/AdvancedUsage.md#security)
- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) (SubjectPublicKeyInfo), [RFC 7469](https://www.rfc-editor.org/rfc/rfc7469) (HTTP Public Key Pinning, historical: pin format and backup-pin rationale)
- [objection](https://github.com/sensepost/objection) (`android sslpinning disable`, `ios sslpinning disable`), [frida-multiple-unpinning](https://codeshare.frida.re/@akabe1/frida-multiple-unpinning/), [HTTP Toolkit frida-interception-and-unpinning](https://github.com/httptoolkit/frida-interception-and-unpinning), [apk-mitm](https://github.com/niklashigi/apk-mitm), [NVISO — Intercepting Flutter traffic](https://blog.nviso.eu/2022/08/18/intercept-flutter-traffic-on-ios-and-android-http-https-dio-pinning/), [NVISO — Circumventing SSL pinning in obfuscated apps with OkHttp](https://blog.nviso.eu/2019/04/02/circumventing-ssl-pinning-in-obfuscated-apps-with-okhttp/)
- CWE: [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
