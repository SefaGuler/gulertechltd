---
title: "MASVS-NETWORK: Testing Network Communication in Android and iOS Apps"
date: 2026-11-09 16:06:00 +0000
subcategory: network
summary: "Hub for the MASVS-NETWORK series: three MASWE weaknesses, all 29 OWASP tests, legacy mapping, attacker positions, a test plan and a cheat sheet."
refs: [MASVS-NETWORK-1, MASVS-NETWORK-2, MASWE-0026, MASWE-0027, MASWE-0028]
tags: [android, ios, masvs-network, tls, methodology]
---

This is the entry point to our series on **OWASP MASVS-NETWORK**. The control group has two requirements:

- **MASVS-NETWORK-1:** "The app secures all network traffic according to the current best practices."
- **MASVS-NETWORK-2:** "The app performs identity pinning for all remote endpoints under the developer's control."

The series follows the [MASWE](https://mas.owasp.org/MASWE/) catalogue: one note per weakness, each with its **Knowledge** and **Tests**. MASWE-0026 has sixteen tests, so we split it into two notes. A lab note covers interception. This page maps the area, lists every OWASP test with a link to the section that covers it, explains what each attacker position can and cannot prove, and collects the commands you will use on every network review.

## Contents

- [What MASVS-NETWORK covers](#what-masvs-network-covers)
- [The series](#the-series)
- [Test matrix](#test-matrix)
- [Legacy v1 tests and their replacements](#legacy-v1-tests-and-their-replacements)
- [What each attacker position can prove](#what-each-attacker-position-can-prove)
- [Test plan](#test-plan)
- [Rating overview](#rating-overview)
- [Command cheat sheet](#command-cheat-sheet)
- [Related weaknesses in other categories](#related-weaknesses-in-other-categories)
- [Other series hubs](#other-series-hubs)
- [References](#references)

## What MASVS-NETWORK covers

TLS protects a connection only when three things are true:

1. the connection is encrypted at all;
2. it uses a protocol version and cipher suite that still count as strong;
3. the client checks that the certificate chains to a trusted root and was issued for the host it meant to reach.

Both platforms do all three by default for their high-level stacks. NETWORK-1 findings are almost always about apps that **opt out** of those defaults, or that **route around** them:

- **Opting out:** a Network Security Configuration or `usesCleartextTraffic` switch, an App Transport Security exception, a trust-all `X509TrustManager`, a `URLSessionDelegate` that accepts any server trust.
- **Routing around:** raw sockets, Network.framework, a TLS library compiled into native code, or a cross-platform runtime with its own stack.

**NETWORK-1** has three weaknesses:

- **MASWE-0026 (Network Traffic Not Encrypted):** cleartext HTTP and other plaintext protocols, and TLS 1.0/1.1 or weak cipher suites. OWASP files both under one weakness; we split it into [cleartext traffic](/mobile/maswe-0026-cleartext-network-traffic/) and [insecure TLS protocol versions](/mobile/maswe-0026-insecure-tls-protocol-versions/).
- **MASWE-0027 (Insecure Certificate Validation):** chain validation, hostname verification, WebView SSL errors, user-installed CAs and the GMS security provider.
- **Related weaknesses from other groups:** two weaknesses also map to NETWORK-1. See [Related weaknesses](#related-weaknesses-in-other-categories).

**NETWORK-2** has one weakness, **MASWE-0028 (Insecure Identity Pinning)**. Pinning narrows "any CA the device trusts" to "keys the operator chose". It matters only once the attacker holds a certificate the device already accepts: a mis-issuing CA, an MDM inspection root, or a user-installed profile.

**Profiles.** MASWE-0026 and MASWE-0027 are tagged **L1, L2 and EUDIW**. They are the baseline for every app, and a failure is a failure whatever the app does. MASWE-0028 is tagged **L2 and EUDIW** only. Pinning is expected of banking, payments, health, identity and EU Digital Identity Wallet apps. For an L1 app, missing pinning is a hardening recommendation, not a failed requirement. Our [rating overview](#rating-overview) reflects that.

**What is out of scope.** Bypassing pinning on a device you control is not a NETWORK finding (see [why](/mobile/maswe-0028-insecure-identity-pinning/#why-a-bypass-on-your-own-device-is-not-a-finding)). Resistance to instrumentation and payload-level protection belong to MASVS-RESILIENCE. Weak server configuration on its own (a backend that accepts TLS 1.0, which the app never offers) is a backend finding: report it to the infrastructure owner, not as an app vulnerability.

## The series

| Note | Weakness | Controls | Profiles | OWASP tests | Our supplementary checks |
|------|----------|----------|----------|-------------|--------------------------|
| [Intercepting Mobile App Traffic: Lab Setup and Techniques](/mobile/mobile-traffic-interception-lab/) | — (techniques) | NETWORK-1, NETWORK-2 | — | — | Interception positions, CA installation (incl. Android 14), non-proxy-aware apps |
| [Cleartext Traffic (MASWE-0026, Part 1)](/mobile/maswe-0026-cleartext-network-traffic/) | MASWE-0026 | NETWORK-1 | L1, L2, EUDIW | 9 (3 placeholders) | GT-0026-1 to GT-0026-3 |
| [Insecure TLS Protocol Versions (MASWE-0026, Part 2)](/mobile/maswe-0026-insecure-tls-protocol-versions/) | MASWE-0026 | NETWORK-1 | L1, L2, EUDIW | 7 | GT-0026-TLS-1 to GT-0026-TLS-3 |
| [Insecure Certificate Validation](/mobile/maswe-0027-insecure-certificate-validation/) | MASWE-0027 | NETWORK-1 | L1, L2, EUDIW | 9 | GT-0027-1, GT-0027-2 |
| [Insecure Identity Pinning](/mobile/maswe-0028-insecure-identity-pinning/) | MASWE-0028 | NETWORK-2 | L2, EUDIW | 4 | GT-0028-1 to GT-0028-4 |

The Knowledge items are spread across the notes. The full explanation of Android's Network Security Configuration ([MASTG-KNOW-0014](/mobile/maswe-0026-cleartext-network-traffic/#android-network-security-configuration-mastg-know-0014)) and iOS App Transport Security ([MASTG-KNOW-0071](/mobile/maswe-0026-cleartext-network-traffic/#ios-app-transport-security-mastg-know-0071)) lives in the cleartext note, and the others refer back to it. Server trust evaluation (MASTG-KNOW-0072) is covered twice: [for validation](/mobile/maswe-0027-insecure-certificate-validation/#ios-server-trust-evaluation-mastg-know-0072) and [for pinning](/mobile/maswe-0028-insecure-identity-pinning/#ios-server-trust-evaluation-and-pinning-mastg-know-0072). The Android pinning mechanisms are in [MASTG-KNOW-0015](/mobile/maswe-0028-insecure-identity-pinning/#android-certificate-pinning-mastg-know-0015), and the security provider is in [MASTG-KNOW-0011](/mobile/maswe-0027-insecure-certificate-validation/#android-security-provider-mastg-know-0011).

## Test matrix

All 29 OWASP v2 tests linked to the three weaknesses. The **Type** column gives OWASP's own classification. Three Android cleartext tests are `status: placeholder` on OWASP. For those, the note gives our own procedure, labelled Guler Tech methodology.

| ID | Title (links to our section) | Platform | Type |
|----|------------------------------|----------|------|
| **MASWE-0026, Part 1: cleartext** | | | |
| [MASTG-TEST-0233](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0233/) | [Hardcoded HTTP URLs](/mobile/maswe-0026-cleartext-network-traffic/#mastg-test-0233-hardcoded-http-urls-android) | Android | static, code |
| [MASTG-TEST-0235](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0235/) | [Android App Configurations Allowing Cleartext Traffic](/mobile/maswe-0026-cleartext-network-traffic/#mastg-test-0235-android-app-configurations-allowing-cleartext-traffic-android) | Android | static, code |
| [MASTG-TEST-0236](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0236/) | [Cleartext Traffic Observed on the Network](/mobile/maswe-0026-cleartext-network-traffic/#mastg-test-0236-cleartext-traffic-observed-on-the-network-android-and-ios) | Network (Android and iOS) | dynamic, network |
| [MASTG-TEST-0237](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0237/) | [Cross-Platform Framework Configurations Allowing Cleartext Traffic](/mobile/maswe-0026-cleartext-network-traffic/#mastg-test-0237-cross-platform-framework-configurations-allowing-cleartext-traffic-android) (placeholder) | Android | static, code |
| [MASTG-TEST-0238](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0238/) | [Runtime Use of Network APIs Transmitting Cleartext Traffic](/mobile/maswe-0026-cleartext-network-traffic/#mastg-test-0238-runtime-use-of-network-apis-transmitting-cleartext-traffic-android) (placeholder) | Android | dynamic, hooks |
| [MASTG-TEST-0239](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0239/) | [Using Low-Level APIs (e.g. Socket) to Set Up a Custom HTTP Connection](/mobile/maswe-0026-cleartext-network-traffic/#mastg-test-0239-using-low-level-apis-eg-socket-to-set-up-a-custom-http-connection-android) (placeholder) | Android | static, code |
| [MASTG-TEST-0321](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0321/) | [Hardcoded HTTP URLs](/mobile/maswe-0026-cleartext-network-traffic/#mastg-test-0321-hardcoded-http-urls-ios) | iOS | static, code |
| [MASTG-TEST-0322](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0322/) | [App Transport Security Configurations Allowing Cleartext Traffic](/mobile/maswe-0026-cleartext-network-traffic/#mastg-test-0322-app-transport-security-configurations-allowing-cleartext-traffic-ios) | iOS | static, code, manual |
| [MASTG-TEST-0323](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0323/) | [Uses of Low-Level Networking APIs for Cleartext Traffic](/mobile/maswe-0026-cleartext-network-traffic/#mastg-test-0323-uses-of-low-level-networking-apis-for-cleartext-traffic-ios) | iOS | static, code, manual |
| **MASWE-0026, Part 2: TLS versions** | | | |
| [MASTG-TEST-0217](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0217/) | [Insecure TLS Protocols Explicitly Allowed in Code](/mobile/maswe-0026-insecure-tls-protocol-versions/#mastg-test-0217-insecure-tls-protocols-explicitly-allowed-in-code-android) | Android | static, code |
| [MASTG-TEST-0218](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0218/) | [Insecure TLS Protocols in Network Traffic](/mobile/maswe-0026-insecure-tls-protocol-versions/#mastg-test-0218-insecure-tls-protocols-in-network-traffic-android) | Android | dynamic, network |
| [MASTG-TEST-0342](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0342/) | [References to Weak ATS TLS Policy Exceptions in Info.plist](/mobile/maswe-0026-insecure-tls-protocol-versions/#mastg-test-0342-references-to-weak-ats-tls-policy-exceptions-in-infoplist-ios) | iOS | static, code |
| [MASTG-TEST-0343](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0343/) | [URLSession TLS Protocol Configuration](/mobile/maswe-0026-insecure-tls-protocol-versions/#mastg-test-0343-urlsession-tls-protocol-configuration-ios) | iOS | static, code, manual |
| [MASTG-TEST-0344](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0344/) | [Network.framework TLS Protocol Configuration](/mobile/maswe-0026-insecure-tls-protocol-versions/#mastg-test-0344-networkframework-tls-protocol-configuration-ios) | iOS | static, code, manual |
| [MASTG-TEST-0345](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0345/) | [Embedded or Third-party TLS Stack Configuration](/mobile/maswe-0026-insecure-tls-protocol-versions/#mastg-test-0345-embedded-or-third-party-tls-stack-configuration-ios) | iOS | static, code, manual |
| [MASTG-TEST-0348](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0348/) | [Insecure TLS Protocols in Network Traffic](/mobile/maswe-0026-insecure-tls-protocol-versions/#mastg-test-0348-insecure-tls-protocols-in-network-traffic-ios) | iOS | dynamic, network |
| **MASWE-0027: certificate validation** | | | |
| [MASTG-TEST-0282](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0282/) | [Unsafe Custom Trust Evaluation](/mobile/maswe-0027-insecure-certificate-validation/#mastg-test-0282-unsafe-custom-trust-evaluation-android) | Android | static, code, manual |
| [MASTG-TEST-0283](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0283/) | [Incorrect Implementation of Server Hostname Verification](/mobile/maswe-0027-insecure-certificate-validation/#mastg-test-0283-incorrect-implementation-of-server-hostname-verification-android) | Android | static, code, manual |
| [MASTG-TEST-0234](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0234/) | [Missing Implementation of Server Hostname Verification with SSLSockets](/mobile/maswe-0027-insecure-certificate-validation/#mastg-test-0234-missing-implementation-of-server-hostname-verification-with-sslsockets-android) | Android | static, code |
| [MASTG-TEST-0284](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0284/) | [Incorrect SSL Error Handling in WebViews](/mobile/maswe-0027-insecure-certificate-validation/#mastg-test-0284-incorrect-ssl-error-handling-in-webviews-android) | Android | static, code, manual |
| [MASTG-TEST-0286](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0286/) | [Network Security Configuration Allowing Trust in User-Provided CAs](/mobile/maswe-0027-insecure-certificate-validation/#mastg-test-0286-network-security-configuration-allowing-trust-in-user-provided-cas-android) | Android | static, code |
| [MASTG-TEST-0285](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0285/) | [Outdated Android Version Allowing Trust in User-Provided CAs](/mobile/maswe-0027-insecure-certificate-validation/#mastg-test-0285-outdated-android-version-allowing-trust-in-user-provided-cas-android) | Android | static, code |
| [MASTG-TEST-0295](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0295/) | [GMS Security Provider Not Updated](/mobile/maswe-0027-insecure-certificate-validation/#mastg-test-0295-gms-security-provider-not-updated-android) | Android | static, code |
| [MASTG-TEST-0396](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0396/) | [References to URLSessionDelegate Bypassing Certificate Validation](/mobile/maswe-0027-insecure-certificate-validation/#mastg-test-0396-references-to-urlsessiondelegate-bypassing-certificate-validation-ios) | iOS | static, code, manual |
| [MASTG-TEST-0397](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0397/) | [References to WKNavigationDelegate Bypassing Certificate Validation](/mobile/maswe-0027-insecure-certificate-validation/#mastg-test-0397-references-to-wknavigationdelegate-bypassing-certificate-validation-ios) | iOS | static, code, manual |
| **MASWE-0028: identity pinning** | | | |
| [MASTG-TEST-0242](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0242/) | [Missing Certificate Pinning in Network Security Configuration](/mobile/maswe-0028-insecure-identity-pinning/#mastg-test-0242-missing-certificate-pinning-in-network-security-configuration-android) | Android | static, code |
| [MASTG-TEST-0243](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0243/) | [Expired Certificate Pins in the Network Security Configuration](/mobile/maswe-0028-insecure-identity-pinning/#mastg-test-0243-expired-certificate-pins-in-the-network-security-configuration-android) | Android | static, code |
| [MASTG-TEST-0244](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0244/) | [Missing Certificate Pinning in Network Traffic](/mobile/maswe-0028-insecure-identity-pinning/#mastg-test-0244-missing-certificate-pinning-in-network-traffic-android) | Network (Android) | dynamic, network |
| [MASTG-TEST-0385](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0385/) | [Missing Certificate Pinning in ATS](/mobile/maswe-0028-insecure-identity-pinning/#mastg-test-0385-missing-certificate-pinning-in-ats-ios) | iOS | static |

The count by weakness is 16 for MASWE-0026, 9 for MASWE-0027 and 4 for MASWE-0028. By platform it is 17 Android (including TEST-0236 and TEST-0244, which OWASP files under Android with `platform: network`) and 12 iOS. TEST-0236 is the only test written for both platforms. The iOS cleartext and pinning tests are almost all static: we add a runtime pinning check ([GT-0028-3](/mobile/maswe-0028-insecure-identity-pinning/#gt-0028-3-runtime-pinning-check-ios)). OWASP's certificate-validation tests are all static, so we add a dynamic proof ([GT-0027-1](/mobile/maswe-0027-insecure-certificate-validation/#gt-0027-1-proving-it-on-the-wire-with-an-untrusted-ca-and-a-wrong-hostname-certificate-android-and-ios)).

## Legacy v1 tests and their replacements

MASTG v1 had nine network tests. All are now `status: deprecated`, with a `covered_by` list pointing to v2 tests. If an older report or a client's checklist cites them, map them like this:

| Legacy test | Platform | v1 title | OWASP `covered_by` | Where we cover it |
|-------------|----------|----------|--------------------|-------------------|
| [MASTG-TEST-0019](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0019/) | Android | Testing Data Encryption on the Network | 0233, 0234, 0235, 0236, 0237, 0238, 0239 | [Cleartext](/mobile/maswe-0026-cleartext-network-traffic/#legacy-tests-and-how-to-approach-this-weakness); TEST-0234 is in [MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/#mastg-test-0234-missing-implementation-of-server-hostname-verification-with-sslsockets-android) |
| [MASTG-TEST-0020](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0020/) | Android | Testing the TLS Settings | 0217, 0218 | [TLS versions](/mobile/maswe-0026-insecure-tls-protocol-versions/#tests) |
| [MASTG-TEST-0021](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0021/) | Android | Testing Endpoint Identify Verification | 0282, 0283, 0284, 0285, 0286 | [MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/#tests), plus TEST-0234 and our dynamic GT-0027-1 |
| [MASTG-TEST-0022](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0022/) | Android | Testing Custom Certificate Stores and Certificate Pinning (L2) | 0242, 0243, 0244 | [MASWE-0028](/mobile/maswe-0028-insecure-identity-pinning/#tests), plus GT-0028-1 for OkHttp, TrustKit and custom trust managers |
| [MASTG-TEST-0023](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0023/) | Android | Testing the Security Provider (L2) | 0295 | [MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/#mastg-test-0295-gms-security-provider-not-updated-android) |
| [MASTG-TEST-0065](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0065/) | iOS | Testing Data Encryption on the Network | 0321, 0322, 0236 | [Cleartext](/mobile/maswe-0026-cleartext-network-traffic/#legacy-tests-and-how-to-approach-this-weakness); its low-level API part is now TEST-0323 |
| [MASTG-TEST-0066](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0066/) | iOS | Testing the TLS Settings | 0342, 0343, 0344, 0345, 0348 | [TLS versions](/mobile/maswe-0026-insecure-tls-protocol-versions/#tests) |
| [MASTG-TEST-0067](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0067/) | iOS | Testing Endpoint Identity Verification | 0322, 0342, 0396, 0397 | [MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/#tests); the ATS parts are in the two MASWE-0026 notes |
| [MASTG-TEST-0068](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0068/) | iOS | Testing Custom Certificate Stores and Certificate Pinning (L2) | 0385 | [MASWE-0028](/mobile/maswe-0028-insecure-identity-pinning/#tests), plus GT-0028-2 and GT-0028-3 |

Two gaps are worth knowing. OWASP's list for TEST-0021 omits TEST-0234, although TEST-0234 is where `SSLSocket` hostname verification now lives. And several v1 tests had a dynamic half that has no v2 equivalent. Our GT checks restore the dynamic halves of the validation and pinning tests. In MASVS v1 terms, MASWE-0026 maps to MSTG-NETWORK-1 and -2, MASWE-0027 to MSTG-NETWORK-3, and MASWE-0028 to MSTG-NETWORK-4.

## What each attacker position can prove

Most network findings are over- or under-rated for one reason: the report does not say what the attacker needs. Each lab set-up reproduces a specific attacker. Name that attacker in the finding.

| Attacker position | Lab equivalent | What a successful read proves | What it cannot prove |
|-------------------|----------------|-------------------------------|----------------------|
| **Passive observer** on the same network (open Wi-Fi, compromised router, ISP) | tcpdump on a rooted device, PCAPdroid, `rvictl`, capture on a gateway you own | Cleartext disclosure (TEST-0236). The negotiated TLS version and cipher suite (TEST-0218/0348). Non-forward-secret suites, which are record-now-decrypt-later. | Anything about certificate validation or pinning. TLS payloads stay opaque. |
| **Proximity attacker** within BLE/NFC range or on a USB link | BLE sniffer, `btsnoop` HCI log | Unencrypted machine-to-machine channels ([GT-0026-3](/mobile/maswe-0026-cleartext-network-traffic/#gt-0026-3-unencrypted-machine-to-machine-channels-ble-nfc-wi-fi-direct-usb)) | Internet traffic |
| **Active MITM, no trusted certificate** (rogue AP, ARP or DNS spoofing) | Proxy with a **fresh, untrusted CA**, reached through a VPN, rogue AP or transparent mode ([GT-0027-1](/mobile/maswe-0027-insecure-certificate-validation/#gt-0027-1-proving-it-on-the-wire-with-an-untrusted-ca-and-a-wrong-hostname-certificate-android-and-ios) step 1) | Tampering with cleartext. Disabled chain validation (TEST-0282, 0284, 0396, 0397, embedded stacks). HTTP-to-HTTPS redirects open to SSL stripping. Insecure TLS fallback ([GT-0026-TLS-2](/mobile/maswe-0026-insecure-tls-protocol-versions/#gt-0026-tls-2-active-client-acceptance-test-with-a-legacy-only-endpoint-android-ios)). | Hostname verification, if chain validation works |
| **Active MITM with a publicly trusted certificate for another domain** (free DV certificate for a domain the attacker owns) | Wrong-hostname leaf signed by a CA the device trusts (GT-0027-1 step 2) | Missing hostname verification (TEST-0283, 0234) | Pinning |
| **Active MITM with a certificate the device trusts for the real host** (MDM inspection root, user-installed CA or profile, mis-issuing public CA) | Proxy CA installed as a **user CA** on Android, or a fully trusted profile on iOS, with **no bypass tooling** | Trust in user CAs (TEST-0286, 0285). Missing, expired or ineffective pinning (TEST-0242, 0243, 0244, 0385, GT-0028-1 to 4) | Nothing about chain or hostname validation: those passed |
| **Controller of the device** (your rooted or jailbroken test phone, malware with root) | System CA, Frida, objection, SSL Kill Switch, repackaging | Nothing about MASVS-NETWORK. A pinning bypass here is methodology, not a finding. | — (see MASVS-RESILIENCE and [MASWE-0062](#related-weaknesses-in-other-categories)) |

The [interception lab](/mobile/mobile-traffic-interception-lab/#choosing-an-interception-position) explains how to set up each position. The rule of thumb: if the app shows you its traffic and you have installed **nothing** on the device, you have found MASWE-0026 or MASWE-0027, not a lab configuration.

## Test plan

Before step 1, build the endpoint inventory: hosts from strings, from the configuration and from a capture. Mark each host as first-party or third-party ([which domains must be pinned](/mobile/maswe-0028-insecure-identity-pinning/#before-you-start-which-domains-must-be-pinned)). Set up the [lab](/mobile/mobile-traffic-interception-lab/) with **two** CAs: your normal proxy CA, and a fresh one the device has never seen.

### 1. Static configuration review

These checks take minutes and tell you where to look.

- **Android:** read `minSdkVersion`, `targetSdkVersion`, `usesCleartextTraffic` and `networkSecurityConfig` from the merged manifest. Then resolve the NSC per supported Android version: cleartext (TEST-0235), `<certificates src="user"/>` and `overridePins` (TEST-0286, 0285), and `<pin-set>` coverage and `expiration` (TEST-0242, 0243). Check `<debug-overrides>` against `android:debuggable`.
- **iOS:** dump `NSAppTransportSecurity` from the app and from every extension. Check for cleartext keys (TEST-0322), TLS exceptions (TEST-0342) and `NSPinnedDomains` (TEST-0385).
- **Cross-platform:** Capacitor, Cordova, React Native, Flutter, .NET and Unity settings in the *built* output (TEST-0237).

### 2. Code review

- **URLs and protocols:** `http://`, `ws://`, `tcp://` and plaintext gRPC (TEST-0233, 0321).
- **Low-level APIs:** sockets, Network.framework, CFNetwork, BSD sockets (TEST-0239, 0323).
- **Protocol selection:** `SSLContext.getInstance`, `setEnabledProtocols`, OkHttp `COMPATIBLE_TLS`, `tlsMinimumSupportedProtocolVersion`, `sec_protocol_options_set_min_tls_protocol_version`, embedded OpenSSL/BoringSSL/curl settings (TEST-0217, 0343, 0344, 0345).
- **Trust code:** `X509TrustManager`, `HostnameVerifier`, raw `SSLSocket`, `onReceivedSslError`, `ProviderInstaller` (TEST-0282, 0283, 0234, 0284, 0295). On iOS, `URLSessionDelegate` and `WKNavigationDelegate` challenge handlers (TEST-0396, 0397).
- **Code-level pinning:** OkHttp `CertificatePinner`, TrustKit, `SecTrust` code (GT-0028-1, GT-0028-2).
- **Reachability:** for every hit, decide whether it is live or dead code ([how](/mobile/maswe-0027-insecure-certificate-validation/#telling-live-code-from-dead-code)).

### 3. Dynamic interception with an untrusted CA

Run every flow through the proxy using the **fresh** CA, with a packet capture running alongside.

- Anything readable over HTTP, `ws://` or another plaintext protocol is cleartext (TEST-0236).
- Anything readable over HTTPS was accepted without chain validation (GT-0027-1 step 1).
- Attribute every hit to a code location with hooks (TEST-0238). Repeat on an API 27 emulator if `minSdkVersion` ≤ 27, because the `targetSdk` 28 cleartext default does not apply below that.

Before you trust a "rejected" result, check the baseline: with your normal CA you must be able to see the traffic. If you cannot, the host is pinned or the app does not use the proxy, and "rejected" tells you nothing.

### 4. Wrong hostname

Serve a leaf issued for `wrong.example.org` and signed by the CA the device trusts (GT-0027-1 step 2). Anything readable means hostname verification is missing. For pinned hosts, neutralise **only** the pin check. Never run a blanket "disable SSL" script, because those also replace the hostname verifier.

### 5. TLS versions

- **Capture without a proxy:** passive capture of the app's real handshakes (TEST-0218, 0348). Read the client's offer, the client's ceiling, the negotiated version and the negotiated suite per host ([how](/mobile/maswe-0026-insecure-tls-protocol-versions/#before-you-start-client-offer-server-acceptance-and-negotiated-version)).
- **The client's floor:** run an active test against a legacy-only endpoint (GT-0026-TLS-2).
- **The backend:** what each first-party server accepts (GT-0026-TLS-1). Report server-only results to the backend owner.

### 6. Pinning

Install your normal proxy CA the way a real attacker's would arrive: as a user CA on Android, or as a trusted profile on iOS. Run no bypass tooling.

- Decrypted first-party traffic means pinning is missing or ineffective for that host (TEST-0244, GT-0028-3).
- Then check how pins are delivered and what happens on a mismatch (GT-0028-4).
- Only after that, bypass pinning ([techniques](/mobile/maswe-0028-insecure-identity-pinning/#bypassing-pinning-during-an-assessment)) so you can test everything else.

### 7. Non-HTTP and non-proxy-aware channels

- Flows missing from the proxy but present in the capture: use the lab's [non-HTTP techniques](/mobile/mobile-traffic-interception-lab/#non-http-and-non-proxy-aware-traffic).
- Native and cross-platform TLS stacks: [GT-0027-2](/mobile/maswe-0027-insecure-certificate-validation/#gt-0027-2-other-tls-stacks-and-cross-platform-frameworks-android-and-ios) and [GT-0026-TLS-3](/mobile/maswe-0026-insecure-tls-protocol-versions/#gt-0026-tls-3-native-and-cross-platform-tls-stacks-android).
- Third-party SDKs ([GT-0026-2](/mobile/maswe-0026-cleartext-network-traffic/#gt-0026-2-third-party-sdks-and-native-libraries-android-and-ios)), WebViews ([GT-0026-1](/mobile/maswe-0026-cleartext-network-traffic/#gt-0026-1-webview-cleartext-and-mixed-content-android-and-ios)), and BLE, NFC, Wi-Fi Direct and USB (GT-0026-3).

## Rating overview

The detailed tables are in each note's *Rating findings* section. This is the shape of them, ordered by what the attacker needs. When the same data is at stake, the less the attacker needs, the higher the rating.

| Finding | Attacker needs | Typical rating | Details |
|---------|----------------|----------------|---------|
| Credentials, tokens or card data in cleartext in a main flow; executable or security-controlling content fetched over HTTP | Network position only (passive) | Critical | [Cleartext](/mobile/maswe-0026-cleartext-network-traffic/#rating-findings) |
| Other sensitive personal data in cleartext; HTTP WebView with a JavaScript bridge | Network position only | High | [Cleartext](/mobile/maswe-0026-cleartext-network-traffic/#rating-findings) |
| Low-sensitivity but modifiable content over HTTP; global cleartext enabled with no sensitive traffic seen | Network position only | Medium | [Cleartext](/mobile/maswe-0026-cleartext-network-traffic/#rating-findings) |
| Chain validation or hostname verification disabled, reachable, on credentials, tokens, payment data or executed content | Active MITM, no CA on the device | Critical (High for other sensitive data) | [MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/#rating-findings) |
| User CAs trusted in the release config for sensitive hosts without pinning; `targetSdkVersion` below 24 | A CA in the victim's user store | Medium | [MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/#rating-findings) |
| NULL or anonymous cipher suite negotiated or accepted on a connection carrying credentials, tokens or regulated data | Network position only | Critical | [TLS versions](/mobile/maswe-0026-insecure-tls-protocol-versions/#rating-findings) |
| SSL 3.0, export-grade or RC4 negotiated or accepted for sensitive traffic, or reachable through version fallback | Active MITM | High | [TLS versions](/mobile/maswe-0026-insecure-tls-protocol-versions/#rating-findings) |
| TLS 1.0/1.1 negotiated for sensitive traffic in normal use; 3DES; static-RSA suites (for example `NSExceptionRequiresForwardSecrecy = false`) | Active MITM (or passive plus a later server-key compromise) | Medium | [TLS versions](/mobile/maswe-0026-insecure-tls-protocol-versions/#rating-findings) |
| Client permits or offers TLS 1.0/1.1, but every observed backend negotiates TLS 1.2+; a backend that accepts legacy versions the app never offers (server finding) | Active MITM plus a server that cooperates | Low | [TLS versions](/mobile/maswe-0026-insecure-tls-protocol-versions/#rating-findings) |
| Pinning missing, expired or fail-open for sensitive first-party hosts in an **L2/EUDIW** app | A certificate the device trusts | Medium | [MASWE-0028](/mobile/maswe-0028-insecure-identity-pinning/#rating-findings) |
| Same gap in an **L1** app; no backup pin | A certificate the device trusts / none (availability) | Low | [MASWE-0028](/mobile/maswe-0028-insecure-identity-pinning/#rating-findings) |
| Pinning bypassed on your own rooted or jailbroken device | Control of the device | Info (methodology) | [MASWE-0028](/mobile/maswe-0028-insecure-identity-pinning/#why-a-bypass-on-your-own-device-is-not-a-finding) |

Two cross-cutting rules apply to every row.

- **Pinning code that breaks validation is not a pinning finding.** If it lets an attacker with no trusted certificate intercept traffic, rate it as MASWE-0027.
- **Reachability changes the rating.** A trust-all manager that is never constructed is Low (dead code), not Critical.

In every report, name the attacker position, the hosts and flows affected, the OS versions concerned, and how you obtained the evidence: which CA, installed where, and whether any bypass was running.

## Command cheat sheet

The most-used commands from the series. Each note has the full procedure, the expected output and how to read it.

### Configuration

```bash
# Android: SDK levels, cleartext flag and NSC reference from the merged manifest
aapt2 dump badging app.apk | grep -E 'sdkVersion|targetSdkVersion'
aapt2 dump xmltree app.apk --file AndroidManifest.xml | grep -iE 'usesCleartextTraffic|networkSecurityConfig|debuggable'
apktool d -f -o out_apktool app.apk
grep -nE 'cleartextTrafficPermitted|certificates src|overridePins|pin-set|expiration|debug-overrides' \
  out_apktool/res/xml*/network_security_config.xml

# iOS: ATS dictionary of the app and every extension
unzip -q App.ipa -d ipa
find ipa/Payload \( -path '*.app/Info.plist' -o -path '*.appex/Info.plist' \) -print
plutil -convert json -o - ipa/Payload/App.app/Info.plist | jq '.NSAppTransportSecurity'
```

### Code

```bash
jadx -d out app.apk
# Cleartext URLs and protocols
grep -rnoE '(http|ws|tcp)://[A-Za-z0-9.-]+' out/sources | sort -u
# TLS versions and trust code
grep -rnE 'SSLContext\.getInstance\(|setEnabledProtocols\(|COMPATIBLE_TLS|tlsVersions\(' out/sources
grep -rnE 'X509(Extended)?TrustManager|checkServerTrusted|HostnameVerifier|onReceivedSslError|setDefaultSSLSocketFactory|CertificatePinner|ProviderInstaller' out/sources
# iOS: strings from the decrypted binary, and linked libraries (embedded TLS stacks)
rabin2 -zz ipa/Payload/App.app/App | grep -E 'http://|ws://|NSAllowsArbitraryLoads|@SECLEVEL'
otool -L ipa/Payload/App.app/App
```

### Interception and capture

```bash
# Android proxy on and off
adb shell settings put global http_proxy 192.168.1.10:8080
adb shell settings put global http_proxy :0

# Untrusted CA: a fresh mitmproxy confdir the device has never seen
mitmdump --listen-port 8080 --set confdir="$HOME/.mitmproxy-untrusted" -w untrusted-ca.flows

# Wrong hostname: leaf for wrong.example.org signed by your trusted lab CA (full openssl steps in MASWE-0027)
mitmdump --listen-port 8080 --certs '*=wrong.pem' -w wrong-host.flows

# Cleartext requests in a saved mitmproxy session
mitmdump -nr untrusted-ca.flows --flow-detail 1 '~u "^http://"'

# Passive capture: rooted Android, or iOS over USB
adb shell su -c 'tcpdump -i any -s 0 -w /data/local/tmp/app.pcap'
rvictl -s <UDID> && sudo tcpdump -i rvi0 -w app.pcap

# Handshake alerts (48 = unknown_ca): the client rejected your certificate
tshark -r app.pcap -Y 'tls.alert_message' -T fields -e ip.dst -e tls.alert_message.desc
```

### TLS versions

```bash
# ServerHello negotiated below TLS 1.2
tshark -r app.pcap -Y 'tls.handshake.type == 2 && tls.handshake.version < 0x0303' -O tls | grep -E 'Version:|Cipher Suite:'
# ClientHello offering TLS 1.0 or 1.1
tshark -r app.pcap -Y 'tls.handshake.type == 1 && tls.handshake.extensions.supported_version in {0x0301 0x0302}' \
  -T fields -e tls.handshake.extensions_server_name
# What the backend accepts (server finding, not an app finding)
testssl.sh -p -E api.example.com:443
nmap -sV --script ssl-enum-ciphers -p 443 api.example.com
```

### Pinning

```bash
# SPKI SHA-256 pin of a live leaf: compare with the app's pins
openssl s_client -connect api.example.com:443 -servername api.example.com </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary | openssl enc -base64

# Visibility only (not a finding): objection's pinning bypass
objection -g com.example.app explore --startup-command "android sslpinning disable"
objection -g com.example.app explore --startup-command "ios sslpinning disable"
```

## Related weaknesses in other categories

Two weaknesses from other control groups also list MASVS-NETWORK-1 in their mappings. They will be covered in their own series, and we note them here so that a NETWORK review does not miss them.

- **[MASWE-0047: Using Non-Standard APIs for Security-Critical Functionality](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0047/)** (MASVS-CODE-3, also AUTH-1, CRYPTO-1 and NETWORK-1; profiles L1, L2, EUDIW). A home-grown networking or TLS stack, an outdated third-party networking library, or a custom DNS resolver used instead of `URLSession`, OkHttp or the platform's Private DNS. In this series it shows up as GT-0027-2 and TEST-0345. We will cover it fully in the MASVS-CODE series.
- **[MASWE-0062: No Application-Level Payload Encryption](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0062/)** (MASVS-RESILIENCE-3 and NETWORK-1; profiles R, EUDIW). Security-relevant payloads protected only by TLS, so they are readable and editable as soon as someone bypasses pinning on a device they control. This is the requirement that covers the attacker our pinning note rules out. We will cover it in the MASVS-RESILIENCE series.

## Other series hubs

- [MASVS-STORAGE: secure storage](/mobile/masvs-storage-1-secure-storage-guide/)
- [MASVS-CRYPTO: cryptography and key management](/mobile/masvs-crypto-cryptography-guide/)
- [MASVS-AUTH: authentication and authorisation](/mobile/masvs-auth-authentication-guide/). A token captured through any finding in this series is only worth what the session design allows; see also [MASWE-0024](/mobile/maswe-0024-sensitive-data-accessible-after-session-termination/).

## References

- OWASP MASVS: [MASVS-NETWORK-1](https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-1/), [MASVS-NETWORK-2](https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-2/) (CC BY-SA 4.0)
- OWASP MASWE: [MASWE-0026](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0026/), [MASWE-0027](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0027/), [MASWE-0028](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0028/), [MASWE-0047](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0047/), [MASWE-0062](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0062/) (CC BY-SA 4.0)
- OWASP MASTG: [Tests](https://mas.owasp.org/MASTG/tests/), [Knowledge](https://mas.owasp.org/MASTG/knowledge/), [Techniques](https://mas.owasp.org/MASTG/techniques/), [Best Practices](https://mas.owasp.org/MASTG/best-practices/) (CC BY-SA 4.0)
- [RFC 8446: TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446), [RFC 8996: Deprecating TLS 1.0 and TLS 1.1](https://www.rfc-editor.org/rfc/rfc8996), [RFC 9325: Recommendations for Secure Use of TLS and DTLS](https://www.rfc-editor.org/rfc/rfc9325)
- [NIST SP 800-52 Rev. 2: Guidelines for TLS Implementations](https://csrc.nist.gov/pubs/sp/800/52/r2/final)
- [OWASP Pinning Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Pinning_Cheat_Sheet.html)
- [Android Developers: Network security configuration](https://developer.android.com/privacy-and-security/security-config), [Security with network protocols](https://developer.android.com/privacy-and-security/security-ssl)
- [Apple: Preventing Insecure Network Connections](https://developer.apple.com/documentation/security/preventing-insecure-network-connections), [NSAppTransportSecurity](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity), [Identity Pinning: How to configure server certificates for your app](https://developer.apple.com/news/?id=g9ejcf8y)
- [CWE-295](https://cwe.mitre.org/data/definitions/295.html), [CWE-297](https://cwe.mitre.org/data/definitions/297.html), [CWE-319](https://cwe.mitre.org/data/definitions/319.html), [CWE-327](https://cwe.mitre.org/data/definitions/327.html)

> Adapted and extended from the OWASP MASVS, MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
