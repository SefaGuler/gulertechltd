---
title: "Network Traffic Not Encrypted: Insecure TLS Protocol Versions (MASWE-0026, Part 2)"
date: 2026-11-09 16:01:00 +0000
subcategory: network
summary: "Finding TLS 1.0/1.1, weak cipher suites and ATS TLS exceptions in Android and iOS apps, and telling client offers from server acceptance."
refs: [MASWE-0026, MASVS-NETWORK-1, CWE-319, CWE-327]
tags: [android, ios, masvs-network, tls, ats, okhttp]
---

This note is part of our [MASVS-NETWORK guide](/mobile/masvs-network-secure-communication-guide/) and covers the second half of OWASP [MASWE-0026](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0026/): traffic that *is* wrapped in TLS, but in a version or with a cipher suite that no longer counts as encryption by current standards. SSL 3.0, TLS 1.0 and TLS 1.1 explicitly enabled in code, OkHttp's `COMPATIBLE_TLS`, App Transport Security exceptions that lower the minimum version or switch off forward secrecy, `URLSession` and Network.framework minimums set to TLS 1.0, and OpenSSL, BoringSSL, mbedTLS or curl compiled into the app with their own settings. The cleartext half (HTTP, raw sockets, Network Security Configuration and ATS cleartext switches) is in the sibling note [Network Traffic Not Encrypted: Cleartext Traffic](/mobile/maswe-0026-cleartext-network-traffic/), which also owns the full Knowledge sections on NSC and ATS. Here you get the protocol background (RFC 8996, RFC 9325, NIST SP 800-52r2), how Android and iOS choose a TLS version, the seven OWASP tests with commands and demos, our server-side and active-client checks, how to read a capture so that you do not confuse what the *client offered*, what the *server accepts* and what was *actually negotiated*, and severity guidance.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Generic: TLS protocol versions, deprecation and cipher suites (Guler Tech)](#generic-tls-protocol-versions-deprecation-and-cipher-suites-guler-tech)
  - [Generic: How version negotiation works and how downgrades happen (Guler Tech)](#generic-how-version-negotiation-works-and-how-downgrades-happen-guler-tech)
  - [Android: How Android chooses TLS versions (Guler Tech)](#android-how-android-chooses-tls-versions-guler-tech)
  - [iOS: App Transport Security TLS requirements (MASTG-KNOW-0071)](#ios-app-transport-security-tls-requirements-mastg-know-0071)
  - [iOS: Network APIs and where the TLS version is set (MASTG-KNOW-0073)](#ios-network-apis-and-where-the-tls-version-is-set-mastg-know-0073)
- [Tests](#tests)
  - [Before you start: client offer, server acceptance and negotiated version](#before-you-start-client-offer-server-acceptance-and-negotiated-version)
  - [MASTG-TEST-0217: Insecure TLS Protocols Explicitly Allowed in Code (Android)](#mastg-test-0217-insecure-tls-protocols-explicitly-allowed-in-code-android)
  - [MASTG-TEST-0218: Insecure TLS Protocols in Network Traffic (Android)](#mastg-test-0218-insecure-tls-protocols-in-network-traffic-android)
  - [MASTG-TEST-0342: References to Weak ATS TLS Policy Exceptions in Info.plist (iOS)](#mastg-test-0342-references-to-weak-ats-tls-policy-exceptions-in-infoplist-ios)
  - [MASTG-TEST-0343: URLSession TLS Protocol Configuration (iOS)](#mastg-test-0343-urlsession-tls-protocol-configuration-ios)
  - [MASTG-TEST-0344: Network.framework TLS Protocol Configuration (iOS)](#mastg-test-0344-networkframework-tls-protocol-configuration-ios)
  - [MASTG-TEST-0345: Embedded or Third-party TLS Stack Configuration (iOS)](#mastg-test-0345-embedded-or-third-party-tls-stack-configuration-ios)
  - [MASTG-TEST-0348: Insecure TLS Protocols in Network Traffic (iOS)](#mastg-test-0348-insecure-tls-protocols-in-network-traffic-ios)
  - [Supplementary checks (Guler Tech methodology)](#supplementary-checks-guler-tech-methodology)
  - [GT-0026-TLS-1: Backend protocol and cipher suite enumeration (server)](#gt-0026-tls-1-backend-protocol-and-cipher-suite-enumeration-server)
  - [GT-0026-TLS-2: Active client acceptance test with a legacy-only endpoint (Android, iOS)](#gt-0026-tls-2-active-client-acceptance-test-with-a-legacy-only-endpoint-android-ios)
  - [GT-0026-TLS-3: Native and cross-platform TLS stacks (Android)](#gt-0026-tls-3-native-and-cross-platform-tls-stacks-android)
- [Best practices](#best-practices)
  - [MASTG-BEST-0042: Use Strong TLS Settings in ATS Configuration](#mastg-best-0042-use-strong-tls-settings-in-ats-configuration)
  - [MASTG-BEST-0043: Enforce Strong TLS Settings When ATS Doesn't Apply](#mastg-best-0043-enforce-strong-tls-settings-when-ats-doesnt-apply)
  - [Secure configuration for Android and the backend (Guler Tech)](#secure-configuration-for-android-and-the-backend-guler-tech)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

The OWASP requirement behind MASWE-0026 is *"The app encrypts all network traffic."* Most of the weakness text is about cleartext, but its mitigations explicitly name *"lowering the minimum TLS version"* as one of the client-side exceptions to avoid, and seven of the sixteen OWASP tests mapped to it are about TLS versions and TLS policy rather than HTTP versus HTTPS. MASVS-NETWORK-1, the control it maps to, asks for traffic secured *"according to the current best practices"*, and current best practice is not "some TLS": it is TLS 1.2 or 1.3 with forward-secret AEAD cipher suites. SSL 3.0, TLS 1.0 and TLS 1.1 have been formally prohibited by the IETF ([RFC 8996](https://www.rfc-editor.org/rfc/rfc8996), [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325)), which is why we map the finding to [CWE-327](https://cwe.mitre.org/data/definitions/327.html) (use of a broken or risky cryptographic algorithm) as well as the weakness's own [CWE-319](https://cwe.mitre.org/data/definitions/319.html) (cleartext transmission of sensitive information).

The threat is MAS-THREAT-0026, *"Attackers can intercept or modify cleartext network traffic"*, reached through MAS-ATTACK-0012 (monitoring traffic on the same network, such as public Wi-Fi or a compromised router) and MAS-ATTACK-0014 (an active machine-in-the-middle: ARP poisoning, DNS spoofing, a rogue access point). The third attack OWASP lists, MAS-ATTACK-0013 (Bluetooth, NFC, USB), belongs to the cleartext note. For TLS versions, the attacker position matters more than usual: a *passive* observer gains little from TLS 1.0 with a modern key exchange, while an *active* one can try to force a downgrade or exploit a weak cipher suite. The [Rating findings](#rating-findings) section turns that into severities.

Keep four questions apart throughout the test. They have different evidence, different owners, and they are frequently confused in reports:

| Question | Where the answer lives | Typical evidence | Who fixes it |
|---|---|---|---|
| What is the client *willing to accept*? | Code, `Info.plist`, library configuration; confirmed by an active test | Decompiled call, ATS exception, a handshake that completes against a TLS 1.0-only server | App developer |
| What does the client *offer*? | The ClientHello | `supported_versions` extension, offered cipher suites | App developer (or platform) |
| What does the server *accept*? | The server's TLS configuration | testssl.sh, nmap, `openssl s_client -tls1` results | Backend / infrastructure team |
| What was *actually negotiated*? | The ServerHello | Selected version and cipher suite in a capture | Both: the overlap of the two policies |

An app can permit TLS 1.0 in code while every backend negotiates TLS 1.3 (a client finding with low practical impact). A backend can accept TLS 1.0 while the app never offers it (a server finding, not an app finding). Only when both meet does a legacy version end up on the wire. [Before you start](#before-you-start-client-offer-server-acceptance-and-negotiated-version) shows how to tell the four apart in a pcap.

**What is covered elsewhere.** HTTP, cleartext sockets, `usesCleartextTraffic`, `cleartextTrafficPermitted` and the cleartext side of ATS: [MASWE-0026 Part 1](/mobile/maswe-0026-cleartext-network-traffic/). Certificate and hostname validation, custom `TrustManager`s and `SSL_VERIFY_NONE`: [MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/) (we flag disabled verification in embedded stacks here only because OWASP's MASTG-TEST-0345 does). Pinning: [MASWE-0028](/mobile/maswe-0028-insecure-identity-pinning/). Setting up a device, a proxy and a capture: our [interception lab](/mobile/mobile-traffic-interception-lab/).

**Profiles and mappings.** MASWE-0026 is tagged L1, L2 and EUDIW: a baseline requirement. MASVS v2: MASVS-NETWORK-1. MASVS v1: MSTG-NETWORK-1 and MSTG-NETWORK-2 (the TLS-settings requirement). The OWASP v2 tests in this note replace the legacy v1 tests [MASTG-TEST-0020](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0020/) (Android, *Testing the TLS Settings*, now covered by MASTG-TEST-0217 and 0218) and [MASTG-TEST-0066](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0066/) (iOS, *Testing the TLS Settings*, now covered by MASTG-TEST-0342, 0343, 0344, 0345 and 0348).

## Modes of Introduction

**ATS exceptions that weaken TLS (iOS).** `NSExceptionMinimumTLSVersion` set to `TLSv1.0` or `TLSv1.1`, `NSExceptionRequiresForwardSecrecy` set to `false`, often with `NSIncludesSubdomains` widening the exception to a whole domain tree; the deprecated `NSTemporaryException…` and `NSThirdPartyException…` variants of the same keys in older projects; and `NSAllowsArbitraryLoads`, which removes the TLS 1.2 floor and the forward-secrecy requirement for every domain not listed in `NSExceptionDomains`.

**Explicit protocol selection in code.** `SSLContext.getInstance("TLSv1")` or `"TLSv1.1"`, `SSLSocket.setEnabledProtocols(...)` or `SSLParameters.setProtocols(...)` with legacy names, an OkHttp `ConnectionSpec` built with `COMPATIBLE_TLS` or `tlsVersions(TlsVersion.TLS_1_0, ...)`; on iOS, `URLSessionConfiguration.tlsMinimumSupportedProtocolVersion = .TLSv10`, the deprecated `tlsMinimumSupportedProtocol = kTLSProtocol1`, `sec_protocol_options_set_min_tls_protocol_version(..., .TLSv10)`, or a `CFStream`/`NSStream` security level of `TLSv1` or `SSLv3`.

**Weak cipher suite selection.** `setEnabledCipherSuites(...)` or an OkHttp `ConnectionSpec.Builder.cipherSuites(...)` that adds static-RSA, 3DES or RC4 suites; `SSL_CTX_set_cipher_list(ctx, "ALL:@SECLEVEL=0")` in native code; `CURLOPT_SSL_CIPHER_LIST`; ATS forward secrecy switched off.

**Insecure version fallback.** Retry logic that catches a handshake failure and reconnects with a lower maximum version: a hand-written `catch (SSLHandshakeException)` that rebuilds the socket with `TLSv1`, or an OkHttp client configured with `listOf(MODERN_TLS, COMPATIBLE_TLS)`, which retries with the second, weaker spec when the first handshake fails. An active attacker can trigger that failure on purpose.

**Stacks that no platform policy covers.** OpenSSL, BoringSSL, mbedTLS, wolfSSL, libcurl and gRPC compiled into native libraries; cross-platform runtimes with their own TLS (Flutter's Dart `HttpClient`, .NET, Unity, game engines); Network.framework, CFNetwork and BSD sockets on iOS, which ATS does not govern. None of them read the Network Security Configuration or ATS.

**Old platform defaults.** An Android app whose `minSdkVersion` admits devices where the platform still enables TLS 1.0 and 1.1 by default and where the TLS stack has not been updated; an iOS app built with an SDK older than iOS 26 that uses Network.framework (whose default minimum was TLS 1.0 until then) or, on iOS 16 and earlier, connects to IP addresses, which ATS did not cover before iOS 17.

**The backend.** Servers, load balancers, CDNs or third-party APIs that still accept TLS 1.0/1.1 or weak suites, and the client-side exceptions developers add to keep talking to them. MASWE-0026 is explicit that the right fix is on the server.

## Impact

- **Weaker confidentiality and integrity than the app's threat model assumes.** TLS 1.0 and 1.1 have no AEAD cipher suites (AES-GCM and ChaCha20-Poly1305 arrived with TLS 1.2), so traffic is protected by CBC with MAC-then-encrypt (the construction behind BEAST and Lucky Thirteen) or by RC4. Their handshake integrity and peer authentication depend on SHA-1 and MD5/SHA-1 combinations, which is RFC 8996's main reason for retiring them. SSL 3.0 is broken outright by POODLE.
- **Loss of forward secrecy.** Static-RSA suites (`TLS_RSA_WITH_*`), allowed when ATS forward secrecy is disabled or a client enables them, let anyone who records traffic today decrypt it later if the server's private key is ever obtained (through breach, legal compulsion or a decommissioned disk). The attacker only needs to be passive.
- **Downgrade exposure.** Every legacy version the client still accepts is a version an active attacker may try to force, either by exploiting insecure fallback logic or by targeting a server that only speaks the old version.
- **Weak cipher suites.** Export-grade, NULL, anonymous, RC4 and 3DES suites range from "decrypt in hours with enough traffic" (3DES and SWEET32) to "no encryption" (NULL) and "no server authentication" (anonymous Diffie-Hellman, which is a full machine-in-the-middle).
- **Compliance and assurance failures.** PCI DSS has required migration away from SSL and "early TLS" since 30 June 2018; NIST SP 800-52r2 requires TLS 1.2 as the minimum for government-only systems and TLS 1.3 support from 1 January 2024. Mobile banking, payments and health apps are routinely audited against both.

Be precise in reports about what is realistic. Against a native app that negotiates TLS 1.0 with ECDHE and AES-CBC, there is no off-the-shelf attack that recovers a session token from a single connection; BEAST needs attacker-controlled plaintext injected into the same connection, which a browser provides and a typical API client does not. The finding is real because the safety margin is gone and because the configuration is prohibited by the standards the app is measured against, but it is not the same as cleartext. SSL 3.0, NULL, anonymous and export suites are a different matter, and the ratings reflect that.

## Mitigations

- **Require TLS 1.2 as the minimum and prefer TLS 1.3, on both ends.** On current Android and iOS this usually means *not* configuring versions at all: Android 10 and later enables TLS 1.3 by default and recent Conscrypt releases deprecate TLS 1.0/1.1; ATS enforces TLS 1.2 for `URLSession`, and apps built with the iOS 26 SDK get a TLS 1.2 default for `URLSession` and Network.framework.
- **Fix servers, not clients.** Upgrade the backend, the load balancer and the CDN configuration to TLS 1.2+ with ECDHE and AEAD suites, then delete the client exception. Treat every ATS TLS exception and every `COMPATIBLE_TLS` as technical debt with an owner and a removal date.
- **Keep unavoidable exceptions narrow.** One host, no `NSIncludesSubdomains`, never `NSAllowsArbitraryLoads`, and a documented justification (Apple requires one at App Store review).
- **Set the version explicitly where no platform policy applies.** Network.framework, CFNetwork, sockets and every embedded TLS library: minimum TLS 1.2, forward-secret AEAD suites only, certificate verification on, and the library kept up to date.
- **Never implement version fallback.** If the handshake fails, fail. Use a single `ConnectionSpec`.
- **Keep the platform's TLS current on old devices.** Raise `minSdkVersion` where you can ([MASTG-BEST-0010](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0010/)) and update the GMS security provider at start-up ([MASTG-BEST-0020](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0020/)).
- **Check the backend continuously.** A testssl.sh or nmap scan in the deployment pipeline catches a load balancer that silently re-enables TLS 1.0 after a configuration change.

## Knowledge

OWASP links two iOS Knowledge pages to these tests: [MASTG-KNOW-0071 (iOS App Transport Security)](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-NETWORK/MASTG-KNOW-0071/) and [MASTG-KNOW-0073 (iOS Network APIs)](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-NETWORK/MASTG-KNOW-0073/). The full ATS and NSC mechanics live in the [cleartext note](/mobile/maswe-0026-cleartext-network-traffic/); below we summarise only their TLS-policy side. There is no OWASP Knowledge page on TLS versions themselves or on how Android selects them, so the first three sections are ours.

### Generic: TLS protocol versions, deprecation and cipher suites (Guler Tech)

| Version | Specification | Value on the wire | Status |
|---|---|---|---|
| SSL 2.0 | (Netscape, 1995) | `0x0002` | Prohibited by [RFC 6176](https://www.rfc-editor.org/rfc/rfc6176) (2011) |
| SSL 3.0 | [RFC 6101](https://www.rfc-editor.org/rfc/rfc6101) | `0x0300` | Deprecated by [RFC 7568](https://www.rfc-editor.org/rfc/rfc7568) (2015); broken by POODLE (CVE-2014-3566) |
| TLS 1.0 | [RFC 2246](https://www.rfc-editor.org/rfc/rfc2246) (1999) | `0x0301` | Deprecated by [RFC 8996](https://www.rfc-editor.org/rfc/rfc8996) (2021): "MUST NOT be used" |
| TLS 1.1 | [RFC 4346](https://www.rfc-editor.org/rfc/rfc4346) (2006) | `0x0302` | Deprecated by RFC 8996: "MUST NOT be used" |
| TLS 1.2 | [RFC 5246](https://www.rfc-editor.org/rfc/rfc5246) (2008) | `0x0303` | MUST be supported ([RFC 9325](https://www.rfc-editor.org/rfc/rfc9325)) |
| TLS 1.3 | [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) (2018) | `0x0304` | SHOULD be supported and, if supported, MUST be preferred (RFC 9325) |

The hexadecimal values are what you will see in Wireshark, in Apple's `tls_protocol_version_t` and in OpenSSL's `TLS1_VERSION` constants, so learn them: `0x0301` is TLS 1.0, `0x0302` TLS 1.1, `0x0303` TLS 1.2, `0x0304` TLS 1.3.

**Why TLS 1.0 and 1.1 were retired.** RFC 8996 (March 2021, part of BCP 195) moved both to Historic status and says negotiation of either "MUST NOT be permitted". Its reasons are worth quoting in a report because they are not "it is old": the versions require obsolete mandatory cipher suites (TLS 1.0 mandates `TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA`); they cannot use AEAD cipher suites, which only exist from TLS 1.2; the integrity of the handshake depends on SHA-1; peer authentication depends on SHA-1 signatures (or an MD5/SHA-1 concatenation that is not appreciably stronger); and supporting four versions increases the chance of misconfiguration. RFC 8996 also prohibits DTLS 1.0, which matters for apps that use WebRTC or other UDP-based TLS.

**What RFC 9325 adds.** [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325) (November 2022, the current BCP 195 *Recommendations for Secure Use of TLS and DTLS*) restates the version rules (MUST NOT negotiate SSL 2/3, TLS 1.0, TLS 1.1; MUST support TLS 1.2; SHOULD support and prefer TLS 1.3) and sets the cipher-suite baseline you should test against:

- MUST NOT negotiate NULL-encryption suites, RC4 suites ([RFC 7465](https://www.rfc-editor.org/rfc/rfc7465)), or suites offering less than 112 bits of security, which includes export-grade ciphers.
- SHOULD NOT negotiate suites below 128 bits of security. 3DES has an effective strength of 112 bits and a 64-bit block (SWEET32, CVE-2016-2183), so it falls here.
- SHOULD NOT negotiate static-RSA key transport (`TLS_RSA_WITH_*`) or static (EC)DH (`TLS_DH_*`, `TLS_ECDH_*`): no forward secrecy.
- MUST support and prefer forward-secret suites; in TLS 1.2, SHOULD NOT use finite-field `TLS_DHE_*` either. In practice that leaves ECDHE with AES-GCM or ChaCha20-Poly1305.

**NIST SP 800-52 Rev. 2.** [NIST SP 800-52r2](https://csrc.nist.gov/pubs/sp/800/52/r2/final) (August 2019) is the US federal guideline and is often written into contracts. Servers for government-only applications *shall* use TLS 1.2, *should* use TLS 1.3, *should not* use TLS 1.1 and *shall not* use TLS 1.0, SSL 3.0 or SSL 2.0. Citizen- or business-facing servers *shall* negotiate TLS 1.2; TLS 1.0 and 1.1 are "generally discouraged" but *may* be configured when needed to reach the public. Clients *shall* be configured for TLS 1.2, *may* use 1.1 and 1.0 to reach private-sector servers, and *shall not* use SSL. Agencies had to support TLS 1.3 by 1 January 2024. Note the nuance: NIST is more permissive than the IETF for public-facing services, so quote RFC 8996 as the primary authority and NIST as supporting evidence.

**Reading cipher suite names.** A TLS 1.2 suite such as `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` names four things: key exchange (ECDHE, ephemeral, so forward-secret), server authentication (an RSA certificate), bulk encryption (AES-128 in GCM, an AEAD mode) and the hash for the PRF (SHA-256). A TLS 1.3 suite such as `TLS_AES_128_GCM_SHA256` names only the AEAD and hash: key exchange is always ephemeral (EC)DHE or a PSK and is negotiated separately through `supported_groups` and `key_share`. OpenSSL uses its own names (`ECDHE-RSA-AES128-GCM-SHA256`) while nmap and testssl.sh show IANA names (testssl.sh shows both); the [IANA registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4) maps between them and gives the two-byte code (for example `0xC02F`) that Wireshark displays.

| Category | Examples | Problem | Typical rating if negotiated |
|---|---|---|---|
| NULL encryption | `TLS_RSA_WITH_NULL_SHA256` | No encryption at all | Critical / High |
| Anonymous key exchange | `TLS_DH_anon_WITH_AES_128_CBC_SHA` | No server authentication: trivial machine-in-the-middle | Critical / High |
| Export grade | `TLS_RSA_EXPORT_WITH_RC4_40_MD5` | 40/56-bit keys; FREAK, Logjam | High |
| RC4 | `TLS_ECDHE_RSA_WITH_RC4_128_SHA` | Keystream biases; prohibited by RFC 7465 | High |
| 3DES | `TLS_RSA_WITH_3DES_EDE_CBC_SHA` | 64-bit block, SWEET32 | Medium |
| Static RSA | `TLS_RSA_WITH_AES_128_GCM_SHA256` | No forward secrecy; ROBOT-type oracles on weak servers | Medium / Low |
| CBC with HMAC-SHA1 | `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA` | MAC-then-encrypt, padding-oracle history; on HTTP/2's blocklist | Low / Info |
| ECDHE + AEAD | `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`, all TLS 1.3 suites | Current best practice | Pass |

### Generic: How version negotiation works and how downgrades happen (Guler Tech)

Understanding the handshake is what lets you read a capture correctly.

**TLS 1.2 and earlier.** The ClientHello carries a single `client_version`: the *highest* version the client supports. The server answers with the highest version it supports that is not above that value. The client's *minimum* is never sent. If the server chooses a version below the client's minimum, the client aborts with a `protocol_version` alert. So a TLS 1.2 ClientHello with no `supported_versions` extension tells you the client's ceiling and nothing about its floor: it may or may not accept TLS 1.0.

**TLS 1.3.** The ClientHello's `legacy_version` is frozen at `0x0303` and the real offer moves into the `supported_versions` extension (extension type 43), which lists *every* version the client will accept, in preference order. The server's ServerHello also says `0x0303` in its version field and carries a `supported_versions` extension with the single version it selected. Consequences for testing:

- A ClientHello with `supported_versions` = `0x0304, 0x0303` proves the client will not accept TLS 1.0 or 1.1 *on that connection*. If the list contains `0x0302` or `0x0301`, the client offers them.
- The *negotiated* version is the ServerHello's `supported_versions` value if the extension is present, otherwise the ServerHello's version field. Reading only the version field makes every TLS 1.3 connection look like TLS 1.2.
- The record-layer version of a ClientHello is frequently `0x0301` even from TLS 1.3 clients, for compatibility with old middleboxes (RFC 8446 specifies `0x0301` for the initial ClientHello, and RFC 8996 requires servers to accept any `{03,XX}` there). It is not a finding.
- Values such as `0x0a0a`, `0x1a1a` or `0xfafa` in the version or cipher lists are GREASE ([RFC 8701](https://www.rfc-editor.org/rfc/rfc8701)), sent by BoringSSL-based stacks (Chromium, WebView, Cronet) to keep servers tolerant. Ignore them.

**In-band downgrade protection.** An attacker cannot simply strip TLS 1.3 from a ClientHello: the `Finished` messages authenticate the whole transcript, so a modified ClientHello causes the handshake to fail. TLS 1.3 adds a second layer: a server that supports TLS 1.3 but negotiates TLS 1.2 sets the last eight bytes of `ServerHello.random` to `44 4F 57 4E 47 52 44 01` ("DOWNGRD" followed by `01`), or `...00` for TLS 1.1 and below, and TLS 1.3 clients must abort if they see it (RFC 8446, section 4.1.3). If you see that sentinel in a capture, the server supports TLS 1.3 but negotiated lower: either the client did not offer TLS 1.3 (check its ClientHello) or something on the path interfered.

**Out-of-band downgrade (fallback).** The classic attack does not touch the handshake: the attacker makes the first attempt fail (drops or resets it), and a client with fallback logic reconnects with a lower maximum version. Browsers did this until POODLE (2014) showed how to turn it into an SSL 3.0 decryption attack. [RFC 7507](https://www.rfc-editor.org/rfc/rfc7507) defines `TLS_FALLBACK_SCSV` (`0x5600`), a signalling value a client adds to a retry so a modern server can refuse with `inappropriate_fallback`. Seeing `0x5600` in a ClientHello means the client is retrying at a lower version. OkHttp requests it when it falls back to a second `ConnectionSpec`, but Android 10 and later omit it when the retry's maximum version is still TLS 1.2 or higher, so its absence proves nothing.

**When does a legacy version actually get used?** Only when (a) the server supports nothing better, in which case no attacker is needed and you will see it in a normal capture, (b) the client falls back and the server does not enforce `TLS_FALLBACK_SCSV`, or (c) an attacker impersonates the server with a legacy-only endpoint, which also requires defeating certificate validation (see [MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/)). This is why "the client permits TLS 1.0" and "TLS 1.0 was negotiated" carry different severities.

### Android: How Android chooses TLS versions (Guler Tech)

Android's Network Security Configuration controls cleartext, trust anchors and pinning, but has **no setting for TLS versions or cipher suites** (OWASP's MASTG-TEST-0217 makes the same point). The version an Android app negotiates is decided by the TLS provider, the networking library and any code that overrides them.

**The stack.** Apps use the `javax.net.ssl` API (`SSLContext`, `SSLSocketFactory`, `SSLSocket`, `SSLEngine`). The default provider is Conscrypt, the platform's JSSE implementation on top of BoringSSL, registered as `AndroidOpenSSL` with classes under `com.android.org.conscrypt`. From Android 10, Conscrypt ships as a Mainline module (`com.android.conscrypt`), so its TLS behaviour can change through Google Play system updates without an OS upgrade. Two things can replace it: the GMS security provider, which `ProviderInstaller.installIfNeeded()` inserts at the top of the provider list (see [MASTG-BEST-0020](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0020/)), and a bundled copy of Conscrypt (`org.conscrypt`, inserted with `Security.insertProviderAt(Conscrypt.newProvider(), 1)`). On top of the provider sit the HTTP libraries: `HttpsURLConnection` (internally a fork of OkHttp, `com.android.okhttp`), OkHttp and everything built on it (Retrofit, Coil, React Native's networking module, many SDKs), Ktor's Android and OkHttp engines, and Volley. Cronet and WebView do **not** use Conscrypt: they carry Chromium's own BoringSSL, and the app cannot change their TLS versions. Flutter, .NET, Unity and native libraries bring their own stacks (see [GT-0026-TLS-3](#gt-0026-tls-3-native-and-cross-platform-tls-stacks-android)).

**Platform defaults.** The [`SSLSocket` reference](https://developer.android.com/reference/javax/net/ssl/SSLSocket) documents the protocol defaults for client sockets obtained from the default factories:

| Protocol | Supported (API levels) | Enabled by default (API levels) |
|---|---|---|
| SSLv3 | 1–25 | 1–22 |
| TLSv1 | 1+ | 1+ |
| TLSv1.1 | 16+ | 20+ |
| TLSv1.2 | 16+ | 20+ |
| TLSv1.3 | 29+ | 29+ |

Two things that table does not tell you:

- **TLS 1.3 from Android 10 (API 29).** Per the [Android 10 TLS notes](https://developer.android.com/privacy-and-security/security-ssl#Updates%20to%20SSL), TLS 1.3 is enabled by default for all TLS connections; TLS 1.3 cipher suites cannot be customised (calls to `setEnabledCipherSuites()` that try to remove them are ignored); 0-RTT is not supported; `SSLContext.getInstance("TLSv1.2")` returns a context with TLS 1.3 disabled; and `TLS_FALLBACK_SCSV` is no longer sent when the maximum version is TLS 1.2 or above. Android 10 also stopped trusting SHA-1-signed certificates.
- **TLS 1.0 and 1.1 are being removed.** The AOSP Conscrypt page states that *"Android 15 restricts the usage of TLS versions 1.0 and 1.1. These versions had previously been deprecated in Android, but are now disallowed for apps targeting Android 15."* The current [Conscrypt source](https://github.com/google/conscrypt) shows how this is implemented: when the platform marks TLS 1.0/1.1 as deprecated, the default enabled list becomes TLS 1.2 and 1.3 only; when it also marks them unsupported, `TLSv1` and `TLSv1.1` passed to `setEnabledProtocols()` are silently dropped for apps targeting API level 35 or lower, and rejected with `IllegalArgumentException` (*"TLSv1 and TLSv1.1 are deprecated and can no longer be enabled for apps targeting API level 36 or higher"*) for apps targeting 36+. Because the behaviour depends on the device's Android version, the installed Conscrypt module version and the app's `targetSdkVersion`, **do not rely on a table: confirm on the device under test** with [GT-0026-TLS-2](#gt-0026-tls-2-active-client-acceptance-test-with-a-legacy-only-endpoint-android-ios), and on the oldest Android version the app's `minSdkVersion` admits.

**`SSLContext.getInstance()` names.** The algorithm name selects a protocol *ceiling*, not "exactly this version", and naming an old version never makes anything safer:

| Name | Conscrypt behaviour |
|---|---|
| `"TLS"`, `"SSL"`, `"Default"` | The default context: every enabled version up to TLS 1.3. `"SSL"` does **not** mean SSL 3.0. |
| `"TLSv1.3"` | Same as the default. |
| `"TLSv1.2"` | TLS 1.3 disabled. Where legacy versions are still allowed, 1.0–1.2; otherwise 1.2 only. |
| `"TLSv1.1"`, `"TLSv1"` | TLS 1.3 disabled; TLS 1.0–1.2 where legacy versions are still allowed, otherwise TLS 1.2 only. |

**`setEnabledProtocols()` semantics.** The Java API accepts any list, but BoringSSL only has a minimum and a maximum. Conscrypt converts the list into the *lowest contiguous run* of supported versions. On a device that still supports TLS 1.0, `{"TLSv1", "TLSv1.2"}` therefore becomes "TLS 1.0 only", because the gap at TLS 1.1 ends the run. That is a real bug pattern in hand-written socket factories, and a reason to read the exact array rather than just noting "setEnabledProtocols is called". `SSLParameters.setProtocols()` followed by `SSLSocket.setSSLParameters()` has the same effect.

**OkHttp `ConnectionSpec`.** OkHttp applies a [`ConnectionSpec`](https://lysine.dev/okhttp/features/https/) to every socket it creates by calling `setEnabledProtocols()` and `setEnabledCipherSuites()` with the *intersection* of the spec and what the socket already has enabled. The built-in specs, per the [TLS configuration history](https://lysine.dev/okhttp/tls_configuration_history/) and the current source:

| Spec | TLS versions | Cipher suites |
|---|---|---|
| `RESTRICTED_TLS` | 1.3, 1.2 | TLS 1.3 suites plus ECDHE with AES-GCM or ChaCha20-Poly1305 only |
| `MODERN_TLS` (default) | 1.3, 1.2 (TLS 1.0 and 1.1 removed in OkHttp 3.13, February 2019) | The above plus ECDHE-CBC-SHA, static-RSA and 3DES suites kept for compatibility |
| `COMPATIBLE_TLS` | 1.3, 1.2, 1.1, 1.0 | Same list as `MODERN_TLS` |
| `CLEARTEXT` | none (plain HTTP) | none |

`OkHttpClient`'s default is `listOf(MODERN_TLS, CLEARTEXT)`. Three practical consequences: on devices where the platform still enables TLS 1.0 by default, `MODERN_TLS` is stricter than a plain `HttpsURLConnection`; `COMPATIBLE_TLS` can only re-enable versions the socket still has enabled, so on a device where Conscrypt has dropped TLS 1.0 it changes nothing (but it is still a finding, for older devices and for intent); and a list containing **two** TLS specs, such as `listOf(MODERN_TLS, COMPATIBLE_TLS)`, makes OkHttp retry a failed handshake with the second spec (adding `TLS_FALLBACK_SCSV`), which is exactly the fallback behaviour an active attacker can trigger. Note too that `MODERN_TLS`, the default, still lists static-RSA and 3DES suites; whether they are offered depends on the platform's enabled cipher suites, so check the ClientHello rather than assuming.

**Other libraries.** Apache HttpClient's `SSLConnectionSocketFactory` takes a `supportedProtocols` array; Ktor's OkHttp engine passes through an OkHttp `ConnectionSpec`; Volley and Glide use whatever `HttpsURLConnection` or OkHttp they are given. The "TLS 1.2 on Android 4.x" workaround (a custom `SSLSocketFactory` that calls `setEnabledProtocols(new String[] {"TLSv1.1", "TLSv1.2"})` because API 16–19 supported but did not enable them) is a *positive* use of the API; do not report it, but check the array.

### iOS: App Transport Security TLS requirements (MASTG-KNOW-0071)

Source: [MASTG-KNOW-0071](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-NETWORK/MASTG-KNOW-0071/). The complete explanation of ATS, including cleartext exceptions, local networking and web content, is in the [cleartext note](/mobile/maswe-0026-cleartext-network-traffic/). What matters for TLS versions:

- ATS (iOS 9+) applies to the URL Loading System, `URLSession` and APIs built on it. By default it requires TLS 1.2 or later, AES-128 or AES-256 encryption, certificates signed with RSA 2048+ or ECC 256+ keys and SHA-256 or better, and forward secrecy through ECDHE key exchange. Apple lists the acceptable forward-secret suites in [Preventing Insecure Network Connections](https://developer.apple.com/documentation/security/preventing-insecure-network-connections).
- Per-domain keys under `NSExceptionDomains` that weaken TLS: [`NSExceptionMinimumTLSVersion`](https://developer.apple.com/documentation/bundleresources/information-property-list/nsexceptionminimumtlsversion) (string: `TLSv1.0`, `TLSv1.1`, `TLSv1.2`, `TLSv1.3`; default `TLSv1.2`) and [`NSExceptionRequiresForwardSecrecy`](https://developer.apple.com/documentation/bundleresources/information-property-list/nsexceptionrequiresforwardsecrecy) (Boolean, default `YES`; `NO` allows the static-RSA suites listed in Apple's documentation). `NSIncludesSubdomains = YES` extends the entry to every subdomain. Older projects may use the deprecated, undocumented `NSTemporaryExceptionMinimumTLSVersion` / `NSTemporaryExceptionRequiresForwardSecrecy` and `NSThirdPartyException…` forms; they still work, so search for them.
- [`NSAllowsArbitraryLoads`](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity/nsallowsarbitraryloads) = `YES` disables ATS for every domain not listed in `NSExceptionDomains`: no TLS 1.2 floor, no forward-secrecy requirement, cleartext allowed. Listed domains keep their own settings. From iOS 10 it is ignored if `NSAllowsArbitraryLoadsInWebContent`, `NSAllowsArbitraryLoadsForMedia` or `NSAllowsLocalNetworking` is also present.
- ATS does not apply to unqualified host names or `.local` names, and it does not apply to lower-level APIs (Network.framework, CFNetwork, BSD sockets, embedded libraries). IP addresses changed in iOS 17: before it, ATS did not restrict connections to IP literals at all; from iOS 17, iPadOS 17 and macOS 14, ATS blocks them by default and `NSExceptionDomains` accepts individual IPv4/IPv6 addresses and CIDR ranges (Apple, `NSAllowsLocalNetworking`). An IP-keyed exception is therefore a real relaxation on iOS 17+, and meaningless on earlier versions, where the connection was never protected.
- ATS settings are read from the `Info.plist` of the running bundle. App extensions (`PlugIns/*.appex`) have their own `Info.plist` and their own ATS policy; check each one.
- Apple requires a justification at App Store review for `NSExceptionMinimumTLSVersion` (and for the arbitrary-loads and insecure-HTTP keys). The justification is context for the report, not a pass.
- `nscurl --ats-diagnostics --verbose https://api.example.com` on macOS runs a server against a series of ATS permutations and tells you the minimum exception it would need ([MASTG-TECH-0149](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0149/)). OWASP's own notes record that on macOS 26 every TLS 1.0/1.1 permutation fails, even with ATS disabled, because the host stack refuses the handshake; treat `nscurl` as a server diagnostic and confirm client behaviour on a device.

### iOS: Network APIs and where the TLS version is set (MASTG-KNOW-0073)

Source: [MASTG-KNOW-0073](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-NETWORK/MASTG-KNOW-0073/). iOS offers several networking layers; what matters here is which ones ATS governs and where each one lets code change the TLS version.

| Layer | Typical APIs | ATS applies? | Where the TLS version is set |
|---|---|---|---|
| URL Loading System | `URLSession`, `URLSessionConfiguration`, Alamofire, AFNetworking | Yes | `URLSessionConfiguration.tlsMinimumSupportedProtocolVersion` / `tlsMaximumSupportedProtocolVersion` (`tls_protocol_version_t`, iOS 13+); deprecated `tlsMinimumSupportedProtocol` / `tlsMaximumSupportedProtocol` (`SSLProtocol`) |
| Network framework | `NWConnection`, `NWListener`, `NWProtocolTLS.Options`; iOS 26 `NetworkConnection` | No | `sec_protocol_options_set_min_tls_protocol_version` / `..._max_...` on `securityProtocolOptions`; deprecated `sec_protocol_options_set_tls_min_version` |
| CFNetwork / streams | `CFReadStream`/`CFWriteStream`, `NSStream`, `CFHTTPMessage` | No | `kCFStreamPropertySSLSettings` and the stream security level (`kCFStreamSocketSecurityLevelTLSv1`, `...SSLv3`, `NSStreamSocketSecurityLevelTLSv1`, …); legacy Secure Transport `SSLSetProtocolVersionMin` |
| BSD sockets + embedded TLS | `socket`/`connect` with OpenSSL, BoringSSL, mbedTLS, wolfSSL, libcurl, gRPC | No | The library's own API (see [MASTG-TEST-0345](#mastg-test-0345-embedded-or-third-party-tls-stack-configuration-ios)) |

**Constants you will meet in disassembly.** `tls_protocol_version_t`: `TLSv10` = `0x0301`, `TLSv11` = `0x0302`, `TLSv12` = `0x0303`, `TLSv13` = `0x0304` (`DTLSv10` = `0xfeff`, `DTLSv12` = `0xfefd`). The legacy `SSLProtocol` enum from `SecureTransport.h`: `kSSLProtocol3` = 2, `kTLSProtocol1` = 4, `kTLSProtocol11` = 7, `kTLSProtocol12` = 8, `kTLSProtocol13` = 10.

**How code settings and ATS combine.** For `URLSession`, the configuration properties are evaluated *in addition to* ATS. Setting `tlsMinimumSupportedProtocolVersion = .TLSv10` does not bypass ATS: without a matching `NSExceptionMinimumTLSVersion` (or ATS disabled for that host), ATS still blocks anything below TLS 1.2. With such an exception, the code value decides how low the session will go. For Network.framework and everything below it there is no ATS safety net: whatever the code sets takes effect.

**The iOS 26 default change.** Apple's OS 26 release notes carry a Security deprecation entry (we checked it in the tvOS 26 notes; the entry itself names iOS 26 and macOS 26) that states: *"For apps linked on or after iOS 26 and macOS 26, the default minimum TLS version of `URLSession` and Network frameworks has changed from 1.0 to 1.2."* Apple's suggested way for apps that must reach legacy third-party servers to restore the old behaviour is exactly the two APIs OWASP's tests look for: `URLSessionConfiguration.tlsMinimumSupportedProtocolVersion` and `sec_protocol_options_set_min_tls_protocol_version`. Three consequences for testing:

1. For an app built with an SDK older than iOS 26, an `NWConnection` with default TLS options accepts TLS 1.0 from a server that offers nothing better, *without any explicit call*. Check the build SDK (`DTSDKName` in `Info.plist`, or the `sdk` field of `LC_BUILD_VERSION` in `otool -l`).
2. For an app built with the iOS 26 SDK, an explicit `.TLSv10`/`.TLSv11` minimum is now the deliberate opt-out Apple describes, which makes it a stronger signal of intent.
3. "Linked on or after" is about the SDK, not the device: an older app on an iOS 26 device keeps the old default.

OWASP's MASTG-BEST-0042/0043 and MASTG-TECH-0149 summarise this change as "ATS exceptions configured to allow TLS 1.0 or 1.1 are no longer accepted by the operating system". Apple's wording is narrower (a changed default, with documented opt-outs) and the same OWASP technique page notes an app with a TLS 1.0 exception connecting on iOS 17. We have not verified whether an `NSExceptionMinimumTLSVersion` exception alone, without the code-level opt-out, still allows TLS 1.0 in an app built with the iOS 26 SDK; test it on the device rather than assuming either way.

Apple has also enabled the hybrid post-quantum key exchange `X25519MLKEM768` by default for TLS 1.3 in `URLSession` and Network.framework on iOS 26 (see Apple's [Prepare your network for quantum-secure encryption in TLS](https://support.apple.com/en-us/122756)). It is a useful fingerprint: a ClientHello from the app that does *not* list that group in `supported_groups` on an iOS 26 device probably came from an embedded TLS stack rather than Apple's.

## Tests

OWASP maps seven v2 tests to this half of MASWE-0026: two for Android (one static, one network) and five for iOS (three static checks of policy and code, one of embedded stacks, one network). They replace the v1 tests MASTG-TEST-0020 and MASTG-TEST-0066. Static tests tell you what the app is *willing* to do; network tests tell you what *happened* with the servers it talked to during your session. You need both, plus the server-side and active checks in our [supplementary section](#supplementary-checks-guler-tech-methodology), to rate a finding properly.

### Before you start: client offer, server acceptance and negotiated version

**Capture without interception.** For the network tests you want the app's own handshakes with the real servers, so do **not** capture through Burp or mitmproxy. An intercepting proxy terminates TLS: the device negotiates with the proxy (mitmproxy's default minimum is TLS 1.2, so a TLS 1.0 handshake will never complete through it) and the proxy negotiates upstream with its own TLS stack. Neither leg tells you what the app and the backend would have done. Capture passively instead, with one of:

- **tcpdump on a rooted Android device** ([MASTG-TECH-0010](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0010/), [tcpdump](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0080/)): `adb shell su -c 'tcpdump -i any -s 0 -w /data/local/tmp/app.pcap'`, then `adb pull /data/local/tmp/app.pcap`.
- **PCAPdroid on an unrooted Android device**: a VPN-service based capture app that can restrict the capture to one app's UID and export a pcap. Leave its TLS decryption feature off for this test.
- **rvictl on iOS** ([MASTG-TECH-0062](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0062/)): with the device on USB and Xcode installed, `rvictl -s <UDID>` creates `rvi0`; capture it with `sudo tcpdump -i rvi0 -w app.pcap` or [Wireshark](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0081/). No jailbreak needed.
- **The gateway.** Put the device on a hotspot you control (for example macOS Internet Sharing) and capture there: `sudo tcpdump -i bridge100 -w app.pcap`. Works for both platforms without touching the device.

You do not need TLS keys: the ClientHello and ServerHello are unencrypted in every TLS version, and they contain everything this note needs.

**Read the four answers from the capture.** In TLS 1.3 the ServerHello's version field says `0x0303`, so always read the `supported_versions` extension as well (see [how negotiation works](#generic-how-version-negotiation-works-and-how-downgrades-happen-guler-tech)). These [tshark](https://www.wireshark.org/docs/man-pages/tshark.html) commands extract both hellos keyed by TCP stream and join them:

```bash
# ClientHello: stream, SNI, legacy version (= the ceiling if no supported_versions), offered versions
tshark -r app.pcap -Y 'tcp && tls.handshake.type == 1' -T fields \
  -e tcp.stream -e tls.handshake.extensions_server_name \
  -e tls.handshake.version -e tls.handshake.extensions.supported_version > ch.tsv

# ServerHello: stream, version field, selected version (TLS 1.3), selected cipher suite
tshark -r app.pcap -Y 'tcp && tls.handshake.type == 2' -T fields \
  -e tcp.stream -e tls.handshake.version \
  -e tls.handshake.extensions.supported_version -e tls.handshake.ciphersuite > sh.tsv

# One line per host: SNI, client ceiling, client offer, negotiated version, cipher suite
awk -F'\t' 'NR==FNR { sni[$1]=$2; ceil[$1]=$3; off[$1]=$4; next }
            { neg = ($3 != "") ? $3 : $2; print sni[$1] "\t" ceil[$1] "\t" off[$1] "\t" neg "\t" $4 }' \
  ch.tsv sh.tsv | sort -u
```

Useful display filters for Wireshark or `tshark -Y`:

| Question | Display filter |
|---|---|
| Was anything negotiated below TLS 1.2? | `tls.handshake.type == 2 && tls.handshake.version < 0x0303` |
| Does any ClientHello *offer* TLS 1.0 or 1.1? | `tls.handshake.type == 1 && tls.handshake.extensions.supported_version in {0x0301 0x0302}` |
| Which ClientHellos hide their floor (no `supported_versions`)? | `tls.handshake.type == 1 && !tls.handshake.extensions.supported_version` |
| Was a static-RSA, 3DES or RC4 suite selected? | `tls.handshake.type == 2 && tls.handshake.ciphersuite in {0x0004 0x0005 0x000a 0x002f 0x0035 0x003c 0x003d 0x009c 0x009d}` |
| Is the client retrying after a failure (fallback)? Absence proves nothing | `tls.handshake.ciphersuite == 0x5600` |
| Did the server reject the client's version? | `tls.alert_message.desc == 70` (protocol_version) |

To see cipher suite names rather than codes, print the decoded handshake: `tshark -r app.pcap -Y 'tls.handshake.type == 2' -O tls | grep 'Cipher Suite:'`.

**Interpreting the result.** For each host, decide which of the four questions you have answered:

| What you see | What it proves | Next step |
|---|---|---|
| ServerHello selects `0x0301`/`0x0302` | Legacy version *negotiated*: the client accepted it and the server chose it | Client finding (it accepted) and server finding (it chose); confirm the server with [GT-0026-TLS-1](#gt-0026-tls-1-backend-protocol-and-cipher-suite-enumeration-server) |
| `supported_versions` lists `0x0301`/`0x0302`, server selects TLS 1.2/1.3 | Client *offers* legacy versions; server does not use them | Client finding, low impact; find the cause with the static tests |
| ClientHello `0x0303` with no `supported_versions` | Client's ceiling is TLS 1.2 (TLS 1.3 disabled); its floor is unknown | Static tests plus [GT-0026-TLS-2](#gt-0026-tls-2-active-client-acceptance-test-with-a-legacy-only-endpoint-android-ios) |
| `supported_versions` = `0x0304, 0x0303` only | Client offers TLS 1.2+ on this connection | Pass for this host; the server may still accept TLS 1.0 (GT-0026-TLS-1) |
| Server accepts TLS 1.0 in a scan but the app never offers it | Server finding only | Report to the backend owner, not as an app vulnerability |

**Attribute every connection.** A device-wide capture includes the OS, Google Play services, other apps and the app's WebView (Chromium's TLS stack, outside the app's control). Map SNIs to the app with the host names you find statically (`strings`, decompiled code, `Info.plist` exception domains), take a baseline capture with the app closed, and on Android prefer PCAPdroid's per-app mode. QUIC (UDP 443, HTTP/3) always uses TLS 1.3 (RFC 9001), so it can be skipped for this weakness.

### MASTG-TEST-0217: Insecure TLS Protocols Explicitly Allowed in Code (Android)

Source: [MASTG-TEST-0217](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0217/). Platform: Android. Type: static (code). Replaces part of MASTG-TEST-0020. OWASP provides no demo for this test; the demo below is ours.

#### Overview

The Network Security Configuration cannot set TLS versions, so on Android every legacy version that gets enabled is enabled in code: by naming it in `SSLContext.getInstance()`, by passing it to `setEnabledProtocols()` / `SSLParameters.setProtocols()`, or by configuring a library such as OkHttp (`ConnectionSpec.COMPATIBLE_TLS`, `ConnectionSpec.Builder.tlsVersions(...)`) or Apache HttpClient (`supportedProtocols`). The test finds those calls and the exact values passed. We extend it to cipher suite configuration (`setEnabledCipherSuites`, `ConnectionSpec.Builder.cipherSuites`) and to fallback logic, because they are configured in the same places and have the same effect on what goes on the wire.

#### Prerequisites

- The APK (and any splits): `adb shell pm path com.example.app`, then `adb pull` each path ([adb](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0004/)).
- [jadx](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/) for decompilation ([MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)); optionally [Apktool](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/) for smali and [semgrep](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/).
- For validation: a device with the app installed and [Frida](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/).
- The app's `minSdkVersion` and `targetSdkVersion` (`aapt2 dump badging base.apk | grep -E 'sdkVersion|targetSdkVersion'`), because they decide which platform defaults apply.

#### Steps

1. **Decompile.**

   ```bash
   jadx -d out --show-bad-code base.apk
   apktool d -o smali-out base.apk   # optional, for string searches that survive bad decompilation
   ```

2. **Search for protocol selection and its neighbours.** Start broad, then read every hit:

   ```bash
   grep -rnE 'SSLContext\.getInstance\(|setEnabledProtocols\(|setProtocols\(|setEnabledCipherSuites\(|setCipherSuites\(|COMPATIBLE_TLS|tlsVersions\(|cipherSuites\(|connectionSpecs\(|TlsVersion\.(TLS_1_0|TLS_1_1|SSL_3_0)|"SSLv3"|"TLSv1(\.1)?"' out/sources \
     | grep -vE '/(okhttp3|org/conscrypt|org/apache/http|kotlin|androidx)/'
   ```

   The exclusion of library packages only works if the app is not obfuscated. In an R8-shrunk app, OkHttp's classes are renamed but its strings survive: the class that contains all of `"TLSv1.3"`, `"TLSv1.2"`, `"TLSv1.1"`, `"TLSv1"` and `"SSLv3"` is OkHttp's `TlsVersion`, and the class whose `toString()` contains `supportsTlsExtensions=` is `ConnectionSpec`. Open them in jadx-gui, then use *Find Usage* on the fields that correspond to `COMPATIBLE_TLS`, `TLS_1_0` and `TLS_1_1` to reach the app's own configuration code.

3. **Run a semgrep rule over the decompiled sources** (ours; adjust as needed):

   ```yaml
   rules:
     - id: legacy-tls-sslcontext
       languages: [java]
       severity: WARNING
       message: SSLContext requested with a legacy protocol name ($V)
       patterns:
         - pattern: SSLContext.getInstance($V, ...)
         - metavariable-regex:
             metavariable: $V
             regex: ^"(SSLv3|TLSv1|TLSv1\.1)"$
     - id: tls-protocols-or-ciphers-set
       languages: [java]
       severity: INFO
       message: Enabled protocols or cipher suites set explicitly; review the values
       pattern-either:
         - pattern: $S.setEnabledProtocols(...)
         - pattern: $S.setEnabledCipherSuites(...)
         - pattern: $P.setProtocols(...)
     - id: okhttp-compatible-tls
       languages: [java]
       severity: WARNING
       message: OkHttp COMPATIBLE_TLS enables TLS 1.0 and 1.1
       pattern: ConnectionSpec.COMPATIBLE_TLS
   ```

   ```bash
   semgrep --config legacy-tls.yaml out/sources
   ```

4. **Resolve each value.** For every hit, establish the actual array or spec: follow constants, string resources and remote configuration. Pay attention to sparse arrays (Conscrypt reduces `{"TLSv1", "TLSv1.2"}` to TLS 1.0 only on devices that still support it), to `listOf(MODERN_TLS, COMPATIBLE_TLS)` (fallback), and to `catch (SSLHandshakeException …)` blocks that rebuild the connection with a different protocol list.

5. **Check reachability.** Note which code path uses the configured factory or client (which hosts, which features). Dead code in an SDK is Info; the client that talks to the payment API is not.

6. **Validate at runtime (optional but recommended).** Log what the app actually requests, with the call stack:

   ```javascript
   // tls-android.js — run with: frida -U -f com.example.app -l tls-android.js
   Java.perform(() => {
     const Log = Java.use('android.util.Log');
     const Exception = Java.use('java.lang.Exception');
     const where = () => Log.getStackTraceString(Exception.$new()).split('\n').slice(2, 7).join('\n');

     const SSLContext = Java.use('javax.net.ssl.SSLContext');
     SSLContext.getInstance.overload('java.lang.String').implementation = function (name) {
       console.log(`[SSLContext.getInstance] ${name}\n${where()}`);
       return this.getInstance(name);
     };

     // Platform Conscrypt: every setEnabledProtocols/setSSLParameters ends up here
     const Params = Java.use('com.android.org.conscrypt.SSLParametersImpl');
     Params.setEnabledProtocols.overload('[Ljava.lang.String;').implementation = function (protocols) {
       const list = [];
       for (let i = 0; i < protocols.length; i++) list.push(protocols[i].toString());
       console.log(`[setEnabledProtocols] ${list.join(', ')}\n${where()}`);
       return this.setEnabledProtocols(protocols);
     };
   });
   ```

   If the app bundles its own Conscrypt, hook `org.conscrypt.SSLParametersImpl` as well. On recent Conscrypt versions you may see legacy names requested and then silently filtered; that is still evidence of the app's configuration.

#### Observation

A list of every protocol and cipher-suite configuration point: file and method, the exact values, which client or socket factory it feeds, which hosts use that client, and (if validated) the Frida log with stack traces. Record `minSdkVersion`, `targetSdkVersion` and the Android version of the test device.

#### Evaluation

The test **fails** if the app:

- requests an `SSLContext` named `SSLv3`, `TLSv1` or `TLSv1.1`;
- passes `SSLv3`, `TLSv1` or `TLSv1.1` to `setEnabledProtocols()` / `SSLParameters.setProtocols()`;
- uses `ConnectionSpec.COMPATIBLE_TLS`, or builds a `ConnectionSpec` whose `tlsVersions` include `TLS_1_0`, `TLS_1_1` or `SSL_3_0`;
- configures any other library to allow versions below TLS 1.2; or
- (our extension) enables NULL, anonymous, export, RC4 or 3DES suites, or implements version fallback.

Context that changes the rating but not the result: whether the affected client is reachable and for which hosts; whether the device population (`minSdkVersion`) includes Android versions on which the legacy version is actually still available; and whether the backend accepts it (GT-0026-TLS-1). Calls that only *raise* security, such as enabling TLS 1.1/1.2 on API 16–19 or restricting to `{"TLSv1.3", "TLSv1.2"}`, pass.

#### Demo

Our sample (Guler Tech), showing the three patterns we meet most often:

```kotlin
// FAIL: legacy context; on devices that still support TLS 1.0 this offers TLS 1.0-1.2 and never TLS 1.3
val ctx = SSLContext.getInstance("TLSv1.1").apply { init(null, null, null) }
val socket = ctx.socketFactory.createSocket("legacy.example.com", 443) as SSLSocket
// FAIL: sparse list -> Conscrypt keeps the lowest contiguous run, i.e. TLS 1.0 only
socket.enabledProtocols = arrayOf("TLSv1", "TLSv1.2")

// FAIL: OkHttp retries with COMPATIBLE_TLS (TLS 1.0-1.3) when the MODERN_TLS handshake fails
val client = OkHttpClient.Builder()
    .connectionSpecs(listOf(ConnectionSpec.MODERN_TLS, ConnectionSpec.COMPATIBLE_TLS))
    .build()
```

Running the grep from step 2 on the decompiled app:

```text
out/sources/com/example/app/net/LegacyGateway.java:31:        SSLContext sSLContext = SSLContext.getInstance("TLSv1.1");
out/sources/com/example/app/net/LegacyGateway.java:35:        sSLSocket.setEnabledProtocols(new String[]{"TLSv1", "TLSv1.2"});
out/sources/com/example/app/net/ApiClientFactory.java:18:        builder.connectionSpecs(CollectionsKt.listOf((Object[]) new ConnectionSpec[]{ConnectionSpec.MODERN_TLS, ConnectionSpec.COMPATIBLE_TLS}));
```

And the Frida log on our Android 11 test device (its Conscrypt module still supports TLS 1.0) when the gateway feature runs:

```text
[SSLContext.getInstance] TLSv1.1
	at com.example.app.net.LegacyGateway.connect(LegacyGateway.java:31)
[setEnabledProtocols] TLSv1, TLSv1.2
	at com.example.app.net.LegacyGateway.connect(LegacyGateway.java:35)
```

The test fails on all three lines. Next, [MASTG-TEST-0218](#mastg-test-0218-insecure-tls-protocols-in-network-traffic-android) shows whether `legacy.example.com` actually negotiates TLS 1.0, and [GT-0026-TLS-1](#gt-0026-tls-1-backend-protocol-and-cipher-suite-enumeration-server) whether the API server behind `ApiClientFactory` would ever make OkHttp fall back.

### MASTG-TEST-0218: Insecure TLS Protocols in Network Traffic (Android)

Source: [MASTG-TEST-0218](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0218/). Platform: Android. Type: dynamic (network). Replaces part of MASTG-TEST-0020. OWASP provides no demo; ours is below.

#### Overview

Static analysis shows what the app allows; the version used is decided at runtime between the app and each server. This test captures the app's real traffic and reads the negotiated version (and, in our extension, the negotiated cipher suite and the client's offer) for every connection. It is also the only practical option when static analysis is incomplete: heavy obfuscation, native code, remote configuration or SDKs you cannot read.

#### Prerequisites

- The app installed ([MASTG-TECH-0005](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/)): `adb install base.apk`, or `adb install-multiple base.apk split_config.arm64_v8a.apk ...` for split APKs.
- A passive capture method from [Before you start](#before-you-start-client-offer-server-acceptance-and-negotiated-version): tcpdump on a rooted device, PCAPdroid, or a gateway you control. **Not** an intercepting proxy.
- tshark or Wireshark.
- Test accounts that reach every feature, including payments, uploads and account management.

#### Steps

1. **Start a clean capture.** Force-stop the app and clear background noise as far as possible, then start capturing. On a rooted device:

   ```bash
   adb shell am force-stop com.example.app
   adb shell su -c 'tcpdump -i any -s 0 -w /data/local/tmp/app.pcap' &
   ```

2. **Exercise the app thoroughly** ([MASTG-TECH-0010](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0010/)): first launch after a fresh install (remote configuration and SDK initialisation happen once), registration and login, every main feature, sensitive data entry, file upload and download, push notification handling, background sync (leave the app in the background for a few minutes), logout. Third-party SDK endpoints count: the app chose to ship them.

3. **Stop and collect.**

   ```bash
   adb shell su -c 'pkill tcpdump'
   adb pull /data/local/tmp/app.pcap
   ```

4. **Extract the hellos and join them** with the tshark commands in [Before you start](#before-you-start-client-offer-server-acceptance-and-negotiated-version), then apply the display filters for legacy negotiation, legacy offers, hidden floors and weak suites.

5. **Attribute the connections** to the app (per-app capture, SNI matched against static strings, baseline capture). Separate WebView traffic, which follows Chromium's policy rather than the app's.

6. **Follow up.** Negotiated legacy versions go to GT-0026-TLS-1 (to confirm the server) and to MASTG-TEST-0217 (to find the client code that allowed it). ClientHellos without `supported_versions` go to GT-0026-TLS-2 (to find the client's floor).

#### Observation

The pcap, and a table per host: SNI, IP, client ceiling, offered versions, negotiated version, negotiated cipher suite, and which feature triggered the connection.

#### Evaluation

The test **fails** if any connection made by the app negotiates SSL 3.0, TLS 1.0 or TLS 1.1 (ServerHello version, or `supported_versions` when present, below `0x0303`). Our extensions, reported in the same finding: the test also fails if a NULL, anonymous, export, RC4 or 3DES suite is negotiated, and we record (as a lower-severity client observation) any ClientHello that *offers* `0x0301`/`0x0302` even though the server chose something better.

A pass applies only to the hosts and flows you exercised. It does not prove the client would refuse TLS 1.0 from a server that offered nothing else; for that, run GT-0026-TLS-2.

#### Demo

Our sample (Guler Tech): the app from the [MASTG-TEST-0217 demo](#mastg-test-0217-insecure-tls-protocols-explicitly-allowed-in-code-android), captured on the same Android 11 device with PCAPdroid. The joined output (SNI, ceiling, offer, negotiated, suite):

```text
api.example.com	0x0303	0x0304,0x0303,0x0302,0x0301	0x0304	0x1301
cdn.example.net	0x0303	0x0304,0x0303,0x0302,0x0301	0x0304	0x1302
legacy.example.com	0x0301		0x0301	0xc013
```

And the decoded ServerHello for the third host:

```bash
tshark -r app.pcap -Y 'tls.handshake.type == 2 && tls.handshake.version < 0x0303' -O tls | grep -E 'Version:|Cipher Suite:'
```

```text
            Version: TLS 1.0 (0x0301)
            Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)
```

Reading it: the OkHttp client used for `api.example.com` and `cdn.example.net` *offers* TLS 1.0 and 1.1 (on this device the platform still enables them and `COMPATIBLE_TLS` keeps them), but both servers choose TLS 1.3: a low-impact client observation. The gateway client's ClientHello carries `client_version` `0x0301` and no `supported_versions`: the sparse `{"TLSv1", "TLSv1.2"}` list collapsed to TLS 1.0 only, so the app could not have negotiated anything better even with a modern server (and a ClientHello with `client_version` `0x0301` is itself prohibited by RFC 8996). `legacy.example.com` negotiated **TLS 1.0** with an ECDHE-CBC-SHA1 suite. The test fails for that host, with both a client cause (the app accepted it) and a server cause (the server chose it).

### MASTG-TEST-0342: References to Weak ATS TLS Policy Exceptions in Info.plist (iOS)

Source: [MASTG-TEST-0342](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0342/). Platform: iOS. Type: static (configuration). Related knowledge: MASTG-KNOW-0071. Best practice: MASTG-BEST-0042. Replaces part of MASTG-TEST-0066.

#### Overview

The test reads the ATS dictionary of every bundle in the app and looks for the three settings that weaken TLS for `URLSession` traffic: a per-domain `NSExceptionMinimumTLSVersion` below TLS 1.2, a per-domain `NSExceptionRequiresForwardSecrecy` set to false, and the global `NSAllowsArbitraryLoads`. The cleartext keys (`NSExceptionAllowsInsecureHTTPLoads`, `NSAllowsArbitraryLoadsInWebContent`, `NSAllowsLocalNetworking`) are tested in the [cleartext note](/mobile/maswe-0026-cleartext-network-traffic/); `NSAllowsArbitraryLoads` appears in both because it removes the TLS floor *and* allows HTTP. Report it once and reference it from the other note.

#### Prerequisites

- A decrypted IPA ([MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/); see the [interception lab](/mobile/mobile-traffic-interception-lab/) for obtaining one). `Info.plist` is not encrypted by FairPlay, so an App Store IPA is enough for this test.
- `plutil` ([MASTG-TOOL-0062](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0062/)) and `jq` on macOS, or Python's `plistlib` on any OS; optionally `gron`.
- macOS with Xcode command-line tools for `nscurl`.

#### Steps

1. **Unpack and list every bundle's `Info.plist`** ([MASTG-TECH-0153](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0153/)). Extensions have their own ATS policy, so do not stop at the main app:

   ```bash
   unzip -q MyApp.ipa -d ipa
   find ipa/Payload \( -path '*.app/Info.plist' -o -path '*.appex/Info.plist' \) -print
   ```

2. **Dump the ATS dictionary** ([MASTG-TECH-0138](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0138/), [MASTG-TECH-0155](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0155/)). App Store builds use binary plists; both tools below handle them:

   ```bash
   plutil -convert json -o - ipa/Payload/MyApp.app/Info.plist | jq '.NSAppTransportSecurity'
   # Without macOS:
   python3 -I -c 'import plistlib,json,sys; print(json.dumps(plistlib.load(open(sys.argv[1],"rb")).get("NSAppTransportSecurity"), indent=2, default=str))' ipa/Payload/MyApp.app/Info.plist
   ```

3. **Extract the weakening keys**, including the deprecated `NSTemporaryException…` and `NSThirdPartyException…` spellings:

   ```bash
   plutil -convert json -o ats.json ipa/Payload/MyApp.app/Info.plist
   jq -r '
     .NSAppTransportSecurity as $ats
     | "NSAllowsArbitraryLoads = \($ats.NSAllowsArbitraryLoads // "absent")",
       ( ($ats.NSExceptionDomains // {}) | to_entries[]
         | .key as $d | .value | to_entries[]
         | select(.key | test("^NS(Temporary|ThirdParty)?Exception(MinimumTLSVersion|RequiresForwardSecrecy)$"))
         | "\($d)\t\(.key) = \(.value)" )' ats.json
   ```

   OWASP's demo does the same with `gron` and `egrep`:

   ```bash
   gron -m ats.json | egrep 'NSAppTransportSecurity\.(NSAllowsArbitraryLoads|NSExceptionDomains\["[^"]+"\]\.(NSExceptionMinimumTLSVersion|NSTemporaryExceptionMinimumTLSVersion|NSExceptionRequiresForwardSecrecy))'
   ```

4. **Record the scope of each exception**: whether `NSIncludesSubdomains` is true, whether the domain belongs to the app owner or a third party, and whether it is an IP address or CIDR range (honoured from iOS 17; on iOS 16 and earlier ATS did not cover IP addresses at all, so on those versions the connection was never protected regardless of the exception).

5. **Check whether each exception is still needed.** Run `nscurl` against every exception domain ([MASTG-TECH-0149](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0149/)). If *ATS Default Connection* passes, the server already meets ATS and the exception is stale; if only the PFS-disabled permutation passes, the server lacks ECDHE. Confirm the server's actual protocols with [GT-0026-TLS-1](#gt-0026-tls-1-backend-protocol-and-cipher-suite-enumeration-server), because `nscurl` on macOS 26 fails every TLS 1.0/1.1 permutation regardless.

   ```bash
   nscurl --ats-diagnostics --verbose https://legacy.example.com
   ```

#### Observation

For each bundle: the ATS dictionary, the list of weakening keys with their domains and values, the subdomain scope, the owner of each domain, the `nscurl` result, and any App Store justification the developer can provide.

#### Evaluation

The test **fails** if any bundle:

1. sets `NSAllowsArbitraryLoads` to true (ATS is off for every unlisted domain);
2. sets `NSExceptionMinimumTLSVersion` (or the `NSTemporary…`/`NSThirdParty…` variant) to `TLSv1.0` or `TLSv1.1` for any domain; or
3. sets `NSExceptionRequiresForwardSecrecy` (or a variant) to `false`/`NO`/`0` for any domain.

Severity depends on scope (one third-party host versus `NSIncludesSubdomains` on the main API domain), on whether the server really needs it (a stale exception is still a failure, but a low one), and on what the network tests show was negotiated. An App Store justification is recorded as context, never as a pass.

#### Demo

[MASTG-DEMO-0109](https://mas.owasp.org/MASTG/demos/ios/MASVS-NETWORK/MASTG-DEMO-0109/MASTG-DEMO-0109/). The sample keeps `NSAllowsArbitraryLoads` false to isolate two per-domain exceptions:

```xml
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <false/>
    <key>NSExceptionDomains</key>
    <dict>
        <key>static-rsa.badssl.com</key>
        <dict>
            <key>NSExceptionMinimumTLSVersion</key>
            <string>TLSv1.2</string>
            <key>NSExceptionRequiresForwardSecrecy</key>
            <false/>
        </dict>
        <key>tls-v1-0.badssl.com</key>
        <dict>
            <key>NSExceptionMinimumTLSVersion</key>
            <string>TLSv1.0</string>
            <key>NSIncludesSubdomains</key>
            <true/>
        </dict>
    </dict>
</dict>
```

OWASP's `gron` pipeline outputs:

```text
json.NSAppTransportSecurity.NSAllowsArbitraryLoads = false;
json.NSAppTransportSecurity.NSExceptionDomains["static-rsa.badssl.com"].NSExceptionMinimumTLSVersion = "TLSv1.2";
json.NSAppTransportSecurity.NSExceptionDomains["static-rsa.badssl.com"].NSExceptionRequiresForwardSecrecy = false;
json.NSAppTransportSecurity.NSExceptionDomains["tls-v1-0.badssl.com"].NSExceptionMinimumTLSVersion = "TLSv1.0";
```

The test fails twice: `tls-v1-0.badssl.com` and all its subdomains may use TLS 1.0, and `static-rsa.badssl.com` may use static-RSA key exchange, so a recording of its traffic can be decrypted later by anyone who obtains the server's private key. The app code simply calls `URLSession.shared.dataTask(with:)` against both hosts; the exceptions alone make the weak handshakes possible. (The demo's Swift comments still label these lines with the ID `MASTG-TEST-0358`; the test that uses the demo is MASTG-TEST-0342.)

### MASTG-TEST-0343: URLSession TLS Protocol Configuration (iOS)

Source: [MASTG-TEST-0343](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0343/). Platform: iOS. Type: static (code) with manual validation. Related knowledge: MASTG-KNOW-0071, MASTG-KNOW-0073. Best practice: MASTG-BEST-0042. Replaces part of MASTG-TEST-0066.

#### Overview

`URLSessionConfiguration.tlsMinimumSupportedProtocolVersion` (and its deprecated predecessor `tlsMinimumSupportedProtocol`) lowers the floor for one session. On its own it does not beat ATS: without a matching exception, ATS still requires TLS 1.2. It is still a finding, for three reasons: it states an intent to talk to legacy servers; combined with an ATS exception from MASTG-TEST-0342 or with a connection ATS does not cover (an IP address on iOS 16 and earlier), it *is* the effective policy; and for apps built with the iOS 26 SDK it is the documented way to undo Apple's new TLS 1.2 default.

#### Prerequisites

- A **decrypted** IPA: App Store binaries are FairPlay-encrypted and their code cannot be analysed until decrypted. `otool -l <binary> | grep -A4 LC_ENCRYPTION_INFO` shows `cryptid 1` for an encrypted binary.
- [radare2](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/) ([MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/)); optionally a jailbroken device with Frida for validation.

#### Steps

1. **List all Mach-O binaries**: the main executable, frameworks and extensions.

   ```bash
   find ipa/Payload -type f -perm -111 -exec file {} + | grep Mach-O
   ```

2. **Triage by selector name.** Swift code that sets the property calls the Objective-C setter, so the selector string appears in the binary:

   ```bash
   for b in ipa/Payload/MyApp.app/MyApp ipa/Payload/MyApp.app/Frameworks/*.framework/*; do
     [ -f "$b" ] && strings -a "$b" | grep -qE 'setTLS(Minimum|Maximum)SupportedProtocol(Version)?:' && echo "$b"
   done
   ```

3. **Find the call sites and the values.** Use OWASP's radare2 approach from [MASTG-DEMO-0110](https://mas.owasp.org/MASTG/demos/ios/MASVS-NETWORK/MASTG-DEMO-0110/MASTG-DEMO-0110/): locate the selector reference and the stub that loads it, then look for the instruction that puts the version in `w2` (on arm64, `x0` = receiver, `x1` = selector, `x2` = first argument) immediately before the call. Because `mov w2, #imm` has a fixed encoding, you can search for the bytes directly:

   | Value | Meaning | Instruction | Bytes to search |
   |---|---|---|---|
   | `0x0301` | `.TLSv10` | `mov w2, 0x301` | `22608052` |
   | `0x0302` | `.TLSv11` | `mov w2, 0x302` | `42608052` |
   | `4` | `kTLSProtocol1` (deprecated setter) | `mov w2, 4` | `82008052` |
   | `7` | `kTLSProtocol11` (deprecated setter) | `mov w2, 7` | `e2008052` |

   ```bash
   r2 -q -A -c 'f~setTLSMinimumSupportedProtocol; /x 22608052; /x 42608052' ipa/Payload/MyApp.app/MyApp
   ```

   For larger scripts, put the commands in a file and use `r2 -q -i script.r2 -A <binary>`, as the OWASP demo does.

   Then disassemble around each hit (`pd -8 @ <hit>` and `pd 4 @ <hit>`) and confirm that the next branch goes to the stub that loads the `setTLSMinimumSupportedProtocolVersion:` selector. Small immediates such as 4 and 7 occur everywhere, so the byte search for the deprecated setter only helps when you check adjacency to the call. If the value is loaded from memory or computed, follow the register back by hand.

4. **Read the ATS policy for the hosts that session talks to** (MASTG-TEST-0342) and the SDK the app was built with (`plutil -extract DTSDKName raw ipa/Payload/MyApp.app/Info.plist`).

5. **Validate at runtime (optional).** Hook every implementation of the setter (the configuration object is a class cluster, so hooking only `NSURLSessionConfiguration` can miss the concrete subclass):

   ```javascript
   // urlsession-tls.js — frida -U -f com.example.app -l urlsession-tls.js
   for (const sel of ['setTLSMinimumSupportedProtocolVersion:', 'setTLSMinimumSupportedProtocol:']) {
     for (const m of new ApiResolver('objc').enumerateMatches(`-[* ${sel}]`)) {
       Interceptor.attach(m.address, {
         onEnter(args) { console.log(`${m.name} -> 0x${args[2].toInt32().toString(16)}`); }
       });
     }
   }
   ```

#### Observation

Each call site with its binary, address, the value set, the session it configures and the hosts it is used for; the ATS policy for those hosts; the build SDK.

#### Evaluation

The test **fails** if the app sets `tlsMinimumSupportedProtocolVersion` to `tls_protocol_version_TLSv10` (`0x0301`) or `tls_protocol_version_TLSv11` (`0x0302`), or the deprecated `tlsMinimumSupportedProtocol` to `kTLSProtocol1` (4) or `kTLSProtocol11` (7) (or to `kSSLProtocol3`, 2). Rate it lower when ATS still enforces TLS 1.2 for every host the session uses, and higher when it combines with an ATS exception, `NSAllowsArbitraryLoads` or IP-address hosts. Setting a *maximum* below TLS 1.2 (`tlsMaximumSupportedProtocolVersion`) is an even stronger signal: it forbids modern versions entirely.

#### Demo

[MASTG-DEMO-0110](https://mas.owasp.org/MASTG/demos/ios/MASVS-NETWORK/MASTG-DEMO-0110/MASTG-DEMO-0110/):

```swift
let configuration = URLSessionConfiguration.ephemeral
configuration.tlsMinimumSupportedProtocolVersion = .TLSv10   // FAIL
let session = URLSession(configuration: configuration)
session.dataTask(with: URL(string: "https://tls-v1-0.badssl.com:1010/")!).resume()
```

OWASP's radare2 script finds the setter and the constant (excerpt):

```text
References to URLSessionConfiguration tlsMinimumSupportedProtocolVersion setter:
0x10000a772 39 str.setTLSMinimumSupportedProtocolVersion:
xrefs to tlsMinimumSupportedProtocolVersion setter:
fcn.1000091a0 0x1000091a4 [DATA:r--] ldr x1, reloc.fixup.setTLSMinimumSupportedProtocolV
0x100004194 hit4_0 22608052
│  0x100004190      mov x24, x0
│  0x100004194      mov w2, 0x301
│  0x100004198      bl fcn.1000091a0
│  0x1000041a8      mov x2, x24
│  0x1000041ac      bl fcn.100009180
```

`fcn.1000091a0` loads the `setTLSMinimumSupportedProtocolVersion:` selector into `x1` and jumps to `objc_msgSend`; `w2 = 0x301` is TLS 1.0; the configured object is then passed to the `URLSession` factory at `0x1000041ac`. The test fails. In the demo app the request itself fails at runtime because there is no ATS exception for that host, which is exactly why the finding is rated on its combination with the ATS policy.

### MASTG-TEST-0344: Network.framework TLS Protocol Configuration (iOS)

Source: [MASTG-TEST-0344](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0344/). Platform: iOS. Type: static (code) with manual validation. Related knowledge: MASTG-KNOW-0073. Best practice: MASTG-BEST-0043. Replaces part of MASTG-TEST-0066.

#### Overview

Network.framework (`NWConnection`, `NWListener`, and iOS 26's `NetworkConnection`) is outside ATS. Its TLS settings live in `NWProtocolTLS.Options().securityProtocolOptions`, a `sec_protocol_options_t` that code configures with `sec_protocol_options_set_min_tls_protocol_version` and `sec_protocol_options_set_max_tls_protocol_version`. Whatever is set takes effect directly; Apple's documentation is explicit that for these APIs "you take responsibility for ensuring the security of the connection". The OWASP test looks for explicit calls with TLS 1.0 or 1.1. We add the implicit case: for apps built with an SDK before iOS 26, the Network.framework default minimum was TLS 1.0, so an `NWConnection` with default TLS options to a legacy server negotiates TLS 1.0 with no call to find.

#### Prerequisites

- A decrypted IPA and radare2, as for MASTG-TEST-0343.
- Optionally a jailbroken device with Frida.

#### Steps

1. **Check whether the framework is used at all** and which TLS functions are imported:

   ```bash
   otool -L ipa/Payload/MyApp.app/MyApp | grep -i network.framework
   nm -u ipa/Payload/MyApp.app/MyApp | grep -E 'sec_protocol_options_(set_(min|max)_tls_protocol_version|set_tls_(min|max)_version|append_tls_ciphersuite|set_verify_block)'
   ```

   `sec_protocol_options_set_tls_min_version` / `..._max_version` are the deprecated `SSLProtocol`-based variants; `append_tls_ciphersuite` changes cipher suites; `set_verify_block` replaces certificate evaluation (record it for [MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/)).

2. **Find the values.** These are plain C calls: `x0` holds the options handle and `w1` the version. Search for the encoded `mov w1, #imm`:

   | Value | Instruction | Bytes |
   |---|---|---|
   | `0x0301` (TLS 1.0) | `mov w1, 0x301` | `21608052` |
   | `0x0302` (TLS 1.1) | `mov w1, 0x302` | `41608052` |

   ```bash
   r2 -q -A -c 'ii~sec_protocol_options; /x 21608052; /x 41608052' ipa/Payload/MyApp.app/MyApp
   ```

   For each hit, `pd -6 @ <hit>` and `pd 3 @ <hit>`: the next `bl` should be `sym.imp.sec_protocol_options_set_min_tls_protocol_version` (or `..._max_...`).

3. **Check the build SDK** (`DTSDKName`, or `otool -l` and the `sdk` field of `LC_BUILD_VERSION`). If it is below iOS 26 and the app creates `NWConnection`s with TLS but never sets a minimum, record that the effective minimum is TLS 1.0.

4. **Validate at runtime (optional).**

   ```javascript
   // nw-tls.js
   const find = n => (Module.findGlobalExportByName ? Module.findGlobalExportByName(n) : Module.findExportByName(null, n));
   for (const n of ['sec_protocol_options_set_min_tls_protocol_version', 'sec_protocol_options_set_max_tls_protocol_version']) {
     const f = find(n);
     if (f) Interceptor.attach(f, { onEnter(args) { console.log(`${n}(0x${args[1].toInt32().toString(16)})`); } });
   }
   ```

#### Observation

The call sites, values and the endpoints those connections use; the build SDK; whether any TLS `NWConnection` relies on the default minimum.

#### Evaluation

The test **fails** if the app calls `sec_protocol_options_set_min_tls_protocol_version` or `sec_protocol_options_set_max_tls_protocol_version` with `tls_protocol_version_TLSv10` (`0x0301`) or `TLSv11` (`0x0302`), or the deprecated variants with the equivalent `SSLProtocol` values. Unlike MASTG-TEST-0343, no ATS policy can soften this: if the server offers TLS 1.0, the connection uses it. Our extension: in an app built with an SDK older than iOS 26, a TLS `NWConnection` without an explicit minimum of TLS 1.2 is reported as a Low finding (it inherits a TLS 1.0 floor), raised if a capture shows a legacy version negotiated.

#### Demo

[MASTG-DEMO-0111](https://mas.owasp.org/MASTG/demos/ios/MASVS-NETWORK/MASTG-DEMO-0111/MASTG-DEMO-0111/):

```swift
let tlsOptions = NWProtocolTLS.Options()
// FAIL: minimum (and here also maximum) set to TLS 1.0, outside any ATS policy
sec_protocol_options_set_min_tls_protocol_version(tlsOptions.securityProtocolOptions, .TLSv10)
sec_protocol_options_set_max_tls_protocol_version(tlsOptions.securityProtocolOptions, .TLSv10)
sec_protocol_options_set_tls_server_name(tlsOptions.securityProtocolOptions, "tls-v1-0.badssl.com")
let connection = NWConnection(host: "tls-v1-0.badssl.com", port: 1010, using: NWParameters(tls: tlsOptions))
connection.start(queue: .main)
```

The radare2 output (excerpt) shows both calls with `w1 = 0x301`:

```text
0x1000041d4 hit4_0 21608052
0x1000041f0 hit4_1 21608052
│  0x1000041cc      bl sym.imp.Network.NWProtocolTLS.Options.allocator.securityProtocol_...vgTj_
│  0x1000041d0      mov x20, x0
│  0x1000041d4      mov w1, 0x301
│  0x1000041d8      bl sym.imp.sec_protocol_options_set_min_tls_protocol_version
│  0x1000041e8      bl sym.imp.Network.NWProtocolTLS.Options.allocator.securityProtocol_...vgTj_
│  0x1000041ec      mov x20, x0
│  0x1000041f0      mov w1, 0x301
│  0x1000041f4      bl sym.imp.sec_protocol_options_set_max_tls_protocol_version
```

The connection is pinned to TLS 1.0 only: it cannot negotiate anything better even with a modern server. The test fails, and the maximum makes it worse than a lowered minimum alone.

### MASTG-TEST-0345: Embedded or Third-party TLS Stack Configuration (iOS)

Source: [MASTG-TEST-0345](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0345/). Platform: iOS. Type: static (code) with manual validation. Related knowledge: MASTG-KNOW-0073. Best practice: MASTG-BEST-0043. Replaces part of MASTG-TEST-0066. OWASP provides no demo; ours is below. The same procedure applies to Android native libraries ([GT-0026-TLS-3](#gt-0026-tls-3-native-and-cross-platform-tls-stacks-android)).

#### Overview

Some apps bring their own TLS: OpenSSL or BoringSSL (often inside a VoIP, video, VPN, database-sync or game SDK), mbedTLS or wolfSSL (IoT companion apps), libcurl, gRPC-Core, or a cross-platform runtime. None of them is governed by ATS or by `URLSession` settings, and their configuration APIs can set the minimum and maximum version, the cipher list, the verification mode and the trust store. The test identifies such stacks and checks how they are configured.

#### Prerequisites

- A decrypted IPA; `otool` ([MASTG-TOOL-0060](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0060/)), `nm`, `strings`, radare2.
- Optionally a jailbroken device with Frida.

#### Steps

1. **Identify bundled libraries** ([MASTG-TECH-0082](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0082/)): frameworks and dylibs in the bundle, load commands of every Mach-O, and fingerprints of statically linked code.

   ```bash
   ls ipa/Payload/MyApp.app/Frameworks/
   otool -L ipa/Payload/MyApp.app/MyApp | grep -v -E '^\s*/(System|usr/lib)/'
   for b in $(find ipa/Payload -type f -perm -111); do
     strings -a "$b" | grep -m1 -E -o '(OpenSSL [0-9]\.[0-9.]+[a-z]?|BoringSSL|[Mm]bed ?TLS [0-9.]+|wolfSSL [0-9.]+|libcurl/[0-9.]+|grpc-c/[0-9.]+)' | sed "s|^|$b: |"
   done
   ```

2. **Find the configuration calls.** For dynamically linked libraries, the app binary imports them by name; for exported frameworks you can confirm the library's own symbols:

   ```bash
   nm -u ipa/Payload/MyApp.app/MyApp | grep -E 'SSL_CTX_(set_min_proto_version|set_max_proto_version|ctrl|set_options|set_cipher_list|set_ciphersuites|set_verify)|TLSv1(_1)?_(client_)?method|SSLv3_(client_)?method|mbedtls_ssl_conf_(min_(tls_)?version|ciphersuites|authmode)|curl_easy_setopt'
   ```

   For statically linked, stripped code, rely on strings that configuration leaves behind (cipher strings and their tell-tale tokens) and on cross-references from them:

   ```bash
   strings -a ipa/Payload/MyApp.app/MyApp | grep -E '@SECLEVEL=0|(^|:)ALL(:|$)|aNULL|eNULL|RC4|3DES|EXPORT|NULL-SHA'
   ```

3. **Determine the values** at each call site with radare2 ([MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/)):

   | Library | What to look for | Insecure values |
   |---|---|---|
   | OpenSSL 1.1+/3.x | `SSL_CTX_set_min_proto_version(ctx, v)` is a macro for `SSL_CTX_ctrl(ctx, 123, v, NULL)` (max: `124`) | `v` = `0x0300`/`0x0301`/`0x0302`, or `0` (library minimum) |
   | BoringSSL | `SSL_CTX_set_min_proto_version` is a real function | Same values |
   | Either, legacy | `TLSv1_client_method`, `TLSv1_1_client_method`, `SSLv3_client_method`; `SSL_CTX_set_options` with `SSL_OP_NO_TLSv1_2`/`_3` | Any of them |
   | Either | `SSL_CTX_set_cipher_list` / `SSL_CTX_set_ciphersuites` | `ALL`, `@SECLEVEL=0`, `aNULL`, `eNULL`, `RC4`, `3DES`, `EXPORT` |
   | Either | `SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, …)` | `SSL_VERIFY_NONE` (0): MASWE-0027 |
   | mbedTLS 2.x | `mbedtls_ssl_conf_min_version(conf, 3, minor)` | minor `1` (TLS 1.0) or `2` (TLS 1.1) |
   | mbedTLS 3.x | `mbedtls_ssl_conf_min_tls_version(conf, v)` (TLS 1.0/1.1 support was removed in 3.0) | anything below `0x0303` is impossible; check `mbedtls_ssl_conf_authmode` for `MBEDTLS_SSL_VERIFY_NONE`/`OPTIONAL` |
   | libcurl | `curl_easy_setopt(h, CURLOPT_SSLVERSION /* 32 */, v)` | `CURL_SSLVERSION_TLSv1_0` (4), `_TLSv1_1` (5), `_SSLv3` (3), `_TLSv1` (1, "1.x or later"; floor depends on curl version and backend) |
   | libcurl | `CURLOPT_SSL_VERIFYPEER` (64), `CURLOPT_SSL_VERIFYHOST` (81), `CURLOPT_SSL_CIPHER_LIST` (10083) | `0` for the verify options: MASWE-0027; weak cipher list |

4. **Validate at runtime (optional).** Hook only the copies of these functions shipped inside the app bundle, not the system's:

   ```javascript
   // embedded-tls.js
   const watch = {
     SSL_CTX_set_min_proto_version: a => `min=0x${a[1].toInt32().toString(16)}`,
     SSL_CTX_ctrl: a => (a[1].toInt32() === 123 ? `ctrl SET_MIN_PROTO_VERSION=0x${a[2].toInt32().toString(16)}` : null),
     SSL_CTX_set_cipher_list: a => `cipher_list=${a[1].readCString()}`,
     mbedtls_ssl_conf_min_tls_version: a => `mbedtls min=0x${a[1].toInt32().toString(16)}`,
     curl_easy_setopt: a => ([32, 64, 81].includes(a[1].toInt32()) ? `curl opt ${a[1].toInt32()}=${a[2].toInt32()}` : null),
   };
   for (const m of Process.enumerateModules().filter(m => m.path.includes('.app/'))) {
     for (const [name, fmt] of Object.entries(watch)) {
       const f = m.findExportByName(name);
       if (f) Interceptor.attach(f, { onEnter(args) { const s = fmt(args); if (s) console.log(`${m.name}!${name} ${s}`); } });
     }
   }
   ```

   Libraries loaded late (on first use of a feature) are not in the module list at spawn; re-run the loop from the REPL after triggering the feature.

5. **Confirm on the wire** with [MASTG-TEST-0348](#mastg-test-0348-insecure-tls-protocols-in-network-traffic-ios). An embedded stack usually has a recognisably different ClientHello from Apple's (different extension order and groups; no `X25519MLKEM768` on iOS 26), which helps attribute connections.

#### Observation

The list of embedded TLS libraries with versions and locations, each configuration call with its values, the features and endpoints that use it, and (if validated) the runtime log.

#### Evaluation

The test **fails** if any embedded TLS library is configured to allow versions below TLS 1.2, to use weak or deprecated cipher suites (NULL, anonymous, export, RC4, 3DES, static RSA, or a blanket `ALL`/`@SECLEVEL=0`), or to skip certificate verification or trust a custom store without proper validation. Report the last case under MASWE-0027 and cross-reference it. A bundled library version with known TLS vulnerabilities (an end-of-life OpenSSL 1.0.x, for example) is a separate dependency finding (see [MASTG-KNOW-0004](/mobile/mastg-know-0004-third-party-libraries/)), but mention it here.

#### Demo

Our sample (Guler Tech): a telemetry SDK that ships OpenSSL as `Frameworks/openssl.framework` and configures it from Objective-C:

```objectivec
SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);        // FAIL: TLS 1.0 floor
SSL_CTX_set_cipher_list(ctx, "ALL:@SECLEVEL=0");         // FAIL: every suite, including NULL/anonymous
SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);          // FAIL: no certificate verification (MASWE-0027)
```

Detection output:

```text
$ strings -a .../Frameworks/openssl.framework/openssl | grep -m1 -oE 'OpenSSL [0-9]\.[0-9.]+[a-z]?'
OpenSSL 1.1.1w
$ nm -u ipa/Payload/MyApp.app/MyApp | grep -E 'SSL_CTX_(ctrl|set_cipher_list|set_verify)'
_SSL_CTX_ctrl
_SSL_CTX_set_cipher_list
_SSL_CTX_set_verify
$ strings -a ipa/Payload/MyApp.app/MyApp | grep '@SECLEVEL'
ALL:@SECLEVEL=0
```

In radare2 the `SSL_CTX_ctrl` call site loads `w1 = 0x7b` (123, `SSL_CTRL_SET_MIN_PROTO_VERSION`) and `x2 = 0x301`, and the `SSL_CTX_set_verify` call site loads `w1 = 0`. The test fails on all three counts; the verification failure is rated under MASWE-0027 and is by far the most serious of the three.

### MASTG-TEST-0348: Insecure TLS Protocols in Network Traffic (iOS)

Source: [MASTG-TEST-0348](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0348/). Platform: iOS. Type: dynamic (network). Replaces part of MASTG-TEST-0066. OWASP provides no demo; ours is below.

#### Overview

The iOS counterpart of MASTG-TEST-0218: capture the app's real traffic and read the negotiated version for every connection. On iOS this matters most for the connections the static tests cannot fully resolve: ATS exceptions whose servers you have not checked, Network.framework connections in apps built with older SDKs, IP-address connections outside ATS, and embedded stacks.

#### Prerequisites

- The app installed on a physical device ([MASTG-TECH-0056](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0056/)). Do not use the Simulator: it uses the Mac's network stack, and on macOS 26 that refuses TLS 1.0/1.1 regardless of the app.
- A Mac with Xcode for `rvictl`, or a gateway you control ([MASTG-TECH-0062](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0062/)). No interception proxy.
- tshark or Wireshark.

#### Steps

1. **Start the capture.**

   ```bash
   xcrun xctrace list devices          # or: idevice_id -l  — to get the UDID
   rvictl -s <UDID>                     # creates rvi0
   sudo tcpdump -i rvi0 -s 0 -w app.pcap
   ```

2. **Exercise the app** as in MASTG-TEST-0218: first launch, login, every feature, background refresh, push handling, logout. Make sure you trigger the features that use the hosts from MASTG-TEST-0342 exceptions and the Network.framework or embedded-stack code from MASTG-TEST-0344/0345.

3. **Stop and clean up:** `Ctrl-C`, then `rvictl -x <UDID>`.

4. **Analyse** with the tshark commands and filters in [Before you start](#before-you-start-client-offer-server-acceptance-and-negotiated-version). On iOS 26, Apple's stack (`URLSession`, Network.framework) offers `X25519MLKEM768` in `supported_groups`; a ClientHello from the app without it most likely comes from an embedded library, which tells you which code to look at:

   ```bash
   tshark -r app.pcap -Y 'tls.handshake.type == 1' -T fields \
     -e tls.handshake.extensions_server_name -e tls.handshake.extensions_supported_group | sort -u
   ```

   (`X25519MLKEM768` has the group code `0x11ec`.)

5. **Follow up** negotiated legacy versions with GT-0026-TLS-1 and the static tests, and hidden floors with GT-0026-TLS-2.

#### Observation

The pcap and the per-host table (SNI, ceiling, offer, negotiated version, cipher suite, triggering feature, and which stack produced the ClientHello).

#### Evaluation

The test **fails** if any connection made by the app negotiates SSL 3.0, TLS 1.0 or TLS 1.1. As on Android, we also fail it for negotiated NULL, anonymous, export, RC4 or 3DES suites, record static-RSA suites negotiated under an `NSExceptionRequiresForwardSecrecy = false` exception, and note ClientHellos that offer legacy versions. A pass covers only the flows you exercised.

#### Demo

Our sample (Guler Tech): the app from the MASTG-TEST-0342 demo, built with the iOS 18 SDK and run on an iOS 18 device, plus a telemetry connection from the embedded OpenSSL in the MASTG-TEST-0345 demo. Joined output:

```text
api.example.com	0x0303	0x0304,0x0303	0x0304	0x1301
static-rsa.badssl.com	0x0303	0x0304,0x0303	0x0303	0x009c
tls-v1-0.badssl.com	0x0303	0x0304,0x0303,0x0302,0x0301	0x0301	0xc014
telemetry.example.org	0x0303	0x0304,0x0303,0x0302,0x0301	0x0304	0x1302
```

Reading it: `api.example.com` is clean. `static-rsa.badssl.com` negotiated TLS 1.2 with `TLS_RSA_WITH_AES_128_GCM_SHA256` (`0x009c`): no forward secrecy, made possible by the ATS exception. For `tls-v1-0.badssl.com`, Apple's stack offered TLS 1.0 and 1.1 only to that host (the other hosts' ClientHellos list `0x0304,0x0303`), reflecting the per-domain ATS exception, and the server chose TLS 1.0: the test fails. The embedded OpenSSL offers TLS 1.0 to `telemetry.example.org`, but that server picked TLS 1.3, so the configuration flaw is real (MASTG-TEST-0345) but did not lead to a legacy handshake in this session.

### Supplementary checks (Guler Tech methodology)

The OWASP tests cover the client's configuration and one capture. Three gaps remain: what the servers accept, what the client accepts when a server offers nothing better, and native or cross-platform TLS stacks on Android. The checks below close them. They are not OWASP tests; we label them GT-0026-TLS-n.

### GT-0026-TLS-1: Backend protocol and cipher suite enumeration (server)

#### Overview

Enumerate the protocol versions and cipher suites each backend accepts. This is a **server** finding in its own right, and it is the other half of every negotiated legacy handshake. It also answers whether a client-side weakness is exploitable: a client that permits TLS 1.0 talking only to servers that refuse it has a latent flaw; one talking to a server that accepts it has a live one.

> **Warning:** Scan only hosts that are in scope and that you are authorised to test. Third-party APIs, CDNs and SDK endpoints the app talks to usually are not. For those, rely on the passive evidence from MASTG-TEST-0218/0348 and report the observation to the app owner.

#### Prerequisites

- The host list: every SNI from your captures plus host names found statically (code, `Info.plist` exception domains, configuration files), with ports.
- [testssl.sh](https://testssl.sh/), nmap with the `ssl-enum-ciphers` script, and an OpenSSL 3.x `openssl` binary (on macOS, `/usr/bin/openssl` is LibreSSL; use Homebrew's).

#### Steps

1. **testssl.sh** uses its own sockets for legacy protocols, so it is not limited by your local OpenSSL build:

   ```bash
   testssl.sh -p -s -f -E -U --jsonfile api.example.com.json https://api.example.com
   # Several hosts:  testssl.sh -p -s -f --file hosts.txt
   # Several IPs behind one name (CDNs, regional load balancers):
   dig +short api.example.com
   testssl.sh -p --ip 203.0.113.10 https://api.example.com
   ```

   `-p` tests protocols, `-s` cipher categories (NULL, anonymous, export, 3DES, …), `-f` forward secrecy, `-E` every cipher per protocol, `-U` known vulnerabilities including the `TLS_FALLBACK_SCSV` check.

2. **nmap** gives a compact per-protocol cipher list with grades. Set the SNI explicitly, because CDNs serve different configurations per name:

   ```bash
   nmap -Pn -p 443 --script ssl-enum-ciphers --script-args tls.servername=api.example.com api.example.com
   ```

3. **openssl s_client** gives a yes/no per version that you can paste into a report. With OpenSSL 3.x you must lower the *local* security level, or the client refuses TLS 1.0/1.1 before sending anything and you get a false "not supported":

   ```bash
   OPENSSL=/opt/homebrew/opt/openssl@3/bin/openssl
   for v in -tls1 -tls1_1 -tls1_2 -tls1_3; do
     printf '%-8s ' "$v"
     "$OPENSSL" s_client -connect api.example.com:443 -servername api.example.com $v \
       -cipher 'DEFAULT:@SECLEVEL=0' -brief </dev/null 2>&1 | grep -m1 -E 'Protocol version|alert|error'
   done
   # A specific weak suite, e.g. static RSA over TLS 1.2:
   "$OPENSSL" s_client -connect api.example.com:443 -servername api.example.com -tls1_2 -cipher 'AES128-SHA' -brief </dev/null
   ```

   `no protocols available` means your local client refused (fix the security level); `tlsv1 alert protocol version` means the *server* refused.

4. **Check the downgrade defences** in the testssl.sh output: TLS 1.3 support (which brings the downgrade sentinel) and `TLS_FALLBACK_SCSV` support.

#### Observation

Per host and IP: accepted protocol versions, accepted cipher suites per version, forward secrecy, `TLS_FALLBACK_SCSV`, TLS 1.3 support, and the raw tool output.

#### Evaluation

The server **fails** if it accepts SSL 2.0/3.0, TLS 1.0 or TLS 1.1, or any NULL, anonymous, export, RC4 or 3DES suite; we also record static-RSA suites and missing TLS 1.3 (required by NIST SP 800-52r2 from 2024). Then cross-reference with the client results: report a *server* finding to the backend owner in every case, and raise the *app* finding only when the app offers or negotiates the same weak option.

#### Demo

Our sample output (abbreviated) for a backend that still accepts legacy versions:

```text
 Testing protocols via sockets except NPN+ALPN

 SSLv2      not offered (OK)
 SSLv3      not offered (OK)
 TLS 1      offered (deprecated)
 TLS 1.1    offered (deprecated)
 TLS 1.2    offered (OK)
 TLS 1.3    not offered and downgraded to a weaker protocol
```

```text
PORT    STATE SERVICE
443/tcp open  https
| ssl-enum-ciphers:
|   TLSv1.0:
|     ciphers:
|       TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (secp256r1) - A
|       TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C
|     warnings:
|       64-bit block cipher 3DES vulnerable to SWEET32 attack
|   TLSv1.2:
|     ciphers:
|       TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (secp256r1) - A
|_  least strength: C
```

The server fails (TLS 1.0, TLS 1.1, 3DES, no TLS 1.3). Without TLS 1.3 there is no downgrade sentinel, so this server is also the kind of host where an app's fallback logic would be exploitable.

### GT-0026-TLS-2: Active client acceptance test with a legacy-only endpoint (Android, iOS)

#### Overview

A capture only shows what happened with the servers you met. To learn the client's *floor* (whether it would accept TLS 1.0 if a server, or an attacker standing in for one, offered nothing better), you have to offer it a legacy-only handshake. This is the only way to measure the effective policy when static analysis is inconclusive, when a ClientHello has no `supported_versions`, or when you need to confirm what Conscrypt or iOS actually allows on the test device.

#### Prerequisites

- The interception set-up from our [lab note](/mobile/mobile-traffic-interception-lab/): the device trusts your mitmproxy CA (on Android, as a system CA or through a debug build's `<debug-overrides>`), and traffic reaches mitmproxy. Use mitmproxy's WireGuard mode (`mitmproxy --mode wireguard`) for traffic that ignores the system proxy, such as Network.framework, embedded stacks and Flutter.
- If the app pins certificates, a pinning bypass ([MASWE-0028](/mobile/maswe-0028-insecure-identity-pinning/)). Check that the bypass does not replace the app's `SSLContext` or socket factory with its own, which would change the version policy you are trying to measure; the control run in step 2 tells you.

#### Steps

1. **Log the outcome of every client handshake** with a small mitmproxy addon:

   ```python
   # tlslog.py
   from mitmproxy import tls

   def tls_established_client(data: tls.TlsData) -> None:
       c = data.conn
       print(f"ACCEPTED  {c.sni}  {c.tls_version}  {c.cipher}")

   def tls_failed_client(data: tls.TlsData) -> None:
       c = data.conn
       print(f"REFUSED   {c.sni}  {c.error}")
   ```

2. **Control run** with mitmproxy's defaults (client side TLS 1.2 minimum). The app should work and the log should show `TLSv1.3` or `TLSv1.2` for each host. If it does not, fix the set-up before going on.

   ```bash
   mitmdump -s tlslog.py
   ```

3. **Legacy runs.** Restrict the device-facing side to one legacy version at a time and exercise the same features:

   ```bash
   mitmdump -s tlslog.py --set tls_version_client_min=TLS1   --set tls_version_client_max=TLS1
   mitmdump -s tlslog.py --set tls_version_client_min=TLS1_1 --set tls_version_client_max=TLS1_1
   ```

   mitmproxy lowers its own OpenSSL security level automatically for these versions. `SSL3` is accepted as a value but most current OpenSSL builds cannot speak SSL 3.0 at all.

4. **Weak cipher run (optional).** Offer only a static-RSA suite over TLS 1.2 to see whether the client accepts a non-forward-secret handshake:

   ```bash
   mitmdump -s tlslog.py --set tls_version_client_max=TLS1_2 --set ciphers_client='AES128-SHA:@SECLEVEL=0'
   ```

5. **Without mitmproxy** (for clients that will not use any proxy or VPN path), run a legacy-only server you control and point the host name at it with your lab DNS (for example `address=/legacy.example.com/192.168.50.10` in dnsmasq). The certificate must chain to a CA the app trusts on the test device:

   ```bash
   openssl s_server -accept 443 -cert legacy.example.com.pem -key legacy.example.com.key \
     -tls1 -cipher 'DEFAULT:@SECLEVEL=0' -www
   ```

#### Observation

Per host and per run: `ACCEPTED` with version and cipher, or `REFUSED` with the error; the device's OS version (and on Android the Conscrypt module version, from *Settings → Security → Google Play system update* or `adb shell pm list packages --apex-only --show-versioncode | grep conscrypt`), and the app's `targetSdkVersion` or build SDK.

#### Evaluation

The client **fails** if any handshake completes at SSL 3.0, TLS 1.0 or TLS 1.1, or (step 4) with a static-RSA suite where the platform should require forward secrecy (for example a `URLSession` host without an ATS exception). Distinguish the errors: a `protocol_version` alert or "unsupported protocol" from the client is a **pass**; a certificate or "unknown CA" error means the set-up failed (trust or pinning), not that the client refused the version.

#### Demo

Our sample (Guler Tech): the Android app from the MASTG-TEST-0217 demo on an Android 11 device, TLS 1.0-only run:

```text
REFUSED   api.example.com     Client TLS handshake failed: unsupported protocol
ACCEPTED  api.example.com     TLSv1  ECDHE-RSA-AES256-SHA
ACCEPTED  legacy.example.com  TLSv1  ECDHE-RSA-AES256-SHA
```

The OkHttp client for `api.example.com` offered TLS 1.2/1.3 first (`MODERN_TLS`), failed, and immediately reconnected with `COMPATIBLE_TLS`, which completed at TLS 1.0: the fallback from the MASTG-TEST-0217 demo, confirmed. Against the real backend, an active attacker on the same network could cause the first failure (by resetting the connection) and push the app to TLS 1.0 whenever that server lacks TLS 1.3 and `TLS_FALLBACK_SCSV` enforcement (see GT-0026-TLS-1). The gateway socket accepted TLS 1.0 directly; in the control run it was the one host that *failed*, because its sparse protocol list leaves it able to speak only TLS 1.0. Repeat the legacy run on the newest Android version you test: if the platform there refuses TLS 1.0 for both clients, the finding is limited to the older devices the app's `minSdkVersion` still admits. (mitmproxy's exact error text varies between versions; what matters is which side refused.)

### GT-0026-TLS-3: Native and cross-platform TLS stacks (Android)

#### Overview

MASTG-TEST-0345 has no Android counterpart in OWASP's test set, but the same weakness is common on Android: `.so` libraries with OpenSSL, BoringSSL, mbedTLS, wolfSSL or libcurl, and runtimes that bring their own TLS. Flutter's Dart `HttpClient` uses the BoringSSL inside `libflutter.so`; .NET MAUI and Xamarin apps can set `SslProtocols` and `ServicePointManager.SecurityProtocol`; game engines and VoIP SDKs often embed curl or OpenSSL. None of them reads the Network Security Configuration.

#### Prerequisites

- The APK and its ABI split; `unzip`, `strings`, `llvm-nm` or GNU `nm`, radare2 ([MASTG-TOOL-0028](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0028/)) or Ghidra; Frida on a device.

#### Steps

1. **List and fingerprint the native libraries:**

   ```bash
   unzip -o -q base.apk 'lib/*' -d apk-native; unzip -o -q split_config.arm64_v8a.apk 'lib/*' -d apk-native 2>/dev/null
   for so in apk-native/lib/arm64-v8a/*.so; do
     strings -a "$so" | grep -m1 -E -o '(OpenSSL [0-9]\.[0-9.]+[a-z]?|BoringSSL|[Mm]bed ?TLS [0-9.]+|wolfSSL [0-9.]+|libcurl/[0-9.]+)' | sed "s|^|$so: |"
   done
   ```

2. **Find configuration calls** with the same symbols and values as in the [MASTG-TEST-0345 table](#mastg-test-0345-embedded-or-third-party-tls-stack-configuration-ios), using the ELF dynamic symbol table:

   ```bash
   llvm-nm -D apk-native/lib/arm64-v8a/libsdk.so | grep -E 'SSL_CTX_(set_min_proto_version|ctrl|set_cipher_list|set_verify)|mbedtls_ssl_conf_(min_(tls_)?version|authmode)|curl_easy_setopt'
   strings -a apk-native/lib/arm64-v8a/libsdk.so | grep -E '@SECLEVEL=0|aNULL|eNULL|RC4|3DES'
   ```

   `U` entries are imports (the library calls the function); `T` entries are definitions (the library contains the TLS stack).

3. **Managed runtimes.** Decompile .NET assemblies (for example with ILSpy) and search for `SslProtocols.Tls`, `SslProtocols.Tls11`, `SecurityProtocolType.Tls`, `SecurityProtocolType.Ssl3` and `ServicePointManager.SecurityProtocol`. For Flutter, the Dart code is AOT-compiled into `libapp.so`; static review is hard, so rely on GT-0026-TLS-2 (in WireGuard mode, since Dart ignores the system proxy).

4. **Hook at runtime** with the `embedded-tls.js` script from MASTG-TEST-0345, changing the module filter to the app's own libraries: `m.path.includes('/data/app/')`.

5. **Confirm on the wire** with MASTG-TEST-0218 and GT-0026-TLS-2.

#### Observation

Embedded TLS libraries with versions, configuration calls and values, the features that use them, runtime logs and the resulting handshakes.

#### Evaluation

Same criteria as MASTG-TEST-0345: the check fails if any embedded stack allows versions below TLS 1.2, weak cipher suites, or (reported under MASWE-0027) disabled verification.

## Best practices

### MASTG-BEST-0042: Use Strong TLS Settings in ATS Configuration

Source: [MASTG-BEST-0042](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0042/). Platform: iOS.

- Do not set `NSExceptionMinimumTLSVersion` to `TLSv1.0` or `TLSv1.1`. If a third-party service needs it, ask the provider to upgrade, record the exception as temporary and remove it when the server is fixed.
- Do not set `NSExceptionRequiresForwardSecrecy` to false; get the server to support ECDHE instead.
- Do not set `tlsMinimumSupportedProtocolVersion` (or the deprecated `tlsMinimumSupportedProtocol`) below TLS 1.2. Leaving it unset inherits the ATS minimum.
- Use `URLSession` for HTTPS so that ATS applies.
- When an exception is unavoidable: one domain, no `NSIncludesSubdomains` unless every subdomain needs it, never `NSAllowsArbitraryLoads`, and an App Store justification.

### MASTG-BEST-0043: Enforce Strong TLS Settings When ATS Doesn't Apply

Source: [MASTG-BEST-0043](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0043/). Platform: iOS.

When code uses Network.framework, CFNetwork, sockets or an embedded library, ATS does not help, so set the policy explicitly. For Network.framework:

```swift
let tlsOptions = NWProtocolTLS.Options()
sec_protocol_options_set_min_tls_protocol_version(tlsOptions.securityProtocolOptions, .TLSv12)
let connection = NWConnection(host: "api.example.com", port: 443, using: NWParameters(tls: tlsOptions))
```

For embedded libraries: minimum TLS 1.2, forward-secret AEAD suites only, full certificate chain and host name validation, and a regular update cycle, because no operating-system mechanism will catch a misconfiguration inside a bundled library.

### Secure configuration for Android and the backend (Guler Tech)

**OkHttp.** Keep the default (`MODERN_TLS` plus `CLEARTEXT`, with cleartext then blocked by the Network Security Configuration), or tighten it. Use a single TLS spec so there is nothing to fall back to:

```kotlin
val client = OkHttpClient.Builder()
    .connectionSpecs(listOf(ConnectionSpec.RESTRICTED_TLS))   // TLS 1.3/1.2, ECDHE + AEAD only; also refuses http://
    .build()
```

Test `RESTRICTED_TLS` against every backend first: it will not connect to a server without ECDHE-GCM or ChaCha20 suites, which is the point.

**Raw `SSLSocket`.** Filter the supported list instead of naming versions, and remember that `SSLSocket` does not verify the host name:

```kotlin
val socket = SSLContext.getDefault().socketFactory.createSocket(host, 443) as SSLSocket
socket.enabledProtocols = socket.supportedProtocols
    .filter { it == "TLSv1.3" || it == "TLSv1.2" }
    .toTypedArray()
val session = socket.session   // performs the handshake
if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(host, session)) {
    socket.close()
    throw SSLPeerUnverifiedException("Host name mismatch: $host")
}
```

**Old devices.** If `minSdkVersion` is below 29, call `ProviderInstaller.installIfNeeded(context)` (or the async variant) before the first connection on devices with Google Play services, and consider bundling Conscrypt elsewhere ([MASTG-BEST-0020](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0020/)).

**Backend.** The fix most findings actually need. For nginx (adapt for your server; Mozilla's [SSL Configuration Generator](https://ssl-config.mozilla.org/) produces equivalent settings for other servers):

```text
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers off;
```

On managed load balancers, select a TLS 1.2+/1.3 policy (on AWS, for example, `ELBSecurityPolicy-TLS13-1-2-2021-06`) and remember that CDNs and API gateways in front of the origin have their own settings. Add a testssl.sh run to the deployment pipeline so a regression fails the build.

## Rating findings

Rate on three things: **what is actually reachable on the wire** (permitted by the client, accepted by the server, or negotiated), **how weak the result is** (a legacy version with ECDHE and AES is not the same as SSL 3.0 or a NULL suite), and **the attacker position it needs** (passive observer on the same network, active machine-in-the-middle such as a rogue access point or ARP/DNS spoofing on shared Wi-Fi, or someone who later obtains a server key). The cleartext-equivalent cases at the top need only an on-path attacker; most version findings need an active one and a server that cooperates.

| Rating | Conditions |
|---|---|
| **Critical** | Credentials, tokens or regulated data sent over a connection that negotiates (or that the client accepts with) a NULL or anonymous cipher suite: equivalent to cleartext or to no server authentication for any on-path attacker. Embedded stack with a legacy floor *and* verification disabled is rated under MASWE-0027 and usually lands here. |
| **High** | SSL 3.0 negotiated or accepted by the client for sensitive traffic; export-grade or RC4 suites negotiated; the client implements version fallback that reaches SSL 3.0 or such suites. |
| **Medium** | Sensitive traffic observed negotiating TLS 1.0/1.1 in normal use (client accepts, server chooses); a client with version fallback (for example `listOf(MODERN_TLS, COMPATIBLE_TLS)`) talking to a backend without TLS 1.3 or `TLS_FALLBACK_SCSV`; 3DES negotiated; static-RSA negotiated for sensitive traffic because of `NSExceptionRequiresForwardSecrecy = false` or client cipher configuration; a Network.framework or embedded-stack minimum of TLS 1.0 on a connection to a server that accepts it; `NSAllowsArbitraryLoads` (report once, with the cleartext note). |
| **Low** | The client permits or offers TLS 1.0/1.1 (code, OkHttp `COMPATIBLE_TLS`, ATS exception, `tlsMinimumSupportedProtocolVersion`, pre-iOS 26 Network.framework default) but every backend you observed negotiates TLS 1.2+ and refuses legacy versions; a stale ATS exception the server no longer needs; a backend that accepts TLS 1.0/1.1 or weak suites while the app never offers them (report to the backend owner as a server finding); a legacy setting that only takes effect on Android versions below the device population the app realistically supports. |
| **Info** | TLS 1.2 without TLS 1.3; narrowly scoped, justified exceptions for third-party hosts with a removal plan; library code containing legacy protocol names that the app never uses; `setEnabledProtocols` calls that only raise the version. |

Raise one level for apps handling payment, health or authentication data for other systems, or when PCI DSS or NIST SP 800-52r2 compliance is in scope, because the configuration is then non-compliant regardless of exploitability. Lower one level when the only path to the weak handshake is through an endpoint you could not show the app actually uses. In the report, separate the **client finding** (the code or `Info.plist` entry, the effective policy on named OS versions, the active-test result) from the **server finding** (host, IP, accepted versions and suites, tool output), state which one produced a negotiated legacy handshake and on which flow, and give each fix to its owner.

## References

- OWASP MASWE — [MASWE-0026: Network Traffic Not Encrypted](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0026/) (CC BY-SA 4.0)
- OWASP MASVS — [MASVS-NETWORK-1](https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-1/) (CC BY-SA 4.0)
- OWASP MASTG — knowledge [MASTG-KNOW-0071: iOS App Transport Security](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-NETWORK/MASTG-KNOW-0071/), [MASTG-KNOW-0073: iOS Network APIs](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-NETWORK/MASTG-KNOW-0073/) (CC BY-SA 4.0)
- OWASP MASTG — tests [MASTG-TEST-0217](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0217/), [MASTG-TEST-0218](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0218/), [MASTG-TEST-0342](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0342/), [MASTG-TEST-0343](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0343/), [MASTG-TEST-0344](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0344/), [MASTG-TEST-0345](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0345/), [MASTG-TEST-0348](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0348/); legacy (MASTG v1) tests [MASTG-TEST-0020](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0020/), [MASTG-TEST-0066](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0066/) (CC BY-SA 4.0)
- OWASP MASTG — demos [MASTG-DEMO-0109](https://mas.owasp.org/MASTG/demos/ios/MASVS-NETWORK/MASTG-DEMO-0109/MASTG-DEMO-0109/), [MASTG-DEMO-0110](https://mas.owasp.org/MASTG/demos/ios/MASVS-NETWORK/MASTG-DEMO-0110/MASTG-DEMO-0110/), [MASTG-DEMO-0111](https://mas.owasp.org/MASTG/demos/ios/MASVS-NETWORK/MASTG-DEMO-0111/MASTG-DEMO-0111/) (CC BY-SA 4.0)
- OWASP MASTG — best practices [MASTG-BEST-0042](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0042/), [MASTG-BEST-0043](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0043/), [MASTG-BEST-0020](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0020/), [MASTG-BEST-0010](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0010/) (CC BY-SA 4.0)
- OWASP MASTG — techniques [MASTG-TECH-0005](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/), [MASTG-TECH-0010](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0010/), [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0056](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0056/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0062](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0062/), [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/), [MASTG-TECH-0082](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0082/), [MASTG-TECH-0138](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0138/), [MASTG-TECH-0149](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0149/), [MASTG-TECH-0153](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0153/), [MASTG-TECH-0155](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0155/) (CC BY-SA 4.0)
- OWASP MASTG — tools [adb (MASTG-TOOL-0004)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0004/), [Apktool (MASTG-TOOL-0011)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/), [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [radare2 for Android (MASTG-TOOL-0028)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0028/), [Frida (MASTG-TOOL-0031)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/), [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/), [otool (MASTG-TOOL-0060)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0060/), [Plutil (MASTG-TOOL-0062)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0062/), [radare2 (MASTG-TOOL-0073)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/), [tcpdump (MASTG-TOOL-0080)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0080/), [Wireshark (MASTG-TOOL-0081)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0081/), [mitmproxy (MASTG-TOOL-0097)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0097/) (CC BY-SA 4.0)
- IETF: [RFC 8996: Deprecating TLS 1.0 and TLS 1.1](https://www.rfc-editor.org/rfc/rfc8996), [RFC 9325: Recommendations for Secure Use of TLS and DTLS](https://www.rfc-editor.org/rfc/rfc9325), [RFC 8446: TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446), [RFC 5246: TLS 1.2](https://www.rfc-editor.org/rfc/rfc5246), [RFC 7568: Deprecating SSL 3.0](https://www.rfc-editor.org/rfc/rfc7568), [RFC 6176: Prohibiting SSL 2.0](https://www.rfc-editor.org/rfc/rfc6176), [RFC 7465: Prohibiting RC4](https://www.rfc-editor.org/rfc/rfc7465), [RFC 7507: TLS Fallback SCSV](https://www.rfc-editor.org/rfc/rfc7507), [RFC 8701: GREASE](https://www.rfc-editor.org/rfc/rfc8701), [RFC 9001: Using TLS to Secure QUIC](https://www.rfc-editor.org/rfc/rfc9001); [IANA TLS Cipher Suites registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4)
- NIST: [SP 800-52 Rev. 2: Guidelines for the Selection, Configuration, and Use of TLS Implementations](https://csrc.nist.gov/pubs/sp/800/52/r2/final)
- Android: [`SSLSocket` (default protocol configuration)](https://developer.android.com/reference/javax/net/ssl/SSLSocket), [Security with network protocols (Android 10 TLS 1.3 changes)](https://developer.android.com/privacy-and-security/security-ssl), [`SSLContext`](https://developer.android.com/reference/javax/net/ssl/SSLContext), [Update your security provider to protect against SSL exploits](https://developer.android.com/privacy-and-security/security-gms-provider), [AOSP Conscrypt module](https://source.android.com/docs/core/ota/modular-system/conscrypt), [Conscrypt source](https://github.com/google/conscrypt)
- OkHttp: [HTTPS and `ConnectionSpec`](https://lysine.dev/okhttp/features/https/), [TLS configuration history](https://lysine.dev/okhttp/tls_configuration_history/)
- Apple: [Preventing Insecure Network Connections](https://developer.apple.com/documentation/security/preventing-insecure-network-connections), [`NSExceptionMinimumTLSVersion`](https://developer.apple.com/documentation/bundleresources/information-property-list/nsexceptionminimumtlsversion), [`NSExceptionRequiresForwardSecrecy`](https://developer.apple.com/documentation/bundleresources/information-property-list/nsexceptionrequiresforwardsecrecy), [`NSAllowsArbitraryLoads`](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity/nsallowsarbitraryloads), [`tlsMinimumSupportedProtocolVersion`](https://developer.apple.com/documentation/foundation/urlsessionconfiguration/tlsminimumsupportedprotocolversion), [`sec_protocol_options_set_min_tls_protocol_version`](https://developer.apple.com/documentation/security/sec_protocol_options_set_min_tls_protocol_version%28_:_:%29), [Network framework](https://developer.apple.com/documentation/network), [TN3151: Choosing the right networking API](https://developer.apple.com/documentation/technotes/tn3151-choosing-the-right-networking-api), [tvOS 26 release notes (Security: default minimum TLS version for apps linked on or after iOS 26 and macOS 26)](https://developer.apple.com/documentation/tvos-release-notes/tvos-26-release-notes), [Prepare your network for quantum-secure encryption in TLS](https://support.apple.com/en-us/122756)
- Tools: [testssl.sh](https://testssl.sh/), [nmap `ssl-enum-ciphers`](https://nmap.org/nsedoc/scripts/ssl-enum-ciphers.html), [OpenSSL `s_client`](https://docs.openssl.org/master/man1/openssl-s_client/), [tshark](https://www.wireshark.org/docs/man-pages/tshark.html), [mitmproxy options](https://docs.mitmproxy.org/stable/concepts/options/), [PCAPdroid](https://github.com/emanuele-f/PCAPdroid), [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- PCI Security Standards Council: information supplement *Migrating from SSL and Early TLS*, available from the [PCI SSC document library](https://www.pcisecuritystandards.org/)
- CWE: [CWE-319](https://cwe.mitre.org/data/definitions/319.html), [CWE-327](https://cwe.mitre.org/data/definitions/327.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
