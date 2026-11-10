---
title: "MASWE-0056: App Attestation Not Implemented"
date: 2026-11-10 20:05:00 +0000
subcategory: resilience
summary: "APK signature schemes, signing keys, iOS CodeDirectory formats, Play Integrity and App Attest app verdicts, and testing that the backend enforces them."
refs: [MASWE-0056, MASVS-RESILIENCE-2, CWE-347]
tags: [android, ios, masvs-resilience, app-attestation, code-signing, play-integrity]
---

This note is part of our [MASVS-RESILIENCE guide](/mobile/masvs-resilience-resilience-testing-guide/) and covers OWASP [MASWE-0056](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0056/): a backend that cannot tell its own app from a modified copy, a script or a bot. App attestation is the answer to one question the server asks on every sensitive request: *was this sent by the unmodified app I published?* The platform answers it with evidence about the app's signing identity, wrapped in a signature the client cannot forge: the Play Integrity `appIntegrity` verdict or a key attestation's `AttestationApplicationId` on Android, an App Attest attestation and its per-request assertions on iOS. All of that evidence rests on code signing. If the signing scheme lets someone change the package without breaking the signature, or the signing key is weak enough to forge, "signed by the right key" stops meaning "unmodified", and every attestation built on it inherits the gap. That is why OWASP files its three signing tests (APK signature scheme, APK signing key size, iOS code signature format) under this weakness. Below you get the signing mechanics on both platforms (summarised for Android, where our [MASTG-KNOW-0003 note](/mobile/mastg-know-0003-app-signing/) goes deeper), what app attestation proves and what the backend has to do with it, the three OWASP tests with lab output, two tests of ours for backend enforcement and coverage, and how to rate what you find. Device-side attestation (is the *device* trustworthy?) is the subject of the sibling note on [MASWE-0054](/mobile/maswe-0054-device-attestation-not-implemented/), which also covers the shared mechanics of Play Integrity tokens, key attestation chains and root certificates. This note links there instead of repeating them.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: App Signing (MASTG-KNOW-0003)](#android-app-signing-mastg-know-0003)
  - [iOS: App Signing (MASTG-KNOW-0058)](#ios-app-signing-mastg-know-0058)
  - [Android: App attestation with Play Integrity and key attestation (Guler Tech)](#android-app-attestation-with-play-integrity-and-key-attestation-guler-tech)
  - [iOS: App Attest (Guler Tech)](#ios-app-attest-guler-tech)
  - [Generic: What the backend has to do (Guler Tech)](#generic-what-the-backend-has-to-do-guler-tech)
- [Tests](#tests)
  - [MASTG-TEST-0224: Usage of Insecure APK Signature Version (Android)](#mastg-test-0224-usage-of-insecure-apk-signature-version-android)
  - [MASTG-TEST-0225: Usage of Insecure APK Signature Key Size (Android)](#mastg-test-0225-usage-of-insecure-apk-signature-key-size-android)
  - [MASTG-TEST-0220: Usage of Outdated Code Signature Format (iOS)](#mastg-test-0220-usage-of-outdated-code-signature-format-ios)
  - [GT-RES-0056-1: Backend enforces app identity (Android, iOS)](#gt-res-0056-1-backend-enforces-app-identity-android-ios)
  - [GT-RES-0056-2: App attestation coverage of sensitive endpoints (Android, iOS)](#gt-res-0056-2-app-attestation-coverage-of-sensitive-endpoints-android-ios)
- [Best practices](#best-practices)
  - [Use Up-to-Date APK Signing Schemes (MASTG-BEST-0006)](#use-up-to-date-apk-signing-schemes-mastg-best-0006)
  - [Server-side app attestation (Guler Tech)](#server-side-app-attestation-guler-tech)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

The OWASP requirement is *"The app implements app attestation."* It maps to MASVS-RESILIENCE-2 ("The app implements anti-tampering mechanisms") and to [CWE-347](https://cwe.mitre.org/data/definitions/347.html) (Improper Verification of Cryptographic Signature). In the MASVS v1 it was part of MSTG-CODE-1 ("The app is signed and provisioned with a valid certificate"), which is why the old signing tests landed here. The weakness has two halves, and a finding can sit in either:

1. **The evidence is missing or weak.** The app sends nothing the server can verify about its own identity, or the signing scheme and key that the evidence describes are weak (a v1-only APK, a 1024-bit RSA signing key, an iOS signature in a pre-2017 format).
2. **The evidence is not enforced.** The app sends a Play Integrity token or an App Attest assertion, and the backend never verifies it, verifies it and ignores the result, accepts requests that simply leave it out, or only checks it at login.

OWASP's three tests are all about the first half, and all static. Nothing in the MASTG tests the second half, which is where the business risk lives, so this note adds two tests of ours (GT-RES-0056-1 and GT-RES-0056-2).

The weakness carries OWASP's **R** and **EUDIW** profiles. It applies to apps whose threat model includes someone running a modified copy of the app or impersonating it with scripts: banking and payments, wallets (including EU Digital Identity Wallets, where the wallet provider has to be confident about the app instance before it issues credentials to it), games with in-app economies, DRM, and any service fighting fake account creation or promotion abuse. App attestation is defence in depth. It raises the cost of automated abuse and of distributing modified clients. It does not replace authentication, authorisation or server-side business rules, and a client-side signature check with no server-side decision can always be bypassed eventually by someone who controls the device.

OWASP describes the threat as MAS-THREAT-0056, *"Attackers can distribute and run modified copies of the app"*, reached through three attacks:

| Attack | Description | What app attestation does about it |
|---|---|---|
| MAS-ATTACK-0040 | Patching or repackaging the app to remove or alter client-side checks | A repackaged copy must be re-signed with a different key, so its attested signing certificate no longer matches. The server can refuse it, even if every client-side check was removed. |
| MAS-ATTACK-0068 | Impersonating the app with scripts, bots, or tampered clients when interacting with the backend | A script cannot produce a fresh, request-bound attestation signed by Google or Apple. This is the main reason to deploy app attestation. |
| MAS-ATTACK-0069 | Installing a repackaged version of the app on victim devices | The signing scheme decides whether a modified package can keep the original signature (Janus on v1-only APKs). Server-side attestation lets the backend refuse trojanised copies even when users install them. |

Why the signing tests belong here: an app attestation is a statement *about the signing identity*. Play Integrity says "this package name and this certificate digest match what Google Play distributes". Key attestation says "the app that owns this key is package X signed by certificate digest Y". App Attest says "this key belongs to an app with App ID `TEAMID.bundle.id`", which Apple only issues to code signed for that team. In each case the platform has verified the code signature first, and the attestation is only as strong as that verification. A weak scheme or key undermines the evidence before any server sees it.

Keep the neighbouring topics apart:

| Question | Where it lives |
|---|---|
| Is the *app* the genuine, unmodified build (signing identity, package, version)? | This note (MASWE-0056) |
| Is the *device* genuine and uncompromised (locked bootloader, certified OS, patch level)? | [MASWE-0054](/mobile/maswe-0054-device-attestation-not-implemented/). Play Integrity's `deviceIntegrity` and key attestation's `RootOfTrust` live there |
| Has the app's code been patched or hooked *while it runs*? | [MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/) |
| Have the app's resources, configuration or data files been altered? | [MASWE-0057](/mobile/maswe-0057-app-resources-integrity-not-verified/) |
| Does the app verify signatures on data it receives (JWS, signed configuration, updates)? | [MASWE-0011](/mobile/maswe-0011-improper-signature-verification/) |
| Does the server refuse outdated app versions? | [MASWE-0043](/mobile/maswe-0043-enforced-updating-not-implemented/) (uses `appIntegrity.versionCode`) |

## Modes of Introduction

**No server-verifiable app identity at all.** The API authenticates the *user* (password, OAuth tokens) and nothing else. Any HTTP client that has the user's credentials, or that creates its own accounts, looks exactly like the app. This is by far the most common state, and for most apps it is acceptable. For R-profile apps it is the core finding.

**Attestation integrated on the client, not enforced on the server.** The app requests a Play Integrity token or an App Attest assertion and sends it in a header. The backend forwards it to a logging pipeline, or decodes it and records the verdict, but never rejects a request. Teams often start in this "monitor mode" to measure false positives, and never switch enforcement on.

**Fail-open paths.** The server rejects a bad token but accepts a request with *no* token, because older app versions, web clients, unsupported devices or attestation outages need to keep working. The fallback is exactly what an attacker uses. Variations: a client-supplied flag such as `"attestationSupported": false` that the server believes; an `UNEVALUATED` verdict treated as a pass; a separate web API that does the same thing without attestation.

**Attestation at login only.** The app attests once, the server issues an ordinary bearer token, and every later request (payments, transfers, voucher redemption) is accepted from anything that holds the token. A script lifts the token from one genuine session and does the rest.

**Evidence not bound to the request.** A Play Integrity token without a `requestHash` or `nonce` that the server checks, or an App Attest assertion whose `clientData` does not include the request body, can be harvested from a genuine device and attached to arbitrary requests until it expires or is detected as reused.

**Wrong expected values.** The backend compares the certificate digest against the *upload key* rather than the Play App Signing key, or hard-codes one digest and breaks on key rotation, after which someone relaxes the check "temporarily". On iOS, the server accepts the development `aaguid` in production, or does not compare the App ID.

**Outdated signing configuration.** A v1-only APK (possible only for `targetSdkVersion` 29 or lower), a signing key generated years ago as RSA-1024, an Android debug key in a release build, or an iOS ad hoc or enterprise build signed with a pre-iOS 15 toolchain without DER entitlements.

**Client-only integrity checks.** The app compares its own signing certificate with a hard-coded digest and exits if they differ, and nothing is reported to the server. That is a MASWE-0056 mitigation in OWASP's list, and it is worth having, but it lives in the code the attacker is modifying. One patched comparison removes it.

## Impact

- **Automated abuse of the API.** Scripts and bots that impersonate the app at scale: fake account registration, credential stuffing against the mobile login (which often has weaker rate limits than the web), SMS and OTP pumping, scraping, promotion and referral abuse, ticket and limited-stock scalping, game economy farming.
- **Modified clients against the real backend.** A repackaged app with pinning, root detection and premium-feature checks removed keeps working against production, because the server never asks which app it is talking to. Cheats, cracked subscriptions and "modded" builds circulate under the app's name.
- **Trojanised copies harvesting users.** A copy with added malicious code, distributed through third-party stores or phishing, logs users in to the genuine backend while stealing their credentials, OTPs or session tokens. The resulting account compromise is attributed to the app.
- **Weaker platform guarantees.** With a v1-only APK, devices that verify only the JAR signature cannot detect some modifications to the archive. With a weak signing key, someone who can forge the key's signatures can produce updates that the platform installs over the genuine app, keeping its data.

## Mitigations

- **Use platform app attestation and verify it on the server.** Play Integrity (`appIntegrity`, plus `accountDetails` where licensing matters) or Android key attestation for apps outside Google Play, and App Attest on iOS. Decode and validate on your server, never on the device.
- **Enforce, and fail closed.** Reject or step up requests whose evidence is missing, invalid, stale, replayed, bound to a different request, or `UNEVALUATED`. Keep any exemption (old app versions, unsupported devices) explicit, limited in time and scope, and monitored.
- **Bind evidence to the action.** Use `requestHash` (Play Integrity standard requests) or a server nonce (classic requests, key attestation challenge), and App Attest assertions over a `clientData` that includes the request body and a server challenge.
- **Cover the sensitive endpoints, not just login.** Attest where the abuse happens: registration, OTP sending, payments, voucher redemption, device enrolment. Bind the session to an attested key where possible.
- **Use current signing schemes and strong keys.** v2 and v3 (v3.1 for rotation) on Android, RSA 2048 or larger or ECDSA P-256 or larger, Play App Signing with an upload key, a key upgrade for legacy RSA-1024 apps. On iOS, sign with a current Xcode (CodeDirectory version 20400 or later, with DER entitlements).
- **Add local packaged-integrity checks as an extra layer.** Compare the running app's signing certificate (`SigningInfo` on Android, the Team ID and entitlements on iOS) with expected values, and report failures to the server instead of only exiting.
- **Respond, do not just detect.** Decide what a failed check does: block, reduce functionality, require step-up, or flag for fraud review. Test the response against known bypass techniques.

## Knowledge

OWASP assigns no Knowledge pages to MASWE-0056 directly. The two that describe the signing identity behind it are MASTG-KNOW-0003 (Android app signing) and MASTG-KNOW-0058 (iOS app signing). The first has a deep-dive note on this site, so it gets a summary with the points this note needs. The second gets the full treatment. Neither OWASP page explains app attestation itself, so three sections of ours follow.

### Android: App Signing (MASTG-KNOW-0003)

Source: [MASTG-KNOW-0003](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0003/). Full walkthrough, including debug-key detection, certificate validity and the repackaging path: our [MASTG-KNOW-0003 note](/mobile/mastg-know-0003-app-signing/).

#### What the signature is for

Android does not use certificate authorities for apps. Every APK carries a (normally self-signed) certificate and a signature made with the matching private key. The package manager checks the signature at install time and uses the certificate as the app's identity: an update must be signed by the same key (or by a key the original one has delegated to through rotation), signature-level permissions and `sharedUserId` depend on it, and so does every attestation of the app's identity. Google Play additionally requires the certificate to be valid until after 22 October 2033.

#### The signature schemes

| Scheme | Verified from | What it covers | Notes |
|---|---|---|---|
| v1 (JAR signing) | Android 1.0 | The uncompressed contents of each ZIP entry, listed in `META-INF/MANIFEST.MF` | Does not cover ZIP metadata or bytes outside the entries. Verification decompresses every entry, which is slow. Basis of the Janus bug. |
| v2 (APK Signature Scheme v2) | Android 7.0 (API 24) | The whole file except the APK Signing Block itself | Any change to the archive, including ZIP metadata, breaks the signature. Faster to verify. |
| v3 | Android 9 (API 28) | Same as v2, plus a signed SDK range and a *proof-of-rotation* structure | Enables signing-key rotation across updates. |
| v3.1 | Android 13 (API 33) | Same as v3, in a separate block | Lets a rotated key target API 33+ while the v3 block keeps the original key for older versions. `apksigner` uses it for rotation by default. |
| v3.2 | Android 17 (API 37) | Hybrid block with one classical and one post-quantum (ML-DSA-65 or ML-DSA-87) signer | New in 2026. Android 16 and lower ignore it, so a v3.0 or v3.1 block is still required. |
| v4 | Android 11 (API 30) | A Merkle tree over the APK, in a separate `.apk.idsig` file | Supports ADB incremental install and streaming. It is not a replacement for v2 or v3 and adds no protection on its own. |

How the platform chooses: a device on Android 7.0 or later looks for the APK Signing Block first and verifies the newest scheme it supports. It falls back to v1 only if there is no v2 or later signature at all. A v2 signature also adds a "stripping protection" attribute to the v1 signature, so removing the v2 block to force a v1-only verification is rejected. Devices before Android 7.0 ignore everything except v1. Two consequences:

- With `minSdkVersion` 24 or higher, the v1 signature is never used and can be dropped. Android Gradle Plugin and `apksigner` make this choice from `minSdkVersion` by default. OWASP's advice to "always sign via all previous schemes" dates from before that and is only right for apps that still support Android 6.0 or lower.
- Since Android 11, apps that **target** API 30 or higher must have a v2 or later signature, or they cannot be installed. In our lab, `apksigner verify` on a v1-only APK targeting API 35 printed `DOES NOT VERIFY` with `Target SDK version 35 requires a minimum of signature scheme v2`. Google Play has required `targetSdkVersion` 30 or higher for new apps since 2021, so a v1-only APK from Play is now rare.

#### Janus (CVE-2017-13156)

A file can be a valid ZIP (parsed from the end, where the central directory is) and a valid DEX (parsed from the start) at the same time. Because the v1 scheme signs only the ZIP entries, bytes prepended to the file do not break it. The Janus bug, found by Guardsquare and fixed in the December 2017 Android security bulletin (NVD lists Android 5.1.1 to 8.0; Guardsquare's write-up says 5.0 to 8.0), was that the runtime would execute a DEX prepended to an APK whose v1 signature still verified. An attacker could therefore build an "update" that the package manager accepted as signed by the original developer, install it over the genuine app and inherit its data and permissions. Only APKs verified with v1 were exploitable: on Android 7.0 to 8.0 that means v1-only APKs, on 5.x and 6.x any APK. Patched devices are not affected. Janus is the concrete reason a v1-only APK fails MASTG-TEST-0224.

#### Keys, rotation and Play App Signing

- **Algorithms and sizes.** APK signatures can use RSA, ECDSA (P-256, P-384, P-521) or DSA. RSA 2048 bits is the floor (NIST has disallowed RSA-1024 for new signatures since 2013), and ECDSA P-256 gives similar strength with a smaller key. Many apps first published around 2010 still carry an RSA-1024 key because changing the key used to be impossible.
- **The certificate's own signature algorithm does not matter.** Android does not validate the certificate chain, so a `SHA1withRSA` or `MD5withRSA` self-signature on the certificate is not a finding. What matters is the key and the digest used for the APK signature (v2 and later use SHA-256 or SHA-512; v1 uses SHA-1 digests when `minSdkVersion` is below 18).
- **Rotation.** v3 lets a new key prove it is trusted by the old one: the *proof-of-rotation* structure is a linked list of certificates, oldest first, each signed by its predecessor, with capability flags per entry (whether the older key keeps installed data, shared UID, signature permissions, `rollback` and `auth` rights). `apksigner rotate` creates the lineage, `apksigner sign --lineage` applies it, and `apksigner lineage --in <apk> --print-certs` prints it from an APK. The AOSP documentation does not recommend rotation on Android 12 and lower, which is why v3.1 targets API 33 by default.
- **Play App Signing.** For apps published as Android App Bundles, Google holds the *app signing key* and signs the APKs delivered to users. The developer signs uploads with a separate *upload key*, which Google can reset if it is lost. Google-generated app signing keys are RSA 4096, a key you supply must be RSA 2048 or larger, and Play Console offers a key upgrade for apps with weak legacy keys. As of late 2026 Google's help page describes "quantum-ready" hybrid keys for new apps, enforced through v3.2 on Android 17 and later. Check the current page before you quote it.
- **What this means for testing.** The APK you get from the developer's CI is signed with the upload key or a local key. The APK users receive from Play is signed with the app signing key. Test the artefact users actually install (pull it from a device that installed from Play), and when you check attestation configuration, the expected certificate digest is the app signing key's, shown in Play Console under the app signing settings.

#### Reading `apksigner verify` correctly

`apksigner verify --verbose` reports the schemes it *verified*, not the schemes present. It verifies only what a device in the APK's supported range would use. For an APK with `minSdkVersion` 24 it does not check the v1 signature (devices on API 24+ never use it), and for `minSdkVersion` 28 with a v3 block it does not check v2 either. Our lab APK with `minSdkVersion` 24, signed by `apksigner` with its defaults, contained `META-INF/K.SF` and `K.RSA` and still printed `Verified using v1 scheme (JAR signing): false`. Do not report that line as "v1 missing", or as "v1 present". If you need an inventory of every block, run the verification again with a lower range, for example `--min-sdk-version 21`.

#### Runtime APIs for the signing identity

Inside the app, `PackageManager.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)` (API 28+) returns a `SigningInfo`. `getApkContentsSigners()` returns the current signers, `getSigningCertificateHistory()` the rotation lineage (valid when `hasMultipleSigners()` is false), and `hasPastSigningCertificates()` tells you a rotation happened. `PackageManager.hasSigningCertificate(packageName, digest, PackageManager.CERT_INPUT_SHA256)` checks for one certificate. The older `GET_SIGNATURES` flag is deprecated since API 28: it does not describe key rotation, and with several signers its ordering is not guaranteed, so do not base an integrity check on it.

### iOS: App Signing (MASTG-KNOW-0058)

Source: [MASTG-KNOW-0058](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CODE/MASTG-KNOW-0058/) (OWASP files it under MASVS-CODE).

#### Mandatory code signing

iOS will not run unsigned code. Every executable page must belong to a binary with a valid signature that chains to Apple, and the kernel checks page hashes lazily as pages are loaded ([Apple Platform Security: app code signing process](https://support.apple.com/guide/security/app-code-signing-process-sec7c917bf14/web)). For third-party apps that means:

- **Who can sign.** App Store and TestFlight builds are re-signed by Apple after review. Development, ad hoc and enterprise (in-house) builds are signed with a certificate Apple issued to a developer team and must be accompanied by a provisioning profile (`embedded.mobileprovision`) that lists the App ID, the entitlements and, for development and ad hoc, the allowed device UDIDs. App Store builds carry no `embedded.mobileprovision`.
- **What is sealed.** The main executable's signature covers its code pages, its `Info.plist`, its entitlements and, through `_CodeSignature/CodeResources`, every resource in the bundle. Nested code (frameworks, dylibs, app extensions, a watchOS app) is signed separately and recorded in the containing bundle's seal.
- **Library validation.** A process may only load libraries that are Apple platform binaries or carry the same Team ID as the main executable, and only if they were installed as part of the signed app. A dylib copied into the container after installation is refused (`code signing blocked mmap()`), even if it carries the developer's own Team ID. App Store apps therefore cannot introduce new native code at runtime, which is why runtime code loading on iOS is limited to interpreted content (see [MASWE-0049](/mobile/maswe-0049-unsafe-dynamic-code-loading/)).
- **Entitlements are in the signature.** Capabilities such as Keychain access groups, App Groups, associated domains, `get-task-allow` and App Attest's environment are entitlements, embedded in the signature (see [MASTG-KNOW-0077](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0077/)). Changing them requires re-signing.

#### Inside the signature: CodeDirectory, slots and cdhash

A signed Mach-O has an `LC_CODE_SIGNATURE` load command pointing to an embedded *SuperBlob*. Its main part is the **CodeDirectory**: a header, then one hash per code page, preceded by *special slots* that hash the other components ([XNU `cs_blobs.h`](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)):

| Slot | Content |
|---|---|
| -1 | `Info.plist` |
| -2 | Internal requirements |
| -3 | Resource directory (`_CodeSignature/CodeResources`) |
| -4 | Application-specific |
| -5 | Entitlements (XML plist) |
| -6 | Representation-specific (used for disk images) |
| -7 | Entitlements, DER-encoded |
| -8 to -11 | Launch and library constraints (newer OS versions) |

The hash of the CodeDirectory itself is the **cdhash**, the identifier the kernel, AMFI and trust caches work with. A CMS blob signs the cdhash. A binary can carry several CodeDirectories with different hash types (SHA-1 and SHA-256) for compatibility with old OS versions. `codesign` adds the SHA-1 one only when the deployment target needs it.

The CodeDirectory has a format version, printed by `codesign` as `v=` (the hex value without `0x`). Each version added fields:

| Version | Added |
|---|---|
| 20100 | Scatter vector |
| 20200 | Team ID |
| 20300 | 64-bit code limit |
| 20400 | Executable segment base, limit and flags (`execSeg`) |
| 20500 | Runtime version (hardened runtime, macOS) |
| 20600 | Linkage hash |

#### The iOS 15 format change

From iOS 15, iPadOS 15, tvOS 15 and watchOS 8, the system requires the newer signature format with **DER-encoded entitlements** in slot -7, and *"apps signed with a previous signature format will not launch"* ([Apple: Using the latest code signature format](https://developer.apple.com/documentation/xcode/using-the-latest-code-signature-format)). Apple's guidance is precise:

- A CodeDirectory version below 20400 needs re-signing.
- At 20400 or higher, if slot -5 (XML entitlements) has a value and slot -7 is zero or absent, the DER entitlements are missing and the app needs re-signing.
- App Store and TestFlight builds are re-signed by Apple and always have the current format. Signing on macOS 11 or later produces DER entitlements by default. Apps distributed ad hoc, through enterprise distribution or through custom pipelines that sign on old macOS are the ones at risk.
- Nested code must be signed inside-out, and frameworks are signed without entitlements.

In practice an app in the old format does not launch on any current iOS version, so the finding is mostly about build pipelines that still produce such artefacts, about nested code signed separately by a vendor, and about enterprise apps for old devices.

#### Reading `codesign` output

Lab output for an ad hoc signed arm64 binary with one entitlement (macOS 14.4, `codesign -d -vvv`; iOS binaries produce the same fields, with `Authority=` lines instead of `Signature=adhoc`):

```text
Format=Mach-O thin (arm64)
CodeDirectory v=20400 size=518 flags=0x2(adhoc) hashes=5+7 location=embedded
Hash type=sha256 size=32
CandidateCDHash sha256=6baad48fff9266b319c003f98bb56c0ac6287117
CandidateCDHashFull sha256=6baad48fff9266b319c003f98bb56c0ac62871170107ceb03412b859bc6faaf5
Hash choices=sha256
CDHash=6baad48fff9266b319c003f98bb56c0ac6287117
Signature=adhoc
TeamIdentifier=not set
```

- `v=20400` is the CodeDirectory version.
- `hashes=5+7` is five code-page hashes and seven special slots, i.e. the special slots reach down to -7. `+7` or more is a quick sign that a DER entitlements slot exists. A signature from before the change typically shows `+5` (OWASP's own legacy example, `v=20200 … hashes=4830+5`, is exactly such a signature).
- `Hash type=sha256` is the primary hash. `Hash choices=sha1,sha256` means an extra SHA-1 CodeDirectory for old OS versions.
- `CDHash` is the 20-byte (truncated) cdhash.
- For App Store builds you see `Authority=Apple iPhone OS Application Signing`. For a developer's own distribution you see `Authority=Apple Distribution: <Team Name> (<TEAMID>)` or the older `iPhone Distribution:` form, followed by the Apple intermediate and root.

With four or more `-v` flags, `codesign -d` also prints the executable-segment fields and the slot hashes after `Page size=`. That is how you check slot -7, as Apple's page describes. In the same lab output:

```text
Executable Segment flags=0x1
Page size=4096
    -7=95c45d9aa842d521acb1d1c896e3dd99aa61872e83ab68e189a23ef211a6ff00
    -6=0000000000000000000000000000000000000000000000000000000000000000
    -5=1d3536fd5e24c336e723af99e03ae2b9ff3026d0bedc6c2fc32e068d00177450
```

Signing the same binary with `-o runtime` produced `v=20500`, `flags=0x10002(adhoc,runtime)` and a `Runtime Version=` line. That is a macOS hardened-runtime feature, so do not expect it on iOS apps.

#### How attackers get around code signing (in general terms)

- **Re-signing.** Anyone with an Apple developer account (including a free one, with short-lived profiles) can re-sign a decrypted IPA with their own certificate and install it on their own registered devices. The signature is valid, but the Team ID and the App ID change. That is exactly what App Attest makes visible to the server.
- **Enterprise certificate abuse.** Enterprise certificates have been abused to distribute modified apps outside the App Store until Apple revoked them.
- **Jailbreaks** disable or bypass signature enforcement, and CoreTrust validation bugs on some iOS versions have let tools install apps with arbitrary signatures. On such devices code signing gives no guarantee, which is why app attestation is paired with device-level risk signals.

### Android: App attestation with Play Integrity and key attestation (Guler Tech)

Android offers two ways to send the backend signed evidence about the app. Both are covered in more depth from the device side in the [MASWE-0054 note](/mobile/maswe-0054-device-attestation-not-implemented/). Here we only look at the app part.

#### Play Integrity: the `appIntegrity` and `accountDetails` verdicts

The app asks Google Play services for an encrypted, signed *integrity token* and sends it to its backend. The backend decrypts and verifies it (standard requests: through Google's `decodeIntegrityToken` endpoint, `playintegrity.googleapis.com/v1/PACKAGE_NAME:decodeIntegrityToken`; classic requests: through that endpoint or locally with keys from Play Console). The JSON verdict contains, among other parts ([Integrity verdicts](https://developer.android.com/google/play/integrity/verdicts)):

```json
{
  "requestDetails": {
    "requestPackageName": "com.example.bank",
    "requestHash": "base64url-sha256-of-the-request",
    "timestampMillis": "1762800000000"
  },
  "appIntegrity": {
    "appRecognitionVerdict": "PLAY_RECOGNIZED",
    "packageName": "com.example.bank",
    "certificateSha256Digest": ["base64url-sha256-of-the-signing-certificate"],
    "versionCode": "4210"
  },
  "accountDetails": {
    "appLicensingVerdict": "LICENSED"
  }
}
```

(Illustrative values.)

- `appRecognitionVerdict`:
  - `PLAY_RECOGNIZED`: the package name and certificate match a version Google Play distributes.
  - `UNRECOGNIZED_VERSION`: the certificate or package name does not match Google Play's records. A re-signed copy lands here, and so does a build the developer installed from CI that was never uploaded to a Play track.
  - `UNEVALUATED`: a necessary requirement was missed, for example the device is not trustworthy enough. `packageName`, `certificateSha256Digest` and `versionCode` are only present when the verdict is not `UNEVALUATED`.
- `certificateSha256Digest` is base64url-encoded, while `apksigner` prints hex. Convert before comparing: `echo <hex> | xxd -r -p | base64 | tr '+/' '-_' | tr -d '='`.
- `versionCode` lets the server enforce a minimum version from an attested value instead of a header (see [MASWE-0043](/mobile/maswe-0043-enforced-updating-not-implemented/)).
- `accountDetails.appLicensingVerdict` is `LICENSED` when the signed-in Play account got the app from Google Play, `UNLICENSED` when it did not (for example after sideloading), and `UNEVALUATED` when it could not be evaluated. It is the paid-app or entitlement signal. A sideloaded copy of the genuine, Play-signed APK is still `PLAY_RECOGNIZED` but `UNLICENSED`.
- **Freshness and binding.** Standard requests carry the developer's `requestHash` (up to 500 bytes, normally a SHA-256 of the request), classic requests a `nonce`. The server must compare `requestPackageName`, the hash or nonce, and `timestampMillis` with the request it is processing. Google also limits reuse of standard tokens: decrypting the same token repeatedly returns cleared verdicts (`UNEVALUATED`, empty device verdict). That protection only helps if the server treats `UNEVALUATED` as a failure.
- **Requirements.** Play Integrity needs Google Play services and the Play Store, so it does not work on devices without them (most devices sold in China, de-Googled ROMs such as GrapheneOS without sandboxed Play, Huawei HMS devices) or for apps distributed only outside Google Play in a way Play does not recognise. The backend needs a policy for those clients.

#### Key attestation: `AttestationApplicationId`

Apps that cannot rely on Play (alternative stores, enterprise distribution, devices without Google services) can use hardware key attestation directly. The app generates a key in Android Keystore with `KeyGenParameterSpec.Builder.setAttestationChallenge(serverChallenge)`, and the Keystore returns a certificate chain whose leaf contains the attestation extension (OID `1.3.6.1.4.1.11129.2.1.17`). Among its authorisation fields is tag 709, `attestationApplicationId` ([Key and ID attestation](https://source.android.com/docs/security/features/keystore/attestation)):

```text
AttestationApplicationId ::= SEQUENCE {
    package_infos      SET OF AttestationPackageInfo,
    signature_digests  SET OF OCTET_STRING,
}
AttestationPackageInfo ::= SEQUENCE {
    package_name  OCTET_STRING,
    version       INTEGER,
}
```

`package_infos` holds the package name and version code (several entries only if packages share a UID), and `signature_digests` the SHA-256 digests of the app's signing certificates. The Android platform fills this field from the package manager, so it is only as trustworthy as the OS that produced it. The server must therefore also check the `RootOfTrust` (locked bootloader, `Verified` boot state) and validate the chain up to Google's attestation roots, including revocation. Those checks are the device side and are described in the MASWE-0054 note. Google's open-source [keyattestation library](https://github.com/android/keyattestation) implements the chain and extension parsing on the server side. GrapheneOS's [attestation compatibility guide](https://grapheneos.org/articles/attestation-compatibility-guide) explains how to accept hardware attestation from alternative operating systems with locked bootloaders, which Play Integrity's device verdict rejects.

#### Firebase App Check and similar wrappers

Many apps do not call Play Integrity or App Attest directly but use Firebase App Check (providers for Play Integrity, App Attest and DeviceCheck) or a commercial mobile app attestation service. The same questions apply: is the token enforced on every protected backend, and is a debug provider (Firebase's `DebugAppCheckProviderFactory` or a hard-coded debug token) present in the release build? A debug provider in production lets anyone who extracts the debug token obtain valid App Check tokens from a script.

### iOS: App Attest (Guler Tech)

App Attest is part of the DeviceCheck framework (`DCAppAttestService`, iOS 14 and later) ([Establishing your app's integrity](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity), [Validating apps that connect to your server](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server)). DeviceCheck's other service, the two per-device bits, is about devices, not apps, and is covered in the MASWE-0054 note.

#### The flow

1. **Key generation.** The app checks `DCAppAttestService.shared.isSupported` and calls `generateKey`. The Secure Enclave creates a P-256 key pair and returns a key identifier (the SHA-256 hash of the public key).
2. **Attestation, once per key.** The app gets a one-time challenge from the server and calls `attestKey(keyId, clientDataHash: SHA256(challenge))`. Apple's servers return an *attestation object*: CBOR in a WebAuthn-like format (`fmt` = `apple-appattest`), with an `x5c` certificate chain to Apple's App Attest root, a receipt and `authData`.
3. **Server validation of the attestation.** The server verifies the certificate chain, recomputes the nonce from `authData` and the challenge and compares it with the credential certificate's extension `1.2.840.113635.100.8.2`, checks that the public key hashes to the key ID, that the `RP ID` in `authData` equals SHA-256 of the **App ID** (`TEAMID.bundle.identifier`), that the counter is 0, that `aaguid` is the production value (`appattest` followed by seven zero bytes) and not the development one, and that `credentialId` equals the key ID. Apple's current documentation also lists two `authData` extensions to check, `apple_validation_category_01` (how the app was signed and launched, e.g. App Store versus development) and `apple_bundle_version_01` (the app version). These are recent additions, and older server libraries may not check them. The server then stores the public key and receipt against the user and device.
4. **Assertions, per request.** For each protected request, the app builds `clientData` (the request, including a server challenge), and calls `generateAssertion(keyId, clientDataHash: SHA256(clientData))`. The server verifies the signature over `SHA256(authenticatorData || SHA256(clientData))` with the stored key, checks the `RP ID` again, checks that the counter is greater than the last one it saw, and checks the embedded challenge.

#### What it proves, and what it does not

- **Identity.** The `RP ID` binds the key to the App ID, and Apple only attests keys for apps signed by that team. A copy re-signed with another team's certificate has a different App ID, so its attestations fail step 3. A development build attests in the development environment and fails the `aaguid` check in production.
- **Per-request integrity.** Each assertion is bound to its `clientData` and has a monotonic counter, so it cannot be replayed or moved to a different request if the server checks both.
- **Not device integrity.** App Attest does not tell you whether the device is jailbroken. A jailbroken device can still run the genuine app and produce valid assertions, and code injected into that app can ask it to sign whatever the attacker wants. Apple's receipt lets the server request a fraud metric (how many keys have been attested on that device for your app), which helps spot one device serving assertions to many clients.
- **Availability.** `isSupported` is false in the Simulator and on unsupported devices, and Apple may rate-limit `attestKey` (Apple suggests ramping up gradually and keeping `attestKey` calls under about 100 per second across all installations). The server needs a policy for clients without App Attest, and that policy is often the weak point.

Apple's pages are not fully consistent about the development `aaguid`: one says `appattestdevelop`, the other `appattestsandbox`. Accept only the production value in production and you avoid the question.

### Generic: What the backend has to do (Guler Tech)

App attestation is a server-side control. Everything on the client can be observed and changed by whoever controls the device. What the attacker cannot do is make Google or Apple sign a statement that their modified copy or their script is your app. That only helps if the server:

1. **Issues the challenge.** A fresh, single-use, server-generated value per attestation or per request, or a `requestHash` computed over the actual request.
2. **Verifies the evidence itself.** Decrypt or verify with Google or Apple, never trust a verdict the client decoded. Validate certificate chains to the documented roots.
3. **Checks every field that carries identity.** Package name or App ID, certificate digest (the Play App Signing key, all accepted keys across a rotation), version code or bundle version, licensing if relevant, production environment, request binding, freshness, counter.
4. **Decides.** Pass, step up (re-authentication, additional verification), restrict, or reject, per endpoint and per verdict, including `UNEVALUATED`, missing, malformed and unsupported.
5. **Keeps the decision server-side.** The app must not be the one that acts on the verdict ("if failed, show error"), because that code can be patched.
6. **Monitors.** Logs verdicts and failure rates, alerts on spikes in `UNRECOGNIZED_VERSION` or invalid assertions, and has a kill switch for false-positive waves.

The two GT tests below check points 1, 3, 4 and coverage, from the outside.

## Tests

OWASP links three tests to MASWE-0056, all static and all about the signing identity: MASTG-TEST-0224 and MASTG-TEST-0225 (Android) and MASTG-TEST-0220 (iOS). They replace the legacy v1 tests [MASTG-TEST-0038](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0038/) ("Making Sure that the App is Properly Signed", Android, `covered_by` 0224 and 0225) and [MASTG-TEST-0081](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0081/) (same title, iOS, `covered_by` 0220). OWASP has no demos for any of the three, so the demos below are ours, built in a lab with `apksigner` and `aapt2` from Android SDK Build Tools 35 and `codesign` on macOS 14.4.

No OWASP test checks whether the backend actually uses an attestation, which is the part that matters in an R-profile assessment. GT-RES-0056-1 and GT-RES-0056-2 cover it. Run them with the app owner's written agreement that backend testing is in scope, against test accounts you control, and at low volume: Play Integrity and App Attest have quotas, and Apple rate-limits attestation.

### MASTG-TEST-0224: Usage of Insecure APK Signature Version (Android)

*OWASP test: [MASTG-TEST-0224](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0224/). Type: static. Front matter: `available_since: 24`. Best practice: MASTG-BEST-0006.*

#### Overview

The test checks that the APK does not rely on the v1 (JAR) scheme alone. A v1 signature covers the ZIP entries but not the archive around them, which is what Janus (CVE-2017-13156) used to slip a DEX into a correctly "signed" APK. v2 and later sign the whole file. The `available_since: 24` field says the test only makes sense for apps whose `minSdkVersion` is 24 or higher: those apps never run on a device that cannot verify v2, so there is no compatibility excuse for v1-only signing.

Two facts change how often this test can fail today. Apps targeting API 30 or higher cannot be installed on Android 11+ with a v1-only signature, and `apksigner` itself reports `DOES NOT VERIFY` for them. And `apksigner verify` reports `v1 … false` for perfectly normal APKs with `minSdkVersion` 24 or higher, because it does not check v1 for them. Both are covered in the evaluation.

#### Prerequisites

- The APK as users receive it. For a Play app, install it from Play on a test device and pull it: `adb shell pm path <package>` lists the base APK and the split APKs. A locally built APK may be signed differently (upload key, debug key, different schemes).
- `apksigner` and `aapt2` from the Android SDK Build Tools ([MASTG-TOOL-0123](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0123/), [MASTG-TOOL-0124](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0124/)). Optionally [jadx](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/) or [apktool](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/) to read the manifest ([MASTG-TECH-0117](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/), [MASTG-TECH-0150](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0150/)).

#### Steps

1. Pull the installed APKs:

   ```bash
   adb shell pm path com.example.app
   # package:/data/app/~~.../com.example.app-.../base.apk
   # package:/data/app/~~.../com.example.app-.../split_config.arm64_v8a.apk
   mkdir apks && cd apks
   for p in $(adb shell pm path com.example.app | sed 's/^package://' | tr -d '\r'); do adb pull "$p"; done
   ```

2. Read `minSdkVersion` and `targetSdkVersion` from the base APK. Recent `aapt2` prints `minSdkVersion:`, older versions `sdkVersion:`, so match both:

   ```bash
   aapt2 dump badging base.apk | grep -E "^(sdkVersion|minSdkVersion|targetSdkVersion)"
   # minSdkVersion:'24'
   # targetSdkVersion:'35'
   ```

   With jadx (`jadx --no-src -d out base.apk`), the `<uses-sdk>` element is in `out/resources/AndroidManifest.xml`. With apktool it is in `apktool.yml`, not in the decoded manifest.

3. Verify the signatures for the APK's own supported range (this is what devices do), for the base APK and every split:

   ```bash
   for a in *.apk; do echo "== $a"; apksigner verify --verbose "$a"; done
   ```

   If `apksigner` cannot determine the minimum SDK of a split, pass the base APK's value with `--min-sdk-version`.

4. Inventory which blocks exist, independent of the range. Lower the range so that `apksigner` checks every scheme, and list the JAR signature files:

   ```bash
   apksigner verify --verbose --min-sdk-version 21 base.apk
   unzip -l base.apk | grep -E 'META-INF/.*\.(SF|RSA|EC|DSA)$'
   ```

   If there is no v1 signature, the first command fails with an error about missing JAR signatures. That is expected for a `minSdkVersion` 24+ app and is not a finding.

#### Observation

Record the `minSdkVersion` and `targetSdkVersion`, the `Verifies` or `DOES NOT VERIFY` line, the five `Verified using …` lines from step 3 for each APK, any `ERROR` or `WARNING` lines, and the inventory from step 4.

#### Evaluation

- **Fail (OWASP criterion):** `minSdkVersion` is 24 or higher and the only scheme that verifies is v1 (`v1 … true`, v2, v3 and v3.1 `false` in step 3, and step 4 confirms there is no APK Signing Block). If `targetSdkVersion` is 30 or higher, `apksigner` reports `DOES NOT VERIFY` with `Target SDK version … requires a minimum of signature scheme v2`. Report that too: the app cannot be installed or updated on Android 11 and later.
- **Fail (our addition):** `minSdkVersion` is below 24 and the APK is v1-only. Devices on Android 7.0 and later then verify only v1, and adding v2 costs no compatibility. OWASP's test does not cover this case.
- **Pass:** v2, v3 or v3.1 verifies for the APK's own range, on the base APK and all splits.
- **Not a finding:** `v1 … false` with `minSdkVersion` 24 or higher, whether or not JAR signature files are present. A v1 signature present alongside v2 or v3 (it is protected by stripping protection). No v4 signature.

#### Demo

*No OWASP demo exists for this test. This one is ours.* A release signing configuration that forces v1-only signing, on an app with `minSdkVersion` 24. It only builds and installs at all because the target is still API 29:

```kotlin
// app/build.gradle.kts (vulnerable)
android {
    defaultConfig {
        minSdk = 24
        targetSdk = 29
    }
    signingConfigs {
        create("release") {
            // storeFile, storePassword, keyAlias, keyPassword ...
            enableV1Signing = true
            enableV2Signing = false
            enableV3Signing = false
        }
    }
}
```

Lab output for the same configuration produced with `apksigner sign --v1-signing-enabled true --v2-signing-enabled false --v3-signing-enabled false`, then the same v1-only signing on the APK built with `targetSdkVersion` 35, then that APK with `apksigner`'s default signing (all output produced in our lab, file names renamed for readability):

```text
$ apksigner verify --verbose v1only-t29.apk
Verifies
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): false
Verified using v3 scheme (APK Signature Scheme v3): false
Verified using v3.1 scheme (APK Signature Scheme v3.1): false
Verified using v4 scheme (APK Signature Scheme v4): false
Verified for SourceStamp: false
Number of signers: 1

$ apksigner verify --verbose v1only-t35.apk
DOES NOT VERIFY
ERROR: Target SDK version 35 requires a minimum of signature scheme v2; the APK is not signed with this or a later signature scheme

$ apksigner verify --verbose modern.apk          # minSdk 24, default apksigner signing
Verifies
Verified using v1 scheme (JAR signing): false
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Verified using v3.1 scheme (APK Signature Scheme v3.1): false
Verified using v4 scheme (APK Signature Scheme v4): false
Verified for SourceStamp: false
Number of signers: 1

$ unzip -l modern.apk | grep -E 'META-INF/.*\.(SF|RSA)$'
      329  01-01-1980 00:00   META-INF/K.SF
     1215  01-01-1980 00:00   META-INF/K.RSA
```

`v1only-t29.apk` fails the test. `v1only-t35.apk` fails and cannot be installed on Android 11+. `modern.apk` passes, and the `v1 … false` line is not a finding: the JAR signature is there, `apksigner` simply did not need to check it.

### MASTG-TEST-0225: Usage of Insecure APK Signature Key Size (Android)

*OWASP test: [MASTG-TEST-0225](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0225/). Type: static.*

#### Overview

The test checks the strength of the key that signs the APK. Whoever can produce signatures with that key can publish "updates" that the platform installs over the genuine app, and passes any check that compares the signing certificate digest. OWASP's criterion is an RSA key shorter than 2048 bits. Three refinements make the test reliable:

- The key size line means different things per algorithm. `apksigner` prints the RSA modulus length for RSA and the curve order length for EC, so a P-256 key shows `256` and is fine. Apply the 2048-bit threshold to RSA (and DSA) only.
- The label is not always `Signer #1`. When the APK has a v3.1 block (key rotation), `apksigner` prints `Signer (minSdkVersion=33, maxSdkVersion=…)` lines instead, one per signer and range. A `grep "Signer #1 key size"` finds nothing.
- Old keys in a rotation lineage still count. If the lineage keeps capabilities for an old RSA-1024 key (for example `rollback`), that key can still sign APKs the platform accepts on some versions.

#### Prerequisites

- The APK as distributed (see MASTG-TEST-0224), signed with the key users actually receive: for a Play App Signing app, pull it from a device that installed from Play.
- `apksigner` ([MASTG-TOOL-0123](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0123/)) and `openssl` for certificate details. OWASP's technique: [MASTG-TECH-0116](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0116/).

#### Steps

1. Print every signer with key details:

   ```bash
   apksigner verify --verbose --print-certs base.apk | grep -E "certificate DN|key algorithm|key size"
   ```

2. If v3.1 verified, or the app is known to have rotated keys, print the whole lineage with key details:

   ```bash
   apksigner lineage --in base.apk --print-certs -v | grep -E "DN|key algorithm|key size|capability"
   # "The provided APK does not contain a valid lineage." = no rotation
   ```

3. Optionally, check the certificate itself (validity dates for the Play 2033 rule, curve name):

   ```bash
   apksigner verify --print-certs-pem base.apk | sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' \
     | openssl x509 -noout -subject -dates -text | grep -E "subject=|notBefore|notAfter|Public-Key|ASN1 OID"
   ```

   `keytool -printcert -jarfile` only reads v1 signatures and prints nothing useful for APKs without one, so prefer `apksigner`.

4. Check whether the debug key was used (`CN=Android Debug, O=Android, C=US`). That is a separate and more serious finding, described in our [MASTG-KNOW-0003 note](/mobile/mastg-know-0003-app-signing/).

#### Observation

For every signer (current, per SDK range, and in the lineage): the certificate DN, the key algorithm, the key size, and the lineage capabilities where present.

#### Evaluation

- **Fail:** any current signer uses RSA (or DSA) with fewer than 2048 bits, e.g. `Signer #1 key size (bits): 1024`.
- **Fail (our addition):** an older key in the lineage is RSA or DSA below 2048 bits *and* still holds capabilities (in particular `rollback`). If the old key's capabilities have been removed, report it as Info.
- **Pass:** RSA 2048 or larger, or EC with a 256-bit or larger curve, for all signers.
- **Not a finding:** a `SHA1withRSA` or `MD5withRSA` signature algorithm on the self-signed certificate (Android does not validate it), and EC key sizes of 256 or 384.

If the key is weak, the realistic fix is a key upgrade through Play App Signing (or v3 rotation for apps signed by the developer), not a new package name.

#### Demo

*No OWASP demo exists for this test. This one is ours.* Four keys generated with `keytool` and used to sign the same lab APK (`minSdkVersion` 24):

```bash
keytool -genkeypair -keystore rsa1024.p12 -storetype PKCS12 -alias k -keyalg RSA -keysize 1024 \
  -validity 10000 -dname "CN=Lab rsa1024, O=Example, C=GB"
keytool -genkeypair -keystore ec256.p12 -storetype PKCS12 -alias k -keyalg EC -groupname secp256r1 \
  -validity 10000 -dname "CN=Lab ec256, O=Example, C=GB"
apksigner sign --ks rsa1024.p12 --out weak.apk base.apk
apksigner sign --ks ec256.p12 --out ec.apk base.apk
# rotation from an RSA-2048 key to an RSA-3072 key, v3.1 targeting API 33+
apksigner rotate --out lineage.bin --old-signer --ks rsa2048.p12 --new-signer --ks rsa3072.p12
apksigner sign --ks rsa2048.p12 --next-signer --ks rsa3072.p12 --lineage lineage.bin --out rotated.apk base.apk
```

Output (lab, digests shortened):

```text
$ apksigner verify --verbose --print-certs weak.apk | grep -E "DN|key"
Signer #1 certificate DN: CN=Lab rsa1024, O=Example, C=GB
Signer #1 key algorithm: RSA
Signer #1 key size (bits): 1024

$ apksigner verify --verbose --print-certs ec.apk | grep -E "key algorithm|key size"
Signer #1 key algorithm: EC
Signer #1 key size (bits): 256

$ apksigner verify --verbose --print-certs rotated.apk | grep -E "DN|key size|v3.1"
Verified using v3.1 scheme (APK Signature Scheme v3.1): true
Signer (minSdkVersion=33, maxSdkVersion=2147483647) certificate DN: CN=Lab rsa3072, O=Example, C=GB
Signer (minSdkVersion=33, maxSdkVersion=2147483647) key size (bits): 3072
Signer (minSdkVersion=24, maxSdkVersion=32) certificate DN: CN=Lab rsa2048, O=Example, C=GB
Signer (minSdkVersion=24, maxSdkVersion=32) key size (bits): 2048

$ apksigner lineage --in rotated.apk --print-certs -v | grep -E "DN|key size|rollback"
Signer #1 in lineage certificate DN: CN=Lab rsa2048, O=Example, C=GB
Signer #1 in lineage key size (bits): 2048
Has rollback capability      : false
Signer #2 in lineage certificate DN: CN=Lab rsa3072, O=Example, C=GB
Signer #2 in lineage key size (bits): 3072
Has rollback capability      : false
```

`weak.apk` fails. `ec.apk` passes even though it shows `256`. `rotated.apk` passes, and shows why OWASP's `Signer #1` pattern needs widening.

### MASTG-TEST-0220: Usage of Outdated Code Signature Format (iOS)

*OWASP test: [MASTG-TEST-0220](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0220/). Type: static.*

#### Overview

The test reads the CodeDirectory version of the app's signature. OWASP says the test fails if the version is "below the recommended one". Apple's page gives the concrete threshold: **20400**. A signature at 20400 or later can still be missing the DER entitlements that iOS 15 and later require, so the test below also checks slot -7, as Apple's page describes. Check every piece of nested code too, not just the main executable: frameworks and extensions are signed separately and can come from a vendor's pipeline.

Expect App Store and TestFlight builds to pass: Apple re-signs them. The test finds real issues in ad hoc, enterprise and custom-pipeline builds, and in third-party frameworks shipped pre-signed.

#### Prerequisites

- The IPA as distributed. Ask the app owner for the exact build (ad hoc, enterprise or the App Store submission), or extract it from a device. Do not test an IPA produced by a decryption tool that re-signs or fake-signs the binary: its signature is the tool's, not the developer's.
- macOS with `codesign` ([MASTG-TOOL-0114](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0114/)). OWASP's techniques: [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/) (exploring the app package) and [MASTG-TECH-0112](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0112/) (obtaining the code signature format version).

#### Steps

1. Unpack the IPA and list the signed bundles and binaries:

   ```bash
   unzip -q App.ipa -d ipa
   APP=$(ls -d ipa/Payload/*.app)
   ls "$APP/Frameworks" "$APP/PlugIns" 2>/dev/null
   ```

2. Read the CodeDirectory version, hash type and signer for the app, each framework and each extension:

   ```bash
   for b in "$APP" "$APP"/Frameworks/*.framework "$APP"/Frameworks/*.dylib "$APP"/PlugIns/*.appex; do
     [ -e "$b" ] || continue
     echo "== $b"
     codesign -d -vvv "$b" 2>&1 | grep -E "^(CodeDirectory|Hash type|Hash choices|Authority|TeamIdentifier)="
   done
   ```

3. For every item whose version is 20400 or higher and that has entitlements (the app and its extensions), check the special slots. Four or more `-v` flags print the `Page size=` block:

   ```bash
   codesign -d -vvvv "$APP" 2>&1 | sed -n '/^Page size=/,/^ *-1=/p'
   ```

4. Print the entitlements to confirm they exist and to note anything unusual (`get-task-allow` belongs to [MASWE-0063](/mobile/maswe-0063-debug-mechanisms-not-disabled/)):

   ```bash
   codesign -d --entitlements - --xml "$APP"
   ```

   The older `--entitlements :-` form still works but now prints a deprecation warning. On Linux, `ldid -e` prints the entitlements of a binary.

#### Observation

For every signed item: the `CodeDirectory v=` value, the `hashes=N+M` count, `Hash type`, the `Authority` chain and Team ID, and for entitled items the values of slots -5 and -7.

#### Evaluation

- **Fail:** any item has `CodeDirectory v=` below 20400.
- **Fail:** an item with entitlements has a non-zero slot -5 and slot -7 zero or absent (missing DER entitlements). `hashes=…+5` on an entitled binary is the quick tell.
- **Pass:** all items at 20400 or later, and every entitled item has a slot -7 hash.
- **Not a finding:** frameworks without slots -5 and -7 (frameworks are signed without entitlements); `Hash choices=sha1,sha256` (compatibility CodeDirectory for an old deployment target, as long as SHA-256 is present); a version of 20500 or 20600 (newer is fine).

The legacy test MASTG-TEST-0081 also said to make sure "no ad hoc certificates are used" for in-house distribution. Ad hoc is a *distribution method* with a device list, not a certificate type, and is legitimate for testing. The real point is that enterprise and ad hoc builds should not reach the general public.

#### Demo

*No OWASP demo exists for this test.* The passing case is our lab binary from the Knowledge section (ad hoc signed on macOS 14.4 with one entitlement, which `codesign` encodes in both XML and DER):

```text
$ codesign -d -vvv demo 2>&1 | grep CodeDirectory
CodeDirectory v=20400 size=518 flags=0x2(adhoc) hashes=5+7 location=embedded
$ codesign -d -vvvv demo 2>&1 | sed -n '/^Page size=/,/-5=/p'
Page size=4096
    -7=95c45d9aa842d521acb1d1c896e3dd99aa61872e83ab68e189a23ef211a6ff00
    -6=0000000000000000000000000000000000000000000000000000000000000000
    -5=1d3536fd5e24c336e723af99e03ae2b9ff3026d0bedc6c2fc32e068d00177450
```

The failing case is the example OWASP itself printed in the legacy test MASTG-TEST-0081 (illustrative, not produced by us):

```text
Format=app bundle with Mach-O universal (armv7 arm64)
CodeDirectory v=20200 size=154808 flags=0x0(none) hashes=4830+5 location=embedded
Hash type=sha256 size=32
Hash choices=sha1,sha256
Authority=iPhone Distribution: Example Ltd
```

`v=20200` is below 20400, and `+5` means there is no DER entitlements slot. This app would not launch on iOS 15 or later until re-signed, which Apple's page shows how to do: `codesign -s "<identity>" -f --preserve-metadata --generate-entitlement-der <path>.app`, inside-out for nested code, on macOS 10.14 or later (macOS 11 or later does it by default).

### GT-RES-0056-1: Backend enforces app identity (Android, iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

The test checks that the backend refuses requests that do not come from the genuine app: requests without attestation evidence, with invalid, stale, replayed or mismatched evidence, and requests from a copy of the app re-signed with a key that is not the developer's. It is a dynamic test of the server's decision, done through the app's own API with your own test accounts. It does not try to make attestation pass on an untrusted device or client, and it needs no such technique: every variant here is something the server should *reject*.

#### Prerequisites

- Written confirmation that the backend is in scope, two or more test accounts you control, and a contact on the app owner's side who can read the server's verdict logs for your test requests (this separates "the server never checked" from "the server checked and decided to allow").
- A test device on which the genuine app, installed from the store, obtains valid evidence. For Play Integrity that means a stock device with Google Play; App Attest needs a real iOS 14+ device. Device-level verdicts are out of scope here (see the MASWE-0054 note), so use a device that passes them, to isolate the app-level checks.
- An intercepting proxy set up as in our [traffic interception lab note](/mobile/mobile-traffic-interception-lab/). If the app pins certificates, use the app owner's test build without pinning or the techniques in the [MASWE-0028 note](/mobile/maswe-0028-insecure-identity-pinning/).
- For step 5: `apksigner` and a throwaway keystore (Android); on iOS, an Apple developer account with your own development certificate and a provisioning profile for your test device, plus the decrypted IPA of the app under test from the app owner. The re-signed copy is installed only on your own test device, for this test, and deleted afterwards. It is never modified or distributed.

#### Steps

1. **Find where the evidence travels.** Statically, look for the attestation APIs and their wrappers:

   ```bash
   # Android (jadx output)
   jadx -d out base.apk
   grep -rlE "com\.google\.android\.play\.core\.integrity|StandardIntegrityManager|IntegrityTokenRequest|setAttestationChallenge|AppCheckProviderFactory" out/sources | head
   # iOS
   otool -L "$APP/$(basename "$APP" .app)" | grep -iE "DeviceCheck|AppCheck"
   strings -a "$APP/$(basename "$APP" .app)" | grep -E "DCAppAttestService|generateAssertion|attestKey|AppCheck" | sort -u
   ```

   At runtime, trace the app's own calls to see when it requests evidence (at launch, at login, per request):

   ```bash
   # Android: Play Integrity client classes
   frida-trace -U -f com.example.app -j '*Integrity*!request*' -j '*Integrity*!prepareIntegrityToken*'
   # iOS: App Attest calls
   frida-trace -U -f com.example.app -m '-[DCAppAttestService *]'
   ```

   Then match the traced calls to traffic in the proxy: a long base64url value in a header (`X-Integrity-Token`, `X-App-Attest`, `X-Firebase-AppCheck` or a custom name) or a JSON field. Note which requests carry it, and whether an App Attest flow has a separate attestation call (once per key) and assertions (per request).

2. **Baseline.** Perform a sensitive action with the genuine app (log in, add a payee, redeem a voucher, start a payment in a test environment) and keep the request and response.

3. **Tamper with the evidence on the baseline request** (proxy repeater, one variant at a time):

   | Variant | What you send | Expected |
   |---|---|---|
   | A. Missing | Header or field removed | Rejected or stepped up |
   | B. Garbage | Random base64url of the same length | Rejected |
   | C. Replayed | The token or assertion from step 2, sent again a minute later | Rejected (Play Integrity returns cleared verdicts on reuse; App Attest counter not increasing) |
   | D. Moved | A valid token from a different request (another action or other parameters) attached to this one | Rejected (`requestHash`, `nonce` or `clientData` mismatch) |
   | E. Stale | A token captured an hour earlier and never used | Rejected (`timestampMillis` or challenge expiry) |
   | F. Downgraded | Any client-side claim changed: `"attestationSupported": false`, `"platform": "web"`, an older `app-version` header that the server exempts | Rejected, or routed to a path with equivalent controls |

4. **Check the alternative routes.** If the same operation exists in a web or partner API, or an older API version (`/v1/` next to `/v2/`), send the same request there without evidence.

5. **Re-signed copy on your own test device.**

   Android: re-sign the unmodified APKs of the app under test with your own key and install them in place of the genuine app:

   ```bash
   keytool -genkeypair -keystore gt-test.p12 -storetype PKCS12 -alias gt -keyalg EC -groupname secp256r1 \
     -validity 30 -dname "CN=GT test only, O=Example"
   mkdir -p resigned
   for a in apks/*.apk; do apksigner sign --ks gt-test.p12 --ks-key-alias gt --out "resigned/$(basename "$a")" "$a"; done
   adb uninstall com.example.app            # different signer: the genuine app must be removed first
   adb install-multiple resigned/*.apk
   ```

   iOS: re-sign the decrypted IPA with your development identity and a development profile for your device (Xcode's devices window or fastlane's `resign` action), install it, and log in with a test account. The bundle identifier may need to change to match your profile, which itself changes the App ID.

   Log in with a test account in the re-signed copy and repeat the action from step 2. With Play Integrity, the copy receives `UNRECOGNIZED_VERSION`. With key attestation, its `signature_digests` contain your certificate's digest. With App Attest, the `RP ID` is the hash of your App ID and the `aaguid` is the development value. Ask the app owner which verdict their server logged.

6. **Clean up.** Uninstall the re-signed copy, delete the test keystore and reinstall the genuine app from the store.

#### Observation

For each variant: the full request, the status code and body, any later effect (the action completed, the account was flagged, a step-up was triggered) and the server-side verdict log entry from the app owner. For the re-signed copy: whether login and the sensitive action succeeded, and the verdict the server recorded.

#### Evaluation

- **Pass:** every variant A to F on the protected endpoints is rejected or stepped up, the alternative routes in step 4 have equivalent controls, and the re-signed copy cannot complete the sensitive action.
- **Fail:** any variant is accepted. Name the failure precisely in the report:
  - A accepted: fail-open on missing evidence (the most common and most serious form).
  - B accepted: the server does not verify the evidence at all.
  - C or E accepted: no freshness or replay control, or `UNEVALUATED` treated as a pass.
  - D accepted: evidence not bound to the request.
  - F or step 4 accepted: client-controlled bypass or unprotected alternative route.
  - Re-signed copy accepted: the server ignores `appRecognitionVerdict`, the certificate digest or the App ID.
- **Monitor mode:** if the server logs the right verdicts but deliberately does not enforce them yet, report it as a finding with the rollout plan as context, not as a pass.

#### Demo

*Our example.* A backend that "has Play Integrity" but only looks for the header, and the same check done properly. Server-side Kotlin, run after `decodeIntegrityToken` returned the verdict JSON:

```kotlin
// Vulnerable: presence check only, and it never rejects
fun checkIntegrity(req: Request) {
    if (req.header("X-Integrity-Token").isNullOrEmpty()) {
        log.warn("request without integrity token")
    }
}

// Better: verify identity, binding and freshness, and fail closed
fun appIdentityOk(verdict: JSONObject, expectedRequestHash: String, nowMs: Long): Boolean {
    val req = verdict.getJSONObject("requestDetails")
    if (req.getString("requestPackageName") != PACKAGE_NAME) return false
    if (req.getString("requestHash") != expectedRequestHash) return false
    if (nowMs - req.getString("timestampMillis").toLong() > MAX_TOKEN_AGE_MS) return false

    val app = verdict.getJSONObject("appIntegrity")
    if (app.getString("appRecognitionVerdict") != "PLAY_RECOGNIZED") return false   // also rejects UNEVALUATED
    if (app.getString("packageName") != PACKAGE_NAME) return false
    val digests = app.getJSONArray("certificateSha256Digest")
    if (digests.length() == 0) return false
    for (i in 0 until digests.length()) {
        if (digests.getString(i) !in ACCEPTED_SIGNING_CERT_DIGESTS) return false      // Play App Signing key(s)
    }
    return app.getString("versionCode").toLong() >= MIN_VERSION_CODE
}
```

Variant results against a vulnerable backend (illustrative):

```text
Variant A (header removed)            -> 200 OK  {"status":"payee_added"}
Variant B (random token)              -> 200 OK  {"status":"payee_added"}
Re-signed copy, same test account     -> 200 OK  {"status":"payee_added"}
Server log (from app owner)           -> integrity: token missing / decode error / UNRECOGNIZED_VERSION, action allowed
```

### GT-RES-0056-2: App attestation coverage of sensitive endpoints (Android, iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

GT-RES-0056-1 shows whether the server enforces evidence where it asks for it. This test checks *where* it asks. Apps often attest once at login, then use an ordinary bearer token for everything else. A script that takes the token from one genuine session can then register accounts, send OTPs, redeem vouchers or move money without ever producing new evidence. The test maps the abuse-relevant endpoints, records which ones require fresh, request-bound evidence, and replays the others from outside the app.

#### Prerequisites

- As for GT-RES-0056-1: backend in scope, test accounts, proxy, a device on which the genuine app obtains valid evidence.
- The app owner's view of which operations are abuse targets (what fraud or bot traffic they see), if they will share it.
- `curl` or the proxy's repeater.

#### Steps

1. **Enumerate the endpoints.** Walk through every feature with the proxy recording. Add endpoints found statically: Retrofit or OkHttp annotations and URL strings in the jadx output (`grep -rhoE '@(GET|POST|PUT|DELETE|PATCH)\("[^"]+"\)' out/sources | sort -u`), and path strings in the iOS binary (`strings -a <binary> | grep -E '^/(api|v[0-9])/'`).

2. **Classify them.** Mark each endpoint by abuse value: account creation, login, OTP or SMS sending, password reset, device binding or enrolment, adding payees or cards, payments and transfers, voucher and referral redemption, in-game currency, high-value data exports. Everything else is "low".

3. **Record the evidence per endpoint.** For each high-value endpoint, note whether the request carries attestation evidence, whether it is fresh per request (a new token or assertion each time) or reused, and whether it is bound to the request body (compare the `requestHash` or `clientData` the app computes with frida-trace on the app's hashing call, or ask the developers).

4. **Replay from outside the app.** Take the session token from an attested session and call each high-value endpoint with `curl`, without any attestation header:

   ```bash
   curl -sS -X POST https://api.example.com/v2/vouchers/redeem \
     -H "Authorization: Bearer $SESSION_TOKEN" -H "Content-Type: application/json" \
     -d '{"code":"TEST-VOUCHER-01"}'
   ```

   Repeat for unauthenticated high-value endpoints (registration, OTP sending, password reset) with no session at all.

5. **Check the session binding.** If the server claims the session is bound to an attested key (for example a proof-of-possession header signed with an App Attest or Keystore-backed key), confirm it: send the request with the session token but without the proof, and with a proof from a different session.

#### Observation

A table per endpoint: abuse value, evidence present (yes or no), fresh per request (yes or no), bound to the request (yes or no), result of the replay from `curl`.

#### Evaluation

- **Pass:** every high-value endpoint requires fresh, request-bound evidence, or the session token is bound to an attested key so a script cannot use it, and unauthenticated high-value endpoints (registration, OTP, reset) require evidence too.
- **Fail:** a high-value endpoint accepts requests from `curl` with a lifted session token or with no session, without evidence. Rate it by what that endpoint lets a script do at scale.
- **Context, not a fail:** low-value endpoints without attestation. Attesting every request costs latency and quota, and nobody needs it on a "get FAQ" endpoint.

#### Demo

*Our example* (illustrative coverage table from an R-profile payments app):

```text
Endpoint                          Abuse value  Evidence  Fresh  Bound  curl replay
POST /v2/auth/login               high         yes       yes    yes    401 attestation_required
POST /v2/users  (registration)    high         no        -      -      201 Created      <- fail
POST /v2/otp/send                 high         no        -      -      200 OK           <- fail (SMS pumping)
POST /v2/payees                   high         yes       no     no     200 OK           <- fail (token reused)
POST /v2/payments/initiate        high         yes       yes    yes    403 invalid_assertion
GET  /v2/content/faq              low          no        -      -      200 OK (fine)
```

## Best practices

### Use Up-to-Date APK Signing Schemes (MASTG-BEST-0006)

Source: [MASTG-BEST-0006](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0006/).

Sign with v2 or v3 at least, use v3 (and v3.1, the default for rotation targeting Android 13+) when the key may need to rotate, and treat v4 as an optional extra for incremental installs. Android Gradle Plugin chooses the schemes from `minSdkVersion` by default, so the usual right answer is to leave the defaults alone and verify the output. Set the flags explicitly only to *add* schemes:

```kotlin
// app/build.gradle.kts
android {
    signingConfigs {
        create("release") {
            // storeFile, storePassword, keyAlias, keyPassword from a secure source, not from the repository
            enableV2Signing = true
            enableV3Signing = true
            enableV4Signing = true   // optional, for incremental installs on Android 11+
        }
    }
    buildTypes {
        getByName("release") {
            signingConfig = signingConfigs.getByName("release")
        }
    }
}
```

OWASP's snippet uses the Groovy form (`enableV3Signing true`), which is equivalent. Additional points OWASP's page does not make:

- Do not set `enableV1Signing = false` if `minSdkVersion` is below 24, and do not keep `enableV2Signing = false` from an old template.
- Use Play App Signing with an upload key, and if the app signing key is a legacy RSA-1024 key, request a key upgrade in Play Console. For apps distributed outside Play, rotate with `apksigner rotate` and `--lineage`, and remove capabilities (especially `rollback`) from the old key once the rotation has settled.
- Verify the artefact in CI with `apksigner verify --verbose --print-certs` and fail the build on `DOES NOT VERIFY`, an unexpected certificate digest or a debug certificate.

On iOS, the equivalent is simply a current Xcode on macOS 11 or later and no hand-rolled `codesign` steps. If a pipeline must re-sign, use `--generate-entitlement-der` and sign nested code inside-out.

### Server-side app attestation (Guler Tech)

What we expect to find in an R-profile app:

- **Android:** Play Integrity standard requests with a `requestHash` over the request, prepared at launch and requested per sensitive action. The server checks `requestDetails`, `appRecognitionVerdict == PLAY_RECOGNIZED`, the package name, the certificate digests against the Play App Signing key(s), a minimum `versionCode`, and `appLicensingVerdict` where the business model depends on it. For apps distributed outside Play or used on devices without Google services: key attestation with a server challenge, the `AttestationApplicationId` checked against the expected package and signing certificate digests, and the device checks from the MASWE-0054 note.
- **iOS:** App Attest with one attestation per key, validated with every step in Apple's list, the public key stored per user and device, and an assertion per sensitive request over a `clientData` that contains the request body and a server challenge. The counter is stored and must increase.
- **Both:** fail closed with explicit, monitored exemptions; the decision on the server; attestation on registration, OTP sending and payment endpoints, not only login; sessions bound to an attested key where possible; and verdict logging with alerting.

A minimal iOS client sketch, showing what the assertion should cover:

```swift
import CryptoKit
import DeviceCheck

func signedRequest(keyId: String, body: Data, challenge: Data) async throws -> (Data, Data) {
    // clientData covers the request body and a fresh server challenge
    var clientData = Data()
    clientData.append(challenge)
    clientData.append(body)
    let clientDataHash = Data(SHA256.hash(data: clientData))
    let assertion = try await DCAppAttestService.shared.generateAssertion(keyId, clientDataHash: clientDataHash)
    return (clientData, assertion)   // send both; the server recomputes the hash and verifies
}
```

Keep a local signing-certificate check as an extra layer if you want one (compare `SigningInfo` digests on Android, or the Team ID on iOS, with expected values), but report the result to the server, and never treat it as a replacement for server-verified evidence. Local checks and their bypasses are covered in the [MASWE-0058 note](/mobile/maswe-0058-runtime-code-integrity-not-verified/).

## Rating findings

Every RESILIENCE weakness applies to apps whose threat model includes reverse engineering, tampering and impersonation of the client. Rate by profile first, then by what the gap lets an attacker do.

- **Apps without the R profile:** missing app attestation is **Info** (an observation with a recommendation). Signing findings still count where they have direct impact (a debug key, a key weak enough to forge).
- **R-profile apps:** missing or unenforced app attestation is usually **Low–Medium**. It rises to **Medium–High** when it directly enables a concrete business abuse: no attestation on account creation, OTP sending, payment or voucher APIs that bots demonstrably abuse (or that the app owner says they abuse), or a fail-open path on exactly those endpoints.
- **A control that exists but is trivially bypassed** (a presence-only check, a client-side flag that disables it, a reusable token) is rated by what the bypass unlocks, as if the control were absent on those endpoints.
- **Debug mechanisms in release builds** found on the way (a release APK signed with the Android debug key, `get-task-allow` in an App Store build) are real vulnerabilities regardless of profile. Rate them on their own; the debug key in particular means anyone can sign updates the platform accepts.

| Rating | Conditions |
|---|---|
| **High** | R-profile app whose high-abuse endpoints (registration, OTP, payments, redemption) accept requests without any app attestation, with demonstrated or reported abuse; or the server accepts a re-signed copy on payment or credential-issuing operations (including wallet credential issuance in EUDIW scope); or a release signed with the Android debug key. |
| **Medium** | Fail-open on missing evidence, evidence not verified, `UNEVALUATED` treated as pass, or attestation only at login with lifted tokens usable on high-value endpoints, in an R-profile app without demonstrated abuse; RSA or DSA signing key below 2048 bits on an R-profile app (forgery is expensive but the key cannot be revoked); a Firebase App Check debug provider in a release build. |
| **Low** | Evidence present and enforced but not bound to the request, or freshness windows of hours; monitor mode with a documented rollout plan; v1-only APK with `targetSdkVersion` below 30 (Janus is patched on updated devices, but the platform's own protection is weaker); weak key in an old lineage entry that still has capabilities; iOS nested code in a pre-20400 format in an ad hoc or enterprise build. |
| **Info** | Any of the above in an app without the R profile; App Store builds (Apple re-signs them, so MASTG-TEST-0220 cannot fail); `v1 … false` lines for `minSdkVersion` 24+ apps; missing v4 signatures; `SHA1withRSA` on the certificate itself; low-value endpoints without attestation. |

In the report give: the endpoint and variant (for GT tests) with the request and response, the verdict the server logged, the APK or IPA path and the exact `apksigner` or `codesign` lines (for signing findings), the app's `minSdkVersion` and `targetSdkVersion`, and the concrete abuse the gap enables.

## References

- OWASP MASWE: [MASWE-0056: App Attestation Not Implemented](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0056/); related [MASWE-0054](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0054/), [MASWE-0057](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0057/), [MASWE-0058](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0058/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-RESILIENCE-2](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-2/) (CC BY-SA 4.0)
- OWASP MASTG knowledge: [MASTG-KNOW-0003](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0003/), [MASTG-KNOW-0058](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CODE/MASTG-KNOW-0058/), [MASTG-KNOW-0077](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0077/) (CC BY-SA 4.0)
- OWASP MASTG tests: [MASTG-TEST-0224](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0224/), [MASTG-TEST-0225](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0225/), [MASTG-TEST-0220](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0220/); legacy [MASTG-TEST-0038](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0038/), [MASTG-TEST-0081](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0081/) (CC BY-SA 4.0)
- OWASP MASTG best practice: [MASTG-BEST-0006](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0006/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0116](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0116/), [MASTG-TECH-0117](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/), [MASTG-TECH-0150](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0150/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0112](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0112/) (CC BY-SA 4.0)
- OWASP MASTG tools: [apksigner (MASTG-TOOL-0123)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0123/), [aapt2 (MASTG-TOOL-0124)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0124/), [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [Apktool (MASTG-TOOL-0011)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/), [codesign (MASTG-TOOL-0114)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0114/), [ios-app-signer (MASTG-TOOL-0102)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0102/), [fastlane (MASTG-TOOL-0117)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0117/) (CC BY-SA 4.0)
- Android (AOSP): [APK signature scheme overview](https://source.android.com/docs/security/features/apksigning), [v2](https://source.android.com/docs/security/features/apksigning/v2), [v3](https://source.android.com/docs/security/features/apksigning/v3), [v3.2](https://source.android.com/docs/security/features/apksigning/v3-2), [v4](https://source.android.com/docs/security/features/apksigning/v4), [Key and ID attestation](https://source.android.com/docs/security/features/keystore/attestation), [apksig source (`ApkVerifier`, `ApkSignerTool`)](https://android.googlesource.com/platform/tools/apksig/)
- Android developers: [apksigner](https://developer.android.com/tools/apksigner), [Sign your app](https://developer.android.com/studio/publish/app-signing), [Android 11 behaviour changes: APK Signature Scheme v2 now required](https://developer.android.com/about/versions/11/behavior-changes-11), [SigningInfo](https://developer.android.com/reference/android/content/pm/SigningInfo), [Play Integrity API](https://developer.android.com/google/play/integrity), [Integrity verdicts](https://developer.android.com/google/play/integrity/verdicts), [Standard API requests](https://developer.android.com/google/play/integrity/standard), [Key attestation](https://developer.android.com/privacy-and-security/security-key-attestation), [android/keyattestation library](https://github.com/android/keyattestation)
- Google Play: [Use Play App Signing](https://support.google.com/googleplay/android-developer/answer/9842756)
- Apple: [Using the latest code signature format](https://developer.apple.com/documentation/xcode/using-the-latest-code-signature-format), [Establishing your app's integrity](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity), [Validating apps that connect to your server](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server), [Preparing to use the App Attest service](https://developer.apple.com/documentation/devicecheck/preparing-to-use-the-app-attest-service), [Assessing fraud risk](https://developer.apple.com/documentation/devicecheck/assessing-fraud-risk), [Apple Platform Security: app code signing process](https://support.apple.com/guide/security/app-code-signing-process-sec7c917bf14/web), [XNU `cs_blobs.h`](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- Janus: [CVE-2017-13156 (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2017-13156), [Guardsquare: New Android vulnerability allows attackers to modify apps without affecting their signatures](https://www.guardsquare.com/en/blog/new-android-vulnerability-allows-attackers-modify-apps-without-affecting-their-signatures)
- Other: [GrapheneOS attestation compatibility guide](https://grapheneos.org/articles/attestation-compatibility-guide), [NIST SP 800-131A Rev. 2](https://csrc.nist.gov/pubs/sp/800/131/a/r2/final), [CWE-347](https://cwe.mitre.org/data/definitions/347.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
