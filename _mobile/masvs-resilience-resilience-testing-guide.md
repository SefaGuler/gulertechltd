---
title: "MASVS-RESILIENCE: Resilience Testing Guide for Mobile Apps"
date: 2026-11-10 20:20:00 +0000
subcategory: resilience
summary: "Hub for the MASVS-RESILIENCE series: 15 weaknesses, all 30 OWASP tests, legacy mapping, RASP design, an assessment workflow and a cheat sheet."
refs: [MASVS-RESILIENCE-1, MASVS-RESILIENCE-2, MASVS-RESILIENCE-3, MASVS-RESILIENCE-4, MASWE-0051, MASWE-0052, MASWE-0053, MASWE-0054, MASWE-0055, MASWE-0056, MASWE-0057, MASWE-0058, MASWE-0059, MASWE-0060, MASWE-0061, MASWE-0062, MASWE-0063, MASWE-0064, MASWE-0065]
tags: [android, ios, masvs-resilience, rasp, anti-tampering, reverse-engineering]
---

This is the entry point to our series on **OWASP MASVS-RESILIENCE**, the control group about how well an app holds up when the attacker owns the device it runs on. It has four requirements:

- **MASVS-RESILIENCE-1:** "The app validates the integrity of the platform."
- **MASVS-RESILIENCE-2:** "The app implements anti-tampering mechanisms."
- **MASVS-RESILIENCE-3:** "The app implements anti-static analysis mechanisms."
- **MASVS-RESILIENCE-4:** "The app implements anti-dynamic analysis techniques."

The series follows the [MASWE](https://mas.owasp.org/MASWE/) catalogue: one note per weakness, MASWE-0051 to MASWE-0065, each with its **Knowledge**, **Tests**, best practices and a rating section. This page explains when the category applies at all, maps the four controls to the fifteen weaknesses, lists all 30 OWASP tests and the note that documents each one, points to the four MASWE-0017 tests that sit in OWASP's RESILIENCE folder, maps the 21 deprecated v1 tests, summarises the eight generic reverse-engineering Knowledge items, and sets out the cross-cutting RASP design guidance. It ends with a step-by-step resilience assessment, a command cheat sheet and an attacker-position table.

Know two things before you start. First, six weaknesses have **no OWASP tests**: MASWE-0052, 0054, 0055, 0060, 0062 and 0065. For those the notes give our own tests, labelled *Guler Tech methodology* and numbered `GT-RES-00NN-x`; other notes add our tests where OWASP leaves a platform or a question uncovered. Second, the scope. Resilience testing asks whether the app's own protections exist, run, and how much effort they cost an attacker. The series covers static identification of checks, runtime tracing of the app's own checks, and neutralising **the app's own check** on your own test device with well-known public techniques so you can record the effort. It does not cover defeating server-verified attestation (Play Integrity, key attestation, App Attest, DeviceCheck), configuring root- or jailbreak-hiding frameworks, or anything that tampers with or redistributes apps other than the one under test.

## Contents

- [What MASVS-RESILIENCE covers](#what-masvs-resilience-covers)
- [The R profile: when this category applies](#the-r-profile-when-this-category-applies)
- [Rating findings: the series-wide rule](#rating-findings-the-series-wide-rule)
- [The four controls and their weaknesses](#the-four-controls-and-their-weaknesses)
- [The series](#the-series)
- [Test index](#test-index)
- [Tests in the RESILIENCE folder that belong to MASWE-0017](#tests-in-the-resilience-folder-that-belong-to-maswe-0017)
- [Legacy v1 tests and their replacements](#legacy-v1-tests-and-their-replacements)
- [Generic reverse-engineering Knowledge](#generic-reverse-engineering-knowledge)
- [Cross-cutting design guidance: RASP signals](#cross-cutting-design-guidance-rasp-signals)
- [What each attacker position can prove](#what-each-attacker-position-can-prove)
- [How to run a resilience assessment](#how-to-run-a-resilience-assessment)
- [Command cheat sheet](#command-cheat-sheet)
- [Related weaknesses in other categories](#related-weaknesses-in-other-categories)
- [Other series hubs](#other-series-hubs)
- [References](#references)

## What MASVS-RESILIENCE covers

The other MASVS groups ask whether a feature is built securely on a platform you can trust: data in the Keystore, TLS validated, IPC protected. RESILIENCE drops that assumption. Its attacker has root or a jailbreak, a debugger, Frida, a decompiler and unlimited time with their own copy of the app. Against that attacker no client-side control is absolute. What the app can do is notice the hostile environment, make itself expensive to understand and modify, and give its backend evidence it can act on. Findings come from four kinds of gap:

1. **Not looking at the platform.** The app runs unchanged on a rooted or jailbroken phone, an emulator, a cloned "dual app" container or a device the backend has never had any evidence about.
2. **Not protecting its own integrity.** A repackaged copy, a modified resource or a hooked function goes unnoticed, and nobody tells the server.
3. **Being easy to read.** Clear identifiers, readable strings and resources, debug symbols and chatty logs tell a reverse engineer where the security logic is, and plaintext API payloads show them the protocol once TLS is intercepted.
4. **Being easy to watch.** The release build is debuggable or has WebView debugging on, and nothing reacts to a debugger, Frida, Xposed/LSPosed or ElleKit.

One group in the category is different in kind. **Debug mechanisms left on in a release build** (MASWE-0063: `android:debuggable`, `get-task-allow`, WebView or `WKWebView` inspection) are not "missing hardening". They hand any person with USB access a debugger or a web inspector on the app, without root. The same is true of **debug artefacts** that switch security off (MASWE-0061: a hidden menu that disables TLS validation). Treat both as ordinary vulnerabilities, whatever the app's profile.

## The R profile: when this category applies

### Who should require it

Every RESILIENCE weakness carries OWASP's **R** profile, and the MASWE files add **EUDIW** (the EU Digital Identity Wallet profile). None carries L1 or L2. R is not "a stricter L2". It is a separate decision, made when the app's threat model includes reverse engineering and tampering by someone who controls the device. Typical R apps:

- **Banking, payments and wallets:** fraud automation, mule accounts, overlay and accessibility malware, device-farm onboarding.
- **DRM and paid content:** licence checks, content keys, offline entitlement flags.
- **Games:** cheating, modified clients, in-app purchase fraud, bots.
- **High-value IP:** proprietary algorithms, risk-scoring models, on-device ML.
- **Identity and EUDIW wallets:** credential presentation from a device the relying party has to trust.
- **Apps whose backend is abused by scripted clients:** promotions, account creation, scraping, ticketing.

If the client has not adopted R, report missing resilience controls as **observations**. If you think the app should be R (because the backend is visibly being abused by bots, or the business sells content locked by a client-side flag), say so in the report and recommend the profile. That recommendation is often more valuable than the individual findings.

### The threat model: the attacker owns the device

In L1 and L2 the device owner is the victim. In R the device owner may be the attacker. Two consequences follow, and every note in this series relies on them.

- **Every client-side check can eventually be bypassed.** A root check is code running on a device whose kernel the attacker controls. It can be hooked, patched, emulated or simply never reached. The useful question is never "can it be bypassed?" but "what does it cost, and what does the attacker gain?".
- **The decision belongs on the server.** A client that says "not rooted" proves nothing. A backend that receives signed, fresh evidence (Play Integrity verdict, key attestation chain, App Attest assertion) and decides what to allow is a different matter: the attacker now has to defeat hardware-backed signing or a vendor's risk engine, not one `if` statement.

### Defence in depth, not a control of its own

RESILIENCE controls raise attacker cost. They never replace the L1/L2 controls. An app that stores tokens in plaintext but detects root has a STORAGE finding, not a pass. An app whose API trusts a client-side "premium" flag has an authorisation flaw that obfuscation only hides. When you find that a resilience control is the *only* thing standing between an attacker and a business-critical action, report the missing primary control under its own category (usually AUTH, NETWORK or the server side), and the resilience gap as the secondary finding.

## Rating findings: the series-wide rule

Every note applies the same rule, adapted to its weakness.

- **App not in scope for R:** missing resilience controls are **Info** (observation). Name the profile and say what would change if the app adopted it.
- **R-profile app, control missing:** usually **Low to Medium**.
- **R-profile app, missing control directly enables a concrete business abuse:** **Medium to High**. Examples: no device or app attestation on a payment or account-creation API that bots are demonstrably abusing; a debuggable release build that exposes secrets.
- **Control present but trivially bypassed** (one public command, one short Frida hook, a renamed `frida-server`): rate it by **what the bypass unlocks**, not by the fact that it was bypassed. Bypassing a root check that guards nothing is Info; bypassing one that is the only gate on offline payments is not.
- **Debug mechanisms enabled in a release build** (`android:debuggable="true"`, `get-task-allow`, unconditional WebView debugging or `isInspectable = true`) and **debug artefacts that disable security**: real vulnerabilities **regardless of profile**. Rate them by what a person with USB access, or the hidden switch, can reach.

| Finding | Typical rating (R app) | Note |
|---------|------------------------|------|
| Debuggable release build, `get-task-allow` in a shipped build, WebView inspection on in release | Medium to High, any profile | [MASWE-0063](/mobile/maswe-0063-debug-mechanisms-not-disabled/) |
| Hidden debug switch that disables TLS validation or authentication | High, any profile | [MASWE-0061](/mobile/maswe-0061-debug-artifacts-not-removed/) |
| No server-side app or device attestation on an API that bots abuse | Medium to High | [MASWE-0054](/mobile/maswe-0054-device-attestation-not-implemented/), [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/) |
| Attestation requested but never verified or enforced server-side | Medium to High | same |
| Security-relevant local data trusted without integrity check (entitlement flag, counter) | Low to Medium; higher with monetary impact | [MASWE-0057](/mobile/maswe-0057-app-resources-integrity-not-verified/) |
| No root/jailbreak, emulator, debugger or hook detection | Low to Medium | 0051, 0053, 0064, 0065 notes |
| Detection present, bypassed with one public command or hook | By what it protects | all detection notes |
| No obfuscation; debug symbols or verbose logs in release | Low (Info outside R) | [MASWE-0059](/mobile/maswe-0059-code-obfuscation-not-implemented/), [MASWE-0061](/mobile/maswe-0061-debug-artifacts-not-removed/) |
| V1-only APK signing with `minSdk` ≥ 24, RSA key under 2048 bits | Low to Medium | [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/) |

## The four controls and their weaknesses

OWASP links each weakness to controls through the `mappings.masvs-v2` field of its MASWE file. Several weaknesses map to two RESILIENCE controls, and three map outside the category.

### MASVS-RESILIENCE-1: platform integrity

*"The app validates the integrity of the platform."* Many MASVS controls assume a trustworthy OS: secure storage relies on the sandbox, biometrics rely on the TEE, IPC relies on permissions. This control asks the app to check that assumption.

- **[MASWE-0051](/mobile/maswe-0051-root-jailbreak-detection-not-implemented/)** root/jailbreak detection (also RESILIENCE-4).
- **[MASWE-0052](/mobile/maswe-0052-app-virtualization-detection-not-implemented/)** app-virtualization and cloning environments: the app runs inside another app's process, without root.
- **[MASWE-0053](/mobile/maswe-0053-emulator-virtual-device-detection-not-implemented/)** emulators and virtual devices (also RESILIENCE-4).
- **[MASWE-0054](/mobile/maswe-0054-device-attestation-not-implemented/)** device attestation: server-verifiable evidence about the device, from Android key attestation, Play Integrity, or Apple's DeviceCheck and App Attest.

### MASVS-RESILIENCE-2: anti-tampering

*"The app implements anti-tampering mechanisms."* The app should notice when its code, resources or runtime have been modified, and when hostile software on the device targets it.

- **[MASWE-0055](/mobile/maswe-0055-malware-detection-not-implemented/)** malware detection: accessibility and overlay abuse, platform threat signals, account-level response.
- **[MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/)** app attestation and signing: Play Integrity `appIntegrity`, key attestation's application ID, App Attest, current APK signature schemes and iOS CodeDirectory versions.
- **[MASWE-0057](/mobile/maswe-0057-app-resources-integrity-not-verified/)** resource and storage integrity (also **MASVS-CODE-4**).
- **[MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/)** runtime code integrity: patched code pages, injected libraries, hooked prologues.

### MASVS-RESILIENCE-3: anti-static analysis

*"The app implements anti-static analysis mechanisms."* Understanding comes before tampering; this control makes understanding expensive.

- **[MASWE-0059](/mobile/maswe-0059-code-obfuscation-not-implemented/)** code obfuscation, Java/Kotlin and native.
- **[MASWE-0060](/mobile/maswe-0060-resource-obfuscation-not-implemented/)** resource obfuscation: strings, configuration, asset names.
- **[MASWE-0061](/mobile/maswe-0061-debug-artifacts-not-removed/)** debug artefacts: symbols, StrictMode, verbose logging, test code and hidden switches.
- **[MASWE-0062](/mobile/maswe-0062-no-application-level-payload-encryption/)** application-level payload encryption (also **MASVS-NETWORK-1**).

### MASVS-RESILIENCE-4: anti-dynamic analysis

*"The app implements anti-dynamic analysis techniques."* Observing and manipulating the running app is the fastest route to understanding it.

- **[MASWE-0063](/mobile/maswe-0063-debug-mechanisms-not-disabled/)** debug mechanisms not disabled (also **MASVS-PLATFORM-2**).
- **[MASWE-0064](/mobile/maswe-0064-debugger-detection-not-implemented/)** debugger detection.
- **[MASWE-0065](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/)** detection of Frida, Xposed/LSPosed, ElleKit/Substrate and similar tools.
- MASWE-0051 and MASWE-0053 map here too: root and emulators are where dynamic analysis happens.

### Cross-maps outside the category

- **MASWE-0057 → MASVS-CODE-4.** Tampered storage is untrusted input. The CODE side (what happens when the data reaches a sink) is in our [MASWE-0050 note](/mobile/maswe-0050-unsafe-handling-of-untrusted-data/); the signature mechanics are in [MASWE-0011](/mobile/maswe-0011-improper-signature-verification/).
- **MASWE-0062 → MASVS-NETWORK-1.** Payload encryption sits on top of TLS, never instead of it. TLS and pinning are in the [NETWORK hub](/mobile/masvs-network-secure-communication-guide/) and [MASWE-0028](/mobile/maswe-0028-insecure-identity-pinning/).
- **MASWE-0063 → MASVS-PLATFORM-2.** WebView debugging exposes the WebView's content and bridges; see [MASWE-0033](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/) and [MASWE-0034](/mobile/maswe-0034-webviews-allow-access-to-local-resources/).

In MASVS v1 terms, the weaknesses map to MSTG-RESILIENCE-1 (0051), 2 (0063, 0064), 3 (0057), 4 (0065), 5 (0053), 6 (0058), 9 and 12 (0059), 10 (0054), 11 (0060), 13 (0062), MSTG-CODE-1 (0056) and MSTG-CODE-3/4 (0061). MASWE-0051 and 0053 also list MSTG-RESILIENCE-8 (detection must trigger a response). MASWE-0052 and 0055 have no v1 mapping.

## The series

| Note | Weakness | Controls | Profiles | OWASP tests: Android | OWASP tests: iOS | Legacy v1 replaced |
|------|----------|----------|----------|----------------------|------------------|--------------------|
| [Root/Jailbreak Detection Not Implemented](/mobile/maswe-0051-root-jailbreak-detection-not-implemented/) | MASWE-0051 | RES-1, RES-4 | R, EUDIW | 0324, 0325 | 0240, 0241 | 0045, 0088 |
| [App Virtualization Detection Not Implemented](/mobile/maswe-0052-app-virtualization-detection-not-implemented/) | MASWE-0052 | RES-1 | R, EUDIW | none | none | — |
| [Emulator/Virtual Device Detection Not Implemented](/mobile/maswe-0053-emulator-virtual-device-detection-not-implemented/) | MASWE-0053 | RES-1, RES-4 | R, EUDIW | 0351 | 0367 | 0049, 0092 |
| [Device Attestation Not Implemented](/mobile/maswe-0054-device-attestation-not-implemented/) | MASWE-0054 | RES-1 | R, EUDIW | none | none | — |
| [Malware Detection Not Implemented](/mobile/maswe-0055-malware-detection-not-implemented/) | MASWE-0055 | RES-2 | R, EUDIW | none | none | — |
| [App Attestation Not Implemented](/mobile/maswe-0056-app-attestation-not-implemented/) | MASWE-0056 | RES-2 | R, EUDIW | 0224, 0225 | 0220 | 0038, 0081 |
| [App Resources Integrity Not Verified](/mobile/maswe-0057-app-resources-integrity-not-verified/) | MASWE-0057 | RES-2, CODE-4 | R, EUDIW | 0338 | 0387 | 0047, 0090 (and CODE 0002) |
| [Runtime Code Integrity Not Verified](/mobile/maswe-0058-runtime-code-integrity-not-verified/) | MASWE-0058 | RES-2 | R, EUDIW | 0341 | 0354 | 0050; 0048 and 0091 shared with 0065 |
| [Code Obfuscation Not Implemented](/mobile/maswe-0059-code-obfuscation-not-implemented/) | MASWE-0059 | RES-3 | R, EUDIW | 0368, 0369 | 0391 | 0051, 0093 |
| [Resource Obfuscation Not Implemented](/mobile/maswe-0060-resource-obfuscation-not-implemented/) | MASWE-0060 | RES-3 | R, EUDIW | none | none | — |
| [Debug Artifacts Not Removed](/mobile/maswe-0061-debug-artifacts-not-removed/) | MASWE-0061 | RES-3 | R, EUDIW | 0263, 0264, 0265, 0288 | 0219, 0358, 0359 | 0040, 0041, 0083, 0084 |
| [No Application-Level Payload Encryption](/mobile/maswe-0062-no-application-level-payload-encryption/) | MASWE-0062 | RES-3, NETWORK-1 | R, EUDIW | none | none | — |
| [Debug Mechanisms Not Disabled](/mobile/maswe-0063-debug-mechanisms-not-disabled/) | MASWE-0063 | RES-4, PLATFORM-2 | R, EUDIW | 0226, 0227 | 0261 | 0039, 0082 |
| [Debugger Detection Not Implemented](/mobile/maswe-0064-debugger-detection-not-implemented/) | MASWE-0064 | RES-4 | R, EUDIW | 0352, 0353 | 0401, 0402 | 0046, 0089 |
| [Dynamic Analysis Tools Detection Not Implemented](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/) | MASWE-0065 | RES-4 | R, EUDIW | none (see 0341) | none (see 0354) | 0048, 0091 (shared with 0058) |

OWASP tags all fifteen weaknesses for both platforms, and every note covers both. Where OWASP has no test, the note's Guler Tech tests (`GT-RES-00NN-x`) are the only tests; elsewhere they fill platform gaps or go beyond OWASP. The series has 30 OWASP tests and 34 Guler Tech tests.

**Where the Knowledge lives.** OWASP does not link Knowledge items from the weakness files, so we placed them by topic:

- **0051:** root detection (KNOW-0027), jailbreak detection (KNOW-0084); best practices BEST-0029 and BEST-0030.
- **0053:** emulator detection (KNOW-0031), iOS Simulator detection (KNOW-0088), virtual devices (KNOW-0135), iPhone apps on Apple silicon Macs (KNOW-0136), and a summary of KNOW-0112; BEST-0046 and BEST-0053.
- **0054:** Play Integrity (KNOW-0035), key attestation (KNOW-0119) and device attestation (KNOW-0120), device binding (KNOW-0034, KNOW-0090). KNOW-0119 and KNOW-0120 are OWASP placeholders, so the note writes them from vendor documentation.
- **0055:** pointers to BEST-0040 (overlays) and BEST-0075 (accessibility); the attack side is in our [MASWE-0039](/mobile/maswe-0039-app-vulnerable-to-overlay-attacks/) and [MASWE-0040](/mobile/maswe-0040-sensitive-data-leaked-via-accessibility/) notes.
- **0056:** Android app signing (KNOW-0003, summarised; the deep dive is our [KNOW-0003 note](/mobile/mastg-know-0003-app-signing/)), iOS app signing (KNOW-0058); BEST-0006.
- **0057:** file integrity (KNOW-0029), Shared Preferences (KNOW-0036, from OWASP's STORAGE folder), iOS storage integrity (KNOW-0086), a summary of KNOW-0109; BEST-0065 and BEST-0066.
- **0058:** runtime integrity (KNOW-0032), RASP (KNOW-0118), iOS source code integrity (KNOW-0140), a summary of KNOW-0110; BEST-0041, BEST-0048, BEST-0067.
- **0059:** obfuscation (KNOW-0033, KNOW-0089), summaries of KNOW-0111, 0113 and 0116; BEST-0029.
- **0061:** debug symbols (KNOW-0008, KNOW-0063), StrictMode (KNOW-0009), non-production resources (KNOW-0064), iOS logs (KNOW-0101, summary); BEST-0022. Our [CODE hub](/mobile/masvs-code-code-quality-guide/) has short versions of several of these; this series owns the full treatment.
- **0063:** debuggable apps (KNOW-0007, KNOW-0062); BEST-0007 and BEST-0008.
- **0064:** anti-debugging (KNOW-0028, KNOW-0085), a summary of KNOW-0114; BEST-0047 and BEST-0074.
- **0065:** reverse-engineering tool detection (KNOW-0030, KNOW-0087), a summary of KNOW-0115; BEST-0053 and a pointer to BEST-0048.
- **0052, 0060, 0062:** no OWASP Knowledge; each note has a `Background` section of its own.

## Test index

All 30 OWASP v2 tests whose `maswe` field names a RESILIENCE weakness, grouped by weakness. **Type** is OWASP's own classification. All 30 live in OWASP's MASVS-RESILIENCE folder and none is a placeholder. The **Note** column links to the note that documents the test in full, with prerequisites, steps, evidence, pass and fail criteria, and a demo.

| ID (OWASP page) | Title | Platform | Type | OWASP demos | Note |
|-----------------|-------|----------|------|-------------|------|
| **MASWE-0051: root/jailbreak detection** | | | | | |
| [MASTG-TEST-0324](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0324/) | References to Root Detection Mechanisms | Android | static, code | 0087 | [0051](/mobile/maswe-0051-root-jailbreak-detection-not-implemented/) |
| [MASTG-TEST-0325](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0325/) | Runtime Use of Root Detection Techniques | Android | dynamic, hooks | 0088 | [0051](/mobile/maswe-0051-root-jailbreak-detection-not-implemented/) |
| [MASTG-TEST-0240](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0240/) | Jailbreak Detection in Code | iOS | static, code | 0021 | [0051](/mobile/maswe-0051-root-jailbreak-detection-not-implemented/) |
| [MASTG-TEST-0241](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0241/) | Runtime Use of Jailbreak Detection Techniques | iOS | dynamic, hooks | — | [0051](/mobile/maswe-0051-root-jailbreak-detection-not-implemented/) |
| **MASWE-0053: emulator / virtual device detection** | | | | | |
| [MASTG-TEST-0351](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0351/) | Runtime Use of Emulator Detection Techniques | Android | dynamic, hooks | 0114 | [0053](/mobile/maswe-0053-emulator-virtual-device-detection-not-implemented/) |
| [MASTG-TEST-0367](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0367/) | Runtime Use of Virtual Device Detection Techniques | iOS | dynamic | 0131 | [0053](/mobile/maswe-0053-emulator-virtual-device-detection-not-implemented/) |
| **MASWE-0056: app attestation and signing** | | | | | |
| [MASTG-TEST-0224](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0224/) | Usage of Insecure APK Signature Version | Android | static, code | — | [0056](/mobile/maswe-0056-app-attestation-not-implemented/) |
| [MASTG-TEST-0225](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0225/) | Usage of Insecure APK Signature Key Size | Android | static, code | — | [0056](/mobile/maswe-0056-app-attestation-not-implemented/) |
| [MASTG-TEST-0220](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0220/) | Usage of Outdated Code Signature Format | iOS | static, code | — | [0056](/mobile/maswe-0056-app-attestation-not-implemented/) |
| **MASWE-0057: resource and storage integrity** | | | | | |
| [MASTG-TEST-0338](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0338/) | References to Storage Integrity Check APIs | Android | static, code, manual | 0101 | [0057](/mobile/maswe-0057-app-resources-integrity-not-verified/) |
| [MASTG-TEST-0387](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0387/) | References to Storage Integrity Check APIs | iOS | static, code, manual | 0150 | [0057](/mobile/maswe-0057-app-resources-integrity-not-verified/) |
| **MASWE-0058: runtime code integrity** | | | | | |
| [MASTG-TEST-0341](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0341/) | Runtime Use of Hook Detection Techniques | Android | dynamic, hooks | 0106, 0107, 0108 | [0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/) |
| [MASTG-TEST-0354](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0354/) | Runtime Use of Hook Detection Techniques | iOS | dynamic, hooks | 0117, 0118, 0119 | [0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/) |
| **MASWE-0059: code obfuscation** | | | | | |
| [MASTG-TEST-0368](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0368/) | Insufficient Obfuscation of Security-Relevant Java/Kotlin Code | Android | static, code, manual | 0132 | [0059](/mobile/maswe-0059-code-obfuscation-not-implemented/) |
| [MASTG-TEST-0369](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0369/) | Insufficient Obfuscation of Security-Relevant Native Code | Android | static, package, manual | 0133 | [0059](/mobile/maswe-0059-code-obfuscation-not-implemented/) |
| [MASTG-TEST-0391](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0391/) | Insufficient Obfuscation of Security-Relevant Native Code | iOS | static, package, manual | — | [0059](/mobile/maswe-0059-code-obfuscation-not-implemented/) |
| **MASWE-0061: debug artefacts** | | | | | |
| [MASTG-TEST-0263](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0263/) | Logging of StrictMode Violations | Android | dynamic, logs | 0037 | [0061](/mobile/maswe-0061-debug-artifacts-not-removed/) |
| [MASTG-TEST-0264](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0264/) | Runtime Use of StrictMode APIs | Android | dynamic, hooks | 0038 | [0061](/mobile/maswe-0061-debug-artifacts-not-removed/) |
| [MASTG-TEST-0265](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0265/) | References to StrictMode APIs | Android | static, code | 0039 | [0061](/mobile/maswe-0061-debug-artifacts-not-removed/) |
| [MASTG-TEST-0288](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0288/) | Debugging Symbols in Native Binaries | Android | static, code | — | [0061](/mobile/maswe-0061-debug-artifacts-not-removed/) |
| [MASTG-TEST-0219](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0219/) | Testing for Debugging Symbols | iOS | static, code | — | [0061](/mobile/maswe-0061-debug-artifacts-not-removed/) |
| [MASTG-TEST-0358](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0358/) | Implementation Details Exposure Through Logging APIs | iOS | static, code | 0124 | [0061](/mobile/maswe-0061-debug-artifacts-not-removed/) |
| [MASTG-TEST-0359](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0359/) | Implementation Details Exposure in Logs | iOS | dynamic, logs | 0125 | [0061](/mobile/maswe-0061-debug-artifacts-not-removed/) |
| **MASWE-0063: debug mechanisms** | | | | | |
| [MASTG-TEST-0226](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0226/) | Debuggable Flag Enabled in the AndroidManifest | Android | static, code | 0040 | [0063](/mobile/maswe-0063-debug-mechanisms-not-disabled/) |
| [MASTG-TEST-0227](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0227/) | Debugging Enabled for WebViews | Android | static, code | — | [0063](/mobile/maswe-0063-debug-mechanisms-not-disabled/) |
| [MASTG-TEST-0261](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0261/) | Debuggable Entitlement Enabled in the entitlements.plist | iOS | static, code | 0036 | [0063](/mobile/maswe-0063-debug-mechanisms-not-disabled/) |
| **MASWE-0064: debugger detection** | | | | | |
| [MASTG-TEST-0352](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0352/) | References to Debugging Detection APIs | Android | static, code, manual | 0115, 0116 | [0064](/mobile/maswe-0064-debugger-detection-not-implemented/) |
| [MASTG-TEST-0353](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0353/) | Runtime Use of Debugging Detection APIs | Android | dynamic, hooks, manual | — | [0064](/mobile/maswe-0064-debugger-detection-not-implemented/) |
| [MASTG-TEST-0401](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0401/) | References to Debugging Detection APIs | iOS | static, code, manual | — | [0064](/mobile/maswe-0064-debugger-detection-not-implemented/) |
| [MASTG-TEST-0402](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0402/) | Runtime Use of Debugging Detection APIs | iOS | dynamic, hooks, manual | — | [0064](/mobile/maswe-0064-debugger-detection-not-implemented/) |

That is 17 Android and 13 iOS tests: 19 static and 11 dynamic. Read the table with these caveats in mind.

- **Presence is not strength.** The detection tests (0324, 0325, 0240, 0241, 0351, 0367, 0352, 0353, 0401, 0402) fail only when *no* check is found. OWASP states explicitly that robustness is out of scope. A pass therefore means "a check exists", not "the app resists analysis". The notes add the resistance step, with the effort recorded (see [step 5](#how-to-run-a-resilience-assessment) of the workflow).
- **Hook tests test outcomes, not mechanisms.** TEST-0341 and 0354 fail if a hook on a sensitive API (`Cipher.doFinal`, `CCCrypt`, `SecItemCopyMatching`) runs and returns data. That catches both runtime-integrity checks (MASWE-0058) and tool detection (MASWE-0065), which is why the v1 "reverse engineering tools detection" tests were folded into them. MASWE-0065 itself has no test of its own; its note adds ours.
- **Static detection tests are false-negative prone.** OWASP flags 0240, 0241, 0338 and 0387 as `false_negative_prone`, and the same holds for every reference-search test: checks in native code, behind string encryption, in a commercial RASP SDK or loaded at runtime do not show up in a grep.
- **TEST-0220 is largely self-enforcing.** Since iOS 15, Apple refuses to launch apps whose signature lacks the newer format with DER entitlements, and App Store and TestFlight builds are re-signed by Apple. A failing CodeDirectory version (below 20400) is realistic only for old Ad Hoc or enterprise builds.
- **TEST-0224 needs context.** It fails V1-only signing when `minSdkVersion` ≥ 24. Android 11 and later already refuse V1-only APKs from apps that target API 30 or higher, so check `targetSdkVersion` too.
- **Demos.** Demo 0040 (debuggable flag with semgrep) belongs to TEST-0226 but lives in OWASP's PLATFORM demo folder. Demos 0108 and 0119 show OWASP bypassing the app's Frida detection to extract data. Our MASWE-0058 note describes what they detect and change in prose only and keeps its code to tracing.

## Tests in the RESILIENCE folder that belong to MASWE-0017

OWASP's MASVS-RESILIENCE test folder holds four more tests. Their `maswe` field points at MASWE-0017 (device secure lock not enforced, mapped to MASVS-CRYPTO-2), and our [MASWE-0017 note](/mobile/maswe-0017-device-secure-lock-not-enforced/) documents them in full. They are not repeated in this series.

| Test | Title | Platform | Type | Documented in |
|------|-------|----------|------|---------------|
| [MASTG-TEST-0247](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0247/) | References to APIs for Detecting Secure Screen Lock | Android | static, code | [MASWE-0017](/mobile/maswe-0017-device-secure-lock-not-enforced/) |
| [MASTG-TEST-0249](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0249/) | Runtime Use of Secure Screen Lock Detection APIs | Android | dynamic, hooks | [MASWE-0017](/mobile/maswe-0017-device-secure-lock-not-enforced/) |
| [MASTG-TEST-0248](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0248/) | References to APIs for Detecting Secure Screen Lock | iOS | static, code | [MASWE-0017](/mobile/maswe-0017-device-secure-lock-not-enforced/) |
| [MASTG-TEST-0246](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0246/) | Runtime Use of Secure Screen Lock Detection APIs | iOS | dynamic, hooks | [MASWE-0017](/mobile/maswe-0017-device-secure-lock-not-enforced/) |

The placement makes sense historically: "is a device passcode set?" is an environment check, like root detection. The weakness, however, is about keys and data that should only exist behind a device credential. If you browse mas.owasp.org by folder, the RESILIENCE folder shows 34 v2 tests (plus the legacy ones); by weakness, MASWE-0051 to 0065 list 30.

## Legacy v1 tests and their replacements

MASTG v1 had 21 tests in the RESILIENCE folders, eleven for Android and ten for iOS. All are now `status: deprecated` with a `covered_by` list. Map older reports and client checklists like this.

| Legacy test | Platform | v1 title | v1 ID | OWASP `covered_by` | Where we cover it |
|-------------|----------|----------|-------|--------------------|-------------------|
| [MASTG-TEST-0038](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0038/) | Android | Making Sure that the App is Properly Signed | CODE-1 | 0224, 0225 | [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/) |
| [MASTG-TEST-0039](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0039/) | Android | Testing whether the App is Debuggable | CODE-2 | 0226, 0227 | [MASWE-0063](/mobile/maswe-0063-debug-mechanisms-not-disabled/) |
| [MASTG-TEST-0040](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0040/) | Android | Testing for Debugging Symbols | CODE-3 | 0288 | [MASWE-0061](/mobile/maswe-0061-debug-artifacts-not-removed/) |
| [MASTG-TEST-0041](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0041/) | Android | Testing for Debugging Code and Verbose Error Logging | CODE-4 | 0263 | [MASWE-0061](/mobile/maswe-0061-debug-artifacts-not-removed/) (with 0264 and 0265) |
| [MASTG-TEST-0045](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0045/) | Android | Testing Root Detection | RESILIENCE-1 | 0324, 0325 | [MASWE-0051](/mobile/maswe-0051-root-jailbreak-detection-not-implemented/) |
| [MASTG-TEST-0046](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0046/) | Android | Testing Anti-Debugging Detection | RESILIENCE-2 | 0352, 0353 | [MASWE-0064](/mobile/maswe-0064-debugger-detection-not-implemented/) |
| [MASTG-TEST-0047](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0047/) | Android | Testing File Integrity Checks | RESILIENCE-3 | 0338 | [MASWE-0057](/mobile/maswe-0057-app-resources-integrity-not-verified/) |
| [MASTG-TEST-0048](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0048/) | Android | Testing Reverse Engineering Tools Detection | RESILIENCE-4 | 0341 | Test in [MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/); topic in [MASWE-0065](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/) |
| [MASTG-TEST-0049](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0049/) | Android | Testing Emulator Detection | RESILIENCE-5 | 0351 | [MASWE-0053](/mobile/maswe-0053-emulator-virtual-device-detection-not-implemented/) |
| [MASTG-TEST-0050](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0050/) | Android | Testing Runtime Integrity Checks | RESILIENCE-6 | 0341 | [MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/) |
| [MASTG-TEST-0051](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0051/) | Android | Testing Obfuscation | RESILIENCE-9 | 0368, 0369 | [MASWE-0059](/mobile/maswe-0059-code-obfuscation-not-implemented/) |
| [MASTG-TEST-0081](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0081/) | iOS | Making Sure that the App Is Properly Signed | CODE-1 | 0220 | [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/) |
| [MASTG-TEST-0082](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0082/) | iOS | Testing whether the App is Debuggable | CODE-2 | 0261 | [MASWE-0063](/mobile/maswe-0063-debug-mechanisms-not-disabled/) |
| [MASTG-TEST-0083](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0083/) | iOS | Testing for Debugging Symbols | CODE-3 | 0219 | [MASWE-0061](/mobile/maswe-0061-debug-artifacts-not-removed/) |
| [MASTG-TEST-0084](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0084/) | iOS | Testing for Debugging Code and Verbose Error Logging | CODE-4 | 0358, 0359 | [MASWE-0061](/mobile/maswe-0061-debug-artifacts-not-removed/) |
| [MASTG-TEST-0088](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0088/) | iOS | Testing Jailbreak Detection | RESILIENCE-1 | 0240, 0241 | [MASWE-0051](/mobile/maswe-0051-root-jailbreak-detection-not-implemented/) |
| [MASTG-TEST-0089](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0089/) | iOS | Testing Anti-Debugging Detection | RESILIENCE-2 | 0401, 0402 | [MASWE-0064](/mobile/maswe-0064-debugger-detection-not-implemented/) |
| [MASTG-TEST-0090](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0090/) | iOS | Testing File Integrity Checks | RESILIENCE-3, 11 | 0387 | [MASWE-0057](/mobile/maswe-0057-app-resources-integrity-not-verified/) |
| [MASTG-TEST-0091](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0091/) | iOS | Testing Reverse Engineering Tools Detection | RESILIENCE-4 | 0354 | Test in [MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/); topic in [MASWE-0065](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/) |
| [MASTG-TEST-0092](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0092/) | iOS | Testing Emulator Detection | RESILIENCE-5 | 0367 | [MASWE-0053](/mobile/maswe-0053-emulator-virtual-device-detection-not-implemented/) |
| [MASTG-TEST-0093](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0093/) | iOS | Testing Obfuscation | RESILIENCE-9 | 0391 | [MASWE-0059](/mobile/maswe-0059-code-obfuscation-not-implemented/) |

**Gaps in the mapping.** The legacy CODE test [MASTG-TEST-0002](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0002/) (local storage input validation) also points to TEST-0338, so the MASWE-0057 note picks it up. TEST-0041's `covered_by` names only 0263, although 0264 and 0265 test StrictMode too; and its verbose-logging half has no Android v2 equivalent of iOS 0358/0359, so the MASWE-0061 note handles Android logging with our own method. The v1 requirements for device binding (MSTG-RESILIENCE-10), resource encryption (11) and payload encryption (13) never had dedicated v1 tests; their v2 weaknesses (0054, 0060, 0062) have no OWASP tests either.

## Generic reverse-engineering Knowledge

OWASP's `generic/MASVS-RESILIENCE` Knowledge folder holds eight items, MASTG-KNOW-0109 to 0116. They describe the attacker's toolbox rather than a defence, and no weakness or test links to them. Each weakness note that relies on one carries a short summary; here is what each says, what we add, and where it is used.

**Binary Patching (MASTG-KNOW-0109).** Changing the compiled app: bytecode, native instructions or resources, by hex editing or by decompiling, editing and rebuilding (apktool and smali on Android). Modern platforms enforce code signing, so a patched app must be re-signed (Android) or run on a device whose signature enforcement is relaxed (a jailbreak, or a re-signed sideload with a developer profile on iOS). That re-signing step is exactly what signature checks, Play Integrity's `appIntegrity` verdict and App Attest detect. Used in the [MASWE-0057](/mobile/maswe-0057-app-resources-integrity-not-verified/) note (summary) and relevant to [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/). [OWASP page](https://mas.owasp.org/MASTG/knowledge/generic/MASVS-RESILIENCE/MASTG-KNOW-0109/).

**Code Injection (MASTG-KNOW-0110).** Loading code into the running process to read memory and replace functions. OWASP names the three frameworks that matter: Frida (both platforms, with an injectable JavaScript runtime), Xposed and its LSPosed successor (Android, ART method hooking) and ElleKit (iOS, the modern Cydia Substrate replacement). In-memory changes leave the package and its signature untouched, which is why package-signature checks alone do not catch them and why MASWE-0058 exists. Used in the [MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/) note (summary). [OWASP page](https://mas.owasp.org/MASTG/knowledge/generic/MASVS-RESILIENCE/MASTG-KNOW-0110/).

**Obfuscation (MASTG-KNOW-0111).** Name obfuscation, instruction substitution, control-flow flattening, dead-code injection, string encryption and packing, with the honest caveat that none of them stops a funded attacker. The practical point for testers: R8 renames, shrinks and optimises (including inlining and class merging), but it does not encrypt strings or obfuscate control flow, and it never touches native code; anything beyond that needs a further tool. Packing appears in some commercial protectors and in malware; the series treats it only as something you may meet when inventorying protections. Used in the [MASWE-0059](/mobile/maswe-0059-code-obfuscation-not-implemented/) note (summary). [OWASP page](https://mas.owasp.org/MASTG/knowledge/generic/MASVS-RESILIENCE/MASTG-KNOW-0111/).

**Emulation-based Dynamic Analysis (MASTG-KNOW-0112).** Emulators give full control and snapshots; Android has many (the AVD emulator is QEMU-based), iOS has the Xcode Simulator, which is not an emulator. Two corrections. OWASP says the Simulator lacks a kernel so syscalls cannot run; in fact Simulator apps are macOS processes using the host's XNU kernel, and the real limit is that device (`iphoneos`) binaries do not run there at all. OWASP also calls Corellium the only iOS emulator. It is the main commercial option, but research projects that virtualise iOS exist (MASWE-0053 cites one), and on Apple silicon Macs iPhone apps can run natively (KNOW-0136). Used in the [MASWE-0053](/mobile/maswe-0053-emulator-virtual-device-detection-not-implemented/) note (summary). [OWASP page](https://mas.owasp.org/MASTG/knowledge/generic/MASVS-RESILIENCE/MASTG-KNOW-0112/).

**Using Disassemblers and Decompilers (MASTG-KNOW-0113).** Why disassembly is hard (code versus data, indirect branches, hand-written assembly) and why decompiler output is approximate. In practice: jadx for DEX, apktool for smali and resources, Ghidra, radare2/rizin or a commercial disassembler for ELF and Mach-O. Obfuscation is judged by how badly it degrades this output. Used in the [MASWE-0059](/mobile/maswe-0059-code-obfuscation-not-implemented/) note (summary). [OWASP page](https://mas.owasp.org/MASTG/knowledge/generic/MASVS-RESILIENCE/MASTG-KNOW-0113/).

**Debugging and Tracing (MASTG-KNOW-0114).** Debuggers stop, inspect and change a process; tracers log what it does. On Android that means JDWP (`jdb`, Android Studio) for Java and `ptrace`-based native debuggers (lldb); on iOS, `debugserver` with lldb. Both platforms allow only one `ptrace` tracer per process, which is the basis of many anti-debugging tricks and of the `TracerPid` and `P_TRACED` checks. Used in the [MASWE-0064](/mobile/maswe-0064-debugger-detection-not-implemented/) note (summary). [OWASP page](https://mas.owasp.org/MASTG/knowledge/generic/MASVS-RESILIENCE/MASTG-KNOW-0114/).

**Dynamic Binary Instrumentation (MASTG-KNOW-0115).** Instruction-level instrumentation by rewriting code at runtime. OWASP's item is short and dated: it names Valgrind and PIN. On mobile today the common DBI engines are Frida's Stalker and QBDI. DBI leaves fewer named artefacts than hooking but changes timing and memory layout, which is what generic integrity and timing checks look for. Used in the [MASWE-0065](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/) note (summary). [OWASP page](https://mas.owasp.org/MASTG/knowledge/generic/MASVS-RESILIENCE/MASTG-KNOW-0115/).

**Symbolic Execution (MASTG-KNOW-0116).** Representing program paths as formulas and solving them with an SMT solver, usually combined with concrete execution (concolic execution) to avoid path explosion; angr is the usual framework, and MASTG-TECH-0037 applies it to an Android licence check. It is relevant to resilience because it is one of the standard ways to simplify opaque predicates and virtualisation-based obfuscation. Used in the [MASWE-0059](/mobile/maswe-0059-code-obfuscation-not-implemented/) note (summary). [OWASP page](https://mas.owasp.org/MASTG/knowledge/generic/MASVS-RESILIENCE/MASTG-KNOW-0116/).

## Cross-cutting design guidance: RASP signals

Two OWASP items frame every detection note in the series. [MASTG-BEST-0029 "Implementing Resilience and RASP Signals"](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0029/) is referenced by the root, obfuscation and debugger tests, but it is a **placeholder**: OWASP has published only its front-matter note, which says resilience controls are defence in depth, inherently bypassable, and should be chosen and tuned to the threat model. [MASTG-KNOW-0118 "Runtime Application Self-Protection (RASP)"](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0118/) (filed under Android, but platform-neutral) describes RASP's capabilities (environment detection, code integrity, anti-tampering, anti-debugging, response), the choice between self-implemented checks, commercial SDKs and compiler-based protectors, Play Integrity as the platform service, and the limits: bypassable, a cat-and-mouse game, a performance cost and false positives on custom ROMs and accessibility tools. The rest of this section is our guidance; each note applies it to its own weakness.

### Client signals, server decision

Design RASP as a **sensor**, not a judge. The client collects signals and the backend decides.

- **Collect many weak signals, not one strong one.** File and property checks, mount and process checks, loaded-library and memory-map checks, hook and debugger checks, emulator traits. Each is cheap to defeat alone; together, implemented in different layers (Kotlin/Swift, native, inlined syscalls), they cost more.
- **Bind the signals to evidence the attacker cannot forge on the device.** On Android, a Play Integrity token (standard request with a `requestHash` over the action) or a key-attestation chain for a Keystore key; on iOS, an App Attest assertion over the request, with DeviceCheck bits for per-device state. The backend verifies these with Google or Apple, checks freshness and binding, and treats a missing or unverifiable token as a negative signal, never as "skip".
- **Do not send verdicts as booleans.** A request that says `"rooted": false` is worthless: the attacker controls it. Send the raw observations inside an integrity-protected envelope (signed with an attested key), and let the server score them.
- **Fail closed on the server, not on the client.** A client that cannot reach the attestation service should get a degraded session, not full access.

### Response strategies

| Response | Where it runs | Good for | Watch out for |
|----------|---------------|----------|---------------|
| Observe and report only | Client → server | Telemetry, tuning thresholds, fraud models | No protection by itself; attacker may strip the reporting |
| Warn the user | Client | Consumer apps on rooted devices; malware hints (MASWE-0055) | Easily dismissed; tells the attacker a check fired |
| Degrade: disable high-risk features | Server, enforced on API | Payments, payee changes, offline content | Must be enforced by the API, not by hiding a button |
| Step-up: re-authenticate, out-of-band confirmation | Server | Suspicious environment during a sensitive action | UX cost; needs a channel the attacker does not control |
| Block the session or the device | Server | Confirmed tampering, failed attestation on critical APIs | False positives on custom ROMs, beta OS versions |
| Terminate the app | Client | Debugger or hook attached during a sensitive operation | An immediate, deterministic exit points straight at the check; delayed or randomised responses are harder to trace |
| Wipe local secrets | Client | Tokens and keys on a device now known to be compromised | Must not destroy user data unrecoverably |
| Account-level action | Server | Malware-driven account takeover (MASWE-0055) | Blocks the attacker's *other* devices too, which is the point |

### Telemetry

RASP that never reports is invisible to the business. Recommend that detections are reported to the backend with the signal type, app version, OS version and an attestation result, rate-limited and integrity-protected, and that someone owns the dashboard. Two things to check when you test: that reporting still happens when the app is about to terminate (send first, then exit), and that an attacker who blocks the reporting endpoint does not thereby get a "clean" device (missing telemetry should itself be a signal).

### What this means for testing

When you assess a RASP setup, separate three questions and report each: **does a check exist and run** (the OWASP tests), **what does it cost to neutralise on your own device** (our effort scale below), and **does the server notice anyway** (attestation and telemetry). An app whose client checks fall to one hook but whose backend refuses the request because the Play Integrity verdict is missing is in far better shape than an app with an elaborate native RASP and a backend that trusts everything.

## What each attacker position can prove

In the other categories, "controller of the device" was only methodology: your rooted phone proved a path existed, and a real attacker had to travel it. In RESILIENCE it is the **primary attacker**. Name the position in every finding anyway, because several weaknesses matter for other attackers too.

| Attacker position | What it needs | Weaknesses it reaches | What a successful test proves | What it cannot prove |
|-------------------|---------------|-----------------------|-------------------------------|----------------------|
| **Device owner as reverse engineer** | Own device with root or jailbreak, Frida, a debugger, time | All fifteen | How much effort each protection costs, and what bypassing it unlocks | Harm to other users, unless the knowledge scales (a published cracked build, a bot) |
| **Repackager / redistributor** | A copy of the package, re-signing (Android) or a sideload or jailbreak route (iOS), a third-party store or a social-engineering channel | 0056, 0057, 0058, 0059, 0060 | Whether a modified, re-signed copy runs and is still served by the backend | User reach; that is distribution, not a client test |
| **Bot operator / device or emulator farm** | Scripted clients, emulators, many cheap or virtual devices | 0053, 0054, 0056, 0062, 0052 (cloning) | Whether the backend can tell genuine app instances on genuine devices from scripts and farms | Volume-based abuse controls (rate limits, risk engines) that sit outside the app |
| **Malware on the victim's device, no root** | User-installed app with accessibility, overlay or "dual app" capabilities | 0055, 0052, with [MASWE-0039](/mobile/maswe-0039-app-vulnerable-to-overlay-attacks/) and [MASWE-0040](/mobile/maswe-0040-sensitive-data-leaked-via-accessibility/) | Whether the app notices the hostile capabilities and responds, ideally at account level | Malware that the platform itself would block; the malware's own delivery |
| **Malware or attacker with root on the victim's device** | A rooting exploit or an already rooted phone | 0051, 0057, 0058, 0065 | Whether data and logic survive a privileged attacker on someone else's device | Exploit availability; rate on what root gives once present |
| **Person with USB access to an unlocked phone** | Physical access, developer options, no root | 0063 (`run-as`, JDWP, `chrome://inspect`, Safari Web Inspector), 0061 (logs via `adb logcat` or Console) | That a debuggable build or inspectable WebView exposes data and control flow without root | Anything that needs root or a jailbreak |
| **Anyone who downloads the package** | The APK or a decrypted IPA | 0059, 0060, 0061 (symbols, strings, staging endpoints), 0056 (signing scheme) | How fast security logic, endpoints and secrets can be located | Runtime behaviour |
| **Network attacker** | A position on the path; TLS must already be broken | 0062 only as a second layer | Nothing new if TLS and pinning hold; see the [NETWORK hub](/mobile/masvs-network-secure-communication-guide/) | — |

The rule of thumb: in this category your rooted phone *is* the attacker, so record effort and outcome rather than "exploitability". The rating then depends on what the effort buys (see [the series-wide rule](#rating-findings-the-series-wide-rule)) and on whether the server-side signals would have caught it.

## How to run a resilience assessment

Each note has the detailed procedures. This is the order we run them in on an engagement, and what each step feeds into the next.

### 1. Scope and threat model

- Confirm the **profile**. Is R in scope? If not, agree that resilience gaps are observations, and still test MASWE-0063 and the security-relevant half of MASWE-0061.
- Write down the **assets** the protections are meant to guard: offline entitlements, content keys, payment and onboarding APIs, risk-scoring logic, credentials in memory.
- Write down the **abuse cases**: cheating, cracked premium features, bot onboarding, mule accounts, malware-driven takeover. Each finding is rated against one of them.
- Agree the **time box per protection** (we use half a day per class of check by default) and that results are reported as effort, not as pass or fail alone.
- Ask whether a **commercial RASP** or protector is used, and for **backend access or logs** for the server-side checks in step 6. Without them, you can only infer server behaviour from responses.

### 2. Lab set-up

You need hostile and clean environments side by side. Our [traffic interception lab](/mobile/mobile-traffic-interception-lab/) covers proxies, Frida, objection and device preparation.

- **Android, rooted:** a physical device with an unlocked bootloader and root, `frida-server` matching your Frida version, Xposed/LSPosed available for the hooking-framework checks.
- **Android, stock:** a physical device with a locked bootloader, current patch level and Google Play services. It is your baseline: it should get a clean Play Integrity verdict and pass every check.
- **Android, emulator:** an AVD with a Google APIs image (where `adb root` works) for MASWE-0053, and a Google Play image for the store-like baseline.
- **iOS, jailbroken:** a device on a jailbreakable iOS version (rootful or rootless), with Frida and a way to run `debugserver`.
- **iOS, stock:** a current, non-jailbroken device with your test build or the store build.
- **Optional:** a Corellium virtual device for MASWE-0053, an Apple silicon Mac for iPhone-apps-on-Mac checks (KNOW-0136), a clone or dual-app environment for MASWE-0052.

Record the exact OS versions, patch levels, root or jailbreak method and tool versions in the report. Detection results change with every one of them.

### 3. Static inventory of protections

Before running anything, find what the app *claims* to do.

- **Package facts:** signing schemes and key size (`apksigner`), `debuggable` (`aapt2`), `minSdk`/`targetSdk`; CodeDirectory version, entitlements and provisioning profile (`codesign`, `ldid`, `security cms`).
- **Symbols and strings:** paths and package names associated with root, jailbreak, emulators and hooking frameworks (`/system/xbin/su`, `magisk`, `/Applications/Cydia.app`, `frida`, `re.frida.server`, `27042`, `TracerPid`, `ro.kernel.qemu`, `goldfish`), anti-debug imports (`ptrace`, `sysctl`, `getppid`, `task_get_exception_ports`, `isDebuggerConnected`), integrity APIs (`Mac`, `Signature`, `MessageDigest`, `HMAC`, `CC_SHA256`, `SecKeyCreateSignature`), attestation APIs (`IntegrityManager`, `StandardIntegrityManager`, `KeyGenParameterSpec.Builder#setAttestationChallenge`, `DCAppAttestService`, `DCDevice`).
- **Obfuscation level:** what jadx and Ghidra show of the security logic; whether strings are encrypted; whether native code is flattened. This sets your expectation for step 5.
- **Debug leftovers:** symbols, StrictMode, logging calls, staging endpoints, hidden menus and flags.
- **SDK fingerprints:** commercial RASP and protector SDKs usually have recognisable class prefixes or native library names. Note them; their presence moves the assessment from "is there a check?" to "is it configured and enforced?".

Run the static OWASP tests here: 0224, 0225, 0226, 0227, 0265, 0288, 0324, 0338, 0352, 0368, 0369 on Android; 0219, 0220, 0240, 0261, 0358, 0387, 0391, 0401 on iOS.

### 4. Runtime tracing

Now watch the app's own checks run, first on the stock device (what a normal user triggers), then on the hostile one.

- Trace file and property probes (`open`, `access`, `stat`, `fopen`, `__system_property_get`, `File.exists`, `NSFileManager fileExistsAtPath:`), process and memory-map reads (`/proc/self/maps`, `/proc/self/status`), sockets to local ports, `dlopen` and `_dyld_image_count` style enumeration, and the anti-debug calls.
- Record **what** is probed, **when** (startup only, or around sensitive operations), **from which layer**, and **what the app does** with the result: nothing, a log line, a dialog, an exit, a network call.
- Watch the network for telemetry and attestation tokens while the checks fire.

Run the dynamic OWASP tests here: 0263, 0264, 0325, 0341, 0351, 0353 on Android; 0241, 0354, 0359, 0367, 0402 on iOS. Expect anti-instrumentation to interfere with tracing itself; if the app dies as soon as Frida attaches, that is a result (record it) and the next step starts there.

### 5. Resistance verification, with effort recorded

For each class of check, neutralise the **app's own check** on your own test device using well-known public techniques, in increasing order of effort, and stop at the first that works. Record the level you reached.

| Level | What it took | Typical examples |
|-------|--------------|------------------|
| E0 | Nothing: no check, or the check has no effect | App runs normally on root with full functionality |
| E1 | One public, generic command or script | objection `android root disable` or `ios jailbreak disable`; a public Frida CodeShare script for common checks |
| E2 | A short custom hook on an identified method | A Frida hook changing the return value of the app's own `isCompromised()`; `frida-server` renamed and on a non-default port |
| E3 | Several hooks or native work, under a day | Hooking native checks, inlined syscalls, multiple redundant checks, simple binary patching of a branch |
| E4 | Deobfuscation or custom tooling, days | Flattened native code, encrypted strings, integrity checks over the checks themselves |
| E5 | Not neutralised within the time box | Record what was tried and how far you got |

Then repeat the sensitive action (payment, content playback, premium feature) with the check neutralised and see whether the **server** still serves it. That outcome, together with the effort level, is what the finding is rated on. The detailed hooks for each class of check are in the weakness notes; they always target the app under test and stop at tracing for OWASP's data-extraction demos.

### 6. Server-side attestation checks

This step tests the backend's handling of attestation evidence, not the attestation services themselves.

- **Is the token checked at all?** Remove it, send an empty or malformed value, send one from a different request. The API must refuse or degrade.
- **Freshness and binding:** replay a captured token after the agreed window; reuse a Play Integrity token whose `requestHash` or `nonce` belongs to another action; reuse an App Attest assertion with an old counter. Each must fail.
- **Identity checks:** the backend should compare `requestPackageName`, `appIntegrity.packageName` and `certificateSha256Digest` (Play Integrity), the `attestationApplicationId` package and signing digests (key attestation), or the App ID in the App Attest attestation, with expected values.
- **Verdict enforcement:** use the stock and rooted lab devices honestly. On the rooted device the device verdict should be empty or reduced; does the API still allow the sensitive action? Is `UNEVALUATED` treated as success?
- **Policy quality:** whether the backend asks for `MEETS_STRONG_INTEGRITY` where it matters (since 2025, on Android 13 and later this label requires `MEETS_DEVICE_INTEGRITY` plus security updates in the last year for all partitions; on Android 12 and lower it requires only hardware-backed boot integrity), uses `appAccessRiskVerdict` and `playProtectVerdict` for malware-sensitive flows, checks key-attestation chains against Google's roots (including the ECDSA root that began signing chains on 1 February 2026) and the revocation list at `https://android.googleapis.com/attestation/status`, and checks `rootOfTrust` (`verifiedBootState`, `deviceLocked`).
- **Fail-open paths:** devices without Google Play services, iOS versions or devices where App Attest is unsupported (`DCAppAttestService.isSupported` is false), and service outages. What does the backend do, and can a client choose that path deliberately?

Out of scope here, as everywhere in the series: any attempt to make a compromised device pass attestation. Spoofing ecosystems exist (leaked keyboxes, attestation-spoofing modules); the reason revocation lists, `MEETS_STRONG_INTEGRITY` and server-side risk scoring matter is precisely that they raise the cost of those ecosystems. Mention that in the report; do not demonstrate it.

### 7. Reporting effort-based results

For each protection class, report:

- **Presence:** the OWASP test result (check found or not, static and runtime).
- **Coverage:** which layers and moments the check runs in (startup only, or around sensitive operations; Java only, or native too).
- **Effort:** the E-level reached, the technique used, the time spent, and the tool versions.
- **Outcome:** what neutralising it unlocked, and whether the server noticed (attestation, telemetry, session controls).
- **Rating:** by the [series-wide rule](#rating-findings-the-series-wide-rule), with the profile stated.

Recommendations should prefer moving decisions to the server, adding attested evidence, and diversifying checks over "add more root checks". Effort results are a snapshot: name the date and the tool versions, and suggest re-testing after major OS or tool releases.

## Command cheat sheet

The most-used commands from the series. Package and paths are placeholders: `com.example.app`, `app.apk`, `Payload/App.app`. Each note has the full procedure and how to read the output.

### Package facts and signing

```bash
# Android: signature schemes, signer certificate and key size (MASWE-0056)
apksigner verify --verbose --print-certs app.apk | grep -E 'Verified using|key size|Signer #'
# Android: debuggable flag, SDK levels (MASWE-0063)
aapt2 dump badging app.apk | grep -E "^package:|sdkVersion|targetSdkVersion|application-debuggable"
aapt2 dump xmltree --file AndroidManifest.xml app.apk | grep -iE 'debuggable|extractNativeLibs'
adb shell dumpsys package com.example.app | grep -E 'pkgFlags|privateFlags'

# iOS: CodeDirectory version, entitlements, profile (MASWE-0056, 0063)
codesign -dvvv Payload/App.app 2>&1 | grep -E 'CodeDirectory|TeamIdentifier|Authority'
codesign -d --entitlements :- Payload/App.app | grep -A1 get-task-allow
ldid -e Payload/App.app/App | grep -A1 get-task-allow
security cms -D -i Payload/App.app/embedded.mobileprovision | grep -A1 get-task-allow
```

### Static inventory of checks

```bash
# Strings and imports in native code and the main Mach-O (illustrative patterns)
rabin2 -I lib/arm64-v8a/libnative.so | grep -E 'stripped|canary|pic'
rabin2 -zz lib/arm64-v8a/libnative.so | grep -iE 'magisk|/su$|frida|27042|TracerPid|goldfish|qemu'
rabin2 -i Payload/App.app/App | grep -E 'ptrace|sysctl|getppid|task_get_exception_ports|dlsym|_dyld_'
nm -u Payload/App.app/App | grep -E '_ptrace|_sysctl|_getppid|_stat|_access|_fork'
# Cross-references to an imported function in r2
r2 -qc 'aaa; axt @ sym.imp.ptrace' Payload/App.app/App
# Java/Kotlin layer
jadx -d jadx_out app.apk
rg -n 'isDebuggerConnected|waitingForDebugger|TracerPid|/proc/self/maps|RootBeer|Magisk|IntegrityManager|setAttestationChallenge' jadx_out/sources
semgrep --config ./rules/ --metrics=off jadx_out/sources
```

### Device state

```bash
adb shell getprop ro.debuggable              # 1 on userdebug/eng builds and many emulators
adb shell getprop ro.build.tags              # release-keys vs test-keys
adb shell getprop ro.boot.verifiedbootstate  # green on a locked, verified device
adb shell getprop ro.boot.flash.locked       # 1 when the bootloader is locked
adb shell getprop ro.kernel.qemu             # 1 on the classic emulator
adb jdwp                                     # PIDs of debuggable processes
adb shell run-as com.example.app id          # works only on a debuggable build
```

### Runtime tracing of the app's own checks

```bash
frida-ps -Uai
# Android: file, property and anti-debug probes, plus a Java method
frida-trace -U -f com.example.app -i 'open' -i 'openat' -i 'access' -i 'fopen' -i '__system_property_get' -i 'ptrace' \
  -j 'android.os.Debug!isDebuggerConnected'
# iOS: file probes, anti-debug calls, an Objective-C method
frida-trace -U -f com.example.app -i 'stat' -i 'access' -i 'fopen' -i 'sysctl' -i 'getppid' -i 'ptrace' \
  -m '-[NSFileManager fileExistsAtPath:]'
# OWASP's declarative hooking tool used by several demos
frooky -U -f com.example.app --platform android hooks.json
```

A minimal tracing script for the Java side, logging which paths the app's own code probes and from where:

```javascript
Java.perform(function () {
  const File = Java.use('java.io.File');
  const Log = Java.use('android.util.Log');
  const Exc = Java.use('java.lang.Exception');
  File.exists.implementation = function () {
    const r = this.exists();
    console.log('[File.exists] ' + this.getAbsolutePath() + ' -> ' + r);
    console.log(Log.getStackTraceString(Exc.$new()).split('\n').slice(1, 4).join('\n'));
    return r;
  };
});
```

### Resistance verification on your own test device

```bash
# Generic, public bypasses of common checks (effort level E1)
objection -n "com.example.app" start     # then: android root disable | ios jailbreak disable
# frida-server under another name and port (effort level E2), then connect through a forward
adb shell "su -c '/data/local/tmp/fsrv -l 127.0.0.1:27043 &'"
adb forward tcp:27043 tcp:27043
frida -H 127.0.0.1:27043 -f com.example.app
```

Changing the return value of the app's own detection method, once you have found it (class and method names are placeholders):

```javascript
Java.perform(function () {
  const Env = Java.use('com.example.app.security.EnvCheck');
  Env.isCompromised.implementation = function () {
    console.log('[EnvCheck.isCompromised] original=' + this.isCompromised() + ', returning false');
    return false;
  };
});
```

### Debuggers

```bash
# Android Java debugger on a debuggable build (MASWE-0063, 0064)
adb shell am set-debug-app -w com.example.app      # app waits for a debugger at next launch
adb forward tcp:8700 jdwp:$(adb shell pidof -s com.example.app)
jdb -connect com.sun.jdi.SocketAttach:hostname=localhost,port=8700
# iOS: on a jailbroken device with a suitably signed debugserver, then from lldb
#   debugserver 0.0.0.0:1234 -a App
lldb -o 'process connect connect://192.168.1.20:1234'
```

## Related weaknesses in other categories

- **[MASWE-0017: device secure lock not enforced](/mobile/maswe-0017-device-secure-lock-not-enforced/)** (CRYPTO). Owns the four secure-lock tests in OWASP's RESILIENCE folder.
- **[MASWE-0020: local authentication bypass](/mobile/maswe-0020-local-authentication-bypass/)** (AUTH). The Frida patterns for hooking authentication checks are the same ones you use against detection checks; the [AUTH hub](/mobile/masvs-auth-authentication-guide/) covers server-side session controls that RASP decisions plug into.
- **[MASWE-0028: insecure identity pinning](/mobile/maswe-0028-insecure-identity-pinning/)** (NETWORK). Pinning is the layer under MASWE-0062; the [NETWORK hub](/mobile/masvs-network-secure-communication-guide/) has the rest.
- **[MASWE-0039](/mobile/maswe-0039-app-vulnerable-to-overlay-attacks/)** and **[MASWE-0040](/mobile/maswe-0040-sensitive-data-leaked-via-accessibility/)** (PLATFORM). The malware techniques MASWE-0055 asks the app to detect.
- **[MASWE-0033](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/)** and **[MASWE-0034](/mobile/maswe-0034-webviews-allow-access-to-local-resources/)** (PLATFORM). What WebView debugging (MASWE-0063) exposes.
- **[MASWE-0004: sensitive data hardcoded in the app package](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/)** (STORAGE). Secrets found while assessing obfuscation; MASWE-0061 covers the debug leftovers, MASWE-0004 the secrets. Sensitive data in logs is [MASWE-0005](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0005/).
- **[MASWE-0011: improper signature verification](/mobile/maswe-0011-improper-signature-verification/)** (CRYPTO). The verification behind MASWE-0057 and app-level signing.
- **[MASWE-0041](/mobile/maswe-0041-running-on-recent-platform-version-not-ensured/)** and **[MASWE-0043](/mobile/maswe-0043-enforced-updating-not-implemented/)** (CODE). Play Integrity's patch-level signals and `appIntegrity`/App Attest for version enforcement.
- **[MASWE-0045](/mobile/maswe-0045-compiler-security-features-not-used/)**, **[MASWE-0048](/mobile/maswe-0048-malicious-code-included-in-the-app/)** and **[MASWE-0049](/mobile/maswe-0049-unsafe-dynamic-code-loading/)** (CODE). Stripping and binary hardening; malicious code in your own build, which no signature check catches; and dynamic code loading, which RASP SDKs sometimes use themselves.

## Other series hubs

- [MASVS-STORAGE: secure storage](/mobile/masvs-storage-1-secure-storage-guide/)
- [MASVS-CRYPTO: cryptography and key management](/mobile/masvs-crypto-cryptography-guide/)
- [MASVS-AUTH: authentication and authorisation](/mobile/masvs-auth-authentication-guide/)
- [MASVS-NETWORK: secure communication](/mobile/masvs-network-secure-communication-guide/)
- [MASVS-PLATFORM: IPC, WebViews and the UI](/mobile/masvs-platform-platform-interaction-guide/)
- [MASVS-CODE: code quality and the supply chain](/mobile/masvs-code-code-quality-guide/)

## References

- OWASP MASVS: [MASVS-RESILIENCE-1](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-1/), [MASVS-RESILIENCE-2](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-2/), [MASVS-RESILIENCE-3](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-3/), [MASVS-RESILIENCE-4](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-4/) (CC BY-SA 4.0)
- OWASP MASWE: [MASWE-0051](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0051/), [0052](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0052/), [0053](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0053/), [0054](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0054/), [0055](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0055/), [0056](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0056/), [0057](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0057/), [0058](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0058/), [0059](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0059/), [0060](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0060/), [0061](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0061/), [0062](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0062/), [0063](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0063/), [0064](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0064/), [0065](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0065/), [MASWE-0005](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0005/) (CC BY-SA 4.0)
- OWASP MASTG Knowledge: [MASTG-KNOW-0109](https://mas.owasp.org/MASTG/knowledge/generic/MASVS-RESILIENCE/MASTG-KNOW-0109/), [0110](https://mas.owasp.org/MASTG/knowledge/generic/MASVS-RESILIENCE/MASTG-KNOW-0110/), [0111](https://mas.owasp.org/MASTG/knowledge/generic/MASVS-RESILIENCE/MASTG-KNOW-0111/), [0112](https://mas.owasp.org/MASTG/knowledge/generic/MASVS-RESILIENCE/MASTG-KNOW-0112/), [0113](https://mas.owasp.org/MASTG/knowledge/generic/MASVS-RESILIENCE/MASTG-KNOW-0113/), [0114](https://mas.owasp.org/MASTG/knowledge/generic/MASVS-RESILIENCE/MASTG-KNOW-0114/), [0115](https://mas.owasp.org/MASTG/knowledge/generic/MASVS-RESILIENCE/MASTG-KNOW-0115/), [0116](https://mas.owasp.org/MASTG/knowledge/generic/MASVS-RESILIENCE/MASTG-KNOW-0116/), [MASTG-KNOW-0118](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0118/) (CC BY-SA 4.0)
- OWASP MASTG Best Practices: [MASTG-BEST-0029](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0029/) (CC BY-SA 4.0)
- OWASP MASTG Tests: the 30 RESILIENCE tests, the four MASWE-0017 tests and the 21 legacy tests linked in the tables above, and legacy [MASTG-TEST-0002](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0002/) (CC BY-SA 4.0)
- OWASP MASTG Demos: [MASTG-DEMO-0040](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0040/MASTG-DEMO-0040/), [MASTG-DEMO-0108](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0108/MASTG-DEMO-0108/), [MASTG-DEMO-0119](https://mas.owasp.org/MASTG/demos/ios/MASVS-RESILIENCE/MASTG-DEMO-0119/MASTG-DEMO-0119/) (CC BY-SA 4.0)
- OWASP MASTG Techniques and Tools: [MASTG-TECH-0037](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0037/), [MASTG-TECH-0112](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0112/), [MASTG-TECH-0144](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0144/), [MASTG-TOOL-0031 (Frida)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/), [MASTG-TOOL-0038 (objection)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0038/), [MASTG-TOOL-0145 (Frooky)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0145/), [MASTG-TOOL-0027 (Xposed)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0027/), [MASTG-TOOL-0139 (ElleKit)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0139/), [MASTG-TOOL-0108 (Corellium)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0108/), [MASTG-TOOL-0030 (Angr)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0030/), [MASTG-TOOL-0123 (apksigner)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0123/), [MASTG-TOOL-0124 (aapt2)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0124/), [MASTG-TOOL-0114 (codesign)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0114/), [MASTG-TOOL-0111 (ldid)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0111/) (CC BY-SA 4.0)
- Android Developers: [Play Integrity API overview](https://developer.android.com/google/play/integrity/overview), [Integrity verdicts](https://developer.android.com/google/play/integrity/verdicts), [Standard requests](https://developer.android.com/google/play/integrity/standard), [Verify hardware-backed key pairs with key attestation](https://developer.android.com/privacy-and-security/security-key-attestation), [android:debuggable risk](https://developer.android.com/privacy-and-security/risks/android-debuggable), [Android 11 behaviour changes (APK signature scheme v2 required)](https://developer.android.com/about/versions/11/behavior-changes-11)
- Android Open Source Project: [Key and ID attestation](https://source.android.com/docs/security/features/keystore/attestation), [APK signature scheme](https://source.android.com/docs/security/features/apksigning)
- Apple: [Using the latest code signature format](https://developer.apple.com/documentation/xcode/using-the-latest-code-signature-format), [DeviceCheck](https://developer.apple.com/documentation/devicecheck), [Establishing your app's integrity](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity), [Validating apps that connect to your server](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server)
- Google Play Protect: [Play Protect](https://developers.google.com/android/play-protect)
- [Frida documentation](https://frida.re/docs/home/), [Android key attestation verification library](https://github.com/android/keyattestation)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
