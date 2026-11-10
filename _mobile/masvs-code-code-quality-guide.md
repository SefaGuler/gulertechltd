---
title: "MASVS-CODE: Code Quality Testing Guide for Mobile Apps"
date: 2026-11-10 10:15:00 +0000
subcategory: code
summary: "Hub for the MASVS-CODE series: ten weaknesses, all 18 OWASP tests, legacy mapping, attacker positions, a test order and a command cheat sheet."
refs: [MASVS-CODE-1, MASVS-CODE-2, MASVS-CODE-3, MASVS-CODE-4, MASWE-0041, MASWE-0042, MASWE-0043, MASWE-0044, MASWE-0045, MASWE-0046, MASWE-0047, MASWE-0048, MASWE-0049, MASWE-0050]
tags: [android, ios, masvs-code, code-quality, supply-chain]
---

This is the entry point to our series on **OWASP MASVS-CODE**, the control group about the code you ship and the platform it runs on. It has four requirements:

- **MASVS-CODE-1:** "The app requires an up-to-date platform version."
- **MASVS-CODE-2:** "The app has a mechanism for enforcing app updates."
- **MASVS-CODE-3:** "The app only uses software components without known vulnerabilities."
- **MASVS-CODE-4:** "The app validates and sanitizes all untrusted inputs."

The series follows the [MASWE](https://mas.owasp.org/MASWE/) catalogue: one note per weakness, MASWE-0041 to MASWE-0050, each with its **Knowledge**, **Tests**, best practices and a rating table. This page maps the area, lists all 18 OWASP tests and the note that documents each one, points to the five tests in OWASP's CODE folder that belong to PLATFORM weaknesses, maps the 14 deprecated v1 tests, explains what each attacker position can prove, and gives a test order with the commands you will use on every CODE review. It also summarises the OWASP CODE Knowledge items that no weakness references.

Know one thing before you start. Half of this category has **no OWASP tests**. MASWE-0042, 0046, 0047, 0048 and 0049 have none, and MASWE-0041 has only an Android test. For those gaps the notes give our own tests, labelled *Guler Tech methodology* and numbered `GT-CODE-00NN-x`. They follow the same structure as the OWASP tests. They detect and verify a weakness in the app under test. They do not include exploit material such as attacker apps, payload generators or gadget chains.

## Contents

- [What MASVS-CODE covers](#what-masvs-code-covers)
- [The series](#the-series)
- [Test index](#test-index)
- [Tests in the CODE folder that belong to PLATFORM](#tests-in-the-code-folder-that-belong-to-platform)
- [Legacy v1 tests and their replacements](#legacy-v1-tests-and-their-replacements)
- [What each attacker position can prove](#what-each-attacker-position-can-prove)
- [Where to start: test order](#where-to-start-test-order)
- [Rating overview](#rating-overview)
- [Command cheat sheet](#command-cheat-sheet)
- [Knowledge items not tied to a weakness](#knowledge-items-not-tied-to-a-weakness)
  - [Android: Debugging Information and Debug Symbols (MASTG-KNOW-0008)](#android-debugging-information-and-debug-symbols-mastg-know-0008)
  - [Android: StrictMode (MASTG-KNOW-0009)](#android-strictmode-mastg-know-0009)
  - [Android: Exception Handling (MASTG-KNOW-0010)](#android-exception-handling-mastg-know-0010)
  - [iOS: App Signing (MASTG-KNOW-0058)](#ios-app-signing-mastg-know-0058)
  - [iOS: Debuggable Apps (MASTG-KNOW-0062)](#ios-debuggable-apps-mastg-know-0062)
  - [iOS: Debugging Information and Debug Symbols (MASTG-KNOW-0063)](#ios-debugging-information-and-debug-symbols-mastg-know-0063)
  - [iOS: Non-Production Resources (MASTG-KNOW-0064)](#ios-non-production-resources-mastg-know-0064)
  - [iOS: Exception Handling (MASTG-KNOW-0065)](#ios-exception-handling-mastg-know-0065)
  - [The older standalone CODE notes](#the-older-standalone-code-notes)
- [Related weaknesses in other categories](#related-weaknesses-in-other-categories)
- [Other series hubs](#other-series-hubs)
- [References](#references)

## What MASVS-CODE covers

The other MASVS groups ask whether a feature is built securely: storage, crypto, authentication, network, IPC. CODE asks about the ground under all of them. Does the app run on a platform that still gets patches? Can a vulnerable version be retired? Does the code you ship, including code you did not write, have known holes or hidden behaviour? Does data from outside the app get checked before it reaches something dangerous? Findings come from four kinds of mistake:

1. **Living in the past.** Supporting OS versions without the protections the app relies on, targeting an old SDK so the OS keeps legacy behaviour on, or calling deprecated APIs.
2. **No way to move users forward.** A fixed vulnerability stays exploitable for as long as old builds keep working against the backend.
3. **Trusting the supply chain.** Libraries with public CVEs, SDKs that do more than their documentation says, home-grown security code, and native code built without exploit mitigations.
4. **Trusting input.** Intents, provider URIs, intent results, URL payloads, files, archives and server responses flowing into SQL, the file system, deserializers or code loaders.

**CODE-1 (platform version)** has two weaknesses. **MASWE-0041** is about the *minimum* version (`minSdkVersion`, `MinimumOSVersion`): the oldest OS the app accepts, and with it every unfixable platform bug of that OS, such as StrandHogg task hijacking on old Android. **MASWE-0042** is about the *target* version (`targetSdkVersion`, the Xcode SDK): the OS applies many protections only to apps that declare they target a new enough release.

**CODE-2 (enforced updating)** has one weakness, **MASWE-0043**. The client part is the Play In-App Updates API or an App Store lookup on iOS. The control that holds is on the server: a backend that knows the minimum supported version and refuses older clients.

**CODE-3 (components without known vulnerabilities)** has five weaknesses. **MASWE-0044** covers dependencies with known vulnerabilities. That means SCA and SBOMs. **MASWE-0045** covers compiler-provided mitigations (PIE, stack canaries, NX, FORTIFY, ARC); OWASP maps it to CODE-4 as well. **MASWE-0046** covers deprecated APIs and also maps to CRYPTO-2, because the example OWASP gives is the deprecated Bouncy Castle keystore. **MASWE-0047** covers security-critical functionality built with non-standard APIs: your own crypto, TLS stack, DNS resolver or authentication flow. It maps to AUTH-1, CRYPTO-1 and NETWORK-1 too. **MASWE-0048** covers malicious code in the shipped app, whether from an insider, a trojanised SDK or a compromised build pipeline.

**CODE-4 (untrusted input)** has three weaknesses. **MASWE-0049** covers code loaded at runtime from writable locations or unverified downloads. **MASWE-0050** covers untrusted data reaching a dangerous sink: SQL injection in providers, path traversal, XXE, unsafe deserialization, unvalidated intent results. MASWE-0045 sits here as well. Four weaknesses from other groups also map to CODE-4: deep links ([MASWE-0029](/mobile/maswe-0029-insecure-deep-links/)), WebView local resources ([MASWE-0034](/mobile/maswe-0034-webviews-allow-access-to-local-resources/)) and WebView content ([MASWE-0035](/mobile/maswe-0035-webviews-loading-untrusted-content/)) from PLATFORM, and [MASWE-0057](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0057/) (app resources integrity) from RESILIENCE. Overlay attacks ([MASWE-0039](/mobile/maswe-0039-app-vulnerable-to-overlay-attacks/)) map to CODE-1 as well; the strongest overlay protections exist only on newer Android versions.

**Profiles.** Five weaknesses are tagged **L1, L2 and EUDIW**: 0042 (target version), 0044 (vulnerable dependencies), 0047 (non-standard security APIs), 0048 (malicious code) and 0050 (untrusted data). They are the baseline for every app. The other five are tagged **L2 and EUDIW** only: 0041 (minimum version), 0043 (enforced updating), 0045 (compiler features), 0046 (deprecated APIs) and 0049 (dynamic code loading). For an L1 app, report a finding against one of these as an observation and say that the requirement belongs to L2, unless it chains into something that is L1.

**Black box versus grey box.** Several CODE tests need more than the app package. MASTG-TEST-0272 runs inside the Gradle project. MASTG-TEST-0274 and 0275 need an SBOM, and OWASP types them `developer`. MASTG-TEST-0273 needs the dependency manager's lock files. You can still identify libraries from an APK or IPA, as our [KNOW-0004 note](/mobile/mastg-know-0004-third-party-libraries/) shows. But version strings are often stripped and transitive dependencies are invisible, so ask for lock files and an SBOM at scoping. If you do not get them, write that limit into the report.

**What is out of scope.** Debuggable builds, debug symbols, logging of implementation details and app-signing format are MASVS-RESILIENCE, even though OWASP files some of their Knowledge items under CODE (see [below](#knowledge-items-not-tied-to-a-weakness)). Sensitive data in logs is [MASWE-0005](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0005/) (STORAGE). Exported components without authorisation are [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/) (AUTH).

## The series

| Note | Weakness | Controls | Profiles | OWASP tests: Android | OWASP tests: iOS | Guler Tech tests |
|------|----------|----------|----------|----------------------|------------------|------------------|
| [Running on a Recent Platform Version Not Ensured](/mobile/maswe-0041-running-on-recent-platform-version-not-ensured/) | MASWE-0041 | CODE-1 | L2, EUDIW | 0245 | none | 2 |
| [Latest Platform Version Not Targeted](/mobile/maswe-0042-latest-platform-version-not-targeted/) | MASWE-0042 | CODE-1 | L1, L2, EUDIW | none | none | 3 |
| [Enforced Updating Not Implemented](/mobile/maswe-0043-enforced-updating-not-implemented/) | MASWE-0043 | CODE-2 | L2, EUDIW | 0392, 0382 | 0383, 0384 | 2 |
| [Dependencies with Known Vulnerabilities](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/) | MASWE-0044 | CODE-3 | L1, L2, EUDIW | 0272, 0274 | 0273, 0275 | 3 |
| [Compiler-Provided Security Features Not Used](/mobile/maswe-0045-compiler-security-features-not-used/) | MASWE-0045 | CODE-3, CODE-4 | L2, EUDIW | 0222 (deprecated since API 21), 0223 | 0228, 0229, 0230 | 1 |
| [Use of Deprecated APIs or Functionality](/mobile/maswe-0046-use-of-deprecated-apis/) | MASWE-0046 | CODE-3, CRYPTO-2 | L2, EUDIW | none | none | 3 |
| [Using Non-Standard APIs for Security-Critical Functionality](/mobile/maswe-0047-non-standard-security-apis/) | MASWE-0047 | CODE-3, AUTH-1, CRYPTO-1, NETWORK-1 | L1, L2, EUDIW | none | none | 4 |
| [Malicious Code Included in the App](/mobile/maswe-0048-malicious-code-included-in-the-app/) | MASWE-0048 | CODE-3 | L1, L2, EUDIW | none | none | 5 |
| [Unsafe Dynamic Code Loading](/mobile/maswe-0049-unsafe-dynamic-code-loading/) | MASWE-0049 | CODE-4 | L2, EUDIW | none | none | 4 |
| [Unsafe Handling of Untrusted Data](/mobile/maswe-0050-unsafe-handling-of-untrusted-data/) | MASWE-0050 | CODE-4 | L1, L2, EUDIW | 0337, 0339, 0375 | 0386 | 6 |

OWASP tags every one of the ten weaknesses for both platforms. Every note covers both. Where OWASP has no test for a platform, or none at all, the note adds Guler Tech tests numbered `GT-CODE-00NN-x`, and any note may add tests that go further than OWASP. In the five notes without OWASP tests, ours are the only tests. The series has 18 OWASP tests and 33 Guler Tech tests.

**Where the Knowledge lives.** OWASP has few CODE Knowledge items tied to weaknesses, and several of them sit in other folders.

- **MASWE-0043:** enforced updating, MASTG-KNOW-0023 for Android and MASTG-KNOW-0074 for iOS. Both live in OWASP's PLATFORM folder. Our PLATFORM hub has short summaries of them; the full treatment is in the MASWE-0043 note.
- **MASWE-0044:** third-party libraries, MASTG-KNOW-0004 for Android and MASTG-KNOW-0059 for iOS.
- **MASWE-0045:** binary protection mechanisms, MASTG-KNOW-0006 for Android and MASTG-KNOW-0061 for iOS, plus short summaries of the memory-corruption items MASTG-KNOW-0005 and 0060.
- **MASWE-0050:** object serialization (MASTG-KNOW-0021 for Android, 0075 for iOS; both PLATFORM folder), ContentProviders (MASTG-KNOW-0117) and URI schemes in intent results (MASTG-KNOW-0138). It summarises explicit versus implicit intents (MASTG-KNOW-0025) and links to [MASWE-0032](/mobile/maswe-0032-insecure-intents/) for the full item.
- **Best practices:** MASTG-BEST-0010 (up-to-date `minSdkVersion`) sits with MASWE-0041, with a pointer from 0042. MASTG-BEST-0039, 0049, 0057 and 0064 sit with MASWE-0050. MASWE-0046 uses BEST-0020 (GMS security provider), BEST-0032 (UIWebView to WKWebView) and BEST-0006 (APK signing schemes) as examples of migrating off deprecated functionality.

## Test index

All 18 OWASP v2 tests whose `maswe` field names a CODE weakness, grouped by note. **Type** is OWASP's own classification. All 18 live in OWASP's MASVS-CODE folder, and none is a placeholder. The **Note** column links to the note that documents the test in full, with prerequisites, steps, evidence, pass and fail criteria, and a demo.

| ID (OWASP page) | Title | Platform | Type | Note |
|-----------------|-------|----------|------|------|
| **MASWE-0041: minimum platform version** | | | | |
| [MASTG-TEST-0245](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0245/) | References to Platform Version APIs | Android | static, code | [MASWE-0041](/mobile/maswe-0041-running-on-recent-platform-version-not-ensured/) |
| **MASWE-0043: enforced updating** | | | | |
| [MASTG-TEST-0392](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0392/) | References to Enforced Updating APIs | Android | static, code, manual | [MASWE-0043](/mobile/maswe-0043-enforced-updating-not-implemented/) |
| [MASTG-TEST-0382](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0382/) | Runtime Use of Enforced Updating APIs | Android | dynamic, network, hooks, manual | [MASWE-0043](/mobile/maswe-0043-enforced-updating-not-implemented/) |
| [MASTG-TEST-0383](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0383/) | References to Enforced Updating APIs | iOS | static, code, manual | [MASWE-0043](/mobile/maswe-0043-enforced-updating-not-implemented/) |
| [MASTG-TEST-0384](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0384/) | Runtime Use of Enforced Updating APIs | iOS | dynamic, network, hooks, manual | [MASWE-0043](/mobile/maswe-0043-enforced-updating-not-implemented/) |
| **MASWE-0044: known-vulnerable dependencies** | | | | |
| [MASTG-TEST-0272](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0272/) | Identify Dependencies with Known Vulnerabilities in the Android Project | Android | static, code | [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/) |
| [MASTG-TEST-0274](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0274/) | Dependencies with Known Vulnerabilities in the App's SBOM | Android | static, developer | [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/) |
| [MASTG-TEST-0273](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0273/) | Identify Dependencies with Known Vulnerabilities by Scanning Dependency Managers Artifacts | iOS | static, code | [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/) |
| [MASTG-TEST-0275](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0275/) | Dependencies with Known Vulnerabilities in the App's SBOM | iOS | static, developer | [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/) |
| **MASWE-0045: compiler security features** | | | | |
| [MASTG-TEST-0222](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0222/) | Position Independent Code (PIC) Not Enabled | Android | static, code | [MASWE-0045](/mobile/maswe-0045-compiler-security-features-not-used/) |
| [MASTG-TEST-0223](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0223/) | Stack Canaries Not Enabled | Android | static, code | [MASWE-0045](/mobile/maswe-0045-compiler-security-features-not-used/) |
| [MASTG-TEST-0228](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0228/) | Position Independent Code (PIC) not Enabled | iOS | static, code | [MASWE-0045](/mobile/maswe-0045-compiler-security-features-not-used/) |
| [MASTG-TEST-0229](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0229/) | Stack Canaries Not enabled | iOS | static, code | [MASWE-0045](/mobile/maswe-0045-compiler-security-features-not-used/) |
| [MASTG-TEST-0230](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0230/) | Automatic Reference Counting (ARC) not enabled | iOS | static, code | [MASWE-0045](/mobile/maswe-0045-compiler-security-features-not-used/) |
| **MASWE-0050: untrusted data** | | | | |
| [MASTG-TEST-0337](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0337/) | References to Object Deserialization of Untrusted Data | Android | static, code | [MASWE-0050](/mobile/maswe-0050-unsafe-handling-of-untrusted-data/) |
| [MASTG-TEST-0339](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0339/) | SQL Injection in Content Providers | Android | static, code | [MASWE-0050](/mobile/maswe-0050-unsafe-handling-of-untrusted-data/) |
| [MASTG-TEST-0375](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0375/) | Missing Validation of Data Returned from Implicit Intents | Android | dynamic, hooks, manual | [MASWE-0050](/mobile/maswe-0050-unsafe-handling-of-untrusted-data/) |
| [MASTG-TEST-0386](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0386/) | References to Object Deserialization of Untrusted Data | iOS | static, code, manual | [MASWE-0050](/mobile/maswe-0050-unsafe-handling-of-untrusted-data/) |

That is 10 Android and 8 iOS tests: 15 static and 3 dynamic. Read the table with four caveats in mind.

- **MASTG-TEST-0222 is effectively retired.** It carries `deprecated_since: 21`. Android 5.0 (API 21) refuses to run non-PIE executables, and the NDK has produced PIE by default for years. Run it only if the app's `minSdkVersion` is below 21. A shared library is `ET_DYN` by definition, and since Android 6.0 the linker also rejects libraries with text relocations, so the useful check is `readelf -h` showing `Type: DYN` and no `TEXTREL` in the dynamic section.
- **MASTG-TEST-0245 measures the wrong thing on its own.** Its fail criterion is "no API calls that check the OS version". The primary control for MASWE-0041 is a high enough `minSdkVersion`, and an app with `minSdk 29` may need no runtime check at all. The MASWE-0041 note evaluates both together.
- **OWASP's MASTG-TEST-0229 has a slip in its evaluation.** It names `objc_autorelease` and `objc_retainAutorelease` as evidence of stack canaries. Those are ARC symbols, the evidence for TEST-0230. Canaries show up as `__stack_chk_fail` and `__stack_chk_guard`. The MASWE-0045 note uses the correct symbols.
- **Demos.** OWASP demos exist for 0245 (DEMO-0025), 0272 (DEMO-0050), the SBOM path (DEMO-0051, which OWASP tags with TEST-0272 although it shows the SBOM workflow of TEST-0274), 0273 (DEMO-0052), 0275 (DEMO-0053), 0337 (DEMO-0100), 0339 (DEMO-0102), 0375 (DEMO-0139, 0141) and 0386 (DEMO-0149). The binary-protection and enforced-updating tests have no demo; the notes supply their own examples.

## Tests in the CODE folder that belong to PLATFORM

OWASP's MASVS-CODE test folder holds five more tests, so their URLs contain `MASVS-CODE`. Their `maswe` field points at PLATFORM weaknesses, and we document them there. They are not repeated in this series.

| Test | Title | Platform | Type | OWASP files under | Documented in |
|------|-------|----------|------|-------------------|---------------|
| [MASTG-TEST-0372](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0372/) | Implicit Intents Used for Internal App Communication | Android | static, code, manual | MASWE-0032 | [Insecure Intents](/mobile/maswe-0032-insecure-intents/) |
| [MASTG-TEST-0374](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0374/) | References to Implicit Intents Carrying Sensitive Extras | Android | static, code, manual | MASWE-0032 | [Insecure Intents](/mobile/maswe-0032-insecure-intents/) |
| [MASTG-TEST-0398](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0398/) | References to WebViewClient URL Loading Handlers | Android | static, code, manual | MASWE-0035 | [WebViews Loading Untrusted Content](/mobile/maswe-0035-webviews-loading-untrusted-content/) |
| [MASTG-TEST-0399](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0399/) | SafeBrowsing Disabled | Android | static, config, code | MASWE-0035 | [WebViews Loading Untrusted Content](/mobile/maswe-0035-webviews-loading-untrusted-content/) |
| [MASTG-TEST-0400](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0400/) | Runtime Use of WebViewClient URL Loading Handlers | Android | dynamic, hooks, manual | MASWE-0035 | [WebViews Loading Untrusted Content](/mobile/maswe-0035-webviews-loading-untrusted-content/) |

The split follows the v1 history. Legacy TEST-0026 (implicit intents) became 0372 and 0374 (sending side, MASWE-0032) and 0375 (receiving side, MASWE-0050). The intent-result test stays in this series because the fault is the caller trusting what another app returns, not the intent it sends. Legacy TEST-0027 (URL loading in WebViews) became 0398 to 0400. If you browse mas.owasp.org by folder, the CODE folder shows 23 tests; by weakness, MASWE-0041 to 0050 list 18.

## Legacy v1 tests and their replacements

MASTG v1 had 14 tests in the CODE folders, nine for Android and five for iOS. All are now `status: deprecated`, and each has a `covered_by` list. If an older report or a client checklist cites them, map them like this.

| Legacy test | Platform | v1 title | OWASP `covered_by` | Where we cover it |
|-------------|----------|----------|--------------------|-------------------|
| [MASTG-TEST-0002](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0002/) | Android | Testing Local Storage for Input Validation | 0338 | 0338 is a RESILIENCE test for [MASWE-0057](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0057/) (storage integrity checks). Our [MASWE-0011 note](/mobile/maswe-0011-improper-signature-verification/) explains it today. The validation half, stored data reaching a sink, is in [MASWE-0050](/mobile/maswe-0050-unsafe-handling-of-untrusted-data/). |
| [MASTG-TEST-0025](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0025/) | Android | Testing for Injection Flaws | 0339 | [MASWE-0050](/mobile/maswe-0050-unsafe-handling-of-untrusted-data/) |
| [MASTG-TEST-0026](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0026/) | Android | Testing Implicit Intents | 0372, 0374, 0375 | 0372 and 0374 in [MASWE-0032](/mobile/maswe-0032-insecure-intents/); 0375 in [MASWE-0050](/mobile/maswe-0050-unsafe-handling-of-untrusted-data/) |
| [MASTG-TEST-0027](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0027/) | Android | Testing for URL Loading in WebViews | 0398, 0399, 0400 | [MASWE-0035](/mobile/maswe-0035-webviews-loading-untrusted-content/) |
| [MASTG-TEST-0034](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0034/) | Android | Testing Object Persistence | 0337 | [MASWE-0050](/mobile/maswe-0050-unsafe-handling-of-untrusted-data/) |
| [MASTG-TEST-0036](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0036/) | Android | Testing Enforced Updating | 0392, 0382 | [MASWE-0043](/mobile/maswe-0043-enforced-updating-not-implemented/) |
| [MASTG-TEST-0042](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0042/) | Android | Checking for Weaknesses in Third Party Libraries | 0272, 0274 | [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/); binary-only identification and licences in the [KNOW-0004 note](/mobile/mastg-know-0004-third-party-libraries/) |
| [MASTG-TEST-0043](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0043/) | Android | Memory Corruption Bugs | — (empty) | No successor; see below. Mitigations in [MASWE-0045](/mobile/maswe-0045-compiler-security-features-not-used/), the bugs themselves in the [KNOW-0005 note](/mobile/mastg-know-0005-memory-corruption-bugs/) |
| [MASTG-TEST-0044](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0044/) | Android | Make Sure That Free Security Features Are Activated | 0222, 0223 | [MASWE-0045](/mobile/maswe-0045-compiler-security-features-not-used/) |
| [MASTG-TEST-0079](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0079/) | iOS | Testing Object Persistence | 0386, 0302 | 0386 in [MASWE-0050](/mobile/maswe-0050-unsafe-handling-of-untrusted-data/); 0302 (unencrypted private files) in STORAGE, [MASWE-0001](/mobile/maswe-0001-sensitive-data-unencrypted-private-storage/) |
| [MASTG-TEST-0080](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0080/) | iOS | Testing Enforced Updating | 0383, 0384 | [MASWE-0043](/mobile/maswe-0043-enforced-updating-not-implemented/) |
| [MASTG-TEST-0085](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0085/) | iOS | Checking for Weaknesses in Third Party Libraries | 0273, 0275 | [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/) |
| [MASTG-TEST-0086](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0086/) | iOS | Memory Corruption Bugs | — (empty) | No successor; see below. Mitigations in [MASWE-0045](/mobile/maswe-0045-compiler-security-features-not-used/) |
| [MASTG-TEST-0087](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0087/) | iOS | Make Sure That Free Security Features Are Activated | 0228, 0229, 0230 | [MASWE-0045](/mobile/maswe-0045-compiler-security-features-not-used/) |

**Why the memory-corruption tests have no successor.** OWASP's deprecation note for TEST-0043 and TEST-0086 says these weaknesses are "best addressed during the development process" and points to MASTG-KNOW-0005 and MASTG-KNOW-0060. The v1 tests asked the tester to find buffer overflows, use-after-free and format-string bugs in native code. That is source review, fuzzing and sanitiser work, not a checklist test that gives a repeatable pass or fail on a release build. The v2 tests that remain (0222, 0223, 0228 to 0230) check whether the *mitigations* are present. They say nothing about whether *bugs* exist. If an engagement includes native code that parses untrusted input, scope fuzzing or source review of that code separately, and report its results under MASWE-0050 (memory corruption in parsers) with MASWE-0045 as the context that decides how exploitable a bug is. The [KNOW-0005 note](/mobile/mastg-know-0005-memory-corruption-bugs/) covers how to scope that for JNI and NDK code.

**Other gaps.** `covered_by` for TEST-0002 points to a resilience test, so the "input validation of local storage" idea has no direct v2 test. Our MASWE-0050 note treats files, preferences and databases the app reads back as one more untrusted source when another app or a backup restore can write them. In MASVS v1 terms, the weaknesses map to MSTG-ARCH-9 (MASWE-0043), MSTG-CODE-5 (0044), MSTG-CRYPTO-4 (0046), MSTG-CRYPTO-2 and MSTG-NETWORK-6 (0047) and MSTG-PLATFORM-2 (0050). The legacy tests also used MSTG-PLATFORM-8 (object persistence), MSTG-CODE-8 (memory corruption) and MSTG-CODE-9 (free security features), which the MASWE front matter does not list. MASWE-0041, 0042, 0045, 0048 and 0049 have no v1 mapping.

## What each attacker position can prove

A CODE finding without an attacker position is unratable. "The app deserializes `Serializable` extras" is High if any installed app can send the extra, and Info if only the app itself can. "A dependency has a CVE" means nothing until you know which input reaches the vulnerable function. Name the position in every finding.

| Attacker position | What it needs | Weaknesses it reaches | What a successful test proves | What it cannot prove |
|-------------------|---------------|-----------------------|-------------------------------|----------------------|
| **Malicious app on the same device, no permissions** | Installed by the user | 0050 (exported providers with injectable queries, `Serializable` and `Parcelable` extras, crafted intent results and provider filenames), 0049 (code loaded from shared or external storage, or through `createPackageContext` from a package it can impersonate), 0041 (task hijacking on old Android versions the app still supports), 0042 (legacy behaviours an old `targetSdkVersion` keeps on) | Data or code crossing from another app into a dangerous sink in yours | Anything that needs the other app's data to reach a sink with the app's privileges, when the entry point is not exported or is permission-protected (that boundary is [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/)) |
| **Malicious link, file or QR code** | The user taps a link, opens a file, scans a code | 0050 (URL payloads decoded with `NSKeyedUnarchiver`, archives extracted without path checks, documents parsed by native code), plus the deep-link and WebView routes in [MASWE-0029](/mobile/maswe-0029-insecure-deep-links/) and [MASWE-0035](/mobile/maswe-0035-webviews-loading-untrusted-content/) | Attacker-chosen input reaching a parser, a path or a decoder with one interaction | Repeated, silent abuse: every delivery needs the user |
| **Network attacker** | Cleartext traffic or broken TLS (see the [NETWORK hub](/mobile/masvs-network-secure-communication-guide/)) | 0049 (code, scripts or plugins downloaded without a signature check), 0043 (an update-policy response the client trusts and fails open on), 0047 (custom TLS or DNS code that a standard stack would have rejected), 0050 (responses parsed unsafely) | Code or data injected into a channel the app treats as trusted | Nothing, if the channel is TLS that validates correctly and the payload is signed |
| **Malicious or compromised server** | Control of a backend, CDN, remote-config service or third-party API the app calls | 0049 (remote code delivery is only as safe as the signature check and pinned key), 0050 (deserialization, XXE and zip-slip on server data), 0043 (a minimum-version policy that can be lowered) | That the app's safety rests on server honesty where a signature or a strict parser should carry it | Server-side bugs; this is a client test |
| **Supply-chain attacker** | A trojanised SDK, hijacked or typosquatted package, compromised build plugin or CI | 0048 (the payload itself), 0044 (pinning and integrity of what is pulled in), 0049 (code a library fetches later) | Unexpected endpoints, permissions, native libraries or loaders in the release build that the declared SDKs do not explain | Intent. A tester shows behaviour and provenance; attribution is incident response |
| **Anyone with a public exploit** | A known CVE in a component the app ships, and a way to deliver input to it | 0044, then 0045 for how hard a native bug is to exploit | That the vulnerable code is present and the vulnerable path is reachable from one of the rows above | Exploitability, if the vulnerable function is never reached; that is a Low or Info finding with a patch recommendation |
| **User on an old OS version** | Not an attacker: the precondition that 0041 creates | 0041, 0042 | That the app installs and runs on a version missing a protection it relies on, or with an unfixable platform bug | An attack by itself; pair it with the row that exploits the OS weakness |
| **Controller of the device** | Your rooted or jailbroken test phone, Frida, `adb` | Every note uses it as methodology | Nothing by itself. Hooking your own process proves a path exists; a finding needs one of the rows above to travel it | — |

The rule of thumb from the PLATFORM series holds here too. `adb`, Frida and a proxy are how you find and reproduce a path. The rating depends on the cheapest real attacker who can travel it. For MASWE-0044, 0045 and 0046, "who can reach the vulnerable code" is the whole question, and a scanner cannot answer it.

## Where to start: test order

Before step 1, get the app package for both platforms, and ask the client for the Gradle project or at least the lock files (`gradle.lockfile`, `Podfile.lock`, `Package.resolved`, `Cartfile.resolved`) and an SBOM. Have one current Android device (Android 14 or later) and one at the app's `minSdkVersion` if it is old, and an iOS device or Simulator. This order runs from cheap static checks to the dynamic work, and each step feeds the next.

### 1. Inventory

- **Android:** package name, version, `minSdkVersion`, `targetSdkVersion`, `compileSdkVersion`, native libraries per ABI (`lib/<abi>/*.so`), extra DEX files, `assets/` content that looks like code (`.dex`, `.jar`, `.so`, `.js` bundles), and the SDKs the code references (package prefixes in jadx).
- **iOS:** the `Info.plist` keys `MinimumOSVersion`, `DTSDKName`, `DTXcode`, `DTPlatformVersion` and `CFBundleShortVersionString`; the main binary; `Frameworks/*.framework` and `*.dylib`; every `.appex`; JavaScript bundles (React Native, Cordova); entitlements.
- Write down the **untrusted inputs** you will trace in step 5: exported components and providers (see [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/)), URL schemes and links, document types, intent-result flows, downloads, remote config.

### 2. Platform versions (MASWE-0041, 0042)

- Compare `minSdkVersion` and `MinimumOSVersion` with the security features the app relies on. Examples: Network Security Configuration (Android 7.0), runtime permissions (Android 6.0), a hardware-backed keystore. Run MASTG-TEST-0245 for runtime version gating.
- Compare `targetSdkVersion` with Google Play's requirement. Since 31 August 2026, new apps and updates must target Android 16 (API 36); extensions ran to 1 November 2026. Existing apps targeting API 34 or lower stop being offered to new users on newer devices ([Android Developers](https://developer.android.com/google/play/requirements/target-sdk)). Android 14 refuses to install apps with a `targetSdkVersion` below 23.
- On iOS, compare `DTXcode` and `DTSDKName` with Apple's upload rule. Since 28 April 2026, uploads must be built with Xcode 26 and an iOS 26 SDK. Since 9 September 2026, iOS and iPadOS apps uploaded to App Store Connect must target iOS 13 or later ([Apple: Upcoming requirements](https://developer.apple.com/news/upcoming-requirements/)).
- An enterprise or MDM-distributed app is outside both store rules. That is where you will find the old targets.

### 3. Binary hardening (MASWE-0045)

- For every `.so`, check that it is position-independent (`Type: DYN`), that `GNU_STACK` is not executable, and that `__stack_chk_fail` is imported where the code has stack buffers. Look for `_chk` FORTIFY variants (`__memcpy_chk`, `__strcpy_chk`), and RELRO with `BIND_NOW`. For the main Mach-O, check the `PIE` flag; for every binary, check `__stack_chk_fail` (canaries) and the ARC runtime symbols.
- Triage by input before you write anything up. A library without canaries that parses network or file data matters. An empty React Native helper library with no stack buffers does not (TEST-0223 lists the known false positives). Flutter's Dart code does not use canaries by design.

### 4. Dependencies, SBOM and what the code is built from (MASWE-0044, 0046, 0047, 0048)

- With project access, run TEST-0272 (Gradle dependency-check) or TEST-0273 (lock files), and TEST-0274 or 0275 (SBOM into Dependency-Track). Cross-check with a second scanner. Results differ between the NVD-based and the OSV-based databases.
- Without project access, identify libraries from the binary. The [KNOW-0004 note](/mobile/mastg-know-0004-third-party-libraries/) covers the methods for Android: package names, version strings, `META-INF/*.version`, native library names.
- Using the same inventory, look for **deprecated APIs** (lint and compiler warnings, `UIWebView`, BKS keystores, legacy signing schemes), **home-grown security code** (custom cipher or hash classes, a TrustManager or DNS resolver of the app's own), and **unexplained code**: endpoints, permissions, native libraries or loaders that no declared SDK accounts for (MASWE-0048).

### 5. Untrusted-input sinks (MASWE-0050)

- For every input from step 1, follow the data to a sink: SQL (`rawQuery`, `execSQL`, `SQLiteQueryBuilder.appendWhere`), file paths (`File(dir, name)`, `ZipEntry.getName`, `OpenableColumns.DISPLAY_NAME`), deserializers (`ObjectInputStream`, `getSerializableExtra`, `NSKeyedUnarchiver`), XML parsers, and native parsers through JNI.
- Run MASTG-TEST-0337, 0339 and 0375 on Android and 0386 on iOS, then the note's own runtime checks with Frida hooks on the app's methods. Run the PLATFORM entry-point tests (deep links, intents, WebViews) alongside; most CODE-4 findings arrive through a PLATFORM channel.

### 6. Dynamic code (MASWE-0049)

- **Android, static:** search for `DexClassLoader`, `PathClassLoader`, `InMemoryDexClassLoader`, `DexFile`, `System.load`, `System.loadLibrary` with a computed name, and `createPackageContext` with `CONTEXT_INCLUDE_CODE`. **Android, runtime:** hook them to record the path, the file permissions and who can write there. Since Android 14, apps targeting API 34 or higher must mark dynamically loaded DEX and JAR files read-only before loading them, or the system throws an exception.
- **iOS:** native code cannot be added after installation (see [App Signing](#ios-app-signing-mastg-know-0058) below). Check `dlopen` and `Bundle.load` for paths inside the bundle, then look at interpreted code instead: JavaScriptCore, React Native and over-the-air JS bundles, Lua and other scripting engines. App Store Review Guideline 2.5.2 limits what downloaded code may do.
- For anything downloaded, find the integrity check and the key it uses. A hash fetched from the same server is not a signature.

### 7. Update enforcement (MASWE-0043)

- Find the mechanism statically: TEST-0392 or 0383. Then run TEST-0382 or 0384 through a proxy. Cancel the immediate flow, background the app, lower the version the app reports, and replay an old build's requests against the API.
- The finding that matters is server-side. If an old build still gets full API access, enforcement is cosmetic, whatever the client does.

### 8. Report

For each finding, state the attacker position from the table above, the profile (L1 or L2), the OS versions tested, whether the path was proven at runtime or only found statically, and for dependency findings the vulnerable function and how input reaches it.

## Rating overview

The detailed tables are in each note's *Rating findings* section. This is their general shape. CODE findings are often Low or Info **on their own**. They go up with reachability, an attacker position that needs little, and what the chained impact is.

| Finding | Attacker needs | Typical rating | Note |
|---------|----------------|----------------|------|
| Malicious or undisclosed functionality in the release build: exfiltration, a hidden remote switch, a backdoor | Nothing; it ships to every user | Critical | [MASWE-0048](/mobile/maswe-0048-malicious-code-included-in-the-app/) |
| Code loaded from a location another app can write, or downloaded without a signature check over a channel an attacker can influence | Malicious app, or network or server control | Critical to High | [MASWE-0049](/mobile/maswe-0049-unsafe-dynamic-code-loading/) |
| SQL injection, path traversal or unsafe deserialization reachable from another app or a link, with data access or overwrite shown | Malicious app or one tap | High (Critical with credentials or code execution) | [MASWE-0050](/mobile/maswe-0050-unsafe-handling-of-untrusted-data/) |
| Known-vulnerable component with a reachable vulnerable path | Whatever delivers the input | The CVE's impact in context | [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/) |
| Custom crypto, TLS or authentication that is shown to be breakable | Depends on the function | High | [MASWE-0047](/mobile/maswe-0047-non-standard-security-apis/) |
| Old builds keep full backend access; client-only, dismissible update gate (L2) | An unpatched user | Medium | [MASWE-0043](/mobile/maswe-0043-enforced-updating-not-implemented/) |
| Deprecated security API with a known weakness in use, such as a BKS keystore for long-term keys or `UIWebView` (L2) | Depends on the API | Low to High (High when app secrets sit in a BKS file whose password ships in the app, or `UIWebView` renders remote content with a native bridge) | [MASWE-0046](/mobile/maswe-0046-use-of-deprecated-apis/) |
| `minSdkVersion` that admits OS versions with unfixable bugs relevant to the app; target behind the store requirement | A user on an old OS | Low to Medium | [MASWE-0041](/mobile/maswe-0041-running-on-recent-platform-version-not-ensured/), [MASWE-0042](/mobile/maswe-0042-latest-platform-version-not-targeted/) |
| Native library parsing untrusted input without canaries or with an executable stack (L2) | A memory-corruption bug as well | Low to Medium | [MASWE-0045](/mobile/maswe-0045-compiler-security-features-not-used/) |
| Known CVE in code never reached; missing canaries in a library with no stack buffers | — | Info to Low | [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/), [MASWE-0045](/mobile/maswe-0045-compiler-security-features-not-used/) |

Three rules apply to every row.

- **Rate the chain, not the scanner output.** A CVE, a missing canary and an exported provider are one finding if together they make one path, and three Info items if they do not.
- **Say what you proved.** "Present", "reachable" and "exploited" are different claims. Most CODE reports blur them.
- **Profile matters.** Five of the ten weaknesses are L2 only. For an L1 app, report them as observations unless they chain into an L1 weakness.

## Command cheat sheet

The most-used commands from the series. Each note has the full procedure, the expected output and how to read it.

### Inventory and platform versions

```bash
# Android: package, versions and SDK levels
aapt2 dump badging app.apk | grep -E "^package:|sdkVersion|targetSdkVersion"
apkanalyzer manifest min-sdk app.apk
apkanalyzer manifest target-sdk app.apk
apkanalyzer manifest debuggable app.apk
apkanalyzer files list app.apk | grep -E '^/lib/|\.dex$|^/assets/.*\.(dex|jar|so|js)$'
# On a device: what is installed and which OS it runs
adb shell dumpsys package com.example.app | grep -E 'versionCode|minSdk|targetSdk'
adb shell getprop ro.build.version.sdk

# iOS: minimum OS, SDK and Xcode used to build
unzip -q App.ipa -d ipa
plutil -p ipa/Payload/App.app/Info.plist | grep -E 'MinimumOSVersion|DTSDKName|DTXcode|DTPlatformVersion|CFBundleShortVersionString'
find ipa/Payload/App.app \( -name '*.framework' -o -name '*.dylib' -o -name '*.appex' \) -maxdepth 2
```

### Binary hardening

```bash
# Android native libraries (llvm-readelf from the NDK takes the same options)
unzip -q app.apk 'lib/*' -d apk_libs
for so in apk_libs/lib/arm64-v8a/*.so; do
  echo "== $so"
  readelf -h "$so" | grep 'Type:'                          # DYN = position-independent
  readelf -lW "$so" | grep GNU_STACK                       # flags RW, not RWE
  readelf -dW "$so" | grep -E 'BIND_NOW|FLAGS|TEXTREL'     # full RELRO; TEXTREL must not appear
  readelf -sW "$so" | grep -cE '__stack_chk_fail'          # canaries referenced
  readelf -sW "$so" | grep -oE '__[a-z0-9_]+_chk' | sort -u   # FORTIFY variants
done
rabin2 -I apk_libs/lib/arm64-v8a/libnative.so | grep -E 'canary|pic|nx|relro|stripped'

# iOS Mach-O (decrypted main binary; frameworks the same way)
otool -hv ipa/Payload/App.app/App | grep -o PIE
otool -Iv ipa/Payload/App.app/App | grep -E '___stack_chk_(fail|guard)'
otool -Iv ipa/Payload/App.app/App | grep -E '_objc_release|_objc_retainAutorelease|_swift_release'
```

### Dependencies and SBOM

```bash
# Android project (needs the source tree)
./gradlew :app:dependencies --configuration releaseRuntimeClasspath
./gradlew dependencyCheckAnalyze        # with the org.owasp.dependencycheck plugin applied
cdxgen -t java -o bom.json .
# iOS lock files (dependency-check analysers for these are experimental)
dependency-check --enableExperimental -f JSON --nvdApiKey "$NVD_API_KEY" -s Podfile.lock
dependency-check --enableExperimental -f JSON --nvdApiKey "$NVD_API_KEY" -s Package.resolved
# A second opinion from a different vulnerability database
osv-scanner scan source -r .
grype sbom:./bom.json
```

### Untrusted input and dynamic code

```bash
# Decompile, then search for sinks and loaders
jadx -d jadx_out app.apk
rg -n 'ObjectInputStream|getSerializableExtra|readSerializable|appendWhere|rawQuery\(|execSQL\(' jadx_out/sources
rg -n 'DexClassLoader|InMemoryDexClassLoader|PathClassLoader|createPackageContext|System\.load\(' jadx_out/sources
rg -n 'ZipEntry|getName\(\)|DISPLAY_NAME|new File\(' jadx_out/sources
semgrep --config ./rules/ --metrics=off jadx_out/sources

# iOS: deserialization and loaders referenced by the binary
nm -u ipa/Payload/App.app/App | grep -E 'NSKeyedUnarchiver|dlopen|NSXMLParser'
rabin2 -zz ipa/Payload/App.app/App | grep -E 'unarchiveObject|decodeObjectForKey|requiresSecureCoding'

# Runtime: trace the app's own calls
frida-trace -U -f com.example.app -j 'dalvik.system.DexClassLoader!$init' -j 'android.content.ContentResolver!query'
frida-trace -U -f com.example.app -i 'dlopen' -m '-[NSKeyedUnarchiver *]'
frida -U -f com.example.app -l hooks.js
```

## Knowledge items not tied to a weakness

OWASP's MASVS-CODE Knowledge folders hold eight items that no CODE weakness links to. Most of them belong in substance to MASVS-RESILIENCE. Debuggable builds, debug symbols, signing format and debug artefacts are tested there, under [MASWE-0061](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0061/) (debug artefacts not removed) and [MASWE-0063](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0063/) (debug mechanisms not disabled). We will test the debuggable-app and debug-symbol topics in our upcoming MASVS-RESILIENCE series. Here is what each item says, what we would add, and the commands to check it now.

### Android: Debugging Information and Debug Symbols (MASTG-KNOW-0008)

Android native code ships as ELF shared objects under `lib/<abi>/`. An ELF file can carry two symbol tables. `.dynsym` is the dynamic table that the linker needs at runtime. It is always present and holds every exported symbol, including the `Java_<package>_<class>_<method>` names of statically registered JNI functions. `.symtab` is the full link-time table with local symbols, and stripping removes it. Debug information is in DWARF sections: `.debug_info` (types, functions, scopes), `.debug_line` (address to source line), `.debug_str` and friends. Some toolchains compress them into `.zdebug_*` sections (clang and GCC `-gz`), which older tools miss and wrongly report as stripped. A note on OWASP's text: it associates `.symtab` with the `DT_SYMTAB` dynamic tag, but `DT_SYMTAB` points to the dynamic table, `.dynsym`. What matters in practice is whether `.symtab` and non-empty DWARF sections exist, not the section names alone.

The Android Gradle plugin strips native libraries in release builds by default. For symbolicated native crash reports, the build produces a separate `native-debug-symbols.zip` (configured with `ndk { debugSymbolLevel = "FULL" }` or `"SYMBOL_TABLE"`) for upload to Play Console. It is the native counterpart of R8's `mapping.txt`, and neither belongs in the APK. Unstripped libraries in a release build tell a reverse engineer function names, source paths and types. That is an information gain, not a vulnerability. On its own it rates Info or Low under MASVS-RESILIENCE. Exported JNI names in `.dynsym` cannot be stripped. Developers who want to hide them register natives with `RegisterNatives` and build with `-fvisibility=hidden`. [OWASP page](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0008/).

```bash
file apk_libs/lib/arm64-v8a/*.so                                  # "stripped" / "not stripped" / "with debug_info"
readelf -SW apk_libs/lib/arm64-v8a/libnative.so | grep -E '\.symtab|\.z?debug_'
rabin2 -I apk_libs/lib/arm64-v8a/libnative.so | grep -E 'stripped|linenum|lsyms'
readelf -W --dyn-syms apk_libs/lib/arm64-v8a/libnative.so | grep -c ' Java_'    # JNI exports
unzip -l app.apk | grep -E 'mapping\.txt|native-debug-symbols|\.dwo$'           # must be empty
```

### Android: StrictMode (MASTG-KNOW-0009)

`StrictMode` is a developer tool that reports policy violations at runtime. `ThreadPolicy` catches slow work on the main thread: `detectDiskReads()`, `detectDiskWrites()`, `detectNetwork()`. `VmPolicy` catches process-wide problems: leaked SQLite cursors and closables. Several `VmPolicy` checks are security checks in disguise: `detectFileUriExposure()`, `detectCleartextNetwork()` (API 23), `detectContentUriWithoutPermission()` (API 26), `detectNonSdkApiUsage()` (API 28) and `detectUnsafeIntentLaunch()` (API 31, which flags intent-redirection patterns). Each policy reacts through `penalty*` methods: `penaltyLog()` writes to logcat, `penaltyDeath()` kills the process, and `penaltyListener()` (API 28) calls back into the app.

Recommend these detectors to developers in debug and CI builds, since they catch [intent redirection](/mobile/maswe-0032-insecure-intents/) and [cleartext traffic](/mobile/maswe-0026-cleartext-network-traffic/) early. In a release build, StrictMode should be absent. The usual pattern is to wrap it in `if (BuildConfig.DEBUG)`, and R8 removes the dead branch. If you find StrictMode active in a release build, `penaltyLog()` puts stack traces and class names in the log. Any `penaltyDeath*` turns a violation an attacker can trigger, such as a crafted `file://` URI, into a crash. Both are low-severity hygiene findings. [OWASP page](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0009/).

```bash
rg -n 'StrictMode\.(set|enable)|penalty(Log|Death|Listener)|detect(UnsafeIntentLaunch|CleartextNetwork|FileUriExposure)' jadx_out/sources
adb logcat -s StrictMode     # exercise the release build; any output means a policy is live
```

### Android: Exception Handling (MASTG-KNOW-0010)

OWASP's item is one paragraph: Java, Kotlin and C++ code can all throw, and the app has to reach a safe state without leaking through the UI or logs. Best practice [MASTG-BEST-0021](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0021/) adds three rules. Keep user-facing errors generic and logs sanitised. **Fail securely**: an exception inside a security check must end in *deny*. **Abort on validation errors** instead of repairing the data until it passes. The second rule is the one that produces real findings. Look for `catch (Exception e) { return true; }` around signature, licence, root or certificate checks. Look for `runCatching { verify() }.getOrDefault(true)` in Kotlin, and for a `TrustManager` that catches `CertificateException` and carries on. Three NETWORK tests reference this Knowledge item for that reason: MASTG-TEST-0282, 0284 and 0295, all in our [MASWE-0027 note](/mobile/maswe-0027-insecure-certificate-validation/).

For leakage, check `printStackTrace()` and `Log.*(…, e)` calls that reach release builds, error dialogs that show `e.getMessage()` from server or SQL errors, and `Thread.setDefaultUncaughtExceptionHandler` implementations. Crash reporters install one, so check what the reports carry: user data, tokens or request bodies. In native code, an uncaught C++ exception or a JNI exception left pending aborts the process. Crafted input that reliably crashes the app is an availability finding under [MASWE-0050](/mobile/maswe-0050-unsafe-handling-of-untrusted-data/). Sensitive data in logs is [MASWE-0005](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0005/). [OWASP page](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0010/).

```bash
rg -n 'catch \((e|ex|t|ignored): (Exception|Throwable)\)|catch \((Exception|Throwable) [a-z]+\)' jadx_out/sources | head -50
rg -n 'printStackTrace\(\)|setDefaultUncaughtExceptionHandler|getStackTraceString' jadx_out/sources
adb logcat --pid="$(adb shell pidof -s com.example.app)" | grep -E 'FATAL EXCEPTION|Caused by|at com\.example'
```

### iOS: App Signing (MASTG-KNOW-0058)

iOS refuses to run unsigned code. The main executable carries an embedded signature whose CodeDirectory holds a hash of every code page. `_CodeSignature/CodeResources` seals the bundle's resources, and nested code (frameworks, dylibs, extensions) is signed separately and recorded in the parent. Entitlements are part of the signature, so they cannot be changed without re-signing. The kernel checks pages as they are mapped. Library validation adds that a process may only load Apple platform binaries or code with its own Team ID. A dylib copied into the container after installation fails to load, even if the developer signed it (`code signing blocked mmap()`). Static libraries are simply part of the main binary and its signature.

Two consequences matter for this series. First, an App Store app cannot add **native** code at runtime. Every library it can ever `dlopen` was in the bundle at install time. On iOS, [MASWE-0049](/mobile/maswe-0049-unsafe-dynamic-code-loading/) is therefore mostly about interpreted code (JavaScript bundles, scripting engines) and about which bundled library is chosen. Second, a signature proves who built the bundle, not what is inside it. It does nothing against [MASWE-0048](/mobile/maswe-0048-malicious-code-included-in-the-app/), where the developer's own pipeline signs the malicious code. The legacy CodeDirectory format is checked by the resilience test MASTG-TEST-0220. The Android counterpart (v1 to v4 signature schemes) is in our [KNOW-0003 note](/mobile/mastg-know-0003-app-signing/). [OWASP page](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CODE/MASTG-KNOW-0058/).

```bash
codesign -dvvv ipa/Payload/App.app 2>&1 | grep -E 'Identifier|TeamIdentifier|CodeDirectory|Authority'
codesign -d --entitlements - ipa/Payload/App.app
codesign --verify --deep --strict --verbose=2 ipa/Payload/App.app   # fails on a decrypted App Store binary: expected
find ipa/Payload/App.app -name '*.dylib' -o -name '*.framework' -maxdepth 2
```

### iOS: Debuggable Apps (MASTG-KNOW-0062)

An iOS app is debuggable when its signature carries the `get-task-allow` entitlement set to `true`. That lets `debugserver` and LLDB attach to it, and lets anyone who holds the device read and change its memory. Xcode adds the entitlement automatically when it signs with a development certificate and provisioning profile. Distribution signing for the App Store, Ad Hoc or Enterprise leaves it out, and App Store Connect rejects builds that contain it. OWASP's item also lists Xcode settings: the `DEBUG` preprocessor macro, `-D DEBUG` in *Other Swift Flags*, and the scheme's *Debug executable* option. Those do not control the entitlement. They decide which `#if DEBUG` code is compiled in and whether Xcode attaches when it launches the app. They are still worth checking, because `#if DEBUG` debug menus and bypasses that leak into a release configuration are a finding of their own (see [Non-Production Resources](#ios-non-production-resources-mastg-know-0064)).

The practical test is on the shipped IPA, not the project. Read the entitlements. If there is an `embedded.mobileprovision` (Ad Hoc, enterprise and development builds), decode it and check the profile type and its own `get-task-allow`. The resilience test MASTG-TEST-0261 covers this under MASWE-0063, and our RESILIENCE series will cover it in full. [OWASP page](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CODE/MASTG-KNOW-0062/).

```bash
codesign -d --entitlements - ipa/Payload/App.app 2>/dev/null | grep -A1 get-task-allow
security cms -D -i ipa/Payload/App.app/embedded.mobileprovision | grep -A1 -E 'get-task-allow|ProvisionsAllDevices|<key>Name</key>'
```

### iOS: Debugging Information and Debug Symbols (MASTG-KNOW-0063)

Debug builds keep symbols and a debug map in the binary. With *Debug Information Format* set to *DWARF with dSYM File* (`DEBUG_INFORMATION_FORMAT = dwarf-with-dsym`), release builds write the DWARF to a separate `.dSYM` bundle. You upload that bundle for crash symbolication, and it never ships. Note what OWASP's item leaves out. Producing a dSYM does not strip the binary. Stripping is a separate step, controlled by `STRIP_INSTALLED_PRODUCT`, `DEPLOYMENT_POSTPROCESSING` and `STRIP_STYLE`, which Xcode applies when archiving with default release settings. Also, Objective-C class and selector names and Swift type metadata stay in every binary, because the runtime needs them. Their presence is normal and not a finding. What you look for is leftover local symbols for C, C++ and Swift functions, debug-map entries, and a `.dSYM` inside the IPA.

Like its Android twin, this is reverse-engineering help, not a vulnerability: Info or Low on its own. The resilience test MASTG-TEST-0219 checks it under MASWE-0061, and our RESILIENCE series will too. [OWASP page](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CODE/MASTG-KNOW-0063/).

```bash
find ipa/Payload -name '*.dSYM'                          # must be empty
nm -a ipa/Payload/App.app/App | grep -c ' - '            # debug-map (stab) entries; 0 when stripped
nm ipa/Payload/App.app/App | grep -c ' t '               # local text symbols that survived
rabin2 -I ipa/Payload/App.app/App | grep -E 'stripped|dbg_file'
```

### iOS: Non-Production Resources (MASTG-KNOW-0064)

Non-production resources are anything meant for development, test or staging that ends up in the release build. Examples are verbose logging frameworks, staging or test API endpoints, sample data files, feature flags that switch on insecure behaviour, development certificates and provisioning profiles, and test credentials or API keys. They matter for two reasons. Test endpoints often have weaker authentication than production. And a flag that the client checks can usually be flipped with Frida or a plist edit on a jailbroken device. The same applies to Android, where OWASP has no matching item: look in `assets/`, `res/raw/` and `BuildConfig` fields.

Look for hostnames containing `dev`, `test`, `staging`, `qa` or `uat`, then confirm whether they are reachable and what they accept. Look for fixture files (`*.json`, `*.sqlite`, `*.realm`) under the bundle, a second `GoogleService-Info.plist` or `.xcconfig`, and debug tools such as FLEX. Check whether `aps-environment` is `development` in the entitlements. Hardcoded secrets go under [MASWE-0004](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/). Implementation details in logs are the resilience tests MASTG-TEST-0358 and 0359 (MASWE-0061). [OWASP page](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CODE/MASTG-KNOW-0064/).

```bash
rg -a -o -N 'https?://[A-Za-z0-9.-]*(dev|test|staging|stage|qa|uat)[A-Za-z0-9.-]*' ipa/Payload/App.app | sort -u
find ipa/Payload/App.app \( -name '*.sqlite' -o -name '*.realm' -o -name '*.xcconfig' -o -name 'GoogleService-Info*.plist' -o -iname '*mock*' -o -iname '*fixture*' \)
nm ipa/Payload/App.app/App | grep -iE 'FLEXManager|Debug(Menu|Panel)'; ls ipa/Payload/App.app/Frameworks
codesign -d --entitlements - ipa/Payload/App.app 2>/dev/null | grep -A1 aps-environment
```

### iOS: Exception Handling (MASTG-KNOW-0065)

iOS has two error worlds, and mixed Objective-C and Swift code falls between them. Objective-C uses `NSException` for programming errors, such as out-of-bounds access or an unrecognised selector. It is raised with `raise` or `@throw` and caught with `@try`/`@catch`/`@finally`. Objective-C uses `NSError` for recoverable errors, returned by reference with a `BOOL` or `nil` result. Swift has `throws`, `do`/`catch`, `try?`, `try!` and `Result`. Swift's `catch` **cannot** catch an `NSException`, so an exception raised in Objective-C code under a Swift caller terminates the app. Apple's guidance is to use `NSError` across the boundary. The `@try` blocks also need care under manual memory management, because objects allocated in the block must be released in `@finally`.

For a tester this splits into three checks. **Crashes from input**: `try!`, force unwraps and unchecked `NSException`-raising calls such as `objectAtIndex:` on data from a URL, file or server give a reliable crash. That is an availability finding under [MASWE-0050](/mobile/maswe-0050-unsafe-handling-of-untrusted-data/), worth more when one link can crash the app every time it launches. **Fail-open handlers**: a `catch` in trust evaluation, jailbreak detection or receipt validation that returns success. **Leakage**: error text shown to users or logged with `NSLog` or `os_log` using `%{public}` on sensitive values, and crash reporters installed through `NSSetUncaughtExceptionHandler` that send more than a stack trace. [OWASP page](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CODE/MASTG-KNOW-0065/).

```bash
nm -u ipa/Payload/App.app/App | grep -E 'NSSetUncaughtExceptionHandler|_objc_exception_throw'
idevicesyslog | grep -E 'App\[|Terminating app due to uncaught exception'
idevicecrashreport -e ./crashes && grep -l 'com.example.app' ./crashes/*.ips
```

### The older standalone CODE notes

Two notes written before this series still apply, and the weakness notes link to them rather than repeat them.

- **[Third-Party Libraries in Android Apps (MASTG-KNOW-0004)](/mobile/mastg-know-0004-third-party-libraries/)** shows how to identify bundled libraries from an APK when you have no source. It covers package names, version resources and native library names, and how to map them to CVEs, plus the licence exposure that most reports leave out. It is the black-box companion to the SCA tests in [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/).
- **[Memory Corruption in Android Apps (MASTG-KNOW-0005)](/mobile/mastg-know-0005-memory-corruption-bugs/)** explains why ART protects managed code but not JNI and NDK code, what to review in native libraries, and why MASTG dropped its black-box memory-corruption tests. Read it with [MASWE-0045](/mobile/maswe-0045-compiler-security-features-not-used/). The note checks the mitigations; KNOW-0005 is about the bugs.

## Related weaknesses in other categories

A CODE review touches these weaknesses from other groups. Where we have a note, the link goes there.

- **[MASWE-0029](/mobile/maswe-0029-insecure-deep-links/), [MASWE-0032](/mobile/maswe-0032-insecure-intents/), [MASWE-0034](/mobile/maswe-0034-webviews-allow-access-to-local-resources/) and [MASWE-0035](/mobile/maswe-0035-webviews-loading-untrusted-content/)** (PLATFORM). These are the entry points that carry untrusted data to the sinks in MASWE-0050. Three of them map to MASVS-CODE-4 as well.
- **[MASWE-0018: Missing authentication on app components](/mobile/maswe-0018-missing-auth-on-app-components/)** (AUTH). Whether another app can reach a provider or activity at all. MASWE-0050 asks what happens to the data once it arrives.
- **[MASWE-0026](/mobile/maswe-0026-insecure-tls-protocol-versions/)** and **[MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/)** (NETWORK). GMS `ProviderInstaller` is the classic "outdated platform security component" from MASWE-0044. Custom trust managers are MASWE-0047 in its network form.
- **[MASWE-0011: Improper signature verification](/mobile/maswe-0011-improper-signature-verification/)** (CRYPTO). Both MASWE-0049 and MASWE-0057 rely on it for the integrity check on downloaded code and stored resources. [MASWE-0012](/mobile/maswe-0012-improper-random-number-generation/) and the [CRYPTO hub](/mobile/masvs-crypto-cryptography-guide/) cover the crypto side of MASWE-0046 and 0047.
- **[MASWE-0004: Sensitive data hardcoded in the app package](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/)** (STORAGE). Test keys and non-production credentials.
- **[MASWE-0057](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0057/), [MASWE-0061](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0061/) and [MASWE-0063](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0063/)** (RESILIENCE). Resource integrity, debug artefacts and debuggable builds. Coming in our RESILIENCE series.
- **[MASWE-0075](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0075/)** (non-reproducible builds) and **[MASWE-0073](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0073/)** (data collection declarations). MASWE-0048 hands over to the first for build provenance, and MASWE-0044 to the second for what SDKs collect.

## Other series hubs

- [MASVS-STORAGE: secure storage](/mobile/masvs-storage-1-secure-storage-guide/)
- [MASVS-CRYPTO: cryptography and key management](/mobile/masvs-crypto-cryptography-guide/)
- [MASVS-AUTH: authentication and authorisation](/mobile/masvs-auth-authentication-guide/)
- [MASVS-NETWORK: secure communication](/mobile/masvs-network-secure-communication-guide/)
- [MASVS-PLATFORM: IPC, WebViews and the UI](/mobile/masvs-platform-platform-interaction-guide/). Most CODE-4 findings arrive through a PLATFORM channel.

## References

- OWASP MASVS: [MASVS-CODE-1](https://mas.owasp.org/MASVS/controls/MASVS-CODE-1/), [MASVS-CODE-2](https://mas.owasp.org/MASVS/controls/MASVS-CODE-2/), [MASVS-CODE-3](https://mas.owasp.org/MASVS/controls/MASVS-CODE-3/), [MASVS-CODE-4](https://mas.owasp.org/MASVS/controls/MASVS-CODE-4/) (CC BY-SA 4.0)
- OWASP MASWE: [MASWE-0041](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0041/), [MASWE-0042](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0042/), [MASWE-0043](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0043/), [MASWE-0044](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0044/), [MASWE-0045](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0045/), [MASWE-0046](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0046/), [MASWE-0047](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0047/), [MASWE-0048](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0048/), [MASWE-0049](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0049/), [MASWE-0050](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0050/), [MASWE-0005](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0005/), [MASWE-0057](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0057/), [MASWE-0061](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0061/), [MASWE-0063](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0063/), [MASWE-0073](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0073/), [MASWE-0075](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0075/) (CC BY-SA 4.0)
- OWASP MASTG Knowledge: Android [MASTG-KNOW-0008](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0008/), [MASTG-KNOW-0009](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0009/), [MASTG-KNOW-0010](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0010/); iOS [MASTG-KNOW-0058](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CODE/MASTG-KNOW-0058/), [MASTG-KNOW-0062](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CODE/MASTG-KNOW-0062/), [MASTG-KNOW-0063](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CODE/MASTG-KNOW-0063/), [MASTG-KNOW-0064](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CODE/MASTG-KNOW-0064/), [MASTG-KNOW-0065](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CODE/MASTG-KNOW-0065/) (CC BY-SA 4.0)
- OWASP MASTG Best Practices: [MASTG-BEST-0021](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0021/) (CC BY-SA 4.0)
- OWASP MASTG Tests: the 18 CODE tests and five PLATFORM tests linked in the tables above; legacy tests [MASTG-TEST-0002](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0002/), [0025](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0025/), [0026](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0026/), [0027](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0027/), [0034](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0034/), [0036](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0036/), [0042](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0042/), [0043](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0043/), [0044](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0044/), [0079](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0079/), [0080](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0080/), [0085](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0085/), [0086](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0086/), [0087](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0087/) (CC BY-SA 4.0)
- OWASP MASTG Techniques and Tools: [MASTG-TECH-0115](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0115/), [MASTG-TECH-0118](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0118/), [MASTG-TECH-0130](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0130/), [MASTG-TECH-0131](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0131/), [MASTG-TECH-0132](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0132/), [MASTG-TECH-0133](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0133/), [MASTG-TECH-0140](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0140/), [MASTG-TOOL-0132 (Dependency-Track)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0132/), [MASTG-TOOL-0134 (cdxgen)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0134/) (CC BY-SA 4.0)
- Android Developers: [Meet Google Play's target API level requirement](https://developer.android.com/google/play/requirements/target-sdk), [In-app updates](https://developer.android.com/guide/playcore/in-app-updates), [Include native symbols](https://developer.android.com/build/include-native-symbols), [StrictMode](https://developer.android.com/reference/android/os/StrictMode), [Dynamic code loading risk](https://developer.android.com/privacy-and-security/risks/dynamic-code-loading), [Log info disclosure risk](https://developer.android.com/privacy-and-security/risks/log-info-disclosure), [Android 14 behaviour changes](https://developer.android.com/about/versions/14/behavior-changes-14)
- Android NDK: [Build System Maintainers Guide](https://android.googlesource.com/platform/ndk/+/master/docs/BuildSystemMaintainers.md); Android security enhancements in [Android 5.0](https://source.android.com/docs/security/enhancements#android-5)
- Apple: [Upcoming requirements](https://developer.apple.com/news/upcoming-requirements/), [App Store Review Guidelines](https://developer.apple.com/app-store/review/guidelines/), [Apple Platform Security: app code signing process](https://support.apple.com/guide/security/app-code-signing-process-sec7c917bf14/web), [Building your app to include debugging information](https://developer.apple.com/documentation/xcode/building-your-app-to-include-debugging-information), [Build settings reference](https://developer.apple.com/documentation/xcode/build-settings-reference), [Third-party SDK requirements](https://developer.apple.com/support/third-party-SDK-requirements/)
- [ELF specification](https://refspecs.linuxfoundation.org/elf/elf.pdf), [DWARF 5](https://dwarfstd.org/doc/DWARF5.pdf), [OWASP Vulnerable Dependency Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html), [CWE-636: Not Failing Securely](https://cwe.mitre.org/data/definitions/636.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
