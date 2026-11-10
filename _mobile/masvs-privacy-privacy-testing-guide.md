---
title: "MASVS-PRIVACY: Privacy Testing Guide for Mobile Apps"
date: 2026-11-10 22:20:00 +0000
subcategory: privacy
summary: "Hub for the MASVS-PRIVACY series: 13 weaknesses, all 13 OWASP tests, legal and store context, a consent-state assessment workflow and a cheat sheet."
refs: [MASVS-PRIVACY-1, MASVS-PRIVACY-2, MASVS-PRIVACY-3, MASVS-PRIVACY-4, MASWE-0066, MASWE-0067, MASWE-0068, MASWE-0069, MASWE-0070, MASWE-0071, MASWE-0072, MASWE-0073, MASWE-0074, MASWE-0075, MASWE-0076, MASWE-0077, MASWE-0078]
tags: [android, ios, masvs-privacy, gdpr, tracking, consent]
---

This is the entry point to our series on **OWASP MASVS-PRIVACY**, the control group about what an app does with the personal data it can reach, and whether the user knows and controls it. It has four requirements:

- **MASVS-PRIVACY-1:** "The app minimizes access to sensitive data and resources."
- **MASVS-PRIVACY-2:** "The app prevents identification of the user."
- **MASVS-PRIVACY-3:** "The app is transparent about data collection and usage."
- **MASVS-PRIVACY-4:** "The app offers user control over their data."

The series follows the [MASWE](https://mas.owasp.org/MASWE/) catalogue: one note per weakness, MASWE-0066 to MASWE-0078, each with its **Knowledge** (or **Background**), **Tests** and a rating section. This page explains when the category applies, gives the legal and store context in brief, maps the four controls to the thirteen weaknesses, lists all 13 OWASP tests and the note that documents each one, and points to the privacy-relevant weaknesses that live in other categories. It ends with a step-by-step privacy assessment, a command cheat sheet and links to the whole MASVS series, which this hub completes.

Know three things before you start. First, the tests are lopsided. Three weaknesses own all 13 OWASP tests (MASWE-0066 has nine, MASWE-0073 three, MASWE-0074 one), three of the 13 are `status: placeholder`, and **ten weaknesses have no OWASP tests at all**. For those, the notes give our own tests, labelled *Guler Tech methodology* and numbered `GT-PRIV-00NN-x`; other notes add our tests where OWASP covers only one platform. Second, the scope. We test the app under assessment, on test devices and test accounts we control, and we capture only our own sessions' traffic. The series shows how to *detect* what an app collects and sends, never how to re-identify or fingerprint real users. Third, this is technical testing guidance, not legal advice. Where a note mentions the law, it says what to check and what evidence to hand to the client's DPO or legal team; whether something breaches a regulation is their call.

## Contents

- [What MASVS-PRIVACY covers](#what-masvs-privacy-covers)
- [The P profile: when this category applies](#the-p-profile-when-this-category-applies)
  - [Who should require it](#who-should-require-it)
  - [What the category can and cannot test](#what-the-category-can-and-cannot-test)
  - [Privacy findings and security findings](#privacy-findings-and-security-findings)
- [Legal and store context in brief](#legal-and-store-context-in-brief)
  - [GDPR and UK GDPR](#gdpr-and-uk-gdpr)
  - [Device access: ePrivacy and PECR](#device-access-eprivacy-and-pecr)
  - [Other regimes](#other-regimes)
  - [Google Play](#google-play)
  - [Apple App Store](#apple-app-store)
- [Rating findings: the series-wide rule](#rating-findings-the-series-wide-rule)
- [The four controls and their weaknesses](#the-four-controls-and-their-weaknesses)
- [The series](#the-series)
- [Test index](#test-index)
- [Privacy-relevant weaknesses in other categories](#privacy-relevant-weaknesses-in-other-categories)
- [How to run a privacy assessment](#how-to-run-a-privacy-assessment)
- [Command cheat sheet](#command-cheat-sheet)
- [The full series](#the-full-series)
- [References](#references)

## What MASVS-PRIVACY covers

The other MASVS groups ask whether the app protects data from an attacker. PRIVACY asks a different question: is the app itself, and every SDK it ships, processing only what it needs, in the way it said it would, with the user in control? The "attacker" in most privacy findings is not a third party breaking in. It is the app's own analytics, advertising, attribution or crash-reporting code doing more than the user agreed to, or a design that exposes the user to other users by default.

OWASP's own [MASVS-PRIVACY chapter](https://mas.owasp.org/MASVS/12-MASVS-PRIVACY/) sets two boundaries that shape the whole series:

- **Collection and sharing are treated as one thing.** Data that leaves the user's control, whether it goes to a server or to another app on the device, counts. What happens on the server afterwards (retention, onward sale, model training) is out of scope, because you usually cannot test it from the app.
- **MASVS-PRIVACY is a baseline, not a privacy programme.** It does not replace a Data Protection Impact Assessment (GDPR Art. 35) or a legal review. The tests produce *evidence*; privacy professionals turn it into compliance conclusions.

Findings come from four kinds of gap, which line up with the four controls:

1. **Too much access.** Permissions, entitlements and keyboard Full Access that the features do not need; broad access where a picker or a coarse variant would do.
2. **Too identifiable.** Persistent or cross-app identifiers, raw personal data where a pseudonym would do, embedded login flows that expose browsing state, privacy-relevant actions with exposing defaults.
3. **Not transparent.** A privacy policy, Data safety form, App Privacy label or privacy manifest that does not match what the app actually does, including what its SDKs do.
4. **Not in the user's control.** No way to delete, export or correct data; no visibility settings; consent that is bundled, pre-ticked, ignored or impossible to withdraw.

## The P profile: when this category applies

### Who should require it

All thirteen PRIVACY weaknesses carry OWASP's **P** (privacy) profile. Twelve also carry **EUDIW**, the profile for EU Digital Identity Wallets; MASWE-0075 (non-reproducible builds) is P only. None carries L1, L2 or R. Like R, the P profile is a separate decision, not a stricter L2. In practice it applies to almost any app that processes personal data of real users, and it is essential for:

- **Health, fitness, fertility and mental-health apps:** special-category data (GDPR Art. 9), sensors, Health Connect and HealthKit.
- **Finance, banking and insurance:** financial data, device and behavioural signals collected for fraud prevention that must not drift into marketing.
- **Social, messaging and dating apps:** contacts, visibility to other users, location sharing, read receipts.
- **Apps used by children** or likely to be: high-privacy defaults are expected (see the ICO's [Children's code](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/childrens-information/childrens-code-guidance-and-resources/)).
- **Ad-funded and free apps:** advertising, attribution and analytics SDKs are where most undeclared collection is found.
- **Identity wallets** (EUDIW): selective disclosure, unlinkability between relying parties, presentation consent.

If the client has not adopted P, report privacy issues you notice anyway as **observations**, and recommend the profile when the app clearly needs it. A finding such as "precise location sent to an advertising endpoint before any consent prompt" is worth raising whatever the agreed scope.

### What the category can and cannot test

Privacy testing mixes two kinds of work, and every note in the series is explicit about which one a test is:

- **Technical checks** with clear evidence: declared permissions and entitlements, purpose strings, privacy manifests, identifiers read by the app, SDK API calls, and above all the network traffic in each consent state.
- **Design and UX reviews** that need judgement: whether a rationale is clear, a default is the narrowest that works, a consent screen is free and specific, a deletion flow really deletes. Make these testable by writing the expected behaviour down first (from the policy, the store declarations and the client's own records of processing) and then recording what the app does, with screenshots.

What you cannot see: server-side retention and onward sharing, server-to-server transfers between the backend and a third party, and data an SDK's backend derives later. Say so in the report. A clean client-side result means "no undeclared flows observed from the device", not "compliant".

### Privacy findings and security findings

Many privacy problems are also security problems, and vice versa. Report each finding once, under the category whose control it breaks most directly, and cross-reference the other. Personal data in logs or unencrypted on shared storage is a STORAGE finding with a privacy impact; personal data sent to an SDK the policy does not mention is a PRIVACY finding even when the TLS is perfect. The list of [privacy-relevant weaknesses in other categories](#privacy-relevant-weaknesses-in-other-categories) shows the usual overlaps.

## Legal and store context in brief

This section is orientation for testers, not legal advice. It tells you which rules your evidence will be read against, so you collect the right evidence. The client's DPO or legal team decides what the evidence means.

### GDPR and UK GDPR

The [GDPR](https://eur-lex.europa.eu/eli/reg/2016/679/oj) applies in the EU; the [UK GDPR](https://www.legislation.gov.uk/eur/2016/679/contents) with the Data Protection Act 2018 applies in the UK, with the [ICO](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/) as regulator. The articles that the series refers to most:

| Article | What it means for an app test | Notes in this series |
|---------|-------------------------------|----------------------|
| Art. 5 principles: lawfulness, fairness, transparency, purpose limitation, data minimisation, storage limitation | Collect only what features need; use it only for the stated purposes | 0066, 0069, 0073 |
| Art. 6 lawful basis; Art. 9 special categories | Consent is one basis among six; health, biometric and similar data need an Art. 9 condition as well | 0078 |
| Art. 7 conditions for consent, Art. 4(11) definition | Freely given, specific, informed, unambiguous; demonstrable; withdrawal as easy as giving | 0078 |
| Art. 12–14 transparency | Concise, intelligible, easily accessible information at collection | 0070, 0072, 0073 |
| Art. 15–22 data subject rights | Access, rectification, erasure, restriction, portability, objection, automated decisions | 0076, 0077 |
| Art. 25 data protection by design and by default | Defaults that process only what is necessary and do not expose data to an indefinite audience | 0071, 0077 |
| Art. 4(5) pseudonymisation; Recital 26 anonymisation | Pseudonymised data is still personal data; only truly anonymous data falls outside the GDPR | 0067, 0068 |

Useful guidance: EDPB [Guidelines 05/2020 on consent](https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-052020-consent-under-regulation-2016679_en), [Guidelines 4/2019 on Article 25](https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-42019-article-25-data-protection-design-and_en), and [Guidelines 01/2025 on pseudonymisation](https://www.edpb.europa.eu/our-work-tools/documents/public-consultations/2025/guidelines-012025-pseudonymisation_en), adopted for consultation in January 2025 (check the EDPB site for the current version).

### Device access: ePrivacy and PECR

Separately from the GDPR, the EU [ePrivacy Directive](https://eur-lex.europa.eu/eli/dir/2002/58/oj) (Art. 5(3)) and the UK's [PECR regulation 6](https://www.legislation.gov.uk/uksi/2003/2426/regulation/6) require consent before storing information on, or reading information from, the user's device, unless the storage or access is strictly necessary for the service the user asked for. This is the "cookie rule", and it is not limited to cookies: the EDPB's [Guidelines 2/2023 on the technical scope of Art. 5(3)](https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-22023-technical-scope-art-53-eprivacy-directive_en) cover SDKs that read device identifiers or write local storage in mobile apps. For a tester, the practical consequence is that **what an SDK reads and sends before the consent decision** is the first thing to capture.

In the UK, the [Data (Use and Access) Act 2025](https://www.legislation.gov.uk/ukpga/2025/18/contents) amended PECR to add narrow exceptions to the consent requirement (for example for some statistical purposes), subject to conditions; the relevant provisions were commenced in stages during 2026. The ICO's [guidance on storage and access technologies](https://ico.org.uk/for-organisations/direct-marketing-and-privacy-and-electronic-communications/guidance-on-the-use-of-storage-and-access-technologies/) is the place to check which exception the client claims and what it requires. Record what the app does; leave the exception analysis to the client's lawyers.

### Other regimes

The [CCPA as amended by the CPRA](https://oag.ca.gov/privacy/ccpa) gives California residents rights to know, delete, correct, and opt out of the "sale" or "sharing" of personal information (sharing includes cross-context behavioural advertising), enforced by the [California Privacy Protection Agency](https://cppa.ca.gov/) and the Attorney General. Several other US states, Brazil (LGPD) and Canada (PIPEDA) have comparable rules. For the test, these change *which* rights flows and opt-outs must exist, not *how* you test them.

### Google Play

- **[User Data policy](https://support.google.com/googleplay/android-developer/answer/10144311):** a privacy policy in the Play Console and inside the app; prominent in-app disclosure and affirmative consent before collecting personal or sensitive data that users would not reasonably expect; limits on selling personal data.
- **[Data safety section](https://support.google.com/googleplay/android-developer/answer/10787469):** the developer's declaration of what data is collected and shared, for what purposes, and whether it is encrypted in transit and can be deleted. It covers data collected by SDKs in the app. Required since July 2022.
- **[Permissions and sensitive APIs](https://support.google.com/googleplay/android-developer/answer/9888170):** request only what core features need. Some permissions are restricted to declared use cases and reviewed: [SMS and Call Log](https://support.google.com/googleplay/android-developer/answer/10208820), [`QUERY_ALL_PACKAGES`](https://support.google.com/googleplay/android-developer/answer/10158779), background location, and the [permissions with minimum-scope alternatives](https://support.google.com/googleplay/android-developer/answer/14115180) such as broad photo and video access, where the photo picker is expected instead.
- **[Advertising ID](https://support.google.com/googleplay/android-developer/answer/6048248):** for advertising and analytics only; not to be linked to persistent device identifiers or personal data without consent; apps targeting Android 13 and later must declare `com.google.android.gms.permission.AD_ID` to read it.
- **[Account deletion](https://support.google.com/googleplay/android-developer/answer/13327111):** apps that let users create an account must offer an in-app path *and* a web link to request deletion of the account and its data. The Data safety deletion questions were due by 7 December 2023 (extensions to 31 May 2024).

### Apple App Store

- **[App Store Review Guidelines](https://developer.apple.com/app-store/review/guidelines/) 5.1.1** (data collection and storage): privacy policy link in App Store Connect and in the app; consent before collection; data minimisation; access to protected resources only with a purpose string; **5.1.1(v)**: apps that support account creation must let users initiate account deletion in the app (enforced since 30 June 2022; see [Offering account deletion in your app](https://developer.apple.com/support/offering-account-deletion-in-your-app/)). **5.1.2** (data use and sharing): tracking only with App Tracking Transparency permission; no repurposing of data without further consent.
- **[App Privacy details](https://developer.apple.com/app-store/app-privacy-details/)** ("nutrition labels"): what is collected, whether it is linked to the user, and whether it is used for tracking, including data collected by SDKs. Required for new apps and updates since December 2020.
- **[App Tracking Transparency](https://developer.apple.com/documentation/apptrackingtransparency)** (iOS 14.5 and later): permission through `ATTrackingManager` before tracking or reading the IDFA; the prompt text comes from `NSUserTrackingUsageDescription`. Apple's definition of tracking is in [User privacy and data use](https://developer.apple.com/app-store/user-privacy-and-data-use/).
- **[Privacy manifests](https://developer.apple.com/documentation/bundleresources/privacy-manifest-files)** (`PrivacyInfo.xcprivacy`, Xcode 15 and later): `NSPrivacyTracking`, `NSPrivacyTrackingDomains`, `NSPrivacyCollectedDataTypes` and `NSPrivacyAccessedAPITypes` with [required-reason API](https://developer.apple.com/documentation/bundleresources/describing-use-of-required-reason-api) declarations. App Store Connect has enforced required reasons, and manifests for Apple's list of commonly used SDKs, since 1 May 2024. If the user has not granted ATT permission, requests to declared tracking domains fail.

Store rules are what most clients feel first: an inaccurate Data safety form or a missing purpose string leads to rejection or removal long before a regulator writes. That is why declaration-versus-behaviour checks are at the centre of this series.

## Rating findings: the series-wide rule

Every note applies the same rule, adapted to its weakness. Rate a privacy finding by:

- **(a) Excess:** what personal data is exposed or processed *beyond* what is necessary, declared or consented to.
- **(b) Sensitivity:** special-category data (health, biometrics, sexual life, beliefs), precise location, children's data, financial data, contacts and communications rank highest; coarse or truly aggregated data lowest.
- **(c) Scale and reversibility:** every user or a niche flow; a resettable identifier or a permanent one; data that can be recalled or data already with a third party.
- **(d) Contradiction:** whether the behaviour contradicts the app's own privacy policy, Data safety section, App Privacy label, privacy manifest or a store policy. Contradiction carries store rejection and removal risk on top of the privacy impact.

The typical range is **Low to High**. Undeclared sharing of sensitive data with third parties, and tracking without consent where consent is required, are **High**. Pure documentation gaps with no data impact are **Low or Info**.

| Finding | Typical rating | Note |
|---------|----------------|------|
| Precise location, health data or contacts sent to an advertising or analytics third party, undeclared or before consent | High | [0073](/mobile/maswe-0073-inadequate-data-collection-declarations/), [0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/) |
| Tracking SDK starts and sends identifiers before the consent decision, or after consent is denied or withdrawn | High | [0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/), [0068](/mobile/maswe-0068-incorrect-use-of-identifiers-for-tracking/) |
| Tracking domain contacted on iOS but missing from `NSPrivacyTrackingDomains` | Medium to High | [0074](/mobile/maswe-0074-inadequate-tracking-domains-declarations/) |
| Advertising ID linked to account ID, email hash or a hardware identifier | Medium to High | [0068](/mobile/maswe-0068-incorrect-use-of-identifiers-for-tracking/) |
| Keyboard extension with Full Access that sends typed text off the device | High | [0066](/mobile/maswe-0066-inadequate-permission-management/) |
| Dangerous permission or entitlement with no reachable feature; deceptive purpose string | Low to Medium (higher for location, contacts, microphone) | [0066](/mobile/maswe-0066-inadequate-permission-management/) |
| Broad media or camera permission where a picker or system intent would do | Low to Medium | [0069](/mobile/maswe-0069-non-privacy-preserving-functionality/) |
| Account deletion missing, or "deletion" that only deactivates | Medium (store policy breach) | [0076](/mobile/maswe-0076-lack-of-data-management-controls/) |
| Profile, location or activity public by default | Medium to High, depending on audience and data | [0071](/mobile/maswe-0071-inadequate-privacy-defaults/), [0077](/mobile/maswe-0077-inadequate-data-visibility-controls/) |
| Privacy policy generic, unreachable in the app, or silent on an SDK category | Low to Medium | [0072](/mobile/maswe-0072-inadequate-privacy-policy/) |
| No reproducible build for an app that claims verifiability | Low (Info outside P) | [0075](/mobile/maswe-0075-non-reproducible-builds/) |

Two rules apply everywhere. First, a severity score is not a legal assessment: regulatory risk (fines, notification duties, lawful-basis questions) is assessed by the client's legal team, and the report should say so. Second, rate by what you observed. "This SDK *could* collect X" is a lead for the dynamic tests, not a finding.

## The four controls and their weaknesses

OWASP links each weakness to controls through the `mappings.masvs-v2` field of its MASWE file. One weakness, MASWE-0073, maps to two controls.

### MASVS-PRIVACY-1: minimise access

*"The app minimizes access to sensitive data and resources."* Request only what the feature needs, ask in context, give it back when it is no longer needed, and make sure SDKs only act on the user's consent.

- **[MASWE-0066](/mobile/maswe-0066-inadequate-permission-management/)** inadequate permission management: dangerous permissions, missing rationale, unused permissions not released (Android); purpose strings, entitlements and custom-keyboard Full Access (iOS).
- **[MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/)** inadequate data collection declarations, which OWASP maps to PRIVACY-3 *and* PRIVACY-1: the SDK data-flow tests (0318, 0319) are minimisation checks as much as declaration checks.

### MASVS-PRIVACY-2: prevent identification

*"The app prevents identification of the user."* Unlinkability: abstraction, anonymisation, pseudonymisation, and isolation of fingerprint-like signals (a fraud signal must not become an audience-measurement signal).

- **[MASWE-0067](/mobile/maswe-0067-lack-of-anonymization-or-pseudonymisation/)** lack of anonymisation or pseudonymisation, including unsalted hashes of emails and phone numbers, Exif location in uploads, and unredacted data sent to AI services.
- **[MASWE-0068](/mobile/maswe-0068-incorrect-use-of-identifiers-for-tracking/)** identifiers for tracking: hardware IDs, `ANDROID_ID`, Advertising ID, IDFA and IDFV, and linking them.
- **[MASWE-0069](/mobile/maswe-0069-non-privacy-preserving-functionality/)** non-privacy-preserving functionality: embedded login WebViews instead of `ASWebAuthenticationSession` or Custom Tabs, permissions instead of pickers, remote instead of on-device processing. It is the privacy counterpart of [MASWE-0047](/mobile/maswe-0047-non-standard-security-apis/).
- **[MASWE-0070](/mobile/maswe-0070-inadequate-awareness-for-privacy-actions/)** awareness for privacy-relevant actions: sharing, exporting, publishing, syncing without showing what goes where.
- **[MASWE-0071](/mobile/maswe-0071-inadequate-privacy-defaults/)** privacy defaults for those same actions: broadest audience preselected, metadata included, long retention.

### MASVS-PRIVACY-3: transparency

*"The app is transparent about data collection and usage."* What the app says it does must match what it does, in every place it says it.

- **[MASWE-0072](/mobile/maswe-0072-inadequate-privacy-policy/)** privacy policy: missing, generic, unreachable in the app, or contradicted by behaviour.
- **[MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/)** Data safety and App Privacy declarations versus traffic and SDK calls (also PRIVACY-1).
- **[MASWE-0074](/mobile/maswe-0074-inadequate-tracking-domains-declarations/)** tracking domains in privacy manifests versus domains contacted.
- **[MASWE-0075](/mobile/maswe-0075-non-reproducible-builds/)** reproducible builds: the only way for an outsider to verify that the binary does what the published source says.

### MASVS-PRIVACY-4: user control

*"The app offers user control over their data."* Users can manage, delete and modify their data, change privacy settings, and withdraw consent; the app re-asks when it wants more.

- **[MASWE-0076](/mobile/maswe-0076-lack-of-data-management-controls/)** data management controls: deletion, export, correction, opt-out.
- **[MASWE-0077](/mobile/maswe-0077-inadequate-data-visibility-controls/)** visibility controls: online status, read receipts, discoverability, profile fields.
- **[MASWE-0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/)** consent mechanisms: prior, specific, unbundled, withdrawable, and re-requested when processing changes.

**History.** MASVS v1 had no privacy group. OWASP maps MASWE-0072 and 0073 to v1's MSTG-STORAGE-12 (user education about personal data), and 0073 also to MSTG-NETWORK-1. There are no legacy v1 privacy tests to replace, so none of the notes has a legacy mapping table. The MASWE files also list `maswe-beta` IDs (for example MASWE-0108 to 0117) from OWASP's earlier draft numbering; you may see them in older OWASP material.

## The series

| Note | Weakness | Controls | Profiles | OWASP tests: Android | OWASP tests: iOS | Our tests |
|------|----------|----------|----------|----------------------|------------------|-----------|
| [Inadequate Permission Management](/mobile/maswe-0066-inadequate-permission-management/) | MASWE-0066 | PRIV-1 | P, EUDIW | 0254, 0255\*, 0256\*, 0257\* | 0360, 0361, 0362, 0363, 0390 | write the three Android placeholders |
| [Lack of Anonymization or Pseudonymisation](/mobile/maswe-0067-lack-of-anonymization-or-pseudonymisation/) | MASWE-0067 | PRIV-2 | P, EUDIW | none | none | both platforms |
| [Incorrect Use of Identifiers for Tracking](/mobile/maswe-0068-incorrect-use-of-identifiers-for-tracking/) | MASWE-0068 | PRIV-2 | P, EUDIW | none | none | both platforms |
| [Non-Privacy-Preserving Functionality](/mobile/maswe-0069-non-privacy-preserving-functionality/) | MASWE-0069 | PRIV-2 | P, EUDIW | none | none | both platforms |
| [Inadequate Awareness for Privacy Actions](/mobile/maswe-0070-inadequate-awareness-for-privacy-actions/) | MASWE-0070 | PRIV-2 | P, EUDIW | none | none | both platforms |
| [Inadequate Privacy Defaults](/mobile/maswe-0071-inadequate-privacy-defaults/) | MASWE-0071 | PRIV-2 | P, EUDIW | none | none | both platforms |
| [Inadequate Privacy Policy](/mobile/maswe-0072-inadequate-privacy-policy/) | MASWE-0072 | PRIV-3 | P, EUDIW | none | none | both platforms |
| [Inadequate Data Collection Declarations](/mobile/maswe-0073-inadequate-data-collection-declarations/) | MASWE-0073 | PRIV-3, PRIV-1 | P, EUDIW | 0206, 0318, 0319 | none | iOS counterparts |
| [Inadequate Tracking Domains Declarations](/mobile/maswe-0074-inadequate-tracking-domains-declarations/) | MASWE-0074 | PRIV-3 | P, EUDIW | none | 0281 | Android counterpart |
| [Non-Reproducible Builds](/mobile/maswe-0075-non-reproducible-builds/) | MASWE-0075 | PRIV-3 | P | none | none | both platforms |
| [Lack of Data Management Controls](/mobile/maswe-0076-lack-of-data-management-controls/) | MASWE-0076 | PRIV-4 | P, EUDIW | none | none | both platforms |
| [Inadequate Data Visibility Controls](/mobile/maswe-0077-inadequate-data-visibility-controls/) | MASWE-0077 | PRIV-4 | P, EUDIW | none | none | both platforms |
| [Inadequate User Consent Mechanisms](/mobile/maswe-0078-inadequate-user-consent-mechanisms/) | MASWE-0078 | PRIV-4 | P, EUDIW | none | none | both platforms |

\* `status: placeholder` on OWASP: title and one-line intent only.

OWASP tags all thirteen weaknesses for both platforms, and every note covers both. "Our tests" says what the note's *Guler Tech methodology* tests (`GT-PRIV-00NN-x`) add: the only tests where OWASP has none, the missing platform where OWASP covers one, and full write-ups of the placeholders. The series has 13 OWASP tests and 47 Guler Tech tests.

**Where the Knowledge lives.** OWASP does not link Knowledge items from the weakness files, so we placed them by topic:

- **0066:** Android app permissions (KNOW-0017) and iOS app permissions (KNOW-0077), both from OWASP's PLATFORM folder, in full; app extensions (KNOW-0082) and custom keyboards (KNOW-0141) as summaries, with the detail in our [MASWE-0031 note](/mobile/maswe-0031-allowing-untrusted-app-extensions/); best practices BEST-0051 (minimise iOS permissions and entitlements) and BEST-0069 (keep sensitive input on the system keyboard). Component-level permissions and protection levels are in our [MASWE-0018 note](/mobile/maswe-0018-missing-auth-on-app-components/).
- **0073:** third-party services embedded in Android apps (KNOW-0026, in OWASP's PRIVACY folder); BEST-0003 (comply with privacy regulations).
- **0072:** a pointer to BEST-0003.
- **All others:** no OWASP Knowledge. Each note has a `Background` section of its own; 0074's explains privacy manifests and how iOS blocks declared tracking domains without ATT permission.

## Test index

All 13 OWASP v2 tests whose `maswe` field names a PRIVACY weakness. **Type** is OWASP's own classification. Twelve live in OWASP's MASVS-PRIVACY folders; **MASTG-TEST-0390 lives in OWASP's iOS MASVS-PLATFORM folder** but belongs to MASWE-0066. The **Note** column links to the note that documents the test in full, with prerequisites, steps, evidence, pass and fail criteria, and a demo.

| ID (OWASP page) | Title | Platform | Type | Status | OWASP demos | Note |
|-----------------|-------|----------|------|--------|-------------|------|
| **MASWE-0066: permission management** | | | | | | |
| [MASTG-TEST-0254](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0254/) | Dangerous App Permissions | Android | static, code | active | [0033](https://mas.owasp.org/MASTG/demos/android/MASVS-PRIVACY/MASTG-DEMO-0033/MASTG-DEMO-0033/) | [0066](/mobile/maswe-0066-inadequate-permission-management/) |
| [MASTG-TEST-0255](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0255/) | Permission Requests Not Minimized | Android | — | placeholder | — | [0066](/mobile/maswe-0066-inadequate-permission-management/) |
| [MASTG-TEST-0256](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0256/) | Missing Permission Rationale | Android | — | placeholder | — | [0066](/mobile/maswe-0066-inadequate-permission-management/) |
| [MASTG-TEST-0257](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0257/) | Not Resetting Unused Permissions | Android | — | placeholder | — | [0066](/mobile/maswe-0066-inadequate-permission-management/) |
| [MASTG-TEST-0360](https://mas.owasp.org/MASTG/tests/ios/MASVS-PRIVACY/MASTG-TEST-0360/) | Purpose String Accuracy for Reachable Protected Resource Access | iOS | static, config, manual | active | — | [0066](/mobile/maswe-0066-inadequate-permission-management/) |
| [MASTG-TEST-0361](https://mas.owasp.org/MASTG/tests/ios/MASVS-PRIVACY/MASTG-TEST-0361/) | Runtime Use of Protected Resource APIs Without Accurate Purpose Strings | iOS | dynamic, hooks, manual | active | [0126](https://mas.owasp.org/MASTG/demos/ios/MASVS-PRIVACY/MASTG-DEMO-0126/MASTG-DEMO-0126/) | [0066](/mobile/maswe-0066-inadequate-permission-management/) |
| [MASTG-TEST-0362](https://mas.owasp.org/MASTG/tests/ios/MASVS-PRIVACY/MASTG-TEST-0362/) | Entitlements for Unjustified Capability Exposure | iOS | static, package, manual | active | — | [0066](/mobile/maswe-0066-inadequate-permission-management/) |
| [MASTG-TEST-0363](https://mas.owasp.org/MASTG/tests/ios/MASVS-PRIVACY/MASTG-TEST-0363/) | Runtime Use of Entitlement-Backed APIs for Unjustified Capability Exposure | iOS | dynamic, hooks, manual | active | [0127](https://mas.owasp.org/MASTG/demos/ios/MASVS-PRIVACY/MASTG-DEMO-0127/MASTG-DEMO-0127/) | [0066](/mobile/maswe-0066-inadequate-permission-management/) |
| [MASTG-TEST-0390](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0390/) | Full Access Requested by a Custom Keyboard Extension | iOS | static, code, manual | active | — | [0066](/mobile/maswe-0066-inadequate-permission-management/) |
| **MASWE-0073: data collection declarations** | | | | | | |
| [MASTG-TEST-0206](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0206/) | Undeclared PII in Network Traffic Capture | Android | dynamic, network | active | [0009](https://mas.owasp.org/MASTG/demos/android/MASVS-PRIVACY/MASTG-DEMO-0009/MASTG-DEMO-0009/) | [0073](/mobile/maswe-0073-inadequate-data-collection-declarations/) |
| [MASTG-TEST-0318](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0318/) | References to SDK APIs Known to Handle Sensitive User Data | Android | static, code | active | — | [0073](/mobile/maswe-0073-inadequate-data-collection-declarations/) |
| [MASTG-TEST-0319](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0319/) | Runtime Use of SDK APIs Known to Handle Sensitive User Data | Android | dynamic, hooks | active | [0081](https://mas.owasp.org/MASTG/demos/android/MASVS-PRIVACY/MASTG-DEMO-0081/MASTG-DEMO-0081/) | [0073](/mobile/maswe-0073-inadequate-data-collection-declarations/) |
| **MASWE-0074: tracking domains declarations** | | | | | | |
| [MASTG-TEST-0281](https://mas.owasp.org/MASTG/tests/ios/MASVS-PRIVACY/MASTG-TEST-0281/) | Undeclared Known Tracking Domains | iOS | static, dynamic | active | — | [0074](/mobile/maswe-0074-inadequate-tracking-domains-declarations/) |

That is 7 Android and 6 iOS tests. Of the ten with a type, five are static only (0254, 0318, 0360, 0362, 0390), four dynamic only (0206, 0319, 0361, 0363) and one both (0281). Five demos exist: 0033 (dangerous permissions with semgrep), 0009 (undeclared PII in traffic), 0081 (sensitive data passed to an analytics SDK, traced with Frida), 0126 (location captured under a deceptive purpose string) and 0127 (excessive entitlements). Read the table with these caveats in mind.

- **Presence is not a finding.** TEST-0254 says it fails "if there are any dangerous permissions", and TEST-0318 fails if the app calls an SDK's data-collection methods at all. Taken literally, every camera app fails 0254 and every app with analytics fails 0318. Both tests then add the real criterion: context, necessity and alternatives. Our notes use the presence results as an inventory and fail only unjustified permissions (0254) or data flows that are sensitive and not declared or consented to (0318, confirmed by 0319 or 0206).
- **TEST-0360 and 0361 contradict themselves on missing purpose strings.** Their "Out of Scope" boxes say they do not check protected-resource access without a matching purpose string (an App Store blocker, `ITMS-90683`), and their Evaluation sections then say that case fails the test. Our note follows the Evaluation, and reports it separately from inaccurate purpose strings, because on current iOS a missing key usually makes the access fail or the app terminate.
- **TEST-0206 finds only what you typed.** It looks for PII you entered. Device-derived data (advertising and vendor identifiers, location, installed-app lists, contacts read in the background) needs the canary and identifier checks in our 0068 and 0073 notes.
- **Tracker lists are leads, not verdicts.** TEST-0281 matches domains against public tracker lists. A listed domain is not necessarily used for tracking in Apple's sense, and an unlisted first-party endpoint can be. Evaluate against Apple's definition of tracking and the data actually sent.
- **Placeholders.** TEST-0255, 0256 and 0257 have only a title and an intent. Our MASWE-0066 note writes all three as *Guler Tech methodology*, against Android's own guidance on [minimising permission requests](https://developer.android.com/privacy-and-security/minimize-permission-requests) and [requesting permissions](https://developer.android.com/training/permissions/requesting).
- **Folder placement.** TEST-0390 sits with the PLATFORM tests on mas.owasp.org. If you browse by folder, the PRIVACY folders show twelve tests; by weakness, MASWE-0066 to 0078 own thirteen. Our [MASWE-0031 note](/mobile/maswe-0031-allowing-untrusted-app-extensions/) covers the other side of the keyboard question: an app protecting its own fields from third-party keyboards.

## Privacy-relevant weaknesses in other categories

Personal data does not stay inside one MASVS group. These weaknesses are rated and documented in their own series, but they belong in a privacy assessment's scope.

- **STORAGE: data at rest.** [MASWE-0001](/mobile/maswe-0001-sensitive-data-unencrypted-private-storage/) (unencrypted in private storage) and [MASWE-0002](/mobile/maswe-0002-sensitive-data-unencrypted-outside-private-storage/) (shared storage readable by other apps); logs ([MASWE-0005](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0005/)) and backups ([MASWE-0006](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0006/)), which copy personal data off the device. See the [STORAGE hub](/mobile/masvs-storage-1-secure-storage-guide/).
- **CRYPTO: hashing is not anonymisation.** An unsalted SHA-256 of an email address is a stable, matchable identifier. [MASWE-0008](/mobile/maswe-0008-improper-hashing/) covers the hashing itself; MASWE-0067 covers why the result is still personal data.
- **AUTH: what survives logout.** [MASWE-0024](/mobile/maswe-0024-sensitive-data-accessible-after-session-termination/) is the client-side half of account deletion and sign-out: cached profiles, tokens and files that stay on the device.
- **NETWORK: personal data in clear.** [MASWE-0026](/mobile/maswe-0026-cleartext-network-traffic/) and the [NETWORK hub](/mobile/masvs-network-secure-communication-guide/). The [traffic interception lab](/mobile/mobile-traffic-interception-lab/) is the set-up for every dynamic test in this series.
- **PLATFORM: data exposed through the OS.** [Clipboard](/mobile/maswe-0030-improper-use-of-the-clipboard/), [UI](/mobile/maswe-0036-sensitive-data-exposed-via-ui/), [notifications](/mobile/maswe-0037-sensitive-data-exposed-via-notifications/), [screenshots and recordings](/mobile/maswe-0038-insufficient-screenshot-protection/), [accessibility services](/mobile/maswe-0040-sensitive-data-leaked-via-accessibility/), [app extensions and keyboards](/mobile/maswe-0031-allowing-untrusted-app-extensions/), and [permissions on exported components](/mobile/maswe-0018-missing-auth-on-app-components/). See the [PLATFORM hub](/mobile/masvs-platform-platform-interaction-guide/).
- **CODE: the SDK supply chain.** [MASWE-0048](/mobile/maswe-0048-malicious-code-included-in-the-app/) covers SDKs that harvest data beyond their stated purpose, Apple's SDK privacy manifest and signature requirements and the Google Play SDK Index; [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/) and our [third-party libraries note](/mobile/mastg-know-0004-third-party-libraries/) build the SDK inventory; [MASWE-0049](/mobile/maswe-0049-unsafe-dynamic-code-loading/) covers code that changes behaviour after review; [MASWE-0042](/mobile/maswe-0042-latest-platform-version-not-targeted/) matters because many Android privacy protections only apply when the app targets a recent API level; [MASWE-0047](/mobile/maswe-0047-non-standard-security-apis/) is the security twin of MASWE-0069. See the [CODE hub](/mobile/masvs-code-code-quality-guide/).
- **RESILIENCE: signals that must stay in their lane.** [MASWE-0055](/mobile/maswe-0055-malware-detection-not-implemented/) (malware detection: stalkerware and accessibility abuse are privacy threats to the user), and [MASWE-0054](/mobile/maswe-0054-device-attestation-not-implemented/) and [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/): Play Integrity, DeviceCheck and App Attest let an app fight fraud without building its own device fingerprint, which is exactly what MASVS-PRIVACY-2 asks for. See the [RESILIENCE hub](/mobile/masvs-resilience-resilience-testing-guide/).

## How to run a privacy assessment

Each note has the detailed procedures. This is the order we run them in on an engagement, and what each step feeds into the next. The output is a declaration-versus-behaviour matrix with evidence that the client's DPO can use.

### 1. Scope and data inventory

- Confirm the **profile** (P, and EUDIW for wallets), the **markets** (EU, UK, California and others decide which rights flows must exist) and whether the app is **likely to be used by children**.
- Get the client's **record of processing** for the app if one exists: data categories, purposes, lawful basis per purpose, recipients and processors, retention. Without it, build a draft one from the app and mark it as yours.
- List the **features** and the personal data each one needs. This list is the yardstick for every "necessary?" question later: a permission, SDK call or field is justified only if it maps to a feature.
- Agree the **test identities**: dedicated test accounts and test devices, with **canary values** (a unique email such as `gt-canary-7f3a@example.com`, a unique name and phone number, a fixed GPS fix in the emulator) that make your own data easy to find in traffic.
- Agree with the client how to handle personal data in **evidence**. You will capture your own test data only; still, store captures as client-confidential and delete them at the end of the retention period.

### 2. Collect the declarations

Capture every place where the app says what it does, with the date and version, before testing behaviour:

- **Google Play Data safety section** and **App Store App Privacy label**, from the public listings (screenshots plus text).
- **Privacy policy:** the version linked from the store, the version reachable *inside* the app, and any differences between them.
- **In-app disclosures:** onboarding, consent screens (consent management platform or custom), permission rationales, iOS purpose strings and the `NSUserTrackingUsageDescription` text.
- **iOS privacy manifests:** the app's and every SDK's `PrivacyInfo.xcprivacy`, plus Xcode's privacy report if the client provides the archive (Organizer, *Generate Privacy Report*).
- **Account and data controls** the policy promises: deletion, export, correction, opt-outs, and the web deletion link required by Google Play.

### 3. Static inventory: SDKs, permissions, identifiers

- **Permissions and entitlements:** `aapt2 dump permissions`, the merged manifest (including permissions added by SDK manifests and `tools:node="remove"` overrides), `maxSdkVersion` limits, iOS `*UsageDescription` keys, signed entitlements of the app and every `.appex`, keyboard `RequestsOpenAccess`. Run TEST-0254, 0360, 0362 and 0390 here.
- **SDKs:** package prefixes (jadx), frameworks under `Frameworks/`, native libraries, Gradle and SwiftPM/CocoaPods lockfiles if available. Categorise them neutrally: analytics, advertising, attribution, crash reporting, customer support, consent management.
- **Identifier APIs:** `Settings.Secure.ANDROID_ID`, `AdvertisingIdClient`, `Build.getSerial()`, `TelephonyManager` device IDs, Wi-Fi and Bluetooth MAC addresses; `ASIdentifierManager.advertisingIdentifier`, `UIDevice.identifierForVendor`, `ATTrackingManager`.
- **SDK data-collection APIs** called by the app's own code (user ID, user properties, custom events with personal fields). Run TEST-0318 here, and treat its hits as leads.
- **Tracking domains** in strings and configuration, compared with `NSPrivacyTrackingDomains` (TEST-0281, static half).

### 4. Dynamic traffic capture across consent states

This is the core of the assessment. Set up interception as in our [traffic interception lab](/mobile/mobile-traffic-interception-lab/) (if the app pins certificates, use a test build without pinning or the lab's documented approach for your own build). Then capture **separate, labelled sessions** for each state, starting each from a clean install:

| Session | How to get there | What to look for |
|---------|------------------|------------------|
| S1 Fresh install, before first UI | Uninstall, reinstall, start capture, launch, do not touch the screen for a minute | Anything an SDK sends at process start: identifiers, device data, config fetches that carry IDs |
| S2 Pre-consent | Reach the consent screen or first permission prompt, do not answer | Same as S1: nothing beyond what is strictly necessary should have left |
| S3 Consent denied | Reject everything (CMP "reject all", ATT "Ask App Not to Track", deny OS permissions); use the app's main flows | Tracking, advertising and analytics calls that should not happen; IDFA all zeros on iOS; requests to declared tracking domains failing |
| S4 Consent given | Accept everything; use the same flows | The baseline of declared processing; compare it with the declarations |
| S5 After withdrawal | Withdraw in the app's settings (and revoke OS permissions, reset the Advertising ID); use the same flows | Processing that continues after withdrawal; identifiers relinked after reset |

In every session, search requests (URLs, headers, bodies, including base64 and common hashes) for your canary values and identifiers, record destination hosts, and note which SDK each request comes from. Run TEST-0206, 0319, 0361, 0363 and the dynamic half of 0281 across these sessions, and trace the app's own identifier and SDK calls with Frida. On iOS, turn on **App Privacy Report** (Settings > Privacy & Security > App Privacy Report) during the sessions: it records the app's sensor and data accesses and the domains it contacted, from the OS's point of view, and you can export it. On Android 12 and later, the **Privacy dashboard** and `cmd appops get` show when the app last used location, camera, microphone and other operations.

### 5. User-rights flows

Walk each right the policy promises, with a test account that has real (test) data in it:

- **Deletion:** in-app path and Google Play's web link; what the app says will happen; what you can observe afterwards (login fails, data gone from other test accounts' view, export no longer returns data, local data cleared). Note any confirmation email and retention statement.
- **Export and access:** what the export contains compared with what you saw in traffic. Fields sent to the backend but missing from the export are worth asking about.
- **Correction, opt-outs and visibility:** that changing a setting changes behaviour, which you confirm in traffic and with a second test account (for visibility).
- **Consent records:** whether the app sends or stores a record of the consent choice and its version, and whether a changed policy or new purpose triggers a new request.

### 6. Declaration-versus-behaviour matrix

Bring it together in one table per platform. Rows are data types (use the store's own categories: location, contact info, identifiers, usage data, health, financial and so on) and the permissions or entitlements. Columns are: declared in Data safety or App Privacy, declared in the policy, declared in privacy manifests, purpose stated, observed in which sessions, to which recipients (first or third party, by SDK category), evidence references. Every cell where "observed" is not covered by "declared", or where S1 to S3 show processing that needs consent, is a candidate finding. Declared but never observed is a note for the client (over-declaring is safer than under-declaring, but should be checked).

### 7. Reporting with evidence for the DPO

For each finding give the data type, the recipient, the session and consent state, the exact request (redacted of anything but test data), the declaration it contradicts, and the store policy or guidance it touches. Rate it with the [series-wide rule](#rating-findings-the-series-wide-rule) and state plainly that legal conclusions are for the client's DPO or counsel. Include the app versions, OS versions, SDK versions where known, dates, and the consent platform's configuration, because SDK behaviour changes with remote configuration. Recommendations should name the control (gate the SDK's initialisation on consent, remove the permission, use the picker, declare the domain, fix the label) rather than restating the regulation.

## Command cheat sheet

The most-used commands from the series. Package and paths are placeholders: `com.example.app`, `app.apk`, `Payload/App.app`. Each note has the full procedure and how to read the output. Run them only against the app under assessment on your own devices.

### Android: permissions and app ops

```bash
# Declared permissions, straight from the APK (MASWE-0066, TEST-0254)
aapt2 dump permissions app.apk
apkanalyzer manifest permissions app.apk
# Merged manifest as XML, to see SDK-added permissions, maxSdkVersion and AD_ID
aapt2 dump xmltree --file AndroidManifest.xml app.apk | grep -E 'uses-permission|maxSdkVersion'
# All dangerous permissions the device knows about, grouped
adb shell pm list permissions -g -d
# Requested, install-time and runtime permissions with grant state and flags
adb shell dumpsys package com.example.app | sed -n '/requested permissions:/,/User 0:/p'
adb shell dumpsys package com.example.app | grep -A40 'runtime permissions:'
# App ops: which sensitive operations ran and when (location, camera, clipboard ...)
adb shell cmd appops get com.example.app
adb shell cmd appops get com.example.app COARSE_LOCATION
# Put the app into a known permission state for a consent-state session
adb shell pm revoke com.example.app android.permission.ACCESS_FINE_LOCATION
adb shell pm grant com.example.app android.permission.ACCESS_COARSE_LOCATION
# Clean slate before session S1
adb shell pm clear com.example.app
```

### iOS: purpose strings, manifests and entitlements

```bash
# Purpose strings and ATT prompt text (TEST-0360)
plutil -convert xml1 -o - Payload/App.app/Info.plist | grep -A1 -E 'UsageDescription'
# Every privacy manifest in the bundle, app and SDKs (TEST-0281, MASWE-0073)
find Payload/App.app -name PrivacyInfo.xcprivacy
plutil -p Payload/App.app/PrivacyInfo.xcprivacy
plutil -extract NSPrivacyTrackingDomains xml1 -o - Payload/App.app/PrivacyInfo.xcprivacy
# Signed entitlements of the app and each extension (TEST-0362)
codesign -d --entitlements :- Payload/App.app
for x in Payload/App.app/PlugIns/*.appex; do echo "== $x"; codesign -d --entitlements :- "$x"; done
# Custom keyboard Full Access (TEST-0390)
plutil -p Payload/App.app/PlugIns/*.appex/Info.plist | grep -E 'NSExtensionPointIdentifier|RequestsOpenAccess'
# Identifier and tracking APIs referenced by the main binary
nm -u Payload/App.app/App | grep -E 'ASIdentifierManager|ATTrackingManager|identifierForVendor'
rabin2 -zz Payload/App.app/App | grep -iE 'advertisingIdentifier|requestTrackingAuthorization'
```

### Traffic capture

```bash
# Proxy with a web UI; one file per consent-state session
mitmweb --listen-port 8080 -w s3-consent-denied.mitm
# Or capture without a device proxy setting, through mitmproxy's WireGuard mode
mitmweb --mode wireguard -w s1-fresh-install.mitm
# Hosts contacted in a session, with counts
mitmdump -nr s1-fresh-install.mitm | grep -oE 'https?://[^/ ]+' | sort | uniq -c | sort -rn
# Search a saved session for your own canary values (addon below)
mitmdump -nr s3-consent-denied.mitm -s find_canaries.py
```

A small mitmproxy addon that flags requests carrying your test identity, in clear, base64 or as common hashes. It only searches your own captured sessions for values you planted:

```python
# find_canaries.py: run with mitmdump -nr <session>.mitm -s find_canaries.py
import base64, hashlib
from mitmproxy import http

CANARIES = ["gt-canary-7f3a@example.com", "+447700900123", "Canary Tester"]

def variants(v):
    out = {v, v.lower()}
    for s in list(out):
        b = s.encode()
        out |= {hashlib.md5(b).hexdigest(), hashlib.sha1(b).hexdigest(),
                hashlib.sha256(b).hexdigest(), base64.b64encode(b).decode()}
    return out

NEEDLES = {n: c for c in CANARIES for n in variants(c)}

def request(flow: http.HTTPFlow) -> None:
    hay = flow.request.pretty_url + str(flow.request.headers) + flow.request.get_text(strict=False)
    for needle, canary in NEEDLES.items():
        if needle in hay:
            print(f"[canary] {canary!r} as {needle[:16]}... -> {flow.request.method} {flow.request.pretty_host}")
```

### Runtime tracing of the app's own calls

```bash
# Android: identifier reads, location, installed-app queries, an analytics SDK entry point
frida-trace -U -f com.example.app \
  -j 'android.provider.Settings$Secure!getString' \
  -j 'com.google.android.gms.ads.identifier.AdvertisingIdClient!getAdvertisingIdInfo' \
  -j 'android.location.LocationManager!getLastKnownLocation' \
  -j 'android.app.ApplicationPackageManager!getInstalledPackages' \
  -j 'com.google.firebase.analytics.FirebaseAnalytics!setUserId'
# iOS: ATT, IDFA, IDFV, location and contacts authorisation
frida-trace -U -f com.example.app \
  -m '+[ATTrackingManager requestTrackingAuthorizationWithCompletionHandler:]' \
  -m '-[ASIdentifierManager advertisingIdentifier]' \
  -m '-[UIDevice identifierForVendor]' \
  -m '-[CLLocationManager requestWhenInUseAuthorization]' \
  -m '-[CNContactStore requestAccessForEntityType:completionHandler:]'
```

Note the moment of each call relative to the consent screen: an identifier read in session S1 or S2, before the user has chosen, is the evidence a consent finding rests on. On device, check the result against **Settings > Privacy & Security > Tracking** and **App Privacy Report** on iOS, and the **Privacy dashboard** and **Settings > Privacy > Ads** on Android (menu names vary by vendor and version).

## The full series

With this hub, the site covers every MASVS v2 control group. Each hub links its weakness notes, test index and assessment workflow.

- [MASVS-STORAGE: secure storage](/mobile/masvs-storage-1-secure-storage-guide/)
- [MASVS-CRYPTO: cryptography and key management](/mobile/masvs-crypto-cryptography-guide/)
- [MASVS-AUTH: authentication and authorisation](/mobile/masvs-auth-authentication-guide/)
- [MASVS-NETWORK: secure communication](/mobile/masvs-network-secure-communication-guide/)
- [MASVS-PLATFORM: IPC, WebViews and the UI](/mobile/masvs-platform-platform-interaction-guide/)
- [MASVS-CODE: code quality and the supply chain](/mobile/masvs-code-code-quality-guide/)
- [MASVS-RESILIENCE: reverse engineering and tampering](/mobile/masvs-resilience-resilience-testing-guide/)
- MASVS-PRIVACY: privacy (this page)

## References

- OWASP MASVS: [MASVS-PRIVACY-1](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-1/), [MASVS-PRIVACY-2](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-2/), [MASVS-PRIVACY-3](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-3/), [MASVS-PRIVACY-4](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-4/), [MASVS-PRIVACY chapter](https://mas.owasp.org/MASVS/12-MASVS-PRIVACY/), [MAS Profiles](https://mas.owasp.org/Profiles/) (CC BY-SA 4.0)
- OWASP MASWE: [MASWE-0066](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0066/), [0067](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0067/), [0068](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0068/), [0069](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0069/), [0070](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0070/), [0071](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0071/), [0072](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0072/), [0073](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0073/), [0074](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0074/), [0075](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0075/), [0076](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0076/), [0077](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0077/), [0078](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0078/), [MASWE-0005](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0005/), [MASWE-0006](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0006/) (CC BY-SA 4.0)
- OWASP MASTG Knowledge: [MASTG-KNOW-0017](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0017/), [MASTG-KNOW-0026](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PRIVACY/MASTG-KNOW-0026/), [MASTG-KNOW-0077](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0077/), [MASTG-KNOW-0082](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0082/), [MASTG-KNOW-0141](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0141/) (CC BY-SA 4.0)
- OWASP MASTG Best Practices: [MASTG-BEST-0003](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0003/), [MASTG-BEST-0051](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0051/), [MASTG-BEST-0069](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0069/) (CC BY-SA 4.0)
- OWASP MASTG Tests: the 13 tests linked in the [test index](#test-index) (CC BY-SA 4.0)
- OWASP MASTG Demos: [MASTG-DEMO-0009](https://mas.owasp.org/MASTG/demos/android/MASVS-PRIVACY/MASTG-DEMO-0009/MASTG-DEMO-0009/), [MASTG-DEMO-0033](https://mas.owasp.org/MASTG/demos/android/MASVS-PRIVACY/MASTG-DEMO-0033/MASTG-DEMO-0033/), [MASTG-DEMO-0081](https://mas.owasp.org/MASTG/demos/android/MASVS-PRIVACY/MASTG-DEMO-0081/MASTG-DEMO-0081/), [MASTG-DEMO-0126](https://mas.owasp.org/MASTG/demos/ios/MASVS-PRIVACY/MASTG-DEMO-0126/MASTG-DEMO-0126/), [MASTG-DEMO-0127](https://mas.owasp.org/MASTG/demos/ios/MASVS-PRIVACY/MASTG-DEMO-0127/MASTG-DEMO-0127/) (CC BY-SA 4.0)
- EU law and guidance: [GDPR (Regulation (EU) 2016/679)](https://eur-lex.europa.eu/eli/reg/2016/679/oj), [ePrivacy Directive 2002/58/EC](https://eur-lex.europa.eu/eli/dir/2002/58/oj), EDPB [Guidelines 05/2020 on consent](https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-052020-consent-under-regulation-2016679_en), [Guidelines 4/2019 on Article 25](https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-42019-article-25-data-protection-design-and_en), [Guidelines 2/2023 on the technical scope of Art. 5(3) ePrivacy Directive](https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-22023-technical-scope-art-53-eprivacy-directive_en), [Guidelines 01/2025 on pseudonymisation](https://www.edpb.europa.eu/our-work-tools/documents/public-consultations/2025/guidelines-012025-pseudonymisation_en)
- UK law and guidance: [UK GDPR](https://www.legislation.gov.uk/eur/2016/679/contents), [PECR regulation 6](https://www.legislation.gov.uk/uksi/2003/2426/regulation/6), [Data (Use and Access) Act 2025](https://www.legislation.gov.uk/ukpga/2025/18/contents), ICO [UK GDPR guidance and resources](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/), [Guidance on the use of storage and access technologies](https://ico.org.uk/for-organisations/direct-marketing-and-privacy-and-electronic-communications/guidance-on-the-use-of-storage-and-access-technologies/), [Children's code](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/childrens-information/childrens-code-guidance-and-resources/)
- California: [CCPA (Attorney General)](https://oag.ca.gov/privacy/ccpa), [California Privacy Protection Agency](https://cppa.ca.gov/)
- Google Play: [User Data](https://support.google.com/googleplay/android-developer/answer/10144311), [Data safety section](https://support.google.com/googleplay/android-developer/answer/10787469), [Permissions and APIs that access sensitive information](https://support.google.com/googleplay/android-developer/answer/9888170), [SMS and Call Log permissions](https://support.google.com/googleplay/android-developer/answer/10208820), [QUERY_ALL_PACKAGES](https://support.google.com/googleplay/android-developer/answer/10158779), [Restricted permissions with minimum-scope alternatives](https://support.google.com/googleplay/android-developer/answer/14115180), [Advertising ID](https://support.google.com/googleplay/android-developer/answer/6048248), [Account deletion requirements](https://support.google.com/googleplay/android-developer/answer/13327111)
- Android Developers: [Request runtime permissions](https://developer.android.com/training/permissions/requesting), [Minimise your permission requests](https://developer.android.com/privacy-and-security/minimize-permission-requests), [Best practices for unique identifiers](https://developer.android.com/identity/user-data-ids), [Audit data access](https://developer.android.com/guide/topics/data/audit-access), [aapt2](https://developer.android.com/tools/aapt2)
- Apple: [App Store Review Guidelines](https://developer.apple.com/app-store/review/guidelines/), [App privacy details](https://developer.apple.com/app-store/app-privacy-details/), [User privacy and data use](https://developer.apple.com/app-store/user-privacy-and-data-use/), [App Tracking Transparency](https://developer.apple.com/documentation/apptrackingtransparency), [Privacy manifest files](https://developer.apple.com/documentation/bundleresources/privacy-manifest-files), [Describing use of required reason API](https://developer.apple.com/documentation/bundleresources/describing-use-of-required-reason-api), [Offering account deletion in your app](https://developer.apple.com/support/offering-account-deletion-in-your-app/), [About App Privacy Report](https://support.apple.com/en-us/102188)
- Tools: [mitmproxy documentation](https://docs.mitmproxy.org/stable/), [Frida documentation](https://frida.re/docs/home/), [Reproducible Builds](https://reproducible-builds.org/)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
