---
title: "MASWE-0073: Inadequate Data Collection Declarations"
date: 2026-11-10 22:07:00 +0000
subcategory: privacy
summary: "Testing Data safety, App Privacy labels and privacy manifests against what the app and its SDKs really collect, share and send over the network."
refs: [MASWE-0073, MASVS-PRIVACY-3, MASVS-PRIVACY-1, CWE-359]
tags: [android, ios, masvs-privacy, data-safety, privacy-manifests, third-party-sdks]
---

This note is part of our [MASVS-PRIVACY guide](/mobile/masvs-privacy-privacy-testing-guide/) and covers OWASP [MASWE-0073](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0073/): an app whose published statements about data collection do not match what it actually does. The statements are the Google Play **Data safety** section, Apple's **App Privacy details** (the "privacy nutrition label"), the **privacy manifests** (`PrivacyInfo.xcprivacy`) bundled in the app and its SDKs, and the **privacy policy**. The behaviour is everything the app and every SDK inside it transmits off the device. In real assessments the gap is rarely in the first-party code. It comes from SDKs that collect more than the team knew, from the store's definitions of "collected" and "shared" being misread, and from labels that stayed the same while the app changed. Testing it means building a matrix with the declarations on one side and observed behaviour on the other: a static SDK inventory, traces of the SDK calls that receive personal data, and a capture of the app's own traffic. Below are the platform mechanisms, the three OWASP Android tests, three of ours (the iOS counterparts and a cross-declaration consistency check), and how to rate what you find.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: Third-party services embedded in the app (MASTG-KNOW-0026)](#android-third-party-services-embedded-in-the-app-mastg-know-0026)
  - [Android: Google Play Data safety section (background)](#android-google-play-data-safety-section-background)
  - [iOS: App Privacy details on the App Store (background)](#ios-app-privacy-details-on-the-app-store-background)
  - [iOS: Privacy manifests and the Xcode privacy report (background)](#ios-privacy-manifests-and-the-xcode-privacy-report-background)
  - [Android and iOS: Who answers for SDK data collection (background)](#android-and-ios-who-answers-for-sdk-data-collection-background)
  - [Android and iOS: The declaration-vs-behaviour matrix (background)](#android-and-ios-the-declaration-vs-behaviour-matrix-background)
- [Tests](#tests)
  - [MASTG-TEST-0206: Undeclared PII in Network Traffic Capture (Android)](#mastg-test-0206-undeclared-pii-in-network-traffic-capture-android)
  - [MASTG-TEST-0318: References to SDK APIs Known to Handle Sensitive User Data (Android)](#mastg-test-0318-references-to-sdk-apis-known-to-handle-sensitive-user-data-android)
  - [MASTG-TEST-0319: Runtime Use of SDK APIs Known to Handle Sensitive User Data (Android)](#mastg-test-0319-runtime-use-of-sdk-apis-known-to-handle-sensitive-user-data-android)
  - [GT-PRIV-0073-1: Undeclared PII in network traffic vs App Privacy details and privacy manifests (iOS)](#gt-priv-0073-1-undeclared-pii-in-network-traffic-vs-app-privacy-details-and-privacy-manifests-ios)
  - [GT-PRIV-0073-2: References to and runtime use of SDK APIs handling sensitive data (iOS)](#gt-priv-0073-2-references-to-and-runtime-use-of-sdk-apis-handling-sensitive-data-ios)
  - [GT-PRIV-0073-3: Declaration consistency across store label, privacy manifests, privacy policy and observed behaviour (Android and iOS)](#gt-priv-0073-3-declaration-consistency-across-store-label-privacy-manifests-privacy-policy-and-observed-behaviour-android-and-ios)
- [Best practices](#best-practices)
  - [MASTG-BEST-0003: Comply with Privacy Regulations and Best Practices](#mastg-best-0003-comply-with-privacy-regulations-and-best-practices)
  - [Guler Tech: keeping declarations true release after release](#guler-tech-keeping-declarations-true-release-after-release)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

The OWASP requirement is *"The app adequately declares all user collected data."* MASWE-0073 maps to **MASVS-PRIVACY-3** ("The app is transparent about data collection and usage") and **MASVS-PRIVACY-1** ("The app minimizes access to sensitive data and resources"), to [CWE-359](https://cwe.mitre.org/data/definitions/359.html) (Exposure of Private Personal Information to an Unauthorized Actor), and in MASVS v1 terms to MSTG-STORAGE-12 and MSTG-NETWORK-1. It merges the beta weaknesses MASWE-0112 and MASWE-0108. It carries OWASP's **P** profile (plus EUDIW): it applies to any app that processes personal data, which is nearly every app with an account, an analytics SDK or an ad SDK.

The PRIVACY-1 mapping matters. The control text says apps should share data with third parties only when necessary, make SDKs respect consent, and know the "supply chain" of SDKs they ship. A declaration test therefore always turns into a data-minimisation question too: once you know what an SDK sends, you can ask whether it needs to.

> **Note:** This note is technical testing guidance, not legal advice. Whether a given flow is lawful under GDPR, UK GDPR, PECR, CCPA or any other law is for the client's DPO and legal team to decide. What a tester can do is produce precise evidence of what is declared, what is collected, by whom, where it goes and when.

The declarations in scope:

| Declaration | Where it lives | Who writes it | Changes with an app update? |
|---|---|---|---|
| Google Play **Data safety** section | Play Console > *Policy* > *App content* > *Data safety*; shown on the store listing and, on Android 14+, partly in permission prompts | Developer, by form | No, edited independently |
| Apple **App Privacy** details | App Store Connect > *App Privacy*; shown on the product page as *Data Used to Track You*, *Data Linked to You*, *Data Not Linked to You* | Developer, by questionnaire | No, Apple lets you change answers without submitting a build |
| **Privacy manifests** (`PrivacyInfo.xcprivacy`) | Inside the app bundle and inside each framework or resource bundle | App developer and each SDK vendor | Yes, they ship in the binary |
| **Privacy policy** | Linked from both stores and from inside the app | Developer (legal) | Independent of both |

Apple's **App Privacy Report** (*Settings > Privacy & Security > App Privacy Report*) is not a declaration. It is the user's on-device log of what apps actually accessed and contacted. MASWE-0073's overview lists it alongside the labels as a "stated data collection practice", which is a mix-up; for a tester it is evidence on the behaviour side, and we use it in [GT-PRIV-0073-1](#gt-priv-0073-1-undeclared-pii-in-network-traffic-vs-app-privacy-details-and-privacy-manifests-ios).

What is covered, and by which test:

| Question | Platform | Test |
|---|---|---|
| Does personal data I entered leave the device to destinations or for data types the declarations do not cover? | Android | [MASTG-TEST-0206](#mastg-test-0206-undeclared-pii-in-network-traffic-capture-android) |
| Does the code hand data to SDK APIs that collect it? | Android | [MASTG-TEST-0318](#mastg-test-0318-references-to-sdk-apis-known-to-handle-sensitive-user-data-android) (static), [MASTG-TEST-0319](#mastg-test-0319-runtime-use-of-sdk-apis-known-to-handle-sensitive-user-data-android) (runtime) |
| Same network question, against App Privacy details and privacy manifests | iOS | [GT-PRIV-0073-1](#gt-priv-0073-1-undeclared-pii-in-network-traffic-vs-app-privacy-details-and-privacy-manifests-ios) (ours) |
| Same SDK API question | iOS | [GT-PRIV-0073-2](#gt-priv-0073-2-references-to-and-runtime-use-of-sdk-apis-handling-sensitive-data-ios) (ours) |
| Do the store label, the manifests, the policy and the observations agree with each other? | Both | [GT-PRIV-0073-3](#gt-priv-0073-3-declaration-consistency-across-store-label-privacy-manifests-privacy-policy-and-observed-behaviour-android-and-ios) (ours) |

There are no legacy v1 PRIVACY tests, but two deprecated STORAGE tests now point here: **MASTG-TEST-0004** (Android, "Determining Whether Sensitive Data Is Shared with Third Parties via Embedded Services", `covered_by` 0318 and 0319) and **MASTG-TEST-0054** (iOS, "Determining Whether Sensitive Data Is Shared with Third Parties", `covered_by` 0206 and 0281). The iOS one is redirected to an Android-only test (0206) and to the tracking-domains test 0281, so OWASP currently has no iOS test for the network half of this weakness; GT-PRIV-0073-1 fills that gap.

Keep the neighbours apart:

| Question | Where it lives |
|---|---|
| Are the declared *tracking domains* complete, and does ATT block them? | [MASWE-0074](/mobile/maswe-0074-inadequate-tracking-domains-declarations/) |
| Is the privacy policy itself complete, findable and readable? | [MASWE-0072](/mobile/maswe-0072-inadequate-privacy-policy/) |
| Does collection wait for valid consent, and can it be withdrawn? | [MASWE-0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/) |
| Does the app request more permissions than it needs? | [MASWE-0066](/mobile/maswe-0066-inadequate-permission-management/) |
| Which identifiers does it use to track users? | [MASWE-0068](/mobile/maswe-0068-incorrect-use-of-identifiers-for-tracking/) |
| Is an SDK harvesting data maliciously, or has it been tampered with? | [MASWE-0048](/mobile/maswe-0048-malicious-code-included-in-the-app/) |
| Which SDKs and versions ship, and are any vulnerable? | [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/) |

## Modes of Introduction

**Only first-party code was declared.** The team filled in the forms from their own backend's data model. The analytics, crash-reporting, attribution, advertising, push and customer-support SDKs each send their own data (device identifiers, app interactions, diagnostics, coarse location derived from the network, advertising IDs) and none of it made it into the label.

**SDK defaults.** Many SDKs collect automatically as soon as they initialise: screen views, sessions, app version, device model, an installation or advertising identifier, crash traces with breadcrumbs. On Android, initialisation often happens through a manifest-merged `ContentProvider` before `Application.onCreate()` runs, so before any consent screen. The developer did not write a single line that "collects" anything.

**Misread exemptions.** Google Play exempts transfers to *service providers* from "sharing", and Apple and Google both exempt certain ephemeral or on-device processing. Teams stretch these: an ad SDK that builds profiles across many apps is not a service provider in Google's sense; a request that is also logged server-side is not ephemeral; a hashed email is pseudonymous, not anonymous; "encrypted" is not end-to-end if the server holds the keys.

**Purpose drift.** Data declared for *App functionality* is also sent to an analytics or marketing pipeline: an account ID passed to `setUserId`, a health value logged as an event parameter, an email hashed for ad audience matching.

**Stale declarations.** An SDK update adds a new data type, a feature adds a location-based search, a remote-config flag turns on session replay. The binary changes, the store labels do not. Apple and Google let labels be edited without a release, which also means nothing forces them to be edited with one.

**Inconsistent sources.** The Android and iOS labels for the same product, with the same backend and SDKs, say different things; the privacy policy lists recipients neither label mentions; an SDK's privacy manifest declares collection that the App Store answers leave out; the "linked to you" or "used to track you" flags contradict the manifests.

**Regional and flavour variants.** A build for one region drops an SDK and the label is written for that build. Google is explicit that the Data safety section must cover the sum of practices across all versions, regions and user types.

**WebViews the app controls.** Google counts data sent from a WebView whose content the app controls as the app's collection; a hybrid onboarding or checkout flow with its own tags is easy to forget.

## Impact

- **Users decide on false information.** The labels exist so people can choose before installing and before granting a permission. On Android 14 and later the location permission prompt even shows whether the app declared sharing location with third parties. A wrong declaration removes that choice.
- **Undisclosed sharing and profiling.** Personal data reaches third parties the user was never told about, is linked to an identity the label says it is not linked to, or feeds cross-app advertising profiles while the label says "not used to track you".
- **Store enforcement.** Google warns that non-compliant Data safety declarations can lead to blocked updates or removal; Apple's guidelines (2.3 on accurate metadata including privacy information, 5.1.2 on data use and sharing) allow rejection and removal. Both say the developer answers for SDK code.
- **Regulatory exposure.** Under GDPR and UK GDPR, the information given to users (Articles 12 to 14) has to reflect real processing and recipients; a store label that contradicts the privacy policy and the traffic is the kind of evidence regulators and litigants use. Consumer-protection law treats misleading privacy claims as deceptive practices in several jurisdictions. Your report supplies the evidence; the legal assessment is the client's.
- **Loss of trust.** Mismatches are easy for researchers and journalists to find with exactly the techniques in this note.

## Mitigations

- **Keep a data inventory per SDK.** For every SDK: which data types it receives from the app, which it collects itself, where it sends them, for what purpose, whether linked to an identity, whether used for tracking, and what configuration controls that. Fill the store forms from this inventory, not from memory.
- **Read the vendor's declarations.** SDK documentation, the [Google Play SDK Index](https://play.google.com/sdks) entry and its linked data-safety guidance, and the SDK's own `PrivacyInfo.xcprivacy`. Treat them as a starting point; verify with traffic.
- **Configure SDKs for minimum collection.** Turn off automatic collection that you do not use (advertising-ID collection, automatic screen reporting, IP-based location, session replay), and initialise data-collecting SDKs only after the consent they depend on ([MASWE-0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/)).
- **Review declarations on every release.** Diff the SDK inventory and the Xcode privacy report against the previous release, and re-run a canary traffic test. Update the labels *before* the release that changes behaviour goes live.
- **Keep one story.** The Play label, the App Store label, the manifests and the privacy policy should be generated from, or at least checked against, the same inventory.

## Knowledge

OWASP assigns one Knowledge item to this weakness, [MASTG-KNOW-0026](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PRIVACY/MASTG-KNOW-0026/), and it is four sentences long. Everything a tester actually needs (what the store forms ask, what counts as collection, how privacy manifests work) is missing from the OWASP material, so the sections after it are ours.

### Android: Third-party services embedded in the app (MASTG-KNOW-0026)

Source: [MASTG-KNOW-0026](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PRIVACY/MASTG-KNOW-0026/). The item lives in OWASP's Android PRIVACY folder, but its front matter still says `masvs_category: MASVS-STORAGE`, a leftover from the v1 test MASTG-TEST-0004 whose text it reuses. Nothing in it is Android-specific; it applies equally to iOS.

OWASP's point is simple and correct: third-party services provide tracking, advertising or user-experience features, developers rarely know in detail what the code does, and therefore the app should send a service no more than it needs and nothing sensitive. It distinguishes a *standalone library* from a *full SDK*. In practice that distinction is about who triggers collection:

| Integration | Who sends data | What to look for |
|---|---|---|
| **Library the app calls** (an HTTP client wrapper, an image loader) | Only what the app passes to it | The app's own calls; usually no autonomous collection |
| **SDK with an API the app feeds** (analytics events, user properties, crash breadcrumbs, support chat) | The app, through the SDK's entry points, *plus* whatever the SDK adds | Calls such as `logEvent`, `setUserId`, `setUserProperty`, custom keys on crash reports (MASTG-TEST-0318/0319) |
| **Self-starting SDK** (attribution, ads, many analytics and crash SDKs) | The SDK itself, from the moment it initialises | Merged-manifest providers and `androidx.startup` initialisers, SDK configuration `meta-data`, the `AD_ID` permission, traffic before any user interaction |

Typical SDK categories and the Data safety types they usually touch (verify per SDK; this is a checklist, not a statement about any vendor):

| SDK category | Data types it commonly involves |
|---|---|
| Analytics | App interactions, Device or other IDs, Diagnostics, sometimes Approximate location (from IP), User IDs if the app sets one |
| Crash reporting | Crash logs, Diagnostics, Device or other IDs, plus whatever the app adds as custom keys or logs |
| Advertising | Device or other IDs (advertising ID), App interactions, Approximate location, sometimes Installed apps |
| Attribution / deep linking | Device or other IDs, App interactions (installs, campaign events), sometimes Purchase history |
| Push messaging | Device or other IDs (push token, installation ID), App interactions if it reports opens |
| Customer support / chat | Name, Email address, Other in-app messages, Photos (attachments), Diagnostics |
| Session replay | App interactions, Other user-generated content, potentially anything on screen |
| Payments | User payment info, Purchase history (unless the payment service collects directly and the app never sees it; Google's FAQ covers this case) |

**Static signals on Android.** Three places in the merged manifest tell you what will start before your consent screen and what is configured:

```bash
# Providers and startup initialisers merged in from SDKs
aapt2 dump xmltree app.apk --file AndroidManifest.xml | grep -A3 -E "E: provider|androidx.startup"
# SDK configuration flags (auto-collection switches, ad-ID collection, consent defaults)
aapt2 dump xmltree app.apk --file AndroidManifest.xml | grep -A2 "E: meta-data" | grep -E 'A: android:(name|value)'
# Advertising ID permission (required from targetSdk 33 to read the ad ID)
aapt2 dump permissions app.apk | grep -i "AD_ID"
```

An app that targets API 33 or higher must declare `com.google.android.gms.permission.AD_ID` to read the advertising ID; SDK manifests often merge it in. Its presence means "Device or other IDs" probably needs declaring, and an app that does not use the ad ID can remove it with `tools:node="remove"`. Configuration `meta-data` names are vendor-specific (for example, Google Analytics for Firebase documents switches such as `firebase_analytics_collection_enabled` and `google_analytics_adid_collection_enabled`); look them up in each vendor's documentation rather than guessing what a flag does.

For building the SDK list itself, see [MASTG-KNOW-0004 on third-party libraries](/mobile/mastg-know-0004-third-party-libraries/) and [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/); the same inventory feeds this test.

### Android: Google Play Data safety section (background)

Not an OWASP Knowledge item; ours. Source: Google's [Provide information for Google Play's Data safety section](https://support.google.com/googleplay/android-developer/answer/10787469) and the Android 14 [app metadata](https://developer.android.com/about/versions/14/features/app-metadata) documentation, which uses the same definitions.

#### Collected and shared

- **Collected** means transmitted off the device. That includes data sent by libraries and SDKs, whether it goes to the developer's servers or a third party's, and data from a WebView opened by the app *if the app controls that WebView's content*. Data typed into a WebView in which the user is browsing the open web does not count.
- **Shared** means transferred to a **third party**: server-to-server, on-device to another app, directly from an SDK in the app, or from an app-controlled WebView. A third party is any organisation other than the developer (the first party) and its service providers.

Not in scope for **collection**:

- data processed **only on the device**;
- data protected by **end-to-end encryption** that no intermediary, including the developer, can read;
- **ephemeral processing**: data held only in memory and kept no longer than needed to serve the specific request in real time (Google's example is a weather lookup by location). Building advertising or user profiles is never ephemeral, and anything logged afterwards must be declared for that use.

Not counted as **sharing**:

- transfers to a **service provider** that processes the data on the developer's behalf and on its instructions (an analytics service working only for you, a cloud host). Google's FAQ is explicit that an SDK provider building advertising profiles across customers is *not* acting as a service provider;
- transfers for **legal purposes** (legal obligation, government requests);
- transfers from a **specific user-initiated action** where the user reasonably expects the sharing, or based on **prominent in-app disclosure and consent**;
- transfers of **fully anonymised** data.

Pseudonymous data must still be declared. Google's FAQ gives two examples that come up constantly in tests: diagnostics sent with a device identifier are still "Diagnostics", and if the IP address is used to derive location, location must be declared.

#### Data types and purposes

The form has 14 categories:

| Category | Data types |
|---|---|
| Location | Approximate location (an area of 3 km² or more, or what `ACCESS_COARSE_LOCATION` gives); Precise location (less than 3 km², or `ACCESS_FINE_LOCATION`) |
| Personal info | Name; Email address; User IDs; Address; Phone number; Race and ethnicity; Political or religious beliefs; Sexual orientation; Other info |
| Financial info | User payment info; Purchase history; Credit score; Other financial info |
| Health and fitness | Health info; Fitness info |
| Messages | Emails; SMS or MMS; Other in-app messages |
| Photos and videos | Photos; Videos |
| Audio files | Voice or sound recordings; Music files; Other audio files |
| Files and docs | Files and docs |
| Calendar | Calendar events |
| Contacts | Contacts |
| App activity | App interactions; In-app search history; Installed apps; Other user-generated content; Other actions |
| Web browsing | Web browsing history |
| App info and performance | Crash logs; Diagnostics; Other app performance data |
| Device or other IDs | Device or other IDs (Google's examples: IMEI, MAC address, Widevine Device ID, Firebase installation ID, advertising identifier) |

For each collected or shared type the developer selects purposes: *App functionality*, *Analytics*, *Developer communications*, *Advertising or marketing*, *Fraud prevention, security, and compliance*, *Personalization*, *Account management*. They also say whether collection is **required** or **optional**. Optional is allowed only if every user, in every region and on every device, can opt in, opt out or choose not to provide the data. If any version of the app requires it, it is required.

#### Security practices and deletion

The same form asks whether all collected data is **encrypted in transit**, whether users can **request deletion** of their data (an automatic deletion or anonymisation within 90 days also qualifies), and, for apps that let users create accounts, for a **web link where users can request account deletion** (Google's [account deletion requirements](https://support.google.com/googleplay/android-developer/answer/13327111); the Data deletion questions were due by 7 December 2023, with extensions to 31 May 2024). Optionally, a developer can show that the app passed an **independent security review** (MASA, against OWASP MASVS); Google notes that such a review may not verify the accuracy of the declarations. Each of these claims is testable: cleartext traffic contradicts the first ([MASWE-0026](/mobile/maswe-0026-cleartext-network-traffic/)), and a missing or broken deletion path contradicts the others ([MASWE-0076](/mobile/maswe-0076-lack-of-data-management-controls/)).

#### Verification and enforcement

Google states that its review "is not designed to verify the accuracy and completeness" of the declarations. Nobody checks them before users see them, which is exactly why this test exists. Every app on Play must complete the form, including apps that collect nothing (they still provide a privacy policy link); apps only on internal testing tracks are exempt. Google can require corrections and warns of blocked updates or removal for non-compliance.

#### What the user sees on the device

On the store listing, the Data safety card summarises *Data shared with third parties*, *Data collected* and the security practices. On **Android 14 and later**, Android reads the app's declared data-safety information (the app metadata bundle that Play delivers) and shows it in the **location permission prompt** when the app declares sharing location with third parties; recent Android versions also list apps whose declared location sharing changed under the location settings (*Data sharing updates for location*). So a wrong Data safety answer for location is displayed by the OS itself at the moment the user decides.

### iOS: App Privacy details on the App Store (background)

Not an OWASP Knowledge item; ours. Source: Apple's [App privacy details on the App Store](https://developer.apple.com/app-store/app-privacy-details/).

#### What counts as collection

Apple defines **collect** as transmitting data off the device in a way that allows the developer and/or its third-party partners to access it for longer than needed to service the request in real time. *Third-party partners* means analytics tools, ad networks, third-party SDKs and other vendors whose code is in the app; their collection is the app's to declare. Data that Apple collects through its own frameworks and services is not the developer's to disclose, but data the app collects *using* Apple frameworks is.

#### Data types and purposes

| Category | Data types |
|---|---|
| Contact Info | Name; Email Address; Phone Number; Physical Address; Other User Contact Info |
| Health & Fitness | Health; Fitness |
| Financial Info | Payment Info; Credit Info; Other Financial Info |
| Location | Precise Location; Coarse Location |
| Sensitive Info | Sensitive Info (special-category data such as racial or ethnic data, sexual orientation, pregnancy, disability, religious or political beliefs, union membership, genetic or biometric data) |
| Contacts | Contacts |
| User Content | Emails or Text Messages; Photos or Videos; Audio Data; Gameplay Content; Customer Support; Other User Content |
| Browsing History | Browsing History |
| Search History | Search History |
| Identifiers | User ID; Device ID |
| Purchases | Purchase History |
| Usage Data | Product Interaction; Advertising Data; Other Usage Data |
| Diagnostics | Crash Data; Performance Data; Other Diagnostic Data |
| Surroundings | Environment Scanning |
| Body | Hands; Head |
| Other Data | Other Data Types |

(*Surroundings* and *Body* arrived with visionOS.) Purposes: *Third-Party Advertising*, *Developer's Advertising or Marketing*, *Analytics*, *Product Personalization*, *App Functionality* (which includes authentication, fraud prevention, security, uptime, crash minimisation and customer support), *Other Purposes*.

#### Linked, tracking, optional

- **Linked to the user**: data linked to the user's identity via their account, device or other details, by the developer *or its partners*. Apple says data is often linked unless it was de-identified *before* collection, and that "Personal Information" or "Personal Data" under privacy law is considered linked. Not-linked data must not later be re-linked or combined with datasets that allow it.
- **Tracking**: linking data collected from the app about a user or device with **Third-Party Data** for targeted advertising or advertising measurement, or sharing it with a **data broker**. Apple's own example: placing an SDK that combines your users' data with other developers' apps' data for ad targeting or measurement counts as tracking *even if you do not use the SDK for that purpose*. Exemptions: linking only on the device, data brokers used solely for fraud prevention or security, and consumer reporting agencies for credit purposes. Tracking requires App Tracking Transparency permission (Guideline 5.1.2(i)); the declared tracking domains side is [MASWE-0074](/mobile/maswe-0074-inadequate-tracking-domains-declarations/).
- **Optional disclosure**: a data type can be left off the label only if it meets **all** of: not used for tracking; not used for Third-Party Advertising, the developer's advertising or marketing, or Other Purposes; collected only infrequently, outside the app's primary functionality, and optional for the user; and provided by the user in the app's interface, clearly, with the user's name or account name prominently displayed in the submission form, and affirmatively chosen each time. There are separate, equally strict criteria for opt-in product improvement programmes, regulated financial services and IRB-approved health research. "We only collect it occasionally" is not enough on its own.

#### Rules around the label

Guideline 2.3 asks that all metadata, *including privacy information*, accurately reflect the app and be kept up to date. Guideline 5.1.1(i) requires the privacy policy to identify what data is collected, how, and all its uses, and to confirm that third parties (analytics tools, ad networks, SDKs) give equal protection. Guideline 5.1.2(i) requires permission before personal data is used, transmitted or shared, and clear disclosure of third-party sharing. Developers can change their App Privacy answers at any time without submitting an update, so **always record the date you captured the label**.

The product page shows three groups: *Data Used to Track You*, *Data Linked to You*, *Data Not Linked to You*. These map one-to-one to the tracking and linked flags in the questionnaire and in privacy manifests.

### iOS: Privacy manifests and the Xcode privacy report (background)

Not an OWASP Knowledge item; ours. Sources: Apple's [Privacy manifest files](https://developer.apple.com/documentation/bundleresources/privacy-manifest-files), [Describing data use in privacy manifests](https://developer.apple.com/documentation/bundleresources/describing-data-use-in-privacy-manifests) and [Adding a privacy manifest to your app or third-party SDK](https://developer.apple.com/documentation/bundleresources/adding-a-privacy-manifest-to-your-app-or-third-party-sdk), introduced at WWDC23 ([Get started with privacy manifests](https://developer.apple.com/videos/play/wwdc2023/10060)).

#### The file

`PrivacyInfo.xcprivacy` is a property list with four top-level keys: `NSPrivacyTracking` (Boolean), `NSPrivacyTrackingDomains` (array of domains), `NSPrivacyCollectedDataTypes` (array of dictionaries) and `NSPrivacyAccessedAPITypes` (required-reason APIs, discussed in the [MASWE-0048 note](/mobile/maswe-0048-malicious-code-included-in-the-app/)). Each `NSPrivacyCollectedDataTypes` entry has:

| Key | Type | Meaning |
|---|---|---|
| `NSPrivacyCollectedDataType` | String | One of Apple's data type constants |
| `NSPrivacyCollectedDataTypeLinked` | Boolean | Linked to the user's identity |
| `NSPrivacyCollectedDataTypeTracking` | Boolean | Used for tracking |
| `NSPrivacyCollectedDataTypePurposes` | Array of strings | Purpose constants |

The data type constants mirror the label: `NSPrivacyCollectedDataTypeName`, `…EmailAddress`, `…PhoneNumber`, `…PhysicalAddress`, `…OtherUserContactInfo`, `…Health`, `…Fitness`, `…PaymentInfo`, `…CreditInfo`, `…OtherFinancialInfo`, `…PreciseLocation`, `…CoarseLocation`, `…SensitiveInfo`, `…Contacts`, `…EmailsOrTextMessages`, `…PhotosorVideos` (note the lower-case "or" in Apple's constant), `…AudioData`, `…GameplayContent`, `…CustomerSupport`, `…OtherUserContent`, `…BrowsingHistory`, `…SearchHistory`, `…UserID`, `…DeviceID`, `…PurchaseHistory`, `…ProductInteraction`, `…AdvertisingData`, `…OtherUsageData`, `…CrashData`, `…PerformanceData`, `…OtherDiagnosticData`, `…EnvironmentScanning`, `…Hands`, `…Head`, `…OtherDataTypes`. Purposes are `NSPrivacyCollectedDataTypePurposeThirdPartyAdvertising`, `…DeveloperAdvertising`, `…Analytics`, `…ProductPersonalization`, `…AppFunctionality` and `…Other`. Apple warns that Xcode will not build the report correctly with any other values.

A minimal app manifest that declares an email address for app functionality and a device ID for analytics:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>NSPrivacyTracking</key>
    <false/>
    <key>NSPrivacyCollectedDataTypes</key>
    <array>
        <dict>
            <key>NSPrivacyCollectedDataType</key>
            <string>NSPrivacyCollectedDataTypeEmailAddress</string>
            <key>NSPrivacyCollectedDataTypeLinked</key>
            <true/>
            <key>NSPrivacyCollectedDataTypeTracking</key>
            <false/>
            <key>NSPrivacyCollectedDataTypePurposes</key>
            <array>
                <string>NSPrivacyCollectedDataTypePurposeAppFunctionality</string>
            </array>
        </dict>
        <dict>
            <key>NSPrivacyCollectedDataType</key>
            <string>NSPrivacyCollectedDataTypeDeviceID</string>
            <key>NSPrivacyCollectedDataTypeLinked</key>
            <false/>
            <key>NSPrivacyCollectedDataTypeTracking</key>
            <false/>
            <key>NSPrivacyCollectedDataTypePurposes</key>
            <array>
                <string>NSPrivacyCollectedDataTypePurposeAnalytics</string>
            </array>
        </dict>
    </array>
</dict>
</plist>
```

#### Where manifests live in an IPA

- The app's own manifest at the root of the app bundle: `Payload/App.app/PrivacyInfo.xcprivacy`.
- Each dynamic framework's manifest at the root of the framework: `Payload/App.app/Frameworks/X.framework/PrivacyInfo.xcprivacy`.
- SDKs linked **statically** cannot carry resources in a `.a` file; their manifests ship in a resource bundle (`Payload/App.app/X_Privacy.bundle/PrivacyInfo.xcprivacy` or similar, depending on the package manager) or in a static framework's resources. Swift packages declare the manifest as a package resource.
- App extensions (`PlugIns/*.appex`) have their own bundles and can have their own manifests.

Apple says the app's manifest does not need to repeat what the SDKs declare in theirs. That is why the meaningful unit is the **aggregate** of all manifests.

#### The privacy report

Xcode aggregates every manifest in an archive into a PDF: *Product > Archive*, then Control-click the archive in the Organizer and choose *Generate Privacy Report*. Apple describes it as organised like the privacy labels and as something to refer to when filling in App Store Connect. App Store Connect does not take its answers from the manifests; the questionnaire is still filled in by hand, which is how the two drift apart.

#### Enforcement and its limits

- Since **1 May 2024**, uploads must give approved reasons for required-reason APIs, and adding an SDK from Apple's [list of commonly used third-party SDKs](https://developer.apple.com/support/third-party-SDK-requirements/) requires that SDK's privacy manifest (and a signature if it is a binary dependency).
- Since **12 February 2025**, Apple's documentation says submitted apps must contain a valid privacy manifest for the listed SDKs they include, and App Store Connect rejects submissions with invalid manifests (unexpected keys or values).
- What App Store Connect validates is the *presence and syntax* of manifests and required-reason declarations. Nothing checks that `NSPrivacyCollectedDataTypes` is complete or matches the label. Apart from tracking domains (which iOS 17+ blocks when the user has not granted ATT permission, see [MASWE-0074](/mobile/maswe-0074-inadequate-tracking-domains-declarations/)), a manifest is a claim, and this weakness is about testing claims.

### Android and iOS: Who answers for SDK data collection (background)

Both stores put SDK collection squarely on the app developer. Google's [Using SDKs safely and securely](https://support.google.com/googleplay/android-developer/answer/13326895) says developers must treat any data collection by an SDK in their app as if they collected it directly, and the Data safety help says the form must include data collected through libraries and SDKs. Apple's App Review Guidelines open with "You are responsible for making sure everything in your app complies with these guidelines, including ad networks, analytics services, and third-party SDKs", and its [SDK requirements page](https://developer.apple.com/support/third-party-SDK-requirements/) repeats that the developer is responsible for all code an SDK includes.

Tooling the stores give you:

- **Google Play SDK Index** ([play.google.com/sdks](https://play.google.com/sdks)): widely used SDKs, their versions, permissions and labels; SDK providers who register in the **SDK Console** can link their own data-safety guidance, which the Data safety help points developers to. Play Console and Android Studio also flag SDK versions labelled outdated or policy-violating ([MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/) covers that side).
- **Apple privacy manifests and SDK signatures**: the vendor's own declaration ships with the binary, and Xcode can verify that an XCFramework update is signed by the same developer.

On the legal side (technical background only, not legal advice):

- Under **GDPR and UK GDPR**, the app's operator is normally the controller for the processing the app initiates, and must tell users the categories of data, purposes, legal basis and **recipients or categories of recipients** (Articles 13 and 14), in a concise, transparent and intelligible way (Article 12; see the Article 29 Working Party's [transparency guidelines, WP260 rev.01](https://ec.europa.eu/newsroom/article29/items/622227), endorsed by the EDPB, and the ICO's [right to be informed](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/individual-rights/the-right-to-be-informed/)). Article 5(1)(a) requires processing to be lawful, fair and transparent.
- Whether an SDK vendor acts as a **processor** (Article 28) or as a **separate or joint controller** (Article 26) depends on who decides purposes and means; the EDPB's [Guidelines 07/2020 on controller and processor](https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-072020-concepts-controller-and-processor-gdpr_en) and the CJEU's [Fashion ID judgment (C-40/17)](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:62017CJ0040) on embedded third-party plugins are the usual references. **The store categories do not map onto these legal roles.** Google's "service provider" and Apple's "third-party partner" are store definitions; a vendor can be a GDPR processor and still need to appear on a label, and vice versa. Do not let a client reuse one answer for the other.
- An SDK that stores or reads identifiers on the device engages **ePrivacy Article 5(3)** / **PECR regulation 6** (consent unless strictly necessary), independently of GDPR; see the EDPB's [Guidelines 2/2023 on the technical scope of Art. 5(3)](https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-22023-technical-scope-art-53-eprivacy-directive_en).
- **CCPA/CPRA** requires a notice at collection listing categories of personal information and whether they are sold or shared ([CCPA, California OAG](https://oag.ca.gov/privacy/ccpa)).

MASWE-0073 also cites an ENISA study on GDPR compliance for mobile apps on third-party processing. The direction is the same: the developer cannot outsource accountability to the SDK vendor.

### Android and iOS: The declaration-vs-behaviour matrix (background)

All six tests below feed one artefact: a matrix with **one row per data type per destination**, the declarations on the left and the evidence on the right. Build it in a spreadsheet; it becomes the core of the report.

| Data type (store taxonomy) | Destination (host, party) | Play label | App Store label | Manifest(s) | Privacy policy | Static (0318 / GT-2) | Runtime (0319 / GT-2) | Network (0206 / GT-1) | Before consent? | Verdict |
|---|---|---|---|---|---|---|---|---|---|---|
| Email address | api.example.com (first party) | Collected, Account management | Linked, App Functionality | App manifest | Yes | n/a | n/a | Seen in sign-up | No | Consistent |
| Email address (SHA-256) | ads.example.net (third party, ad SDK) | Not declared | Not declared | Ad SDK manifest: not declared | Not mentioned | `setUserData` call | Hash passed at login | Seen in event batch | No | **Undeclared sharing** |
| Health info | analytics.example.org (third party) | Not declared | Not declared | None | "Health data stays on your device" | `logEvent` with `blood_type` | Value `AB-` | Seen | Yes | **Undeclared sharing, contradicts policy** |
| Device or other IDs | crash.example.org (service provider) | Collected, Analytics | Not linked, Analytics | Crash SDK manifest: DeviceID, linked | Mentioned | n/a | n/a | Install ID in every report | Yes | **Linked flag inconsistent** |

The method has three evidence sources, in increasing order of strength:

1. **Static inventory and references**: which SDKs ship, what their manifests and Index entries say, which collection APIs the app calls and with what. Cheap, complete over the code, but only shows *potential* collection.
2. **Runtime traces**: what values actually reach SDK APIs, with a stack trace that names the app code responsible. Shows the data and the code, but not what leaves the device.
3. **Network capture**: what actually leaves the device, to which host. Shows the transmission, but not which code caused it, and misses anything you cannot decrypt.

**Seed the app with canary values.** Use a dedicated test account whose data is unique and searchable: a name like "Canary Tester", an address such as `canary.0073@example.com`, a phone number from Ofcom's drama range (`+44 7700 900073`), a fixed test location, and a recognisable value in every free-text and health or finance field. Then search for those values, *and* for the forms SDKs commonly transmit: URL-encoded, Base64, lower-cased and trimmed, and the MD5, SHA-1 and SHA-256 hashes of the normalised value (ad and attribution SDKs often hash emails and phone numbers for matching). For identifiers you cannot choose (advertising ID, `ANDROID_ID`, IDFV, push tokens, installation IDs), record the values the app sees, using the device's ads settings where shown or a Frida trace of the app's own getter calls. Note that `ANDROID_ID` is scoped per signing key and user since Android 8, so `adb shell settings get secure android_id` does not give you the app's value.

**Record consent state.** Run each flow at least three times: fresh install before any consent choice, after declining (or "Ask App Not to Track" on iOS), and after accepting. Declarations of "optional" collection are only true if the decline run is clean.

## Tests

### MASTG-TEST-0206: Undeclared PII in Network Traffic Capture (Android)

OWASP page: [MASTG-TEST-0206](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0206/). Type: dynamic, network.

#### Overview

Captures the app's decrypted traffic while you use it with known personal data, and checks every place that data appears against the Data safety section and the privacy policy. OWASP's overview phrases the goal as verifying that PII "is not being sent over the network, even if the traffic is encrypted". Read the evaluation instead: the test is about **undeclared** transmission. An app that sends your email to its own backend at sign-up and declares it is fine.

OWASP lists the proxies [mitmproxy](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0097/), [Burp Suite](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0077/) and [ZAP](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0079/), and [Wireshark](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0081/) for cleartext. The technique is [MASTG-TECH-0100](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0100/) (logging sensitive data from network traffic with a mitmproxy addon).

#### Prerequisites

- **A definition of the sensitive data.** OWASP's prerequisite page *identify-sensitive-data* applies; for this test, use the Data safety taxonomy above, so every hit maps to a type.
- **The declarations, captured and dated**: screenshots or a copy of the Data safety section from the store listing (*About this app > Data safety*), the client's Play Console answers if they can share them, and the privacy policy version in force. OWASP's test also lists `privacy-policy` and `app-store-privacy-declarations` prerequisites, which do not exist as pages in the MASTG yet.
- **The client's list of first-party domains and contracted service providers**, so you can classify destinations.
- An interception lab: a rooted device or emulator with your CA as a system CA, or an app build that trusts user CAs, and a way around certificate pinning in the app and in its SDKs. See our [traffic interception lab](/mobile/mobile-traffic-interception-lab/).
- A test account seeded with canary values (see the matrix section).

#### Steps

1. **Install the app** ([MASTG-TECH-0005](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/)). Install the production build from Play on the test device, or install the client-supplied release build. Do **not** use `adb install -g`: granting every permission up front changes which code paths run.

   ```bash
   adb install-multiple base.apk split_config.arm64_v8a.apk split_config.en.apk
   adb shell pm clear com.example.app      # fresh state before each consent-state run
   ```

2. **Start the proxy with a canary logger.** OWASP's addon matches exact strings in URL, request body and response body. Ours searches requests only (responses that echo your data back are not transmissions), includes headers, adds encoded and hashed forms, and labels each destination:

   ```python
   # gt_canary_logger.py - mitmproxy addon: find your own canary values in the app's requests
   import base64, hashlib, json, urllib.parse
   from mitmproxy import http

   CANARIES = {
       "Name": "Canary Tester",
       "Email address": "canary.0073@example.com",
       "Phone number": "+447700900073",
       "User IDs": "gt-user-0073",
       "Precise location": "51.5013",      # first 4 decimals of the test latitude
       "Health info": "AB-",
   }
   FIRST_PARTY = ["example.com"]           # from the client's domain list

   def variants(value):
       v = value.strip()
       forms = {v, v.lower(), urllib.parse.quote(v), urllib.parse.quote_plus(v),
                base64.b64encode(v.encode()).decode()}
       for algo in ("md5", "sha1", "sha256"):
           forms.add(hashlib.new(algo, v.lower().encode()).hexdigest())
       return [f.lower().encode() for f in forms if len(f) >= 3]

   NEEDLES = [(label, variants(value)) for label, value in CANARIES.items()]

   def party(host):
       return "first" if any(host == d or host.endswith("." + d) for d in FIRST_PARTY) else "THIRD"

   def scan(flow, where, blob):
       hay = blob.lower()
       for label, needles in NEEDLES:
           if any(n in hay for n in needles):
               host = flow.request.pretty_host
               print(json.dumps({"type": label, "host": host, "party": party(host),
                                 "where": where, "url": flow.request.pretty_url[:160]}))

   def request(flow: http.HTTPFlow):
       scan(flow, "url", flow.request.pretty_url.encode())
       scan(flow, "headers", bytes(flow.request.headers))
       scan(flow, "body", flow.request.content or b"")
   ```

   ```bash
   mitmdump -s gt_canary_logger.py -w flows.mitm | tee canary_hits.ndjson
   ```

   Keep `flows.mitm`: it is your evidence, and you can re-run the addon over it later with new search terms (`mitmdump -nr flows.mitm -s gt_canary_logger.py`). Short or common canaries (like `AB-`) produce false positives; check each hit in the flow.
3. **Exercise the app in three consent states** (fresh, declined, accepted). In each: first launch and onboarding, sign-up and login, profile editing, every feature that takes personal input (search, health or finance entry, support chat, uploads), location features with the emulator's location fixed (`adb emu geo fix <longitude> <latitude>`), purchase flows in a sandbox, logout, and a few minutes in the background. Note the time of each action so you can line flows up with screens.
4. **Look beyond the canaries.** For each third-party host in `flows.mitm`, read a few requests in `mitmweb` or Burp: device identifiers, advertising ID, installed-app lists, coarse location fields, screen names and event names often reveal data types you did not seed. Binary bodies (protobuf, compressed batches) need decoding; mitmproxy's protobuf view or a `protoc --decode_raw` of the body is usually enough to see strings.
5. **Check for traffic you cannot see.** Compare the hosts in the capture with DNS queries (or the device's Private DNS logs if you control the resolver). An SDK that pins its certificate or uses QUIC will be missing from the proxy; block UDP 443 to force a TCP fallback, and bypass pinning as described in the [interception lab](/mobile/mobile-traffic-interception-lab/). Cleartext traffic can be captured with Wireshark or `tcpdump` without a CA.

OWASP notes that this test does not tell you which code sent the data; pair it with MASTG-TEST-0318 and 0319 (OWASP points to [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/) and MASTG-TECH-0015 for that, but the dynamic-analysis technique 0015 is still a "TBD" page).

#### Observation

A log of canary hits (data type, host, first or third party, where in the request), the saved flows, the list of third-party hosts with what each received, and the consent state for each.

#### Evaluation

For each hit, decide: is this **collection** (transmitted off the device and kept beyond real-time servicing), and is the recipient a **third party** (sharing) or the developer or its service provider? Then the test **fails** if any of these holds:

- a data type is transmitted that the Data safety section does not declare as collected (and no exemption from the help page applies);
- a data type goes to a third party and the section does not declare it as shared;
- the purpose is evidently outside the declared purposes (for example, an email sent to an advertising SDK while the email is declared only for *Account management*);
- data declared as **optional** is sent in the declined run;
- the privacy policy contradicts what was observed (for example, it says health data never leaves the device).

It **passes** if every transmitted data type and every destination is covered by the declarations with a plausible purpose. Common false positives: the server echoing request data in responses (count the request only), data sent to the developer's own backend that is declared, ephemeral lookups (send location, get weather, nothing stored) that the client can show are not logged, and transfers the user explicitly initiated to a third party they chose.

#### Demo

From [MASTG-DEMO-0009](https://mas.owasp.org/MASTG/demos/android/MASVS-PRIVACY/MASTG-DEMO-0009/MASTG-DEMO-0009/). The sample posts six data items to an echo endpoint (`httpbin.org/post`); OWASP asks you to imagine none of them is declared:

```kotlin
val SENSITIVE_DATA = mapOf(
    "precise_location_latitude" to "37.7749",
    "precise_location_longitude" to "-122.4194",
    "name" to "John Doe",
    "email_address" to "john.doe@example.com",
    "phone_number" to "+11234567890",
    "credit_card_number" to "1234 5678 9012 3456"
)
val url = URL("https://httpbin.org/post")
val conn = url.openConnection() as HttpURLConnection
conn.requestMethod = "POST"
conn.doOutput = true
conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
val postData = SENSITIVE_DATA.map { (k, v) ->
    "${URLEncoder.encode(k, "UTF-8")}=${URLEncoder.encode(v, "UTF-8")}"
}.joinToString("&")
// ... write postData to conn.outputStream
```

OWASP runs `mitmdump -s mitm_sensitive_logger.py` with the same six values in the addon. Its log (trimmed):

```text
REQUEST URL: https://httpbin.org/post
Request Body: precise_location_latitude=37.7749&precise_location_longitude=-122.4194&name=John+Doe&email_address=john.doe%40example.com&phone_number=%2B11234567890&credit_card_number=1234+5678+9012+3456

RESPONSE URL: https://httpbin.org/post
Response Body: {
  "form": {
    "credit_card_number": "1234 5678 9012 3456",
    "email_address": "john.doe@example.com",
    ...
```

The same flow through our addon (illustrative, with the demo's values as canaries and no first-party domains configured):

```text
{"type": "Name", "host": "httpbin.org", "party": "THIRD", "where": "body", "url": "https://httpbin.org/post"}
{"type": "Email address", "host": "httpbin.org", "party": "THIRD", "where": "body", "url": "https://httpbin.org/post"}
{"type": "Phone number", "host": "httpbin.org", "party": "THIRD", "where": "body", "url": "https://httpbin.org/post"}
{"type": "Precise location", "host": "httpbin.org", "party": "THIRD", "where": "body", "url": "https://httpbin.org/post"}
{"type": "User payment info", "host": "httpbin.org", "party": "THIRD", "where": "body", "url": "https://httpbin.org/post"}
```

Two remarks. In the *request*, OWASP's exact-match addon finds only the coordinates: the form encoding turns `John Doe` into `John+Doe`, the `@` into `%40` and the `+` into `%2B`, so the name, email, phone and card number match only in httpbin's decoded echo in the *response*. Against a real server that does not echo, those four would be missed; the encoded variants close that gap. And the demo's conclusion, that the test fails "because the sensitive data is sent over the network", should read: it fails because Name, Email address, Phone number, Precise location (four decimals, about 10 m) and User payment info go to a host that is not the developer's and none of it is declared as collected or shared. With a declaration covering those types for that recipient, the same traffic would pass.

### MASTG-TEST-0318: References to SDK APIs Known to Handle Sensitive User Data (Android)

OWASP page: [MASTG-TEST-0318](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0318/). Type: static, code.

#### Overview

Finds where the app's code calls SDK methods that feed personal data to a third party, so you can work out what it passes. OWASP's example is Google Analytics for Firebase's `FirebaseAnalytics.setUserId`, `setUserProperty` and `logEvent`. The same idea applies to any SDK with an API that accepts user data: crash-reporting custom keys and user identifiers, attribution SDKs' user-data setters, support-chat user profiles, ad SDKs' targeting parameters. This test only shows **potential** handling; MASTG-TEST-0319 confirms it.

#### Prerequisites

- The release APK (or APK set), decompiled with jadx ([MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [jadx](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/)).
- The SDK inventory from [MASTG-KNOW-0004](/mobile/mastg-know-0004-third-party-libraries/) and [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/).
- For each data-handling SDK, a list of its **data entry points**, taken from the vendor's API reference (OWASP's prerequisite: "identify the SDK API methods it uses as entry points for data collection by reviewing the library's documentation or codebase").
- `semgrep` ([MASTG-TOOL-0110](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/)) and `grep` ([MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)).

#### Steps

1. **Decompile** and separate app code from SDK code:

   ```bash
   jadx -d out app.apk
   ls out/sources        # top-level packages: your app's package vs SDK namespaces
   ```

2. **Find the calls** from app code into the entry points. A quick sweep that ignores the SDK's own packages:

   ```bash
   grep -rnE "\.(logEvent|setUserId|setUserProperty|setDefaultEventParameters)\(" out/sources \
     | grep -v "^out/sources/com/google/"
   ```

   Then run a rule so the sweep is repeatable (rule in the demo below). R8 renames the app's classes but usually not the SDK's public API, because SDKs ship consumer keep rules; if the SDK itself is obfuscated, search for its class in smali (`apktool d`) by its string constants or by the event names you saw in traffic.
3. **Trace each argument back** to its source in jadx (*Find usage* on the variable, or right-click the method and *Find usage*): a constant event name is harmless; an account ID, an email, a health value, a search query, a location, a free-text field is not. Kotlin's inline `logEvent(name) { param(...) }` builder compiles to a plain `logEvent(String, Bundle)` call, so look at how the `Bundle` is filled.
4. **Look at what the SDK does on its own**: auto-initialisation providers, configuration `meta-data` and the `AD_ID` permission (commands in the [KNOW-0026 section](#android-third-party-services-embedded-in-the-app-mastg-know-0026)). An SDK that auto-collects needs declaring even if the app never calls it.
5. **Map each finding to a data type and destination** and add it to the matrix.

#### Observation

The list of call sites (class, method, line) for each SDK entry point, what data each passes, and the SDK's auto-collection configuration.

#### Evaluation

OWASP fails the test if the SDK methods are used at all. That is too blunt: logging `"screen_view"` with no parameters is not a privacy issue. We fail the test if an entry point receives, or is wired to receive, a value of a data type that the declarations do not cover **for that SDK's destination and purpose**: an account ID passed to `setUserId` while *User IDs* is not declared (or the iOS counterpart is labelled *Not Linked*), a health or financial value as an event parameter, free text that can hold anything. It passes if every call site passes only declared data types or non-personal values. Flag calls whose arguments you cannot resolve statically for MASTG-TEST-0319.

#### Demo

OWASP has no demo for this test. Using the sample code from MASTG-DEMO-0081 as the target, and our rule:

```kotlin
class MastgTest(context: Context) {
    val analytics = FirebaseAnalytics.getInstance(context)
    val userId: String = (1..8).map { Random.nextInt(0, 10) }.joinToString("")

    fun mastgTest(bloodType: String): String {
        analytics.logEvent("user_blood_type") {
            param("user_id", userId)
            param("blood_type", bloodType)
        }
        return "'user_blood_type' event was sent to Firebase Analytics."
    }
}
```

```yaml
# gt-sdk-data-entry-points.yml - run against jadx Java output
rules:
  - id: gt-android-sdk-data-entry-points
    languages: [java]
    severity: INFO
    message: >-
      SDK data entry point $METHOD called; trace its arguments and check they are
      declared for this SDK's destination and purpose
    patterns:
      - pattern: (FirebaseAnalytics $SDK).$METHOD(...)
      - metavariable-regex:
          metavariable: $METHOD
          regex: ^(logEvent|setUserId|setUserProperty|setDefaultEventParameters)$
```

```bash
semgrep -c gt-sdk-data-entry-points.yml out/sources/org/owasp/
```

Illustrative output:

```text
out/sources/org/owasp/mastestapp/MastgTest.java
❯❱ gt-android-sdk-data-entry-points
      SDK data entry point logEvent called; trace its arguments and check they are
      declared for this SDK's destination and purpose
       31┆ firebaseAnalytics.logEvent("user_blood_type", parametersBuilder.getBundle());
```

Tracing the builder's `param` calls gives `user_id` (a per-user identifier: *User IDs*) and `blood_type` (*Health info*). Both reach a third-party analytics service; if neither is declared as shared, the test fails, and the health parameter is also a minimisation question for PRIVACY-1 (does the analytics event need it at all?). Extend the `pattern` and regex per SDK in the inventory.

### MASTG-TEST-0319: Runtime Use of SDK APIs Known to Handle Sensitive User Data (Android)

OWASP page: [MASTG-TEST-0319](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0319/). Type: dynamic, hooks.

#### Overview

The dynamic counterpart to MASTG-TEST-0318: hook the SDK entry points while you use the app and record the actual values and the call stack. This turns "the app may pass an identifier" into "the app passed `blood_type=A+` with `user_id=90600554` from `MastgTest.kt:35`", and catches values built at runtime, remote-config-driven events and code paths that static analysis could not resolve.

#### Prerequisites

- A rooted device or emulator with `frida-server` ([Frida](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/)), or the app repackaged with Frida Gadget if the client allows it.
- OWASP's demo uses [frooky](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0145/), a Frida-based tool that takes a JSON list of classes and methods to hook and writes NDJSON with arguments and stack traces (`pip install frooky`). Plain Frida works too.
- The entry-point list from MASTG-TEST-0318 and the canary test account.

#### Steps

1. **Install** the app ([MASTG-TECH-0005](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/)) and start `frida-server` on the device.
2. **Describe the hooks** ([MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/), method hooking). With frooky, one entry per method:

   ```json
   {
     "category": "PRIVACY",
     "hooks": [
       { "class": "com.google.firebase.analytics.FirebaseAnalytics", "method": "logEvent" },
       { "class": "com.google.firebase.analytics.FirebaseAnalytics", "method": "setUserId" },
       { "class": "com.google.firebase.analytics.FirebaseAnalytics", "method": "setUserProperty" }
     ]
   }
   ```

   ```bash
   frooky -U -f com.example.app --platform android hooks.json > sdk_calls.ndjson
   ```

   Or with plain Frida, an observe-only script that logs arguments and the caller and then calls the original:

   ```javascript
   // trace-sdk-entry-points.js - observe only
   Java.perform(() => {
     const FA = Java.use('com.google.firebase.analytics.FirebaseAnalytics');
     const Log = Java.use('android.util.Log');
     const Ex = Java.use('java.lang.Exception');
     const where = () => Log.getStackTraceString(Ex.$new()).split('\n').slice(1, 6).join('\n');

     FA.logEvent.overload('java.lang.String', 'android.os.Bundle').implementation = function (name, b) {
       if (b !== null) b.size();          // unparcel so toString() shows the contents
       console.log('[sdk] logEvent ' + name + ' ' + b + '\n' + where());
       return this.logEvent(name, b);
     };
     FA.setUserId.implementation = function (id) {
       console.log('[sdk] setUserId ' + id + '\n' + where());
       return this.setUserId(id);
     };
     FA.setUserProperty.implementation = function (k, v) {
       console.log('[sdk] setUserProperty ' + k + '=' + v + '\n' + where());
       return this.setUserProperty(k, v);
     };
   });
   ```

   ```bash
   frida -U -f com.example.app -l trace-sdk-entry-points.js
   ```

3. **Exercise the app** in the three consent states, entering canary data everywhere. Hook early enough (`-f` spawns the app) to catch calls made at start-up.
4. **Correlate** each call with a data type, and with the network capture from MASTG-TEST-0206: the SDK may batch and send later, so a hooked call with no matching request yet is still collection once the batch goes.

#### Observation

Every hooked call with its arguments, timestamp, consent state and stack trace.

#### Evaluation

The test **fails** if a hooked SDK entry point receives a value of a data type that is not declared for that SDK's destination and purpose, or receives declared-optional data in the declined run. It **passes** if all observed values are declared, or are not personal data. Watch for argument values that only *look* harmless: a "user_id" that is the account number, a "screen" parameter containing a search query, a hashed email.

#### Demo

From [MASTG-DEMO-0081](https://mas.owasp.org/MASTG/demos/android/MASVS-PRIVACY/MASTG-DEMO-0081/MASTG-DEMO-0081/). The sample (shown under MASTG-TEST-0318 above, built with `firebase-analytics:23.0.0`) lets you pick a blood type and sends it with a random user ID through `logEvent`; OWASP stipulates that neither User IDs nor Health info is declared. The hooks file lists only `FirebaseAnalytics.logEvent`, and the run is `frooky -U -f org.owasp.mastestapp --platform android hooks.json`. Output (trimmed):

```json
{
  "type": "hook",
  "category": "PRIVACY",
  "class": "com.google.firebase.analytics.FirebaseAnalytics",
  "method": "logEvent",
  "stackTrace": [
    "com.google.firebase.analytics.FirebaseAnalytics.logEvent(Native Method)",
    "org.owasp.mastestapp.MastgTest.mastgTest(MastgTest.kt:35)",
    "org.owasp.mastestapp.MainActivityKt.MainScreen$lambda$15$lambda$14(MainActivity.kt:107)",
    "java.lang.Thread.run(Thread.java:1119)"
  ],
  "inputParameters": [
    { "declaredType": "java.lang.String", "value": "user_blood_type" },
    { "declaredType": "android.os.Bundle", "instanceToString": "Bundle[{blood_type=A+, user_id=90600554}]" }
  ]
}
```

The `(Native Method)` frame is Frida's replacement implementation, not the SDK; the first app frame, `MastgTest.kt:35`, is the call site to fix. The test fails: *Health info* linked to a *User ID* goes to a third-party analytics service without declaration. Beyond the declaration, a blood type is health data, special-category data under GDPR Article 9, so the client's DPO should also look at whether it should reach an analytics SDK at all.

### GT-PRIV-0073-1: Undeclared PII in network traffic vs App Privacy details and privacy manifests (iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

The iOS counterpart of MASTG-TEST-0206, which OWASP's legacy iOS test MASTG-TEST-0054 now points to even though 0206 is Android-only. It captures the app's traffic with seeded data and compares it with three iOS-specific declarations: the App Store **App Privacy** details (including the *linked* and *tracking* groupings), the aggregated **privacy manifests**, and the privacy policy. It adds the on-device **App Privacy Report** as an independent record of which domains the app contacted, which also catches hosts your proxy missed.

#### Prerequisites

- An iOS device set up as in the [traffic interception lab](/mobile/mobile-traffic-interception-lab/) (Wi-Fi proxy, CA installed and fully trusted under *Settings > General > About > Certificate Trust Settings*), and a way past pinning for the app and its SDKs (a jailbroken test device with Frida or objection is the practical option for production builds).
- The App Store product page's App Privacy section, captured and dated, and the client's App Store Connect answers if available.
- The aggregated privacy manifests from the IPA (GT-PRIV-0073-3, step 2) or the client's Xcode privacy report.
- The canary test account; for location, a fixed physical test location (on a production build you cannot simulate location without a debugger or jailbreak tweaks).

#### Steps

1. **Turn on App Privacy Report** before you start: *Settings > Privacy & Security > App Privacy Report > Turn On App Privacy Report* (iOS 15.2 and later). It records, for the last seven days, the app's data and sensor accesses and the domains it contacted directly or through in-app web content.
2. **Start the proxy** with the same addon as MASTG-TEST-0206 (`mitmdump -s gt_canary_logger.py -w flows.mitm`), with the client's first-party domains filled in.
3. **Exercise the app in three tracking and consent states**: fresh install before the App Tracking Transparency prompt and any in-app consent screen; after choosing *Ask App Not to Track* and declining in-app consent; after *Allow* and accepting. Between runs, delete and reinstall the app, which normally brings the ATT prompt back, and check *Settings > Privacy & Security > Tracking* (*Allow Apps to Request to Track* must be on, or the app never gets to ask). Cover the same flows as on Android.
4. **Compare hosts.** Open *App Privacy Report* > the app > *App Network Activity*, and list every domain. Any domain missing from your proxy capture is traffic you did not decrypt (pinning, QUIC, a non-proxy-aware socket); route it with a packet capture (`rvictl -s <UDID>` on a Mac, then Wireshark on the `rvi0` interface) or bypass the pinning, and repeat. The report screen can also be exported (in the iOS versions we have used, *Save App Activity* at the bottom writes an NDJSON file) for your evidence pack.
5. **Map every hit** to Apple's data types, decide linked or not linked (was it sent with, or joinable to, an account or device identifier?), and decide whether it is tracking (does a third party combine it with other apps' data for advertising or measurement?). Add to the matrix.

#### Observation

The canary-hit log per consent state, the full host list from the proxy and from App Privacy Report, and for each data type: destination, linked or not, tracking or not, purpose evidence.

#### Evaluation

The test **fails** if:

- an observed data type is missing from the App Privacy details (and does not meet *all* of Apple's optional-disclosure criteria);
- a data type appears under *Data Not Linked to You* but is transmitted with a user ID, an account token or a device identifier, or the destination is known to link it;
- data reaches a third party that combines it for advertising or ad measurement, or a data broker, but the label has no *Data Used to Track You* entry, or it happens when the user chose *Ask App Not to Track*;
- the aggregated privacy manifests omit a data type that the traffic shows the corresponding SDK collecting;
- the privacy policy contradicts what was observed.

It **passes** if every observed data type, destination, linkage and tracking use is reflected in the label and in the manifests of the code that sends it. False positives are as for 0206; also, data collected by Apple's own services (for example StoreKit purchases processed by Apple) is not the developer's to declare.

#### Demo

A vulnerable pattern: a profile screen that forwards the user's email, hashed, to an advertising SDK's matching endpoint, while the label lists Email Address only as *Linked to You* for *App Functionality*:

```swift
import CryptoKit

func didUpdateProfile(email: String) {
    let normalised = email.trimmingCharacters(in: .whitespaces).lowercased()
    let digest = SHA256.hash(data: Data(normalised.utf8))
    let hex = digest.map { String(format: "%02x", $0) }.joined()
    AdSDK.shared.setUserData(["em": hex])     // third-party ad SDK, sends on next batch
}
```

Illustrative addon output and App Privacy Report entry:

```text
{"type": "Email address", "host": "events.ads.example.net", "party": "THIRD", "where": "body", "url": "https://events.ads.example.net/v2/batch"}
App Privacy Report > App > App Network Activity: events.ads.example.net, api.example.com
```

The SHA-256 of `canary.0073@example.com` appears in the ad SDK's batch, in the run where the user chose *Ask App Not to Track*. The test fails three ways: the email is shared with a third party for advertising (not declared), it is used for tracking (no *Data Used to Track You* entry, and against the ATT choice), and the ad SDK's manifest declares no email collection, because the SDK only receives what the app passes. That last point is typical: an SDK manifest describes what the SDK collects by itself, not what the app feeds it.

### GT-PRIV-0073-2: References to and runtime use of SDK APIs handling sensitive data (iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

The iOS counterpart of MASTG-TEST-0318 and 0319 combined: find where the app calls SDK entry points that accept personal data, and record the values passed at runtime with the caller. On iOS, SDKs are often linked statically into the main binary, so the inventory step (which SDKs, which manifests) and the code search work on the same Mach-O.

#### Prerequisites

- The decrypted IPA ([MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/) to explore the package), radare2/[rabin2](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/) or Ghidra.
- The SDK inventory from [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/) (frameworks, resource bundles, `PrivacyInfo.xcprivacy` files) and the vendors' API references for the entry points.
- A jailbroken test device with Frida for the runtime part ([MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/) method hooking, [MASTG-TECH-0086](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0086/) method tracing).

#### Steps

1. **Locate the SDKs and their entry points in the binaries.** Objective-C SDK APIs leave class names and selectors in the binary; Swift-only APIs leave mangled symbols if not stripped:

   ```bash
   APP=Payload/App.app
   for b in "$APP/$(plutil -extract CFBundleExecutable raw -o - "$APP/Info.plist")" "$APP"/Frameworks/*.framework/*; do
     [ -f "$b" ] && file "$b" | grep -q Mach-O || continue
     rabin2 -zz "$b" 2>/dev/null | grep -qE 'logEventWithName:parameters:|setUserID:|setUserPropertyString:forName:' \
       && echo "analytics entry points referenced: $b"
   done
   ```

   Use the selectors of each SDK in your inventory. For Swift SDKs, `nm -gU <binary> | swift demangle | grep -i <SDK type name>` lists exported symbols; for statically linked Swift code you may have only strings and cross-references to go on.
2. **Read the call sites.** In r2 or Ghidra, follow cross-references from each selector reference (`objc_msgSend` call sites that load it) back to app code, and identify what is passed: constants, model fields, user input.
3. **Hook at runtime** and log arguments and callers without changing them. For an Objective-C entry point (in Google Analytics for Firebase, the Swift type `Analytics` is the Objective-C class `FIRAnalytics`, so `Analytics.logEvent(_:parameters:)` is `+[FIRAnalytics logEventWithName:parameters:]`):

   ```javascript
   // trace-ios-sdk.js - observe only
   const hooks = [
     ['FIRAnalytics', '+ logEventWithName:parameters:'],
     ['FIRAnalytics', '+ setUserID:'],
     ['FIRAnalytics', '+ setUserPropertyString:forName:'],
   ];
   for (const [cls, sel] of hooks) {
     const c = ObjC.classes[cls];
     if (!c || !c[sel]) { console.log('[!] not found: ' + cls + ' ' + sel); continue; }
     Interceptor.attach(c[sel].implementation, {
       onEnter(args) {
         const n = (sel.match(/:/g) || []).length;          // number of object arguments
         const a = [];
         for (let i = 0; i < n; i++) a.push(args[2 + i].isNull() ? 'nil' : new ObjC.Object(args[2 + i]).toString());
         console.log('[sdk] ' + cls + ' ' + sel + ' ' + a.join(' | ') + '\n' +
           Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0, 6).map(DebugSymbol.fromAddress).join('\n'));
       }
     });
   }
   ```

   ```bash
   frida -U -f com.example.app -l trace-ios-sdk.js
   ```

   The script assumes every argument is an object, which holds for these selectors; check the signature before reusing it for others. For pure-Swift SDK APIs with no Objective-C entry point, hook the exported Swift function by its mangled symbol if present, or rely on GT-PRIV-0073-1 for the transmitted data.
4. **Exercise the app** in the three consent states with canary data, and add each observed call to the matrix.

#### Observation

The SDK entry points referenced in each binary, the resolved call sites, and the runtime calls with argument values, consent state and caller.

#### Evaluation

As for MASTG-TEST-0318 and 0319: the test **fails** if an SDK entry point receives a value of a data type that the App Privacy details do not declare for that use, with the right *linked* and *tracking* classification, or receives it after the user declined. It **passes** if every value is declared or is not personal data.

#### Demo

The iOS version of the OWASP Android sample:

```swift
import FirebaseAnalytics

func sendBloodType(_ bloodType: String, userId: String) {
    Analytics.logEvent("user_blood_type", parameters: [
        "user_id": userId,
        "blood_type": bloodType,
    ])
}
```

Illustrative trace:

```text
[sdk] FIRAnalytics + logEventWithName:parameters: user_blood_type | {
    "blood_type" = "AB-";
    "user_id" = 90600554;
}
0x1023a4f10 App!ProfileViewController.sendBloodType(_:userId:)
0x1023a51c4 App!ProfileViewController.saveTapped(_:)
```

The test fails if the label has no *Health* entry (linked, for Analytics) and no *User ID* entry covering this flow. Apple has a dedicated *Health* type; *Sensitive Info* is for the other special categories, so a blood type belongs under *Health*.

### GT-PRIV-0073-3: Declaration consistency across store label, privacy manifests, privacy policy and observed behaviour (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

The OWASP tests compare behaviour with one declaration at a time. In practice the most common and most defensible findings are **inconsistencies between declarations**: a Play label that says "no data shared" while an ad SDK ships in the same build; an App Store label with no tracking entry while an SDK's manifest sets `NSPrivacyTracking` to `true`; a privacy policy naming recipients that neither label mentions. This test assembles all the declarations and the evidence from the other tests into the matrix and checks them against each other. It needs no rooted device and can be done for both platforms in one pass.

#### Prerequisites

- The Play store listing's Data safety section and the App Store product page's App Privacy section, both captured with date, app version and region. If the client can, ask for their Play Console Data safety answers and App Store Connect App Privacy answers directly; they contain the purposes and optional/required flags that the store pages summarise.
- The IPA (decrypted not required: manifests are plain resources) and the APK.
- The privacy policy linked from each store and from inside the app (check they are the same document).
- The results of MASTG-TEST-0206/0318/0319 and GT-PRIV-0073-1/2, and the SDK inventory.

#### Steps

1. **Capture the store labels.** Record every data type, purpose, collected/shared (Play) and tracking/linked/not linked (Apple), and the security-practice claims (encryption in transit, deletion). Note the date: labels change without app updates.
2. **Aggregate the privacy manifests** from the IPA (or ask for the client's Xcode privacy report for the same build and compare):

   ```bash
   unzip -q app.ipa -d ipa
   find ipa/Payload -name PrivacyInfo.xcprivacy -print0 | while IFS= read -r -d '' f; do
     echo "== ${f#ipa/Payload/}"
     plutil -convert json -o - "$f" | jq -r '
       "  tracking=\(.NSPrivacyTracking // false) domains=\((.NSPrivacyTrackingDomains // []) | join(","))",
       (.NSPrivacyCollectedDataTypes // [] | .[] |
         "  \(.NSPrivacyCollectedDataType | sub("NSPrivacyCollectedDataType"; "")) linked=\(.NSPrivacyCollectedDataTypeLinked) tracking=\(.NSPrivacyCollectedDataTypeTracking) purposes=\(.NSPrivacyCollectedDataTypePurposes | map(sub("NSPrivacyCollectedDataTypePurpose"; "")) | join(","))")'
   done
   ```

   On Linux, replace `plutil -convert json -o - "$f"` with `python3 -c 'import plistlib,json,sys; print(json.dumps(plistlib.load(open(sys.argv[1],"rb"))))' "$f"`. Also list SDKs in the inventory that have **no** manifest: statically linked SDKs whose resource bundle was dropped, or SDKs that should have one under Apple's rules.
3. **Collect the Android-side static declarations**: the merged manifest's permissions (location, contacts, `AD_ID`, `QUERY_ALL_PACKAGES`), auto-initialising SDK providers, and SDK configuration `meta-data` (commands in the KNOW-0026 section). A permission is not collection, but each one is a question: Google's FAQ says you only declare data actually collected, so ask the client to account for each sensitive permission.
4. **Read the privacy policy** for categories of data, purposes, recipients or categories of recipients, retention and deletion, and any absolute statements ("we never share…", "stays on your device").
5. **Fill the matrix** and run these checks:

   | # | Check | Typical inconsistency |
   |---|---|---|
   | 1 | Every data type in any manifest appears on the App Store label with the same linked/tracking classification | SDK manifest declares Device ID *linked*; label lists it under *Not Linked* |
   | 2 | `NSPrivacyTracking` true or any `NSPrivacyCollectedDataTypeTracking` true implies a *Data Used to Track You* entry and an ATT prompt | Tracking SDK manifest, no tracking label, no ATT prompt ([MASWE-0074](/mobile/maswe-0074-inadequate-tracking-domains-declarations/), [MASWE-0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/)) |
   | 3 | The Play and App Store labels describe the same practices where the SDK set and backend are the same | iOS label lists Crash Data and Product Interaction; Play label says no data collected |
   | 4 | "No data shared with third parties" (Play) is compatible with the third-party SDKs in the build and with the traffic | Ad or attribution SDK present and sending identifiers |
   | 5 | The privacy policy names the categories and recipients both labels imply, and its absolute statements hold | Policy says health data stays on device; 0319 shows it in analytics events |
   | 6 | Security-practice claims hold | "Encrypted in transit" with cleartext requests ([MASWE-0026](/mobile/maswe-0026-cleartext-network-traffic/)); "you can request deletion" with no working path ([MASWE-0076](/mobile/maswe-0076-lack-of-data-management-controls/)) |
   | 7 | Data declared *optional* is not collected in the declined run | Location declared optional, sent by an SDK before any prompt |
   | 8 | Every row of observed behaviour (0206, 0318, 0319, GT-1, GT-2) maps to a declaration | Any unmapped row |

#### Observation

The completed matrix, the aggregated manifest output, the dated label captures, and the list of inconsistencies with the evidence for each.

#### Evaluation

The test **fails** if any check in step 5 fails: two declarations contradict each other, or a declaration contradicts observed behaviour. It **passes** if all declarations are mutually consistent and every observed row maps to them. Over-declaration (declaring a type that is never collected) is not a privacy harm, but it is still inaccurate; report it as Info so the labels stay useful.

#### Demo

Illustrative aggregated manifest output for an IPA with an app manifest and three SDK manifests:

```text
== App.app/PrivacyInfo.xcprivacy
  tracking=false domains=
  EmailAddress linked=true tracking=false purposes=AppFunctionality
== App.app/Frameworks/CrashKit.framework/PrivacyInfo.xcprivacy
  tracking=false domains=
  CrashData linked=false tracking=false purposes=AppFunctionality
  DeviceID linked=true tracking=false purposes=Analytics
== App.app/AttributionKit_Privacy.bundle/PrivacyInfo.xcprivacy
  tracking=true domains=attr.example.net
  DeviceID linked=true tracking=true purposes=ThirdPartyAdvertising
  ProductInteraction linked=true tracking=true purposes=ThirdPartyAdvertising
```

Against an App Store label that lists Email Address (linked) and Crash Data (not linked) only, and a Play label that says "No data shared with third parties", this build fails checks 1, 2, 3 and 4: Device ID and Product Interaction are missing from the App Store label, the attribution SDK declares tracking with no *Data Used to Track You* entry, and the Play label's "no sharing" claim is contradicted by the same attribution SDK in the Android build, which MASTG-TEST-0206 shows sending the advertising ID.

## Best practices

### MASTG-BEST-0003: Comply with Privacy Regulations and Best Practices

OWASP page: [MASTG-BEST-0003](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0003/). OWASP marks it `platform: android`, but nothing in it is Android-specific.

The item reproduces CWE-359's mitigations. In the **requirements phase**, identify every privacy regulation that applies (by location, sector and type of data) and consult it. In **architecture and design**, weigh security against privacy: security logging wants every important operation recorded, while recording personal data creates its own risk, often through misplaced trust in the local environment (files, logs, caches readable by more people than assumed).

Two cautions about its references. It lists the US-EU **Safe Harbor** framework, which the CJEU invalidated in 2015 ([Schrems, C-362/14](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:62014CJ0362)); and it links Wikipedia for GDPR. Use the primary texts: [GDPR on EUR-Lex](https://eur-lex.europa.eu/eli/reg/2016/679/oj), [UK GDPR on legislation.gov.uk](https://www.legislation.gov.uk/eur/2016/679/contents), and the [CCPA page of the California Attorney General](https://oag.ca.gov/privacy/ccpa). For this weakness, the practical translation of "consult the regulations" is: the information the law requires you to give users (GDPR Articles 12 to 14) and the information the stores require (Data safety, App Privacy, manifests) must describe the same processing.

### Guler Tech: keeping declarations true release after release

No OWASP best practice covers the mechanics; ours:

- **Treat the data inventory as code.** Keep a machine-readable file in the repository listing, per SDK and per first-party feature, the data types, destination, purpose, linked/tracking flags, optional/required, and the consent that gates it. Generate (or at least check) the Play answers, the App Store answers and your own `PrivacyInfo.xcprivacy` from it.
- **Gate SDK onboarding.** Before adding an SDK: read its documentation, Google Play SDK Index entry and privacy manifest; decide the minimal configuration; add its rows to the inventory; name an owner.
- **Collect only after consent, by configuration.** Disable auto-initialisation or auto-collection where the SDK supports it and enable it after the user's choice, so that the declined path is genuinely clean:

  ```xml
  <!-- AndroidManifest.xml: remove the ad ID permission an SDK merged in, if you do not use the ad ID -->
  <uses-permission android:name="com.google.android.gms.permission.AD_ID"
      tools:node="remove" />
  ```

- **Diff on every release.** In CI, compare the SDK inventory (Gradle dependency report, `Package.resolved`, `Podfile.lock`) and the aggregated manifests against the last release; any new SDK, new data type or changed flag blocks the release until the inventory and the labels are updated.
- **Run a canary traffic test** on release candidates: a scripted UI run (for example with Maestro, as OWASP's demo automation does) through the main flows with a seeded account, behind mitmproxy with the canary addon, in the declined-consent state. New third-party hosts or canary hits fail the build.
- **Update labels before release.** Both stores let you edit labels without shipping; publish the label change before the build that changes behaviour reaches users, and keep a dated history of what was declared.
- **Mind the WebViews and regions.** Include app-controlled web content in the inventory, and declare the union of practices across flavours and regions.

## Rating findings

Rate by what personal data is involved beyond what is declared, how sensitive it is, scale and reversibility, and whether it contradicts the app's own declarations or store policy. These findings are almost never exploitable in the security sense; their weight comes from the people affected and from the declarations being false. Regulatory risk is for the client's legal team to assess, not for a severity score.

| Rating | Conditions |
|---|---|
| **High** | Undeclared sharing of sensitive data with a third party: health, precise location, financial or payment data, contacts, messages, special-category data, or data about children. Tracking (cross-app ad targeting or measurement, data broker) while the label says *not used to track*, or after the user chose *Ask App Not to Track* or declined consent. A store claim such as "No data shared with third parties" or a policy statement such as "never leaves your device" that the traffic directly contradicts for personal data. |
| **Medium** | Undeclared collection or sharing of ordinary personal data (email, name, user IDs, device or advertising identifiers, app interactions linked to an account) with analytics, attribution or ad SDKs. Data shown as *Not Linked* that is sent with an account or device identifier. Missing purposes (data declared for app functionality but also used for advertising or marketing). Data declared optional collected in the declined run. Privacy policy omitting recipients that the labels or traffic reveal. |
| **Low** | Undeclared diagnostics, crash or performance data with no direct identifiers; inconsistencies between the Play and App Store labels or between manifests and labels that do not hide any personal data flow from users; a missing SDK privacy manifest where the label is nonetheless complete. |
| **Info** | Over-declaration; correctly applied exemptions worth documenting (ephemeral lookups, service providers, user-initiated transfers); declarations that are accurate but vague; observations limited by traffic you could not decrypt. |

Raise a level for large-scale apps, apps aimed at children, or where the undeclared data feeds advertising; lower a level when the client shows the flow is limited to a pre-release build. In the report give: the matrix rows that fail, the dated declaration captures, the canary hits and flows (host, request excerpt), the hook traces with the responsible call site, the consent state of each observation, and the specific label, manifest or code change that fixes each one.

## References

- OWASP MASWE: [MASWE-0073: Inadequate Data Collection Declarations](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0073/); related [MASWE-0074](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0074/), [MASWE-0044](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0044/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-PRIVACY-3](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-3/), [MASVS-PRIVACY-1](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-1/) (CC BY-SA 4.0)
- OWASP MASTG knowledge: [MASTG-KNOW-0026](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PRIVACY/MASTG-KNOW-0026/) (CC BY-SA 4.0)
- OWASP MASTG tests: [MASTG-TEST-0206](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0206/), [MASTG-TEST-0318](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0318/), [MASTG-TEST-0319](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0319/); legacy [MASTG-TEST-0004](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0004/), [MASTG-TEST-0054](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0054/) (CC BY-SA 4.0)
- OWASP MASTG demos: [MASTG-DEMO-0009](https://mas.owasp.org/MASTG/demos/android/MASVS-PRIVACY/MASTG-DEMO-0009/MASTG-DEMO-0009/), [MASTG-DEMO-0081](https://mas.owasp.org/MASTG/demos/android/MASVS-PRIVACY/MASTG-DEMO-0081/MASTG-DEMO-0081/) (CC BY-SA 4.0)
- OWASP MASTG best practices: [MASTG-BEST-0003](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0003/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0005](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/), [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0015](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0015/), [MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/), [MASTG-TECH-0100](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0100/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0086](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0086/), [MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/) (CC BY-SA 4.0)
- OWASP MASTG tools: [mitmproxy (MASTG-TOOL-0097)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0097/), [Burp Suite (MASTG-TOOL-0077)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0077/), [ZAP (MASTG-TOOL-0079)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0079/), [Wireshark (MASTG-TOOL-0081)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0081/), [frooky (MASTG-TOOL-0145)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0145/), [Frida (MASTG-TOOL-0031)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/), [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/), [rabin2 (MASTG-TOOL-0129)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/) (CC BY-SA 4.0)
- Sibling notes: [PRIVACY hub](/mobile/masvs-privacy-privacy-testing-guide/), [MASWE-0066](/mobile/maswe-0066-inadequate-permission-management/), [MASWE-0068](/mobile/maswe-0068-incorrect-use-of-identifiers-for-tracking/), [MASWE-0072](/mobile/maswe-0072-inadequate-privacy-policy/), [MASWE-0074](/mobile/maswe-0074-inadequate-tracking-domains-declarations/), [MASWE-0076](/mobile/maswe-0076-lack-of-data-management-controls/), [MASWE-0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/); [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/), [MASTG-KNOW-0004](/mobile/mastg-know-0004-third-party-libraries/), [MASWE-0048](/mobile/maswe-0048-malicious-code-included-in-the-app/), [MASWE-0026](/mobile/maswe-0026-cleartext-network-traffic/), [traffic interception lab](/mobile/mobile-traffic-interception-lab/)
- Google Play: [Provide information for Google Play's Data safety section](https://support.google.com/googleplay/android-developer/answer/10787469), [Understand app privacy and security practices with the Data safety section (user help)](https://support.google.com/googleplay/answer/11416267), [User Data policy](https://support.google.com/googleplay/android-developer/answer/10144311), [Account deletion requirements](https://support.google.com/googleplay/android-developer/answer/13327111), [Using SDKs safely and securely](https://support.google.com/googleplay/android-developer/answer/13326895), [Google Play SDK Index](https://play.google.com/sdks)
- Android: [App metadata bundles (Android 14)](https://developer.android.com/about/versions/14/features/app-metadata), [Review how your app collects and shares user data](https://developer.android.com/guide/topics/data/collect-share)
- Apple: [App privacy details on the App Store](https://developer.apple.com/app-store/app-privacy-details/), [App Review Guidelines](https://developer.apple.com/app-store/review/guidelines/) (2.3, 5.1.1, 5.1.2), [Privacy manifest files](https://developer.apple.com/documentation/bundleresources/privacy-manifest-files), [Describing data use in privacy manifests](https://developer.apple.com/documentation/bundleresources/describing-data-use-in-privacy-manifests), [`NSPrivacyCollectedDataTypes`](https://developer.apple.com/documentation/bundleresources/app-privacy-configuration/nsprivacycollecteddatatypes), [Adding a privacy manifest to your app or third-party SDK](https://developer.apple.com/documentation/bundleresources/adding-a-privacy-manifest-to-your-app-or-third-party-sdk), [Third-party SDK requirements](https://developer.apple.com/support/third-party-SDK-requirements/), [Privacy updates for App Store submissions (29 February 2024)](https://developer.apple.com/news/?id=3d8a9yyh), [WWDC23: Get started with privacy manifests](https://developer.apple.com/videos/play/wwdc2023/10060), [About App Privacy Report](https://support.apple.com/en-us/102188), [About privacy information on the App Store](https://support.apple.com/kb/HT211970)
- Law and guidance: [GDPR (EUR-Lex)](https://eur-lex.europa.eu/eli/reg/2016/679/oj), [UK GDPR (legislation.gov.uk)](https://www.legislation.gov.uk/eur/2016/679/contents), [ePrivacy Directive 2002/58/EC](https://eur-lex.europa.eu/legal-content/EN/ALL/?uri=CELEX:32002L0058), [PECR regulation 6](https://www.legislation.gov.uk/uksi/2003/2426/regulation/6), [ICO: The right to be informed](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/individual-rights/the-right-to-be-informed/), [WP29 Guidelines on transparency (WP260 rev.01)](https://ec.europa.eu/newsroom/article29/items/622227), [EDPB Guidelines 07/2020 on controller and processor](https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-072020-concepts-controller-and-processor-gdpr_en), [EDPB Guidelines 2/2023 on Art. 5(3) ePrivacy](https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-22023-technical-scope-art-53-eprivacy-directive_en), [CJEU C-40/17 Fashion ID](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:62017CJ0040), [CJEU C-362/14 Schrems](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:62014CJ0362), [CCPA (California OAG)](https://oag.ca.gov/privacy/ccpa), [ENISA: Privacy and data protection in mobile applications (2017)](https://www.enisa.europa.eu/sites/default/files/publications/WP2017%20O-2-2-4%20GDPR%20Mobile.pdf)
- CWE: [CWE-359](https://cwe.mitre.org/data/definitions/359.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
