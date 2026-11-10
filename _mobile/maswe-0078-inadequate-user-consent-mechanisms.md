---
title: "MASWE-0078: Inadequate or Ambiguous User Consent Mechanisms"
date: 2026-11-10 22:12:00 +0000
subcategory: privacy
summary: "Testing consent in mobile apps: the consent UI, what SDKs send before a choice, after reject all and after withdrawal, and how each SDK learns the choice."
refs: [MASWE-0078, MASVS-PRIVACY-4, CWE-200, CWE-285, CWE-358, CWE-359]
tags: [android, ios, masvs-privacy, consent, gdpr, tracking]
---

This note is part of our [MASVS-PRIVACY guide](/mobile/masvs-privacy-privacy-testing-guide/) and covers OWASP [MASWE-0078](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0078/): an app that processes personal data, or reads and writes identifiers on the device, without consent that is freely given, specific, informed, unambiguous and obtained *before* the processing starts, or that asks for consent in a way that is vague, bundled or coercive. In a mobile app the interesting part is rarely the wording of the banner. It is what the code does around it: the analytics SDK that initialises itself from a content provider before the first screen is drawn, the ads SDK that fetches a bid with the advertising ID while the dialog is still on screen, the "Reject all" button that writes a choice nobody reads, the settings toggle that flips a preference but never tells the attribution SDK. OWASP has no tests and no Knowledge items for this weakness yet, so everything below is ours: the legal and platform background a tester needs, five tests (consent UI, pre-consent traffic, consent-denied traffic, withdrawal, and how the choice reaches each SDK), the implementation pattern that passes them, and how to rate what you find. This is technical testing guidance, not legal advice: whether consent is the right legal basis for a given processing operation, and whether a given implementation is lawful, is for the client's DPO and lawyers. Your job is to hand them precise evidence.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Background](#background)
  - [Android and iOS: what makes consent valid under GDPR and UK GDPR](#android-and-ios-what-makes-consent-valid-under-gdpr-and-uk-gdpr)
  - [Android and iOS: when consent is the right basis, and when it is not](#android-and-ios-when-consent-is-the-right-basis-and-when-it-is-not)
  - [Android and iOS: storage and access on the device (ePrivacy and PECR)](#android-and-ios-storage-and-access-on-the-device-eprivacy-and-pecr)
  - [Android and iOS: consent management platforms, IAB TCF and Google's requirements](#android-and-ios-consent-management-platforms-iab-tcf-and-googles-requirements)
  - [iOS: App Tracking Transparency is a separate permission](#ios-app-tracking-transparency-is-a-separate-permission)
  - [Android and iOS: OS permission prompts and store rules](#android-and-ios-os-permission-prompts-and-store-rules)
  - [Android and iOS: starting SDKs only after consent](#android-and-ios-starting-sdks-only-after-consent)
  - [Android and iOS: granular purposes, records and re-consent](#android-and-ios-granular-purposes-records-and-re-consent)
  - [Android and iOS: children](#android-and-ios-children)
  - [Android and iOS: outside the EU and UK](#android-and-ios-outside-the-eu-and-uk)
- [Tests](#tests)
  - [GT-PRIV-0078-1: Consent UI review (Android and iOS)](#gt-priv-0078-1-consent-ui-review-android-and-ios)
  - [GT-PRIV-0078-2: Traffic and device access before any choice (Android and iOS)](#gt-priv-0078-2-traffic-and-device-access-before-any-choice-android-and-ios)
  - [GT-PRIV-0078-3: Traffic after consent is refused (Android and iOS)](#gt-priv-0078-3-traffic-after-consent-is-refused-android-and-ios)
  - [GT-PRIV-0078-4: Withdrawal of consent (Android and iOS)](#gt-priv-0078-4-withdrawal-of-consent-android-and-ios)
  - [GT-PRIV-0078-5: Consent state storage and propagation to SDKs (Android and iOS)](#gt-priv-0078-5-consent-state-storage-and-propagation-to-sdks-android-and-ios)
- [Secure implementation](#secure-implementation)
  - [Consent gate before SDK start-up](#consent-gate-before-sdk-start-up)
  - [Android: defaults denied and explicit propagation](#android-defaults-denied-and-explicit-propagation)
  - [iOS: defaults denied, propagation and ATT](#ios-defaults-denied-propagation-and-att)
  - [Withdrawal, records and re-consent](#withdrawal-records-and-re-consent)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

The OWASP requirement is *"The app requests user consent prior to any data processing."* MASWE-0078 maps to **MASVS-PRIVACY-4** ("The app offers user control over their data"), whose description explicitly includes revoking consent and re-prompting when the app needs more data than it first asked for. It maps to [CWE-359](https://cwe.mitre.org/data/definitions/359.html) (Exposure of Private Personal Information to an Unauthorized Actor), [CWE-200](https://cwe.mitre.org/data/definitions/200.html) (Exposure of Sensitive Information to an Unauthorized Actor), [CWE-285](https://cwe.mitre.org/data/definitions/285.html) (Improper Authorization) and [CWE-358](https://cwe.mitre.org/data/definitions/358.html) (Improperly Implemented Security Check for Standard). In OWASP's beta numbering it absorbed MASWE-0115 and MASWE-0060. It carries the **P** and **EUDIW** profiles.

**OWASP has no tests and no Knowledge items for MASWE-0078**, and there are no legacy v1 privacy tests (privacy arrived with MASVS v2). The `## Background` section below replaces Knowledge, and the five tests are Guler Tech methodology, numbered GT-PRIV-0078-1 to -5.

Read the OWASP requirement with care. "Consent prior to *any* data processing" overstates the law: GDPR offers six lawful bases, and consent is only one of them (see [when consent is the right basis](#android-and-ios-when-consent-is-the-right-basis-and-when-it-is-not)). What the weakness is really about is narrower and very testable: **where the app relies on consent, or where consent is required for device storage and access, is the consent real, and does the code obey it?**

What is covered, and by which test:

| Question | Test |
|---|---|
| Is the consent request granular, unbundled, neutral, understandable, with a reject option as easy as accept? | [GT-PRIV-0078-1](#gt-priv-0078-1-consent-ui-review-android-and-ios) |
| What leaves the device, and what is written to it, before the user has chosen? | [GT-PRIV-0078-2](#gt-priv-0078-2-traffic-and-device-access-before-any-choice-android-and-ios) |
| What still leaves the device after "Reject all"? | [GT-PRIV-0078-3](#gt-priv-0078-3-traffic-after-consent-is-refused-android-and-ios) |
| Can the user withdraw as easily as they consented, and does withdrawal stop the processing (and trigger deletion)? | [GT-PRIV-0078-4](#gt-priv-0078-4-withdrawal-of-consent-android-and-ios) |
| Where is the choice stored, and does every SDK receive it before it collects? | [GT-PRIV-0078-5](#gt-priv-0078-5-consent-state-storage-and-propagation-to-sdks-android-and-ios) |

Keep the neighbours apart:

| Question | Where it lives |
|---|---|
| Does the app ask for OS permissions it does not need, or at the wrong time? | [MASWE-0066](/mobile/maswe-0066-inadequate-permission-management/) |
| Which identifiers does the app use (advertising ID, IDFV, Android ID, custom IDs), and are they resettable? | [MASWE-0068](/mobile/maswe-0068-incorrect-use-of-identifiers-for-tracking/) |
| Are the privacy-relevant settings on or off by default? | [MASWE-0071](/mobile/maswe-0071-inadequate-privacy-defaults/) |
| Does the privacy policy describe the processing? | [MASWE-0072](/mobile/maswe-0072-inadequate-privacy-policy/) |
| Do Data safety, App Privacy labels and privacy manifests match what the app sends? | [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/), [MASWE-0074](/mobile/maswe-0074-inadequate-tracking-domains-declarations/) |
| Can the user see, export and delete their data? | [MASWE-0076](/mobile/maswe-0076-lack-of-data-management-controls/) |
| Is the user told when something privacy-relevant happens (recording, background location)? | [MASWE-0070](/mobile/maswe-0070-inadequate-awareness-for-privacy-actions/) |
| Is an SDK harvesting data the developer never asked for? | [MASWE-0048](/mobile/maswe-0048-malicious-code-included-in-the-app/) |

## Modes of Introduction

**SDKs that start themselves.** Many analytics, crash-reporting, attribution and ads SDKs initialise from a `ContentProvider` (or an `androidx.startup` initializer) declared in their own manifest, which Android instantiates before `Application.onCreate()`; on iOS they start from `application(_:didFinishLaunchingWithOptions:)` or a `+load` method. They read or create identifiers and queue (often send) a first-open event before the app has drawn anything, let alone a consent screen.

**A consent screen that is decoration.** The UI stores `consent_given = true/false` in preferences, but nothing passes that value to the SDKs, or only the ads SDK reads it through the IAB TCF string and the analytics, attribution and session-replay SDKs never learn about it.

**Defaults that assume yes.** An SDK's consent API exists, but no default is set, and for several SDKs "no value" means "granted" (Google's consent mode documentation, for example, says that by default no consent values are set). The CMP shows the dialog, the SDK runs fully until the user answers, and nobody notices because the dialog is on screen.

**Bundling.** "By continuing you agree to our Terms, Privacy Policy and the use of your data for personalised advertising", one button, no way to agree to the terms without the advertising. Or consent hidden in the sign-up form with a single checkbox covering several purposes.

**Asymmetric choices.** "Accept all" on the first layer and "Manage options" (several taps, then a dozen toggles) as the only way to refuse; pre-ticked toggles on the second layer; "Reject" in grey text; dialogs that cannot be dismissed without accepting; re-prompts on every launch after a refusal and never after an acceptance.

**Consent treated as permanent.** New SDKs or purposes added in a release (a new attribution partner, a session-replay tool, an AI feature that sends content to a third party) under the old consent, without asking again. MASWE calls this failure to prompt for consent changes.

**Withdrawal that does not work.** No settings entry to change the choice, an entry that only links to a web page, or a toggle that updates the UI but not the SDKs until the next cold start, or never.

**Platform permission mistaken for consent.** The team treats the Android location permission or the iOS ATT "Allow" as the user's consent to everything downstream: sharing location with an ads partner, profiling, sale of data.

## Impact

- **Processing the user did not agree to.** Device identifiers, events, location and behavioural data reach analytics, ads and attribution vendors who build profiles from them. Once the data has left the device and been joined with other datasets, the user cannot take it back; withdrawal only stops future processing.
- **Regulatory exposure.** Processing that relies on invalid consent has no lawful basis under GDPR / UK GDPR Art. 6; device access without required consent breaches ePrivacy Art. 5(3) / PECR reg. 6. Consent-related enforcement in the EU and UK has been frequent, and fines under both regimes can be substantial. (Assessing that exposure is the client's legal team's job, not yours.)
- **Store and ad-partner consequences.** Apple can reject or remove apps that track without ATT permission (guideline 5.1.2(i)); Google Play requires affirmative consent before collecting personal and sensitive data outside users' reasonable expectations; Google's ad products limit EEA, UK and Swiss traffic to non-personalised or "limited" ads without a certified CMP.
- **Trust.** Users who discover that "Reject" did nothing tend to say so publicly.

## Mitigations

- **Decide the lawful basis per purpose first.** Ask for consent only for purposes that need it, and do not ask for consent where you could not honour a refusal.
- **Gate non-essential SDKs on the choice.** Start them in a "denied" state (or not at all) and enable each one only for the purposes the user accepted.
- **Make the request valid**: separate from terms of service, one purpose per choice, no pre-ticked boxes, reject as visible and easy as accept, plain language in the user's language, named third parties, information on how to withdraw.
- **Make withdrawal as easy as consent**, from inside the app, with immediate effect on every SDK, and trigger deletion of data that no longer has a basis.
- **Keep records** of who consented, when, to what (the notice version), how, and when they withdrew.
- **Re-ask when the processing changes**: new purposes, new vendors, a new version of the notice.
- **Treat OS permissions and ATT as separate layers** that sit on top of, not instead of, legal consent.

## Background

OWASP has no Knowledge items for this weakness. The sections below give the legal frame the tests are built on (as far as a tester needs it), the consent signalling standards you will meet in app code, and the platform mechanics that decide whether a consent screen actually controls anything.

### Android and iOS: what makes consent valid under GDPR and UK GDPR

GDPR [Art. 4(11)](https://eur-lex.europa.eu/eli/reg/2016/679/oj) defines consent as *any freely given, specific, informed and unambiguous indication of the data subject's wishes by which he or she, by a statement or by a clear affirmative action, signifies agreement*. UK GDPR keeps the same definition. Art. 7 and Recitals 32, 42 and 43 add the conditions; the EDPB's [Guidelines 05/2020 on consent](https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-052020-consent-under-regulation-2016679_en) (4 May 2020) and the ICO's [consent guidance](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/lawful-basis/consent/) explain how regulators read them. Translated into things you can observe in an app:

| Legal condition | Source | What you check in the app |
|---|---|---|
| **Clear affirmative action** | Art. 4(11); Recital 32: *silence, pre-ticked boxes or inactivity should not … constitute consent* | No pre-ticked toggles; dismissing, scrolling, swiping, backgrounding or tapping outside the dialog is not treated as acceptance; nothing processed while the dialog is open |
| **Specific and granular** | Recital 32 (consent for each purpose when there are several), Recital 43 (separate consent for different operations), EDPB 05/2020 | One choice per purpose; no "all or nothing" unless there is only one purpose |
| **Unbundled** | Art. 7(2): request *clearly distinguishable from the other matters*; Art. 7(4) and Recital 43 on making a contract conditional on unnecessary consent | Not merged into terms of service or sign-up; no "accept to continue" wall for an unrelated purpose |
| **Freely given** | Recital 42: *no genuine or free choice or … unable to refuse or withdraw consent without detriment* | Refusing does not remove features unrelated to the purpose; the EDPB treats "cookie walls" as invalid consent |
| **Informed** | Recital 42 (at least the identity of the controller and the purposes), EDPB 05/2020 (also what data, the right to withdraw, automated decisions, transfer risks) | Purposes, data, and recipients named; how to withdraw explained before the choice |
| **Clear and plain language** | Art. 7(2); Recital 32 (*clear, concise and not unnecessarily disruptive*) | Text in the user's language; no legalese or euphemism ("improve your experience" for ad profiling) |
| **Withdrawable, as easily as given** | Art. 7(3): *It shall be as easy to withdraw as to give consent*; user informed of this before consenting | In-app, same interface, comparable number of steps; immediate effect |
| **Demonstrable** | Art. 7(1), Recital 42 | Records of what each user agreed to and when (ask for them; see [records](#android-and-ios-granular-purposes-records-and-re-consent)) |
| **Prior** | Implicit in Art. 6 (a basis must exist when processing starts) | Nothing that needs consent happens before the choice |

Special-category data (health, biometrics for identification, sexual orientation and the rest of Art. 9) needs **explicit** consent where consent is the basis: an express statement, such as a separate confirmation, not just an affirmative action.

The EDPB's [Cookie Banner Taskforce report](https://www.edpb.europa.eu/our-work-tools/our-documents/other/report-work-undertaken-cookie-banner-taskforce_en) (January 2023) records the common position of EU supervisory authorities on banner design: no reject option on the first layer, pre-ticked boxes, deceptive link design and colour contrast that hides the reject option were all found problematic. Its examples are websites, but the same reasoning applies to an in-app dialog, and so does the EDPB's guidance on deceptive design patterns (Guidelines 03/2022).

Two court rulings come up often. [Planet49 (C-673/17)](https://curia.europa.eu/juris/liste.jsf?num=C-673/17), 1 October 2019: a pre-ticked checkbox is not valid consent for storing or accessing information on the device, whether or not the information is personal data. [IAB Europe (C-604/22)](https://curia.europa.eu/juris/liste.jsf?num=C-604/22), 7 March 2024: the TCF consent string (combined with an identifier such as an IP address) is personal data, which matters when you find one being sent around.

### Android and iOS: when consent is the right basis, and when it is not

GDPR Art. 6(1) lists six lawful bases: consent, contract, legal obligation, vital interests, public task and legitimate interests. Consent is the right basis when the user has a real choice and the controller is prepared to honour a "no". It is the wrong basis, and asking for it is itself misleading, when the processing would happen anyway:

- **Necessary for the service the user asked for**: sending the user's messages, processing a payment, keeping a session. That is contract (Art. 6(1)(b)). Asking for consent to it implies the user could refuse and still use the feature, which is false.
- **Required by law**: anti-money-laundering checks, tax records. Legal obligation (Art. 6(1)(c)).
- **Security and fraud prevention, first-party product analytics, crash reporting**: often legitimate interests (Art. 6(1)(f)), subject to a balancing test and a right to object. But see the next section: if the SDK stores or reads information on the device, ePrivacy / PECR may still require consent *for that access* even where GDPR does not for the later processing.

The EDPB's position is that a controller cannot switch from consent to another basis after the fact, for example by continuing to process under "legitimate interests" when a user withdraws. A test finding is therefore never "the app should ask for consent for X" in the abstract. It is "the app asks for consent for X but processes X anyway", or "the app processes X, which in our understanding requires consent, with no request at all; please confirm the basis". Leave the choice of basis to the client's legal team, and record what each data flow does so they can make it.

### Android and iOS: storage and access on the device (ePrivacy and PECR)

Article 5(3) of the [ePrivacy Directive](https://eur-lex.europa.eu/eli/dir/2002/58/oj) (implemented in the UK by [PECR regulation 6](https://www.legislation.gov.uk/uksi/2003/2426/regulation/6)) requires consent, to the GDPR standard, before **storing information or gaining access to information already stored** in the user's terminal equipment, unless an exemption applies. It is technology-neutral: it is the "cookie rule", but it covers apps and SDKs just as much. It applies whether or not the information is personal data. In an app this includes:

- an SDK generating an installation ID and writing it to `SharedPreferences`, the keychain or `NSUserDefaults`;
- reading the advertising ID (AAID on Android, IDFA on iOS), the IDFV, Android ID or any stored identifier and sending it off the device;
- reading device characteristics to build a fingerprint (also forbidden outright by Apple's licence agreement);
- an SDK reading information the app or OS stores (installed apps, contacts, clipboard) for its own purposes.

The EDPB's [Guidelines 2/2023 on the technical scope of Art. 5(3)](https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-22023-technical-scope-art-53-eprivacy-directive_en) (final version published October 2024) read "gaining access" broadly, including instructions from an SDK or server that make the device send information it would not otherwise send. Treat SDK initialisation that reads or creates identifiers as in scope.

The exemptions are narrow. In the EU: storage or access *strictly necessary* for a service the user explicitly requested, or for the sole purpose of carrying out a transmission. In the UK, the Data (Use and Access) Act 2025 amended PECR reg. 6, and the ICO's [guidance on storage and access technologies](https://ico.org.uk/for-organisations/direct-marketing-and-privacy-and-electronic-communications/guidance-on-the-use-of-storage-and-access-technologies/) now lists [five exceptions](https://ico.org.uk/for-organisations/direct-marketing-and-privacy-and-electronic-communications/guidance-on-the-use-of-storage-and-access-technologies/what-are-the-exceptions/): communication, strictly necessary (where the ICO places security and fraud prevention), **statistical purposes** (first-party analytics, with clear information and a simple, free way to object; a third-party analytics provider must act as a processor and only help improve your service), appearance (remembering display preferences) and emergency assistance. The ICO is explicit that none of them covers online advertising, including ad measurement, and that an exception only applies when the technology is used *solely* for that purpose. Check the commencement status of the UK changes and the current guidance at the time of your engagement; they were phased in during 2025 and 2026.

What this means for testing: "does any SDK touch the device before the user chooses?" is a question with legal weight even for first-party analytics in the EU, and for advertising and attribution SDKs in both the EU and the UK. Record every such access in [GT-PRIV-0078-2](#gt-priv-0078-2-traffic-and-device-access-before-any-choice-android-and-ios) and let legal decide which exemption, if any, applies.

### Android and iOS: consent management platforms, IAB TCF and Google's requirements

Most apps that show ads in Europe use a **consent management platform** (CMP): an SDK that shows the dialog, stores the choice and signals it to vendors in a standard format. The dominant format is the IAB Europe [Transparency and Consent Framework](https://iabeurope.eu/transparency-consent-framework/) (TCF).

**TCF in brief.** The CMP produces a **TC string**, a base64url-encoded bitfield recording, for a given version of the Global Vendor List: which of the standard purposes the user consented to (purpose 1 is "store and/or access information on a device"), which vendors received consent, which purposes and vendors rely on legitimate interests, the special features (precise geolocation, active scanning of device characteristics) and publisher restrictions. TCF v2.2 (2023) removed legitimate interests as a basis for the advertising and content personalisation purposes and tightened the information CMPs must show. TCF v2.3 (released 19 June 2025) made the `disclosedVendors` segment mandatory; [IAB Europe](https://iabeurope.eu/all-you-need-to-know-about-the-transition-to-tcf-v2-3/) states that strings created after 28 February 2026 without it are invalid. Check the current version and policy when you test; the framework changes every year or two.

**In-app storage.** The [TCF CMP API specification](https://github.com/InteractiveAdvertisingBureau/GDPR-Transparency-and-Consent-Framework) requires an in-app CMP to store the TC string and pre-parsed values in the app's **default `SharedPreferences`** on Android (file `/data/data/<package>/shared_prefs/<package>_preferences.xml`) and in **`NSUserDefaults`** on iOS (the standard defaults, in `Library/Preferences/<bundle id>.plist` in the app's data container), under well-known keys that vendor SDKs read directly:

| Key | Type | Meaning |
|---|---|---|
| `IABTCF_CmpSdkID` | number | Which CMP is present; set as soon as the CMP initialises |
| `IABTCF_gdprApplies` | number | 1 if GDPR applies to this user, 0 if not, unset if unknown |
| `IABTCF_TCString` | string | The full TC string |
| `IABTCF_PurposeConsents` | binary string | Position *n* is purpose *n+1* (`"1000000000"` = only purpose 1) |
| `IABTCF_VendorConsents` | binary string | Position *n* is vendor ID *n+1* |
| `IABTCF_PurposeLegitimateInterests`, `IABTCF_VendorLegitimateInterests` | binary string | Legitimate-interest signals the user has not objected to |
| `IABTCF_SpecialFeaturesOptIns` | binary string | Precise geolocation, device scanning |
| `IABTCF_PublisherRestrictions{ID}` | string | Per-purpose restrictions the publisher imposes on vendors |
| `IABTCF_PolicyVersion`, `IABTCF_PublisherCC`, `IABTCF_PurposeOneTreatment`, `IABTCF_UseNonStandardTexts` | various | Framework metadata |

Google's **Additional Consent** string (for ad-tech providers not registered with the TCF) is stored as `IABTCF_AddtlConsent`; IAB's Global Privacy Platform, used for US state signals, has its own `IABGPP_` keys. If the app removes its CMP, the publisher must clear the stale `IABTCF_*` values.

The TCF only reaches vendors that read these keys. Analytics, crash reporting, attribution, session replay and the app's own backend do not, unless the developer wires the choice to them (see [GT-PRIV-0078-5](#gt-priv-0078-5-consent-state-storage-and-propagation-to-sdks-android-and-ios)).

**Google's requirements.** Google's [EU user consent policy](https://www.google.com/about/company/user-consent-policy/) requires apps and sites that use Google's ad and measurement products for users in the EEA, the UK and Switzerland to obtain legally valid consent for cookies or other local storage where legally required and for personalised ads, retain records of that consent, give clear instructions for revoking it, and identify each party that receives the data. Since 16 January 2024 for the EEA and UK (31 July 2024 for Switzerland), [Google requires a Google-certified CMP](https://support.google.com/admob/answer/13554116) integrated with the TCF for personalised ads; other traffic is limited to non-personalised or "limited ads". Google's own CMP for apps is the **User Messaging Platform** (UMP) SDK ([Android](https://developers.google.com/admob/android/privacy), [iOS](https://developers.google.com/admob/ios/privacy)):

- `requestConsentInfoUpdate()` on every launch; `loadAndShowConsentFormIfRequired()` (Android) / `loadAndPresentIfRequired(from:)` (iOS) to show the form;
- `canRequestAds()` / `canRequestAds`: whether a consent decision has been gathered (or is not required). **It does not mean the user accepted**: after "Reject all" it is true as well, and the ads SDK serves limited or non-personalised ads based on the TC string;
- `getPrivacyOptionsRequirementStatus()` / `privacyOptionsRequirementStatus` and `showPrivacyOptionsForm()` / `presentPrivacyOptionsForm(from:)`: the **privacy options entry point**, which Google expects to be visible in the app when required. It is the withdrawal path you test in [GT-PRIV-0078-4](#gt-priv-0078-4-withdrawal-of-consent-android-and-ios);
- debug settings (`setDebugGeography(DEBUG_GEOGRAPHY_EEA)` / `geography = .EEA`, test device hashed IDs) and `reset()`, which only work on registered test devices. Finding them active in a production build is worth a note.

**Google consent mode v2** controls Google Analytics for Firebase through four consent types: `analytics_storage`, `ad_storage`, `ad_user_data` and `ad_personalization` (the last two added in late 2023 for the EEA update). Defaults are set in the [Android manifest or Info.plist](https://developers.google.com/tag-platform/security/guides/app-consent), and updated at runtime with `setConsent`, which persists across launches. Google's documentation states that **by default no consent mode values are set**, so an app that never sets them runs with everything effectively granted. "Basic" consent mode blocks the SDK until consent; "advanced" consent mode loads it with denied defaults and lets it send cookieless, reduced pings. Whether those reduced pings are acceptable before consent is a legal question; your job is to show what they contain.

### iOS: App Tracking Transparency is a separate permission

Since iOS 14.5 (April 2021) an app must obtain permission through the [AppTrackingTransparency](https://developer.apple.com/documentation/apptrackingtransparency) framework before it *tracks* the user, which Apple [defines](https://developer.apple.com/app-store/user-privacy-and-data-use/) as linking user or device data collected from the app with data from other companies' apps, websites or offline properties for targeted advertising or advertising measurement, or sharing it with data brokers. The app calls `ATTrackingManager.requestTrackingAuthorization(completionHandler:)`, shows a system alert with its `NSUserTrackingUsageDescription` purpose string, and reads `ATTrackingManager.trackingAuthorizationStatus` (`.notDetermined`, `.restricted`, `.denied`, `.authorized`). Without `.authorized`, `ASIdentifierManager.shared().advertisingIdentifier` returns all zeros, and Apple's FAQ is explicit that the app may not track with a substitute identifier (a hashed email address, for example). Guideline 5.1.2(i) forbids gating functionality or offering incentives for allowing tracking; a pre-prompt explaining the request is allowed if it is transparent and does not manipulate (5.1.1(iv)).

ATT is **not GDPR or ePrivacy consent by itself**:

- It covers only Apple's definition of tracking. First-party analytics, crash reporting, sharing data with a processor, and SDK access to on-device identifiers other than the IDFA are outside it, but may still need consent in the EU and UK.
- It is one yes/no for "tracking", not one choice per purpose, and Apple controls the wording; it does not name the vendors or purposes the law requires.
- A "yes" to ATT does not tell vendors which TCF purposes and vendors the user accepted.

So EU and UK apps that track usually need both a CMP and ATT. Apple lets the app reference the earlier CMP consent in the ATT purpose string, and order the two so that the CMP comes first. The French competition authority's [€150 million decision against Apple](https://www.autoritedelaconcurrence.fr/en/press-release/targeted-advertising-autorite-de-la-concurrence-imposes-fine-eu150000000-apple) (31 March 2025) turned partly on this point: it found that the ATT prompt did not on its own collect legally valid consent, so publishers needed a second consent pop-up. From a testing point of view: an app that relies on the ATT "Allow" as its only consent for EU users is a finding to report; an app that tracks when ATT is denied or not yet determined is a finding regardless of jurisdiction. ATT has no Android equivalent; on Android the user can delete or reset the advertising ID, which [MASWE-0068](/mobile/maswe-0068-incorrect-use-of-identifiers-for-tracking/) covers.

### Android and iOS: OS permission prompts and store rules

A runtime permission (location, camera, contacts, photos, notifications) is the operating system asking the user to let the *app* access a resource. It is not GDPR consent to whatever the app later does with that data: a location grant for a store finder does not cover sharing location with an advertising partner. MASWE-0078's mitigation that apps should *"request explicit permission"* through purpose strings or permission rationale is good practice ([MASWE-0066](/mobile/maswe-0066-inadequate-permission-management/) covers it), but it is a different layer from the consent this note tests.

Both stores add their own consent rules, enforced through review:

- **Google Play** [User Data policy](https://support.google.com/googleplay/android-developer/answer/10144311), *Prominent Disclosure and Consent Requirement*: where collection may be outside what users reasonably expect, the app must show an in-app disclosure during normal use (not only in the privacy policy or terms, not bundled with unrelated disclosures) describing the data and its use, immediately followed by a consent request that requires affirmative user action, does not treat navigating away (tapping outside, back, home) as consent, does not use auto-dismissing or expiring messages, and is granted **before** collection starts.
- **Apple** [App Store Review Guidelines](https://developer.apple.com/app-store/review/guidelines/) 5.1.1(ii): apps that collect user or usage data *must secure user consent for the collection, even if such data is considered to be anonymous*, paid functionality must not depend on granting access, and apps must provide an *easily accessible and understandable way to withdraw consent*; apps relying on GDPR legitimate interests instead must comply with all of that law. 5.1.1(iv): do not *manipulate, trick, or force people to consent to unnecessary data access*. 5.1.2(i): obtain explicit permission before sharing personal data with third parties (the current text names third-party AI), and use ATT for tracking.

### Android and iOS: starting SDKs only after consent

A consent screen controls nothing if the SDKs have already started. How SDKs start, and how to stop them:

**Android auto-initialisation.** An SDK can declare a `<provider>` in its library manifest; manifest merging puts it in the app, and Android creates every provider when the process starts, before `Application.onCreate()`. Jetpack [App Startup](https://developer.android.com/topic/libraries/app-startup) does the same through a single `androidx.startup.InitializationProvider` with `<meta-data>` entries per initializer. Find them in the merged manifest of the build you test:

```bash
apktool d -s -o app_out app.apk >/dev/null
grep -n -A4 '<provider' app_out/AndroidManifest.xml | grep -E 'android:name|authorities|meta-data'
grep -n 'androidx.startup' -A12 app_out/AndroidManifest.xml | grep 'meta-data'
```

The fixes are SDK-specific: a manifest flag that keeps collection off until the app enables it, removing the auto-init provider (`tools:node="remove"`) and initialising manually after consent, or the SDK's consent API with denied defaults. For Google Analytics for Firebase, the [documented](https://firebase.google.com/docs/analytics/android/configure-data-collection) keys are `firebase_analytics_collection_enabled` (`false` until `setAnalyticsCollectionEnabled(true)`), `firebase_analytics_collection_deactivated` (permanently off), `google_analytics_adid_collection_enabled` (no advertising ID) and the four consent-mode defaults `google_analytics_default_allow_analytics_storage`, `google_analytics_default_allow_ad_storage`, `google_analytics_default_allow_ad_user_data` and `google_analytics_default_allow_ad_personalization_signals`. Older Google Mobile Ads SDK versions documented a `com.google.android.gms.ads.DELAY_APP_MEASUREMENT_INIT` flag; Google's forum staff have since said current versions no longer start app measurement themselves, so check the behaviour of the version you find rather than the flag. Other analytics, attribution and crash-reporting SDKs have their own "auto-init" or "collection enabled" switches; read the vendor documentation for the version in the app.

**iOS start-up.** SDKs usually start from an explicit call in `application(_:didFinishLaunchingWithOptions:)` or the SwiftUI `App` initialiser, sometimes from Objective-C `+load` or a static initialiser in a framework. Info.plist flags do the same job as the Android manifest keys: for Firebase, [`FIREBASE_ANALYTICS_COLLECTION_ENABLED`](https://firebase.google.com/docs/analytics/ios/configure-data-collection), `FIREBASE_ANALYTICS_COLLECTION_DEACTIVATED`, `GOOGLE_ANALYTICS_IDFV_COLLECTION_ENABLED` and the `GOOGLE_ANALYTICS_DEFAULT_ALLOW_*` consent defaults (`ANALYTICS_STORAGE`, `AD_STORAGE`, `AD_USER_DATA`, `AD_PERSONALIZATION_SIGNALS`).

```bash
plutil -p Payload/App.app/Info.plist | grep -Ei 'COLLECTION|DEFAULT_ALLOW|AutoInit|AutoLog|Tracking|Consent'
```

**The pattern that works:** create no identifier, send no event and initialise no non-essential SDK until either (a) the CMP reports that consent is not required for this user, or (b) the user has chosen; then enable exactly the purposes chosen. "Initialise everything, then call `setConsent(denied)`" leaves a window in which the SDK can already have read the device and queued events, and some SDKs send their first request at initialisation.

### Android and iOS: granular purposes, records and re-consent

**Granularity.** A reasonable app-level model is one choice per purpose (for example: product analytics, crash diagnostics if the client treats it as consent-based, personalised advertising, ad measurement and attribution, personalised content, sharing with named partners), with vendors listed under each. The TCF purposes are finer still. What fails is a single "I agree" that covers several purposes, or a toggle labelled "Analytics" that in fact controls an attribution SDK as well.

**Records.** Art. 7(1) requires the controller to be able to demonstrate consent; Google's policy requires records too. A usable record holds a pseudonymous user or install ID, the timestamp, the choices per purpose and vendor, the version of the notice and the UI shown, the channel (in-app CMP version, platform, app version), and later withdrawals. On the device that is the TC string plus the CMP's own state; server-side it is a consent log. In a test, ask for the log entry for your test account after each step; it is the easiest way to check that the backend sees what the device shows.

**Re-consent.** MASVS-PRIVACY-4 and MASWE both require re-prompting when the app's data practices change: new purposes, new vendors, a new Global Vendor List version that adds vendors the CMP will disclose, a new privacy notice. The EDPB also recommends refreshing consent at appropriate intervals. Google's UMP documentation says it re-requests consent when the TC string has expired. Check that an update to the vendor list or notice in a new app version actually triggers the dialog for existing users, and that the app does not re-prompt only users who refused.

### Android and iOS: children

GDPR [Art. 8](https://eur-lex.europa.eu/eli/reg/2016/679/oj): where an information society service offered directly to a child relies on consent, a child below the age of digital consent (16 by default; Member States may set it as low as 13; [13 in the UK](https://www.legislation.gov.uk/ukpga/2018/12/section/9)) needs consent given or authorised by a parent, and the controller must make reasonable efforts to verify it. The ICO's [Age Appropriate Design Code](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/childrens-information/childrens-code-guidance-and-resources/age-appropriate-design-a-code-of-practice-for-online-services/) adds high-privacy settings by default, profiling off by default and no nudge techniques towards weaker privacy choices for services likely to be accessed by children. On the SDK side, look for the under-age flags: UMP's `setTagForUnderAgeOfConsent` / `tagForUnderAgeOfConsent`, the ads SDK's child-directed and under-age request configuration, and Google Play's Families policy for apps that target children. An app with a young audience that shows the standard adult consent dialog and enables personalised advertising on "Accept" is a finding.

### Android and iOS: outside the EU and UK

Other regimes use different models; follow the client's scope. The California **CCPA/CPRA** is mainly an opt-out regime ("Do Not Sell or Share My Personal Information", "Limit the Use of My Sensitive Personal Information", honouring Global Privacy Control), with opt-in consent required for selling or sharing the data of consumers under 16. Its statutory definition of consent excludes agreement obtained through dark patterns, and the [CPPA regulations](https://cppa.ca.gov/regulations/) require symmetry in choice. Brazil's LGPD and Canada's PIPEDA, which MASWE also cites, have their own consent rules. The tests below still apply; only the evaluation criteria change, and the client's legal team should set them.

## Tests

OWASP has no tests for MASWE-0078. The five tests below are ours. Run them in this order on the same build: GT-PRIV-0078-1 maps the UI, -2 sets the "no choice" baseline, -3 and -4 vary the choice, and -5 explains the differences you see. Related OWASP tests in sibling notes: undeclared data in network traffic and data collection declarations ([MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/)) and declared tracking domains on iOS ([MASWE-0074](/mobile/maswe-0074-inadequate-tracking-domains-declarations/)).

Common lab set-up for all five:

- The production build from the store (or the release candidate), a rooted Android device or one running a debuggable build of the same code for file access, and an iOS device (jailbroken for file access and Frida; stock for the UI and traffic parts).
- An intercepting proxy with the CA installed and pinning bypassed where needed ([traffic interception lab](/mobile/mobile-traffic-interception-lab/)). SDKs that pin their own endpoints will show up as TLS failures; still record the host names, and use DNS logs (PCAPdroid on Android, or the proxy host's resolver) as a fallback.
- A **jurisdiction that triggers the consent flow**: device region and language set to an EEA country or the UK, and an EEA or UK exit IP, because most CMPs decide whether to show the dialog from the IP address. UMP debug geography only works on test devices registered by the developer; on a production build, use a real exit IP. Run a second pass from outside the EU and UK if the client wants to know what other users get.
- Your **test device's identifiers**, so you can recognise them in traffic: the advertising ID (Android: *Settings > Privacy > Ads*, or *Settings > Google > Ads* depending on version; iOS: the IDFA is only non-zero after ATT "Allow", so log it from the app with Frida in GT-PRIV-0078-5), the IDFV, and the test account's email and user ID.

### GT-PRIV-0078-1: Consent UI review (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

A structured review of every surface where the app asks for, records or lets the user change consent: first-run dialog, sign-up, settings, re-consent prompts, ATT pre-prompt and prompt. It checks the conditions in the [validity table](#android-and-ios-what-makes-consent-valid-under-gdpr-and-uk-gdpr) and the store rules, and produces the inventory of purposes and vendors the traffic tests compare against.

#### Prerequisites

- A fresh install in an EEA or UK configuration (see the common set-up), and a second device or reinstall for repeat runs.
- Screen recording (`adb shell screenrecord /sdcard/consent.mp4`; iOS Control Centre screen recording or QuickTime with the device connected).
- The app's privacy policy and terms, and the store listing's Data safety section and App Privacy label, to compare against.

#### Steps

1. **Record the first run from launch.** Start the recording, launch the app, and do not touch anything for 30 seconds. Note what appears, in which order (splash, onboarding, CMP dialog, ATT pre-prompt, ATT alert, OS permission prompts, sign-up) and whether anything is dismissed automatically.
2. **First layer.** Capture the full text and both buttons. Check: is there a reject or "continue without accepting" option on this layer; is it the same type of control (button vs link), size, contrast and position class as accept; are purposes named in plain language; are third parties named or counted with a link to the list; is withdrawal explained; is the language the device's; does closing the dialog (X, back, tap outside, swipe down) record a choice, and which.
3. **Second layer ("Manage options", "Settings", "Partners").** For every purpose and vendor toggle: default position (any pre-ticked consent toggle fails), whether legitimate-interest toggles are on by default with an "object" control (that is the TCF model; record it), whether "Reject all" or "Save" with all off is available here, and whether the vendor list contains vendors whose SDKs or endpoints you later see in traffic.
4. **Bundling.** Walk the sign-up or onboarding flow. Note any single control that accepts terms of service and a consent purpose together, any consent sentence in the terms, and any feature gated on accepting an unrelated purpose ("Accept personalised ads to use the app", a "pay or accept" choice).
5. **Freely given.** After rejecting everything, use the app's main features. List anything that stops working and whether it is plausibly related to the refused purpose.
6. **ATT (iOS).** Capture any screen before the system alert and the purpose string in the alert. Check that the pre-prompt does not imitate the system alert, offer an incentive, or point at "Allow", and that the app works after "Ask App Not to Track". Note the order of CMP and ATT, and whether the CMP choice influences whether ATT is shown.
7. **Permission and disclosure prompts.** For any collection outside reasonable expectations (background location, contacts upload, SMS), check for the Google Play prominent disclosure immediately before the runtime permission request, and that its text matches the use.
8. **Re-launch behaviour.** Kill and relaunch after accepting, and separately after rejecting. Record whether the dialog reappears, and how soon after a refusal compared with an acceptance (re-asking only those who refused is a nudge).
9. **Fill in the inventory**: every purpose shown, every vendor named, every SDK you expect to see; you will compare it with GT-PRIV-0078-2 to -5.

#### Observation

Screenshots or recording of every consent surface with timestamps; the checklist below filled in; the purpose and vendor inventory.

| Check | Result |
|---|---|
| Reject available on first layer, same prominence as accept | |
| No pre-ticked consent toggles | |
| Dismissal not treated as consent | |
| Purposes specific, in plain language, in the device language | |
| Third parties identified | |
| Not bundled with terms or sign-up | |
| No unrelated feature gated on consent | |
| Withdrawal explained before the choice | |
| ATT pre-prompt neutral; app works when tracking is denied | |
| Re-prompt behaviour symmetric | |

#### Evaluation

The test **fails** if any consent request relies on pre-ticked boxes or on dismissal, scrolling or continued use as acceptance; if it is bundled with terms of service or another purpose; if refusing requires materially more effort than accepting (no reject on the first layer while accept is there, or reject hidden behind several screens); if purposes are vague or misleading; if unrelated features are gated on consent; if an ATT pre-prompt manipulates or the app is gated on tracking; or if Play's prominent-disclosure rules are not met where they apply. It **passes** if every condition in the checklist holds. Record design concerns that are matters of degree (contrast, wording, layer depth) as observations for the client's legal team rather than as fails, with the screenshots.

#### Demo

A consent screen state model that fails, and one that passes (Kotlin, Jetpack Compose state only):

```kotlin
// Fails: purposes pre-ticked, one button, closing the sheet counts as acceptance
data class Choices(var analytics: Boolean = true, var ads: Boolean = true, var partners: Boolean = true)

ModalBottomSheet(onDismissRequest = { consentRepo.save(Choices()) }) {
    Text("We use cookies and similar technologies to improve your experience.")
    Button(onClick = { consentRepo.save(Choices()) }) { Text("Continue") }
}

// Passes: nothing on by default, reject and accept are equal buttons, dismissal is not a choice
data class Choices(val analytics: Boolean = false, val ads: Boolean = false, val partners: Boolean = false)

ModalBottomSheet(onDismissRequest = { /* no choice recorded; ask again before any SDK starts */ }) {
    Text("Choose how we use your data. You can change this at any time in Settings > Privacy.")
    Row {
        OutlinedButton(onClick = { consentRepo.save(Choices()) }) { Text("Reject all") }
        OutlinedButton(onClick = { consentRepo.save(Choices(true, true, true)) }) { Text("Accept all") }
    }
    TextButton(onClick = { showPurposeDetails() }) { Text("Choose by purpose") }
}
```

Illustrative checklist excerpt for the failing version:

```text
Reject on first layer ............ FAIL  (only "Continue"; reject reachable via Menu > Settings > Privacy > Manage, 5 taps)
Pre-ticked toggles ............... FAIL  (Analytics, Advertising, Partners all ON on second layer)
Dismissal treated as consent ..... FAIL  (swipe-down stored analytics=true, ads=true, partners=true)
Third parties identified ......... FAIL  ("our partners", no list)
```

### GT-PRIV-0078-2: Traffic and device access before any choice (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Establishes what the app sends, and what it reads or writes on the device, between a fresh install and the moment the user answers the consent request. This is the baseline for the other traffic tests and the most common place to find a real violation: SDKs that run while the dialog is still on screen.

#### Prerequisites

- Common lab set-up; proxy running **before** the app is installed or launched.
- A truly fresh state: on Android `adb uninstall <package>` then install (or `adb shell pm clear <package>`, which also wipes the CMP state); on iOS delete the app and reinstall. iOS 14 and later have no user-facing IDFA reset, but the IDFA reads as zeros until the app is allowed to track, and the IDFV changes once every app from that vendor has been removed from the device.
- For device access: a rooted Android device or debuggable build (file listing), a jailbroken iOS device or objection on a re-signed build, and Frida for observe-only traces.

#### Steps

1. **Capture from install to choice.** Start a fresh capture, install and launch, and leave the consent dialog unanswered for at least two minutes. Then background the app for a minute, bring it back, and finally kill and relaunch it, still without answering.

   ```bash
   mitmdump --listen-port 8080 -w pre-consent.flow
   # in another terminal, Android
   adb install app.apk && adb shell monkey -p com.example.app -c android.intent.category.LAUNCHER 1
   ```

2. **Summarise hosts and flag your own identifiers.** A small mitmproxy add-on run over the saved flow lists each host with request counts and marks requests that contain the test device's known identifiers (you supply them; nothing is collected about anyone else):

   ```python
   # consent_audit.py  -  mitmdump -nr pre-consent.flow -s consent_audit.py
   import os, collections
   from mitmproxy import http

   KNOWN = [v.lower() for v in os.environ.get("TEST_IDS", "").split(",") if v]  # your test device's AAID/IDFA/IDFV, test email
   hosts = collections.Counter()
   hits = collections.defaultdict(set)

   def response(flow: http.HTTPFlow):
       hosts[flow.request.pretty_host] += 1
       blob = (flow.request.pretty_url + (flow.request.get_text(strict=False) or "")).lower()
       for v in KNOWN:
           if v in blob:
               hits[flow.request.pretty_host].add(v[:8] + "...")

   def done():
       for h, n in hosts.most_common():
           print(f"{n:4d}  {h}  {'IDS:' + ','.join(sorted(hits[h])) if h in hits else ''}")
   ```

   ```bash
   TEST_IDS="38400000-8cf0-11bd-b23e-10b96e40000d,tester@example.com" \
     mitmdump -nr pre-consent.flow -s consent_audit.py
   ```

   Many analytics SDKs send protobuf or compressed bodies, so a miss does not prove absence: open the largest requests per host in the mitmproxy UI, decode protobuf with `protoc --decode_raw`, and check gzip bodies.
3. **Classify every host** against the inventory from GT-PRIV-0078-1: app backend, CMP (configuration and vendor list), analytics, crash reporting, ads, attribution, A/B testing and remote config, session replay, push, other. Use the SDK inventory from the binary to attribute hosts ([MASTG-KNOW-0004 third-party libraries](/mobile/mastg-know-0004-third-party-libraries/)).
4. **Device access before the choice.** Android (rooted or debuggable build), list what has been written:

   ```bash
   adb shell su -c 'ls -la /data/data/com.example.app/shared_prefs/ /data/data/com.example.app/files/ /data/data/com.example.app/databases/'
   adb shell su -c 'cat /data/data/com.example.app/shared_prefs/*.xml' | grep -Ei 'install|device|uuid|_id|first_open|IABTCF'
   ```

   iOS (objection on a jailbroken device or re-signed build): `ios nsuserdefaults get`, `ios keychain dump` and `env` to find the data container, then list `Library/Preferences` and `Library/Application Support`. With Frida, trace reads of the advertising ID and creation of IDs during start-up (observe-only; see the script in [GT-PRIV-0078-5](#gt-priv-0078-5-consent-state-storage-and-propagation-to-sdks-android-and-ios)).
5. **Repeat outside the EU/UK** if in scope, and note whether the app decides "consent not required" on IP or device region.

#### Observation

A table of hosts contacted before any choice, with SDK category, number of requests, whether they carry identifiers (advertising ID, IDFV, install ID, user ID) or behavioural events, and the identifiers and files created on the device before the choice.

#### Evaluation

The test **fails** if, before the user has chosen, any SDK whose purpose needs consent in the client's legal assessment (advertising, attribution, ad measurement, cross-app analytics, session replay; in the EU usually any third-party analytics) sends events or identifiers, receives the advertising ID, or creates or reads non-essential identifiers on the device. It also fails if the app treats the time before the choice as "consent not yet refused" and processes on that basis. It **passes** if pre-choice traffic is limited to the app's own essential backend calls, the CMP fetching its configuration and vendor list, and services the client documents as strictly necessary (record each, with what it sends, for legal review). Consent-mode "cookieless pings" and similar reduced signals are recorded as observations with their exact content, not judged by you.

Common false positives: CMP configuration and Global Vendor List downloads (expected); OS-level traffic (connectivity checks, push token registration by the OS); the store's own install referrer handling. Common false negatives: SDKs that queue events locally and flush after consent, so nothing is on the wire yet but the data was collected before consent. Check the SDK's local database or queue files in step 4.

#### Demo

Illustrative output for an app whose analytics and attribution SDKs start from content providers:

```text
$ TEST_IDS="38400000-8cf0-11bd-b23e-10b96e40000d" mitmdump -nr pre-consent.flow -s consent_audit.py
  14  api.example.com
   3  cmp.example.net
   6  analytics.example.org  IDS:38400000...
   2  attribution.example.org  IDS:38400000...
   1  crash.example.org
```

Two third-party SDKs received the advertising ID while the consent dialog was on screen: a fail. The provider entries explain why:

```text
$ grep -n -A2 '<provider' app_out/AndroidManifest.xml | grep 'android:name'
  412:  android:name="com.example.analytics.internal.AnalyticsInitProvider"
  418:  android:name="com.example.attribution.AttributionInitProvider"
```

### GT-PRIV-0078-3: Traffic after consent is refused (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Repeats the capture after the user refuses everything, and compares it with the pre-consent baseline and an "accept all" capture. A refusal that does not change what the SDKs send is the clearest consent finding you can produce, because it needs no legal interpretation: the user said no, and the data went anyway.

#### Prerequisites

- GT-PRIV-0078-2 completed (baseline), and its lab set-up.
- Two more fresh installs: one for "Reject all", one for "Accept all".

#### Steps

1. **Reject on the first layer.** Fresh install, capture from launch, press "Reject all" (or the closest equivalent on the first layer; if there is none, use the second layer and switch every toggle off, including legitimate-interest ones, then save). Use the main features of the app for five minutes, background, relaunch, use them again.

   ```bash
   mitmdump --listen-port 8080 -w rejected.flow
   ```

2. **On iOS, also deny ATT** ("Ask App Not to Track") if it is shown, and do a separate run with CMP rejected but ATT allowed, to see whether the app treats ATT as overriding the CMP.
3. **Accept all** on a third fresh install, same script, saved as `accepted.flow`.
4. **Compare the three.** Run the add-on over each and diff the host lists; then, per third-party host, compare request counts and payloads:

   ```bash
   for f in pre-consent rejected accepted; do
     TEST_IDS="$IDS" mitmdump -nr $f.flow -s consent_audit.py > $f.hosts; done
   diff <(awk '{print $2}' rejected.hosts | sort) <(awk '{print $2}' accepted.hosts | sort)
   ```

5. **Check the signals the remaining requests carry.** Ad requests in the rejected run should carry the TCF signals (commonly `gdpr=1` and `gdpr_consent=<TC string>` parameters, or equivalents in the body) and should be non-personalised or limited ads; the advertising ID should be absent or zeroed. For analytics, look for consent-state fields in the payload and for the absence of the advertising ID and stable user IDs.

#### Observation

A three-column comparison (pre-consent, rejected, accepted) per host: requests, identifiers, event types; plus the TCF parameters seen in ad requests after rejection.

#### Evaluation

The test **fails** if after "Reject all" any SDK still sends events or identifiers for a purpose the user refused, the advertising ID (or IDFA, with ATT denied) still reaches a third party, a vendor not covered by TCF keeps collecting because nobody told it, or the app's own backend still forwards behavioural data to partners server-side (look for partner IDs or event names echoed in backend calls). It **passes** if third-party traffic after rejection is limited to what the client documents as necessary or non-consent-based, ad requests carry the refusal and request limited or non-personalised ads, and no identifiers reach consent-based vendors. "Fewer requests than accept-all" is not a pass on its own.

#### Demo

Illustrative comparison where the analytics SDK ignores the refusal:

```text
host                         pre-consent   rejected   accepted
api.example.com                       14         31         33
cmp.example.net                        3          1          1
ads.example.net                        0          8          9   rejected: gdpr=1&gdpr_consent=CQ...  npa=1   (ok)
analytics.example.org                  6         22         24   rejected: adid present, events: screen_view, purchase   (FAIL)
attribution.example.org                2          0          3   (ok after choice; pre-consent fail recorded in GT-PRIV-0078-2)
```

### GT-PRIV-0078-4: Withdrawal of consent (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Checks that a user who accepted can withdraw from inside the app, as easily as they accepted (GDPR Art. 7(3), App Store guideline 5.1.1(ii)), that withdrawal takes effect immediately for every SDK, and what happens to data already collected and identifiers already created.

#### Prerequisites

- A fresh install on which you chose "Accept all" (from GT-PRIV-0078-3, or a new one), signed in with a test account if the app has accounts.
- Proxy capture and, for step 4, file access and Frida as in GT-PRIV-0078-2.

#### Steps

1. **Find the way back.** Starting from the home screen, find the control that reopens the consent choices. Count the taps and compare with the taps needed to accept on first run. Note where it is (settings, profile, footer of a web view, only in the privacy policy, only by reinstalling) and whether it is labelled so a user would find it. If the app uses UMP, check that a privacy options entry point is shown when the CMP reports it as required.
2. **Withdraw** all purposes (or "Reject all" on the reopened dialog) with the proxy running, **without restarting the app**. Keep using it for five minutes and compare the traffic with the accept-all run. Then kill and relaunch, and compare again.
3. **Partial withdrawal.** Turn off only one purpose (for example advertising) and check that only the matching SDKs change behaviour, and that other purposes' toggles do not change silently.
4. **Identifiers and local data.** After withdrawal, list the SDKs' files and preferences again (GT-PRIV-0078-2 step 4). Note whether installation IDs and queued events are deleted or reset, and whether the TC string and SDK consent state changed (GT-PRIV-0078-5).
5. **Deletion of collected data.** Note whether the app tells the user what happens to data already collected, whether it calls any deletion endpoint (look for backend calls such as a consent or deletion API after withdrawal), and ask the client for the server-side consent log entry and for their deletion process for vendors (for example the analytics provider's user deletion API). Under GDPR, data processed on the basis of consent should be erased once consent is withdrawn if no other basis allows keeping it (Art. 17(1)(b)); the EDPB makes the same point. This step is often answered by the client, not observed; record the answer.
6. **Account-level consent.** If consent is stored server-side against the account, sign in on a second device and check the withdrawal is honoured there.

#### Observation

Steps to withdraw versus steps to consent; traffic before and after withdrawal in the same session and after relaunch; state of identifiers and consent signals after withdrawal; the client's answer on deletion of collected data.

#### Evaluation

The test **fails** if there is no in-app way to withdraw; if withdrawing takes materially more effort than consenting (for example one tap to accept, a web form or support email to withdraw); if SDKs keep sending data for withdrawn purposes after the change (in the same session, or until the next cold start without the user being told); if partial withdrawal turns off nothing or the wrong things; or if the user is not told how withdrawal affects the app and their data. It **passes** if withdrawal is reachable in a comparable number of steps, takes effect for every SDK immediately, consent-based identifiers are reset, and there is a documented process for deleting data that no longer has a basis. Missing deletion with no data impact demonstrated is a Low observation; continued sending after withdrawal is rated like GT-PRIV-0078-3.

#### Demo

A settings toggle that changes only the app's preference (fails) and one that propagates (passes), Kotlin:

```kotlin
// Fails: the UI and the preference change, the SDKs never hear about it
fun onAnalyticsToggled(enabled: Boolean) {
    prefs.edit().putBoolean("analytics_consent", enabled).apply()
}

// Passes: update every consumer immediately, reset identifiers, record the change
fun onAnalyticsToggled(enabled: Boolean) {
    prefs.edit().putBoolean("analytics_consent", enabled).apply()
    Firebase.analytics.setConsent {
        analyticsStorage(if (enabled) ConsentStatus.GRANTED else ConsentStatus.DENIED)
    }
    Firebase.analytics.setAnalyticsCollectionEnabled(enabled)
    if (!enabled) {
        Firebase.analytics.resetAnalyticsData()   // clears the SDK's local identifiers and queued data
        consentApi.recordWithdrawal(purpose = "analytics", noticeVersion = NOTICE_VERSION)
    }
}
```

Illustrative same-session result for the failing version:

```text
14:02:10  toggle "Analytics" OFF (settings)
14:02:31  POST analytics.example.org/collect  events=[screen_view, add_to_cart]  (FAIL: still sending)
14:09:48  cold start
14:09:50  POST analytics.example.org/collect  events=[app_open]  (FAIL)
```

### GT-PRIV-0078-5: Consent state storage and propagation to SDKs (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Explains the results of the traffic tests by looking inside the app: where the choice is stored (TC string, CMP state, app preferences), which SDK consent APIs the app calls, with which values and **in what order relative to SDK start-up**. It uses static analysis and an observe-only Frida trace of the app's own calls on your test device.

#### Prerequisites

- Decompiled app (jadx for Android, the decrypted binary for iOS), the SDK inventory.
- Rooted Android device or debuggable build; jailbroken iOS device. Frida and objection.
- Optionally the IAB `@iabtcf/core` library (Node.js) to decode TC strings locally.

#### Steps

1. **Static: who reads the choice?** Search for TCF keys, consent APIs and manual-init calls:

   ```bash
   jadx -d app_src app.apk
   grep -rnE 'IABTCF_|IABGPP_' app_src | grep -v '/com/google/' | head      # app or SDK code reading TCF keys
   grep -rnE 'setConsent\(|setAnalyticsCollectionEnabled|canRequestAds|requestConsentInfoUpdate|MobileAds\.initialize' app_src/sources | grep -v '^app_src/sources/com/google/'
   grep -rniE 'consent|gdpr|tracking' app_src/sources/com/example | head -40
   ```

   ```bash
   # iOS
   rabin2 -zz Payload/App.app/App | grep -E 'IABTCF_|setConsent:|setAnalyticsCollectionEnabled:|requestTrackingAuthorization'
   for f in Payload/App.app/Frameworks/*.framework/*; do [ -f "$f" ] && rabin2 -zz "$f" 2>/dev/null | grep -q 'IABTCF_' && echo "reads TCF: $f"; done
   ```

   Build a matrix: SDK, purpose, how it receives the choice (TCF keys, its own API, nothing), and what the app passes on "reject".
2. **Read the stored state** after each of GT-PRIV-0078-2 (no choice), -3 (rejected, accepted) and -4 (withdrawn):

   ```bash
   # Android: default SharedPreferences, where TCF CMPs must write
   adb shell su -c 'cat /data/data/com.example.app/shared_prefs/com.example.app_preferences.xml' | grep -E 'IABTCF_(gdprApplies|PurposeConsents|VendorConsents|CmpSdkID|TCString)'
   ```

   ```bash
   # iOS: attach objection, then run "ios nsuserdefaults get" at its prompt and look for the IABTCF_ keys
   objection -g "App" explore
   ```

   Decode the TC string locally and check the purposes and vendors match what you chose:

   ```javascript
   // decode-tc.mjs  -  node decode-tc.mjs "<TC string from your test device>"
   import { TCString } from '@iabtcf/core';
   const tc = TCString.decode(process.argv[2]);
   console.log('created', tc.created, 'cmpId', tc.cmpId, 'vendorListVersion', tc.vendorListVersion, 'policy', tc.policyVersion);
   const on = (vector) => { const ids = []; vector.forEach((has, id) => { if (has) ids.push(id); }); return ids; };
   console.log('purpose consents', on(tc.purposeConsents));
   console.log('vendor consents ', on(tc.vendorConsents).length, 'vendors');
   console.log('special features', on(tc.specialFeatureOptins));
   ```

3. **Trace the order of events at runtime** (observe-only; it logs the app's own calls and changes nothing). Android:

   ```javascript
   // consent-trace-android.js  -  frida -U -f com.example.app -l consent-trace-android.js
   const t0 = Date.now();
   const log = (m) => console.log(`[+${((Date.now() - t0) / 1000).toFixed(2)}s] ${m}`);
   Java.perform(() => {
     const Editor = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
     Editor.putString.implementation = function (k, v) {
       if (k && (k.startsWith('IABTCF_') || k.startsWith('IABGPP_'))) log(`prefs ${k}=${String(v).slice(0, 40)}`);
       return this.putString(k, v);
     };
     Editor.putInt.implementation = function (k, v) {
       if (k && k.startsWith('IABTCF_')) log(`prefs ${k}=${v}`);
       return this.putInt(k, v);
     };
     const hook = (cls, method) => {
       try {
         Java.use(cls)[method].overloads.forEach((o) => {
           o.implementation = function () {
             log(`${cls.split('.').pop()}.${method}(${[...arguments].map(String).join(', ').slice(0, 120)})`);
             return o.apply(this, arguments);
           };
         });
       } catch (e) { log(`not present: ${cls}.${method}`); }
     };
     hook('com.google.firebase.analytics.FirebaseAnalytics', 'setConsent');
     hook('com.google.firebase.analytics.FirebaseAnalytics', 'setAnalyticsCollectionEnabled');
     hook('com.google.android.gms.ads.MobileAds', 'initialize');
     hook('com.google.android.gms.ads.identifier.AdvertisingIdClient', 'getAdvertisingIdInfo');
     // add the app's own consent repository and other SDKs' init/consent methods found in step 1
   });
   ```

   iOS:

   ```javascript
   // consent-trace-ios.js  -  frida -U -f com.example.app -l consent-trace-ios.js
   const t0 = Date.now();
   const log = (m) => console.log(`[+${((Date.now() - t0) / 1000).toFixed(2)}s] ${m}`);
   const watch = (cls, sel, fmt) => {
     const c = ObjC.classes[cls];
     if (!c || !c[sel]) { log(`not present: ${cls} ${sel}`); return; }
     Interceptor.attach(c[sel].implementation, {
       onEnter(args) { const m = fmt(args, this); if (m) log(m); }
     });
   };
   watch('NSUserDefaults', '- setObject:forKey:', (a) => {
     const k = new ObjC.Object(a[3]).toString();
     if (!k.startsWith('IABTCF_')) return '';
     return `defaults ${k}=${a[2].isNull() ? 'nil' : String(new ObjC.Object(a[2])).slice(0, 40)}`;
   });
   watch('NSUserDefaults', '- setInteger:forKey:', (a) => {
     const k = new ObjC.Object(a[3]).toString();
     return k.startsWith('IABTCF_') ? `defaults ${k}=${a[2].toInt32()}` : '';
   });
   watch('FIRAnalytics', '+ setConsent:', (a) => `FIRAnalytics setConsent: ${new ObjC.Object(a[2])}`);
   watch('FIRAnalytics', '+ setAnalyticsCollectionEnabled:', (a) => `FIRAnalytics collectionEnabled=${a[2].toInt32() & 1}`);
   watch('ATTrackingManager', '+ requestTrackingAuthorizationWithCompletionHandler:', () => 'ATT prompt requested');
   watch('ASIdentifierManager', '- advertisingIdentifier', (a, ctx) => 'IDFA read by:\n' +
     Thread.backtrace(ctx.context, Backtracer.FUZZY).slice(0, 6).map(DebugSymbol.fromAddress).join('\n'));
   ```

   The defaults hooks fire for every key the app writes and only log the `IABTCF_` ones. On Android, if R8 renamed an SDK's public classes, find the obfuscated names in jadx first; most SDKs keep their public API names.
4. **Build the timeline** for a fresh install: first SDK network request (from the proxy, by timestamp), first advertising ID read, first `IABTCF_*` write, first `setConsent`, user's tap. Repeat for reject and for withdrawal.

#### Observation

The SDK/consent matrix; the stored consent state after each scenario; the decoded TC string; the runtime timeline showing which consent calls the app makes, with which values, and how they relate to SDK start-up and the user's tap.

#### Evaluation

The test **fails** if: a consent-based SDK starts, reads the advertising ID or sends data before the consent state is set; the app writes a refusal to its own preferences but never passes it to an SDK that needs it (no TCF support and no call to the SDK's consent API); the values passed do not match the choice (for example "Reject all" yields `setConsent` with `ad_storage` granted, or a TC string with purpose 1 consent); consent-mode defaults are absent so the SDK runs as granted; the TC string is not updated on withdrawal; or UMP or CMP debug settings (forced geography, test device IDs, `reset()` on every launch) are active in the production build. It **passes** if every consent-based SDK is either gated until the choice or started with denied defaults and updated immediately, and the stored and propagated values match the user's choice in every scenario.

#### Demo

A non-compliant set-up: no defaults, consent only stored by the app.

```xml
<!-- AndroidManifest.xml: no consent defaults, collection enabled by default -->
<application android:name=".App">
    <!-- nothing here: analytics SDK auto-initialises with everything granted -->
</application>
```

Illustrative trace on a fresh install, user taps "Reject all" at 9.8 s:

```text
[+0.41s] AdvertisingIdClient.getAdvertisingIdInfo(...)
[+1.12s] prefs IABTCF_CmpSdkID=300
[+9.84s] prefs IABTCF_gdprApplies=1
[+9.84s] prefs IABTCF_PurposeConsents=0000000000
[+9.85s] prefs IABTCF_TCString=CQ...
```

No `setConsent` call at any point and an advertising ID read 9.4 seconds before the user chose: the ads SDK will honour the TC string, but the analytics SDK ran with full consent and never learned of the refusal. The compliant version is in [Secure implementation](#secure-implementation); its trace shows `FirebaseAnalytics.setConsent({ANALYTICS_STORAGE=DENIED, AD_STORAGE=DENIED, ...})` at the user's tap and no advertising ID read before it.

## Secure implementation

OWASP has no best-practice items for consent. This is what passes the tests above.

### Consent gate before SDK start-up

1. Disable automatic start-up of every SDK whose purpose needs consent (manifest and Info.plist flags, removed init providers, manual initialisation).
2. Set denied defaults for any SDK that must start early (for example a CMP-integrated ads SDK, or analytics running in consent mode).
3. On launch, ask the CMP for the current state. If consent is not required, or the user has already chosen, apply the stored choice. Otherwise show the dialog and apply the choice when it returns.
4. Only then initialise and enable SDKs, purpose by purpose. Keep a single "consent applied" event that each integration subscribes to, so a new SDK cannot be added without wiring it.
5. Apply the same logic on the backend: server-to-server forwarding of events to partners checks the user's current consent record.

### Android: defaults denied and explicit propagation

```xml
<application android:name=".App">
    <meta-data android:name="firebase_analytics_collection_enabled" android:value="false" />
    <meta-data android:name="google_analytics_default_allow_analytics_storage" android:value="false" />
    <meta-data android:name="google_analytics_default_allow_ad_storage" android:value="false" />
    <meta-data android:name="google_analytics_default_allow_ad_user_data" android:value="false" />
    <meta-data android:name="google_analytics_default_allow_ad_personalization_signals" android:value="false" />
</application>
```

```kotlin
class ConsentGate(private val activity: Activity) {
    private val info = UserMessagingPlatform.getConsentInformation(activity)
    private val adsStarted = AtomicBoolean(false)

    fun run() {
        val params = ConsentRequestParameters.Builder()
            .setTagForUnderAgeOfConsent(isUnderAgeUser())   // from your own age flow
            .build()
        info.requestConsentInfoUpdate(activity, params, {
            UserMessagingPlatform.loadAndShowConsentFormIfRequired(activity) { _ -> apply() }
        }, { _ -> apply() })                                   // on error, UMP falls back to the last known state
    }

    private fun apply() {
        val c = AppConsent.fromTcfAndAppToggles(activity)    // read IABTCF_PurposeConsents plus your own toggles
        Firebase.analytics.setConsent {
            analyticsStorage(if (c.analytics) ConsentStatus.GRANTED else ConsentStatus.DENIED)
            adStorage(if (c.adStorage) ConsentStatus.GRANTED else ConsentStatus.DENIED)
            adUserData(if (c.adUserData) ConsentStatus.GRANTED else ConsentStatus.DENIED)
            adPersonalization(if (c.adPersonalization) ConsentStatus.GRANTED else ConsentStatus.DENIED)
        }
        Firebase.analytics.setAnalyticsCollectionEnabled(c.analytics)
        if (info.canRequestAds() && adsStarted.compareAndSet(false, true)) {
            MobileAds.initialize(activity)                  // ads SDK reads the TC string itself
        }
        OtherSdks.apply(c)                                   // attribution, replay, etc.: their own consent APIs
    }
}
```

`canRequestAds()` only tells you a decision exists; personalisation is decided from the TC string. Non-TCF SDKs must be driven from the decoded purposes or your own toggles.

### iOS: defaults denied, propagation and ATT

```xml
<key>FIREBASE_ANALYTICS_COLLECTION_ENABLED</key><false/>
<key>GOOGLE_ANALYTICS_DEFAULT_ALLOW_ANALYTICS_STORAGE</key><false/>
<key>GOOGLE_ANALYTICS_DEFAULT_ALLOW_AD_STORAGE</key><false/>
<key>GOOGLE_ANALYTICS_DEFAULT_ALLOW_AD_USER_DATA</key><false/>
<key>GOOGLE_ANALYTICS_DEFAULT_ALLOW_AD_PERSONALIZATION_SIGNALS</key><false/>
<key>NSUserTrackingUsageDescription</key>
<string>With your permission we use your device's advertising identifier to measure which of our ads you saw. You chose this in our privacy settings and can change it there at any time.</string>
```

```swift
func applyConsent(_ c: AppConsent) {
    Analytics.setConsent([
        .analyticsStorage: c.analytics ? .granted : .denied,
        .adStorage: c.adStorage ? .granted : .denied,
        .adUserData: c.adUserData ? .granted : .denied,
        .adPersonalization: c.adPersonalization ? .granted : .denied,
    ])
    Analytics.setAnalyticsCollectionEnabled(c.analytics)
    // Ask for ATT only if the user accepted a tracking purpose in the CMP, and only once the app is active
    if c.tracking, ATTrackingManager.trackingAuthorizationStatus == .notDetermined {
        ATTrackingManager.requestTrackingAuthorization { status in
            OtherSdks.setTrackingAllowed(status == .authorized)
        }
    } else {
        OtherSdks.setTrackingAllowed(c.tracking && ATTrackingManager.trackingAuthorizationStatus == .authorized)
    }
}
```

Tracking needs both: the CMP purpose and ATT `.authorized`. Either one alone is not enough.

### Withdrawal, records and re-consent

- Put a permanent "Privacy choices" entry in settings that reopens the same dialog (UMP: show it when `getPrivacyOptionsRequirementStatus()` is `REQUIRED` and call `showPrivacyOptionsForm()`), with the same buttons as the first run.
- On every change, call the same `apply()` path immediately, reset consent-based identifiers (`resetAnalyticsData()` for Firebase; the equivalent for other SDKs), and record the change server-side.
- Log consent records with the notice version, the CMP version and the vendor list version, and keep them for as long as you process on that consent.
- Bump the notice version when purposes or vendors change, and re-ask everyone (not only those who refused).
- Remove CMP debug settings and test device IDs from release builds; check in CI with a grep for `setDebugGeography`, `addTestDeviceHashedId`, `testDeviceIdentifiers` and `reset()` calls in production code paths.

## Rating findings

Rate by the series-wide rule: what personal data is processed beyond what the user agreed to, how sensitive it is, at what scale and how reversibly, and whether it contradicts the app's own declarations or a store rule. The severity is about the evidence you have; regulatory risk is for the client's legal team.

| Rating | Conditions |
|---|---|
| **High** | Advertising, attribution or cross-app tracking SDKs receive identifiers or behavioural data **after the user refused** or withdrew consent (GT-PRIV-0078-3/-4); tracking on iOS with ATT denied or not determined; special-category, precise location or children's data shared with third parties before or despite a refusal; personalised advertising enabled for a child audience on an adult consent flow. |
| **Medium** | Consent-based SDKs send identifiers or events **before** the user chooses (GT-PRIV-0078-2) but stop after a refusal; consent bundled with terms of service or forced by gating unrelated features; no reject option of equal prominence where advertising or tracking is involved; withdrawal not possible in the app, or not effective until restart without telling the user; a non-TCF SDK never told about the choice while it collects personal data; ATT used as the only consent for EU/UK tracking. |
| **Low** | Consent-based processing correctly gated, but UI weaknesses: pre-ticked toggles for low-impact purposes, vague wording, missing vendor names, asymmetric re-prompting, withdrawal that takes more steps than consent; first-party analytics pings before choice that carry no persistent identifier; no deletion process communicated after withdrawal; CMP debug settings left in production. |
| **Info** | Observations for legal review where the basis is genuinely open (crash reporting before choice, consent-mode cookieless pings, CMP and vendor-list fetches); consent asked for processing that appears to rely on another basis (misleading but not over-collecting); differences between regions that the client should confirm are intended. |

Raise a level when the data is sensitive (health, finance, precise location, children), when the app's Data safety section, App Privacy label or privacy manifest says the data is not collected, linked or used for tracking ([MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/), [MASWE-0074](/mobile/maswe-0074-inadequate-tracking-domains-declarations/)), or when the user base is large. Lower a level when the only flow is to a processor acting solely for the client with no identifier that persists across sessions.

In the report give: the scenario (fresh install, rejected, withdrawn) and region set-up, the host and the SDK it belongs to, the exact identifiers or events in the request (redacted to your test device's values), timestamps relative to the user's tap, the stored consent state and decoded TC string, the screenshots from GT-PRIV-0078-1, and the code or configuration change that fixes it. State that legal qualification of the finding is for the client's DPO or counsel.

## References

- OWASP MASWE: [MASWE-0078: Inadequate or Ambiguous User Consent Mechanisms](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0078/); related [MASWE-0066](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0066/), [MASWE-0068](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0068/), [MASWE-0071](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0071/), [MASWE-0073](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0073/), [MASWE-0076](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0076/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-PRIVACY-4](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-4/), [MASVS-PRIVACY-3](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-3/) (CC BY-SA 4.0)
- Sibling notes: [PRIVACY hub](/mobile/masvs-privacy-privacy-testing-guide/), [MASWE-0066](/mobile/maswe-0066-inadequate-permission-management/), [MASWE-0068](/mobile/maswe-0068-incorrect-use-of-identifiers-for-tracking/), [MASWE-0070](/mobile/maswe-0070-inadequate-awareness-for-privacy-actions/), [MASWE-0071](/mobile/maswe-0071-inadequate-privacy-defaults/), [MASWE-0072](/mobile/maswe-0072-inadequate-privacy-policy/), [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/), [MASWE-0074](/mobile/maswe-0074-inadequate-tracking-domains-declarations/), [MASWE-0076](/mobile/maswe-0076-lack-of-data-management-controls/), [MASWE-0048](/mobile/maswe-0048-malicious-code-included-in-the-app/), [third-party libraries](/mobile/mastg-know-0004-third-party-libraries/), [traffic interception lab](/mobile/mobile-traffic-interception-lab/)
- EU law and guidance: [GDPR (Regulation (EU) 2016/679)](https://eur-lex.europa.eu/eli/reg/2016/679/oj) Art. 4(11), 6, 7, 8, 9, 17 and Recitals 32, 42, 43; [ePrivacy Directive 2002/58/EC](https://eur-lex.europa.eu/eli/dir/2002/58/oj) Art. 5(3); EDPB [Guidelines 05/2020 on consent](https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-052020-consent-under-regulation-2016679_en), [Guidelines 2/2023 on the technical scope of Art. 5(3)](https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-22023-technical-scope-art-53-eprivacy-directive_en), [Cookie Banner Taskforce report](https://www.edpb.europa.eu/our-work-tools/our-documents/other/report-work-undertaken-cookie-banner-taskforce_en); CJEU [C-673/17 Planet49](https://curia.europa.eu/juris/liste.jsf?num=C-673/17), [C-604/22 IAB Europe](https://curia.europa.eu/juris/liste.jsf?num=C-604/22)
- UK law and guidance: [PECR regulation 6](https://www.legislation.gov.uk/uksi/2003/2426/regulation/6), [Data Protection Act 2018 s. 9](https://www.legislation.gov.uk/ukpga/2018/12/section/9), [Data (Use and Access) Act 2025](https://www.legislation.gov.uk/ukpga/2025/18/contents); ICO [consent](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/lawful-basis/consent/), [storage and access technologies](https://ico.org.uk/for-organisations/direct-marketing-and-privacy-and-electronic-communications/guidance-on-the-use-of-storage-and-access-technologies/), [exceptions](https://ico.org.uk/for-organisations/direct-marketing-and-privacy-and-electronic-communications/guidance-on-the-use-of-storage-and-access-technologies/what-are-the-exceptions/), [Age Appropriate Design Code](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/childrens-information/childrens-code-guidance-and-resources/age-appropriate-design-a-code-of-practice-for-online-services/)
- Other: [CPPA regulations (CCPA/CPRA)](https://cppa.ca.gov/regulations/); Autorité de la concurrence, [ATT decision press release](https://www.autoritedelaconcurrence.fr/en/press-release/targeted-advertising-autorite-de-la-concurrence-imposes-fine-eu150000000-apple)
- IAB: [Transparency and Consent Framework](https://iabeurope.eu/transparency-consent-framework/), [TCF specifications (CMP API, in-app keys)](https://github.com/InteractiveAdvertisingBureau/GDPR-Transparency-and-Consent-Framework), [transition to TCF v2.3](https://iabeurope.eu/all-you-need-to-know-about-the-transition-to-tcf-v2-3/)
- Google: [EU user consent policy](https://www.google.com/about/company/user-consent-policy/), [certified CMP requirement](https://support.google.com/admob/answer/13554116), [UMP SDK Android](https://developers.google.com/admob/android/privacy), [UMP SDK iOS](https://developers.google.com/admob/ios/privacy), [consent mode for apps](https://developers.google.com/tag-platform/security/guides/app-consent), [Firebase Analytics data collection (Android)](https://firebase.google.com/docs/analytics/android/configure-data-collection), [(iOS)](https://firebase.google.com/docs/analytics/ios/configure-data-collection), [Google Play User Data policy](https://support.google.com/googleplay/android-developer/answer/10144311); Android: [App Startup](https://developer.android.com/topic/libraries/app-startup), [Request runtime permissions](https://developer.android.com/training/permissions/requesting)
- Apple: [App Store Review Guidelines](https://developer.apple.com/app-store/review/guidelines/) 5.1.1, 5.1.2; [User privacy and data use](https://developer.apple.com/app-store/user-privacy-and-data-use/); [AppTrackingTransparency](https://developer.apple.com/documentation/apptrackingtransparency), [`requestTrackingAuthorization(completionHandler:)`](https://developer.apple.com/documentation/apptrackingtransparency/attrackingmanager/requesttrackingauthorization%28completionhandler%3A%29), [`trackingAuthorizationStatus`](https://developer.apple.com/documentation/apptrackingtransparency/attrackingmanager/authorizationstatus), [`NSUserTrackingUsageDescription`](https://developer.apple.com/documentation/bundleresources/information-property-list/nsusertrackingusagedescription), [`ASIdentifierManager`](https://developer.apple.com/documentation/adsupport/asidentifiermanager); [HIG: Privacy](https://developer.apple.com/design/human-interface-guidelines/privacy)
- CWE: [CWE-200](https://cwe.mitre.org/data/definitions/200.html), [CWE-285](https://cwe.mitre.org/data/definitions/285.html), [CWE-358](https://cwe.mitre.org/data/definitions/358.html), [CWE-359](https://cwe.mitre.org/data/definitions/359.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
