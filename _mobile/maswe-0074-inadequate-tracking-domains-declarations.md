---
title: "MASWE-0074: Inadequate Tracking Domains Declarations"
date: 2026-11-10 22:08:00 +0000
subcategory: privacy
summary: "Checking NSPrivacyTrackingDomains against the domains an app really contacts, with ATT denied and allowed, and Android's Data safety equivalent."
refs: [MASWE-0074, MASVS-PRIVACY-3, CWE-359]
tags: [android, ios, masvs-privacy, privacy-manifest, app-tracking-transparency, data-safety]
---

This note is part of our [MASVS-PRIVACY guide](/mobile/masvs-privacy-privacy-testing-guide/) and covers OWASP [MASWE-0074](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0074/): an app that contacts tracking domains without declaring them. On iOS this has a precise meaning. Since iOS 17, an app's privacy manifests (`PrivacyInfo.xcprivacy`) list the hosts it uses for tracking in `NSPrivacyTrackingDomains`, and the system blocks connections to those hosts when the user has not granted App Tracking Transparency (ATT) permission. The declaration is therefore not only a label: it is the input to an enforcement mechanism. Leave a domain out and the user's "Ask App Not to Track" stops applying to it. Android has no equivalent declaration and no network-level enforcement, so on Android we test the nearest thing: whether the tracking, advertising and attribution hosts the app talks to are reflected in the Data safety section. Below are the platform mechanisms, OWASP's one test (MASTG-TEST-0281), two Guler Tech tests (an iOS runtime comparison with ATT denied and allowed, and the Android Data safety mapping), and how to rate what you find.

> **Note:** This is technical testing guidance, not legal advice. Whether a data flow is "tracking" under a store's definition, or lawful under GDPR, PECR or the ePrivacy Directive, is for the client's legal team to decide; you provide the evidence.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Background](#background)
  - [iOS: what Apple counts as tracking](#ios-what-apple-counts-as-tracking)
  - [iOS: App Tracking Transparency](#ios-app-tracking-transparency)
  - [iOS: privacy manifests and tracking keys](#ios-privacy-manifests-and-tracking-keys)
  - [iOS: how the system blocks declared tracking domains](#ios-how-the-system-blocks-declared-tracking-domains)
  - [iOS: tools that show tracking domains](#ios-tools-that-show-tracking-domains)
  - [Android: no tracking domain declaration](#android-no-tracking-domain-declaration)
  - [Generic: tracker lists and their limits](#generic-tracker-lists-and-their-limits)
- [Tests](#tests)
  - [MASTG-TEST-0281: Undeclared Known Tracking Domains (iOS)](#mastg-test-0281-undeclared-known-tracking-domains-ios)
  - [GT-PRIV-0074-1: Tracking domains contacted with ATT denied and allowed (iOS)](#gt-priv-0074-1-tracking-domains-contacted-with-att-denied-and-allowed-ios)
  - [GT-PRIV-0074-2: Tracking domains against Data safety declarations (Android)](#gt-priv-0074-2-tracking-domains-against-data-safety-declarations-android)
- [Secure implementation](#secure-implementation)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

The OWASP requirement is *"The app adequately declares all tracking domains it connects to."* MASWE-0074 maps to **MASVS-PRIVACY-3** ("The app is transparent about data collection and usage") and to [CWE-359](https://cwe.mitre.org/data/definitions/359.html). It has no MASVS v1 ancestor (privacy manifests did not exist then) and replaces the beta weakness MASWE-0108. It carries OWASP's **P** and **EUDIW** profiles.

OWASP has one test, the iOS [MASTG-TEST-0281](https://mas.owasp.org/MASTG/tests/ios/MASVS-PRIVACY/MASTG-TEST-0281/), with no demo, no Knowledge item and no legacy tests to replace. The test is static plus a traffic capture; it does not compare behaviour with ATT denied and allowed, which is where the enforcement actually shows. OWASP has no Android test, because Android has nothing to declare tracking domains in. We add one test for each gap.

| Question | Platform | Test |
|---|---|---|
| Are all tracking domains found in code, SDKs and traffic listed in some `NSPrivacyTrackingDomains`? | iOS | [MASTG-TEST-0281](#mastg-test-0281-undeclared-known-tracking-domains-ios) |
| With ATT denied, does the app still reach tracking hosts, declared or not? Does the declaration actually block anything? | iOS | [GT-PRIV-0074-1](#gt-priv-0074-1-tracking-domains-contacted-with-att-denied-and-allowed-ios) (ours) |
| Are the tracking, advertising and attribution hosts the app contacts reflected in Data safety as shared or collected data? | Android | [GT-PRIV-0074-2](#gt-priv-0074-2-tracking-domains-against-data-safety-declarations-android) (ours) |

Keep the neighbours apart:

| Question | Where it lives |
|---|---|
| Do `NSPrivacyCollectedDataTypes`, the App Privacy label and the Data safety section match what the app collects? | [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/) |
| Which identifiers does the app use (IDFA, IDFV, Advertising ID, Android ID, own IDs), and are they used appropriately? | [MASWE-0068](/mobile/maswe-0068-incorrect-use-of-identifiers-for-tracking/) |
| Is the ATT prompt or the consent banner itself valid, and is the decision respected? | [MASWE-0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/) |
| Does the privacy policy name the tracking recipients? | [MASWE-0072](/mobile/maswe-0072-inadequate-privacy-policy/) |
| Which SDKs are in the app at all, and what do they do? | [MASWE-0048](/mobile/maswe-0048-malicious-code-included-in-the-app/), [third-party libraries](/mobile/mastg-know-0004-third-party-libraries/), [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/) |

## Modes of Introduction

OWASP names one mode: missing or incomplete declarations. These are the ways it happens:

**The app's manifest is missing or declares nothing.** The team added a manifest for the required-reason APIs to get past App Store Connect and left `NSPrivacyTracking` at `false` with no domains, although the app shows an ATT prompt and bundles advertising or attribution SDKs.

**The SDK's manifest is missing or out of date.** Tracking domains for an SDK are normally declared in the SDK's own manifest. An old SDK version without a manifest, an SDK linked as a static library (`.a`, which cannot carry resources), or a manifest the integrator stripped during a build fix leaves the SDK's tracking hosts undeclared.

**Hosts that change at runtime.** The SDK reads its endpoint from remote configuration or picks a regional host (`eu.`, `us.` prefixes, numbered shards). The manifest lists the hostnames the SDK vendor knew about at release time, not the ones served today.

**First-party hostnames for third-party tracking.** A subdomain of the app's own domain that is a CNAME to a tracking provider, or a first-party endpoint that forwards events and identifiers server-side. Neither looks like a tracker in the app, and declaring the first-party host would block legitimate API traffic, so it is left out. The declaration cannot fix server-side forwarding: that is tracking without permission, whatever the manifest says.

**Mixed-use hosts.** One hostname serves both tracking and functionality (configuration, crash upload, deep-link resolution). Declaring it breaks the feature for users who deny ATT, so it is left out. Apple's guidance is to split the functions onto separate hostnames.

**Web content.** Tracking scripts inside a `WKWebView` (an embedded checkout, a help centre, a marketing page) contact third-party hosts that nobody thought of as part of the app.

**On Android**: no declaration exists, so the mode is the Data safety form saying "no data shared" while ads, attribution or analytics SDKs send identifiers and events to their own servers.

## Impact

- **Tracking despite the user's refusal.** The iOS block applies only to declared hosts. An undeclared tracking host keeps receiving requests after the user tapped "Ask App Not to Track". The user believes they opted out and they did not. This is the core harm, and why we do not treat the declaration as paperwork.
- **Misleading declarations.** The privacy manifest, the App Privacy label ("Data Used to Track You") and the Data safety section are what users, reviewers and researchers rely on. A gap between them and the traffic is easy to show with tools that ship on every iPhone (App Privacy Report).
- **Store consequences.** Apple requires ATT permission for tracking (guideline 5.1.2(i)) and validates privacy manifests; Google requires accurate Data safety answers including SDK data. Discrepancies lead to rejection, update blocks or removal.
- **Regulatory exposure.** Tracking typically involves storing or reading identifiers on the device and sharing them with third parties, which in the UK and EU generally needs consent (PECR regulation 6, ePrivacy Art. 5(3), GDPR Art. 6 and 7). A user who refused ATT and is tracked anyway is the kind of fact a regulator understands immediately. The legal analysis is the client's.

## Mitigations

- **Declare every tracking host** in `NSPrivacyTrackingDomains`, in the app's manifest or the manifest of the SDK that contacts it, and set `NSPrivacyTracking` to `true` wherever tracking happens.
- **Keep SDKs current** and use versions that ship a privacy manifest (and a signature, for SDKs on Apple's list); do not strip SDK manifests from the bundle.
- **Split mixed-use hosts**: tracking on one hostname, functionality on another, and declare the tracking one.
- **Gate tracking in code as well**: do not initialise tracking features or send identifiers to tracking hosts until ATT is `authorized` (and, where consent is needed, until consent is given). The OS block is a backstop, not the design.
- **Do not route around the block** with first-party proxies, CNAMEs or server-side forwarding when the user has denied tracking.
- **On Android**, declare SDK data sharing in Data safety accurately, honour the Advertising ID controls, and gate SDKs behind consent.
- **Test it** each release with GT-PRIV-0074-1 and GT-PRIV-0074-2 below.

## Background

OWASP has no Knowledge item for this weakness. The sections below are ours.

### iOS: what Apple counts as tracking

Everything in this note turns on Apple's definition, from the [App Privacy details](https://developer.apple.com/app-store/app-privacy-details/) page and [User Privacy and Data Use](https://developer.apple.com/app-store/user-privacy-and-data-use/). In our words: **tracking** is linking data collected from your app about a particular user or device (a user ID, device ID or profile) with **third-party data** (data collected from apps, websites or offline properties you do not own) for targeted advertising or advertising measurement, or sharing data collected from your app about a user or device with a **data broker**.

Apple's examples include showing ads targeted with data from other companies' apps and websites, sharing location data or email lists with a data broker, sharing emails or advertising IDs with an ad network that retargets those users elsewhere, and, importantly for this note, **embedding a third-party SDK that combines your app's data with other developers' app data for ad targeting or measurement, even if you do not use it for that purpose yourself.**

Apple lists three things that are **not** tracking: data linked solely on the device and not sent off it in an identifying way; sharing with a data broker solely for fraud detection, prevention or security; and sharing with a consumer reporting agency for creditworthiness purposes.

Consequences for testing:

- **A host is a tracking domain because of what is done with the data**, not because of what the host is called or which list it appears on. A crash-reporting endpoint, a first-party analytics endpoint that never meets third-party data, or a payment provider's fraud check is normally not tracking. An attribution provider that matches installs across apps is.
- **The SDK's behaviour counts**, not just the app owner's intent.
- **Fingerprinting is not allowed at all.** Apple's user privacy page says that deriving data from a device (device characteristics, signals) to uniquely identify it is not allowed, whether or not the user grants ATT. If, with ATT denied, an attribution host receives a bundle of device characteristics instead of the IDFA, that is a finding for [MASWE-0068](/mobile/maswe-0068-incorrect-use-of-identifiers-for-tracking/) as well as here. You detect it from the app's own traffic; do not build fingerprinting tooling to "prove" it.

### iOS: App Tracking Transparency

The [AppTrackingTransparency](https://developer.apple.com/documentation/apptrackingtransparency) framework has been required for tracking since iOS 14.5 (April 2021). The app adds an `NSUserTrackingUsageDescription` string to `Info.plist` and calls `ATTrackingManager.requestTrackingAuthorization(completionHandler:)`. The status is one of:

| `ATTrackingManager.AuthorizationStatus` | Meaning | IDFA (`ASIdentifierManager.advertisingIdentifier`) |
|---|---|---|
| `notDetermined` | Not asked yet, or the prompt was dismissed without an answer | All zeros |
| `restricted` | Tracking restricted on the device (for example by a profile or parental controls) | All zeros |
| `denied` | User chose "Ask App Not to Track", or turned off "Allow Apps to Request to Track" | All zeros |
| `authorized` | User allowed tracking | Real IDFA |

Details that matter when testing:

- The system shows the prompt only when the app is active, and not at all when the user has turned off **Settings > Privacy & Security > Tracking > Allow Apps to Request to Track**; then the status is `denied` immediately.
- Per-app choices appear in the same Tracking screen and can be toggled there. Deleting and reinstalling the app resets it to `notDetermined`, which is how you get a clean state for each test run.
- Apple's documentation now notes regional differences: in some EU countries the system shows a full-page sheet instead of an alert, and in the EU an answered prompt cannot be shown again for a year. None of this changes the test, but it explains why prompts look different on test devices set to different regions.
- `denied` blocks the IDFA, not tracking as such. Tracking with other identifiers (IDFV, hashed email, account ID, fingerprints) is equally prohibited by Apple without permission, and it is exactly what an undeclared tracking domain lets through.

### iOS: privacy manifests and tracking keys

A privacy manifest is a property list named `PrivacyInfo.xcprivacy` (despite the extension, an ordinary plist) that an app or a third-party SDK includes as a resource. Apple's [Privacy manifest files](https://developer.apple.com/documentation/bundleresources/privacy-manifest-files) documentation defines four top-level keys:

| Key | Type | Meaning |
|---|---|---|
| `NSPrivacyTracking` | Boolean | The app or SDK uses data for tracking as defined under ATT. When `true`, you must list domains in `NSPrivacyTrackingDomains` |
| `NSPrivacyTrackingDomains` | Array of strings | The internet domains the app or SDK connects to that engage in tracking. If the user has not granted ATT permission, network requests to these domains fail and the app receives an error |
| `NSPrivacyCollectedDataTypes` | Array of dictionaries | Data types collected, linked or not, used for tracking or not, and purposes (tested in [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/)) |
| `NSPrivacyAccessedAPITypes` | Array of dictionaries | Required-reason APIs used and the reason codes (not a tracking declaration; see our [MASWE-0048](/mobile/maswe-0048-malicious-code-included-in-the-app/) note) |

Where manifests live in an iOS bundle ([Adding a privacy manifest to your app or third-party SDK](https://developer.apple.com/documentation/bundleresources/adding-a-privacy-manifest-to-your-app-or-third-party-sdk)):

- the app's own manifest at the root of the `.app` bundle: `App.app/PrivacyInfo.xcprivacy`;
- each framework's at the framework root: `App.app/Frameworks/SDK.framework/PrivacyInfo.xcprivacy`;
- Swift package and CocoaPods resources typically inside a resource bundle: `App.app/SDK_Privacy.bundle/PrivacyInfo.xcprivacy`;
- app extensions have their own: `App.app/PlugIns/Widget.appex/PrivacyInfo.xcprivacy`.

Static libraries (`.a`) cannot carry resources, so an SDK distributed that way has no manifest unless the vendor moved to a static framework or a resource bundle. That is a common reason for an SDK's tracking hosts to be missing.

**All manifests count.** Apple's WWDC23 session [Get started with privacy manifests](https://developer.apple.com/videos/play/wwdc2023/10060/) says iOS 17 blocks connections to tracking domains "specified in any privacy manifest included in your app". The app does not have to repeat an SDK's domains in its own manifest, but the tester has to read every manifest in the bundle to know the declared set.

Dates and enforcement (Apple has moved these before; check [third-party SDK requirements](https://developer.apple.com/support/third-party-SDK-requirements/) for the current state):

- Privacy manifests were introduced with Xcode 15 and iOS 17 (2023).
- From 1 May 2024, App Store Connect requires required-reason API declarations, and a manifest and signature for SDKs on Apple's list of commonly used SDKs when they are added to an app.
- From 12 February 2025, according to Apple's documentation, apps must contain a valid privacy manifest for a set of commonly used SDKs, and App Store Connect rejects submissions with invalid manifests (unexpected keys or values).

App Store Connect validates that manifests are well formed and checks the required-reason and listed-SDK rules. As far as Apple documents, **it does not check that `NSPrivacyTrackingDomains` is complete.** Completeness is what this note tests.

The Xcode **privacy report** (Organizer > Archives > control-click an archive > *Generate Privacy Report*) aggregates all manifests in an archive into a PDF organised like the App Privacy label. It is the quickest way to see collected data types across SDKs. It is a summary of declared data use; for tracking domains, read `NSPrivacyTrackingDomains` from the manifests directly, as in MASTG-TEST-0281.

### iOS: how the system blocks declared tracking domains

Apple's description is short: on iOS 17 and iPadOS 17 and later, if the user has not granted tracking permission, network requests to domains listed in `NSPrivacyTrackingDomains` fail and the app receives an error. A few points follow, some documented, some not:

- **"Not granted" includes `notDetermined`.** Read literally, requests to declared hosts fail before the user has answered the prompt too. That is what you want, and it is one of the things GT-PRIV-0074-1 confirms.
- **Only declared hosts are blocked.** The system does not infer tracking hosts and block them on its own, though it may flag them (see the tools below).
- **Matching rules are not documented.** Apple does not say whether a declared `tracker.example.com` also covers `eu.tracker.example.com`, or whether declaring `example.com` covers all subdomains. Declare the exact hostnames you see in traffic and verify with GT-PRIV-0074-1.
- **Coverage of networking stacks is not documented.** Apple says "network requests"; it does not list which APIs are covered. Requests through the URL Loading System and the Network framework are what Apple's own examples use. Test web content (`WKWebView`), and anything using its own sockets, empirically.
- **Developer reports are mixed.** Several Apple Developer Forums threads report declared domains not being blocked in some configurations, without an Apple answer. Treat the block as something to verify on a device, not as an assumption.
- **The block is a backstop.** Requests to declared hosts fail at the client, which also means that a mixed-use host that is declared breaks the functionality behind it. Apple's recommendation in the WWDC23 session is to separate tracking and non-tracking functions onto different hostnames (for example `tracking.example.com` and `api.example.com`) and declare only the tracking one.

### iOS: tools that show tracking domains

**App Privacy Report (on the device).** Available since iOS 15.2: *Settings > Privacy & Security > App Privacy Report > Turn On App Privacy Report*. The device keeps seven days of per-app data and sensor accesses and network activity. The Share button exports an NDJSON file, documented in [Inspecting app activity data](https://developer.apple.com/documentation/network/inspecting-app-activity-data). Each `networkActivity` record has `bundleID`, `domain`, `firstTimeStamp`, `timeStamp`, `hits`, `initiatedType` (`AppInitiated`, or `NonAppInitiated` for user-driven browsing such as `SFSafariViewController`), `domainOwner`, and **`domainType`**: `1` means Apple has identified the domain as "potentially collecting information across apps and sites, and potentially profiling users"; `2` means it has not. It works on App Store builds, needs no jailbreak and no proxy, and attributes traffic to the app. Its limits: domain granularity only (no paths or payloads), Apple's classification is opaque, and whether attempts blocked by the tracking-domain rule are recorded is not documented.

**Instruments, Points of Interest.** In the WWDC23 session Apple says that in Xcode 15 the Points of Interest instrument "now shows connections to domains that may be following people across multiple apps and websites to combine their activity into a profile", and an Apple engineer on the Developer Forums says such accesses show up there automatically. Use it when you have a development-signed build (Instruments needs to attach to the process, so a production App Store build will not work; ask the client for a development build or re-sign your test copy). Run the app under Instruments with the Points of Interest instrument (add it to a blank trace, or use a template that includes it), exercise it, and look for the tracking-domain events. Apple does not document exactly how the events are labelled, and forum reports describe them differently, so screenshot what you see and corroborate with the App Privacy Report.

**Traffic capture.** The OWASP test uses [Basic Network Monitoring/Sniffing (MASTG-TECH-0062)](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0062/): `rvictl -s <UDID>` on a Mac creates a remote virtual interface `rvi0` for a USB-connected device, and Wireshark or `tshark` captures everything on it. You do not need to decrypt TLS to get hostnames: DNS queries and the TLS SNI in each ClientHello name the host. The capture covers the whole device, not just the app, so filter carefully and pair it with the App Privacy Report. For payloads (which identifiers reach which host), use an intercepting proxy as in our [traffic interception lab](/mobile/mobile-traffic-interception-lab/).

### Android: no tracking domain declaration

Android has nothing equivalent to `NSPrivacyTrackingDomains`: no manifest element for tracking hosts, no OS-level tracking permission, and no system component that blocks an app's connections based on a user's tracking choice. What exists instead:

- **The Advertising ID**, controlled by Google Play services. Apps targeting Android 13 (API 33) or higher must declare `com.google.android.gms.permission.AD_ID` to read it; without it, or after the user deletes the ID (Settings > Privacy > Ads, or Settings > Google > Ads, depending on the device), the API returns a string of zeros. Google Play's [User Data policy](https://support.google.com/googleplay/android-developer/answer/10144311) also restricts linking the Advertising ID to persistent device identifiers or personal data without consent, and linking a reset ID to the old one. See [MASWE-0068](/mobile/maswe-0068-incorrect-use-of-identifiers-for-tracking/).
- **The Data safety section.** The developer declares, per data type, whether it is **collected** (transmitted off the device) and **shared** (transferred to a third party), and for which purposes, including "Advertising or marketing" and "Analytics". Google's [Data safety help](https://support.google.com/googleplay/android-developer/answer/10787469) says data transmitted by libraries and SDKs in the app counts, and that sending data from the device directly to a third party is sharing. Exceptions where a transfer is not declared as sharing: to a service provider processing on the developer's behalf, for legal purposes, on a specific user-initiated action, and fully anonymised data. Building advertising or user profiles cannot be treated as ephemeral processing.
- **Store-side lists and programmes**: Google Play's [SDK Index](https://play.google.com/sdks) describes the data practices of common SDKs; the Families policy restricts which ads SDKs apps for children may use.
- **Consent tooling**, such as a consent management platform, which gates SDKs in the app's own code. There is no OS backstop.

So on Android the transparency question becomes: given the hosts the app contacts and what it sends them, does the Data safety section say "shared" for the right data types and purposes, and does the privacy policy name the recipients? That is GT-PRIV-0074-2.

### Generic: tracker lists and their limits

OWASP's test uses curated tracker lists to decide which domains are "known tracking domains":

- **DuckDuckGo tracker blocklists** ([repository](https://github.com/duckduckgo/tracker-blocklists)): JSON files with a `trackers` object keyed by domain, each with an owner and, in the web and iOS lists, categories such as "Advertising", "Analytics", "Ad Motivated Tracking" and "Action Pixels". There is an iOS list (`web/v5/ios-tds.json`) and an app tracking protection list for Android (`app/android-tds.json`).
- **Exodus Privacy** ([trackers](https://reports.exodus-privacy.eu.org/en/trackers/), with a JSON API at `https://reports.exodus-privacy.eu.org/api/trackers`): each tracker has categories ("Advertisement", "Analytics", "Profiling", and others), a `network_signature` regular expression for hostnames and a `code_signature` for Java/Kotlin package prefixes. It was built for Android, which makes it a good fit for GT-PRIV-0074-2; the network signatures are useful on iOS too.

Use them as **candidate generators**, not verdicts. Lists are built for blocking in browsers and VPN-based blockers, so they include hosts that are not tracking under Apple's definition (crash reporting, first-party analytics, CDNs owned by advertising companies), and they miss first-party and CNAME-cloaked endpoints. Every match needs a judgement on purpose, and every non-match with suspicious payloads (identifiers, device signals going to a third party) needs a look.

## Tests

### MASTG-TEST-0281: Undeclared Known Tracking Domains (iOS)

OWASP page: [MASTG-TEST-0281](https://mas.owasp.org/MASTG/tests/ios/MASVS-PRIVACY/MASTG-TEST-0281/).

#### Overview

Platform: iOS. Type: static and dynamic.

The test collects every privacy manifest in the app, builds the declared set from their `NSPrivacyTrackingDomains`, and compares it with three sources of tracking candidates: hostnames hard-coded in the app and its frameworks, tracking SDKs identified in the bundle, and hosts contacted at runtime. Candidates are matched against curated tracker lists (DuckDuckGo, Exodus). Any tracking domain missing from all manifests is a fail.

#### Prerequisites

- The IPA. For string searches in the main binary you need a **decrypted** build: App Store binaries are FairPlay-encrypted (`otool -l App | grep -A4 LC_ENCRYPTION_INFO` shows `cryptid 1`). Ask the client for an unencrypted build, or decrypt your test copy on a jailbroken device. Framework binaries embedded in the bundle and all plist and JSON resources are readable either way.
- macOS with `plutil` and `PlistBuddy` (built in), Python 3, `jq`, radare2 (`r2`, `rabin2`).
- A test device on iOS 17 or later, with App Privacy Report turned on, and either `rvictl` plus Wireshark/`tshark` or an intercepting proxy.
- A copy of the tracker lists you will use, with their version or download date for the report.

#### Steps

1. **Extract the app package** ([MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/)). An IPA is a ZIP; the bundle is in `Payload/`:

   ```bash
   mkdir work && unzip -q App.ipa -d work && cd work/Payload
   ls App.app/Frameworks App.app/PlugIns 2>/dev/null
   ```

2. **Find networking APIs and tracking SDKs** ([MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), static analysis with radare2). The OWASP step looks for networking APIs (`URLSession`, `NSURLSession`, `NSURLConnection`, third-party networking libraries) and for references to known tracking libraries. In practice, the frameworks list and class names identify SDKs quickly:

   ```bash
   BIN=App.app/$(plutil -extract CFBundleExecutable raw App.app/Info.plist)
   rabin2 -i "$BIN" | grep -iE 'urlsession|nsurlconnection|nw_connection|CFNetwork' | head
   for f in App.app/Frameworks/*.framework; do
     n=$(basename "$f" .framework); echo "== $n"
     rabin2 -c "$f/$n" 2>/dev/null | grep -ciE 'track|attribution|advert|analytics|adid|idfa'
   done
   rabin2 -zz "$BIN" | grep -E 'ASIdentifierManager|ATTrackingManager|advertisingIdentifier'
   ```

   Statically linked SDKs show up as class names in the main binary (`rabin2 -c "$BIN"`), not as frameworks. `ASIdentifierManager` and `ATTrackingManager` references tell you the app or an SDK reads the IDFA and asks for tracking permission: then `NSPrivacyTracking` should be `true` somewhere.

3. **Search for hard-coded tracking hostnames** ([MASTG-TECH-0071](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0071/), retrieving strings). Pull URLs and hostnames from the main binary, every framework and every resource:

   ```bash
   { rabin2 -zz "$BIN"; for fw in App.app/Frameworks/*.framework; do rabin2 -zz "$fw/$(basename "$fw" .framework)" 2>/dev/null; done; \
     grep -rhaoE 'https?://[A-Za-z0-9.-]+' App.app --include='*.plist' --include='*.json' --include='*.js' --include='*.html'; } \
     | grep -oE 'https?://[A-Za-z0-9.-]+' | sed -E 's#https?://##' | tr 'A-Z' 'a-z' | sort -u > static-hosts.txt
   wc -l static-hosts.txt
   ```

   Hostnames built at runtime from parts, or served by remote configuration, will not appear; the dynamic step covers them.

4. **Retrieve all privacy manifests** ([MASTG-TECH-0136](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0136/)):

   ```bash
   find . -name PrivacyInfo.xcprivacy
   ```

   Expect one at `App.app/`, one per framework or resource bundle that has one, and one per extension in `PlugIns/`. Note SDKs from step 2 that have **no** manifest.

5. **Extract the declared tracking domains** ([MASTG-TECH-0137](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0137/), with [MASTG-TECH-0138](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0138/) for JSON conversion). With `plutil` and `jq`, keeping the source manifest:

   ```bash
   find . -name PrivacyInfo.xcprivacy -print0 | while IFS= read -r -d '' m; do
     plutil -convert json -o - "$m" | jq -r --arg m "$m" \
       '"\($m)\ttracking=\(.NSPrivacyTracking // false)\t\((.NSPrivacyTrackingDomains // []) | join(","))"'
   done
   ```

   Or with `PlistBuddy` for one file: `/usr/libexec/PlistBuddy -c "Print NSPrivacyTrackingDomains" App.app/PrivacyInfo.xcprivacy`. Record inconsistencies as you go: `NSPrivacyTracking` `true` with no domains (Apple requires domains when it is `true`), domains listed with `NSPrivacyTracking` `false`, and entries that are URLs rather than hostnames.

6. **Capture runtime traffic** ([MASTG-TECH-0062](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0062/)). Delete and reinstall the app, **allow** tracking at the ATT prompt (so declared hosts are not blocked and you see the full set), and exercise all features, including ads, sign-up, purchase flows and web content. Capture hostnames from DNS and TLS SNI:

   ```bash
   rvictl -s <UDID>
   tshark -i rvi0 -w run.pcapng          # stop with Ctrl-C when the script is done
   rvictl -x <UDID>
   tshark -r run.pcapng -Y 'dns.flags.response == 0 || tls.handshake.type == 1' \
     -T fields -e dns.qry.name -e tls.handshake.extensions_server_name | tr '\t' '\n' | grep . | sort -u > rvi-hosts.txt
   ```

   `rvi0` carries the whole device's traffic. Export the App Privacy Report as well and take the app's own domains, which removes system noise:

   ```bash
   jq -r 'select(.type=="networkActivity" and .bundleID=="com.example.app") | .domain' App_Privacy_Report.ndjson | sort -u > apr-hosts.txt
   jq -r 'select(.type=="networkActivity" and .bundleID=="com.example.app" and .domainType==1) | .domain' App_Privacy_Report.ndjson | sort -u
   ```

   The second command lists the domains Apple itself flags as potentially tracking; treat each as a candidate.

7. **Compare.** Merge the static and dynamic host lists and match them against the declared set and a tracker list. This read-only script (ours; OWASP has no demo for this test) does it:

   ```python
   #!/usr/bin/env python3
   """compare-tracking-domains.py PAYLOAD_DIR HOSTS_TXT [ios-tds.json]
   Matches contacted/static hosts against NSPrivacyTrackingDomains in every manifest
   and, optionally, against the DuckDuckGo iOS tracker list. Reads files only."""
   import json, plistlib, sys
   from pathlib import Path

   payload, hosts_file = Path(sys.argv[1]), Path(sys.argv[2])
   tds = json.load(open(sys.argv[3]))["trackers"] if len(sys.argv) > 3 else {}

   declared = {}
   for m in payload.rglob("PrivacyInfo.xcprivacy"):
       with m.open("rb") as fp:
           pl = plistlib.load(fp)
       for d in pl.get("NSPrivacyTrackingDomains", []):
           declared.setdefault(d.lower().rstrip("."), []).append(str(m.relative_to(payload)))

   def suffixes(host):
       parts = host.split(".")
       return [".".join(parts[i:]) for i in range(len(parts) - 1)]

   hosts = sorted({h.strip().lower().rstrip(".") for h in hosts_file.read_text().split() if h.strip()})
   for host in hosts:
       parent = next((s for s in suffixes(host)[1:] if s in declared), None)
       listed = next((s for s in suffixes(host) if s in tds), None)
       if host in declared:
           status = "declared"
       elif parent:
           status = "parent-declared:" + parent
       else:
           status = "NOT-declared"
       cats = ",".join(tds[listed].get("categories", [])) if listed else ""
       print("\t".join([host, status, "list:" + listed if listed else "-", cats]))

   for d, where in sorted(declared.items()):
       if d not in hosts:
           print("\t".join([d, "declared-not-seen", ";".join(where), ""]))
   ```

   ```bash
   cat static-hosts.txt rvi-hosts.txt apr-hosts.txt | sort -u > all-hosts.txt
   python3 -I compare-tracking-domains.py . all-hosts.txt ios-tds.json | sort -k2 > comparison.tsv
   ```

   Every `NOT-declared` row with a tracker-list match, a `domainType` of 1, or a payload carrying identifiers to a third party is a candidate. Confirm its purpose against Apple's definition (vendor documentation, the SDK's role in the app, what the payload contains). `parent-declared` rows depend on undocumented matching rules: resolve them in GT-PRIV-0074-1.

#### Observation

- All `PrivacyInfo.xcprivacy` files, with the `NSPrivacyTracking` value and `NSPrivacyTrackingDomains` of each, and the SDKs that have no manifest.
- The static host list and the SDK and API matches.
- The runtime capture and the list of contacted domains (rvi0 and App Privacy Report).
- The comparison table, with your purpose assessment for each candidate.

#### Evaluation

OWASP's criterion: the test **fails** if any of the following is missing from the `NSPrivacyTrackingDomains` of the app or any of its components (frameworks, plug-ins and so on):

- tracking domains contacted by the app at runtime;
- tracking domains found in the code;
- domains corresponding to tracking SDKs found in the code.

How we apply it:

- "Tracking domain" means a domain used for tracking **as Apple defines it**, not a domain that appears on a blocklist. A list match that you have confirmed is not tracking (crash reporting, first-party analytics with no third-party linking, fraud prevention) is a pass, with the reasoning recorded.
- A domain declared in an SDK's manifest counts as declared; the app does not need to repeat it.
- An SDK that is used for tracking, contacts its hosts, and has no manifest at all is a fail even if you only saw its hosts with ATT allowed.
- `NSPrivacyTracking` `true` with an empty domain list, or a tracking SDK present with every manifest saying `false`, is a fail on its own: the declaration is internally wrong.
- Declared domains never seen at runtime are not a fail. Note them; they may be dead entries or features you did not exercise.

The test **passes** when every confirmed tracking host, static or dynamic, appears in some manifest's `NSPrivacyTrackingDomains`, and the `NSPrivacyTracking` flags are consistent with it.

#### Demo

OWASP has no demo for this test; the following is our illustration. A main-app manifest declaring one first-party tracking host:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>NSPrivacyTracking</key>
    <true/>
    <key>NSPrivacyTrackingDomains</key>
    <array>
        <string>trk.example.com</string>
    </array>
    <key>NSPrivacyCollectedDataTypes</key>
    <array/>
    <key>NSPrivacyAccessedAPITypes</key>
    <array/>
</dict>
</plist>
```

Illustrative output of the manifest listing (step 5):

```text
./App.app/PrivacyInfo.xcprivacy                               tracking=true   trk.example.com
./App.app/Frameworks/AnalyticsKit.framework/PrivacyInfo.xcprivacy  tracking=false
./App.app/AttributionSDK_Privacy.bundle/PrivacyInfo.xcprivacy tracking=true   attr.example.net
```

and of `comparison.tsv` (step 7):

```text
api.example.com          NOT-declared  -                           -
attr.example.net         declared      list:example.net            Advertising,Ad Motivated Tracking
events.adnet.example.org NOT-declared  list:adnet.example.org      Advertising
eu.trk.example.com       parent-declared:trk.example.com  -        -
trk.example.com          declared      -                           -
```

`api.example.com` is the app's own API: not declared, no list match, no identifiers going to a third party, so not a candidate. The `events.adnet.example.org` row is a fail if the ad SDK that calls it uses data for targeting or measurement across apps, which is what an ad network does. `eu.trk.example.com` goes to GT-PRIV-0074-1 to check whether the parent declaration actually blocks it.

### GT-PRIV-0074-1: Tracking domains contacted with ATT denied and allowed (iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Platform: iOS. Type: dynamic.

MASTG-TEST-0281 tells you what is declared. This test tells you what happens. You run the same script twice on a clean install, once with tracking denied (and once more with the prompt left unanswered if the app sends traffic before it asks), once with tracking allowed, and compare the hosts reached and the identifiers sent. It answers three questions: does any tracking traffic leave the app when the user said no; does the OS block the declared hosts in practice; and does the app route around the block.

#### Prerequisites

- A test device on iOS 17 or later that you control, with App Privacy Report on and an intercepting proxy configured as in our [traffic interception lab](/mobile/mobile-traffic-interception-lab/) (pinning bypass on the test build if needed).
- The declared domain set from MASTG-TEST-0281 step 5.
- A written test script (screens, actions, waits) so both runs are comparable. Analytics and attribution SDKs batch and delay uploads: keep the app in the foreground for several minutes, background and foreground it, and relaunch it at least once.
- Optional: a development-signed build for Instruments.

#### Steps

1. **Reset.** Turn App Privacy Report off and on again (this clears it). Delete the app. Check *Settings > Privacy & Security > Tracking*: "Allow Apps to Request to Track" on.

2. **Run A: ATT not determined, then denied.** Install, start the proxy recording (`mitmdump -w run-a.flows`), launch the app and **do not answer** the ATT prompt for as long as the app lets you use it; note when the prompt appears. Then tap *Ask App Not to Track* and run the script. Export the App Privacy Report as `apr-a.ndjson` and stop the capture.

3. **Run B: ATT allowed.** Repeat step 1, install, launch, tap *Allow*, run the same script, export `apr-b.ndjson`, save `run-b.flows`.

4. **Run C (optional): global switch off.** With "Allow Apps to Request to Track" off, the prompt never appears and the status is `denied`. Some SDKs behave differently when the prompt never shows. Run it if time allows.

5. **Extract hosts per run.** From the App Privacy Report and from the proxy:

   ```bash
   for r in a b; do
     jq -r 'select(.type=="networkActivity" and .bundleID=="com.example.app") | "\(.domain)\t\(.domainType)\t\(.hits)"' apr-$r.ndjson | sort -u > apr-$r.tsv
     mitmdump -q -n -r run-$r.flows -s list-hosts.py | sort | uniq -c | sort -rn > proxy-$r.txt
   done
   comm -13 <(cut -f1 apr-a.tsv | sort -u) <(cut -f1 apr-b.tsv | sort -u)   # only with ATT allowed
   comm -12 <(cut -f1 apr-a.tsv | sort -u) <(cut -f1 apr-b.tsv | sort -u)   # in both runs
   ```

   where `list-hosts.py` is a two-line mitmproxy addon:

   ```python
   # list-hosts.py - print host and path of each request in a saved capture
   def request(flow):
       print(flow.request.pretty_host + "\t" + flow.request.path.split("?")[0])
   ```

6. **Check the declared hosts in run A.** For each declared domain (and each `parent-declared` host from MASTG-TEST-0281), look for it in `proxy-a.txt`. A request that reached the proxy got past the client; that means the OS did not block it. If the app logs errors, or you can attach Instruments to a development build, note the failure the app received for blocked requests.

7. **Check the payloads of the shared hosts.** For hosts present in both runs, compare what is sent. Use the field-name logger from our [MASWE-0072 note](/mobile/maswe-0072-inadequate-privacy-policy/) or inspect flows in mitmproxy's UI. Look for: the IDFA (should be all zeros in run A), the IDFV, account IDs, hashed emails or phone numbers, and bundles of device characteristics (model, OS build, screen, locale, time zone, uptime, storage, battery) sent to advertising or attribution hosts in run A.

8. **Look for routing around the block.** In run A, check first-party hosts for requests whose payload mirrors what an SDK sent to its tracking host in run B (same event names and identifiers, now to `collect.example.com`), and resolve unfamiliar first-party subdomains (`dig +short CNAME metrics.example.com`) to see whether they point at a tracking provider.

9. **Instruments (if you have a development build).** Profile with the Points of Interest instrument during run A and B, and note any tracking-domain events and their hosts.

#### Observation

Host lists per run with Apple's `domainType`, the hosts only in run B, the hosts in both, the per-host payload comparison for shared hosts, the result for each declared host in run A (blocked or reached), any CNAME or first-party forwarding found, and Instruments events if available.

#### Evaluation

The test **fails** if, in run A (ATT not determined or denied):

- the app reaches a host used for tracking under Apple's definition that is **not declared** in any manifest;
- a **declared** host is reached (the request arrives at the proxy), meaning the declaration does not block it in practice: typically a hostname that differs from the declared one, web content, or a networking path the block does not cover;
- the app sends identifiers or device signals to an advertising or attribution host, or to a first-party endpoint that forwards them to one, in a way that allows tracking without permission (this is also an Apple 5.1.2 issue and a [MASWE-0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/) finding);
- a first-party hostname that is a CNAME to a tracking provider receives tracking traffic.

It **passes** if in run A no tracking host is reached, every declared host is blocked or never called, and the hosts reached in both runs receive no tracking identifiers or fingerprinting signals. Hosts that appear only in run B are expected; check that they are all declared (that is MASTG-TEST-0281's job, but this run often finds hosts the static pass missed).

Common false positives:

- **Attribution in privacy-preserving mode.** With ATT denied, attribution SDKs often switch to Apple's SKAdNetwork or AdAttributionKit and send aggregated or coarse data to a non-tracking hostname. Postbacks to ad networks under those frameworks are sent by the system, not the app. A request to a separate, undeclared hostname of the same vendor is not automatically a fail: check the payload for identifiers.
- **Configuration and consent calls.** SDKs fetch remote configuration or the consent state at start-up. These are functional if they carry no persistent identifier beyond what is needed.
- **`NonAppInitiated` entries** in the App Privacy Report come from user browsing in `SFSafariViewController` and similar; they are not the app's own traffic.

#### Demo

Illustrative extract of the comparison:

```text
# hosts only with ATT allowed (comm -13)
attr.example.net
events.adnet.example.org

# hosts in both runs (comm -12)
api.example.com
config.adnet.example.org
eu.trk.example.com
```

`events.adnet.example.org` appears only in run B, so the app or SDK gates it correctly; if MASTG-TEST-0281 found it undeclared, that is still a declaration gap but with no tracking observed while denied (see [Rating findings](#rating-findings)). `eu.trk.example.com` appears in run A although `trk.example.com` is declared: the parent declaration did not block the subdomain. Illustrative flow from run A:

```text
POST https://eu.trk.example.com/v1/event
  idfa: 00000000-0000-0000-0000-000000000000
  idfv: 6F1C...redacted
  user_id: test-user-0042
  event: purchase
```

The IDFA is zeroed, but the IDFV and the account ID still go to a host the client itself declared as tracking. That fails: the user denied tracking and the data flowed anyway, through a hostname the declaration does not cover. The fix is to declare `eu.trk.example.com` explicitly and to stop sending tracking events when the status is not `authorized`.

### GT-PRIV-0074-2: Tracking domains against Data safety declarations (Android)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Platform: Android. Type: static and dynamic.

The Android counterpart of MASTG-TEST-0281. There is no tracking-domain declaration to check, so this test maps the tracking, advertising, attribution and analytics hosts the app contacts, and the data it sends them, to the **Data safety** section's "Data shared" and "Data collected" entries and to the Advertising ID controls. It also checks the consent-declined state, because on Android nothing but the app's own code stops the traffic.

#### Prerequisites

- The APK (or the base and split APKs pulled from a test device with `adb shell pm path com.example.app` and `adb pull`).
- `jadx` or `apkanalyzer`, `aapt2`, Python 3, `mitmproxy`, and optionally [PCAPdroid](https://github.com/emanuele-f/PCAPdroid), an open-source per-app capture tool built on Android's `VpnService` that records hostnames (DNS and SNI) for one app without root.
- A test device with a test Google account and the proxy configured ([traffic interception lab](/mobile/mobile-traffic-interception-lab/)); pinning bypass on the test build if needed.
- The Exodus trackers JSON (`https://reports.exodus-privacy.eu.org/api/trackers`) and optionally DuckDuckGo's `android-tds.json`.
- The app's Data safety section (Play listing > *Data safety* > *See details*), saved with the date.

#### Steps

1. **Identify SDKs statically.** List defined packages and match Exodus code signatures:

   ```bash
   apkanalyzer dex packages --defined-only app-release.apk | awk '$1=="P" {print $NF}' | sort -u > packages.txt
   aapt2 dump permissions app-release.apk | grep -E 'AD_ID|ACCESS_ADSERVICES|INTERNET'
   ```

   ```python
   #!/usr/bin/env python3
   """exodus-match.py exodus.json packages.txt hosts.txt - read-only matching against Exodus signatures"""
   import json, re, sys
   trackers = json.load(open(sys.argv[1]))["trackers"].values()
   packages = [l.strip() for l in open(sys.argv[2]) if l.strip()]
   hosts = [l.strip().lower() for l in open(sys.argv[3]) if l.strip()]
   for t in trackers:
       cats = ",".join(t.get("categories", []))
       code = [s for s in (t.get("code_signature") or "").split("|") if s]
       net = t.get("network_signature") or ""
       pk = sorted({p for p in packages for s in code if p.startswith(s.rstrip("."))})
       try:
           hs = sorted({h for h in hosts if net and re.search(net, h)})
       except re.error:
           hs = []
       if pk or hs:
           print("\t".join([t["name"], cats, "code:" + ",".join(pk[:3]) if pk else "-", "net:" + ",".join(hs) if hs else "-"]))
   ```

   A declared `com.google.android.gms.permission.AD_ID` tells you the app (or an SDK's merged manifest) intends to read the Advertising ID. Its absence on a `targetSdk` 33+ app means the ID reads as zeros.

2. **Capture in two states.** Fresh install each time.
   - **Run A, declined:** decline every optional consent in the app's consent screen, and on the device delete the Advertising ID (Settings > Privacy > Ads, or Settings > Google > Ads). Run your script.
   - **Run B, accepted:** accept all consents, keep an Advertising ID. Run the same script.

   Record with mitmproxy (`mitmdump -w run-a.flows`), and optionally run PCAPdroid filtered to the app to catch hosts that bypass the proxy (non-HTTP, QUIC, pinned connections that fail through the proxy). Extract host lists as in GT-PRIV-0074-1.

3. **Classify hosts.** Run `exodus-match.py` on the union of hosts; add DuckDuckGo's `android-tds.json` matches by domain suffix if you use it. For each candidate, decide the category (advertising, attribution, analytics, crash reporting, functional) from the SDK's role and the payload.

4. **Record what each candidate host receives.** Field names (Advertising ID, App set ID, Android ID, account IDs, hashed email, location, installed-app data, events) per host and per run, using the field-name logger from our [MASWE-0072 note](/mobile/maswe-0072-inadequate-privacy-policy/). With the Advertising ID deleted, check whether another persistent identifier takes its place in requests to ad or attribution hosts.

5. **Map to Data safety.** For each candidate host and data type, find the matching Data safety entry:

   | Host (category) | Data types sent | Run | Data safety: collected? | Data safety: shared? purpose | Policy names recipient? |
   |---|---|---|---|---|---|

   Apply Google's definitions: data sent by an SDK directly to its provider is **shared** unless an exception applies (a service provider processing only on the developer's behalf, legal purposes, a user-initiated action, fully anonymised data). An analytics provider acting purely as the developer's processor can be "collected, not shared"; an advertising or attribution network that uses the data across apps is shared, with "Advertising or marketing" as a purpose.

#### Observation

The SDK and host classification, the per-host data types for both runs, the Data safety entries, and the completed mapping table.

#### Evaluation

The test **fails** if:

- data reaches an advertising, attribution or tracking host and the corresponding data type is not declared as shared (or the section says "No data shared with third parties");
- the declared purposes omit "Advertising or marketing" for data that goes to advertising or attribution providers, or "Analytics" for analytics flows;
- in run A (consents declined), identifiers or events reach advertising or attribution hosts where the app's own consent screen or privacy policy says they will not ([MASWE-0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/));
- after Advertising ID deletion, a persistent identifier such as the Android ID is sent to advertising hosts in its place (also [MASWE-0068](/mobile/maswe-0068-incorrect-use-of-identifiers-for-tracking/), and against Google Play's Advertising ID rules).

It **passes** if every tracking, advertising and attribution flow observed has a matching shared entry with the right data type and purpose, and the declined state sends them nothing beyond what the policy and consent screen describe. Data safety answers that over-declare are not a fail; note them for [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/).

#### Demo

Illustrative `exodus-match.py` output (tracker names replaced by categories):

```text
<analytics SDK>     Analytics                code:com.example.analytics   net:events.analytics.example
<attribution SDK>   Analytics,Profiling      code:com.example.attrib      net:attr.example.net
<ads SDK>           Advertisement            code:com.example.ads         net:ads.adnet.example.org,events.adnet.example.org
```

Mapping extract:

| Host (category) | Data types sent | Run | Collected? | Shared? purpose | Result |
|---|---|---|---|---|---|
| `attr.example.net` (attribution) | Device or other IDs (Android ID), app interactions | A and B | Yes | Not declared | Fail: shared with an attribution provider, and Android ID sent in run A after Advertising ID deletion |
| `events.adnet.example.org` (ads) | Device or other IDs (Advertising ID), approximate location | B only | Yes | Yes, Advertising or marketing | Pass |
| `events.analytics.example` (analytics, processor) | App interactions, crash logs | A and B | Yes, Analytics | No (service provider) | Pass, if the contract confirms processor role |

## Secure implementation

No OWASP best practice exists for this weakness; ours:

- **Inventory first.** Keep a list of every SDK, its hosts, what it sends, and whether it tracks under Apple's definition. The privacy manifests, App Privacy label, Data safety section and privacy policy are all generated from it ([MASWE-0072](/mobile/maswe-0072-inadequate-privacy-policy/), [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/)).
- **Use SDK versions that ship privacy manifests** with their tracking domains, as frameworks or resource bundles, not static libraries without resources. Read each SDK's manifest when you update it.
- **Declare your own tracking hosts** in the app's manifest:

  ```xml
  <key>NSPrivacyTracking</key>
  <true/>
  <key>NSPrivacyTrackingDomains</key>
  <array>
      <string>trk.example.com</string>
      <string>eu.trk.example.com</string>
  </array>
  ```

  List exact hostnames, including regional variants; do not rely on a parent domain until you have verified that the block covers subdomains.
- **Split hostnames** so that configuration, crash reporting and other functions never share a hostname with tracking.
- **Gate in code.** Initialise tracking features only when ATT is `authorized` and consent (where required) is given, and re-check on each launch because the user can change it in Settings:

  ```swift
  import AppTrackingTransparency

  // ConsentStore and TrackingSDK stand for your consent layer and the SDK's own API
  func configureTracking() {
      guard ATTrackingManager.trackingAuthorizationStatus == .authorized,
            ConsentStore.shared.advertisingConsent else {
          TrackingSDK.disable()     // no identifiers, no tracking endpoints
          return
      }
      TrackingSDK.enable()
  }
  ```

- **No workarounds.** Do not forward events to a tracker server-side, through a first-party proxy or a CNAME, when the user has denied tracking; do not replace the IDFA or Advertising ID with other identifiers or device signals.
- **Android**: gate SDK initialisation behind consent, declare `AD_ID` only if you need it, honour Advertising ID deletion, and declare SDK sharing in Data safety with the right purposes.
- **Release check**: on each release, compare the merged `NSPrivacyTrackingDomains` with an App Privacy Report export from a denied-ATT test run, and fail the release on any undeclared tracking host.

## Rating findings

The series-wide rule applies: rate by what personal data is processed beyond what is declared or consented, how sensitive it is, the scale, and whether it contradicts the app's declarations or store policy. Regulatory risk is the client's legal team's call.

| Rating | Conditions |
|---|---|
| **High** | With ATT denied (iOS) or consent declined (Android), tracking identifiers or sensitive data (precise location, contact data, health or financial signals, children's data) reach a tracking host, through an undeclared domain, a subdomain the declaration does not cover, a CNAME or server-side forwarding; device-signal bundles sent to attribution hosts in place of a denied IDFA; on Android, sensitive data shared with ad networks while Data safety says nothing is shared |
| **Medium** | Undeclared tracking hosts receiving ordinary device and event data with ATT denied; a tracking SDK with no manifest, or `NSPrivacyTracking` `false` throughout while tracking SDKs are active; Data safety omitting "shared" or the advertising purpose for ad or attribution flows of ordinary data |
| **Low** | Tracking hosts missing from `NSPrivacyTrackingDomains` but only contacted after ATT is `authorized` (the app gates correctly, so the gap is the missing backstop and the review risk); minor Data safety purpose mismatches for data that is declared as shared |
| **Info** | Tracker-list matches confirmed not to be tracking; declared domains never contacted; over-declaration; `NonAppInitiated` browsing traffic |

Raise a level for apps aimed at children or handling special-category data, and when the app's own ATT prompt text or consent screen promises something the traffic contradicts. Lower a level when the only evidence is static (a hostname string in a framework never seen in traffic) and you could not confirm the SDK is active.

In the report give: the manifests and declared domains (with paths), the host comparison per run, the exact request that proves each flow (host, path, field names, run, ATT state), your reasoning on why each host is tracking under Apple's definition (or Google's sharing definition), and the fix (declaration, hostname split, code gating, Data safety change).

## References

- OWASP MASWE: [MASWE-0074: Inadequate Tracking Domains Declarations](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0074/); related [MASWE-0072](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0072/), [MASWE-0073](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0073/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-PRIVACY-3](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-3/) (CC BY-SA 4.0)
- OWASP MASTG tests: [MASTG-TEST-0281](https://mas.owasp.org/MASTG/tests/ios/MASVS-PRIVACY/MASTG-TEST-0281/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0062](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0062/), [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0071](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0071/), [MASTG-TECH-0136](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0136/), [MASTG-TECH-0137](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0137/), [MASTG-TECH-0138](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0138/) (CC BY-SA 4.0)
- OWASP MASTG tools: [radare2 (MASTG-TOOL-0073)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/), [rabin2 (MASTG-TOOL-0129)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/), [Wireshark (MASTG-TOOL-0081)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0081/), [plutil (MASTG-TOOL-0062)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0062/), [PlistBuddy (MASTG-TOOL-0135)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0135/), [plistlib (MASTG-TOOL-0136)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0136/) (CC BY-SA 4.0)
- Sibling notes: [PRIVACY hub](/mobile/masvs-privacy-privacy-testing-guide/), [MASWE-0068](/mobile/maswe-0068-incorrect-use-of-identifiers-for-tracking/), [MASWE-0072](/mobile/maswe-0072-inadequate-privacy-policy/), [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/), [MASWE-0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/); also [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/), [MASWE-0048](/mobile/maswe-0048-malicious-code-included-in-the-app/), [third-party libraries](/mobile/mastg-know-0004-third-party-libraries/), [traffic interception lab](/mobile/mobile-traffic-interception-lab/)
- Apple: [Privacy manifest files](https://developer.apple.com/documentation/bundleresources/privacy-manifest-files), [`NSPrivacyTracking`](https://developer.apple.com/documentation/bundleresources/app-privacy-configuration/nsprivacytracking), [`NSPrivacyTrackingDomains`](https://developer.apple.com/documentation/bundleresources/app-privacy-configuration/nsprivacytrackingdomains), [Adding a privacy manifest to your app or third-party SDK](https://developer.apple.com/documentation/bundleresources/adding-a-privacy-manifest-to-your-app-or-third-party-sdk), [Third-party SDK requirements](https://developer.apple.com/support/third-party-SDK-requirements/), [App Tracking Transparency](https://developer.apple.com/documentation/apptrackingtransparency), [`requestTrackingAuthorization(completionHandler:)`](https://developer.apple.com/documentation/apptrackingtransparency/attrackingmanager/requesttrackingauthorization%28completionhandler%3A%29), [App Privacy details](https://developer.apple.com/app-store/app-privacy-details/), [User Privacy and Data Use](https://developer.apple.com/app-store/user-privacy-and-data-use/), [App Review Guidelines 5.1.2](https://developer.apple.com/app-store/review/guidelines/#5.1.2), [Inspecting app activity data](https://developer.apple.com/documentation/network/inspecting-app-activity-data), WWDC23 [Get started with privacy manifests](https://developer.apple.com/videos/play/wwdc2023/10060/), Developer Forums [Tracking domains - Network Instrument Points of Interest](https://developer.apple.com/forums/thread/748533)
- Google: [User Data policy](https://support.google.com/googleplay/android-developer/answer/10144311), [Data safety section](https://support.google.com/googleplay/android-developer/answer/10787469), [Google Play SDK Index](https://play.google.com/sdks)
- Tracker lists and tools: [DuckDuckGo tracker blocklists](https://github.com/duckduckgo/tracker-blocklists), [Exodus Privacy trackers](https://reports.exodus-privacy.eu.org/en/trackers/), [PCAPdroid](https://github.com/emanuele-f/PCAPdroid)
- CWE: [CWE-359](https://cwe.mitre.org/data/definitions/359.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
