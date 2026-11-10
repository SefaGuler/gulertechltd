---
title: "MASWE-0068: Incorrect Use of Identifiers for User Tracking"
date: 2026-11-10 22:02:00 +0000
subcategory: privacy
summary: "Which device, advertising and app identifiers an app reads, when, and where it sends them: testing tracking, consent, ATT and reset bridging."
refs: [MASWE-0068, MASVS-PRIVACY-2, CWE-359]
tags: [android, ios, masvs-privacy, tracking, identifiers, att]
---

This note is part of our [MASVS-PRIVACY guide](/mobile/masvs-privacy-privacy-testing-guide/) and covers OWASP [MASWE-0068](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0068/): an app, or an SDK inside it, that uses identifiers in a way that lets people be recognised over time and across apps without their knowledge or consent. Both platforms have spent a decade closing the worst doors. Hardware IDs are gone for ordinary apps, advertising IDs can be deleted or are zero without permission, and `ANDROID_ID` and the IDFV are scoped. So the findings today are mostly about *use*, not access. Typical cases: the advertising ID read before the user has answered the consent banner; the IDFV or a keychain UUID sent to an attribution partner after the user tapped "Ask App Not to Track"; an install ID that survives reinstall through backup or the keychain and quietly re-links a user who reset everything; an SDK that bundles boot time, disk size and a dozen device properties into one request. OWASP has no tests and no Knowledge items for this weakness. Below you get the identifier landscape on both platforms with the version behaviour that matters, the store rules, four tests of our own (static inventory, runtime trace against consent, identifiers in traffic, reset and persistence), the implementation patterns that fix it, and how to rate what you find.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Background](#background)
  - [Android and iOS: what makes an identifier a tracking risk](#android-and-ios-what-makes-an-identifier-a-tracking-risk)
  - [Android: Advertising ID](#android-advertising-id)
  - [Android: App Set ID, Android ID (SSAID), Firebase installation ID and app-generated IDs](#android-app-set-id-android-id-ssaid-firebase-installation-id-and-app-generated-ids)
  - [Android: non-resettable hardware identifiers](#android-non-resettable-hardware-identifiers)
  - [Android: Google Play policy on identifiers](#android-google-play-policy-on-identifiers)
  - [Android: Privacy Sandbox status](#android-privacy-sandbox-status)
  - [iOS: IDFA and App Tracking Transparency](#ios-idfa-and-app-tracking-transparency)
  - [iOS: IDFV, DeviceCheck and keychain-persisted identifiers](#ios-idfv-devicecheck-and-keychain-persisted-identifiers)
  - [iOS: SKAdNetwork and AdAttributionKit](#ios-skadnetwork-and-adattributionkit)
  - [Android and iOS: fingerprinting and Apple's required-reason APIs](#android-and-ios-fingerprinting-and-apples-required-reason-apis)
  - [Android and iOS: legal context](#android-and-ios-legal-context)
- [Tests](#tests)
  - [GT-PRIV-0068-1: Static inventory of identifier APIs (Android and iOS)](#gt-priv-0068-1-static-inventory-of-identifier-apis-android-and-ios)
  - [GT-PRIV-0068-2: Runtime trace of identifier reads relative to consent and ATT (Android and iOS)](#gt-priv-0068-2-runtime-trace-of-identifier-reads-relative-to-consent-and-att-android-and-ios)
  - [GT-PRIV-0068-3: Identifiers in outgoing traffic and their destinations (Android and iOS)](#gt-priv-0068-3-identifiers-in-outgoing-traffic-and-their-destinations-android-and-ios)
  - [GT-PRIV-0068-4: Identifier reset and persistence behaviour (Android and iOS)](#gt-priv-0068-4-identifier-reset-and-persistence-behaviour-android-and-ios)
- [Secure implementation](#secure-implementation)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

The OWASP requirement is *"The app does not use persistent or unique identifiers in a way that enables user tracking."* MASWE-0068 maps to **MASVS-PRIVACY-2** ("The app prevents identification of the user"), to [CWE-359](https://cwe.mitre.org/data/definitions/359.html) (Exposure of Private Personal Information to an Unauthorized Actor), and to the Android core app quality item `Hardware_IDs`. In OWASP's beta numbering it was MASWE-0110. It carries the **P** and **EUDIW** profiles.

The PRIVACY-2 control text also asks for "technical barriers" around fingerprint-like signals (device IDs, IP addresses, behavioural patterns): a signal collected for fraud detection must not be repurposed for audience measurement. That is directly testable, and it is the reason this note looks at *where identifiers go*, not just which ones are read.

**OWASP has no tests and no Knowledge items for MASWE-0068**, and there are no legacy v1 tests to replace. The `## Background` section and the four `GT-PRIV-0068-x` tests are Guler Tech methodology.

This is technical testing guidance, not legal advice. It tells you what to look for and what evidence to hand to the client's DPO or legal team, who decide whether a given use is lawful.

What is covered, and by which test:

| Question | Test |
|---|---|
| Which identifier APIs and identifier-related permissions are in the app and its SDKs? | [GT-PRIV-0068-1](#gt-priv-0068-1-static-inventory-of-identifier-apis-android-and-ios) |
| Which identifiers are actually read, by which code, and when relative to the consent banner and the ATT prompt? | [GT-PRIV-0068-2](#gt-priv-0068-2-runtime-trace-of-identifier-reads-relative-to-consent-and-att-android-and-ios) |
| Which identifiers leave the device, to which hosts, together with what? | [GT-PRIV-0068-3](#gt-priv-0068-3-identifiers-in-outgoing-traffic-and-their-destinations-android-and-ios) |
| Does a reset (ad ID deletion, reinstall, ATT denial) actually give the user a fresh start? | [GT-PRIV-0068-4](#gt-priv-0068-4-identifier-reset-and-persistence-behaviour-android-and-ios) |

Keep the neighbours apart:

| Question | Where it lives |
|---|---|
| Personal data (emails, phone numbers, location) and hashes of it in payloads; whether "anonymised" data is | [MASWE-0067](/mobile/maswe-0067-lack-of-anonymization-or-pseudonymisation/) |
| Whether the consent banner and ATT pre-prompt are fair and valid | [MASWE-0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/) |
| Whether tracking is off until the user turns it on | [MASWE-0071](/mobile/maswe-0071-inadequate-privacy-defaults/) |
| Whether "Device or other IDs" and tracking are declared in Data safety and App Privacy labels | [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/) |
| Whether tracking domains are declared in `PrivacyInfo.xcprivacy` | [MASWE-0074](/mobile/maswe-0074-inadequate-tracking-domains-declarations/) |
| Device binding and attestation (identifiers used for security) | [MASWE-0054](/mobile/maswe-0054-device-attestation-not-implemented/), [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/) |
| SDKs that harvest identifiers or data the app never handed them | [MASWE-0048](/mobile/maswe-0048-malicious-code-included-in-the-app/) |
| Permissions such as `READ_PHONE_STATE` requested only to read identifiers | [MASWE-0066](/mobile/maswe-0066-inadequate-permission-management/) |

## Modes of Introduction

**Non-resettable identifiers.** IMEI, serial number, MAC addresses, SIM serial (ICCID) or subscriber ID (IMSI) used as a device or user key. On current platforms ordinary apps cannot read most of them, so this mostly appears in apps with old `targetSdkVersion` values, in privileged or pre-installed apps, in enterprise apps on managed devices, and in code paths that still try and fall back to something else. The fallbacks are worth reading: "IMEI, else serial, else `ANDROID_ID`, else a fingerprint hash" is a common shape.

**Resettable identifiers used against the user's choice.** The advertising ID read and sent before the user has consented where consent is required; `isLimitAdTrackingEnabled()` ignored; the ad ID cached in storage so a deletion or reset does not take effect; on iOS, an SDK initialised before the ATT prompt or regardless of its answer.

**Linking identifiers, and bridging resets.** The ad ID sent together with a persistent ID (`ANDROID_ID`, an install GUID restored from backup, a keychain UUID, a hashed email) to the same third party, so that a new ad ID can be joined to the old profile. Google Play's policy forbids exactly this without explicit consent.

**Tracking without permission on iOS.** IDFA is zero when the user has not authorised tracking, so SDKs that want to track fall back to something else: the IDFV, a keychain-persisted UUID, a hashed email or phone, an IP address combined with device properties. Apple treats all of these as tracking when used to link data with other companies' data for advertising, and requires ATT permission for them.

**Fingerprinting.** Combining many individually weak signals (model, OS build, locale, time zone, screen size, boot time, disk size, installed keyboards, carrier, IP) into a stable identifier. Apple prohibits it whether or not the user allowed tracking. The required-reason APIs in Apple's privacy manifests exist because of it.

**Repurposing.** A device signal collected for fraud prevention or security (a device-binding key, an attestation-derived ID, a risk-engine fingerprint) also sent to analytics or ads, against the PRIVACY-2 "technical barriers" principle.

## Impact

- **Cross-app and cross-service profiles.** A shared identifier lets third parties join this app's data to data from other apps and websites, and build profiles of interests, location patterns, health, finances, religion or sexuality that the user never chose to share.
- **Defeated user choices.** Ad ID deletion, ATT denial, reinstalling the app or clearing data are the controls users have. When an app bridges them, the user believes they reset their profile and they did not.
- **Long-term tracking.** Identifiers that survive reinstall or factory reset allow tracking over years and across device owners (a second-hand phone inherits the profile).
- **Store enforcement.** Google Play can reject or remove apps that misuse the advertising ID or link persistent identifiers; Apple can reject apps that track without ATT permission or fingerprint, including when the behaviour comes from an SDK.
- **Regulatory exposure.** Reading identifiers from the device and using them for advertising generally requires consent in the EU and UK (ePrivacy/PECR) and is "sharing" under the CCPA. The client's legal team assesses this.

## Mitigations

- **Pick the narrowest identifier for the purpose.** App-scoped, resettable IDs (a random install GUID, the Firebase installation ID, the IDFV for same-vendor analytics) for analytics and crash reporting; the advertising ID (IDFA with ATT authorisation) only for advertising; platform attestation (Play Integrity, App Attest, DeviceCheck) for abuse prevention instead of hardware IDs.
- **Respect the user's choice at the moment of each read.** Read the ad ID each time it is needed, never cache it; check `isLimitAdTrackingEnabled()` on Android and `ATTrackingManager.trackingAuthorizationStatus` on iOS; do not initialise advertising and attribution SDKs, or put them in a restricted mode, until consent and ATT are resolved.
- **Never bridge resets.** Do not send a persistent identifier alongside the advertising ID to the same party, do not restore install IDs from backup or keep them in the keychain across reinstall for analytics, and do not fall back to another identifier when the IDFA is zero.
- **Do not fingerprint**, and do not ship SDKs that do. Declare required-reason API use honestly.
- **Keep security identifiers separate.** Fraud and device-binding signals stay in the security backend with their own access controls and are not passed to analytics or ads.
- **Declare it.** "Device or other IDs" in Data safety; "Device ID" and tracking in App Privacy; `NSPrivacyTracking` and `NSPrivacyTrackingDomains` in the privacy manifest.
- **On attribution APIs:** OWASP's mitigation recommends the Android Attribution Reporting API from the Privacy Sandbox. In October 2025 Google announced it is retiring that API, among others (see [Privacy Sandbox status](#android-privacy-sandbox-status)), so do not recommend a migration to it. On iOS, SKAdNetwork and AdAttributionKit remain Apple's privacy-preserving attribution options.

## Background

OWASP has no Knowledge item for this weakness. These sections cover the identifiers on each platform, the rules around them, and the reasons behind the required-reason APIs, with the version behaviour you need to interpret what you see on a test device.

### Android and iOS: what makes an identifier a tracking risk

Android's [identifier guidance](https://developer.android.com/identity/user-data-ids) describes identifiers by three properties, and they work for both platforms:

- **Scope**: who can read the same value. One app, a group of apps (same developer or vendor), or every app on the device. The wider the scope, the easier cross-app linking.
- **Resettability and persistence**: session-only, reset on reinstall, reset on factory reset, or surviving factory reset. The longer it persists, the longer the tracking.
- **Uniqueness**: whether the value identifies one device or user, or is shared by many.

The identifiers you will meet, in one table:

| Identifier | Platform | Scope | Reset by | Access |
|---|---|---|---|---|
| Advertising ID (AAID / GAID) | Android (Play services) | Device user, all apps | User deletes or resets it in settings | `AD_ID` normal permission for targetSdk 33+; zeros after deletion or opt-out |
| App Set ID | Android (Play services) | Apps of the same Play developer account (or one app) | 13 months unused by the set, last app of the set uninstalled, factory reset | No permission |
| `ANDROID_ID` (SSAID), Android 8+ | Android | App-signing key + user + device | Factory reset, signing-key change | No permission |
| Firebase installation ID (FID) | Android, iOS | One app installation | Uninstall, clear data, API delete | No permission |
| App-generated GUID | Both | One app (unless shared) | Uninstall (if stored in app storage and excluded from backup) | No permission |
| IMEI/MEID, serial, ICCID, IMSI | Android | Device / SIM | Never (hardware) or SIM change | Privileged, carrier or device-owner apps only since Android 10 |
| Wi-Fi / Bluetooth MAC | Android | Device | Never (hardware); per-network randomised MAC is what networks see | System apps only since Android 6 |
| IDFA | iOS | Device, all apps | Tracking authorisation changes; user settings | ATT authorisation since iOS 14.5; zeros otherwise |
| IDFV | iOS | Apps from the same vendor | All the vendor's apps removed | No permission |
| DeviceCheck bits | iOS | Developer team, per device | Developer decides; survives reinstall | Server-side via Apple |
| Keychain item with a UUID | iOS | App or keychain access group | Survives app deletion in practice; not a documented guarantee | No permission |

Two general points for testing. First, an identifier is not a finding on its own; what it is *used for*, *where it is sent* and *what it is combined with* make it one. Second, a combination of an app-scoped identifier with a cross-app one in the same payload to the same third party gives the third party the wider scope of the two.

### Android: Advertising ID

The advertising ID is provided by Google Play services through `com.google.android.gms.ads.identifier.AdvertisingIdClient.getAdvertisingIdInfo(context)` (a blocking call, made off the main thread), which returns an `AdvertisingIdClient.Info` with `getId()` and `isLimitAdTrackingEnabled()` ([reference](https://developers.google.com/android/reference/com/google/android/gms/ads/identifier/AdvertisingIdClient)). An AndroidX library (`androidx.ads:ads-identifier`) exposes the same idea for devices with other ad ID providers ([guide](https://developer.android.com/identity/ad-id)). Behaviour that matters:

- **Deletion and opt-out give zeros.** Since a Google Play services update in late 2021 (Android 12 first, all Play devices from April 2022), when the user deletes the advertising ID in settings, or (per the API reference) when limit ad tracking is on, `getId()` returns `00000000-0000-0000-0000-000000000000` ([Play Console help](https://support.google.com/googleplay/android-developer/answer/6048248)). The setting lives under *Settings > Privacy > Ads* on many devices, or *Settings > Google > Ads*, depending on the device and Play services version.
- **The `AD_ID` permission.** Apps targeting Android 13 (API 33) or higher must declare `com.google.android.gms.permission.AD_ID` (a normal permission, granted at install). Without it, the API returns the zeroed ID. Advertising SDKs commonly declare it in their library manifest, so it is merged into the app even if the app's own manifest does not mention it; an app that does not want it removes it with `tools:node="remove"`. Apps targeting API 32 or lower do not need it.
- **Do not cache it.** The user can reset or delete the ID at any time. Google's guidance is to call the API each time the value is needed; a stored copy keeps the old ID alive after the user reset it.
- **Limit ad tracking** (shown to users as opting out of ads personalisation on older versions). Google Play policy allows only contextual advertising, frequency capping, conversion tracking, reporting, and security and fraud detection for opted-out users, not profiling or personalised ads.
- **Multi-user devices** can return different IDs for different users of the same device.

### Android: App Set ID, Android ID (SSAID), Firebase installation ID and app-generated IDs

**App Set ID** ([guide](https://developer.android.com/identity/app-set-id)) is Play services' identifier for analytics and fraud prevention across one developer's apps. `AppSet.getClient(context).appSetIdInfo` returns an `AppSetIdInfo` with a UUID `id` and a `scope`: *developer* scope (shared by apps installed from Play under the same developer account, even with different signing keys) or *app* scope (when installed from another installer, when Play cannot determine the developer, or without Play services). It resets when no app in the set has accessed it for over 13 months, when the last app of the set is uninstalled, or on factory reset. The Play User Data policy forbids connecting it to Android identifiers such as the advertising ID, or to personal and sensitive data, for advertising.

**`ANDROID_ID`** (`Settings.Secure.getString(contentResolver, Settings.Secure.ANDROID_ID)`, also called SSAID): on Android 8.0 (API 26) and higher it is a 64-bit value **unique to each combination of app-signing key, user and device** ([reference](https://developer.android.com/reference/android/provider/Settings.Secure#ANDROID_ID), [Android 8.0 changes](https://developer.android.com/about/versions/oreo/android-8.0-changes)). It changes on factory reset or if the signing key changes. It does **not** change when the app is uninstalled and reinstalled. Consequences:

- Apps signed with the same key (the same developer, usually) see the same value, so it is a developer-scoped identifier.
- Because it survives reinstall, using it as an "install ID" or analytics ID means **reinstalling does not reset anything**, which defeats the user's most obvious reset.
- Before Android 8.0 it was one value per device user, shared by all apps; that is why old code and old advice treat it as a device ID.

**Firebase installation ID (FID)**: one per app installation, readable only by that app instance, gone when the app is uninstalled or its data cleared, and deletable with `FirebaseInstallations.getInstance().delete()` ([Manage installations](https://firebase.google.com/docs/projects/manage-installations)). Google recommends it (or an app-generated GUID) for most non-advertising uses.

**App-generated GUIDs** (`UUID.randomUUID()` stored in app-private storage) have the same properties as an FID, with one trap: **Auto Backup and device-to-device transfer**. If the GUID is in shared preferences or a file that is backed up, it is restored on reinstall or on a new device, and the "fresh install" is linked to the old one. Exclude identifiers from backup with `dataExtractionRules` (Android 12+) or `fullBackupContent`, or that is a reset bridge. Never store such IDs in shared storage, where other apps could read them.

### Android: non-resettable hardware identifiers

- **IMEI/MEID, serial number, ICCID, IMSI.** Since Android 10 (API 29), `TelephonyManager.getImei()`, `getMeid()`, `getDeviceId()`, `getSimSerialNumber()`, `getSubscriberId()` and `Build.getSerial()` require the privileged `READ_PRIVILEGED_PHONE_STATE` permission, carrier privileges, or a device/profile owner app ([Android 10 privacy changes](https://developer.android.com/about/versions/10/privacy/changes)). For other apps: a `SecurityException` if the app targets Android 10 or higher; `null` or placeholder data if it targets Android 9 or lower and holds `READ_PHONE_STATE`; a `SecurityException` otherwise. Android 11 restricted `getIccId()` further regardless of target SDK. Google recommends the Subscription ID (`SubscriptionInfo.getSubscriptionId()`) where an app genuinely needs to tell SIMs apart.
- **MAC addresses.** Since Android 6.0, `WifiInfo.getMacAddress()` and `BluetoothAdapter.getAddress()` return the constant `02:00:00:00:00:00` to third-party apps. Since Android 10, devices use a randomised MAC per Wi-Fi network by default. Apps targeting Android 11 and higher cannot see the device MAC through `NetworkInterface.getHardwareAddress()` (it returns `null`), `getifaddrs()` or Netlink ([identifier guidance](https://developer.android.com/identity/user-data-ids)).
- **Network and nearby identifiers.** The Wi-Fi BSSID/SSID and Bluetooth scan results are location-equivalent and gated by location or nearby-device permissions ([MASWE-0066](/mobile/maswe-0066-inadequate-permission-management/)).
- **DRM device ID.** `MediaDrm` can expose a device unique ID property (`PROPERTY_DEVICE_UNIQUE_ID`); Google's guidance describes the Widevine ID as a per-APK identifier for content protection. It has no user-facing reset and is listed by Play as a "Device or other ID" for Data safety, so its use outside DRM is a finding.

A modern app reading any of these outside a carrier, MDM or DRM use case is a red flag, and an attempt that fails at runtime still tells you what the code *wanted*.

### Android: Google Play policy on identifiers

Play's rules are specific and testable:

- **Ads policy, advertising ID** ([Ads policy](https://support.google.com/googleplay/android-developer/answer/9857753)): for advertising, apps must use the advertising ID where available. It "must not be connected to personally-identifiable information or associated with any persistent device identifier (for example: SSAID, MAC address, IMEI, etc.) without explicit consent of the user", and "if reset, a new advertising identifier must not be connected to a previous advertising identifier or data derived from a previous advertising identifier without the explicit consent of the user" (quoted in Google's [identifier guidance](https://developer.android.com/identity/user-data-ids)). The user's opt-out of interest-based ads must be honoured.
- **User Data policy** ([User Data](https://support.google.com/googleplay/android-developer/answer/10144311)): "Persistent device identifiers may not be linked to other personal and sensitive user data or resettable device identifiers"; third-party SDKs must not associate the advertising ID with the SIM serial; the App Set ID may not be connected to other Android identifiers or personal data for advertising.
- **Families policy** ([Families](https://support.google.com/googleplay/android-developer/answer/9893335)): apps that target only children must not transmit the AAID, SIM serial, build serial, BSSID, MAC, SSID, IMEI or IMSI; apps for children and older audiences must not transmit them from children or users of unknown age.
- **Data safety**: "Device or other IDs" (examples include IMEI, MAC address, Widevine Device ID, Firebase installation ID and advertising identifier) must be declared when collected or shared, with the purposes ([MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/)).

Google's own guidance shows how subtle the "no linking" rule is: an analytics table keyed by ad ID with an `account_id` column links the ad ID to PII; even without the account ID, rare events with exact timestamps and device model can be joined back. Testing can only see the app side of that, which is why GT-PRIV-0068-3 looks at what travels *together*.

### Android: Privacy Sandbox status

The Privacy Sandbox on Android was Google's planned privacy-preserving replacement for cross-app advertising identifiers: Topics, Protected Audience, Attribution Reporting and an SDK Runtime that would isolate ad SDKs from the app. OWASP's mitigations still point to the [Attribution Reporting API for Android](https://developers.google.com/privacy-sandbox/private-advertising/attribution-reporting/android).

On 17 October 2025 Google [announced](https://privacysandbox.google.com/blog/update-on-plans-for-privacy-sandbox-technologies) that, citing ecosystem feedback and low adoption, it is retiring the Attribution Reporting API, Protected Audience, Topics, Protected App Signals, On-Device Personalization, SDK Runtime and other Privacy Sandbox technologies across Chrome and Android, with timelines to follow on its developer sites. At the time of writing the advertising ID remains the identifier Play policy requires for ads. Check Google's current documentation before recommending any of these APIs, and treat an app that integrated them as using a deprecated path, not as a privacy improvement to rely on.

### iOS: IDFA and App Tracking Transparency

The **IDFA** (`ASIdentifierManager.shared().advertisingIdentifier`) is device-wide and meant for advertising only. Since iOS 14.5 an app must request tracking authorisation through the **App Tracking Transparency** framework before it gets a real value ([`advertisingIdentifier`](https://developer.apple.com/documentation/adsupport/asidentifiermanager/advertisingidentifier)). The IDFA is all zeros (`00000000-0000-0000-0000-000000000000`) when the app has not requested authorisation, when the user denied it, when tracking is restricted by a profile, in the Simulator, and for iOS apps running on macOS or visionOS. Apple's advice is not to store it but to read it when needed, because users can change the authorisation in *Settings > Privacy & Security > Tracking* at any time.

**ATT mechanics** ([framework](https://developer.apple.com/documentation/apptrackingtransparency), [`requestTrackingAuthorization(completionHandler:)`](https://developer.apple.com/documentation/apptrackingtransparency/attrackingmanager/requesttrackingauthorization%28completionhandler%3A%29)):

- The app must include `NSUserTrackingUsageDescription` in `Info.plist`, and calls `ATTrackingManager.requestTrackingAuthorization`. The current state is in `ATTrackingManager.trackingAuthorizationStatus`: `.notDetermined`, `.restricted`, `.denied`, `.authorized`.
- The prompt only appears when the app is active, and not at all if the user switched off *Allow Apps to Request to Track* (the completion handler runs immediately with the current status). In some EU countries the system shows a full-page sheet instead of an alert, and in the EU an answered prompt cannot be shown again for a year.
- **Apple's definition of tracking** ([User Privacy and Data Use](https://developer.apple.com/app-store/user-privacy-and-data-use/)): linking user or device data collected from the app with data collected from other companies' apps, websites or offline properties for targeted advertising or advertising measurement, or sharing it with data brokers. Apple's FAQ makes three points that drive testing: tracking without ATT permission is not allowed with *any* identifier, explicitly including hashed emails and phone numbers; the IDFV may be used for analytics across the same vendor's apps without ATT, but not combined with other data to track across other companies' apps; and apps may not gate functionality on, or offer incentives for, allowing tracking (Guideline 5.1.2(i)).
- **Third-party SDKs count.** Apple's App Privacy guidance counts placing an SDK that combines the app's data with other developers' data for advertising as tracking by the app, even if the app itself never uses the SDK for that.

### iOS: IDFV, DeviceCheck and keychain-persisted identifiers

**IDFV** (`UIDevice.current.identifierForVendor`, [reference](https://developer.apple.com/documentation/uikit/uidevice/identifierforvendor)) is the same for all apps from one vendor on a device and different across vendors and devices. The vendor is normally determined from App Store data; for enterprise and development builds it is derived from the bundle ID (all components but the last). It stays the same while any app from the vendor is installed and changes when the user deletes all of them and reinstalls. It can also change for Xcode and ad hoc installs, and is `nil` after a reboot until the device is unlocked. It is a sensible analytics ID within one vendor's apps. It becomes a finding when sent to third parties as a substitute for the IDFA after ATT denial.

**DeviceCheck** ([`DCDevice`](https://developer.apple.com/documentation/devicecheck/dcdevice)) lets the developer's server store **two bits per device** with Apple, plus a last-update month, queried and set with an ephemeral device token the app generates. Apple records the bits and leaves resetting them to the developer (for example when a device changes hands), and they are designed to survive app reinstall: that is what makes them useful for "this device already had a free trial". Two bits cannot identify a device by themselves, which is the privacy design. Using DeviceCheck for fraud prevention is the privacy-friendly choice; its security use is covered in [MASWE-0054](/mobile/maswe-0054-device-attestation-not-implemented/).

**Keychain-persisted identifiers.** Keychain items are not removed when an app is deleted. That is long-standing behaviour that Apple does not document as a guarantee (a beta of iOS 10.3 briefly changed it). A UUID that the app or an SDK stores in the keychain therefore **survives reinstall**, and with `kSecAttrSynchronizable` it syncs through iCloud Keychain to the user's other devices. That is legitimate for some security uses (device binding, see [MASWE-0054](/mobile/maswe-0054-device-attestation-not-implemented/)). Used as an analytics or advertising ID, it silently bridges the user's reset, and it is a classic IDFA substitute in SDKs. `UserDefaults` and files in the app container, by contrast, are deleted with the app.

### iOS: SKAdNetwork and AdAttributionKit

Apple's answer to ad attribution without user-level identifiers is **SKAdNetwork** ([StoreKit](https://developer.apple.com/documentation/storekit/skadnetwork)) and its successor **AdAttributionKit** ([framework](https://developer.apple.com/documentation/adattributionkit), introduced with iOS 17.4). The ad network signs the ad; the publisher app shows it; the advertised app updates a coarse **conversion value** as the person engages; the device sends delayed, crowd-anonymised **postbacks** to the ad network (and optionally the developer) without any device identifier. The level of detail in a postback depends on a privacy threshold ("crowd anonymity" tier). For testing, the relevant artefacts are the `SKAdNetworkItems` (ad network IDs) and AdAttributionKit configuration in `Info.plist`, and calls that update conversion values. Their presence is a positive sign; it does not excuse identifier-based attribution running alongside it after ATT denial.

### Android and iOS: fingerprinting and Apple's required-reason APIs

Fingerprinting derives a stable identifier from properties of the device and its configuration instead of reading an ID: model, OS build, kernel version, locale and time zone, screen metrics, font scale, installed keyboards, free and total disk space, boot time, file timestamps of system or app files, carrier, network, IP address, sensor calibration and so on. No single value is unique, but enough of them together usually are. It is invisible to the user and survives every reset the platform offers, which is why both platforms oppose it:

- **Apple**: "you may not derive data from a device for the purpose of uniquely identifying it" (Developer Program License Agreement, as quoted in Apple's [User Privacy and Data Use](https://developer.apple.com/app-store/user-privacy-and-data-use/) FAQ), whether or not the user allowed tracking; apps containing SDKs that do it may be rejected.
- **Google**: do not bridge advertising ID resets "by using another identifier or fingerprint" without consent ([identifier guidance](https://developer.android.com/identity/user-data-ids)).

Apple's **required-reason APIs** ([Describing use of required reason API](https://developer.apple.com/documentation/bundleresources/describing-use-of-required-reason-api)) are its structural response. Apple identified API categories with legitimate uses that are also classic fingerprinting inputs: **file timestamps**, **system boot time**, **disk space**, **active keyboards** and **user defaults**. Since 1 May 2024, App Store Connect does not accept apps that use them without declaring an approved reason in a privacy manifest (`PrivacyInfo.xcprivacy`, under `NSPrivacyAccessedAPITypes` with `NSPrivacyAccessedAPITypeReasons`), and each SDK must declare its own use in its own manifest. Declared reasons must match the app's functionality, and the APIs and derived data may not be used for tracking. Apple's documentation is explicit that "regardless of whether a user gives your app permission to track, fingerprinting is not allowed." The same manifests carry `NSPrivacyTracking` and `NSPrivacyTrackingDomains`: on iOS 17 and later, when the user has not authorised tracking, the system blocks connections to declared tracking domains. Manifest testing lives in [MASWE-0074](/mobile/maswe-0074-inadequate-tracking-domains-declarations/) and [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/); SDK signatures and the commonly-used-SDK list in [MASWE-0048](/mobile/maswe-0048-malicious-code-included-in-the-app/).

For testing, the goal is to **detect** fingerprinting, not to build it: an SDK that reads many of these signals together and sends them in one payload to a third party, especially when ATT is denied, is the finding. GT-PRIV-0068-1 and GT-PRIV-0068-2 show how to spot it.

### Android and iOS: legal context

Short, because the client's legal team owns it:

- **GDPR / UK GDPR**: [Recital 30](https://eur-lex.europa.eu/eli/reg/2016/679/oj) names device identifiers and other online identifiers as data that can make people identifiable when combined with other information; advertising and device IDs are generally personal data.
- **ePrivacy Art. 5(3) / PECR regulation 6**: reading an identifier from the device (gaining access to information stored in the terminal equipment) needs consent unless strictly necessary for the service the user asked for ([Directive 2002/58/EC](https://eur-lex.europa.eu/eli/dir/2002/58/oj), [PECR reg. 6](https://www.legislation.gov.uk/uksi/2003/2426/regulation/6)); the EDPB's [Guidelines 2/2023](https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-22023-technical-scope-art-53-eprivacy-directive_en) read this to cover identifiers read by apps and SDKs. That is why the *timing* of reads relative to consent (GT-PRIV-0068-2) is evidence worth collecting.
- **CCPA/CPRA**: unique and persistent identifiers, including device identifiers, are personal information; disclosure for cross-context behavioural advertising is "sharing" that users can opt out of.

## Tests

All four tests are Guler Tech methodology. Run them on test devices you own, with test accounts, and record only your own devices' identifiers and your own traffic. The Frida scripts below observe the app's calls and print values; they do not change behaviour.

### GT-PRIV-0068-1: Static inventory of identifier APIs (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Builds the list of identifiers the app and each SDK *can* read, the permissions and declarations that go with them, and any fingerprinting-style collection of device signals. It tells you what to trace in GT-PRIV-0068-2 and what to search for in GT-PRIV-0068-3.

#### Prerequisites

- The release APK or AAB-derived APKs and the decrypted IPA.
- jadx ([MASTG-TOOL-0018](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/)), apktool, `aapt2`, rabin2 ([MASTG-TOOL-0129](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/)), `plutil`, `codesign`.
- The SDK inventory ([third-party libraries](/mobile/mastg-know-0004-third-party-libraries/)).

#### Steps

**Android**

1. **Permissions and merged manifest entries** (see [MASTG-TECH-0117](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/) and [MASTG-TECH-0126](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0126/)):

   ```bash
   aapt2 dump badging app.apk | grep -E "targetSdkVersion|sdkVersion"
   aapt2 dump permissions app.apk | grep -E "AD_ID|READ_PHONE_STATE|READ_PRIVILEGED_PHONE_STATE|READ_PHONE_NUMBERS|ACCESS_WIFI_STATE|BLUETOOTH|QUERY_ALL_PACKAGES|ACCESS_(FINE|COARSE)_LOCATION"
   ```

   Note whether `AD_ID` is present and whether that is intended (often merged from an SDK), and what `targetSdkVersion` is, since several restrictions depend on it.
2. **Identifier API references** in the decompiled code, grouped by package so you can attribute them to the app or to an SDK:

   ```bash
   jadx -d jadx_out app.apk
   grep -rnoE 'AdvertisingIdClient|getAdvertisingIdInfo|isLimitAdTrackingEnabled|AppSet\.getClient|getAppSetIdInfo|"android_id"|Settings\$Secure|Secure\.ANDROID_ID|getImei|getMeid|getDeviceId|getSubscriberId|getSimSerialNumber|getLine1Number|Build\.getSerial|Build\.SERIAL|getMacAddress|getHardwareAddress|getBSSID|FirebaseInstallations|PROPERTY_DEVICE_UNIQUE_ID|deviceUniqueId' \
     jadx_out/sources | awk -F: '{split($1,p,"/"); print p[3]"/"p[4]"/"p[5], $3}' | sort | uniq -c | sort -rn
   ```

3. **Fingerprint-style signal collection.** Look for code that reads many device properties into one structure. A rough first pass is to find classes that reference several of these together:

   ```bash
   for f in $(grep -rlE 'Build\.(MODEL|FINGERPRINT|BOARD|HARDWARE)' jadx_out/sources); do
     n=$(grep -cE 'Build\.(MODEL|FINGERPRINT|BOARD|HARDWARE|DISPLAY)|StatFs|elapsedRealtime|TimeZone\.getDefault|getInstalledPackages|getInstalledApplications|DisplayMetrics|getNetworkOperator|SensorManager|default_input_method' "$f")
     [ "$n" -ge 5 ] && echo "$n $f"
   done | sort -rn | head -20
   ```

   Read the top hits: is it a crash reporter collecting device context (normal), a security SDK (check where its output goes), or an attribution or ads SDK assembling a device profile?
4. **Backup rules for stored IDs.** Check `android:allowBackup`, `android:dataExtractionRules` and `android:fullBackupContent` in the manifest and the referenced XML in `res/xml/`; note whether the files holding install or analytics IDs (from step 2 call sites) are excluded.

**iOS**

5. **Frameworks and symbols** in the main binary and every embedded framework:

   ```bash
   for b in Payload/App.app/App Payload/App.app/Frameworks/*.framework/*; do
     [ -f "$b" ] || continue
     libs=$(rabin2 -l "$b" 2>/dev/null | grep -oE 'AdSupport|AppTrackingTransparency|DeviceCheck|AdServices|AdAttributionKit|StoreKit' | sort -u | tr '\n' ' ')
     sels=$(rabin2 -zz "$b" 2>/dev/null | grep -oE 'advertisingIdentifier|identifierForVendor|requestTrackingAuthorization[A-Za-z:]*|trackingAuthorizationStatus|isAdvertisingTrackingEnabled|generateTokenWithCompletionHandler:|kern\.boottime|NSFileSystemSize|NSFileSystemFreeSize|activeInputModes|systemUptime' | sort -u | tr '\n' ' ')
     [ -n "$libs$sels" ] && echo "== ${b#Payload/App.app/}: $libs| $sels"
   done
   ```

6. **Keychain use** that could persist IDs: `rabin2 -i <binary> | grep -E 'SecItemAdd|SecItemCopyMatching|SecItemUpdate'` and, in strings, service or account names that look like install or device IDs (`device_id`, `install_uuid`, `udid`).
7. **Declarations**:

   ```bash
   plutil -p Payload/App.app/Info.plist | grep -A3 -E "NSUserTrackingUsageDescription|SKAdNetworkItems|AdAttributionKit"
   find Payload/App.app -name PrivacyInfo.xcprivacy | while read f; do
     echo "== $f"; plutil -p "$f" | grep -E -A2 "NSPrivacyTracking|NSPrivacyTrackingDomains|DeviceID|NSPrivacyAccessedAPIType\""
   done
   ```

   OWASP's techniques for privacy manifests are [MASTG-TECH-0136](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0136/) (retrieving) and [MASTG-TECH-0137](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0137/) (analysing).

#### Observation

A table per platform: identifier or signal, API, code location (app or SDK), related permission or declaration. Plus the backup rules, keychain usage, ATT and SKAdNetwork/AdAttributionKit configuration, and the classes that collect many device signals.

#### Evaluation

This is an inventory step; on its own it **fails** only for:

- Code that reads non-resettable identifiers (IMEI, serial, MAC, ICCID, IMSI, DRM device ID) outside a carrier, MDM or DRM use case, or permissions requested only for that.
- An `AD_ID` permission, `AdSupport` link or IDFA access in an app that declares it does not track or does not use advertising, or in a Families/child-directed app.
- IDFA access with no `NSUserTrackingUsageDescription` and no ATT call (the IDFA will be zeros, but the intent and SDK configuration are wrong).
- Required-reason API references in a binary or framework whose privacy manifest does not declare them (also a submission blocker; record for [MASWE-0074](/mobile/maswe-0074-inadequate-tracking-domains-declarations/)).

Everything else feeds the runtime tests, which decide.

#### Demo

Illustrative Android output:

```text
     14 com/example/app ANDROID_ID
      6 com/adsdk/core getAdvertisingIdInfo
      2 com/adsdk/core isLimitAdTrackingEnabled
      3 com/attribution/sdk "android_id"
      1 com/attribution/sdk getHardwareAddress
```

Illustrative iOS output:

```text
== App: AdSupport AppTrackingTransparency StoreKit | advertisingIdentifier identifierForVendor requestTrackingAuthorizationWithCompletionHandler: trackingAuthorizationStatus
== Frameworks/AttribSDK.framework/AttribSDK: AdSupport | advertisingIdentifier identifierForVendor kern.boottime NSFileSystemSize systemUptime
```

The attribution SDK reading `android_id` and a MAC address on Android, and boot time, disk size and uptime on iOS, is the shape to trace next.

### GT-PRIV-0068-2: Runtime trace of identifier reads relative to consent and ATT (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Static references show capability. This test shows which identifiers are read on a real launch, by which code, with what value, and **when**: before the consent banner is answered, after a refusal, before or after the ATT prompt. Reads before consent are where ePrivacy and ATT findings come from.

#### Prerequisites

- A rooted Android test device and a jailbroken iOS test device (or test builds with Frida Gadget), Frida ([MASTG-TOOL-0031](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/)); method tracing as in [MASTG-TECH-0033](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0033/) and [MASTG-TECH-0086](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0086/).
- A clean state for each run: `adb shell pm clear com.example.app` on Android; delete and reinstall on iOS, and reset the ATT state (*Settings > Privacy & Security > Tracking*, or *Settings > General > Transfer or Reset iPhone > Reset > Reset Location & Privacy* on a dedicated test device).
- A screen recording or notes with timestamps of when the consent banner appears and what you chose.

#### Steps

1. **Android trace.** Spawn the app with the script below. It logs reads of the main identifiers with the time since spawn, the value, and the first app frames of the stack, and it logs writes of IAB TCF consent keys to `SharedPreferences` (`IABTCF_*`, where TCF-based consent tools store the decision), which gives you the consent timestamp:

   ```javascript
   // trace-ids-android.js - observe only
   const t0 = Date.now();
   function where() {
     const st = Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new());
     return st.split('\n').filter(l => l.includes('at ') && !l.includes('java.lang.') && !l.includes('android.')).slice(0, 3).join(' | ');
   }
   function log(what, val) { console.log('+' + (Date.now() - t0) + 'ms ' + what + ' = ' + val + '  <- ' + where()); }
   Java.perform(() => {
     const Secure = Java.use('android.provider.Settings$Secure');
     Secure.getString.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (cr, name) {
       const v = this.getString(cr, name);
       if (name === 'android_id') log('ANDROID_ID', v);
       return v;
     };
     const TM = Java.use('android.telephony.TelephonyManager');
     ['getImei', 'getMeid', 'getDeviceId', 'getSubscriberId', 'getSimSerialNumber', 'getLine1Number'].forEach(m => {
       if (!TM[m]) return;
       TM[m].overloads.forEach(o => { o.implementation = function () {
         log('TelephonyManager.' + m, '(called)');
         return o.apply(this, arguments);
       }; });
     });
     const NI = Java.use('java.net.NetworkInterface');
     NI.getHardwareAddress.implementation = function () { log('NetworkInterface.getHardwareAddress', '(called)'); return this.getHardwareAddress(); };
     try {
       const Info = Java.use('com.google.android.gms.ads.identifier.AdvertisingIdClient$Info');
       Info.getId.implementation = function () { const v = this.getId(); log('AdvertisingId', v); return v; };
       Info.isLimitAdTrackingEnabled.implementation = function () { const v = this.isLimitAdTrackingEnabled(); log('LimitAdTracking', v); return v; };
     } catch (e) { console.log('[i] ad ID client class not found under its public name (renamed by R8?)'); }
     try {
       const AppSet = Java.use('com.google.android.gms.appset.AppSetIdInfo');
       AppSet.getId.implementation = function () { const v = this.getId(); log('AppSetId', v); return v; };
     } catch (e) {}
     const Editor = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
     Editor.putString.implementation = function (k, v) {
       if (k && k.startsWith('IABTCF_')) log('consent ' + k, v === null ? 'null' : v.substring(0, 40));
       return this.putString(k, v);
     };
   });
   ```

   ```bash
   frida -U -f com.example.app -l trace-ids-android.js -o ids-run1.log
   ```

   If the app uses its own consent tool, find where it stores the decision (GT-PRIV-0068-1, or [MASWE-0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/)) and add a hook there; otherwise use your screen-recording timestamps.
2. **iOS trace.** The same idea with the Objective-C runtime; it also logs keychain lookups by service and account name (not contents), boot-time `sysctl` reads, and the ATT status the app sees:

   ```javascript
   // trace-ids-ios.js - observe only
   const t0 = Date.now();
   const exp = n => (Module.findGlobalExportByName ? Module.findGlobalExportByName(n) : Module.findExportByName(null, n));
   function log(what, val, ctx) {
     const bt = ctx ? Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, 3).map(DebugSymbol.fromAddress).join(' | ') : '';
     console.log('+' + (Date.now() - t0) + 'ms ' + what + ' = ' + val + (bt ? '  <- ' + bt : ''));
   }
   function onRet(cls, sel, label, fmt) {
     const c = ObjC.classes[cls]; if (!c || !c[sel]) return;
     Interceptor.attach(c[sel].implementation, {
       onEnter() { this.c = this.context; },
       onLeave(r) { log(label, fmt(r), this.c); }
     });
   }
   const uuid = r => r.isNull() ? 'nil' : new ObjC.Object(r).UUIDString().toString();
   onRet('ASIdentifierManager', '- advertisingIdentifier', 'IDFA', uuid);
   onRet('UIDevice', '- identifierForVendor', 'IDFV', uuid);
   onRet('ATTrackingManager', '+ trackingAuthorizationStatus', 'ATT status (0 notDet,1 restr,2 denied,3 auth)', r => r.toInt32());
   const req = ObjC.classes.ATTrackingManager && ObjC.classes.ATTrackingManager['+ requestTrackingAuthorizationWithCompletionHandler:'];
   if (req) Interceptor.attach(req.implementation, { onEnter() { log('ATT prompt requested', '', this.context); } });
   const dc = ObjC.classes.DCDevice && ObjC.classes.DCDevice['- generateTokenWithCompletionHandler:'];
   if (dc) Interceptor.attach(dc.implementation, { onEnter() { log('DeviceCheck token requested', '', this.context); } });
   ['SecItemCopyMatching', 'SecItemAdd'].forEach(fn => {
     Interceptor.attach(exp(fn), { onEnter(args) {
       const d = new ObjC.Object(args[0]);
       log(fn, 'svce=' + d.objectForKey_('svce') + ' acct=' + d.objectForKey_('acct') + ' sync=' + d.objectForKey_('sync'), this.context);
     } });
   });
   Interceptor.attach(exp('sysctlbyname'), { onEnter(args) {
     const n = args[0].readUtf8String();
     if (n === 'kern.boottime') log('sysctlbyname', n, this.context);
   } });
   const UD = ObjC.classes.NSUserDefaults['- setObject:forKey:'];
   Interceptor.attach(UD.implementation, { onEnter(args) {
     if (args[3].isNull()) return;
     const k = new ObjC.Object(args[3]).toString();
     if (k.startsWith('IABTCF_')) log('consent ' + k, args[2].isNull() ? 'nil' : new ObjC.Object(args[2]).toString().substring(0, 40));
   } });
   ```

   ```bash
   frida -U -f com.example.app -l trace-ids-ios.js -o ids-ios-run1.log
   ```

   (`svce`, `acct` and `sync` are the raw values of `kSecAttrService`, `kSecAttrAccount` and `kSecAttrSynchronizable`.)
3. **Run the consent scenarios**, each from a clean state: (a) launch and wait at the consent banner for a minute without answering; (b) refuse all optional purposes; (c) accept all; on iOS additionally (d) deny ATT and (e) allow ATT. Keep one log per scenario.
4. **Build the timeline.** For each identifier read, note whether it happened before the consent decision, after a refusal, or only after acceptance; on iOS, whether IDFV reads, keychain ID lookups or boot-time reads by an advertising or attribution SDK happen after ATT denial. Map each stack to the app or a specific SDK.

#### Observation

Per scenario: a time-ordered list of identifier reads with value, caller and the consent or ATT events around them.

#### Evaluation

The test **fails** if:

- The advertising ID, IDFA request path, or identifiers used by advertising, attribution or cross-app analytics SDKs are read before the user has made a consent decision, or after a refusal, where the app's consent model says those purposes need consent (the app's own consent text and the client's legal position decide which purposes those are).
- After ATT denial (or before ATT is answered), an advertising or attribution SDK reads the IDFV, a keychain-persisted ID, or several fingerprint-type signals (boot time, disk space, uptime) together; confirm with GT-PRIV-0068-3 that they are sent.
- The app reads non-resettable identifiers at all outside a justified carrier, MDM or DRM use.
- `isLimitAdTrackingEnabled()` is never read by code that uses the ad ID for profiling.

It **passes** if advertising-related identifiers are only read after the relevant consent (and ATT authorisation on iOS), analytics uses app-scoped IDs, and nothing tracking-related runs on the denied paths. Reads by the app's own security or fraud code are observations: check in GT-PRIV-0068-3 that their output goes only to the security backend.

#### Demo

Illustrative Android log from scenario (a), waiting at the banner without answering:

```text
+412ms ANDROID_ID = 3f1c9a7be0d2c4a1  <- at com.attribution.sdk.c.a(SourceFile:88) | at com.attribution.sdk.Init.start(SourceFile:30) | at com.example.app.App.onCreate(App.kt:41)
+655ms AdvertisingId = 6b0e3c1d-4f8a-4b2e-9d7c-0a1b2c3d4e5f  <- at com.attribution.sdk.c.b(SourceFile:112) | ...
+656ms LimitAdTracking = false  <- ...
```

Nothing `IABTCF_` was written during the run, so both reads happened with no consent decision. The fix is in the init order (App.kt:41), not in the SDK.

Illustrative iOS log from scenario (d), ATT denied:

```text
+1210ms ATT prompt requested =   <- App`AppDelegate.application(_:didFinishLaunchingWithOptions:)
+5032ms ATT status (0 notDet,1 restr,2 denied,3 auth) = 2  <- AttribSDK`-[ATBConfig trackingAllowed]
+5040ms IDFV = 9E1C0B6A-2F43-4D7E-8C55-1B2A3C4D5E6F  <- AttribSDK`-[ATBDeviceInfo collect]
+5041ms SecItemCopyMatching = svce=com.attribsdk.persist acct=uid sync=null  <- AttribSDK`-[ATBStore loadPersistentID]
+5042ms sysctlbyname = kern.boottime  <- AttribSDK`-[ATBDeviceInfo collect]
```

### GT-PRIV-0068-3: Identifiers in outgoing traffic and their destinations (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Takes the identifier values your test devices produced in GT-PRIV-0068-2 and finds them in the app's traffic, by destination and consent state, together with what travels with them. Two things make a finding here: an identifier reaching a party it should not, and two identifiers (or an identifier and account data) arriving at the same third party together, which lets that party link them.

#### Prerequisites

- An interception set-up for both platforms ([traffic interception lab](/mobile/mobile-traffic-interception-lab/), [MASTG-TECH-0120](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0120/)); mitmproxy ([MASTG-TOOL-0097](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0097/)).
- The identifier values from GT-PRIV-0068-2 for each test device (ad ID or IDFA when authorised, `ANDROID_ID` as the app sees it, IDFV, FID or install ID, keychain IDs if visible), and a test account with canary email and user ID (as in [MASWE-0067](/mobile/maswe-0067-lack-of-anonymization-or-pseudonymisation/)).
- The app's declared tracking domains (`NSPrivacyTrackingDomains`) and Data safety / App Privacy declarations.

#### Steps

1. **Write the identifier list** (`ids.txt`, one `label=value` per line) and run an addon that searches each request for the values in raw, lower/upper case, without hyphens, and as MD5/SHA-1/SHA-256 hex (some SDKs hash IDs), and reports which identifiers appear *together* in one request:

   ```python
   # id_search.py - mitmproxy addon; searches YOUR devices' identifiers in the app's own traffic.
   # mitmdump -s id_search.py --set ids=ids.txt -w ids.flows
   import hashlib, json
   from mitmproxy import ctx, http

   def forms(v):
       base = {v, v.lower(), v.upper(), v.replace("-", ""), v.replace("-", "").lower()}
       out = set(base)
       for b in base:
           for alg in ("md5", "sha1", "sha256"):
               out.add(hashlib.new(alg, b.encode()).hexdigest())
       return out

   class IdSearch:
       def load(self, loader):
           loader.add_option("ids", str, "ids.txt", "label=value per line")

       def running(self):
           self.ids = []
           with open(ctx.options.ids) as fh:
               for line in fh:
                   if "=" in line:
                       label, value = line.strip().split("=", 1)
                       self.ids.append((label, [f.lower() for f in forms(value)]))

       def request(self, flow: http.HTTPFlow):
           r = flow.request
           blob = (r.pretty_url + "\n" + "\n".join(k + ": " + v for k, v in r.headers.items())
                   + "\n" + (r.get_text(strict=False) or "")).lower()
           found = sorted({label for label, fs in self.ids if any(f in blob for f in fs)})
           if found:
               ctx.log.warn(json.dumps({"host": r.pretty_host, "path": r.path.split("?")[0],
                                        "ids": found, "linked": len(found) > 1}))

   addons = [IdSearch()]
   ```

   With, for example:

   ```text
   adid=6b0e3c1d-4f8a-4b2e-9d7c-0a1b2c3d4e5f
   android_id=3f1c9a7be0d2c4a1
   install_id=0d6c2f0e-7a51-4c3e-b1f2-9a8b7c6d5e4f
   account_email=canary.pt7k2@example.com
   account_id=U-58114
   ```

2. **Repeat the consent scenarios** from GT-PRIV-0068-2 with the proxy running, waiting a few minutes in each so batched events are flushed. On iOS, run once with ATT denied and once allowed.
3. **Classify each destination**: the client's own API, a first-party proxy, or a third party (and which SDK). On iOS, note whether the host is in `NSPrivacyTrackingDomains`; with ATT denied on iOS 17 or later, connections to declared tracking domains should be blocked by the system, so traffic to an *undeclared* host carrying identifiers after denial is the interesting case ([MASWE-0074](/mobile/maswe-0074-inadequate-tracking-domains-declarations/)).
4. **Look at what travels with the identifiers**: account IDs, hashed emails, IP-based or device-property bundles, the fraud or device-binding token. A security token from [MASWE-0054](/mobile/maswe-0054-device-attestation-not-implemented/) appearing in an analytics or ads request breaks the PRIVACY-2 separation principle.
5. **Cross-check the declarations**: identifiers seen leaving the device versus "Device or other IDs" in Data safety and "Device ID" / tracking in App Privacy, and `NSPrivacyTracking` in the manifest ([MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/)).

#### Observation

A matrix of identifier × destination × consent/ATT state, with a "linked" flag for requests carrying more than one identifier, the accompanying data, and the declaration status of each destination.

#### Evaluation

The test **fails** if:

- The advertising ID or IDFA is sent to third parties before consent or after refusal where consent is required, or the IDFA-substitutes (IDFV, keychain ID, hashed email or phone, fingerprint bundle) are sent to an advertising or attribution party after ATT denial or before ATT is answered.
- The advertising ID travels to the same third party with a persistent identifier (`ANDROID_ID`, a restored install ID, IMEI, MAC) or with account data, without explicit consent for that linking (Play Ads policy).
- A non-resettable identifier leaves the device.
- Identifiers are sent to a destination not reflected in the app's declarations, or the app declares no tracking while sending ad IDs to advertising parties.
- Fraud or device-binding identifiers are sent to analytics or advertising parties.

It **passes** if each identifier reaches only the destinations its purpose needs, advertising identifiers only after consent and ATT authorisation, no persistent ID travels with the ad ID to third parties, and the declarations match. App-scoped IDs to first-party or processor analytics are observations, not failures.

#### Demo

Illustrative output with consent not yet given (Android) and ATT denied (iOS):

```text
[12:02:11.401] {"host": "api.example.com", "path": "/v2/session", "ids": ["account_id", "install_id"], "linked": true}
[12:02:11.957] {"host": "attribution.example.org", "path": "/install", "ids": ["adid", "android_id", "install_id"], "linked": true}
[12:07:40.220] {"host": "collect.example.net", "path": "/d", "ids": ["idfv", "keychain_uid"], "linked": true}
```

The first line is the app's own API and expected. The second sends the ad ID with `ANDROID_ID` to an attribution party before consent, which is both a consent issue and a Play policy issue. The third, on iOS after ATT denial, sends the IDFV and a keychain-persisted ID to a host not in `NSPrivacyTrackingDomains`.

### GT-PRIV-0068-4: Identifier reset and persistence behaviour (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Users reset tracking in three ways: resetting or deleting the advertising ID, reinstalling or clearing the app, and (on iOS) denying or revoking ATT. This test performs each reset on your test device and checks, in the trace and the traffic, whether the app or an SDK carries a value across it. That would let the old profile be re-linked.

#### Prerequisites

- The scripts and addon from GT-PRIV-0068-2 and GT-PRIV-0068-3.
- Android: a test device signed in to a test Google account (for backup tests), adb. iOS: a test device with the app from TestFlight or the App Store (IDFV behaviour differs for Xcode and ad hoc installs).

#### Steps

**Android**

1. **Advertising ID reset or deletion.** Record the current ad ID and the identifiers sent with it (baseline run). In *Settings > Privacy > Ads* (or *Settings > Google > Ads*), delete the advertising ID (or reset it on versions that offer that). Relaunch with the trace and proxy running. Check: does `getId()` now return zeros, and does the app stop sending an ad ID? Does any third-party request now carry a persistent ID (`ANDROID_ID`, install ID, account data) that also accompanied the *old* ad ID in the baseline? If a new ad ID is issued later, the same question applies to it.
2. **Clear data and reinstall.**

   ```bash
   adb shell pm clear com.example.app       # then relaunch and capture
   adb uninstall com.example.app && adb install app.apk   # or reinstall from Play; then relaunch and capture
   ```

   Compare the install, analytics and attribution IDs in traffic before and after. An app-generated GUID or FID should change. `ANDROID_ID` will not change (same signing key), so if the app uses it as its install or analytics ID, reinstall resets nothing.
3. **Backup restore.** Use the local backup transport from Google's [backup testing guide](https://developer.android.com/identity/data/testingbackup) to see whether stored IDs come back after reinstall:

   ```bash
   adb shell bmgr enable true
   adb shell bmgr transport com.android.localtransport/.LocalTransport
   adb shell bmgr backupnow com.example.app
   adb shell pm path com.example.app            # pull the APK(s) first
   adb shell pm uninstall --user 0 com.example.app
   adb install-multiple -t --user 0 base.apk split_*.apk
   adb shell bmgr transport com.google.android.gms/.backup.BackupTransportService   # restore the normal transport
   ```

   Launch and check whether the pre-backup install or analytics ID reappears in traffic.
4. **Limit ad tracking / ads personalisation opt-out** (devices and Play services versions that still offer it separately): set it and confirm in the trace that `isLimitAdTrackingEnabled()` returns `true` and that requests change accordingly (no personalisation parameters, or none at all).

**iOS**

5. **ATT denied.** Fresh install, deny the prompt (or turn off *Allow Apps to Request to Track*). With trace and proxy running, use the app for a few minutes. IDFA must be zeros. Check whether advertising or attribution hosts receive the IDFV, a keychain ID, hashed account data or a device-property bundle instead (GT-PRIV-0068-3).
6. **ATT revoked after being allowed.** Allow tracking, use the app, then turn it off for the app in *Settings > Privacy & Security > Tracking* and return. The next reads should get zeros and the same substitute checks apply.
7. **Delete and reinstall.** Note the install ID in traffic, delete the app, reinstall it from the same channel, and launch with the trace running. A `SecItemCopyMatching` for the SDK's or app's ID item that succeeds on the very first launch, and the same install ID reappearing in traffic, shows a keychain-persisted ID surviving reinstall. The IDFV only changes if no other app from the same vendor is installed; note which other vendor apps are on the device.

#### Observation

For each reset: the identifier values before and after, which values persisted, where the persisted values were sent, and whether they travelled with the new advertising identifier or appeared on a denied path.

#### Evaluation

The test **fails** if:

- After ad ID deletion or reset, a third party receives a persistent identifier that also accompanied the old ad ID, or the app keeps sending a cached ad ID (Play Ads policy: no connecting a reset ID to the previous one without explicit consent).
- The app uses `ANDROID_ID`, a backup-restored GUID or a keychain-persisted UUID as its analytics, attribution or advertising identifier, so that reinstalling or clearing data does not reset it, and that identifier reaches third parties.
- After ATT denial or revocation, IDFA substitutes reach advertising or attribution parties.
- `isLimitAdTrackingEnabled()` is ignored for personalisation.

It **passes** if every reset produces fresh identifiers for tracking purposes and nothing on the third-party side links the old and new values. A persisted ID used only for security (device binding, fraud) and sent only to the security backend is an observation; record the purpose and separation for the client.

#### Demo

Illustrative summary table from an Android run:

```text
reset                     id             before                                after                                 sent to
ad ID deleted             adid           6b0e3c1d-...-0a1b2c3d4e5f             00000000-0000-0000-0000-000000000000  (no longer sent)
ad ID deleted             android_id     3f1c9a7be0d2c4a1                      3f1c9a7be0d2c4a1                      attribution.example.org  <- same party as old adid
uninstall + reinstall     install_id     0d6c2f0e-...-9a8b7c6d5e4f             0d6c2f0e-...-9a8b7c6d5e4f             attribution.example.org  <- restored from backup
```

Both persisting rows are reset bridges: the attribution party can join the user's new state to the old profile.

## Secure implementation

No OWASP best practice exists for this weakness. What we recommend, and what a retest should find:

**Choose the identifier by purpose.**

| Purpose | Use | Avoid |
|---|---|---|
| Analytics, crash reporting, A/B tests | Random install GUID or FID; IDFV for same-vendor analytics on iOS; App Set ID across own apps on Android (not for ads) | Advertising ID, `ANDROID_ID`, keychain-persisted IDs, hardware IDs |
| Advertising and ad measurement | Advertising ID / IDFA, only with consent and ATT authorisation; SKAdNetwork / AdAttributionKit on iOS | Any substitute when the ad ID is unavailable |
| Fraud and abuse prevention | Play Integrity, App Attest, DeviceCheck; device-binding keys ([MASWE-0054](/mobile/maswe-0054-device-attestation-not-implemented/)) | Hardware IDs, fingerprints shared with ad or analytics parties |
| Content protection | Platform DRM | Exporting the DRM ID for other purposes |
| Carrier or SIM features | Subscription ID; carrier APIs | IMEI, ICCID for non-carrier apps |

**Android: read the advertising ID only when allowed, never cache it, honour the opt-out.**

```kotlin
private const val ZERO_ID = "00000000-0000-0000-0000-000000000000"

suspend fun adIdForPersonalisation(context: Context): String? = withContext(Dispatchers.IO) {
    if (!Consent.adsPersonalisationAllowed()) return@withContext null
    val info = runCatching { AdvertisingIdClient.getAdvertisingIdInfo(context) }.getOrNull()
        ?: return@withContext null
    if (info.isLimitAdTrackingEnabled || info.id.isNullOrEmpty() || info.id == ZERO_ID) null else info.id
}
```

If the app does no advertising, remove the merged permission explicitly:

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          xmlns:tools="http://schemas.android.com/tools">
    <uses-permission android:name="com.google.android.gms.permission.AD_ID" tools:node="remove" />
</manifest>
```

**Android: keep install IDs out of backup and transfer** so that reinstall is a reset:

```xml
<!-- res/xml/data_extraction_rules.xml (Android 12+); mirror it in fullBackupContent for older versions -->
<data-extraction-rules>
    <cloud-backup>
        <exclude domain="sharedpref" path="analytics_ids.xml" />
    </cloud-backup>
    <device-transfer>
        <exclude domain="sharedpref" path="analytics_ids.xml" />
    </device-transfer>
</data-extraction-rules>
```

**iOS: ask for ATT before starting tracking SDKs, and start them in a non-tracking mode otherwise.**

```swift
import AppTrackingTransparency

func startAdvertisingStack() {
    ATTrackingManager.requestTrackingAuthorization { status in
        DispatchQueue.main.async {
            // Initialise ad/attribution SDKs only now, telling them the outcome.
            AdStack.start(trackingAllowed: status == .authorized)   // .denied/.restricted: SKAdNetwork/AdAttributionKit only
        }
    }
}
```

Call it when the app is active (for example from the first screen's `onAppear`), not from `application(_:didFinishLaunchingWithOptions:)`, where the prompt may not show. Do not gate features on the answer.

**iOS: do not let the keychain bridge reinstall for analytics IDs.** Store analytics IDs in the app container (`UserDefaults` or a file), which is deleted with the app. If an SDK or legacy code keeps IDs in the keychain, clear them on first launch after install:

```swift
let key = "hasLaunchedBefore"
if !UserDefaults.standard.bool(forKey: key) {
    // First launch after (re)install: remove identifiers left over from a previous install.
    SecItemDelete([kSecClass: kSecClassGenericPassword,
                   kSecAttrService: "com.example.app.analytics"] as CFDictionary)
    UserDefaults.standard.set(true, forKey: key)
}
```

Keychain items that serve security (device binding) are the exception, and should use a `...ThisDeviceOnly` accessibility class and not be synchronisable.

**Both: keep security signals separate.** Fraud and device-binding identifiers and risk scores go only to the security backend, in their own data store with their own access controls; analytics and ad SDKs never receive them.

**Both: vet SDKs as your own code.** Configure SDKs to stop collecting identifiers they do not need (most expose switches for advertising ID, IDFV and device-ID collection), require privacy manifests and accurate required-reason declarations from iOS SDKs, and re-run GT-PRIV-0068-3 when SDK versions change ([MASWE-0048](/mobile/maswe-0048-malicious-code-included-in-the-app/)).

## Rating findings

Apply the series-wide rule: rate by (a) what is processed beyond what is necessary, declared or consented, (b) sensitivity, (c) scale and reversibility, and (d) contradiction with the app's declarations or store policy. Regulatory risk is assessed by the client's legal team, not by these ratings.

| Rating | Typical conditions |
|---|---|
| **High** | Advertising or attribution identifiers sent to third parties without consent where consent is required, or IDFA substitutes (IDFV, keychain ID, hashed email, fingerprint bundle) sent to advertising or attribution parties after ATT denial. Reset bridging: a persistent ID sent with the advertising ID to the same third party, or analytics/advertising IDs that survive reinstall via the keychain or backup and reach third parties. Non-resettable hardware identifiers leaving the device. Any identifier transmission prohibited by the Families policy in a child-directed app. Fingerprinting by an SDK. |
| **Medium** | Ad ID read before consent but not observed leaving the device; `ANDROID_ID` used as the analytics ID sent to a processor-type analytics party; `isLimitAdTrackingEnabled()` ignored; security or fraud identifiers also sent to analytics; identifiers sent to destinations missing from the declarations. |
| **Low** | `AD_ID` permission merged but unused; cached ad ID with no observed misuse; keychain-persisted ID used only by the client's own backend for analytics; missing `NSUserTrackingUsageDescription` where the IDFA is never read. |
| **Info** | App-scoped IDs (GUID, FID, IDFV) to first-party or processor analytics; hardware-ID code paths that fail with `SecurityException` on current targets; security identifiers correctly separated; SKAdNetwork/AdAttributionKit in use. |

Raise a level for apps used by children, apps in sensitive categories (health, dating, religion, finance) where the profile itself reveals special-category data, and when the app's labels or privacy policy say it does not track. Lower a level when the behaviour is limited to a first-party context the user would expect and nothing reaches third parties.

In the report give: the identifier, the code that reads it (app or SDK, with stack), when it is read relative to consent and ATT, the destination hosts and what else travelled with it, the reset behaviour, the relevant store rule (quoted), the app's declarations, and the fix. Store-policy findings should name the policy section so that the client can check it against the current text.

## References

- OWASP MASWE: [MASWE-0068: Incorrect Use of Identifiers for User Tracking](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0068/); related [MASWE-0067](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0067/), [MASWE-0074](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0074/), [MASWE-0078](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0078/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-PRIVACY-2](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-2/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0117](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/), [MASTG-TECH-0126](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0126/), [MASTG-TECH-0033](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0033/), [MASTG-TECH-0086](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0086/), [MASTG-TECH-0120](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0120/), [MASTG-TECH-0136](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0136/), [MASTG-TECH-0137](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0137/) (CC BY-SA 4.0)
- OWASP MASTG tools: [Frida (MASTG-TOOL-0031)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/), [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [rabin2 (MASTG-TOOL-0129)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/), [mitmproxy (MASTG-TOOL-0097)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0097/), [plutil (MASTG-TOOL-0062)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0062/) (CC BY-SA 4.0)
- Sibling notes: [PRIVACY hub](/mobile/masvs-privacy-privacy-testing-guide/), [MASWE-0067](/mobile/maswe-0067-lack-of-anonymization-or-pseudonymisation/), [MASWE-0066](/mobile/maswe-0066-inadequate-permission-management/), [MASWE-0071](/mobile/maswe-0071-inadequate-privacy-defaults/), [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/), [MASWE-0074](/mobile/maswe-0074-inadequate-tracking-domains-declarations/), [MASWE-0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/); [MASWE-0054](/mobile/maswe-0054-device-attestation-not-implemented/), [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/), [MASWE-0048](/mobile/maswe-0048-malicious-code-included-in-the-app/), [traffic interception lab](/mobile/mobile-traffic-interception-lab/), [third-party libraries](/mobile/mastg-know-0004-third-party-libraries/)
- Android: [Best practices for unique identifiers](https://developer.android.com/identity/user-data-ids), [Advertising ID (AndroidX)](https://developer.android.com/identity/ad-id), [`AdvertisingIdClient`](https://developers.google.com/android/reference/com/google/android/gms/ads/identifier/AdvertisingIdClient), [App set ID](https://developer.android.com/identity/app-set-id), [`Settings.Secure.ANDROID_ID`](https://developer.android.com/reference/android/provider/Settings.Secure#ANDROID_ID), [Android 8.0 behaviour changes](https://developer.android.com/about/versions/oreo/android-8.0-changes), [Android 10 privacy changes](https://developer.android.com/about/versions/10/privacy/changes), [Privacy and security: resettable identifiers](https://developer.android.com/privacy-and-security/about), [Test backup and restore](https://developer.android.com/identity/data/testingbackup), [Firebase: manage installations](https://firebase.google.com/docs/projects/manage-installations), [Attribution Reporting for Android](https://developers.google.com/privacy-sandbox/private-advertising/attribution-reporting/android), [Update on plans for Privacy Sandbox technologies (17 October 2025)](https://privacysandbox.google.com/blog/update-on-plans-for-privacy-sandbox-technologies)
- Google Play: [Advertising ID (Play Console Help)](https://support.google.com/googleplay/android-developer/answer/6048248), [Ads policy](https://support.google.com/googleplay/android-developer/answer/9857753), [User Data policy](https://support.google.com/googleplay/android-developer/answer/10144311), [Families policies](https://support.google.com/googleplay/android-developer/answer/9893335), [Data safety guidance](https://support.google.com/googleplay/android-developer/answer/10787469)
- Apple: [User Privacy and Data Use](https://developer.apple.com/app-store/user-privacy-and-data-use/), [App Privacy details](https://developer.apple.com/app-store/app-privacy-details/), [App Review Guidelines](https://developer.apple.com/app-store/review/guidelines/) (5.1.1, 5.1.2), [App Tracking Transparency](https://developer.apple.com/documentation/apptrackingtransparency), [`requestTrackingAuthorization(completionHandler:)`](https://developer.apple.com/documentation/apptrackingtransparency/attrackingmanager/requesttrackingauthorization%28completionhandler%3A%29), [`advertisingIdentifier`](https://developer.apple.com/documentation/adsupport/asidentifiermanager/advertisingidentifier), [`identifierForVendor`](https://developer.apple.com/documentation/uikit/uidevice/identifierforvendor), [`DCDevice`](https://developer.apple.com/documentation/devicecheck/dcdevice), [SKAdNetwork](https://developer.apple.com/documentation/storekit/skadnetwork), [AdAttributionKit](https://developer.apple.com/documentation/adattributionkit), [Privacy manifest files](https://developer.apple.com/documentation/bundleresources/privacy-manifest-files), [Describing use of required reason API](https://developer.apple.com/documentation/bundleresources/describing-use-of-required-reason-api)
- Law and guidance: [GDPR (Regulation (EU) 2016/679)](https://eur-lex.europa.eu/eli/reg/2016/679/oj), Recital 30; [ePrivacy Directive 2002/58/EC](https://eur-lex.europa.eu/eli/dir/2002/58/oj); [PECR regulation 6](https://www.legislation.gov.uk/uksi/2003/2426/regulation/6); [EDPB Guidelines 2/2023 on the technical scope of Art. 5(3) ePrivacy](https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-22023-technical-scope-art-53-eprivacy-directive_en); CCPA/CPRA, Cal. Civ. Code § 1798.140
- CWE: [CWE-359](https://cwe.mitre.org/data/definitions/359.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
