---
title: "MASWE-0071: Inadequate Defaults for Privacy Relevant Actions"
date: 2026-11-10 22:05:00 +0000
subcategory: privacy
summary: "Testing what a fresh install, a third-party SDK and an app update switch on before the user decides: public profiles, sharing, backup, analytics and ads."
refs: [MASWE-0071, MASVS-PRIVACY-2, CWE-359]
tags: [android, ios, masvs-privacy, privacy-by-default, sdk, settings]
---

This note is part of our [MASVS-PRIVACY guide](/mobile/masvs-privacy-privacy-testing-guide/) and covers OWASP [MASWE-0071](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0071/): an app whose default settings expose more personal data than the feature needs. Most users never open the privacy settings, so whatever the app ships with is, for most of them, the privacy level they get. A profile that starts public, live location that starts on, contact sync enabled at sign-up, analytics and personalised ads running before anyone has answered the consent banner, a full cloud backup of a health diary, or precise location requested where the city would do: each is a decision made for the user, and usually in the direction that collects more. Defaults come from three places, and you test all three: the app's own settings, the platform behaviour the app inherits (Android Auto Backup, iOS backups, location accuracy, notification previews), and the third-party SDKs it embeds, which typically start collecting the moment they are initialised. Defaults also change: an update can switch on a new sharing feature for existing users or reset a choice. Below you will find the background (data protection by default, typical bad defaults, platform and SDK defaults), our three tests, secure patterns and how to rate the findings.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Background](#background)
  - [Android and iOS: Data protection by default](#android-and-ios-data-protection-by-default)
  - [Android and iOS: Typical bad defaults](#android-and-ios-typical-bad-defaults)
  - [Android: Platform defaults the app inherits](#android-platform-defaults-the-app-inherits)
  - [iOS: Platform defaults the app inherits](#ios-platform-defaults-the-app-inherits)
  - [Android and iOS: SDK defaults](#android-and-ios-sdk-defaults)
  - [Android and iOS: Defaults across updates and migrations](#android-and-ios-defaults-across-updates-and-migrations)
- [Tests](#tests)
  - [GT-PRIV-0071-1: Fresh-install default settings review (Android and iOS)](#gt-priv-0071-1-fresh-install-default-settings-review-android-and-ios)
  - [GT-PRIV-0071-2: SDK default configuration and pre-choice traffic (Android and iOS)](#gt-priv-0071-2-sdk-default-configuration-and-pre-choice-traffic-android-and-ios)
  - [GT-PRIV-0071-3: Defaults after update and migration (Android and iOS)](#gt-priv-0071-3-defaults-after-update-and-migration-android-and-ios)
- [Secure implementation](#secure-implementation)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

The OWASP requirement is *"The app uses adequate defaults for privacy relevant actions."* OWASP uses the same definition of privacy-relevant actions as [MASWE-0070](/mobile/maswe-0070-inadequate-awareness-for-privacy-actions/): sharing, exporting, publishing, synchronising, backing up, changing visibility, responding to another party's request, and moving data out of private storage. The weakness is present when the default configuration of such an action results in a more exposing privacy state than the requested functionality needs: a broader audience, more data, longer retention, public visibility or extra recipients, where a narrower default would work.

The test question is therefore always relative to the feature: "does this default expose more than what a user who wants *this feature* needs?" Live location on by default in a family-safety app the user installed to share location is not the same as live location on by default in a running app. A public profile is the point of a professional networking profile page; a public friends list, phone number discoverability and search-engine indexing usually are not.

MASWE-0071 carries OWASP's **P** and **EUDIW** profiles, applies to Android and iOS, and maps to [CWE-359](https://cwe.mitre.org/data/definitions/359.html). Its front matter maps it to **MASVS-PRIVACY-2**; in practice it also touches MASVS-PRIVACY-1 (minimisation, and SDKs that must not collect before consent) and MASVS-PRIVACY-4 (user control). We keep OWASP's mapping in the front matter.

**OWASP has no tests and no Knowledge items for this weakness**, and there are no legacy v1 PRIVACY tests to replace. The background below is ours, and the three tests are Guler Tech methodology, numbered GT-PRIV-0071-1 to -3.

Keep the neighbours apart:

| Question | Where it lives |
|---|---|
| Is the more exposing option preselected, switched on, or the result of doing nothing? | This note |
| Is the user told what an action discloses at the moment it happens? | [MASWE-0070](/mobile/maswe-0070-inadequate-awareness-for-privacy-actions/) |
| Is consent valid where consent is the basis (no pre-ticked boxes, prior, specific)? | [MASWE-0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/) |
| Does the app request more permissions or more precise access than needed? | [MASWE-0066](/mobile/maswe-0066-inadequate-permission-management/) |
| Can users change visibility settings later, and are the controls granular? | [MASWE-0077](/mobile/maswe-0077-inadequate-data-visibility-controls/) |
| Are advertising and other identifiers used for tracking appropriately? | [MASWE-0068](/mobile/maswe-0068-incorrect-use-of-identifiers-for-tracking/) |
| Does sensitive data end up in backups or on the lock screen at all? | [STORAGE hub](/mobile/masvs-storage-1-secure-storage-guide/), [MASWE-0037](/mobile/maswe-0037-sensitive-data-exposed-via-notifications/) |

The OWASP text of MASWE-0071 repeats one mode of introduction and one mitigation of MASWE-0070 word for word (*Unclear Disclosure Context* and *Provide Clear Disclosure Context and Control*). We cover those in the MASWE-0070 note and keep this one to defaults.

## Modes of Introduction

**Growth-driven defaults.** Discoverability by phone number, public profiles, contact sync and "people you may know" switched on because they improve network effects, not because the user asked.

**Pre-ticked and pre-selected options.** Opt-out checkboxes at sign-up ("Share my activity with partners"), "Select all" contacts preselected in an invite flow, audience selectors that start at "Public", share dialogs that include location by default. OWASP calls this *overly exposing defaults*: a broader audience, more data, longer retention, public visibility or extra recipients preselected.

**SDKs on by default.** Analytics, attribution, advertising and crash-reporting SDKs initialised in `Application.onCreate()` or `application(_:didFinishLaunchingWithOptions:)` with their default configuration, which is to collect, before the app has asked the user anything.

**Inherited platform defaults.** Android Auto Backup is on unless the app opts out; iOS includes the app's Documents and Library in device backups unless files are excluded; Android notifications are shown in full on many lock screens; location requests default to precise when the app asks for fine location.

**Long or unlimited retention by default.** Messages, location history or search history kept forever unless the user finds a setting; live sharing with no expiry.

**Defaults that drift.** A new feature shipped "on" for existing users, a settings migration that resets an opt-out, a server-side default changed for everyone, a restore or new-device sign-in that does not carry the user's choices.

## Impact

- **Exposure by inaction.** Data reaches other users, the public or third parties without the user ever making a choice. Because defaults apply to every user who does not act, the scale is the whole user base, and the most affected users are the least technical ones, including children.
- **Physical-world risk.** Location sharing, phone-number discoverability and public profiles on by default are the common route from an app setting to stalking, harassment and doxxing.
- **Third-party collection before consent.** SDKs that send device identifiers, events and location before the consent dialog has been answered process data for which there may be no lawful basis, and may contradict the app's Data safety and App Privacy declarations.
- **Durable copies.** Backups and sync create copies outside the app's control, with their own retention and access rules.
- **Regulatory and store exposure.** GDPR / UK GDPR Article 25(2) is explicitly about defaults; the ICO Children's code has a standard on them; Apple 5.1.2(v) forbids defaulting to all contacts. The client's legal team assesses the regulatory risk; your rating covers privacy impact.

## Mitigations

- **Default to the narrowest setting that delivers the feature**: private or friends-only audiences, location off or approximate, no discoverability by phone or email until switched on, no contact sync until requested, shortest sensible retention, expiry on live sharing. This is OWASP's *use privacy protective defaults*.
- **Make every optional processing opt-in.** No pre-ticked boxes, no preselected recipients, no "Select all".
- **Start SDKs disabled** and enable them only after the user's choice, using each SDK's documented collection and consent flags; verify with traffic, not only with code.
- **Decide platform defaults deliberately**: configure `dataExtractionRules` / `fullBackupContent` on Android and `isExcludedFromBackup` on iOS for data that should not leave the device; request approximate location when it is enough; set notification visibility for sensitive content.
- **Preserve choices across updates**, and default new features to the most private setting for existing users, with a notice ([MASWE-0070](/mobile/maswe-0070-inadequate-awareness-for-privacy-actions/)).

## Background

There is no OWASP Knowledge item for this weakness. This section explains the mechanisms and the reference points.

### Android and iOS: Data protection by default

*This is technical testing guidance, not legal advice. Hand the evidence to the client's DPO or legal team for the legal assessment.*

- **GDPR / UK GDPR Article 25(2)** requires measures that ensure that, **by default**, only personal data necessary for each specific purpose is processed, covering the amount collected, the extent of processing, the storage period and accessibility. Its last sentence is the one most relevant to apps: by default, personal data must not be made accessible *without the individual's intervention to an indefinite number of natural persons*. A profile, post or location that is public unless the user changes a setting is exactly that.
- **EDPB Guidelines 4/2019 on Article 25** (version 2.0, adopted October 2020) explain "by default" as the pre-existing or preselected value of a configurable setting, and stress that defaults must be the most privacy-protective option where a choice exists.
- **Pre-ticked boxes are not consent.** GDPR Recital 32 says silence, pre-ticked boxes or inactivity do not constitute consent, and the CJEU confirmed this for device storage in *Planet49* (C-673/17, 2019). Where analytics or advertising SDKs rely on consent (and under ePrivacy / PECR regulation 6 their storage of, and access to, identifiers on the device usually needs it), "on until you opt out" is not a valid default. The UK Data (Use and Access) Act 2025 adds PECR exemptions for some low-risk purposes, including certain statistical analytics; check commencement and current ICO guidance before relying on them.
- **ICO Age appropriate design code (Children's code)**, standard 7 *Default settings*: settings must be "high privacy" by default unless there is a compelling reason, taking the child's best interests into account. The standard also says optional uses such as personalisation and third-party sharing should be on only if the child switches them on, that choices should survive software updates, and that new features which cannot inherit existing settings should default to high privacy. Standards 10 (geolocation) and 12 (profiling) add "off by default" for those. The code applies to online services likely to be accessed by children in the UK, which is broader than apps aimed at children.
- **EU Digital Services Act**, Article 28, requires online platforms accessible to minors to ensure a high level of privacy, safety and security for them; the Commission's guidelines on Article 28 treat private-by-default accounts as a key measure.
- **Apple App Store Review Guideline 5.1.2(v)**: *"do not include a Select All option or default the selection of all contacts"*. 5.1.2(i) requires explicit permission before sharing personal data with third parties, which rules out sharing switched on by default.
- **Google Play**: the User Data policy's prominent disclosure and consent requirement cannot be met by a preselected option; the Families policy restricts identifiers and SDKs in apps whose audience includes children (check the current text for the exact rules).

### Android and iOS: Typical bad defaults

| Default | Why it is a problem | Less exposing default |
|---|---|---|
| Profile, posts or activity **public** | Article 25(2) "indefinite number of persons"; indexing and scraping are irreversible | Friends or private; public as an explicit choice per item or in settings |
| **Discoverable by phone number / email** | Lets anyone with a number confirm an account and see the profile | Off, or contacts-only |
| **Location sharing on** (live sharing, location on posts, "nearby" visibility) | Physical risk; continuous disclosure | Off; on per session with expiry |
| **Contact sync on** at sign-up | Uploads data about non-users; cannot be undone on their behalf | Off; on request, with selection |
| **Analytics and personalised ads on** before the consent choice | Processing without a lawful basis where consent is needed; contradicts declarations | SDK collection disabled until the user chooses |
| **Cloud backup of sensitive data** (health logs, messages, documents) | Copies outside the app's control and key management | Excluded from backup, or app-managed end-to-end encrypted backup the user enables |
| **Precise location** where approximate suffices | More data than the purpose needs; precise location is highly identifying | Approximate (Android coarse, iOS reduced accuracy) |
| **Notification previews of sensitive content** | Content on the lock screen, watch and car display | Generic text with the content inside the app; see [MASWE-0037](/mobile/maswe-0037-sensitive-data-exposed-via-notifications/) |
| **Read receipts, online status, last seen** visible to everyone | Behavioural data to all users | Contacts only, user-configurable ([MASWE-0077](/mobile/maswe-0077-inadequate-data-visibility-controls/)) |
| **Unlimited retention** of history | Longer storage than needed | Time-limited default with an option to keep longer |
| **AI features using user content** for model improvement by default | Secondary use, possibly by a third party | Off; opt-in with a clear statement |

### Android: Platform defaults the app inherits

- **Auto Backup** is on by default for apps targeting API 23 or higher: `android:allowBackup` defaults to `true`, and the system backs up most of the app's private files (not `cache/`, `code_cache/` or `no_backup/`) to the user's Google account, up to 25 MB per app. For apps targeting Android 12 (API 31) or higher, `allowBackup="false"` disables cloud backup but **not** device-to-device transfer; only `android:dataExtractionRules` controls both. Older targets use `android:fullBackupContent`. The [STORAGE hub](/mobile/masvs-storage-1-secure-storage-guide/) and [MASWE-0001](/mobile/maswe-0001-sensitive-data-unencrypted-private-storage/) cover the mechanics and how to test what a backup contains. For this note the question is whether sensitive data is backed up *by default* without the user choosing it.
- **Location accuracy.** Since Android 12, apps targeting API 31 or higher that request `ACCESS_FINE_LOCATION` must also request `ACCESS_COARSE_LOCATION` in the same request, and the user can choose approximate. Requesting only coarse location is the privacy-protective default when the feature works with it.
- **Notification visibility.** `VISIBILITY_PRIVATE` is the default for notifications, but redaction depends on the user's lock-screen setting, and many devices default to showing all content. Details and tests are in [MASWE-0037](/mobile/maswe-0037-sensitive-data-exposed-via-notifications/).
- **Advertising ID permission.** Apps targeting Android 13 (API 33) or higher must declare `com.google.android.gms.permission.AD_ID` to read the advertising ID. Several Google Play services libraries (ads, and the analytics measurement library) merge that permission into the app's manifest automatically, so an app can end up with advertising ID access it never asked for. Check the **merged** manifest, and remove the permission with `tools:node="remove"` if the app does not need it. Identifier use is [MASWE-0068](/mobile/maswe-0068-incorrect-use-of-identifiers-for-tracking/).
- **Media access.** The photo picker (Android 13, backported via Google Play services) and partial photo access (Android 14, `READ_MEDIA_VISUAL_USER_SELECTED`) let the app work with selected items. Requesting full media access by default is a permission question for [MASWE-0066](/mobile/maswe-0066-inadequate-permission-management/).

### iOS: Platform defaults the app inherits

- **Device backups** (iCloud Backup and Finder / iTunes backups) include the app container's `Documents/` and `Library/` directories, except `Library/Caches/` and `tmp/`, unless the app sets `URLResourceValues.isExcludedFromBackup` on files or directories. iCloud Backup is end-to-end encrypted only when the user has turned on Advanced Data Protection (iOS 16.2 and later); otherwise Apple holds the keys. Keychain items are backed up unless they use a `ThisDeviceOnly` accessibility class. The [STORAGE hub](/mobile/masvs-storage-1-secure-storage-guide/) has the testing details.
- **App-level iCloud sync.** CloudKit, iCloud Drive documents and `NSUbiquitousKeyValueStore` sync data across the user's devices. Turning these on by default for sensitive data is an app decision, visible in the entitlements (`com.apple.developer.icloud-services`, `com.apple.developer.ubiquity-kvstore-identifier`).
- **Location accuracy.** Since iOS 14 the user can switch off *Precise Location* per app. The app can make reduced accuracy the default by setting `NSLocationDefaultAccuracyReduced` to `true` in `Info.plist`, and ask for temporary full accuracy with `requestTemporaryFullAccuracyAuthorization(withPurposeKey:)` only where a feature needs it.
- **Notification previews.** Under *Settings > Notifications > Show Previews* the default on Face ID devices is "When Unlocked"; on other devices, or when the user chose "Always", previews appear on the lock screen. The app controls the content and the hidden-preview placeholder ([MASWE-0037](/mobile/maswe-0037-sensitive-data-exposed-via-notifications/)).
- **Tracking.** Since iOS 14.5 the advertising identifier is all zeros until the user authorises tracking through App Tracking Transparency, so the platform default is "no tracking". An app that tracks by other means before asking circumvents that default ([MASWE-0068](/mobile/maswe-0068-incorrect-use-of-identifiers-for-tracking/)).
- **Photos and contacts.** `PHPickerViewController`, limited photo library access and, since iOS 18, limited contacts access let the app work with a subset. Defaulting to full access requests is covered in [MASWE-0066](/mobile/maswe-0066-inadequate-permission-management/).

### Android and iOS: SDK defaults

Most analytics, attribution, advertising and crash-reporting SDKs start collecting when they are initialised, and many initialise themselves automatically (through a merged `ContentProvider` or an `androidx.startup` `Initializer` on Android, or at app launch on iOS). Unless the app sets a "disabled by default" flag and enables the SDK after the user's choice, collection starts before any consent dialog is answered. The flags are documented per SDK; Firebase / Google Analytics is a common example and shows the pattern:

| Purpose | Android (`<meta-data>` in the manifest) | iOS (`Info.plist`) |
|---|---|---|
| Disable collection until enabled in code with `setAnalyticsCollectionEnabled(true)` | `firebase_analytics_collection_enabled` = `false` | `FIREBASE_ANALYTICS_COLLECTION_ENABLED` = `NO` |
| Deactivate collection permanently for this build | `firebase_analytics_collection_deactivated` = `true` | `FIREBASE_ANALYTICS_COLLECTION_DEACTIVATED` = `YES` |
| Do not collect the advertising ID / IDFV | `google_analytics_adid_collection_enabled` = `false` | `GOOGLE_ANALYTICS_IDFV_COLLECTION_ENABLED` = `NO` (IDFA collection is controlled by not linking AdSupport) |
| Ad personalisation off by default | `google_analytics_default_allow_ad_personalization_signals` = `false` | `GOOGLE_ANALYTICS_DEFAULT_ALLOW_AD_PERSONALIZATION_SIGNALS` = `NO` |
| Consent mode defaults (`analytics_storage`, `ad_storage`, `ad_user_data`, `ad_personalization`) | `google_analytics_default_allow_analytics_storage`, `..._ad_storage`, `..._ad_user_data`, `..._ad_personalization_signals` | `GOOGLE_ANALYTICS_DEFAULT_ALLOW_ANALYTICS_STORAGE`, `..._AD_STORAGE`, `..._AD_USER_DATA`, `..._AD_PERSONALIZATION_SIGNALS` |

Without these keys, analytics collection is enabled, and Google documents that no consent mode values are set by default, so nothing restricts collection until the app calls `setConsent`. Other SDKs have equivalents (auto-logging of app events, advertiser ID collection, auto-initialisation flags); find them in each vendor's documentation and in the SDK's own merged manifest entries. The SDK names here are examples of a pattern, not a judgement on any vendor: almost every SDK in these categories defaults to collecting.

Two further points:

- **Consent management platforms** that implement the IAB Transparency and Consent Framework store the user's choice in the app's default `SharedPreferences` or `NSUserDefaults` under `IABTCF_` keys (for example `IABTCF_TCString`, `IABTCF_gdprApplies`), and ad SDKs read them. Before the user has chosen, those keys should be absent and the SDKs should not be sending identifiers.
- **Flags in code are not proof.** An app may set the flag correctly and still initialise a second SDK, a server-side integration, or a web view with its own trackers. Traffic before the user's choice (GT-PRIV-0071-2) is the evidence that counts.

### Android and iOS: Defaults across updates and migrations

Defaults are not only a first-install question. Watch for:

- **New features shipped on** for existing users (a new "nearby" mode, a new AI feature that uses message history, a new partner integration) without asking.
- **Settings migrations** that rename or restructure preferences and fall back to the default for users who had opted out, or a consent framework upgrade that resets stored choices to "accepted".
- **Server-side defaults** changed for all accounts without an app release.
- **Restore and new-device sign-in**: Auto Backup, device-to-device transfer, iCloud restore or a cloud-stored profile may or may not carry the user's privacy choices; a fresh device that silently re-enables contact sync is a finding.

The ICO Children's code says this outright: keep existing settings through updates, and default new features to high privacy where they cannot inherit them. The same principle is a good test baseline for every app.

## Tests

Run all three on Android and iOS. The two platforms often disagree: a default fixed on one is commonly still on in the other, and SDK configuration lives in different files.

### GT-PRIV-0071-1: Fresh-install default settings review (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Record every privacy-relevant setting and preselected option exactly as a new user gets it, check its effect on the server and on other users, and judge it against the narrowest setting the feature needs.

#### Prerequisites

- The release build, installed fresh on Android and iOS test devices you control. Clear state first: `adb uninstall com.example.app` (or `adb shell pm clear com.example.app`); on iOS delete the app and reinstall.
- A new test account created during the test, a second unconnected test account and a logged-out browser to see what others see.
- Proxy interception of the app's own traffic ([traffic interception lab](/mobile/mobile-traffic-interception-lab/)).
- The decompiled app (apktool / jadx for Android; the extracted IPA for iOS).

#### Steps

1. **Sign-up flow.** Go through registration and onboarding and capture every checkbox, toggle and selector with its initial state. Note any pre-ticked option and any "Continue" that accepts more than the screen shows.
2. **Settings inventory.** Open every privacy, account, notification, sharing and integration setting and record its default. Then fetch the server-side view through the proxy (typically a `GET` on a settings or profile endpoint) and compare: a toggle shown "off" in the UI while the API returns `true` is a strong finding.
3. **Look from outside.** From the second account, search for the new account by name, phone number and email, and view its profile, posts, friends list and status. From the logged-out browser, open any public profile URL. Record what is visible by default.
4. **Per-action defaults.** For each disclosing action from the [MASWE-0070](/mobile/maswe-0070-inadequate-awareness-for-privacy-actions/) inventory, open it and note the preselected audience, items, metadata and duration (for example "Share live location: 8 hours", "Audience: Public", "Invite: all 214 contacts selected").
5. **Platform defaults, Android.**

   ```bash
   apktool d -s -o out app.apk
   grep -oE 'android:(allowBackup|fullBackupContent|dataExtractionRules)="[^"]*"' out/AndroidManifest.xml
   grep -E 'ACCESS_(FINE|COARSE|BACKGROUND)_LOCATION|READ_CONTACTS|READ_MEDIA_|AD_ID' out/AndroidManifest.xml
   adb shell dumpsys package com.example.app | grep -E 'pkgFlags=|ALLOW_BACKUP'
   ```

   Read the referenced `res/xml/` backup rules and check whether the sensitive data stores are excluded. Check notification channel lock-screen visibility as described in [MASWE-0037](/mobile/maswe-0037-sensitive-data-exposed-via-notifications/).
6. **Platform defaults, iOS.**

   ```bash
   plutil -p Payload/App.app/Info.plist | grep -E 'NSLocation|NSUserTracking|UIBackgroundModes' -A3
   codesign -d --entitlements :- Payload/App.app | grep -A4 -E 'icloud|ubiquity'
   ```

   On a jailbroken test device or with a debuggable build, check whether sensitive files carry the backup exclusion attribute, for example by hooking `-[NSURL setResourceValue:forKey:error:]` and `-[NSURL setResourceValues:error:]` with Frida and watching for `NSURLIsExcludedFromBackupKey` (objection's `env` command shows the Data container paths to compare against). Alternatively, make an encrypted Finder backup of the test device and look for the app's sensitive files in it (see the [STORAGE hub](/mobile/masvs-storage-1-secure-storage-guide/)).
7. **Location accuracy.** Trigger the location feature and note what the system dialog offers: on Android whether the app asked for precise; on iOS whether "Precise: On" is the preselected state (it is, unless `NSLocationDefaultAccuracyReduced` is set). Judge it against what the feature needs.
8. **Rate each default** with three questions: is it needed for the feature the user asked for; is there a narrower setting that still works; is it reversible.

#### Observation

A defaults table per platform (setting, default in UI, default on server, visible to whom, needed for the feature, narrower option), the backup and location configuration, and screenshots of preselected options.

#### Evaluation

The test **fails** when a setting or preselection exposes more than the requested feature needs: public or discoverable by default where the feature works without it, location or contact sync on before the user asks, all contacts or all items preselected, sensitive data backed up or synced off-device by default, precise location where approximate would do, sensitive notification content shown by default, or a UI state that differs from the server state. It **passes** when every optional disclosure starts at the narrowest option and the user turns it on.

Common false positives: a setting that is public because public is the feature the user signed up for (a seller profile on a marketplace), as long as the extra fields (phone, location, friends) are not; data in backups that is not sensitive or is protected end-to-end by the app; precise location for turn-by-turn navigation.

#### Demo

Illustrative Android manifest and backup rules with an inadequate default, then a fixed version:

```xml
<!-- Before: Auto Backup on by default, nothing excluded, includes the health diary database -->
<application
    android:allowBackup="true"
    android:label="@string/app_name">
</application>

<!-- After: data_extraction_rules.xml excludes sensitive stores from cloud backup and device transfer -->
<application
    android:allowBackup="true"
    android:dataExtractionRules="@xml/data_extraction_rules"
    android:fullBackupContent="@xml/backup_rules_legacy"
    android:label="@string/app_name">
</application>
```

```xml
<!-- res/xml/data_extraction_rules.xml -->
<data-extraction-rules>
    <cloud-backup>
        <exclude domain="database" path="diary.db" />
        <exclude domain="sharedpref" path="session.xml" />
    </cloud-backup>
    <device-transfer>
        <exclude domain="sharedpref" path="session.xml" />
    </device-transfer>
</data-extraction-rules>
```

Illustrative defaults table excerpt:

```text
Setting                      UI default   API default                    Visible to (2nd acct / logged out)   Needed?   Result
Profile visibility           Friends      "visibility":"public"          name, photo, city / same             no        FAIL (UI != server)
Find me by phone number      On           "discoverable_by_phone":true   account found by number              no        FAIL
Share location on posts      Off          "post_location":false          -                                    -         pass
Live location duration       8 h          -                              -                                    1 h ok    LOW
Diary in cloud backup        (no option)  -                              allowBackup=true, no rules           no        FAIL
```

### GT-PRIV-0071-2: SDK default configuration and pre-choice traffic (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Check how embedded SDKs are configured by default, then prove what they actually send before the user has made any choice. This is the test where the code says "disabled until consent" and the traffic often says otherwise.

#### Prerequisites

- The release build, a clean install, and proxy interception set up **before** the first launch.
- An SDK inventory: package prefixes on Android, frameworks under `Payload/App.app/Frameworks/` on iOS; see [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/) and [third-party libraries](/mobile/mastg-know-0004-third-party-libraries/) for building one.
- Optional: a rooted or jailbroken test device with Frida; App Privacy Report switched on before installation on iOS.

#### Steps

1. **Static configuration, Android.** List `<meta-data>` entries, auto-initialising providers and permissions merged from SDKs:

   ```bash
   grep -E '<meta-data' out/AndroidManifest.xml | grep -iE 'collection|analytics|ads?_|adid|consent|auto_?init|AutoLog|AdvertiserID|personali'
   grep -E '<provider' out/AndroidManifest.xml | grep -oE 'android:name="[^"]*"'
   grep -n 'AD_ID' out/AndroidManifest.xml
   ```

   Then find where the app initialises each SDK and whether it calls the SDK's enable or consent API only after the user's choice (jadx output: `setAnalyticsCollectionEnabled`, `setConsent`, and each SDK's own `init` / `start` / `setEnabled` calls).
2. **Static configuration, iOS.**

   ```bash
   plutil -p Payload/App.app/Info.plist | grep -iE 'COLLECTION|GOOGLE_ANALYTICS|AutoLog|AdvertiserID|AutoInit|NSPrivacy|NSUserTracking'
   ls Payload/App.app/Frameworks/
   otool -L Payload/App.app/App | grep -i AdSupport
   ```

   Linking AdSupport means the app can read the IDFA once tracking is authorised; check whether `ATTrackingManager.requestTrackingAuthorization` is called and when. The privacy manifests (`PrivacyInfo.xcprivacy`) of the app and its SDKs declare tracking domains; compare them with traffic as described in [MASWE-0074](/mobile/maswe-0074-inadequate-tracking-domains-declarations/).
3. **Pre-choice traffic.** Start capturing, launch the app for the first time and **do not answer** the consent dialog or any prompt for two minutes. Background the app, bring it back, wait again, then kill it and relaunch. List the hosts contacted:

   ```bash
   mitmdump -q -w prechoice.mitm            # capture; stop with Ctrl+C
   mitmdump -nr prechoice.mitm --flow-detail 1 | grep -oE 'https?://[^/ ]+' | sort | uniq -c | sort -rn
   ```

   For each non-first-party host, open the requests and note what they carry: advertising ID or IDFV, install or device identifiers, event names, screen names, location, and the user's account ID.
4. **After "reject" and after "accept".** Repeat from a clean install, choosing "reject all", then again with "accept". The reject run should look like the pre-choice run minus anything the user did not agree to; it must not look like the accept run.
5. **Stored consent state.** Check what the app stored before and after the choice (rooted / jailbroken test devices):

   ```bash
   adb shell su -c "cat /data/data/com.example.app/shared_prefs/com.example.app_preferences.xml" | grep -E 'IABTCF_|consent'
   ```

   On iOS, `objection -g com.example.app explore` then `ios nsuserdefaults get`, and look for `IABTCF_` and consent keys.
6. **Runtime trace** (optional), to show the order of initialisation and consent calls:

   ```bash
   frida-trace -U -f com.example.app \
     -j 'com.google.firebase.analytics.FirebaseAnalytics!setAnalyticsCollectionEnabled' \
     -j 'com.google.firebase.analytics.FirebaseAnalytics!setConsent'
   frida-trace -U -f com.example.app -m '+[FIRAnalytics setAnalyticsCollectionEnabled:]' -m '+[FIRAnalytics setConsent:]'
   ```

   Replace the class names with the SDKs the app actually uses. For Firebase Analytics on Android you can also turn on its verbose logging, which prints every logged event: `adb shell setprop log.tag.FA VERBOSE`, `adb shell setprop log.tag.FA-SVC VERBOSE`, then `adb logcat -v time -s FA FA-SVC`.
7. **iOS App Privacy Report.** After the pre-choice run, open the report and note the domains the app contacted and any sensor or data access. Export it as evidence.

#### Observation

The SDK flags found (or missing) per platform, the order of initialisation and consent calls, the hosts and identifiers seen before the choice, after reject and after accept, and the stored consent keys.

#### Evaluation

The test **fails** when an analytics, attribution or advertising SDK sends identifiers or behavioural events before the user has made a choice where the app's own design or declarations say it asks for one, or after the user rejected; when ad personalisation is on by default without a choice; when the `AD_ID` permission is merged in without a need; or when the consent state defaults to granted. It **passes** when, before a choice and after rejection, only strictly necessary first-party traffic and requests the app has declared occur, and SDK collection begins only after acceptance.

Whether a particular SDK needs consent in a particular market is a legal question; report the facts (what was sent, to whom, before which choice) and let the client's legal team decide. Common false positives: a consent platform fetching its own configuration; crash reports sent without identifiers where the policy declares them; a first-party request that carries no personal data.

#### Demo

Illustrative manifest with collection off until the user chooses, and the code that switches it on:

```xml
<application>
    <meta-data android:name="firebase_analytics_collection_enabled" android:value="false" />
    <meta-data android:name="google_analytics_adid_collection_enabled" android:value="false" />
    <meta-data android:name="google_analytics_default_allow_analytics_storage" android:value="false" />
    <meta-data android:name="google_analytics_default_allow_ad_storage" android:value="false" />
    <meta-data android:name="google_analytics_default_allow_ad_user_data" android:value="false" />
    <meta-data android:name="google_analytics_default_allow_ad_personalization_signals" android:value="false" />
</application>
```

```kotlin
fun onPrivacyChoice(analytics: Boolean, ads: Boolean) {
    val fa = Firebase.analytics
    fa.setConsent {
        analyticsStorage(if (analytics) ConsentStatus.GRANTED else ConsentStatus.DENIED)
        adStorage(if (ads) ConsentStatus.GRANTED else ConsentStatus.DENIED)
        adUserData(if (ads) ConsentStatus.GRANTED else ConsentStatus.DENIED)
        adPersonalization(if (ads) ConsentStatus.GRANTED else ConsentStatus.DENIED)
    }
    fa.setAnalyticsCollectionEnabled(analytics)
}
```

Illustrative host list from a non-compliant pre-choice run (hosts replaced with documentation names):

```text
$ mitmdump -nr prechoice.mitm --flow-detail 1 | grep -oE 'https?://[^/ ]+' | sort | uniq -c | sort -rn
  14 https://api.example.com
   6 https://analytics.example.net        <- events with device ID, before consent dialog answered
   3 https://attribution.example.org      <- install referrer + advertising ID
   2 https://consent.example.com
```

The compliant build shows only `api.example.com` and `consent.example.com` until the user accepts.

### GT-PRIV-0071-3: Defaults after update and migration (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Check that an existing user's privacy choices survive an app update, a restore and a new-device sign-in, and that features new in the update start in their most private state.

#### Prerequisites

- Two consecutive builds signed with the same key (previous production release and the candidate), from the client: Android APKs or AABs converted to APKs; iOS builds installable on your test device (Ad Hoc or TestFlight). Release notes for the candidate, so you know which features are new.
- A test account, the proxy, and for local state a rooted Android or jailbroken iOS test device (or debuggable builds).

#### Steps

1. **Install the previous build** and sign in. Set every privacy setting to its most restrictive value, reject analytics and ads in the consent dialog, and switch off any sharing.
2. **Record the baseline**: screenshots of the settings, the settings API response from the proxy, the local preferences and stored consent keys (as in GT-PRIV-0071-2, step 5).
3. **Upgrade in place.** On Android: `adb install -r new.apk` (or `adb install-multiple -r` for split APKs). On iOS: install the new build over the old one through TestFlight or Xcode's *Devices and Simulators* window, without deleting the app.
4. **Launch with the proxy on** and do not touch anything for two minutes. Note any traffic to SDK hosts that the baseline did not have, and any settings write the app makes on its own (`PUT`/`PATCH`/`POST` to settings or consent endpoints).
5. **Compare** the settings screens, the API response, the local preferences and the consent keys with the baseline. Then open every **new** feature and record its default.
6. **Restore and new device.** Back up and restore (Android: device-to-device transfer, or a cloud backup restore on a second test device; iOS: an encrypted Finder backup restored to a second test device), and separately sign in fresh on a second device. Compare again.
7. **Server-side drift** (if the engagement runs for weeks): fetch the settings API for an untouched test account at the start and the end and compare.

#### Observation

Baseline versus post-update, post-restore and new-device values for every setting, consent key and SDK host, plus the defaults of new features.

#### Evaluation

The test **fails** when an update, restore or new-device sign-in turns a user's restrictive choice into a more exposing one, resets a consent rejection, starts SDK traffic the user had rejected, or ships a new disclosing feature switched on for existing users without a choice. It **passes** when every choice persists, or the app asks again with the private option as the default, and new features start off.

A re-prompt is acceptable when the processing really changed; it must default to the private option and be explained ([MASWE-0070](/mobile/maswe-0070-inadequate-awareness-for-privacy-actions/), [MASWE-0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/)). Losing local preferences after a restore is not a finding if the app then asks again or defaults to private; it is a finding if it defaults to sharing.

#### Demo

Illustrative migration bug: a renamed preference key falls back to `true` for users who had opted out.

```kotlin
// v5: key "share_activity" (user had set false)
// v6: renamed to "activity_sharing_enabled" with a "growth-friendly" default
val sharing = prefs.getBoolean("activity_sharing_enabled", true)   // old value ignored -> sharing on
```

Fixed: migrate the old value and default to the private option.

```kotlin
val sharing = if (prefs.contains("activity_sharing_enabled")) {
    prefs.getBoolean("activity_sharing_enabled", false)
} else {
    prefs.getBoolean("share_activity", false).also {
        prefs.edit().putBoolean("activity_sharing_enabled", it).remove("share_activity").apply()
    }
}
```

Illustrative comparison:

```text
Setting / signal               Baseline (v5)    After update (v6)   Result
share_activity / API           false            true                FAIL (reset by migration)
IABTCF_TCString                rejected         rejected            pass
Hosts before interaction       api only         api + analytics     FAIL (SDK upgraded, flag dropped)
New "Nearby" feature           n/a              On                  FAIL (new feature on by default)
```

## Secure implementation

No OWASP best practice exists for this weakness; ours:

- **Write down the default for every privacy-relevant setting** with its justification ("needed for the feature" or "most private option"), keep it next to the code, and review it like a security control.
- **Private, off, approximate, short.** Friends-only or private audiences; no discoverability by phone or email; location and contact sync off; approximate location; live sharing with expiry; time-limited history by default.
- **No pre-ticked boxes, no preselected recipients**, no "Select all" (Apple 5.1.2(v)); bulk actions start with nothing selected.
- **SDKs disabled until the choice**: set each SDK's "collection disabled" and consent-default flags in the manifest and `Info.plist`, initialise or enable after the user decides, remove the `AD_ID` permission if not needed (`<uses-permission android:name="com.google.android.gms.permission.AD_ID" tools:node="remove" />`), and add a release test that captures traffic on first launch and fails on any non-allowlisted host.
- **Backups**: Android `dataExtractionRules` (and `fullBackupContent` for older targets) excluding sensitive stores and session tokens; iOS `isExcludedFromBackup` on sensitive files and `ThisDeviceOnly` keychain classes; or an app-managed, end-to-end encrypted backup the user turns on.
- **Location**: request `ACCESS_COARSE_LOCATION` only, or set `NSLocationDefaultAccuracyReduced`, unless the feature needs precision; ask for precise or temporary full accuracy at the moment it is needed.
- **Notifications**: generic text for sensitive notifications by default, with a user option for full previews ([MASWE-0037](/mobile/maswe-0037-sensitive-data-exposed-via-notifications/)).
- **Updates**: migrate preferences explicitly with a private fallback, ship new disclosing features off for existing users, and re-run GT-PRIV-0071-3 for every release that touches settings or SDK versions.
- **Children and likely child users**: apply the ICO Children's code standards on defaults, geolocation and profiling regardless of the app's intended audience, if children are likely to use it.

## Rating findings

Apply the series-wide rule: rate by what personal data the default exposes beyond what the feature needs, its sensitivity, scale (defaults affect every user who does not act) and reversibility, and whether it contradicts the app's declarations or store policy. Regulatory risk is assessed by the client's legal team, not by this rating.

| Rating | Conditions |
|---|---|
| **High** | Precise location, contacts, health, children's data or private content shared with other users, the public or third parties by default; analytics, attribution or advertising SDKs sending identifiers before the user's choice or after rejection where the app asks for consent or declares that it does; an update that silently reverses a user's opt-out for sensitive sharing; profiles discoverable by phone number by default in an app with sensitive content; any of these in an app likely to be used by children. |
| **Medium** | Public profile or posts by default with personal fields beyond what the feature needs; contact sync or "select all" preselected; sensitive data included in cloud backup by default without app-level protection; precise location requested where approximate would do; ad personalisation on by default; `AD_ID` merged without need where the ID is then sent; UI and server defaults that disagree. |
| **Low** | Exposing defaults for low-sensitivity data (read receipts, online status to contacts); long default retention; live sharing with a long but finite default duration; new features on by default with clear notice and easy reversal. |
| **Info** | Defaults that match the feature the user chose; recommendations to document defaults or add release checks; SDK flags missing where traffic shows no collection before choice. |

Raise a level when the default contradicts the Data safety section, App Privacy details, the privacy policy or the consent dialog's own wording, and for apps likely to be used by children. Lower a level when the exposed data reaches only the user's own devices or individually chosen recipients.

In the report give the setting or SDK, the default on each platform (UI and server), the evidence (screenshots, manifest or `Info.plist` lines, captured requests with field names and redacted values, the host list before choice), who can see or receives the data by default, the narrower default that would still deliver the feature, and how the user can currently change it.

## References

- OWASP MASWE: [MASWE-0071: Inadequate Defaults for Privacy Relevant Actions](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0071/); related [MASWE-0070](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0070/), [MASWE-0078](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0078/), [MASWE-0068](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0068/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-PRIVACY-1](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-1/), [MASVS-PRIVACY-2](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-2/), [MASVS-PRIVACY-4](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-4/) (CC BY-SA 4.0)
- Series: [MASVS-PRIVACY hub](/mobile/masvs-privacy-privacy-testing-guide/), [MASWE-0070 awareness for privacy-relevant actions](/mobile/maswe-0070-inadequate-awareness-for-privacy-actions/), [MASWE-0066](/mobile/maswe-0066-inadequate-permission-management/), [MASWE-0068](/mobile/maswe-0068-incorrect-use-of-identifiers-for-tracking/), [MASWE-0074](/mobile/maswe-0074-inadequate-tracking-domains-declarations/), [MASWE-0077](/mobile/maswe-0077-inadequate-data-visibility-controls/), [MASWE-0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/); other notes: [MASWE-0037 notifications](/mobile/maswe-0037-sensitive-data-exposed-via-notifications/), [STORAGE hub](/mobile/masvs-storage-1-secure-storage-guide/), [MASWE-0001](/mobile/maswe-0001-sensitive-data-unencrypted-private-storage/), [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/), [third-party libraries](/mobile/mastg-know-0004-third-party-libraries/), [traffic interception lab](/mobile/mobile-traffic-interception-lab/)
- Law and regulators: [GDPR (Regulation (EU) 2016/679), EUR-Lex](https://eur-lex.europa.eu/eli/reg/2016/679/oj), [UK GDPR Article 25, legislation.gov.uk](https://www.legislation.gov.uk/eur/2016/679/article/25), [EDPB Guidelines 4/2019 on Article 25](https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-42019-article-25-data-protection-design-and_en), [EDPB Guidelines 05/2020 on consent](https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-052020-consent-under-regulation-2016679_en), [CJEU C-673/17 Planet49](https://curia.europa.eu/juris/liste.jsf?num=C-673/17), [PECR regulation 6](https://www.legislation.gov.uk/uksi/2003/2426/regulation/6), [Data (Use and Access) Act 2025](https://www.legislation.gov.uk/ukpga/2025/18/contents), [ICO Children's code standard 7: Default settings](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/childrens-information/childrens-code-guidance-and-resources/age-appropriate-design-a-code-of-practice-for-online-services/7-default-settings/), [Digital Services Act (Regulation (EU) 2022/2065)](https://eur-lex.europa.eu/eli/reg/2022/2065/oj)
- Stores: [Apple App Store Review Guidelines (5.1.2)](https://developer.apple.com/app-store/review/guidelines/), [Google Play User Data policy](https://support.google.com/googleplay/android-developer/answer/10144311), [Google Play: Advertising ID](https://support.google.com/googleplay/android-developer/answer/6048248)
- Android: [Back up user data with Auto Backup](https://developer.android.com/identity/data/autobackup), [Location permissions](https://developer.android.com/develop/sensors-and-location/location/permissions)
- Apple: [`isExcludedFromBackup`](https://developer.apple.com/documentation/foundation/urlresourcevalues/isexcludedfrombackup), [`NSLocationDefaultAccuracyReduced`](https://developer.apple.com/documentation/bundleresources/information-property-list/nslocationdefaultaccuracyreduced), [App Tracking Transparency](https://developer.apple.com/documentation/apptrackingtransparency), [Inspecting app activity data (App Privacy Report)](https://developer.apple.com/documentation/network/inspecting-app-activity-data)
- SDK configuration: [Firebase: Configure Analytics data collection and usage](https://firebase.google.com/docs/analytics/configure-data-collection), [Google: Consent mode for apps](https://developers.google.com/tag-platform/security/guides/app-consent), [Firebase DebugView and verbose logging](https://firebase.google.com/docs/analytics/debugview)
- Tools: [mitmproxy](https://docs.mitmproxy.org/stable/), [frida-trace](https://frida.re/docs/frida-trace/), [objection](https://github.com/sensepost/objection), [Apktool](https://apktool.org/)
- CWE: [CWE-359](https://cwe.mitre.org/data/definitions/359.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
