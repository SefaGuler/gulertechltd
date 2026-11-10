---
title: "MASWE-0069: Usage of Non-Privacy-Preserving Functionality"
date: 2026-11-10 22:03:00 +0000
subcategory: privacy
summary: "Finding broad permissions, embedded logins and remote processing where a system picker, scoped API or on-device option would do, and how to rate it."
refs: [MASWE-0069, MASVS-PRIVACY-2, CWE-359]
tags: [android, ios, masvs-privacy, pickers, data-minimisation, permissions]
---

This note is part of our [MASVS-PRIVACY guide](/mobile/masvs-privacy-privacy-testing-guide/) and covers OWASP [MASWE-0069](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0069/): an app that uses a mechanism exposing more user data than its feature needs, when the platform offers a mechanism that exposes less. The textbook case is a profile-picture screen that asks for the whole photo library when the system photo picker would hand over the one photo the user taps, with no permission at all. The same pattern repeats across contacts, location, files, Bluetooth, SMS codes, installed apps, sign-in flows and, more and more, AI features that ship user content to a server when the device could do the work. Both platforms have spent the last six years adding these alternatives, and both stores now treat them as the default: Google Play makes apps justify `READ_MEDIA_IMAGES`, `READ_CONTACTS`, `MANAGE_EXTERNAL_STORAGE` or `QUERY_ALL_PACKAGES` against the picker or scoped option, and Apple's guideline 5.1.1(iii) asks apps to use "the out-of-process picker or a share sheet" where possible. Below is a catalogue of "broad access vs privacy-preserving alternative" pairs for Android and iOS with the versions and API names to look for, three tests of our own (OWASP has none yet), code for the preferred patterns, and how to rate what you find.

> **Note:** OWASP has not yet published any tests or Knowledge items for MASWE-0069. The `## Background` section and the three tests (`GT-PRIV-0069-1` to `-3`) are Guler Tech methodology. There are no legacy MASVS v1 privacy tests, so nothing is replaced. The OWASP tests that check *which permissions an app requests* belong to [MASWE-0066](/mobile/maswe-0066-inadequate-permission-management/); this note asks the next question: *for each of those permissions, did the app need it at all, or would a narrower mechanism have done?*

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Background](#background)
  - [Generic: what counts as a privacy-preserving alternative](#generic-what-counts-as-a-privacy-preserving-alternative)
  - [Android: quick reference](#android-quick-reference)
  - [Android: photos, videos and files](#android-photos-videos-and-files)
  - [Android: camera and barcode scanning](#android-camera-and-barcode-scanning)
  - [Android: location](#android-location)
  - [Android: nearby devices and the local network](#android-nearby-devices-and-the-local-network)
  - [Android: contacts](#android-contacts)
  - [Android: SMS codes, phone numbers and call logs](#android-sms-codes-phone-numbers-and-call-logs)
  - [Android: accounts, installed apps, screen capture and health data](#android-accounts-installed-apps-screen-capture-and-health-data)
  - [iOS: quick reference](#ios-quick-reference)
  - [iOS: photos](#ios-photos)
  - [iOS: contacts](#ios-contacts)
  - [iOS: location](#ios-location)
  - [iOS: pasteboard, calendars and accessories](#ios-pasteboard-calendars-and-accessories)
  - [Android and iOS: system authentication sessions](#android-and-ios-system-authentication-sessions)
  - [Android and iOS: on-device processing](#android-and-ios-on-device-processing)
- [Tests](#tests)
  - [GT-PRIV-0069-1: Broad access where a privacy-preserving alternative exists (Android)](#gt-priv-0069-1-broad-access-where-a-privacy-preserving-alternative-exists-android)
  - [GT-PRIV-0069-2: Broad access where a privacy-preserving alternative exists (iOS)](#gt-priv-0069-2-broad-access-where-a-privacy-preserving-alternative-exists-ios)
  - [GT-PRIV-0069-3: Which access path each feature uses at runtime (Android and iOS)](#gt-priv-0069-3-which-access-path-each-feature-uses-at-runtime-android-and-ios)
- [Secure implementation](#secure-implementation)
  - [Android: pickers, scoped permissions and on-device options](#android-pickers-scoped-permissions-and-on-device-options)
  - [iOS: pickers, limited access and on-device options](#ios-pickers-limited-access-and-on-device-options)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

The OWASP requirement is *"The app uses privacy-preserving functionality."* MASWE-0069 maps to **MASVS-PRIVACY-2** ("The app prevents identification of the user"), to [CWE-359](https://cwe.mitre.org/data/definitions/359.html) (Exposure of Private Personal Information to an Unauthorized Actor), and to the `Minimize_Permissions` item of Android's [core app quality guidelines](https://developer.android.com/docs/quality-guidelines/core-app-quality#Minimize_Permissions) ("App requests only the absolute minimum permissions needed to support the current use case"). It carries OWASP's **P** and **EUDIW** profiles. The threat is MAS-THREAT-0069 and the referenced attacks are MAS-ATTACK-0076 and MAS-ATTACK-0088.

OWASP describes it as the privacy counterpart of [MASWE-0047](/mobile/maswe-0047-non-standard-security-apis/) (*Using Non-Standard APIs for Security-Critical Functionality*): both say "prefer what the platform provides", one for security, one for privacy. Some mechanisms serve both, the system authentication session being the obvious one. In practice most findings here are about data minimisation, which is **MASVS-PRIVACY-1** ("The app minimizes access to sensitive data and resources"); OWASP's mapping only lists PRIVACY-2, but we cite both controls when we report, because a picker that returns one photo is minimisation, and on-device processing that keeps content away from a server also reduces identifiability.

Keep the neighbouring weaknesses apart:

| Question | Where it lives |
|---|---|
| Does the app request permissions it never uses, request them out of context, or mishandle denial? | [MASWE-0066](/mobile/maswe-0066-inadequate-permission-management/) |
| For a feature the app really has, does it use a broad mechanism where a narrower one would do? | This note |
| Does the app read the clipboard without user intent? | [MASWE-0030](/mobile/maswe-0030-improper-use-of-the-clipboard/) (we list the paste control below only as one more pair) |
| Does the app build its own crypto, TLS or login when the platform provides one? | [MASWE-0047](/mobile/maswe-0047-non-standard-security-apis/) |
| Does the app collect identifiers that let it or SDKs track the user? | [MASWE-0068](/mobile/maswe-0068-incorrect-use-of-identifiers-for-tracking/) |
| Does the user understand that a privacy-relevant action is happening? | [MASWE-0070](/mobile/maswe-0070-inadequate-awareness-for-privacy-actions/) |
| Do the store declarations (Data safety, App Privacy) match what the app collects? | [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/) |
| Does an SDK harvest data the host app never needed? | [MASWE-0048](/mobile/maswe-0048-malicious-code-included-in-the-app/) |

A typical engagement produces a finding in MASWE-0066 *and* one here: "the app requests `READ_CONTACTS` at launch, before any feature needs it" (0066), and "the only feature that uses contacts is 'invite a friend', which the contact picker covers without any permission" (0069). Report the root cause here and the request-handling issue there, cross-referenced.

**Legal and store context.** This note is technical testing guidance, not legal advice. The data minimisation principle in [GDPR Art. 5(1)(c)](https://eur-lex.europa.eu/eli/reg/2016/679/oj) ("adequate, relevant and limited to what is necessary") and data protection by design and by default in Art. 25 (same text in the [UK GDPR](https://www.legislation.gov.uk/eur/2016/679/contents)) are the legal backdrop: a controller that can build the same feature with less personal data is expected to. The ICO's guidance on [data minimisation](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/data-protection-principles/a-guide-to-the-data-protection-principles/data-minimisation/) and the EDPB's [Guidelines 4/2019 on Article 25](https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-42019-article-25-data-protection-design-and_en) are worth handing to the client's DPO alongside your findings. The store rules are more concrete and change faster, and they are often what makes the client act:

- **Google Play** treats several permissions as *restricted permissions with minimum scope alternatives*: [photos and videos](https://support.google.com/googleplay/android-developer/answer/14115180) (`READ_MEDIA_IMAGES`, `READ_MEDIA_VIDEO` only if the photo picker is not sufficient; full compliance was required from 28 May 2025), contacts (`READ_CONTACTS` for apps targeting Android 17 and later only if the Android Contact Picker is not sufficient; Google's help page gives 27 January 2027 as the compliance date), [all files access](https://support.google.com/googleplay/android-developer/answer/10467955) (`MANAGE_EXTERNAL_STORAGE`), [package visibility](https://support.google.com/googleplay/android-developer/answer/10158779) (`QUERY_ALL_PACKAGES`) and [SMS and Call Log](https://support.google.com/googleplay/android-developer/answer/10208820). Each needs a Play Console declaration explaining why the narrower option is insufficient. The [Permissions and APIs that Access Sensitive Information](https://support.google.com/googleplay/android-developer/answer/9888170) policy also asks for "the minimum scope necessary (for example, coarse instead of fine, and foreground instead of background)" for location. Dates on these pages move; re-check them when you write the report.
- **Apple** [App Review Guideline 5.1.1(iii)](https://developer.apple.com/app-store/review/guidelines/#data-collection-and-storage) (Data Minimization): "Where possible, use the out-of-process picker or a share sheet rather than requesting full access to protected resources like Photos or Contacts." Guideline 4.8 requires apps that use a third-party login to also offer one that "allows users to keep their email address private".

## Modes of Introduction

**Permissions instead of pickers.** The app requests `READ_MEDIA_IMAGES`, `READ_EXTERNAL_STORAGE`, `READ_CONTACTS`, `NSPhotoLibraryUsageDescription` or `NSContactsUsageDescription` and builds its own gallery or contact list for a feature that only ever needs one or a few items the user chooses: an avatar, an attachment, a "send to" contact, an invite.

**Legacy code paths kept alive.** The picker was added for new OS versions, but the old permission path is still the first branch taken, or the manifest still carries the permission "for older devices" without `android:maxSdkVersion`, so it is requested everywhere.

**Precision and scope by default.** `ACCESS_FINE_LOCATION` for a "stores near you" list, `requestAlwaysAuthorization` where "when in use" would do, location permission held only to scan Bluetooth or Wi-Fi, `MANAGE_EXTERNAL_STORAGE` to open one document, `QUERY_ALL_PACKAGES` to check whether one known app is installed.

**Embedded authentication flows.** A third-party identity provider's login page loaded in a `WebView` or `WKWebView` the app controls (or in the deprecated `SFAuthenticationSession`), so the app and every SDK in it can read the credentials, cookies and page content.

**Remote processing by default.** Speech, OCR, translation, image classification or summarisation features that send the user's audio, images or text to a remote service, including third-party AI APIs, when an on-device model or framework supports the feature.

**SDK-driven broad access.** An SDK adds `QUERY_ALL_PACKAGES`, location or contacts permissions through manifest merging, or asks for them at runtime, for a purpose the host app does not need. Check the merged manifest, not the source one.

## Impact

- **Over-collection of personal data.** A picker returns one photo; a library permission returns every photo, with location metadata, faces and screenshots of other apps. A contact pick returns one entry; `READ_CONTACTS` returns the address book, which is mostly personal data of people who never used the app. Whatever the app does next (cache, upload, hand to an SDK), it does with all of it.
- **Profiling and correlation.** Precise location history, the list of installed apps, Bluetooth and Wi-Fi scan results and full contact graphs are strong identifiers and reveal sensitive traits (health, religion, sexuality, finances) by inference. Remote processing gives a server, sometimes a third party, the raw content of voice notes, documents and photos.
- **Credential and session exposure.** An embedded login hands the app the user's identity-provider password and session cookies, which it can store or forward, and which an SDK in the same process can read.
- **Larger breach surface.** Data the app never needed still ends up in caches, backups, logs and server-side stores, and is exposed when any of them leaks.
- **Store enforcement and user trust.** Restricted permissions without a valid declaration lead to Play rejection or removal; App Review rejects apps under 5.1.1. Users refuse prompts that look excessive, which breaks the feature for everyone who says no.

## Mitigations

- **Use system pickers and intents first.** Photo picker, Storage Access Framework, contact picker, camera intents, `PHPickerViewController` / `PhotosPicker`, `CNContactPickerViewController`, EventKitUI, document pickers, share sheets. They need no permission and return only what the user selects.
- **Choose the narrowest grant.** Approximate over precise location, foreground over background, add-only over read-write photo access, write-only over full calendar access, `<queries>` over `QUERY_ALL_PACKAGES`, `neverForLocation` for Bluetooth and Wi-Fi scanning that does not derive location, and support limited and partial grants gracefully.
- **Use system-mediated discovery for devices.** Companion Device Manager and the `NsdManager` picker on Android, AccessorySetupKit on iOS, rather than broad Bluetooth, Wi-Fi, location or local-network permissions.
- **Use the verification and identity APIs built for the job.** SMS Retriever, SMS User Consent, Phone Number Hint, Credential Manager, Sign in with Apple with Hide My Email, rather than SMS, phone-state or account permissions.
- **Authenticate in a system session.** Custom Tabs or Auth Tab on Android, `ASWebAuthenticationSession` on iOS, as RFC 8252 requires for native apps.
- **Process on device where it works.** On-device speech recognition, Vision, ML Kit, Gemini Nano through ML Kit GenAI APIs, Apple's Foundation Models. Where remote processing is genuinely needed, send the minimum, tell the user, and declare it.
- **Keep broad access only for core functionality**, documented, declared to the store, and with a working fallback for users who refuse it.

## Background

### Generic: what counts as a privacy-preserving alternative

The alternatives in this catalogue share a few properties, and you can use them to judge cases the catalogue does not list:

1. **The selection happens outside the app.** The picker, chooser or confirmation runs in a system process (MediaProvider's photo picker on Android, an out-of-process remote view on iOS). The app never sees the items the user did not choose, so it cannot copy, upload or profile them, even if it wanted to.
2. **The grant is scoped to the selection.** The app receives a URI with a temporary read grant (Android) or a copy or item provider for the selected content (iOS), not a standing permission over the collection.
3. **The grant is short-lived or user-visible.** One-time location, a single SMS message, a per-session screen-capture consent, an accessory the user picked.
4. **The user acts in context.** Tapping a system-drawn button (`CLLocationButton`, `UIPasteControl`, `ContactAccessButton`, Android's location button) counts as consent for that one action, without a dialog about the whole resource.

Two things a tester must keep in mind. First, **availability**: many alternatives exist only from a given OS version or need Google Play services; an app with `minSdk 24` or a deployment target of iOS 15 may legitimately keep the broad path as a fallback on older systems, and the finding is then about whether the broad path is limited to those systems. Second, **sufficiency**: a gallery app, a file manager, a contact-sync app, a navigation app or a backup tool may genuinely need broad access. Both stores accept that, against a declaration. The question is always *does this feature need more than the alternative gives?*, answered feature by feature.

### Android: quick reference

| Need | Broad route | Privacy-preserving route | Availability |
|---|---|---|---|
| Choose photos or videos | `READ_MEDIA_IMAGES` / `READ_MEDIA_VIDEO` (13+), `READ_EXTERNAL_STORAGE` (12 and lower) + own gallery | Photo picker: `PickVisualMedia` / `PickMultipleVisualMedia`, `MediaStore.ACTION_PICK_IMAGES` | Android 11+ via system updates; Play services backport to 4.4+ |
| Open or save a document | `MANAGE_EXTERNAL_STORAGE`, `READ_EXTERNAL_STORAGE` | Storage Access Framework: `ACTION_OPEN_DOCUMENT`, `ACTION_CREATE_DOCUMENT`, `ACTION_OPEN_DOCUMENT_TREE` | 4.4+ |
| Take a photo or video | `CAMERA` + own capture UI | `ACTION_IMAGE_CAPTURE`, `ACTION_VIDEO_CAPTURE` intents; Google Code Scanner for barcodes | All; Code Scanner needs Play services |
| Location | `ACCESS_FINE_LOCATION`, `ACCESS_BACKGROUND_LOCATION` | `ACCESS_COARSE_LOCATION`; user-chosen approximate; location button (experimental Jetpack library) | Approximate option in the dialog from 12 |
| Pair a Bluetooth or Wi-Fi device | Location permission for scans; `BLUETOOTH_ADMIN` | `CompanionDeviceManager`; `BLUETOOTH_SCAN` with `neverForLocation` | CDM 8.0+; `BLUETOOTH_SCAN` 12+ |
| Manage Wi-Fi connections | `ACCESS_FINE_LOCATION` | `NEARBY_WIFI_DEVICES` with `neverForLocation` | 13+ |
| Find a device on the LAN | `ACCESS_LOCAL_NETWORK` (required when targeting 17) | `NsdManager` system picker (`DiscoveryRequest.FLAG_SHOW_PICKER`); Output Switcher for Cast | 17 |
| Choose a contact | `READ_CONTACTS` + own list | `ACTION_PICK` on `ContactsContract`, `ActivityResultContracts.PickContact`; `ACTION_PICK_CONTACTS` Contact Picker | `ACTION_PICK` all; Contact Picker 17+ |
| Create or edit one contact | `WRITE_CONTACTS` | `ACTION_INSERT`, `ACTION_EDIT`, `ACTION_INSERT_OR_EDIT` intents | All |
| Auto-fill an SMS code | `READ_SMS`, `RECEIVE_SMS` | SMS Retriever API; SMS User Consent API | Play services |
| Get the user's phone number | `READ_PHONE_NUMBERS`, `READ_PHONE_STATE` | Phone Number Hint API; Digital Credentials API for verification | Play services |
| Sign in, pick an account | `GET_ACCOUNTS`, embedded `WebView` login | Credential Manager; `AccountManager.newChooseAccountIntent()`; Custom Tabs / Auth Tab | GET_ACCOUNTS stopped being sufficient in 8.0 |
| Check for another app | `QUERY_ALL_PACKAGES`, `getInstalledPackages()` | `<queries>` element | Filtering from targetSdk 30 |
| Share or record the screen | Full-display `MediaProjection` (opt-out of app sharing) | App screen sharing (default user choice) | 14 QPR2 / 14+ |
| Heart rate, steps, health data | `BODY_SENSORS`, own sensor collection | Health Connect granular `android.permission.health.*` | Framework module from 14; 16 replaces `BODY_SENSORS` |
| Speech, OCR, image understanding | Upload to a remote API | `SpeechRecognizer.createOnDeviceSpeechRecognizer()`, ML Kit on-device APIs, Gemini Nano via ML Kit GenAI | 12+ for on-device speech; device-dependent for Gemini Nano |

The subsections give the details a tester needs for each pair.

### Android: photos, videos and files

**Photo picker.** The [photo picker](https://developer.android.com/training/data-storage/shared/photopicker) shows the user's media library in a system UI and grants the app temporary read access to the URIs of the items the user selects, with no runtime permission. Apps use it through the AndroidX activity result contracts `PickVisualMedia` and `PickMultipleVisualMedia` (`androidx.activity` 1.7.0 or later), which launch `MediaStore.ACTION_PICK_IMAGES` where available. The picker is available on Android 11 and later devices that receive Modular System Components through Google System Updates; on Android 4.4 to 10, and on Android Go devices running 11 or 12, Google Play services can install a backported picker if the app declares a `com.google.android.gms.metadata.ModuleDependencies` service with `photopicker_activity:0:required` metadata. Where neither is available, AndroidX falls back to `ACTION_OPEN_DOCUMENT`. Access lasts until the device restarts or the app stops, unless the app calls `takePersistableUriPermission()`.

**Granular media permissions.** Android 13 split `READ_EXTERNAL_STORAGE` into `READ_MEDIA_IMAGES`, `READ_MEDIA_VIDEO` and `READ_MEDIA_AUDIO`. Android 14 added [Selected Photos Access](https://developer.android.com/about/versions/14/changes/partial-photo-video-access): when an app targeting 34 or higher requests the visual media permissions, the user can pick "Select photos and videos", and the app gets `READ_MEDIA_VISUAL_USER_SELECTED` instead of full access. An app that declares `READ_MEDIA_VISUAL_USER_SELECTED` controls reselection itself; one that does not runs in a compatibility mode. Partial access is better than full access, but it is still a permission and a custom gallery; the picker is better still.

**What to look for.** `READ_MEDIA_IMAGES`, `READ_MEDIA_VIDEO` or `READ_EXTERNAL_STORAGE` without `android:maxSdkVersion="32"` in an app whose features only attach or upload a few user-chosen items; queries against `MediaStore.Images.Media.EXTERNAL_CONTENT_URI` or `MediaStore.Video.Media.EXTERNAL_CONTENT_URI` that enumerate the library to build an in-app grid; no reference to `PickVisualMedia`, `android.provider.action.PICK_IMAGES` or the backport metadata. `ACCESS_MEDIA_LOCATION` on top of these means the app also asks for the GPS coordinates embedded in photos. Since Play enforces the photo and video policy for apps targeting 13 and later, a finding here is also a store-policy risk.

**Storage Access Framework vs all files access.** [`MANAGE_EXTERNAL_STORAGE`](https://developer.android.com/training/data-storage/manage-all-files) ("All files access", Android 11+) grants read and write access to all of shared storage and the `MediaStore.Files` table. The user grants it on a settings page reached through `ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION`, and the app checks it with `Environment.isExternalStorageManager()`. Google's own examples of legitimate use are file managers, backup and restore, anti-virus and document management apps. For opening, creating or picking a folder of documents, the [Storage Access Framework](https://developer.android.com/training/data-storage/shared/documents-files) (`ACTION_OPEN_DOCUMENT`, `ACTION_CREATE_DOCUMENT`, `ACTION_OPEN_DOCUMENT_TREE`) needs no permission and grants access only to what the user picks. On Android 11+ `ACTION_OPEN_DOCUMENT_TREE` cannot select the storage root, the Download directory or `Android/data/`, which stops apps from using it as a back door to broad access. Look for `MANAGE_EXTERNAL_STORAGE` in apps that just import a file, and `READ_EXTERNAL_STORAGE` without `maxSdkVersion` for documents (Google's guidance is to cap it at 28 for compatibility only).

### Android: camera and barcode scanning

An app that only needs a picture or a video the user takes can send [`MediaStore.ACTION_IMAGE_CAPTURE`](https://developer.android.com/reference/android/provider/MediaStore#ACTION_IMAGE_CAPTURE) or `ACTION_VIDEO_CAPTURE` to the camera app and receive the result, without declaring `CAMERA`. There is a trap that confuses developers and testers alike: if the app *declares* `CAMERA` in the manifest and the user has not granted it, `ACTION_IMAGE_CAPTURE` throws a `SecurityException`. So an app may declare `CAMERA` only because it once broke the intent; check whether any code really opens the camera itself (CameraX, `Camera2`, `android.hardware.Camera`). For barcodes, the [Google Code Scanner](https://developers.google.com/ml-kit/vision/barcode-scanning/code-scanner) (Play services) scans in a system-provided UI, processes images on the device and returns only the decoded value, again with no camera permission. Apps that need live camera preview, AR, video calls or document capture with custom framing do need `CAMERA`; a "scan a QR code to log in" screen usually does not.

### Android: location

[Location permissions](https://developer.android.com/develop/sensors-and-location/location/permissions) come in two accuracies. `ACCESS_COARSE_LOCATION` gives an estimate accurate to about 3 square kilometres; `ACCESS_FINE_LOCATION` gives precise location. From Android 12, an app targeting 31 or higher that asks for fine location must request coarse in the same call, and the system dialog lets the user choose "Approximate"; the app then has coarse only, whatever it declared. Android 10 moved background access into `ACCESS_BACKGROUND_LOCATION`, and Android 11 added "Only this time" grants and auto-reset of unused permissions.

The privacy-preserving choices, in Google's order of preference in [Minimize your permission requests](https://developer.android.com/privacy-and-security/minimize-permission-requests): ask for an address or postcode if location is needed once; use coarse location if it is needed often but not precisely; use the [location button](https://developer.android.com/guide/topics/permissions/private-alternatives/location-button) for a momentary precise fix ("search near me", filling in a delivery address). The location button is a system-rendered button provided through an experimental Jetpack library; it needs a `USE_LOCATION_BUTTON` permission, and an app can mark `ACCESS_FINE_LOCATION` with `android:usesPermissionFlags="onlyForLocationButton"` so that precise location is only ever available through the button. Treat the library as subject to change and check its current documentation before recommending it.

**What to look for.** `ACCESS_FINE_LOCATION` for features that work at city or district level (weather, local news, store lists, currency, language, regional pricing); `ACCESS_BACKGROUND_LOCATION` without a feature that runs while the app is not visible (the Play policy names this explicitly); the app breaking or nagging when the user chooses "Approximate"; location held only to scan Bluetooth or Wi-Fi (next section).

### Android: nearby devices and the local network

**Bluetooth.** Until Android 11, a Bluetooth scan required `ACCESS_FINE_LOCATION`, because scan results reveal where you are. Android 12 introduced the [nearby devices permissions](https://developer.android.com/develop/connectivity/bluetooth/bt-permissions) `BLUETOOTH_SCAN`, `BLUETOOTH_CONNECT` and `BLUETOOTH_ADVERTISE`. An app that never derives location from scan results declares `BLUETOOTH_SCAN` with `android:usesPermissionFlags="neverForLocation"` and caps the legacy permissions with `android:maxSdkVersion="30"`; Google notes that `neverForLocation` filters some BLE beacons out of the results, which is the price of not being treated as a location app. For the initial set-up of a watch, tracker or other companion device, [`CompanionDeviceManager`](https://developer.android.com/develop/connectivity/bluetooth/companion-device-pairing) (Android 8.0+) scans on the app's behalf, shows a system chooser filtered by the app's `AssociationRequest`, and returns only the device the user picks, without location permission (Location Services must be on). Look for `ACCESS_FINE_LOCATION` without `maxSdkVersion="30"` in an app whose only location-like need is pairing; for `BLUETOOTH_SCAN` without `neverForLocation` where the app does not use location; and for continuous scans where a one-off association would do.

**Wi-Fi.** Android 13 added [`NEARBY_WIFI_DEVICES`](https://developer.android.com/develop/connectivity/wifi/wifi-permissions) for apps that manage Wi-Fi connections (for example `WifiManager.startLocalOnlyHotspot()` and Wi-Fi Aware), with the same `neverForLocation` assertion, so `ACCESS_FINE_LOCATION` can be capped at `maxSdkVersion="32"`. Note one exception testers often get wrong: `WifiManager.startScan()` and `getScanResults()` still require `ACCESS_FINE_LOCATION` on Android 13 and later, so an app that genuinely lists nearby networks still needs location. The question then becomes whether it needs to list networks at all (`WifiNetworkSpecifier` and network suggestions connect to a known network without a scan).

**Local network.** Android 17 introduces the [`ACCESS_LOCAL_NETWORK`](https://developer.android.com/privacy-and-security/local-network-permission) runtime permission, in the nearby devices group, and enforces it for apps targeting Android 17 (Android 16 allowed opting in). Apps that target 36 or lower get local network access implicitly. The privacy-preserving route is a system picker: `NsdManager` can show a system dialog for mDNS discovery (`DiscoveryRequest.Builder(...).setFlags(DiscoveryRequest.FLAG_SHOW_PICKER)`), after which the app may connect to the one selected service without the permission, and Cast apps can use the Output Switcher. Google Play's permissions policy now lists the local network permission as restricted to core functionality "when device pickers are insufficient", with a declaration for apps targeting 17. Broad LAN access matters for privacy because the set of devices on a home network is a strong fingerprint.

### Android: contacts

`READ_CONTACTS` returns the entire address book: names, numbers, emails, addresses, notes, photos, of people who have not consented to anything. For "choose a contact", Android has always offered a permission-free path: an [`ACTION_PICK`](https://developer.android.com/guide/components/intents-common#Contacts) intent on `ContactsContract.Contacts.CONTENT_URI` (or a `CommonDataKinds` type to pick one phone number or email), or the AndroidX `ActivityResultContracts.PickContact` contract. The result is a content URI with a temporary grant to read that contact, "even if your app doesn't include the `READ_CONTACTS` permission".

Android 17 adds the [Contact Picker](https://developer.android.com/about/versions/17/features/contact-picker), launched with the `ACTION_PICK_CONTACTS` intent action. The app lists the data fields it needs (phone, email, postal address, as `CommonDataKinds` MIME types in `EXTRA_PICK_CONTACTS_REQUESTED_DATA_FIELDS`) and can allow multiple selection with `Intent.EXTRA_ALLOW_MULTIPLE`; the user picks contacts and the app reads only the selected data. It is not backported. For apps targeting 17, Google says the system upgrades `ACTION_PICK` to the new picker UI. The Play [contacts permission policy](https://support.google.com/googleplay/android-developer/answer/14115180) then restricts `READ_CONTACTS` for apps targeting 17 and later to cases where the picker is not sufficient, and names "sharing files, collaborating, inviting/referring someone to join a service, choosing a contact to transact with" as cases that "typically should not request the permission". In October 2026 Google also announced a policy pushing single-contact creation and edits to the `ACTION_INSERT`, `ACTION_EDIT` and `ACTION_INSERT_OR_EDIT` intents instead of write permissions; it is not yet enforced at the time of writing.

**What to look for.** `READ_CONTACTS` in apps whose contact features are invite, refer, send money to, share with, or call one person; queries on `ContactsContract.Contacts.CONTENT_URI` or `ContactsContract.CommonDataKinds.Phone.CONTENT_URI` without a selection, which read the whole table; and, most important, any upload of the contact list (friend matching, "find friends", or an SDK). Server-side matching may be a legitimate core feature under the Play policy, but it then needs disclosure and consent, which belong to [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/) and [MASWE-0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/).

### Android: SMS codes, phone numbers and call logs

`READ_SMS` and `RECEIVE_SMS` give access to every message on the device, including bank codes and private conversations, to fill in one verification code. Google offers two permission-free APIs through Play services:

- The [SMS Retriever API](https://developers.google.com/identity/sms-retriever/overview) (`SmsRetriever.getClient(context).startSmsRetriever()`): the server includes an 11-character hash of the app's signing certificate in the SMS, Play services matches it and hands *that message only* to the app. No permission, no user prompt.
- The [SMS User Consent API](https://developers.google.com/identity/sms-retriever/user-consent/overview) (`startSmsUserConsent(...)`): for messages whose format the app does not control. The system asks the user whether to share the content of one message with the app.

For the phone number itself, the [Phone Number Hint API](https://developer.android.com/identity/phone-number-hint) shows the SIM numbers in a system UI and returns the one the user selects, with no permission; Google now recommends the Digital Credentials API to *verify* a number without device permissions. The Play [SMS and Call Log policy](https://support.google.com/googleplay/android-developer/answer/10208820) only allows these permission groups for apps that are the default SMS, Phone or Assistant handler (and some listed exceptions), and Google has announced that account verification by phone call will no longer be a permitted use of `READ_CALL_LOG`. Google's [minimize permissions](https://developer.android.com/privacy-and-security/minimize-permission-requests) page lists more alternatives: `CallScreeningService` instead of `READ_PHONE_STATE` to filter calls, `ACTION_DIAL` instead of `ACTION_CALL` and `CALL_PHONE`, audio focus callbacks instead of phone state to pause playback, and an app-generated identifier instead of the IMEI (which ordinary apps cannot read since Android 10). In apps distributed through Play, broad SMS or call-log access without a default-handler role is rare; in sideloaded, enterprise or alternative-store builds it is common, and it is a High-severity pattern when the content leaves the device.

### Android: accounts, installed apps, screen capture and health data

**Accounts and sign-in.** Since [Android 8.0](https://developer.android.com/about/versions/oreo/android-8.0-changes), `GET_ACCOUNTS` no longer gives access to the device's accounts; the app has to use `AccountManager.newChooseAccountIntent()` (the user chooses one account) or be the authenticator. For signing in, [Credential Manager](https://developer.android.com/identity/sign-in/credential-manager) (`androidx.credentials`) brings passwords, passkeys and Sign in with Google into one system bottom sheet, where the user chooses what to share. Seeing `GET_ACCOUNTS` today usually means legacy code or an SDK; reading the account email to pre-fill a form or as an identifier is a tracking concern for [MASWE-0068](/mobile/maswe-0068-incorrect-use-of-identifiers-for-tracking/).

**Installed apps.** For apps targeting Android 11 or higher, [package visibility filtering](https://developer.android.com/training/package-visibility) hides most other apps from `getInstalledPackages()`, `queryIntentActivities()` and similar calls. The app declares what it needs to see in a `<queries>` element (specific packages, intent filters or provider authorities). `QUERY_ALL_PACKAGES` lifts the filter, and Google Play treats the installed-app list as personal and sensitive data: the [policy](https://support.google.com/googleplay/android-developer/answer/10158779) permits it for device search, anti-virus, file managers and browsers, with temporary exceptions such as security checks in dedicated banking and wallet apps. Look for `QUERY_ALL_PACKAGES` used to check for one or two known apps, `getInstalledApplications()` results sent to a server, and the permission arriving through an SDK's merged manifest. Note that Play also restricts "alternative methods to approximate the broad visibility", such as a `<queries>` element listing every launcher intent.

**Screen capture.** The [`MediaProjection`](https://developer.android.com/media/grow/media-projection) API captures the display for screen sharing and recording. App screen sharing, first enabled in Android 14 QPR2 and part of Android 15, lets the user share a single app window instead of the whole screen, which keeps notifications, the status bar and every other app out of the stream. It is the default: `createScreenCaptureIntent()` and `createConfigForUserChoice()` offer the choice. An app opts out with `createScreenCaptureIntent(MediaProjectionConfig.createConfigForDefaultDisplay())`, which forces whole-screen capture. Look for that call in apps (remote support, meeting, recording) where single-app sharing would serve the feature. Apps targeting 14 or higher must also obtain consent for each capture session.

**Health and fitness data.** [Health Connect](https://developer.android.com/health-and-fitness/guides/health-connect) is the on-device store for health data, with one permission per data type and access mode (for example `android.permission.health.READ_STEPS`), managed by the user in one place; it is part of the framework from Android 14. By default an app can read data from only up to 30 days before the permission was granted; older data needs `READ_HEALTH_DATA_HISTORY`, and background reads need `READ_HEALTH_DATA_IN_BACKGROUND`. For apps targeting Android 16, APIs that previously required `BODY_SENSORS` require the granular health permissions instead (`READ_HEART_RATE` and so on). Look for history or background permissions without a feature that needs them, and for apps requesting many data types to display one.

### iOS: quick reference

| Need | Broad route | Privacy-preserving route | Availability |
|---|---|---|---|
| Choose photos or videos | `PHPhotoLibrary` authorisation (`NSPhotoLibraryUsageDescription`) + own grid | `PHPickerViewController` (UIKit), `PhotosPicker` (SwiftUI) | iOS 14 / iOS 16 |
| Save a photo | Read-write library access | `PHAccessLevel.addOnly` with `NSPhotoLibraryAddUsageDescription` | iOS 14 for the access level API |
| Choose a contact | `CNContactStore.requestAccess(for:)` + own list | `CNContactPickerViewController` (no authorisation); limited access with `ContactAccessButton` / `contactAccessPicker` | iOS 9; limited access iOS 18 |
| Location | Precise, "Always" | `NSLocationDefaultAccuracyReduced`, `kCLLocationAccuracyReduced`; `CLLocationButton` / `LocationButton` one-time grant; "when in use" | iOS 14; buttons iOS 15 |
| Paste | Programmatic `UIPasteboard` reads (prompt since iOS 16) | `UIPasteControl` / `PasteButton` | iOS 16 |
| Add an event | Full calendar access | `EKEventEditViewController` out of process with no access; `requestWriteOnlyAccessToEvents` | iOS 17 |
| Set up a Bluetooth or Wi-Fi accessory | Core Bluetooth (`NSBluetoothAlwaysUsageDescription`), local network | AccessorySetupKit (`ASAccessorySession`) | iOS 18 |
| Open a file | (no broad file permission on iOS) | `UIDocumentPickerViewController`, share sheet | iOS 8+ |
| Third-party login | `WKWebView`, deprecated `SFAuthenticationSession` | `ASWebAuthenticationSession` | iOS 12 |
| Email address at sign-up | Asking for or reading the real email | Sign in with Apple with Hide My Email | iOS 13 |
| Speech, text, image analysis | Server-based recognition, remote AI APIs | `requiresOnDeviceRecognition`, Vision, Foundation Models (on-device model) | iOS 13; Foundation Models iOS 26 |

### iOS: photos

[`PHPickerViewController`](https://developer.apple.com/documentation/photosui/phpickerviewcontroller) (iOS 14) and SwiftUI's [`PhotosPicker`](https://developer.apple.com/documentation/photosui/photospicker) (iOS 16) run out of process. Apple's words: "Because the system manages its life cycle in a separate process, it's private by default. The user doesn't need to explicitly authorize your app to select photos." The app receives item providers for the selected assets only. Since iOS 14 the library authorisation itself also has a limited mode ([`PHAuthorizationStatus.limited`](https://developer.apple.com/documentation/photos/phauthorizationstatus/limited)): the user chooses which assets the app can see, the system offers to update the selection, and the app can present `presentLimitedLibraryPicker(from:)` or suppress the automatic prompt with `PHPhotoLibraryPreventAutomaticLimitedAccessAlert`. For apps that only *save* to the library, `PHAccessLevel.addOnly` with `NSPhotoLibraryAddUsageDescription` gives write access without read access.

**What to look for.** `NSPhotoLibraryUsageDescription` and calls to `PHPhotoLibrary.requestAuthorization(for: .readWrite)` (`requestAuthorizationForAccessLevel:handler:`) or `PHAsset.fetchAssets(with:)` in an app whose photo features are "choose an avatar" or "attach an image". A picker configured with `PHPickerConfiguration(photoLibrary: .shared())` returns asset identifiers; fetching the `PHAsset` behind them needs library authorisation again, so check why the app wants the asset rather than the image data (often: to read location or creation date metadata). An app that requests read-write access only to save a generated image should use add-only. Apple's guideline 5.1.1(iii) is directly on point.

### iOS: contacts

[`CNContactPickerViewController`](https://developer.apple.com/documentation/contactsui/cncontactpickerviewcontroller) (iOS 9) has always been the permission-free route: "The app using contact picker view does not need access to the user's contacts and the user will not be prompted for 'grant permission' access. The app has access only to the user's final selection." Predicates such as `predicateForEnablingContact` and `displayedPropertyKeys` limit what the user can pick (for example, only contacts with an email address).

iOS 18 added limited contacts access. When the app calls `requestAccess(for:)`, the user can share all contacts or a chosen subset, and the app's status becomes [`CNAuthorizationStatus.limited`](https://developer.apple.com/documentation/contacts/cnauthorizationstatus/limited). Two system UIs let the user add contacts to that subset in context: [`ContactAccessButton`](https://developer.apple.com/documentation/contactsui/contactaccessbutton), a SwiftUI button that the app pairs with its own search field (it shows matching contacts the app cannot see yet; tapping grants access to that contact; it disappears if the app has full access), and the [`contactAccessPicker(isPresented:completionHandler:)`](https://developer.apple.com/documentation/swiftui/view/contactaccesspicker%28ispresented:completionhandler:%29) view modifier. Both are iOS 18 only.

**What to look for.** `NSContactsUsageDescription` and `CNContactStore` enumeration (`enumerateContacts(with:usingBlock:)`, `unifiedContacts(matching:keysToFetch:)`) in apps whose contact features pick one person; an app that does not handle `.limited` (treats it as denied and nags for full access, or breaks); and uploads of the address book, which need the declarations and consent covered in sibling notes.

### iOS: location

iOS 14 made [accuracy](https://developer.apple.com/documentation/corelocation/claccuracyauthorization) a separate user choice: the authorisation prompt has a Precise toggle, and `CLLocationManager.accuracyAuthorization` tells the app whether it has `.fullAccuracy` or `.reducedAccuracy`. An app can ask for reduced accuracy by default with the Info.plist key [`NSLocationDefaultAccuracyReduced`](https://developer.apple.com/documentation/bundleresources/information-property-list/nslocationdefaultaccuracyreduced) (the prompt then shows an approximate map and Precise is off in Settings), or for a single operation with `desiredAccuracy = kCLLocationAccuracyReduced`. When it needs precision once, `requestTemporaryFullAccuracyAuthorization(withPurposeKey:)` asks for it for the session, with purpose strings in `NSLocationTemporaryUsageDescriptionDictionary`.

[`CLLocationButton`](https://developer.apple.com/documentation/corelocationui/cllocationbutton) (UIKit) and [`LocationButton`](https://developer.apple.com/documentation/corelocationui/locationbutton) (SwiftUI), both iOS 15 in CoreLocationUI, grant one-time "when in use" authorisation when tapped, which expires when the app is no longer in use; after the first confirmation, later taps grant it without an alert. They are the natural fit for "use my current location" in a search or address form.

**What to look for.** `NSLocationAlwaysAndWhenInUseUsageDescription` and `requestAlwaysAuthorization` without a background feature; precise location for features that work with a region; no handling of `.reducedAccuracy`; persistent "while using" authorisation for a feature used once per order.

### iOS: pasteboard, calendars and accessories

**Pasteboard.** Since iOS 16, reading another app's pasteboard content programmatically shows a "paste from" confirmation, while [`UIPasteControl`](https://developer.apple.com/documentation/uikit/uipastecontrol) (and SwiftUI's `PasteButton`) is a system-drawn Paste button whose tap counts as consent. Our [clipboard note](/mobile/maswe-0030-improper-use-of-the-clipboard/) covers the detail and the tests; here it is one more pair to check: apps that read the pasteboard on launch or on foreground "to detect a link" should offer a paste control instead.

**Calendars.** iOS 17 split calendar access into write-only (`requestWriteOnlyAccessToEvents`, `NSCalendarsWriteOnlyAccessUsageDescription`) and full access (`requestFullAccessToEvents`, `NSCalendarsFullAccessUsageDescription`). Apple's [Accessing the event store](https://developer.apple.com/documentation/eventkit/accessing-the-event-store) explains that on iOS 17 and later, EventKitUI's chooser and editor run out of process, so "your app can use EventKitUI without requesting write-only or full calendar access": create an `EKEvent`, present `EKEventEditViewController`, and the user saves it to the calendar they choose. An app that requests full access to add a booking to the calendar reads every appointment the user has, for nothing.

**Accessories.** [AccessorySetupKit](https://developer.apple.com/documentation/accessorysetupkit) (iOS 18) discovers and configures Bluetooth or Wi-Fi accessories through a system picker showing the accessory images and names the app provides, "without granting overly-broad Bluetooth or Wi-Fi access". The app declares `NSAccessorySetupKitSupports` (`Bluetooth`, `WiFi`) and, for Bluetooth, the company identifiers, names or services it will discover (`NSAccessorySetupBluetoothCompanyIdentifiers`, `NSAccessorySetupBluetoothNames`, `NSAccessorySetupBluetoothServices`); it then uses `ASAccessorySession.showPicker(for:completionHandler:)` and can talk to the selected accessory. Compare with Core Bluetooth (`NSBluetoothAlwaysUsageDescription`), which lets the app scan for every device around it. For apps that support a specific product family, the broad Core Bluetooth prompt plus open scanning is the over-exposing choice on iOS 18 and later.

### Android and iOS: system authentication sessions

[RFC 8252](https://www.rfc-editor.org/rfc/rfc8252) (OAuth 2.0 for Native Apps) requires native apps to send authorisation requests to an external user agent, the browser or an in-app browser tab, and not to an embedded web view, because the app controls an embedded view: it can read what the user types, read the session cookies the identity provider sets, and inject script. On Android the in-app browser tab is [Custom Tabs](https://developer.chrome.com/docs/android/custom-tabs), and Chrome now offers [Auth Tab](https://developer.chrome.com/docs/android/custom-tabs/guide-auth-tab) (`AuthTabIntent`, from Chrome 137, in the AndroidX browser library), a stripped-down Custom Tab that returns the result through a callback and falls back to Custom Tabs where unsupported. On iOS it is [`ASWebAuthenticationSession`](https://developer.apple.com/documentation/authenticationservices/aswebauthenticationsession) (iOS 12), which shows the user which domain the app is authenticating with and ensures only the calling app receives the callback; `prefersEphemeralWebBrowserSession` (iOS 13) also keeps the session from sharing cookies with Safari. `SFAuthenticationSession` (iOS 11) was deprecated in iOS 12.

From the privacy side, the point is that the user's identity-provider password, other sessions in the browser, and the identity provider's page content stay out of the app's process, and therefore out of reach of every SDK in it. The app gets an authorisation code, nothing more. How to detect embedded or custom login flows, and the security consequences, are in [MASWE-0047](/mobile/maswe-0047-non-standard-security-apis/); passkeys and password managers are in [MASWE-0019](/mobile/maswe-0019-no-autofill-support-for-credential-providers/).

Two related identity choices limit what the app learns about the user. Sign in with Apple lets the user share a random relay address through **Hide My Email** instead of their real email, and App Review guideline 4.8 requires apps with third-party logins to offer a login with that property. Android's Credential Manager and Phone Number Hint likewise put the user in a system sheet to choose what to share.

### Android and iOS: on-device processing

Features that turn user content into something useful (speech to text, text recognition in photos, translation, classification, summarisation, generative AI) can often run on the device:

- **Speech.** On Android, [`SpeechRecognizer.createOnDeviceSpeechRecognizer()`](https://developer.android.com/reference/android/speech/SpeechRecognizer#createOnDeviceSpeechRecognizer%28android.content.Context%29) (API 31) and `isOnDeviceRecognitionAvailable()`; `RecognizerIntent.EXTRA_PREFER_OFFLINE` only expresses a preference. On iOS, setting [`requiresOnDeviceRecognition`](https://developer.apple.com/documentation/speech/sfspeechrecognitionrequest/requiresondevicerecognition) to `true` on an `SFSpeechRecognitionRequest` (iOS 13) prevents the request "from sending audio over the network"; it is honoured only if the recogniser's `supportsOnDeviceRecognition` is `true`, so check both. Server-based recognition sends audio to the platform vendor, not to the app developer, but it still leaves the device.
- **Vision and ML.** Apple's Vision framework runs its requests on the device. ML Kit's on-device APIs (barcode, text recognition, face detection, translation) process locally; the Google Code Scanner processes images on the device and does not keep them.
- **Generative AI.** On Android, [Gemini Nano](https://developer.android.com/ai/gemini-nano) runs in the AICore system service on supported devices and is exposed through the ML Kit GenAI APIs; on iOS 26 and later the [Foundation Models](https://developer.apple.com/documentation/foundationmodels) framework gives access to Apple's on-device model. Both are device- and region-dependent, so apps need a fallback, and Apple's framework documentation now also describes routing requests to Private Cloud Compute or server model providers; check which model the app selects rather than assuming that the framework means "on device".

Remote processing is not wrong in itself: many models do not fit on a phone. The finding is when an on-device option clearly supports the feature on the app's target devices, and the app nonetheless sends personal content (voice notes, photos of documents, messages, health notes) to its own or a third-party service, especially without telling the user. Whether that transfer is disclosed and lawful is for [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/) and [MASWE-0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/); here the question is whether it needed to happen.

## Tests

OWASP has no tests for MASWE-0069 yet. Our three tests work as a pair of static inventories (one per platform) and one dynamic confirmation. The static tests find candidates quickly; the dynamic test decides them, because only by using each feature can you see whether the broad path is the one users actually hit and what data it reaches. Run them after the permission tests of [MASWE-0066](/mobile/maswe-0066-inadequate-permission-management/), whose output (the list of requested permissions and when they are requested) is your starting point.

### GT-PRIV-0069-1: Broad access where a privacy-preserving alternative exists (Android)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Static review of the APK or AAB to list every broad-access mechanism in the [Android quick reference](#android-quick-reference) (permissions and the APIs behind them), find whether the corresponding alternative is present, and map each broad mechanism to the feature that uses it.

#### Prerequisites

- The release APK (or the universal APK from the AAB with `bundletool`), plus `minSdkVersion` and `targetSdkVersion`.
- [aapt2](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0124/), [jadx](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/) or [apktool](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/), and optionally [semgrep](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/).
- The app's feature list (store listing, client walkthrough), because sufficiency is judged per feature.

#### Steps

1. **List permissions with their flags and SDK caps.** `aapt2 dump permissions` gives the names ([MASTG-TECH-0126](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0126/)); the manifest XML tree also shows `maxSdkVersion` and `usesPermissionFlags`, which matter here ([MASTG-TECH-0117](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/)). Always use the merged manifest from the built APK, so SDK-added permissions are included.

   ```bash
   aapt2 dump badging app.apk | grep -E "sdkVersion|targetSdkVersion"
   aapt2 dump permissions app.apk
   aapt2 dump xmltree --file AndroidManifest.xml app.apk | grep -A4 "E: uses-permission" \
     | grep -E "name|maxSdkVersion|usesPermissionFlags"
   ```

2. **Flag the broad mechanisms.** Mark every entry from the "Broad route" column of the quick reference: `READ_MEDIA_IMAGES`, `READ_MEDIA_VIDEO`, `READ_EXTERNAL_STORAGE` (uncapped), `ACCESS_MEDIA_LOCATION`, `MANAGE_EXTERNAL_STORAGE`, `CAMERA`, `ACCESS_FINE_LOCATION`, `ACCESS_BACKGROUND_LOCATION`, `BLUETOOTH_SCAN` without `neverForLocation`, `NEARBY_WIFI_DEVICES` without it, `ACCESS_LOCAL_NETWORK`, `READ_CONTACTS`, `WRITE_CONTACTS`, `READ_SMS`, `RECEIVE_SMS`, `READ_CALL_LOG`, `READ_PHONE_STATE`, `READ_PHONE_NUMBERS`, `GET_ACCOUNTS`, `QUERY_ALL_PACKAGES`, `BODY_SENSORS`, and the health history and background permissions.
3. **Decompile and find the code behind each one** ([MASTG-TECH-0017](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0017/)). Search for the broad-access APIs and, separately, for the alternatives. String constants survive R8, so the intent actions and content URIs are reliable even in obfuscated builds:

   ```bash
   jadx -d out app.apk
   # Broad access
   grep -rnE "MediaStore\.(Images|Video)\.Media\.EXTERNAL_CONTENT_URI|content://media/external" out/sources | head
   grep -rnE "ContactsContract\.(Contacts|CommonDataKinds\.Phone)\.CONTENT_URI|content://com\.android\.contacts" out/sources | head
   grep -rnE "ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION|isExternalStorageManager" out/sources | head
   grep -rnE "getInstalledPackages|getInstalledApplications|content://sms|Telephony\.Sms" out/sources | head
   grep -rnE "createConfigForDefaultDisplay|getScanResults|startScan\(" out/sources | head
   # Alternatives
   grep -rnE "android\.provider\.action\.PICK_IMAGES|PickVisualMedia|photopicker_activity" out/ | head
   grep -rnE "android\.intent\.action\.(OPEN_DOCUMENT|CREATE_DOCUMENT|PICK)|PICK_CONTACTS|PickContact" out/sources | head
   grep -rnE "android\.media\.action\.IMAGE_CAPTURE|SmsRetriever|startSmsUserConsent|getPhoneNumberHintIntent" out/sources | head
   grep -rnE "CompanionDeviceManager|FLAG_SHOW_PICKER|CredentialManager|CustomTabsIntent|AuthTabIntent" out/sources | head
   grep -rnE "createOnDeviceSpeechRecognizer|com\.google\.mlkit" out/sources | head
   ```

   Separate the app's own packages from SDK packages; an SDK that queries installed apps or location is a finding against the app all the same, and a lead for [MASWE-0048](/mobile/maswe-0048-malicious-code-included-in-the-app/).
4. **Look for embedded logins and remote processing.** Search for identity-provider authorisation URLs (`/authorize`, `/oauth2/`, `/login`) passed to `WebView.loadUrl`, and for `CookieManager.getCookie` on those hosts. Collect the hosts that receive audio, images or documents (multipart uploads, `audio/`, `image/` content types near AI, OCR or transcription features).
5. **Build the matrix.** For each broad mechanism, record: the feature that uses it, the alternative from the catalogue, the alternative's availability against `minSdkVersion` (is the broad path limited to older versions by `maxSdkVersion` or a `Build.VERSION.SDK_INT` check?), and whether the feature needs more than the alternative gives.
6. **Optional: encode recurring checks as semgrep rules** over the jadx output, for example "a query on the contacts table with a null selection":

   ```yaml
   rules:
     - id: full-contacts-enumeration
       languages: [java]
       severity: WARNING
       message: Full contacts table query; check whether a contact picker would do
       pattern-either:
         - pattern: $CR.query(ContactsContract.Contacts.CONTENT_URI, $P, null, ...)
         - pattern: $CR.query(ContactsContract.CommonDataKinds.Phone.CONTENT_URI, $P, null, ...)
   ```

#### Observation

The permission list with flags and caps, the code locations of broad-access calls and of alternatives, and the feature-by-feature matrix.

#### Evaluation

The test **fails** for each feature that uses a broad mechanism where an alternative from the catalogue covers the feature on the OS versions where the broad path runs, and nothing in the feature needs more (a full library, all contacts, continuous scanning, precise background location). Typical failures: `READ_MEDIA_IMAGES` for an avatar; `READ_CONTACTS` for invites; `READ_SMS` for OTP auto-fill; `ACCESS_FINE_LOCATION` for a store list or for pairing; `QUERY_ALL_PACKAGES` to check one app; `MANAGE_EXTERNAL_STORAGE` to import one file; `createConfigForDefaultDisplay()` without a reason; full-calendar-style broad grants when an intent exists. It **passes** when the alternatives are used, when broad permissions are capped to the OS versions without an alternative, or when the broad access serves a documented core use case (gallery, file manager, dialer, contact sync, navigation) that you have confirmed and that the client has declared to Google Play. Leave a candidate open, not passed, if you cannot connect it to a feature; the dynamic test decides it.

#### Demo

Illustrative manifest and code from a chat app whose only image feature is "send a photo" and whose only contact feature is "invite a friend":

```xml
<uses-permission android:name="android.permission.READ_MEDIA_IMAGES" />
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
<uses-permission android:name="android.permission.READ_CONTACTS" />
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
<uses-permission android:name="android.permission.BLUETOOTH_SCAN" />
```

```kotlin
// Builds an in-app gallery of every image on the device
val cursor = contentResolver.query(
    MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
    arrayOf(MediaStore.Images.Media._ID, MediaStore.Images.Media.DATE_TAKEN),
    null, null, "${MediaStore.Images.Media.DATE_TAKEN} DESC")

// "Invite a friend" reads the whole address book
val contacts = contentResolver.query(
    ContactsContract.CommonDataKinds.Phone.CONTENT_URI, null, null, null, null)
```

Illustrative detection output:

```text
$ aapt2 dump xmltree --file AndroidManifest.xml app.apk | grep -A4 "E: uses-permission" | grep -E "name|maxSdk|usesPermissionFlags"
        A: http://schemas.android.com/apk/res/android:name(0x01010003)="android.permission.READ_MEDIA_IMAGES" (Raw: ...)
        A: http://schemas.android.com/apk/res/android:name(0x01010003)="android.permission.READ_EXTERNAL_STORAGE" (Raw: ...)
        A: http://schemas.android.com/apk/res/android:name(0x01010003)="android.permission.READ_CONTACTS" (Raw: ...)
        A: http://schemas.android.com/apk/res/android:name(0x01010003)="android.permission.ACCESS_FINE_LOCATION" (Raw: ...)
        A: http://schemas.android.com/apk/res/android:name(0x01010003)="android.permission.BLUETOOTH_SCAN" (Raw: ...)
$ grep -rnE "PICK_IMAGES|PickVisualMedia|PICK_CONTACTS|PickContact" out/ | wc -l
0
```

No `maxSdkVersion` on the storage permission, no `neverForLocation` on `BLUETOOTH_SCAN`, no picker anywhere: three candidate findings (photos, contacts, location for Bluetooth), each to confirm in GT-PRIV-0069-3.

### GT-PRIV-0069-2: Broad access where a privacy-preserving alternative exists (iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Static review of the IPA: purpose strings, linked frameworks and referenced classes, selectors and Swift symbols, to find broad-access paths from the [iOS quick reference](#ios-quick-reference) and whether the alternatives are present, then map them to features.

#### Prerequisites

- A decrypted IPA of the release build ([MASTG-TECH-0054](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0054/)) and its `MinimumOSVersion`.
- macOS with Xcode command-line tools ([plutil](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0062/), [otool](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0060/), `nm`, `xcrun swift-demangle`) or [rabin2](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/) on any OS.

#### Steps

1. **Read the purpose strings and privacy keys** ([MASTG-TECH-0153](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0153/), [MASTG-TECH-0154](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0154/)). Each `UsageDescription` key is a resource the app can ask for; the others show whether it opted into the narrower behaviour.

   ```bash
   unzip -q app.ipa -d ipa && APP=$(ls -d ipa/Payload/*.app)
   plutil -p "$APP/Info.plist" | grep -E "MinimumOSVersion|UsageDescription|NSLocationDefaultAccuracyReduced|NSLocationTemporaryUsageDescriptionDictionary|PHPhotoLibraryPreventAutomaticLimitedAccessAlert|NSAccessorySetup"
   ```

2. **List linked frameworks** ([MASTG-TECH-0158](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0158/)) for the main binary and every embedded framework and extension, because SDKs do their own access:

   ```bash
   for b in "$APP/$(plutil -extract CFBundleExecutable raw "$APP/Info.plist")" "$APP"/Frameworks/*.framework/* "$APP"/PlugIns/*.appex/*; do
     [ -f "$b" ] && file "$b" | grep -q Mach-O && { echo "== $b"; otool -L "$b" | grep -E "/(Photos|PhotosUI|Contacts|ContactsUI|CoreLocation|CoreLocationUI|CoreBluetooth|AccessorySetupKit|EventKit|EventKitUI|Speech|AuthenticationServices|WebKit|FoundationModels)\.framework"; }
   done
   ```

3. **Find referenced classes, selectors and Swift types.** Objective-C class references and selector names identify the broad calls even in Swift code; SwiftUI-only alternatives appear as Swift symbols, which you demangle:

   ```bash
   BIN="$APP/$(plutil -extract CFBundleExecutable raw "$APP/Info.plist")"
   nm -u "$BIN" | grep -oE "_OBJC_CLASS_\\\$_(PHPhotoLibrary|PHAsset|PHPickerViewController|CNContactStore|CNContactPickerViewController|CLLocationManager|CLLocationButton|CBCentralManager|ASAccessorySession|EKEventStore|EKEventEditViewController|UIPasteControl|ASWebAuthenticationSession|WKWebView|SFSpeechRecognizer)" | sort -u
   strings - "$BIN" | grep -E "^(requestAuthorizationForAccessLevel:handler:|requestAuthorization:|fetchAssetsWithOptions:|requestAccessForEntityType:completionHandler:|enumerateContactsWithFetchRequest:error:usingBlock:|requestAlwaysAuthorization|requestTemporaryFullAccuracyAuthorizationWithPurposeKey:completion:|scanForPeripheralsWithServices:options:|requestFullAccessToEventsWithCompletion:|requestWriteOnlyAccessToEventsWithCompletion:|setRequiresOnDeviceRecognition:)$" | sort -u
   nm -u "$BIN" | xcrun swift-demangle | grep -oE "PhotosPicker|ContactAccessButton|contactAccessPicker|LocationButton|PasteButton" | sort -u
   ```

4. **Look for embedded logins and remote processing.** Identity-provider authorisation URLs in the binary's strings next to `WKWebView` use and no `ASWebAuthenticationSession`; upload endpoints for audio, images or documents near speech, scanning or AI features; whether `setRequiresOnDeviceRecognition:` appears where `SFSpeechRecognizer` is used.
5. **Build the matrix** as in GT-PRIV-0069-1: feature, broad path, alternative, availability against `MinimumOSVersion` (is the broad path behind an `if #available` check for older systems?), sufficiency.

#### Observation

The purpose strings and privacy keys, frameworks per binary, the referenced classes, selectors and Swift types, and the feature matrix.

#### Evaluation

The test **fails** for each feature that requests broad authorisation where an alternative covers it on the app's supported iOS versions: library authorisation (`NSPhotoLibraryUsageDescription` with `requestAuthorizationForAccessLevel:`) to choose an image when `PHPickerViewController` or `PhotosPicker` is available; contacts authorisation to pick one contact; read-write photo access only to save; full calendar access to add an event on iOS 17+; "Always" location without a background feature; precise location by default for a region-level feature; Core Bluetooth scanning to set up the app's own accessory on iOS 18+ where AccessorySetupKit fits; a `WKWebView` login to a third-party identity provider; server speech recognition where `supportsOnDeviceRecognition` is available and accuracy is not critical. It **passes** when alternatives are used, when broad access is limited to OS versions without them, or when the broad access serves a confirmed core feature (a photo editor managing albums, a contact manager, turn-by-turn navigation). As on Android, leave unresolved candidates for the dynamic test.

#### Demo

Illustrative Swift for an app that requests full library access to choose a profile picture:

```swift
PHPhotoLibrary.requestAuthorization(for: .readWrite) { status in
    guard status == .authorized else { return }   // .limited treated as failure
    let assets = PHAsset.fetchAssets(with: .image, options: nil)
    DispatchQueue.main.async { self.showCustomGrid(assets) }
}
```

Illustrative detection output:

```text
$ plutil -p "$APP/Info.plist" | grep -E "MinimumOSVersion|UsageDescription"
  "MinimumOSVersion" => "16.0"
  "NSPhotoLibraryUsageDescription" => "Choose a profile picture"
  "NSContactsUsageDescription" => "Invite your friends"
  "NSLocationAlwaysAndWhenInUseUsageDescription" => "Find shops near you"
$ nm -u "$BIN" | grep -oE "_OBJC_CLASS_\\\$_(PHPhotoLibrary|PHAsset|PHPickerViewController|CNContactStore|CNContactPickerViewController)" | sort -u
_OBJC_CLASS_$_CNContactStore
_OBJC_CLASS_$_PHAsset
_OBJC_CLASS_$_PHPhotoLibrary
```

The purpose string itself says the feature is a single image; `PHPickerViewController` exists on every supported version (iOS 14+) and is not referenced: a failing candidate, to confirm dynamically. The same goes for contacts ("invite") and "Always" location ("shops near you").

### GT-PRIV-0069-3: Which access path each feature uses at runtime (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Use each privacy-relevant feature on a clean install and record what the user sees (a system picker, a scoped prompt, or a broad permission prompt), what access the app ends up holding, what it actually reads, and, for processing features, whether content leaves the device. This settles the candidates from the static tests and catches paths they cannot see (server-driven flows, SDK prompts, web content).

#### Prerequisites

- Test devices you control: Android 14 or later (ideally also the app's minimum supported version) and an iPhone on a current iOS, with the release build from its real distribution channel and a test account.
- A traffic interception set-up for the app's own traffic ([lab guide](/mobile/mobile-traffic-interception-lab/); [MASTG-TECH-0120](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0120/)).
- Optional: a rooted or jailbroken test device with [Frida](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/) to trace the app's own calls ([MASTG-TECH-0033](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0033/), [MASTG-TECH-0086](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0086/)). Observe only; do not change behaviour.
- Use test data on the device: a seeded photo library and address book of fictitious entries. Never exercise contact or photo uploads with a real person's data.

#### Steps

**Android**

1. **Install clean, without auto-grants**, and log the activity launches the app makes:

   ```bash
   adb install app.apk                     # not -g, so nothing is pre-granted
   UID=$(adb shell dumpsys package com.example.app | grep -m1 -oE "userId=[0-9]+" | cut -d= -f2)
   adb logcat -c && adb logcat -s ActivityTaskManager:I | grep --line-buffered "from uid $UID"
   ```

   `ActivityTaskManager` logs every activity start with its action and component, so you see whether a feature launched `android.provider.action.PICK_IMAGES`, `android.intent.action.PICK`, `android.media.action.IMAGE_CAPTURE` or the app's own gallery activity.
2. **Exercise each feature from the matrix** (attach a photo, change avatar, invite a friend, find nearby, pair a device, verify a phone number, import a file, share screen, dictate, scan a document). For each one, note the UI that appears; while a picker or dialog is shown, record whose it is:

   ```bash
   adb shell dumpsys activity activities | grep -E "topResumedActivity|ResumedActivity"
   ```

   A picker belongs to the MediaProvider module or the Play services package; a permission dialog to the permission controller; an in-app gallery to the app itself.
3. **Record the resulting grants and access** after each feature:

   ```bash
   adb shell dumpsys package com.example.app | sed -n '/runtime permissions:/,/^ *$/p'
   adb shell cmd appops get com.example.app      # ops with last access times, e.g. COARSE_LOCATION, FINE_LOCATION, READ_CONTACTS, READ_MEDIA_IMAGES
   ```

   Repeat the location features choosing **Approximate** and the media features choosing **Select photos and videos**, and the contact and photo features denying the permission, to check that the feature still works through a picker (Play requires a reasonable alternative for users who decline restricted permissions). Cross-check with **Settings > Security & privacy > Privacy > Privacy dashboard** (wording varies by vendor), which shows recent location, camera and microphone use per app.
4. **See what the app reads** (rooted test device). Log the content URIs the app itself queries while you use the features:

   ```javascript
   // trace-cr-query.js - observe only: which content URIs does the app query?
   Java.perform(() => {
     const CR = Java.use('android.content.ContentResolver');
     CR.query.overloads.forEach((o) => {
       o.implementation = function (...args) {
         console.log('[query] ' + args[0]);
         return o.apply(this, args);
       };
     });
   });
   ```

   ```bash
   frida -U -f com.example.app -l trace-cr-query.js
   ```

   A picker result is a single URI the system handed to the app; an enumeration is a query on the collection URI (`content://media/external/images/media`, `content://com.android.contacts/data/phones`) with no selection.
5. **Capture traffic during processing and sharing features.** With the proxy on, use dictation, scanning, translation, AI features and "find friends". Note what personal content each request carries (audio, image bytes, text, phone numbers or hashes of them) and to which host. Platform speech services send audio from a system process, not from the app, so for speech confirm the on-device flag by code or trace rather than by its absence in your proxy.

**iOS**

1. **Install clean** and reset privacy prompts if the app was installed before (delete and reinstall, or **Settings > General > Transfer or Reset iPhone > Reset > Reset Location & Privacy** on a dedicated test device). Turn on **Settings > Privacy & Security > App Privacy Report** (iOS 15.2+).
2. **Exercise each feature** and note the UI: the system photo picker without any prompt; a limited-access prompt; the full "Allow Full Access" photo or contacts alert; the location alert with or without the Precise toggle on; a one-time grant from a location button; the paste confirmation; the AccessorySetupKit sheet versus the Bluetooth alert; the `ASWebAuthenticationSession` "wants to use example.com to sign in" alert versus an in-app web page.
3. **Record the resulting state** in **Settings > Privacy & Security** (Photos: None / Limited Access / Full Access / Add Photos Only; Contacts: limited or full on iOS 18; Location Services: Never / Ask Next Time / While Using / Always, and Precise Location; Bluetooth; Calendars; Local Network). An app that only uses the picker does not appear under Photos at all, because it never asked.
4. **Read the App Privacy Report**: Data & Sensor Access shows when and how often the app accessed location, photos, contacts, camera and microphone over the last seven days, and App Network Activity lists the domains it contacted. Export it for evidence with the share button at the bottom of the report (a newline-delimited JSON file in current versions).
5. **Trace authorisation and enumeration calls** on a jailbroken test device:

   ```bash
   frida-trace -U -f com.example.app \
     -m "+[PHPhotoLibrary requestAuthorization*]" -m "+[PHAsset fetchAssets*]" \
     -m "-[CNContactStore requestAccessForEntityType:completionHandler:]" \
     -m "-[CNContactStore enumerateContactsWithFetchRequest:error:usingBlock:]" \
     -m "-[CLLocationManager request*]" \
     -m "-[SFSpeechRecognitionRequest setRequiresOnDeviceRecognition:]"
   ```

6. **Capture traffic** for processing and sharing features as on Android.

#### Observation

Per feature: the UI shown (system picker, scoped prompt, broad prompt, in-app web login), the resulting permission state, the app's recorded accesses (appops, Privacy dashboard, App Privacy Report), the URIs or APIs it read, and any personal content sent off the device with destination hosts.

#### Evaluation

The test **fails** for a feature when, on a device where the privacy-preserving alternative is available, the feature shows a broad permission prompt or grants broad access and the feature's purpose is served by the alternative; or when the app enumerates a collection (library, address book, installed apps, Bluetooth scan) beyond what the feature displays; or when the feature does not work after the user chooses the narrower option (Approximate, Selected photos, limited contacts, denial with a picker available); or when personal content is processed remotely where an on-device option supports the feature on that device. It **passes** when each feature uses the system picker or scoped grant, works with the narrower choices, and processing stays on the device or the remote processing is justified (and handed to the declaration and consent reviews). Combine with the static matrix: a broad permission declared but never reached by any feature is still a Low finding (and a MASWE-0066 one), because it can be requested later and must be declared to the store.

#### Demo

Illustrative Android run for the "invite a friend" feature, before and after the fix:

```text
-- Before: in-app list built from READ_CONTACTS
I ActivityTaskManager: START u0 {act=android.content.pm.action.REQUEST_PERMISSIONS pkg=com.google.android.permissioncontroller ...} from uid 10234
$ adb shell cmd appops get com.example.app | grep CONTACTS
READ_CONTACTS: allow; time=+12s310ms ago
[query] content://com.android.contacts/data/phones

-- After: contact pick intent, no permission
I ActivityTaskManager: START u0 {act=android.intent.action.PICK dat=content://com.android.contacts/... } from uid 10234
[query] content://com.android.contacts/data/1043
```

Illustrative App Privacy Report export lines (field names can differ between iOS versions):

```json
{"accessor":{"identifier":"com.example.app","identifierType":"bundleID"},"category":"contacts","kind":"intervalBegin","timeStamp":"2026-11-03T10:14:22.118+00:00"}
{"accessor":{"identifier":"com.example.app","identifierType":"bundleID"},"category":"photos","kind":"intervalBegin","timeStamp":"2026-11-03T10:15:02.511+00:00"}
```

A `photos` access for an app whose only photo feature should be the picker means the app holds library authorisation and used it.

## Secure implementation

### Android: pickers, scoped permissions and on-device options

```kotlin
// Photos: no permission. Falls back to ACTION_OPEN_DOCUMENT where no picker exists.
val pickImage = registerForActivityResult(ActivityResultContracts.PickVisualMedia()) { uri ->
    uri?.let { upload(it) }
}
pickImage.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly))

// One contact: temporary read grant on the returned URI, no READ_CONTACTS.
val pickContact = registerForActivityResult(ActivityResultContracts.PickContact()) { uri ->
    uri?.let { readSelectedContact(it) }
}

// Documents: Storage Access Framework, no storage permission.
val openDoc = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
    uri?.let { importFile(it) }
}
openDoc.launch(arrayOf("application/pdf"))

// Camera photo through the camera app: do NOT declare CAMERA, or this throws if not granted.
val takePicture = registerForActivityResult(ActivityResultContracts.TakePicture()) { ok -> /* ... */ }

// Speech on the device where available (API 31+).
val recognizer = if (Build.VERSION.SDK_INT >= 31 &&
        SpeechRecognizer.isOnDeviceRecognitionAvailable(context))
    SpeechRecognizer.createOnDeviceSpeechRecognizer(context)
else null  // offer typing instead, or ask before using a remote service
```

```xml
<!-- Storage permissions only where no picker exists -->
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"
    android:maxSdkVersion="28" />

<!-- Photo picker backport for Android 4.4-10 through Play services -->
<service android:name="com.google.android.gms.metadata.ModuleDependencies"
    android:enabled="false" android:exported="false" tools:ignore="MissingClass">
    <intent-filter>
        <action android:name="com.google.android.gms.metadata.MODULE_DEPENDENCIES" />
    </intent-filter>
    <meta-data android:name="photopicker_activity:0:required" android:value="" />
</service>

<!-- Approximate location is enough for a nearby-stores list -->
<uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION" />

<!-- BLE without location on Android 12+, location only for 11 and lower -->
<uses-permission android:name="android.permission.BLUETOOTH_SCAN"
    android:usesPermissionFlags="neverForLocation" />
<uses-permission android:name="android.permission.BLUETOOTH_CONNECT" />
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"
    android:maxSdkVersion="30" />

<!-- Name the apps you interact with instead of QUERY_ALL_PACKAGES -->
<queries>
    <package android:name="com.example.partnerapp" />
</queries>
```

For OTP auto-fill use the SMS Retriever API (and SMS User Consent where you do not control the message), for the phone number the Phone Number Hint API, for sign-in Credential Manager, and for third-party OAuth Custom Tabs or Auth Tab. For pairing, prefer `CompanionDeviceManager.associate()` with a `DeviceFilter` over open scans. Leave `createScreenCaptureIntent()` at its default so users can share a single app.

### iOS: pickers, limited access and on-device options

```swift
import PhotosUI
import ContactsUI
import CoreLocationUI
import Speech

// Photos: out-of-process picker, no authorisation, no purpose string needed.
var config = PHPickerConfiguration()          // no photoLibrary: no asset identifiers
config.filter = .images
config.selectionLimit = 1
let picker = PHPickerViewController(configuration: config)
picker.delegate = self
present(picker, animated: true)

// One contact: no Contacts authorisation.
let contactPicker = CNContactPickerViewController()
contactPicker.predicateForEnablingContact = NSPredicate(format: "emailAddresses.@count > 0")
contactPicker.delegate = self
present(contactPicker, animated: true)

// "Use my location" for a single search: one-time grant from a system button.
let locationButton = CLLocationButton()
locationButton.label = .currentLocation
locationButton.addTarget(self, action: #selector(searchNearby), for: .touchUpInside)

// Dictation that never leaves the device.
if let recognizer = SFSpeechRecognizer(), recognizer.supportsOnDeviceRecognition {
    let request = SFSpeechAudioBufferRecognitionRequest()
    request.requiresOnDeviceRecognition = true
}
```

```swift
// SwiftUI equivalents (iOS 16 / 15 / 18)
PhotosPicker(selection: $item, matching: .images) { Text("Choose photo") }
LocationButton(.currentLocation) { manager.requestLocation() }
ContactAccessButton(queryString: searchText)   // with limited contacts access
```

```xml
<!-- Info.plist: ask for approximate location by default -->
<key>NSLocationDefaultAccuracyReduced</key>
<true/>
<!-- Only saving to the library: add-only, not read-write -->
<key>NSPhotoLibraryAddUsageDescription</key>
<string>Save your edited images to Photos</string>
```

Handle `.limited` for Photos and Contacts as a working state, not a failure. On iOS 17 and later add calendar events with `EKEventEditViewController` and no EventKit authorisation. Set up your own accessories with AccessorySetupKit on iOS 18 and later. Sign users in to third parties with `ASWebAuthenticationSession`, and offer Sign in with Apple, which lets them hide their email address.

## Rating findings

Use the series-wide rule: rate by what personal data the broad mechanism exposes beyond what the feature needs, how sensitive it is, at what scale and how reversibly, and whether it contradicts the app's own declarations or a store policy. Regulatory risk (for example under the data minimisation and data protection by design principles) is for the client's legal team to assess, not for the severity score.

| Rating | Conditions |
|---|---|
| **High** | Broad access to highly sensitive data where an alternative clearly covers the feature **and** the data leaves the device or reaches an SDK: the address book uploaded for an invite feature; SMS content read for OTP auto-fill and sent anywhere; the installed-apps list collected and transmitted outside a permitted use; precise background location collected for a feature that needs a region; an embedded `WebView`/`WKWebView` login to a third-party identity provider where the app or an SDK can read credentials or cookies; personal content (voice, documents, health notes) sent to a third-party AI service when an on-device option supports the feature, without the user being told. Also undeclared use of a Play restricted permission on these data types (removal risk). |
| **Medium** | Broad access granted and used locally beyond the feature (the app enumerates the photo library or contacts to build its own UI, reads precise location for a list of nearby stores, scans Bluetooth with location permission to pair one device) without evidence of transmission; features that break or nag when the user chooses Approximate, Selected photos or limited contacts; remote processing of personal content that is disclosed but where on-device processing was feasible. |
| **Low** | Broad permissions declared and requested but not reaching more data than the alternative would (for example a library permission requested but only the picker path used), or reachable only from rarely used code; missing `maxSdkVersion` caps or `neverForLocation` assertions; opting out of app screen sharing without a stated reason; read-write photo access requested only to save; full calendar access to add events on iOS 17+. These are also store-policy risks; say so. |
| **Info** | Broad access confined to OS versions where no alternative exists; broad access that serves a confirmed, declared core feature (gallery, file manager, dialer, contact sync, navigation, backup); alternatives correctly implemented (record as a positive observation). |

Raise a level for special-category or children's data, for location histories, for contacts (because the people affected never used the app), and when the access contradicts the app's Data safety section, App Privacy details or privacy policy (report the contradiction under [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/) as well). Lower a level when the broad grant is user-initiated, short-lived and visible, and the app demonstrably reads only what the feature shows.

In the report give: the feature, the broad mechanism with its evidence (manifest line or purpose string, code location, `dumpsys`/appops or App Privacy Report entry, traffic sample redacted to test data), the privacy-preserving alternative with its OS availability against the app's minimum version, what extra data the broad route exposed, the store policy it touches, and the code change that fixes it. Hand the client's DPO the data-minimisation argument; do not make the legal call yourself.

## References

- OWASP MASWE: [MASWE-0069: Usage of Non-Privacy-Preserving Functionality](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0069/); related [MASWE-0066](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0066/), [MASWE-0047](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0047/), [MASWE-0030](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0030/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-PRIVACY-1](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-1/), [MASVS-PRIVACY-2](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-2/) (CC BY-SA 4.0)
- OWASP MASTG knowledge and best practices: [MASTG-KNOW-0077](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0077/), [MASTG-BEST-0051](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0051/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0017](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0017/), [MASTG-TECH-0033](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0033/), [MASTG-TECH-0117](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/), [MASTG-TECH-0126](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0126/), [MASTG-TECH-0054](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0054/), [MASTG-TECH-0086](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0086/), [MASTG-TECH-0153](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0153/), [MASTG-TECH-0154](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0154/), [MASTG-TECH-0158](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0158/), [MASTG-TECH-0120](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0120/) (CC BY-SA 4.0)
- OWASP MASTG tools: [aapt2 (MASTG-TOOL-0124)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0124/), [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [Apktool (MASTG-TOOL-0011)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/), [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/), [Frida (MASTG-TOOL-0031)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/), [rabin2 (MASTG-TOOL-0129)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/), [Plutil (MASTG-TOOL-0062)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0062/), [otool (MASTG-TOOL-0060)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0060/) (CC BY-SA 4.0)
- Sibling notes: [PRIVACY hub](/mobile/masvs-privacy-privacy-testing-guide/), [MASWE-0066](/mobile/maswe-0066-inadequate-permission-management/), [MASWE-0068](/mobile/maswe-0068-incorrect-use-of-identifiers-for-tracking/), [MASWE-0070](/mobile/maswe-0070-inadequate-awareness-for-privacy-actions/), [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/), [MASWE-0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/); other series: [MASWE-0047](/mobile/maswe-0047-non-standard-security-apis/), [MASWE-0030](/mobile/maswe-0030-improper-use-of-the-clipboard/), [MASWE-0019](/mobile/maswe-0019-no-autofill-support-for-credential-providers/), [MASWE-0048](/mobile/maswe-0048-malicious-code-included-in-the-app/), [traffic interception lab](/mobile/mobile-traffic-interception-lab/)
- Android: [Minimize your permission requests](https://developer.android.com/privacy-and-security/minimize-permission-requests), [Photo picker](https://developer.android.com/training/data-storage/shared/photopicker), [Selected Photos Access](https://developer.android.com/about/versions/14/changes/partial-photo-video-access), [Storage Access Framework](https://developer.android.com/training/data-storage/shared/documents-files), [Manage all files](https://developer.android.com/training/data-storage/manage-all-files), [`MediaStore.ACTION_IMAGE_CAPTURE`](https://developer.android.com/reference/android/provider/MediaStore#ACTION_IMAGE_CAPTURE), [Location permissions](https://developer.android.com/develop/sensors-and-location/location/permissions), [Location button](https://developer.android.com/guide/topics/permissions/private-alternatives/location-button), [Bluetooth permissions](https://developer.android.com/develop/connectivity/bluetooth/bt-permissions), [Companion device pairing](https://developer.android.com/develop/connectivity/bluetooth/companion-device-pairing), [Nearby Wi-Fi devices permission](https://developer.android.com/develop/connectivity/wifi/wifi-permissions), [Local network permission](https://developer.android.com/privacy-and-security/local-network-permission), [Common intents: contacts](https://developer.android.com/guide/components/intents-common#Contacts), [Contact picker (Android 17)](https://developer.android.com/about/versions/17/features/contact-picker), [Phone Number Hint](https://developer.android.com/identity/phone-number-hint), [Credential Manager](https://developer.android.com/identity/sign-in/credential-manager), [Android 8.0 behaviour changes (accounts)](https://developer.android.com/about/versions/oreo/android-8.0-changes), [Package visibility](https://developer.android.com/training/package-visibility), [Media projection](https://developer.android.com/media/grow/media-projection), [Android 15 features (app screen sharing)](https://developer.android.com/about/versions/15/features), [Health Connect](https://developer.android.com/health-and-fitness/guides/health-connect), [Android 16 behaviour changes (health permissions)](https://developer.android.com/about/versions/16/behavior-changes-16), [`SpeechRecognizer`](https://developer.android.com/reference/android/speech/SpeechRecognizer), [Gemini Nano](https://developer.android.com/ai/gemini-nano), [Core app quality guidelines](https://developer.android.com/docs/quality-guidelines/core-app-quality#Minimize_Permissions)
- Google: [SMS Retriever API](https://developers.google.com/identity/sms-retriever/overview), [SMS User Consent API](https://developers.google.com/identity/sms-retriever/user-consent/overview), [Google Code Scanner](https://developers.google.com/ml-kit/vision/barcode-scanning/code-scanner), [Custom Tabs](https://developer.chrome.com/docs/android/custom-tabs), [Auth Tab](https://developer.chrome.com/docs/android/custom-tabs/guide-auth-tab)
- Google Play policy: [Restricted permissions with minimum scope alternatives (photos, videos, contacts)](https://support.google.com/googleplay/android-developer/answer/14115180), [Permissions and APIs that Access Sensitive Information](https://support.google.com/googleplay/android-developer/answer/9888170), [All files access](https://support.google.com/googleplay/android-developer/answer/10467955), [QUERY_ALL_PACKAGES](https://support.google.com/googleplay/android-developer/answer/10158779), [SMS or Call Log permission groups](https://support.google.com/googleplay/android-developer/answer/10208820)
- Apple: [App Review Guidelines](https://developer.apple.com/app-store/review/guidelines/) (4.8, 5.1.1), [`PHPickerViewController`](https://developer.apple.com/documentation/photosui/phpickerviewcontroller), [`PhotosPicker`](https://developer.apple.com/documentation/photosui/photospicker), [Delivering an enhanced privacy experience in your photos app](https://developer.apple.com/documentation/photokit/delivering-an-enhanced-privacy-experience-in-your-photos-app), [`PHAuthorizationStatus.limited`](https://developer.apple.com/documentation/photos/phauthorizationstatus/limited), [`CNContactPickerViewController`](https://developer.apple.com/documentation/contactsui/cncontactpickerviewcontroller), [`CNAuthorizationStatus.limited`](https://developer.apple.com/documentation/contacts/cnauthorizationstatus/limited), [`ContactAccessButton`](https://developer.apple.com/documentation/contactsui/contactaccessbutton), [`contactAccessPicker(isPresented:completionHandler:)`](https://developer.apple.com/documentation/swiftui/view/contactaccesspicker%28ispresented:completionhandler:%29), [`CLAccuracyAuthorization`](https://developer.apple.com/documentation/corelocation/claccuracyauthorization), [`NSLocationDefaultAccuracyReduced`](https://developer.apple.com/documentation/bundleresources/information-property-list/nslocationdefaultaccuracyreduced), [`CLLocationButton`](https://developer.apple.com/documentation/corelocationui/cllocationbutton), [`LocationButton`](https://developer.apple.com/documentation/corelocationui/locationbutton), [`UIPasteControl`](https://developer.apple.com/documentation/uikit/uipastecontrol), [Accessing the event store](https://developer.apple.com/documentation/eventkit/accessing-the-event-store), [AccessorySetupKit](https://developer.apple.com/documentation/accessorysetupkit), [Discovering and configuring accessories](https://developer.apple.com/documentation/accessorysetupkit/discovering-and-configuring-accessories), [`ASWebAuthenticationSession`](https://developer.apple.com/documentation/authenticationservices/aswebauthenticationsession), [`requiresOnDeviceRecognition`](https://developer.apple.com/documentation/speech/sfspeechrecognitionrequest/requiresondevicerecognition), [Foundation Models](https://developer.apple.com/documentation/foundationmodels), [Sign in with Apple](https://developer.apple.com/documentation/signinwithapple), [About App Privacy Report](https://support.apple.com/en-gb/102188), [Sign in with Apple and Hide My Email](https://support.apple.com/en-gb/102609)
- Standards and law: [RFC 8252 OAuth 2.0 for Native Apps](https://www.rfc-editor.org/rfc/rfc8252), [CWE-359](https://cwe.mitre.org/data/definitions/359.html), [GDPR](https://eur-lex.europa.eu/eli/reg/2016/679/oj), [UK GDPR](https://www.legislation.gov.uk/eur/2016/679/contents), [ICO: data minimisation](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/data-protection-principles/a-guide-to-the-data-protection-principles/data-minimisation/), [EDPB Guidelines 4/2019 on Article 25](https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-42019-article-25-data-protection-design-and_en)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
