---
title: "MASWE-0066: Inadequate Permission Management"
date: 2026-11-10 22:00:00 +0000
subcategory: privacy
summary: "Testing Android permissions and iOS purpose strings, entitlements and keyboard Full Access against what the app really needs, and rating it."
refs: [MASWE-0066, MASVS-PRIVACY-1, CWE-250]
tags: [android, ios, masvs-privacy, permissions, entitlements, data-minimisation]
---

This note is part of our [MASVS-PRIVACY guide](/mobile/masvs-privacy-privacy-testing-guide/) and covers OWASP [MASWE-0066](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0066/): an app that asks for more access to the device and the user's data than its features need, keeps that access after it stops needing it, or asks without explaining why. Permissions are where data minimisation becomes concrete. Every runtime permission on Android and every authorisation prompt on iOS is a gate in front of personal data (location, contacts, photos, microphone, health, the local network), and whatever the app is allowed through, every SDK inside the app is allowed through too. The checks themselves are not hard: you list what the app declares, find what it actually calls, and match both against what the user can see. The judgement is in the matching. "Declares `ACCESS_FINE_LOCATION`" is not a finding; "requests precise location on first launch for a feature that needs a postcode, and an analytics SDK reads it every five minutes" is. Below are the platform mechanisms for both operating systems, the nine OWASP tests (three of them OWASP placeholders that we have written ourselves), six of our own tests that fill the gaps between the platforms, the fixes, and how to rate what you find.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: App Permissions (MASTG-KNOW-0017)](#android-app-permissions-mastg-know-0017)
  - [iOS: App Permissions (MASTG-KNOW-0077)](#ios-app-permissions-mastg-know-0077)
  - [iOS: App Extensions (MASTG-KNOW-0082)](#ios-app-extensions-mastg-know-0082)
  - [iOS: Custom Keyboards (MASTG-KNOW-0141)](#ios-custom-keyboards-mastg-know-0141)
- [Tests](#tests)
  - [MASTG-TEST-0254: Dangerous App Permissions (Android)](#mastg-test-0254-dangerous-app-permissions-android)
  - [MASTG-TEST-0255: Permission Requests Not Minimized (Android)](#mastg-test-0255-permission-requests-not-minimized-android)
  - [MASTG-TEST-0256: Missing Permission Rationale (Android)](#mastg-test-0256-missing-permission-rationale-android)
  - [MASTG-TEST-0257: Not Resetting Unused Permissions (Android)](#mastg-test-0257-not-resetting-unused-permissions-android)
  - [MASTG-TEST-0360: Purpose String Accuracy for Reachable Protected Resource Access (iOS)](#mastg-test-0360-purpose-string-accuracy-for-reachable-protected-resource-access-ios)
  - [MASTG-TEST-0361: Runtime Use of Protected Resource APIs Without Accurate Purpose Strings (iOS)](#mastg-test-0361-runtime-use-of-protected-resource-apis-without-accurate-purpose-strings-ios)
  - [MASTG-TEST-0362: Entitlements for Unjustified Capability Exposure (iOS)](#mastg-test-0362-entitlements-for-unjustified-capability-exposure-ios)
  - [MASTG-TEST-0363: Runtime Use of Entitlement-Backed APIs for Unjustified Capability Exposure (iOS)](#mastg-test-0363-runtime-use-of-entitlement-backed-apis-for-unjustified-capability-exposure-ios)
  - [MASTG-TEST-0390: Full Access Requested by a Custom Keyboard Extension (iOS)](#mastg-test-0390-full-access-requested-by-a-custom-keyboard-extension-ios)
  - [GT-PRIV-0066-1: Broader authorisation scope than the feature needs (iOS)](#gt-priv-0066-1-broader-authorisation-scope-than-the-feature-needs-ios)
  - [GT-PRIV-0066-2: Request timing, explanation and denial handling (iOS)](#gt-priv-0066-2-request-timing-explanation-and-denial-handling-ios)
  - [GT-PRIV-0066-3: Runtime permission requests and protected API use (Android)](#gt-priv-0066-3-runtime-permission-requests-and-protected-api-use-android)
  - [GT-PRIV-0066-4: Special app access and restricted permissions (Android)](#gt-priv-0066-4-special-app-access-and-restricted-permissions-android)
  - [GT-PRIV-0066-5: Permissions added by libraries and SDKs (Android)](#gt-priv-0066-5-permissions-added-by-libraries-and-sdks-android)
  - [GT-PRIV-0066-6: Bundled input method that collects typed text (Android)](#gt-priv-0066-6-bundled-input-method-that-collects-typed-text-android)
- [Best practices](#best-practices)
  - [MASTG-BEST-0051: Minimize iOS Permissions and Entitlements](#mastg-best-0051-minimize-ios-permissions-and-entitlements)
  - [MASTG-BEST-0069: Keep Sensitive Input on the System Keyboard](#mastg-best-0069-keep-sensitive-input-on-the-system-keyboard)
  - [Android: request less, explain, give it back (Guler Tech)](#android-request-less-explain-give-it-back-guler-tech)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

The OWASP requirement is *"The app adequately manages permissions."* MASWE-0066 maps to **MASVS-PRIVACY-1** ("The app minimizes access to sensitive data and resources"), to [CWE-250](https://cwe.mitre.org/data/definitions/250.html) (Execution with Unnecessary Privileges), and to the Android core app quality items for minimal, runtime and explained permissions. It carries OWASP's **P** (privacy) and **EUDIW** profiles. In the earlier MASWE beta numbering it was MASWE-0117. One of its tests, the custom keyboard Full Access test, is filed by OWASP under MASVS-PLATFORM but mapped here. There are no legacy v1 tests to replace: privacy entered the MASVS with v2.

"Adequately" has four parts, and the tests split along them:

| Question | Android | iOS |
|---|---|---|
| Does the app ask for access it does not need? | [MASTG-TEST-0254](#mastg-test-0254-dangerous-app-permissions-android), [GT-PRIV-0066-4](#gt-priv-0066-4-special-app-access-and-restricted-permissions-android), [GT-PRIV-0066-5](#gt-priv-0066-5-permissions-added-by-libraries-and-sdks-android) | [MASTG-TEST-0360](#mastg-test-0360-purpose-string-accuracy-for-reachable-protected-resource-access-ios), [MASTG-TEST-0362](#mastg-test-0362-entitlements-for-unjustified-capability-exposure-ios), [MASTG-TEST-0390](#mastg-test-0390-full-access-requested-by-a-custom-keyboard-extension-ios) |
| Does it ask for broader access than a less intrusive alternative would give? | [MASTG-TEST-0255](#mastg-test-0255-permission-requests-not-minimized-android) | [GT-PRIV-0066-1](#gt-priv-0066-1-broader-authorisation-scope-than-the-feature-needs-ios) |
| Does it explain, ask in context and cope with "no"? | [MASTG-TEST-0256](#mastg-test-0256-missing-permission-rationale-android) | [MASTG-TEST-0360](#mastg-test-0360-purpose-string-accuracy-for-reachable-protected-resource-access-ios), [GT-PRIV-0066-2](#gt-priv-0066-2-request-timing-explanation-and-denial-handling-ios) |
| What does it really do with the access, and when does it give it back? | [MASTG-TEST-0257](#mastg-test-0257-not-resetting-unused-permissions-android), [GT-PRIV-0066-3](#gt-priv-0066-3-runtime-permission-requests-and-protected-api-use-android), [GT-PRIV-0066-6](#gt-priv-0066-6-bundled-input-method-that-collects-typed-text-android) | [MASTG-TEST-0361](#mastg-test-0361-runtime-use-of-protected-resource-apis-without-accurate-purpose-strings-ios), [MASTG-TEST-0363](#mastg-test-0363-runtime-use-of-entitlement-backed-apis-for-unjustified-capability-exposure-ios) |

Three of OWASP's Android tests (0255, 0256, 0257) are `status: placeholder` in the MASTG: a title and a one-line note, no content. We kept their IDs and titles so you can map results to OWASP, and wrote the method ourselves; each says so at the top.

Keep the neighbours apart. Permissions show up in several places in the MASVS, and this note is only about the permissions the app **holds** and what it does with them:

| Question | Where it lives |
|---|---|
| Does a component the app exports require a permission, and is that permission's protection level strong enough to keep other apps out? (`android:permission`, custom permissions, `signature` vs `normal`) | [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/) |
| Can other apps or extensions reach the app's data through App Groups, keychain sharing, share and keyboard extensions? | [MASWE-0031](/mobile/maswe-0031-allowing-untrusted-app-extensions/) |
| Does the app read device identifiers (IMEI, advertising ID, IDFA) for tracking? | [MASWE-0068](/mobile/maswe-0068-incorrect-use-of-identifiers-for-tracking/) |
| Does the app tell the user, in the UI, when it uses a sensitive resource? | [MASWE-0070](/mobile/maswe-0070-inadequate-awareness-for-privacy-actions/) |
| Is tracking or sharing gated on consent (ATT, consent banners)? | [MASWE-0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/) |
| Do the store declarations (Data safety, App Privacy, privacy manifest) match what the permissions collect? | [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/) |
| Is an SDK harvesting data through the app's permissions on purpose? | [MASWE-0048](/mobile/maswe-0048-malicious-code-included-in-the-app/) |
| Which targetSdk-gated privacy changes does the app opt out of by targeting an old API level? | [MASWE-0042](/mobile/maswe-0042-latest-platform-version-not-targeted/) |

This is technical testing guidance, not legal advice. Where we mention the GDPR, the UK GDPR or store policies below, it is to explain why a finding matters and what evidence to hand to the client's DPO or legal team, who assess the regulatory position.

## Modes of Introduction

**Permissions for features that do not exist, or no longer exist.** A permission added for a feature that was cut, a prototype, or a "we might need it" request. On Android it stays in the manifest; on iOS a purpose string stays in `Info.plist` and the API call stays in the binary behind a feature flag.

**The broad permission instead of the narrow tool.** `CAMERA` to take one profile photo instead of `ACTION_IMAGE_CAPTURE`; `READ_MEDIA_IMAGES` or full Photos access instead of the photo picker; `READ_CONTACTS` or full Contacts access to invite one friend; `ACCESS_FINE_LOCATION` for a weather forecast; background location for a feature the user only uses with the app open; `QUERY_ALL_PACKAGES` to check whether one partner app is installed.

**Permissions arriving with libraries.** On Android, every library's manifest is merged into the app's, so an advertising, analytics or attribution SDK can add `ACCESS_FINE_LOCATION`, `READ_PHONE_STATE` or `ACCESS_WIFI_STATE` without anyone on the app team writing the line. On iOS an SDK cannot add a purpose string, but it can call any protected API the app already has authorisation for, and the app team adds purpose strings because the SDK's integration guide says so.

**SDKs piggybacking on the app's grants.** Neither platform separates the app's own code from the SDKs inside it. If the user grants location to the app for a map, every SDK in the process can read location too, and many SDKs check for a granted permission and opportunistically collect when they find one.

**Asking at the wrong time, or without explanation.** A burst of prompts on first launch before the user has seen any feature, generic purpose strings ("This app needs access to your camera"), Android prompts with no in-app explanation, or a pre-prompt designed to pressure the user into accepting.

**Never giving access back.** A permission used once during onboarding (contacts import, a one-off location check) stays granted for the life of the install. On Android 13+ the app could call `revokeSelfPermissionsOnKill()`; some apps instead ask the user to switch off the platform's "unused app" reset so that grants never expire.

**Over-privileged AI features.** An assistant or agent feature that is given tools backed by permissions (read contacts, read location, send messages) beyond its task, or that can trigger permission-backed actions from model output. Android's guidance on [excessive agency](https://developer.android.com/privacy-and-security/risks/ai-risks/excessive-agency) describes the pattern.

**Entitlements switched on "just in case".** iOS capabilities enabled in Xcode during development (HealthKit, App Groups, iCloud, HomeKit, multicast networking) and never removed.

**A keyboard extension with Full Access.** A custom keyboard bundled with the app that sets `RequestsOpenAccess` to `true` and uses network access or a shared container without a feature that needs it.

## Impact

- **Collection beyond purpose.** The direct effect: location histories, address books, photo libraries, call logs, health data or audio collected that the user did not need to give. Precise and background location reveal home, work, religious attendance and health visits; contacts expose people who never used the app. Under the GDPR this is the data minimisation principle (Art. 5(1)(c)) and data protection by design and by default (Art. 25(2) explicitly covers "the extent of their processing" and "their accessibility").
- **Third-party exposure.** Whatever the app can read, its SDKs can read and send to their back ends, often under the SDK vendor's own terms. The app owner usually remains responsible for it.
- **Larger breach footprint.** Data collected without need is still data to lose: in device storage, in backups, in the app's back end and in every SDK provider's back end.
- **Store enforcement.** Google Play rejects or removes apps that hold SMS, call log, background location, broad photo and video, `QUERY_ALL_PACKAGES` or `MANAGE_EXTERNAL_STORAGE` without an approved declaration, and, from January 2027 for apps targeting Android 17, `READ_CONTACTS` where the contact picker would do. Apple rejects apps with vague purpose strings, unnecessary access, or permission manipulation (App Review Guidelines 5.1.1(ii)–(iv)), and keyboards that do not work without Full Access (4.4.1).
- **User trust.** Users deny, uninstall and leave reviews. Denied permissions then break features the app did legitimately need.

## Mitigations

- **Inventory every permission, purpose string and entitlement against a feature**, including those that arrive from libraries, and remove the rest. Make it a release gate.
- **Use the narrowest platform mechanism**: system intents and pickers (camera intent, photo picker, document picker, contact picker), coarse or reduced-accuracy location, while-in-use instead of background, write-only or add-only access, companion device and accessory pickers instead of Bluetooth scanning and local-network access.
- **Ask in context, explain, and accept "no".** Request at the moment the user starts the feature, explain with an in-app rationale and a specific purpose string, and keep the rest of the app working when the user declines.
- **Give access back.** On Android 13+ call `revokeSelfPermissionsOnKill()` for permissions the app no longer needs (after a one-off import, after the user turns a feature off); do not ask users to disable the auto-reset of unused apps unless a background feature depends on it.
- **Constrain SDKs**: configure them not to collect location or other permission-backed data, remove permissions they add with `tools:node="remove"`, and check what they do at runtime.
- **Bundled keyboards**: do not set `RequestsOpenAccess` unless a user-facing feature requires it, and never transmit or store what the keyboard types.

## Knowledge

OWASP assigns two full Knowledge items, MASTG-KNOW-0017 (Android) and MASTG-KNOW-0077 (iOS), both filed under MASVS-PLATFORM. Our [MASWE-0018 note](/mobile/maswe-0018-missing-auth-on-app-components/) already covers the half of KNOW-0017 about permissions an app *defines* to protect its components (protection levels from the defender's side, custom permissions, enforcement per component, URI permissions); we do not repeat it here. This note covers the other half: permissions the app *requests*, how users grant and revoke them on each OS version, and the store rules around them. The keyboard test also uses MASTG-KNOW-0082 and MASTG-KNOW-0141, which we summarise and link to their full treatment in [MASWE-0031](/mobile/maswe-0031-allowing-untrusted-app-extensions/).

### Android: App Permissions (MASTG-KNOW-0017)

Source: [MASTG-KNOW-0017](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0017/).

#### Permission types and protection levels

Every Android app runs as its own Linux UID in its own sandbox. To reach anything outside it (sensors, shared data, other apps' data, system features) it declares a `<uses-permission>` in its manifest, and the platform decides how that permission is granted from its **protection level** in the framework manifest:

| Type | Protection level | How it is granted | Examples |
|---|---|---|---|
| Install-time | `normal` | Automatically at install, no UI | `INTERNET`, `ACCESS_NETWORK_STATE`, `ACCESS_WIFI_STATE`, `VIBRATE`, `QUERY_ALL_PACKAGES`, `USE_EXACT_ALARM` |
| Install-time | `signature` (with flags such as `privileged`) | Only to apps signed with the same key as the platform or the defining app; `privileged` adds pre-installed apps on the system image | `ACCESS_MOCK_LOCATION`, `READ_LOGS`, `INSTALL_PACKAGES`, `READ_PRIVILEGED_PHONE_STATE` |
| Runtime | `dangerous` | Prompt at runtime (on Android 6.0+ for apps targeting API 23+); user can revoke at any time | Location, camera, microphone, contacts, calendar, SMS, call log, phone, body sensors, nearby devices, media, notifications |
| Special | `appop` combined with other flags | User toggles it on a dedicated Settings page (**Settings > Apps > Special app access**) after the app sends them there | `SYSTEM_ALERT_WINDOW`, `MANAGE_EXTERNAL_STORAGE`, `PACKAGE_USAGE_STATS`, `SCHEDULE_EXACT_ALARM`, `WRITE_SETTINGS`, `REQUEST_INSTALL_PACKAGES` |

The protection level a permission really has is the one in the platform's [core manifest](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/res/AndroidManifest.xml), and several carry extra flags that matter for testing: `SYSTEM_ALERT_WINDOW` is `signature|setup|appop|installer|pre23|development`, `MANAGE_EXTERNAL_STORAGE` is `signature|appop|preinstalled`, and SMS, call log, `ACCESS_BACKGROUND_LOCATION` and the legacy storage permissions carry `hardRestricted` or `softRestricted` flags. A hard-restricted permission can only be granted if the installer allowlisted it at install time; Google Play does that only for apps whose declaration it approved. A permission declared with `normal` level is not "harmless" from a privacy point of view: `ACCESS_WIFI_STATE` and `QUERY_ALL_PACKAGES` are granted silently, yet the first can reveal network details and the second the full list of installed apps, which Play treats as personal and sensitive data.

OWASP's KNOW-0017 adds a risk table from the [Uraniborg preloaded-app scoring paper](https://www.android-device-security.org/publications/2020-lau-uraniborg/Lau_2020_Uraniborg_Scoring_Whitepaper_20200827.pdf). It is useful for one thing in this weakness: reminding you that protection level and privacy risk are different axes (`ACCESS_WIFI_STATE` is `normal` and rated HIGH). Most of the table lists signature permissions that only pre-installed or platform apps can hold. For a third-party app review, the `dangerous`, special and the few sensitive `normal` permissions are what you rate.

To see what a permission is on the device under test (the definition can differ between Android versions and OEM builds):

```bash
# All dangerous permissions on this device, grouped
adb shell pm list permissions -d -g

# Definition of one permission: defining package, protection level, flags
adb shell dumpsys package permission android.permission.ACCESS_BACKGROUND_LOCATION
```

#### The runtime model and what changed per version

Runtime permissions arrived in Android 6.0 (API 23). Most later privacy changes apply only to apps that target the new API level, which is why an old `targetSdkVersion` is a privacy finding in its own right ([MASWE-0042](/mobile/maswe-0042-latest-platform-version-not-targeted/)).

| Android | Change relevant to permission minimisation | Applies to |
|---|---|---|
| 6.0 (API 23) | Dangerous permissions requested at runtime and revocable in Settings; legacy apps (target 22 or lower) still get them at install | Apps targeting 23+ |
| 8.0 (API 26) | A runtime request grants only the permission requested, not the whole group; later requests in an already-granted group are granted without a dialog | Apps targeting 26+ |
| 9 (API 28) | Call log permissions split into their own `CALL_LOG` group; Wi-Fi scan results and SSID need location permission and location on | All apps |
| 10 (API 29) | **Background location** becomes a separate permission, `ACCESS_BACKGROUND_LOCATION`, and the user can choose "Allow only while using the app"; `ACTIVITY_RECOGNITION` becomes runtime; `ACCESS_MEDIA_LOCATION` needed for photo EXIF location; scoped storage; non-resettable identifiers need `READ_PRIVILEGED_PHONE_STATE` | Mostly apps targeting 29+; the "while using" choice for all |
| 11 (API 30) | **One-time permissions** ("Only this time") for location, microphone and camera; **auto-reset** of runtime permissions for unused apps; background location must be requested separately after foreground (the dialog no longer offers "Allow all the time"); package visibility filtering and `QUERY_ALL_PACKAGES`; `MANAGE_EXTERNAL_STORAGE` | One-time: all apps; auto-reset, separate background request and package visibility: apps targeting 30+ |
| 12 (API 31) | **Approximate location**: the user can grant coarse when the app asks for fine, and apps targeting 31 must request `ACCESS_COARSE_LOCATION` together with `ACCESS_FINE_LOCATION`; **Bluetooth permissions** `BLUETOOTH_SCAN`, `BLUETOOTH_CONNECT`, `BLUETOOTH_ADVERTISE` (runtime, "Nearby devices" group) replace location for Bluetooth, with `usesPermissionFlags="neverForLocation"` to assert no location is derived; Privacy Dashboard; camera and microphone indicators and toggles; hibernation adds more effects to auto-reset; `SCHEDULE_EXACT_ALARM` becomes a special permission | Mixed: indicators and dashboard for all, permission splits for apps targeting 31+ |
| 13 (API 33) | **`POST_NOTIFICATIONS`** runtime permission; **granular media** `READ_MEDIA_IMAGES`, `READ_MEDIA_VIDEO`, `READ_MEDIA_AUDIO` replace `READ_EXTERNAL_STORAGE` for media; **`NEARBY_WIFI_DEVICES`** for Wi-Fi operations without location; `BODY_SENSORS_BACKGROUND`; **`revokeSelfPermissionsOnKill()`**; photo picker | Apps targeting 33+ (apps targeting 32 or lower get a notification prompt from the system when they create their first channel) |
| 14 (API 34) | **Selected Photos Access**: the user can grant access to chosen photos and videos only; apps declare `READ_MEDIA_VISUAL_USER_SELECTED` to handle it, otherwise they run in a compatibility mode; Health Connect becomes part of the platform | Apps targeting 34+ (compatibility behaviour otherwise) |
| 16 (API 36) | `BODY_SENSORS` and `BODY_SENSORS_BACKGROUND` are replaced by granular `android.permission.health.*` permissions; local network protection available as an opt-in | Apps targeting 36+ |
| 17 (API 37) | **`ACCESS_LOCAL_NETWORK`** runtime permission ("Nearby devices" group) required for LAN discovery and connections unless a system device picker is used; a system **contact picker** as the alternative to `READ_CONTACTS`; the Contacts Provider hides some account columns from the data view; a **location button** (experimental Jetpack library) for session-scoped precise location | Apps targeting 37+ |

Three behaviours that trip up testers and developers:

- **Permanent denial.** If the user taps **Deny** for the same permission twice during the app's install lifetime, the system treats it as "don't ask again" and further requests return denied without a dialog. `dumpsys package` shows this as `USER_FIXED` (denied once is `USER_SET`). Reset between test runs with `adb shell pm clear-permission-flags <pkg> <permission> user-set user-fixed`.
- **Groups still matter for the user, not for the developer.** Since Android 8.0 the system grants exactly the permission requested, but a later request for another permission in the same group is granted silently. An app that requests `READ_CONTACTS` for an invite feature and later `WRITE_CONTACTS` will get the second without the user seeing a prompt. Group membership is not stable across releases; never rely on it.
- **Approximate wins.** If the user picks "Approximate", the app gets only `ACCESS_COARSE_LOCATION`, whatever it declared, and should still work. If it does not, that is a design problem: the app should only need precise location for features that genuinely require it.

#### Explaining, asking and accepting "no"

The [platform workflow](https://developer.android.com/training/permissions/requesting) is: wait until the user interacts with the feature, check with `ContextCompat.checkSelfPermission()`, and if the permission is not granted call `shouldShowRequestPermissionRationale()`. It returns `true` after the user has denied the permission once (and not permanently), which is the cue to show an in-app explanation before asking again. Then request with the `RequestPermission` or `RequestMultiplePermissions` activity result contract, and handle denial by degrading only the feature that needs the permission.

Two further places for explanations exist since Android 12: an activity protected by `android.permission.START_VIEW_PERMISSION_USAGE` that handles `android.intent.action.VIEW_PERMISSION_USAGE` (shown as an info icon on the app's permission page in Settings) and `android.intent.action.VIEW_PERMISSION_USAGE_FOR_PERIOD` (an info icon in the Privacy Dashboard, with the permission group, attribution tags and time window as extras) ([Explain access to more sensitive information](https://developer.android.com/training/permissions/explaining-access)).

Google Play's [permissions policy](https://support.google.com/googleplay/android-developer/answer/9888170) turns this into rules: request permissions incrementally and in context, use data only for the purposes the user consented to, honour a decline without manipulation, and make a reasonable effort to keep the app usable without the permission (for example, manual address entry when location is denied).

#### Giving access back

Android offers two ways to return runtime permissions to their default, denied state:

- **The app does it.** On Android 13 (API 33)+, `Context.revokeSelfPermissionOnKill(String)` and `revokeSelfPermissionsOnKill(Collection<String>)` remove the app's own runtime permissions. Removal is asynchronous: the system kills all processes of the app's UID when it judges it safe, usually after the app has spent a while in the background. To make Settings show that the app no longer accesses a group, revoke every permission in that group.
- **The system does it.** For apps targeting Android 11+ that the user has not used for a few months, the system resets runtime permissions (Android 11) or puts the app into **hibernation** (Android 12+: permissions reset, no background jobs or alarms, no push messages, cache cleared). Through Google Play services the reset was extended to Android 6.0 to 10 devices from December 2021. "Use" means an activity resumed, a widget or notification interaction, or another app or the system binding to the app's components; scheduled jobs, implicit broadcasts and alarms do not count. Apps without a launcher icon, work profile apps, device policy controllers and carrier-privileged apps are exempt.

An app can ask the user to exempt it. The recommended APIs are AndroidX `PackageManagerCompat.getUnusedAppRestrictionsStatus()` and `IntentCompat.createManageUnusedAppRestrictionsIntent()` (launched with `startActivityForResult()`), which take the user to the setting called **Pause app activity if unused** on Android 13+, **Remove permissions and free up space** on Android 12 and **Remove permissions if app isn't used** on Android 11. The older platform API, `PackageManager.isAutoRevokeWhitelisted()` plus an `Intent.ACTION_APPLICATION_DETAILS_SETTINGS` intent, is not formally deprecated in the reference, but the [app hibernation guide](https://developer.android.com/topic/performance/app-hibernation) calls it legacy and advises against it because it ignores the backported behaviour on older Android versions; `setAutoRevokeWhitelisted()` can only be called by the package's installer of record. Asking for an exemption is legitimate for background features the user relies on (family location sharing, device sync, companion devices); asking for it so that grants never expire is a finding.

#### Permissions from libraries: the manifest merger

The Android Gradle Plugin [merges](https://developer.android.com/build/manage-manifests) the manifests of all modules and library dependencies into one. Every `<uses-permission>` in a library manifest ends up in the app, and the app team often never sees it. Two details matter:

- The merger can also add permissions **implicitly**: if a library targets a very old API level (3 or lower, or 15 or lower with contacts access), it adds `WRITE_EXTERNAL_STORAGE`, `READ_PHONE_STATE`, `READ_CALL_LOG` or `WRITE_CALL_LOG` to keep the library working.
- The app can drop an unwanted permission with a merge rule marker in its own manifest:

  ```xml
  <manifest xmlns:android="http://schemas.android.com/apk/res/android"
      xmlns:tools="http://schemas.android.com/tools">
      <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"
          tools:node="remove" />
  </manifest>
  ```

The merger writes a report showing which library contributed each element to `build/outputs/logs/manifest-merger-<variant>-report.txt`, and Android Studio's **Merged Manifest** tab shows the same. That report is the fastest way to prove where a permission came from, if the client gives you the source.

Removing a permission from the manifest does not change the SDK's code: it will typically check `checkSelfPermission()` and skip collection, which is the desired outcome, but test it (see [GT-PRIV-0066-5](#gt-priv-0066-5-permissions-added-by-libraries-and-sdks-android)).

#### App ops and data access auditing

Behind runtime and special permissions sits **AppOps**, which records the app's use of protected operations (location, camera, microphone, contacts reads and so on), with the last access time, and enforces per-operation modes (`allow`, `ignore`, `deny`, `foreground`). It is the system's own record of what the app actually did, and the source of the Privacy Dashboard:

```bash
adb shell cmd appops get com.example.app            # ops with mode and last access time
adb shell dumpsys appops --package com.example.app  # more detail, per attribution tag
adb shell cmd appops set com.example.app COARSE_LOCATION ignore   # silently deny one op
```

Since Android 11 apps can audit themselves: declare `<attribution android:tag="...">` elements, create attribution contexts with `Context.createAttributionContext()` for each feature, and register an `AppOpsManager.OnOpNotedCallback` to log every protected access with the tag and a stack trace ([data access auditing](https://developer.android.com/guide/topics/data/audit-access)). A client that uses this can tell you exactly which feature or SDK reads location; if they do not, Frida gives you the same answer ([GT-PRIV-0066-3](#gt-priv-0066-3-runtime-permission-requests-and-protected-api-use-android)).

#### Google Play policies for sensitive permissions

Google Play's [Permissions and APIs that Access Sensitive Information](https://support.google.com/googleplay/android-developer/answer/9888170) policy is stricter than the platform and changes often; check the current wording when you report. As of November 2026:

| Permission | Play rule |
|---|---|
| Any permission | Only for current features promoted in the store listing; incremental, in-context requests; no use for undisclosed purposes; never sold |
| Restricted permissions (dangerous, special, signature) | Respect declines without manipulation; offer an alternative (for example, manual entry) |
| SMS and call log groups | Only for the default SMS, Phone or Assistant handler, with an approved declaration; may not even appear in the manifest otherwise ([details](https://support.google.com/googleplay/android-developer/answer/9047303)) |
| Location | Minimum scope (coarse before fine, foreground before background); never solely for ads or analytics; background location only for core features with a declaration; foreground-service location only as a continuation of a user action |
| `READ_MEDIA_IMAGES`, `READ_MEDIA_VIDEO` | Apps targeting 33+ only if the photo picker is insufficient for core functionality, with a declaration; compliance mandatory since 28 May 2025 ([details](https://support.google.com/googleplay/android-developer/answer/14115180)) |
| `READ_CONTACTS` | Apps targeting 37+ only if the Android contact picker is insufficient, with a declaration; announced April 2026, mandatory from 27 January 2027 according to Google's timeline |
| `MANAGE_EXTERNAL_STORAGE` | Apps targeting 30+ only if the Storage Access Framework and similar are insufficient, with a declaration |
| `QUERY_ALL_PACKAGES` | Only where awareness of all installed apps is core functionality; use targeted `<queries>` otherwise ([details](https://support.google.com/googleplay/android-developer/answer/10158779)) |
| Location button | Apps targeting 37+ whose features only need session-based location must use the system location button |

#### Where OWASP's item is outdated

KNOW-0017's version history stops at Android 10, so the changes that matter most for minimisation (one-time permissions, auto-reset, approximate location, Bluetooth and Wi-Fi permissions without location, notification and media permissions, photo and contact pickers, local network) are missing; the table above fills the gap. A few smaller points: the risk table lists `WRITE_SMS` as a `normal` permission, but the current core manifest marks it `removed`; it lists `ACCESS_LOCAL_NETWORK` and `RANGING` with a protection level of "runtime", which is not a protection level name (the Android 17 notes call `ACCESS_LOCAL_NETWORK` a runtime permission in the Nearby devices group, so read "runtime" as `dangerous`); and the custom permission example uses `protectionLevel="normal"`, which protects nothing (see [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/)). Its Android 9 note that reading "the phone number" requires `READ_CALL_LOG` refers to the incoming or outgoing call number delivered with phone-state events, not the device's own number. The statement that `Build.getSerial()` needs `READ_PHONE_STATE` was true for API 28; from Android 10 it needs `READ_PRIVILEGED_PHONE_STATE`, which third-party apps cannot hold.

#### Inspecting permissions on a device

`dumpsys package` gives requested, install-time and runtime permissions with their grant state and flags:

```bash
adb shell dumpsys package com.example.app | grep -E -A40 'requested permissions:'
```

```text
    requested permissions:
      android.permission.INTERNET
      android.permission.ACCESS_COARSE_LOCATION
      android.permission.ACCESS_FINE_LOCATION
      android.permission.READ_CONTACTS
    install permissions:
      android.permission.INTERNET: granted=true
    ...
    runtime permissions:
      android.permission.ACCESS_FINE_LOCATION: granted=true, flags=[ USER_SET|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED|ONE_TIME]
      android.permission.READ_CONTACTS: granted=false, flags=[ USER_SET|USER_FIXED|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]
```

(Illustrative output; flag names vary slightly by Android version.) `ONE_TIME` marks an "Only this time" grant and `USER_FIXED` a permanent denial. Grant and revoke manually to exercise both paths: `adb shell pm grant <pkg> <perm>`, `adb shell pm revoke <pkg> <perm>`; `adb install -g` grants everything at install, which is handy for coverage and wrong for testing the request flow. On the device, **Settings > Security & privacy > Privacy > Permission manager** and the **Privacy Dashboard** (names vary by OEM) show the same from the user's side.

### iOS: App Permissions (MASTG-KNOW-0077)

Source: [MASTG-KNOW-0077](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0077/).

#### Three layers

Every third-party iOS app runs as the `mobile` user inside a sandbox profile that applies to all apps; nothing in it is configurable by the developer or the user. Access beyond the sandbox goes through three separate layers, and a feature can need one, two, all three or none of them:

| Layer | Where it lives | Who decides | Example |
|---|---|---|---|
| **Purpose strings** (`NS…UsageDescription`) | `Info.plist` of the app or extension | Developer writes the text; it is shown in the system prompt | `NSCameraUsageDescription` |
| **Runtime authorisation** | Per-framework API and system prompt; state in Settings | The user, and they can change it at any time | `AVCaptureDevice.requestAccess(for: .video)` |
| **Entitlements** | Signed into the code signature; must be allowed by the provisioning profile | Developer enables the capability; Apple controls which entitlements a team can have | `com.apple.developer.healthkit` |

There is no install-time grant of a protected resource on iOS: every privacy-sensitive resource needs runtime authorisation, and the system will not show the prompt without the matching purpose string. Since iOS 10, an app that touches a protected resource without the key is terminated (for most resources) or has the request fail, and App Store Connect rejects such builds with `ITMS-90683: Missing purpose string in Info.plist`. iOS has no API for an app to give an authorisation back and no automatic reset for unused apps; once granted, access lasts until the user changes it in Settings or deletes the app. That makes the initial request, and the scope of what is requested, the main control.

#### Purpose strings and authorisation APIs

The authoritative list of keys is Apple's [Protected resources](https://developer.apple.com/documentation/bundleresources/protected-resources) page. The ones you will meet most, with the APIs to look for in the binary and to hook at runtime:

| Resource | `Info.plist` key(s) | Request / status APIs | Narrower alternative |
|---|---|---|---|
| Location | `NSLocationWhenInUseUsageDescription`, `NSLocationAlwaysAndWhenInUseUsageDescription` (iOS 11+), `NSLocationTemporaryUsageDescriptionDictionary` | `CLLocationManager.requestWhenInUseAuthorization()`, `requestAlwaysAuthorization()`, `authorizationStatus`, `accuracyAuthorization`, `requestTemporaryFullAccuracyAuthorization(withPurposeKey:)` | When-in-use; reduced accuracy (`NSLocationDefaultAccuracyReduced`); `CLLocationButton` (iOS 15+) for one-off use |
| Camera | `NSCameraUsageDescription` | `AVCaptureDevice.requestAccess(for:)`, `authorizationStatus(for:)` | `UIImagePickerController` camera still needs the key; there is no permission-free camera |
| Microphone | `NSMicrophoneUsageDescription` | `AVAudioApplication.requestRecordPermission`, `AVCaptureDevice.requestAccess(for: .audio)` | None |
| Photos | `NSPhotoLibraryUsageDescription`, `NSPhotoLibraryAddUsageDescription` | `PHPhotoLibrary.requestAuthorization(for:)`, `authorizationStatus(for:)` | `PHPickerViewController` / `PhotosPicker` (no permission); `.addOnly` access level; limited library |
| Contacts | `NSContactsUsageDescription` | `CNContactStore.requestAccess(for:)`, `authorizationStatus(for:)` | `CNContactPickerViewController` (no permission); limited access, `ContactAccessButton` and `contactAccessPicker` (iOS 18) |
| Calendar, reminders | `NSCalendarsFullAccessUsageDescription`, `NSCalendarsWriteOnlyAccessUsageDescription`, `NSRemindersFullAccessUsageDescription` (iOS 17+) | `EKEventStore.requestFullAccessToEvents`, `requestWriteOnlyAccessToEvents`, `requestFullAccessToReminders` | Write-only access; EventKitUI's event editor |
| Bluetooth | `NSBluetoothAlwaysUsageDescription` (iOS 13+; `NSBluetoothPeripheralUsageDescription` deprecated) | `CBManager.authorization`, creating a `CBCentralManager` or `CBPeripheralManager` | AccessorySetupKit (iOS 18) for pairing specific accessories |
| Local network | `NSLocalNetworkUsageDescription`, `NSBonjourServices` (iOS 14+) | No request API: the prompt appears on the first Bonjour browse, multicast or connection to a local address | Avoid LAN discovery; AccessorySetupKit for accessories |
| Health | `NSHealthShareUsageDescription`, `NSHealthUpdateUsageDescription`, plus the HealthKit entitlement | `HKHealthStore.requestAuthorization(toShare:read:)` | Request only the sample types used |
| Motion and fitness | `NSMotionUsageDescription` | `CMMotionActivityManager`, `CMPedometer` | None |
| Speech recognition | `NSSpeechRecognitionUsageDescription` | `SFSpeechRecognizer.requestAuthorization` | On-device recognition reduces exposure, not the permission |
| Media library, HomeKit, Siri, Face ID, TV provider | `NSAppleMusicUsageDescription`, `NSHomeKitUsageDescription`, `NSSiriUsageDescription`, `NSFaceIDUsageDescription`, `NSVideoSubscriberAccountUsageDescription` | `MPMediaLibrary`, `HMHomeManager`, `INPreferences.requestSiriAuthorization`, `LAContext.evaluatePolicy`, `VSAccountManager` | — |
| Tracking | `NSUserTrackingUsageDescription` | `ATTrackingManager.requestTrackingAuthorization` | See [MASWE-0068](/mobile/maswe-0068-incorrect-use-of-identifiers-for-tracking/) and [MASWE-0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/) |

Two practical details. Purpose strings are often **localised** in `<lang>.lproj/InfoPlist.strings` (or compiled from a string catalogue); review the language your users see, not only the development-language value in `Info.plist`. And extensions have their **own** `Info.plist`: a widget, notification service or keyboard extension that uses location needs its own key, and you should read each `.appex` separately.

A declared purpose string does not prove the app uses the resource, and an API reference does not prove the code is reachable. OWASP's tests treat both as evidence to combine with runtime traces and the visible feature set, which is the right approach.

#### Reduced-scope access on iOS

Apple has steadily added ways to give an app less than the full resource:

- **Approximate location (iOS 14+).** The user can switch off **Precise** in the prompt or in Settings; the app sees `accuracyAuthorization == .reducedAccuracy` and gets locations accurate to a few kilometres. An app can ask for reduced accuracy by default with `NSLocationDefaultAccuracyReduced`, and request temporary precise access for one task with `requestTemporaryFullAccuracyAuthorization(withPurposeKey:)`, explained by an entry in `NSLocationTemporaryUsageDescriptionDictionary`.
- **When in use, Allow Once and Always.** "Allow Once" (iOS 13+) gives one session. Always access is requested in a second step after when-in-use, and iOS periodically reminds the user of apps using location in the background, with a map of where.
- **Limited photo library (iOS 14+).** The user can grant access to selected photos only (`PHAuthorizationStatus.limited`); the app can offer to change the selection with `presentLimitedLibraryPicker(from:)`, and suppress the system's automatic re-selection prompt with `PHPhotoLibraryPreventAutomaticLimitedAccessAlert`. The picker (`PHPickerViewController`, `PhotosPicker`) runs out of process and needs no permission at all.
- **Limited contacts (iOS 18+).** The user can share selected contacts only (`CNAuthorizationStatus.limited`); `ContactAccessButton` and `contactAccessPicker(isPresented:completionHandler:)` let the user add contacts to the shared set in context. `CNContactPickerViewController` remains the permission-free way to pick one contact.
- **Write-only calendar (iOS 17+).** An app that only adds events does not need to read the calendar.
- **AccessorySetupKit (iOS 18+).** Pairs a specific Bluetooth or Wi-Fi accessory through a system sheet without the app needing broad Bluetooth or local network authorisation.

#### Entitlements and capabilities

Entitlements are key-value pairs in the code signature that enable a service or relax a sandbox restriction. A capability is the Xcode switch that writes them (plus `Info.plist` keys, linked frameworks and provisioning). An entitlement is not a prompt and not an API call: some are configuration only (`com.apple.developer.default-data-protection`), some add a data-sharing surface (`com.apple.security.application-groups`, `keychain-access-groups`, iCloud containers, `com.apple.developer.associated-domains`), and some come with their own user authorisation on top (`com.apple.developer.healthkit`, `com.apple.developer.homekit`). Privacy-relevant entitlements to look for:

| Entitlement | What it unlocks | User prompt? |
|---|---|---|
| `com.apple.developer.healthkit`, `com.apple.developer.healthkit.access` (clinical records) | Requesting HealthKit authorisation | Yes, per data type |
| `com.apple.security.application-groups` | Shared container and defaults with extensions or other apps of the team | No |
| `keychain-access-groups` | Shared keychain items | No |
| `com.apple.developer.icloud-container-identifiers`, `com.apple.developer.icloud-services`, `com.apple.developer.ubiquity-kvstore-identifier` | iCloud and CloudKit sync of app data | No (iCloud must be on) |
| `com.apple.developer.homekit` | Home data and accessories | Yes |
| `com.apple.developer.networking.multicast` | Raw multicast and broadcast, arbitrary Bonjour browsing | Local network prompt still applies |
| `com.apple.developer.networking.wifi-info` | SSID and BSSID of the current Wi-Fi network (also needs location authorisation or another qualifying condition) | Indirect |
| `com.apple.developer.associated-domains` | Universal links, web credentials, App Clips | No |
| `com.apple.developer.nfc.readersession.formats` | NFC tag reading | System sheet per session |
| `com.apple.developer.siri` | Handling Siri requests | Yes |
| `com.apple.developer.contacts.notes` | Reading the notes field of contacts (needs Apple approval) | Contacts prompt |

Read entitlements from the signed binary (`codesign -d --entitlements :- Payload/App.app`, `rabin2 -OC`, `ldid -e`, `ipsw macho info -e`), for the main app **and** every `.appex` in `PlugIns/` and `Extensions/`. The `embedded.mobileprovision` file shows what the profile allowed at signing time (`security cms -D -i embedded.mobileprovision`), but App Store builds do not contain one, and re-signed test builds carry your profile, not the developer's. KNOW-0077 notes this correctly.

`UIRequiredDeviceCapabilities` (for example `gps`, `nfc`, `bluetooth-le`) and `UIBackgroundModes` (`location`, `bluetooth-central`, `audio`) are related but different. The first only filters which devices can install the app; it grants nothing. The second does matter for this weakness: `UIBackgroundModes` with `location` is what allows continuous background location updates, so its presence in an app with no visible background location feature is a lead.

#### What Apple's review rules say

App Review Guideline **5.1.1(ii)** requires purpose strings that "clearly and completely describe your use of the data"; **5.1.1(iii)** says apps "should only request access to data relevant to the core functionality" and should use the out-of-process picker or share sheet "rather than requesting full access to protected resources like Photos or Contacts"; **5.1.1(iv)** forbids manipulating, tricking or forcing users into unnecessary access and gives the example of requiring microphone access to post photos; **5.1.2(i)** forbids making system features such as location or notifications a condition of using the app. Guideline **4.4.1** requires keyboard extensions to remain functional without full network access and without requiring Full Access, and to collect user activity only to enhance the keyboard itself. Apple's tech talk [Write clear purpose strings](https://developer.apple.com/videos/play/tech-talks/110152/) covers the common rejection reasons.

#### Inspecting authorisation state on a device

**Settings > Privacy & Security** lists, per resource, every app that has asked; **Settings > [App]** lists the resources one app has asked for (a category only appears after the app has requested it once). **Settings > Privacy & Security > App Privacy Report** (iOS 15.2+), once switched on, logs each app's access to location, photos, camera, microphone and contacts with timestamps, and its network domains: on a stock device with an App Store build, it is the cheapest runtime evidence you can get. On the Simulator, `xcrun simctl privacy booted grant|revoke|reset <service> <bundle-id>` sets and clears authorisation without UI.

### iOS: App Extensions (MASTG-KNOW-0082)

Source: [MASTG-KNOW-0082](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0082/). Full treatment: [MASWE-0031](/mobile/maswe-0031-allowing-untrusted-app-extensions/).

An app extension is a separate binary (`.appex` under `PlugIns/`) shipped inside the containing app, with exactly one extension point (`NSExtensionPointIdentifier`), its own sandbox, its own `Info.plist` and its own entitlements. It runs in its own process, never talks directly to its containing app, and shares data with it only through an App Group container or a keychain access group. For this weakness, two consequences: every extension is a separate subject for the purpose string and entitlement tests (0360 to 0363), and an extension's App Group membership is a permission-like capability that widens who can read the app's data.

### iOS: Custom Keyboards (MASTG-KNOW-0141)

Source: [MASTG-KNOW-0141](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0141/). Full treatment: [MASWE-0031](/mobile/maswe-0031-allowing-untrusted-app-extensions/).

A custom keyboard is an extension (`com.apple.keyboard-service`) that the user enables in **Settings > General > Keyboard > Keyboards** and that then serves text input in every app, except secure text fields, phone-pad fields and apps that reject keyboard extensions. Without Full Access it has no network and no shared container. If its `Info.plist` sets [`RequestsOpenAccess`](https://developer.apple.com/documentation/bundleresources/information-property-list/nsextension/nsextensionattributes/requestsopenaccess) to `true`, the user can switch on **Allow Full Access** (iOS warns that the developer could then transmit anything typed), and the keyboard sees the grant through [`UIInputViewController.hasFullAccess`](https://developer.apple.com/documentation/uikit/uiinputviewcontroller/hasfullaccess). Through `textDocumentProxy` it can also read the text around the cursor and the field's traits, including `textContentType` values such as `.oneTimeCode` or `.creditCardNumber`. A keyboard is therefore the most privileged permission an app can ask the user for: one switch gives it a view of what the user types everywhere. That is why MASWE-0066 includes it, from the point of view of the app that *ships* a keyboard; the other side, an app protecting its own fields from third-party keyboards, is MASWE-0031.

## Tests

Nine OWASP tests belong to this weakness: four Android tests filed under MASVS-PRIVACY (three of them placeholders that we wrote ourselves), four iOS tests under MASVS-PRIVACY, and the iOS keyboard test that OWASP files under MASVS-PLATFORM. Our six GT tests give each platform the checks that OWASP has only for the other one, plus the SDK provenance check that matters most in practice.

Before you start, collect three things that every test below relies on:

1. **The feature inventory.** What the app visibly does, from using it, the store listing, help pages and the client's own description. You cannot judge necessity without it. Record which features are behind login, paywall, region or remote configuration.
2. **The SDK inventory.** Which analytics, advertising, attribution, crash reporting, customer support, maps and payment SDKs are in the build ([MASTG-KNOW-0004 note](/mobile/mastg-know-0004-third-party-libraries/), [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/) for building an SBOM).
3. **The declarations.** The Play Data safety section and the App Store privacy label, the privacy manifest, and the privacy policy. A permission whose data is not declared there is also a [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/) finding.

### MASTG-TEST-0254: Dangerous App Permissions (Android)

OWASP page: [MASTG-TEST-0254](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0254/). Type: static.

#### Overview

Lists the permissions declared in the merged manifest and identifies those with `dangerous` protection level, each of which has to be justified by a feature. OWASP's evaluation reads "fails if there are any dangerous permissions", softened by a "context consideration" paragraph. Taken literally that would fail every camera, maps or messaging app, so we evaluate each dangerous permission against the feature inventory instead: the test fails for every dangerous permission without a reasonable, user-visible feature behind it.

#### Prerequisites

- The release APK, or the APK set from a device (`adb shell pm path <pkg>`, then `adb pull` each path), or the `.aab`.
- `aapt2` (Android SDK build-tools) or `apkanalyzer`; jadx or apktool; optionally semgrep and a test device to read the platform's dangerous permission list.
- The feature and SDK inventories.

#### Steps

1. **Get the manifest** ([MASTG-TECH-0117](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/)). jadx keeps `<uses-sdk>` in the decoded manifest; apktool moves it to `apktool.yml`:

   ```bash
   jadx --no-src -d out app.apk          # out/resources/AndroidManifest.xml
   apktool d -s -f -o out-apktool app.apk
   ```

2. **List the declared permissions** ([MASTG-TECH-0126](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0126/)) with any `maxSdkVersion` and `usesPermissionFlags`, and the target SDK, which decides which version-gated behaviour applies:

   ```bash
   aapt2 dump permissions app.apk
   aapt2 dump badging app.apk | grep -E "targetSdkVersion|uses-permission"
   apkanalyzer manifest permissions app.apk
   grep -E '<uses-permission(-sdk-23)?' out/resources/AndroidManifest.xml
   ```

   `<uses-permission-sdk-23>` declares a permission only for API 23+ and is easy to miss with a grep for `uses-permission "`.

3. **Classify them against the device's own definitions** rather than a static list, because the set of dangerous permissions grows with each release:

   ```bash
   adb shell pm list permissions -d -g | sed -n 's/^ *permission://p' | sort -u > dangerous.txt
   aapt2 dump permissions app.apk | sed -n "s/^uses-permission: name='\([^']*\)'.*/\1/p" | sort -u > declared.txt
   comm -12 declared.txt dangerous.txt      # declared AND dangerous on this device
   ```

   Use a device on the newest Android version the app supports. Also note sensitive permissions that are not `dangerous` (`ACCESS_WIFI_STATE`, `QUERY_ALL_PACKAGES`, special permissions); [GT-PRIV-0066-4](#gt-priv-0066-4-special-app-access-and-restricted-permissions-android) covers them.

4. **Map each dangerous permission to a feature.** For each one, find where it is used: search the decompiled code for the permission string and for the APIs it guards, and note whether the caller is app code or an SDK package:

   ```bash
   jadx -d src app.apk
   grep -rn --include=*.java -E 'ACCESS_FINE_LOCATION|READ_CONTACTS|RECORD_AUDIO|CAMERA"' src/sources | awk -F/ '{print $3"/"$4"/"$5}' | sort | uniq -c
   ```

5. **Discount permissions that cannot be granted** on the devices the app supports: a `maxSdkVersion` below the app's `minSdkVersion`, or legacy permissions with no effect for the app's target SDK (`WRITE_EXTERNAL_STORAGE` with target 30+, `READ_EXTERNAL_STORAGE` for media with target 33+). Record them as clean-up items, not privacy findings.

#### Observation

A table of declared dangerous permissions with: `maxSdkVersion`/flags, the feature that justifies it (or "none found"), the code location and package that uses it, and whether the use is in app code or an SDK.

#### Evaluation

The test **fails** for each dangerous permission that has no reasonable connection to a user-visible feature, including permissions that only an SDK uses for its own purposes, and for permissions that could only serve a removed or unreleased feature. It **passes** when every dangerous permission maps to a feature the user can see. A permission that is justified but broader than needed is evaluated in [MASTG-TEST-0255](#mastg-test-0255-permission-requests-not-minimized-android).

False positives to rule out: permissions limited by `maxSdkVersion` to Android versions the app does not support; permissions for features hidden behind a region or account type you did not have (ask the client); system-handler apps (SMS, dialer) for which SMS or call log access is the core feature.

#### Demo

From [MASTG-DEMO-0033](https://mas.owasp.org/MASTG/demos/android/MASVS-PRIVACY/MASTG-DEMO-0033/MASTG-DEMO-0033/). The sample manifest declares four dangerous permissions next to `INTERNET`:

```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
<uses-permission android:name="android.permission.READ_CONTACTS" />
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
```

OWASP's semgrep rule `mastg-android-dangerous-app-permissions.yaml` lists about forty dangerous permissions as literal element patterns (excerpt):

```yaml
rules:
  - id: detect-dangerous-android-permissions
    languages: [xml]
    message: "Dangerous Android permission found:"
    severity: WARNING
    pattern-either:
      - pattern: <uses-permission android:name="android.permission.READ_CONTACTS"/>
      - pattern: <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
      - pattern: <uses-permission android:name="android.permission.READ_MEDIA_IMAGES"/>
      # ... camera, microphone, SMS, call log, phone, calendar, sensors,
      # nearby devices, notifications, GET_ACCOUNTS
```

```bash
semgrep -c mastg-android-dangerous-app-permissions.yaml AndroidManifest_reversed.xml
```

Output (from the demo):

```text
┌─────────────────┐
│ 4 Code Findings │
└─────────────────┘

    AndroidManifest_reversed.xml
    ❯❱ rules.detect-dangerous-android-permissions
          Dangerous Android permission found:

            3┆ <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
            4┆ <uses-permission android:name="android.permission.READ_CONTACTS"/>
            5┆ <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
            6┆ <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
```

The demo app has no contacts, location or storage feature, so all four fail. Two caveats on the rule: it is a fixed list (it predates `ACCESS_LOCAL_NETWORK` and the `android.permission.health.*` permissions), and it does not look at `<uses-permission-sdk-23>`. The device-based `comm` comparison in step 3 does not have either gap.

### MASTG-TEST-0255: Permission Requests Not Minimized (Android)

OWASP page: [MASTG-TEST-0255](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0255/). OWASP status: **placeholder** ("checks if the app requests permissions that have privacy-preserving alternatives"). *The method below is Guler Tech methodology.*

#### Overview

A permission can be justified by a feature and still be the wrong tool. Android provides narrower mechanisms for most common needs, and Google Play now requires several of them. This test takes the justified permissions from [MASTG-TEST-0254](#mastg-test-0254-dangerous-app-permissions-android) and checks whether a less intrusive alternative would provide the same feature.

| Permission | Typical feature | Narrower alternative |
|---|---|---|
| `CAMERA` | Take a photo or video | `MediaStore.ACTION_IMAGE_CAPTURE` / `ACTION_VIDEO_CAPTURE` intent, no permission. If the app declares `CAMERA` but does not hold it, the intent throws `SecurityException`, so remove the declaration |
| `READ_MEDIA_IMAGES`, `READ_MEDIA_VIDEO`, `READ_EXTERNAL_STORAGE` | Pick a photo, attach media | Photo picker (`ActivityResultContracts.PickVisualMedia`), no permission; Storage Access Framework (`ACTION_OPEN_DOCUMENT`) for files; Play policy since 2025 |
| `READ_CONTACTS` | Pick a contact, invite a friend | `Intent.ACTION_PICK` on `ContactsContract.Contacts`; the Android 17 contact picker; Play policy for apps targeting 37+ |
| `ACCESS_FINE_LOCATION` | Nearby results, weather, region | `ACCESS_COARSE_LOCATION` only; manual postcode entry; the location button for one-off precise use |
| `ACCESS_BACKGROUND_LOCATION` | Tracking during an activity | A foreground service of type `location` started by the user |
| Location for Bluetooth or Wi-Fi | Scan for a device | `BLUETOOTH_SCAN` with `neverForLocation`, `NEARBY_WIFI_DEVICES` with `neverForLocation`; companion device pairing |
| `READ_SMS`, `RECEIVE_SMS` | Read an OTP | SMS Retriever API or SMS User Consent API |
| `READ_PHONE_STATE`, `READ_PHONE_NUMBERS` | Device or phone number identification | App-scoped random identifier; phone number verification flows that do not read the SIM |
| `RECORD_AUDIO` | Voice search | `RecognizerIntent.ACTION_RECOGNIZE_SPEECH` (the system speech UI records, not the app) |
| `GET_ACCOUNTS` | Prefill an email address | Credential Manager or a sign-in SDK's account chooser |
| `QUERY_ALL_PACKAGES` | Check whether a partner app is installed | `<queries>` with the specific package or intent |
| `MANAGE_EXTERNAL_STORAGE` | Open or save a file | Storage Access Framework; app-specific storage |

#### Prerequisites

- The output of MASTG-TEST-0254 (justified dangerous permissions and their features).
- The decompiled code (jadx) and a test device on a recent Android version with the app installed.

#### Steps

1. **Look at the declarations that set scope.** In the decoded manifest, check:

   ```bash
   M=out/resources/AndroidManifest.xml
   grep -n -E 'ACCESS_(FINE|COARSE|BACKGROUND)_LOCATION|BLUETOOTH_SCAN|NEARBY_WIFI_DEVICES|READ_MEDIA_|READ_EXTERNAL_STORAGE|CAMERA|READ_CONTACTS|QUERY_ALL_PACKAGES' $M
   grep -n -o 'usesPermissionFlags="[^"]*"' $M
   grep -n -A6 '<queries>' $M
   grep -n -o 'foregroundServiceType="[^"]*"' $M
   ```

2. **Find how each feature reaches the resource** in the decompiled code. For example, a profile photo flow that requests `CAMERA` and opens `CameraX` versus one that launches `ACTION_IMAGE_CAPTURE`; a contact invite that queries `ContactsContract.CommonDataKinds.Phone.CONTENT_URI` for the whole address book versus `ACTION_PICK`:

   ```bash
   grep -rn -E 'PickVisualMedia|ACTION_PICK_IMAGES|ACTION_IMAGE_CAPTURE|ACTION_OPEN_DOCUMENT|ACTION_PICK"|ContactsContract|RecognizerIntent|SmsRetriever|setPriority\(|PRIORITY_HIGH_ACCURACY|PRIORITY_BALANCED_POWER_ACCURACY' src/sources | grep -v -E '/(androidx|kotlin)/'
   ```

3. **Use each feature on the device** with the narrowest grants: deny the permission, grant "Approximate" instead of "Precise", grant "Select photos" instead of "Allow all". Note what still works. A feature that works with approximate location or a picker proves that the broader permission is not needed for it.
4. **Check the location priority and frequency** if the app uses location: a weather or store-finder feature requesting `PRIORITY_HIGH_ACCURACY` updates every few seconds is broader than needed even with a coarse grant.

#### Observation

For each justified sensitive permission: the feature, the mechanism the app uses, the narrower alternative available on the app's supported Android versions, and what happened when you granted only the narrower scope.

#### Evaluation

The test **fails** for each permission where a narrower mechanism from the table would provide the same user-visible feature on the app's supported Android versions, and where the narrower scope was not chosen: for example, `READ_MEDIA_IMAGES` for profile photos, `ACCESS_FINE_LOCATION` for a city-level feature, `READ_CONTACTS` to send one invite, `CAMERA` for one photo, `QUERY_ALL_PACKAGES` to check for one app. It also fails if `BLUETOOTH_SCAN` or `NEARBY_WIFI_DEVICES` is used for device discovery without `neverForLocation` and the app does not use the results to derive location (it then needlessly needs location permission on older versions and implies location use). It **passes** when each permission is the narrowest that does the job, and the app works when the user grants less.

Cases where the broad permission is legitimately needed: gallery and media management apps (`READ_MEDIA_*`), dialers and contact managers, navigation and fitness tracking (fine, sometimes background, location), apps that must work with devices where the picker or Play services are not available (check `minSdkVersion` and the client's markets).

#### Demo

Our example. A profile screen that takes a photo by opening the camera itself needs `CAMERA`; the narrower version needs nothing:

```kotlin
// Broad: requires CAMERA, a runtime prompt, and gives the app a live camera feed
cameraPermissionLauncher.launch(Manifest.permission.CAMERA)

// Narrow: the system camera app takes the picture; no permission declared at all
private val takePicture = registerForActivityResult(ActivityResultContracts.TakePicture()) { saved ->
    if (saved) viewModel.setAvatar(photoUri)
}
fun onChangeAvatar() = takePicture.launch(photoUri)   // photoUri from a FileProvider

// Narrow, for choosing an existing photo: the photo picker, no READ_MEDIA_* needed
private val pickMedia = registerForActivityResult(ActivityResultContracts.PickVisualMedia()) { uri ->
    uri?.let(viewModel::setAvatar)
}
fun onChooseAvatar() = pickMedia.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly))
```

A failing result as it would appear in a report (illustrative):

```text
CAMERA               feature: change profile photo   mechanism: CameraX preview in ProfileActivity
                     alternative: ACTION_IMAGE_CAPTURE / TakePicture contract    -> FAIL
READ_MEDIA_IMAGES    feature: choose profile photo   mechanism: MediaStore query of all images
                     alternative: photo picker (Play policy, target 33+)         -> FAIL
```

### MASTG-TEST-0256: Missing Permission Rationale (Android)

OWASP page: [MASTG-TEST-0256](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0256/). OWASP status: **placeholder** ("checks if the app does not provide a rationale for requesting permissions"). *The method below is Guler Tech methodology.*

#### Overview

Unlike iOS, Android has no developer-supplied text in the system prompt. The only explanation the user gets is what the app shows itself: an in-app rationale before or after the prompt, and optionally the rationale activity linked from Settings and the Privacy Dashboard. This test checks that each runtime request is made in context, explained, and that a denial leaves the rest of the app usable. Google Play's policy (in-context incremental requests, honour declines, no manipulation) and Android's core app quality guidelines both expect this.

#### Prerequisites

- A test device on a recent Android version, the app freshly installed (no `-g`), and a test account.
- The decompiled code (jadx) and the list of runtime permissions from MASTG-TEST-0254.

#### Steps

1. **First launch.** Install without granting (`adb install app.apk`), start the app and record every system permission dialog that appears before you have used any feature. Screen-record the session (`adb shell screenrecord /sdcard/first-run.mp4`).
2. **Per feature.** Use each feature that needs a permission and record: whether an explanation appears before the system dialog, whether it says what the permission is for in this feature, and whether it offers a way to continue without it.
3. **Deny once, then use the feature again.** `shouldShowRequestPermissionRationale()` now returns `true`; the app should explain before asking again. Then deny a second time (permanent denial) and use the feature again: the app should explain that the feature is unavailable and, at most, offer a link to Settings, not loop or block.
4. **Deny everything and use the app.** Check that features that do not need the permission still work, and that the app does not refuse to start or show a full-screen wall until you grant.
5. **Find the request sites in code** and check whether a rationale branch exists:

   ```bash
   grep -rn -E 'shouldShowRequestPermissionRationale|RequestPermission\(\)|RequestMultiplePermissions|requestPermissions\(' src/sources | grep -v -E '/(androidx|kotlin)/'
   ```

6. **Check the Settings and Privacy Dashboard entry points.** Look for an activity with `android:permission="android.permission.START_VIEW_PERMISSION_USAGE"` handling `android.intent.action.VIEW_PERMISSION_USAGE` or `VIEW_PERMISSION_USAGE_FOR_PERIOD`:

   ```bash
   grep -n -B3 -A8 'START_VIEW_PERMISSION_USAGE' out/resources/AndroidManifest.xml
   ```

   If present, tap the info icon on the app's permission page in Settings and check that the screen explains the use. Its absence is not a failure on its own; it is good practice for location, camera and microphone apps.

7. **Reset between runs**: `adb shell pm revoke <pkg> <perm>` and `adb shell pm clear-permission-flags <pkg> <perm> user-set user-fixed`, or reinstall.

#### Observation

A timeline of prompts (launch, feature, after denial), the text of each rationale, screenshots, and the code locations of requests with and without a rationale branch.

#### Evaluation

The test **fails** if:

- a dangerous permission is requested on launch or during onboarding, before the user uses the feature that needs it, without an explanation of that feature (a pre-prompt for core functionality that the app cannot work without, such as a navigation app's location, is acceptable when explained);
- a permission whose purpose is not obvious from the screen (location in a shopping app, contacts in a game, microphone in a note app) is requested without any rationale;
- after a denial, the app re-requests in a loop, blocks unrelated features, or uses dark patterns (a rationale whose only button is "Allow", fake system-style dialogs, threats of reduced service) to obtain the grant;
- the rationale misstates the use (says "to find nearby stores" while the data is also sent to an advertising SDK).

It **passes** when each request follows a user action, permissions with non-obvious purposes are explained, the explanation matches the actual use, and denial degrades only the feature concerned.

#### Demo

Our example of the platform pattern, with the rationale branch and graceful degradation:

```kotlin
private val requestLocation =
    registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) showNearbyStores() else showPostcodeSearch()   // feature still usable
    }

fun onFindNearbyStoresTapped() {
    when {
        ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_COARSE_LOCATION) ==
            PackageManager.PERMISSION_GRANTED -> showNearbyStores()
        shouldShowRequestPermissionRationale(Manifest.permission.ACCESS_COARSE_LOCATION) ->
            showRationale(
                text = "We use your approximate location once to list stores near you. " +
                       "It is not stored. You can search by postcode instead.",
                onContinue = { requestLocation.launch(Manifest.permission.ACCESS_COARSE_LOCATION) },
                onSkip = { showPostcodeSearch() })
        else -> requestLocation.launch(Manifest.permission.ACCESS_COARSE_LOCATION)
    }
}
```

A failing first-run timeline (illustrative):

```text
00:02  System dialog: Allow App to access your location?           (no in-app context, splash screen)
00:04  System dialog: Allow App to access your contacts?
00:06  System dialog: Allow App to send you notifications?
00:09  Deny contacts -> full-screen "We need your contacts to continue" with only an "Allow" button
```

### MASTG-TEST-0257: Not Resetting Unused Permissions (Android)

OWASP page: [MASTG-TEST-0257](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0257/). OWASP status: **placeholder** ("checks if the app does not remove unnecessary access to granted permissions"). *The method below is Guler Tech methodology.*

#### Overview

Some permissions are needed once: importing contacts during onboarding, scanning a QR code during device setup, setting a home location. After that the grant is pure exposure, available to every SDK in the process for as long as the app stays installed. On Android 13+ the app can give the permission back with `revokeSelfPermissionsOnKill()`. Separately, the platform resets permissions of apps that are not used for months; an app that asks the user to turn that off, without a background feature that needs it, keeps grants alive on purpose. This test checks both directions.

#### Prerequisites

- A test device on Android 13 or later (for `revokeSelfPermissionsOnKill`) and, for the hibernation step, Android 12 or later with `adb` access.
- The decompiled code and the feature inventory, in particular which permissions serve one-off flows and which features the user can switch off in the app.

#### Steps

1. **Identify one-off and switchable uses.** From the feature inventory: which permissions serve a one-time flow (import, setup, verification), and which serve a feature the user can disable in the app's own settings (location sharing, contact sync, voice notes).
2. **Look for self-revocation and for exemption requests in code:**

   ```bash
   grep -rn -E 'revokeSelfPermissionOnKill|revokeSelfPermissionsOnKill' src/sources
   grep -rn -E 'getUnusedAppRestrictionsStatus|createManageUnusedAppRestrictionsIntent|isAutoRevokeWhitelisted|ACTION_APPLICATION_DETAILS_SETTINGS' src/sources
   ```

3. **Exercise a one-off flow, then leave it.** Grant the permission, complete the flow, use the app normally for a while, background it, and check whether the grant is still there and whether the app keeps using the resource:

   ```bash
   adb shell dumpsys package com.example.app | grep -A30 'runtime permissions:' | grep -E 'CONTACTS|LOCATION|CAMERA|RECORD_AUDIO'
   adb shell cmd appops get com.example.app | grep -E 'READ_CONTACTS|LOCATION|CAMERA|RECORD_AUDIO'
   ```

   The `appops` output shows the last access time per operation; access long after the one-off flow ended, or while you were in unrelated screens, is the evidence you need.
4. **Switch a feature off in the app** (for example "Share my location with friends") and repeat step 3. If the operation keeps being noted, the app still collects the data the user just declined.
5. **Check the hibernation behaviour.** If the app asks the user to disable "Pause app activity if unused" (or the older equivalents), note when and with what justification. Then simulate hibernation using the commands from the [app hibernation guide](https://developer.android.com/topic/performance/app-hibernation) and confirm that the app copes with the reset (re-requests in context, does not crash or silently fail):

   ```bash
   adb shell device_config put app_hibernation app_hibernation_enabled true      # Android 12+
   threshold=$(adb shell device_config get permissions auto_revoke_unused_threshold_millis2)
   adb shell device_config put permissions auto_revoke_unused_threshold_millis2 1000
   adb shell am wait-for-broadcast-idle
   adb shell cmd jobscheduler run -u 0 -f com.google.android.permissioncontroller 2
   adb shell cmd app_hibernation get-state com.example.app
   adb shell device_config put permissions auto_revoke_unused_threshold_millis2 $threshold
   ```

   On devices without Google's permission controller (AOSP images, some OEMs) the package is `com.android.permissioncontroller`.

#### Observation

For each one-off or switchable permission: whether it is still granted after the flow or after the feature was switched off, the app ops last-access times, any `revokeSelfPermissionsOnKill` call, and any request to exempt the app from hibernation with its wording.

#### Evaluation

The test **fails** if:

- the app keeps accessing a resource after the feature that needed it has finished or after the user switched the feature off in the app (this is the serious case: collection beyond the user's choice);
- a permission used only for a one-off flow stays granted on Android 13+ and the app (or an SDK) can still use it, with no `revokeSelfPermissionsOnKill` call;
- the app asks the user to disable the unused-app reset without a background feature that depends on it, or presents it as required to use the app.

It **passes** when one-off grants are given back (or the flow uses a mechanism that needs no lasting grant, see [MASTG-TEST-0255](#mastg-test-0255-permission-requests-not-minimized-android)), switching a feature off stops the access, and hibernation exemptions are requested only for background features with an explanation.

Lower the weight of the second bullet if the permission is idle (no app ops access after the flow): a granted but unused permission is latent exposure, not collection.

#### Demo

Our example of giving a one-off grant back after an import (API 33+):

```kotlin
fun onContactImportFinished() {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        // Asynchronous: the system kills the app's processes later, usually after time in the background
        applicationContext.revokeSelfPermissionsOnKill(
            listOf(Manifest.permission.READ_CONTACTS, Manifest.permission.WRITE_CONTACTS))
    }
    showMessage("Import complete. We've removed our access to your contacts.")
}
```

A failing observation (illustrative): `READ_CONTACTS` used once during onboarding, still noted three days later from an SDK's background job:

```text
$ adb shell cmd appops get com.example.app READ_CONTACTS
READ_CONTACTS: allow; time=+3d1h12m4s ago
```

```text
# frida backtrace from GT-PRIV-0066-3 for the same access
[ContentResolver.query] content://com.android.contacts/data/phones
    at com.example.sdk.attribution.ContactHasher.collect(Unknown Source)
    at com.example.sdk.attribution.SyncWorker.doWork(Unknown Source)
```

### MASTG-TEST-0360: Purpose String Accuracy for Reachable Protected Resource Access (iOS)

OWASP page: [MASTG-TEST-0360](https://mas.owasp.org/MASTG/tests/ios/MASVS-PRIVACY/MASTG-TEST-0360/). Type: static, config, manual.

#### Overview

Pairs every `NS…UsageDescription` key in the app and its extensions with the protected-resource APIs referenced in the binaries, and checks two things: that each reachable access has a real, user-visible feature behind it, and that the purpose string shown to the user explains that access accurately and specifically. OWASP explicitly leaves two cases out of scope: a purpose string with no matching API (not a privacy issue by itself) and an API with no purpose string (an App Store blocker that crashes the app). We agree on the first. On the second, OWASP's own evaluation then says the test "also fails" for reachable access without a matching purpose string, which contradicts its scope note; we record it as a finding only when the access is reachable in the shipped build (it usually means a crash, not a privacy leak).

#### Prerequisites

- A **decrypted** IPA (App Store binaries are FairPlay-encrypted; obtain a decrypted copy from the client or decrypt from a jailbroken device) or a development/Ad Hoc build from the client.
- macOS with `plutil`, `otool`, `nm`, `strings`, or radare2's `rabin2` on any OS.
- The feature inventory and the App Store listing.

#### Steps

1. **Unzip** the IPA ([MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/)) and list the app and its extensions:

   ```bash
   unzip -q App.ipa -d ipa && APP=$(ls -d ipa/Payload/*.app)
   ls -d "$APP"/PlugIns/*.appex "$APP"/Extensions/*.appex 2>/dev/null
   ```

2. **Read the purpose strings** ([MASTG-TECH-0153](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0153/), [MASTG-TECH-0138](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0138/), [MASTG-TECH-0154](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0154/)) from the app, each extension and the localisations users see:

   ```bash
   for p in "$APP/Info.plist" "$APP"/PlugIns/*.appex/Info.plist; do
     [ -f "$p" ] || continue
     echo "== $p"; plutil -p "$p" | grep -E 'UsageDescription|NSBonjourServices|NSLocationDefaultAccuracyReduced|NSLocationTemporaryUsageDescriptionDictionary'
     plutil -extract UIBackgroundModes json -o - "$p" 2>/dev/null
   done
   plutil -p "$APP/en.lproj/InfoPlist.strings" 2>/dev/null     # repeat for the client's languages
   ```

3. **Find the protected-resource APIs in the binaries** ([MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/)): the linked frameworks, the classes imported, and the request selectors. Do it for the main executable, each extension and each dynamic framework in `Frameworks/` (SDKs often live there):

   ```bash
   BIN="$APP/$(plutil -extract CFBundleExecutable raw "$APP/Info.plist")"
   otool -L "$BIN" | grep -E 'CoreLocation|Contacts|Photos|AVFoundation|AVFAudio|HealthKit|CoreBluetooth|EventKit|Speech|CoreMotion|HomeKit|MediaPlayer'
   nm -u "$BIN" | grep -E 'OBJC_CLASS_\$_(CLLocationManager|CNContactStore|PHPhotoLibrary|PHAsset|AVCaptureDevice|AVAudioApplication|CBCentralManager|CBPeripheralManager|HKHealthStore|EKEventStore|SFSpeechRecognizer|CMMotionActivityManager|CMPedometer)'
   strings -a "$BIN" | grep -x -E 'requestWhenInUseAuthorization|requestAlwaysAuthorization|startUpdatingLocation|startMonitoringSignificantLocationChanges|requestAccessForMediaType:completionHandler:|requestAccessForEntityType:completionHandler:|requestAuthorizationForAccessLevel:handler:|requestAuthorization:|requestFullAccessToEventsWithCompletion:|scanForPeripheralsWithServices:options:'
   # same with rabin2: rabin2 -zz "$BIN" | grep ...; rabin2 -i "$BIN" | grep OBJC_CLASS
   ```

4. **Find who calls them.** In a disassembler (radare2, Ghidra, Hopper), follow cross-references from each selector or class reference to the calling function and note its module and symbol (app code, or a class with an SDK prefix). That is what lets you distinguish "map screen requests location" from "analytics SDK requests location at start-up".
5. **Match each access to a feature and to its purpose string.** For each resource: the feature that uses it, whether it is reachable in normal use, and whether the text tells the user what that feature does with the data.

#### Observation

A table per binary: the resource, the declared key and its text (in each shipped language), the referenced APIs, the calling module, and the user-visible feature (or "none found").

#### Evaluation

The test **fails** when the evidence shows a reachable request or access to a protected resource and the purpose string does not accurately and specifically explain it: a vague string ("This app needs your location"), a string that describes a feature that does not exist, a string that omits a material use (location "to show nearby stores" when the binary also passes it to an advertising SDK), or access with no user-visible feature at all. It also fails, as an availability issue, when a reachable code path uses a resource with no purpose string. It **passes** when every reachable access maps to a feature and the purpose string explains that feature's use specifically.

Absence of an API reference is not proof of absence: dynamically resolved selectors (`NSSelectorFromString`), Swift code calling C APIs, obfuscated or downloaded code and server-side feature flags all hide references. Confirm important cases with [MASTG-TEST-0361](#mastg-test-0361-runtime-use-of-protected-resource-apis-without-accurate-purpose-strings-ios).

#### Demo

OWASP has no demo for the static test; this is our static pass over the app from [MASTG-DEMO-0126](https://mas.owasp.org/MASTG/demos/ios/MASVS-PRIVACY/MASTG-DEMO-0126/MASTG-DEMO-0126/), whose only feature is a three-second countdown. The purpose string output is from the demo; the binary lines are illustrative of what the commands return for its code:

```bash
plutil -p Info.plist | grep -i "UsageDescription"
```

```text
  "NSLocationWhenInUseUsageDescription" => "We use your location to show you nearby content and recommendations."
```

```text
$ nm -u MASTestApp | grep -E 'OBJC_CLASS_\$_CL'
                 _OBJC_CLASS_$_CLLocationManager
$ strings -a MASTestApp | grep -x -E 'requestWhenInUseAuthorization|startUpdatingLocation'
requestWhenInUseAuthorization
startUpdatingLocation
```

The location APIs are referenced and called from the countdown flow, the app has no nearby content or recommendations, and the purpose string describes a feature that does not exist: fail.

### MASTG-TEST-0361: Runtime Use of Protected Resource APIs Without Accurate Purpose Strings (iOS)

OWASP page: [MASTG-TEST-0361](https://mas.owasp.org/MASTG/tests/ios/MASVS-PRIVACY/MASTG-TEST-0361/). Type: dynamic, hooks, manual.

#### Overview

The runtime counterpart of MASTG-TEST-0360: hook the authorisation and access APIs, use the app, and record which ones fire, from which code, in response to which user action, and which prompt the user saw. This is the test that turns "the binary references `CLLocationManager`" into "an SDK starts location updates two seconds after launch, before any location feature is opened".

#### Prerequisites

- The app installed on a jailbroken device with frida-server ([MASTG-TECH-0056](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0056/), [MASTG-TOOL-0039](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/)), or a re-signed build with the Frida gadget on a stock device. For a no-instrumentation baseline, a stock device with **App Privacy Report** switched on.
- Authorisation reset before each run: delete and reinstall the app, or **Settings > General > Transfer or Reset iPhone > Reset > Reset Location & Privacy** on a dedicated test device.
- The purpose strings from MASTG-TEST-0360.

#### Steps

1. **Hook the resource APIs** ([MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/)). `frida-trace` is the quickest broad net:

   ```bash
   frida-trace -U -f com.example.app \
     -m '-[CLLocationManager request*]' -m '-[CLLocationManager start*]' \
     -m '+[AVCaptureDevice requestAccessForMediaType:completionHandler:]' \
     -m '-[CNContactStore requestAccessForEntityType:completionHandler:]' \
     -m '-[CNContactStore enumerateContactsWithFetchRequest:error:usingBlock:]' \
     -m '+[PHPhotoLibrary requestAuthorizationForAccessLevel:handler:]' \
     -m '+[PHAsset fetchAssetsWithOptions:]' \
     -m '-[CBCentralManager scanForPeripheralsWithServices:options:]' \
     -m '-[HKHealthStore requestAuthorizationToShareTypes:readTypes:completion:]' \
     -m '-[EKEventStore request*]'
   ```

   For backtraces, use a script like the demo's, extended to the resources the app's purpose strings declare:

   ```javascript
   // purpose-trace.js: frida -U -f com.example.app -l purpose-trace.js
   const targets = [
     ["CLLocationManager", "- requestWhenInUseAuthorization"],
     ["CLLocationManager", "- requestAlwaysAuthorization"],
     ["CLLocationManager", "- startUpdatingLocation"],
     ["CLLocationManager", "- requestLocation"],
     ["CLLocationManager", "- startMonitoringSignificantLocationChanges"],
     ["CNContactStore", "- requestAccessForEntityType:completionHandler:"],
     ["CNContactStore", "- enumerateContactsWithFetchRequest:error:usingBlock:"],
     ["PHPhotoLibrary", "+ requestAuthorizationForAccessLevel:handler:"],
     ["AVCaptureDevice", "+ requestAccessForMediaType:completionHandler:"]
   ];
   function backtrace(ctx) {
     return Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, 8)
       .map(DebugSymbol.fromAddress).join("\n    ");
   }
   targets.forEach(function (t) {
     const cls = ObjC.classes[t[0]];
     if (!cls || !cls[t[1]]) { console.log("[-] not loaded: " + t.join(" ")); return; }
     Interceptor.attach(cls[t[1]].implementation, {
       onEnter: function () {
         console.log("\n[+] " + t[0] + " " + t[1] + "\n    " + backtrace(this.context));
       }
     });
   });
   ```

2. **Use the app systematically.** Cold start and wait; go through onboarding; open every feature; leave the app in the background for a few minutes; return. For each hit, note the screen and action, and whether a system prompt appeared with which text.
3. **Check without instrumentation too.** On a stock device, switch on **App Privacy Report**, repeat the session, and export the report (it is JSON-lines `.ndjson` when saved from **Save App Privacy Report**). It shows each access with category and timestamps, which corroborates the Frida trace and catches what you did not hook.
4. **Attribute each call** using the backtrace: app module and symbol, or an SDK class.

#### Observation

For each observed call: the class and method, arguments (resource type, accuracy, requested types), return value or authorisation status, the backtrace, the user action that triggered it, and the prompt shown with its text.

#### Evaluation

The test **fails** when a runtime path requests or accesses a protected resource and the purpose string shown does not accurately and specifically explain that access, or when the access has no connection to the action or screen that triggered it (location requested on launch by an SDK, contacts enumerated in the background, photos fetched in bulk when the user picked one). It also fails if a runtime path accesses a resource without a matching purpose string. It **passes** when every observed access follows from a user action in a feature that the purpose string describes.

As OWASP stresses, flows you did not trigger (account states, regions, remote flags, extensions) are not covered; combine with [MASTG-TEST-0360](#mastg-test-0360-purpose-string-accuracy-for-reachable-protected-resource-access-ios).

#### Demo

From [MASTG-DEMO-0126](https://mas.owasp.org/MASTG/demos/ios/MASVS-PRIVACY/MASTG-DEMO-0126/MASTG-DEMO-0126/). The app's only feature is a countdown popup, but tapping **Start** requests location and collects it for the three seconds of the countdown:

```swift
final class LocationCapture: NSObject, CLLocationManagerDelegate {
    private let manager = CLLocationManager()
    override init() {
        super.init()
        manager.delegate = self
        manager.desiredAccuracy = kCLLocationAccuracyKilometer
        manager.requestWhenInUseAuthorization()   // FAIL: no location feature exists
    }
    func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        if manager.authorizationStatus == .authorizedWhenInUse { manager.startUpdatingLocation() }
    }
}
```

```xml
<key>NSLocationWhenInUseUsageDescription</key>
<string>We use your location to show you nearby content and recommendations.</string>
```

Frida output from the demo (trimmed):

```text
[+] CLLocationManager.requestWhenInUseAuthorization called
    Purpose string key: NSLocationWhenInUseUsageDescription
Backtrace:
0x1010cfef0 MASTestApp.debug.dylib!LocationCapture.init()
0x1010cc2a0 MASTestApp.debug.dylib!static MastgTest.mastgTest(completion:)
0x1010d26e0 MASTestApp.debug.dylib!closure #1 in closure #1 in closure #1 in ContentView.body.getter

[+] CLLocationManager.startUpdatingLocation called
Backtrace:
0x1010cffd4 MASTestApp.debug.dylib!LocationCapture.locationManagerDidChangeAuthorization(_:)
0x199549ccc CoreLocation!-[CLLocationManager onClientEventAuthStatus:]

[+] CLLocationManager.stopUpdatingLocation called
Backtrace:
0x1010cca18 MASTestApp.debug.dylib!LocationCapture.stop()
0x18f4a53a0 UIKitCore!-[UIPresentationController transitionDidFinish:]
```

The request is reached from the countdown flow, the user is shown a purpose string about nearby content that does not exist, and coordinates are collected and written to a file: fail. (OWASP's sample describes the collection as happening "in the background" and calls it GPS; it is foreground, kilometre-accuracy collection while the alert is on screen, hidden from the user rather than running in the background.)

### MASTG-TEST-0362: Entitlements for Unjustified Capability Exposure (iOS)

OWASP page: [MASTG-TEST-0362](https://mas.owasp.org/MASTG/tests/ios/MASVS-PRIVACY/MASTG-TEST-0362/). Type: static, package, manual.

#### Overview

Extracts the entitlements signed into the app and each extension and checks that each one is justified by a feature, prioritising those that open personal data (HealthKit, HomeKit, contacts notes), shared storage (App Groups, keychain groups), cloud sync (iCloud), network reach (multicast, Wi-Fi info) or system entry points (associated domains, Siri). An unused entitlement is latent capability, not active collection; OWASP frames it as least privilege, and so do we when rating.

#### Prerequisites

- The IPA, decrypted if you also want to search the binary.
- `codesign` (macOS), or `rabin2`, `ldid` or `ipsw` on any OS ([MASTG-TECH-0111](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0111/)).

#### Steps

1. **Extract entitlements** from every signed binary, not only the main app:

   ```bash
   for b in "$APP" "$APP"/PlugIns/*.appex "$APP"/Extensions/*.appex; do
     [ -e "$b" ] || continue
     echo "== $b"; codesign -d --entitlements :- "$b" 2>/dev/null
   done
   rabin2 -OC "$BIN"               # same from the Mach-O, works on Linux too
   ```

   If `embedded.mobileprovision` is present (development, Ad Hoc and enterprise builds), compare with what the profile allowed:

   ```bash
   security cms -D -i "$APP/embedded.mobileprovision" > profile.plist
   plutil -extract Entitlements xml1 -o - profile.plist
   ```

2. **Ignore the routine ones** (`application-identifier`, `com.apple.developer.team-identifier`, `keychain-access-groups` containing only the app's own group, `aps-environment` for push) and list the rest.
3. **Search for the APIs and identifiers each entitlement unlocks** ([MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/)):

   ```bash
   nm -u "$BIN" | grep -E 'OBJC_CLASS_\$_(HKHealthStore|HMHomeManager|CKContainer|NWConnectionGroup|NFCTagReaderSession|NFCNDEFReaderSession|INPreferences)'
   strings -a "$BIN" | grep -E '^group\.|containerURLForSecurityApplicationGroupIdentifier:|initWithSuiteName:|CNCopyCurrentNetworkInfo|fetchCurrentWithCompletionHandler:'
   ```

4. **Match each entitlement to a feature** and to the data it exposes: for an App Group, which targets are members and what is written to the shared container (see [MASWE-0031](/mobile/maswe-0031-allowing-untrusted-app-extensions/)).

#### Observation

Per binary: the entitlements, their values (group identifiers, container identifiers, domains), the related API references and the feature that justifies each.

#### Evaluation

The test **fails** when an entitlement has no reasonable connection to a user-visible feature, or creates a broader personal-data, shared-storage, cloud or network surface than the feature needs (for example, an App Group shared with an extension that never reads it, HealthKit with no health feature, Wi-Fi information in an app that only needs connectivity). When an entitlement has no matching API references and no plausible feature, report it; when the code may be hidden (dynamic loading, frameworks, feature flags), mark it for runtime confirmation with [MASTG-TEST-0363](#mastg-test-0363-runtime-use-of-entitlement-backed-apis-for-unjustified-capability-exposure-ios). It **passes** when each entitlement maps to a feature.

#### Demo

From [MASTG-DEMO-0127](https://mas.owasp.org/MASTG/demos/ios/MASVS-PRIVACY/MASTG-DEMO-0127/MASTG-DEMO-0127/) (OWASP attaches it to the runtime test; the extraction step is this static test). The countdown app is signed with HealthKit:

```bash
rabin2 -OC MASTestApp | sed -n '1,/<\/plist>/p' > entitlements_reversed.plist
```

```xml
<dict>
	<key>application-identifier</key>
	<string>org.owasp.mastestapp.MASTestApp-iOS</string>
	<key>com.apple.developer.healthkit</key>
	<true/>
</dict>
```

The Swift source does not import HealthKit, there is no `HKHealthStore` reference and no health feature: fail (unused, privacy-relevant entitlement).

### MASTG-TEST-0363: Runtime Use of Entitlement-Backed APIs for Unjustified Capability Exposure (iOS)

OWASP page: [MASTG-TEST-0363](https://mas.owasp.org/MASTG/tests/ios/MASVS-PRIVACY/MASTG-TEST-0363/). Type: dynamic, hooks, manual.

#### Overview

The runtime counterpart of MASTG-TEST-0362: hook the APIs, shared containers and entry points behind each entitlement and record which are used, by which code, and for which user action.

#### Prerequisites

- As for [MASTG-TEST-0361](#mastg-test-0361-runtime-use-of-protected-resource-apis-without-accurate-purpose-strings-ios): Frida on a jailbroken device or a gadget build.
- The entitlement list from MASTG-TEST-0362.

#### Steps

1. **Hook per entitlement.** For example:

   ```bash
   frida-trace -U -f com.example.app \
     -m '-[NSFileManager containerURLForSecurityApplicationGroupIdentifier:]' \
     -m '-[NSUserDefaults initWithSuiteName:]' \
     -m '-[HKHealthStore *]' -m '-[HMHomeManager *]' \
     -m '+[CKContainer containerWithIdentifier:]' -m '+[CKContainer defaultContainer]' \
     -i 'CNCopyCurrentNetworkInfo'
   ```

   Record arguments that identify the data: App Group identifiers, HealthKit types, container identifiers.
2. **Exercise the app**, including extensions (open the widget, share into the share extension, trigger notifications), since extensions often use the App Group.
3. **Inspect what lands in shared locations** (App Group container under `/private/var/mobile/Containers/Shared/AppGroup/<UUID>/` on a jailbroken device) to see what the entitlement actually exposes.

#### Observation

The entitlement-backed calls observed, with identifiers, backtraces and triggering actions, and the contents of any shared container.

#### Evaluation

The test **fails** when an entitlement-backed API or entry point is used without a connection to a user-visible feature, or creates a broader data-sharing or data-access surface than the feature needs (personal data written to an App Group that an extension does not need, HealthKit reads beyond the feature's types). Missing calls are absence of evidence, not proof: an entitlement that is present but never used at runtime is reported under MASTG-TEST-0362.

#### Demo

From [MASTG-DEMO-0127](https://mas.owasp.org/MASTG/demos/ios/MASVS-PRIVACY/MASTG-DEMO-0127/MASTG-DEMO-0127/). The demo script hooks `HKHealthStore` (`isHealthDataAvailable`, `requestAuthorizationToShareTypes:readTypes:completion:`, `authorizationStatusForType:`, `executeQuery:`, `saveObject:withCompletion:` and others); output after exercising the app:

```text
[*] Starting HealthKit entitlement-backed API tracing...

[-] Failed to hook HKHealthStore: class not found

[*] Hook setup finished. Interact with the app to trigger HealthKit API calls.
```

The HealthKit class is not even loaded. OWASP's demo concludes that the test fails because the entitlement is present and no HealthKit API is used. That conclusion is right for the app, but strictly it is the static finding of MASTG-TEST-0362 confirmed at runtime; by OWASP's own rule, an empty runtime trace alone would only be absence of evidence.

### MASTG-TEST-0390: Full Access Requested by a Custom Keyboard Extension (iOS)

OWASP page: [MASTG-TEST-0390](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0390/) (filed under MASVS-PLATFORM, mapped to MASWE-0066). Type: static, code, manual.

#### Overview

Applies when the app ships a custom keyboard extension. Checks whether the keyboard requests Full Access (`RequestsOpenAccess` = `true`) and, if so, whether it uses that access to send what the user types off the device or write it to a shared container without a feature that needs it. Full Access is the broadest grant an iOS app can ask a user for: the keyboard serves text input in other apps (except secure and phone-pad fields and apps that reject keyboards) and can read the text around the cursor. OWASP's prerequisites include "identify sensitive data": you need to know what the keyboard could see.

#### Prerequisites

- The (decrypted) IPA with the keyboard `.appex`.
- A test device to install the app, enable the keyboard and, if it is requested, Full Access.
- An interception proxy configured on the device ([traffic interception lab](/mobile/mobile-traffic-interception-lab/)); extensions use the device's proxy settings.

#### Steps

1. **Find the keyboard extension** ([MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/)) and read its `NSExtension` dictionary:

   ```bash
   for x in "$APP"/PlugIns/*.appex; do
     if plutil -extract NSExtension.NSExtensionPointIdentifier raw -o - "$x/Info.plist" 2>/dev/null | grep -q com.apple.keyboard-service; then
       KBX="$x"; echo "== keyboard: $KBX"
       plutil -extract NSExtension json -o - "$KBX/Info.plist"
     fi
   done
   ```

   Look for `"RequestsOpenAccess": true` under `NSExtensionAttributes`.
2. **Search the keyboard binary** ([MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/)) for the Full Access check, for networking, for shared storage, and for reads of the document context:

   ```bash
   KB="$KBX/$(plutil -extract CFBundleExecutable raw "$KBX/Info.plist")"
   strings -a "$KB" | grep -E '^(hasFullAccess|documentContextBeforeInput|documentContextAfterInput|selectedText|textDidChange:|containerURLForSecurityApplicationGroupIdentifier:|initWithSuiteName:)$'
   nm -u "$KB" | grep -E 'OBJC_CLASS_\$_(NSURLSession|NSURLRequest|NWConnection)|_nw_connection|_CFSocket'
   codesign -d --entitlements :- "$KBX" 2>/dev/null | grep -A3 application-groups
   ```

3. **Review the handlers** ([MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/)): in a disassembler, follow the `hasFullAccess` checks and the `textDidChange:` / key handlers to see whether typed text or document context reaches a network call or a shared-container write.
4. **Confirm dynamically with canaries.** Enable the keyboard and Full Access on the test device, type distinctive canary strings in a notes app and in a non-secure text field of a test app (for example `canary-0066-kb-7f3a`), use the keyboard's features, and search the captured traffic and the App Group container for the canary.

#### Observation

Whether `RequestsOpenAccess` is `true`; references to `hasFullAccess`, networking, shared-container and document-context APIs; the code paths that connect them; and any canary seen in traffic or shared storage.

#### Evaluation

The test **fails** if the keyboard requests Full Access and uses it to send typed text or document context off the device, or to write it to a shared container, without a user-facing feature that needs it and that the user opted into (for example, cloud predictions the user switched on). Apple's guideline 4.4.1 also requires the keyboard to stay functional without Full Access; a keyboard that refuses to work until Full Access is granted fails too. It **passes** if the keyboard does not request Full Access, or requests it for a clear, user-enabled feature, transmits only what that feature needs, and works without it.

#### Demo

OWASP has no demo for this test; ours is illustrative. Non-compliant: the keyboard forwards the text before the cursor whenever Full Access is on.

```swift
final class KeyboardViewController: UIInputViewController {
    override func textDidChange(_ textInput: UITextInput?) {
        guard hasFullAccess,
              let typed = textDocumentProxy.documentContextBeforeInput else { return }
        // FAIL: typed text leaves the device with no user-enabled feature behind it
        var req = URLRequest(url: URL(string: "https://api.example.com/v1/suggest")!)
        req.httpMethod = "POST"
        req.httpBody = Data(typed.utf8)
        URLSession.shared.dataTask(with: req).resume()
    }
}
```

```xml
<key>NSExtension</key>
<dict>
    <key>NSExtensionAttributes</key>
    <dict>
        <key>RequestsOpenAccess</key>
        <true/>
    </dict>
    <key>NSExtensionPointIdentifier</key>
    <string>com.apple.keyboard-service</string>
</dict>
```

Detection output (illustrative):

```text
== keyboard: Payload/App.app/PlugIns/AppKeyboard.appex
      "RequestsOpenAccess" : true
hasFullAccess
documentContextBeforeInput
textDidChange:
                 _OBJC_CLASS_$_NSURLSession
mitmproxy: POST https://api.example.com/v1/suggest  body: "meet at canary-0066-kb-7f3a"
```

### GT-PRIV-0066-1: Broader authorisation scope than the feature needs (iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

The iOS counterpart of [MASTG-TEST-0255](#mastg-test-0255-permission-requests-not-minimized-android). OWASP's iOS tests check that access is justified and explained, but not whether a narrower scope would do. Apple's guideline 5.1.1(iii) asks for exactly that ("use the out-of-process picker or a share sheet rather than requesting full access to protected resources like Photos or Contacts"), and iOS offers reduced scopes for most resources (see [Reduced-scope access on iOS](#reduced-scope-access-on-ios)).

#### Prerequisites

- The purpose string and API table from [MASTG-TEST-0360](#mastg-test-0360-purpose-string-accuracy-for-reachable-protected-resource-access-ios).
- A test device where you can reset authorisations, and the feature inventory.

#### Steps

1. **Look for broad-scope markers in the bundle and binary:**

   ```bash
   plutil -p "$APP/Info.plist" | grep -E 'NSLocationAlwaysAndWhenInUseUsageDescription|NSLocationDefaultAccuracyReduced|NSPhotoLibraryUsageDescription|NSPhotoLibraryAddUsageDescription|NSContactsUsageDescription|NSCalendarsFullAccessUsageDescription|NSCalendarsWriteOnlyAccessUsageDescription'
   plutil -extract UIBackgroundModes json -o - "$APP/Info.plist" 2>/dev/null
   nm -u "$BIN" | grep -E '_kCLLocationAccuracy(BestForNavigation|Best|NearestTenMeters|Kilometer|ThreeKilometers|Reduced)|OBJC_CLASS_\$_(PHPickerViewController|CNContactPickerViewController|CLLocationButton|ASAccessorySession|EKEventEditViewController)'
   strings -a "$BIN" | grep -x -E 'requestAlwaysAuthorization|startMonitoringSignificantLocationChanges|requestAuthorizationForAccessLevel:handler:|requestAccessForEntityType:completionHandler:|requestFullAccessToEventsWithCompletion:|requestWriteOnlyAccessToEventsWithCompletion:|presentLimitedLibraryPickerFromViewController:'
   ```

   SwiftUI pickers (`PhotosPicker`, `ContactAccessButton`) are Swift types; search for their mangled names or the strings `PhotosPicker` and `ContactAccessButton` in the binary.
2. **Compare with the feature.** For each resource, which scope is requested (always vs when in use, precise vs reduced, full vs limited vs picker, full vs write-only calendar) and which the feature needs.
3. **Grant the narrow scope and use the feature**: **Allow Once** or **While Using** instead of Always, **Precise** off, **Select Photos** or limited contacts, **Add Events Only**. Record whether the feature still works and how the app reacts: does it repeatedly push the user to widen access, or degrade gracefully?
4. **For background location**, check whether a background feature is visible to the user (tracking a run, geofenced reminders) and whether the blue location indicator or the periodic iOS reminder would surprise the user.

#### Observation

Per resource: the requested scope, the scope the feature needs, the narrower API available on the app's minimum iOS version, and the app's behaviour under the narrow grant.

#### Evaluation

The test **fails** when the app requests a broader scope than the feature needs and a narrower mechanism is available on its minimum iOS version: full photo library access to pick an avatar (instead of `PHPickerViewController`), full contacts access to choose one recipient (instead of `CNContactPickerViewController`, or limited access on iOS 18), Always location for a feature used only in the foreground, precise location for a regional feature, full calendar access to add an event. It also fails if the app nags, blocks or degrades unrelated features when the user grants the narrower scope. It **passes** when each scope matches the feature and the app works with reduced grants.

#### Demo

Our example. Broad and narrow ways to set a profile photo:

```swift
// Broad: full library read access, a permission prompt, and every photo readable by the app and its SDKs
PHPhotoLibrary.requestAuthorization(for: .readWrite) { status in
    guard status == .authorized else { return }
    let all = PHAsset.fetchAssets(with: .image, options: nil)   // FAIL for an avatar feature
    // ...
}

// Narrow: out-of-process picker, no permission, no purpose string, only the chosen image
var config = PHPickerConfiguration()
config.filter = .images
config.selectionLimit = 1
let picker = PHPickerViewController(configuration: config)
picker.delegate = self
present(picker, animated: true)
```

Reported result (illustrative):

```text
Photos     requested: readWrite (NSPhotoLibraryUsageDescription)   feature: avatar
           narrower: PHPickerViewController (iOS 14+, app minimum iOS 16)   -> FAIL
Location   requested: Always + UIBackgroundModes=location            feature: store finder (foreground)
           narrower: When In Use, reduced accuracy                          -> FAIL
```

### GT-PRIV-0066-2: Request timing, explanation and denial handling (iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

The iOS counterpart of [MASTG-TEST-0256](#mastg-test-0256-missing-permission-rationale-android) and, as far as iOS allows, of [MASTG-TEST-0257](#mastg-test-0257-not-resetting-unused-permissions-android). The purpose string is the system's explanation, but timing and behaviour after a denial are up to the app. iOS shows each system prompt only once; after a denial, only the user can change it in Settings. That puts pressure on apps to "prime" the user, which is acceptable when honest and a finding when manipulative. Apple's guidelines 5.1.1(iv) (no manipulating or forcing consent, offer alternatives) and 5.1.2(i) (no conditioning use of the app on enabling location, notifications or tracking) apply.

#### Prerequisites

- A test device (or Simulator, where `xcrun simctl privacy booted reset all <bundle-id>` resets authorisations) and a fresh install.
- Screen recording (Control Centre on the device, or QuickTime with the device connected to a Mac).

#### Steps

1. **First launch.** Install fresh and record the session. Note every system prompt before you have used any feature (location, notifications, tracking, contacts, Bluetooth, local network), and any custom pre-prompt.
2. **Timestamp the requests** with Frida if possible, to separate launch-time SDK requests from feature-driven ones:

   ```bash
   frida-trace -U -f com.example.app \
     -m '-[CLLocationManager request*]' -m '-[UNUserNotificationCenter requestAuthorizationWithOptions:completionHandler:]' \
     -m '+[ATTrackingManager requestTrackingAuthorizationWithCompletionHandler:]' \
     -m '-[CNContactStore requestAccessForEntityType:completionHandler:]' -m '-[CBCentralManager initWithDelegate:queue:options:]'
   ```

   Creating a `CBCentralManager` is what triggers the Bluetooth prompt, and the first local-network traffic triggers the local network prompt, so look for those too.
3. **Review pre-prompts.** A custom screen before the system prompt should explain the feature and offer a real "Not now" that does not lead straight to the system prompt. Check that it does not imitate the system alert's look.
4. **Deny each prompt** and keep using the app: features that do not need the resource must work; the feature that needs it should explain and, at most, offer a button that opens Settings (`UIApplication.openSettingsURLString`). Note any repeated nagging, blocking screens or reduced service.
5. **Check the purpose string at the moment of the request**: does the screen the user is on make the text make sense?
6. **Check whether access is used after the feature is switched off in the app** (iOS has no API for the app to give a grant back, so the app must stop using it): switch off the in-app feature (location sharing, contact sync), keep using the app, and check the Frida trace or **App Privacy Report** for continued access.

#### Observation

The prompt timeline, pre-prompt screenshots and texts, the behaviour after each denial, and any access after an in-app opt-out.

#### Evaluation

The test **fails** if the app requests protected-resource authorisation on launch or during onboarding for a feature the user has not reached, without an explanation, or bundles several prompts at start-up; if a pre-prompt misleads (looks like a system dialog, has no "Not now", or misstates the use); if denial blocks the app or unrelated features, triggers repeated nagging, or is "punished" (reduced service, withheld rewards); or if the app keeps accessing a resource after the user switched the feature off in the app. It **passes** when requests follow user actions, pre-prompts are honest and skippable, denial degrades only the feature concerned, and opting out stops access.

#### Demo

Our example of a clean pattern: check status first, ask in context, send to Settings only after an explicit denial.

```swift
func findNearbyStoresTapped() {
    switch locationManager.authorizationStatus {
    case .notDetermined:
        locationManager.requestWhenInUseAuthorization()   // purpose string explains store search
    case .authorizedWhenInUse, .authorizedAlways:
        locationManager.requestLocation()
    case .denied, .restricted:
        showPostcodeSearch(withHint: "Location is off for this app. You can turn it on in Settings.")
    @unknown default:
        showPostcodeSearch(withHint: nil)
    }
}
```

A failing first-run timeline (illustrative):

```text
00:01  frida: +[ATTrackingManager requestTrackingAuthorization...]   backtrace: AdsSDK.start
00:01  frida: -[CLLocationManager requestWhenInUseAuthorization]      backtrace: AnalyticsSDK.collectContext
00:02  prompt: "Allow App to use your location?"  text: "Your location improves your experience."
00:05  deny -> full-screen "Enable location to continue" with Settings button only
```

### GT-PRIV-0066-3: Runtime permission requests and protected API use (Android)

*Guler Tech methodology — not an OWASP test.*

#### Overview

The Android counterpart of [MASTG-TEST-0361](#mastg-test-0361-runtime-use-of-protected-resource-apis-without-accurate-purpose-strings-ios). Static analysis tells you what is declared and referenced; this test records what the app and its SDKs actually request and access while you use it, with stack traces that attribute each access to a package. It is also the evidence base for [MASTG-TEST-0257](#mastg-test-0257-not-resetting-unused-permissions-android) and [GT-PRIV-0066-5](#gt-priv-0066-5-permissions-added-by-libraries-and-sdks-android).

#### Prerequisites

- A rooted test device or emulator with frida-server, or a repackaged build with the Frida gadget.
- The permission inventory from MASTG-TEST-0254 and the feature and SDK inventories.

#### Steps

1. **Baseline with app ops** (no instrumentation): reset app ops history by reinstalling, use the app, and read the last-access times and the Privacy Dashboard:

   ```bash
   adb shell cmd appops get com.example.app
   adb shell dumpsys appops --package com.example.app | grep -E -A3 'COARSE_LOCATION|FINE_LOCATION|CAMERA|RECORD_AUDIO|READ_CONTACTS|READ_CALL_LOG|READ_SMS|READ_MEDIA'
   ```

2. **Trace requests and protected API calls** with a script that prints the Java stack for each call:

   ```javascript
   // perm-trace.js: frida -U -f com.example.app -l perm-trace.js
   Java.perform(function () {
     const Log = Java.use("android.util.Log");
     const Exc = Java.use("java.lang.Exception");
     function where() {
       return Log.getStackTraceString(Exc.$new()).split("\n").slice(2, 10).join("\n");
     }
     function hookAll(className, method, filter) {
       const C = Java.use(className);
       C[method].overloads.forEach(function (o) {
         o.implementation = function () {
           const args = Array.prototype.slice.call(arguments);
           if (!filter || filter(args)) {
             console.log("\n[" + className.split(".").pop() + "." + method + "] " + args.slice(0, 2).join(" | ") + "\n" + where());
           }
           return o.apply(this, arguments);
         };
       });
     }
     hookAll("android.app.Activity", "requestPermissions");
     hookAll("android.location.LocationManager", "getLastKnownLocation");
     hookAll("android.location.LocationManager", "requestLocationUpdates");
     hookAll("android.location.LocationManager", "getCurrentLocation");
     hookAll("android.media.AudioRecord", "startRecording");
     hookAll("android.hardware.camera2.CameraManager", "openCamera");
     hookAll("android.content.ContentResolver", "query", function (a) {
       return /contacts|call_log|sms|media/.test(String(a[0]));
     });
   });
   ```

   `Activity.requestPermissions` receives a `String[]`; print it element by element if your Frida version does not render it. Add hooks for Google Play services location (`com.google.android.gms.location.FusedLocationProviderClient` implementations) and for `WifiManager.getScanResults`, `BluetoothLeScanner.startScan` and `TelephonyManager` getters when the app declares those permissions.
3. **Use the app in phases**: cold start without touching anything; each feature; background for several minutes; return. Note the phase of each hit.
4. **Attribute each hit** from the stack: the first non-framework frame tells you whether app code or which SDK package made the call. Obfuscated names still keep package structure often enough; map them with the SDK inventory.
5. **Repeat with the permission granted for one feature only** (for example, location granted for the map) and watch for other packages using it outside that feature.

#### Observation

Per hit: the API, its arguments, the stack (calling package), the phase and user action, and the matching app ops entry.

#### Evaluation

The test **fails** when a protected resource is requested or accessed without a connection to a user action or visible feature (location at cold start by an SDK, contacts read in a background job, the microphone opened on a screen without a voice feature), or when an SDK uses a permission the app holds for its own feature to collect data for the SDK's purposes. It **passes** when every request and access follows from a user action in a feature that needs it.

#### Demo

Illustrative output for an app whose only location feature is a store finder:

```text
[Activity.requestPermissions] [Ljava.lang.String;@5f2c1a3 | 1001
    at com.example.app.onboarding.WelcomeActivity.onStart(WelcomeActivity.kt:41)
    -> printed: android.permission.ACCESS_FINE_LOCATION, android.permission.ACCESS_COARSE_LOCATION

[LocationManager.getLastKnownLocation] network
    at com.example.sdk.analytics.DeviceContext.location(Unknown Source)
    at com.example.sdk.analytics.EventQueue.flush(Unknown Source)
```

The request comes from the welcome screen, not the store finder, and the analytics SDK reads location on every event flush: fail on both counts.

### GT-PRIV-0066-4: Special app access and restricted permissions (Android)

*Guler Tech methodology — not an OWASP test.*

#### Overview

The Android counterpart of [MASTG-TEST-0362](#mastg-test-0362-entitlements-for-unjustified-capability-exposure-ios) and [MASTG-TEST-0363](#mastg-test-0363-runtime-use-of-entitlement-backed-apis-for-unjustified-capability-exposure-ios). Special permissions and privileged service bindings are not `dangerous`, so MASTG-TEST-0254 misses them, yet several give more access than any runtime permission. Google Play treats most of them as restricted, with declaration forms.

| Capability | How it appears | What it exposes |
|---|---|---|
| `QUERY_ALL_PACKAGES` (normal, granted silently) | `<uses-permission>`; or broad `<queries>` intent filters | The full list of installed apps (health, religion, finance, dating apps reveal a lot) |
| `MANAGE_EXTERNAL_STORAGE` (special) | `<uses-permission>`; `Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION` | All files on shared storage |
| `PACKAGE_USAGE_STATS` (special) | `<uses-permission>`; `Settings.ACTION_USAGE_ACCESS_SETTINGS` | Which apps the user uses and when |
| `SYSTEM_ALERT_WINDOW` (special) | `<uses-permission>`; `Settings.ACTION_MANAGE_OVERLAY_PERMISSION` | Drawing over other apps (phishing overlays) |
| Accessibility service | `<service android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE">` | Screen content and input in every app ([MASWE-0040](/mobile/maswe-0040-sensitive-data-leaked-via-accessibility/)) |
| Notification listener | `<service android:permission="android.permission.BIND_NOTIFICATION_LISTENER_SERVICE">` | Content of every notification, including OTPs and messages |
| Device admin, VPN service | `BIND_DEVICE_ADMIN`, `BIND_VPN_SERVICE` | Device policy; all network traffic |
| SMS and call log groups (hard restricted) | `<uses-permission>` | Messages, OTPs, call history |
| `REQUEST_INSTALL_PACKAGES` | `<uses-permission>` | Installing other APKs |

#### Prerequisites

- The decoded manifest and decompiled code; a test device.

#### Steps

1. **List special permissions and privileged service bindings:**

   ```bash
   M=out/resources/AndroidManifest.xml
   grep -n -E 'QUERY_ALL_PACKAGES|MANAGE_EXTERNAL_STORAGE|PACKAGE_USAGE_STATS|SYSTEM_ALERT_WINDOW|REQUEST_INSTALL_PACKAGES|WRITE_SETTINGS|SCHEDULE_EXACT_ALARM|ACCESS_NOTIFICATION_POLICY|REQUEST_IGNORE_BATTERY_OPTIMIZATIONS|_SMS"|CALL_LOG"' $M
   grep -n -E 'BIND_(ACCESSIBILITY_SERVICE|NOTIFICATION_LISTENER_SERVICE|DEVICE_ADMIN|VPN_SERVICE|INPUT_METHOD)' $M
   grep -n -A12 '<queries>' $M
   ```

2. **Find how the app sends the user to grant them** and what it does with them:

   ```bash
   grep -rn -E 'ACTION_MANAGE_(OVERLAY_PERMISSION|APP_ALL_FILES_ACCESS_PERMISSION)|ACTION_USAGE_ACCESS_SETTINGS|ACTION_ACCESSIBILITY_SETTINGS|ACTION_NOTIFICATION_LISTENER_SETTINGS|getInstalledPackages|getInstalledApplications|queryIntentActivities|UsageStatsManager' src/sources | grep -v -E '/(androidx|kotlin)/'
   ```

3. **Check the grant state** on the device:

   ```bash
   adb shell cmd appops get com.example.app | grep -E 'SYSTEM_ALERT_WINDOW|MANAGE_EXTERNAL_STORAGE|GET_USAGE_STATS|QUERY_ALL_PACKAGES'
   adb shell settings get secure enabled_accessibility_services
   adb shell settings get secure enabled_notification_listeners
   ```

4. **Look for the data leaving the device.** For `QUERY_ALL_PACKAGES` and usage stats in particular, capture traffic and search for package names of apps you installed as canaries (for example a small test app named `org.example.canary0066`).

#### Observation

The special capabilities declared or bound, the code that requests and uses them, their grant state, and any related data in traffic.

#### Evaluation

The test **fails** for any special permission or privileged binding that no user-visible core feature needs, for `QUERY_ALL_PACKAGES` where targeted `<queries>` would do, for an installed-app list or usage data sent to a server without a feature that requires it, and for SMS or call log permissions in an app that is not the default SMS, phone or assistant handler. It **passes** when each special capability maps to a core feature and is requested through the system settings flow with an explanation.

#### Demo

Illustrative manifest and finding: a shopping app checking for one payment app.

```xml
<!-- FAIL: broad visibility to check one package -->
<uses-permission android:name="android.permission.QUERY_ALL_PACKAGES" />

<!-- PASS: targeted visibility -->
<queries>
    <package android:name="com.example.paymentapp" />
</queries>
```

```text
$ grep -rn getInstalledApplications src/sources | grep -v androidx
src/sources/com/example/sdk/attribution/InstallScan.java:58:  pm.getInstalledApplications(0)
mitmproxy: POST https://collect.example.org/v2/apps   body contains "org.example.canary0066"
```

### GT-PRIV-0066-5: Permissions added by libraries and SDKs (Android)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Finds which permissions in the final manifest were contributed by libraries rather than the app team, and whether SDKs use the app's permissions for their own collection. It fills a gap OWASP names in the weakness ("third-party permission requirements") but has no test for.

#### Prerequisites

- Ideally the project source and Gradle build (ask the client); otherwise the APK and decompiled code.
- The SDK inventory and each SDK's documentation on the permissions it uses or adds.

#### Steps

1. **With source: read the merger report.** Build the release variant and open `app/build/outputs/logs/manifest-merger-release-report.txt`, or Android Studio's **Merged Manifest** tab:

   ```bash
   ./gradlew :app:processReleaseMainManifest
   grep -A2 -E '^uses-permission#' app/build/outputs/logs/manifest-merger-release-report.txt
   ```

   Every `ADDED from [group:artifact:version]` line under a `uses-permission#` entry names the library that contributed it. Also check for existing `tools:node="remove"` lines in the app manifest and whether they took effect.
2. **Without source: infer provenance.** Compare the merged permission list with what the app's own code uses (MASTG-TEST-0254 step 4). A permission referenced only from SDK packages, and documented by that SDK, is SDK-introduced. Library manifests in cached AARs (`~/.gradle/caches/.../<sdk>.aar` → `AndroidManifest.xml`) confirm it if you can fetch the same SDK version.
3. **Check SDK configuration** for location, contacts or device-data collection switches (often `collectLocation`, `trackLocation` or manifest `<meta-data>` flags) and what the app sets.
4. **Check runtime use** with [GT-PRIV-0066-3](#gt-priv-0066-3-runtime-permission-requests-and-protected-api-use-android): does the SDK access the resource when the app holds the permission for its own feature?

#### Observation

Each permission with its contributing module, whether the app's own features need it, the SDK's configuration, and runtime access by SDK packages.

#### Evaluation

The test **fails** for any permission contributed by a library that no app feature needs and that the app did not remove, and for any SDK that uses a permission granted for an app feature to collect data for the SDK's own purposes without that being part of the feature, disclosed and, where required, consented to. It **passes** when SDK-contributed permissions are either needed by a feature or removed, and SDK collection through app permissions is switched off or limited to the feature.

#### Demo

Illustrative merger report excerpt and fix:

```text
uses-permission#android.permission.ACCESS_FINE_LOCATION
ADDED from [com.example.sdk:ads-core:5.2.0] /home/build/.gradle/caches/.../AndroidManifest.xml:9:5-79
uses-permission#android.permission.READ_PHONE_STATE
ADDED from [com.example.sdk:attribution:3.1.4] /home/build/.gradle/caches/.../AndroidManifest.xml:11:5-75
```

```xml
<!-- app/src/main/AndroidManifest.xml -->
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" tools:node="remove" />
<uses-permission android:name="android.permission.READ_PHONE_STATE" tools:node="remove" />
```

After the change, rerun MASTG-TEST-0254 on the built APK to confirm the permissions are gone, and GT-PRIV-0066-3 to confirm the SDKs still work and no longer read the data.

### GT-PRIV-0066-6: Bundled input method that collects typed text (Android)

*Guler Tech methodology — not an OWASP test.*

#### Overview

The Android counterpart of [MASTG-TEST-0390](#mastg-test-0390-full-access-requested-by-a-custom-keyboard-extension-ios). An app can ship an input method (IME) as a service bound with `BIND_INPUT_METHOD`. Once the user enables it in the keyboard settings (**Settings > System > Keyboard** on recent Pixel builds; the path varies), Android warns that the input method "may be able to collect all the text you type, including personal data like passwords and credit card numbers", and from then on the IME receives text input in every app. Unlike iOS, there is no separate Full Access switch: the IME runs with the containing app's permissions, so if the app has `INTERNET`, the keyboard can send what it sees.

#### Prerequisites

- The decoded manifest and decompiled code; a test device with an interception proxy.

#### Steps

1. **Find the IME:**

   ```bash
   grep -n -B2 -A10 'android.permission.BIND_INPUT_METHOD' out/resources/AndroidManifest.xml   # service, android.view.InputMethod filter, android.view.im metadata
   ```

2. **Review what it reads and where it goes**: `InputMethodService` subclasses, `getCurrentInputConnection().getTextBeforeCursor(...)`, `onUpdateSelection`, and whether it checks `EditorInfo.inputType` for password variations and `EditorInfo.imeOptions` for `IME_FLAG_NO_PERSONALIZED_LEARNING` before storing or sending anything:

   ```bash
   grep -rn -E 'extends InputMethodService|getTextBeforeCursor|getTextAfterCursor|TYPE_TEXT_VARIATION_(WEB_)?PASSWORD|TYPE_NUMBER_VARIATION_PASSWORD|IME_FLAG_NO_PERSONALIZED_LEARNING' src/sources
   ```

3. **Canary test**: enable the IME, type canary strings in normal, password and "incognito" (no personalised learning) fields of a test app, and search captured traffic and the app's storage (`adb shell run-as` on a debug build, or root) for them.

#### Observation

The IME declaration, the code paths from text access to storage or network, the handling of password and no-learning fields, and any canary found.

#### Evaluation

The test **fails** if the IME sends typed text or text around the cursor off the device without a user-enabled feature that needs it, or stores or sends text from password fields or fields that set `IME_FLAG_NO_PERSONALIZED_LEARNING`. It **passes** if typed text stays on the device, or leaves only for an opted-in feature with password and no-learning fields excluded.

#### Demo

Illustrative compliant check in an IME:

```kotlin
override fun onStartInput(info: EditorInfo, restarting: Boolean) {
    val variation = info.inputType and InputType.TYPE_MASK_VARIATION
    val isPassword = variation == InputType.TYPE_TEXT_VARIATION_PASSWORD ||
        variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD ||
        variation == InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD ||
        variation == InputType.TYPE_NUMBER_VARIATION_PASSWORD
    val noLearning = info.imeOptions and EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING != 0
    learningEnabled = !isPassword && !noLearning && userEnabledCloudSuggestions
}
```

## Best practices

### MASTG-BEST-0051: Minimize iOS Permissions and Entitlements

OWASP page: [MASTG-BEST-0051](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0051/).

- **Review purpose strings, signed entitlements and provisioning-profile entitlements together before each release.** Every prompt and capability should map to a feature a user would recognise; remove "just in case" entries.
- **Prefer the narrowest access path**: `PHPickerViewController` or `PhotosPicker` over library access; `CNContactPickerViewController` or limited contacts over full contacts; when-in-use and reduced accuracy before Always and precise; write-only calendar; AccessorySetupKit for accessory pairing.
- **Treat data-sharing entitlements as design decisions**: App Groups, iCloud containers and associated domains create paths for data to flow to extensions, devices and websites. Document the data flow, limit membership to the targets that need it, and protect what is shared ([MASWE-0031](/mobile/maswe-0031-allowing-untrusted-app-extensions/)).
- **Privacy manifests complement, not replace, these checks.** `PrivacyInfo.xcprivacy` and required-reason API declarations do not authorise anything; you still minimise purpose strings and entitlements ([MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/), [MASWE-0074](/mobile/maswe-0074-inadequate-tracking-domains-declarations/)).

We add one practice: put the reviewed lists under version control and fail CI when a build adds a key or entitlement that is not on them.

```bash
APP=$(find build/export -name '*.app' -maxdepth 3 | head -1)
plutil -p "$APP/Info.plist" | grep -o '"NS[A-Za-z]*UsageDescription"' | sort > keys.txt
codesign -d --entitlements :- "$APP" 2>/dev/null | grep -o '<key>[^<]*</key>' | sort > ents.txt
diff -u privacy/usage-keys.allow keys.txt && diff -u privacy/entitlements.allow ents.txt
```

### MASTG-BEST-0069: Keep Sensitive Input on the System Keyboard

OWASP page: [MASTG-BEST-0069](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0069/). Full treatment with code: [MASWE-0031](/mobile/maswe-0031-allowing-untrusted-app-extensions/).

This best practice protects an app's own fields from third-party keyboards: mark secrets with `isSecureTextEntry` (or `SecureField`), and reject keyboard extensions app-wide with `application(_:shouldAllowExtensionPointIdentifier:)` only where no field should ever use one. OWASP links it to MASTG-TEST-0390 because both sides of the keyboard trust boundary meet there. For an app that *ships* a keyboard, the practice that matters for this weakness is the one in the MASWE mitigation: do not set `RequestsOpenAccess` unless a user-enabled feature needs it, keep the keyboard fully functional without it (guideline 4.4.1), and never transmit or store typed text, least of all from fields with `.oneTimeCode`, `.password` or payment content types.

### Android: request less, explain, give it back (Guler Tech)

OWASP has no Android best practice for this weakness; ours:

- **Keep a permission allowlist** and check the built APK against it in CI, so SDK updates cannot add permissions silently:

  ```bash
  aapt2 dump permissions app-release.apk | sed -n "s/^uses-permission: name='\([^']*\)'.*/\1/p" | sort > actual.txt
  diff -u privacy/permissions.allow actual.txt || { echo "permission set changed" >&2; exit 1; }
  ```

- **Remove what libraries add and you do not need** with `tools:node="remove"`, and turn off SDK features that collect location, contacts or device data.
- **Use intents and pickers first**: `TakePicture`, `PickVisualMedia`, `ACTION_OPEN_DOCUMENT`, `ACTION_PICK`, the contact picker on Android 17, `RecognizerIntent`, SMS Retriever, companion device pairing, targeted `<queries>`.
- **Ask for the least location**: coarse only unless precise is needed; request `ACCESS_COARSE_LOCATION` with `ACCESS_FINE_LOCATION` so the user can choose; foreground service started by the user instead of background location; consider the location button for one-off precise use.
- **Assert what you do not derive**: `usesPermissionFlags="neverForLocation"` on `BLUETOOTH_SCAN` and `NEARBY_WIFI_DEVICES` when you do not derive location; `maxSdkVersion` on legacy permissions (`READ_EXTERNAL_STORAGE` with `maxSdkVersion="32"`, legacy Bluetooth with `maxSdkVersion="30"`).
- **Ask in context and explain**: request when the user starts the feature, handle `shouldShowRequestPermissionRationale()`, degrade gracefully on denial; for location, camera and microphone apps, provide the `VIEW_PERMISSION_USAGE` rationale activity.
- **Give it back**: call `revokeSelfPermissionsOnKill()` after one-off flows and when the user switches a feature off; request a hibernation exemption only for genuine background features, with an explanation.
- **Audit yourself**: use attribution tags and `AppOpsManager.OnOpNotedCallback` in debug and QA builds to log which feature or SDK touches protected data.

## Rating findings

Privacy findings are rated by what personal data is exposed or processed beyond what is necessary, declared or consented; how sensitive it is; the scale and reversibility; and whether it contradicts the app's own declarations or store policy. For this weakness, the key distinction is between **latent** access (a permission or entitlement the app holds or could request but does not use) and **exercised** access (data actually read, and especially data that leaves the device).

| Rating | Conditions |
|---|---|
| **High** | Sensitive data (precise or background location, contacts, SMS or call log, photo library, microphone or camera, health, installed-app inventory) accessed without a user-visible feature or beyond the user's choice, and sent to the app's back end or a third party (typically an SDK) without disclosure; a deceptive purpose string or rationale covering real collection; a bundled keyboard or IME with Full Access or network that transmits typed text; collection continuing after the user switched the feature off. Raise further for children's apps or special-category data. |
| **Medium** | Sensitive access that is exercised but broader than the feature needs, with data staying within the app's own processing (full photo library for an avatar, fine location for a city-level feature, full contacts to invite one person, Always location for a foreground feature); launch-time prompt bursts or manipulative pre-prompts that obtain grants; SDK-added sensitive permissions that are granted and used by the SDK, but disclosed; restricted permissions held without the Play declaration or against App Review guidance (store removal or rejection risk); special access (`QUERY_ALL_PACKAGES`, usage stats, notification listener) without a core need. |
| **Low** | Dangerous permissions, purpose strings or privacy-relevant entitlements declared but not requested or used at runtime (latent exposure, often an SDK or a removed feature); vague but not misleading purpose strings for justified access; missing in-app rationale for permissions whose purpose is obvious from the screen; one-off grants not given back but not used afterwards; hibernation exemption requested with a weak justification. |
| **Info** | `normal` permissions with no privacy effect; legacy permissions limited by `maxSdkVersion` to versions the app does not support; missing `VIEW_PERMISSION_USAGE` activity; a purpose string with no API use; good practice observed (pickers, reduced accuracy, self-revocation). |

Raise a level when the data is special-category (health, sexual orientation, religion from location patterns), concerns children, or is collected at scale, or when the finding contradicts the app's Data safety section, App Privacy label, privacy manifest or privacy policy (see [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/)). Lower a level when the access is reachable only in a build or region the client does not ship.

Severity here describes technical privacy impact. Whether a finding is also a breach of the GDPR, the UK GDPR, PECR or the CCPA/CPRA, or of a store policy, is for the client's DPO and legal team to assess; give them the evidence, not a legal conclusion.

In the report give: each permission, purpose string or entitlement with its feature (or "none found"); the code location and calling package; the runtime evidence (app ops times, Frida backtraces, App Privacy Report entries, captured requests); what the user was shown (prompt, purpose string, rationale) and when; the narrower alternative; and, for store-policy issues, the policy section concerned.

## References

- OWASP MASWE: [MASWE-0066: Inadequate Permission Management](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0066/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-PRIVACY-1](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-1/) (CC BY-SA 4.0)
- OWASP MASTG knowledge: [MASTG-KNOW-0017](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0017/), [MASTG-KNOW-0077](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0077/), [MASTG-KNOW-0082](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0082/), [MASTG-KNOW-0141](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0141/) (CC BY-SA 4.0)
- OWASP MASTG tests: [MASTG-TEST-0254](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0254/), [MASTG-TEST-0255](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0255/), [MASTG-TEST-0256](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0256/), [MASTG-TEST-0257](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0257/), [MASTG-TEST-0360](https://mas.owasp.org/MASTG/tests/ios/MASVS-PRIVACY/MASTG-TEST-0360/), [MASTG-TEST-0361](https://mas.owasp.org/MASTG/tests/ios/MASVS-PRIVACY/MASTG-TEST-0361/), [MASTG-TEST-0362](https://mas.owasp.org/MASTG/tests/ios/MASVS-PRIVACY/MASTG-TEST-0362/), [MASTG-TEST-0363](https://mas.owasp.org/MASTG/tests/ios/MASVS-PRIVACY/MASTG-TEST-0363/), [MASTG-TEST-0390](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0390/) (CC BY-SA 4.0)
- OWASP MASTG demos: [MASTG-DEMO-0033](https://mas.owasp.org/MASTG/demos/android/MASVS-PRIVACY/MASTG-DEMO-0033/MASTG-DEMO-0033/), [MASTG-DEMO-0126](https://mas.owasp.org/MASTG/demos/ios/MASVS-PRIVACY/MASTG-DEMO-0126/MASTG-DEMO-0126/), [MASTG-DEMO-0127](https://mas.owasp.org/MASTG/demos/ios/MASVS-PRIVACY/MASTG-DEMO-0127/MASTG-DEMO-0127/) (CC BY-SA 4.0)
- OWASP MASTG best practices: [MASTG-BEST-0051](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0051/), [MASTG-BEST-0069](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0069/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0117](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/), [MASTG-TECH-0126](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0126/), [MASTG-TECH-0056](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0056/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/), [MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/), [MASTG-TECH-0111](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0111/), [MASTG-TECH-0138](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0138/), [MASTG-TECH-0153](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0153/), [MASTG-TECH-0154](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0154/) (CC BY-SA 4.0)
- OWASP MASTG tools: [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/), [rabin2 (MASTG-TOOL-0129)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/), [Frida for iOS (MASTG-TOOL-0039)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/), [aapt2 (MASTG-TOOL-0124)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0124/), [codesign (MASTG-TOOL-0114)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0114/), [plutil (MASTG-TOOL-0062)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0062/) (CC BY-SA 4.0)
- Sibling notes: [PRIVACY hub](/mobile/masvs-privacy-privacy-testing-guide/), [MASWE-0068](/mobile/maswe-0068-incorrect-use-of-identifiers-for-tracking/), [MASWE-0070](/mobile/maswe-0070-inadequate-awareness-for-privacy-actions/), [MASWE-0073](/mobile/maswe-0073-inadequate-data-collection-declarations/), [MASWE-0074](/mobile/maswe-0074-inadequate-tracking-domains-declarations/), [MASWE-0078](/mobile/maswe-0078-inadequate-user-consent-mechanisms/); [MASWE-0018](/mobile/maswe-0018-missing-auth-on-app-components/), [MASWE-0031](/mobile/maswe-0031-allowing-untrusted-app-extensions/), [MASWE-0040](/mobile/maswe-0040-sensitive-data-leaked-via-accessibility/), [MASWE-0042](/mobile/maswe-0042-latest-platform-version-not-targeted/), [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/), [MASWE-0048](/mobile/maswe-0048-malicious-code-included-in-the-app/), [MASTG-KNOW-0004 third-party libraries](/mobile/mastg-know-0004-third-party-libraries/), [traffic interception lab](/mobile/mobile-traffic-interception-lab/)
- Android: [Permissions on Android](https://developer.android.com/guide/topics/permissions/overview), [Request runtime permissions](https://developer.android.com/training/permissions/requesting), [Request special permissions](https://developer.android.com/training/permissions/requesting-special), [Explain access to more sensitive information](https://developer.android.com/training/permissions/explaining-access), [App permissions best practices](https://developer.android.com/training/permissions/usage-notes), [Minimize your permission requests](https://developer.android.com/privacy-and-security/minimize-permission-requests), [App hibernation](https://developer.android.com/topic/performance/app-hibernation), [Request location permissions](https://developer.android.com/training/location/permissions), [Location button](https://developer.android.com/guide/topics/permissions/private-alternatives/location-button), [Bluetooth permissions](https://developer.android.com/develop/connectivity/bluetooth/bt-permissions), [Notification runtime permission](https://developer.android.com/develop/ui/views/notifications/notification-permission), [Partial photo and video access](https://developer.android.com/about/versions/14/changes/partial-photo-video-access), [Photo picker](https://developer.android.com/training/data-storage/shared/photo-picker), [Contact picker](https://developer.android.com/about/versions/17/features/contact-picker), [Android 17 behaviour changes](https://developer.android.com/about/versions/17/behavior-changes-17), [Manage manifest files](https://developer.android.com/build/manage-manifests), [Audit data access](https://developer.android.com/guide/topics/data/audit-access), [Package visibility](https://developer.android.com/training/package-visibility), [`PackageManager`](https://developer.android.com/reference/android/content/pm/PackageManager), [`Manifest.permission`](https://developer.android.com/reference/android/Manifest.permission), [Excessive agency (AI risks)](https://developer.android.com/privacy-and-security/risks/ai-risks/excessive-agency), [AOSP core manifest](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/res/AndroidManifest.xml)
- Google Play: [Permissions and APIs that Access Sensitive Information](https://support.google.com/googleplay/android-developer/answer/9888170), [Restricted permissions with minimum scope alternatives](https://support.google.com/googleplay/android-developer/answer/14115180), [SMS or Call Log permission groups](https://support.google.com/googleplay/android-developer/answer/9047303), [QUERY_ALL_PACKAGES](https://support.google.com/googleplay/android-developer/answer/10158779)
- Apple: [Requesting access to protected resources](https://developer.apple.com/documentation/uikit/requesting-access-to-protected-resources), [Protected resources](https://developer.apple.com/documentation/bundleresources/protected-resources), [Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements), [Adding capabilities to your app](https://developer.apple.com/documentation/xcode/adding-capabilities-to-your-app), [HIG: Privacy](https://developer.apple.com/design/human-interface-guidelines/privacy), [Write clear purpose strings](https://developer.apple.com/videos/play/tech-talks/110152/), [`PHPickerViewController`](https://developer.apple.com/documentation/photosui/phpickerviewcontroller), [`PHAuthorizationStatus.limited`](https://developer.apple.com/documentation/photos/phauthorizationstatus/limited), [`CNAuthorizationStatus.limited`](https://developer.apple.com/documentation/contacts/cnauthorizationstatus/limited), [`ContactAccessButton`](https://developer.apple.com/documentation/contactsui/contactaccessbutton), [`NSLocationDefaultAccuracyReduced`](https://developer.apple.com/documentation/bundleresources/information-property-list/nslocationdefaultaccuracyreduced), [`requestTemporaryFullAccuracyAuthorization(withPurposeKey:completion:)`](https://developer.apple.com/documentation/corelocation/cllocationmanager/requesttemporaryfullaccuracyauthorization%28withpurposekey:completion:%29), [`NSLocalNetworkUsageDescription`](https://developer.apple.com/documentation/bundleresources/information-property-list/nslocalnetworkusagedescription), [AccessorySetupKit](https://developer.apple.com/documentation/accessorysetupkit), [Configuring open access for a custom keyboard](https://developer.apple.com/documentation/uikit/configuring-open-access-for-a-custom-keyboard), [`RequestsOpenAccess`](https://developer.apple.com/documentation/bundleresources/information-property-list/nsextension/nsextensionattributes/requestsopenaccess), [`hasFullAccess`](https://developer.apple.com/documentation/uikit/uiinputviewcontroller/hasfullaccess), [App Store Review Guidelines](https://developer.apple.com/app-store/review/guidelines/) (4.4.1, 5.1.1, 5.1.2)
- Law and regulators (context only, not legal advice): [GDPR (EUR-Lex)](https://eur-lex.europa.eu/eli/reg/2016/679/oj), Art. 5(1)(c) and Art. 25; [UK GDPR (legislation.gov.uk)](https://www.legislation.gov.uk/eur/2016/679/contents); [ICO: data minimisation](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/data-protection-principles/a-guide-to-the-data-protection-principles/data-minimisation/); [EDPB Guidelines 4/2019 on Article 25 Data Protection by Design and by Default](https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-42019-article-25-data-protection-design-and_en)
- Research cited by OWASP: [Engineering Privacy in Smartphone Apps (IEEE)](https://ieeexplore.ieee.org/document/9001128); [Uraniborg preloaded app risk scoring](https://www.android-device-security.org/publications/2020-lau-uraniborg/Lau_2020_Uraniborg_Scoring_Whitepaper_20200827.pdf)
- CWE: [CWE-250](https://cwe.mitre.org/data/definitions/250.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
