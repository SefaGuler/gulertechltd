---
title: "MASWE-0042: Latest Platform Version Not Targeted"
date: 2026-11-10 10:01:00 +0000
subcategory: code
summary: "Testing whether Android apps target a current API level and iOS apps are built with a current SDK, and whether they opt back out of new protections."
refs: [MASWE-0042, MASVS-CODE-1, CWE-693, CWE-1357]
tags: [android, ios, masvs-code, targetsdkversion, xcode-sdk, platform-version]
---

This note is part of our [MASVS-CODE guide](/mobile/masvs-code-code-quality-guide/) and covers OWASP [MASWE-0042](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0042/): apps that do not target the latest platform version. Both mobile platforms keep old apps working by applying new, stricter behaviour only to apps that declare they are ready for it: on Android through `targetSdkVersion`, on iOS through the SDK the app was linked against. An app that stays on an old target runs on a brand-new phone with the platform's compatibility behaviour switched on, so it silently misses protections such as scoped storage, cleartext blocking, safer intents, read-only dynamic code and, on iOS, a TLS 1.2 floor. **OWASP has no tests and no Knowledge pages for this weakness**, so the tests below are our own. You will find what each platform gates on the target, Google Play's and Apple's current requirements (checked in November 2026), how to read the target from a release build, three Guler Tech tests (including one for apps that raise the target and then opt back out), and how to rate what you find. The related question, which OS versions the app may *run* on, is [MASWE-0041](/mobile/maswe-0041-running-on-recent-platform-version-not-ensured/).

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Background](#background)
  - [Android: targetSdkVersion and compatibility behaviour](#android-targetsdkversion-and-compatibility-behaviour)
  - [iOS: the SDK an app is built with](#ios-the-sdk-an-app-is-built-with)
- [Tests](#tests)
  - [GT-CODE-0042-1: targetSdkVersion below the current Google Play requirement (Android)](#gt-code-0042-1-targetsdkversion-below-the-current-google-play-requirement-android)
  - [GT-CODE-0042-2: App built with an outdated SDK or Xcode (iOS)](#gt-code-0042-2-app-built-with-an-outdated-sdk-or-xcode-ios)
  - [GT-CODE-0042-3: Target-gated protections opted out or worked around (Android)](#gt-code-0042-3-target-gated-protections-opted-out-or-worked-around-android)
- [Secure implementation](#secure-implementation)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

MASWE-0042 applies when an app does not target the latest platform version and therefore misses the platform's newest enforced protections and behaviour changes. The OWASP requirement is *"The app targets the latest platform version."* It maps to [MASVS-CODE-1](https://mas.owasp.org/MASVS/controls/MASVS-CODE-1/) ("The app requires an up-to-date platform version"), to [CWE-693](https://cwe.mitre.org/data/definitions/693.html) (Protection Mechanism Failure) and [CWE-1357](https://cwe.mitre.org/data/definitions/1357.html) (Reliance on Insufficiently Trustworthy Component), and to the `Target_SDK_Version` and `Compile_SDK_Version` items of Android's [core app quality guidelines](https://developer.android.com/docs/quality-guidelines/core-app-quality). Unlike MASWE-0041, it is tagged for **L1, L2 and EUDIW**: every app is expected to keep its target current.

OWASP status: **no tests, no Knowledge pages**. The only related OWASP material is [MASTG-BEST-0010](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0010/), which is about `minSdkVersion` but explains the difference between the two values well; we cover it in the [MASWE-0041 note](/mobile/maswe-0041-running-on-recent-platform-version-not-ensured/). No legacy (MASTG v1) test maps to this weakness.

OWASP describes the threat as MAS-THREAT-0042, *"Attackers can exploit the absence of modern platform protections"*, through one attack:

| Attack | Description | Attacker position |
|---|---|---|
| MAS-ATTACK-0056 | Accessing app data exposed by legacy compatibility behaviours that the platform still applies to apps targeting an old version | Malicious app on the same device (shared storage, intents, broadcasts), or a network attacker (cleartext, old TLS defaults, user-installed CAs) |

Keep it apart from MASWE-0041. The *minimum* decides which devices may run the app; the *target* decides which rules the app plays by on devices that are new enough to have them. A high target does nothing on an old device, and a high minimum does nothing if the target keeps the app in compatibility mode. You need both.

## Modes of Introduction

**The target is never raised.** The app is maintained, but `targetSdk` stays where it was when the project started, because raising it means testing behaviour changes. Apps distributed outside Google Play (enterprise MDM, sideloading, other stores) are the worst case, because nothing forces the upgrade.

**The target is raised only to the store minimum.** The team moves the target once a year when Google Play's deadline arrives, always one release behind, and treats the change as a compliance task, not a security one.

**The target is raised, then the protection is switched back off.** Most target-gated protections have an escape hatch: `requestLegacyExternalStorage`, `cleartextTrafficPermitted="true"`, `<certificates src="user"/>`, `FLAG_ALLOW_UNSAFE_IMPLICIT_INTENT`, `ZipPathValidator.clearCallback()`, `intentMatchingFlags="none"`. Using them to make the build pass keeps the old behaviour under a new number.

**iOS apps built with an old toolchain.** A CI image pinned to an old Xcode, or a binary SDK built long ago and embedded unchanged, keeps "linked on or after" protections off. On the App Store this ends when Apple raises its upload requirement; enterprise and ad-hoc builds have no such deadline.

**Workarounds instead of migrations.** Code catches the exception a new restriction throws (`SecurityException`, `ZipException`, `IllegalArgumentException`) and retries a different, older path.

## Impact

- **Exposure of user data through legacy behaviour.** Files on shared storage readable by other apps (no scoped storage), cleartext HTTP allowed by default, user-installed CAs trusted, intents to internal components resolvable by other apps.
- **Weaker integrity of the app's own code.** Writable dynamically loaded DEX or native code, zip extraction that accepts `../` entries.
- **Missed hardening against newer attack classes.** Intent-filter matching, background activity launches, implicit `PendingIntent`s, TLS 1.0/1.1, certificate transparency.
- **Blocked or delayed security fixes.** An app below Google Play's target requirement cannot publish updates, and below the "existing apps" level it disappears for new users on newer devices. An iOS project that cannot build with the required Xcode cannot ship to the App Store. Either way, the next security fix cannot reach users.

## Mitigations

- **Target the latest stable API level** (and compile against it) in each yearly Android cycle; do not wait for Google Play's deadline, which trails the latest release by about a year.
- **Build with the current Xcode and SDK** for every iOS release, including enterprise builds and embedded binary frameworks.
- **Migrate, do not opt out.** Treat every escape hatch as a documented exception with an owner and an expiry date.
- **Read the behaviour-change pages** for each new Android and iOS release, and add tests for the security-relevant ones (see the tables below).

## Background

OWASP has no Knowledge page for this weakness. This section explains the mechanisms you need: how each platform gates behaviour on the target or SDK, which security behaviours are gated, and what the stores currently require.

### Android: targetSdkVersion and compatibility behaviour

#### What targetSdkVersion does

Three numbers live in the Gradle file and, except `compileSdk`, in the merged manifest's `<uses-sdk>` element:

| Value | Meaning | Visible in the APK |
|---|---|---|
| `minSdk` | Oldest Android version that may install the app ([MASWE-0041](/mobile/maswe-0041-running-on-recent-platform-version-not-ensured/)) | `android:minSdkVersion` |
| `targetSdk` | The API level the app has been tested against. The platform enables behaviour changes "for apps targeting API N or higher" by comparing with this value | `android:targetSdkVersion` |
| `compileSdk` | The SDK the app was compiled against; decides which APIs and constants the code can use | `android:compileSdkVersion` and `platformBuildVersionCode` on `<manifest>` (written by the build tools) |

Internally, Android's **app compatibility framework** registers each target-gated behaviour as a *change ID* that is enabled for packages whose `targetSdkVersion` is at or above a given level. That has three practical consequences:

- **Target-gated behaviour needs both conditions.** The device must run the release that introduced the change *and* the app must target it. On an older device the app behaves as that device's release dictates, whatever its target.
- **You can see the switches.** `adb shell dumpsys platform_compat` lists every registered change with its ID, name and gate (`enableAfterTargetSdk=32` means "enabled for apps targeting 33 or higher"), plus per-package overrides. The first time a process hits a gated API, logcat also prints `CompatibilityChangeReporter: Compat change id reported: <id>; UID <uid>; state: ENABLED|DISABLED`.
- **You can only flip them for debuggable apps.** `adb shell am compat enable|disable|reset <CHANGE_ID or NAME> <package>` works for debuggable builds only; on a public user build only target-gated changes can be toggled, and never for a non-debuggable release app ([compatibility framework tools](https://developer.android.com/guide/app-compatibility/test-debug)). On a production device with a release build, test the behaviour the app actually gets.

Android also has blunter rules for very old targets, independent of the compat framework:

- Since Android 10, users see a warning the first time they open an app that targets API 22 or lower.
- Since **Android 14**, apps targeting below **API 23** cannot be installed (`INSTALL_FAILED_DEPRECATED_SDK_VERSION`); since **Android 15** the threshold is **API 24**. Apps already installed before the device upgraded stay installed. Testers can bypass the block with `adb install --bypass-low-target-sdk-block app.apk` ([Android 14](https://developer.android.com/about/versions/14/behavior-changes-all), [Android 15](https://developer.android.com/about/versions/15/behavior-changes-all) behaviour changes). Google's stated reason is malware that targets API 22 to avoid runtime permissions.

#### Security behaviour gated on targetSdkVersion

The behaviours below apply only to apps that target the given level or higher, on devices running at least that release. The list is selective: it contains the changes that matter for security testing and that we have checked against Android's behaviour-change pages. Changes that apply to *all* apps regardless of target (for example Android 16's intent redirection hardening) are not in it, because a low target does not lose them.

| Target | Release | Behaviour the app gets only by targeting it |
|---|---|---|
| 23 | Android 6.0 | Runtime permissions (below 23, dangerous permissions are granted at install) |
| 24 | Android 7.0 | User-installed CAs no longer trusted by default; `file://` URIs passed to other apps throw `FileUriExposedException`; private app directories no longer world-accessible and `MODE_WORLD_READABLE`/`MODE_WORLD_WRITEABLE` throw `SecurityException` |
| 26 | Android 8.0 | Manifest receivers no longer receive most implicit broadcasts |
| 28 | Android 9 | Cleartext traffic blocked by default; per-app SELinux domains (no data sharing through world-accessible Unix permissions); WebView no longer sniffs MIME types of `file:` URIs; `Build.SERIAL` always `UNKNOWN` |
| 29 | Android 10 | Scoped storage (opt-out with `requestLegacyExternalStorage`) |
| 30 | Android 11 | Scoped storage enforced (`requestLegacyExternalStorage` ignored); package visibility filtering; APK Signature Scheme v2 required; more non-SDK interfaces blocked |
| 31 | Android 12 | `android:exported` must be explicit on components with intent filters; every `PendingIntent` must declare `FLAG_IMMUTABLE` or `FLAG_MUTABLE` |
| 33 | Android 13 | Intents to an exported component are dropped unless they match one of its filters; `POST_NOTIFICATIONS` runtime permission; granular media permissions |
| 34 | Android 14 | Implicit intents reach exported components only; mutable `PendingIntent`s with implicit base intents throw; runtime receivers must declare `RECEIVER_EXPORTED`/`RECEIVER_NOT_EXPORTED`; **dynamically loaded DEX/JAR files must be read-only**; `ZipFile` and `ZipInputStream` reject entries containing `..` or starting with `/`; `PendingIntent` senders must opt in to lend background-launch privileges; user consent per `MediaProjection` session |
| 35 | Android 15 | **TLS 1.0 and 1.1 disallowed**; `PendingIntent` creators block background activity launches by default, plus further background-launch restrictions |
| 36 | Android 16 | `MediaStore#getVersion()` unique per app (anti-fingerprinting); TLS 1.0/1.1 passed to `setEnabledProtocols()` rejected with an exception (see our [TLS versions note](/mobile/maswe-0026-insecure-tls-protocol-versions/)) |
| 37 | Android 17 | **Certificate transparency enabled by default**; Encrypted Client Hello used where the networking library supports it; `ACCESS_LOCAL_NETWORK` runtime permission required for LAN access; **native libraries loaded with `System.load()` must be read-only**; background-launch hardening extended to `IntentSender`; `setContentCaptureEnabled(false)` no longer disables content capture (use `FLAG_SECURE`); standard SMS containing OTPs withheld for three hours from most apps |

Sources: Android's behaviour-change pages for [Android 14](https://developer.android.com/about/versions/14/behavior-changes-14), [15](https://developer.android.com/about/versions/15/behavior-changes-15), [16](https://developer.android.com/about/versions/16/behavior-changes-16) and [17](https://developer.android.com/about/versions/17/behavior-changes-17), the [network security configuration](https://developer.android.com/privacy-and-security/security-config) guide, and Google's [target API migration guide](https://developer.android.com/google/play/requirements/target-sdk) for the older levels.

Two entries show why "latest" matters and "Play minimum" is not enough. Android 16's **Safer Intents** (strict intent-filter matching for incoming explicit intents) is *opt-in* through `android:intentMatchingFlags="enforceIntentFilter"` even for apps targeting 36; Google says it plans to make it the default later. And Android 16's local network protection was opt-in through a compat flag; it becomes mandatory only for apps targeting 37. An app that just meets this year's Play requirement gets neither.

The `BEST-0010` caution applies in the other direction too: a high target does not protect users on old devices. Cleartext is blocked by default only on Android 9+ devices for apps targeting 28+; on Android 7 and 8 the same app allows it ([MASWE-0041](/mobile/maswe-0041-running-on-recent-platform-version-not-ensured/)).

#### Google Play target API requirements

From Google's [target SDK page](https://developer.android.com/google/play/requirements/target-sdk) and the [Play Console Help article](https://support.google.com/googleplay/android-developer/answer/11926878), as of November 2026:

| Since | Requirement |
|---|---|
| 31 August 2026 | **New apps and app updates** must target **Android 16 (API 36)** or higher; Wear OS and Android Automotive OS apps API 35; Android TV and Android XR apps API 34 |
| 31 August 2026 | **Existing apps** must target **Android 15 (API 35)** or higher to remain available to new users on devices running a newer Android than the app's target; apps targeting API 34 or lower are only offered to devices running the same or a lower version |
| 1 November 2026 | End of the extension developers could request to keep updating while they migrated |
| 31 August 2025 | Previous cycle: new apps and updates API 35 |

So today an app on Google Play that targets below 36 cannot ship an update, and one below 35 is invisible to new users with newer phones. Google announces the next cycle each year (historically one API level higher, with an August deadline); check the two pages above before you quote a future date. Permanently private apps distributed only within one organisation through Play are exempt, and apps outside Play are not bound at all; for those, the platform install blocks above are the only floor.

Android lint enforces the same thing during development: `ExpiredTargetSdkVersion` (an error in the release `lintVital` check when the target is below Play's requirement) and `OldTargetApi` (a warning when the target is below the latest API level the lint version knows).

#### Reading the target from a build

```bash
aapt2 dump badging app.apk | grep -E "^package:|targetSdkVersion|sdkVersion"
# package: name='com.example.app' versionCode='311' versionName='3.1.1' platformBuildVersionName='13' platformBuildVersionCode='33' compileSdkVersion='33' compileSdkVersionCodename='13'
# sdkVersion:'24'
# targetSdkVersion:'33'

apkanalyzer manifest target-sdk app.apk
apktool d app.apk -o apk_out && grep -A2 sdkInfo apk_out/apktool.yml
bundletool dump manifest --bundle=app.aab --xpath=/manifest/uses-sdk/@android:targetSdkVersion
adb shell dumpsys package com.example.app | grep -E "versionName|targetSdk"
```

### iOS: the SDK an app is built with

#### Where the build SDK is recorded

iOS has no "target SDK" setting. The equivalent is the **SDK the app was linked against**, which is whatever SDK the Xcode used for the build ships with (Xcode 26 ships the iOS 26 SDK). It is recorded in two places:

**`Info.plist` build keys.** Xcode adds a set of `DT*` keys at build time:

| Key | Example | Meaning |
|---|---|---|
| `DTSDKName` | `iphoneos26.0` | SDK used for the build |
| `DTPlatformVersion` | `26.0` | Platform (SDK) version |
| `DTSDKBuild`, `DTPlatformBuild` | build numbers | Exact SDK build |
| `DTXcode` | `2600` | Xcode version, without dots (`1520` is Xcode 15.2) |
| `DTXcodeBuild` | Xcode build number | Exact Xcode build |
| `DTCompiler` | `com.apple.compilers.llvm.clang.1_0` | Compiler |
| `BuildMachineOSBuild` | macOS build number | The build machine's macOS |

**`LC_BUILD_VERSION` in each Mach-O.** Next to `minos` (MASWE-0041) it carries `sdk`, and a list of tools (`ld`, `clang`, `swift`) with their versions. Older binaries carry `LC_VERSION_MIN_IPHONEOS` with an `sdk` field instead.

Embedded frameworks keep their own values. A framework built years ago with an old SDK, linked into an app built with the current one, is a stale binary dependency (see [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/)). Apple's "linked on or after" checks are normally based on the SDK of the main executable, so the framework's old SDK rarely changes the app's behaviour, but it tells you nobody has rebuilt that code.

#### Linked-on-or-after behaviour

Apple's frameworks switch behaviour on the SDK the app was linked with, not only on the OS it runs on. Apple's release notes describe such changes as applying to apps "linked on or after" a given SDK. Two security examples we have checked:

- **App Transport Security** is on by default for apps linked against the iOS 9 SDK or later. Linked against an older SDK, ATS is off on every iOS version ([`NSAppTransportSecurity`](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity)). No current Xcode can produce such a binary, but it is the cleanest illustration of the mechanism.
- **TLS 1.2 minimum for `URLSession` and Network.framework.** Apple's OS 26 release notes state that *"for apps linked on or after iOS 26 and macOS 26, the default minimum TLS version of `URLSession` and Network frameworks has changed from 1.0 to 1.2."* An app built with an older SDK keeps the TLS 1.0 default for `NWConnection` even on an iOS 26 device. The details and the opt-out APIs are in our [TLS versions note](/mobile/maswe-0026-insecure-tls-protocol-versions/).

Not every version-dependent behaviour is SDK-gated. ATS's treatment of local networking changed by **OS version**: iOS 10 to 16 did not restrict IP addresses, unqualified names or `.local` hosts, and iOS 17 restricts IP addresses by default whatever SDK the app used ([`NSAllowsLocalNetworking`](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity/nsallowslocalnetworking)). Likewise, since iOS 10, ATS ignores `NSAllowsArbitraryLoads` when finer global keys such as `NSAllowsLocalNetworking` are present. When you report an ATS or TLS behaviour, say whether it depends on the SDK (this weakness) or the OS (MASWE-0041).

#### App Store SDK requirements

From Apple's [upcoming requirements](https://developer.apple.com/news/upcoming-requirements/) page, as of November 2026:

| Since | Requirement |
|---|---|
| 28 April 2026 | *"Apps uploaded to App Store Connect must be built with Xcode 26 or later using an SDK for iOS 26, iPadOS 26, tvOS 26, visionOS 26, or watchOS 26."* |
| 29 April 2024 | Previous cycle on that page: Xcode 15 for iOS 17, iPadOS 17, tvOS 17 or watchOS 10 |
| 9 September 2026 | Separate deployment-target rule: iOS and iPadOS apps uploaded must target iOS 13 or later (MASWE-0041) |

Apple has raised the SDK requirement roughly once a year, in spring, about six months after the corresponding Xcode release. The rule applies to *uploads*: a build already on the store is not removed. So an App Store binary with `DTSDKName` below `iphoneos26.0` today is a build uploaded before 28 April 2026 that has not been updated since. Enterprise (in-house) and ad-hoc builds are not checked by App Store Connect at all.

## Tests

OWASP has no tests for MASWE-0042. The three tests below are Guler Tech methodology. The first two read the target (Android) or build SDK (iOS) and compare it with the store requirements and the latest platform release. The third catches the common case where the number is current but the protections it should bring have been switched back off.

### GT-CODE-0042-1: targetSdkVersion below the current Google Play requirement (Android)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Reads `targetSdkVersion` and `compileSdkVersion` from the release build and compares them with Google Play's current requirement (API 36 for phone and tablet updates since 31 August 2026) and with the latest stable API level (37). For each level the app is behind, lists the target-gated security behaviours it misses. Type: static, with optional dynamic confirmation. Profile: L1, L2, EUDIW.

#### Prerequisites

- The release APK(s) or AAB; for Play apps, the build actually distributed.
- `aapt2` or `apkanalyzer` (Android SDK), apktool.
- The current requirements from Google's target SDK page (re-check on the day of the test).
- Optional: a device on the latest Android release with `adb`.

#### Steps

1. **Read the values:**

   ```bash
   aapt2 dump badging app.apk | grep -E "^package:|targetSdkVersion|sdkVersion"
   ```

   Record `targetSdkVersion`, `compileSdkVersion` (and `platformBuildVersionCode`), and `sdkVersion` (the minimum).

2. **Check the distribution channel and form factor.** Play phone/tablet app, Wear OS, TV, Automotive, XR, or outside Play (MDM, sideload, other store). The requirement differs by form factor, and outside Play only the platform install blocks apply.

3. **Compare with the references:**
   - Below the platform install block (23 on Android 14, 24 on Android 15+): the app cannot be installed on current devices without `--bypass-low-target-sdk-block`.
   - Below Play's "existing apps" level (35): invisible to new users on Android 16+ devices.
   - Below Play's "new apps and updates" level (36): cannot ship updates on Play.
   - Below the latest stable API (37): misses the newest protections.

4. **List the missed protections** from the [targetSdk table](#android-targetsdkversion-and-compatibility-behaviour) for every level between the app's target and the latest, and keep only those that matter for *this* app (does it use shared storage, cleartext, dynamic code, zip extraction, implicit intents, `PendingIntent`s, local network access?):

   ```bash
   SRC=out/sources/com/example/app
   rg -l 'DexClassLoader|PathClassLoader|InMemoryDexClassLoader|System\.load\(' $SRC
   rg -l 'ZipInputStream|ZipFile' $SRC
   rg -l 'getExternalStorage|Environment\.getExternalStoragePublicDirectory|MediaStore' $SRC
   rg -l 'http://' apk_out/res/values/strings.xml $SRC
   ```

5. **Optional runtime confirmation.** On the newest device, check which compat changes apply to the package and confirm one behaviour that matters (for example, an `http://` request succeeding where an app targeting 28+ would be refused):

   ```bash
   adb shell dumpsys platform_compat | grep -i com.example.app
   adb shell dumpsys package com.example.app | grep -m1 userId=   # UID to match in the logcat lines
   adb logcat | grep -E 'CompatibilityChangeReporter|Cleartext HTTP traffic|FileUriExposed|ZipException'
   ```

#### Observation

`minSdkVersion`, `targetSdkVersion`, `compileSdkVersion`; distribution channel and form factor; the gap to each reference level; the target-gated protections missed that are relevant to the app's features, with the code location that makes each relevant.

#### Evaluation

The test **fails** if:

- the app is distributed on Google Play and `targetSdkVersion` is below the current requirement for its form factor (API 36 for phone and tablet apps since 31 August 2026); or
- the app is distributed outside Play and `targetSdkVersion` is below the current Play requirement anyway (the same protections are missing; there is just no store to enforce it); or
- whatever the channel, a target-gated protection the app's own features need is missing because of the target (for example target below 30 in an app that writes sensitive files to shared storage).

It **passes** with a note if the target meets the store requirement but is below the latest stable API level; list the missed protections as hardening. It passes outright when the target is the latest stable API level and `compileSdk` matches it.

#### Demo

An app distributed on Google Play, last updated in 2024:

```text
$ aapt2 dump badging app.apk | grep -E "^package:|targetSdkVersion|sdkVersion"
package: name='com.example.app' versionCode='311' versionName='3.1.1' platformBuildVersionName='13' platformBuildVersionCode='33' compileSdkVersion='33' compileSdkVersionCodename='13'
sdkVersion:'24'
targetSdkVersion:'33'

$ rg -l 'DexClassLoader' out/sources/com/example/app
out/sources/com/example/app/plugins/PluginLoader.java
```

Target 33 is below Play's API 36 requirement for updates and below the API 35 level for availability to new users on newer devices. The app loads plugin DEX files: on Android 14+ an app targeting 34 or higher would have to make them read-only, and this app does not have to. Report the target finding, and test the loader itself under [MASWE-0049](/mobile/maswe-0049-unsafe-dynamic-code-loading/).

### GT-CODE-0042-2: App built with an outdated SDK or Xcode (iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Reads the SDK and Xcode version the app (and each embedded binary) was built with and compares them with Apple's current App Store requirement and the latest SDK. Type: static. Profile: L1, L2, EUDIW.

#### Prerequisites

- The IPA (encrypted is fine; the plist and load commands are readable).
- macOS with `plutil`, `otool` and optionally `vtool`, or Linux with Python's `plistlib` and `llvm-objdump`.
- Apple's upcoming requirements page, re-checked on the day.

#### Steps

1. **Unpack and read the `DT*` keys:**

   ```bash
   mkdir ipa && cd ipa && unzip -q ../App.ipa
   APP=$(ls -d Payload/*.app)
   plutil -p "$APP/Info.plist" | grep -E '"DT|"BuildMachineOSBuild"|"MinimumOSVersion"'
   ```

2. **Read the `sdk` field of the main executable:**

   ```bash
   EXE=$(plutil -extract CFBundleExecutable raw -o - "$APP/Info.plist")
   otool -l "$APP/$EXE" | grep -A4 LC_BUILD_VERSION
   vtool -show-build "$APP/$EXE"            # alternative on macOS
   ```

3. **Do the same for extensions and frameworks**, and list them by SDK:

   ```bash
   find "$APP" -type f -perm -u+x | while read -r f; do
     file "$f" | grep -q Mach-O && printf '%s\t%s\n' \
       "$(otool -l "$f" | awk '/LC_BUILD_VERSION/{f=1} f&&/ sdk /{print $2; exit}')" "$f"
   done | sort -V
   ```

4. **Compare** the main executable's SDK with Apple's requirement (iOS 26 SDK and Xcode 26 since 28 April 2026) and with the latest SDK release. Note the distribution channel: App Store, TestFlight, enterprise or ad hoc.

5. **List the SDK-gated protections** the app misses and check whether they matter here, for example whether it uses Network.framework (`NWConnection`) and would get the TLS 1.0 default:

   ```bash
   strings -a "$APP/$EXE" | grep -E 'NWConnection|nw_connection|NWProtocolTLS|sec_protocol_options' | sort -u
   ```

#### Observation

`DTSDKName`, `DTPlatformVersion`, `DTXcode`, `DTXcodeBuild`; `sdk` and `minos` for each Mach-O; distribution channel; relevant SDK-gated protections missed.

#### Evaluation

The test **fails** if the main executable was built with an SDK older than Apple's current App Store requirement (iOS 26 SDK as of 28 April 2026), whatever the channel: on the App Store this means the build has not been updated since before the deadline; for enterprise and ad-hoc builds it means no toolchain update is being enforced at all. Raise the rating if a missed SDK-gated protection is relevant to the app (for example Network.framework connections that would accept TLS 1.0).

It **passes** if the main executable was built with the current or required SDK. Embedded frameworks built with much older SDKs are reported separately as stale binary dependencies (Info, or under [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/) if they have known vulnerabilities).

#### Demo

```text
$ plutil -p Payload/Example.app/Info.plist | grep -E '"DT'
  "DTCompiler" => "com.apple.compilers.llvm.clang.1_0"
  "DTPlatformName" => "iphoneos"
  "DTPlatformVersion" => "17.2"
  "DTSDKName" => "iphoneos17.2"
  "DTXcode" => "1520"
  "DTXcodeBuild" => "15C500b"

$ otool -l Payload/Example.app/Example | grep -A4 LC_BUILD_VERSION
      cmd LC_BUILD_VERSION
  cmdsize 32
 platform 2
    minos 15.0
      sdk 17.2

$ strings -a Payload/Example.app/Example | grep -E 'NWConnection|NWProtocolTLS' | sort -u
NWConnection
NWProtocolTLS
```

Built with Xcode 15.2 and the iOS 17.2 SDK: below the iOS 26 SDK requirement, so this App Store build predates April 2026. It also uses Network.framework, and because it is not linked on or after iOS 26, an `NWConnection` with default TLS options accepts TLS 1.0 from a server that offers nothing better. Confirm that part with the dynamic test in our [TLS versions note](/mobile/maswe-0026-insecure-tls-protocol-versions/).

### GT-CODE-0042-3: Target-gated protections opted out or worked around (Android)

*Guler Tech methodology — not an OWASP test.*

#### Overview

A current `targetSdkVersion` is only worth what the app keeps of it. This test looks for the manifest attributes, configuration entries, API calls, lint suppressions and code patterns that switch target-gated protections back off or route around them. Type: static (manifest, resources, code), with source review where available. Profile: L1, L2, EUDIW.

#### Prerequisites

- The APK decoded with apktool and decompiled with jadx; the source tree and build files if you have them (grey-box).
- The app's `targetSdkVersion` from GT-CODE-0042-1 (an opt-out only matters if the target would otherwise enable the protection).

#### Steps

1. **Manifest and resource opt-outs:**

   ```bash
   grep -nE 'requestLegacyExternalStorage|preserveLegacyExternalStorage|usesCleartextTraffic|intentMatchingFlags|QUERY_ALL_PACKAGES|networkSecurityConfig' apk_out/AndroidManifest.xml
   grep -rnE 'cleartextTrafficPermitted="true"|src="user"|certificateTransparency enabled="false"|domainEncryption mode="disabled"|overridePins="true"' apk_out/res/xml/
   ```

2. **API-level opt-outs in code:**

   ```bash
   SRC=out/sources/com/example/app
   rg -n 'ZipPathValidator\.clearCallback|removeLaunchSecurityProtection|FLAG_ALLOW_UNSAFE_IMPLICIT_INTENT|16777216|MODE_BACKGROUND_ACTIVITY_START_ALLOWED|setPendingIntentBackgroundActivityStartMode|RECEIVER_EXPORTED|setContentCaptureEnabled' $SRC
   rg -n 'setEnabledProtocols\(|"TLSv1"|"TLSv1\.1"' $SRC
   ```

   `16777216` (`0x01000000`) is `FLAG_ALLOW_UNSAFE_IMPLICIT_INTENT` as jadx prints it; verify that a hit is a `PendingIntent` flag before reporting it.

3. **Workarounds for new restrictions.** Look for code that catches the exception a target-gated rule throws and then takes another path:

   ```bash
   rg -n -B2 -A6 'catch \((SecurityException|ZipException|IllegalArgumentException|FileUriExposedException)' $SRC | rg -n 'SDK_INT|setWritable|setReadable|chmod|legacy|fallback'
   ```

   Also look for `SDK_INT` branches that *weaken* behaviour on newer versions (for example making a loaded file writable again, or using reflection to reach a hidden API on API 34+).

4. **Build-level suppressions (source available):**

   ```bash
   rg -n 'OldTargetApi|ExpiredTargetSdkVersion|checkReleaseBuilds|abortOnError' --glob '*.{xml,kts,gradle}' .
   rg -n 'tools:targetApi|tools:ignore=|@SuppressLint\("NewApi"\)|@TargetApi\(' --glob '*.{xml,kt,java}' app/src/main
   ```

   `tools:targetApi` does not change the target: it tells lint that an element or attribute is only used from that API level, which silences `NewApi` warnings. It is a review pointer, not a finding in itself. Suppressing `ExpiredTargetSdkVersion` or `OldTargetApi` (`tools:ignore` in the manifest, `lint.xml`, or the Gradle `lint` block), or turning off `checkReleaseBuilds`, is a process finding: the team has switched off the check that would have told them about this weakness.

5. **Confirm reachability.** For each opt-out, find the feature that uses it (the storage path, the zip import, the forwarded intent) and, where you can, observe it on a device running the release that introduced the protection.

#### Observation

Each opt-out or workaround with location, the protection it disables, the target level that would otherwise enable it, the feature that relies on it, and runtime evidence where gathered.

#### Evaluation

The test **fails** if the app's target would enable a protection and the app disables or bypasses it for a feature that handles sensitive data or untrusted input, without a documented, time-limited justification. Typical failures: `ZipPathValidator.clearCallback()` in an app that extracts downloaded archives; `requestLegacyExternalStorage` together with sensitive files on shared storage; `cleartextTrafficPermitted="true"` in `base-config`; `<certificates src="user"/>` outside `debug-overrides`; `removeLaunchSecurityProtection()` on intents taken from extras; suppressed `ExpiredTargetSdkVersion`.

It **passes** if no opt-outs exist, or each one is narrowly scoped (a single domain, a debug-only override, a component that handles no sensitive data) and documented.

#### Demo

```xml
<!-- AndroidManifest.xml, app targets API 35 -->
<application
    android:requestLegacyExternalStorage="true"
    android:networkSecurityConfig="@xml/network_security_config">
```

```kotlin
// ImportManager.kt
fun importBackup(zip: File, dest: File) {
    ZipPathValidator.clearCallback()             // "fixes" ZipException on Android 14+
    ZipInputStream(zip.inputStream()).use { zis ->
        generateSequence { zis.nextEntry }.forEach { e ->
            File(dest, e.name).outputStream().use { zis.copyTo(it) }
        }
    }
}
```

```text
$ grep -n requestLegacyExternalStorage apk_out/AndroidManifest.xml
12:        android:requestLegacyExternalStorage="true"

$ rg -n 'ZipPathValidator\.clearCallback' out/sources/com/example/app
out/sources/com/example/app/backup/ImportManager.java:27:        ZipPathValidator.clearCallback();
```

`requestLegacyExternalStorage` has no effect for a target of 35 (it only mattered for apps targeting 29), so it is an Info-level leftover. The `clearCallback()` call is the finding: it removes the zip path traversal check the target would give the app on Android 14+, in a method that writes entry names straight into `File(dest, e.name)`. Verify the traversal itself with the methodology in [MASWE-0050](/mobile/maswe-0050-unsafe-handling-of-untrusted-data/) (a crafted entry name observed reaching `File(...)` unchanged), not with an exploit.

## Secure implementation

**Android.**

- Raise `targetSdk` and `compileSdk` to the latest stable API level in each annual cycle, ideally within a few months of the release, not at Play's deadline:

  ```kotlin
  android {
      compileSdk = 37
      defaultConfig {
          minSdk = 30        // see MASWE-0041
          targetSdk = 37
      }
  }
  ```

- Use each behaviour-change page as a checklist. For the security items in the [targetSdk table](#android-targetsdkversion-and-compatibility-behaviour), write a test that proves the new behaviour applies (for example a unit test that a zip entry with `../` throws `ZipException`, an instrumentation test that `http://` is refused).
- Opt in to protections that are still optional: `android:intentMatchingFlags="enforceIntentFilter"` on Android 16+, certificate transparency in the network security configuration on Android 16.
- Keep lint's `ExpiredTargetSdkVersion` and `OldTargetApi` checks enabled, and keep `checkReleaseBuilds` on so release builds fail on them.
- Use the compat framework on debug builds (`adb shell am compat enable ...`) to test the next release's changes before raising the target.

**iOS.**

- Build every release, including enterprise and ad-hoc builds, with the current Xcode; pin the CI image to an Xcode version and update it on a schedule, not ad hoc.
- Rebuild or replace binary frameworks that were built with old SDKs; prefer source or recently built XCFrameworks.
- Read the "linked on or after" entries in each Xcode and OS release note and remove the opt-outs you no longer need (for example explicit TLS 1.0 minimums kept from before iOS 26).

**Both.** Pair the current target with a sensible minimum ([MASWE-0041](/mobile/maswe-0041-running-on-recent-platform-version-not-ensured/)) and with enforced app updates ([MASWE-0043](/mobile/maswe-0043-enforced-updating-not-implemented/)); targeting the latest platform helps only users who run the latest build. OWASP's [MASTG-BEST-0010](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0010/) explains the target/minimum distinction for Android.

## Rating findings

Rate on three things: **how far behind** the target or SDK is (latest, store minimum, below store minimum, below platform install block), **which missed protections matter for the app's own features**, and **who can exploit them** (MAS-ATTACK-0056: a malicious app on the same device for storage, intent and code-loading behaviours; a network attacker for cleartext, user-CA and TLS defaults). No user interaction is needed beyond normal use. On its own, an old target is a hygiene problem; it becomes a vulnerability when a concrete legacy behaviour exposes the app's data.

| Rating | Conditions |
|---|---|
| **Critical** | Not used for a target finding alone. Rate the concrete vulnerability it enables under its own weakness (for example remote code execution through writable dynamically loaded code) and cite this note as the root cause. |
| **High** | A legacy behaviour kept by the old target (or by an opt-out, GT-CODE-0042-3) directly exposes sensitive data or code integrity: target below 30 (or `requestLegacyExternalStorage` effective at 29) with sensitive files on shared storage; target below 24 with sensitive traffic and no pinning (user CAs trusted); target below 28 with cleartext endpoints carrying sensitive data; `ZipPathValidator.clearCallback()` on archives from untrusted sources. |
| **Medium** | Google Play app below the current target requirement (cannot ship updates, so security fixes are blocked) or below the "existing apps" level; iOS App Store build older than Apple's SDK requirement while the app uses an SDK-gated protection that matters (Network.framework with the TLS 1.0 default); enterprise or sideloaded apps more than two API levels behind. |
| **Low** | Target meets the store requirement but is below the latest stable API, and some missed protections are relevant; iOS build one SDK behind the latest while still meeting Apple's requirement; lint suppression of `ExpiredTargetSdkVersion` or `OldTargetApi`. |
| **Info** | Target at the latest stable API, or one behind during the months after a new release; `compileSdk` behind `targetSdk` cycles; leftover opt-outs that no longer have an effect at the current target; embedded frameworks built with old SDKs and no known vulnerabilities. |

Raise a level for L2 and EUDIW apps when the missed protection is part of the app's stated security design. Lower a level when the app is not distributed through a store and the owner has a documented upgrade plan with a date. In the report give the `minSdkVersion`/`targetSdkVersion`/`compileSdkVersion` (or `DTSDKName`, `DTXcode`, `sdk`, `minos`), the distribution channel, the requirement quoted with its source and the date you checked it, each missed protection with the feature that makes it relevant, and any opt-out with its location.

## References

- OWASP MASWE: [MASWE-0042: Latest Platform Version Not Targeted](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0042/); related [MASWE-0041](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0041/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-CODE-1](https://mas.owasp.org/MASVS/controls/MASVS-CODE-1/) (CC BY-SA 4.0)
- OWASP MASTG best practice: [MASTG-BEST-0010](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0010/) (CC BY-SA 4.0)
- Guler Tech notes: [MASVS-CODE guide](/mobile/masvs-code-code-quality-guide/), [MASWE-0041](/mobile/maswe-0041-running-on-recent-platform-version-not-ensured/), [MASWE-0043](/mobile/maswe-0043-enforced-updating-not-implemented/), [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/), [MASWE-0049](/mobile/maswe-0049-unsafe-dynamic-code-loading/), [MASWE-0050](/mobile/maswe-0050-unsafe-handling-of-untrusted-data/), [MASWE-0026 TLS versions](/mobile/maswe-0026-insecure-tls-protocol-versions/), [MASWE-0026 cleartext](/mobile/maswe-0026-cleartext-network-traffic/), [MASWE-0032](/mobile/maswe-0032-insecure-intents/)
- Google Play and Android Developers: [Meet Google Play's target API level requirement](https://developer.android.com/google/play/requirements/target-sdk), Play Console Help [Target API level requirements for Google Play apps](https://support.google.com/googleplay/android-developer/answer/11926878), [Core app quality guidelines](https://developer.android.com/docs/quality-guidelines/core-app-quality), [`<uses-sdk>` element](https://developer.android.com/guide/topics/manifest/uses-sdk-element), [Compatibility framework tools](https://developer.android.com/guide/app-compatibility/test-debug), [Network security configuration](https://developer.android.com/privacy-and-security/security-config)
- Android behaviour changes: [Android 14 (all apps)](https://developer.android.com/about/versions/14/behavior-changes-all), [Android 14 (target 34)](https://developer.android.com/about/versions/14/behavior-changes-14), [Android 15 (all apps)](https://developer.android.com/about/versions/15/behavior-changes-all), [Android 15 (target 35)](https://developer.android.com/about/versions/15/behavior-changes-15), [Android 16 (all apps)](https://developer.android.com/about/versions/16/behavior-changes-all), [Android 16 (target 36)](https://developer.android.com/about/versions/16/behavior-changes-16), [Android 17 (all apps)](https://developer.android.com/about/versions/17/behavior-changes-all), [Android 17 (target 37)](https://developer.android.com/about/versions/17/behavior-changes-17)
- Apple Developer: [Upcoming requirements](https://developer.apple.com/news/upcoming-requirements/), [`NSAppTransportSecurity`](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity), [`NSAllowsLocalNetworking`](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity/nsallowslocalnetworking), [`MinimumOSVersion`](https://developer.apple.com/documentation/bundleresources/information-property-list/minimumosversion)
- CWE: [CWE-693](https://cwe.mitre.org/data/definitions/693.html), [CWE-1357](https://cwe.mitre.org/data/definitions/1357.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
