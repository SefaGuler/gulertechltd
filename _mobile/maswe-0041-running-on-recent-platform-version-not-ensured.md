---
title: "MASWE-0041: Running on a Recent Platform Version Not Ensured"
date: 2026-11-10 10:00:00 +0000
subcategory: code
summary: "Testing whether Android and iOS apps set a safe minSdkVersion or deployment target and react when they run on an OS that no longer gets fixes."
refs: [MASWE-0041, MASVS-CODE-1, CWE-451, CWE-693, CWE-1104, CWE-1357]
tags: [android, ios, masvs-code, minsdkversion, deployment-target, platform-version]
---

This note is part of our [MASVS-CODE guide](/mobile/masvs-code-code-quality-guide/) and covers OWASP [MASWE-0041](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0041/): apps that do not make sure they run on a recent enough version of Android or iOS. Every OS release fixes vulnerabilities and adds protections. An app can do nothing about the first and can only use the second where they exist. When the app accepts installation on an old OS, it takes on all of that OS's unfixed platform bugs, and every protection it relies on (network security configuration, declarative pinning, hardware-backed keys, overlay and task-hijacking defences) quietly disappears on those devices. Below you will find where the minimum version is declared on each platform and how to read it from a release build, what each Android API level and iOS version actually guarantees, how apps check the version at runtime, the single OWASP test (Android, with its demo and its limits), two Guler Tech tests that cover iOS and runtime enforcement, a secure implementation, and how to rate what you find. The neighbouring question, whether the app *targets* the latest platform, is [MASWE-0042](/mobile/maswe-0042-latest-platform-version-not-targeted/).

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Background](#background)
  - [Android: minSdkVersion and the platform floor](#android-minsdkversion-and-the-platform-floor)
  - [iOS: deployment target and the OS floor](#ios-deployment-target-and-the-os-floor)
- [Tests](#tests)
  - [MASTG-TEST-0245: References to Platform Version APIs (Android)](#mastg-test-0245-references-to-platform-version-apis-android)
  - [GT-CODE-0041-1: Minimum deployment target too low (iOS)](#gt-code-0041-1-minimum-deployment-target-too-low-ios)
  - [GT-CODE-0041-2: Runtime OS version and security patch level enforcement (Android, iOS)](#gt-code-0041-2-runtime-os-version-and-security-patch-level-enforcement-android-ios)
- [Best practices](#best-practices)
  - [MASTG-BEST-0010: Use Up-to-Date minSdkVersion](#mastg-best-0010-use-up-to-date-minsdkversion)
  - [Secure implementation (Guler Tech)](#secure-implementation-guler-tech)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

MASWE-0041 applies when an app does not ensure that it runs on a sufficiently recent platform version. The OWASP requirement is *"The app detects if it is running on an unsupported OS version and reacts appropriately."* It maps to [MASVS-CODE-1](https://mas.owasp.org/MASVS/controls/MASVS-CODE-1/) ("The app requires an up-to-date platform version") and to four CWEs: [CWE-451](https://cwe.mitre.org/data/definitions/451.html) (User Interface Misrepresentation of Critical Information, the task-hijacking angle), [CWE-693](https://cwe.mitre.org/data/definitions/693.html) (Protection Mechanism Failure), [CWE-1104](https://cwe.mitre.org/data/definitions/1104.html) (Use of Unmaintained Third Party Components, here the OS itself) and [CWE-1357](https://cwe.mitre.org/data/definitions/1357.html) (Reliance on Insufficiently Trustworthy Component). OWASP also lists two Android risk pages, [StrandHogg](https://developer.android.com/privacy-and-security/risks/strandhogg) and [unsafe Download Manager use](https://developer.android.com/privacy-and-security/risks/unsafe-download-manager), as examples of platform flaws that only an OS upgrade fixes.

The weakness is tagged for profiles **L2 and EUDIW** only. For an ordinary L1 app a low minimum version is a hardening observation, not a failure. For banking, health, identity-wallet and other high-assurance apps it is a real requirement.

OWASP describes the threat as MAS-THREAT-0041, *"Attackers can exploit platform-level weaknesses that the app cannot fix on its own"*, through two attacks:

| Attack | Description | Attacker position |
|---|---|---|
| MAS-ATTACK-0054 | Installing a malicious app on a device running an OS version affected by unpatched platform vulnerabilities | Malicious app on the same device (task hijacking, privilege escalation, sandbox escape) |
| MAS-ATTACK-0055 | Running the app on a device whose OS version lacks the platform protections the app relies on | Network attacker (no NSC or ATS-era defaults), malicious app on the device, or a user tricked into installing a CA profile |

The user is the victim, not the attacker. They did nothing wrong except keep using an old phone, which is exactly why the app has to decide for them whether it is safe to continue.

Keep the neighbouring weaknesses apart:

| Question | Where it lives |
|---|---|
| Which OS versions may the app run on (`minSdkVersion`, `MinimumOSVersion`), and does it react to unsupported ones? | This note (MASWE-0041) |
| Which platform behaviour does the app opt into (`targetSdkVersion`, the SDK it is built with)? | [MASWE-0042](/mobile/maswe-0042-latest-platform-version-not-targeted/) |
| Does the app force users onto its own latest version? | [MASWE-0043](/mobile/maswe-0043-enforced-updating-not-implemented/) |
| Does the app call APIs the platform has deprecated? | [MASWE-0046](/mobile/maswe-0046-use-of-deprecated-apis/) |

## Modes of Introduction

**Low floor kept for reach.** `minSdk` stays at 21 or 23, or the iOS deployment target at 12 or 13, because "some users are still on it". Nobody revisits it when those versions stop receiving security updates.

**Modern assumptions on an old floor.** The app's security design assumes features its floor does not guarantee: pinning declared in a network security configuration (ignored below API 24), `NSPinnedDomains` (ignored below iOS 14), StrongBox or App Attest, biometric binding of keys. On old devices the feature is silently absent and the app carries on without it.

**Unsafe fallbacks.** The code does check the version (`if (Build.VERSION.SDK_INT >= 28)`, `if #available(iOS 14, *)`), but the `else` branch drops the protection instead of refusing the operation: no attestation, a software key, no overlay protection.

**Library floors inherited without thought.** The app's floor is whatever the oldest dependency allows. Conversely, a dependency silently raises it (manifest merging) and the team never notices which protections that bought them.

**No reaction to unpatched devices.** Even with a reasonable floor, a device can sit years behind on security patches. The app never looks at `Build.VERSION.SECURITY_PATCH` or an attestation verdict, so it cannot warn or restrict.

## Impact

- **Compromise of sensitive data.** On versions without network security configuration, user-installed CAs are trusted and NSC pinning is ignored, so traffic that is pinned on new devices can be intercepted on old ones. Files on shared storage are readable by any app with the storage permission on pre-scoped-storage devices.
- **Credential phishing and account takeover.** Task-hijacking (StrandHogg) and overlay attacks let a malicious app present its own screen as if it were the app's login screen on unpatched Android versions.
- **Full device compromise.** Public kernel and system-service exploits for unpatched versions let malware read the app's sandbox, keys in software keystores and session tokens. App-level controls cannot stop this.
- **Silent loss of the security design.** The app's threat model says "keys are hardware-bound" or "the device is attested", and on part of the user base it is simply not true.

## Mitigations

- **Raise the floor** to the oldest version that still receives security updates and provides every protection the app's design relies on. Revisit it every year.
- **Gate sensitive features at runtime** where the business keeps older versions: detect the OS version and patch level, and restrict or refuse high-risk operations (payments, key enrolment, wallet presentation) instead of falling back to weaker paths.
- **Enforce on the server too.** Use signals the device cannot simply lie about: Play Integrity (`MEETS_STRONG_INTEGRITY` and `deviceAttributes.sdkVersion`), Android key attestation (`osVersion`, `osPatchLevel`), and refuse or step up accordingly.
- **Never let a version check remove a protection.** The fallback for "feature not available" is "operation not available", not "operation without the feature".

## Background

OWASP has no Knowledge page for this weakness. This section explains what you need to test it: where each platform declares its minimum version, how to read it from a release build, what each version floor really guarantees, and how apps check the version at runtime.

### Android: minSdkVersion and the platform floor

#### Where minSdkVersion lives

The developer sets the floor in the module's Gradle file. The Android Gradle Plugin writes it into the `<uses-sdk>` element of the merged manifest, which is compiled into binary XML in the APK:

```kotlin
// app/build.gradle.kts
android {
    compileSdk = 36
    defaultConfig {
        minSdk = 26        // oldest Android version that can install the app
        targetSdk = 36     // behaviour the app opts into (MASWE-0042)
    }
}
```

```xml
<!-- merged AndroidManifest.xml, as decoded from the APK -->
<uses-sdk android:minSdkVersion="26" android:targetSdkVersion="36" />
```

Three properties matter for testing:

- **The package manager enforces it at install time.** A device below `minSdkVersion` refuses the APK (`INSTALL_FAILED_OLDER_SDK`), and Google Play does not offer the app to such devices. This is the only hard guarantee the floor gives.
- **Manifest merging takes the highest value.** A library with a higher `minSdk` fails the build unless the app overrides it with `tools:overrideLibrary`. That override means "this library may crash or misbehave below its own floor". Note it when you see it in source.
- **App bundles can produce several floors.** Play generates split APKs from an AAB and can serve different variants per API range. Check `base.apk` and, if you have the bundle, the bundle manifest.

#### Reading it from an APK, AAB or device

`AndroidManifest.xml` inside an APK is binary XML, so `grep` on the raw file (as MASTG-TECH-0014's example suggests) does not work. Use one of these:

```bash
# aapt2 (Android SDK build-tools)
aapt2 dump badging app.apk | grep -E "^package:|sdkVersion|targetSdkVersion"
# package: name='com.example.app' versionCode='4201' versionName='4.2.1' platformBuildVersionName='16' platformBuildVersionCode='36' compileSdkVersion='36' compileSdkVersionCodename='16'
# sdkVersion:'23'
# targetSdkVersion:'36'

# apkanalyzer (Android SDK command-line tools)
apkanalyzer manifest min-sdk app.apk
apkanalyzer manifest target-sdk app.apk

# apktool moves <uses-sdk> out of the decoded manifest into apktool.yml
apktool d app.apk -o apk_out
grep -A2 sdkInfo apk_out/apktool.yml

# An app bundle
bundletool dump manifest --bundle=app.aab --xpath=/manifest/uses-sdk/@android:minSdkVersion

# An installed app, and the device it is on
adb shell dumpsys package com.example.app | grep -E "versionName|minSdk|targetSdk"
adb shell getprop ro.build.version.sdk
adb shell getprop ro.build.version.release
adb shell getprop ro.build.version.security_patch
```

In `aapt2` output, `sdkVersion` is the minimum. `dumpsys package` prints `minSdk=` and `targetSdk=` on the `versionCode` line.

#### What each API floor guarantees

A floor guarantees that *every* device running the app has at least the features of that release. Some protections also depend on `targetSdkVersion` (marked **T** below): the device must have them *and* the app must opt in, so they appear only when both conditions hold. The table lists what we are sure of and what matters for security testing. It is not exhaustive.

| Floor | Release | Guaranteed on every device at this floor |
|---|---|---|
| 21 | Android 5.0 | ART only; SELinux enforcing for all domains; WebView updated through Google Play independently of the OS; TLS 1.1 and 1.2 enabled by default for `SSLSocket` (since API 20) |
| 23 | Android 6.0 | Runtime permissions; Android Keystore symmetric keys and `KeyGenParameterSpec` with user-authentication binding; `Build.VERSION.SECURITY_PATCH`; `android:usesCleartextTraffic`; `PendingIntent.FLAG_IMMUTABLE`; verified App Links |
| 24 | Android 7.0 | Network Security Configuration (trust anchors, `cleartextTrafficPermitted`, `<pin-set>`); user-added CAs not trusted by default (**T** 24+); key attestation; file-based encryption with Direct Boot; APK Signature Scheme v2 |
| 26 | Android 8.0 | Per-source permission to install unknown apps; `ANDROID_ID` scoped per app signing key; Autofill framework |
| 28 | Android 9 | StrongBox-backed keys (where the hardware exists); `BiometricPrompt`; `setUnlockedDeviceRequired`; APK Signature Scheme v3; cleartext blocked by default (**T** 28+) |
| 29 | Android 10 | TLS 1.3 enabled by default; Conscrypt delivered as an updatable Mainline module; background activity launch restrictions; scoped storage (**T** 29+, opt-out possible); apps in the background can no longer read the clipboard |
| 30 | Android 11 | The task-affinity (StrandHogg) fixes, per Android's risk page; scoped storage enforced (**T** 30+); package visibility filtering (**T** 30+); one-time permissions; permission auto-reset |
| 31 | Android 12 | Touches passing through untrusted overlays are blocked; `setHideOverlayWindows()`; clipboard access notification; `exported` and `PendingIntent` mutability must be explicit (**T** 31+) |
| 33 | Android 13 | Sensitive clipboard flag (`ClipDescription.EXTRA_IS_SENSITIVE`); runtime receiver export flags; Play Integrity's `MEETS_STRONG_INTEGRITY` requires a security patch from the last year |
| 34 | Android 14 | Apps targeting below API 23 cannot be installed; read-only dynamic code loading (**T** 34+); implicit intents reach exported components only (**T** 34+) |
| 35 | Android 15 | Apps targeting below API 24 cannot be installed; TLS 1.0 and 1.1 disallowed (**T** 35+) |

Sources: the Android behaviour-change pages for each release, the [network security configuration guide](https://developer.android.com/privacy-and-security/security-config), the [StrandHogg risk page](https://developer.android.com/privacy-and-security/risks/strandhogg) and the [Play Integrity verdicts](https://developer.android.com/google/play/integrity/verdicts) page.

The column that matters most to a tester is the reverse: **what silently stops working below its API level**. When an app declares a protection and its floor is lower than the protection's API level, check what happens on the oldest supported device:

| Protection the app declares or calls | Needs | On older devices |
|---|---|---|
| `android:networkSecurityConfig` (pins, trust anchors, cleartext rules) | API 24 | Ignored. System **and user** CAs are trusted, cleartext is allowed, no pins |
| `android:usesCleartextTraffic="false"` | API 23 | Ignored |
| `KeyGenParameterSpec.setUserAuthenticationRequired()` | API 23 | No Keystore user-auth binding exists |
| `setIsStrongBoxBacked(true)` | API 28 | Not available; on 28+ devices without StrongBox the call throws `StrongBoxUnavailableException`, and many apps fall back to TEE or software keys |
| `BiometricPrompt` (AndroidX) with `DEVICE_CREDENTIAL` or `BIOMETRIC_STRONG or DEVICE_CREDENTIAL` | API 30 | Android's biometric guide lists both combinations as unsupported on API 29 and lower; on 23 to 27 AndroidX falls back to `FingerprintManager` |
| `Window.setHideOverlayWindows(true)` | API 31 | Overlays stay visible |
| Play Integrity `MEETS_STRONG_INTEGRITY` as a patch-recency signal | Android 13 | On Android 12 and lower the label does not require a recent patch |

The first row is the classic finding. A pinned banking app with `minSdk 23` is pinned on Android 7 and later and unpinned, with user CAs trusted, on Android 6. Android's own documentation now says that apps with a minimum API below 24 must set both `usesCleartextTraffic` and a configuration file ([Android 17 behaviour changes](https://developer.android.com/about/versions/17/behavior-changes-all)).

#### Runtime version checks and Jetpack fallbacks

Code that needs a newer API checks the running version first:

```kotlin
import android.os.Build

if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {        // API 28
    spec.setIsStrongBoxBacked(true)
}
val patch: String = Build.VERSION.SECURITY_PATCH            // "2026-10-05", API 23+
```

What you see in a release build:

- **Kotlin/Java source (jadx):** `Build.VERSION.SDK_INT >= 28`. Constants such as `Build.VERSION_CODES.P` are compile-time constants, so they appear as plain numbers.
- **smali (apktool):** `sget v0, Landroid/os/Build$VERSION;->SDK_INT:I` followed by a compare, and `Landroid/os/Build$VERSION;->SECURITY_PATCH:Ljava/lang/String;` for patch-level reads. This survives R8 renaming of app classes.
- **R8 artefacts:** R8 can drop checks that are always true for the app's `minSdk`, and it moves calls to newer APIs into synthetic classes whose names contain `ExternalSyntheticApiModelOutline`. Their presence shows where the app calls version-dependent APIs.
- **Annotations in source:** `@RequiresApi(28)`, `@TargetApi` and `@ChecksSdkIntAtLeast` mark version-gated code; lint's `NewApi` check flags calls above `minSdk` that are not gated.

Jetpack ("compat") libraries hide many of these checks: `ContextCompat`, `IntentCompat`, `ActivityCompat`, `androidx.biometric`. They pick the platform API when it exists and an older path otherwise. That is fine for functionality and a review point for security: always ask what the *older path* is. `androidx.biometric` on Android 6 to 8 uses `FingerprintManager`, which has no class-3/class-2 distinction; a compat call that writes a file has no scoped-storage protection on Android 9. Every AndroidX library is full of `SDK_INT` checks, which is why the mere presence of one (MASTG-TEST-0245's criterion) says almost nothing.

#### Security patch level and platform patches

The API level says which *release* a device runs, not whether it is *patched*. Android publishes a monthly [Android Security Bulletin](https://source.android.com/docs/security/bulletin). Each vulnerability table has an "Updated AOSP versions" column that tells you which releases still get fixes; check the latest bulletin for the current list rather than relying on a fixed number. Device makers ship those fixes with their own delay, and stop after their own support window.

The patch level the device claims is in `Build.VERSION.SECURITY_PATCH` (API 23+), a string in `YYYY-MM-DD` form, and in the `ro.build.version.security_patch` property. Two caveats:

- It is **self-reported** by the OS image. A rooted or custom ROM can report anything, and an app hook can change what the app sees. For decisions that matter, use a signal the TEE or Google vouches for: the `osPatchLevel` (and `vendorPatchLevel`, `bootPatchLevel`) fields of an [Android key attestation](https://developer.android.com/privacy-and-security/security-key-attestation) certificate, verified on your server, or Play Integrity's `MEETS_STRONG_INTEGRITY`, which on Android 13 and higher requires security updates in the last year for all partitions.
- Some components are patched **outside** the OS release: WebView and Chrome through Google Play (Android 5.0+), Mainline modules such as Conscrypt through Google Play system updates (Android 10+), and the GMS security provider through Google Play services ([MASWE-0026 TLS note](/mobile/maswe-0026-insecure-tls-protocol-versions/)). These reduce the gap for those components only. Kernel, driver and system-service bugs still need an OS update.

StrandHogg is the textbook "unfixable in the app" example. Android's risk page says the original task-affinity attack was patched in March 2019, a more comprehensive variant in September 2020, and that API 30 and newer contain the fixes; it recommends `minSdkVersion="30"`. The second variant (StrandHogg 2.0, [CVE-2020-0096](https://nvd.nist.gov/vuln/detail/CVE-2020-0096), disclosed by Promon and fixed for Android 8.0 to 9 in the May 2020 bulletin) could not be prevented by app configuration at all. Details and app-side mitigations for the first variant are in our [MASWE-0032](/mobile/maswe-0032-insecure-intents/) and [MASWE-0039](/mobile/maswe-0039-app-vulnerable-to-overlay-attacks/) notes.

### iOS: deployment target and the OS floor

#### Where the deployment target lives

In Xcode the floor is the **Minimum Deployments** setting (`IPHONEOS_DEPLOYMENT_TARGET` in build settings, `platforms: [.iOS(.v16)]` in a Swift package). At build time Xcode writes it to two places:

- **`MinimumOSVersion`** in the app's `Info.plist`. Apple's documentation says not to set it by hand, because Xcode fills it from the deployment target. The App Store uses it to decide which devices see the app. For macOS apps, including Mac Catalyst builds, the equivalent key is **`LSMinimumSystemVersion`**.
- **The Mach-O load commands** of every executable. Binaries with a deployment target of iOS 12 or later normally carry `LC_BUILD_VERSION` with a `minos` field (and an `sdk` field, see [MASWE-0042](/mobile/maswe-0042-latest-platform-version-not-targeted/)); older binaries carry `LC_VERSION_MIN_IPHONEOS` with `version` and `sdk`.

App extensions (`PlugIns/*.appex`) and embedded frameworks (`Frameworks/*.framework`) have their own `Info.plist` and their own `minos`. They can differ from the main app, and the lowest value tells you which code may run on the oldest OS.

#### Reading it from an IPA

```bash
mkdir ipa && cd ipa && unzip -q ../App.ipa
APP=$(ls -d Payload/*.app)

# Info.plist (binary plist; plutil prints it on macOS)
plutil -p "$APP/Info.plist" | grep -E '"MinimumOSVersion"|"LSMinimumSystemVersion"|"UIDeviceFamily"'
# "MinimumOSVersion" => "15.0"

# Mach-O load command of the main executable
EXE=$(plutil -extract CFBundleExecutable raw -o - "$APP/Info.plist")
otool -l "$APP/$EXE" | grep -A5 LC_BUILD_VERSION
#       cmd LC_BUILD_VERSION
#   cmdsize 32
#  platform 2
#     minos 15.0
#       sdk 26.0

# Every executable in the bundle: extensions and frameworks too
find "$APP" -type f -perm -u+x | while read -r f; do
  file "$f" | grep -q Mach-O && printf '%s\t%s\n' \
    "$(otool -l "$f" | awk '/LC_BUILD_VERSION/{f=1} f&&/minos/{print $2; exit}')" "$f"
done | sort -V
```

`platform 2` means iOS; recent `otool` versions and `vtool -show-build` print the name instead. Load commands sit in the unencrypted Mach-O header, so this works on FairPlay-encrypted App Store binaries without decrypting them. On Linux, `llvm-objdump --macho --private-headers` prints the same load commands, and Python's `plistlib` reads `Info.plist`.

#### What each iOS floor guarantees

As on Android, some iOS protections depend on the OS the app runs on and others on the SDK it was linked with ([MASWE-0042](/mobile/maswe-0042-latest-platform-version-not-targeted/)). The OS-dependent ones that matter most for a floor decision:

| Floor | Guaranteed on every device at this floor |
|---|---|
| iOS 9 | App Transport Security (for apps linked with the iOS 9 SDK or later, which is every current app) |
| iOS 10 | ATS honours the finer global exceptions (`NSAllowsArbitraryLoadsInWebContent`, `NSAllowsLocalNetworking`) and ignores `NSAllowsArbitraryLoads` when they are present |
| iOS 13 | CryptoKit, including `SecureEnclave.P256` keys; `URLSessionConfiguration.tlsMinimumSupportedProtocolVersion`; stricter requirements for trusted TLS certificates |
| iOS 14 | `NSPinnedDomains` (declarative pinning in `Info.plist`); App Attest (`DCAppAttestService`); local network privacy prompt |
| iOS 16 | Paste permission prompt and `UIPasteControl`; Lockdown Mode; passkeys |
| iOS 17 | ATS also covers connections to IP addresses; IP and CIDR keys accepted in `NSExceptionDomains` |

The reverse view again gives the findings: `NSPinnedDomains` in an app whose `MinimumOSVersion` is 13 means no pinning on iOS 13; App Attest behind `if #available(iOS 14, *)` with an empty `else` means no attestation on iOS 13; an IP-address ATS exception means nothing on iOS 16, where the connection was never covered. ATS details are in our [MASWE-0026 cleartext note](/mobile/maswe-0026-cleartext-network-traffic/).

#### Runtime availability checks

```swift
import Foundation
import DeviceCheck

if #available(iOS 14.0, *) {
    if DCAppAttestService.shared.isSupported { /* attest the key */ }
} else {
    // the review point: what happens here?
}

let v = ProcessInfo.processInfo.operatingSystemVersion          // majorVersion, minorVersion, patchVersion
let modern = ProcessInfo.processInfo.isOperatingSystemAtLeast(
    OperatingSystemVersion(majorVersion: 17, minorVersion: 0, patchVersion: 0))
```

`@available(iOS 14, *)` marks declarations; Objective-C uses `if (@available(iOS 14, *))`. `UIDevice.current.systemVersion` returns the version as a string and is common in older code. In a compiled binary the `#available` and `@available` checks become calls into availability-check helpers (the exact symbol depends on the toolchain; strings such as `_availability_version_check` or `SystemVersion.plist` are typical traces), while `operatingSystemVersion`, `isOperatingSystemAtLeastVersion:` and `systemVersion` appear as Objective-C selectors you can find with `strings`, `otool -ov` or r2 and hook with Frida.

iOS has no public API for a "security patch level". Apple ships fixes as point releases (and, from iOS 16, occasional Rapid Security Responses), so the patch state is the full version number compared against Apple's [security releases](https://support.apple.com/en-us/100100) list.

#### App Store distribution and old OS versions

- **The App Store filters by `MinimumOSVersion`.** Devices below it do not see the app or its updates.
- **Old builds stay reachable.** A user on an iOS version below a new build's floor can usually still download the *last compatible version* of an app they obtained before. Raising the deployment target therefore does not remove old app versions from old devices; it freezes them. Pair a higher floor with server-side minimum-app-version enforcement ([MASWE-0043](/mobile/maswe-0043-enforced-updating-not-implemented/)) if the old version must stop working.
- **Apple sets its own floor.** Apple's [upcoming requirements](https://developer.apple.com/news/upcoming-requirements/) page states that since **9 September 2026**, *"iOS and iPadOS apps uploaded to App Store Connect must target iOS 13 or later."* A current App Store build can therefore not have `MinimumOSVersion` below 13. A lower value tells you the build was uploaded before that date (and is at least that stale).
- **Older iOS versions get only some fixes.** Apple has shipped security updates for older major versions (for example the iOS 15.8.x and 16.7.x lines) for devices that cannot upgrade, but it does not commit to backporting every fix. Check Apple's security release notes for what an older line actually received before you treat it as supported.

## Tests

OWASP links one test to MASWE-0041: [MASTG-TEST-0245](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0245/) (Android, static). There is no iOS test, and no legacy (MASTG v1) test in OWASP's MASVS-CODE folders is replaced by it. MASTG-TEST-0245 only checks that version-checking code exists, so we add two Guler Tech tests: one that reads and judges the iOS deployment target (the Android floor is read in the first steps of MASTG-TEST-0245 below), and one that checks whether the app, or its backend, actually reacts to an unsupported OS or patch level.

### MASTG-TEST-0245: References to Platform Version APIs (Android)

Source: [MASTG-TEST-0245](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0245/). Platform: Android. Type: static (code). Demo: [MASTG-DEMO-0025](https://mas.owasp.org/MASTG/demos/android/MASVS-CODE/MASTG-DEMO-0025/MASTG-DEMO-0025/). Best practice: [MASTG-BEST-0010](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0010/) (not linked from the test's front matter, but the obvious companion).

#### Overview

The test looks for code that reads the running Android version, mainly `Build.VERSION.SDK_INT` compared with a `Build.VERSION_CODES` constant (`UPSIDE_DOWN_CAKE` is Android 14, API 34). OWASP's reasoning: `minSdkVersion` sets the hard floor, and runtime checks let the app use newer protections where they exist while staying compatible. The test fails if the app contains no version check at all.

That criterion is weak, and you should say so in a report. Almost every real app passes it trivially, because AndroidX, Kotlin coroutines, OkHttp and nearly every SDK contain dozens of `SDK_INT` checks. Presence proves nothing about whether the app *reacts* to an unsupported version. We therefore run the OWASP procedure, restrict it to app code, and add two questions it skips: **what is the floor**, and **what do the app's own checks do**.

#### Prerequisites

- The APK (and splits) pulled from a device or the store build you were given.
- jadx for decompilation and apktool for smali ([MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), reverse engineering), plus `aapt2` or `apkanalyzer`.
- semgrep ([MASTG-TOOL-0110](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/)) with the OWASP rule, or ripgrep ([MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), static analysis).
- The app's package prefix, so you can separate app code from library code.

#### Steps

1. **Read the floor and the target** (this is MASTG-TECH-0014's own example, done on the binary manifest):

   ```bash
   aapt2 dump badging app.apk | grep -E "sdkVersion|targetSdkVersion"
   ```

2. **Decompile** the app:

   ```bash
   jadx -d out app.apk
   apktool d app.apk -o apk_out
   ```

3. **Run the OWASP rule** (`mastg-android-sdk-version.yml`, which matches the expression `Build.VERSION.SDK_INT` in Java):

   ```yaml
   rules:
     - id: mastg-android-sdk-version
       languages:
         - java
       severity: WARNING
       metadata:
         summary: This rule scans for API that checks the version of the operating system
       message: "[MASVS-PLATFORM] Make sure to verify that your app runs on a device with an up-to-date OS version to make sure it satisfy your security requirements"
       patterns:
         - pattern: Build.VERSION.SDK_INT
   ```

   ```bash
   semgrep -c mastg-android-sdk-version.yml out/sources/com/example/app/ --text
   ```

   Point it at the app's own package, not the whole tree, or you will drown in AndroidX hits.

4. **Cover what the rule misses.** Patch-level reads, string version reads and obfuscated code:

   ```bash
   SRC=out/sources/com/example/app
   rg -n 'Build\.VERSION\.(SDK_INT|SECURITY_PATCH|RELEASE|BASE_OS)|VERSION_CODES\.' $SRC
   rg -n 'ro\.build\.version\.(sdk|security_patch|release)' out/sources/

   # smali survives class renaming: list app classes that read SDK_INT or SECURITY_PATCH
   rg -l 'Landroid/os/Build\$VERSION;->(SDK_INT|SECURITY_PATCH)' apk_out/smali*/ | grep -v -E '/(androidx|kotlin|kotlinx|com/google)/'
   ```

5. **Classify each hit in app code.** For each check, decide which of three kinds it is:
   - *Compatibility switch:* chooses between a new and an old API to get the same feature (most hits). Neutral.
   - *Protection fallback:* uses a protection on new versions and drops it on old ones (StrongBox, attestation, overlay hiding, biometric binding). A finding if the protected operation still runs.
   - *Policy check:* compares the version or patch level with a threshold and warns, restricts or blocks. This is what MASWE-0041 asks for.

6. **Compare the floor with the protections the app declares** (the "silently stops working" table in the [Background](#android-minsdkversion-and-the-platform-floor)):

   ```bash
   grep -nE 'networkSecurityConfig|usesCleartextTraffic' apk_out/AndroidManifest.xml
   ls apk_out/res/xml/ | grep -i network
   rg -n 'setIsStrongBoxBacked|setUserAuthenticationRequired|setUnlockedDeviceRequired|setHideOverlayWindows|BiometricPrompt' $SRC
   ```

#### Observation

The `minSdkVersion` and `targetSdkVersion`; the list of version and patch-level checks in app code with file, method and the classification from step 5; the protections whose API level is above the floor.

#### Evaluation

As written by OWASP, the test **fails** if the app contains no API call that checks the OS version. Apply it with two refinements, and state them in the report:

- The test **fails** if `minSdkVersion` admits Android releases that no longer receive security updates *and* the app's own code contains no policy check (step 5) that warns, restricts or blocks on those versions; or if a protection fallback lets a sensitive operation run without its protection on supported versions.
- It **passes** if the floor itself excludes unsupported releases and every protection the app depends on, or if a policy check (in the app or, per [GT-CODE-0041-2](#gt-code-0041-2-runtime-os-version-and-security-patch-level-enforcement-android-ios), on the server) handles the versions the floor still admits.

Library-only hits never make the test pass on their own.

#### Demo

[MASTG-DEMO-0025](https://mas.owasp.org/MASTG/demos/android/MASVS-CODE/MASTG-DEMO-0025/MASTG-DEMO-0025/) reads the version and returns it as a string:

```kotlin
class MastgTest(private val context: Context) {
    fun mastgTest(): String = "AndroidSdkVersion:${getSystemSdkVersion()}\n"
    fun getSystemSdkVersion(): Int = android.os.Build.VERSION.SDK_INT
}
```

semgrep on the decompiled class finds the read:

```text
MastgTest_reversed.java
❯❱ rules.mastg-android-sdk-version
      [MASVS-PLATFORM] Make sure to verify that your app runs on a device with an up-to-date OS version to
      make sure it satisfy your security requirements
       26┆ return Build.VERSION.SDK_INT;
```

OWASP marks the demo as a **pass** because the API is referenced. By our refinement it would not be: the value is read and displayed, but nothing is compared or enforced. (The rule's message also still carries a `[MASVS-PLATFORM]` tag, although the test belongs to MASVS-CODE.) A sample that would pass on substance looks like this:

```kotlin
private const val MIN_SUPPORTED_SDK = Build.VERSION_CODES.R          // 30
private const val MAX_PATCH_AGE_DAYS = 365L

fun platformPolicy(): Policy {
    if (Build.VERSION.SDK_INT < MIN_SUPPORTED_SDK) return Policy.BLOCK_SENSITIVE
    val patch = runCatching { LocalDate.parse(Build.VERSION.SECURITY_PATCH) }.getOrNull()
        ?: return Policy.WARN
    val age = ChronoUnit.DAYS.between(patch, LocalDate.now())
    return if (age > MAX_PATCH_AGE_DAYS) Policy.WARN else Policy.OK
}
```

### GT-CODE-0041-1: Minimum deployment target too low (iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

The iOS counterpart of the floor check. It reads the deployment target of every executable in the IPA and compares it with two references: the oldest iOS line that still receives security fixes, and the OS versions that provide the protections the app declares. Type: static. Profile: L2 and EUDIW (for L1 apps report as Info).

#### Prerequisites

- A decrypted or encrypted IPA (load commands are readable either way), or the `.app` from a test device.
- macOS with Xcode command-line tools (`plutil`, `otool`, `vtool`), or Linux with `llvm-objdump` and Python.
- Apple's [security releases](https://support.apple.com/en-us/100100) page, to see which iOS lines received fixes in the last few months.

#### Steps

1. **Read `MinimumOSVersion`** and the device families from the main `Info.plist`, then from every extension and framework:

   ```bash
   find Payload -name Info.plist -path '*.app*' | while read -r p; do
     printf '%s\t%s\n' "$(plutil -extract MinimumOSVersion raw -o - "$p" 2>/dev/null || echo '-')" "$p"
   done | sort -V
   ```

2. **Read `minos` from the Mach-O headers** with the loop from [Reading it from an IPA](#ios-deployment-target-and-the-os-floor). A framework whose `minos` is lower than the app's is harmless (the app's floor still applies); an extension with a lower `MinimumOSVersion` than the app is unusual and worth a note.

3. **Determine the supported iOS lines.** From Apple's security releases page, list the major versions that received a security update in roughly the last six months. Anything older is unsupported for this test.

4. **Compare the floor with declared protections:**

   ```bash
   plutil -p Payload/*.app/Info.plist | grep -E 'NSPinnedDomains|NSAppTransportSecurity|NSExceptionDomains'
   # $EXE is the CFBundleExecutable value read in the Background section
   strings -a Payload/*.app/"$EXE" | grep -E 'DCAppAttestService|appattest|SecureEnclave|CryptoKit' | sort -u
   ```

   Then look for the version gates around them (in the binary with r2 or Ghidra, or at runtime with the Frida script from [GT-CODE-0041-2](#gt-code-0041-2-runtime-os-version-and-security-patch-level-enforcement-android-ios)).

#### Observation

`MinimumOSVersion` and `minos` for the app, its extensions and frameworks; the list of iOS lines that currently receive fixes; protections whose minimum OS is above the floor; whether runtime checks or server checks cover the gap.

#### Evaluation

The test **fails** if:

- the floor admits iOS lines that no longer receive security fixes and neither the app nor its backend restricts sensitive functions on them ([GT-CODE-0041-2](#gt-code-0041-2-runtime-os-version-and-security-patch-level-enforcement-android-ios)); or
- a protection the app depends on (for example `NSPinnedDomains`, App Attest, Secure Enclave keys through CryptoKit) needs a newer iOS than the floor, and the app runs the protected operation without it on those versions.

It **passes** if the floor is within Apple's currently patched lines and covers every protection the app relies on, or if every gap is closed by a runtime or server-side policy. A `MinimumOSVersion` below 13 additionally tells you the build predates Apple's September 2026 upload rule; report it as a stale build.

#### Demo

A vulnerable configuration: declarative pinning with a floor that does not guarantee it.

```xml
<key>MinimumOSVersion</key>
<string>13.0</string>
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSPinnedDomains</key>
    <dict>
        <key>api.example.com</key>
        <dict>
            <key>NSIncludesSubdomains</key>
            <true/>
            <key>NSPinnedLeafIdentities</key>
            <array><!-- SPKI hashes --></array>
        </dict>
    </dict>
</dict>
```

```text
$ otool -l Payload/Example.app/Example | grep -A4 LC_BUILD_VERSION
      cmd LC_BUILD_VERSION
  cmdsize 32
 platform 2
    minos 13.0
```

`NSPinnedDomains` is honoured from iOS 14, so on iOS 13 `api.example.com` is not pinned. The same app would pass with `MinimumOSVersion` 14 or later (and a floor inside Apple's patched lines), or with code-level pinning that works on 13.

### GT-CODE-0041-2: Runtime OS version and security patch level enforcement (Android, iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

MASWE-0041's requirement is that the app *detects* an unsupported OS *and reacts*. This test checks for that reaction: a warning, a restriction of sensitive functions, or a block, decided either in the app or on the server. It observes only the app's own behaviour on test devices you control. Type: static and dynamic. Profile: L2 and EUDIW.

A note on the threat model before you start: the person on the old phone is the *victim*, not the attacker. A client-side check that a rooted user could hook away still protects the honest user, which is its purpose. Server-side signals (Play Integrity, key attestation) matter when you also want the decision to hold on a compromised device.

#### Prerequisites

- The floor from MASTG-TEST-0245 step 1 or GT-CODE-0041-1.
- **Android:** an emulator or device at the app's `minSdkVersion` (create an AVD with that system image), and ideally one with an old security patch level; Frida on a rooted test device.
- **iOS:** a test device on the oldest iOS the app supports, if available, and Frida on a jailbroken test device.
- An interception proxy to watch the app's API traffic ([traffic interception lab](/mobile/mobile-traffic-interception-lab/)).

#### Steps

1. **Find policy checks statically.** Android: the step 4 and 5 results of MASTG-TEST-0245, plus Play Integrity and attestation use:

   ```bash
   rg -n 'SECURITY_PATCH|StandardIntegrityManager|IntegrityManagerFactory|setAttestationChallenge' out/sources/
   ```

   iOS: the selectors and strings that read the version:

   ```bash
   strings -a Payload/*.app/"$EXE" | grep -E 'operatingSystemVersion|isOperatingSystemAtLeastVersion|systemVersion' | sort -u
   ```

2. **Observe what the app reads at runtime.** Android, logging only:

   ```javascript
   // version-read.js — frida -U -f com.example.app -l version-read.js
   Java.perform(function () {
     var V = Java.use('android.os.Build$VERSION');
     console.log('[device] SDK_INT=' + V.SDK_INT.value + ' SECURITY_PATCH=' + V.SECURITY_PATCH.value);
     var SP = Java.use('android.os.SystemProperties');
     SP.get.overload('java.lang.String').implementation = function (k) {
       var r = this.get(k);
       if (k.indexOf('ro.build.version') === 0) console.log('[SystemProperties.get] ' + k + ' = ' + r);
       return r;
     };
   });
   ```

   Field reads of `SDK_INT` cannot be hooked; the smali list from MASTG-TEST-0245 step 4 tells you where they are. iOS:

   ```javascript
   // ios-version-read.js — frida -U -f com.example.app -l ios-version-read.js
   ['- operatingSystemVersion', '- isOperatingSystemAtLeastVersion:', '- operatingSystemVersionString'].forEach(function (sel) {
     var m = ObjC.classes.NSProcessInfo[sel];
     if (!m) return;
     Interceptor.attach(m.implementation, {
       onEnter: function () {
         console.log('[NSProcessInfo ' + sel + ']\n' +
           Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0, 5).map(DebugSymbol.fromAddress).join('\n'));
       }
     });
   });
   Interceptor.attach(ObjC.classes.UIDevice['- systemVersion'].implementation, {
     onLeave: function (r) { console.log('[UIDevice systemVersion] ' + new ObjC.Object(r)); }
   });
   ```

3. **Run the app on the oldest supported version** (the AVD at `minSdk`, the oldest iOS device you have) and go through login, key enrolment and the most sensitive transactions. Note any warning, disabled feature or block.

4. **Simulate an old patch level (Android, optional).** On a test device running Android 16 or lower, spawn the app with a script that changes only what the app sees:

   ```javascript
   Java.perform(function () {
     Java.use('android.os.Build$VERSION').SECURITY_PATCH.value = '2019-01-05';
   });
   ```

   Do not change `SDK_INT`; the framework itself reads it and will misbehave. Android 17 makes `static final` fields unmodifiable for apps targeting API 37, and changing one through JNI crashes the app, so use a real old-patch device or emulator image for those apps.

5. **Check the server side.** In the proxy, look for the OS version in request headers or bodies (`User-Agent`, custom headers) and for Play Integrity tokens or attestation certificate chains sent at login. Replay a request with only the reported OS version changed to an old value and see whether the backend responds differently. This tests the backend's policy, not a bypass: a client-reported version is advisory, and the stronger design verifies `deviceAttributes.sdkVersion`, `MEETS_STRONG_INTEGRITY` or the attestation `osPatchLevel`.

#### Observation

The checks found (where, what threshold, what reaction); runtime evidence of the version reads with stack frames; the app's behaviour on the oldest supported OS and with an old patch level; the backend's response to an old reported version; whether an attested signal is used.

#### Evaluation

The test **fails** if the floor admits OS versions or patch levels the app owner considers unsupported (or, without such a policy, OS lines that no longer receive security updates) and neither the app nor its backend reacts: sensitive operations run exactly as on a current device. It also fails if the only reaction is a check whose fallback *weakens* security (skips attestation, uses software keys) instead of restricting the operation.

It **passes** if, on unsupported versions or stale patch levels, the app or backend warns the user and restricts or blocks high-risk operations, and that decision is documented. A server-side decision based on Play Integrity or key attestation is the strongest pass.

#### Demo

Vulnerable pattern: the version is checked, but the fallback removes the protection.

```kotlin
fun createSigningKey(alias: String) {
    val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
        .setDigests(KeyProperties.DIGEST_SHA256)
        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            .setUserAuthenticationRequired(true)
    }
    // else: key usable without any user authentication on API 23-29
    KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        .apply { initialize(builder.build()) }.generateKeyPair()
}
```

Detection with ripgrep on the decompiled code, and the trace from step 2 on an Android 10 emulator:

```text
$ rg -n -A3 'SDK_INT >= 30' out/sources/com/example/app/crypto/
KeyFactory.java:41:        if (Build.VERSION.SDK_INT >= 30) {
KeyFactory.java:42-            builder.setUserAuthenticationParameters(0, 2).setUserAuthenticationRequired(true);

[device] SDK_INT=29 SECURITY_PATCH=2021-09-01
(no warning shown; transaction signing completed without a biometric prompt)
```

The fix is to bind the key on API 23 to 29 as well, with the older API (`setUserAuthenticationRequired(true)` plus `setUserAuthenticationValidityDurationSeconds(-1)` for per-use biometric authentication), or to refuse key enrolment there. "No authentication" is never the fallback.

## Best practices

### MASTG-BEST-0010: Use Up-to-Date minSdkVersion

Source: [MASTG-BEST-0010](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0010/). Platform: Android.

The best practice asks developers to set `minSdkVersion` as high as their user base allows, and makes three points worth keeping:

- **The floor is a security decision.** Google Play enforces a minimum *target* API, not a minimum *min* API, so nobody else will raise the floor for you.
- **`targetSdkVersion` does not protect old devices.** An app with `targetSdk 33` and `minSdk 21` still installs on Android 5, which lacks years of fixes and protections.
- **"Targeting" in Android's documentation often means "targeting and running on".** The network security configuration page says cleartext is disabled by default from Android 9; that applies only to apps that target API 28+ *and* run on API 28+ devices. On API 24 to 27 devices, the platform's own default (cleartext allowed) applies whatever the target. This is correct, and it is a good example of why the floor matters.

Corrections we apply when using BEST-0010's version timeline:

- Android 4.2 is API **17**, not 16 (4.1 is API 16). SELinux arrived in Android 4.3 in permissive mode, was partly enforcing in 4.4, and fully enforcing from 5.0 ([AOSP SELinux overview](https://source.android.com/docs/security/features/selinux)).
- Android 7.0 is API 24 and 7.1 is API 25; Android 8.0 is API 26 and 8.1 is API 27. The page's ranges merge two releases each.
- Android 9 did not give "default HTTPS for all apps": only apps targeting API 28 on Android 9+ (the page itself explains this further down). Android 10 *enabled* TLS 1.3 by default; it does not *enforce* it.
- `targetSdkVersion` is the API level the app has been tested against and opts into, not "the highest API level the app is designed to run on" (that would be `maxSdkVersion`, which should not be used).
- Android 16 is no longer beta, and Android 17 (API 37) is published.

### Secure implementation (Guler Tech)

**Choose the floor deliberately.** Write down which OS versions the app supports and why, and review it every year. For L2 and EUDIW apps, start from: Android at least API 30 (Android's own StrandHogg guidance) and within the releases listed in the current security bulletin; iOS within the lines Apple patched in the last months. Then raise it further if a protection you depend on needs it.

**Map protections to versions.** For each protection in the threat model (pinning, attestation, hardware keys, biometric binding, overlay hiding), record the minimum OS that provides it. If it is above the floor, decide per protection: raise the floor, or restrict the protected operation below that version.

**Fail closed in fallbacks.**

```kotlin
val canUseStrongAuthKey = Build.VERSION.SDK_INT >= Build.VERSION_CODES.R
if (!canUseStrongAuthKey) {
    showUnsupportedDeviceNotice()        // explain and offer a safer channel
    return                               // do not enrol a weaker key
}
```

```swift
guard #available(iOS 14.0, *), DCAppAttestService.shared.isSupported else {
    presentUnsupportedDeviceNotice()     // no silent downgrade to an unattested session
    return
}
```

**Decide on the server.** For high-value operations, verify Play Integrity verdicts with `deviceAttributes` and `MEETS_STRONG_INTEGRITY` opted in, or verify a key attestation chain and its `osPatchLevel`, and apply a documented policy (allow, step up, restrict, block). On iOS, combine the reported OS version with App Attest and a server-side minimum app version.

**Tell the user why.** A clear notice ("Your phone no longer receives security updates. Payments are disabled on this device.") is part of "reacts appropriately". Silent failure leads users to sideload old app versions.

## Rating findings

Rate on four things: **the profile** (L1 apps: Info at most), **how old the oldest admitted OS is** (still patched, recently unsupported, years unsupported), **which protections are lost** on those versions, and **what the app does there** (nothing, weakened fallback, restriction). The attacker is a malicious app on the same device (MAS-ATTACK-0054) or a network attacker who benefits from missing defaults (MAS-ATTACK-0055); the user needs no further interaction beyond using the app, but must be on an old OS, which limits the affected population. Use your client's analytics for that share when you have it.

| Rating | Conditions |
|---|---|
| **Critical** | Rarely justified for this weakness alone. Use it only when a version fallback disables a control that protects authentication material or transaction signing for *all* users on admitted versions and a known public exploit for those versions reaches the app's data (chain the finding with that platform CVE). |
| **High** | L2/EUDIW app whose floor admits OS versions without the protections its design relies on, and the protected operation still runs: NSC pinning or trust anchors with `minSdk` below 24 (user CAs trusted, no pins), `NSPinnedDomains` below iOS 14, attestation or hardware-bound user-authenticated keys skipped by a version fallback. |
| **Medium** | L2/EUDIW app whose floor admits Android releases or iOS lines that no longer receive security updates (for Android, anything below API 30 given StrandHogg), with no warning, restriction or server-side policy; or a policy check exists but only warns on high-risk operations. |
| **Low** | Floor admits unsupported versions but sensitive operations are restricted there, or the gap is closed only by a client-side check while a server-side signal would be expected for the profile; protection fallbacks that affect non-sensitive features. |
| **Info** | L1 apps with a low floor; floors within currently patched releases; library-only `SDK_INT` hits; stale-build observations such as `MinimumOSVersion` below 13. |

Raise a level when the app's own data or design makes the missing protection central (a wallet whose credentials depend on hardware-bound keys) or when the old-OS share of real users is large. Lower a level when the business has documented the risk acceptance and shows the user a warning. In the report give the floor (`minSdkVersion` or `MinimumOSVersion`/`minos`), the target or SDK, the specific OS versions affected, the protection lost on each with its documentation link, the code location of any fallback, and the runtime evidence from the oldest supported OS.

## References

- OWASP MASWE: [MASWE-0041: Running on a Recent Platform Version Not Ensured](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0041/); related [MASWE-0042](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0042/), [MASWE-0043](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0043/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-CODE-1](https://mas.owasp.org/MASVS/controls/MASVS-CODE-1/) (CC BY-SA 4.0)
- OWASP MASTG test and demo: [MASTG-TEST-0245](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0245/), [MASTG-DEMO-0025](https://mas.owasp.org/MASTG/demos/android/MASVS-CODE/MASTG-DEMO-0025/MASTG-DEMO-0025/) (CC BY-SA 4.0)
- OWASP MASTG best practice: [MASTG-BEST-0010](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0010/) (CC BY-SA 4.0)
- OWASP MASTG techniques and tools: [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/) (CC BY-SA 4.0)
- Guler Tech notes: [MASVS-CODE guide](/mobile/masvs-code-code-quality-guide/), [MASWE-0042](/mobile/maswe-0042-latest-platform-version-not-targeted/), [MASWE-0043](/mobile/maswe-0043-enforced-updating-not-implemented/), [MASWE-0026 cleartext](/mobile/maswe-0026-cleartext-network-traffic/), [MASWE-0026 TLS versions](/mobile/maswe-0026-insecure-tls-protocol-versions/), [MASWE-0032](/mobile/maswe-0032-insecure-intents/), [MASWE-0039](/mobile/maswe-0039-app-vulnerable-to-overlay-attacks/)
- Android Developers: [`<uses-sdk>` element](https://developer.android.com/guide/topics/manifest/uses-sdk-element), [Network security configuration](https://developer.android.com/privacy-and-security/security-config), [StrandHogg risk page](https://developer.android.com/privacy-and-security/risks/strandhogg), [Unsafe Download Manager risk page](https://developer.android.com/privacy-and-security/risks/unsafe-download-manager), [Key attestation](https://developer.android.com/privacy-and-security/security-key-attestation), [Play Integrity verdicts](https://developer.android.com/google/play/integrity/verdicts), [`Build.VERSION`](https://developer.android.com/reference/android/os/Build.VERSION)
- Android behaviour changes: [Android 14 (all apps)](https://developer.android.com/about/versions/14/behavior-changes-all), [Android 15 (all apps)](https://developer.android.com/about/versions/15/behavior-changes-all), [Android 15 (target 35)](https://developer.android.com/about/versions/15/behavior-changes-15), [Android 17 (all apps)](https://developer.android.com/about/versions/17/behavior-changes-all), [Android 17 (target 37)](https://developer.android.com/about/versions/17/behavior-changes-17)
- Android Open Source Project: [Android Security Bulletins](https://source.android.com/docs/security/bulletin), [SELinux overview](https://source.android.com/docs/security/features/selinux)
- Apple Developer: [`MinimumOSVersion`](https://developer.apple.com/documentation/bundleresources/information-property-list/minimumosversion), [`NSAppTransportSecurity`](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity), [`NSAllowsLocalNetworking`](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity/nsallowslocalnetworking), [`ProcessInfo.operatingSystemVersion`](https://developer.apple.com/documentation/foundation/processinfo/operatingsystemversion), [Upcoming requirements](https://developer.apple.com/news/upcoming-requirements/); Apple Support: [Apple security releases](https://support.apple.com/en-us/100100)
- NVD: [CVE-2020-0096](https://nvd.nist.gov/vuln/detail/CVE-2020-0096) (StrandHogg 2.0)
- CWE: [CWE-451](https://cwe.mitre.org/data/definitions/451.html), [CWE-693](https://cwe.mitre.org/data/definitions/693.html), [CWE-1104](https://cwe.mitre.org/data/definitions/1104.html), [CWE-1357](https://cwe.mitre.org/data/definitions/1357.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
