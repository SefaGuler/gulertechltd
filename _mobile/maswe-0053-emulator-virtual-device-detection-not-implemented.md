---
title: "MASWE-0053: Emulated or Virtual Device Detection Not Implemented"
date: 2026-11-10 20:02:00 +0000
subcategory: resilience
summary: "Android emulator, iOS Simulator, Corellium-style virtual device and Apple silicon Mac detection: signals, false positives, Frida tracing and rating."
refs: [MASWE-0053, MASVS-RESILIENCE-1, MASVS-RESILIENCE-4]
tags: [android, ios, masvs-resilience, emulator-detection, virtual-devices, frida]
---

This note is part of our [MASVS-RESILIENCE guide](/mobile/masvs-resilience-resilience-testing-guide/) and covers OWASP [MASWE-0053](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0053/): an app that does not notice it is running on an emulator, a cloud phone, a virtual iOS device or a desktop. Emulators are where reverse engineers work, because everything is visible and everything can be snapshotted and reset. They are also where bot farms run, because a thousand emulated phones cost less than ten real ones. Emulator detection makes both a little harder. It is also one of the most over-rated controls in mobile security: every local signal can be faked by someone who builds their own system image, and the controls that actually stop emulator fleets live on the server. Below you get the four OWASP Knowledge pages on Android emulators, the iOS Simulator, iOS virtual devices and iPhone apps on Macs, with what they leave out; the two OWASP tests (Frida tracing of the app's own checks) plus our own static and response tests; the two OWASP best practices; and how to rate what you find. Like every control in this series, emulator detection is defence in depth that raises an attacker's cost. It never replaces the L1/L2 controls, and a client-side check without a server-side decision will be bypassed eventually.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: Emulator Detection (MASTG-KNOW-0031)](#android-emulator-detection-mastg-know-0031)
  - [iOS: Simulator Detection (MASTG-KNOW-0088)](#ios-simulator-detection-mastg-know-0088)
  - [iOS: Virtual Devices Detection (MASTG-KNOW-0135)](#ios-virtual-devices-detection-mastg-know-0135)
  - [iOS: iOS Apps Running on macOS Detection (MASTG-KNOW-0136)](#ios-ios-apps-running-on-macos-detection-mastg-know-0136)
  - [Generic: Emulation-based Dynamic Analysis (MASTG-KNOW-0112)](#generic-emulation-based-dynamic-analysis-mastg-know-0112)
- [Tests](#tests)
  - [GT-RES-0053-1: Static identification of emulator and virtual device checks (Android and iOS)](#gt-res-0053-1-static-identification-of-emulator-and-virtual-device-checks-android-and-ios)
  - [MASTG-TEST-0351: Runtime Use of Emulator Detection Techniques (Android)](#mastg-test-0351-runtime-use-of-emulator-detection-techniques-android)
  - [MASTG-TEST-0367: Runtime Use of Virtual Device Detection Techniques (iOS)](#mastg-test-0367-runtime-use-of-virtual-device-detection-techniques-ios)
  - [GT-RES-0053-2: Response and strength of emulator and virtual device detection (Android and iOS)](#gt-res-0053-2-response-and-strength-of-emulator-and-virtual-device-detection-android-and-ios)
- [Best practices](#best-practices)
  - [MASTG-BEST-0046: Hardening Against Emulation (Android)](#mastg-best-0046-hardening-against-emulation-android)
  - [MASTG-BEST-0053: Hardening Against Virtual Devices (iOS)](#mastg-best-0053-hardening-against-virtual-devices-ios)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

The OWASP requirement is *"The app detects when it is running in an emulated or virtual device environment."* It maps to MASVS-RESILIENCE-1 ("The app validates the integrity of the platform") and MASVS-RESILIENCE-4 ("The app implements anti-dynamic analysis techniques"), and to the v1 requirements MSTG-RESILIENCE-5 and MSTG-RESILIENCE-8. OWASP gives no CWE. The closest fit is [CWE-693](https://cwe.mitre.org/data/definitions/693.html) (Protection Mechanism Failure), and you can use it if your report template needs one.

The weakness carries OWASP's **R** profile and the **EUDIW** profile. It is in scope when the threat model includes reverse engineering on attacker-controlled devices or automated abuse: banking, payments, wallets, games with an economy, ticketing, apps whose sign-up or promotion flows attract bots. For an app without that threat model, missing emulator detection is an observation.

OWASP describes the threat as MAS-THREAT-0053, *"Attackers can analyze and automate the app in a fully controlled environment"*, reached through MAS-ATTACK-0066 (*"Running the app in an emulator or virtual device"*) and MAS-ATTACK-0003 (*"Using dynamic instrumentation"*). The two attacks describe two different attackers, and the distinction is useful for rating:

| Attacker | What the emulator gives them | What actually stops them |
|---|---|---|
| Reverse engineer analysing one app | Full visibility, root by default on many images, snapshots, easy instrumentation | Nothing stops them; detection only adds work. They can also move to a real rooted device |
| Fraud operator running many instances | Cheap scale, scripting, fresh "devices" on demand | Server-side attestation, device and account velocity rules, risk scoring |

Four kinds of environment fall under this weakness, and they need different checks:

| Environment | Runs | Typical examples |
|---|---|---|
| Android emulator | An Android system image on emulated or virtualized hardware | Android Studio AVD, Genymotion, consumer "app players", Cuttlefish, Corellium Android |
| Android in containers and cloud phones | Android user space in a container or VM on a server or PC, often with ARM-to-x86 translation | Cloud phone services, Android-in-container projects, ChromeOS, Google Play Games for PC |
| iOS Simulator | Simulator builds of the app on macOS. Not device binaries | Xcode Simulator |
| iOS virtual device | iOS device binaries on a virtualized iPhone | Corellium; research projects based on Apple's virtualization stack |
| iPhone and iPad app on a Mac | The App Store device binary on an Apple silicon Mac, through Apple's official channel | Any Mac with Apple silicon, unless the developer opted out |

Keep the neighbouring topics apart:

| Question | Where it lives |
|---|---|
| Does the app notice an emulator, virtual device or Mac? | This note (MASWE-0053) |
| Does the app notice root or a jailbreak? Emulator images are often rooted | [MASWE-0051](/mobile/maswe-0051-root-jailbreak-detection-not-implemented/) |
| Does the app notice it is running inside another app on a real phone? | [MASWE-0052](/mobile/maswe-0052-app-virtualization-detection-not-implemented/) |
| Does the backend get server-verified proof of a genuine device (Play Integrity, key attestation, App Attest)? | [MASWE-0054](/mobile/maswe-0054-device-attestation-not-implemented/) and [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/) |
| Does the app notice Frida, debuggers and hooks, which come with emulators? | [MASWE-0064](/mobile/maswe-0064-debugger-detection-not-implemented/) and [MASWE-0065](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/) |

The tests in this note replace the legacy v1 tests MASTG-TEST-0049 (Android, "Testing Emulator Detection", `covered_by: MASTG-TEST-0351`) and MASTG-TEST-0092 (iOS, "Testing Emulator Detection", `covered_by: MASTG-TEST-0367`). The legacy tests asked a question the new ones leave out on purpose: how hard is the detection to bypass? We keep that question in GT-RES-0053-2.

## Modes of Introduction

**No checks at all.** The app runs the same way on an AVD as on a phone.

**One signal, usually `Build.FINGERPRINT`.** A single string comparison against `generic` or `sdk` finds the stock AVD and nothing else. Custom images, consumer emulators that copy real device fingerprints, and anyone who edits `build.prop` get through.

**Out-of-date signal lists.** Copied lists of emulator values age badly. The telephony numbers and `Build.ID` values in most public lists come from emulator images that are ten years old. Newer emulator images can return different values (see the demo output below).

**Checks that cannot fire in a shipped build.** On iOS, `#if targetEnvironment(simulator)` is decided by the compiler. A device build never contains the code inside it. Teams that think they have "simulator detection" because of such a block have nothing in the App Store binary.

**Detection with no response, or a response only on the client.** The app computes the result and continues, or shows a dialog that a one-line hook removes, while the backend never learns about it.

**Blocking legitimate virtual environments.** ChromeOS devices and Google Play Games for PC run Android apps in virtualized environments for real users, and iPhone apps run on Apple silicon Macs through Apple's own store. Blocking them is a product decision, not an automatic security win.

## Impact

- **Cheaper reverse engineering.** Snapshots let an attacker try a bypass, roll back, and try again in seconds. Emulators make instrumentation, memory inspection and traffic interception routine.
- **Automation at scale.** Emulator and cloud-phone fleets drive sign-up fraud, credential stuffing through the real app, promotion and referral abuse, fake engagement, and in games, farming and cheating.
- **Weakened device-based risk scoring.** Fresh emulator instances look like fresh devices. If the backend trusts client-reported device identifiers, every reset is a new customer.
- **Lower cost of attacking the app's other defences.** Root detection, debugger detection and pinning can be studied and defeated on an emulator first, then the bypass is carried over to real devices.

## Mitigations

- **Combine several independent local signals** across categories: system properties, hardware features and sensors, graphics, file artefacts, CPU architecture. A single value is trivial to fake. A consistent picture across categories is not.
- **Prefer server-verified attestation.** On Android, Play Integrity's device verdict and key attestation; on iOS, App Attest. Emulators and virtual devices fail these in ways the client cannot hide (see [MASWE-0054](/mobile/maswe-0054-device-attestation-not-implemented/)).
- **Respond on the server.** Send local signals with sensitive requests and let the backend decide: step-up verification, lower limits, blocked promotions, or refusal. Do not reveal which check fired.
- **Harden the checks themselves.** Obfuscate them, run them at different times and in different code paths, and duplicate key ones in native code ([MASWE-0059](/mobile/maswe-0059-code-obfuscation-not-implemented/)).
- **Allow legitimate virtual environments explicitly**, or block them deliberately with a documented reason.
- **Retest against current emulators** on every release. Signal lists rot.

## Knowledge

OWASP links no Knowledge pages from the weakness itself. The tests reference MASTG-KNOW-0031 (Android) and MASTG-KNOW-0135 (iOS), and the best practices add MASTG-KNOW-0088 and MASTG-KNOW-0136. MASTG-KNOW-0112 is a short generic page on emulation-based analysis and gets a summary.

### Android: Emulator Detection (MASTG-KNOW-0031)

Source: [MASTG-KNOW-0031](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0031/).

The aim of emulator detection is not to make emulation impossible. It is to force the analyst either to defeat the checks or to move to physical hardware, which is slower and costs more per instance. Anyone willing to build a custom AOSP image with realistic properties and hardware stubs will get past local checks, so treat everything below as signals that feed a decision, not as a decision.

#### Inspect the environment first

Before you read an app's checks, look at what your own emulator exposes. Most checks are reading the same values you can see from `adb`:

```bash
adb shell getprop | grep -iE 'qemu|goldfish|ranchu|vbox|genymotion|emulator|sdk_gphone|native.bridge|abilist|build.tags|build.type|characteristics'
adb shell 'ls -l /dev/qemu_pipe /dev/goldfish_pipe /dev/socket/qemud /dev/socket/genyd /sys/qemu_trace 2>&1'
adb shell dumpsys sensorservice | grep -iE 'goldfish|vendor' | head
adb shell uname -m
```

Illustrative output from an Android Studio AVD with a Google Play image on an Apple silicon Mac:

```text
[ro.boot.qemu]: [1]
[ro.build.characteristics]: [emulator]
[ro.build.tags]: [release-keys]
[ro.build.type]: [user]
[ro.hardware]: [ranchu]
[ro.product.model]: [sdk_gphone64_arm64]
[ro.product.cpu.abilist]: [arm64-v8a]
```

Note the last four lines. Google Play system images are `user` builds signed with `release-keys`, so the classic `test-keys` and `userdebug` checks miss them. Google APIs images without Play are `userdebug` builds with `test-keys` and allow `adb root`.

#### System properties and Build fields

Android builds the `android.os.Build` fields from system properties when the zygote starts, so `Build.FINGERPRINT` is `ro.build.fingerprint`, `Build.HARDWARE` is `ro.hardware`, and so on. Apps read them either through [`android.os.Build`](https://developer.android.com/reference/android/os/Build) or directly, through the hidden `android.os.SystemProperties` class, reflection, or the native `__system_property_get()` in bionic.

| Source | Example emulator values | Notes |
|---|---|---|
| `ro.kernel.qemu`, `ro.boot.qemu` | `1` | Set by the Android emulator. Older images use `ro.kernel.qemu`, newer ones `ro.boot.qemu`; check both. Not exposed through `Build` |
| `ro.hardware`, `Build.HARDWARE` | `goldfish` (old emulator), `ranchu` (current emulator), `vbox86` (VirtualBox-based emulators), vendor strings of consumer emulators | One of the more reliable fields, because apps and HALs depend on it |
| `Build.FINGERPRINT` | starts with `generic`, contains `generic/sdk/generic`, `sdk_gphone`, `vbox86p`, `test-keys` | Consumer emulators often copy a real phone's fingerprint |
| `Build.MODEL`, `Build.PRODUCT`, `Build.DEVICE` | `sdk`, `google_sdk`, `sdk_gphone64_arm64`, `emu64a`, `Android SDK built for x86`, `vbox86p`, names of consumer emulators | Normalise to lower case |
| `Build.MANUFACTURER`, `Build.BRAND`, `Build.BOARD` | `unknown`, `generic`, `goldfish_arm64`, emulator vendor names | `Build.BOARD=unknown` also appears on some real budget devices |
| `Build.TAGS`, `ro.build.type` | `test-keys`, `userdebug`, `eng` | Also true for many custom ROMs on real phones, and false for Play images |
| `Build.USER` | `android-build` | Google's build servers; weak |
| `Build.ID` | `FRF91` | Android 2.2 era. Irrelevant on anything current |
| `ro.build.characteristics` | `emulator` | Set on many AVD images; a single property, easy to change on a rooted image |
| `ro.product.cpu.abilist`, `ro.dalvik.vm.native.bridge` | `x86_64,arm64-v8a` with a bridge such as `libndk_translation.so` or `libhoudini.so` | ARM translation on x86 hosts; see below |

Three pitfalls:

- `Build.SERIAL` is deprecated and returns `unknown` for apps targeting Android 8.0 (API 26) or higher, on every device. `Build.getSerial()` needs `READ_PRIVILEGED_PHONE_STATE` from Android 10 and is not available to normal apps. Neither is an emulator signal any more.
- `Build.RADIO` is deprecated; use `Build.getRadioVersion()`. Wi-Fi-only tablets also return an empty value.
- Values a user can change on a rooted image (anything in `build.prop`, any property settable through `resetprop`-style tooling) are cheap to fake. Prefer signals that would break the system if changed, such as `ro.hardware`, which selects HAL implementations.

#### Telephony characteristics

The old Android emulator returned fixed values through [`TelephonyManager`](https://developer.android.com/reference/android/telephony/TelephonyManager): `getLine1Number()` returned `15555215554` (and other even numbers up to `15555215584`, one per emulator port), `getNetworkOperatorName()` returned `Android`, and `getVoiceMailNumber()` returned `15552175049`.

Values vary by image and many newer images return different, more realistic-looking ones. OWASP's own demo output, from an Android 16 (LineageOS-based) emulator image, shows `+15551234567`, an operator name of `T-Mobile`, MCC/MNC `310260` and a voicemail number of `+15557654321`. The old list does not match them. The `555` prefix and the operator code `310260` are the patterns to look at, and both are weak: telephony values are easy to set on emulators and genuinely vary on real devices.

Permissions limit what an app can read:

- Check telephony only when the device declares [`FEATURE_TELEPHONY`](https://developer.android.com/reference/android/content/pm/PackageManager#FEATURE_TELEPHONY) (or `FEATURE_TELEPHONY_CALLING` for calling APIs). Tablets and Chromebooks legitimately lack it.
- `getLine1Number()` needs `READ_PHONE_NUMBERS` (or `READ_SMS`, default SMS app status, or carrier privileges) and is deprecated from Android 13 in favour of `SubscriptionManager.getPhoneNumber(int)`. `getVoiceMailNumber()` needs `READ_PHONE_STATE`.
- Since Android 10, non-resettable identifiers (IMEI, MEID, SIM serial, subscriber ID, `Build.getSerial()`) need `READ_PRIVILEGED_PHONE_STATE`, which ordinary apps cannot hold. Apps targeting API 29 or higher get a `SecurityException`. An app that asks for phone permissions purely to detect emulators is also a privacy finding waiting to happen.

#### Installed packages and launcher activities

Consumer emulators ship helper apps with recognisable package names: OWASP lists prefixes and names such as `com.bluestacks`, `com.bignox.`, `com.nox.mopen.app`, `com.microvirt.`, `com.vphone.`, `me.haima.`, `cn.itools.`, `com.kaopu.` and `com.google.android.launcher.layouts.genymotion`.

On Android 11 (API 30) and later, [package visibility](https://developer.android.com/training/package-visibility) filtering hides other apps unless the app declares them in `<queries>` or holds `QUERY_ALL_PACKAGES` (restricted by Google Play policy). A hidden package looks exactly like an absent one: `getPackageInfo()` throws `NameNotFoundException`. So a package-based check without matching `<queries>` entries silently never fires. Declaring the packages, or the `MAIN`/`LAUNCHER` intent, fixes visibility:

```xml
<queries>
    <package android:name="com.bignox.app" />
    <intent>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
    </intent>
</queries>
```

The `<queries>` block is itself a useful static finding: it tells you exactly which emulator packages the app looks for.

[`ActivityManager.getRunningServices()`](https://developer.android.com/reference/android/app/ActivityManager#getRunningServices%28int%29) only returns the caller's own services since Android 8.0, so checks for emulator services through it are dead code on any current device.

#### File system artefacts

Emulators expose device nodes, sockets and binaries that real devices do not have:

| Path | Belongs to |
|---|---|
| `/dev/qemu_pipe`, `/dev/goldfish_pipe` | QEMU pipe devices of the Android emulator |
| `/dev/socket/qemud` | Old emulator daemon socket |
| `/sys/qemu_trace` | Old emulator trace marker |
| `/system/bin/qemu-props`, `/vendor/bin/qemu-props` | Emulator property service (the location moved to `/vendor` on newer images) |
| `/dev/socket/genyd`, `/dev/socket/baseband_genyd` | Genymotion daemons |

Two details matter for both developers and testers. First, SELinux prevents untrusted apps from looking at many of these paths, so `File.exists()` can return `false` on an emulator because access was denied, not because the file is absent. A native `stat()` or `access()` that distinguishes `ENOENT` from `EACCES` gives a better signal: "permission denied" for a path that does not exist on real phones is itself telling. Second, paths change between emulator generations, so lists need maintenance.

#### Sensors, graphics and hardware behaviour

Hardware is harder to fake well than strings:

- **Sensors.** `SensorManager.getSensorList(Sensor.TYPE_ALL)` on the AVD returns sensors with names such as "Goldfish 3-axis Accelerometer". Many emulators have no gyroscope, magnetometer or barometer at all, or sensors whose readings never change. Readings with no noise over several seconds are a behavioural signal that is costly to fake convincingly.
- **OpenGL renderer.** Read `GLES20.glGetString(GL_RENDERER)` with a current EGL context. The AVD reports a renderer containing `Android Emulator OpenGL ES Translator` (often with SwiftShader or ANGLE in the string), and some consumer emulators include their own name. Real devices report Adreno, Mali, PowerVR, Xclipse and similar GPU names.
- **Camera, battery and thermal.** Virtual camera devices, a battery that is always charging at a fixed level, and missing thermal zones are softer signals.
- **CPU.** `Os.uname().machine` (the kernel's architecture) versus the ABI the app's native code was loaded as. An `x86_64` kernel running your `arm64-v8a` library means binary translation (next section).

#### ARM translation, cloud phones and containers

Many emulators run on x86 hosts. To run apps that ship only ARM native code, they use a **native bridge** that translates ARM instructions to x86: Google's `libndk_translation.so` or Intel's `libhoudini.so`. The bridge is named in `ro.dalvik.vm.native.bridge` (which is `0` when there is none), and `ro.product.cpu.abilist` lists both x86 and ARM ABIs. On a phone with an ARM SoC there is no bridge.

**Cloud phones** run Android in containers or VMs on servers, increasingly on ARM servers where no translation is needed. They often lack sensors, telephony and cameras, and they share kernel features with the host. **Android-in-container** projects on Linux desktops look similar. **ChromeOS** runs Android apps in a VM for real users, and **Google Play Games for PC** runs them in a Google-built emulator, also for real users. (Microsoft's Windows Subsystem for Android, which used to be in this list, was discontinued in March 2025.) Decide deliberately whether those are allowed; ChromeOS declares ARC-specific system features you can test for with `hasSystemFeature`.

#### Google Play Integrity: the stronger signal

Local checks are things the attacker controls. The [Play Integrity API](https://developer.android.com/google/play/integrity/verdicts) is evaluated by Google Play services and verified by your server. Per Google's documentation, an empty `deviceRecognitionVerdict` means the device shows signs of attack or compromise *"or the app is not running on a physical device (such as an emulator that does not pass Google Play integrity checks)"*. The only emulator label is `MEETS_VIRTUAL_INTEGRITY`, returned for Google Play Games for PC to apps released there. On Android 13 and higher, `MEETS_BASIC_INTEGRITY` also needs a key attestation root of trust provided by Google, which emulators are not expected to have.

That is why OWASP's best practice puts Play Integrity next to local checks, and why the server's decision matters more than the client's. Request flows, verdicts, `MEETS_STRONG_INTEGRITY`, device recall and the hardware-backed key attestation that underpins them are covered in [MASWE-0054](/mobile/maswe-0054-device-attestation-not-implemented/). Version enforcement through the same verdict is in [MASWE-0041](/mobile/maswe-0041-running-on-recent-platform-version-not-ensured/).

#### How emulator checks are defeated

In general terms, without a recipe: attackers patch or hook the app's own check functions, hook the property and file APIs the checks call so they return values copied from a real device, edit properties on rooted images, build custom system images with realistic properties and hardware stubs, or give up on emulators and use real phones in device farms. Each step costs more than the previous one, which is the whole point of the control. The last step is why emulator detection cannot replace server-side abuse controls.

### iOS: Simulator Detection (MASTG-KNOW-0088)

Source: [MASTG-KNOW-0088](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0088/).

#### Why the Simulator is not an attack platform for App Store apps

Apple's Simulator, shipped with Xcode, does not emulate iPhone hardware. It runs apps compiled for the **iOS Simulator platform** as ordinary macOS processes against simulator copies of the iOS frameworks. On Apple silicon, simulator binaries are `arm64` like device binaries, but they are still different binaries: the Mach-O `LC_BUILD_VERSION` load command records the platform, `IOS` (2) for device builds and `IOSSIMULATOR` (7) for simulator builds, and the loader will not run one as the other. App Store binaries are device builds (Xcode refuses to archive for a simulator destination) and are FairPlay-encrypted.

You can see the platform of any binary:

```bash
otool -l Payload/App.app/App | grep -A4 LC_BUILD_VERSION
#       cmd LC_BUILD_VERSION
#   cmdsize 32
#  platform 2        <- iOS device. A simulator build shows 7.
#     minos 15.0
vtool -show-build Payload/App.app/App      # same information, more readable
```

So a shipped App Store app does not need Simulator detection, and an attacker cannot simply drop your IPA into the Simulator. What they can do with a decrypted IPA is run it on a jailbroken device, a virtual device (next section) or, with some apps, an Apple silicon Mac (the section after).

#### Compile-time vs. runtime checks

The two indicators OWASP lists behave very differently:

```swift
// Compile time: decided by the compiler for each build destination
#if targetEnvironment(simulator)
    blockSensitiveFeatures()      // never present in a device build
#endif

// Run time: an environment variable the Simulator sets
let inSimulator = ProcessInfo.processInfo.environment["SIMULATOR_DEVICE_NAME"] != nil
```

`#if targetEnvironment(simulator)` (and the Objective-C `TARGET_OS_SIMULATOR` macro) is evaluated when the code is compiled. In the device build that ships to the App Store, the condition is false and the code inside it is not compiled at all: it does not exist in the binary to be bypassed or to run. It is useful for development (skipping APIs the Simulator lacks), and it is useless as a resilience control. If a team cites it as "emulator detection" for an App Store app, the finding is that there is no detection, not that the detection is weak.

The reverse use is worth a glance in code review: `#if targetEnvironment(simulator)` blocks that disable pinning, jailbreak checks or App Attest for convenience are harmless in device builds for the same reason, but make sure the same switch is not keyed to a runtime value or a `DEBUG` flag that could leak into a release build ([MASWE-0063](/mobile/maswe-0063-debug-mechanisms-not-disabled/)).

The runtime environment variables (`SIMULATOR_DEVICE_NAME`, `SIMULATOR_UDID` and others) only exist in Simulator processes and can be set or removed by anyone controlling the launch. Since device binaries do not run in the Simulator, they are of little use either.

### iOS: Virtual Devices Detection (MASTG-KNOW-0135)

Source: [MASTG-KNOW-0135](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0135/).

#### What virtual iOS devices are

A virtual iOS device virtualizes the hardware an iOS device binary expects, so the real iOS kernel and the real app binary run. [Corellium](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0108/) is the established commercial platform: it describes itself as an ARM hypervisor that runs production code unmodified, and its devices can be jailbroken from the start, with a built-in Frida server, file browser, network monitor and snapshots. Public research projects have since booted virtual iPhones on Apple silicon Macs using Apple's virtualization stack and the Private Cloud Compute Virtual Research Environment (OWASP cites vPhone and a modified version of the Tart virtualization tool). Expect more of these, and expect them to change quickly.

Corellium's own documentation lists what its iOS devices lack: the App Store, Apple services such as push notifications and iMessage, GPU and Metal support, camera, cellular, NFC and Bluetooth. Apps cannot be downloaded from the App Store on a Corellium device, and encrypted App Store binaries copied from another device will not run, so users load a decrypted, re-signed build. Those gaps are the basis of the detection signals.

#### App Attest

[App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity) lets the app generate a key in the Secure Enclave and get Apple to attest that the key belongs to a genuine instance of the app (team ID plus bundle ID) on a genuine Apple device. The backend verifies the attestation and later assertions. The app first checks `DCAppAttestService.shared.isSupported`, then calls `generateKey(completionHandler:)` and `attestKey(_:clientDataHash:completionHandler:)`.

OWASP's argument is about app identity rather than virtualization: an app that has been decrypted and re-signed to run on a virtual device (or on a jailbroken phone) is not the production app instance the backend expects, so server-side App Attest validation should fail. A `false` from `isSupported` in the main app, or a failure to generate a key, is also a signal in itself, since physical iPhones running iOS 14 or later support the service (it can legitimately be unavailable in most app extensions). Treat this as the strongest of the iOS signals, precisely because the decision is made on the server. Details are in [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/) and [MASWE-0054](/mobile/maswe-0054-device-attestation-not-implemented/).

#### Hardware capability probes

Probe hardware the virtual device lacks:

```swift
import Metal
import CoreNFC

let hasGPU = MTLCreateSystemDefaultDevice() != nil   // nil means no Metal device
let hasNFC = NFCReaderSession.readingAvailable       // false on hardware without tag reading
```

Bluetooth is probed by creating a `CBCentralManager` and reading its state in `centralManagerDidUpdateState(_:)`: `.unsupported` means no Bluetooth LE central support, while `.poweredOff` only means the user switched it off.

The false positives are where these checks fail in production:

- **Metal** is available on every iPhone and iPad that runs a supported iOS version, so a missing Metal device is a strong signal.
- **NFC tag reading** is not available on iPads, so `readingAvailable == false` on an iPad is normal. Only use it as a signal when `hw.machine` claims an iPhone model that has NFC.
- **Bluetooth** needs an `NSBluetoothAlwaysUsageDescription` string and shows a permission prompt the first time a `CBCentralManager` is created. Adding a Bluetooth prompt to an app that has no Bluetooth feature, just to detect virtual devices, is poor UX and may be questioned in App Review.

#### Device properties

`sysctlbyname("hw.machine")` (or `uname()`) returns the model identifier, such as `iPhone15,2`. On its own it says little. Its value is as a cross-check: a model identifier that claims an iPhone with NFC and a GPU, on a device without either, is inconsistent.

#### Virtualization engine files

Corellium documents a daemon, `corelliumd`, that it adds to its virtual devices, and also that iOS devices can be created without it. A check such as `stat("/usr/libexec/corelliumd", &st) == 0` is therefore a positive signal when it fires and says nothing when it does not. Like all file checks, it is easy to defeat by hiding the file or hooking `stat`. Also note that sandboxed apps cannot freely enumerate the file system; checks for specific paths work, directory listings mostly do not.

### iOS: iOS Apps Running on macOS Detection (MASTG-KNOW-0136)

Source: [MASTG-KNOW-0136](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0136/).

On Macs with Apple silicon, iPhone and iPad apps from the App Store can run directly on macOS, unmodified, using the same frameworks as on iOS. This is an official distribution path, made available by default unless the developer opts out in App Store Connect. It is not the Simulator and it is not evidence of tampering.

It still matters for resilience. A Mac is a general-purpose computer the user administers: desktop tooling, a different input model, a file system the user can browse, different hardware. Public write-ups have shown Frida listing and, once macOS protections such as System Integrity Protection were relaxed, attaching to iPhone apps on M1 Macs. Frida's macOS documentation notes it needs authorisation to use `task_for_pid` and that SIP may need to be disabled.

The runtime check is one property, available from iOS 14:

```swift
func isRunningOnMac() -> Bool {
    if #available(iOS 14.0, *) {
        return ProcessInfo.processInfo.isiOSAppOnMac || ProcessInfo.processInfo.isMacCatalystApp
    }
    if #available(iOS 13.0, *) {
        return ProcessInfo.processInfo.isMacCatalystApp
    }
    return false
}
```

[`isiOSAppOnMac`](https://developer.apple.com/documentation/foundation/processinfo/isiosapponmac) is `true` for an iPhone or iPad app running on a Mac. `isMacCatalystApp` covers Mac Catalyst builds, which are Mac apps built from an iPad codebase, a different case. `#if targetEnvironment(macCatalyst)` is again compile-time and does not detect an iPhone app on a Mac.

The preferred control, if the app should not run on Macs at all, is distribution-level: [turn off availability on Apple silicon Macs in App Store Connect](https://developer.apple.com/help/app-store-connect/manage-your-apps-availability/manage-availability-of-iphone-and-ipad-apps-on-macs-with-apple-silicon/). That stops official distribution through the Mac App Store. It does not stop a decrypted, re-signed copy, which is why the runtime check and server-side attestation still matter. For testers, the first question is simply: is the app available on the Mac App Store for Apple silicon, and did the client mean it to be?

### Generic: Emulation-based Dynamic Analysis (MASTG-KNOW-0112)

Summary of [MASTG-KNOW-0112](https://mas.owasp.org/MASTG/knowledge/generic/MASVS-RESILIENCE/MASTG-KNOW-0112/). An emulator imitates a platform's hardware and software, while a simulator imitates only the software environment. Android has many emulators (QEMU-based and others), which give analysts full control, instruction-level tracing and cheap resets. For iOS, OWASP describes the Simulator as running simulator builds only and Corellium as the only commercial option for running device binaries virtually. The research projects mentioned in MASTG-KNOW-0135 have since started to change that picture. One statement on the OWASP page is inaccurate: it says the Simulator lacks the iOS kernel so apps that use syscalls cannot run. Simulator apps run as macOS processes on the macOS (XNU) kernel and can make system calls; the real limitation is that they are simulator builds against simulator frameworks, not device binaries.

## Tests

Two OWASP tests cover this weakness, both dynamic: MASTG-TEST-0351 for Android and MASTG-TEST-0367 for iOS. Both explicitly exclude robustness. We add a static test (GT-RES-0053-1) to find the checks first, and a response and strength test (GT-RES-0053-2) that brings back the effort questions from the legacy tests.

### GT-RES-0053-1: Static identification of emulator and virtual device checks (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

The test finds emulator, Simulator, virtual device and Mac checks in the app package, and tells you what to hook in the dynamic tests. Run it first: hooking blind misses most checks, especially `Build` field reads, which cannot be hooked at all (see MASTG-TEST-0351).

#### Prerequisites

- Android: the APK and splits, [jadx](https://github.com/skylot/jadx), `apktool` or `aapt2` for the manifest, `strings`, rabin2 and Ghidra for native libraries.
- iOS: a decrypted IPA (App Store binaries are FairPlay-encrypted; see our [lab note](/mobile/mobile-traffic-interception-lab/)), `otool`, `nm`, rabin2 or `strings`, and optionally Ghidra or Hopper.

#### Steps

1. **Android, managed code.** Decompile and search for the signals:

   ```bash
   jadx -d out/ --show-bad-code base.apk
   grep -rnE 'ro\.(kernel|boot)\.qemu|goldfish|ranchu|qemu_pipe|qemud|genyd|vbox86|sdk_gphone|google_sdk|test-keys|native\.bridge|houdini|ndk_translation|Emulator OpenGL|bluestacks|bignox|microvirt|genymotion' out/sources/ \
     | grep -vE '/(androidx|kotlin|kotlinx)/' | head -50
   grep -rnE 'Build\.(FINGERPRINT|HARDWARE|MODEL|PRODUCT|MANUFACTURER|BRAND|DEVICE|BOARD|TAGS)' out/sources/ \
     | grep -vE '/(androidx|kotlin|kotlinx|com/google)/' | head -50
   ```

2. **Android, manifest.** `<queries>` entries naming emulator packages are a direct hint:

   ```bash
   aapt2 dump xmltree base.apk --file AndroidManifest.xml | grep -A3 -E 'queries|package'
   ```

3. **Android, Play Integrity.** Look for the Play Integrity client library (`com.google.android.play.core.integrity`) and find where tokens are requested. Whether the server checks the verdict is outside the APK; ask, or test it in GT-RES-0053-2.

4. **Android, native code.**

   ```bash
   unzip -o -q base.apk 'lib/*' -d out/native/
   for f in out/native/lib/arm64-v8a/*.so; do
     echo "== $f"; strings -a "$f" | grep -iE 'qemu|goldfish|ranchu|genyd|vbox|houdini|ndk_translation|__system_property' | head
   done
   ```

5. **iOS.** Search the decrypted main binary and frameworks:

   ```bash
   BIN=Payload/App.app/App
   strings -a "$BIN" | grep -iE 'corellium|SIMULATOR_|hw\.machine|isiOSAppOnMac|readingAvailable'
   nm -u "$BIN" | grep -E '_sysctlbyname|_MTLCreateSystemDefaultDevice|_uname|_stat$'
   otool -L "$BIN" | grep -E 'Metal|CoreNFC|CoreBluetooth|DeviceCheck'
   ```

   `DeviceCheck.framework` linked plus references to `DCAppAttestService` means App Attest may be in use. For each hit, follow cross-references in Ghidra to the calling function and to what it does with the result.

6. **Third-party RASP SDKs.** Identify them by package or framework name. Emulator detection is usually a configurable option; find out whether it is enabled and what the configured response is.

#### Observation

A list of checks: location (class and method, or binary and function), signal type (property, file, package, sensor, GPU, telephony, CPU, Play Integrity, App Attest, Mac), and what the result feeds into (UI block, feature flag, request header, telemetry).

#### Evaluation

- **Fail** for an R-profile app if there are no checks in any category and no server-side attestation.
- **Fail (weak)** if all checks belong to one category (typically `Build` strings), or the only iOS "check" is `#if targetEnvironment(simulator)`, or package checks exist without matching `<queries>` entries on a `targetSdkVersion` of 30 or higher.
- **Pass, verify dynamically** if checks span several categories or attestation is used. Confirm with MASTG-TEST-0351 or MASTG-TEST-0367 and GT-RES-0053-2.

#### Demo

Illustrative jadx hit for a typical single-category check, and the iOS dead-code case:

```text
$ grep -rn 'Build.FINGERPRINT' out/sources/com/example/
out/sources/com/example/env/a.java:14:        return Build.FINGERPRINT.startsWith("generic") || Build.MODEL.contains("google_sdk");
```

```text
$ strings -a Payload/App.app/App | grep -c SIMULATOR_
0
$ grep -rn 'targetEnvironment(simulator)' Sources/
Sources/Security/EnvironmentGuard.swift:8:#if targetEnvironment(simulator)
```

The Android check passes the static test but fails on any current Play image (`Build.FINGERPRINT` starts with `google/`) and is a single category. The iOS source has a Simulator block that, as the empty `strings` result shows, is not in the shipped binary: no detection.

### MASTG-TEST-0351: Runtime Use of Emulator Detection Techniques (Android)

*OWASP test: [MASTG-TEST-0351](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0351/). Type: dynamic (hooks). Replaces legacy MASTG-TEST-0049.*

#### Overview

The test verifies at runtime that the app implements emulator detection, by hooking the APIs that emulator checks call and tracing the related system calls. OWASP is explicit about what it does not cover: the robustness and effectiveness of the detection. It proves that checks exist and run, nothing more. OWASP recommends running it on an emulator so that code paths that only run on positive detection are also exercised, while noting that many apps run their checks on physical devices too.

#### Prerequisites

- An emulator (an AVD with a Google APIs image is easiest, because `adb root` works and you can run `frida-server` as root) and, ideally, a physical rooted test device for comparison. Set-up is in our [lab note](/mobile/mobile-traffic-interception-lab/).
- [Frida](https://frida.re/) 17 or later on the host, `frida-server` of the same version on the device.
- The app installed with `adb install` (OWASP's [MASTG-TECH-0005](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/)); `adb install -g` grants runtime permissions up front, which saves you from missing telephony checks behind a denied prompt.
- The results of GT-RES-0053-1, so you know which app methods to hook.

#### Steps

OWASP's steps reference three techniques: installing apps ([MASTG-TECH-0005](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/)), method hooking ([MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/), with Frida here rather than its Xposed example) and execution tracing ([MASTG-TECH-0032](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0032/), here with Frida's native interception and optionally `strace`).

1. Install and start `frida-server`:

   ```bash
   adb install -g app.apk
   adb root && adb push frida-server /data/local/tmp/ && adb shell 'chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server -D'
   frida-ps -Uai | grep -i example
   ```

2. Hook the Java APIs checks use. OWASP's demo script hooks `TelephonyManager` getters, `ApplicationPackageManager.hasSystemFeature`, `queryIntentActivities` and `getPackageInfo`, `ActivityManager.getRunningServices`, `GLES20.glGetString`, `Build.getSerial` and `Build.getRadioVersion`, and logs only calls whose Java stack contains the app's package, which removes framework noise. Add `android.os.SystemProperties.get` and `SensorManager.getSensorList` to that list.

3. Hook the native layer for property reads and file probes. A compact script (ours, Frida 17 API):

   ```javascript
   // emu-native-trace.js
   const PAT = /qemu|goldfish|ranchu|genyd|vbox|houdini|native\.bridge|ndk_translation|hardware|build\.(tags|type|characteristics)/i;

   function bt(ctx) {
     return Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, 4)
       .map(DebugSymbol.fromAddress).join("\n    ");
   }

   function hook(name, pathArg) {
     const addr = Module.findGlobalExportByName(name);
     if (addr === null) return;
     Interceptor.attach(addr, {
       onEnter(args) {
         const p = args[pathArg].readCString();
         if (p !== null && PAT.test(p)) { this.p = p; this.ctx = this.context; }
       },
       onLeave(ret) {
         if (this.p) console.log(`[${name}] ${this.p} -> ${ret.toInt32()}\n    ${bt(this.ctx)}`);
       }
     });
   }

   hook("__system_property_get", 0);   // returns the value length; 0 = unset
   ["access", "stat", "lstat", "open"].forEach(n => hook(n, 0));
   ["openat", "faccessat", "fstatat"].forEach(n => hook(n, 1));
   ```

   Run both scripts together:

   ```bash
   frida -U -f com.example.app -l emu-java-trace.js -l emu-native-trace.js -o emu-trace.txt
   ```

   For a quick first pass without writing scripts, `frida-trace` generates handlers for you:

   ```bash
   frida-trace -U -f com.example.app -i '__system_property_get' -i 'access' -i 'openat' \
     -j 'android.os.SystemProperties!get*' -j 'android.hardware.SensorManager!getSensorList'
   ```

4. **`Build` fields cannot be hooked.** `Build.FINGERPRINT` and friends are static final fields filled from properties in the zygote, before your app's process exists. Reading them is a field access, not a method call, so neither Frida's Java hooks nor a `__system_property_get` hook will see it. That is why OWASP's demo hooks the demo app's own helper method (`MastgTest.queryBuildValue`) to log build values. In a real app, find the methods that read `Build` fields in GT-RES-0053-1 and hook those methods; their arguments and return values show the check.

5. Optionally trace syscalls with `strace` from the emulator's root shell (some userdebug and eng images include an `strace` binary; otherwise build it from source with the NDK), as described in [MASTG-TECH-0032](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0032/):

   ```bash
   adb shell 'strace -f -e trace=openat,faccessat,newfstatat,readlinkat -p $(pidof com.example.app)' 2>&1 | grep -iE 'qemu|goldfish|genyd|vbox'
   ```

   `strace` uses `ptrace` and fails against apps with anti-debugging ([MASWE-0064](/mobile/maswe-0064-debugger-detection-not-implemented/)).

6. Exercise the app: launch, log in, open each sensitive feature. Many apps run environment checks at start-up and again before transactions.

#### Observation

The trace: each hooked call with its argument and result and, for native calls, the backtrace showing which library made it. Note which checks come from the app's own code, which from a third-party SDK, and which happen only at particular moments (start-up, login, payment).

#### Evaluation

The test **fails** if no emulator detection checks are observed. It **passes** if checks are observed, but OWASP is clear that a pass is evidence of presence, not of robustness. Read the result together with GT-RES-0053-1 (are the checks spread over several categories?) and GT-RES-0053-2 (does anything happen?).

Expected false negatives: checks outside your hooks (custom native code that makes raw `svc` system calls, reads `/proc` files directly, or reads `Build` fields), obfuscated or dynamically loaded detection code, and apps that stop running Frida-visible code once they detect Frida itself ([MASWE-0065](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/)). Absence of evidence here is not evidence of absence; cross-check with static analysis before you write "no emulator detection".

#### Demo

OWASP's demo [MASTG-DEMO-0114](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0114/MASTG-DEMO-0114/) is a Kotlin sample that reads build properties, telephony values, emulator packages through `<queries>`, running services and the OpenGL renderer. Shortened:

```kotlin
private fun queryOpenGlRenderer(): String? {
    // A current EGL context is required: create a 1x1 pbuffer surface first (omitted)
    return GLES20.glGetString(GLES20.GL_RENDERER)
}

private fun buildIndicators(): List<String> {
    val hits = mutableListOf<String>()
    val hw = Build.HARDWARE.lowercase()
    if (listOf("goldfish", "ranchu", "vbox86", "nox", "ttvm").any { hw.contains(it) }) hits += "HARDWARE=$hw"
    if (Build.TAGS.contains("test-keys")) hits += "TAGS=${Build.TAGS}"
    if (Build.FINGERPRINT.startsWith("generic")) hits += "FINGERPRINT"
    return hits
}
```

Excerpt from OWASP's output, captured on an Android 16 LineageOS-based emulator image (not produced by us):

```text
[Build] Build.BOARD=goldfish_arm64
[Build] Build.FINGERPRINT=Android/lineage_sdk_phone_arm64/emu64a:16/BP2A.250805.005/eng.jcasad:userdebug/test-keys
[Build] Build.HARDWARE=ranchu
[Build] Build.TAGS=test-keys
[PackageManager.hasSystemFeature] android.hardware.telephony -> true
[TelephonyManager.getLine1Number] -> +15551234567
[TelephonyManager.getNetworkOperatorName] -> T-Mobile
[PackageManager.getPackageInfo] com.bignox.app -> not found
[ActivityManager.getRunningServices] count=0
[GLES20.glGetString] GL_RENDERER -> Android Emulator OpenGL ES Translator (ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device ...
```

The demo passes: checks from four categories run. Two things the output also shows: the telephony values do not match the old emulator numbers in MASTG-KNOW-0031, so a check based on that list would have missed this emulator; and `getRunningServices` returns nothing, as expected on Android 8.0 and later. OWASP's demo description mentions file checks, but the sample code does not contain any; if you reuse it, add the native file probes above.

### MASTG-TEST-0367: Runtime Use of Virtual Device Detection Techniques (iOS)

*OWASP test: [MASTG-TEST-0367](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0367/). Type: dynamic. Replaces legacy MASTG-TEST-0092.*

#### Overview

The test verifies at runtime that the app implements checks for iOS virtual devices such as Corellium, by hooking the APIs those checks use. Like its Android counterpart it establishes presence, not robustness. It also covers, in our version, the Mac check from MASTG-KNOW-0136, which uses the same method.

#### Prerequisites

- A jailbroken test device or a virtual iOS device with Frida. A physical device is enough to observe the checks; a virtual device is needed to see what happens on a positive result (or use GT-RES-0053-2's technique of flipping the app's own check).
- The app installed (OWASP's [MASTG-TECH-0056](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0056/): `ideviceinstaller`, `xcrun devicectl device install app`, or re-signing as in [MASTG-TECH-0092](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0092/) when needed).
- Frida 17 or later and the GT-RES-0053-1 results.

#### Steps

1. Hook the APIs, following OWASP's method hooking technique [MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/). OWASP's demo script hooks `sysctlbyname` (logging only `hw.machine` reads with a non-null output buffer), `MTLCreateSystemDefaultDevice` (logging whether a device came back) and `stat` (logging only the Corellium daemon path), each with a backtrace. Extend it to the other signals:

   ```bash
   frida-trace -U -f com.example.app \
     -i 'sysctlbyname' -i 'uname' -i 'MTLCreateSystemDefaultDevice' -i 'stat' -i 'access' \
     -m '+[NFCReaderSession readingAvailable]' \
     -m '-[NSProcessInfo isiOSAppOnMac]' -m '-[NSProcessInfo isMacCatalystApp]' \
     -m '-[NSProcessInfo environment]' \
     -m '-[DCAppAttestService isSupported]' -m '-[DCAppAttestService attestKey:clientDataHash:completionHandler:]'
   ```

   `stat` and `access` are noisy; edit the generated handler in `__handlers__/libsystem_kernel.dylib/stat.js` (or wherever frida-trace puts it) to print only paths you care about.

2. Exercise the app, including the flows that call App Attest (usually first launch, login and sensitive transactions).

#### Observation

Each hooked call with its argument, result and backtrace, showing whether it comes from the app's code, a framework or the system. The system itself calls `sysctlbyname("hw.machine")` early (CoreFoundation reads the product name), so the backtrace is what separates a check from noise.

#### Evaluation

The test **fails** if no virtual device detection checks are observed. It **passes** if the app's own code calls such checks; record which categories (device properties, hardware probes, engine files, App Attest, Mac). As for Android, expect false negatives from inlined `svc` calls, obfuscated or dynamically resolved symbols, and anti-Frida logic, and do not report "no detection" without a static cross-check.

#### Demo

OWASP's demo [MASTG-DEMO-0131](https://mas.owasp.org/MASTG/demos/ios/MASVS-RESILIENCE/MASTG-DEMO-0131/MASTG-DEMO-0131/), shortened:

```swift
private func currentMachineIdentifier() -> String {
    var size = 0
    guard sysctlbyname("hw.machine", nil, &size, nil, 0) == 0, size > 1 else { return "unknown" }
    var buf = [CChar](repeating: 0, count: size)
    guard sysctlbyname("hw.machine", &buf, &size, nil, 0) == 0 else { return "unknown" }
    return String(cString: buf)
}

private func metalAvailable() -> Bool { MTLCreateSystemDefaultDevice() != nil }

private func corelliumDaemonExists() -> Bool {
    var st = stat()
    return stat("/usr/libexec/corelliumd", &st) == 0
}
```

The hook for `sysctlbyname` from OWASP's script:

```javascript
Interceptor.attach(Module.findGlobalExportByName("sysctlbyname"), {
  onEnter(args) {
    this.ctx = this.context;
    this.name = args[0].readCString();
    this.out = args[1];
  },
  onLeave(ret) {
    if (this.name === "hw.machine" && !this.out.isNull() && ret.toInt32() === 0)
      console.log(`sysctlbyname("hw.machine") => ${this.out.readCString()}\n` +
        Thread.backtrace(this.ctx, Backtracer.ACCURATE).slice(0, 4).map(DebugSymbol.fromAddress).join("\n"));
  }
});
```

Excerpt from OWASP's output on a physical iPhone (not produced by us):

```text
sysctlbyname("hw.machine") => iPhone10,6
0x1c2ac4368 CoreFoundation!___CFGetProductName_block_invoke
...
sysctlbyname("hw.machine") => iPhone10,6
0x104e287cc MASTestApp.debug.dylib!VirtualDeviceDetector.currentMachineIdentifier()
MTLCreateSystemDefaultDevice() => available
0x104e28b4c MASTestApp.debug.dylib!VirtualDeviceDetector.metalIndicator()
stat("/usr/libexec/corelliumd") => missing
0x104e29dec MASTestApp.debug.dylib!VirtualDeviceDetector.corelliumDaemonExists()
```

The first `hw.machine` read comes from CoreFoundation and is not a check; the second, with the app's own frame, is. The demo passes on three categories. It deliberately leaves out NFC and Bluetooth (entitlements, prompts, user state) and App Attest (needs a server).

### GT-RES-0053-2: Response and strength of emulator and virtual device detection (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

The two OWASP tests stop at "checks exist". This test answers the questions that decide the rating and that the legacy tests used to ask: does the app or backend do anything when the checks fire, and how much effort does it take to make them not fire? It stays within the series scope: you neutralise the app's own checks on your own test environment and record the effort, and you observe the server's decision without trying to defeat attestation.

#### Prerequisites

- The trace from MASTG-TEST-0351 or MASTG-TEST-0367 and the check locations from GT-RES-0053-1.
- Android: an AVD (Google APIs image for root, Google Play image to see a realistic user build) and a physical device. iOS: a physical jailbroken device; a virtual iOS device if the engagement provides one; an Apple silicon Mac if the app is offered there.
- Test accounts and, if possible, access to backend logs or the fraud team's view of the test sessions.

#### Steps

1. **Positive run.** Launch the app in the emulated or virtual environment and go through sign-up, login and the sensitive flows. Record any warning, block, degraded feature, forced logout or silent behaviour change.

2. **Server view.** For the same session, find out what the backend received and decided: Play Integrity or App Attest result, any client-reported signals, and the action taken. If the app uses Play Integrity, an emulator run should produce an empty `deviceRecognitionVerdict`; the question is whether the backend acts on that.

3. **Response without a virtual device (iOS especially).** If you have no virtual iOS device, verify the response logic on a physical device by forcing the app's own detection function to report "detected" with a short Frida hook, and observe what the app and backend do. For example, for a Swift method found in GT-RES-0053-1:

   ```javascript
   // Force the app's own check to report a virtual device, to observe the response path
   const app = Process.getModuleByName("App");
   // Internal Swift functions are rarely exported: take the offset (function address minus image base) from Ghidra
   const isVirtualDevice = app.base.add(0x1a2b4);
   Interceptor.attach(isVirtualDevice, {
     onLeave(ret) { ret.replace(ptr(1)); }   // 1 = "virtual device detected"
   });
   ```

   On Android the equivalent is a Java hook on the app's own method: `Java.perform(() => { Java.use("com.example.env.EnvGuard").isEmulator.implementation = function () { return true; }; });`.

4. **Strength.** Now measure the opposite direction on the emulator: neutralise the app's own detection and record what it took. Start with the cheapest step and stop when the checks no longer fire:
   - one Frida hook that makes the app's own detection method return `false`;
   - hooks on several app methods or on the property and file APIs those methods call (return values copied from your physical device);
   - patching native checks;
   - none of these suffice in reasonable time.

   Record the number of hooks, whether native code was involved, whether checks were scattered or centralised, and the time spent. Do not try to make attestation pass; if the backend still refuses the emulator after all local checks are neutralised, that is the result you want to report.

5. **Mac (iOS).** If the app is available on Apple silicon Macs, install it there and run the same flows. Check with the client whether that availability is intended.

6. **Negative control.** Confirm the app works on a normal physical device and, if relevant, on ChromeOS or other virtual environments the client wants to support.

#### Observation

For each environment: app behaviour, server-side decision, and the bypass ladder with the step at which local checks stopped firing and the effort it took. Screenshots, Frida scripts and backend log excerpts.

#### Evaluation

- **Fail** if the app and backend behave identically on an emulator or virtual device and on a real device.
- **Fail (trivially bypassed)** if detection exists but one hook on one app method removes all of its effects and the backend does not independently notice the emulator. Rate by what that unlocks (see below).
- **Pass** if detection leads to a proportionate response and survives at least the single-hook step, or if the backend refuses or restricts the emulator session independently of local checks (attestation).
- Note separately any **legitimate environment** the app blocks without a documented reason.

#### Demo

*Illustrative result, not from a specific engagement.* An app with emulator checks centralised in one Kotlin method:

```text
AVD (Google APIs image), no hooks       -> "Unsupported device" dialog at launch
Hook: EnvGuard.isEmulator() -> false    -> app fully usable, login and transfer to saved payee succeed
Backend                                 -> no Play Integrity request observed; session accepted
Effort                                  -> one hook, under 15 minutes including finding the method
```

Result: fail (trivially bypassed), with no server-side backstop.

## Best practices

### MASTG-BEST-0046: Hardening Against Emulation (Android)

Source: [MASTG-BEST-0046](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0046/). OWASP recommends three layers:

- **Detective controls.** Check emulator indicators across categories (MASTG-KNOW-0031) and use the Play Integrity API (MASTG-KNOW-0035, covered in [MASWE-0054](/mobile/maswe-0054-device-attestation-not-implemented/)) to identify risky devices, emulated environments, modified binaries and untrusted interactions.
- **Deterrent controls.** Obfuscate the detection logic (MASTG-KNOW-0033, see [MASWE-0059](/mobile/maswe-0059-code-obfuscation-not-implemented/)), scatter checks through the app and vary their timing.
- **Hardening against reverse-engineering tools.** Detect the tools that usually come with emulators (MASTG-KNOW-0030, see [MASWE-0065](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/)).

What we add in practice:

- **Return signals, not a boolean.** A function that returns a list of indicators (`ranchu`, `native_bridge`, `no_gyroscope`, `renderer:swiftshader`) is harder to neutralise with one hook than `isEmulator()`, and gives the backend something to score.
- **Make the server decide.** Bind the signals to a Play Integrity request (put a hash of them in the `requestHash` of a standard request) so the backend sees both the client's view and Google's verdict, and can spot a client claiming "real device" while the verdict says otherwise.
- **Check `<queries>`** for every package-based check on `targetSdkVersion` 30 and above.
- **Weight hardware-dependent signals higher** than strings: `ro.hardware`, sensor behaviour, GPU renderer, CPU architecture versus native bridge.
- **Keep the allow-list explicit** for ChromeOS and Play Games for PC if you support them.

The cross-cutting guidance on resilience signals, RASP SDKs and response strategies (MASTG-BEST-0029) is summarised in the [series hub](/mobile/masvs-resilience-resilience-testing-guide/).

### MASTG-BEST-0053: Hardening Against Virtual Devices (iOS)

Source: [MASTG-BEST-0053](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0053/). OWASP's points, with our notes:

- **Do not confuse the three iOS environments.** Simulator (simulator builds only), virtual devices (device binaries on virtual hardware) and iPhone apps on Macs (official channel) need different answers. Only the second is an analysis platform for your App Store binary; the third is a product decision first.
- **Treat local checks as risk signals**, not decisions, because they can be hooked or patched.
- **Detect virtual devices** through missing hardware (Metal, NFC where the model should have it), inconsistent properties, engine artefacts, and App Attest failures.
- **Detect reverse-engineering tools** (MASTG-KNOW-0087, see [MASWE-0065](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/)), since virtual devices are used with them.
- **Enforce on the server** for high-risk actions: App Attest validation, integrity checks, risk scoring, throttling, step-up verification, refusing sensitive features when several signals agree.
- **Obfuscate and diversify** the checks (MASTG-KNOW-0089, see [MASWE-0059](/mobile/maswe-0059-code-obfuscation-not-implemented/)).
- **Respond without explaining.** Generic errors, reduced functionality or delayed server-side decisions, not "Corellium detected".

OWASP closes with the point that summarises this whole note: these controls do not make execution in virtual devices impossible; they raise the cost of analysis, make large-scale automation less reliable, and make bypasses harder to maintain across releases.

## Rating findings

Series-wide rules apply, adapted here:

- **Info** if the app's threat model does not include the R profile. Missing emulator or virtual device detection is an observation; say so plainly.
- **Info** for an iOS App Store app that "lacks Simulator detection". Device binaries cannot run in the Simulator, so there is nothing to detect. A `#if targetEnvironment(simulator)` block presented as a control is worth an Info note so the client stops counting it.
- **Low** for an R-profile app with no emulator detection, or detection that one hook removes, when the backend independently restricts emulator sessions (for example by acting on Play Integrity or App Attest), or when the app's sensitive functions do not attract automated abuse.
- **Medium** for an R-profile app (banking, payments, wallet, high-value game) whose app and backend behave identically on an emulator or virtual device and a real phone, with no attestation-based server decision.
- **Medium–High** only when the gap directly enables concrete business abuse that you can show or that the client's data shows: emulator-farm sign-ups claiming bonuses, scripted transactions or credential stuffing through the real app, game-economy farming. Put the abuse path in the report.
- A check that **exists but is trivially bypassed** is rated by what the bypass unlocks, on the same scale, and the report gives the bypass effort from GT-RES-0053-2.
- **Unintended availability on Apple silicon Macs** for an app whose threat model excludes desktop environments: Low, with the App Store Connect setting as the fix. Intended availability is not a finding.
- **Blocking legitimate virtual environments** (ChromeOS, Play Games for PC, Macs where intended) is a usability observation, not a security weakness.
- Asking for phone-state permissions solely to read emulator telephony values is a separate privacy observation.

In the report give the environment (image type, Android or iOS version), the checks found and their categories, the trace evidence, the app's and server's behaviour, the bypass effort, and the specific fix: more categories of signal, a server-side decision on Play Integrity or App Attest, and abuse controls that do not depend on detection.

## References

- OWASP MASWE: [MASWE-0053: Emulated or Virtual Device Detection Not Implemented](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0053/); related [MASWE-0051](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0051/), [MASWE-0052](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0052/), [MASWE-0054](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0054/), [MASWE-0065](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0065/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-RESILIENCE-1](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-1/), [MASVS-RESILIENCE-4](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-4/) (CC BY-SA 4.0)
- OWASP MASTG knowledge: [MASTG-KNOW-0031](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0031/), [MASTG-KNOW-0088](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0088/), [MASTG-KNOW-0135](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0135/), [MASTG-KNOW-0136](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0136/), [MASTG-KNOW-0112](https://mas.owasp.org/MASTG/knowledge/generic/MASVS-RESILIENCE/MASTG-KNOW-0112/) (CC BY-SA 4.0)
- OWASP MASTG tests: [MASTG-TEST-0351](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0351/), [MASTG-TEST-0367](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0367/); legacy [MASTG-TEST-0049](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0049/), [MASTG-TEST-0092](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0092/) (CC BY-SA 4.0)
- OWASP MASTG demos: [MASTG-DEMO-0114](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0114/MASTG-DEMO-0114/), [MASTG-DEMO-0131](https://mas.owasp.org/MASTG/demos/ios/MASVS-RESILIENCE/MASTG-DEMO-0131/MASTG-DEMO-0131/) (CC BY-SA 4.0)
- OWASP MASTG best practices: [MASTG-BEST-0046](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0046/), [MASTG-BEST-0053](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0053/) (CC BY-SA 4.0)
- OWASP MASTG techniques and tools: [MASTG-TECH-0005](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/), [MASTG-TECH-0032](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0032/), [MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/), [MASTG-TECH-0056](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0056/), [MASTG-TECH-0092](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0092/), [MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/), [Corellium (MASTG-TOOL-0108)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0108/) (CC BY-SA 4.0)
- Android: [`android.os.Build`](https://developer.android.com/reference/android/os/Build), [`TelephonyManager`](https://developer.android.com/reference/android/telephony/TelephonyManager), [Package visibility](https://developer.android.com/training/package-visibility), [Android 10 privacy changes: non-resettable identifiers](https://developer.android.com/about/versions/10/privacy/changes#non-resettable-device-ids), [`ActivityManager.getRunningServices`](https://developer.android.com/reference/android/app/ActivityManager#getRunningServices%28int%29), [`GLES20`](https://developer.android.com/reference/android/opengl/GLES20), [Android Emulator](https://developer.android.com/studio/run/emulator)
- Google Play: [Play Integrity API overview](https://developer.android.com/google/play/integrity/overview), [Integrity verdicts](https://developer.android.com/google/play/integrity/verdicts), [Use of the broad package (app) visibility permission](https://support.google.com/googleplay/android-developer/answer/10158779)
- Apple: [Running your iOS apps in macOS](https://developer.apple.com/documentation/apple-silicon/running-your-ios-apps-in-macos), [`ProcessInfo.isiOSAppOnMac`](https://developer.apple.com/documentation/foundation/processinfo/isiosapponmac), [Manage availability of iPhone and iPad apps on Macs with Apple silicon](https://developer.apple.com/help/app-store-connect/manage-your-apps-availability/manage-availability-of-iphone-and-ipad-apps-on-macs-with-apple-silicon/), [Running code on a specific platform or OS version](https://developer.apple.com/documentation/xcode/running-code-on-a-specific-version), [DeviceCheck and App Attest](https://developer.apple.com/documentation/devicecheck), [Establishing your app's integrity](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity), [`MTLCreateSystemDefaultDevice()`](https://developer.apple.com/documentation/metal/mtlcreatesystemdefaultdevice%28%29), [`NFCReaderSession.readingAvailable`](https://developer.apple.com/documentation/corenfc/nfcreadersession-swift.class/readingavailable), [`CBManagerState`](https://developer.apple.com/documentation/corebluetooth/cbmanagerstate), [Virtualization framework](https://developer.apple.com/documentation/virtualization), [Private Cloud Compute Virtual Research Environment](https://security.apple.com/documentation/private-cloud-compute/virtualresearchenvironment)
- Corellium: [iOS devices](https://support.corellium.com/devices/ios), [Testing iOS apps](https://support.corellium.com/features/apps/testing-ios-apps), [What is corelliumd?](https://support.corellium.com/troubleshooting-faqs/general-faqs#what-is-corelliumd), [Corellium vs. the iOS Simulator](https://www.corellium.com/compare/ios-simulator)
- Frida: [macOS examples (task_for_pid and SIP)](https://frida.re/docs/examples/macos/), [JavaScript API](https://frida.re/docs/javascript-api/)
- Research referenced by OWASP: [vPhone](https://github.com/Lakr233/vphone-cli), [Super Tart write-up](https://github.com/wh1te4ever/super-tart-vphone-writeup), [Frida issue 1734 (iOS apps on M1 Macs)](https://github.com/frida/frida/issues/1734), [Taking a look at iOS apps on an M1 Mac (forensicmike1)](https://forensicmike1.com/post/taking-a-look-at-ios-apps-on-an-m1-mac/)
- CWE: [CWE-693](https://cwe.mitre.org/data/definitions/693.html) (our mapping; OWASP gives none)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
