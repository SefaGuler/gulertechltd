---
title: "MASWE-0063: Debug Mechanisms Not Disabled"
date: 2026-11-10 20:12:00 +0000
subcategory: resilience
summary: "Finding debuggable release builds, get-task-allow, and WebView or WKWebView inspection left on: what each exposes, how to prove it and how to rate it."
refs: [MASWE-0063, MASVS-RESILIENCE-4, MASVS-PLATFORM-2, CWE-489]
tags: [android, ios, masvs-resilience, debugging, webview, code-signing]
---

This note is part of our [MASVS-RESILIENCE guide](/mobile/masvs-resilience-resilience-testing-guide/) and covers OWASP [MASWE-0063](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0063/): a production build that still has a debugging mechanism switched on. On Android that is `android:debuggable="true"` in the manifest or a call to `WebView.setWebContentsDebuggingEnabled(true)`; on iOS it is the `get-task-allow` entitlement in the code signature or `isInspectable = true` on a `WKWebView` or `JSContext`. Unlike most of this series, these are not missing defences that raise attacker cost. They are open doors the platform provides on purpose for developers, and a debuggable release build gives anyone with ADB access to an unlocked device the app's private files with one command and its memory with a debugger, no root needed. The checks are fast and objective. The care goes into knowing what each flag really enables on current OS versions, which builds the flag actually reached, and the false positives that come from your own tooling (a re-signed IPA, a userdebug device). Below are the mechanisms, the three OWASP tests plus two of ours (iOS web inspection and runtime confirmation), the build settings that fix it, and how to rate it.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: Debuggable Apps (MASTG-KNOW-0007)](#android-debuggable-apps-mastg-know-0007)
  - [iOS: Debuggable Apps (MASTG-KNOW-0062)](#ios-debuggable-apps-mastg-know-0062)
  - [Android and iOS: Web content debugging (background)](#android-and-ios-web-content-debugging-background)
- [Tests](#tests)
  - [MASTG-TEST-0226: Debuggable Flag Enabled in the AndroidManifest (Android)](#mastg-test-0226-debuggable-flag-enabled-in-the-androidmanifest-android)
  - [MASTG-TEST-0227: Debugging Enabled for WebViews (Android)](#mastg-test-0227-debugging-enabled-for-webviews-android)
  - [MASTG-TEST-0261: Debuggable Entitlement Enabled in the entitlements.plist (iOS)](#mastg-test-0261-debuggable-entitlement-enabled-in-the-entitlementsplist-ios)
  - [GT-RES-0063-1: Web content inspection enabled in WKWebView or JSContext (iOS)](#gt-res-0063-1-web-content-inspection-enabled-in-wkwebview-or-jscontext-ios)
  - [GT-RES-0063-2: Debug mechanisms in the installed build and runtime toggles (Android and iOS)](#gt-res-0063-2-debug-mechanisms-in-the-installed-build-and-runtime-toggles-android-and-ios)
- [Best practices](#best-practices)
  - [MASTG-BEST-0007: Debuggable Flag Disabled in the AndroidManifest (Android)](#mastg-best-0007-debuggable-flag-disabled-in-the-androidmanifest-android)
  - [MASTG-BEST-0008: Debugging Disabled for WebViews (Android)](#mastg-best-0008-debugging-disabled-for-webviews-android)
  - [iOS: distribution signing and inspectability (Guler Tech)](#ios-distribution-signing-and-inspectability-guler-tech)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

The OWASP requirement is *"The app disables debug mechanisms."* MASWE-0063 maps to **MASVS-RESILIENCE-4** ("The app implements anti-dynamic analysis techniques") and **MASVS-PLATFORM-2** ("The app uses WebViews securely"), to [CWE-489](https://cwe.mitre.org/data/definitions/489.html) (Active Debug Code), and to Android's own risk page [android:debuggable](https://developer.android.com/privacy-and-security/risks/android-debuggable). It replaces MASVS v1's MSTG-RESILIENCE-2 and merges two beta weaknesses (MASWE-0067 and MASWE-0074).

The weakness carries OWASP's **R** profile (plus EUDIW), because it sits in the RESILIENCE group. Do not read that as "only matters for high-value apps". Turning debugging *on* is not the absence of an anti-analysis control; it hands an attacker the platform's own analysis tools. We treat a debug mechanism in a release build as a vulnerability for **every** app, whatever its profile (see [Rating findings](#rating-findings)). What the R profile adds is the next step: detecting a debugger that the attacker brings along anyway, which is [MASWE-0064](/mobile/maswe-0064-debugger-detection-not-implemented/).

What is covered, and by which test:

| Mechanism | Platform | Test |
|---|---|---|
| `android:debuggable="true"` | Android | [MASTG-TEST-0226](#mastg-test-0226-debuggable-flag-enabled-in-the-androidmanifest-android) |
| `WebView.setWebContentsDebuggingEnabled(true)` | Android | [MASTG-TEST-0227](#mastg-test-0227-debugging-enabled-for-webviews-android) |
| `get-task-allow` entitlement | iOS | [MASTG-TEST-0261](#mastg-test-0261-debuggable-entitlement-enabled-in-the-entitlementsplist-ios) |
| `WKWebView.isInspectable` / `JSContext.isInspectable` | iOS | [GT-RES-0063-1](#gt-res-0063-1-web-content-inspection-enabled-in-wkwebview-or-jscontext-ios) (ours; OWASP has no iOS test) |
| What the installed build really does, including remote toggles | Both | [GT-RES-0063-2](#gt-res-0063-2-debug-mechanisms-in-the-installed-build-and-runtime-toggles-android-and-ios) (ours) |

These tests replace the legacy v1 tests **MASTG-TEST-0039** (Android, "Testing whether the App is Debuggable", `covered_by` 0226 and 0227) and **MASTG-TEST-0082** (iOS, same title, `covered_by` 0261). The dynamic checks from those legacy tests (`dumpsys`, `run-as`, `jdb`, attaching LLDB) live on in our GT-RES-0063-2.

Keep the neighbours apart:

| Question | Where it lives |
|---|---|
| Is a debug mechanism switched on in the release build? | This note |
| Are debug symbols, logging, test code, debug menus or `#if DEBUG` leftovers in the release build? | [MASWE-0061](/mobile/maswe-0061-debug-artifacts-not-removed/) |
| Does the app notice a debugger the attacker attaches anyway (after repackaging or with root)? | [MASWE-0064](/mobile/maswe-0064-debugger-detection-not-implemented/) |
| Does the app notice Frida, Xposed, objection? | [MASWE-0065](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/) |
| Would a repackaged, re-signed copy with debugging turned on still run? | [MASWE-0057](/mobile/maswe-0057-app-resources-integrity-not-verified/), [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/) |
| What can JavaScript in the WebView reach (bridges, files)? | [MASWE-0033](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/), [MASWE-0034](/mobile/maswe-0034-webviews-allow-access-to-local-resources/) |

## Modes of Introduction

**The wrong variant ships.** A CI job builds `assembleDebug` or `bundleDebug` instead of the release task, a flavour is wired to the debug build type, or a release build type sets `isDebuggable = true` "temporarily" to chase a crash. On iOS, a build exported with a development or Ad Hoc method where the distribution path expected App Store, or an enterprise build signed with a development profile.

**The flag is hard-coded in the manifest.** `android:debuggable="true"` written into `AndroidManifest.xml` by hand (Android lint flags this as `HardcodedDebugMode`) or by a cross-platform build tool's template.

**WebView debugging switched on unconditionally.** `setWebContentsDebuggingEnabled(true)` in `Application.onCreate()` without a debug guard, a debug guard based on something other than the build (a remote-config flag, a hidden settings screen, a server response), or a hybrid framework's "debugging" option left on in the release config.

**`isInspectable = true` everywhere.** Since iOS 16.4 WebKit requires an explicit opt-in, and teams add it to every web view to keep their debugging workflow, without a `#if DEBUG` around it.

**Non-production builds that escape.** QA, UAT and beta builds distributed to large tester groups through Firebase App Distribution, MDM, or a download page, often against production backends with real accounts.

## Impact

The attacker position is the same for all four mechanisms: **access to an unlocked device with developer access**, meaning USB debugging (or wireless debugging) enabled and the attacker's computer authorised, or, on iOS, a paired Mac and Developer Mode on. That covers the device owner acting against the app's interests (fraud, cheating, licence abuse: the R threat model), anyone who gets a few minutes with an unlocked phone that has developer options on, and test or shared devices. It is not a remote attack.

- **Private data read (and written) without root.** On Android, `adb shell run-as <package>` runs commands as the app's UID in its data directory on a production, unrooted device: databases, `shared_prefs`, tokens, cached files, the content of the app's files directory. Write access too, so an attacker can plant or modify configuration and cached content the app trusts.
- **Memory, keys and tokens.** A Java debugger (JDWP), LLDB, a heap dump, or a JVMTI agent reads values that never touch the disk: session tokens, decrypted data, keys derived at runtime, the plaintext before [payload encryption](/mobile/maswe-0062-no-application-level-payload-encryption/).
- **Control flow manipulation.** Breakpoints on authentication, licence, root-detection or payment checks, with return values or locals changed in place, skip them, without repackaging and without tripping signature or integrity checks, because the app is unmodified.
- **Web content takeover.** With WebView or WKWebView inspection on, a DevTools or Web Inspector session can read and change the DOM, cookies, `localStorage`, network requests and responses, and run arbitrary JavaScript in the page's origin, which includes calling any JavaScript bridge the page can see ([MASWE-0033](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/)).
- **Cheap reverse engineering.** Every other resilience control becomes easier to study and bypass when the platform debugger is available. That is the RESILIENCE-4 angle.

## Mitigations

- **Never set the debuggable flag in release builds.** Let the Android Gradle Plugin set it from the build type (`isDebuggable` is `true` only for `debug`), do not hard-code `android:debuggable` in the manifest, and fail CI if a release artefact is debuggable.
- **Sign iOS builds for distribution.** App Store, Ad Hoc and Enterprise distribution profiles do not grant `get-task-allow`; verify the entitlement on the exported IPA, not in the project.
- **Guard WebView debugging and inspectability by build configuration**: `BuildConfig.DEBUG` or `ApplicationInfo.FLAG_DEBUGGABLE` on Android, `#if DEBUG` on iOS. Never drive them from remote config or a runtime setting.
- **Use `android:profileable`** (Android 10+) rather than `debuggable` when you need to profile a release-like build: it allows performance profiling without JDWP, `run-as` or memory inspection.
- **For R-profile apps, add debugger detection** ([MASWE-0064](/mobile/maswe-0064-debugger-detection-not-implemented/)) and integrity checks, because an attacker can still re-sign the app with debugging on, or debug it on a rooted or jailbroken device.

## Knowledge

OWASP assigns two Knowledge items here: MASTG-KNOW-0007 (Android) and MASTG-KNOW-0062 (iOS). Both are short, and the iOS one is partly wrong, so the sections below go well beyond them. OWASP has no Knowledge item on web content debugging; the third section is ours. Our [CODE hub](/mobile/masvs-code-code-quality-guide/) has one-paragraph summaries of the same items; this note is the full treatment.

### Android: Debuggable Apps (MASTG-KNOW-0007)

Source: [MASTG-KNOW-0007](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0007/).

#### Where the flag comes from

`android:debuggable` is an attribute of the `<application>` element. It applies to the whole app and cannot be overridden per component. **Its default is `false`** in every build; the build tools are what set it:

- The **Android Gradle Plugin** writes `android:debuggable="true"` into the merged manifest for any build type with `isDebuggable = true` (Kotlin DSL) or `debuggable true` (Groovy). The built-in `debug` build type has it on; `release` has it off. Custom build types created with `initWith(getByName("debug"))` inherit `true`, which is a common way for "staging" builds to end up debuggable.
- **Hard-coding** the attribute in the source manifest overrides that logic in confusing ways; Android lint reports it as `HardcodedDebugMode` and recommends leaving it out.
- **Android Studio "Run"** also adds `android:testOnly="true"` to builds it deploys, which prevents normal installation outside `adb install -t`.
- **Google Play rejects debuggable uploads** ("You uploaded a debuggable APK or Android App Bundle"), and the ART documentation repeats that Play does not distribute debuggable apps. A debuggable production app therefore almost always comes from somewhere else: a download page, an alternative store, an enterprise MDM, a tester distribution channel, or a pre-installed build.

At runtime the flag appears as `ApplicationInfo.FLAG_DEBUGGABLE` in `applicationInfo.flags`, and in `dumpsys package` output as `DEBUGGABLE` in `flags=[...]` and `pkgFlags=[...]`.

#### What a debuggable app exposes

When an app is debuggable, the system starts its process with JDWP enabled (the runtime starts a JDWP thread for it), allows debuggers to attach and relaxes several shell-side restrictions. All of the following work on a production (`user` build), unrooted device, from an authorised ADB host:

| Mechanism | What it gives | Command |
|---|---|---|
| **JDWP** (Java Debug Wire Protocol) | Java/Kotlin debugger: method breakpoints, read and set fields and locals, evaluate expressions | `adb jdwp` lists debuggable PIDs; `adb forward tcp:7777 jdwp:<pid>`; `jdb -attach localhost:7777`, or Android Studio's *Attach Debugger* |
| **`run-as`** | A shell as the app's UID in `/data/user/0/<package>`: read and write all private files | `adb shell run-as com.example.app ls -R`; `adb exec-out run-as com.example.app cat databases/app.db > app.db` |
| **Wait for debugger** | Suspend the app at start so a debugger catches early code (root checks, key setup) | `adb shell am set-debug-app -w com.example.app`, or `adb shell am start -D -n com.example.app/.MainActivity` |
| **Native debugging** | LLDB on JNI and native libraries; Android Studio pushes `lldb-server` and starts it through `run-as` as the app's UID | Android Studio *Debug type: Native/Dual*, or a manual `lldb-server` started through `run-as` |
| **JVMTI agents** | Load a native agent into the running app: method tracing, heap walking, class redefinition | `adb shell cmd activity attach-agent <process> <agent.so>` (ART only allows this for debuggable apps) |
| **Heap dumps** | A Java heap snapshot with every live string and byte array | `adb shell am dumpheap <process> /data/local/tmp/app.hprof` |
| **WebView debugging** | DevTools on every WebView in the app, automatically, with WebView 113 or later (see below) | `chrome://inspect` |

`run-as` is the one that matters most in practice. The AOSP source states its rule plainly: it refuses a package that is not debuggable (`package not debuggable`) and otherwise drops to the app's UID and runs the command in the app's data directory ([run-as.cpp](https://android.googlesource.com/platform/system/core/+/refs/heads/main/run-as/run-as.cpp)). It needs no root and no exploit. It also bypasses everything the app did to keep data out of backups (`allowBackup="false"`, `dataExtractionRules`).

#### `ro.debuggable` and devices where every app is debuggable

Whether the *device* treats all apps as debuggable is a separate question, and the answer has changed:

- **Android 13 and earlier:** if the system property `ro.debuggable` is `1` (userdebug and eng builds, many emulator images, many custom ROMs), zygote enables JDWP for **every** app, debuggable or not (`applyDebuggerSystemProperty()` in `Zygote.java`).
- **Android 14:** zygote enables JDWP for all apps only on `eng` builds, or when `persist.debug.dalvik.vm.jdwp.enabled` is `1`.
- **Android 15 and later:** only on `eng` builds, or on `userdebug` builds with `persist.debug.dalvik.vm.jdwp.enabled=1`; a separate `persist.debug.ptrace.enabled` controls native ptrace in the same way.

Two consequences for testing. First, on an emulator or a userdebug device, `adb jdwp` may list your target even though it is not debuggable: **always check the flag on the APK and with `dumpsys`, not by whether a debugger attaches**. Second, the old trick of setting `ro.debuggable=1` on a rooted device to debug every app (MASTG-TECH-0031 still describes it) no longer has that effect on Android 14 and later, because zygote now keys off the build type and the `persist.debug.*` properties instead.

#### Checking debuggability at runtime

Code that should only run in debug builds can test two things:

```kotlin
// Compile time: removed from release builds by R8 as dead code.
if (BuildConfig.DEBUG) { /* debug-only */ }

// Run time: what the installed package actually says.
val isDebuggable = (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
```

`BuildConfig.DEBUG` is the safer guard for debug-only *features* because the code disappears from the release build. Note that AGP 8 no longer generates `BuildConfig` by default (`buildFeatures { buildConfig = true }` turns it back on). `FLAG_DEBUGGABLE` is what to check when you want to know whether the running package is debuggable, which is how an R-profile app refuses to run debuggable in production. An attacker can hook either check, so neither is a security control on its own.

#### How attackers get a debugger anyway

The flag being off does not stop a determined attacker; it forces them to do more work, which is what the rest of this series is about. In general terms: repackaging the APK with the flag set and re-signing it (defeated by signature and integrity checks, [MASWE-0057](/mobile/maswe-0057-app-resources-integrity-not-verified/) and [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/)); hooking frameworks on rooted devices that make the system treat an app as debuggable; and native debugging as root. OWASP's [MASTG-BEST-0007](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0007/) makes the same point. Debugger detection is [MASWE-0064](/mobile/maswe-0064-debugger-detection-not-implemented/).

### iOS: Debuggable Apps (MASTG-KNOW-0062)

Source: [MASTG-KNOW-0062](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CODE/MASTG-KNOW-0062/).

#### `get-task-allow` and code signing

On iOS, debuggability is a property of the **code signature**, not of `Info.plist` or the compiler settings. The signature carries an entitlements blob, and the boolean entitlement `get-task-allow` tells the kernel and `taskgated` that other processes (a debugger) may obtain this process's task port, which is what LLDB and `debugserver` need to read and write memory and registers (iOS's `ptrace` lacks memory read and write; everything goes through Mach task ports, see [MASTG-TECH-0084](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0084/)).

The entitlement comes from the provisioning profile:

| Signing | Profile's `get-task-allow` | Result |
|---|---|---|
| Xcode *Run* / development export | `true` | Debuggable; Xcode attaches LLDB |
| Ad Hoc distribution | `false` | Not debuggable |
| Enterprise (In-House) distribution | `false` | Not debuggable |
| App Store / TestFlight | `false`, and Apple re-signs for distribution | Not debuggable |

Apple's documentation describes the same flow from the other side: Xcode adds the *Get task allow* entitlement to builds for debugging and removes it before App Store submission. So an App Store app downloaded from the store never has it. In practice the finding appears on development-signed builds that reached users: enterprise apps signed with the wrong profile, QA builds distributed beyond the team, apps side-loaded through developer accounts.

#### What a debuggable iOS app enables

With `get-task-allow` set, on a **non-jailbroken** device with Developer Mode on (iOS 16 and later) and a paired Mac:

- **LLDB attach** through Xcode (*Debug > Attach to Process*) or `debugserver`: breakpoints, memory reads of keys and tokens, register changes to flip checks.
- **Dynamic instrumentation without a jailbreak**: tools that inject through the debugging interface, Frida among them, can work with debuggable apps on stock devices (check the current Frida documentation for the exact requirements).
- **Web inspection** for apps built with an SDK older than iOS 16.4 (see the next section).

Without the entitlement, attaching on a stock device fails, and the attacker needs a jailbreak with a `debugserver` re-signed with `task_for_pid-allow`, or a re-signed copy of the app.

#### Where OWASP's item goes wrong

MASTG-KNOW-0062 tells you to make sure the `DEBUG` or `DEBUG_MODE` preprocessor macros, `-D DEBUG` in *Other Swift Flags* and the scheme's *Debug executable* option are off. **None of those controls debuggability.** The macros decide which `#if DEBUG` code is compiled in (debug menus and bypasses that leak into release builds are a [MASWE-0061](/mobile/maswe-0061-debug-artifacts-not-removed/) finding), and *Debug executable* only decides whether Xcode attaches when it launches the app. A Debug-configuration build signed for distribution is not debuggable; a Release-configuration build signed for development is. Check the entitlement on the signed binary. The item also links MASTG-TECH-0031, which is the Android debugging technique (the iOS one is MASTG-TECH-0084), and a macOS notarisation article. Similarly, MASWE-0063 links "the `get-task-allow` entitlement" to Apple's page for `com.apple.security.cs.debugger`, which is a different, macOS-only entitlement: it lets an app **be** a debugger of other processes, the opposite role.

#### Reading entitlements and the provisioning profile

Unzip the IPA ([MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/)) and extract the entitlements from the main binary ([MASTG-TECH-0111](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0111/)). Any of these works:

```bash
codesign -d --entitlements :- Payload/App.app/App      # macOS: raw XML plist
ldid -e Payload/App.app/App                            # macOS or Linux
rabin2 -OC Payload/App.app/App                         # radare2's rabin2, any OS
ipsw macho info -e Payload/App.app/App                 # blacktop/ipsw
```

Then look at the provisioning profile, if there is one. Builds installed from the App Store have no `embedded.mobileprovision`; development, Ad Hoc and Enterprise builds do:

```bash
security cms -D -i Payload/App.app/embedded.mobileprovision > profile.plist
grep -A1 -E 'get-task-allow|ProvisionsAllDevices|<key>Name</key>' profile.plist
grep -c ProvisionedDevices profile.plist   # development and Ad Hoc profiles list device UDIDs
```

App extensions (`PlugIns/*.appex`) and the watch app are signed separately; check each executable.

### Android and iOS: Web content debugging (background)

Not an OWASP Knowledge item; ours. WebView basics, bridges and the bigger WebView attack surface are covered in the PLATFORM notes [MASWE-0033](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/) and [MASWE-0034](/mobile/maswe-0034-webviews-allow-access-to-local-resources/); this section is only about the debugging switch.

#### Android: `setWebContentsDebuggingEnabled`

`WebView.setWebContentsDebuggingEnabled(boolean)` (API 19) is **static and process-wide**: one call makes every WebView in the app debuggable. When enabled, the WebView's DevTools server listens on an abstract Unix socket named `webview_devtools_remote_<pid>`. Desktop Chrome's `chrome://inspect` finds it through ADB and offers a full DevTools session: DOM and CSS, console with JavaScript execution in the page, network requests and responses, cookies and `localStorage`, breakpoints in the page's scripts.

Two details from the platform and Chromium sources:

- **Debuggable apps get it for free.** The Android reference states that with WebView 113.0.5656.0 and later, web contents debugging is enabled automatically if the app is declared `android:debuggable="true"`; otherwise the default is `false`. OWASP's MASTG-TEST-0227 says the WebView flag "works independently" of the debuggable attribute; that is true in one direction (a non-debuggable app can still turn it on) but no longer in the other.
- **Who can connect.** Chromium's DevTools socket accepts connections only from the `shell` user (ADB), `root`, or the app's own UID (`CanUserConnectToDevTools()` in `content/browser/android/devtools_auth.cc`). Another app on the device cannot use it. The attacker position is therefore ADB access to the unlocked device, or root.

Hybrid frameworks wrap the call: Cordova enables it when the app is debuggable, Capacitor has a `webContentsDebuggingEnabled` setting in its configuration, `react-native-webview` has a `webviewDebuggingEnabled` prop, and Flutter's `webview_flutter` has an Android-specific debugging switch. In each case the platform call lives in framework code with a variable argument, so static analysis finds the call site but not the value.

#### iOS: `isInspectable` on `WKWebView` and `JSContext`

Since **iOS 16.4** (macOS 13.3), `WKWebView.isInspectable` and `JSContext.isInspectable` (`inspectable` in Objective-C, `JSGlobalContextSetInspectable` in the C API) decide whether Safari's Web Inspector can attach. Both **default to `false`**, are set per instance and can be changed at any time; setting `false` during inspection closes the inspector. According to WebKit's announcement, apps linked against an SDK *before* iOS 16.4 keep the old behaviour, where web content is inspectable whenever the app is built for debugging (signed with `get-task-allow`). Apps linked against iOS 16.4 SDK or later are inspectable only when they opt in, even in debug builds. App Store submissions have required much newer SDKs for some time, so for a store build the question is simply whether the code sets `isInspectable = true`.

When it does, inspection works on a **stock, non-jailbroken device** with the App Store build: enable *Settings > Safari > Advanced > Web Inspector* on the device and *Show features for web developers* in Safari on a Mac, connect, and the app's web views appear under *Develop > (device)*. The inspector gives the same capabilities as Chrome DevTools: DOM, console with JavaScript execution, network, storage. On jailbroken devices, tweaks such as GlobalWebInspect force inspection for any app, which is why a missing `isInspectable` is not a protection against a jailbroken attacker, only against everyone else. OWASP's [MASTG-TECH-0139](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0139/) describes the Safari set-up.

Apple's own guidance gives one legitimate production use: an in-app browser showing ordinary third-party web content, which would be inspectable in Safari anyway. That is a very different case from a web view that holds the app's session or exposes a bridge.

## Tests

### MASTG-TEST-0226: Debuggable Flag Enabled in the AndroidManifest (Android)

OWASP page: [MASTG-TEST-0226](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0226/). Type: static.

#### Overview

Checks whether the release APK or App Bundle has `android:debuggable="true"` on its `<application>` element. OWASP repeats Android's statement that the flag is "not considered a direct vulnerability"; for a build distributed to users we disagree, because `run-as` alone turns it into private-data disclosure for anyone with ADB access.

#### Prerequisites

- The **release** artefact as distributed: the APK from the download page or MDM, or the APK set pulled from a device that installed the production build (`adb shell pm path com.example.app`, then `adb pull` each path), or the `.aab` from the build pipeline.
- `aapt2` (Android SDK build-tools), and either jadx or apktool. Optionally `semgrep` and `bundletool`.

#### Steps

1. **Quick check with aapt2** ([MASTG-TECH-0150](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0150/)). `aapt2 dump badging` prints `application-debuggable` only when the flag is set:

   ```bash
   aapt2 dump badging app.apk | grep -E "^package:|application-debuggable"
   aapt2 dump xmltree app.apk --file AndroidManifest.xml | grep -i debuggable
   ```

2. **Decode the manifest** ([MASTG-TECH-0117](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/)) for evidence and context (build type hints, `testOnly`, exported debug-only components):

   ```bash
   jadx --no-src -d out app.apk                    # out/resources/AndroidManifest.xml
   # or: apktool d -s -f -o out app.apk           # out/AndroidManifest.xml
   grep -o 'android:debuggable="[a-z]*"' out/resources/AndroidManifest.xml
   grep -o 'android:testOnly="[a-z]*"' out/resources/AndroidManifest.xml
   ```

3. **For an App Bundle**, read the base module's manifest directly:

   ```bash
   bundletool dump manifest --bundle app.aab | grep -E 'debuggable|testOnly'
   ```

4. **For split APKs**, check `base.apk`; the `<application>` flags come from the base.
5. **Note debug-only components** in the same manifest while you are there: an exported `androidx.compose.ui.tooling.PreviewActivity` or a LeakCanary activity are signs of a debug build and belong in [MASWE-0061](/mobile/maswe-0061-debug-artifacts-not-removed/).

#### Observation

The `application-debuggable` line (or its absence) from `aapt2`, the `android:debuggable` attribute from the decoded manifest, and the source of the artefact (store, download page, MDM, tester channel).

#### Evaluation

The test **fails** if `android:debuggable="true"` is present in a build that is, or is meant to be, distributed to users. It **passes** if the attribute is absent or `false`. An absent attribute means `false`.

False positives to rule out: a debug build supplied to you on purpose for testing (record that the release build must be checked separately), and a debuggable flag you added yourself by repackaging.

#### Demo

From [MASTG-DEMO-0040](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0040/MASTG-DEMO-0040/) (OWASP files it under MASVS-PLATFORM). The source manifest hard-codes the flag:

```xml
<application
    android:allowBackup="true"
    android:debuggable="true"
    android:label="@string/app_name"
    tools:targetApi="31">
```

OWASP's semgrep rule `mastg-android-debuggable-flag` matches the attribute in the decoded manifest:

```yaml
rules:
  - id: mastg-android-debuggable-flag
    severity: WARNING
    languages: [xml]
    message: "[MASVS-RESILIENCE-4] debuggable detected as $ARG."
    patterns:
      - pattern: 'android:debuggable="$ARG"'
```

```bash
semgrep -c mastg-android-debuggable-flag.yml AndroidManifest_reversed.xml
```

Output (from the demo, trimmed):

```text
AndroidManifest_reversed.xml
❯❱ mastg-android-debuggable-flag
      [MASVS-RESILIENCE-4] debuggable detected as true.
        5┆ <application android:allowBackup="true" ... android:debuggable="true" ...
```

The same demo manifest also exports `androidx.compose.ui.tooling.PreviewActivity`, the Compose tooling activity that only debug builds should contain.

### MASTG-TEST-0227: Debugging Enabled for WebViews (Android)

OWASP page: [MASTG-TEST-0227](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0227/). Type: static (with a runtime confirmation in GT-RES-0063-2).

#### Overview

Finds calls to `WebView.setWebContentsDebuggingEnabled(true)` that run in release builds. OWASP lists MASTG-KNOW-0028 (debugger detection) as this test's Knowledge, which is not the right reference; the relevant background is the [web content debugging](#android-setwebcontentsdebuggingenabled) section above and the PLATFORM WebView notes.

#### Prerequisites

- The release APK, decompiled with jadx ([MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)) and disassembled to smali with apktool.
- `semgrep` and `grep` ([MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)).

#### Steps

1. **Decompile and find every call site:**

   ```bash
   jadx -d out app.apk
   apktool d -f -o smali_out app.apk
   grep -rn "setWebContentsDebuggingEnabled" out/sources
   grep -rn -B3 "Landroid/webkit/WebView;->setWebContentsDebuggingEnabled(Z)V" smali_out/smali*
   ```

   In smali, the argument is the register loaded just before the call: `const/4 v0, 0x1` is `true`.
2. **Classify each call** by its argument and guard:
   - literal `true` with no guard;
   - guarded by `BuildConfig.DEBUG` (in a release build R8 usually removes the branch, so a surviving unguarded `true` in release code means the guard is not there) or by `(applicationInfo.flags & FLAG_DEBUGGABLE) != 0`;
   - a variable from remote config, `SharedPreferences`, an intent extra, a server response or a hidden settings screen;
   - inside a framework or SDK (Cordova, Capacitor, React Native, Flutter plugin): follow the argument back to the framework's configuration.
3. **Run a rule over the jadx output** to make the sweep repeatable (rule below).
4. **Look for the reverse case**: calls with `false` to turn debugging off after an SDK turned it on are fine, but note them.
5. **Confirm at runtime** where the value is not a literal (GT-RES-0063-2).

#### Observation

Each call site with its class and method, the argument, the guard condition, and whether the code is first-party or a library.

#### Evaluation

The test **fails** if `setWebContentsDebuggingEnabled(true)` can execute in the release build: called unconditionally, or under a condition that a user, a server or an attacker with ADB access can make true (remote config, a preference, an intent extra, a debug screen reachable in production). It **passes** if there are no calls, all calls pass `false`, or every `true` call is guarded by `BuildConfig.DEBUG` or `FLAG_DEBUGGABLE` (and the release build is not debuggable, per MASTG-TEST-0226).

OWASP fails the test only when the `FLAG_DEBUGGABLE` check is missing; a `BuildConfig.DEBUG` guard is equally correct, and arguably better because the code is removed from release builds.

#### Demo

OWASP has no demo for this test. A minimal vulnerable sample and our semgrep rule:

```kotlin
class App : Application() {
    override fun onCreate() {
        super.onCreate()
        WebView.setWebContentsDebuggingEnabled(true)   // every WebView, every build
    }
}
```

```yaml
# gt-webview-debugging.yml - run against jadx Java output
rules:
  - id: gt-android-webview-debugging-enabled
    languages: [java]
    severity: WARNING
    message: WebView debugging enabled; check that this call is debug-only
    pattern-either:
      - pattern: WebView.setWebContentsDebuggingEnabled(true)
      - pattern: android.webkit.WebView.setWebContentsDebuggingEnabled(true)
```

```bash
semgrep -c gt-webview-debugging.yml out/sources
```

Illustrative output:

```text
out/sources/com/example/app/App.java
❯❱ gt-android-webview-debugging-enabled
      WebView debugging enabled; check that this call is debug-only
       14┆ WebView.setWebContentsDebuggingEnabled(true);
```

### MASTG-TEST-0261: Debuggable Entitlement Enabled in the entitlements.plist (iOS)

OWASP page: [MASTG-TEST-0261](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0261/). Type: static.

#### Overview

Checks whether the signed app binary carries `get-task-allow` set to `true`. The title says "entitlements.plist", but the project's entitlements file is not what matters: the provisioning profile used at signing decides the final value. Always check the signed binary.

#### Prerequisites

- The IPA **as distributed**: from the enterprise portal or MDM, the tester channel, or the store (decrypted from a jailbroken device if you need the binary itself; the entitlements blob survives decryption).
- A Mac with `codesign` and `security`, or `ldid`, `rabin2` or `ipsw` on any OS.
- Know how you obtained the IPA. If **you** re-signed it (for Frida Gadget injection, or to install a decrypted copy with your own development certificate), the entitlements now reflect your signing, not the client's.

#### Steps

1. **Unzip** the IPA ([MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/)): `unzip -q app.ipa -d ipa`.
2. **Extract the entitlements** of the main binary and every extension ([MASTG-TECH-0111](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0111/)):

   ```bash
   for b in ipa/Payload/*.app/$(plutil -extract CFBundleExecutable raw -o - ipa/Payload/*.app/Info.plist) \
            ipa/Payload/*.app/PlugIns/*.appex/*; do
     [ -f "$b" ] && file "$b" | grep -q Mach-O || continue
     echo "== $b"
     codesign -d --entitlements :- "$b" 2>/dev/null | grep -A1 get-task-allow
   done
   ```

   On Linux, replace the `codesign` line with `ldid -e "$b" | grep -A1 get-task-allow` or `rabin2 -OC "$b" | grep -A1 get-task-allow`.
3. **Check the provisioning profile**, if present:

   ```bash
   ls ipa/Payload/*.app/embedded.mobileprovision 2>/dev/null && \
     security cms -D -i ipa/Payload/*.app/embedded.mobileprovision | grep -A1 -E 'get-task-allow|<key>Name</key>|ProvisionsAllDevices'
   ```

   No profile at all is normal for an App Store install. A profile with a `ProvisionedDevices` list and `get-task-allow` `true` is a development profile.

#### Observation

The entitlements of each executable, the `get-task-allow` value, and the profile name and type.

#### Evaluation

The test **fails** if `get-task-allow` is present and `true` on any executable of a build distributed to users. It **passes** if the key is absent or `false`. A development-signed build that you received for testing, or that you re-signed yourself, is not a finding against the production app; record it and check the distributed build.

#### Demo

From [MASTG-DEMO-0036](https://mas.owasp.org/MASTG/demos/ios/MASVS-RESILIENCE/MASTG-DEMO-0036/MASTG-DEMO-0036/). The sample's entitlements:

```xml
<plist version="1.0">
<dict>
    <key>get-task-allow</key>
    <true/>
</dict>
</plist>
```

```bash
rabin2 -OC MASTestApp | grep -A1 get-task-allow
```

Output:

```text
        <key>get-task-allow</key>
        <true/>
```

The test fails: the binary was signed with a development profile and any paired Mac with Developer Mode on the device can attach LLDB to it.

### GT-RES-0063-1: Web content inspection enabled in WKWebView or JSContext (iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

OWASP has an Android test for WebView debugging but none for iOS, although `isInspectable` has existed since iOS 16.4 and works on stock devices with App Store builds. This test finds web views and JavaScript contexts that opt in to Web Inspector in production.

#### Prerequisites

- The decrypted app binary and frameworks; radare2/rabin2 or Ghidra.
- A stock (non-jailbroken) iPhone with the **production** build installed, a Mac with Safari, and a cable. Optionally a jailbroken device with Frida for the trace.

#### Steps

1. **Static: find the opt-in.** Swift's `webView.isInspectable = true` compiles to an Objective-C message `setInspectable:`; the C API is `JSGlobalContextSetInspectable`:

   ```bash
   for b in Payload/App.app/App Payload/App.app/Frameworks/*.framework/*; do
     [ -f "$b" ] || continue
     rabin2 -zz "$b" 2>/dev/null | grep -q 'setInspectable:' && echo "selector: $b"
     rabin2 -i "$b" 2>/dev/null | grep -q JSGlobalContextSetInspectable && echo "C API: $b"
   done
   ```

   In Ghidra or r2, follow cross-references from the `setInspectable:` selector reference to each call site and read the value passed in `w2` (`mov w2, #1` is `true`), and whether the call sits behind an `#available(iOS 16.4, *)` check only (normal) or also behind something that should not exist in release (a remote flag, a user default).
2. **Dynamic, stock device: does Safari see it?** Enable *Settings > Safari > Advanced > Web Inspector* on the device and *Show features for web developers* in Safari on the Mac. Connect the device, open each screen of the app that contains web content, and look under *Develop > (device name)*. Any entry for the app is an inspectable web view or context in the build you are holding. Open it and note what the inspector shows: URL, cookies and storage, whether the app's session is present, and which `window.webkit.messageHandlers` exist (type `Object.keys(window.webkit.messageHandlers)` in the console).
3. **Optional trace (jailbroken device).** Log calls to the setter with their argument and caller, without changing them:

   ```javascript
   // trace-inspectable.js (Frida, ObjC bridge) - observe only
   for (const cls of ['WKWebView', 'JSContext']) {
     const m = ObjC.classes[cls] && ObjC.classes[cls]['- setInspectable:'];
     if (!m) continue;
     Interceptor.attach(m.implementation, {
       onEnter(args) {
         console.log('[app] ' + cls + ' setInspectable:' + (args[2].toInt32() & 1) + '\n' +
           Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n'));
       }
     });
   }
   ```

   ```bash
   frida -U -f com.example.app -l trace-inspectable.js
   ```

#### Observation

The binaries and call sites that set `isInspectable`, the argument, the screens whose web content appears in Safari's Develop menu with the production build, and what each inspectable context holds (session cookies or tokens, bridges, content origin).

#### Evaluation

The test **fails** if a production build makes a `WKWebView` or `JSContext` inspectable that shows authenticated or sensitive content, holds the app's session, injects app scripts, or exposes message handlers. It **passes** if no production web view or context is inspectable, or the only inspectable one is an in-app browser for third-party content with no app session or bridge (record that as an observation).

#### Demo

Vulnerable and fixed Swift:

```swift
// Vulnerable: every account web view is inspectable in the App Store build
let webView = WKWebView(frame: .zero, configuration: config)
if #available(iOS 16.4, *) { webView.isInspectable = true }

// Fixed: debug builds only
#if DEBUG
if #available(iOS 16.4, *) { webView.isInspectable = true }
#endif
```

Illustrative static output for the vulnerable build:

```text
selector: Payload/App.app/App
```

and in Safari on the Mac, *Develop > Test iPhone* lists `App — https://account.example.com/statements`, with the session cookie visible under *Storage*.

### GT-RES-0063-2: Debug mechanisms in the installed build and runtime toggles (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Static tests look at an artefact. This test confirms what the build installed from the real distribution channel actually allows, demonstrates impact for the report, and catches debug switches that only turn on at runtime (remote configuration, hidden settings, server flags). It carries forward the dynamic checks of the legacy MASTG-TEST-0039 and MASTG-TEST-0082.

#### Prerequisites

- The production build installed from its real channel on a **production** Android device (`ro.build.type` = `user`; check with `adb shell getprop ro.build.type`) and on a stock iPhone with Developer Mode on and a paired Mac with Xcode.
- A test account. Optionally a rooted/jailbroken device with Frida for the runtime-toggle trace.

#### Steps

**Android**

1. **Confirm the package flags** on the device:

   ```bash
   adb shell getprop ro.build.type                      # must be "user" for a meaningful result
   adb shell dumpsys package com.example.app | grep -E "^ *(flags|pkgFlags)="
   ```

2. **Prove `run-as`** with a harmless command, then list (not exfiltrate more than you need) the private files:

   ```bash
   adb shell run-as com.example.app id
   adb shell run-as com.example.app ls -la shared_prefs databases files
   ```

   A non-debuggable app returns `run-as: package not debuggable: com.example.app`.
3. **Prove JDWP**: start the app, then `adb jdwp` (the app's PID should be listed) and attach `jdb` through `adb forward tcp:7777 jdwp:<pid>`; `classes` or `threads` in `jdb` is enough evidence.
4. **Check WebView debugging at runtime.** Open each WebView screen, then:

   ```bash
   adb shell cat /proc/net/unix | grep -o 'webview_devtools_remote_[0-9]*' | sort -u
   adb shell pidof com.example.app
   ```

   A socket whose number matches the app's PID means DevTools can attach; confirm in `chrome://inspect/#devices`. (`chrome_devtools_remote` belongs to the Chrome browser, not to the app.)
5. **Look for runtime toggles.** Trace who calls the WebView switch and with what value, on a rooted test device, without changing it:

   ```javascript
   // trace-webview-debug.js - observe only
   Java.perform(() => {
     const WV = Java.use('android.webkit.WebView');
     WV.setWebContentsDebuggingEnabled.implementation = function (on) {
       console.log('[app] setWebContentsDebuggingEnabled(' + on + ')\n' +
         Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new()));
       return this.setWebContentsDebuggingEnabled(on);
     };
   });
   ```

   Exercise the app, including any hidden developer screen you found statically, and note whether the value depends on remote configuration or a preference.

**iOS**

1. **Attach a debugger** to the running production app from Xcode (*Debug > Attach to Process*, choose the app). With `get-task-allow` it attaches; without it, Xcode reports that it cannot attach. That single result is your dynamic evidence for MASTG-TEST-0261.
2. **Check Web Inspector** as in GT-RES-0063-1, step 2.
3. **Runtime toggles**: on a jailbroken test device, run the trace from GT-RES-0063-1 while exercising remote-config refreshes and any hidden settings.

#### Observation

`ro.build.type`, the `dumpsys` flags, `run-as` and `jdb` output, DevTools sockets matched to the app's PID, the Xcode attach result, the Safari Develop menu entries, and the traced calls with their callers and conditions.

#### Evaluation

The test **fails** if, on a production device with the production build, `run-as` or a debugger works, a DevTools socket or Web Inspector entry for the app appears, or a remote or user-reachable toggle turns web content debugging on. It **passes** if all of these are refused. A result on a `userdebug` or `eng` device, an emulator, or a re-signed build does not count.

#### Demo

Illustrative output for a debuggable release build on a production device:

```text
$ adb shell getprop ro.build.type
user
$ adb shell dumpsys package com.example.app | grep -E "^ *(flags|pkgFlags)="
    flags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ]
    pkgFlags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ]
$ adb shell run-as com.example.app ls shared_prefs
auth_session.xml
com.example.app_preferences.xml
```

and for a correctly built one:

```text
$ adb shell run-as com.example.app id
run-as: package not debuggable: com.example.app
```

## Best practices

### MASTG-BEST-0007: Debuggable Flag Disabled in the AndroidManifest (Android)

OWASP page: [MASTG-BEST-0007](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0007/).

Let the build system own the flag and verify the output:

```kotlin
// build.gradle.kts
android {
    buildTypes {
        getByName("release") {
            isDebuggable = false          // the default; state it so reviews see it
            isMinifyEnabled = true
        }
        create("staging") {
            initWith(getByName("release")) // not "debug", or staging inherits isDebuggable = true
            matchingFallbacks += listOf("release")
        }
    }
    lint { fatal += "HardcodedDebugMode" }
}
```

- Remove any `android:debuggable` attribute from source manifests.
- Add a CI gate on the artefact you publish:

  ```bash
  if aapt2 dump badging app-release.apk | grep -q application-debuggable; then
    echo "release APK is debuggable" >&2; exit 1
  fi
  ```

- Use `<profileable android:shell="true"/>` (Android 10+) in builds you need to profile.
- OWASP's note applies: the flag being off is a first step. An attacker can repackage the app or use instrumentation; for R-profile apps add debugger detection ([MASWE-0064](/mobile/maswe-0064-debugger-detection-not-implemented/)) and integrity checks.

### MASTG-BEST-0008: Debugging Disabled for WebViews (Android)

OWASP page: [MASTG-BEST-0008](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0008/).

- Do not call `setWebContentsDebuggingEnabled(true)` in release code. On WebView 113 and later, debuggable builds get WebView debugging automatically, so in many apps the call can simply be deleted.
- If you keep it, guard it by build:

  ```kotlin
  if (BuildConfig.DEBUG) {
      WebView.setWebContentsDebuggingEnabled(true)
  }
  // or, at run time:
  if ((applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
      WebView.setWebContentsDebuggingEnabled(true)
  }
  ```

  OWASP's example also checks `Build.VERSION_CODES.KITKAT`; with any current `minSdk` that check is redundant.
- Set the equivalent option off in hybrid framework configuration for release builds.
- Never drive the flag from remote configuration, a preference or a server response.

OWASP notes that exploitation needs an unlocked device with ADB access, and that an attacker can still patch the app or hook the method to enable debugging. Both are true; the second is why R-profile apps also need integrity checks and instrumentation detection ([MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/), [MASWE-0065](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/)).

### iOS: distribution signing and inspectability (Guler Tech)

No OWASP best practice exists for iOS; ours:

- Export every build that leaves the development team with a **distribution** method (App Store Connect, Ad Hoc, Enterprise), never Development, and check the result in CI:

  ```bash
  APP=$(find build/export -name '*.app' -maxdepth 3 | head -1)
  if codesign -d --entitlements :- "$APP" 2>/dev/null | grep -A1 get-task-allow | grep -q '<true/>'; then
    echo "exported build is debuggable" >&2; exit 1
  fi
  ```

- Wrap every `isInspectable = true` (and `JSGlobalContextSetInspectable`) in `#if DEBUG`, and set the hybrid framework's inspection option off for release.
- If an in-app browser for third-party content is deliberately inspectable, keep it in a separate web view with its own non-persistent `WKWebsiteDataStore`, no app session and no message handlers.
- Do not rely on the `DEBUG` macro for anything security-related; it does not decide whether the app is debuggable.

## Rating findings

The series-wide rule for RESILIENCE is that missing resilience controls are rated low unless they enable concrete abuse. **This weakness is the exception**: a debug mechanism switched on in a release build is a vulnerability for every app, whatever its profile, because it hands the platform's own debugging and data-access tools to anyone with ADB or Web Inspector access to the unlocked device. The attacker position (physical or ADB access to an unlocked device with developer access) keeps it below Critical.

| Rating | Conditions |
|---|---|
| **High** | `android:debuggable="true"` or `get-task-allow` in a build distributed to end users (download page, alternative store, enterprise MDM fleet, tester channel with real customer accounts) of an app that stores credentials, tokens or sensitive personal or financial data, demonstrated with `run-as` file access or a debugger attach. WebView debugging or `isInspectable` in a production build where the web content holds the user's authenticated session or exposes a bridge to sensitive native functionality, demonstrated in DevTools or Web Inspector. |
| **Medium** | The same mechanisms in a production build of an app with less sensitive data; WebView debugging or inspection on authenticated content with no sensitive bridge; a toggle reachable at runtime (remote config, hidden setting) that enables WebView debugging in production. |
| **Low** | Debuggable or development-signed pre-release builds distributed to a closed group against non-production data (rate the pipeline weakness that lets it happen); inspectable web views showing only public content but carrying app scripts. |
| **Info** | Builds supplied for testing as debug builds, or re-signed by the tester; apps that only appear debuggable on `userdebug`/`eng` devices or emulators; debug calls correctly guarded by `BuildConfig.DEBUG`, `FLAG_DEBUGGABLE` or `#if DEBUG`; a deliberately inspectable in-app browser for third-party content with no app session or bridge; KNOW-0062-style `DEBUG` macro observations with no effect on the signature. |

Raise a level for an R-profile app (banking, payments, wallet, DRM) where the debugger directly unlocks the abuse the app's threat model is about, for example stepping past a transaction-signing check or reading a wallet key from memory. Lower a level when the only exposure is a WebView that never handles authenticated content.

In the report give: the artefact and its distribution channel, the exact evidence (`aapt2` line, entitlements XML, call site with guard), the dynamic proof on a production device (`run-as` listing, `jdb` attach, Xcode attach, DevTools or Web Inspector screenshot description), what data or functionality that exposed, and the build setting or code change that fixes it.

## References

- OWASP MASWE: [MASWE-0063: Debug Mechanisms Not Disabled](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0063/); related [MASWE-0061](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0061/), [MASWE-0064](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0064/), [MASWE-0062](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0062/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-RESILIENCE-4](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-4/), [MASVS-PLATFORM-2](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-2/) (CC BY-SA 4.0)
- OWASP MASTG knowledge: [MASTG-KNOW-0007](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0007/), [MASTG-KNOW-0062](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CODE/MASTG-KNOW-0062/) (CC BY-SA 4.0)
- OWASP MASTG tests: [MASTG-TEST-0226](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0226/), [MASTG-TEST-0227](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0227/), [MASTG-TEST-0261](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0261/); legacy [MASTG-TEST-0039](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0039/), [MASTG-TEST-0082](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0082/) (CC BY-SA 4.0)
- OWASP MASTG demos: [MASTG-DEMO-0040](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0040/MASTG-DEMO-0040/), [MASTG-DEMO-0036](https://mas.owasp.org/MASTG/demos/ios/MASVS-RESILIENCE/MASTG-DEMO-0036/MASTG-DEMO-0036/) (CC BY-SA 4.0)
- OWASP MASTG best practices: [MASTG-BEST-0007](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0007/), [MASTG-BEST-0008](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0008/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0117](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/), [MASTG-TECH-0150](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0150/), [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0031](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0031/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0084](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0084/), [MASTG-TECH-0111](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0111/), [MASTG-TECH-0139](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0139/) (CC BY-SA 4.0)
- OWASP MASTG tools: [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/), [rabin2 (MASTG-TOOL-0129)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/), [ldid (MASTG-TOOL-0111)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0111/), [codesign (MASTG-TOOL-0114)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0114/), [aapt2 (MASTG-TOOL-0124)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0124/), [jdb (MASTG-TOOL-0019)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0019/) (CC BY-SA 4.0)
- Sibling notes: [MASWE-0062 no application-level payload encryption](/mobile/maswe-0062-no-application-level-payload-encryption/), [MASWE-0061](/mobile/maswe-0061-debug-artifacts-not-removed/), [MASWE-0064](/mobile/maswe-0064-debugger-detection-not-implemented/), [MASWE-0065](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/); PLATFORM: [MASWE-0033](/mobile/maswe-0033-sensitive-native-functionality-exposed-in-webviews/), [MASWE-0034](/mobile/maswe-0034-webviews-allow-access-to-local-resources/), [PLATFORM hub](/mobile/masvs-platform-platform-interaction-guide/)
- Android: [`<application>` element](https://developer.android.com/guide/topics/manifest/application-element), [Risks: android:debuggable](https://developer.android.com/privacy-and-security/risks/android-debuggable), [Prepare your app for release](https://developer.android.com/studio/publish/preparing), [`WebView.setWebContentsDebuggingEnabled`](https://developer.android.com/reference/android/webkit/WebView#setWebContentsDebuggingEnabled%28boolean%29), [Remote debug WebViews](https://developer.chrome.com/docs/devtools/remote-debugging/webviews/), [`<profileable>`](https://developer.android.com/guide/topics/manifest/profileable-element), [ART TI](https://source.android.com/docs/core/runtime/art-ti), [run-as.cpp](https://android.googlesource.com/platform/system/core/+/refs/heads/main/run-as/run-as.cpp), [Zygote.java](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/com/android/internal/os/Zygote.java)
- Chromium: [aw_devtools_server.cc](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/android_webview/browser/aw_devtools_server.cc), [devtools_auth.cc](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/content/browser/android/devtools_auth.cc)
- Apple: [`WKWebView.isInspectable`](https://developer.apple.com/documentation/webkit/wkwebview/isinspectable), [`JSContext.isInspectable`](https://developer.apple.com/documentation/javascriptcore/jscontext/isinspectable), [Debugging tool entitlement (`com.apple.security.cs.debugger`, macOS)](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.debugger), [Inspecting iOS and iPadOS](https://developer.apple.com/documentation/safari-developer-tools/inspecting-ios), [Enabling Developer Mode on a device](https://developer.apple.com/documentation/xcode/enabling-developer-mode-on-a-device); WebKit: [Enabling the Inspection of Web Content in Apps](https://webkit.org/blog/13936/enabling-the-inspection-of-web-content-in-apps/)
- CWE: [CWE-489](https://cwe.mitre.org/data/definitions/489.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
