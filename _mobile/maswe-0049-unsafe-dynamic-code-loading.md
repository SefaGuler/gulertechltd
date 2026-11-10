---
title: "MASWE-0049: Unsafe Dynamic Code Loading"
date: 2026-11-10 10:08:00 +0000
subcategory: code
summary: "Testing Android and iOS apps that load DEX, native libraries, other packages' code or OTA script bundles at runtime from writable or unverified sources."
refs: [MASWE-0049, MASVS-CODE-4, CWE-494]
tags: [android, ios, masvs-code, dynamic-code-loading, code-integrity, ota-updates]
---

This note is part of our [MASVS-CODE guide](/mobile/masvs-code-code-quality-guide/) and covers OWASP [MASWE-0049](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0049/): apps that load and run code they did not ship in their signed package, from a place someone else can write to, or without checking that the code is what the developer published. On Android that means class loaders pointed at DEX, JAR or APK files, `System.load()` on native libraries, and `createPackageContext()` with code inclusion. On iOS, the operating system blocks unsigned native code on stock devices, so the risk moves to interpreted code: JavaScriptCore scripts, React Native and Expo over-the-air (OTA) bundles, Lua and similar engines. In every case the question is the same. If an attacker can change the bytes the app is about to execute, they get code execution *as the app*, with its permissions, its tokens and its data. **OWASP has no tests and no Knowledge pages for this weakness yet.** The background sections below are our own, and the four tests are Guler Tech methodology, numbered `GT-CODE-0049-1` to `-4`. No legacy MASTG v1 test covered this weakness, so none are replaced.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Background](#background)
  - [Android: class loaders and DEX files](#android-class-loaders-and-dex-files)
  - [Android: native libraries](#android-native-libraries)
  - [Android: code from other packages](#android-code-from-other-packages)
  - [Android: where code can come from and who can write it](#android-where-code-can-come-from-and-who-can-write-it)
  - [Android: managed delivery with Play Feature Delivery](#android-managed-delivery-with-play-feature-delivery)
  - [Android: Google Play policy](#android-google-play-policy)
  - [iOS: code signing, dlopen and NSBundle](#ios-code-signing-dlopen-and-nsbundle)
  - [iOS: App Store rules on downloaded code](#ios-app-store-rules-on-downloaded-code)
  - [Cross-platform: interpreted code and OTA updates](#cross-platform-interpreted-code-and-ota-updates)
  - [Integrity verification of delivered code](#integrity-verification-of-delivered-code)
- [Tests](#tests)
  - [GT-CODE-0049-1: References to dynamic code loading from non-constant or writable paths (Android)](#gt-code-0049-1-references-to-dynamic-code-loading-from-non-constant-or-writable-paths-android)
  - [GT-CODE-0049-2: Runtime tracing of loaded code and its file permissions (Android)](#gt-code-0049-2-runtime-tracing-of-loaded-code-and-its-file-permissions-android)
  - [GT-CODE-0049-3: Integrity verification of downloaded code (Android, iOS)](#gt-code-0049-3-integrity-verification-of-downloaded-code-android-ios)
  - [GT-CODE-0049-4: Native loading, OTA bundles and downloaded scripts (iOS)](#gt-code-0049-4-native-loading-ota-bundles-and-downloaded-scripts-ios)
- [Secure implementation](#secure-implementation)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

The OWASP requirement is *"The app loads dynamic code safely from trusted sources."* MASWE-0049 maps to MASVS-CODE-4 ("The app validates and sanitizes all untrusted inputs"), because code fetched or read at runtime is input like any other, only with the worst possible sink. The CWE is [CWE-494](https://cwe.mitre.org/data/definitions/494.html) (Download of Code Without Integrity Check). Android's risk catalogue has two matching pages: [Dynamic code loading](https://developer.android.com/privacy-and-security/risks/dynamic-code-loading) and [createPackageContext](https://developer.android.com/privacy-and-security/risks/create-package-context). OWASP also links Android's App Bundles core app quality guideline, which points at the safe, managed way to deliver code on demand. The weakness is tagged for profiles **L2** and **EUDIW**, not L1, and corresponds to MASWE-0085 in OWASP's earlier beta catalogue.

OWASP describes the threat as MAS-THREAT-0049, *"Attackers can execute arbitrary code within the app's context"*, reached through two attacks:

| Attack | Description | Attacker position |
|---|---|---|
| MAS-ATTACK-0057 | Substituting or modifying code that the app loads at runtime from writable or unverified locations | Another app on the device (shared storage, a squatted package name); whoever controls the server, CDN or update service; in rare cases physical access or a restored backup |
| MAS-ATTACK-0014 | Performing a machine-in-the-middle (MITM) attack, e.g. via ARP poisoning, DNS spoofing or a rogue access point | Network attacker, when code is downloaded over cleartext or TLS that the app does not validate properly |

Dynamic code loading itself is not the finding. Android's own platform uses it (split APKs, WebView, Play Feature Delivery) and so do many legitimate frameworks. The finding is **loading code whose integrity and origin the app cannot vouch for**. You prove that by answering three questions for each load site: where do the bytes come from, who else can write them on the way, and does the app check them against something an attacker cannot also replace?

Keep the neighbouring weaknesses apart:

| Question | Where it lives |
|---|---|
| Does the app load code at runtime from a writable or unverified source? | This note (MASWE-0049) |
| Is the signature check itself correct (algorithm, key handling, result checked)? | [MASWE-0011](/mobile/maswe-0011-improper-signature-verification/) |
| Does a bundled SDK or library contain or fetch malicious code? | [MASWE-0048](/mobile/maswe-0048-malicious-code-included-in-the-app/) |
| Does the app use a dependency with known vulnerabilities (including an OTA framework)? | [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/) |
| Does a WebView load untrusted content, or expose a JavaScript bridge to it? | [MASWE-0035](/mobile/maswe-0035-webviews-loading-untrusted-content/) |
| Does the app hide code with packers or encrypted DEX to resist analysis? | MASVS-RESILIENCE ([MASTG-KNOW-0033](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0033/)); a finding here only if the hidden code is loaded from a writable place |
| Can non-code resources (configuration, downloaded content) be tampered with? | MASWE-0057 (MASVS-RESILIENCE), which points back here for code |

## Modes of Introduction

**Loading from writable or shared storage.** A plugin, patch or SDK component is written to external storage (`getExternalFilesDir()`, `Download/`, a removable card) or to a world-writable file, and loaded from there with `DexClassLoader` or `System.load()`. On devices where other apps can write to that path, they can replace the file between download and load, or at any later start.

**Downloading code without authenticating it.** The app fetches a DEX, JAR, APK, `.so`, JavaScript bundle or Lua script from a server and runs it. Either there is no check at all, or the check is a hash that comes from the same server as the code. That catches corruption, but anyone who can swap the code can also swap the hash. Downloads over `http://`, or over TLS with broken certificate validation ([MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/)), add the network attacker to the list.

**Trusting another package by name.** The app calls `createPackageContext(name, CONTEXT_INCLUDE_CODE or CONTEXT_IGNORE_SECURITY)` for a companion app or plugin, or builds a `PathClassLoader` over another app's `sourceDir`, without checking that app's signing certificate. If the expected app is not installed, any app that claims the package name is loaded instead.

**OTA script updates without code signing.** React Native (CodePush, Expo Updates), Capacitor and Cordova live updates, Shorebird for Flutter and home-grown script engines replace app logic after release. Most of these systems offer update signing, but it is optional and frequently not switched on. The script then runs with every native capability the bridge exposes.

**Hot-fix and plugin frameworks.** Android hot-fix libraries that swap DEX at runtime, iOS "hot patching" libraries that map downloaded scripts onto `performSelector:` and method swizzling, and game engines that download Lua. These are high-risk by design and conflict with store policy as well.

**Third-party SDKs that fetch code.** Ad, analytics or "remote feature" SDKs that download DEX or native code. The app developer often does not know. You find them with the same tests, and report them here and under [MASWE-0048](/mobile/maswe-0048-malicious-code-included-in-the-app/) when the behaviour is undisclosed.

**Verify-then-load races.** The app verifies a file, then loads it again by path from a location another party can write to, or downloads it a second time for loading. The verified bytes are not the executed bytes (time-of-check to time-of-use).

## Impact

- **Code execution with the app's identity.** Loaded DEX and native code run in the app's process, with its UID, permissions, Keystore and Keychain access (within the access-control rules of the keys), session tokens and private files. Script code runs with whatever the bridge offers, which in React Native and Capacitor is usually a lot: storage, networking, crypto, device APIs.
- **Persistence.** A replaced plugin or bundle is usually cached and loaded on every start, so one successful substitution survives restarts and sometimes app updates.
- **Fleet-wide compromise.** When the source is a server, CDN or update service, one compromise there reaches every installed copy. This is why a pinned signature, not TLS alone, is the expected control.
- **Denial of service.** Even an attacker who can only corrupt or delete the code breaks the feature or the whole app. Android's own risk page notes the availability impact.
- **Store enforcement.** Downloading executable code violates Google Play's Device and Network Abuse policy and App Store Review Guideline 2.5.2. That is a compliance risk on top of the security one.

## Mitigations

- **Do not load code at runtime if you can ship it.** Put everything in the signed APK, AAB or IPA. For on-demand modules on Android, use Play Feature Delivery, which installs signed splits through Google Play.
- **Load only from locations that only the app (or the installer) can write**: the APK install directory, or app-internal storage. Never external or shared storage, never another app's files.
- **Verify a signature over every delivered bundle against a public key pinned in the app** before loading it. Verify the exact bytes you load, keep the file read-only after writing it, and protect against rollback with a signed version number.
- **Verify the signing certificate of any package** whose code or context you load (`PackageManager.hasSigningCertificate()`), and never combine `CONTEXT_INCLUDE_CODE` with `CONTEXT_IGNORE_SECURITY` without that check.
- **For OTA frameworks, switch code signing on** (CodePush public key, Expo Updates code signing, Shorebird patch signing, Capacitor live-update signing) and keep the private key out of CI logs and source control.
- **Keep the native bridge small.** Downloaded or interpreted code should not be able to reach credential storage, payments or arbitrary file and network access through it.
- **Use TLS with proper validation for every download**, and treat it as transport protection, not as code authentication.

## Background

There are no OWASP Knowledge pages for this weakness. The sections below explain the mechanisms a tester needs to recognise, with the platform behaviour that decides whether a load site is exploitable.

### Android: class loaders and DEX files

Android apps run Java and Kotlin code as DEX bytecode in ART. The app's own code is loaded at start-up by a `PathClassLoader` over the installed `base.apk` and any split APKs. Everything else that executes DEX goes through the classes in [`dalvik.system`](https://developer.android.com/reference/dalvik/system/package-summary):

| API | Since | What it loads | Notes for testers |
|---|---|---|---|
| `DexClassLoader(dexPath, optimizedDirectory, librarySearchPath, parent)` | API 3 | DEX, JAR or APK files from any path, `:`-separated | The classic plugin loader. `optimizedDirectory` is deprecated and ignored from API 26 |
| `PathClassLoader(dexPath, parent)` and `(dexPath, librarySearchPath, parent)` | API 1 | Same as above | Used by the system for the app itself; in app code it is as dangerous as `DexClassLoader` |
| `DelegateLastClassLoader(dexPath, parent)` | API 27 | Same, but looks in its own path before the parent | Lets loaded code shadow classes of the app or libraries |
| `InMemoryDexClassLoader(ByteBuffer, parent)` and array variants | API 26 | DEX bytes from memory | No file on disk; used by packers and by code that decrypts or downloads DEX |
| `BaseDexClassLoader` | API 14 | Superclass of all of the above | One hook point for runtime tracing |
| `DexFile.loadDex()`, `new DexFile()` | API 1, deprecated in API 26 | DEX, JAR or APK | Still found in old SDKs and packers |

Whatever the loader, the result is the same. Once `loadClass()` returns and the code calls into the class, its static initialisers, constructors and methods run in the app's process. Loading code "only to read a few constants" is still code execution.

Platform changes that matter:

| Release | Applies to | Change |
|---|---|---|
| Android 8.0 (API 26) | All | `InMemoryDexClassLoader` added; `DexFile` deprecated; `optimizedDirectory` ignored |
| Android 10 (API 29) | Apps targeting 29+ | `execve()` on files in the app's home directory is blocked (a [W^X](https://en.wikipedia.org/wiki/W%5EX) rule); libraries opened with `dlopen()` can no longer be mapped executable through a writable file descriptor, which also breaks `.so` files with text relocations |
| Android 10 (API 29) | All | ART no longer runs `dex2oat` in the app process and only accepts system-generated OAT files; secondary DEX files are compiled in the background |
| Android 14 (API 34) | Apps targeting 34+ | **All dynamically loaded files must be read-only.** If a DEX, JAR or APK passed to a class loader is writable, loading fails with `java.lang.SecurityException: Writable dex file '…' is not allowed` (thrown from `DexFile.openDexFileNative`) |

The Android 10 change is described on the [Android 10 behaviour changes](https://developer.android.com/about/versions/10/behavior-changes-10) page under "Removed execute permission for app home directory". It stops apps from running downloaded executables, but **it does not stop `DexClassLoader` or `System.load()`** from loading files in the app's own data directory. Do not report it as a mitigation for class-loader findings.

The Android 14 rule comes from the [Android 14 behaviour changes](https://developer.android.com/about/versions/14/behavior-changes-14) ("Safer dynamic code loading"). Google's guidance is to call `setReadOnly()` on the file as soon as it is opened for writing and before content is written, and to delete and recreate existing files rather than re-labelling them, or to verify their integrity first if you do re-label them. Three things to keep in mind when you assess an app:

- The rule protects against *the app's own process* or a same-UID component accidentally leaving code writable. It is not an integrity check. The owner can `chmod` the file back. A file on shared storage that another app replaced is still loaded if it arrives read-only.
- It applies by **target SDK**. An app targeting 33 runs on Android 14, 15 and 16 without the check.
- It concerns files handed to `DexFile` (and thus all file-based class loaders). `InMemoryDexClassLoader` has no file. Native libraries are governed by SELinux and the Android 10 W^X rules, not by this check.

When you see a crash with the `Writable dex file` message on a test device, you have found a dynamic loading site, often inside a third-party SDK. The message names the path.

### Android: native libraries

Native code is loaded through the dynamic linker. Java code reaches it with:

- `System.loadLibrary("foo")`: resolves `libfoo.so` in the app's native library path, which is the APK's `lib/<abi>/` directory or the extracted `nativeLibraryDir` under `/data/app/…`. Only installer-written files are candidates, so this call is not a finding by itself.
- `System.load("/absolute/path/libfoo.so")` and `Runtime.getRuntime().load(path)`: load whatever is at that path. This is the native equivalent of `DexClassLoader`.
- `dlopen()` / `android_dlopen_ext()` from native code: the same, from C or C++. Look for it in the app's own `.so` files.

Internally, `System.load()` calls `Runtime.load0(Class, String)`, `System.loadLibrary()` calls `Runtime.loadLibrary0(…)`, and both end in `Runtime.nativeLoad(String filename, ClassLoader loader, …)` with the absolute file name. The exact overloads differ between Android releases. The `System` methods are *caller-sensitive*: they use the calling class to pick the class loader and linker namespace. That is why the runtime test below hooks the `Runtime` methods instead, which receive the caller explicitly.

When native libraries are stored uncompressed in the APK (`android:extractNativeLibs="false"`, the default with recent Android Gradle Plugin versions for `minSdk` 23 and higher), the linker maps them straight from the APK and `/proc/<pid>/maps` shows paths such as `base.apk!/lib/arm64-v8a/libfoo.so`. Libraries that some loaders (for example ReLinker-style helpers) extract into app-internal directories such as `app_lib/` are a grey zone: they come from the signed APK, but they then live in a directory the app can write. That is low risk unless another write primitive exists.

Native code loaded from a writable place is worse than DEX in one respect: it is not constrained by ART at all. It can patch the app's memory, hook its methods, and read everything in the process.

### Android: code from other packages

[`Context.createPackageContext(packageName, flags)`](https://developer.android.com/reference/android/content/Context#createPackageContext(java.lang.String,%20int)) returns a `Context` for another installed app. On its own it gives access to that app's resources. Two flags turn it into code loading:

| Flag | Value | Meaning |
|---|---|---|
| `CONTEXT_INCLUDE_CODE` | `0x1` | Build a class loader for the other package's code, available through `getClassLoader()` |
| `CONTEXT_IGNORE_SECURITY` | `0x2` | Ignore the security restrictions that would otherwise refuse to load that code into this process |
| `CONTEXT_RESTRICTED` | `0x4` | Restricted context (resources only); not relevant here |

Without `CONTEXT_IGNORE_SECURITY`, the framework refuses to load another package's code into the caller's process unless both run with the same UID (a shared user ID) or the other package is a system UID, and throws a `SecurityException` ("Requesting code from … to be run in process …"). The flag exists to skip exactly that check. jadx usually shows the combination as the literal `3`: `createPackageContext("com.example.plugin", 3)`.

Android's [risk page](https://developer.android.com/privacy-and-security/risks/create-package-context) lists the conditions for exploitation: the app calls `createPackageContext` with both flags and then `getClassLoader()`; and a malicious app can claim the expected package name, typically because the real companion app is not installed (package squatting), and declares an `android:appComponentFactory`. [Oversecured's write-up](https://oversecured.com/blog/android-arbitrary-code-execution-via-third-party-package-contexts) describes how that factory class is instantiated while the foreign class loader is set up, so the other package's code can run before the app calls `loadClass()` at all.

On Android 11 and higher, an app targeting API 30+ can only create a context for a package that is visible to it. The code that does this therefore usually comes with a `<queries><package android:name="…"/></queries>` entry in the manifest, and that entry is a good static lead. The same reasoning applies to building a `PathClassLoader` over `packageManager.getApplicationInfo(name, 0).sourceDir`: the package name is not an identity, the signing certificate is.

### Android: where code can come from and who can write it

The exploitability of a load site depends almost entirely on who else can write the file. Use this table when you evaluate paths found by the tests:

| Location | Typical API or path | Who can write it on a stock device |
|---|---|---|
| Installed APK and splits | `applicationInfo.sourceDir`, `splitSourceDirs`, `nativeLibraryDir` under `/data/app/` | Only the package installer; changes require a validly signed update |
| App-internal storage | `filesDir`, `cacheDir`, `codeCacheDir`, `noBackupFilesDir`, `getDir(name, MODE_PRIVATE)` under `/data/user/0/<pkg>/` (also `/data/data/<pkg>/`) | The app's own UID, apps sharing its `sharedUserId`, root. Possibly a backup restore, depending on `allowBackup`, target SDK and Android version |
| App-specific external storage | `getExternalFilesDir()`, `getExternalCacheDir()` under `/storage/emulated/0/Android/data/<pkg>/` | Android 10 and lower: any app with `WRITE_EXTERNAL_STORAGE`. Android 11+: not other apps; still the user over USB on some devices, and `adb shell` |
| Shared storage | `Download/`, `Documents/`, `getExternalStoragePublicDirectory()`, MediaStore | Android 10 and lower: any app with storage permission. Android 11+: apps holding "All files access" (`MANAGE_EXTERNAL_STORAGE`), the user, USB |
| Removable media | SD card, USB OTG | Anyone with the card |
| Another package | `createPackageContext()`, another app's `sourceDir` | Whoever owns that package name on this device |
| Network | `https://…`, `http://…` | The server, its CDN and update service; anyone on the path if cleartext or certificate validation is broken |

Record the app's `minSdkVersion`: if it allows Android 10 or lower, the "Android 10 and lower" column applies to part of its user base, regardless of the device you test on. World-writable files created with `MODE_WORLD_WRITEABLE` are no longer possible for apps targeting API 24+ (the call throws), but files given world permissions with `File.setWritable(true, false)` or `chmod` still are. Check modes on the device instead of assuming.

### Android: managed delivery with Play Feature Delivery

[Play Feature Delivery](https://developer.android.com/guide/playcore/feature-delivery/on-demand) lets an app bundle contain feature modules that Google Play installs later, on demand (`SplitInstallManager.startInstall()`), deferred, or conditionally. The modules are split APKs signed with the app's key and installed by Play, so they end up in the install directory next to `base.apk`. That is the managed, policy-compliant answer to "we need to add code later".

To use code from a module without restarting, the app enables SplitCompat. It declares `SplitCompatApplication` as its `Application` class, or calls `SplitCompat.install(context)` in `attachBaseContext()`, plus `SplitCompat.installActivity()` in feature-module activities. SplitCompat makes freshly downloaded splits available to the running process until the next start. During testing you will see split APKs in `adb shell pm path`, classes such as `com.google.android.play.core.splitcompat.SplitCompat` in jadx, and class-loader activity at runtime. That is expected and is **not** a finding. What would be a finding is a custom implementation that downloads "modules" from its own server and loads them with `DexClassLoader`.

### Android: Google Play policy

Google Play's [Device and Network Abuse policy](https://support.google.com/googleplay/android-developer/answer/9888379) states that an app distributed through Play *"may not modify, replace, or update itself using any method other than Google Play's update mechanism"* and *"may not download executable code (such as dex, JAR, .so files) from a source other than Google Play"*. The exception is code that runs in a virtual machine or interpreter with only indirect access to Android APIs, such as JavaScript in a WebView or browser. Android's own risk page warns that many forms of dynamic loading from remote sources violate the policy and can lead to suspension.

Two practical consequences: an app on Play that downloads DEX or `.so` files is both a security finding and a policy problem, and should be reported as both. And interpreted code (JavaScript, Lua) is tolerated by the policy, but that says nothing about whether it is *safe*: an unsigned React Native bundle with a full native bridge is policy-compliant and still a remote code execution channel for whoever controls the update server.

### iOS: code signing, dlopen and NSBundle

iOS enforces code signing on every executable page. OWASP's iOS app-signing Knowledge page ([MASTG-KNOW-0058](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CODE/MASTG-KNOW-0058/)) summarises the rules, and Apple's [Platform Security guide](https://support.apple.com/guide/security/app-code-signing-process-sec7c917bf14/web) describes the mechanism:

- Before the app executable or any dynamic library loads (at launch or through `dlopen()` at runtime), the kernel and `dyld` check that it carries a valid signature from an Apple-issued certificate.
- Libraries must be Apple platform binaries or carry the **same Team ID** as the main executable (library validation).
- Code pages are checked against the signature's hashes as they are mapped. A library copied into the app container after installation is refused even if signed with the developer's own Team ID; `dlopen` fails with an error such as `code signing blocked mmap()`.
- Ordinary third-party apps do not get the `dynamic-codesigning` entitlement (special cases such as alternative browser engines in some regions aside), so they cannot create executable memory for a JIT either. JavaScriptCore inside an app therefore runs in interpreter mode (WebKit's JIT runs in the separate WebContent process of `WKWebView`).

The result: **on a stock device an App Store app cannot introduce new native code at runtime.** `dlopen()` and `-[NSBundle load]` / `loadAndReturnError:` are still used legitimately to load frameworks *inside the app bundle* lazily, and those are signed. A `dlopen()` with a path in `Documents/`, `Library/` or `tmp/` is either dead code or code meant for jailbroken devices, where signing is bypassed. It is worth a Low or Info note and a closer look at what else the app does, not a critical finding.

What remains possible is the **behaviour-changing** variant that does not need new native code: calling `dlsym()`, `NSClassFromString()`, `performSelector:` or `method_exchangeImplementations()` with names and arguments taken from a downloaded script. That is how iOS hot-patching libraries worked. In March 2017 Apple rejected and warned apps that contained such frameworks, citing the then section 3.3.2 of the developer agreement and Guideline 2.5.2 (the wording was widely reported at the time). For testing purposes, treat a downloaded script that drives these APIs like downloaded native code: it can call anything already linked into the process.

### iOS: App Store rules on downloaded code

Two Apple documents set the rules, and you should cite them precisely:

- **[App Store Review Guideline 2.5.2](https://developer.apple.com/app-store/review/guidelines/)** (guidelines last updated 16 October 2026 at the time of writing): apps *"should be self-contained in their bundles … nor may they download, install, or execute code which introduces or changes features or functionality of the app, including other apps."* The only exception in 2.5.2 itself is educational apps that let students write and test code, with the source fully viewable and editable.
- **[Apple Developer Program License Agreement](https://developer.apple.com/support/terms/apple-developer-program-license-agreement/), section 3.3.1(B) "Executable Code"**: *"an Application may not download or install executable code. Interpreted code may be downloaded to an Application but only so long as such code: (a) does not change the primary purpose of the Application … (b) does not bypass signing, sandbox, or other security features of the OS; and (c) for Applications distributed on the App Store, does not create a store or storefront for other Applications."*

The interpreted-code allowance in 3.3.1(B) is what React Native OTA updates, JavaScriptCore scripts and similar mechanisms rely on. Guideline 2.5.6 additionally requires apps that browse the web to use WebKit, and Guideline 4.7 allows HTML5 and JavaScript mini apps, mini games, streaming games, chatbots and plug-ins that are not embedded in the binary, provided the app takes responsibility for them and does not expose native platform APIs to them without Apple's permission (4.7.2). Older versions of the agreement only allowed downloaded scripts that ran in Apple's WebKit or JavaScriptCore; you will still see that version quoted in older material.

For the tester, the store rules are a sanity check, not a control: they are enforced at review time, and an OTA bundle changes after review.

### Cross-platform: interpreted code and OTA updates

Most runtime-delivered code on modern apps is interpreted. The risk is set by two things: whether the update is **signed with a key the app pins**, and **how much native capability** the script can reach.

**JavaScriptCore (`JSContext`) on iOS.** `-[JSContext evaluateScript:]` and `evaluateScript:withSourceURL:` run a JavaScript string. Native objects become reachable through `JSExport` protocols or blocks assigned to the context (`context[@"name"] = ^{ … }`). A script downloaded at runtime runs with exactly those bridges. Look for downloaded strings reaching `evaluateScript`. On Android the equivalent is an embedded engine (QuickJS, J2V8, Rhino, Duktape) or a WebView with `addJavascriptInterface`, which is covered in [MASWE-0035](/mobile/maswe-0035-webviews-loading-untrusted-content/).

**React Native CodePush.** The CodePush SDK downloads a new JavaScript bundle and assets (a zip), stores it in the app's data container and loads it on the next start. Integrity: the client compares the package hash from the update metadata, which only protects against corruption. Authenticity needs **code signing**. The release is signed with a private key at publish time (`--privateKeyPath`), the bundle carries a signed JWT in a `.codepushrelease` file, and the app verifies it against a public key configured as `CodePushPublicKey` in `Info.plist` on iOS and as a `CodePushPublicKey` string resource on Android. Without that key in the app, there is no signature check. Microsoft retired Visual Studio App Center, including hosted CodePush, on 31 March 2025, and archived the `react-native-code-push` repository in May 2025. Apps now use the open-source standalone CodePush server, a community fork or a commercial CodePush-compatible service. That change of server is a good moment to check that signing survived the migration.

**Expo Updates (EAS Update).** The app fetches a manifest and assets from an update URL. Code signing is enabled by `updates.codeSigningCertificate` (a certificate in the app) and `updates.codeSigningMetadata` (`keyid`, `alg`, e.g. `rsa-v1_5-sha256`) in `app.json`, with keys generated by `npx expo-updates codesigning:generate`. Expo's documentation says an update is applied only if the certificate and signature are valid and rejected otherwise, and that this feature requires a paid EAS plan. In the built app, the settings appear in `Expo.plist` (iOS) and as `expo.modules.updates.*` metadata in `AndroidManifest.xml`.

**Flutter.** Flutter has no official OTA mechanism. Release builds compile Dart ahead of time to native code inside the signed app. Third-party services fill the gap. Shorebird, for example, ships patches and supports **patch signing**: the public key is embedded at release time (`shorebird release … --public-key-path`) and patches are signed with the private key (`shorebird patch … --private-key-path`), so the updater only applies patches signed with the matching key. Check which mode the app's releases were built with.

**Capacitor, Cordova and Ionic live updates.** The web assets (`www/` or `public/`) are replaced from a server and loaded in the WebView, where the plugin bridge gives them native access. Commercial live-update services offer bundle signing; check that the app has the public key configured.

**Lua and other embedded engines.** Game engines and some business apps embed Lua (or a similar interpreter) and download scripts. Look for interpreter libraries (`liblua*.so`, symbols such as `luaL_loadbuffer` or `luaL_loadstring`) and `.lua` or compiled `.luac` files in downloads or the data container.

In each case, the worst realistic outcome depends on the bridge. A script that can only lay out screens is a content-integrity issue. A script that can read the keychain wrapper module, call payment APIs or post arbitrary authenticated requests is code execution in practice.

### Integrity verification of delivered code

TLS protects the transport. It does not prove that the bundle is the one the developer published: the server, its storage bucket, the CDN, the update service account or the CI pipeline can all serve something else. The control that closes that gap is a **signature over the bundle, made with a private key the developer keeps offline or in an HSM, verified in the app against a public key compiled into the signed app**. The cryptographic side of signature verification, including algorithm choice and common verification bugs, is covered in [MASWE-0011](/mobile/maswe-0011-improper-signature-verification/). The parts specific to code delivery:

- **Pin the key, not the hash.** A SHA-256 checked against a value downloaded with the bundle proves nothing about origin. A hash compiled into the app does, but then the code cannot change without an app update, which defeats the purpose. A pinned *public key* allows new bundles without trusting the delivery path.
- **Sign the metadata too.** Version, minimum and target app versions, and file list belong inside the signed data. Otherwise an attacker can replay an old, validly signed but vulnerable bundle (rollback), or a bundle built for another app version.
- **Verify the bytes you load.** Verify the file at its final location, make it read-only, and load it from there, from app-internal storage only. Do not verify a download stream and then load a file another party can write, and do not download again for loading.
- **Fail closed.** On any verification failure, discard the bundle and fall back to the bundled version. Log the failure without disabling the check.
- **Plan key rotation.** The app should accept a small, explicit set of keys. Rotation happens through an app update, not through the update channel itself.

Android's [dynamic code loading](https://developer.android.com/privacy-and-security/risks/dynamic-code-loading) page suggests hash checks for files on external storage, with the hashes stored securely in internal storage, and recommends code signing as the stronger option. It points to [Tink's digital signature primitives](https://developers.google.com/tink/digitally-sign-data) as one implementation route.

## Tests

OWASP has not published tests for MASWE-0049. The four tests below are ours. They only *detect and verify*: static search, configuration review, runtime tracing of the app's own calls, and file and permission checks on a test device you control. None of them involves an attacker app or a payload. Where proof is needed, the proof is a benign observation, for example "the loader reads a path that the `adb` shell user can write" or "the app loaded a bundle in which we changed one comment line".

Before you start, collect the basics: the APK (with splits) and IPA, `minSdkVersion` and `targetSdkVersion`, `MinimumOSVersion`, the frameworks in use (React Native, Expo, Flutter, Capacitor, Unity and so on), and which update mechanisms the app's Info.plist and manifest mention.

### GT-CODE-0049-1: References to dynamic code loading from non-constant or writable paths (Android)

*Guler Tech methodology — not an OWASP test.*

Platform: Android. Type: static.

#### Overview

The test lists every place the app (including bundled SDKs) loads DEX, JAR, APK or native code at runtime, or loads another package's code, and classifies the path it loads from. A load from a constant path inside the install directory is normal. A load from a variable path, external storage, a download location or another package is a candidate that GT-CODE-0049-2 and -3 then confirm.

#### Prerequisites

- The APK and its splits pulled from a device ([MASTG-TECH-0003](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0003/)), decompiled with [jadx](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/) ([MASTG-TECH-0017](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0017/)) and decoded with [Apktool](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/).
- ripgrep or grep, [semgrep](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/), `llvm-nm` / `llvm-readelf` from the NDK, `file`, and optionally [APKiD](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0009/) to identify packers.

#### Steps

1. **Pull, decompile and record SDK levels:**

   ```bash
   adb shell pm path com.example.app          # base.apk plus any split_*.apk
   adb pull /data/app/~~XXXX/com.example.app-YYYY/base.apk
   jadx -d out base.apk
   apktool d base.apk -o apk_out
   grep -E 'minSdkVersion|targetSdkVersion' apk_out/apktool.yml
   ```

2. **Find every loading API** across the whole tree, libraries included:

   ```bash
   rg -n --no-heading \
     -e 'new (DexClassLoader|PathClassLoader|DelegateLastClassLoader|InMemoryDexClassLoader|BaseDexClassLoader)\(' \
     -e 'DexFile\.loadDex\(|new DexFile\(' \
     -e 'System\.load\(|Runtime\.getRuntime\(\)\.load\(' \
     -e 'createPackageContext\(|CONTEXT_INCLUDE_CODE|CONTEXT_IGNORE_SECURITY' \
     out/sources > dcl-sites.txt
   wc -l dcl-sites.txt
   ```

   `System.loadLibrary(` is left out on purpose: it only resolves libraries from the install directory. Grep for it separately if you want the full native inventory.

3. **Run a semgrep rule** that highlights load sites with non-constant arguments, which are the ones worth tracing:

   ```yaml
   # gt-android-dcl.yml
   rules:
     - id: gt-android-dcl-non-constant-path
       languages: [java]
       severity: WARNING
       message: Runtime code loading from $PATH - trace where it comes from and who can write it
       patterns:
         - pattern-either:
             - pattern: new DexClassLoader($PATH, ...)
             - pattern: new PathClassLoader($PATH, ...)
             - pattern: new DelegateLastClassLoader($PATH, ...)
             - pattern: new InMemoryDexClassLoader($PATH, ...)
             - pattern: DexFile.loadDex($PATH, ...)
             - pattern: new DexFile($PATH)
             - pattern: System.load($PATH)
             - pattern: Runtime.getRuntime().load($PATH)
         - metavariable-pattern:
             metavariable: $PATH
             patterns:
               - pattern-not: |
                   "..."
     - id: gt-android-package-context-with-code
       languages: [java]
       severity: WARNING
       message: createPackageContext($PKG, $FLAGS) - check for CONTEXT_INCLUDE_CODE (0x1) and CONTEXT_IGNORE_SECURITY (0x2) and a signer check on $PKG
       pattern: $CTX.createPackageContext($PKG, $FLAGS)
   ```

   ```bash
   semgrep -c gt-android-dcl.yml out/sources --text
   ```

   jadx folds the flag constants into integers, so `createPackageContext(str, 3)` is the dangerous combination, and `createPackageContext(str, 1)` loads code but leaves the framework's UID check in place.

4. **Classify each path source.** Open each hit in jadx-gui and follow the path argument back to where it is built. Search the app's own packages for the storage APIs and file names that usually feed loaders:

   ```bash
   SRC=out/sources/com/example/app
   rg -n -e 'getExternalStorageDirectory|getExternalFilesDir|getExternalCacheDir|getExternalStoragePublicDirectory|/sdcard|/storage/emulated' $SRC
   rg -n -e '\.(dex|jar|apk|so|zip|bundle|lua)"' $SRC
   rg -n -e 'setReadOnly\(|setWritable\(|setExecutable\(' $SRC
   rg -n -e 'sourceDir|publicSourceDir|nativeLibraryDir' $SRC
   ```

   Map each path to a row of the [location table](#android-where-code-can-come-from-and-who-can-write-it). For `createPackageContext` and `sourceDir` hits, note the package name and look for a signing-certificate check before the load (`hasSigningCertificate`, `GET_SIGNING_CERTIFICATES`, `GET_SIGNATURES`). Then check the manifest for that package in `<queries>`:

   ```bash
   grep -n -A3 '<queries' apk_out/AndroidManifest.xml
   adb shell pm list packages | grep -F com.example.plugin    # installed on the test device?
   ```

5. **Find code that is not in `classes*.dex`.** Packed or downloadable code often ships as an asset first:

   ```bash
   unzip -l base.apk | grep -E '\.(dex|jar|apk|so|zip|odex|vdex)$' \
     | grep -v -E ' (classes[0-9]*\.dex|lib/[^ ]+\.so)$'
   find apk_out/assets apk_out/res/raw -type f -exec file {} + | grep -i -E 'dalvik|java archive|zip|elf'
   apkid base.apk
   ```

   A DEX or JAR inside `assets/` that is loaded with `InMemoryDexClassLoader` or written to app-internal storage is packing (a resilience topic), not this weakness, unless the file is written somewhere writable by others or replaced from the network.

6. **Inspect native libraries for their own loading.** Find the app's `.so` files that import `dlopen` and look at the strings near it:

   ```bash
   for so in apk_out/lib/*/*.so; do
     llvm-nm -D --undefined-only "$so" | grep -q -E ' (dlopen|android_dlopen_ext)(@.*)?$' && echo "$so"
   done
   strings -a apk_out/lib/arm64-v8a/libexample.so | grep -E '/data/|/sdcard|/storage/|\.so$|https?://'
   ```

   Most `dlopen` imports load system or bundled libraries by name. Paths into data or storage directories, or URLs next to them, are leads.

7. **Note the Play Feature Delivery and OTA frameworks** you see (SplitCompat, CodePush, Expo Updates, Capacitor live updates, Shorebird), so that you do not report them as custom loading, and so that GT-CODE-0049-3 can check their signing configuration.

#### Observation

A table of load sites with: class and method, loading API, path expression and its resolved location type, constant or variable, read-only handling (`setReadOnly`), the `targetSdkVersion` effect (Android 14 rule active or not), and for package contexts the package name, flags, signer check and installed state.

#### Evaluation

The test **fails** (candidate finding, to be confirmed with GT-CODE-0049-2 or -3) if:

- a class loader, `DexFile` or `System.load()`/`Runtime.load()` reads from external or shared storage, removable media, a world-writable file, or a path built from input (intent extras, server responses, deep-link parameters);
- code is downloaded and loaded, from any location, without a verification step visible in the code path (see GT-CODE-0049-3);
- `createPackageContext` is called with `CONTEXT_INCLUDE_CODE` and `CONTEXT_IGNORE_SECURITY` (or a `PathClassLoader` is built over another package's `sourceDir`) without a signing-certificate check of that package.

It **passes** if every load site uses a constant path inside the install directory, Play Feature Delivery splits, or app-internal storage with content that is verified before loading, and every foreign package whose code is loaded is pinned by signing certificate.

Common false positives: the system's own `PathClassLoader` calls inside AndroidX and Play Core, `System.loadLibrary()` of bundled libraries, WebView provider loading inside the framework, and test code that R8 left in the APK but that is unreachable. Confirm reachability with GT-CODE-0049-2 before rating.

#### Demo

A plugin manager that stores downloaded plugins on app-specific external storage and loads them without a check. The app targets API 33, so the Android 14 read-only rule does not apply:

```kotlin
class PluginManager(private val context: Context) {
    fun loadPromo(): Class<*> {
        val jar = File(context.getExternalFilesDir(null), "plugins/promo.jar")
        if (!jar.exists()) download("https://cdn.example.com/plugins/promo.jar", jar)
        val loader = DexClassLoader(jar.absolutePath, context.codeCacheDir.absolutePath,
            null, context.classLoader)
        return loader.loadClass("com.example.promo.Entry")
    }
}
```

What jadx and semgrep show (abridged):

```text
out/sources/com/example/app/plugins/PluginManager.java
  gt-android-dcl-non-constant-path
     Runtime code loading from file.getAbsolutePath() - trace where it comes from and who can write it
      21┆ return new DexClassLoader(file.getAbsolutePath(), this.context.getCodeCacheDir().getAbsolutePath(), null, this.context.getClassLoader()).loadClass("com.example.promo.Entry");
```

The path traces back to `getExternalFilesDir(null)`. With `minSdkVersion` 24, devices on Android 7 to 10 let any app holding storage permission replace that file, and there is no verification step. Candidate confirmed for GT-CODE-0049-2 and -3.

### GT-CODE-0049-2: Runtime tracing of loaded code and its file permissions (Android)

*Guler Tech methodology — not an OWASP test.*

Platform: Android. Type: dynamic.

#### Overview

Static search misses loaders called through reflection, inside obfuscated SDKs or from native code, and it cannot tell you the actual file path and mode on the device. This test hooks the app's own loading calls with Frida, logs every path, flag and buffer size with a stack trace, and then checks each logged file on the device: who owns it, its mode, whether it is on shared storage and whether it is read-only. The script only logs and passes every call through unchanged.

#### Prerequisites

- A rooted test device or emulator with [Frida](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0001/) server, or the app repackaged with Frida Gadget. Method hooking is described in [MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/).
- [adb](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0004/). Access to the app's data directory ([MASTG-TECH-0008](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0008/)) through root, or `run-as` for debuggable builds.
- The candidate list from GT-CODE-0049-1, so you know which features to exercise.

#### Steps

1. **Save the trace script.** It covers all file-based class loaders (they share the `BaseDexClassLoader` constructor), `InMemoryDexClassLoader`, `DexFile`, the `Runtime` methods behind `System.load()` and `System.loadLibrary()`, native `dlopen` calls, and `createPackageContext`:

   ```javascript
   // dcl-trace.js — logs the app's own code-loading calls; arguments pass through unchanged
   function where() {
     var Log = Java.use('android.util.Log');
     var Ex = Java.use('java.lang.Exception');
     return Log.getStackTraceString(Ex.$new()).split('\n').slice(2, 8).join('\n    ');
   }
   function show(a) {
     if (a === null || a === undefined) return 'null';
     if (typeof a === 'string' || typeof a === 'number' || typeof a === 'boolean') return String(a);
     if (typeof a.remaining === 'function') return 'ByteBuffer(' + a.remaining() + ' bytes)';
     if (typeof a.length === 'number') {
       var parts = [];
       for (var i = 0; i < a.length; i++) parts.push(show(a[i]));
       return '[' + parts.join(', ') + ']';
     }
     return String(a);
   }
   function logAll(cls, method, tag, fmt) {
     var C;
     try { C = Java.use(cls); } catch (e) { return; }
     if (!C[method]) return;
     C[method].overloads.forEach(function (ov) {
       ov.implementation = function () {
         var args = Array.prototype.slice.call(arguments);
         var text = fmt ? fmt(args) : args.map(show).join(' | ');
         console.log('[' + tag + '] ' + text + '\n    ' + where());
         return ov.apply(this, arguments);
       };
     });
   }

   Java.perform(function () {
     // DexClassLoader, PathClassLoader, DelegateLastClassLoader, InMemoryDexClassLoader
     logAll('dalvik.system.BaseDexClassLoader', '$init', 'BaseDexClassLoader');
     logAll('dalvik.system.InMemoryDexClassLoader', '$init', 'InMemoryDexClassLoader');
     logAll('dalvik.system.DexFile', 'loadDex', 'DexFile.loadDex');

     // Native libraries: System.load()/loadLibrary() are caller-sensitive, so hook Runtime instead
     logAll('java.lang.Runtime', 'load0', 'Runtime.load0');
     logAll('java.lang.Runtime', 'loadLibrary0', 'Runtime.loadLibrary0');
     logAll('java.lang.Runtime', 'nativeLoad', 'Runtime.nativeLoad');

     // Code from other packages; flags decoded
     logAll('android.app.ContextImpl', 'createPackageContext', 'createPackageContext', function (a) {
       var f = a[1] >>> 0, names = [];
       if (f & 0x1) names.push('INCLUDE_CODE');
       if (f & 0x2) names.push('IGNORE_SECURITY');
       if (f & 0x4) names.push('RESTRICTED');
       return 'pkg=' + a[0] + ' flags=0x' + f.toString(16) + ' (' + (names.join('|') || 'none') + ')';
     });
   });

   // Native dlopen calls, including ones made from the app's own .so files
   ['android_dlopen_ext', 'dlopen'].forEach(function (name) {
     var addr = Module.findGlobalExportByName ? Module.findGlobalExportByName(name)
                                              : Module.findExportByName(null, name);
     if (addr === null) return;
     Interceptor.attach(addr, {
       onEnter: function (args) {
         if (args[0].isNull()) return;
         var path = args[0].readUtf8String();
         if (path.indexOf('/') !== -1 && path.indexOf('/system/') !== 0 &&
             path.indexOf('/apex/') !== 0 && path.indexOf('/vendor/') !== 0) {
           console.log('[' + name + '] ' + path);
         }
       }
     });
   });
   ```

   The `Module.findGlobalExportByName` / `Module.findExportByName(null, …)` switch keeps the script working on Frida 17, which removed the static `findExportByName`, and on older releases.

2. **Run it from a cold start** and exercise every feature from your GT-CODE-0049-1 list: first launch, login, settings, any "plugins", "themes" or "modules" screen, and a restart after the app has been online for a while (many loaders fetch on first run and load on the next start):

   ```bash
   frida -U -f com.example.app -l dcl-trace.js -o dcl-trace.log
   ```

   The first `BaseDexClassLoader` lines come from the system creating the app's own loader for `/data/app/…/base.apk` and its splits. Ignore those and anything under `/system/`, `/apex/` or `/product/`.

3. **Cross-check with the process view.** Loaded DEX and libraries show up in the memory map, which also catches loads your hooks missed:

   ```bash
   PID=$(adb shell pidof com.example.app)
   adb shell su -c "cat /proc/$PID/maps" | grep -E '\.(dex|jar|apk|so)' \
     | grep -v -E '/system/|/apex/|/vendor/|/product/|/data/app/' | sort -u
   ```

   Anything that remains is code mapped from outside the install directory.

4. **Check each logged path on the device.** For every file the trace reports:

   ```bash
   F=/data/user/0/com.example.app/files/plugins/promo.jar      # path from the trace
   adb shell su -c "ls -lZ '$F'"
   adb shell su -c "stat -c '%A %U:%G %s bytes, modified %y' '$F'"
   adb shell su -c "ls -ld '$(dirname "$F")'"                   # the directory matters too
   ```

   For files on external or shared storage, also check from the unprivileged `adb` shell user, without root and without modifying anything:

   ```bash
   adb shell 'f=/storage/emulated/0/Android/data/com.example.app/files/plugins/promo.jar;
     ls -l "$f"; test -w "$f" && echo "writable by the adb shell user"'
   ```

   Then decide, using the [location table](#android-where-code-can-come-from-and-who-can-write-it) and the app's `minSdkVersion`, which other parties can write that location on the Android versions the app supports. `writable by the adb shell user` on shared storage is your benign proof that the file is outside the app's private sandbox. On Android 10 and lower, apps with storage permission have the same access.

5. **Check read-only handling** against the Android 14 rule: is the file mode `-r--------` or similar without a write bit when loaded? If the app targets 34+ and the file was writable, the trace shows a `SecurityException: Writable dex file … is not allowed` instead of a successful load. Note that a read-only bit set by the app does not stop the owner, or another app on shared storage, from replacing the file.

6. **For package contexts**, record the package name and flags from the trace, whether that package is installed (`adb shell pm list packages`), and its signer if it is:

   ```bash
   adb shell dumpsys package com.example.plugin | grep -i -A2 'signatures\|signing'
   apksigner verify --print-certs plugin.apk          # after pulling it, for the certificate digest
   ```

   Compare with the certificate the app expects (if it checks one at all).

7. **Optional: recover in-memory DEX** for review. When the trace shows `InMemoryDexClassLoader` with a buffer of non-trivial size, dump the DEX from the process with a DEX-dumping Frida tool or by reading the mapped region, then decompile it and run GT-CODE-0049-1 on it. Keep the dump on your analysis machine as part of the evidence.

#### Observation

The trace log with stack traces, the `/proc/<pid>/maps` extract, and for each loaded file: path, owner, SELinux label, mode, directory mode, location type, whether the shell user can write it, and the app's `minSdkVersion` and `targetSdkVersion`. For package contexts: package name, flags, installed state and signer.

#### Evaluation

The test **fails** if at runtime the app:

- loads DEX, JAR, APK or a native library from external or shared storage, removable media, a world-writable file or directory, or any location another app can write on an Android version the app supports;
- loads code from another package with `CONTEXT_INCLUDE_CODE | CONTEXT_IGNORE_SECURITY` (`flags=0x3`) or through that package's `sourceDir` without a signer check; or
- loads downloaded code from app-internal storage without the verification established in GT-CODE-0049-3.

It **passes** if every loaded file outside the install directory lies in app-internal storage, is read-only, and its content is verified before load (or comes from the APK itself, as with packers), and every foreign package is signer-checked.

#### Demo

Trace output for the `PluginManager` demo above, on an Android 13 device:

```text
[BaseDexClassLoader] /storage/emulated/0/Android/data/com.example.app/files/plugins/promo.jar | null | null | dalvik.system.PathClassLoader[...]
    at dalvik.system.DexClassLoader.<init>(DexClassLoader.java:55)
    at com.example.app.plugins.PluginManager.loadPromo(PluginManager.java:21)
    at com.example.app.MainActivity.onResume(MainActivity.java:88)
[createPackageContext] pkg=com.example.themes flags=0x3 (INCLUDE_CODE|IGNORE_SECURITY)
    at android.content.ContextWrapper.createPackageContext(ContextWrapper.java)
    at com.example.app.themes.ThemeLoader.load(ThemeLoader.java:34)
```

```text
$ adb shell 'f=/storage/emulated/0/Android/data/com.example.app/files/plugins/promo.jar; test -w "$f" && echo "writable by the adb shell user"'
writable by the adb shell user
$ adb shell pm list packages | grep -F com.example.themes
$
```

Two findings: a plugin loaded from shared storage (exploitable by other apps on Android 10 and lower, which the app's `minSdkVersion` 24 supports), and a package context with code for a theme package that is not installed and is not signer-checked, so any app published under that name would run inside this one.

### GT-CODE-0049-3: Integrity verification of downloaded code (Android, iOS)

*Guler Tech methodology — not an OWASP test.*

Platform: Android and iOS. Type: static and dynamic.

#### Overview

For every piece of code the app downloads (DEX, JAR, `.so`, JavaScript bundles, OTA updates, scripts), the test establishes whether the app checks a signature against a key it pins *before* loading, whether the check covers the bytes actually loaded, and what the app does when the check fails. The dynamic part runs on your own test device, against your own traffic: you corrupt or slightly modify the bundle in transit with an interception proxy and observe whether the app loads it. The modification is benign (a changed byte or an appended comment line). Its only purpose is to show whether altered content is accepted.

#### Prerequisites

- Load sites from GT-CODE-0049-1/-2 (Android) or GT-CODE-0049-4 (iOS), and the decompiled code.
- An interception proxy on your own test device with the app's TLS trusting it ([MASTG-TECH-0011](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0011/), [MASTG-TECH-0063](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0063/); our [traffic interception lab](/mobile/mobile-traffic-interception-lab/) covers the setup, including pinning on test builds).
- Frida on the device for the verification trace.
- For OTA frameworks: the app's Info.plist, `Expo.plist`, `AndroidManifest.xml` and `res/values/strings.xml`.

#### Steps

1. **Trace the download-to-load path statically.** In jadx (or Hopper/Ghidra on iOS), start at each load site and walk backwards: where is the file written, where does the content come from (URL, response field), and is there anything between "write" and "load" that looks at the content? Search for the verification primitives:

   ```bash
   SRC=out/sources/com/example/app
   rg -n -e 'Signature\.getInstance|\.initVerify\(|\.verify\(' $SRC
   rg -n -e 'MessageDigest\.getInstance|MessageDigest\.isEqual|DigestUtils' $SRC
   rg -n -e 'PublicKeyVerify|KeysetHandle|X509EncodedKeySpec|BEGIN PUBLIC KEY' out/sources
   ```

   Classify what you find:

   | Pattern | What it proves |
   |---|---|
   | Nothing between write and load | Nothing |
   | Hash or size from the same server response or a sibling URL | Corruption detection only, no origin |
   | Hash compiled into the app | Integrity of one fixed file (rarely used for updatable code) |
   | Signature verified with a public key compiled into the app | Origin and integrity, if done correctly ([MASWE-0011](/mobile/maswe-0011-improper-signature-verification/)) |
   | Signature verified with a key fetched at runtime | Nothing more than the transport provides |

2. **Check OTA framework signing configuration** without running anything:

   ```bash
   # React Native CodePush: public key present?
   grep -n 'CodePushPublicKey\|CodePushDeploymentKey\|CodePushServerURL' apk_out/res/values/strings.xml
   plutil -p Payload/Example.app/Info.plist | grep -i codepush

   # Expo Updates: code signing certificate configured?
   grep -n 'expo.modules.updates' apk_out/AndroidManifest.xml
   plutil -p Payload/Example.app/Expo.plist

   # Signature file inside a downloaded CodePush package (from the device's data container)
   unzip -l update.zip | grep -F .codepushrelease
   ```

   A CodePush integration with a deployment key but no `CodePushPublicKey` does not verify signatures. An Expo configuration with an update URL but no code-signing certificate does not either. For Shorebird, Capacitor live updates and similar, find the equivalent public-key setting in the app's configuration and the vendor's documentation.

3. **Trace verification at runtime** on Android by appending these hooks to `dcl-trace.js`, so that verification calls and loads appear in one timeline:

   ```javascript
   // verify-trace.js — logs verification results; return values are passed through unchanged
   Java.perform(function () {
     var Sig = Java.use('java.security.Signature');
     Sig.verify.overloads.forEach(function (ov) {
       ov.implementation = function () {
         var r = ov.apply(this, arguments);
         console.log('[Signature.verify] alg=' + this.getAlgorithm() + ' result=' + r);
         return r;
       };
     });
     var MD = Java.use('java.security.MessageDigest');
     MD.isEqual.implementation = function (a, b) {
       var r = this.isEqual(a, b);
       console.log('[MessageDigest.isEqual] result=' + r);
       return r;
     };
     MD.digest.overloads.forEach(function (ov) {
       ov.implementation = function () {
         console.log('[MessageDigest.digest] alg=' + this.getAlgorithm());
         return ov.apply(this, arguments);
       };
     });
   });
   ```

   ```bash
   cat dcl-trace.js verify-trace.js > gt-0049.js
   frida -U -f com.example.app -l gt-0049.js -o gt-0049.log
   ```

   Libraries that verify through Tink, Bouncy Castle or their own code do not go through these classes. Find their verify method in jadx and hook it by name in the same way. Hash comparisons done with `String.equals()` or `Arrays.equals()` are invisible here; the static trace from step 1 covers them. On iOS, hook `SecKeyVerifySignature` (Security framework) or the CryptoKit call site you found statically.

   Read the timeline: a `Signature.verify … result=true` immediately before the loader call for the same feature is what a passing app looks like. A loader call with no verification before it, or only a `digest` whose expected value came from the server, is a fail.

4. **Verify fail-closed behaviour with a benign modification** of your own traffic. With the proxy in place, let the app download the bundle once unmodified and note what it loads (the trace from GT-CODE-0049-2, or the bundle file in the data container). Then repeat with one of these modifications applied by the proxy to the response for the code download only:

   - **Corruption**: change a single byte in the middle of the file, or truncate it. Use this for DEX, JAR, `.so` and zip-packaged updates.
   - **Benign change**: for a plain JavaScript or Lua bundle, append one comment line such as `// gt-integrity-check` to the end. For a zip-packaged update (CodePush), unpack it, append the comment line to the bundle file, re-pack it with the same layout and serve that. Do not change any logic.

   Observe the result in the trace, the logs (`adb logcat`, Console.app on macOS for iOS) and the data container:

   ```bash
   adb shell su -c 'find /data/user/0/com.example.app -type f -mmin -30' | grep -E '\.(dex|jar|apk|so|bundle|zip|js|hbc|lua)$'
   adb shell su -c "tail -c 64 /data/user/0/com.example.app/files/CodePush/<hash>/<bundle-file>"
   ```

   The exact storage path differs per framework and version; use the paths from the trace. On iOS, look in the app's `Library/` and `Documents/` directories ([MASTG-TECH-0059](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0059/)). If your appended comment is present in the bundle the app loaded on the next start, the app accepted modified code.

   Two caveats. A corrupted DEX usually fails ART's own checks and a corrupted zip fails to unpack, so "the app did not load it" is only a pass if the *app's* verification rejected it first. Confirm that with the trace (`result=false` and no loader call). And a CodePush client that compares the package hash from the server's metadata rejects a body you changed without updating the metadata. That is the hash check doing corruption detection, not a signature check. Report the configuration from step 2 for the authenticity question.

5. **Check the transport.** Is the code downloaded over `https://` with proper validation? A cleartext download, or one the app accepts through a proxy whose CA the device does not trust, turns a server-side risk into a network attacker's one. Check the [certificate validation](/mobile/maswe-0027-insecure-certificate-validation/) and Network Security Configuration findings for the download host.

6. **Check rollback.** If the app verifies signatures, serve an older, validly signed bundle captured earlier (from your own previous session) and see whether the app accepts it. Accepting an older version than the one installed is a separate, lower-rated finding.

#### Observation

For each download: URL and transport, verification method found statically, verification calls observed at runtime and their order relative to the load, OTA signing configuration (key present or absent), and the result of the corruption and benign-change checks (accepted, rejected by the app, rejected by the runtime), with log extracts and the loaded file's content or hash.

#### Evaluation

The test **fails** if any downloaded code is loaded:

- without verification;
- after only a hash or size check whose expected value comes from the delivery channel;
- after a signature check against a key that is not pinned in the app;
- after a check whose result is not enforced, or that covers different bytes from the ones loaded; or
- if the app accepts the benign-modified bundle.

OTA frameworks without code signing configured fail regardless of the transport. Accepting an older signed bundle is a partial failure (rollback).

It **passes** if every downloaded bundle is verified with a pinned public key before loading, the verified file is the loaded file, modified bundles are rejected by the app with a fallback to known-good code, and older bundles are refused.

#### Demo

The failing pattern: a hash that arrives with the bundle.

```kotlin
// FAIL: manifest and bundle come from the same server; the "check" proves no origin
val manifest = api.get("https://updates.example.com/plugins/manifest.json")
val bytes = api.download(manifest.getString("url"))
if (sha256Hex(bytes) == manifest.getString("sha256")) {
    val f = File(context.filesDir, "promo.jar").apply { writeBytes(bytes) }
    DexClassLoader(f.absolutePath, context.codeCacheDir.absolutePath, null, context.classLoader)
}
```

The passing pattern is shown under [Secure implementation](#secure-implementation). Trace extract for the failing app with a one-byte change in transit:

```text
[MessageDigest.digest] alg=SHA-256
[BaseDexClassLoader] /data/user/0/com.example.app/files/promo.jar | ...
```

No `Signature.verify` appears, and the hash matched because the proxy did not alter the manifest. Here the corrupted DEX then failed ART's own checks. With the manifest's hash updated as well, the modified file would load. The evidence for the finding is the code path and the absence of a pinned key, not a working exploit.

### GT-CODE-0049-4: Native loading, OTA bundles and downloaded scripts (iOS)

*Guler Tech methodology — not an OWASP test.*

Platform: iOS. Type: static and dynamic.

#### Overview

On a stock iOS device unsigned native code cannot be loaded, so this test focuses on the paths that remain: `dlopen`/`NSBundle` loads from outside the app bundle (dead code, jailbreak-only behaviour, or a sign of a hot-patching framework), downloaded scripts handed to JavaScriptCore or another interpreter, and OTA update frameworks with their signing configuration. It records what can execute, from where, and with how much native reach.

#### Prerequisites

- A decrypted IPA ([MASTG-TECH-0054](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0054/)), unzipped.
- [otool](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0060/), `nm`, `strings`, `plutil`, optionally [radare2](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/) for cross-references ([MASTG-TECH-0070](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0070/)).
- For the dynamic part: a jailbroken test device with [Frida](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/), or the app re-signed with Frida Gadget ([MASTG-TECH-0090](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0090/)); method hooking as in [MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/).

#### Steps

1. **Inventory frameworks and bundled scripts:**

   ```bash
   unzip -q Example.ipa -d ipa && cd ipa/Payload/Example.app
   ls Frameworks/
   otool -L Example | grep -v -E '/System/|/usr/lib/'
   find . -name '*.jsbundle' -o -name '*.hbc' -o -name '*.bundle.js' -o -name '*.lua' -o -name '*.luac'
   plutil -p Info.plist | grep -i -E 'codepush|update'
   [ -f Expo.plist ] && plutil -p Expo.plist
   ```

   React Native shows up as `React`, `hermes` or `ReactNative*` frameworks and a `main.jsbundle`. Flutter shows `Flutter.framework` and `App.framework`. Capacitor and Cordova show a `public/` or `www/` directory. Record which update framework is present and whether a public key or code-signing certificate is configured (`CodePushPublicKey`, the Expo code-signing keys, the vendor's equivalent).

2. **Find native loading APIs and their arguments:**

   ```bash
   nm -u Example | grep -E '_dlopen|_dlsym|_NSClassFromString|_NSSelectorFromString|_method_exchangeImplementations'
   otool -Iv Example | grep -E 'dlopen|dlsym'
   for f in Frameworks/*.framework/*; do
     [ -f "$f" ] && nm -u "$f" 2>/dev/null | grep -q '_dlopen' && echo "$f imports dlopen"
   done
   strings -a Example | grep -E '\.dylib|\.framework/|/Documents/|/Library/|/tmp/'
   ```

   Then look at each `dlopen` call site in a disassembler: a path built from `[[NSBundle mainBundle] privateFrameworksPath]` or `bundlePath` is normal lazy loading. A path into `Documents`, `Library`, `tmp` or derived from downloaded data is the case to report. Do the same for `NSBundle` `bundleWithPath:` followed by `load` / `loadAndReturnError:`, and for selectors and class names that come from server data. Script-driven `performSelector:` or swizzling is the hot-patching pattern Apple rejects.

3. **Find script evaluation:**

   ```bash
   strings -a Example | grep -E 'evaluateScript|JSContext|JSExport|luaL_load|lua_pcall'
   otool -ov Example | grep -B2 -A6 'JSExport'        # classes and protocols exported to JavaScript
   ```

   For each `evaluateScript:` call site, find where the string comes from: a bundled resource (fine), or a network response or a file the app downloaded (report, and continue with GT-CODE-0049-3). For each `JSExport` protocol, list the methods exposed, because that list is the downloaded script's reach.

4. **Trace at runtime** with a logging-only script:

   ```javascript
   // ios-dcl-trace.js — logs the app's own loading and evaluation calls; nothing is changed
   var bundlePath = ObjC.classes.NSBundle.mainBundle().bundlePath().toString();
   function bt(ctx) {
     return Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, 6)
       .map(DebugSymbol.fromAddress).join('\n    ');
   }
   var dl = Module.findGlobalExportByName ? Module.findGlobalExportByName('dlopen')
                                          : Module.findExportByName(null, 'dlopen');
   Interceptor.attach(dl, {
     onEnter: function (args) {
       if (args[0].isNull()) return;
       var p = args[0].readUtf8String();
       if (p.indexOf(bundlePath) !== 0 && p.indexOf('/System/') !== 0 && p.indexOf('/usr/lib/') !== 0) {
         console.log('[dlopen] OUTSIDE BUNDLE ' + p + '\n    ' + bt(this.context));
       }
     }
   });
   [['NSBundle', '- load'], ['NSBundle', '- loadAndReturnError:']].forEach(function (h) {
     Interceptor.attach(ObjC.classes[h[0]][h[1]].implementation, {
       onEnter: function (args) {
         console.log('[' + h[1] + '] ' + new ObjC.Object(args[0]).bundlePath() + '\n    ' + bt(this.context));
       }
     });
   });
   if (ObjC.classes.JSContext) {
     ['- evaluateScript:', '- evaluateScript:withSourceURL:'].forEach(function (m) {
       var meth = ObjC.classes.JSContext[m];
       if (!meth) return;
       Interceptor.attach(meth.implementation, {
         onEnter: function (args) {
           var src = new ObjC.Object(args[2]).toString();
           var url = (m.indexOf('withSourceURL') !== -1 && !args[3].isNull()) ? ' url=' + new ObjC.Object(args[3]) : '';
           console.log('[JSContext ' + m + '] length=' + src.length + url +
                       ' head=' + JSON.stringify(src.substring(0, 80)) + '\n    ' + bt(this.context));
         }
       });
     });
   }
   if (ObjC.classes.CodePush && ObjC.classes.CodePush['+ bundleURL']) {
     Interceptor.attach(ObjC.classes.CodePush['+ bundleURL'].implementation, {
       onLeave: function (ret) { console.log('[CodePush bundleURL] ' + new ObjC.Object(ret)); }
     });
   }
   ```

   ```bash
   frida -U -f com.example.app -l ios-dcl-trace.js -o ios-dcl-trace.log
   ```

   Exercise the app, including a restart after it has been online (OTA updates usually apply on the next start). React Native with Hermes or the C-level JavaScriptCore API does not pass through `-[JSContext evaluateScript:]`; for those, the CodePush `bundleURL` line and the files in the data container tell you which bundle is running.

5. **Inspect the data container** for downloaded code ([MASTG-TECH-0059](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0059/)): bundles, scripts, zips and their modification times under `Library/Application Support/`, `Library/Caches/` and `Documents/`. A `main.jsbundle` or `.hbc` outside the `.app` directory is a downloaded update. Then run GT-CODE-0049-3 on it.

#### Observation

The framework inventory with update mechanism and signing configuration, the `dlopen`/`NSBundle` call sites with their path sources, the `evaluateScript` sites with their string sources and the `JSExport` surface, the runtime trace, and the list of downloaded code files in the container.

#### Evaluation

The test **fails** if:

- downloaded JavaScript, Lua or another script is evaluated without verification against a pinned key (confirm with GT-CODE-0049-3), and the script can reach native functionality through `JSExport`, a React Native or Capacitor bridge, or selector and class names it supplies;
- an OTA update framework is in use without its code-signing feature configured; or
- the app maps script data onto `dlsym`, `NSClassFromString`, `performSelector:` or method swizzling (hot patching), regardless of signing, because it lets delivered data call arbitrary linked code. Also report the store-policy conflict.

Report as Low or Info (not a fail of the main requirement): `dlopen` or `NSBundle` loads from container paths, which cannot succeed on stock devices but indicate jailbreak-only behaviour or leftover code.

It **passes** if all native code is loaded from the bundle, scripts are bundled or verified with a pinned key before evaluation, OTA frameworks have signing enabled, and the native surface exposed to scripts is limited to what they need.

#### Demo

A failing pattern: a "rules" script fetched at runtime and evaluated in a context that exposes a native object.

```swift
let context = JSContext()!
context.setObject(NativeBridge.shared, forKeyedSubscript: "native" as NSString)   // JSExport: token, request(), openURL()
let (data, _) = try await URLSession.shared.data(from: URL(string: "https://api.example.com/rules.js")!)
context.evaluateScript(String(decoding: data, as: UTF8.self))                     // FAIL: no signature check
```

Trace output:

```text
[JSContext - evaluateScript:] length=18342 head="\"use strict\";var rules=function(){var e=native.request(..."
    0x1003f2a10 Example!RulesEngine.refresh() ...
```

Whoever controls `rules.js` (the server, its CDN, or the network if TLS validation is broken) can call every method on `NativeBridge`, including the one that returns the session token.

## Secure implementation

The safest dynamic code is none. These patterns apply where an app genuinely needs it.

**Android: on-demand code through Google Play.** Use feature modules with Play Feature Delivery and enable SplitCompat. The splits are signed with the app's key and installed by Play into the install directory:

```kotlin
class App : SplitCompatApplication()

val request = SplitInstallRequest.newBuilder().addModule("promotions").build()
SplitInstallManagerFactory.create(context).startInstall(request)
```

**Android: verified plugin loading**, where Play delivery is not possible (enterprise or non-Play distribution). Verify a detached signature over the exact file, with a key pinned in the app, from app-internal storage, then load the same file read-only:

```kotlin
private const val PINNED_KEY_B64 = "<base64 SubjectPublicKeyInfo of the release-signing key>"

fun loadVerifiedPlugin(context: Context, file: File, signature: ByteArray): ClassLoader {
    require(file.canonicalPath.startsWith(context.filesDir.canonicalPath)) { "plugin outside private storage" }
    val key = KeyFactory.getInstance("EC")
        .generatePublic(X509EncodedKeySpec(Base64.decode(PINNED_KEY_B64, Base64.NO_WRAP)))
    val verifier = Signature.getInstance("SHA256withECDSA")
    verifier.initVerify(key)
    file.inputStream().use { input ->
        val buf = ByteArray(8192)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            verifier.update(buf, 0, n)
        }
    }
    if (!verifier.verify(signature)) {
        file.delete()
        throw SecurityException("plugin signature invalid")
    }
    file.setReadOnly()          // required for targetSdk 34+, and set before writing when creating the file
    return DexClassLoader(file.absolutePath, context.codeCacheDir.absolutePath, null, context.classLoader)
}
```

Sign a small manifest (version, minimum app version, file digests) rather than each file if a plugin has several parts, and refuse versions lower than the highest one already accepted. Google's Android 14 guidance is to call `setReadOnly()` right after opening the file for writing and before writing content; the call above is the backstop for files written earlier.

**Android: code from another package.** Pin the signer before creating the context, and avoid `CONTEXT_IGNORE_SECURITY` unless there is no alternative:

```kotlin
val pm = context.packageManager
val trusted = Build.VERSION.SDK_INT >= 28 &&
    pm.hasSigningCertificate(PLUGIN_PKG, PLUGIN_CERT_SHA256, PackageManager.CERT_INPUT_SHA256)
if (!trusted) return null
val pluginCtx = context.createPackageContext(PLUGIN_PKG,
    Context.CONTEXT_INCLUDE_CODE or Context.CONTEXT_IGNORE_SECURITY)
```

On API 27 and lower, compare `getPackageInfo(PLUGIN_PKG, GET_SIGNATURES).signatures` against the expected certificate digest. A better design is a bound service with an AIDL interface protected by a `signature` permission, so no foreign code runs in your process at all.

**iOS: verified scripts.** Verify the script against a pinned P-256 key with CryptoKit before evaluation, and expose only the native methods the script needs:

```swift
import CryptoKit

func verifiedScript(_ data: Data, signature: Data) throws -> String {
    let key = try P256.Signing.PublicKey(derRepresentation: pinnedKeyDER)
    let sig = try P256.Signing.ECDSASignature(derRepresentation: signature)
    guard key.isValidSignature(sig, for: data),
          let script = String(data: data, encoding: .utf8) else { throw BundleError.untrusted }
    return script
}
```

A DER-encoded signature from Java's `SHA256withECDSA` or from `openssl dgst -sha256 -sign` verifies with this code, so one signing pipeline can serve both platforms.

**OTA frameworks.** Turn on the framework's signing feature and confirm it in the built app: `CodePushPublicKey` in `Info.plist` and `strings.xml` with releases signed using `--privateKeyPath`; Expo `codeSigningCertificate` and `codeSigningMetadata`; Shorebird releases built with `--public-key-path` and patches signed with `--private-key-path`; the live-update vendor's signing key for Capacitor. Keep the private key in a secrets manager or HSM, not in the repository or the CI log, and bind updates to the binary version (Expo `runtimeVersion`, CodePush target binary version) so a bundle cannot run on a binary it was not built for.

**Everywhere.** Download over validated TLS, store in app-private locations only, fail closed to the bundled version, and keep the native bridge small.

## Rating findings

Rate on three things: **where the attacker must stand** (another app on the device; network position; control of the server, CDN or update service; a squatted package name), **whether user interaction is needed** (installing an app, accepting a storage permission), and **what the loaded code can do** (full process code execution for DEX and native code; bridge-limited for scripts). Then check reachability: is the load site used in the release build, and on which Android or iOS versions within the app's supported range?

| Rating | Conditions |
|---|---|
| **Critical** | Without user interaction beyond normal use, a network attacker can supply code the app executes: DEX, native code or a script with a broad native bridge downloaded over cleartext or over TLS with broken validation, with no pinned signature check. Or code loaded at start-up from a location any app with a common permission can write, on Android versions the app supports, in an app that holds credentials, payment or health data. |
| **High** | Downloaded DEX, native code or broadly bridged scripts loaded without a pinned signature over properly validated TLS, so that compromise of the server, CDN, storage bucket or update account executes code on every installation. OTA frameworks (CodePush, Expo Updates, Shorebird, live updates) without code signing in apps with sensitive data. `createPackageContext` with both `CONTEXT_INCLUDE_CODE` and `CONTEXT_IGNORE_SECURITY` (or a `sourceDir` class loader) for a package that is not always installed, without a signer check. Code on shared storage reachable only on older supported Android versions. |
| **Medium** | Verification exists but proves no origin (hash delivered with the bundle, key fetched at runtime), or is not enforced on all paths. Verify-then-load races where the window requires another app with storage access. Downloaded scripts without signing but with a narrow bridge (layout, content only). Signed bundles that can be rolled back to older vulnerable versions. Package contexts with code for a package that is preinstalled or signer-checked only by package name. |
| **Low** | Downloaded code verified and loaded from app-internal storage but left writable (attacker needs the app's UID or root). Verified code missing rollback protection where no older vulnerable version exists. iOS `dlopen`/`NSBundle` loads from container paths (blocked on stock devices). Hot-patching code paths present but disabled. |
| **Info** | Play Feature Delivery and SplitCompat; bundled code unpacked with `InMemoryDexClassLoader` (packers; see MASVS-RESILIENCE); OTA updates with signing enabled; store-policy observations (Play Device and Network Abuse policy, App Store 2.5.2 and DPLA 3.3.1(B)) reported alongside the security rating. |

Raise a level when the loaded code runs automatically at start-up, when the app handles authentication material that the loaded code can reach, or when one compromise reaches all users. Lower a level when the only path needs a user to install a specific app *and* grant it "All files access", or when the load site is only reachable in a debug or internal build. Do not lower for the Android 14 read-only rule unless the app targets API 34 or higher *and* the attacker would need to write the file after it was made read-only. A replaced file that arrives read-only still loads. Policy violations are not a security severity, but report them: they are often what gets the fix prioritised.

In the report give the load site (class and method, or the Mach-O function), the path or URL, the location type and who can write it, the `minSdkVersion`/`targetSdkVersion` or `MinimumOSVersion`, the trace extract that shows the load at runtime, the verification evidence from GT-CODE-0049-3, and the fix (ship the code, Play Feature Delivery, pinned-key signature verification, signer pinning or OTA signing).

## References

- OWASP MASWE: [MASWE-0049: Unsafe Dynamic Code Loading](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0049/); related [MASWE-0011](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0011/), [MASWE-0035](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0035/), [MASWE-0048](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0048/), [MASWE-0057](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0057/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-CODE-4](https://mas.owasp.org/MASVS/controls/MASVS-CODE-4/) (CC BY-SA 4.0)
- OWASP MASTG knowledge: [MASTG-KNOW-0058 (iOS App Signing)](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CODE/MASTG-KNOW-0058/), [MASTG-KNOW-0033 (Android Obfuscation, dynamic code loading and packing)](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0033/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0003](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0003/), [MASTG-TECH-0008](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0008/), [MASTG-TECH-0011](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0011/), [MASTG-TECH-0017](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0017/), [MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/), [MASTG-TECH-0054](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0054/), [MASTG-TECH-0059](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0059/), [MASTG-TECH-0063](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0063/), [MASTG-TECH-0070](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0070/), [MASTG-TECH-0090](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0090/), [MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/) (CC BY-SA 4.0)
- OWASP MASTG tools: [Frida for Android (MASTG-TOOL-0001)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0001/), [adb (MASTG-TOOL-0004)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0004/), [APKiD (MASTG-TOOL-0009)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0009/), [Apktool (MASTG-TOOL-0011)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/), [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [Frida for iOS (MASTG-TOOL-0039)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/), [otool (MASTG-TOOL-0060)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0060/), [radare2 for iOS (MASTG-TOOL-0073)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/), [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/) (CC BY-SA 4.0)
- Android Developers, risk pages: [Dynamic code loading](https://developer.android.com/privacy-and-security/risks/dynamic-code-loading), [createPackageContext](https://developer.android.com/privacy-and-security/risks/create-package-context)
- Android Developers, behaviour changes: [Android 10 (apps targeting 29+)](https://developer.android.com/about/versions/10/behavior-changes-10), [Android 14 (apps targeting 34+)](https://developer.android.com/about/versions/14/behavior-changes-14)
- Android Developers, guides and reference: [`dalvik.system` package](https://developer.android.com/reference/dalvik/system/package-summary), [`Context.createPackageContext`](https://developer.android.com/reference/android/content/Context#createPackageContext(java.lang.String,%20int)), [Configure on-demand delivery and SplitCompat](https://developer.android.com/guide/playcore/feature-delivery/on-demand)
- Google Play Console Help: [Device and Network Abuse policy](https://support.google.com/googleplay/android-developer/answer/9888379)
- Google: [Tink, digitally sign data](https://developers.google.com/tink/digitally-sign-data)
- Oversecured: [Android arbitrary code execution via third-party package contexts](https://oversecured.com/blog/android-arbitrary-code-execution-via-third-party-package-contexts)
- Apple: [App Store Review Guidelines](https://developer.apple.com/app-store/review/guidelines/) (2.5.2, 2.5.6, 4.7), [Apple Developer Program License Agreement](https://developer.apple.com/support/terms/apple-developer-program-license-agreement/) (3.3.1(B)), [Apple Platform Security: app code signing process](https://support.apple.com/guide/security/app-code-signing-process-sec7c917bf14/web)
- React Native CodePush: [iOS setup, code signing](https://github.com/microsoft/react-native-code-push/blob/master/docs/setup-ios.md), [Android setup, code signing](https://github.com/microsoft/react-native-code-push/blob/master/docs/setup-android.md) (repository archived May 2025)
- Expo: [EAS Update code signing](https://docs.expo.dev/eas-update/code-signing/)
- Shorebird: [Patch signing](https://docs.shorebird.dev/code-push/guides/patch-signing/)
- CWE: [CWE-494](https://cwe.mitre.org/data/definitions/494.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
