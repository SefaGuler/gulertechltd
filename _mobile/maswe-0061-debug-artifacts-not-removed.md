---
title: "MASWE-0061: Debug Artifacts Not Removed"
date: 2026-11-10 20:10:00 +0000
subcategory: resilience
summary: "Finding debug symbols, StrictMode, verbose logs, debug menus and hidden switches left in Android and iOS release builds, and rating them."
refs: [MASWE-0061, MASVS-RESILIENCE-3, CWE-489, CWE-497, CWE-540, CWE-912, CWE-1295]
tags: [android, ios, masvs-resilience, debug-symbols, logging, strictmode]
---

This note is part of our [MASVS-RESILIENCE guide](/mobile/masvs-resilience-resilience-testing-guide/) and covers OWASP [MASWE-0061](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0061/): a release build that still carries what developers needed while building it. That means symbol tables and DWARF in native code, a debug map in a Mach-O binary, `StrictMode` writing stack traces to logcat, `Log.d`, `NSLog` and `print` calls that narrate the app's internals, and the worst case, a debug menu or hidden switch that turns off TLS validation or points the app at a staging backend. Most of these artefacts are reverse-engineering aids. They save an attacker hours, and they turn a stripped, obfuscated binary back into a readable one. A few are real vulnerabilities, because they give anyone who finds the switch a way to disable a security control. Below you get the mechanisms per platform, all seven OWASP tests with commands and demos, two tests of our own for Android logging and for debug menus and hidden switches, the build settings that remove each artefact, and how to rate what you find. Our [MASVS-CODE hub](/mobile/masvs-code-code-quality-guide/) has short summaries of the four Knowledge items. This note is the full treatment.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: Debugging Information and Debug Symbols (MASTG-KNOW-0008)](#android-debugging-information-and-debug-symbols-mastg-know-0008)
  - [Android: StrictMode (MASTG-KNOW-0009)](#android-strictmode-mastg-know-0009)
  - [Android: Logging and debug-only code](#android-logging-and-debug-only-code)
  - [iOS: Debugging Information and Debug Symbols (MASTG-KNOW-0063)](#ios-debugging-information-and-debug-symbols-mastg-know-0063)
  - [iOS: Non-Production Resources (MASTG-KNOW-0064)](#ios-non-production-resources-mastg-know-0064)
  - [iOS: Logs (MASTG-KNOW-0101)](#ios-logs-mastg-know-0101)
- [Tests](#tests)
  - [Before you start: unpack once, keep everything](#before-you-start-unpack-once-keep-everything)
  - [MASTG-TEST-0263: Logging of StrictMode Violations (Android)](#mastg-test-0263-logging-of-strictmode-violations-android)
  - [MASTG-TEST-0264: Runtime Use of StrictMode APIs (Android)](#mastg-test-0264-runtime-use-of-strictmode-apis-android)
  - [MASTG-TEST-0265: References to StrictMode APIs (Android)](#mastg-test-0265-references-to-strictmode-apis-android)
  - [MASTG-TEST-0288: Debugging Symbols in Native Binaries (Android)](#mastg-test-0288-debugging-symbols-in-native-binaries-android)
  - [GT-RES-0061-1: Implementation Details in Logs (Android)](#gt-res-0061-1-implementation-details-in-logs-android)
  - [MASTG-TEST-0219: Testing for Debugging Symbols (iOS)](#mastg-test-0219-testing-for-debugging-symbols-ios)
  - [MASTG-TEST-0358: Implementation Details Exposure Through Logging APIs (iOS)](#mastg-test-0358-implementation-details-exposure-through-logging-apis-ios)
  - [MASTG-TEST-0359: Implementation Details Exposure in Logs (iOS)](#mastg-test-0359-implementation-details-exposure-in-logs-ios)
  - [GT-RES-0061-2: Debug Menus, Hidden Switches and Non-Production Configuration (Android and iOS)](#gt-res-0061-2-debug-menus-hidden-switches-and-non-production-configuration-android-and-ios)
- [Best practices](#best-practices)
  - [iOS: Disable Verbose and Debug Logging in Production Builds (MASTG-BEST-0022)](#ios-disable-verbose-and-debug-logging-in-production-builds-mastg-best-0022)
  - [Android: logging, StrictMode and debug code in release builds](#android-logging-strictmode-and-debug-code-in-release-builds)
  - [Both platforms: symbols and a release gate](#both-platforms-symbols-and-a-release-gate)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

The OWASP requirement is short: *"The app does not contain debug artifacts."* It maps to **MASVS-RESILIENCE-3**, *"The app implements anti-static analysis mechanisms"*, and to the v1 controls MSTG-CODE-3 (debugging symbols) and MSTG-CODE-4 (debugging code and verbose error logging). The weakness carries OWASP's **R** and **EUDIW** profiles. It applies when the threat model includes someone reverse engineering the app on a device they control: banking, payments, wallets, DRM, games, apps with high-value logic. For an app without that threat model, most of what this note finds is an observation, with one exception covered below.

OWASP describes the threat as MAS-THREAT-0061, *"Attackers can analyze the app's internals and disable its security controls"*, reached through two attacks:

| Attack | Description | Role here |
|---|---|---|
| MAS-ATTACK-0001 | Obtaining the app package and reverse engineering it | Symbols, debug maps, log strings and debug-menu code are read straight out of the APK or IPA |
| MAS-ATTACK-0006 | Accessing the system logs on a compromised device or from an app holding log-access permissions | Verbose logs and StrictMode stack traces are read from logcat or the unified log while the app runs |

The weakness groups four kinds of leftovers:

1. **Debug symbols and debug information.** `.symtab` and DWARF sections in Android `.so` files, the STABS debug map and local symbols in Mach-O binaries, a `.dSYM` or `native-debug-symbols.zip` packaged by mistake.
2. **Verbose logging and diagnostic paths.** `Log.d`/`Log.v`, `printStackTrace()`, `NSLog`, `print`, `dump`, `os_log` at debug level, HTTP logging interceptors at body level.
3. **Testing utilities.** `StrictMode` with `penaltyLog()`, network inspectors, database viewers, leak detectors and other development libraries.
4. **Backdoors, hidden switches and debug menus.** A flag, preference, launch argument, deep link or gesture that unlocks a debug screen, switches the backend, or disables a security control such as certificate validation.

The first three are information. They make static and dynamic analysis cheaper. The fourth is behaviour, and it is the one OWASP calls "most critical": an insecure trust manager behind a switch is a TLS bypass waiting for someone to find the switch.

CWE mappings from the weakness front matter:

| CWE | Name | Where it fits |
|---|---|---|
| [CWE-489](https://cwe.mitre.org/data/definitions/489.html) | Active Debug Code | StrictMode, debug menus, test hooks left in the release build |
| [CWE-497](https://cwe.mitre.org/data/definitions/497.html) | Exposure of Sensitive System Information to an Unauthorized Control Sphere | Stack traces, internal hosts and component versions in logs |
| [CWE-540](https://cwe.mitre.org/data/definitions/540.html) | Inclusion of Sensitive Information in Source Code | Symbol names, source paths and log strings compiled into the binary |
| [CWE-912](https://cwe.mitre.org/data/definitions/912.html) | Hidden Functionality | Hidden switches, backdoors, undocumented debug screens |
| [CWE-1295](https://cwe.mitre.org/data/definitions/1295.html) | Debug Messages Revealing Unnecessary Information | Verbose error and debug logging |

Keep the neighbouring weaknesses apart. They change both the finding and its rating:

| Question | Where it lives |
|---|---|
| Is the app debuggable (`android:debuggable`, `get-task-allow`, WebView debugging)? | [MASWE-0063](/mobile/maswe-0063-debug-mechanisms-not-disabled/). Those are real vulnerabilities regardless of profile. |
| Do logs contain secrets or personal data (tokens, passwords, emails)? | [MASWE-0005](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0005/) (STORAGE), tests MASTG-TEST-0203/0231 (Android) and 0296/0297 (iOS). Our [STORAGE hub](/mobile/masvs-storage-1-secure-storage-guide/) has the context. |
| Does the package contain staging URLs, developer emails, source files? | [MASWE-0004](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/). A staging URL in `strings.xml` is MASWE-0004. A hidden toggle that switches the app to it is this note. |
| Are Java/Kotlin class and method names readable? | [MASWE-0059](/mobile/maswe-0059-code-obfuscation-not-implemented/) (R8 renaming, obfuscation). |
| Is native code built with canaries, PIE, RELRO? | [MASWE-0045](/mobile/maswe-0045-compiler-security-features-not-used/). Stripping is shared ground: that note checks hardening, this one checks symbols. |
| Is the trust manager insecure? | [MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/). If a debug switch enables it, report both. |

Like every control in this series, removing debug artefacts is defence in depth. It raises attacker cost. It does not replace L1/L2 controls, and a determined analyst will recover function names from a stripped binary eventually. The exception is the fourth class: a switch that disables a security control is not a resilience gap, it is the security control's own failure.

## Modes of Introduction

**Debug-only code without a compile-time guard.** On Android, StrictMode set up in `Application.onCreate()` without `if (BuildConfig.DEBUG)`, or behind a runtime check such as `ApplicationInfo.FLAG_DEBUGGABLE`, which keeps the code in the release DEX. On iOS, `print` and `NSLog` without `#if DEBUG`, or a custom compilation condition (`DEBUG_LOGGING`, `STAGING`) that is also set in the Release configuration. Since Android Gradle Plugin (AGP) 8.0, `BuildConfig` is not generated unless `buildFeatures.buildConfig = true`. Teams that lose it sometimes replace it with a runtime check, which keeps the debug code in the release build.

**Native stripping disabled or failing.** AGP strips `.so` files when it packages a release build. That stops when someone adds `packaging.jniLibs.keepDebugSymbols` (formerly `packagingOptions.doNotStrip`) for a library, when the NDK is missing on the build machine and AGP warns that it is unable to strip the libraries and packages them as they are, or when libraries are injected into the APK outside the Gradle packaging step. Vendor SDKs that ship prebuilt `.so` files with symbols are common. On iOS, stripping depends on `DEPLOYMENT_POSTPROCESSING` (set when you archive), `STRIP_INSTALLED_PRODUCT` and `STRIP_STYLE`. Custom build scripts that export with `xcodebuild build` rather than `archive`, or set `STRIP_INSTALLED_PRODUCT = NO` to "fix" a crash reporter, ship the debug map.

**Companion files in the package.** `mapping.txt`, `native-debug-symbols.zip`, a `.dSYM` bundle or a `.map` file copied into assets or the app bundle by a misconfigured build phase.

**Development libraries in the release dependency set.** Network inspectors (Chucker, Flipper, Stetho), leak detectors (LeakCanary), view debuggers (Hyperion on Android, FLEX on iOS), declared as `implementation` instead of `debugImplementation`, or linked into all configurations in a Podfile or Swift package.

**Logging configured for the developer, not the user.** OkHttp's `HttpLoggingInterceptor` at `Level.BODY`, Alamofire or URLSession loggers, Timber with a `DebugTree` planted unconditionally, SDK debug modes switched on in code (`setLogLevel(VERBOSE)`), `Log.isLoggable()` used as a "release switch" although any ADB user can change it with a system property.

**Backdoors and switches kept "for support".** A debug menu opened by tapping a version label seven times, a `myapp://debug` deep link, a hidden Settings.bundle toggle, a `SharedPreferences` or `UserDefaults` key, a launch argument, an environment picker that still lists staging, a remote-config flag that disables pinning. Each was convenient for QA. Each becomes hidden functionality in production.

**Cross-platform frameworks.** React Native's `__DEV__` and Flutter's `kDebugMode` are compile-time constants, so code guarded by them is removed in release. Code guarded by custom flags read from a bundled JSON file or environment config is not. Debug strings in a Hermes bundle or a Flutter `libapp.so` are the same problem in another container.

## Impact

- **Cheaper reverse engineering.** A `.symtab` turns `sub_31578` into `check_frida_port`. A Mach-O debug map lists every function and the build machine's source paths. StrictMode traces and verbose logs name classes, methods, SQL statements and endpoints. Each removes hours from the attacker's work on [code obfuscation](/mobile/maswe-0059-code-obfuscation-not-implemented/), [runtime integrity](/mobile/maswe-0058-runtime-code-integrity-not-verified/) and [debugger detection](/mobile/maswe-0064-debugger-detection-not-implemented/) controls, because it tells them where those controls are.
- **Bypass of protection mechanisms.** A leftover switch that disables certificate validation, pinning, root detection or a server-side check is the shortest possible bypass. No hooking, no patching: flip the flag.
- **Information that enables further attacks.** Internal hostnames, API versions, feature flags, the state of security checks ("SSL pinning: disabled", "root check passed") and library versions point the attacker at the next target. Detailed errors sometimes include values that belong under [MASWE-0005](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0005/).
- **Reachable non-production backends.** A switchable environment gives the attacker access to staging servers that often run older code, accept test credentials or hold restored production data.

## Mitigations

- **Compile debug code out.** Guard it with compile-time constants (`BuildConfig.DEBUG`, `#if DEBUG`, `kDebugMode`, `__DEV__`) so the compiler and R8 remove it. Runtime checks are not removal.
- **Strip native symbols and keep them outside the package.** Let AGP strip `.so` files and upload `native-debug-symbols.zip` to Play Console. Archive iOS builds with stripping on and upload the `.dSYM` to your crash reporter.
- **Remove or silence verbose logging in release.** R8 `-assumenosideeffects` for `android.util.Log` debug levels, no planted Timber tree, `#if DEBUG` around `print`/`NSLog`, unified logging with privacy modifiers for whatever remains.
- **Keep testing utilities out.** StrictMode only in debug builds. Development libraries as `debugImplementation` or their no-op release artefacts.
- **Eliminate backdoors.** No debug menus, environment pickers or security toggles in release builds. Enforce it with a release gate in CI and a code-review rule.

Details per platform are in [Best practices](#best-practices).

## Knowledge

OWASP does not link Knowledge items from the weakness file. We assign the five items below by topic: two Android and three iOS. We add one Android background section, because OWASP's Android logging material lives under MASWE-0005 and does not cover implementation details.

### Android: Debugging Information and Debug Symbols (MASTG-KNOW-0008)

*OWASP page: [MASTG-KNOW-0008](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0008/).*

Android native code is written in C, C++ or Rust with the NDK and compiled into ELF shared objects under `lib/<abi>/` in the APK (`arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`). Java and Kotlin reach it through JNI. When an attacker wants to understand a root check, an integrity check or a crypto routine that the developer moved into native code "for security", the first thing they look at is how much of the original naming survived.

#### ELF symbol tables

An ELF file can carry two symbol tables:

| Section | Purpose | Stripped by `llvm-strip --strip-unneeded`? |
|---|---|---|
| `.dynsym` | Dynamic symbol table. The runtime linker needs it to resolve imports and exports. | No. It is required at load time. |
| `.symtab` | Full link-time symbol table, including local (`static`) functions and variables. | Yes. Nothing at runtime needs it. |

Each symbol has a binding. **Local** symbols are visible only inside their object file (a `static` C function). **Global** symbols are visible to other objects and, if their visibility is default, exported through `.dynsym`. **Weak** symbols are globals that a strong definition of the same name overrides. In a stripped library you see only `.dynsym`: imports from libc and liblog, plus whatever the library exports. That export list is not a finding by itself. Statically registered JNI functions must be exported under their `Java_<package>_<class>_<method>` names or the runtime cannot find them, so these names always survive stripping.

The developer controls how much `.dynsym` gives away. `-fvisibility=hidden` hides every symbol not explicitly marked as exported, `-Wl,--exclude-libs,ALL` stops static libraries from re-exporting their symbols, and registering natives from `JNI_OnLoad` with `RegisterNatives` removes the need for `Java_*` exports altogether. These are hardening choices, not requirements of this weakness.

A correction to OWASP's text. KNOW-0008 associates `.symtab` with the `DT_SYMTAB` dynamic tag. `DT_SYMTAB` is an entry in the `.dynamic` section that points to the **dynamic** symbol table, `.dynsym`. The link-time `.symtab` has no dynamic tag, which is exactly why stripping it is harmless. The r2 output OWASP shows (`SYMTAB .symtab`) is the section *type* `SHT_SYMTAB`, which is something else again.

#### DWARF sections and compressed debug info

[DWARF](https://dwarfstd.org/doc/DWARF5.pdf) is the debug format used in ELF files (and, in a different arrangement, on Apple platforms). The sections you will see:

| Section | Contents |
|---|---|
| `.debug_info` | Compilation units, functions, parameters, local variables, types and scopes |
| `.debug_line` | Machine address to source file and line mapping |
| `.debug_str`, `.debug_line_str` | Strings used by the above, including source paths and the compile directory |
| `.debug_abbrev`, `.debug_aranges`, `.debug_ranges`/`.debug_rnglists`, `.debug_loc`/`.debug_loclists` | Encoding tables, address ranges, variable locations |
| `.debug_frame` | Call frame information (separate from `.eh_frame`, which stays because exceptions and unwinding need it) |

Clang and GCC can compress DWARF with `-gz`. Older GNU-style compression uses `.zdebug_*` section names. Current toolchains keep the `.debug_*` names and set the `SHF_COMPRESSED` flag instead. Either way, a tool that does not decompress may show the sections as empty or call the file stripped. `file` from a recent libmagic, `llvm-readelf` and `llvm-dwarfdump` handle both.

What matters is content, not names. A section header named `.debug_info` with size zero is not debug information. A non-empty `.debug_info` with your project's function names and source paths is. That is also why `.eh_frame`, `.note.gnu.build-id` and `.gnu_debuglink` are not findings: they carry unwinding data, a build identifier and a pointer to an external debug file, not symbols.

#### What the Android Gradle plugin strips, and when it does not

The NDK's CMake toolchain compiles with `-g`, so every intermediate library has full DWARF. AGP then strips the `.so` files with the NDK's `llvm-strip` when it packages the APK or bundle. The [Android documentation](https://developer.android.com/build/include-native-symbols) states that release builds are stripped by default. AGP also strips prebuilt libraries you place in `jniLibs`, if it can find an NDK. The cases where unstripped libraries reach a release build are therefore specific:

- `packaging { jniLibs { keepDebugSymbols += "**/libfoo.so" } }` (AGP 8 DSL) or the older `packagingOptions { doNotStrip "..." }`.
- No NDK installed on the CI machine, so AGP cannot run `llvm-strip` and packages the libraries unchanged, with a warning that is easy to miss.
- Libraries added after AGP's packaging step: a post-processing script, a repackaging step, some cross-platform toolchains.
- Vendor binaries that AGP never sees, for example libraries extracted from an asset at runtime.

#### Companion files: native-debug-symbols.zip and mapping.txt

For symbolicated native crash reports in Play Console, you set `ndk { debugSymbolLevel = "SYMBOL_TABLE" }` or `"FULL"` in the release build type. AGP writes `app/build/outputs/native-debug-symbols/<variant>/native-debug-symbols.zip`. With `FULL`, it contains unstripped `.so` files with their DWARF inside, not split `.dwo` files. With `SYMBOL_TABLE`, it contains symbol tables only. When you upload an App Bundle, AGP can include the symbols in the bundle's metadata for Play to use. They do not end up in the APKs that Play generates for devices. The Java and Kotlin counterpart is R8's `mapping.txt`, which you upload so Play can deobfuscate stack traces. Neither file belongs inside an APK, and finding one there is a finding.

#### Java and Kotlin debug metadata in DEX

The DEX side has its own debug information. `javac` and `kotlinc` emit a source-file attribute, line-number tables and local-variable tables. R8 removes local-variable tables and, by default, the attributes too, unless rules keep them. Many projects add `-keepattributes SourceFile,LineNumberTable` for readable stack traces. That is normal and not a finding. Rules that keep `LocalVariableTable`, or a release build with `isMinifyEnabled = false`, are. jadx shows the difference immediately: an unshrunk build decompiles with original parameter and local names and `/* compiled from: Foo.kt */` comments on every class. Whether class and method names are renamed is an obfuscation question for [MASWE-0059](/mobile/maswe-0059-code-obfuscation-not-implemented/).

### Android: StrictMode (MASTG-KNOW-0009)

*OWASP page: [MASTG-KNOW-0009](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0009/).*

[`StrictMode`](https://developer.android.com/reference/android/os/StrictMode) is a development tool that detects bad practice at runtime and reports it. It is valuable in debug and CI builds. In a release build it serves no user, and with `penaltyLog()` it prints stack traces of the app's own code, with class names, method names, file names and line numbers, into the system log.

#### Policies, detectors and penalties

There are two policies, each built with a builder:

| Policy | Builder | Typical detectors | Scope |
|---|---|---|---|
| Thread policy | `StrictMode.ThreadPolicy.Builder` | `detectDiskReads()`, `detectDiskWrites()`, `detectNetwork()`, `detectCustomSlowCalls()`, `detectResourceMismatches()`, `detectUnbufferedIo()`, `detectAll()` | The thread that sets it, usually the main thread |
| VM policy | `StrictMode.VmPolicy.Builder` | `detectLeakedSqlLiteObjects()`, `detectLeakedClosableObjects()`, `detectActivityLeaks()`, `detectFileUriExposure()`, `detectCleartextNetwork()` (API 23), `detectContentUriWithoutPermission()` (API 26), `detectNonSdkApiUsage()` (API 28), `detectUnsafeIntentLaunch()` (API 31), `detectAll()` | The whole process |

Penalties decide what happens on a violation: `penaltyLog()` (logcat, tag `StrictMode`), `penaltyDeath()` (crash), `penaltyDialog()` (thread policy only), `penaltyDropBox()` (the system DropBox), `penaltyFlashScreen()` (thread policy only), `penaltyListener()` (API 28, a callback into the app), plus targeted variants such as `penaltyDeathOnNetwork()`, `penaltyDeathOnCleartextNetwork()` and `penaltyDeathOnFileUriExposure()`. `StrictMode.enableDefaults()` turns on `detectAll()` with `penaltyLog()` for both policies in one call, so search for it as well.

The canonical pattern, from OWASP and the Android reference, is to install the policies in `Application.onCreate()` inside `if (BuildConfig.DEBUG)`. In a release build `DEBUG` is the constant `false`, so the compiler and R8 remove the whole block, and the release DEX contains no StrictMode call from first-party code.

#### What the platform enables on its own

This matters for testing, and OWASP's dynamic demo trips over it. Android installs default policies in every app process while it binds the application. `ActivityThread.handleBindApplication()` calls `StrictMode.initThreadDefaults()` and `StrictMode.initVmDefaults()`. For apps targeting API 24 or higher, the VM defaults include `detectFileUriExposure()` (this is where `FileUriExposedException` comes from). For apps targeting API 11 or higher, the thread defaults include network-on-main-thread detection (`NetworkOnMainThreadException`). AOSP's builders also add `penaltyLog()` when a policy has detectors but none of the basic penalties. The result: every app, including one with no StrictMode code, calls `setVmPolicy()` and `penaltyLog()` at startup, from framework code. On engineering and userdebug builds of Android, bundled system apps get more detectors. That does not affect third-party apps on a retail device.

A hook on `setVmPolicy` therefore always fires. What you must look at is the caller. See [MASTG-TEST-0264](#mastg-test-0264-runtime-use-of-strictmode-apis-android).

#### Libraries that touch StrictMode

AndroidX, Google Play services and many SDKs call `StrictMode.allowThreadDiskReads()` or `allowThreadDiskWrites()` around a short operation, then restore the previous policy with `StrictMode.setThreadPolicy(oldPolicy)`. That code relaxes a policy. It does not enable one, and it is not a finding. When static analysis lists `setThreadPolicy` calls, separate first-party code that **builds** a policy with detectors and a penalty from library code that saves and restores one.

### Android: Logging and debug-only code

*Background for this note. No OWASP Knowledge item covers implementation details in Android logs. OWASP's Android logging material sits under MASWE-0005 (tests MASTG-TEST-0203 and 0231) and is about sensitive data.*

[`android.util.Log`](https://developer.android.com/reference/android/util/Log) writes to the kernel-backed log buffers that `logcat` reads. A few facts that testers and developers often get wrong:

- **Nothing filters `Log.d` or `Log.v` in a release build.** The calls write whatever level they are called with. `Log.isLoggable(tag, level)` only reports a configured threshold (INFO by default). It filters nothing unless the code calls it. And the threshold can be changed by anyone with ADB: `adb shell setprop log.tag.<TAG> VERBOSE`. Code that uses `isLoggable` as its release switch has a switch that the attacker controls.
- **Who can read logs.** Since Android 4.1 (API 16), third-party apps cannot read other apps' log entries. `READ_LOGS` is reserved for system, privileged and development use. Android 13 added a user consent prompt when an app with log access requests it. So the reader is someone with ADB on the device (the attacker's own device in a resilience assessment), a bug report, an OEM or preinstalled component with log access, or a crash-reporting SDK that collects logcat lines as "breadcrumbs" and uploads them. Android's own risk page on [log information disclosure](https://developer.android.com/privacy-and-security/risks/log-info-disclosure) covers the same ground.
- **`printStackTrace()` goes to logcat** under the `System.err` tag, with every frame. `System.out.println` goes to `System.out`. Both are easy to miss in a grep that looks only for `Log.`.
- **Wrappers.** Timber, SLF4J-Android and in-house `Logger` classes. Timber with no tree planted logs nothing, but the message strings are still built and are still in the DEX. Timber with `DebugTree` planted unconditionally logs everything at every level.
- **HTTP clients.** OkHttp's `HttpLoggingInterceptor` at `Level.HEADERS` or `Level.BODY` logs URLs, headers and bodies, which almost always includes session tokens (MASWE-0005) and always includes the full API surface (this note).
- **R8 can remove calls.** `-assumenosideeffects class android.util.Log { public static int d(...); public static int v(...); }` tells R8 that these methods have no effect, so it deletes the calls and, where it can, the string building that feeds them. This only works when R8 optimises, that is with `proguard-android-optimize.txt` rather than the old `proguard-android.txt`, which contains `-dontoptimize`. Literals that are also used elsewhere stay in the DEX.
- **`BuildConfig.DEBUG` is the compile-time switch.** AGP generates it per variant. In release it is `false`, so guarded code disappears. `0 != (applicationInfo.flags & ApplicationInfo.FLAG_DEBUGGABLE)` is a runtime check: the code stays, and repackaging the app as debuggable (or hooking the check) turns it back on.

### iOS: Debugging Information and Debug Symbols (MASTG-KNOW-0063)

*OWASP page: [MASTG-KNOW-0063](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CODE/MASTG-KNOW-0063/).*

Every Mach-O binary in an app (the main executable, each framework under `Frameworks/`, each extension under `PlugIns/`) has a symbol table (`LC_SYMTAB`) in its `__LINKEDIT` segment. Before stripping, it holds global and local symbols for C, C++, Objective-C and Swift functions, and, in builds compiled with `-g`, a *debug map* of STABS entries. OWASP says, correctly, that release builds should not carry them. The mechanism is different from ELF in a way that changes what you test.

#### Where DWARF lives on Apple platforms: the debug map and dSYM

Apple's linker does not copy DWARF into the linked binary. DWARF stays in the object files (`.o`) in the build directory. The linked binary gets a debug map: STABS symbol entries (`N_SO` for source files and the compile directory, `N_OSO` for the path of each object file, `N_FUN`, `N_BNSYM` and `N_ENSYM` for functions) that tell `dsymutil` where to find the DWARF for each address range. `dsymutil` follows that map, collects the DWARF and writes a `.dSYM` bundle (`App.app.dSYM/Contents/Resources/DWARF/App`), matched to the binary by its `LC_UUID`.

This is what Xcode's **Debug Information Format** (`DEBUG_INFORMATION_FORMAT`) chooses between:

- `dwarf`: DWARF stays in the `.o` files and only the debug map points to it. Fast to build, the Debug default.
- `dwarf-with-dsym`: the same, plus `dsymutil` runs and produces a `.dSYM`. The Release default, and what crash symbolication needs.

OWASP, and the iOS test MASTG-TEST-0219, describe "DWARF" as embedding debug information in the binary. On Apple platforms that is not what happens. What "embeds" is the debug map. It is still a finding: it carries every function name and the absolute build path of every object file, which often includes a developer's username and the project's directory structure. We verified this on a small C program built with `clang -g`. The unstripped executable had no `__DWARF` segment, but `nm -a` showed `SO` and `OSO` entries with the full build path and a `FUN` entry for every function, including `static` ones.

#### Xcode settings that decide what ships

| Setting (build setting name) | What it does | Release recommendation |
|---|---|---|
| Generate Debug Symbols (`GCC_GENERATE_DEBUGGING_SYMBOLS`) | Passes `-g` to the compiler | `YES`. You need it to produce a dSYM. |
| Debug Information Format (`DEBUG_INFORMATION_FORMAT`) | `dwarf` or `dwarf-with-dsym` | `dwarf-with-dsym` |
| Deployment Postprocessing (`DEPLOYMENT_POSTPROCESSING`) | Master switch for install-time processing, including stripping. Xcode sets it when you archive or install. | Leave it to the archive action |
| Strip Linked Product (`STRIP_INSTALLED_PRODUCT`) | Strips the linked binary when postprocessing runs | `YES` |
| Strip Style (`STRIP_STYLE`) | `all` (everything not needed for dynamic linking), `non-global` (keep exported symbols), `debugging` (remove only debug symbols) | `all` for apps. Frameworks need `non-global` to keep their exports. The default depends on the product type. |
| Strip Swift Symbols (`STRIP_SWIFT_SYMBOLS`) | Also removes Swift symbols when stripping | `YES` |
| Strip Debug Symbols During Copy (`COPY_PHASE_STRIP`) | Strips binaries copied by Copy Files phases, such as embedded frameworks | `YES` for Release |

Two corrections to the OWASP test text follow from this table. First, MASTG-TEST-0219 contradicts itself. Its evaluation tells you to verify that **Generate Debug Symbols** is set to **No**, and in the next paragraph it advises **DWARF with dSYM File** for release builds. The two cannot both hold: with Generate Debug Symbols off, the compiler gets no `-g`, there is no DWARF for `dsymutil` to collect, and no usable dSYM is produced (`dsymutil` warns "no debug symbols in executable"). Crash reports then cannot be symbolicated. Nor does the setting achieve what the test wants, because it does **not** remove local symbols. Our test build without `-g` still listed `t _check_frida_port` in `nm`. The resolution is to treat symbols and stripping as two separate steps: keep **Generate Debug Symbols = Yes** so the debug information exists, put it in a dSYM that stays off the device (in your artefact store and your crash reporter), and strip the shipped binary. Second, generating a dSYM does not strip anything. A build with `dwarf-with-dsym` and stripping disabled ships both a dSYM (on the build machine) and the full debug map (in the app). The legacy test MASTG-TEST-0083 pointed at **Strip Debug Symbols During Copy**. That setting covers copied binaries such as embedded frameworks, not the main executable.

Apple's `strip` maps onto those styles. We checked each one on the test binary:

| Command | Debug map (STABS) | Local symbols (`t`) | Global symbols |
|---|---|---|---|
| none | present | present | present |
| `strip -S` (debugging) | removed | kept | kept |
| `strip -x` (non-global) | removed | removed | kept |
| `strip` (all) | removed | removed | only what dynamic linking needs |

After `strip -x` and `strip`, `nm -a` still lists one STABS-type entry, `OPT radr://5614542`. It is a marker that Apple's `strip` leaves behind. It is not debug information. Do not count it as a debug symbol. `objdump --syms` shows it with the `d` flag, which is exactly the flag OWASP's technique tells you to look for.

#### What stripping can never remove

The Objective-C runtime needs class names, selector names, protocol names, ivar names and method type encodings (`__objc_classname`, `__objc_methname`, `__objc_methtype`). Swift needs type metadata, nominal type descriptors and, unless disabled, reflection metadata with field names (`__swift5_typeref`, `__swift5_reflstr`, `__swift5_fieldmd`). They are in every iOS binary, stripped or not. Their presence is not a finding under this test. `SWIFT_REFLECTION_METADATA_LEVEL = none` reduces the Swift field names, at the cost of features that use `Mirror`. Beyond that, readable names are an [obfuscation](/mobile/maswe-0059-code-obfuscation-not-implemented/) question.

Also note that App Store binaries are FairPlay-encrypted, but only a range of the `__TEXT` segment. The symbol table in `__LINKEDIT` is readable without decryption, so symbol checks work on an encrypted binary. String and disassembly checks do not.

### iOS: Non-Production Resources (MASTG-KNOW-0064)

*OWASP page: [MASTG-KNOW-0064](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CODE/MASTG-KNOW-0064/).*

Non-production resources are assets, endpoints and configuration meant for development, test or staging that end up in the release build. OWASP lists verbose logging frameworks, test servers or endpoints without proper authentication or encryption, sample data files, feature flags that enable insecure behaviour, development certificates and provisioning profiles, and test credentials or API keys. They matter for two different reasons, and they belong to two different weaknesses:

- **Confidentiality.** A staging hostname, a sample database with real-looking records, test credentials. These leak information whether or not anything uses them. They are [MASWE-0004](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/).
- **Resilience and control bypass.** Configuration that changes behaviour: an environment picker, a "use staging" toggle, a flag that disables pinning, a debug menu, a development library such as FLEX linked into Release. These are this note.

Where they hide on iOS:

| Location | What to look for |
|---|---|
| `Settings.bundle/Root.plist` | Toggles or multi-value pickers (`PSToggleSwitchSpecifier`, `PSMultiValueSpecifier`) with keys like `environment`, `use_staging`, `debug_logging`. Anyone can change them in the Settings app, no jailbreak needed. |
| `Info.plist` | Extra URL schemes (`CFBundleURLTypes`) used for debug deep links, custom keys such as `API_BASE_URL` or `Environment`, `NSAllowsArbitraryLoads` added for a test server |
| Bundled config | A second `GoogleService-Info.plist`, `.xcconfig` remnants, `config-staging.json`, mock response files (`*.json`, `*.har`), fixture databases (`*.sqlite`, `*.realm`) |
| Code | `ProcessInfo.processInfo.arguments` or `environment` checks (launch arguments only reach the app from Xcode, a test runner or a jailbreak tool, but they are still a switch), `UserDefaults` keys, shake gestures (`motionEnded(_:with:)`), "tap the version label N times" counters, `sandboxReceipt` checks that enable menus on TestFlight |
| Frameworks | FLEX, network debuggers, in-house debug-menu frameworks, `XCTest` or test-support frameworks copied into `Frameworks/` |
| Signing | `embedded.mobileprovision` and `aps-environment = development` indicate a development or ad hoc build. That is a build-identification finding, and the debuggable side (`get-task-allow`) belongs to [MASWE-0063](/mobile/maswe-0063-debug-mechanisms-not-disabled/). |

Android has no OWASP Knowledge item for this, but the same classes exist. Look in `assets/`, `res/raw/`, `res/xml/` (a second network security config), `BuildConfig` fields (`BASE_URL`, `FLAVOR`, `BUILD_TYPE`), `SharedPreferences` keys, exported activities with "debug" in their names, deep-link hosts such as `debug` or `dev`, and dependencies such as Chucker, LeakCanary, Stetho or Flipper in the release DEX. [GT-RES-0061-2](#gt-res-0061-2-debug-menus-hidden-switches-and-non-production-configuration-android-and-ios) tests both platforms.

### iOS: Logs (MASTG-KNOW-0101)

*Summary. OWASP page: [MASTG-KNOW-0101](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0101/). It is a STORAGE item, referenced by the two iOS logging tests in this note.*

iOS has two separate output paths, and testers who mix them up get incomplete results:

| API | Destination | Visible with |
|---|---|---|
| `NSLog` | Unified logging (default level), and stderr | `idevicesyslog`, Console.app, `log collect`/`log show`, Xcode |
| `os_log`, `Logger` | Unified logging at the chosen level (`debug`, `info`, `notice`/default, `error`, `fault`) | Same, subject to level and privacy rules |
| `print`, `debugPrint`, `dump` | Standard output of the process | Xcode console, `simctl launch --console-pty` on the Simulator, or Frida hooking `write`/`fwrite`. Not in the device's unified log. |
| `printf`, `fprintf`, `std::cout` in bundled C/C++ | stdout/stderr | Same as `print` |

Unified logging adds two behaviours that matter for testing:

- **Levels and persistence.** Debug messages are normally captured only while someone is streaming with debug enabled. Info messages are kept in memory and persisted only in some situations. Default/notice, error and fault are written to the persistent store. A debug-level message is therefore less exposed than an `NSLog` line, but it is still in the binary and still visible to anyone streaming the device's log.
- **Privacy.** In `os_log` and `Logger`, dynamic strings and objects interpolated into a message are redacted as `<private>` by default. Scalars are not. `%{public}@` in `os_log`, or `privacy: .public` in `Logger`, makes a value visible. Static text in the format string is always visible. `NSLog` has no privacy model: the rendered string is logged as is. When a debugger is attached, for example because Xcode launched the app, private values are shown, so test with the app launched normally from the home screen.

Other sources OWASP lists: crash reporters and analytics SDKs that collect breadcrumbs and logs before upload, HTTP client debug modes, and WebViews that bridge JavaScript `console` output into native logging. For implementation details, the strings in the binary matter as much as what you see at runtime, which is why [MASTG-TEST-0358](#mastg-test-0358-implementation-details-exposure-through-logging-apis-ios) is static and [MASTG-TEST-0359](#mastg-test-0359-implementation-details-exposure-in-logs-ios) dynamic.

## Tests

OWASP assigns seven tests to MASWE-0061: four for Android (three on StrictMode, one on native symbols) and three for iOS (symbols, and logging in static and dynamic form). There is no OWASP test for implementation details in Android logs, and none for debug menus, hidden switches or non-production configuration on either platform. Our tests GT-RES-0061-1 and GT-RES-0061-2 fill those gaps. One mapping detail: legacy MASTG-TEST-0041 lists only MASTG-TEST-0263 in its `covered_by` field, although 0264 and 0265 test the same StrictMode behaviour from the hook and static side. And 0041's title promises "Debugging Code and Verbose Error Logging", but its verbose-logging half has no Android v2 successor at all. That is why GT-RES-0061-1 exists.

| Test | Platform | Type | Replaces legacy v1 test |
|---|---|---|---|
| MASTG-TEST-0263 | Android | Dynamic (logs) | [MASTG-TEST-0041](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0041/) Testing for Debugging Code and Verbose Error Logging (StrictMode half) |
| MASTG-TEST-0264 | Android | Dynamic (hooks) | MASTG-TEST-0041 in substance, although its `covered_by` does not list it |
| MASTG-TEST-0265 | Android | Static | MASTG-TEST-0041 in substance, although its `covered_by` does not list it |
| MASTG-TEST-0288 | Android | Static | [MASTG-TEST-0040](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0040/) Testing for Debugging Symbols |
| GT-RES-0061-1 | Android | Static and dynamic | The verbose-logging half of legacy 0041, which no Android v2 test covers |
| MASTG-TEST-0219 | iOS | Static | [MASTG-TEST-0083](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0083/) Testing for Debugging Symbols |
| MASTG-TEST-0358 | iOS | Static | [MASTG-TEST-0084](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0084/) Testing for Debugging Code and Verbose Error Logging (with 0359) |
| MASTG-TEST-0359 | iOS | Dynamic (logs) | MASTG-TEST-0084 (with 0358) |
| GT-RES-0061-2 | Android and iOS | Static, dynamic, manual | Covers the "debug-management code" part of legacy 0084 (debug views, server selection, stub responses) that no v2 test kept |

### Before you start: unpack once, keep everything

Most tests below work on the same artefacts. Collect them once. Test the build that users get: the Play or App Store version, or the exact release artefact from the pipeline. A debug or QA build fails every test in this note by design and proves nothing.

```bash
# Android: all APKs of the installed package (base + splits)
PKG=com.example.app
mkdir -p apk && for p in $(adb shell pm path "$PKG" | cut -d: -f2); do adb pull "$p" apk/; done
aapt2 dump badging apk/base.apk | grep -E "^package|^application-debuggable"   # debuggable = MASWE-0063
mkdir -p apk_libs && for a in apk/*.apk; do unzip -oq "$a" 'lib/*' -d apk_libs 2>/dev/null; done
jadx -d jadx_out apk/base.apk            # Java view, for semgrep and rg
apktool d -f -o smali_out apk/base.apk   # smali view, robust against decompiler failures
for a in apk/*.apk; do unzip -l "$a" | grep -E 'mapping\.txt|native-debug-symbols|\.dwo$|\.debug$'; done  # must be empty

# iOS: unpack the IPA (decrypted for string/disassembly checks; symbol checks work either way)
unzip -oq App.ipa -d ipa
APP=$(ls -d ipa/Payload/*.app); EXE="$APP/$(plutil -extract CFBundleExecutable raw "$APP/Info.plist")"
find "$APP" -name '*.dSYM' -o -name '*.map' -o -name '*.xcconfig'   # must be empty
otool -l "$EXE" | grep -A4 LC_ENCRYPTION_INFO | grep cryptid      # 1 = still encrypted
```

Tools: the NDK's LLVM tools (`$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/<host>/bin/llvm-readelf`, `llvm-nm`, `llvm-objdump`, `llvm-strip`) or GNU binutils, [rabin2](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/) and [radare2](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/), [semgrep](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/), [Frida](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/), jadx and apktool, and for iOS Xcode's command-line tools (`nm`, `otool`, `strip`, `dsymutil`, `xcrun swift-demangle`) plus the [libimobiledevice suite](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0126/). Recent NDKs ship only LLVM binutils, so the GNU `arm-linux-androideabi-nm` path in the legacy test no longer exists. Set-up for rooted and jailbroken devices, Frida and proxies is in our [lab note](/mobile/mobile-traffic-interception-lab/).

### MASTG-TEST-0263: Logging of StrictMode Violations (Android)

*OWASP test: [MASTG-TEST-0263](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0263/). Type: dynamic (logs). Platform: Android. Demo: [MASTG-DEMO-0037](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0037/MASTG-DEMO-0037/).*

#### Overview

The test runs the production build and watches logcat for StrictMode violation reports. If any appear, a StrictMode policy with `penaltyLog()` is active in the release build, and the app is writing stack traces of its own code to the system log. It is the most direct of the three StrictMode tests, because it proves both that a policy is installed and that it produces output. It is also the least complete: a policy that is installed but never violated during your session produces nothing.

#### Prerequisites

- The release build installed on a device or emulator. OWASP's technique is [MASTG-TECH-0005](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/) (`adb install`, or `adb install-multiple` for splits).
- ADB access. Root is not required: on a retail device `adb logcat` shows every app's log to the shell user.
- The package name.

#### Steps

1. Clear the log and start the app, so you can filter by its process ID ([MASTG-TECH-0009](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0009/)):

   ```bash
   PKG=com.example.app
   adb logcat -c
   adb shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1
   PID=$(adb shell pidof -s "$PKG"); echo "$PID"
   ```

2. Capture StrictMode output for that process, and a full capture in parallel in case the app restarts and changes PID:

   ```bash
   adb logcat --pid="$PID" -v threadtime -s StrictMode:V > strictmode.txt &
   adb logcat -v threadtime -s StrictMode:V > strictmode_all.txt &
   ```

3. Exercise the app. Violations are triggered by behaviour, so cover the paths that do I/O: start-up (preferences and databases are often read on the main thread), login, lists that load data, settings, file import and export, sharing. VM-policy leak violations are reported when the leaked object is finalised, so put the app in the background, open other apps and come back to give the garbage collector time.

4. Stop the captures and check the result:

   ```bash
   kill %1 %2
   grep -c 'StrictMode policy violation' strictmode.txt
   grep -E 'Violation|at [a-z]' strictmode.txt | grep -v -E 'at (android|java|kotlin|dalvik|com\.android)\.' | head -40
   ```

   The second command shows the violation type and the frames from app and library code, which is where the implementation details are.

#### Observation

Save the logcat lines with the StrictMode tag, attributed to the app's PID. For each violation, record the class (`DiskReadViolation`, `LeakedClosableViolation`, `NetworkViolation`, `UntaggedSocketViolation`, `CleartextNetworkViolation` and so on) and the app frames in the trace: class, method, file and line.

#### Evaluation

- **Fail** if the release build produces any `StrictMode policy violation` lines for the app's process. Quote the frames that show first-party implementation details.
- **Fail, and look closer**, if the violations come with a dialog or a crash (`penaltyDialog()`, `penaltyDeath()`). A crash an attacker can trigger, for example by sending a `file://` URI that the app shares onward, is an availability issue as well as an artefact.
- **Inconclusive, not pass**, if nothing appears. Run [MASTG-TEST-0265](#mastg-test-0265-references-to-strictmode-apis-android) to confirm that no policy is installed.
- Be careful with attribution. A `FileUriExposedException` or `NetworkOnMainThreadException` comes from the platform's default policies, not from app-enabled StrictMode, and it is not this finding.

#### Demo

OWASP's sample installs a VM policy without a debug guard and leaks a cursor (abridged from [MASTG-DEMO-0037](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0037/MASTG-DEMO-0037/)):

```kotlin
private fun enableStrictMode() {
    StrictMode.setVmPolicy(
        StrictMode.VmPolicy.Builder()
            .detectLeakedClosableObjects()
            .penaltyLog()
            .build()
    )
}

private fun triggerSqliteCursorLeak() {
    val db = context.openOrCreateDatabase("test.db", Context.MODE_PRIVATE, null)
    db.execSQL("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT)")
    val cursor = db.rawQuery("SELECT * FROM users", null)   // never closed
}
```

OWASP's logcat output, shortened:

```text
D StrictMode: StrictMode policy violation: android.os.strictmode.LeakedClosableViolation: A resource was acquired at attached stack trace but never released. ...
D StrictMode: Caused by: java.lang.Throwable: Explicit termination method 'AbstractCursor.close' not called
D StrictMode:   at android.database.sqlite.SQLiteDatabase.rawQuery(SQLiteDatabase.java:1653)
D StrictMode:   at org.owasp.mastestapp.MastgTest.triggerSqliteCursorLeak(MastgTest.kt:35)
D StrictMode:   at org.owasp.mastestapp.MastgTest.mastgTest(MastgTest.kt:12)
D StrictMode:   at org.owasp.mastestapp.MainActivityKt$MyScreenContent$1$1$1.invoke(MainActivity.kt:117)
```

The test fails. The trace gives the attacker the class, method, source file and line of a database access, the UI path that leads to it, and the fact that the code uses raw SQL. In an R8-obfuscated app the frames would show renamed classes, but still with line numbers if `LineNumberTable` is kept, and still with the framework calls that reveal what the code does.

### MASTG-TEST-0264: Runtime Use of StrictMode APIs (Android)

*OWASP test: [MASTG-TEST-0264](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0264/). Type: dynamic (hooks). Platform: Android. Demo: [MASTG-DEMO-0038](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0038/MASTG-DEMO-0038/).*

#### Overview

The test hooks the StrictMode APIs with Frida ([MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/), method hooking) and records whether the app installs a policy at runtime. It catches policies that never produce a violation in your session, which MASTG-TEST-0263 misses. It needs one correction to be useful. As explained in [the Knowledge section](#what-the-platform-enables-on-its-own), the framework calls `setVmPolicy()`, `setThreadPolicy()` and `penaltyLog()` for every app at bind time. The OWASP evaluation, "fails if the output shows the runtime usage of StrictMode APIs", would therefore fail every app. OWASP's own demo output shows only that framework call (its backtrace runs through `StrictMode.initVmDefaults` and `ActivityThread.handleBindApplication`), not the sample's call. You must classify each call by its caller.

#### Prerequisites

- A rooted device or emulator with `frida-server` running, or a debuggable re-signed build with the Frida gadget for apps you are allowed to repackage. Lab set-up is in our [lab note](/mobile/mobile-traffic-interception-lab/). [Frida for Android](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0001/).
- The app's first-party package prefix, from the manifest or jadx (for example `com.example.app`). Obfuscated apps keep their top-level package in most cases. If not, use the application class's package.

#### Steps

1. Save this script as `strictmode.js`. It extends OWASP's script to cover both policies and `enableDefaults()`, and labels every call as app or framework from the stack:

   ```javascript
   Java.perform(() => {
     const PREFIX = 'com.example.app';           // first-party package prefix
     const SM = Java.use('android.os.StrictMode');
     const Log = Java.use('android.util.Log');
     const Ex = Java.use('java.lang.Exception');

     function report(what) {
       const frames = Log.getStackTraceString(Ex.$new()).split('\n').slice(1, 10);
       const fromApp = frames.some(f => f.includes(PREFIX));
       console.log('\n[' + (fromApp ? 'APP' : 'framework/library') + '] ' + what);
       frames.forEach(f => console.log('   ' + f.trim()));
     }

     SM.setThreadPolicy.implementation = function (p) { report('setThreadPolicy ' + p); return this.setThreadPolicy(p); };
     SM.setVmPolicy.implementation = function (p) { report('setVmPolicy ' + p); return this.setVmPolicy(p); };
     SM.enableDefaults.implementation = function () { report('enableDefaults'); return this.enableDefaults(); };
     ['android.os.StrictMode$ThreadPolicy$Builder', 'android.os.StrictMode$VmPolicy$Builder'].forEach(n => {
       Java.use(n).penaltyLog.implementation = function () { report(n.split('$')[1] + '.penaltyLog'); return this.penaltyLog(); };
     });
   });
   ```

2. Spawn the app with the script, so the hooks are in place before `Application.onCreate()`:

   ```bash
   frida -U -f com.example.app -l strictmode.js -o strictmode_hooks.txt
   ```

3. Exercise the app as in MASTG-TEST-0263. Policies set in an `Activity` or after login only appear when you reach that code.

4. Filter the result:

   ```bash
   grep -A10 '^\[APP\]' strictmode_hooks.txt
   ```

#### Observation

Record every `[APP]` call with its stack, and the policy it installs (the `toString()` of a policy shows its mask). Keep the `[framework/library]` calls in your evidence too. They show that you looked and why you did not count them.

#### Evaluation

- **Fail** if first-party code calls `setThreadPolicy()` or `setVmPolicy()` with a policy built with detectors and `penaltyLog()`, `penaltyDialog()`, `penaltyDropBox()` or `penaltyDeath()`, or calls `enableDefaults()`.
- **Pass** if the only calls come from `ActivityThread.handleBindApplication` (platform defaults), or from library code that relaxes and restores a policy (`allowThreadDiskReads()` followed by `setThreadPolicy(oldPolicy)`).
- A first-party `penaltyListener()` that sends violations to a crash reporter is still StrictMode in production. Report it as an artefact, and check what the listener sends.

#### Demo

OWASP's demo output, abridged. Both entries come from the platform, not from the sample app:

```text
[*] StrictMode.VmPolicy.Builder.penaltyLog() called
android.os.StrictMode$VmPolicy$Builder.penaltyLog(Native Method)
android.os.StrictMode$VmPolicy$Builder.build(StrictMode.java:1226)
android.os.StrictMode.initVmDefaults(StrictMode.java:1522)
android.app.ActivityThread.handleBindApplication(ActivityThread.java:6844)

[*] StrictMode.setVmPolicy() called
android.os.StrictMode.setVmPolicy(Native Method)
android.os.StrictMode.initVmDefaults(StrictMode.java:1522)
android.app.ActivityThread.handleBindApplication(ActivityThread.java:6844)
```

`penaltyLog()` is called from `Builder.build()`, which is AOSP adding the default penalty to the platform's own VM policy. With the script above, these lines are labelled `[framework/library]`. The call that makes the sample app fail is the one after you tap **Start** (illustrative, not from OWASP's output):

```text
[APP] VmPolicy.penaltyLog
   at android.os.StrictMode$VmPolicy$Builder.penaltyLog(Native Method)
   at org.owasp.mastestapp.MastgTest.enableStrictMode(MastgTest.kt:21)
   at org.owasp.mastestapp.MastgTest.mastgTest(MastgTest.kt:11)
```

### MASTG-TEST-0265: References to StrictMode APIs (Android)

*OWASP test: [MASTG-TEST-0265](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0265/). Type: static. Platform: Android. Demo: [MASTG-DEMO-0039](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0039/MASTG-DEMO-0039/).*

#### Overview

The test decompiles the app ([MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), reverse engineering) and searches for StrictMode API calls ([MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), static analysis). It finds policies on code paths you never reach at runtime. It is reliable even on obfuscated apps, because `android.os.StrictMode` is a framework class that R8 cannot rename. OWASP's semgrep rule only matches `StrictMode.setVmPolicy(...)`. It misses `setThreadPolicy`, `enableDefaults` and the builders, so we use a wider rule and a smali grep.

#### Prerequisites

- The release APKs, decompiled with jadx and disassembled with apktool (see [Before you start](#before-you-start-unpack-once-keep-everything)).
- [semgrep](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/) and `rg` (ripgrep) or `grep`.

#### Steps

1. Find every StrictMode call site in smali. This survives jadx decompilation failures:

   ```bash
   rg -n 'Landroid/os/StrictMode(\$ThreadPolicy|\$VmPolicy)?(\$Builder)?;->(setThreadPolicy|setVmPolicy|enableDefaults|penalty[A-Za-z]*|detect[A-Za-z]*)' smali_out \
     | awk -F: '{print $1}' | sort | uniq -c | sort -rn
   ```

2. Run a wider semgrep rule over the jadx output. Save as `strictmode.yml`:

   ```yaml
   rules:
     - id: gt-android-strictmode-policy
       languages: [java]
       severity: WARNING
       message: StrictMode policy or penalty in the APK - confirm it cannot run in the release build
       pattern-either:
         - pattern: StrictMode.enableDefaults()
         - pattern: StrictMode.setThreadPolicy(...)
         - pattern: StrictMode.setVmPolicy(...)
         - pattern: $B.penaltyLog()
         - pattern: $B.penaltyDeath()
         - pattern: $B.penaltyDialog()
   ```

   ```bash
   semgrep --config strictmode.yml jadx_out/sources --metrics=off
   ```

3. Triage each hit. Open the enclosing method in jadx, decide whether it is first-party (the app's package) or a library (`androidx.`, `com.google.`, SDK packages), and whether it builds a policy with a penalty or only relaxes and restores one. Follow the callers (jadx "Find usage") to see when the method runs: `Application.onCreate()`, an activity, a debug menu.

4. Check whether a guard survived. In a release build, a correct `if (BuildConfig.DEBUG)` guard leaves no code behind. If you see the policy code wrapped in a runtime check such as `(getApplicationInfo().flags & 2) != 0` (`FLAG_DEBUGGABLE`), a preference or a remote-config value, the code ships and can be switched on.

#### Observation

List each first-party call site with its file, method and caller chain, and the policy it builds. List library hits separately with the reason they do not count.

#### Evaluation

- **Fail** if first-party code in the release APK builds and installs a StrictMode policy with a penalty, or calls `enableDefaults()`, whether or not it is guarded by a runtime condition. A runtime guard lowers the likelihood but leaves the artefact in place.
- **Pass** if the only references are library relax-and-restore patterns, or no references exist.
- Report the finding with MASTG-TEST-0263 or 0264 evidence when you have it. Static presence plus observed log output is the strongest form.

#### Demo

OWASP's decompiled sample (jadx output, abridged from [MASTG-DEMO-0039](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0039/MASTG-DEMO-0039/)):

```java
/* compiled from: MastgTest.kt */
public final class MastgTest {
    private final void enableStrictMode() {
        StrictMode.setVmPolicy(new StrictMode.VmPolicy.Builder().detectLeakedClosableObjects().penaltyLog().build());
    }
}
```

OWASP's rule output:

```text
MastgTest_reversed.java
❯❱ rules.mastg-android-strictmode
      [MASVS-RESILIENCE] Detected usage of StrictMode
       29┆ StrictMode.setVmPolicy(new StrictMode.VmPolicy.Builder().detectLeakedClosableObjects().penaltyLog().build());
```

The wider rule reports the same line twice, once for `setVmPolicy` and once for `penaltyLog()`, and would also report a `setThreadPolicy` call that OWASP's rule misses. Also note the `/* compiled from: MastgTest.kt */` comment and the `app_debug` module name in the Kotlin `@Metadata` of the demo class: OWASP's demo was decompiled from a debug build. In a release build, check whether those survive. See [Java and Kotlin debug metadata in DEX](#java-and-kotlin-debug-metadata-in-dex) for what is and is not a finding.

### MASTG-TEST-0288: Debugging Symbols in Native Binaries (Android)

*OWASP test: [MASTG-TEST-0288](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0288/). Type: static. Platform: Android. No OWASP demo; the demo below is ours.*

#### Overview

The test checks every native library in the APK for a link-time symbol table and DWARF debug information, using OWASP's technique [MASTG-TECH-0140](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0140/) (obtaining debugging information and symbols). OWASP's evaluation fails the test if debugging information is present in any native binary. We keep that, and make it precise: `.dynsym` exports, build IDs and empty section headers do not count.

#### Prerequisites

- All APKs of the package with their `lib/` directories extracted (`apk_libs/`). Split APKs carry the ABI-specific libraries, so the base APK alone is often empty.
- `file` (libmagic 5.40 or later shows "with debug_info"), `llvm-readelf` and `llvm-nm` from the NDK or GNU `readelf` and `nm`. Optionally [rabin2](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/) or [radare2 for Android](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0028/).

#### Steps

1. Triage all libraries with `file`:

   ```bash
   find apk_libs/lib -name '*.so' -exec file {} + | sed 's/, BuildID\[[^]]*\]//'
   ```

   `stripped` means no `.symtab`. `not stripped` means `.symtab` is present. `with debug_info` means a `.debug_info` section is present.

2. For every library that is not stripped, list the symbol and debug sections and their sizes:

   ```bash
   llvm-readelf -SW apk_libs/lib/arm64-v8a/libfoo.so | grep -E '\.symtab|\.strtab|\.z?debug_'
   ```

   Zero-size sections do not count. Check the `Flg` column for `C` (compressed).

3. Count the local symbols that `.symtab` adds over the exports, and read the names:

   ```bash
   L=apk_libs/lib/arm64-v8a/libfoo.so
   llvm-nm --defined-only "$L" | wc -l          # .symtab (0 / "no symbols" when stripped)
   llvm-nm -D --defined-only "$L" | wc -l       # .dynsym exports, always present
   llvm-nm --defined-only "$L" | grep -E ' [tbdr] ' | head -30   # local functions and data
   ```

   OWASP's technique uses `diff <(nm lib) <(nm -a lib)`. That shows debugger-only entries such as `STT_FILE` source-file symbols. The comparison above, `.symtab` against `.dynsym`, answers the more useful question: which names did stripping fail to remove?

4. If DWARF is present, read what it reveals:

   ```bash
   llvm-dwarfdump --debug-info "$L" | grep -E 'DW_AT_(name|comp_dir)' | head -30
   llvm-dwarfdump --debug-line "$L" | grep -E '^(include_directories|file_names)' -A2 | head -30
   ```

   With GNU binutils: `readelf --debug-dump=info "$L" | grep -E 'DW_AT_(name|comp_dir)'`.

5. Attribute each library: first-party (`System.loadLibrary` call in the app's package), a framework runtime (Flutter, React Native, Unity), or a vendor SDK. `rg -n 'loadLibrary\("' jadx_out/sources` maps library names to callers.

6. Optional cross-check with rabin2: `rabin2 -I "$L" | grep -E 'stripped|linenum|lsyms|dbg_file'`.

#### Observation

For each library: ABI, path, `file` result, the `.symtab` and `.debug_*` sections with sizes, the count of local symbols, a sample of the most revealing names (security checks, crypto, licence, protocol functions), `DW_AT_comp_dir` and source paths if present, and whether the library is first-party or third-party.

#### Evaluation

- **Fail** if any library has a non-empty `.symtab` with local symbols, or non-empty DWARF sections (`.debug_info`, `.debug_line`, or their compressed forms). Compressed DWARF counts: it is the same information.
- **Fail** if an APK contains `native-debug-symbols.zip`, `.dwo`/`.debug` files or `mapping.txt`.
- **Not a finding:** `.dynsym` exports, including `Java_*` JNI names. They are needed at runtime. Recommend `RegisterNatives` and `-fvisibility=hidden` separately if the names reveal security logic. Also not findings: `.eh_frame`, `.note.gnu.build-id`, `.gnu_debuglink`, and section headers with size zero.
- Rate the severity by what the names reveal. `check_frida_port`, `verify_license_key` and `decrypt_payload` in a first-party library of an R-profile app are worth more to an attacker than symbols in a vendor's image decoder.

#### Demo

*Ours.* The same JNI library built three ways with Clang for aarch64. Output from our build, trimmed. NDK builds look the same apart from the toolchain-specific lines.

```c
static int check_frida_port(void) { /* ... */ return 0; }
static int verify_license_key(const char *k) { return strcmp(k, "x") == 0; }
JNIEXPORT jboolean JNICALL
Java_com_example_app_Native_isTampered(JNIEnv *env, jobject thiz) {
    return check_frida_port() || verify_license_key("y");
}
```

```text
$ file libnative-*.so
libnative-debug.so:    ELF 64-bit LSB shared object, ARM aarch64, ..., with debug_info, not stripped
libnative-symtab.so:   ELF 64-bit LSB shared object, ARM aarch64, ..., not stripped
libnative-stripped.so: ELF 64-bit LSB shared object, ARM aarch64, ..., stripped

$ llvm-nm --defined-only libnative-debug.so | grep -E 'check|verify|Java'
0000000000031520 T Java_com_example_app_Native_isTampered
0000000000031578 t check_frida_port
0000000000031580 t verify_license_key

$ llvm-nm libnative-stripped.so
llvm-nm: libnative-stripped.so: no symbols
$ llvm-nm -D --defined-only libnative-stripped.so
0000000000031520 T Java_com_example_app_Native_isTampered
```

`libnative-debug.so` and `libnative-symtab.so` fail: the local functions `check_frida_port` and `verify_license_key` name the anti-tampering logic, and the first also carries DWARF with source paths. `libnative-stripped.so` passes. Its JNI export is still visible, which is expected.

### GT-RES-0061-1: Implementation Details in Logs (Android)

*Guler Tech methodology — not an OWASP test.*

#### Overview

OWASP tests implementation details in logs only on iOS (MASTG-TEST-0358 and 0359), and on Android only StrictMode output. This test is the Android counterpart to the two iOS tests. It looks for log output that exposes how the app works: stack traces, class and method names, SQL statements, internal URLs and routes, feature flags and configuration, the state of security checks, library versions. Secrets and personal data in the same logs are reported under [MASWE-0005](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0005/) (OWASP tests MASTG-TEST-0203 and 0231). It is one test with a static and a dynamic part, because each finds what the other misses.

#### Prerequisites

- The release build, decompiled (`jadx_out/`, `smali_out/`), and installed on a device with ADB.
- For the system-property check, ADB is enough. No root needed.
- Optional: Frida, to attribute log lines to call sites.

#### Steps

1. **Static: find the logging calls.** Framework classes are never renamed, so smali greps work on obfuscated apps:

   ```bash
   rg -c 'Landroid/util/Log;->(v|d|i|w|e|wtf|println)\(' smali_out | sort -t: -k2 -rn | head -20
   rg -n 'Ljava/lang/(Throwable|Exception);->printStackTrace\(\)V|Ljava/io/PrintStream;->println' smali_out | wc -l
   rg -n 'HttpLoggingInterceptor\$Level;->(BODY|HEADERS)|Timber\$DebugTree|setLogLevel|isLoggable' smali_out | head
   ```

   The first command ranks files by number of `Log` calls. First-party files at the top are where to read. Also check jadx for wrappers (a class whose methods all end in `Log.d`) and add their names to the search.

2. **Static: read the messages.** For each first-party call site, look at the string passed and what is concatenated into it. Useful patterns:

   ```bash
   rg -n 'Log\.(v|d|i|w|e)\(' jadx_out/sources/com/example | rg -i 'url|endpoint|http|sql|select |insert |query|token|pinn|root|tamper|debug|config|flag|version|exception|stack' | head -50
   rg -n --no-filename -o '"https?://[^"]+"' jadx_out/sources | sort -u | head -50
   ```

3. **Static: check that release removal worked.** In a correctly configured R8 build with `-assumenosideeffects` for `Log.d` and `Log.v`, first-party code has no `Log;->d` or `Log;->v` calls left. If they remain, the R8 rules did not remove them. The rules are not in the APK, so ask the client for `proguard-rules.pro` or report the result as observed.

4. **Dynamic: capture the log while you exercise the app,** including error paths: airplane mode during a request, invalid input, expired session (log out on another device), rotated certificate (a proxy without a trusted CA), a rooted device if the app has root detection:

   ```bash
   adb logcat -c
   adb shell monkey -p com.example.app -c android.intent.category.LAUNCHER 1
   adb logcat --pid="$(adb shell pidof -s com.example.app)" -v threadtime '*:V' > app_log.txt
   ```

5. **Dynamic: try the `isLoggable` switch.** Take the tags from step 1 (the first argument of `Log.*` calls or of `isLoggable`) and raise their level, then repeat the session:

   ```bash
   adb shell setprop log.tag.ExampleApi VERBOSE
   adb shell setprop log.tag.OkHttp VERBOSE
   adb shell am force-stop com.example.app   # properties are read when the code checks them; restart to be sure
   ```

   SDKs often use the same mechanism. Firebase Analytics, for example, logs verbosely when you set `log.tag.FA` to `VERBOSE`. Third-party switches like that are documented behaviour and not a finding against the app, but first-party ones are.

6. **Optional attribution with Frida.** To map a log line back to code in an obfuscated app, hook `android.util.Log` and print the caller:

   ```javascript
   Java.perform(() => {
     const Log = Java.use('android.util.Log');
     const Ex = Java.use('java.lang.Exception');
     Log.d.overload('java.lang.String', 'java.lang.String').implementation = function (tag, msg) {
       const caller = Log.getStackTraceString(Ex.$new()).split('\n')[2].trim();
       console.log('[Log.d] ' + tag + ': ' + msg + '   <- ' + caller);
       return this.d(tag, msg);
     };
   });
   ```

#### Observation

For each exposure: the log line (tag, level, message), the call site in the APK (smali or jadx path, method), the category (endpoint, SQL, stack trace, configuration, security-check state, version), whether it appears without any switch or only after a `setprop`, and whether it is first-party or an SDK.

#### Evaluation

The test **fails** if the release build logs, or contains reachable code that logs, implementation details that are not needed to operate the app. Base the decision on what is logged, not on the mere presence of `android.util.Log`. Failing examples, matching OWASP's list for iOS:

- internal class, method or function names and code paths (`"enter PaymentFlowController.validateMerchant()"`);
- stack traces from `printStackTrace()` or `Log.e(TAG, msg, e)` for handled errors;
- API endpoints, backend routes, internal hostnames, full request URLs with parameters;
- SQL statements, query parameters, database or table names;
- feature flags, remote-config values, environment names;
- the state or outcome of security checks (`"pinning disabled for host"`, `"root check: magisk found"`, `"signature OK"`);
- library and component versions in developer-oriented messages.

It **passes** if production logging is limited to high-level operational events (`"sync failed: network unavailable"`) and first-party `Log.d`/`Log.v` calls are gone from the DEX. Messages that only an SDK emits after you set a documented debug property are noted, not failed.

#### Demo

*Ours.* A repository class that logs its query and endpoint, and an `isLoggable` gate that the attacker can open:

```kotlin
class AccountRepository(private val api: AccountApi) {
    suspend fun load(id: String): Account {
        if (Log.isLoggable(TAG, Log.DEBUG)) {
            Log.d(TAG, "GET https://api-internal.example.com/v3/accounts/$id?expand=limits")
        }
        try {
            return api.account(id)
        } catch (e: HttpException) {
            Log.e(TAG, "AccountRepository.load failed, falling back to cache (SELECT * FROM account WHERE id=?)", e)
            return cache.find(id)
        }
    }
    companion object { const val TAG = "AcctRepo" }
}
```

Illustrative session:

```text
$ adb logcat --pid=$(adb shell pidof -s com.example.app) -s AcctRepo:V
E AcctRepo: AccountRepository.load failed, falling back to cache (SELECT * FROM account WHERE id=?)
E AcctRepo: retrofit2.HttpException: HTTP 503
E AcctRepo:   at com.example.app.data.AccountRepository.load(AccountRepository.kt:14)
$ adb shell setprop log.tag.AcctRepo DEBUG
$ adb logcat ... (after restarting the app)
D AcctRepo: GET https://api-internal.example.com/v3/accounts/8812?expand=limits
```

The test fails twice: the error path logs the class, method, SQL and fallback behaviour by default, and the debug line that "only appears in debug" appears in release as soon as someone sets one system property.

### MASTG-TEST-0219: Testing for Debugging Symbols (iOS)

*OWASP test: [MASTG-TEST-0219](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0219/). Type: static. Platform: iOS. No OWASP demo; the demo below is ours.*

#### Overview

The test checks every binary in the app for debug symbols: the main executable, every framework and every app extension. OWASP's steps are [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/) (exploring the app package) and [MASTG-TECH-0113](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0113/) (obtaining debugging symbols with radare2, `objdump --syms` or `nm`). Its evaluation fails the test if "there are symbols marked as debug symbols in the output". On Apple platforms that means the STABS debug map described in [the Knowledge section](#where-dwarf-lives-on-apple-platforms-the-debug-map-and-dsym). We also check local symbols, because stripping style `debugging` removes the map but leaves every `static` function name. We ignore Objective-C and Swift runtime metadata and the `radr://5614542` strip marker.

#### Prerequisites

- The unpacked IPA (`ipa/Payload/App.app`). Decryption is not required for symbol tables.
- macOS with Xcode command-line tools (`nm`, `otool`, `dsymutil`, `xcrun swift-demangle`), or `llvm-nm` and `llvm-objdump` elsewhere. Optionally [radare2](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/) and [nm (iOS)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0041/).

#### Steps

1. List every Mach-O in the bundle:

   ```bash
   APP=$(ls -d ipa/Payload/*.app)
   find "$APP" -type f -exec sh -c 'file -b "$1" | grep -q Mach-O && echo "$1"' _ {} \; > machos.txt
   cat machos.txt
   ```

2. Check each for a debug map. `OSO` entries point to object files on the build machine. `SO` entries name source files and the compile directory. `FUN` entries name functions:

   ```bash
   while read -r b; do
     printf '%-70s stabs=%s locals=%s\n' "${b#ipa/Payload/}" \
       "$(nm -ap "$b" 2>/dev/null | grep -cE ' (SO|OSO|FUN|BNSYM|GSYM|STSYM) ')" \
       "$(nm -p "$b" 2>/dev/null | grep -cE ' [tbsd] ')"
   done < machos.txt
   ```

3. For any binary with a non-zero count, read what leaked:

   ```bash
   nm -ap "$EXE" | grep -E ' (SO|OSO) ' | head          # build paths, source file names
   nm -p "$EXE" | grep -E ' t ' | head -40 | awk '{print $3}' | xcrun swift-demangle --simplified
   ```

4. Check for a dSYM or other debug files in the package: `find "$APP" -name '*.dSYM' -o -name '*.dwarf' -o -name '*.o'`.

5. Optional, with radare2 as in OWASP's technique: `r2 -qc 'is~LOCAL' "$EXE" | head`, or `rabin2 -I "$EXE" | grep -E 'stripped|dbg_file'`.

#### Observation

For each binary: the number of debug-map entries and local symbols, sample `SO`/`OSO` paths, the most revealing local symbol names (demangled), and whether the binary is the app's own code or a vendor framework.

#### Evaluation

- **Fail** if any binary contains a debug map (`SO`, `OSO`, `FUN` and related STABS entries). It reveals build paths and every function name.
- **Fail** if the main executable or a first-party framework keeps local (`t`, `d`, `b`, `s`) symbols for first-party C, C++, Objective-C or Swift functions. That is stripping style `debugging` or no stripping. Report it with lower weight than a full debug map.
- **Fail** if a `.dSYM` or object files are in the IPA.
- **Not a finding:** exported (global) symbols of frameworks, imports (`U`), Objective-C class, selector and method names, Swift type metadata and reflection strings, and the single `OPT radr://5614542` entry left by `strip`. These are required at runtime or harmless.
- Do not recommend OWASP's "Generate Debug Symbols = No": it contradicts the test's own dSYM advice and does not strip anything (see [the Knowledge section](#xcode-settings-that-decide-what-ships)). Recommend the settings in [Best practices](#both-platforms-symbols-and-a-release-gate): keep `-g`, `dwarf-with-dsym`, strip on archive, dSYM uploaded and kept outside the app.

#### Demo

*Ours, run on macOS arm64 with Apple's toolchain. The Mach-O structure is the same on iOS.*

```c
static int check_frida_port(void) { return 0; }
int is_jailbroken(void) { return check_frida_port(); }
```

```text
$ clang -g -c app.c -o app.o && clang app.o -o App
$ nm -ap App | grep -E ' (SO|OSO|FUN) '
0000000000000000 - 00 0000    SO /Users/dev/src/ExampleApp/
0000000000000000 - 00 0000    SO app.c
000000006af39d1c - 00 0001   OSO /Users/dev/src/ExampleApp/app.o
0000000100003f30 - 01 0000   FUN _is_jailbroken
0000000100003f44 - 01 0000   FUN _check_frida_port
$ otool -l App | grep -c __DWARF
0
$ strip -S App && nm -ap App | grep -E ' (OSO|FUN) |check'
0000000100003f44 t _check_frida_port
$ strip -x App && nm -ap App
0000000100000000 T __mh_execute_header
0000000100003f30 T _is_jailbroken
0000000100003f4c T _main
                 U _printf
0000000005614542 - 00 0000   OPT radr://5614542
```

(The build path is replaced with `/Users/dev/src/ExampleApp/`.) The unstripped binary fails: it has no DWARF of its own, but its debug map names the build directory, the object file and both functions. After `strip -S` the map is gone, but the local function `_check_frida_port` remains, which still fails the second criterion. After `strip -x` only exported symbols and the strip marker remain: pass.

### MASTG-TEST-0358: Implementation Details Exposure Through Logging APIs (iOS)

*OWASP test: [MASTG-TEST-0358](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0358/). Type: static. Platform: iOS. Demo: [MASTG-DEMO-0124](https://mas.owasp.org/MASTG/demos/ios/MASVS-RESILIENCE/MASTG-DEMO-0124/MASTG-DEMO-0124/). Best practice: [MASTG-BEST-0022](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0022/).*

#### Overview

The test reverse engineers the app binary to find logging calls (`NSLog`, `print`, `debugPrint`, `dump`, `os_log`, `Logger`) and to recover what they log. OWASP is explicit that the decision rests on the arguments and the code paths, not on the presence of the APIs. Every app links `os_log` through system frameworks. Its steps use [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/) (static analysis on iOS), [MASTG-TECH-0071](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0071/) (retrieving strings) and [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/) (reviewing disassembled Objective-C and Swift code). Static analysis finds paths you would never reach at runtime. It struggles with stripped binaries, obfuscated strings and messages built at runtime. [MASTG-TEST-0359](#mastg-test-0359-implementation-details-exposure-in-logs-ios) is its dynamic counterpart.

#### Prerequisites

- A **decrypted** main binary and frameworks. String sections are in the encrypted range of App Store binaries. Use your usual decryption method on a jailbroken device, or test a release build provided by the client (Ad Hoc or the archive's `.app`).
- radare2 or another disassembler (Ghidra, Hopper, IDA). `strings` and `nm`.

#### Steps

1. Confirm which logging APIs the binary imports:

   ```bash
   nm -um "$EXE" | grep -E 'NSLog|os_log|print_9separator|debugPrint_9separator|dump_4name|Logger' | xcrun swift-demangle --simplified | sort -u
   ```

   Swift's `print` and `debugPrint` are imported as mangled names containing `print_9separator10terminator`. `Logger` calls compile down to `_os_log_impl` with `os_log_type_enabled` checks, as OWASP's demo notes.

2. Pull the candidate strings. `NSLog` and `print` literals are in `__TEXT,__cstring`. Static `Logger`/`os_log` format strings are in `__TEXT,__oslogstring`:

   ```bash
   strings -a "$EXE" | grep -E '\[(DEBUG|TRACE|VERBOSE)\]|https?://|Error code|Module:|SELECT |pinning|jailbreak|stack|\.swift' | sort -u | head -60
   r2 -qc 'iz~oslogstring' "$EXE" | head -40
   ```

   Short Swift literals (up to 15 UTF-8 bytes on 64-bit) can be encoded directly in instructions instead of `__cstring`, so `strings` misses them. The disassembly in step 3 does not.

3. Map call sites to messages. OWASP's demo uses an r2 script: list cross-references to each logging import, then disassemble from the string load (`adrp`/`add`) to the `bl` into the logging function. A minimal version:

   ```text
   e bin.relocs.apply=true
   e asm.bytes=false
   axt @@ sym.imp.*~NSLog
   axt @@ sym.imp.*~print.separator
   axt @@ sym.imp.*~_os_log_impl
   ```

   ```bash
   r2 -e bin.relocs.apply=true -q -i logs.r2 -A "$EXE" > log_xrefs.txt
   # then, per call site: r2 -qc 'pd 12 @ 0x100006864' -A "$EXE"
   ```

4. For each first-party call site, record what is logged and under which condition: always, only on error, only behind a flag. Note interpolated values that static analysis cannot resolve (`\(error)`, `Thread.callStackSymbols`) for dynamic confirmation.

#### Observation

A list of logging call sites with the function they are in, the API, the recovered message text, and the condition that reaches them.

#### Evaluation

The test **fails** if the release binary contains logging paths that emit verbose debug or error messages exposing implementation details. OWASP's examples: internal function names or code paths; detailed error information, stack-related details or diagnostic context; API endpoints, backend routes or internal URLs; internal state, configuration or feature behaviour; library, framework or component versions; developer-oriented debug messages. It **passes** when the only logging is high-level and operational, and debug statements are compiled out. A message that logs a secret or personal data is also reported under MASWE-0005 (OWASP tests MASTG-TEST-0296 and 0297).

#### Demo

OWASP's sample (abridged from [MASTG-DEMO-0124](https://mas.owasp.org/MASTG/demos/ios/MASVS-RESILIENCE/MASTG-DEMO-0124/MASTG-DEMO-0124/)):

```swift
static func mastgTest(completion: @escaping (String) -> Void) {
    NSLog("[DEBUG] Attempting to connect to API endpoint: https://internal-api.example.com/v2/auth/login")
    completion(performLogin(username: "testuser", password: "testpass"))
}

static func performNetworkRequest() {
    print("[DEBUG] - SSL pinning: disabled")
    print("[DEBUG] - Certificate validation: relaxed for staging environment")
}

static func validateCredentials(username: String, password: String) -> Bool {
    let logger = Logger(subsystem: "com.example.mastg", category: "Authentication")
    logger.debug("Checking password hash: SHA256 algorithm")
    return !username.isEmpty && !password.isEmpty
}

static func properlyGuardedLogging() {
    #if DEBUG
    print("[DEBUG] This message only appears in debug builds")   // compiled out in Release
    #endif
}
```

OWASP's r2 output for two call sites, abridged:

```text
sym.func.100006840 0x10000688c [CALL:--x] bl sym.imp.Foundation.NSLogCVarArg_...dtF_
sym.func.100004be8 0x100004d74 [CALL:--x] bl sym.imp.print.separator.terminator.St

0x100006868  add x8, x8, 0xa80  ; "[DEBUG] Attempting to connect to API endpoint: https://internal-api.example.com/v2/auth/login"
0x10000688c  bl sym.imp.Foundation.NSLogCVarArg_...dtF_

0x100004d48  add x8, x8, 0x140  ; "[DEBUG] SSL pinning: disabled"
0x100004d74  bl sym.imp.print.separator.terminator.St
```

The test fails. The binary tells the attacker the internal authentication endpoint, that pinning is off and certificate validation is relaxed (which says where to look next), the password hashing algorithm, and an internal error code with a module and method name. The `Logger.debug` call site loads its format from `__oslogstring`, which r2 does not annotate inline. You find that text with `iz` or `strings`.

### MASTG-TEST-0359: Implementation Details Exposure in Logs (iOS)

*OWASP test: [MASTG-TEST-0359](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0359/). Type: dynamic (logs). Platform: iOS. Demo: [MASTG-DEMO-0125](https://mas.owasp.org/MASTG/demos/ios/MASVS-RESILIENCE/MASTG-DEMO-0125/MASTG-DEMO-0125/). Best practice: [MASTG-BEST-0022](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0022/).*

#### Overview

The dynamic counterpart to MASTG-TEST-0358. You install the app ([MASTG-TECH-0056](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0056/)), monitor its logs ([MASTG-TECH-0060](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0060/)) while you exercise normal and error paths, and judge what is actually emitted. It confirms runtime values that static analysis cannot resolve, such as interpolated errors and stack traces, but only for the paths you trigger. OWASP flags two limitations. Mapping a log line back to code needs manual work or a hook with a backtrace ([MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/), method hooking). Coverage is never complete.

#### Prerequisites

- The release build on a device. `idevicesyslog` from the [libimobiledevice suite](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0126/), or Console.app, or `log collect` on a Mac.
- For `print`/`debugPrint`/`dump` output, which never reaches the unified log on a device: [Frida for iOS](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/) on a jailbroken device, or a build re-signed with the Frida gadget where that is allowed.
- The process name (`CFBundleExecutable`).

#### Steps

1. Launch the app **from the home screen**, not from Xcode. An attached debugger makes `<private>` values visible and changes what you see.

2. Stream the unified log for the process:

   ```bash
   idevicesyslog -p ExampleApp | tee unified.log
   ```

   On a Mac with the device connected, Console.app (select the device, enable **Include Info Messages** and **Include Debug Messages** in the Action menu) shows the same stream with levels. For a historical capture: `sudo log collect --device --last 10m --output app.logarchive`, then `log show app.logarchive --info --debug --predicate 'process == "ExampleApp"'`.

3. In parallel, capture stdout/stderr and the format strings of unified-logging calls with Frida. A compact version of OWASP's script (Frida 17 API; with Frida 16 use `Module.findExportByName(null, name)`):

   ```javascript
   const hook = (name, onEnter) => {
     const p = Module.findGlobalExportByName(name);
     if (p) Interceptor.attach(p, { onEnter }); else console.log('[missing] ' + name);
   };
   hook('NSLogv', a => console.log('[NSLog] ' + new ObjC.Object(a[0]).toString()));
   hook('_os_log_impl', a => console.log('[os_log fmt] ' + a[3].readUtf8String()));
   hook('write', a => {
     const fd = a[0].toInt32();
     if (fd === 1 || fd === 2) console.log('[fd' + fd + '] ' + a[1].readUtf8String(a[2].toInt32()));
   });
   hook('fwrite', a => console.log('[fwrite] ' + a[0].readUtf8String(a[1].toInt32() * a[2].toInt32())));
   ```

   ```bash
   frida -U -n ExampleApp -l ioslog.js -o frida.log    # or -f com.example.app to spawn
   ```

   `NSLog` in Swift goes through `NSLogv`, which is why the script hooks that. The `_os_log_impl` hook sees the format string with its `%{public}@` and `%{private}@` placeholders, not the rendered message. The rendered message, with redaction applied, is what `idevicesyslog` shows.

4. Exercise the app: launch, login and logout, every main feature, then error conditions: airplane mode during a request, invalid input, an expired session, a proxy with an untrusted certificate, and, for an R-profile app, a jailbroken device to see what the security checks log.

5. Optionally add a backtrace to a hook to locate the code: `Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n')` inside `onEnter` (use a `function` rather than an arrow function so `this` is the invocation context).

#### Observation

Both captures, with the steps that produced each message. For each relevant line: source (unified log, stdout, `os_log` format), level, and the category of detail exposed.

#### Evaluation

Same criteria as MASTG-TEST-0358, applied to what is emitted at runtime. The test **fails** if the release build emits messages that expose internal function names or code paths, detailed error or stack information, endpoints and routes, internal state or configuration, component versions, or developer-oriented debug messages. Messages that only appear on the Frida capture (`print` to stdout) are still a failure. They are compiled into the release build, and the strings are in the binary. They are less exposed than unified-log messages, and you should say so in the rating. Values that appear only as `<private>` are redacted. The static text around them still counts.

#### Demo

OWASP's capture from the same sample (abridged). The unified log via `idevicesyslog`:

```text
MASTestApp(Foundation)[2781] <Notice>: [DEBUG] Attempting to connect to API endpoint: https://internal-api.example.com/v2/auth/login
MASTestApp(MASTestApp.debug.dylib)[2781] <Debug>: Validating credentials against local database
MASTestApp(MASTestApp.debug.dylib)[2781] <Debug>: Checking password hash: SHA256 algorithm
```

The Frida capture adds what the unified log never shows:

```text
[NSLogv.format] [DEBUG] Attempting to connect to API endpoint: https://internal-api.example.com/v2/auth/login
[fwrite] [DEBUG] performLogin() called with username: testuser
[_os_log_impl.format] Checking password hash: SHA256 algorithm
[fwrite] "[DEBUG] User profile loaded from cache, bypassing network call"
```

The test fails: the internal endpoint, the authentication flow, local credential validation, the hashing algorithm and the cache behaviour are all visible. The username in the `print` line, and a session token in another line we left out, are MASWE-0005 findings. Two caveats about the demo. The `MASTestApp.debug.dylib` image name shows the capture came from a **Debug** build, which Xcode 16 splits into a debug dylib. In a Release build, the guarded `#if DEBUG` lines would be gone. The unguarded ones would remain. And the `<Debug>` lines appear because the stream was live. They would not be in a persisted log.

### GT-RES-0061-2: Debug Menus, Hidden Switches and Non-Production Configuration (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

This test covers the part of MASWE-0061 that OWASP calls most critical and does not test: debug and test code that changes the app's behaviour. That includes debug menus, environment pickers, hidden toggles, test hooks, development libraries, and switches that weaken security controls such as certificate validation, pinning, root or jailbreak detection, or client-side checks. It also covers the non-production resources from MASTG-KNOW-0064 that are configuration rather than data. The legacy iOS test MASTG-TEST-0084 had a "debug-management code" step for this (debug views, server selection, stubbed responses), which no v2 test kept. The test answers three questions for each switch: does it exist in the release build, who can flip it, and what does it unlock?

#### Prerequisites

- Decompiled Android APK (`jadx_out/`, `smali_out/`, manifest) and the unpacked, decrypted IPA.
- A test device. Root or jailbreak plus Frida to verify switches that need them. Only neutralise or flip the app's own checks on your own test device.
- An interception proxy to see which backend the app talks to after a switch. See our [lab note](/mobile/mobile-traffic-interception-lab/).

#### Steps

**Android, static:**

1. Components and deep links with debug-like names:

   ```bash
   aapt2 dump xmltree --file AndroidManifest.xml apk/base.apk | grep -iE -B2 -A2 'debug|test|staging|qa|dev(ice)?menu|internal|playground'
   adb shell dumpsys package com.example.app | grep -iE -A3 'debug|test|staging' | head -40
   ```

2. Development libraries in the release DEX:

   ```bash
   ls jadx_out/sources | head -50
   rg -l -e 'com/chuckerteam/chucker' -e 'com/facebook/flipper' -e 'com/facebook/stetho' -e 'leakcanary' -e 'com/willowtreeapps/hyperion' smali_out | cut -d/ -f2-4 | sort -u
   ```

   Chucker's `library-no-op` and LeakCanary's absence in release are the correct patterns. Real classes (`ChuckerInterceptor` that writes to a database, `LeakCanary` install code) are not.

3. Switches and environment code:

   ```bash
   rg -n -i 'staging|sandbox|uat|qa\.|dev\.|BASE_URL|setBaseUrl|Environment\.(DEV|STAGING|QA)' jadx_out/sources/com/example | head -40
   rg -n -i 'getBoolean\("(debug|dev|test|disable|bypass|skip|mock|fake)[^"]*"' jadx_out/sources | head -40
   rg -n 'checkServerTrusted|HostnameVerifier|setHostnameVerifier|CertificatePinner' jadx_out/sources/com/example | head
   ls smali_out/res/xml; rg -n -i 'debug|staging|test|cleartext' smali_out/res/xml   # apktool decodes resources too
   ```

   For each trust manager, hostname verifier or pinner, read the branch that decides whether it is used. A flag, preference or build field in that branch is the finding. A `<debug-overrides>` block in the network security configuration is not: Android applies it only when the app is debuggable.

4. `BuildConfig` and resource configuration: `rg -n 'BUILD_TYPE|FLAVOR|BASE_URL|DEBUG' jadx_out/sources/com/example/**/BuildConfig.java` and `assets/`, `res/raw/` for `config*.json`, `*staging*`, mock responses.

**Android, dynamic:**

5. Try each candidate entry point as the attacker would, from the least privileged position:

   ```bash
   adb shell am start -n com.example.app/.debug.DebugMenuActivity          # works only if exported
   adb shell am start -a android.intent.action.VIEW -d 'exampleapp://debug/menu'
   adb shell su -c 'am start -n com.example.app/.debug.DebugMenuActivity'  # root: non-exported too
   adb shell su -c 'cat /data/data/com.example.app/shared_prefs/*.xml' | grep -iE 'debug|env|staging|pinn'
   ```

6. Verify a flag found in code by flipping the app's own check on your test device, and record the effort:

   ```javascript
   Java.perform(() => {
     const Flags = Java.use('com.example.app.config.FeatureFlags');
     Flags.isDebugMenuEnabled.implementation = function () { return true; };
   });
   ```

   `frida-trace -U -f com.example.app -j 'com.example.app.*!*debug*/i'` is a quick way to find candidate methods first.

**iOS, static:**

7. Settings bundle, URL schemes and configuration:

   ```bash
   plutil -p "$APP/Settings.bundle/Root.plist" 2>/dev/null | grep -E '"(Key|Title|Type|Values)"'
   plutil -extract CFBundleURLTypes json -o - "$APP/Info.plist"
   find "$APP" \( -iname '*staging*' -o -iname '*mock*' -o -iname '*fixture*' -o -name 'GoogleService-Info*.plist' -o -name '*.xcconfig' \)
   ```

8. Debug frameworks and switch code in the binaries:

   ```bash
   ls "$APP/Frameworks"; nm -m "$EXE" | grep -iE 'FLEX|DebugMenu|Environment(Picker|Switch)' | head
   strings -a "$EXE" | grep -iE '^-?(debug|staging|uitest|mock)[A-Za-z_-]*$|disable(Pinning|SSL|Jailbreak)|useStaging|environment' | sort -u | head -40
   ```

   Look for launch-argument names (`-UITestMode`, `-useMockServer`), `UserDefaults` keys, URL paths such as `debug` or `devmenu`, and the code that reads them (`ProcessInfo.processInfo.arguments`, `UserDefaults.standard.bool(forKey:)`).

**iOS, dynamic:**

9. Flip what you can without a jailbreak first: Settings app toggles from `Settings.bundle`, URL schemes (`xcrun devicectl device process launch --device <udid> --payload-url 'exampleapp://debug' com.example.app` from a Mac, or a link in Notes or Safari), shake gestures and tap counters on the version label. Then, on a jailbroken test device, `UserDefaults` keys (edit the plist under the app's `Library/Preferences/`) and the app's own flag checks with Frida, for example `frida-trace -U -f com.example.app -m '*[* *ebug*]'` for Objective-C methods.

10. After each switch, check what changed: new screens, a different backend in the proxy, a different certificate accepted (point the proxy at the app without its CA installed), security checks that no longer fire.

#### Observation

For every switch: where it is defined (file, class, key, scheme), how it is reached (no privileges, user interaction, ADB, root/jailbreak, instrumentation), what it unlocks, and evidence (screenshot of the menu, proxy log showing the staging host or an accepted untrusted certificate).

#### Evaluation

- **Fail (vulnerability)** if a switch in the release build disables or weakens a security control (certificate validation, pinning, authentication, authorisation, encryption, root or jailbreak detection, integrity checks), or points the app at a non-production backend, and it is reachable **without** root, jailbreak or instrumentation: a Settings toggle, an exported component, a deep link, a file or preference another app can write, a remote-config value the server does not tightly control. Report it with the affected control's weakness as well, for example [MASWE-0027](/mobile/maswe-0027-insecure-certificate-validation/) or [MASWE-0028](/mobile/maswe-0028-insecure-identity-pinning/).
- **Fail (artefact)** if a debug menu, environment picker, development library or security-weakening switch exists in the release build but needs root, a jailbreak or instrumentation to reach. For an attacker on their own device it removes the work of finding and patching the control.
- **Fail (artefact)** if non-production configuration ships that the app can use (a selectable staging environment, mock responses that a flag enables).
- **Pass** if debug functionality is absent from the release binary. Strings left by a third-party SDK with no reachable code path are noted, not failed.

#### Demo

*Ours.* An Android environment switch that also turns off certificate validation, reachable through a deep link:

```kotlin
// DeepLinkActivity (exported, handles exampleapp://debug/...)
if (uri.host == "debug" && uri.getQueryParameter("env") == "staging") {
    prefs.edit().putString("env", "staging").putBoolean("trust_all", true).apply()
}

// HttpClientFactory
fun create(prefs: SharedPreferences): OkHttpClient {
    val b = OkHttpClient.Builder()
    if (prefs.getBoolean("trust_all", false)) {
        b.sslSocketFactory(trustAllContext().socketFactory, TrustAllManager)   // test leftover
         .hostnameVerifier { _, _ -> true }
    }
    return b.build()
}
```

Illustrative verification:

```text
$ rg -n 'trust_all' jadx_out/sources
com/example/app/net/HttpClientFactory.java:21:        if (prefs.getBoolean("trust_all", false)) {
com/example/app/DeepLinkActivity.java:44:            edit.putBoolean("trust_all", true);
$ adb shell am start -a android.intent.action.VIEW -d 'exampleapp://debug?env=staging'
$ adb shell su -c 'cat /data/data/com.example.app/shared_prefs/app.xml' | grep trust_all
    <boolean name="trust_all" value="true" />
proxy: CONNECT api-staging.example.com:443 accepted with the proxy's untrusted certificate
```

The test fails as a vulnerability. One link, which a web page or message can deliver, switches the app to staging and disables TLS validation for every later connection. The iOS equivalent is a `Settings.bundle` toggle:

```text
$ plutil -p Payload/ExampleApp.app/Settings.bundle/Root.plist | grep -E '"(Key|Title|Type)"'
      "Type" => "PSToggleSwitchSpecifier"
      "Title" => "Use staging API"
      "Key" => "use_staging_api"
```

## Best practices

### iOS: Disable Verbose and Debug Logging in Production Builds (MASTG-BEST-0022)

*OWASP page: [MASTG-BEST-0022](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0022/).*

OWASP's best practice has three parts, which we extend with the details that make them work.

**Keep production logs minimal.** Log only operational events that support needs: a generic authentication failure, a timeout, an unexpected state transition. Do not log request or response headers and bodies, tokens, cookies, session IDs or API keys, personal data, full error objects with `userInfo`, nested causes or stack traces, backend hostnames, staging endpoints, feature flags or internal class names, or certificate-validation and pinning behaviour.

**Use unified logging with privacy controls.** Prefer [`Logger`](https://developer.apple.com/documentation/os/logger) in Swift and `os_log` in Objective-C over `print` and `NSLog`. Leave dynamic values at their default privacy, or mark them explicitly. Use [`OSLogPrivacy`](https://developer.apple.com/documentation/os/oslogprivacy) `.private`, `.private(mask: .hash)` for correlation without the value, or `.sensitive` for values that must stay redacted even when private logging is enabled. Mark `.public` only what is safe for anyone to read. Choose levels deliberately: `debug` for developer detail (not persisted by default), `info`, `notice` (the default), `error` and `fault`. OWASP's list omits `notice`. Privacy modifiers protect values. They do not make a verbose message acceptable, because the static text is always public.

```swift
import os

let log = Logger(subsystem: "com.example.app", category: "network")

log.error("Request failed: \(error.localizedDescription, privacy: .private)")  // value redacted
log.notice("Sync finished, \(count) items")                                     // integers are public
#if DEBUG
log.debug("GET \(url.absoluteString, privacy: .public)")                       // never in Release
#endif
```

**Compile verbose diagnostics out.** Wrap `print`, `debugPrint`, `dump` and `NSLog` in `#if DEBUG`, which Xcode defines as an active compilation condition (`SWIFT_ACTIVE_COMPILATION_CONDITIONS = DEBUG`) and preprocessor macro (`GCC_PREPROCESSOR_DEFINITIONS = DEBUG=1`) in the Debug configuration only. Check the Release configuration of every target and every `.xcconfig` to make sure neither `DEBUG` nor custom flags such as `DEBUG_LOGGING` leaked into it. For Objective-C, OWASP's macro redefines `NSLog` in both branches. The release branch alone is enough:

```objectivec
#ifndef DEBUG
#define NSLog(...) do { } while (0)
#endif
```

Put it in a header that every file includes (the prefix header or a common logging header). A macro that discards its arguments also discards any side effects in them, so do not log the result of a function call that must run.

### Android: logging, StrictMode and debug code in release builds

*Ours. OWASP has no Android best practice for this weakness.*

**Install StrictMode in debug builds only:**

```kotlin
class ExampleApp : Application() {
    override fun onCreate() {
        super.onCreate()
        if (BuildConfig.DEBUG) {
            StrictMode.setThreadPolicy(StrictMode.ThreadPolicy.Builder().detectAll().penaltyLog().build())
            StrictMode.setVmPolicy(StrictMode.VmPolicy.Builder().detectAll().penaltyLog().build())
        }
    }
}
```

With AGP 8 or later, enable `buildFeatures { buildConfig = true }` or place this code in a `src/debug/` source set. Do not replace `BuildConfig.DEBUG` with a runtime `FLAG_DEBUGGABLE` check.

**Remove debug and verbose logging with R8.** With `proguard-android-optimize.txt` as the base configuration:

```text
# proguard-rules.pro (release)
-assumenosideeffects class android.util.Log {
    public static boolean isLoggable(java.lang.String, int);
    public static int v(...);
    public static int d(...);
}
```

Add `i(...)` if info-level messages are developer-oriented too. Keep `w` and `e` for operational errors, and review what they contain. Then check the result in the release APK with GT-RES-0061-1's smali grep. If you use Timber, plant `DebugTree` only in debug builds and, in release, either nothing or a tree that forwards warnings and errors to your crash reporter without stack traces of handled exceptions.

**Keep development libraries out of release:** `debugImplementation("com.squareup.leakcanary:leakcanary-android:<version>")`, Chucker's `library` for debug and `library-no-op` for release, Flipper and Stetho only in debug source sets. Set `HttpLoggingInterceptor` to `Level.NONE` in release, or do not add it.

**Keep debug screens in the debug source set.** Put debug activities and their manifest entries in `src/debug/`, so the release manifest and DEX never contain them. Remove environment pickers from release builds rather than hiding them. Pin the production base URL per build type in `buildConfigField`. Never put a security toggle (trust-all, pinning off, root check off) in code that is compiled into release.

**Strip native libraries and keep the symbols outside:**

```kotlin
android {
    buildTypes {
        release {
            isMinifyEnabled = true
            ndk { debugSymbolLevel = "FULL" }   // native-debug-symbols.zip for Play Console, not the APK
        }
    }
    // no packaging.jniLibs.keepDebugSymbols entries for release
}
```

Install the NDK on the CI machine that builds releases, and treat AGP's "unable to strip" warning as an error. For native code that implements security checks, also build with `-fvisibility=hidden` and register JNI methods with `RegisterNatives`.

### Both platforms: symbols and a release gate

**iOS build settings for Release:**

```text
// Release.xcconfig (or the target's Build Settings)
GCC_GENERATE_DEBUGGING_SYMBOLS = YES
DEBUG_INFORMATION_FORMAT = dwarf-with-dsym
STRIP_INSTALLED_PRODUCT = YES
STRIP_STYLE = all                 // non-global for framework targets
STRIP_SWIFT_SYMBOLS = YES
COPY_PHASE_STRIP = YES
SWIFT_ACTIVE_COMPILATION_CONDITIONS = $(inherited)   // no DEBUG here
```

Build distribution builds with **Product › Archive** or `xcodebuild archive`, which sets `DEPLOYMENT_POSTPROCESSING`. Upload the `.dSYM` from the archive to App Store Connect or your crash reporter, keep it in your artefact store, and never copy it into the app bundle. Since Xcode 14 removed bitcode, the stripped binary you archive is the binary that ships, apart from App Store encryption and thinning.

**A release gate in CI.** Run on the final signed artefact, fail the pipeline on any hit:

```bash
# Android
for a in out/*.apk; do unzip -oq "$a" 'lib/*' -d gate_libs; unzip -l "$a" | grep -E 'mapping\.txt|native-debug-symbols|\.dwo$' && exit 1; done
find gate_libs -name '*.so' -exec file {} + | grep -E 'not stripped|with debug_info' && exit 1
apktool d -f -o gate_smali out/app-release.apk >/dev/null
rg -q 'Landroid/os/StrictMode;->(enableDefaults|setVmPolicy|setThreadPolicy)' gate_smali/smali*/com/example && exit 1
rg -q 'Landroid/util/Log;->(v|d)\(' gate_smali/smali*/com/example && exit 1

# iOS
find build/App.app -name '*.dSYM' | grep -q . && exit 1
find build/App.app -type f -perm -111 -exec sh -c 'nm -ap "$1" 2>/dev/null | grep -qE " (OSO|SO|FUN) " && echo "$1"' _ {} \; | grep -q . && exit 1
exit 0
```

Add the strings of your known debug menus, staging hosts and debug flags to the gate as a deny-list. A code-review rule that rejects security toggles outside debug source sets catches what a gate cannot.

## Rating findings

Rate on three things: **what the artefact reveals or unlocks**, **who can reach it** (anyone with the package, anyone with ADB or a Mac and a cable, a root or jailbreak user, any web page through a link), and **the app's threat model**. Missing resilience controls are rated by the profile. Switches that weaken security controls are rated as vulnerabilities, whatever the profile.

| Rating | Conditions |
|---|---|
| **High** | A hidden switch in the release build that disables a security control (certificate validation, pinning, authentication, authorisation) or redirects the app to a non-production backend, reachable without root, jailbreak or instrumentation (Settings toggle, exported component, deep link, a file or preference another app can write). Debug code that exposes secrets on the same terms. Applies to every profile. |
| **Medium** | R-profile app: a debug menu, environment picker or security-weakening switch that needs root, a jailbreak or instrumentation to reach, where it directly enables a concrete abuse (bypassing a payment or account-creation control, unlocking paid features, switching off root or tamper checks that the server relies on). A first-party switch opened by `setprop` (ADB) that turns on detailed security-relevant logging. Verbose logs that reveal the state and logic of security controls (pinning, root, integrity) in an app that relies on them. |
| **Low** | R-profile app: unstripped first-party native libraries or Mach-O binaries (debug map, local symbols) naming security or business logic. StrictMode with `penaltyLog()` in release. Verbose logging of endpoints, SQL, class and method names, or stack traces. `print`/`NSLog` debug statements compiled into release. Development libraries in release with no exposed entry point. Debug companion files (`mapping.txt`, a `.dSYM`, `native-debug-symbols.zip`) in the package. |
| **Info** | Any of the Low items in an app whose threat model does not include R. In every profile: expected metadata (`.dynsym` JNI exports, Objective-C selectors, Swift type metadata, the `radr://5614542` marker), platform default StrictMode calls, library relax-and-restore StrictMode code, symbols in third-party SDKs that the team cannot rebuild (report to the vendor), SDK debug output that only appears after setting the SDK's documented debug property. |

Adjustments:

- **Raise a level** when the leaked names or messages locate the app's other resilience controls (anti-Frida, anti-debug, integrity checks) in an app whose business case depends on them, or when the information leads directly to a further finding, such as a reachable staging server with weaker authentication.
- **Lower a level** when the artefact is in a library that cannot be loaded or a code path that cannot be reached in release, or when the information is already public (open-source code, documented API).
- **Do not double count.** Secrets or personal data in logs are rated under MASWE-0005. The debuggable flag, `get-task-allow` and WebView debugging are rated under [MASWE-0063](/mobile/maswe-0063-debug-mechanisms-not-disabled/), as vulnerabilities in every profile. An insecure trust manager is rated under MASWE-0027. Reference the related finding here, and rate the switch that enables it here.

In the report, give the artefact's exact location (file path in the package, ABI or slice, class and method, log tag), the raw tool output that proves it (`file`, `llvm-readelf`, `nm`, logcat or `idevicesyslog` lines, Frida trace), who can reach it and with what effort, what it reveals or unlocks, and the specific build setting, R8 rule or code change that removes it.

## References

- OWASP MASWE: [MASWE-0061: Debug Artifacts Not Removed](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0061/); related [MASWE-0004](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0004/), [MASWE-0005](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0005/), [MASWE-0063](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0063/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-RESILIENCE-3](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-3/) (CC BY-SA 4.0)
- OWASP MASTG knowledge: [MASTG-KNOW-0008](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0008/), [MASTG-KNOW-0009](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0009/), [MASTG-KNOW-0063](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CODE/MASTG-KNOW-0063/), [MASTG-KNOW-0064](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CODE/MASTG-KNOW-0064/), [MASTG-KNOW-0101](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0101/) (CC BY-SA 4.0)
- OWASP MASTG tests: [MASTG-TEST-0263](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0263/), [MASTG-TEST-0264](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0264/), [MASTG-TEST-0265](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0265/), [MASTG-TEST-0288](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0288/), [MASTG-TEST-0219](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0219/), [MASTG-TEST-0358](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0358/), [MASTG-TEST-0359](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0359/); related [MASTG-TEST-0203](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0203/), [MASTG-TEST-0231](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0231/), [MASTG-TEST-0296](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0296/), [MASTG-TEST-0297](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0297/); legacy [MASTG-TEST-0040](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0040/), [MASTG-TEST-0041](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0041/), [MASTG-TEST-0083](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0083/), [MASTG-TEST-0084](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0084/) (CC BY-SA 4.0)
- OWASP MASTG demos: [MASTG-DEMO-0037](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0037/MASTG-DEMO-0037/), [MASTG-DEMO-0038](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0038/MASTG-DEMO-0038/), [MASTG-DEMO-0039](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0039/MASTG-DEMO-0039/), [MASTG-DEMO-0124](https://mas.owasp.org/MASTG/demos/ios/MASVS-RESILIENCE/MASTG-DEMO-0124/MASTG-DEMO-0124/), [MASTG-DEMO-0125](https://mas.owasp.org/MASTG/demos/ios/MASVS-RESILIENCE/MASTG-DEMO-0125/MASTG-DEMO-0125/) (CC BY-SA 4.0)
- OWASP MASTG best practice: [MASTG-BEST-0022](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0022/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0005](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/), [MASTG-TECH-0009](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0009/), [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/), [MASTG-TECH-0140](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0140/), [MASTG-TECH-0056](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0056/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0060](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0060/), [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/), [MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/), [MASTG-TECH-0113](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0113/), [MASTG-TECH-0114](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0114/), [MASTG-TECH-0071](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0071/) (CC BY-SA 4.0)
- OWASP MASTG tools: [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/), [Frida (MASTG-TOOL-0031)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/), [Frida for Android (MASTG-TOOL-0001)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0001/), [Frida for iOS (MASTG-TOOL-0039)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/), [radare2 for Android (MASTG-TOOL-0028)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0028/), [radare2 for iOS (MASTG-TOOL-0073)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/), [rabin2 (MASTG-TOOL-0129)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/), [nm for iOS (MASTG-TOOL-0041)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0041/), [libimobiledevice suite (MASTG-TOOL-0126)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0126/) (CC BY-SA 4.0)
- Android: [StrictMode](https://developer.android.com/reference/android/os/StrictMode), [StrictMode source (AOSP)](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/android/os/StrictMode.java), [Log](https://developer.android.com/reference/android/util/Log), [Logcat command-line tool](https://developer.android.com/tools/logcat), [Risks: log info disclosure](https://developer.android.com/privacy-and-security/risks/log-info-disclosure), [Include native symbols](https://developer.android.com/build/include-native-symbols), [Shrink, obfuscate and optimize your app](https://developer.android.com/build/shrink-code), [Configure build variants](https://developer.android.com/build/build-variants)
- Apple: [Building your app to include debugging information](https://developer.apple.com/documentation/xcode/building-your-app-to-include-debugging-information), [Adding identifiable symbol names to a crash report](https://developer.apple.com/documentation/xcode/adding-identifiable-symbol-names-to-a-crash-report), [Build settings reference](https://developer.apple.com/documentation/xcode/build-settings-reference), [Logging](https://developer.apple.com/documentation/os/logging), [Generating log messages from your code](https://developer.apple.com/documentation/os/generating-log-messages-from-your-code), [Logger](https://developer.apple.com/documentation/os/logger), [OSLogPrivacy](https://developer.apple.com/documentation/os/oslogprivacy), [OSLogType](https://developer.apple.com/documentation/os/oslogtype)
- Formats: [DWARF Debugging Information Format, version 5](https://dwarfstd.org/doc/DWARF5.pdf), [ELF specification (Linux Foundation reference)](https://refspecs.linuxfoundation.org/elf/elf.pdf), [Clang command-line reference (`-g`, `-gz`, `-gsplit-dwarf`)](https://clang.llvm.org/docs/ClangCommandLineReference.html)
- CWE: [CWE-489](https://cwe.mitre.org/data/definitions/489.html), [CWE-497](https://cwe.mitre.org/data/definitions/497.html), [CWE-540](https://cwe.mitre.org/data/definitions/540.html), [CWE-912](https://cwe.mitre.org/data/definitions/912.html), [CWE-1295](https://cwe.mitre.org/data/definitions/1295.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
