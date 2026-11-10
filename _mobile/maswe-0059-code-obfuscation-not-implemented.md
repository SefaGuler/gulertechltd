---
title: "MASWE-0059: Code Obfuscation Not Implemented"
date: 2026-11-10 20:08:00 +0000
subcategory: resilience
summary: "Assessing obfuscation of security-relevant code: R8 and keep rules, native and Swift binaries, Flutter and Hermes, with an effort-based rating."
refs: [MASWE-0059, MASVS-RESILIENCE-3, CWE-693]
tags: [android, ios, masvs-resilience, obfuscation, reverse-engineering, r8]
---

This note is part of our [MASVS-RESILIENCE guide](/mobile/masvs-resilience-resilience-testing-guide/) and covers OWASP [MASWE-0059](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0059/): app code, and in particular the code that makes security decisions, shipped in a form that a reverse engineer can read almost as easily as the source. Obfuscation is the most misunderstood control in mobile security. Developers switch on R8, see `a.b.c` in a stack trace and assume the job is done. Testers run jadx, see `a.b.c` and write "obfuscation present: pass". Neither has answered the question OWASP's current tests ask, which is narrower and harder: **can an attacker find, understand and neutralise the app's security-relevant logic (root detection, integrity checks, licence or entitlement logic, request signing, fraud scoring) with reasonable effort?** Below you get what R8, ProGuard, LLVM-level obfuscators, Swift and the cross-platform toolchains actually do and do not do, the three OWASP tests with their demos, one of ours for Flutter, React Native and other runtimes, an effort-based way to grade what you find, and how to rate it. Keep one thing in mind throughout: obfuscation never fixes a vulnerability. It buys time. A secret in the code is still a secret in the code ([MASWE-0004](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/)), and a client-side check without a server-side decision can always be bypassed eventually. Resources and assets are covered separately in [MASWE-0060](/mobile/maswe-0060-resource-obfuscation-not-implemented/).

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: Obfuscation (MASTG-KNOW-0033)](#android-obfuscation-mastg-know-0033)
  - [iOS: Obfuscation (MASTG-KNOW-0089)](#ios-obfuscation-mastg-know-0089)
  - [Generic: Obfuscation (MASTG-KNOW-0111)](#generic-obfuscation-mastg-know-0111)
  - [Generic: Using Disassemblers and Decompilers (MASTG-KNOW-0113)](#generic-using-disassemblers-and-decompilers-mastg-know-0113)
  - [Generic: Symbolic Execution (MASTG-KNOW-0116)](#generic-symbolic-execution-mastg-know-0116)
- [Tests](#tests)
  - [Before you start: map the security-relevant code and grade the effort](#before-you-start-map-the-security-relevant-code-and-grade-the-effort)
  - [MASTG-TEST-0368: Insufficient Obfuscation of Security-Relevant Java/Kotlin Code (Android)](#mastg-test-0368-insufficient-obfuscation-of-security-relevant-javakotlin-code-android)
  - [MASTG-TEST-0369: Insufficient Obfuscation of Security-Relevant Native Code (Android)](#mastg-test-0369-insufficient-obfuscation-of-security-relevant-native-code-android)
  - [MASTG-TEST-0391: Insufficient Obfuscation of Security-Relevant Native Code (iOS)](#mastg-test-0391-insufficient-obfuscation-of-security-relevant-native-code-ios)
  - [GT-RES-0059-1: Obfuscation of cross-platform app code (Android, iOS)](#gt-res-0059-1-obfuscation-of-cross-platform-app-code-android-ios)
- [Best practices](#best-practices)
  - [MASTG-BEST-0029: Implementing Resilience and RASP Signals](#mastg-best-0029-implementing-resilience-and-rasp-signals)
  - [Android: R8 configuration that actually protects something](#android-r8-configuration-that-actually-protects-something)
  - [Android: native libraries](#android-native-libraries)
  - [iOS: build settings and tooling](#ios-build-settings-and-tooling)
  - [Design: give the obfuscated code nothing worth stealing](#design-give-the-obfuscated-code-nothing-worth-stealing)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

OWASP states the requirement as *"The app implements code obfuscation."* MASWE-0059 maps to **MASVS-RESILIENCE-3**, *"The app implements anti-static analysis mechanisms"*, and to [CWE-693](https://cwe.mitre.org/data/definitions/693.html) (Protection Mechanism Failure). In MASVS v1 it was MSTG-RESILIENCE-9 (obfuscation applied to programmatic defences) and MSTG-RESILIENCE-12 (obfuscation sufficient against a defined threat). The weakness carries the **R** profile (and EUDIW): it only applies to apps whose threat model includes an attacker who reverse engineers the package on a device or workstation they control. Banking and payment apps, wallets, DRM and media apps, games with an economy, and apps with valuable on-device IP are the typical candidates. For an L1/L2-only assessment, record your observations as Info and move on.

OWASP's threat is MAS-THREAT-0059 and the attack is MAS-ATTACK-0001, *obtaining the app package and reverse engineering it*. That attack is free: the APK is on mirror sites, the IPA can be pulled from a device or decrypted on a jailbroken one, and jadx, Ghidra and radare2 cost nothing. Obfuscation is the only control that acts on that step, and its only effect is on **cost**: how many hours an analyst needs before they understand a piece of logic well enough to patch, hook, clone or abuse it.

The current OWASP tests (MASTG v2, 2025–2026) changed the question compared to the legacy v1 tests. MASTG-TEST-0051 and MASTG-TEST-0093 asked "has the codebase been obfuscated?" and were answered by spotting one-letter class names. MASTG-TEST-0368, 0369 and 0391 ask whether **security-relevant** logic can be *identified, correlated and reverse engineered with reasonable effort*. That is a judgement, and it needs evidence: what you searched for, how long it took, and what you could do with the result. The "Before you start" section below gives you a repeatable way to produce that evidence.

What counts as security-relevant code:

- environment checks: root, jailbreak, emulator, debugger, hooking framework and virtualisation detection ([MASWE-0051](/mobile/maswe-0051-root-jailbreak-detection-not-implemented/), [MASWE-0053](/mobile/maswe-0053-emulator-virtual-device-detection-not-implemented/), [MASWE-0064](/mobile/maswe-0064-debugger-detection-not-implemented/), [MASWE-0065](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/));
- integrity and anti-tampering: signature, installer, resource and runtime code checks ([MASWE-0057](/mobile/maswe-0057-app-resources-integrity-not-verified/), [MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/));
- attestation plumbing: where the app requests Play Integrity or App Attest tokens and what it does with the result ([MASWE-0054](/mobile/maswe-0054-device-attestation-not-implemented/), [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/));
- certificate pinning and payload encryption ([MASWE-0028](/mobile/maswe-0028-insecure-identity-pinning/), [MASWE-0062](/mobile/maswe-0062-no-application-level-payload-encryption/));
- business logic the client decides on: licence and entitlement checks, offline limits, fraud and risk scoring, anti-cheat, request signing, key derivation and white-box crypto.

Keep the neighbouring topics apart:

| Question | Where it lives |
|---|---|
| Can an attacker read and understand the app's security-relevant **code**? | This note (MASWE-0059) |
| Do strings, layouts, configuration files, models or JS bundles give the app away? | [MASWE-0060](/mobile/maswe-0060-resource-obfuscation-not-implemented/) |
| Are there secrets (API keys, private keys, passwords) in the package? | [MASWE-0004](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/). Obfuscation does not fix it |
| Are debug symbols, `mapping.txt`, logging or source maps shipped? | [MASWE-0061](/mobile/maswe-0061-debug-artifacts-not-removed/) (symbols and logs); this note covers what they do to obfuscation |
| Can a modified copy of the obfuscated code run? | [MASWE-0057](/mobile/maswe-0057-app-resources-integrity-not-verified/), [MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/) |
| Is the native code built with canaries, PIE, RELRO? | [MASWE-0045](/mobile/maswe-0045-compiler-security-features-not-used/) |

## Modes of Introduction

**No obfuscation at all.** `isMinifyEnabled = false` (or `minifyEnabled false`) in the release build type, a Bazel or custom build that never runs R8, an iOS app built without stripping, a Flutter build without `--obfuscate`. Decompiled output matches the source almost line for line, down to local variable names in Kotlin's parameter null checks.

**Renaming only, and the anchors left in place.** This is the most common state of a "protected" Android app and the one OWASP's demo 0132 shows. R8 renames the app's own classes and members, but every string literal, every call into the Android framework, every library API and every log message stays readable. An analyst does not need class names: searching for `"magisk"`, `getPackageInfo`, `/proc/self/maps` or the text of the "rooted device" dialog lands on the check in seconds.

**Keep rules that switch renaming off where it matters.** `-keep class com.example.** { *; }` copied from a Stack Overflow answer to fix a crash, `-keepnames` on the security package, `@Keep` on the detector class, `-dontobfuscate` in the app's rules or, before AGP 9.0, in a library's consumer rules (AGP 9.0 now filters global options such as `-dontobfuscate` out of library consumer rules). The result is an app where everything is obfuscated *except* the code an attacker is looking for.

**Security logic moved into native code "because it is harder".** A `librootcheck.so` with exported `Java_com_example_security_RootChecker_isRooted`, plaintext paths in `.rodata` and a single `access()` loop is easier to understand than the Java equivalent, and one `Interceptor.replace` neutralises it.

**Obfuscation that public tools undo.** String "encryption" with a static XOR key and a side-effect-free decryptor that a deobfuscator can call; control-flow flattening with a single dispatcher variable that symbolic execution simplifies; Hermes bytecode or Dart AOT snapshots treated as if compilation alone hid the logic.

**Original names shipped next to the obfuscated code.** `mapping.txt` committed to a public repository or bundled into `assets/`, `-keepattributes SourceFile` without `-renamesourcefileattribute`, Swift reflection metadata and Objective-C selectors that name every method, unstripped `.so` files, `.dSYM` contents in the IPA, JavaScript source maps.

**Third-party protection taken on trust.** A RASP or app-shielding SDK whose own package name, classes and log strings are kept (so the attacker immediately knows which product it is and which public write-up defeats it), or a commercial obfuscator configured with defaults that exclude most of the app.

## Impact

- **Fast bypass of client-side protections.** Readable detection logic tells the attacker which file paths, properties, packages, ports and libraries are probed, and where the single boolean that controls the response lives. Each of the RESILIENCE controls in this series loses most of its value if the code that implements it is legible.
- **Recovery of algorithms and business rules.** Request-signing schemes, offline licence formats, scoring thresholds and anti-cheat heuristics can be reimplemented outside the app. OWASP's example scenario for MASTG-TEST-0368 is a fintech app whose fraud-scoring thresholds are read from decompiled code, so that fraudulent transfers are crafted to stay just under them.
- **Faster discovery of real vulnerabilities.** Every other finding class (exported components, WebView bridges, weak crypto, hardcoded secrets) is found faster in readable code. Obfuscation is not a fix for any of them, but it changes how quickly an outsider finds them.
- **Intellectual property loss and clones.** Repackaged and cloned apps start from decompiled code.

## Mitigations

- **Enable the platform's optimiser on every release build** (R8 on Android, stripping and dead-code stripping on iOS, `--obfuscate` for Flutter) and verify the shipped artefact, not the build file.
- **Remove the anchors from security-relevant code**: encrypt or derive the strings it uses, avoid descriptive log and error messages, and reach framework APIs indirectly where the check is worth protecting.
- **Apply stronger transformations selectively** (string encryption, control-flow obfuscation, arithmetic and constant obfuscation, indirect calls) to the security-relevant code paths, using an open-source tool such as dProtect or O-MVLL or a commercial product.
- **Prefer lossy transformations** that remove information (inlining, merging, stripping, flattening with opaque state) over reversible ones (static XOR string tables).
- **Never ship the decoder ring**: no `mapping.txt`, symbol files, `.dSYM`, source maps or obfuscation maps in the package or in public repositories.
- **Test the result**: have someone who did not write the code try to find and neutralise the protections in the release build with current tools, and track the effort over releases.
- **Combine with runtime protections and server-side decisions** ([MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/), [MASWE-0065](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/), [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/)), because obfuscation on its own only delays an attacker.

## Knowledge

OWASP does not link Knowledge pages from weakness files, so we assign them by topic. The two platform pages, MASTG-KNOW-0033 (Android) and MASTG-KNOW-0089 (iOS), are the core of this note and get full sections. The generic pages on obfuscation (MASTG-KNOW-0111), disassemblers and decompilers (MASTG-KNOW-0113) and symbolic execution (MASTG-KNOW-0116) get summaries.

### Android: Obfuscation (MASTG-KNOW-0033)

Source: [MASTG-KNOW-0033](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0033/).

An APK carries code in three forms: DEX bytecode from Java and Kotlin (`classes*.dex`), native ELF libraries (`lib/<abi>/*.so`), and code for another runtime packaged as data (a Dart AOT snapshot in `libapp.so`, a Hermes or plain JavaScript bundle in `assets/`, .NET assemblies, Unity IL2CPP metadata). Each needs its own obfuscation story, and the weakest one decides how much the others are worth.

#### What R8 does

R8 is the Android Gradle Plugin's optimiser and has replaced ProGuard in the standard toolchain. In one pass it does three things, all documented in [Enable app optimization](https://developer.android.com/topic/performance/app-optimization/enable-app-optimization):

- **Shrinking (tree shaking).** Starting from entry points (manifest components, keep rules), R8 builds a reference graph and removes unreachable classes, methods and fields, including unused library code. This is the most effective "lossy" thing R8 does for you: debug menus, test hooks and dead feature code that never ships cannot be reverse engineered.
- **Optimisation.** Inlining, class merging, constant propagation, removal of unused arguments, devirtualisation, and (when you ask for it with `-assumenosideeffects`) removal of logging calls. Inlining and merging destroy structure an analyst would otherwise use: a small `isRooted()` method may disappear into its caller.
- **Obfuscation (renaming).** Classes, methods and fields that are not kept get short names (`a`, `b`, `a0`), and since AGP 9.1 R8 also repackages classes into the unnamed top-level package by default, the effect `-repackageclasses` used to have. Package structure, which often mirrors architecture (`com.example.security.detection`), is then gone.

How it is switched on depends on the AGP version:

```kotlin
// AGP < 9.3 (legacy DSL, still supported)
android {
    buildTypes {
        release {
            isMinifyEnabled = true          // code shrinking, optimisation, renaming
            isShrinkResources = true        // resource shrinking (see MASWE-0060)
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
}

// AGP 9.3+: new DSL; keep rules go in src/<variant>/keepRules/*.keep
android {
    buildTypes {
        release {
            optimization {
                enable = true
            }
        }
    }
}
```

Version behaviour worth knowing when you read a project's build files (from Google's version table on the same page):

| AGP | Change |
|---|---|
| 7.0 | R8 *full mode* available as opt-in (`android.enableR8.fullMode=true`) |
| 8.0 | Full mode on by default; `android.enableR8.fullMode=false` in `gradle.properties` turns it off |
| 8.12 | Optimised resource shrinking (R8 handles resources), opt-in |
| 9.0 | `getDefaultProguardFile("proguard-android.txt")` no longer supported (it contained `-dontoptimize`); global options such as `-dontobfuscate` in library consumer rules are filtered out; Kotlin null checks optimised by default |
| 9.1 | Classes repackaged by default |
| 9.3 | `optimization { enable = true }` DSL and `keepRules` source set |

**Full mode** matters for obfuscation because R8 makes stricter assumptions about reflection: it does not implicitly keep default constructors and is stricter about which attributes (generic signatures, inner-class information, annotations) survive, so more code can be renamed, merged and removed. If you find `android.enableR8.fullMode=false` in a project, ask why. It is usually a workaround for a reflection bug that a targeted keep rule would have fixed.

#### What R8 does not do

R8 is a size and speed optimiser that renames as a side effect. It does not:

- **encrypt or hide string literals.** Every `const-string` survives, including URLs, file paths, package names, error messages and log tags;
- **rename anything outside the app's own code.** Calls to `PackageManager.getPackageInfo`, `File.exists`, `Debug.isDebuggerConnected`, `Build.TAGS`, `Cipher.getInstance` or `IntegrityManagerFactory.create` keep their names because the framework and libraries define them. These calls are the analyst's best anchors;
- **change control flow to hinder analysis.** Its optimisations restructure code for speed; the result still decompiles cleanly;
- **rename kept code**: manifest components (activity, service and receiver class names referenced from `AndroidManifest.xml`), custom views referenced from layouts, `native` methods (the default rules keep their names so JNI lookup works), classes reached by reflection, Gson/Moshi models without proper annotations, enum methods used by `valueOf`, and anything matched by `-keep`, `-keepnames` or `@Keep`;
- **touch native code, resources or assets.**

That is why OWASP's demo 0132 fails even though R8 ran: names are short, but the root manager package names, the `getPackageInfo` lookups and the `finishAffinity()` call are all in clear.

#### Leaks that survive renaming

Things we look for in every R8-built app, because they hand back the names R8 removed:

- **Kotlin parameter null checks.** `Intrinsics.checkNotNullParameter(context, "context")` carries the parameter name as a string. In a renamed build it appears as `AbstractC0902k.e(context, "context")` (demo 0132). R8 can rewrite these checks; since AGP 9.0 that optimisation is on by default, so on older toolchains expect many of them.
- **Kotlin `@Metadata`.** For classes that are kept, R8 keeps the Kotlin metadata annotation, whose `d2` array lists member names. jadx shows it as a comment-like annotation above the class.
- **Enum constant names.** `enum class Threat { ROOT, FRIDA, DEBUGGER }` compiles to a static initialiser that passes `"ROOT"`, `"FRIDA"`, `"DEBUGGER"` as strings to the enum constructor. They survive renaming.
- **`toString()` of data classes** (`"RiskResult(score=…, rooted=…)"`), string templates in exceptions and log calls, `BuildConfig` constants, and analytics event names.
- **Source file attributes.** With `-keepattributes SourceFile,LineNumberTable` and without `-renamesourcefileattribute SourceFile`, jadx prints `/* compiled from: RootChecker.kt */` above renamed classes. Compare demo 0133 (unobfuscated, `compiled from: MastgTest.kt`) with demo 0132 (R8, no such line).
- **Third-party security SDKs.** Library authors ship consumer keep rules. A RASP SDK's public API, and often much more, keeps its original names.

#### `mapping.txt` and other build outputs

R8 writes `mapping.txt` (original → obfuscated names, plus line-number mapping for retracing), `seeds.txt` (what the keep rules kept), `usage.txt` (what was removed) and, with `-printconfiguration`, the merged configuration, under `app/build/outputs/mapping/<variant>/`. The mapping file belongs in the Play Console (for deobfuscated crash reports) and your crash reporter, not in the APK, not on a public CDN and not in a public Git repository. A shipped or leaked mapping file reverses renaming completely: Decompilers and IDE plugins can apply it (jadx supports loading deobfuscation mappings; check which formats your version accepts, or convert the file) and the app reads like source again. When you assess an app, check the package and any public sources for it.

The merged configuration is also the fastest way for a developer, or a tester given source access, to see which rules disable obfuscation:

```text
# proguard-rules.pro: print the effective configuration after all libraries' rules are merged
-printconfiguration build/outputs/mapping/release/configuration.txt
```

Then search `configuration.txt` for `-dontobfuscate`, `-keep class <your package>.**`, `-keepnames` and `-keepattributes SourceFile`.

#### Keep rules that defeat renaming

A keep rule is a statement that *this code must not change*. Broad rules are the main reason renaming fails in practice:

```text
# defeats renaming for the whole app package
-keep class com.example.** { *; }

# keeps the class name (and here a member), which is what OWASP's demo 0132 does
-keepnames class org.owasp.mastestapp.MastgTest
-keepclassmembers class org.owasp.mastestapp.MastgTest {
    public boolean getShouldRunInMainThread();
}

# disables renaming entirely
-dontobfuscate
```

Good rules are narrow and say *why*: keep the one model class Gson deserialises, the one method a WebView calls through `@JavascriptInterface`, the JNI methods the native library looks up by name. Google's [keep rules guide](https://developer.android.com/topic/performance/app-optimization/add-keep-rules) has the syntax and best practices.

#### String encryption, control-flow obfuscation, reflection and dynamic loading

These are the techniques R8 does not provide. OWASP names [dProtect](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0153/) (an open-source ProGuard extension from the open-obfuscator project) as a reference, alongside [ProGuard](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0022/) itself and commercial products:

- **String encryption** replaces literals with encrypted blobs and a call to a decryptor. Done well, the decryptor is different per call site or per class, keys are derived from code or state, and decrypted strings are not cached in an obvious static table. Done badly, it is one static method that takes a constant and returns a string: an analyst calls it with Frida or emulates it, and every string is back in minutes. dProtect's rule syntax:

  ```text
  -obfuscate-strings class com.example.security.EnvChecks {
      private static java.lang.String[] PATHS;
      public boolean check();
  }
  ```

- **Control-flow obfuscation** rewrites method bodies so the decompiled control-flow graph no longer resembles the source: opaque predicates (conditions whose outcome is fixed but hard to prove statically), inserted bogus branches, jumps that break decompiler patterns. jadx often falls back to "Code decompiled incorrectly" output or raw smali. dProtect: `-obfuscate-control-flow class com.example.security.** { *; }`.
- **Arithmetic and constant obfuscation** replace `x + y` or a magic constant with equivalent but opaque expressions (mixed boolean-arithmetic), hiding thresholds and algorithm constants.
- **Reflection and indirect invocation** remove direct call edges: `Class.forName(decrypt(…)).getDeclaredMethod(decrypt(…)).invoke(…)`. Combined with string encryption, framework anchors disappear from static view. At runtime the reflective calls are still visible to a tracer.
- **Dynamic loading and packing** keep code out of `classes.dex`: an encrypted DEX in `assets/` decrypted and loaded with `InMemoryDexClassLoader` or `DexClassLoader`. Static analysis sees the loader only; the payload appears in memory at runtime. If the payload is downloaded rather than shipped, it is also a [MASWE-0049](/mobile/maswe-0049-unsafe-dynamic-code-loading/) question.
- **Dead and junk code** adds methods and branches that never matter, to waste analyst time and inflate graphs.

Use [APKiD](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0009/) ([MASTG-TECH-0165](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0165/)) to fingerprint compilers, obfuscators, packers and known anti-analysis libraries. It recognises R8, DexGuard-style patterns, O-LLVM string encryption and many packers. Absence of a match does not mean absence of protection: custom schemes have no signature.

#### Native layer: stripping, visibility and JNI registration

Native code has no rename step, so what a `.so` reveals depends on build hygiene first:

- **Symbol stripping.** AGP strips debug information and the local symbol table (`.symtab`) from `.so` files it packages for release (the "strip debug symbols" task, using the NDK's `llvm-strip`). Stripping does not touch the **dynamic** symbol table (`.dynsym`), which the loader needs. Any function exported from the library keeps its name there. Debug symbols themselves are the subject of MASTG-KNOW-0008 and [MASWE-0061](/mobile/maswe-0061-debug-artifacts-not-removed/).
- **Visibility.** By default every non-static C/C++ function with external linkage is exported. Building with `-fvisibility=hidden` (CMake: `set(CMAKE_CXX_VISIBILITY_PRESET hidden)` and `set(CMAKE_C_VISIBILITY_PRESET hidden)`) or a linker version script limits exports to what you mark with `JNIEXPORT` / `__attribute__((visibility("default")))`. `-Wl,--exclude-libs,ALL` stops statically linked libraries re-exporting their symbols.
- **`Java_` exports versus `RegisterNatives`.** If the app relies on the runtime finding native methods by name, each one must be exported as `Java_<package>_<class>_<method>`, which spells out the Java class and method the function implements (`Java_org_owasp_mastestapp_MastgTest_findRootArtifactPath` in demo 0133). Registering methods explicitly with `RegisterNatives()` from `JNI_OnLoad` means only `JNI_OnLoad` needs exporting; the implementations can be hidden, static functions. Android's [JNI tips](https://developer.android.com/ndk/guides/jni-tips) recommend exactly this, with a version script or `-fvisibility=hidden`, for speed and size reasons. The obfuscation benefit is a side effect: the attacker now has to find the `JNINativeMethod` table (or trace `RegisterNatives` at runtime, see MASTG-TEST-0369) to connect Java methods to native code. Note that the method *name strings* in that table are still plaintext unless they are encrypted too.
- **libc versus syscalls.** Calls to `access`, `stat`, `fopen` and `open` are imports with names; a check that uses inline `svc` instructions for the same syscalls removes those anchors (and avoids simple libc hooks). The legacy MASTG-TEST-0051 already listed this as an indicator.

#### Native obfuscation passes (O-LLVM style)

Native obfuscators work on LLVM IR during compilation. The original academic [Obfuscator-LLVM](https://github.com/obfuscator-llvm/obfuscator) project introduced the classic passes (control-flow flattening, bogus control flow, instruction substitution) and is no longer maintained; its ideas live on in forks, commercial products and in [O-MVLL](https://obfuscator.re/omvll/), the open-source LLVM obfuscator that OWASP uses as a reference. O-MVLL is configured with a Python file whose callbacks decide, per module and function, which passes apply:

```python
import omvll

class Config(omvll.ObfuscationConfig):
    def flatten_cfg(self, mod: omvll.Module, func: omvll.Function):
        return func.name in ("check_env", "verify_signature")

    def obfuscate_string(self, _, __, string: bytes):
        if string.startswith(b"/system/") or string.startswith(b"/sbin/"):
            return omvll.StringEncOptLocal()
        return False

    def obfuscate_arithmetic(self, mod, func):
        return omvll.ArithmeticOpt(rounds=8) if func.name == "derive_key" else False
```

The passes and what they cost an analyst:

| Pass | Effect in Ghidra/r2 | What it costs the analyst |
|---|---|---|
| Control-flow flattening | One large function with a dispatcher loop and a `switch` on a state variable; the original `if`/`else` structure is gone | Recovering the state machine, by hand, by emulation or with symbolic execution |
| Bogus control flow / opaque predicates, basic-block duplication | Extra branches guarded by conditions that are always true or false | Proving which branches are dead |
| Instruction substitution / arithmetic (MBA) | `a + b` becomes a chain of `xor`, `and`, `neg`, multiplications | Simplifying expressions (tools exist, but each variant costs time) |
| String encoding | No interesting strings in `.rodata`; decoding happens in a constructor (`.init_array`) or just before use | Running the code (Frida, emulation) or writing a decoder |
| Opaque constants | Algorithm constants and thresholds no longer visible | Same as above |
| Indirect calls/branches | Call graph broken; `blr x8` instead of `bl check_env` | Runtime tracing to recover edges |

Two practical observations. String encoding that decrypts everything in `.init_array` at load time protects only against `strings`: dump the library's memory after `System.loadLibrary` and the plaintext is there. And obfuscation applied to *all* code is rare because of size and speed; good configurations target the security-relevant functions, which also means the obfuscated functions stand out. That is fine, as long as understanding them is still expensive.

#### Cross-platform runtimes

- **Flutter.** Dart code is compiled ahead of time into `lib/<abi>/libapp.so` (Android) or `App.framework/App` (iOS). Without obfuscation, the snapshot contains readable Dart library URIs, class and function names, and tools such as [blutter](https://github.com/worawit/blutter) can recover a lot of structure for supported Dart versions. `flutter build <target> --obfuscate --split-debug-info=<dir>` renames symbols in release builds; both flags are required and the symbols directory must be kept for `flutter symbolize`. Flutter's [own documentation](https://docs.flutter.dev/deployment/obfuscate) is blunt: obfuscation *"does not encrypt resources nor does it protect against reverse engineering. It only renames symbols"*, and enum names are not obfuscated. String literals are not encrypted.
- **React Native.** Release builds bundle all JavaScript into one file (`assets/index.android.bundle`, `main.jsbundle` on iOS). With Hermes, which has been React Native's default engine since 0.70, that file is Hermes bytecode compiled at build time. Hermes bytecode is a compilation format, not obfuscation: it keeps a string table and function names, and public disassemblers and decompilers exist (for example [hermes-dec](https://github.com/P1sec/hermes-dec)). Minification by Metro shortens local identifiers only. If you want obfuscation, apply a JavaScript obfuscator to the bundle before Hermes compiles it, and keep security decisions in native modules or on the server. A shipped source map (`*.map`) undoes all of it.
- **.NET MAUI / Xamarin.** Managed assemblies (in `assemblies.blob` or as `*.dll` files, depending on version) decompile back to near-source C# with ILSpy or dnSpy-style tools unless an IL obfuscator is used or the app is compiled fully AOT.
- **Unity (IL2CPP).** C# is compiled to native code in `libil2cpp.so` / the iOS binary, but `global-metadata.dat` keeps type and method names; public dumpers rebuild symbol information from it. Obfuscating the managed assemblies before IL2CPP, or protecting the metadata file, is the usual answer.

### iOS: Obfuscation (MASTG-KNOW-0089)

Source: [MASTG-KNOW-0089](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0089/).

iOS apps are native Mach-O code. There is no bytecode that decompiles back to near-source, so an iOS app without any obfuscation is still harder to read than an Android app without any. That is the reason people over-estimate it. The analyst's starting points on iOS are runtime metadata, symbols and strings, and Swift and Objective-C leave plenty of all three.

#### What a Mach-O exposes

| Source of names | Where | Survives `strip`? |
|---|---|---|
| Exported symbols | Export trie / symbol table (`nm -gU`) | Yes (needed for linking; frameworks export their API) |
| Local function symbols | Symbol table (`nm -U`) | No, removed by stripping (`STRIP_STYLE = all` for executables) |
| Objective-C classes, protocols, categories, properties, selectors, ivar names and types | `__DATA,__objc_classlist`, `__TEXT,__objc_classname`, `__TEXT,__objc_methname`, `__TEXT,__objc_methtype` | **Yes.** The runtime needs them for message dispatch, KVC, nibs and storyboards |
| Swift nominal type names (classes, structs, enums, protocols) | Type context descriptors in `__TEXT,__const`, listed in `__swift5_types` | **Yes** |
| Swift stored property and enum case names | Reflection metadata (`__swift5_fieldmd`, `__swift5_reflstr`) | Yes, unless reflection metadata is reduced at build time |
| Swift members exposed to Objective-C (`@objc`, `NSObject` subclasses) | Objective-C metadata | Yes |
| String literals | `__TEXT,__cstring`, `__TEXT,__const`, inline immediates | Yes |
| Debug information | `.dSYM` bundle (separate), never needed in the IPA | Not in the binary if built with `dwarf-with-dsym` |

Practical consequences:

- **Objective-C metadata cannot be stripped.** `rabin2 -c`, `otool -oV`, class-dump-style tools and Frida's `ObjC.classes` list every class and selector, stripped or not. A class called `JailbreakDetector` with a method `isDeviceCompromised` is a signpost no matter what `strip` did. Renaming Objective-C identifiers at source level, or with a metadata-cleaning pass (O-MVLL documents an Objective-C cleaner that is still marked as work in progress), is the only fix, and it has to preserve every name a nib, storyboard, KVC path or `NSClassFromString` call needs.
- **Swift mangling is not obfuscation.** A Swift symbol such as `$s10MASTestApp17JailbreakDetectorC12isJailbrokenSbyF` encodes module, type and member names; `xcrun swift-demangle` ([MASTG-TECH-0114](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0114/)) turns it back into `MASTestApp.JailbreakDetector.isJailbroken() -> Swift.Bool`. C++ symbols are demangled with `c++filt`.
- **Stripping still matters.** A stripped release build loses the local symbols for pure Swift and C functions (non-`@objc` methods have no names anywhere else), so the analyst has to start from type names, strings and call sites. Check `STRIP_INSTALLED_PRODUCT`, `STRIP_STYLE` and `DEPLOYMENT_POSTPROCESSING` (stripping during archive) in the project.
- **Swift reflection metadata** lists stored property names (`paths`, `isRooted`, `riskThreshold`). The Xcode build setting *Reflection Metadata Level* (`SWIFT_REFLECTION_METADATA_LEVEL`) can reduce it; this breaks `Mirror`-based code and degrades debugger output, and some frameworks (App Intents is a reported example) need the metadata, so test before you change it.
- **Swift short strings hide from `strings`.** On 64-bit platforms a Swift string literal of up to 15 UTF-8 bytes is usually materialised as two immediate 64-bit values in the instruction stream rather than stored in `__cstring`. `"/bin/bash"` or `"/etc/apt"` will not appear in `strings` output at all. Do not mistake that for string encryption: look at the disassembly, or trace at runtime.
- **App Store encryption is not obfuscation.** Binaries downloaded from the App Store are FairPlay-encrypted (`LC_ENCRYPTION_INFO_64` with `cryptid 1`), which stops static analysis of the downloaded file only. A decrypted copy is a routine step for anyone with a jailbroken device (our [MASWE-0004 note](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/) explains it). Assess the decrypted or the developer-provided binary.

#### Obfuscation options on iOS

- **Source-level renaming**: [SwiftShield](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0068/) analyses an Xcode project and replaces Swift identifiers before compilation, producing a `conversionMap.txt` for crash-log deobfuscation (keep it off the device and out of public repositories). It is no longer actively developed, so check compatibility with your Swift version. Renaming does nothing to the code itself: the disassembly of a renamed function is identical.
- **Compiler-level transformations**: O-MVLL and commercial LLVM-based obfuscators provide the passes described in the Android section (string encoding, flattening, opaque constants, indirect calls and branches, arithmetic) for C, C++, Objective-C and Swift, because they work on LLVM IR. O-MVLL's documentation notes limitations for some passes on iOS (control-flow breaking with Swift, indirect branches in Release builds), so validate the transformed release build.
- **Packing**: code signing and the absence of a JIT entitlement for third-party apps mean an iOS app cannot generate or decrypt and execute native code at runtime. Protection products therefore transform code before signing, or ship a signed interpreter or state machine and encrypt its *data* (OWASP's example is a signed loader that decrypts a `policy.vm.enc` bytecode blob). Dynamic analysis after decryption still sees the plaintext.
- **Commercial app shielding** combines these with jailbreak, debugger, hook and integrity checks. Evaluate it the way MASTG-TEST-0391 does: by the effort needed against the release build, not by the feature list.

Flutter (`App.framework/App`) and React Native (`main.jsbundle`, usually Hermes bytecode) behave on iOS as described in the Android section.

### Generic: Obfuscation (MASTG-KNOW-0111)

Source: [MASTG-KNOW-0111](https://mas.owasp.org/MASTG/knowledge/generic/MASVS-RESILIENCE/MASTG-KNOW-0111/). Summary.

Obfuscation transforms code and data so they are harder to understand, and sometimes harder to disassemble. It is not on or off: an app can be obfuscated partly or completely and to very different degrees. OWASP lists six families: name obfuscation, instruction substitution, control-flow flattening, dead code injection, string encryption and packing. Its key caveat is the one this note keeps repeating: none of these stops an attacker with enough time and budget. The aim is to make analysis expensive enough that the attacker gives up or moves to an easier target. Two points from the page are worth stressing in reports: renaming changes names but not code, so the logic is still there to be read; and packing (compress or encrypt the code, restore it at runtime) moves the problem to runtime rather than removing it.

### Generic: Using Disassemblers and Decompilers (MASTG-KNOW-0113)

Source: [MASTG-KNOW-0113](https://mas.owasp.org/MASTG/knowledge/generic/MASVS-RESILIENCE/MASTG-KNOW-0113/). Summary.

Disassemblers turn machine code into assembly (and DEX into smali); decompilers go further, to pseudo-source. Disassembly is harder than it looks (telling code from data, indirect branches, functions reached without a direct call, hand-written assembly), and decompilation is heuristic: output is approximate, depends on how much information the binary still carries, and is exactly what obfuscators target. For this weakness the tools are your measuring instruments: jadx ([MASTG-TOOL-0018](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/)) and apktool/baksmali for DEX, Ghidra and radare2 ([MASTG-TOOL-0028](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0028/), [MASTG-TOOL-0073](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/)) for ELF and Mach-O. When the decompiler gives up or produces nonsense, that is evidence of effective obfuscation, but check smali or the disassembly before you say so: decompilers also fail on perfectly ordinary code, and they sometimes produce plausible but wrong output. OWASP's own demo 0132 shows a decompiled loop with the early exit missing.

### Generic: Symbolic Execution (MASTG-KNOW-0116)

Source: [MASTG-KNOW-0116](https://mas.owasp.org/MASTG/knowledge/generic/MASVS-RESILIENCE/MASTG-KNOW-0116/). Summary.

Symbolic execution represents program inputs as symbols, collects the conditions along each path as formulas, and asks an SMT solver for inputs that reach a chosen point, for example "licence accepted". Pure symbolic execution runs into path explosion, loops and system calls; *concolic* (dynamic symbolic) execution mixes concrete runs with symbolic reasoning to stay tractable. Frameworks such as [angr](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0030/) and Triton automate it, and OWASP's [MASTG-TECH-0037](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0037/) solves an Android licence crackme this way. For obfuscation the relevance is twofold: symbolic and concolic execution are standard tools for *removing* opaque predicates, simplifying flattened control flow and even analysing VM-based protections, and a validation routine that is a pure function of its input (a licence or serial check) is exactly the shape a solver handles well. Design such checks so the decision depends on something the server holds, not only on code the attacker has.

## Tests

OWASP links three tests to MASWE-0059. They replace the legacy v1 tests **MASTG-TEST-0051** (Testing Obfuscation, Android; `covered_by` 0368 and 0369) and **MASTG-TEST-0093** (Testing Obfuscation, iOS; `covered_by` 0391). All three are static and manual: OWASP provides the steps to get the code and leaves the judgement to you, under the heading "Further Validation Required". The "Before you start" section turns that judgement into something you can defend in a report. We add one test of our own for apps whose logic lives in a cross-platform runtime, which none of the OWASP tests covers.

### Before you start: map the security-relevant code and grade the effort

*Guler Tech methodology for all tests in this note.*

1. **List the targets.** From the app's functionality and your other RESILIENCE tests, list the security-relevant logic the app should have: root/jailbreak and emulator detection, debugger and Frida detection, integrity checks, pinning, attestation calls, licence or entitlement checks, request signing, payload encryption, fraud or risk scoring. Each becomes a row in your evidence table.
2. **Find each target the way an attacker would.** Use anchors that obfuscation does not touch (or should have touched): user-visible error text, log tags, file paths and package names the check must use, framework API calls, JNI method names, Objective-C selectors, and network endpoints. Start with the cheapest method and only escalate when it fails.
3. **Time-box and record.** For each target, record how you found it, how long it took, and what it took to understand the decision (which branch, which return value, which server call). Optionally, on your own test device, confirm the understanding by neutralising **the app's own check** with a single public technique (objection's `android root disable` / `ios jailbreak disable`, or a short Frida hook that changes the return value of the app's detection method) and note the effort. Do not go further than that: the purpose is to measure the cost, not to build a bypass.
4. **Grade the result** with a simple scale. This scale is ours, not OWASP's:

| Level | What you see in the security-relevant code | Typical analyst effort to locate and understand |
|---|---|---|
| 0 | Original names, plaintext strings, readable control flow | Minutes |
| 1 | Renamed identifiers, but plaintext strings and direct framework/library calls | Minutes to an hour (string and API search) |
| 2 | Renaming plus encrypted strings and indirect calls (reflection, `RegisterNatives`, hidden exports); static anchors gone | Hours; needs runtime tracing to find the check |
| 3 | Level 2 plus control-flow and arithmetic obfuscation (or a VM-based scheme), with integrity or anti-hooking checks covering the obfuscated code | Days; needs deobfuscation tooling, emulation or symbolic execution |

For an R-profile app we expect security-relevant code at Level 2 or above, and Level 3 for apps protecting high-value logic (DRM, wallets, anti-cheat, offline payment limits). Level 0 or 1 on security-relevant code is a fail for MASTG-TEST-0368, 0369 and 0391 in an R assessment, whatever the rest of the app looks like.

### MASTG-TEST-0368: Insufficient Obfuscation of Security-Relevant Java/Kotlin Code (Android)

*OWASP test: [MASTG-TEST-0368](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0368/). Type: static, code, manual. Best practice: MASTG-BEST-0029. Knowledge: MASTG-KNOW-0033. Replaces legacy MASTG-TEST-0051 (with 0369).*

#### Overview

The test asks whether the obfuscation applied to the DEX layer stops an attacker from *identifying, correlating and reverse engineering* security-relevant Java or Kotlin logic with reasonable effort. OWASP's steps are short: reverse engineer the app ([MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), in practice decompilation with jadx per [MASTG-TECH-0017](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0017/)), review the decompiled code ([MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)) and fall back to smali ([MASTG-TECH-0016](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0016/)) where decompilation fails. The evaluation looks at three indicators: renamed identifiers, plaintext string literals that locate the logic, and control flow that is still easy to follow.

#### Prerequisites

- The release APK and all split APKs, ideally the exact build that ships.
- [jadx](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/) (CLI and GUI), [apktool](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/) for smali, [APKiD](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0009/).
- Optional, for confirmation: a rooted test device or emulator with Frida (set-up in our [mobile traffic interception lab](/mobile/mobile-traffic-interception-lab/)).

#### Steps

1. Pull the installed APKs and fingerprint them:

   ```bash
   adb shell pm path com.example.app
   # package:/data/app/~~…/com.example.app-…/base.apk
   # package:/data/app/~~…/com.example.app-…/split_config.arm64_v8a.apk
   adb pull /data/app/~~…/com.example.app-…/base.apk
   apkid base.apk
   ```

   APKiD's `compiler : r8` line tells you R8 ran; `obfuscator : unreadable field names, unreadable method names` tells you renaming is applied somewhere. Neither says anything about the security-relevant code yet.

2. Decompile, keeping output for methods jadx cannot fully decompile:

   ```bash
   jadx --show-bad-code -d out base.apk
   ```

3. Look at build hygiene: is the app's own package still there, and what is left in it? With repackaging, renamed classes move to short top-level packages (`a3/`, `h1/`), so whatever remains under the app package was kept by a rule:

   ```bash
   find out/sources/com/example -name '*.java' | sed 's|out/sources/||' | head -50
   grep -rl "compiled from:" out/sources | head        # SourceFile attribute kept?
   unzip -l base.apk | grep -iE 'mapping|proguard|\.map$|seeds|usage'   # build outputs shipped?
   ```

4. Search for anchors in the decompiled code, excluding framework and library packages. Adapt the patterns to the targets on your list:

   ```bash
   grep -rnE --include='*.java' \
     'magisk|supersu|kernelsu|/system/xbin/su|test-keys|frida|xposed|lsposed|/proc/self/maps|isDebuggerConnected|TracerPid|getInstallerPackageName|getInstallSourceInfo|signingInfo|GET_SIGNING_CERTIFICATES|IntegrityManager|StandardIntegrityManager|Cipher\.getInstance|Mac\.getInstance|CertificatePinner' \
     out/sources | grep -vE '^out/sources/(androidx|kotlin|kotlinx|com/google/android/gms|okhttp3)/'
   ```

   Also search for the user-visible text of the app's warnings (for example the "This device is not supported" dialog). jadx resolves `R.string` IDs, and the resource name or value leads straight to the calling code (see [MASWE-0060](/mobile/maswe-0060-resource-obfuscation-not-implemented/)).

5. For each hit, open the method in jadx-gui, follow callers (`x` for usages), rename as you go (`n`), and find the decision point: the boolean, the branch, the call that closes the app or reports to the server. Note the time.

6. Where decompilation fails or the code looks wrong, check the smali (`apktool d base.apk -o smali_out`) before you credit obfuscation.

7. Optional runtime confirmation on your own device. Trace what the check actually probes, for example the package lookups behind a root check:

   ```javascript
   // trace-pm.js: log package lookups made by the app (frida -U -f com.example.app -l trace-pm.js)
   Java.perform(() => {
     const PM = Java.use('android.app.ApplicationPackageManager');
     PM.getPackageInfo.overloads.forEach((o) => {
       o.implementation = function (...args) {
         console.log('[getPackageInfo] ' + args[0]);
         return o.call(this, ...args);
       };
     });
   });
   ```

   If the decision method is renamed but obvious (say `org.example.a.c()` returning a boolean), record that a one-line hook on its return value is enough to neutralise it, and how long it took you to find it.

#### Observation

The decompiled sources, and for each target on your list: where it lives (class and method, obfuscated and your renamed label), the anchor that led you there, the time to locate and understand it, whether strings were in clear, whether the control flow was readable, and, if you confirmed at runtime, what you changed and what the app did. Add the APKiD output and any build outputs found in the package.

#### Evaluation

- **Fail** if any security-relevant Java/Kotlin logic on your list can be located and understood with string or API search and ordinary reading (Level 0 or 1 in the scale above). Renamed identifiers alone do not make it pass: OWASP's demo fails with R8 active.
- **Fail** if keep rules, `SourceFile` attributes, a shipped `mapping.txt`, Kotlin metadata or similar leaks restore meaningful names to the security-relevant classes, even if the rest of the app is renamed.
- **Pass** if, for each target, static anchors are removed (strings encrypted or derived, framework calls indirect) and locating the logic required runtime tracing or significant manual work (Level 2+), with control flow that resisted straightforward reading. Say which tools and how much time you used, because "pass" in this test means "resisted this effort", not "secure".
- **Not applicable** if the app has no security-relevant client-side logic in the DEX layer (everything relevant is in native code, a cross-platform runtime, or on the server). Say where it is instead and test that.

Common false impressions: framework and library code (AndroidX, Play Services, OkHttp) is often kept or partially readable for legitimate reasons and is not the app's security logic; obfuscated-looking code in a third-party SDK says nothing about the app's own checks; and jadx failing on one method is not proof of control-flow obfuscation.

#### Demo

OWASP's [MASTG-DEMO-0132](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0132/MASTG-DEMO-0132/) is a Kotlin root check that looks for root manager packages, built with R8 (`proguard-android-optimize.txt`) and a `-keepnames` rule for the demo class:

```kotlin
class MastgTest(private val context: Context) {
    private val rootManagerPackages = listOf(
        "com.topjohnwu.magisk", "eu.chainfire.supersu", "me.weishu.kernelsu"
    )

    fun mastgTest(): String {
        val detected = rootManagerPackages.firstOrNull(::isPackageInstalled)
        if (detected != null) {
            Log.w("MASTG-DEMO-0132", "Detected root manager package '$detected'…")
            closeApp()                       // (context as? Activity)?.finishAffinity()
        }
        // …
    }

    private fun isPackageInstalled(name: String): Boolean = try {
        context.packageManager.getPackageInfo(name, 0); true
    } catch (_: PackageManager.NameNotFoundException) { false }
}
```

jadx output from the release build (shortened):

```java
public final class MastgTest {
    public final Context f7310a;          // renamed by R8
    public final List f7311b;             // renamed by R8

    public MastgTest(Context context) {
        AbstractC0902k.e(context, "context");   // Kotlin null check keeps the parameter name
        this.f7310a = context;
        this.f7311b = AbstractC0489n.I0("com.topjohnwu.magisk", "eu.chainfire.supersu", "me.weishu.kernelsu");
    }

    public final String a() {             // mastgTest(), renamed; isPackageInstalled() was inlined
        // … iterates f7311b and calls packageManager.getPackageInfo(str, …)
        String str3 = "Detected root manager package '" + str2 + "'. The app closes when root-related packages are found.";
        Log.w("MASTG-DEMO-0132", str3);
        // … activity.finishAffinity();
    }
}
```

The test fails: R8 renamed the members and inlined the helper, but the package names, the `getPackageInfo` calls, the log message and `finishAffinity()` are all in clear, so finding and understanding the check takes minutes. The class name survived because of the `-keepnames` rule, which is exactly the pattern to look for in real apps. Two details in OWASP's demo files: the build snippet enables minification on the `debug` build type rather than `release` (harmless for a demo, but check the build type in real projects), the decompiled loop no longer shows the early exit when a package is found (read literally, it would never report a match), a small reminder that decompiler output is approximate, and the decompiled log message differs from the one in the Kotlin source, so the published output was produced from an earlier revision of the sample.

### MASTG-TEST-0369: Insufficient Obfuscation of Security-Relevant Native Code (Android)

*OWASP test: [MASTG-TEST-0369](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0369/). Type: static, package, manual. Best practice: MASTG-BEST-0029. Knowledge: MASTG-KNOW-0033. Replaces legacy MASTG-TEST-0051 (with 0368).*

#### Overview

The same question for native libraries: can strings, constants, exported symbols, call structure or control flow in the app's `.so` files be used to locate and understand security-relevant logic with reasonable effort? OWASP's steps are to extract the libraries ([MASTG-TECH-0157](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0157/)), disassemble them ([MASTG-TECH-0018](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0018/)) and review the disassembly ([MASTG-TECH-0024](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0024/)). The evaluation looks at plaintext strings and constants, recognisable function structure and call edges, and descriptive JNI exports. Moving checks into native code is common; leaving them unobfuscated there often makes them *easier* to find than in Kotlin.

#### Prerequisites

- The APK and its ABI split (native libraries of App Bundle installs are in `split_config.<abi>.apk`).
- `readelf`/`llvm-readelf`, `nm`, [radare2/rabin2](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/) and Ghidra; APKiD.
- Optional: Frida on a rooted test device, for tracing `RegisterNatives` and the library's file and property probes.

#### Steps

1. Extract the libraries and identify which are the app's own (vendor SDK libraries are usually recognisable by name and strings):

   ```bash
   unzip -o base.apk 'lib/*' -d app; unzip -o split_config.arm64_v8a.apk 'lib/*' -d app
   find app/lib -name '*.so'
   apkid base.apk          # also reports O-LLVM-style string encryption and known anti-root libraries in .so files
   ```

2. Check symbols and exports per library:

   ```bash
   f=app/lib/arm64-v8a/libsecurity.so
   readelf -SW "$f" | grep -q '\.symtab' && echo "NOT stripped (.symtab present)"
   nm -D --defined-only "$f" | awk '$2 ~ /[TW]/' | wc -l      # number of exported functions
   nm -D --defined-only "$f" | grep -E ' Java_|JNI_OnLoad'     # name-based JNI exports vs RegisterNatives
   nm -D --defined-only "$f" | c++filt | grep -iE 'root|jail|integrity|tamper|debug|frida|hook|licen|sign' 
   ```

3. Look for plaintext strings and constants in data sections (`-z`) and the whole file (`-zz`):

   ```bash
   rabin2 -z "$f" | grep -iE '/su$|/sbin|/system/(x?bin)|magisk|frida|gum-js|gadget|xposed|zygisk|/proc/self/(maps|status)|TracerPid|ro\.(debuggable|secure|build\.tags)|test-keys|27042'
   ```

4. Follow the strings to code and look at the structure. In radare2:

   ```text
   $ r2 -A app/lib/arm64-v8a/libsecurity.so
   [0x…]> iz~/sbin/su          # address of the string
   [0x…]> axt @ <string addr>  # functions that reference it
   [0x…]> pdf @ <function>     # disassembly; or use Ghidra's decompiler
   [0x…]> ii~access,stat,fopen,open,syscall,__system_property_get   # imports used for probing
   ```

   To spot flattened or junk-heavy functions, sort by basic-block count: `r2 -qc 'aaa; aflj' "$f" | jq -r 'sort_by(-.nbbs) | .[:10][] | "\(.nbbs)\t\(.name)"'`. A function with hundreds of blocks around one dispatcher is a sign of flattening; check it in Ghidra's graph view.

5. Check for load-time string decoding: `readelf -SW "$f" | grep init_array` and `rabin2 -ee "$f"` list constructors. If strings are absent statically but constructors exist, dump the strings at runtime (for example with `frida` reading the library's data sections after `System.loadLibrary`) and note that the protection only works against static extraction.

6. If there are no `Java_` exports, recover the Java ↔ native mapping by tracing the app's own `RegisterNatives` calls on your test device:

   ```javascript
   // trace-registernatives.js: frida -U -f com.example.app -l trace-registernatives.js
   const art = Process.getModuleByName('libart.so');
   const sym = art.enumerateSymbols().find((s) =>
     s.name.includes('RegisterNatives') && s.name.includes('JNI') && !s.name.includes('CheckJNI'));
   Interceptor.attach(sym.address, {
     onEnter(args) {
       const table = args[2];
       const count = args[3].toInt32();
       for (let i = 0; i < count; i++) {
         const e = table.add(i * Process.pointerSize * 3);
         const name = e.readPointer().readCString();
         const sig = e.add(Process.pointerSize).readPointer().readCString();
         const fn = e.add(Process.pointerSize * 2).readPointer();
         const m = Process.findModuleByAddress(fn);
         console.log(name + sig + ' -> ' + (m ? m.name + '+' + fn.sub(m.base) : fn));
       }
     },
   });
   ```

   Readable method names in the table (`isDeviceRooted`) are themselves an anchor; obfuscated ones push the analyst back to the Java side.

7. Correlate with the DEX layer: the Java class that declares the `native` method and the code that acts on its result (MASTG-TEST-0368).

#### Observation

Per library: stripped or not, number of exports, `Java_` exports and their names, relevant plaintext strings and constants with addresses, the functions that reference them, indicators of flattening or encoded strings, the import set used for probing, and the Java ↔ native mapping. For each security-relevant target, how it was found and how long it took.

#### Evaluation

- **Fail** if monitored paths, properties, package names, tokens or integrity values are plaintext in the library, or if `Java_` exports or other symbols name the security-relevant functions, so that the logic can be located and understood with `strings`, `nm` and ordinary disassembly (Level 0–1).
- **Fail** if the native check is a small, readable function whose return value decides the outcome, even with stripped symbols, when the Java side tells the analyst exactly which native method to look at.
- **Pass** if strings and constants are not recoverable statically (or only at runtime), exports are minimal (`JNI_OnLoad` plus genuinely public API), the security-relevant functions show control-flow and data obfuscation that resists straightforward reading, and you needed runtime tracing or significant manual work to understand them.
- Note separately: a library that is **not stripped** is also a [MASWE-0061](/mobile/maswe-0061-debug-artifacts-not-removed/) observation.

False positives: Flutter's `libapp.so` and `libflutter.so`, Hermes and other engine libraries have their own story (see GT-RES-0059-1); prebuilt vendor libraries may be someone else's responsibility, but if the app's security depends on them they still count.

#### Demo

OWASP's [MASTG-DEMO-0133](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0133/MASTG-DEMO-0133/) moves a root check into `librootcheck.so` with no protection at all:

```cpp
namespace {
constexpr const char *kRootPaths[] = { "/system/bin/su", "/system/xbin/su", "/sbin/su" };
}

extern "C" JNIEXPORT jstring JNICALL
Java_org_owasp_mastestapp_MastgTest_findRootArtifactPath(JNIEnv *env, jobject) {
    for (const char *path : kRootPaths) {
        if (access(path, F_OK) == 0 || errno == EACCES) return env->NewStringUTF(path);
    }
    return nullptr;
}
```

OWASP's radare2 script and its output:

```text
$ r2 -q -i root_detection.r2 -A librootcheck.so     # script: izz~su
Strings containing "su":
16  0x000005c8 0x000005c8 14  15   .rodata             ascii   /system/bin/su
17  0x000005d7 0x000005d7 8   9    .rodata             ascii   /sbin/su
18  0x000005e0 0x000005e0 15  16   .rodata             ascii   /system/xbin/su
```

The test fails on the strings alone: they tell the attacker exactly what the library looks for. The exported symbol `Java_org_owasp_mastestapp_MastgTest_findRootArtifactPath` (visible with `nm -D`) and the unobfuscated Kotlin caller, which logs the result and calls `finishAffinity()`, complete the picture in a few minutes. A hardened version would register the method through `RegisterNatives` with a non-descriptive name, build with `-fvisibility=hidden`, encode the paths and use syscalls rather than `access()`, and flatten the function. Even then the decision ends in one return value, which is why the result should also go to the server (see [MASWE-0051](/mobile/maswe-0051-root-jailbreak-detection-not-implemented/)).

### MASTG-TEST-0391: Insufficient Obfuscation of Security-Relevant Native Code (iOS)

*OWASP test: [MASTG-TEST-0391](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0391/). Type: static, package, manual. Best practice: MASTG-BEST-0029. Knowledge: MASTG-KNOW-0089. Replaces legacy MASTG-TEST-0093.*

#### Overview

The test checks whether the main executable, embedded frameworks, app extensions and dynamic libraries let an attacker locate and understand security-relevant logic through strings, constants, symbols, Objective-C and Swift runtime metadata, call structure or control flow. OWASP's steps: explore the app package and extract the binaries ([MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/)), run static analysis ([MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/)) and review the disassembly ([MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/)), retrieve strings ([MASTG-TECH-0071](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0071/)) and demangle Swift and C++ symbols ([MASTG-TECH-0114](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0114/)). The evaluation adds a fourth indicator to the Android ones: whether protected code or data is encrypted, packed or decoded only at runtime. OWASP provides no demo for this test; the one below is ours.

#### Prerequisites

- A decrypted IPA: ideally the release build from the developer (ad hoc or enterprise-signed, same configuration as App Store), otherwise a decrypted copy from a jailbroken test device. Check: `otool -l Payload/App.app/App | grep -A4 LC_ENCRYPTION_INFO` must show `cryptid 0`.
- macOS with Xcode command-line tools (`otool`, `nm`, `xcrun swift-demangle`), radare2/rabin2, and Ghidra or Hopper (pipe Swift names through `swift-demangle` if your disassembler does not demangle them).
- Optional: a jailbroken test device with Frida for runtime confirmation.

#### Steps

1. Unpack and list every Mach-O in the bundle:

   ```bash
   unzip -q App.ipa -d ipa && cd ipa/Payload/App.app
   find . -type f -exec sh -c 'file "$1" | grep -q "Mach-O" && echo "$1"' _ {} \;
   # ./App   ./Frameworks/Security.framework/Security   ./PlugIns/Widget.appex/Widget …
   ```

2. Symbols: count local symbols (a stripped executable has few) and search the demangled names:

   ```bash
   nm -U App | wc -l
   nm -U App | xcrun swift-demangle | grep -iE 'jailbr|root|integrity|tamper|debug|frida|hook|licen|pinn|attest'
   nm -gU Frameworks/Security.framework/Security | xcrun swift-demangle | head   # framework exports are always present
   ```

3. Runtime metadata, which stripping does not remove:

   ```bash
   rabin2 -c App | grep -iE 'jailbr|security|integrity|detect|guard|shield'   # Objective-C classes
   strings - App | grep -iE '^[A-Za-z]*(Jailbr|Integrity|Detect|Guard|Tamper)[A-Za-z]*$'   # Swift type names (plain C strings)
   otool -oV App | grep -E '^\s+name 0x' | grep -iE 'jailbr|isRooted|isDebug|check'   # ObjC classes and selectors
   rabin2 -S App | grep -E 'swift5_(types|fieldmd|reflstr)'                      # Swift metadata sections present
   ```

4. Strings, remembering that Swift literals up to 15 bytes are often immediates and will not appear here:

   ```bash
   rabin2 -z App | grep -iE 'cydia|sileo|zebra|/Applications/|/bin/(ba)?sh|/usr/sbin/sshd|/etc/apt|/var/jb|/private/preboot|substrate|substitute|libhooker|ellekit|frida|27042|DYLD_INSERT'
   ```

5. Open the binary in Ghidra or r2, go from the hits (string xrefs, class names, `fileExistsAtPath:` / `access` / `stat` / `dlopen` / `sysctl` imports) to the decision point, and judge the control flow. In r2: `axt @ <string addr>`, `afl~Jailbreak`, `pdf @ <function>`.

6. Optional runtime confirmation on a jailbroken test device: trace what the app probes.

   ```bash
   frida-trace -U -f com.example.app -i 'access' -i 'stat' -i 'lstat' -i 'fopen' -i 'dlopen' \
     -m '-[NSFileManager fileExistsAtPath:]'
   ```

   This shows the paths and libraries checked, including the short Swift strings you could not see statically. To see which app function makes a call, add a backtrace (`Thread.backtrace(this.context, Backtracer.ACCURATE)` mapped through `DebugSymbol.fromAddress`) to the generated handler.

7. Repeat for each embedded framework and extension that contains security logic (commercial shielding SDKs are often a separate framework).

#### Observation

Per binary: encryption state, stripped or not, relevant symbols (demangled), Objective-C classes and selectors, Swift type and field names, relevant strings, the function(s) implementing each target and how you reached them, signs of control-flow or string obfuscation, and time spent.

#### Evaluation

- **Fail** if security-relevant logic can be located through class names, selectors, Swift type or field names, symbols or plaintext strings and understood by reading the disassembly or decompiler output (Level 0–1).
- **Fail** if the logic sits behind obfuscated code but a descriptive Objective-C or Swift API (`SecurityManager.isJailbroken`) leads straight to it.
- **Pass** if names in the security-relevant code are not descriptive, strings and constants are not recoverable statically, control flow resists reading, and you needed runtime tracing or significant manual work (Level 2+). For high-value apps, expect Level 3.
- Note separately: unstripped binaries or `.dSYM` content in the IPA ([MASWE-0061](/mobile/maswe-0061-debug-artifacts-not-removed/)), and binaries you could only analyse encrypted (state that the result is incomplete).

False impressions: few strings because Swift inlines short literals (not obfuscation); missing method names because the build is stripped (stripping, not renaming; type names are still there); a commercial framework that is obfuscated while the app calls it through a descriptive wrapper (the wrapper is the weak point).

#### Demo

*No OWASP demo exists for this test. This one is ours.* A Swift jailbreak check, release build, stripped:

```swift
final class JailbreakDetector {
    private let paths = ["/Applications/Cydia.app", "/Library/MobileSubstrate/MobileSubstrate.dylib",
                         "/bin/bash", "/usr/sbin/sshd", "/etc/apt"]

    func isJailbroken() -> Bool {
        paths.contains { FileManager.default.fileExists(atPath: $0) }
    }
}
```

Illustrative output (not from a specific engagement; addresses shortened):

```text
$ nm -U MASTestApp | xcrun swift-demangle | grep -i jailbreak
(no output: stripped, the method name is gone)

$ strings - MASTestApp | grep -x JailbreakDetector
JailbreakDetector                                     # Swift type descriptor name survives stripping

$ strings - MASTestApp | grep -E 'Cydia|Substrate|bash|sshd|/etc/apt'
/Applications/Cydia.app
/Library/MobileSubstrate/MobileSubstrate.dylib
                                                      # /bin/bash, /usr/sbin/sshd, /etc/apt: ≤15 bytes, inline immediates
$ strings - MASTestApp | grep -x paths
paths                                                 # stored property name from Swift reflection metadata
```

Fail. The type name `JailbreakDetector`, the property name `paths` and the two long paths locate the check immediately; following the xrefs from `/Applications/Cydia.app` lands in the function that builds the array, and the caller of `fileExistsAtPath:` is the check. The short paths are hidden from `strings` only by accident of the Swift string ABI, which `frida-trace` reveals in seconds.

### GT-RES-0059-1: Obfuscation of cross-platform app code (Android, iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

None of the OWASP tests covers logic that lives in a Dart AOT snapshot, a JavaScript or Hermes bundle, .NET assemblies or Unity metadata, yet for many apps that is where all the business and security logic is. Running MASTG-TEST-0368 on a Flutter app finds a small Java shell and passes it; the real code is in `libapp.so`. This test applies the same question to the runtime that actually holds the logic.

#### Prerequisites

The APK/IPA; `strings`, `xxd`, `unzip`; framework-specific tools where you need them (for example blutter for Flutter, hermes-dec for Hermes bytecode, ILSpy for .NET, an IL2CPP metadata dumper for Unity).

#### Steps

1. Identify the runtime:

   ```bash
   unzip -l base.apk | grep -E 'libapp\.so|libflutter\.so|libhermes|index\.android\.bundle|libmonodroid|assemblies|libil2cpp\.so|global-metadata\.dat|assets/www/|assets/public/'
   # iOS: Frameworks/App.framework (Flutter), main.jsbundle (React Native), Data/Managed/Metadata/global-metadata.dat (Unity)
   ```

2. **Flutter.** Check whether the build was obfuscated and what is still readable:

   ```bash
   strings -n 8 lib/arm64-v8a/libapp.so | grep -E '^package:' | head          # app library URIs
   strings -n 6 lib/arm64-v8a/libapp.so | grep -iE 'jailbr|rooted|frida|emulator|integrity|licen' | head
   ```

   Readable app class and function names (for example `RootDetectionService`, `_checkSuPaths`) mean the build lacks `--obfuscate`. With obfuscation, look at what is still there: string literals and enum names are not obfuscated by Flutter.

3. **React Native.** Determine the bundle format and search it:

   ```bash
   xxd -l 8 assets/index.android.bundle
   # c6 1f bc 03 c1 03 19 1f  → Hermes bytecode; otherwise plain (minified) JavaScript
   strings -n 6 assets/index.android.bundle | grep -iE 'jailbr|isRooted|JailMonkey|frida|emulator|sslPinning|signature'
   unzip -l base.apk | grep -E '\.map$'                                        # shipped source maps
   ```

   For plain JS, pretty-print it and read; for Hermes, a disassembler recovers function names and the string table.

4. **.NET / Unity.** Check whether managed assemblies or IL2CPP metadata expose type and method names of security-relevant classes.

5. Grade each security-relevant target with the scale above and, if needed, confirm at runtime as in the OWASP tests (the native side of a Flutter or React Native plugin is often where root or jailbreak detection actually runs).

#### Observation

Runtime and bundle format, whether the framework's obfuscation option was used, readable identifiers and strings for each target, any maps or symbol files shipped, and effort to locate and understand the logic.

#### Evaluation

- **Fail** if security-relevant logic in the runtime's code can be located and understood from readable identifiers or strings (Flutter without `--obfuscate`; React Native with plain or Hermes bytecode and descriptive names; .NET assemblies without obfuscation; IL2CPP metadata naming the security classes).
- **Fail** if source maps, Flutter symbol files or obfuscation maps are shipped.
- **Pass** only if identifiers are obfuscated *and* security-relevant strings are not in clear *and* the logic required runtime work to understand, or if the security decisions are demonstrably not made in this layer (for example a native plugin with its own protections plus a server-side decision).

#### Demo

Illustrative output for a Flutter release build without `--obfuscate`:

```text
$ strings -n 8 lib/arm64-v8a/libapp.so | grep -E '^package:app/'
package:app/security/root_detection_service.dart
package:app/payments/transfer_limits.dart
$ strings -n 6 lib/arm64-v8a/libapp.so | grep -E 'RootDetectionService|_isRooted|dailyTransferLimit'
RootDetectionService
_isRooted
dailyTransferLimit
```

Rebuilt with `flutter build apk --obfuscate --split-debug-info=build/symbols`, the class and function names are gone, but the `su` paths the service checks and the user-facing "rooted device" message are still plaintext strings. That build moves from Level 0 to Level 1, and still fails.

## Best practices

### MASTG-BEST-0029: Implementing Resilience and RASP Signals

Source: [MASTG-BEST-0029](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0029/). OWASP's page is a placeholder; its only content is a note that resilience controls and RASP-style checks are defence-in-depth measures that raise attacker cost, do not replace secure design, are inherently bypassable, and should be chosen and tuned to the app's threat model and risk tolerance. Our hub summarises it for the whole series. For obfuscation that means: decide which code is worth protecting, protect that code properly, and make sure that what it decides is also checked where the attacker cannot reach (the server). The sections below are our own guidance.

### Android: R8 configuration that actually protects something

- Release build type with optimisation on (`isMinifyEnabled = true`, or `optimization { enable = true }` on AGP 9.3+), `proguard-android-optimize.txt` (the only default file AGP 9 accepts), full mode left on, no `-dontobfuscate` anywhere in the merged configuration.
- Narrow keep rules, reviewed with `-printconfiguration` and, on AGP 9.3 and later, Google's R8 Configuration Analyzer. Nothing in the security package is kept unless something outside R8's view needs it, and then only that member.
- No `-keepattributes SourceFile` without `-renamesourcefileattribute SourceFile`; keep `LineNumberTable` only if you need it for crash retracing.
- Remove logging and descriptive messages from release builds, for example with `-assumenosideeffects` on `android.util.Log` (and your own logging wrapper), and keep user-facing messages generic ("This action is not available") rather than "Root detected".
- `mapping.txt` uploaded to Play Console and the crash reporter from CI, never committed or bundled.
- For security-relevant code, add string encryption and control-flow obfuscation (dProtect or a commercial obfuscator), restricted to the classes that need it so performance stays acceptable, and verify the output with jadx after every toolchain upgrade.

### Android: native libraries

```cmake
# CMakeLists.txt
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)
target_link_options(security PRIVATE "-Wl,--exclude-libs,ALL")
```

Register native methods with `RegisterNatives` from `JNI_OnLoad` and export nothing else. Let AGP strip the libraries (do not add them to `keepDebugSymbols`), upload native debug symbols to Play separately, and apply an LLVM-level obfuscator (O-MVLL or commercial) to the functions that implement checks or handle keys. Prefer syscalls over libc wrappers in detection code and do not leave the decision in a single exported boolean.

### iOS: build settings and tooling

- Release configuration: `DEBUG_INFORMATION_FORMAT = dwarf-with-dsym`, `STRIP_INSTALLED_PRODUCT = YES`, `STRIP_STYLE = all` for the app executable (`non-global` for frameworks), `DEAD_CODE_STRIPPING = YES`, `GCC_SYMBOLS_PRIVATE_EXTERN = YES` for C and Objective-C code. Keep `.dSYM` files for symbolication, out of the IPA.
- Avoid descriptive Objective-C names for security classes and selectors, and avoid `@objc` on Swift security code unless needed: everything visible to the Objective-C runtime keeps its name.
- Consider reducing Swift reflection metadata for release builds (`SWIFT_REFLECTION_METADATA_LEVEL`) after testing what depends on it.
- Use an LLVM-level obfuscator for string encoding and control-flow obfuscation of security-relevant functions; source-level renaming alone does not change the code.
- Flutter: always `--obfuscate --split-debug-info=<dir>`, keep the symbols in CI. React Native: keep security decisions out of JavaScript, never ship source maps, and consider a JavaScript obfuscator before Hermes compilation.

### Design: give the obfuscated code nothing worth stealing

Obfuscation protects logic, not secrets. If the client holds a static API secret, signing key or licence algorithm that grants something on its own, the fix is to move it ([MASWE-0004](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/), the [CRYPTO hub](/mobile/masvs-crypto-cryptography-guide/)): hardware-backed per-device keys, server-side licence and entitlement decisions, attestation verified on the server ([MASWE-0054](/mobile/maswe-0054-device-attestation-not-implemented/), [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/)). Detection checks should report signals to the server rather than only taking local action, so that a bypassed check still leaves a trace. Then obfuscate what remains to raise the cost of the bypass.

## Rating findings

The series-wide rules apply, adapted to obfuscation:

- **App without the R profile** in its threat model (no reverse-engineering or tampering threat): missing or weak obfuscation is **Info**. Record the level you observed and recommend R8/stripping for size and hygiene.
- **R-profile app**, missing or ineffective obfuscation of security-relevant code (Level 0–1): usually **Low**, **Medium** when the readable logic guards a concrete business control that the client decides on its own.
- **Medium–High** only when the readable code directly enables a concrete, demonstrated abuse: for example a request-signing scheme recovered from readable code lets bots forge calls the backend accepts, or an offline licence algorithm can be reimplemented as a key generator. In that case the root cause is the design (a client-side secret or decision); rate and report it under that weakness ([MASWE-0004](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/), the relevant CRYPTO or AUTH weakness) and cite the lack of obfuscation as a contributing factor.
- **A protection that exists but is trivially bypassed** (one Frida hook, one renamed method) is rated by what the bypass unlocks, not by the existence of the protection.

| Rating | Typical conditions |
|---|---|
| **Info** | Non-R app; R app where all security decisions are server-side and the client code only collects signals; obfuscation level observations for the record; absence of a commercial obfuscator as such |
| **Low** | R app; security-relevant checks at Level 0–1 whose bypass unlocks little that the server does not also control; `-keepnames`/`SourceFile` leaks; Flutter without `--obfuscate` where the logic is low value |
| **Medium** | R app; readable client-side logic that alone decides a business control (entitlement, offline limits, anti-cheat, fraud thresholds as in OWASP's scenario); `mapping.txt`, source maps or Flutter symbols shipped or publicly available for an R app; security logic in an unobfuscated native library with descriptive exports and plaintext indicators that is the app's main protection |
| **Medium–High** | Readable logic that directly enables demonstrated abuse (forged signed requests, key generator, recovered thresholds used to evade fraud controls), with no server-side compensating control |

Debug mechanisms left on in a release build (`android:debuggable`, `get-task-allow`, WebView debugging) are real vulnerabilities regardless of profile; they are covered in [MASWE-0063](/mobile/maswe-0063-debug-mechanisms-not-disabled/) and should not be folded into an obfuscation finding. In the report, give the level per target, the anchor that found it, the time taken, the specific build setting or rule responsible (`-keepnames`, missing `--obfuscate`, `Java_` exports), and the concrete fix.

## References

- OWASP MASWE: [MASWE-0059: Code Obfuscation Not Implemented](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0059/); related [MASWE-0060](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0060/), [MASWE-0057](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0057/), [MASWE-0058](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0058/), [MASWE-0065](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0065/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-RESILIENCE-3](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-3/) (CC BY-SA 4.0)
- OWASP MASTG knowledge: [MASTG-KNOW-0033](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0033/), [MASTG-KNOW-0089](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0089/), [MASTG-KNOW-0111](https://mas.owasp.org/MASTG/knowledge/generic/MASVS-RESILIENCE/MASTG-KNOW-0111/), [MASTG-KNOW-0113](https://mas.owasp.org/MASTG/knowledge/generic/MASVS-RESILIENCE/MASTG-KNOW-0113/), [MASTG-KNOW-0116](https://mas.owasp.org/MASTG/knowledge/generic/MASVS-RESILIENCE/MASTG-KNOW-0116/) (CC BY-SA 4.0)
- OWASP MASTG tests: [MASTG-TEST-0368](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0368/), [MASTG-TEST-0369](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0369/), [MASTG-TEST-0391](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0391/); legacy [MASTG-TEST-0051](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0051/), [MASTG-TEST-0093](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0093/) (CC BY-SA 4.0)
- OWASP MASTG demos: [MASTG-DEMO-0132](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0132/MASTG-DEMO-0132/), [MASTG-DEMO-0133](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0133/MASTG-DEMO-0133/) (CC BY-SA 4.0)
- OWASP MASTG best practices: [MASTG-BEST-0029](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0029/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0016](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0016/), [MASTG-TECH-0017](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0017/), [MASTG-TECH-0018](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0018/), [MASTG-TECH-0023](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/), [MASTG-TECH-0024](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0024/), [MASTG-TECH-0037](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0037/), [MASTG-TECH-0157](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0157/), [MASTG-TECH-0165](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0165/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/), [MASTG-TECH-0114](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0114/), [MASTG-TECH-0071](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0071/) (CC BY-SA 4.0)
- OWASP MASTG tools: [APKiD (MASTG-TOOL-0009)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0009/), [Apktool (MASTG-TOOL-0011)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/), [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [ProGuard (MASTG-TOOL-0022)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0022/), [radare2 for Android (MASTG-TOOL-0028)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0028/), [angr (MASTG-TOOL-0030)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0030/), [dProtect (MASTG-TOOL-0153)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0153/), [swift-demangle (MASTG-TOOL-0067)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0067/), [SwiftShield (MASTG-TOOL-0068)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0068/), [radare2 for iOS (MASTG-TOOL-0073)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/), [rabin2 (MASTG-TOOL-0129)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/) (CC BY-SA 4.0)
- Android: [Enable app optimization (R8, AGP version table)](https://developer.android.com/topic/performance/app-optimization/enable-app-optimization), [Add keep rules](https://developer.android.com/topic/performance/app-optimization/add-keep-rules), [R8 full mode](https://developer.android.com/topic/performance/app-optimization/full-mode), [Global options](https://developer.android.com/topic/performance/app-optimization/global-options), [JNI tips (RegisterNatives, symbol visibility)](https://developer.android.com/ndk/guides/jni-tips), [Symbol visibility](https://developer.android.com/ndk/guides/symbol-visibility)
- Apple: [Build settings reference](https://developer.apple.com/documentation/xcode/build-settings-reference), [Objective-C runtime](https://developer.apple.com/documentation/objectivec/objective-c_runtime)
- Flutter: [Obfuscating Dart code](https://docs.flutter.dev/deployment/obfuscate); React Native: [Using Hermes](https://reactnative.dev/docs/hermes)
- Obfuscators and analysis tools: [O-MVLL](https://obfuscator.re/omvll/), [dProtect](https://obfuscator.re/dprotect/), [Obfuscator-LLVM](https://github.com/obfuscator-llvm/obfuscator), [hermes-dec](https://github.com/P1sec/hermes-dec), [blutter](https://github.com/worawit/blutter); background: ["Protecting Million-User iOS Apps with Obfuscation"](https://faculty.ist.psu.edu/wu/papers/obf-ii.pdf)
- CWE: [CWE-693](https://cwe.mitre.org/data/definitions/693.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
