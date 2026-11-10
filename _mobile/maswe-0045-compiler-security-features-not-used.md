---
title: "MASWE-0045: Compiler-Provided Security Features Not Used"
date: 2026-11-10 10:04:00 +0000
subcategory: code
summary: "Verifying PIE, stack canaries, RELRO, NX, FORTIFY and ARC in Android .so and iOS Mach-O binaries, with false positives and severity guidance."
refs: [MASWE-0045, MASVS-CODE-3, MASVS-CODE-4]
tags: [android, ios, masvs-code, native-code, binary-hardening, ndk]
---

This note is part of our [MASVS-CODE guide](/mobile/masvs-code-code-quality-guide/) and covers OWASP [MASWE-0045](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0045/): native code that ships without the exploit mitigations its compiler and linker can add for free. Stack canaries, position-independent executables, read-only relocations, a non-executable stack, fortified libc calls and, on iOS, Automatic Reference Counting do not fix a single bug. What they do is turn many memory-corruption bugs from "reliable code execution" into "crash", and that difference is what an attacker pays for. The checks are static, quick and objective, which makes them some of the easiest findings in a mobile report to prove, and some of the easiest to over-rate. Most of the work is in telling a real gap from the usual false positives: libraries with no stack buffers, Dart, Go and Rust code, Swift, dylibs that "lack PIE" by design, and symbol heuristics that OWASP itself gets wrong in places. Below you get the mechanisms per platform, a script that sweeps every native binary in an APK or IPA, the five OWASP tests plus one of ours for RELRO, NX and FORTIFY on Android, the build settings that fix each gap, and how to rate what you find. Memory-corruption bugs themselves are covered in our [MASTG-KNOW-0005 note](/mobile/mastg-know-0005-memory-corruption-bugs/). Outdated native libraries with known CVEs are covered in [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/).

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: Binary Protection Mechanisms (MASTG-KNOW-0006)](#android-binary-protection-mechanisms-mastg-know-0006)
  - [iOS: Binary Protection Mechanisms (MASTG-KNOW-0061)](#ios-binary-protection-mechanisms-mastg-know-0061)
  - [Android: Memory Corruption Bugs (MASTG-KNOW-0005)](#android-memory-corruption-bugs-mastg-know-0005)
  - [iOS: Memory Corruption Bugs (MASTG-KNOW-0060)](#ios-memory-corruption-bugs-mastg-know-0060)
- [Tests](#tests)
  - [Before you start: sweep every native binary in the package](#before-you-start-sweep-every-native-binary-in-the-package)
  - [MASTG-TEST-0222: Position Independent Code (PIC) Not Enabled (Android)](#mastg-test-0222-position-independent-code-pic-not-enabled-android)
  - [MASTG-TEST-0223: Stack Canaries Not Enabled (Android)](#mastg-test-0223-stack-canaries-not-enabled-android)
  - [GT-CODE-0045-1: RELRO, non-executable stack and FORTIFY in native libraries (Android)](#gt-code-0045-1-relro-non-executable-stack-and-fortify-in-native-libraries-android)
  - [MASTG-TEST-0228: Position Independent Code (PIC) Not Enabled (iOS)](#mastg-test-0228-position-independent-code-pic-not-enabled-ios)
  - [MASTG-TEST-0229: Stack Canaries Not Enabled (iOS)](#mastg-test-0229-stack-canaries-not-enabled-ios)
  - [MASTG-TEST-0230: Automatic Reference Counting (ARC) Not Enabled (iOS)](#mastg-test-0230-automatic-reference-counting-arc-not-enabled-ios)
- [Secure implementation](#secure-implementation)
  - [Android: NDK, CMake and ndk-build](#android-ndk-cmake-and-ndk-build)
  - [iOS: Xcode build settings](#ios-xcode-build-settings)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

MASWE-0045 applies when an app's native code (C, C++, Objective-C, and the native libraries of third-party SDKs) is built without the mitigations that the toolchain offers. The OWASP requirement is *"The app uses the compiler-provided security features of the platform."* It maps to MASVS-CODE-3 ("The app only uses software components without known vulnerabilities") and MASVS-CODE-4 ("The app validates and sanitizes all untrusted inputs"). The second mapping is the one that explains the weakness: mitigations matter exactly where native code handles input an attacker controls. OWASP gives no CWE. The closest fit is [CWE-693](https://cwe.mitre.org/data/definitions/693.html) (Protection Mechanism Failure), and you can use it in a report if your template needs one. Android's own risk catalogue covers the topic in [Use of native code](https://developer.android.com/privacy-and-security/risks/use-of-native-code).

The weakness is tagged for the **L2** and **EUDIW** profiles only, not L1. In an L1-only assessment it is out of scope, although the sweep below takes five minutes and the results often belong in an appendix anyway. The legacy v1 tests (MASTG-TEST-0044 and MASTG-TEST-0087) were L1 and L2. That changed in v2.

OWASP describes the threat as MAS-THREAT-0045, *"Attackers can exploit memory-corruption bugs with substantially less effort"*, reached through two attacks:

| Attack | Description | Role here |
|---|---|---|
| MAS-ATTACK-0001 | Obtaining the app package and reverse engineering it | How the attacker learns which mitigations are missing and finds the bug to use them on |
| MAS-ATTACK-0059 | Supplying crafted input through any external interface (network, IPC, files, UI, or peripherals) | How the bug is triggered: a malicious server or network position, a crafted file or link, another app on the device |

The order matters for rating. A missing canary is not exploitable on its own. It lowers the cost of exploiting a memory-corruption bug that someone has to find first, in code that crafted input can reach. Rate the gap by what the affected binary does, not by the flag.

Keep the neighbouring topics apart:

| Question | Where it lives |
|---|---|
| Was the native code built with canaries, PIE, RELRO, NX, FORTIFY, ARC? | This note (MASWE-0045) |
| Does the native code contain memory-corruption bugs, and can untrusted input reach them? | [MASTG-KNOW-0005 note](/mobile/mastg-know-0005-memory-corruption-bugs/) (Android), the iOS summary below, and [MASWE-0050](/mobile/maswe-0050-unsafe-handling-of-untrusted-data/) for input handling |
| Is a bundled native library (OpenSSL, libpng, SQLite, a media SDK) a version with known CVEs? | [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/) |
| Are debug symbols, logging or debuggable flags left in the release build? | MASVS-RESILIENCE ([MASWE-0061](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0061/) Debug Artifacts Not Removed, [MASWE-0063](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0063/) Debug Mechanisms Not Disabled), not this note |

## Modes of Introduction

**Third-party build systems and prebuilt SDKs.** The NDK's CMake toolchain and ndk-build add stack protection and FORTIFY by default. A library built with autotools, Bazel, a hand-written Makefile or an SDK vendor's own toolchain gets only what that build passes. Most real gaps we find are in prebuilt `.so` files and XCFrameworks from vendors, not in the app team's own JNI code.

**Flags removed for size or speed.** `-fno-stack-protector`, `-U_FORTIFY_SOURCE`, `-Wl,-z,lazy` or `-Wl,-z,norelro` added to shave bytes or startup time, often in a game engine or codec build.

**Old toolchains and old code.** GCC-era NDK builds (GCC left the NDK in r18), GNU `ld` instead of LLD, 32-bit ARM objects built without `-fPIC` that produce text relocations, Objective-C files from before ARC, CocoaPods with `requires_arc = false`.

**Per-file opt-outs.** `-fno-objc-arc` on individual files in Xcode's Compile Sources phase, `#pragma` or attribute-level `no_stack_protector`, assembly files without a `.note.GNU-stack` section, which can make the whole library's stack executable when linked with GNU `ld`.

**Executables shipped as "libraries".** Apps that need to run a command-line tool (an ffmpeg build, a VPN helper, a proxy) ship it as `lib/<abi>/libsomething.so`, because since Android 10 apps targeting API 29 or higher cannot `exec()` files in their writable home directory. These are real executables, and PIE does apply to them.

**Unsafe memory management choices.** Objective-C compiled with manual retain/release (MRR) where ARC was available. C/C++ for parsers and protocol code where a memory-safe language was an option.

## Impact

- **Easier code execution from memory-corruption bugs.** Without a canary a linear stack overflow overwrites the saved return address undetected. Without PIE a fixed-address executable gives the attacker known gadget addresses. Without full RELRO the GOT stays writable after start-up and is a classic overwrite target. With an executable stack, injected bytes on the stack can run directly.
- **Exposure of data in memory.** An exploited native bug runs with the app's identity. It can read tokens, keys held in process memory, and anything the app's sandbox can read.
- **Reduced value of other defences.** Mitigations are layers. Each missing one removes a step the attacker would otherwise have to defeat with an extra information leak or a second bug.

## Mitigations

- **Build all native code with the toolchain defaults intact**: stack protector (`-fstack-protector-strong`), PIE for executables and PIC for libraries, full RELRO (`-Wl,-z,relro,-z,now`), a non-executable stack, and `-D_FORTIFY_SOURCE=2` on Android.
- **Verify the release binaries, not the build files.** Run the sweep below on the APK or IPA you ship, including every third-party `.so`, framework and app extension. Make it a CI step.
- **Ask vendors for evidence.** For prebuilt SDK binaries, require the build flags or a hardening report as part of procurement, and re-check on every SDK update.
- **Keep ARC on** for all Objective-C (`CLANG_ENABLE_OBJC_ARC = YES`) and remove per-file `-fno-objc-arc` exceptions.
- **Prefer memory-safe languages** (Kotlin, Java, Swift, Rust) for new code that parses untrusted input, and use the newer platform mitigations (MTE on Android, Enhanced Security on iOS) where your threat model justifies them.

## Knowledge

OWASP links two Knowledge pages to this weakness: MASTG-KNOW-0006 (Android) and MASTG-KNOW-0061 (iOS), both titled "Binary Protection Mechanisms". They are short, so the sections below go well beyond them. The two "Memory Corruption Bugs" pages, MASTG-KNOW-0005 and MASTG-KNOW-0060, explain why these mitigations matter and get a summary each.

### Android: Binary Protection Mechanisms (MASTG-KNOW-0006)

Source: [MASTG-KNOW-0006](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0006/).

#### What gets compiled, and what you can actually check

An APK contains two kinds of code:

- **DEX bytecode** (`classes*.dex`) from Java and Kotlin. ART compiles it to native code on the device (OAT/ODEX files under `/data/app/.../oat/` or in the dalvik-cache), with the platform's own toolchain and settings. Those files are not in the APK, the app developer does not control how they are built, and there is nothing in this weakness to test on them. Managed code is memory-safe by design (bounds-checked arrays, no pointer arithmetic, garbage collection), so canaries and fortified libc calls do not apply to it.
- **Native libraries** in `lib/<abi>/*.so` (ABIs `arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`). These are ELF shared objects built by the developer or a vendor with the NDK or another toolchain, loaded with `System.loadLibrary()` and called over JNI. All checks in this note are about these files.

Two things to know when collecting them:

- **App bundles and split APKs.** Apps published as Android App Bundles reach the device as a base APK plus configuration splits. The native libraries are in the ABI split, e.g. `split_config.arm64_v8a.apk`, not in `base.apk`. Pull all of them with `adb shell pm path <package>` and unzip each.
- **Libraries outside `lib/`.** Some apps keep native code in `assets/` (to load it themselves, often packed or encrypted) or download it later. A quick `find . -type f -exec sh -c 'head -c4 "$1" | grep -q ELF && echo "$1"' _ {} \;` over the unpacked APK finds ELF files wherever they are. Downloaded code is the topic of [MASWE-0049](/mobile/maswe-0049-unsafe-dynamic-code-loading/).

The ELF format exposes every mitigation in four places, all readable with `readelf` (GNU binutils) or `llvm-readelf` (in the NDK under `toolchains/llvm/prebuilt/<host>/bin/`):

| Mitigation | Where it shows | Command |
|---|---|---|
| PIE / PIC | ELF header `Type`, `INTERP` program header, `FLAGS_1` `PIE`, absence of `TEXTREL` | `readelf -hW`, `readelf -lW`, `readelf -dW` |
| Stack canaries | Import of `__stack_chk_fail` (and `__stack_chk_guard` on 32-bit ARM) | `readelf --dyn-syms -W` |
| RELRO | `GNU_RELRO` program header, plus `BIND_NOW` / `FLAGS_1 NOW` for full RELRO | `readelf -lW`, `readelf -dW` |
| NX stack | `GNU_STACK` program header flags (`RW` vs `RWE`) | `readelf -lW` |
| FORTIFY | Imports of `__*_chk` functions such as `__memcpy_chk`, `__strcpy_chk`, `__vsnprintf_chk` | `readelf --dyn-syms -W` |

Always read imports from the **dynamic** symbol table (`--dyn-syms`). Release libraries are normally stripped, which removes `.symtab`, but `.dynsym` has to stay because the dynamic linker needs it to resolve imports. A check that greps `nm` output (which reads `.symtab` by default) reports "no canary" for every stripped library. `nm -D` reads the dynamic table and is fine.

#### Position-independent code, PIE and text relocations

Position-independent code can run at any load address. That is what lets the loader place it at a random address (ASLR). Android added ASLR in 4.0 and PIE support in 4.1, and since **Android 5.0 (API 21)** it requires all dynamically linked executables to be PIE ([Android security enhancements](https://source.android.com/docs/security/enhancements)). The dynamic linker refuses to run a non-PIE executable.

What "PIE" means depends on the file:

- **Shared libraries** (`.so` loaded with `System.loadLibrary()`) are ELF type `DYN` by definition and are always loaded at a randomised address. Asking whether a shared library "is PIE" is not a meaningful question, and the `FLAGS_1 PIE` bit is only set on executables. The meaningful question for a library is whether its code is actually position-independent, and the tell-tale for code that is not is a **`TEXTREL`** entry in the dynamic section: the loader would have to patch the code segment at load time, which means making code writable. 64-bit Android never supported text relocations, and since API 23 the loader refuses to load libraries with text relocations for apps targeting API 23 or higher ([Android changes for NDK developers](https://android.googlesource.com/platform/bionic/+/main/android-changes-for-ndk-developers.md)).
- **Executables** (a tool shipped as `lib/<abi>/libfoo.so` and run with `ProcessBuilder` or `Runtime.exec()`) have an `INTERP` program header naming `/system/bin/linker64` or `/system/bin/linker`. A PIE executable is type `DYN` and has `FLAGS_1` containing `PIE`. A non-PIE executable is type `EXEC`.

What it looks like (lab build, GNU readelf 2.47):

```text
$ readelf -hW lib/arm64-v8a/libtool_pie.so | grep Type
  Type:                              DYN (Position-Independent Executable file)
$ readelf -dW lib/arm64-v8a/libtool_pie.so | grep FLAGS_1
 0x000000006ffffffb (FLAGS_1)            Flags: NOW PIE
$ readelf -hW lib/arm64-v8a/libtool_nopie.so | grep Type
  Type:                              EXEC (Executable file)
$ readelf -dW lib/armeabi-v7a/liblegacy-parser.so | grep TEXTREL
 0x0000001e (FLAGS)                      TEXTREL
 0x00000016 (TEXTREL)                    0x0
```

Recent GNU readelf prints "Position-Independent Executable file" for PIE executables. `llvm-readelf` and older binutils print `DYN (Shared object file)` for both, so do not rely on the wording: check `INTERP` and `FLAGS_1` instead. Clang builds PIE by default for every Android target, so non-PIE executables only come from very old or non-Clang toolchains.

#### Stack canaries

A stack canary (stack-smashing protector, SSP) is a random value placed between a function's local buffers and its saved return address. The function prologue stores it and the epilogue compares it before returning. If a linear overflow of a local buffer has changed it, the epilogue calls `__stack_chk_fail()`, which aborts the process. Android has used ProPolice-style `-fstack-protector` since 1.5.

The compiler decides per function whether to add the check:

| Flag | Which functions get a canary |
|---|---|
| `-fstack-protector` | Functions with character arrays of 8 bytes or more, or `alloca()` |
| `-fstack-protector-strong` | Any function with a local array (of any type), or a local whose address is taken. The NDK default |
| `-fstack-protector-all` | Every function, at a measurable cost |
| `-fno-stack-protector` | None |

What this means for detection:

- A library has canaries if it **imports `__stack_chk_fail`**. One protected function is enough to cause the import, so the import tells you SSP was on for at least part of the library, not for every function.
- A library **without** that import was either built without SSP, or has no function that qualifies. A small JNI bridge, a library that only does arithmetic, or a near-empty library (React Native ships several) legitimately has no canary even when built with `-fstack-protector-strong`. In our lab a one-line function built with `-fstack-protector-strong` produced no `__stack_chk_fail` import at all, and the same file built with `-fstack-protector-all` did. This is the most common false positive in this whole area.
- Where the canary lives depends on the ABI. On **arm64, x86 and x86_64** Android, Clang reads the canary from a fixed thread-local slot that bionic reserves, so the only import is `__stack_chk_fail`. On **32-bit ARM** the canary is the global `__stack_chk_guard`, so you see both. We confirmed this with Clang targeting `aarch64-linux-android24`, `x86_64-linux-android24` and `armv7a-linux-androideabi21`. Do not require `__stack_chk_guard` on 64-bit libraries.
- **Not C/C++ at all.** Flutter's `libapp.so` is Dart AOT code (it exports `_kDartIsolateSnapshotData` and `_kDartVmSnapshotData`). Dart has no stack-allocated arrays and does not use canaries, and Flutter's [security false positives page](https://docs.flutter.dev/reference/security-false-positives) says so explicitly (its C++ engine, `libflutter.so`, is normal native code). Go libraries (gomobile, ".go.buildinfo" section) use Go's own stack management and do not use SSP. Rust does not enable stack protectors by default. For all three, "no canary" is expected and does not mean "vulnerable": the languages prevent the bug class the canary is there to catch, except in `unsafe` code and FFI.

#### RELRO and immediate binding

Calls from a library into another library go through the Procedure Linkage Table (PLT) and Global Offset Table (GOT). The GOT holds resolved function addresses, and an attacker with a write primitive who can overwrite a GOT entry redirects the next call to that function. RELRO (relocation read-only) closes this:

- **Partial RELRO** (`-Wl,-z,relro`): after relocation, the loader `mprotect`s the region described by the `GNU_RELRO` program header read-only. The lazily bound part of the GOT stays writable.
- **Full RELRO** (`-Wl,-z,relro,-z,now`): all symbols are resolved at load time (`BIND_NOW`, shown as `FLAGS BIND_NOW` and/or `FLAGS_1 NOW`), so the whole GOT can be read-only.

Android has supported both since 4.1. Bionic's linker does not do lazy binding, so on Android every library is effectively bound at load time. The `BIND_NOW` flag still matters, because with GNU `ld` it also decides how much of the GOT is placed inside the `GNU_RELRO` region. Without a `GNU_RELRO` header nothing is made read-only. Current Clang passes `-z relro -z now` to the linker for every Android target (see the [Clang Linux driver source](https://github.com/llvm/llvm-project/blob/main/clang/lib/Driver/ToolChains/Linux.cpp)), so a release library without full RELRO has had it switched off explicitly or comes from a different toolchain.

```text
$ readelf -lW lib/arm64-v8a/libnative-lib.so | grep GNU_RELRO
  GNU_RELRO      0x000440 0x0000000000020440 0x0000000000020440 0x000110 0x000bc0 R   0x1
$ readelf -dW lib/arm64-v8a/libnative-lib.so | grep FLAGS
 0x000000000000001e (FLAGS)              BIND_NOW
 0x000000006ffffffb (FLAGS_1)            Flags: NOW
```

Flutter's `libapp.so` again is a special case: Dart code does not use PLT/GOT at all, so "no RELRO" there means nothing.

#### Non-executable stack and segments

NX (no-execute, DEP) marks data pages, including the stack, as non-executable. Android has used hardware NX since 2.3. For ELF files the stack's executability is requested through the `GNU_STACK` program header: `RW` is non-executable, `RWE` asks for an executable stack. Compilers emit a `.note.GNU-stack` section in every object file to say "this object does not need an executable stack". Hand-written assembly files that lack that note can make GNU `ld` mark the whole library `RWE`. LLD defaults to a non-executable stack.

Separately, since API 26 the bionic loader refuses segments that are both writable and executable, for the same reason ([Android changes for NDK developers](https://android.googlesource.com/platform/bionic/+/main/android-changes-for-ndk-developers.md)). Whether an `RWE` `GNU_STACK` header actually leads to an executable stack depends on the loader and Android version, so treat it as a build defect to report, not as proof that injected code would run.

```text
$ readelf -lW lib/arm64-v8a/liblegacy-parser.so | grep GNU_STACK
  GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RWE 0
```

#### FORTIFY

`_FORTIFY_SOURCE` makes the C library's headers replace calls such as `memcpy`, `strcpy`, `sprintf` and `read` with checked variants when the compiler knows the destination size. If the size is exceeded at run time the process aborts instead of overflowing. Bionic has implemented FORTIFY since Android 4.2 and level 2 since 4.4. Some of the checked functions exist only from certain API levels, so the protection you get also depends on the library's `minSdkVersion` ([Build System Maintainers Guide](https://android.googlesource.com/platform/ndk/+/master/docs/BuildSystemMaintainers.md)).

Evidence in a binary is imports such as `__memcpy_chk`, `__strcpy_chk`, `__strlen_chk`, `__vsnprintf_chk`, `__read_chk`. Absence is weak evidence. When the size is known and the call is provably safe, there is no runtime check. Some checks happen only at compile time. A library that never calls a fortifiable function has nothing to fortify. Treat FORTIFY as supporting evidence: "no `_chk` imports, but imports of `strcpy`, `sprintf` and `memcpy`" is worth a line in the report, and "no `_chk` imports" on its own is not.

#### What the NDK and Clang turn on by default

These are the defaults of the current tools. Older releases differed, and a library built outside the NDK's build system gets none of the NDK-specific ones.

| Mitigation | Who enables it | Source |
|---|---|---|
| PIE executables | Clang, for all Android targets | NDK Build System Maintainers Guide; Clang driver `isPIEDefault` |
| `-fstack-protector-strong` | NDK CMake toolchain and ndk-build (not Clang itself) | Build System Maintainers Guide; NDK `build/cmake/flags.cmake` |
| `-D_FORTIFY_SOURCE=2` | NDK CMake toolchain and ndk-build | same |
| `-z relro -z now` (full RELRO) | Clang driver, for all Android targets | Clang `Linux.cpp` |
| Non-executable stack | LLD default; compilers emit `.note.GNU-stack` | LLD behaviour; NDK r22 made LLD the default linker |
| `-Wformat -Werror=format-security` | NDK CMake toolchain (unless `ANDROID_DISABLE_FORMAT_STRING_CHECKS`) | `flags.cmake` |
| `-Wl,-z,max-page-size=16384` | Only when `ANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES` is set | `flags.cmake` |

The practical reading: a library built with the NDK's own CMake toolchain or ndk-build, unmodified, passes every check in this note. A library that fails one was built some other way, or someone switched the default off. Both are worth asking the developer about.

#### Newer mitigations: CFI, shadow call stack, MTE, HWASan

These are context, not pass/fail criteria. No OWASP test requires them and most apps do not use them, so do not report their absence as a finding. Mention them under recommendations for apps with a large native attack surface.

- **Control Flow Integrity** (`-fsanitize=cfi`, needs LTO): checks that indirect calls go to valid targets of the right type. Android uses it in the media stack since 8.0 and in parts of the platform since. It is possible but rare in apps.
- **ShadowCallStack** (`-fsanitize=shadow-call-stack`, arm64 only): keeps return addresses on a separate stack, so a stack overflow cannot change them. Used in the Android platform since Android 10.
- **Memory Tagging Extension (MTE)**: an Armv9 hardware feature on select devices from Android 13 (Pixel 8 and later). Apps opt in for their heap with `android:memtagMode="off|default|sync|async"` on `<application>` or `<process>` in the manifest ([Arm MTE guide](https://developer.android.com/ndk/guides/arm-mte)). Async mode is designed to be cheap enough for release builds. During a test, check the manifest for the attribute and `adb shell grep mte /proc/cpuinfo` on the test device.
- **HWASan and ASan**: debugging tools for finding memory bugs, not production mitigations. If you find a library linked against `libclang_rt.hwasan` or `libclang_rt.asan` in a release APK, report it as a debug build in production, not as hardening.

#### Reading rabin2 and r2 output

OWASP's technique ([MASTG-TECH-0115](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0115/)) uses [rabin2](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/) from radare2. `rabin2 -I` prints a summary that includes the hardening fields:

```text
$ rabin2 -I lib/x86_64/libtool-checker.so | grep -E "canary|pic|nx|relro|stripped"
canary   false
nx       true
pic      true
relro    full
stripped true
```

It is convenient, but know what each line is based on. `canary` is a symbol heuristic based on the stack-protector imports, so everything said above about functions without arrays applies. `pic` is derived from the ELF type, so for a shared library it is effectively always `true` and tells you nothing. `relro` reads the same `GNU_RELRO` and `BIND_NOW` information as `readelf`. When rabin2 and `readelf` disagree, trust the raw `readelf` output and quote it in the report. The interactive equivalent in r2 is `i~canary,pic,nx,relro`. `checksec` (the shell script or the pwntools version) gives the same picture, and MobSF reports the same fields, including the Dart false positives that Flutter's page answers.

### iOS: Binary Protection Mechanisms (MASTG-KNOW-0061)

Source: [MASTG-KNOW-0061](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CODE/MASTG-KNOW-0061/).

#### Mach-O files in an IPA

An IPA is a ZIP file with the app bundle under `Payload/<Name>.app/`. Executable code lives in several places, and all of it is in scope ([MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0082](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0082/)):

| Location | Mach-O file type | Notes |
|---|---|---|
| `Payload/<Name>.app/<CFBundleExecutable>` | `MH_EXECUTE` | The main binary. Usually named like the bundle, but the `CFBundleExecutable` key in `Info.plist` is authoritative |
| `Frameworks/<X>.framework/<X>` | `MH_DYLIB` | Embedded dynamic frameworks: yours, third-party, Flutter's `App.framework` and `Flutter.framework` |
| `Frameworks/*.dylib` | `MH_DYLIB` | Mostly Swift runtime libraries (`libswiftCore.dylib` and others) on older deployment targets |
| `PlugIns/<Y>.appex/<Y>` | `MH_EXECUTE` | App extensions (widgets, share, notification service). Separate executables with their own settings |
| `Watch/`, `AppClips/` | `MH_EXECUTE` | Watch apps and App Clips |

Statically linked libraries (Swift packages are static by default, CocoaPods with `use_frameworks! :linkage => :static`, mergeable libraries) do not appear as files. Their code is inside the main binary and inherits *its own* compile flags, not the main target's: a static library built without SSP still has unprotected functions inside a binary that imports `___stack_chk_fail` for other reasons.

App Store binaries are thin `arm64` today. Fat (universal) binaries with several slices still show up in enterprise and older builds. `otool` and `nm` handle both, and the sweep script checks every slice.

#### PIE and MH_PIE

For `MH_EXECUTE` files, PIE is a flag in the Mach-O header, `MH_PIE`, which tells the kernel to load the executable at a random address. `otool -hv` prints it in the `flags` column:

```text
$ otool -hv "Payload/Demo App.app/Demo App"
Mach header
      magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64        ALL  0x00     EXECUTE    21       1864   NOUNDEFS DYLDLINK TWOLEVEL PIE
```

Dylibs and frameworks (`MH_DYLIB`) are always position-independent and dyld always slides them. They never carry `MH_PIE`, so tools that report "PIE: False" for them (objection does) are reporting a non-issue. Xcode has built PIE executables by default for many years. The relevant build settings are `GCC_DYNAMIC_NO_PIC` ("Generate Position-Dependent Code") and `LD_NO_PIE` ("Generate Position-Dependent Executable"), and both must stay `NO`. A non-PIE `arm64` iOS executable is something you are unlikely ever to see. The test exists for old 32-bit builds and misconfigured projects.

#### Stack canaries on Darwin

The mechanism is the same as on Android. On Apple platforms the symbols carry one extra leading underscore, so you look for `___stack_chk_fail` and `___stack_chk_guard` among the imports:

```text
$ nm -u "Payload/Demo App.app/Demo App" | grep stack_chk
___stack_chk_fail
___stack_chk_guard
$ otool -Iv "Payload/Demo App.app/Demo App" | grep stack_chk
0x0000000100003f24     5 ___stack_chk_fail
0x0000000100004008     5 ___stack_chk_fail
0x0000000100004010     6 ___stack_chk_guard
```

`nm -u` lists undefined (imported) symbols, and `otool -Iv` lists the indirect symbol table used by stubs and pointers. Both survive stripping, because dyld needs them to bind imports. They also survive App Store FairPlay encryption, which covers the code pages, not the header, load commands or `__LINKEDIT`.

Clang's Darwin toolchain turns on `-fstack-protector` by default for iOS targets ([Clang Darwin toolchain source](https://github.com/llvm/llvm-project/blob/main/clang/lib/Driver/ToolChains/Darwin.h)). We confirmed with Apple clang that a plain compile without any flag adds `-stack-protector 1` and that a function with a 64-byte local buffer gets a canary. So C and Objective-C code built by Xcode has canaries in functions with character buffers unless someone passed `-fno-stack-protector`. `-fstack-protector-strong` widens that to all functions with arrays or address-taken locals, and is the flag to recommend. MASTG-KNOW-0061 suggests `-fstack-protector-all` in "Other C Flags". That works, but costs performance in every function and is not needed to pass the test.

Swift is different. Swift code does not have C-style unchecked stack buffers, so most Swift functions need no canary. Recent Swift compilers do add one where Swift code takes an unsafe pointer to stack memory: with Swift 5.10, a function that calls `withUnsafeMutableBytes(of: &localTuple)` imported `___stack_chk_fail`, and the import disappeared with `-Xfrontend -disable-stack-protector`. Neither the presence nor the absence of the import in a Swift-only binary says much, which is why OWASP tells you to skip pure Swift binaries in [MASTG-TEST-0229](#mastg-test-0229-stack-canaries-not-enabled-ios).

#### Automatic Reference Counting

ARC is a Clang feature for Objective-C (`-fobjc-arc`) and the only memory model Swift has. The compiler inserts the retain and release operations that manual retain/release (MRR) code has to write by hand. The security relevance is narrow but real: MRR bugs are over-releases (use-after-free, double free of Objective-C objects, which are exploitable) and missing releases (leaks). ARC removes that whole class of mistakes. It does not stop retain cycles, and it does nothing for C memory (`malloc`/`free`, `CFRetain`/`CFRelease` without bridging).

Detecting ARC from imports is harder than OWASP suggests, and we verified why. Recent Clang converts MRR message sends such as `[obj retain]`, `[obj release]` and `[obj autorelease]` into direct calls to `objc_retain`, `objc_release` and `objc_autorelease`. A file compiled with `-fno-objc-arc` therefore imports the same `_objc_release` and `_objc_retain` that OWASP lists as ARC indicators:

```text
$ clang -fno-objc-arc -c mrr.m -o mrr.o && nm -u mrr.o
_objc_release
_objc_retain
```

The more reliable signals are the entry points that only ARC's code generator emits:

| Symbol | Why it indicates ARC |
|---|---|
| `_objc_storeStrong` | ARC's strong assignment to a `__strong` variable or ivar |
| `_objc_retainAutoreleasedReturnValue`, `_objc_claimAutoreleasedReturnValue`, `_objc_unsafeClaimAutoreleasedReturnValue` | Caller side of ARC's return-value optimisation |
| `_objc_autoreleaseReturnValue`, `_objc_retainAutoreleaseReturnValue` | Callee side of the same optimisation |

`_objc_release`, `_objc_retain`, `_objc_autorelease`, `_objc_autoreleasePoolPush` and register-specific variants such as `_objc_release_x20` (newer toolchains) are consistent with ARC but do not prove it. `_objc_msgSend` with none of the ARC-specific imports in a binary that clearly contains Objective-C classes is the pattern to investigate. Swift calling Objective-C APIs also produces `_objc_retainAutoreleasedReturnValue`, so a Swift binary that uses UIKit or Foundation usually shows "ARC-specific" imports too, which is correct: Swift is always ARC.

#### Swift binaries

You can tell Swift code from imports and load commands: `_swift_allocObject`, `_swift_retain`, `_swift_release`, `_swift_bridgeObjectRetain`, a dependency on `libswiftCore.dylib` (`otool -L`), and `__swift5_*` sections (`otool -l | grep __swift5`). For Swift:

- **ARC is implicit.** There is no MRR mode, so there is nothing to test. Report "Swift, ARC by language design" and move on.
- **Canaries are mostly irrelevant** (see above), except for `Unsafe*Pointer`, `withUnsafe*` and C interop code.
- **Mixed binaries are the norm.** An app with Swift UI code, an Objective-C networking layer and a C image library statically linked into one main binary has three different answers in one file. When the binary imports `_objc_msgSend` and defines Objective-C classes (`otool -oV`), the Objective-C part still needs to be checked for ARC and canaries.

#### Xcode build settings

If you have the project (white-box testing or a developer asking how to fix a finding), the settings are:

| Setting (display name) | Build setting | Secure value |
|---|---|---|
| Objective-C Automatic Reference Counting | `CLANG_ENABLE_OBJC_ARC` | `YES` (and no `-fno-objc-arc` per-file flags in Compile Sources) |
| Generate Position-Dependent Code | `GCC_DYNAMIC_NO_PIC` | `NO` |
| Generate Position-Dependent Executable | `LD_NO_PIE` | `NO` |
| Other C Flags | `OTHER_CFLAGS` | Contains `-fstack-protector-strong`, does not contain `-fno-stack-protector` |
| Enable C++ Standard Library Hardening | `CLANG_CXX_STANDARD_LIBRARY_HARDENING` | `Yes (fast)` or stronger for C++ code |
| Exclusive Access to Memory | `SWIFT_ENFORCE_EXCLUSIVE_ACCESS` | Left at its default (on) |

Two settings are often mentioned in reports but are not compiler security features: `GCC_GENERATE_DEBUGGING_SYMBOLS` ("Generate Debug Symbols") and `STRIP_INSTALLED_PRODUCT` / `STRIP_STYLE` (stripping). Stripping and debug symbols affect how easy the binary is to reverse engineer, which is MASVS-RESILIENCE, not this weakness.

Search a project for the risky values with:

```bash
grep -rnE 'CLANG_ENABLE_OBJC_ARC = NO|-fno-objc-arc|-fno-stack-protector|LD_NO_PIE = YES|GCC_DYNAMIC_NO_PIC = YES' \
  --include=project.pbxproj --include='*.xcconfig' --include='*.podspec' --include=Podfile .
grep -rn 'requires_arc' --include='*.podspec' --include='*.podspec.json' .
```

#### Pointer authentication and Enhanced Security

These are context for apps with significant native attack surface, not pass/fail criteria.

- **Pointer authentication (PAC)** on the `arm64e` architecture signs return addresses and code pointers with keys held by the CPU, so a corrupted pointer fails authentication instead of being followed. Apple's own code has used it for years. Third-party apps can adopt it through Xcode's **Enhanced Security** capability, which sets `ENABLE_POINTER_AUTHENTICATION` and adds an `arm64e` slice ([Enabling enhanced security for your app](https://developer.apple.com/documentation/xcode/enabling-enhanced-security-for-your-app)). `otool -hv` shows `ARM64` with cpusubtype `E` for such slices. The sweep script notes them.
- **Enhanced Security** also bundles typed allocators (`CLANG_ENABLE_C_TYPED_ALLOCATOR_SUPPORT`, `CLANG_ENABLE_CPLUSPLUS_TYPED_ALLOCATOR_SUPPORT`), zero-initialised stack variables (`CLANG_ENABLE_STACK_ZERO_INIT`), C++ standard library hardening and bounds-safe buffers (`ENABLE_CPLUSPLUS_BOUNDS_SAFE_BUFFERS`), optional `-fbounds-safety` for C (`ENABLE_C_BOUNDS_SAFETY`), security-related compiler warnings, and hardware memory tagging (Memory Integrity Enforcement) through the `com.apple.security.hardened-process.checked-allocations` entitlement, effective on A19 and M5 devices and later. You can see whether an app opted in from its entitlements: `codesign -d --entitlements - "Payload/<Name>.app"` and look for `com.apple.security.hardened-process` keys.

Apple itself warns that Enhanced Security can affect performance and stability and should follow the app's threat model. Recommend it for apps that parse complex untrusted content in native code. Do not report its absence as a finding.

#### Encrypted App Store binaries

Binaries from the App Store are FairPlay-encrypted. `otool -l <binary> | grep -A4 LC_ENCRYPTION_INFO` shows `cryptid 1`. The header, load commands, symbol tables and import information are outside the encrypted range, so every check in this note works on an encrypted binary. You only need a decrypted binary (from a jailbroken device or a build supplied by the client) when you want to disassemble a function and check its canary by hand.

### Android: Memory Corruption Bugs (MASTG-KNOW-0005)

Source: [MASTG-KNOW-0005](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0005/). Full treatment: our standalone note [Memory Corruption in Android Apps: Where It Still Applies](/mobile/mastg-know-0005-memory-corruption-bugs/).

In short: ART makes Java and Kotlin code memory-safe, and that protection ends at the JNI boundary. NDK code and native SDKs are exposed to buffer overflows, out-of-bounds access, integer overflows, use-after-free and format-string bugs. Stagefright is the textbook example of input that is only *processed* triggering native memory corruption. Leaks of `Context` and `Activity` references are the managed-code counterpart: a stability problem rather than a corruption one. OWASP removed its black-box memory-corruption tests because finding these bugs in compiled code without source is unreliable. The work belongs in development (sanitizers, fuzzing, static analysis), with OWASP SAMM and NIST SP 800-218 (SSDF) as frameworks. Our note covers the black-box steps that still pay off: mapping the JNI surface, checking compiler hardening (this note goes deeper), spotting unsafe libc imports, and memory-leak testing.

The connection to this weakness: compiler mitigations are what make a native bug expensive to exploit. Where KNOW-0005 work finds a reachable parser in C, the hardening status of that library decides whether you are looking at a crash or a credible code-execution path.

### iOS: Memory Corruption Bugs (MASTG-KNOW-0060)

Source: [MASTG-KNOW-0060](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CODE/MASTG-KNOW-0060/).

Swift is memory-safe by default and Objective-C under ARC avoids most object lifetime bugs, but neither covers everything:

- **C and C++ code**, whether yours or in an SDK, and reached through bridging headers or Objective-C++ wrappers, has the full range of memory-safety bugs: overflows, out-of-bounds reads and writes, integer overflows, use-after-free.
- **Swift's escape hatches**: `UnsafePointer`, `UnsafeMutableRawPointer`, `withUnsafeBytes`, `Unmanaged` (manual retain and release of Objective-C or Core Foundation objects), and `unowned(unsafe)`. Misusing `Unmanaged.takeRetainedValue()` versus `takeUnretainedValue()` is a classic over-release.
- **Objective-C under MRR**: double releases and use-after-free of objects. ARC removes this class, which is why MASTG-TEST-0230 exists.
- **Retain cycles** (strong references between objects, often through closures capturing `self`) cause leaks under ARC. They are a stability issue, not corruption.

As on Android, OWASP dropped the black-box tests for this. The developer-side tools are Xcode's scheme diagnostics (Address Sanitizer, Thread Sanitizer, Undefined Behavior Sanitizer, Malloc Scribble, Guard Malloc, Zombie Objects), the Memory Graph Debugger, and the Allocations and Leaks instruments. When you have source access, grep for `Unmanaged`, `Unsafe`, `memcpy`, `strcpy` and `sprintf` and review what feeds them. When you do not, check the hardening of the binaries that contain C/C++ (this note) and report reachable native parsers as an area for the developer's own fuzzing.

## Tests

OWASP links five current tests to MASWE-0045: two for Android (MASTG-TEST-0222 and MASTG-TEST-0223) and three for iOS (MASTG-TEST-0228, MASTG-TEST-0229 and MASTG-TEST-0230). OWASP publishes no demos for any of them. The demos below are ours, built in our lab with the stated flags, and every output shown is real. On Android, OWASP only tests PIE and canaries, so we add GT-CODE-0045-1 for RELRO, the non-executable stack and FORTIFY, which come out of the same `readelf` run.

They replace these legacy v1 tests:

| Legacy test | Title | `covered_by` | Where the content went |
|---|---|---|---|
| [MASTG-TEST-0044](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0044/) (Android) | Make Sure That Free Security Features Are Activated | MASTG-TEST-0222, MASTG-TEST-0223 | The two Android tests below |
| [MASTG-TEST-0087](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0087/) (iOS) | Make Sure That Free Security Features Are Activated | MASTG-TEST-0228, MASTG-TEST-0229, MASTG-TEST-0230 | The three iOS tests below |
| [MASTG-TEST-0043](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0043/) (Android) | Memory Corruption Bugs | empty | Deliberately not replaced. OWASP moved the topic into MASTG-KNOW-0005 as development-time work. Our [KNOW-0005 note](/mobile/mastg-know-0005-memory-corruption-bugs/) keeps the black-box steps that still make sense |
| [MASTG-TEST-0086](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0086/) (iOS) | Memory Corruption Bugs | empty | Deliberately not replaced. Moved into MASTG-KNOW-0060, summarised [above](#ios-memory-corruption-bugs-mastg-know-0060) |

An empty `covered_by` means OWASP decided the old test should not have a v2 successor, not that it was forgotten. The serialisation and memory-leak parts of MASTG-TEST-0043 live on in other places. Java deserialisation is covered under [MASWE-0050](/mobile/maswe-0050-unsafe-handling-of-untrusted-data/), and leaks under our KNOW-0005 note.

### Before you start: sweep every native binary in the package

All six tests read the same few fields, so collect them once for every binary and then evaluate per test. The script below does that with standard tools. It takes an unpacked APK (`unzip app.apk -d app/`, merging every split APK into the same directory) or an unpacked IPA (`unzip app.ipa -d app/`) and prints one table row per binary.

- **ELF:** every `lib/<abi>/*.so`, using `readelf` (GNU binutils) or `llvm-readelf` from the NDK. On macOS, use the NDK's `llvm-readelf` or Homebrew's binutils and point `READELF` at it.
- **Mach-O:** the main binary and every other Mach-O file at the top level of each `.app`, `.framework` and `.appex` bundle, plus loose `.dylib` files. It recognises files by magic bytes, so it does not depend on bundle names or `Info.plist` parsing. It needs `otool` and `nm` (macOS command line tools), or `llvm-otool` and `llvm-nm` elsewhere.
- **Stripped binaries:** all symbol checks use the dynamic symbol table (ELF `.dynsym`) or the undefined-symbol list (Mach-O), which survive stripping.

```bash
#!/usr/bin/env bash
# binhard.sh - list compiler hardening for every native binary in an unpacked APK or IPA.
# Usage: binhard.sh <unzipped-apk-dir | unzipped-ipa-dir>
# Needs: readelf (GNU binutils) or llvm-readelf for ELF; otool + nm (macOS) or llvm-otool + llvm-nm for Mach-O.
set -u
ROOT=${1:?usage: $0 <unzipped-apk-or-ipa-dir>}

READELF=${READELF:-$(command -v readelf || command -v llvm-readelf || true)}
if [ "$(uname)" = Darwin ]; then
  OTOOL=${OTOOL:-$(command -v otool || true)}; MNM=${MNM:-$(command -v nm || true)}
else
  OTOOL=${OTOOL:-$(command -v llvm-otool || true)}; MNM=${MNM:-$(command -v llvm-nm || true)}
fi

magic() { od -An -tx1 -N4 "$1" 2>/dev/null | tr -d ' \n'; }

elf_row() {
  local f=$1 hdr ph dyn syms type pie relro nx canary fort note=""
  hdr=$("$READELF" -hW "$f" 2>/dev/null); ph=$("$READELF" -lW "$f" 2>/dev/null)
  dyn=$("$READELF" -dW "$f" 2>/dev/null); syms=$("$READELF" --dyn-syms -W "$f" 2>/dev/null)
  # ELF type: shared library, PIE executable or fixed-address executable
  if grep -q 'Type:.*EXEC' <<<"$hdr"; then type=exe; pie=NO
  elif grep -q 'INTERP' <<<"$ph" || grep -q 'FLAGS_1.*PIE' <<<"$dyn"; then type=exe; pie=yes
  else type=lib; pie=n/a; fi
  grep -q 'TEXTREL' <<<"$dyn" && { pie=TEXTREL; note+="text-relocs "; }
  # RELRO: GNU_RELRO segment, full when symbols are bound at load time (BIND_NOW / FLAGS_1 NOW)
  if grep -q 'GNU_RELRO' <<<"$ph"; then
    if grep -Eq '\(BIND_NOW\)|\(FLAGS\).*BIND_NOW|\(FLAGS_1\).*NOW' <<<"$dyn"; then relro=full; else relro=partial; fi
  else relro=NO; fi
  # NX: PT_GNU_STACK must exist and must not carry the E flag
  if grep -q 'GNU_STACK' <<<"$ph"; then
    # flags are the fields between MemSiz and Align, e.g. "RW" or "RWE" (GNU prints "R E" with a gap)
    if awk '$1=="GNU_STACK"{f=""; for(i=7;i<NF;i++) f=f $i; print f}' <<<"$ph" | grep -q E; then nx=NO; else nx=yes; fi
  else nx=no-hdr; fi
  # Canary and FORTIFY: imports in .dynsym survive stripping, .symtab does not
  if grep -q '__stack_chk_fail' <<<"$syms"; then canary=yes; else canary=no; fi
  fort=$(grep -Eo '__[A-Za-z0-9_]+_chk' <<<"$syms" | grep -v '__stack_chk' | sort -u | wc -l | tr -d ' ')
  # Hints that explain a missing canary (not built from C/C++ at all, or a near-empty library)
  grep -Eq '_kDartIsolateSnapshot(Data|Instructions)' <<<"$syms" && note+="dart-aot "
  "$READELF" -SW "$f" 2>/dev/null | grep -Eq '\.go\.buildinfo|\.note\.go\.buildid|\.gopclntab' && note+="go "
  LC_ALL=C grep -aqE '/rustc/[0-9a-f]{40}|\.cargo/registry/src|rust_panic|rust_begin_unwind' "$f" && note+="rust? "
  local sec; sec=$("$READELF" -SW "$f" 2>/dev/null | sed 's/^ *\[ *[0-9]*\]//')
  local text; text=$(awk '$1==".text"{print $5; exit}' <<<"$sec")
  [ -n "$text" ] && [ "$(printf '%d' "0x$text")" -lt 4096 ] && note+="tiny-.text "
  grep -q '^ *\.symtab ' <<<"$sec" || note+="stripped "
  printf '%-44s %-4s %-7s %-7s %-6s %-6s %-4s %s\n' "${f#$ROOT/}" "$type" "$pie" "$relro" "$nx" "$canary" "$fort" "$note"
}

macho_row() {
  local f=$1 hdr imps libs ftype pie canary arc lang enc note=""
  hdr=$("$OTOOL" -arch all -hv "$f" 2>/dev/null || "$OTOOL" -hv "$f" 2>/dev/null); imps=$("$MNM" -u "$f" 2>/dev/null); libs=$("$OTOOL" -L "$f" 2>/dev/null)
  case "$hdr" in *EXECUTE*) ftype=exe;; *DYLIB*) ftype=dylib;; *BUNDLE*) ftype=bundle;; *) ftype=other;; esac
  if [ "$ftype" = exe ]; then grep -q 'EXECUTE.* PIE' <<<"$hdr" && pie=yes || pie=NO; else pie=n/a; fi
  grep -q '___stack_chk_fail' <<<"$imps" && canary=yes || canary=no
  # Language: Swift if it imports the Swift runtime, ObjC if it sends messages
  lang=""
  { grep -q '_swift_' <<<"$imps" || grep -q 'libswiftCore' <<<"$libs"; } && lang+="swift "
  grep -q '_objc_msgSend' <<<"$imps" && lang+="objc "
  [ -z "$lang" ] && lang="c/c++ "
  # ARC: only entry points that the ARC optimiser emits. objc_retain/objc_release/objc_autorelease alone
  # also appear in MRR code built by recent clang, so they are not proof.
  if grep -Eq '_objc_(storeStrong|retainAutoreleasedReturnValue|claimAutoreleasedReturnValue|unsafeClaimAutoreleasedReturnValue|autoreleaseReturnValue|retainAutoreleaseReturnValue)$' <<<"$imps"; then arc=yes
  elif grep -q 'swift' <<<"$lang"; then arc=swift; grep -q objc <<<"$lang" && note+="check-objc-parts "
  elif grep -q 'objc' <<<"$lang"; then arc=NO?
  else arc=n/a; fi
  enc=$("$OTOOL" -l "$f" 2>/dev/null | awk '/LC_ENCRYPTION_INFO/{e=1} e&&/cryptid/{print $2; exit}')
  [ -z "$enc" ] && enc=-
  grep -q 'arm64e' <<<"$hdr" && note+="arm64e "
  [ "$(grep -c 'Mach header' <<<"$hdr")" -gt 1 ] && note+="fat "
  printf '%-64s %-6s %-4s %-6s %-6s %-12s %-3s %s\n' "${f#$ROOT/}" "$ftype" "$pie" "$canary" "$arc" "$lang" "$enc" "$note"
}

# ---------- Android: every lib/<abi>/*.so ----------
if [ -d "$ROOT/lib" ]; then
  [ -n "$READELF" ] || { echo "readelf/llvm-readelf not found (set READELF=...)" >&2; exit 1; }
  printf '%-44s %-4s %-7s %-7s %-6s %-6s %-4s %s\n' FILE TYPE PIE RELRO NX CANARY FORT NOTES
  find "$ROOT/lib" -type f -name '*.so' -print0 | sort -z | while IFS= read -r -d '' so; do
    [ "$(magic "$so")" = 7f454c46 ] && elf_row "$so" || echo "${so#$ROOT/}: not an ELF file (packed or encrypted?)"
  done
fi

# ---------- iOS: main binary, Frameworks, PlugIns (app extensions) ----------
if [ -d "$ROOT/Payload" ]; then
  [ -n "$OTOOL" ] && [ -n "$MNM" ] || { echo "otool/nm (or llvm-otool/llvm-nm) not found" >&2; exit 1; }
  printf '%-64s %-6s %-4s %-6s %-6s %-12s %-3s %s\n' FILE TYPE PIE CANARY ARC LANG ENC NOTES
  # Mach-O files at the top of each bundle (.app, .framework, .appex) plus loose .dylib files
  find "$ROOT/Payload" \( -name '*.app' -o -name '*.framework' -o -name '*.appex' \) -type d -print0 |
  while IFS= read -r -d '' b; do find "$b" -maxdepth 1 -type f -print0; done |
  cat - <(find "$ROOT/Payload" -type f -name '*.dylib' -print0) | sort -zu |
  while IFS= read -r -d '' f; do
    case "$(magic "$f")" in cffaedfe|cefaedfe|cafebabe|cafebabf) macho_row "$f";; esac
  done
fi
```

We tested it with bash 3.2 (the macOS default) and GNU readelf 2.47 against lab libraries built for `aarch64-linux-android24` and `armv7a-linux-androideabi21`, and with the macOS `otool` and `nm` against Objective-C, Swift, C and fat Mach-O files. Output on the Android lab set:

```text
FILE                                         TYPE PIE     RELRO   NX     CANARY FORT NOTES
lib/arm64-v8a/liblegacy-parser.so            lib  n/a     NO      NO     no     0    tiny-.text
lib/arm64-v8a/libnative-lib.so               lib  n/a     full    yes    yes    0    tiny-.text stripped
lib/arm64-v8a/libtool_nopie.so               exe  NO      partial yes    yes    0    tiny-.text
lib/arm64-v8a/libtool_pie.so                 exe  yes     full    yes    yes    0    tiny-.text
lib/armeabi-v7a/liblegacy-parser.so          lib  TEXTREL NO      yes    no     0    text-relocs tiny-.text
lib/armeabi-v7a/libnative-lib.so             lib  n/a     full    yes    yes    0    tiny-.text
```

And on the Mach-O lab set:

```text
FILE                                                             TYPE   PIE  CANARY ARC    LANG         ENC NOTES
Payload/Demo App.app/Demo App                                    exe    yes  yes    yes    objc         -
Payload/Demo App.app/Frameworks/Legacy.framework/Legacy          dylib  n/a  no     NO?    objc         -
Payload/Demo App.app/Frameworks/SwiftKit.framework/SwiftKit      dylib  n/a  no     swift  swift        -
Payload/Demo App.app/Frameworks/libfat.dylib                     dylib  n/a  yes    n/a    c/c++        -   fat
Payload/Demo App.app/Frameworks/libhelper.dylib                  dylib  n/a  yes    n/a    c/c++        -
Payload/Demo App.app/PlugIns/Widget.appex/Widget                 exe    yes  no     yes    swift objc   -
```

How to read the columns:

- `PIE` is `n/a` for shared libraries and dylibs by design. `TEXTREL` means the library contains non-PIC code.
- `CANARY no` is a lead, not a finding. Check the `NOTES` column (`dart-aot`, `go`, `rust?`, `tiny-.text`) and the test sections below before you write anything up.
- `FORT` counts distinct `__*_chk` imports. Zero is only meaningful next to unsafe libc imports.
- `ARC NO?` means Objective-C code without any ARC-specific import: investigate it with MASTG-TEST-0230. `swift` means ARC by language design.
- `ENC 1` is an App Store-encrypted binary. All checks still work.

The lab binaries are tiny, which is why every Android row has the `tiny-.text` note. The Mach-O lab files were built for macOS arm64. The Mach-O format and the checks are identical for iOS.

To fetch the files in the first place:

```bash
# Android: pull every APK of the installed package (base + splits) and merge them
adb shell pm path com.example.app | sed 's/package://' | while read -r p; do adb pull "$p" apks/; done
for a in apks/*.apk; do unzip -oq "$a" 'lib/*' -d app/; done
aapt2 dump badging apks/base.apk | grep -E "sdkVersion|targetSdkVersion"   # needed for MASTG-TEST-0222

# iOS: unpack the IPA (decryption is not needed for these checks)
unzip -q app.ipa -d app/
bash binhard.sh app/
```

### MASTG-TEST-0222: Position Independent Code (PIC) Not Enabled (Android)

*OWASP test: [MASTG-TEST-0222](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0222/). Type: static. Front matter: `deprecated_since: 21`.*

#### Overview

The test checks that the app's native code is position-independent, so that ASLR can randomise where it is loaded. Read the front-matter field before you spend any time on it. OWASP's test schema defines `deprecated_since` as the *last applicable platform/API level*. Here it records that since Android 5.0 (API 21) the platform itself enforces PIE: the dynamic linker will not run a non-PIE executable, Clang builds PIE by default, and shared libraries are position-independent by construction. Strictly, API 20 is the last level where non-PIE code could run at all, so if you read the field literally it is off by one. The intent is clear either way: **the test only matters for apps whose `minSdkVersion` is below 21**, which can still be installed on Android 4.x devices where a non-PIE executable would run at a fixed address.

Two refinements make the test useful beyond that:

- For **shared libraries**, "PIC not enabled" shows up as text relocations (`TEXTREL`), not as a missing PIE flag. Apps targeting API 23 or higher cannot load such libraries at all, and 64-bit Android never could. A `TEXTREL` library in an app with a lower `targetSdkVersion`, or one that only loads on old devices, is the remaining real case.
- For **executables shipped as `lib*.so`**, PIE applies directly, and the ELF header tells you.

#### Prerequisites

- The APK and all split APKs, unpacked (see the sweep section). OWASP's technique for this is [MASTG-TECH-0157](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0157/) (Extracting Bundled Native Libraries), using `unzip` or [apktool](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/).
- `aapt2` (Android SDK build-tools) or `apkanalyzer` for the SDK levels.
- `readelf` or `llvm-readelf`. Optionally [rabin2](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/), as in OWASP's technique [MASTG-TECH-0115](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0115/).

#### Steps

1. Read the SDK levels:

   ```bash
   aapt2 dump badging app.apk | grep -E "^sdkVersion|^targetSdkVersion"
   # sdkVersion:'24'
   # targetSdkVersion:'35'
   # or: apkanalyzer manifest min-sdk app.apk
   ```

2. List the native files and classify them. Executables have an `INTERP` header:

   ```bash
   for f in app/lib/*/*.so; do
     t=$(readelf -hW "$f" | awk -F: '/Type:/{gsub(/^ +/,"",$2); print $2}')
     i=$(readelf -lW "$f" | grep -c INTERP)
     echo "$f | $t | interp=$i"
   done
   ```

3. For each **executable**, confirm PIE: type `DYN` and `FLAGS_1` containing `PIE`. Type `EXEC` is non-PIE:

   ```bash
   readelf -dW app/lib/arm64-v8a/libtool.so | grep FLAGS_1
   ```

4. For each **library**, check for text relocations:

   ```bash
   readelf -dW app/lib/armeabi-v7a/libfoo.so | grep -E 'TEXTREL'
   ```

5. Optional cross-check with rabin2: `rabin2 -I <file> | grep -E "pic|relocs"`. Remember that `pic true` is automatic for every shared library.

#### Observation

Record the `minSdkVersion` and `targetSdkVersion`, and for each native file its ABI, its type (library or executable), the `Type` line, and any `FLAGS_1` or `TEXTREL` lines. The sweep script's `TYPE` and `PIE` columns contain the same information.

#### Evaluation

- **Not applicable** if `minSdkVersion` ≥ 21 and no library has `TEXTREL`. Document it explicitly instead of leaving the test out, for example: *"MASTG-TEST-0222: not applicable. minSdkVersion 24 (aapt2 output attached), so the platform enforces PIE on every supported device (Android 5.0+). No native library contains text relocations (readelf -d, all ABIs)."*
- **Fail** if an executable shipped in the APK is type `EXEC` (non-PIE) and `minSdkVersion` < 21. On API 21+ devices the same file would simply not run, so it is also a functional bug.
- **Fail** if a library contains `TEXTREL`. Say in the report whether it can load at all for the app's `targetSdkVersion`, and on which devices: on 64-bit ABIs it cannot exist, and on 32-bit with `targetSdkVersion` ≥ 23 the loader refuses it. If it never loads, it is dead code and the finding drops to Info.
- **Pass** otherwise. Shared libraries without `TEXTREL` pass regardless of what any tool's "PIE" or "PIC" column says.

#### Demo

*No OWASP demo exists for this test. This one is ours.* The same tool source built three ways for Android:

```bash
# PIE executable (the Clang default)
clang --target=aarch64-linux-android24 -O2 -fPIE -pie tool.c -o lib/arm64-v8a/libtool_pie.so
# non-PIE executable (would not run on Android 5.0+)
clang --target=aarch64-linux-android24 -O2 -fno-pie -no-pie tool.c -o lib/arm64-v8a/libtool_nopie.so
# 32-bit library from non-PIC objects, text relocations allowed
clang --target=armv7a-linux-androideabi21 -O2 -fno-pic -shared -Wl,-z,notext parser.c -o lib/armeabi-v7a/liblegacy-parser.so
```

Detection output:

```text
$ readelf -hW lib/arm64-v8a/libtool_pie.so | grep Type ; readelf -dW lib/arm64-v8a/libtool_pie.so | grep FLAGS_1
  Type:                              DYN (Position-Independent Executable file)
 0x000000006ffffffb (FLAGS_1)            Flags: NOW PIE
$ readelf -hW lib/arm64-v8a/libtool_nopie.so | grep Type
  Type:                              EXEC (Executable file)
$ readelf -dW lib/armeabi-v7a/liblegacy-parser.so | grep TEXTREL
 0x0000001e (FLAGS)                      TEXTREL
 0x00000016 (TEXTREL)                    0x0
```

`libtool_nopie.so` and `liblegacy-parser.so` fail. `libtool_pie.so` passes.

### MASTG-TEST-0223: Stack Canaries Not Enabled (Android)

*OWASP test: [MASTG-TEST-0223](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0223/). Type: static.*

#### Overview

The test checks that the native libraries were built with stack-smashing protection. NDK builds get `-fstack-protector-strong` from the CMake toolchain and ndk-build by default. Libraries from other build systems may not. The difficulty is not running the check but interpreting a negative result, because a library can be built with SSP and still have no canary anywhere.

#### Prerequisites

- Unpacked APK and splits (MASTG-TECH-0157).
- `readelf --dyn-syms` or `llvm-readelf --dyn-syms` (or `nm -D`), optionally `rabin2 -I`.
- For the follow-up on negatives: a disassembler (Ghidra, r2, `llvm-objdump -d`), and `jadx` to see which Java code loads the library.

#### Steps

1. Run the sweep, or per library:

   ```bash
   for f in app/lib/*/*.so; do
     printf '%s: ' "$f"
     readelf --dyn-syms -W "$f" | grep -qE '__stack_chk_fail' && echo canary || echo NO-canary
   done
   ```

   OWASP's version of the same check (from MASTG-TECH-0115):

   ```bash
   rabin2 -I lib/x86_64/libnative-lib.so | grep -E "canary|pic"
   ```

2. For every library without `__stack_chk_fail`, decide whether that is expected:
   - **Not C/C++**: Dart AOT (`libapp.so`, exports `_kDartIsolateSnapshotData`), Go (`.go.buildinfo` or `.gopclntab` sections: `readelf -SW f.so | grep -E 'go\.buildinfo|gopclntab'`), Rust (panic strings with `.rs` paths: `strings f.so | grep -m3 '\.rs'`).
   - **Nothing to protect**: a tiny `.text` section (`readelf -SW f.so | grep ' .text'`), few exported functions (`readelf --dyn-syms -W f.so | grep -c FUNC`), and no imports of buffer-handling libc functions.
   - **A real gap**: substantial C/C++ code that imports `memcpy`, `strcpy`, `strcat`, `sprintf`, `read`, `recv` or `fgets`.

3. For a likely real gap, confirm in the disassembly that functions with local buffers have no canary check. In AArch64 Android code the canary is loaded from the thread pointer: `mrs x8, TPIDR_EL0` followed by `ldr x8, [x8, #0x28]` in the prologue and a compare before `ret`. A function that allocates a large stack frame, calls `memcpy` or `strcpy` into it, and has neither is unprotected.

   ```bash
   llvm-objdump -d --no-show-raw-insn app/lib/arm64-v8a/libfoo.so | grep -c 'tpidr_el0'
   ```

   The count is only a pointer: thread-local storage is also used for `errno` and C++ `thread_local` variables, so look at the prologue and epilogue of the specific functions.

4. Find out what the library is for and what feeds it: the `System.loadLibrary("foo")` call site and the `native` methods in jadx, the library's strings, and the vendor if it is a third-party SDK.

#### Observation

Per library: canary yes/no, the explanation for each "no" (language, size, imports), and for real gaps the evidence (unsafe imports, an unprotected function from the disassembly, and the Java-side caller and input source).

#### Evaluation

The test **fails** for a library that contains C or C++ code with functions that would qualify for protection (local arrays, unsafe libc calls) and has no `__stack_chk_fail` import, or where the disassembly shows unprotected buffer-handling functions.

It **passes** (an expected false positive, as OWASP itself lists) when:

- the library is Dart AOT, Go or Rust (state which, with the evidence);
- the library is empty or nearly empty, or its functions have no stack buffers. OWASP's example is React Native's `libreact_utils.so`, `libreact_config.so` and `libreact_debug.so`, which are built with `-fstack-protector-strong` but contain nothing that qualifies;
- the import exists. A single import does not prove every function is protected, but per-function opt-outs are rare and only worth chasing for a specific security-critical function.

Note the coverage limitation in the report: a static check proves that SSP was on for the library, not that a particular function is protected.

#### Demo

*No OWASP demo exists for this test. This one is ours.* The legacy test MASTG-TEST-0044 used the MASTG's own sample app, where `libnative-lib.so` showed `canary true` and `libtool-checker.so` showed `canary false`. Our minimal version:

```text
// parser.c
#include <string.h>
#include <stdio.h>
int parse(const char *in) { char buf[64]; strcpy(buf, in); return puts(buf); }  // unbounded copy into a stack buffer
int add(int a, int b) { return a + b; }                                         // no buffer: never gets a canary
```

```bash
clang --target=aarch64-linux-android24 -O2 -fPIC -shared -fstack-protector-strong parser.c -o libnative-lib.so
clang --target=aarch64-linux-android24 -O2 -fPIC -shared -fno-stack-protector    parser.c -o liblegacy-parser.so
```

```text
$ readelf --dyn-syms -W libnative-lib.so | grep UND
     1: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND strcpy
     2: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND puts
     3: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND __stack_chk_fail
$ readelf --dyn-syms -W liblegacy-parser.so | grep -c __stack_chk_fail
0
```

`liblegacy-parser.so` fails: it has a function with a stack buffer filled by `strcpy` and no canary. The 32-bit build of `libnative-lib.so` would also import `__stack_chk_guard`. Had `parser.c` contained only `add()`, neither build would import `__stack_chk_fail`, and that is the false positive you have to rule out.

### GT-CODE-0045-1: RELRO, non-executable stack and FORTIFY in native libraries (Android)

*Guler Tech methodology — not an OWASP test.*

#### Overview

OWASP's Android tests stop at PIE and canaries. The same `readelf` run tells you three more things that matter for exploitability and that the legacy MASTG chapter and every scanner report: whether the GOT is read-only after loading (RELRO), whether the stack is non-executable (NX), and whether FORTIFY was applied to libc calls. All three are on by default with the current NDK and Clang, so a library that lacks them was built differently. That is useful information about the supply chain even before you decide on severity.

#### Prerequisites

Same as MASTG-TEST-0223: unpacked APK and splits, `readelf` or `llvm-readelf`.

#### Steps

1. Run the sweep and look at the `RELRO`, `NX` and `FORT` columns, or per library:

   ```bash
   f=app/lib/arm64-v8a/libfoo.so
   readelf -lW "$f" | grep -E 'GNU_RELRO|GNU_STACK'           # RELRO segment, stack flags
   readelf -dW "$f" | grep -E 'BIND_NOW|FLAGS'                 # BIND_NOW / FLAGS_1 NOW => full RELRO
   readelf --dyn-syms -W "$f" | grep -oE '__[a-z0-9_]+_chk' | grep -v stack | sort -u   # FORTIFY imports
   readelf --dyn-syms -W "$f" | grep -wE 'UND (strcpy|strcat|sprintf|vsprintf|gets|memcpy|memmove|read)'
   ```

2. For a `GNU_STACK` with `E`, find the cause, typically an assembly object without `.note.GNU-stack`. The library name and strings usually point to the bundled project (a crypto or codec library with hand-written assembly).

3. For libraries without RELRO or FORTIFY, record the build origin if you can tell: the `.comment` section often names the compiler (`readelf -p .comment "$f"`, e.g. `Android (…) clang version …` versus a GCC string), and the `.note.android.ident` note is present in NDK-built libraries (`readelf -n "$f"`).

#### Observation

Per library: RELRO (none / partial / full), NX (`RW` / `RWE` / missing `GNU_STACK`), FORTIFY imports, unsafe libc imports, and the `.comment` toolchain string where present.

#### Evaluation

- **Fail (RELRO)**: no `GNU_RELRO` segment. Partial RELRO (segment present, no `BIND_NOW`) is a weaker fail, worth a Low on a library that handles untrusted input and Info elsewhere.
- **Fail (NX)**: `GNU_STACK` with `E`, or no `GNU_STACK` header in a library built with GNU `ld`.
- **Fail (FORTIFY)**: imports of unsafe libc functions such as `strcpy`, `sprintf` or `memcpy` with no `__*_chk` imports at all. Treat this as supporting evidence that the library was built outside the NDK defaults, not as a separate finding of its own.
- **Not applicable**: Dart AOT `libapp.so` (no PLT/GOT, no libc calls, as Flutter documents), Go libraries.
- **Pass**: full RELRO, `GNU_STACK RW`, and either `_chk` imports or no unsafe libc imports.

#### Demo

```bash
# hardened (NDK-equivalent flags)
clang --target=aarch64-linux-android24 -O2 -fPIC -shared -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
      -Wl,-z,relro,-z,now -Wl,-z,noexecstack parser.c -o libnative-lib.so
# everything switched off
clang --target=aarch64-linux-android24 -O2 -fPIC -shared -fno-stack-protector \
      -Wl,-z,norelro -Wl,-z,lazy -Wl,-z,execstack parser.c -o liblegacy-parser.so
```

```text
$ readelf -lW liblegacy-parser.so | grep -E 'GNU_RELRO|GNU_STACK'
  GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RWE 0
$ readelf -lW libnative-lib.so | grep -E 'GNU_RELRO|GNU_STACK'
  GNU_RELRO      0x000440 0x0000000000020440 0x0000000000020440 0x000110 0x000bc0 R   0x1
  GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RW  0
```

With a C library that implements FORTIFY, the hardened build also imports `__strcpy_chk` instead of `strcpy` (in our glibc-based lab build: `__strcpy_chk` and `__vprintf_chk`). With bionic the exact set of `_chk` functions depends on the `minSdkVersion`.

### MASTG-TEST-0228: Position Independent Code (PIC) Not Enabled (iOS)

*OWASP test: [MASTG-TEST-0228](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0228/). Type: static.*

#### Overview

The test checks that the main executable has the `MH_PIE` flag, so the kernel loads it at a randomised address. It applies to `MH_EXECUTE` files only: the main binary, and by extension app extensions and Watch or App Clip executables. Frameworks and dylibs (`MH_DYLIB`) are always slid by dyld and never carry the flag. On any IPA built for `arm64` with a current Xcode this test passes. It exists for legacy builds and for projects with `LD_NO_PIE` or `GCC_DYNAMIC_NO_PIC` set.

#### Prerequisites

- The unpacked IPA ([MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/)). It does not have to be decrypted.
- [otool](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0060/) (macOS command line tools) or `llvm-otool`. Optionally [radare2](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/), as in OWASP's technique [MASTG-TECH-0118](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0118/).

#### Steps

1. Identify the executables:

   ```bash
   APP=$(ls -d app/Payload/*.app)
   EXE=$(plutil -extract CFBundleExecutable raw -o - "$APP/Info.plist")
   find "$APP" -name '*.appex' -maxdepth 2   # extensions have their own executables
   ```

2. Check the header flags of each one:

   ```bash
   otool -arch all -hv "$APP/$EXE"
   ```

3. Alternatively, in r2: `r2 "$APP/$EXE"`, then `i~pic`.

#### Observation

The `filetype` and `flags` columns of `otool -hv` for each executable (and each slice of a fat binary), or r2's `pic` line.

#### Evaluation

The test **fails** if an `MH_EXECUTE` binary lacks `PIE` in its flags (r2: `pic false`). The test **does not apply** to `MH_DYLIB` files. "PIE: False" for frameworks and dylibs in objection's `ios info binary` or similar tools is expected, not a finding.

#### Demo

*No OWASP demo exists for this test. This one is ours.* Lab build, default flags:

```text
$ otool -hv "Payload/Demo App.app/Demo App" | tail -1
MH_MAGIC_64    ARM64        ALL  0x00     EXECUTE    21       1864   NOUNDEFS DYLDLINK TWOLEVEL PIE
$ otool -hv "Payload/Demo App.app/Frameworks/Legacy.framework/Legacy" | tail -1
MH_MAGIC_64    ARM64        ALL  0x00       DYLIB    18       2008   NOUNDEFS DYLDLINK TWOLEVEL NO_REEXPORTED_DYLIBS
```

The executable passes. The framework has no `PIE` flag and is not in scope for the check. A failing executable would show `EXECUTE` without `PIE`, which the Xcode settings `LD_NO_PIE = YES` or `GCC_DYNAMIC_NO_PIC = YES` attempt to produce on older targets. Current Apple linkers produce PIE `arm64` executables regardless, so we could not reproduce a failing `arm64` sample.

### MASTG-TEST-0229: Stack Canaries Not Enabled (iOS)

*OWASP test: [MASTG-TEST-0229](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0229/). Type: static.*

#### Overview

The test checks that every binary containing C, C++ or Objective-C code (the main executable, frameworks, extensions) was built with stack-smashing protection. Clang enables `-fstack-protector` for Apple targets by default, so a miss usually means `-fno-stack-protector` in a vendor's build or in "Other C Flags". Pure Swift binaries can be skipped, as OWASP says, because Swift does not have the unchecked stack buffers that canaries protect, and import-based checks say little about Swift code either way.

> **Warning:** The OWASP test's evaluation says a binary fails if it does not contain "methods indicating stack canaries like `objc_autorelease` or `objc_retainAutorelease`". Those are ARC runtime functions, not stack-protector symbols. The correct indicators are `___stack_chk_fail` and `___stack_chk_guard`, which the legacy test MASTG-TEST-0087 and OWASP's own note in the same test also use.

#### Prerequisites

- Unpacked IPA; decryption not needed ([MASTG-TECH-0082](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0082/) for finding all bundled libraries).
- `nm`, `otool` (or `llvm-nm`, `llvm-otool`); optionally r2 or objection.
- For confirming a negative: a decrypted binary and a disassembler.

#### Steps

1. Enumerate the Mach-O files (the sweep does this) and classify the language of each:

   ```bash
   f="app/Payload/X.app/Frameworks/Vendor.framework/Vendor"
   nm -u "$f" | grep -cE '^_swift_'            # Swift runtime imports
   nm -u "$f" | grep -c '_objc_msgSend'        # Objective-C message sends
   otool -L "$f" | grep -E 'libswiftCore|libc\+\+'
   ```

2. Check for the canary imports in every binary that is not pure Swift:

   ```bash
   nm -u "$f" | grep -E '___stack_chk_(fail|guard)'
   otool -Iv "$f" | grep stack_chk
   ```

   In r2 (OWASP's technique MASTG-TECH-0118): `i~canary`. On a running app with [objection](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0074/) (repackaged with the Frida gadget, or on a jailbroken device): `ios info binary`, which prints PIE, ARC, Canary and Stack Exec per loaded image.

3. For a non-Swift binary without the imports, rule out "nothing to protect": count Objective-C classes (`otool -oV "$f" | grep -c 'name '`) and look for C buffer functions among the imports (`nm -u "$f" | grep -E '_(memcpy|strcpy|strcat|sprintf|vsprintf|strncpy)(_chk)?$'`, which also matches the fortified `___strcpy_chk` forms that Apple's SDK headers produce by default). A framework that is a thin Objective-C wrapper with no C buffers may legitimately have no canary.

4. For security-critical functions (a parser, a crypto routine, the code behind a URL handler), check the disassembly of the decrypted binary for the canary load and compare. As OWASP notes, the import only proves that SSP was on somewhere in the binary, and a statically linked library built without it can sit inside a binary that has the import.

#### Observation

Per Mach-O file: type, language mix, `___stack_chk_fail` / `___stack_chk_guard` present or absent, and for negatives the evidence of whether there is anything to protect.

#### Evaluation

- **Fail**: a binary containing C, C++ or Objective-C code with stack buffers or unsafe libc imports, but no `___stack_chk_fail` import.
- **Pass**: the import is present, or the binary is pure Swift.
- **Expected false positives** (pass, as OWASP lists): Flutter's `App.framework` (Dart AOT code), binaries where the compiler had nothing to protect (OWASP cites React Native libraries built with `-fstack-protector-strong` that contain no qualifying function).

#### Demo

*No OWASP demo exists for this test. This one is ours.* An MRR Objective-C framework built with `-fno-stack-protector` and containing a `strcpy` into a stack buffer:

```objectivec
// Legacy.m, compiled with -fno-objc-arc -fno-stack-protector
@implementation Legacy
+ (NSString *)name:(const char *)s {
    char b[64];
    strcpy(b, s);                                       // unbounded copy, no canary
    NSString *r = [[NSString alloc] initWithUTF8String:b];
    return [r autorelease];
}
@end
```

```text
$ nm -u "Payload/Demo App.app/Frameworks/Legacy.framework/Legacy" | grep -E 'stack_chk|strcpy|msgSend'
___strcpy_chk
_objc_msgSend
$ nm -u "Payload/Demo App.app/Demo App" | grep stack_chk
___stack_chk_fail
___stack_chk_guard
```

`Legacy` fails: Objective-C and C code, a string copy into a stack buffer and no canary. Note that the `strcpy` appears as `___strcpy_chk`: Apple's SDK headers (the macOS SDK in our lab) applied FORTIFY to a plain compile without any flag, which caught this particular overflow at run time but does not replace the canary for loops, `memcpy` with computed lengths or array indexing. The main binary passes.

### MASTG-TEST-0230: Automatic Reference Counting (ARC) Not Enabled (iOS)

*OWASP test: [MASTG-TEST-0230](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0230/). Type: static.*

#### Overview

The test checks that Objective-C code is compiled with ARC (`-fobjc-arc`, Xcode `CLANG_ENABLE_OBJC_ARC = YES`). Swift is always ARC and C/C++ is out of scope. In practice the test is about Objective-C frameworks from vendors and old Objective-C files in the app that were exempted with `-fno-objc-arc`. As explained in the Knowledge section, OWASP's indicator list (`objc_autorelease`, `objc_retainAutorelease`, `objc_release`, `objc_retain`) does not separate ARC from MRR in binaries built by recent Clang. Use the ARC-specific entry points instead.

#### Prerequisites

Same as MASTG-TEST-0229.

#### Steps

1. For each Mach-O file, list the Objective-C runtime imports:

   ```bash
   nm -u "$f" | grep -E '_objc_(msgSend|retain|release|autorelease|storeStrong|retainAutoreleasedReturnValue|claimAutoreleasedReturnValue|autoreleaseReturnValue)'
   ```

   OWASP's r2 equivalent: `is~release,retain`.

2. Classify:
   - ARC-specific imports present (`_objc_storeStrong`, `_objc_retainAutoreleasedReturnValue`, `_objc_claimAutoreleasedReturnValue`, `_objc_autoreleaseReturnValue`): **ARC in use**.
   - Swift binary (`_swift_*` imports, `libswiftCore`): **ARC by design**.
   - `_objc_msgSend` and Objective-C classes present (`otool -oV`), but none of the ARC-specific imports: **likely MRR**. Continue with step 3.
   - No Objective-C or Swift at all: **not applicable**.

3. Confirm a "likely MRR" binary. Look in the decrypted binary's disassembly for explicit retain/release patterns in methods that return objects. ARC methods returning a new object end with `objc_autoreleaseReturnValue`, while MRR code ends with `objc_autorelease` or a message send of `autorelease`. If you have the source, check `CLANG_ENABLE_OBJC_ARC` and per-file `-fno-objc-arc` flags (grep in the Knowledge section), and the `requires_arc` attribute in podspecs.

#### Observation

Per Mach-O file: language classification, the Objective-C runtime imports found, and for "likely MRR" binaries the confirming evidence (disassembly excerpt or build setting).

#### Evaluation

- **Fail**: a binary with Objective-C code compiled without ARC, shown by the absence of every ARC-specific import plus disassembly or build-setting evidence. Note which framework it is and whether the app or a vendor owns it.
- **Pass**: ARC-specific imports present, or Swift-only.
- **Limitation** (as OWASP notes): the result is per binary. A static library compiled without ARC inside an ARC main binary is invisible to this check, and only the source or the disassembly of the specific methods shows it.

#### Demo

*No OWASP demo exists for this test. This one is ours.* The same lab IPA. `Demo App` is compiled with `-fobjc-arc`, `Legacy.framework` with `-fno-objc-arc` (source above):

```text
$ nm -u "Payload/Demo App.app/Demo App" | grep -E '_objc_'
_objc_autoreleasePoolPop
_objc_autoreleasePoolPush
_objc_msgSend
_objc_retainAutoreleasedReturnValue
_objc_storeStrong
$ nm -u "Payload/Demo App.app/Frameworks/Legacy.framework/Legacy" | grep -E '_objc_'
_objc_autorelease
_objc_msgSend
```

`Legacy` fails, and it also shows why OWASP's indicator list is misleading: the MRR framework imports `_objc_autorelease`, one of the symbols OWASP treats as evidence of ARC. A second MRR file in our lab with explicit `[o retain]` and `[o release]` imported `_objc_retain` and `_objc_release`. The ARC binary is identified by `_objc_storeStrong` and `_objc_retainAutoreleasedReturnValue`.

## Secure implementation

### Android: NDK, CMake and ndk-build

Build native code with the NDK's own toolchain integration and do not remove its defaults. With the NDK CMake toolchain (`-DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake`, which Android Gradle Plugin uses for `externalNativeBuild`) you already get `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, PIE and full RELRO. Make them explicit for code that is also built outside Gradle:

```text
# CMakeLists.txt
target_compile_options(foo PRIVATE -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIC
                                   -Wformat -Werror=format-security)
target_link_options(foo PRIVATE -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack)
```

```text
# Android.mk / Application.mk (ndk-build)
LOCAL_CFLAGS  += -fstack-protector-strong -D_FORTIFY_SOURCE=2
LOCAL_LDFLAGS += -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
```

- For autotools, Bazel or vendor builds, pass the NDK Clang driver for the right target (`aarch64-linux-android<minSdk>-clang` from the NDK's `toolchains/llvm/prebuilt/<host>/bin/`) and the same flags. Follow the [Build System Maintainers Guide](https://android.googlesource.com/platform/ndk/+/master/docs/BuildSystemMaintainers.md).
- Assembly files need `.section .note.GNU-stack,"",%progbits` (or the linker flag `-z noexecstack`).
- Never use `-Wl,-z,notext` to "fix" text relocations. Rebuild the objects with `-fPIC`.
- Add the sweep script to CI with a policy: fail the build if a library has `TEXTREL`, `NX NO`, `RELRO NO`, or `CANARY no` without an approved exception (Dart, Go, Rust, a known-empty library).
- For third-party SDKs, include the hardening table in vendor due diligence, alongside the dependency scan from [MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/).
- Beyond the baseline, for libraries that parse untrusted input: consider MTE (`android:memtagMode="async"` for release on supported devices), fuzzing with ASan or HWASan builds in development, and Rust for new parsers.

### iOS: Xcode build settings

```text
// Release.xcconfig (or the target's Build Settings)
CLANG_ENABLE_OBJC_ARC = YES
GCC_DYNAMIC_NO_PIC = NO
LD_NO_PIE = NO
OTHER_CFLAGS = $(inherited) -fstack-protector-strong
```

- Remove `-fno-objc-arc` from Build Phases › Compile Sources. If a file cannot be converted yet, track it as technical debt with an owner.
- In podspecs keep `requires_arc` at its default (`true`). For vendor frameworks, ask for their build settings or check them with the sweep.
- `-fstack-protector-strong` is the recommendation. `-fstack-protector-all`, as MASTG-KNOW-0061 suggests, is not required and costs performance in every function.
- For apps that handle complex untrusted content in C, C++ or Objective-C, evaluate the **Enhanced Security** capability (pointer authentication via `arm64e`, typed allocators, stack zero-initialisation, C++ library hardening, hardware memory tagging on supported devices), following Apple's guidance to test thoroughly before shipping.
- For C++ code, set "Enable C++ Standard Library Hardening" (`CLANG_CXX_STANDARD_LIBRARY_HARDENING`) to the fast mode or stronger, using the value Xcode offers in the Build Settings editor.
- Keep Swift's runtime checks on: do not ship with `-Ounchecked`, and do not disable exclusivity enforcement.

## Rating findings

Rate on three things: **what the binary does** (parses network data, files from other apps, media, documents, or only internal constants), **how much is missing** (one mitigation or several), and **whether there is a known or demonstrated memory-corruption bug** in it. The attacker position is whatever can deliver input to that code: a malicious server or network attacker (MAS-ATTACK-0059 over the network, after TLS if pinning or validation is weak), a malicious file or link the user opens (one user interaction), or another app on the device through IPC. A missing mitigation never gives an attacker anything on its own, so it is never Critical by itself.

| Rating | Conditions |
|---|---|
| **Critical** | Not used for missing hardening alone. Rate the memory-corruption bug: a demonstrated or published (CVE) memory-corruption bug in a bundled library, reachable without user interaction from remote input, in a binary that also lacks canaries, NX or RELRO, is Critical, and the missing mitigations go into the finding as aggravating factors. |
| **High** | A known or demonstrated memory-corruption bug reachable from remote or IPC input with one user interaction, with missing mitigations; or a native library that parses remote content (protocol, media, document, image) and lacks several mitigations at once (no canary *and* no RELRO, or an executable stack), confirmed by disassembly. |
| **Medium** | A substantial C/C++ library that handles untrusted input (network data, files from shared storage, IPC payloads passed over JNI) without stack protection, or with an `RWE` stack, or with `TEXTREL` that loads on supported devices; Objective-C code under MRR that processes untrusted input; a non-PIE executable shipped for `minSdkVersion` < 21 that processes untrusted input. |
| **Low** | One mitigation missing (canary, full RELRO, FORTIFY) in a library whose input is mostly app-controlled; partial RELRO; Objective-C MRR code with no evident untrusted input; a non-PIE executable on `minSdkVersion` < 21 that only handles internal data. |
| **Info** | Expected false positives (Dart, Go, Rust, empty or buffer-free libraries, pure Swift); dylibs or frameworks reported as "not PIE"; MASTG-TEST-0222 for `minSdkVersion` ≥ 21; `TEXTREL` libraries that cannot load for the app's ABI or `targetSdkVersion`; absence of optional mitigations (CFI, MTE, PAC, Enhanced Security) as recommendations. |

Lower a level when the library is clearly not reachable in the release app (no `System.loadLibrary` call, no import from the main binary, an unused ABI). Raise a level when the affected library is also an outdated version with known memory-corruption CVEs ([MASWE-0044](/mobile/maswe-0044-dependencies-with-known-vulnerabilities/)), or when it runs in a privileged context (an accessibility service, a VPN service, a keyboard extension). In the report give the file path inside the package and the ABI or slice, the raw `readelf`, `otool` or `nm` lines that prove the gap, what feeds the library (Java call site or Objective-C caller), whether it is first-party or a vendor's, and the exact build flag or Xcode setting that fixes it.

## References

- OWASP MASWE: [MASWE-0045: Compiler-Provided Security Features Not Used](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0045/); related [MASWE-0044](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0044/), [MASWE-0049](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0049/), [MASWE-0050](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0050/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-CODE-3](https://mas.owasp.org/MASVS/controls/MASVS-CODE-3/), [MASVS-CODE-4](https://mas.owasp.org/MASVS/controls/MASVS-CODE-4/) (CC BY-SA 4.0)
- OWASP MASTG knowledge: [MASTG-KNOW-0006](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0006/), [MASTG-KNOW-0061](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CODE/MASTG-KNOW-0061/), [MASTG-KNOW-0005](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0005/), [MASTG-KNOW-0060](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CODE/MASTG-KNOW-0060/) (CC BY-SA 4.0)
- OWASP MASTG tests: [MASTG-TEST-0222](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0222/), [MASTG-TEST-0223](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0223/), [MASTG-TEST-0228](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0228/), [MASTG-TEST-0229](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0229/), [MASTG-TEST-0230](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0230/); legacy [MASTG-TEST-0044](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0044/), [MASTG-TEST-0043](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0043/), [MASTG-TEST-0087](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0087/), [MASTG-TEST-0086](https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0086/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0157](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0157/), [MASTG-TECH-0115](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0115/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0082](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0082/), [MASTG-TECH-0118](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0118/) (CC BY-SA 4.0)
- OWASP MASTG tools: [rabin2 (MASTG-TOOL-0129)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/), [radare2 for iOS (MASTG-TOOL-0073)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/), [objection for iOS (MASTG-TOOL-0074)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0074/), [objection (MASTG-TOOL-0038)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0038/), [otool (MASTG-TOOL-0060)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0060/), [Apktool (MASTG-TOOL-0011)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/) (CC BY-SA 4.0)
- Android: [Security enhancements by release](https://source.android.com/docs/security/enhancements), [NDK Build System Maintainers Guide](https://android.googlesource.com/platform/ndk/+/master/docs/BuildSystemMaintainers.md), [NDK CMake flags (`flags.cmake`)](https://android.googlesource.com/platform/ndk/+/refs/heads/main/build/cmake/flags.cmake), [Android changes for NDK developers (bionic)](https://android.googlesource.com/platform/bionic/+/main/android-changes-for-ndk-developers.md), [Risks: use of native code](https://developer.android.com/privacy-and-security/risks/use-of-native-code), [Arm Memory Tagging Extension](https://developer.android.com/ndk/guides/arm-mte), [HWASan](https://developer.android.com/ndk/guides/hwasan)
- LLVM/Clang: [Clang Linux driver (`Linux.cpp`)](https://github.com/llvm/llvm-project/blob/main/clang/lib/Driver/ToolChains/Linux.cpp), [Clang Darwin driver (`Darwin.h`)](https://github.com/llvm/llvm-project/blob/main/clang/lib/Driver/ToolChains/Darwin.h), [Clang Automatic Reference Counting specification](https://clang.llvm.org/docs/AutomaticReferenceCounting.html), [libc++ hardening modes](https://libcxx.llvm.org/Hardening.html)
- Apple: [Build settings reference](https://developer.apple.com/documentation/xcode/build-settings-reference), [Enabling enhanced security for your app](https://developer.apple.com/documentation/xcode/enabling-enhanced-security-for-your-app), [Transitioning to ARC release notes](https://developer.apple.com/library/archive/releasenotes/ObjectiveC/RN-TransitioningToARC/Introduction/Introduction.html), [Apple Platform Security: runtime process security](https://support.apple.com/en-gb/guide/security/sec15bfe098e/web)
- Flutter: [Security false positives](https://docs.flutter.dev/reference/security-false-positives); React Native: [issue 36870 on stack canaries](https://github.com/react/react-native/issues/36870)
- Background: [On iOS Binary Protections (SensePost)](https://sensepost.com/blog/2021/on-ios-binary-protections/), [Stack canaries – gingerly sidestepping the cage (SANS)](https://www.sans.org/blog/stack-canaries-gingerly-sidestepping-the-cage/), [ELF gABI specification](https://refspecs.linuxfoundation.org/elf/gabi4+/contents.html)
- CWE: [CWE-693](https://cwe.mitre.org/data/definitions/693.html) (our mapping; OWASP gives none)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
