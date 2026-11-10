---
title: "MASWE-0058: Runtime Code Integrity Not Verified"
date: 2026-11-10 20:07:00 +0000
subcategory: resilience
summary: "Testing whether Android and iOS apps notice hooks, injected code and in-memory patches and respond, with Frida tracing, RASP design and rating rules."
refs: [MASWE-0058, MASVS-RESILIENCE-2]
tags: [android, ios, masvs-resilience, runtime-integrity, hooking, rasp]
---

This note is part of our [MASVS-RESILIENCE guide](/mobile/masvs-resilience-resilience-testing-guide/) and covers OWASP [MASWE-0058](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0058/): an app that never checks whether its own code, or the code it calls, was changed while it runs. A correctly signed app that passed every install-time check can still be rewritten in memory a second after launch. Someone can redirect a function with a trampoline, rebind an imported symbol, swap an Objective-C method implementation, rewrite an ART method's entry point, or load a library the developer never shipped. Runtime integrity verification is the set of checks that look for those *modifications*. It is different from looking for the *tools* that make them (a process called `frida-server`, port 27042, a library with "gadget" in its name), which is [MASWE-0065](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/). The difference matters because tool artefacts can be renamed in minutes, but a hooked function has to look different from an unhooked one somewhere. Below you get the mechanisms on both platforms (the four OWASP Knowledge items, including RASP architecture), the two OWASP tests with their six demos, two tests of our own that tell integrity checks apart from artefact checks and measure how much effort a bypass costs, the three OWASP best practices, and how to rate what you find. As with every weakness in this series, these controls are defence in depth. They raise attacker cost on a device the attacker controls. They never replace the L1/L2 controls, and a client-side check whose result no server ever relies on will be bypassed eventually.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: Runtime Integrity Verification (MASTG-KNOW-0032)](#android-runtime-integrity-verification-mastg-know-0032)
  - [iOS: Source Code Integrity Checks (MASTG-KNOW-0140)](#ios-source-code-integrity-checks-mastg-know-0140)
  - [Android: Runtime Application Self-Protection (MASTG-KNOW-0118)](#android-runtime-application-self-protection-mastg-know-0118)
  - [Generic: Code Injection (MASTG-KNOW-0110)](#generic-code-injection-mastg-know-0110)
- [Tests](#tests)
  - [MASTG-TEST-0341: Runtime Use of Hook Detection Techniques (Android)](#mastg-test-0341-runtime-use-of-hook-detection-techniques-android)
  - [MASTG-TEST-0354: Runtime Use of Hook Detection Techniques (iOS)](#mastg-test-0354-runtime-use-of-hook-detection-techniques-ios)
  - [GT-RES-0058-1: Static inventory of runtime integrity checks (Android and iOS)](#gt-res-0058-1-static-inventory-of-runtime-integrity-checks-android-and-ios)
  - [GT-RES-0058-2: Integrity checks versus artefact checks, and bypass effort (Android and iOS)](#gt-res-0058-2-integrity-checks-versus-artefact-checks-and-bypass-effort-android-and-ios)
- [Best practices](#best-practices)
  - [MASTG-BEST-0041: Hardening Against Runtime Hooking (Android)](#mastg-best-0041-hardening-against-runtime-hooking-android)
  - [MASTG-BEST-0048: Hardening Against Reverse Engineering Tools (iOS)](#mastg-best-0048-hardening-against-reverse-engineering-tools-ios)
  - [MASTG-BEST-0067: Implementing Source Code Integrity Checks on iOS](#mastg-best-0067-implementing-source-code-integrity-checks-on-ios)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

OWASP states the requirement as *"The app detects unauthorized changes to its code and execution flow at runtime."* The weakness maps to MASVS-RESILIENCE-2 ("The app implements anti-tampering mechanisms") and to the v1 requirement MSTG-RESILIENCE-6. OWASP gives no CWE. If your report template needs one, [CWE-693](https://cwe.mitre.org/data/definitions/693.html) (Protection Mechanism Failure) is the closest fit, and it is our mapping, not OWASP's.

The threat is MAS-THREAT-0058, *"Attackers can modify the app's code while it runs"*, reached through two attacks: MAS-ATTACK-0002 (debugging the app at runtime) and MAS-ATTACK-0003 (using dynamic instrumentation). The weakness carries OWASP's **R** profile (plus EUDIW). It applies to apps whose threat model includes reverse engineering and tampering on a device the attacker controls: banking and payments, wallets, DRM, competitive games, apps that hold valuable IP. For an L1/L2-only assessment it is out of scope, and a missing check is at most an observation.

OWASP's overview frames the weakness as an app "running in an unsafe environment (rooted or jailbroken device)". That is the common case, but not the only one. An attacker can also repackage the app with Frida Gadget and run it on a stock device ([MASTG-TECH-0026](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0026/) on Android). OWASP's own BEST-0041 makes this point. Runtime integrity checks are the layer that still has something to say in that case, because root detection has nothing to find.

### What "runtime code integrity" covers

Every hooking technique changes something you can check. The table lists the modifications, how a hooking framework makes each one, and where a check would look. It is the map for the rest of this note.

| Modification | Typical mechanism | What an integrity check inspects |
|---|---|---|
| Inline hook on a native function | First instructions overwritten with a branch to a trampoline (Frida Interceptor, Substrate/ElleKit `MSHookFunction`, Dobby) | Function prologue bytes, compared with a known-good copy or scanned for branch patterns; checksum of the code section |
| Imported symbol rebinding | GOT/PLT slot overwritten on Android (xHook, bhook), lazy or non-lazy symbol pointer rewritten on iOS (fishhook) | Each slot resolves into the image that should export the symbol |
| Java method hook | The method's `ArtMethod` entry point and access flags rewritten (Frida's Java bridge, Xposed/LSPosed via LSPlant) | Entry points fall in OAT, interpreter, JNI stub or JIT regions; `native` flag on a method that is not native in the DEX |
| Objective-C method hook | `method_setImplementation` / `method_exchangeImplementations` (swizzling), or the `ObjC` bridge in Frida | `method_getImplementation()` resolves (via `dladdr`) into the image that defines the class |
| Injected library or code | A shared library loaded into the process, or anonymous executable memory | Loaded-image list or `/proc/self/maps` against an allowlist of expected paths; executable regions with no backing image |
| Patched code or data | `mprotect` + write, or a patched binary loaded in place of the original | Checksums over `.text` / `__TEXT,__text`, and over read-only-after-relocation data |

What it does *not* cover, and where that lives:

| Question | Where it lives |
|---|---|
| Is the app's code and memory modified at runtime? | This note (MASWE-0058) |
| Is a known tool present: `frida-server`, port 27042, `frida-agent` or `FridaGadget` names, `gum-js-loop` threads, Xposed packages? | [MASWE-0065](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/) |
| Was the package re-signed or repackaged? Does the server know it is talking to the genuine app? | [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/) |
| Were files, resources or stored data modified? | [MASWE-0057](/mobile/maswe-0057-app-resources-integrity-not-verified/) |
| Is a debugger attached? | [MASWE-0064](/mobile/maswe-0064-debugger-detection-not-implemented/) |
| Is the device rooted or jailbroken? | [MASWE-0051](/mobile/maswe-0051-root-jailbreak-detection-not-implemented/) |

The line between this note and MASWE-0065 is blurred in OWASP's own material: both "passing" demos for the tests linked to this weakness detect tool artefacts, not modifications. We point this out where the tests are documented below, because it changes how you write up a "pass".

## Modes of Introduction

**No runtime integrity checks at all.** The app relies on install-time code signing and, at best, a root check. Nothing looks at the code once it is running. This is the most common case outside banking and games.

**Only artefact checks.** The app looks for `frida` in `/proc/self/maps`, probes port 27042, or walks `_dyld_get_image_name()` for "FridaGadget", and calls that "hook detection". Each of these is a reasonable tripwire, but none of them notices a hook made by a renamed or custom tool. On iOS, frida-server's injected agent is not even in dyld's image list (see BEST-0048 below).

**Checks that do not cover what attackers hook.** A `__text` hash covers the app's own binary, but the sensitive call (`CCCrypt`, `SecItemCopyMatching`, `Cipher.doFinal`) runs inside a system library or the framework. A `.text` checksum of `libapp.so` says nothing about a Java hook on `Cipher.doFinal`, because Java hooks do not change native code.

**Checks in the wrong place or at the wrong time.** A single `detectHooking()` in `Application.onCreate()` or `application(_:didFinishLaunchingWithOptions:)` misses an attacker who attaches after start-up. A check written in Kotlin or Swift as one named method is a one-line hook away from returning `false`.

**Detection without a response, or with a response nobody acts on.** The check runs and logs an event, but the app carries on, or it sends a flag that the backend never reads.

**Fragile checks that get switched off.** An overly broad check flags the ART JIT cache, an APM SDK's own PLT hooks or a WebView's memory, users complain, and the check is disabled in the next release.

## Impact

- **Bypass of client-side protections.** Root, jailbreak, debugger, pinning, licence and integrity checks are all functions. If nothing notices them being hooked, each one costs an attacker one hook. This is the impact that matters most for an R-profile app: the remaining RESILIENCE controls are only as strong as the app's ability to notice that they were tampered with.
- **Exposure of data in transit through the app.** Hooks on cryptographic, Keychain/Keystore, database and networking APIs see plaintext, keys in use and tokens. On the device owner's own device that is mostly a reverse-engineering aid. It becomes a real loss when the data is not the device owner's to see: DRM content keys, a licence secret shared by every install, an API signing secret, or another party's data in a multi-user or kiosk setting.
- **Abuse of business logic.** Changing the return value of `isPremium()`, the amount passed to a signing routine, or a game's score submission turns a client-side decision into fraud, cheating or free content, unless the server re-checks it.
- **Automation at scale.** A hooked genuine app is a convenient bot: it carries valid attestation tokens and device fingerprints, while the attacker drives it from a script. That is why integrity signals matter more on account-creation, promotion and payment flows.

## Mitigations

- **Check the code, not just the environment.** Verify that security-critical functions (your own and the platform APIs you depend on) have unmodified prologues, that imported symbols and Objective-C implementations resolve into the expected images, that there are no unexpected executable mappings or images, and that your own code segments match a reference hash.
- **Check where it matters and more than once.** Run checks before each sensitive operation, at random intervals and from several call sites, not only at start-up. Inline them so there is no single function to hook.
- **Implement checks natively and avoid hookable plumbing.** Do the work in C/C++, read `/proc/self/maps` with direct system calls rather than through `BufferedReader` or `fopen`, and protect the checks with obfuscation ([MASWE-0059](/mobile/maswe-0059-code-obfuscation-not-implemented/)).
- **Respond in a way that helps the server.** Terminate, degrade or wipe locally if you must, but above all report to the backend, and let the backend decide on high-risk transactions together with attestation ([MASWE-0054](/mobile/maswe-0054-device-attestation-not-implemented/), [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/)).
- **Test against current tooling every release.** Hooking frameworks change their trampolines, injection methods and artefacts. A check that worked against last year's Frida may not work against this year's.

## Knowledge

OWASP does not link Knowledge pages from the weakness itself. We assign four to this note by topic: MASTG-KNOW-0032 (Android runtime integrity verification), MASTG-KNOW-0140 (iOS source code integrity checks), MASTG-KNOW-0118 (RASP) and, as a summary, MASTG-KNOW-0110 (code injection). The artefact-based pages MASTG-KNOW-0030 (Android) and MASTG-KNOW-0087 (iOS) belong to [MASWE-0065](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/). They come up below where OWASP's tests use them.

### Android: Runtime Integrity Verification (MASTG-KNOW-0032)

Source: [MASTG-KNOW-0032](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0032/).

OWASP groups Android runtime integrity checks by the question they answer:

| Question | Category | Checks |
|---|---|---|
| Did an indirect call target change? | Control flow integrity | PLT/GOT slot verification, vtable verification, ART entry-point verification |
| Did executable code or protected data change? | Code integrity | Memory checksums, inline hook detection |
| Was new executable code loaded into the process? | Code injection detection | Library and executable-mapping validation |
| Was the runtime modified by a hooking framework? | Framework modification | Xposed/LSPosed class and hook detection |

#### Reading the process memory map

Almost every Android check starts from [`/proc/self/maps`](https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html), which any process can read about itself. Each line is one mapping: address range, permissions (`r`, `w`, `x`, `p`rivate or `s`hared), file offset, device, inode and path. You can look at it for the app under test:

```bash
adb shell pidof com.example.app
adb shell su -c 'cat /proc/<pid>/maps' | grep -E ' (r-xp|rwxp) '
```

What a normal app process contains, so you know what not to flag (illustrative, paths shortened):

```text
7a1c200000-7a1c2c4000 r-xp 00000000 fd:05 1234   /apex/com.android.runtime/lib64/bionic/libc.so
7a0e400000-7a0e55c000 r-xp 0012c000 fd:21 5678   /data/app/~~Xy==/com.example.app-Ab==/split_config.arm64_v8a.apk
7a00a00000-7a00b00000 r-xp 00000000 00:01 9012   /memfd:jit-cache (deleted)
7a2f1f0000-7a2f1f1000 r-xp 00000000 00:00 0      [vdso]
```

Three things in that output surprise people:

- **Native libraries loaded straight from the APK.** When native libraries are stored uncompressed and not extracted (`android:extractNativeLibs="false"`, the default in current Android Gradle Plugin versions for `minSdk` 23 and higher), the mapping shows the APK or split APK path with a non-zero file offset, not `lib/arm64-v8a/libfoo.so`. An allowlist keyed on `.so` paths will miss your own libraries and flag them as "unknown".
- **The ART JIT code cache.** ART keeps JIT-compiled code in executable memory that is backed by a memfd (`/memfd:jit-cache (deleted)`, and `jit-zygote-cache` for code shared from zygote) or, on older versions, an anonymous `dalvik-jit-code-cache` region. The exact names vary by Android version. These are executable, deleted or anonymous, and completely legitimate.
- **System code from APEX modules.** Since Android 10, `libc.so`, `libart.so` and friends live under `/apex/...`, not `/system/lib64`.

Now compare with what OWASP recorded in [MASTG-DEMO-0108](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0108/MASTG-DEMO-0108/) for a process with the Frida agent loaded (recent Frida maps its agent from a memfd):

```text
6d6a352000-6d6b092000 r-xp 00946000 00:01 188   /memfd:frida-agent-64.so (deleted)
```

A name check looks for "frida" in that line. An integrity check asks a different question: *is this executable mapping one of the ones I expect?* A deleted, memfd-backed executable mapping that is not the JIT cache is suspicious whatever it is called.

OWASP also suggests using permissions as a pre-filter. Code mappings are `r-xp` and never writable, so a `rwxp` mapping, or a library's `.data.rel.ro`/GOT region that is writable after start-up when it should be read-only after relocation, means someone called `mprotect` on it. Ordinary `rw-p` data mappings are normal and should not be flagged on their own.

#### Control flow integrity: PLT/GOT, vtables and ART entry points

All three checks look for the same thing: a pointer in an indirection table that was overwritten to send control flow somewhere else.

**PLT/GOT.** A native library calls imported functions (`open`, `read`, `strcmp`, `SSL_write`) through its Global Offset Table. The bionic linker fills the GOT when it loads the library and, as far as the bionic source history shows, never did lazy binding, so every slot holds a resolved address from the start. With full RELRO, the NDK default (`-Wl,-z,relro,-z,now`), the GOT is read-only after relocation. A PLT hook (xHook, ByteDance's bhook) overwrites a slot to point to its own function, which needs an `mprotect` first. To check, the library parses its own ELF dynamic section (`dl_iterate_phdr()` gives you the load address and program headers), walks the `DT_JMPREL` jump-slot relocations, reads each GOT slot and verifies that the address falls inside the library that should export that symbol (`dladdr()` on the slot value, or a range check against `/proc/self/maps`).

**Vtables.** C++ virtual dispatch goes through vtables, which compilers place in relocation read-only sections such as `.data.rel.ro`. The linker writes them during relocation and then makes them read-only, just like the GOT. Overwriting a vtable entry again needs `mprotect`. Detection is the same walk: every entry should point into an expected executable mapping.

**ART entry points.** Every Java or Kotlin method in memory is an `ArtMethod` structure. Its fields include `access_flags_` and `entry_point_from_quick_compiled_code_`, plus a `data_` field that holds the JNI entry point for native methods. Older ART versions (Android 6 and earlier) also had `entry_point_from_interpreter_`, which OWASP lists, but later versions removed it. Java hooking engines work by rewriting these fields. Frida's Java bridge, for example, reroutes a hooked method through a JNI-style trampoline into its own code, and Xposed-style engines redirect the entry point to a bridge. Detection options:

- **Entry-point range checks.** Verify that `entry_point_from_quick_compiled_code_` of each sensitive method points into the app's OAT/ODEX file, the interpreter bridge, a JNI stub or the JIT code cache, not into an anonymous or foreign mapping.
- **`kAccNative` (0x0100) on methods that are not native in the DEX.** Engines that turn a hooked method into a JNI method set this flag. On Android, `Class.getDeclaredMethod()` builds the `Method` object from the current `ArtMethod`, so a Java-side `Modifier.isNative(method.modifiers)` on a method you know is not native is a cheap version of this check. It catches engines that set the flag. Others only swap the entry point, so verify the check against the specific tools you care about.
- **Trampoline signatures** at the entry point, as with native inline hooks.

The hard part is reaching the `ArtMethod`. There is no public API for it. `FromReflectedMethod` returns a `jmethodID` that is *often* an `ArtMethod*`, but ART can use opaque, index-based JNI IDs, so it is not guaranteed. The structure's layout also changes between Android versions, so offsets have to be tracked per version. OWASP's KNOW-0032 says this clearly. OWASP's BEST-0041 recommends `FromReflectedMethod` without the caveat. Treat this check as brittle: maintain it per Android version, fail safe (report, do not crash) when the layout is unknown, and test it on every new Android release.

#### Code integrity: text checksums and inline hook detection

**Memory checksums.** At build time, record a hash of each security-critical code range (a whole `.text` section or individual functions). At runtime, locate the loaded range, hash it and compare. On Android arm64, `.text` contains no relocations (text relocations are forbidden for 64-bit code), so the in-memory bytes of your own library should equal the bytes in the file. That gives you two references:

- the hash embedded at build time, which catches both on-disk patching (a repackaged APK) and in-memory patching;
- the bytes of the same library on disk, which you can read from the APK (or from `/apex/com.android.runtime/lib64/bionic/libc.so` for libc). This comparison catches in-memory patching even when you cannot predict the reference, which is the case for system libraries that differ per device and patch level.

Ranges that contain relocations, pointers or anything patched legitimately at runtime must be excluded or normalised, or you will produce false positives. The obvious bypasses are to hook the hash function, patch the comparison, or patch the stored reference. That is why checksums need to be duplicated, inlined and obfuscated.

**Inline hook detection.** Most native hooking engines overwrite the first instructions of the target with a branch to a trampoline. On ARM64 the classic long-range form loads a 64-bit absolute address into a scratch register and branches to it:

```text
50 00 00 58    LDR  X16, #8        ; load the 8-byte literal that follows
00 02 1F D6    BR   X16
xx xx xx xx    <absolute target, low word>
xx xx xx xx    <absolute target, high word>
```

X16 and X17 are the intra-procedure-call scratch registers in the [AAPCS64](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst), which is why trampolines use them. Engines also use shorter forms when the trampoline is within range, such as a single `B` (±128 MB) or an `ADRP`/`ADD`/`BR` sequence. So do not look only for the 16-byte pattern. A robust prologue check does two things:

1. compares the first 16 to 32 bytes of each critical function with a known-good copy (build-time constant for your own code, on-disk bytes for system libraries);
2. if they differ or cannot be compared, decodes the first instructions and flags any unconditional branch whose target is outside the function's own library.

The [O-MVLL anti-hook pass](https://obfuscator.re/omvll/passes/anti-hook/) takes a preventive angle: it inserts prologues that use X16/X17 themselves, which breaks Frida's Interceptor on those functions. It is effective against stock Frida but not against a modified build that uses other registers. ARM32/Thumb code uses different patterns (for example `LDR PC, [PC, #-4]`) and has to be checked separately if you still ship 32-bit libraries.

#### Injected code and unexpected executable mappings

Injected code has to be mapped executable somewhere. OWASP lists three approaches, all built on `/proc/self/maps`:

- **Path validation.** Flag executable mappings from writable or unexpected locations: `/data/local/tmp`, the app's own `files/` or `cache/` directories, extraction directories.
- **Allowlisting.** Compare every executable mapping with the set you expect: your APK and splits, any dynamic feature modules, `/system`, `/system_ext`, `/vendor`, `/product`, `/apex`, `[vdso]` and the JIT cache. Keep the list per ABI and Android version, because system and APEX paths change.
- **Executable-mapping validation.** Flag anonymous executable mappings, deleted file-backed ones and `rwx` ones, except the known JIT cache names.

None of this relies on a tool's name, which is what makes it an integrity check rather than an artefact check. Its weak point is how the map is read. If the check reads `/proc/self/maps` through `java.io.BufferedReader`, or through libc `fopen`/`fgets`, an attacker can filter the lines before your code sees them. That is exactly what MASTG-DEMO-0108 does (described under the test below). Reading with `openat` and `read` issued as raw system calls from native code removes the easy interception points. It does not remove the possibility of patching your code instead.

Some legitimate software also adds executable code to your process: JIT-based JavaScript engines bundled with the app, APM and crash-reporting SDKs that install their own PLT hooks, accessibility and enterprise-management components on managed devices. Profile a clean build on several devices before you decide what to flag.

#### Xposed and LSPosed runtime modification

Xposed-compatible frameworks inject their bridge into the app's class loader at process start. The classic check looks for `de.robv.android.xposed.XposedBridge` through the app's class loader. LSPosed forks still provide that legacy API for old modules. The modern LSPosed API uses different entry points (modules declare `META-INF/xposed/java_init.list` and `native_init.list`), so a complete check needs probes for the newer class names as well. OWASP's KNOW-0032 shows a native routine that finds `XposedBridge`, disables it and clears registered hooks. Note that a class-name probe is closer to artefact detection. The integrity checks above (entry points, `kAccNative`) catch the effect of an LSPosed hook whatever the framework's classes are called. Installed-package and file checks for these frameworks belong to [MASWE-0065](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/).

#### How Android checks are defeated, in general terms

OWASP is candid that runtime integrity checking is a cat-and-mouse game, and that a determined attacker on a rooted device usually wins. The standard moves are: hook the check's inputs (the file read of `/proc/self/maps`, `dladdr`, `dl_iterate_phdr`), hook or patch the check itself so it returns "clean", restore the original bytes while the check runs and re-apply the hook afterwards, hook at a level the app cannot see (a kernel module, or a hook installed in zygote before the app's code runs), or use instrumentation that does not patch code at all (Frida's Stalker, hardware breakpoints). None of this makes the checks pointless. It means their value is in the effort they force and in the signal they give the server, not in a guarantee.

### iOS: Source Code Integrity Checks (MASTG-KNOW-0140)

Source: [MASTG-KNOW-0140](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0140/).

iOS verifies an app's code signature before launch and, on stock devices, enforces it page by page at runtime: a signed code page that changes is no longer valid, and the kernel kills the process when it is used. That is what makes runtime code patching on a stock device hard. On a jailbroken device the enforcement is weakened so that tweaks and Frida can patch code, and a re-signed app with an embedded Gadget carries its own valid signature. App-level integrity checks are for those two cases.

#### Hashing the code section at runtime

KNOW-0140 describes the classic approach:

1. use `dladdr()` on a symbol inside the app to find the Mach-O header of the loaded executable (`Dl_info.dli_fbase`);
2. walk the `mach_header_64` load commands to the `LC_SEGMENT_64` named `__TEXT` and its `section_64` named `__text`;
3. hash the section with `CC_SHA256` and compare with a stored reference value.

The core of OWASP's Swift example (64-bit structures only, which is all modern iOS uses):

```swift
// anchorAddress: the address of any function in the app, as in OWASP's @_cdecl anchor
var info = Dl_info()
guard dladdr(anchorAddress, &info) != 0, let fbase = info.dli_fbase else { return false }
let base = UnsafeRawPointer(fbase)
let header = base.load(as: mach_header_64.self)
var offset = MemoryLayout<mach_header_64>.size
for _ in 0..<Int(header.ncmds) {
    let cmd = base.load(fromByteOffset: offset, as: load_command.self)
    if cmd.cmd == LC_SEGMENT_64 {
        let seg = base.load(fromByteOffset: offset, as: segment_command_64.self)
        // ...find sectname "__text" inside segname "__TEXT", then:
        // let code = base.advanced(by: Int(sec.addr - seg.vmaddr)); hash Int(sec.size) bytes
    }
    offset += Int(cmd.cmdsize)
}
```

`sec.addr - seg.vmaddr` is the offset of `__text` inside `__TEXT`. Because `dli_fbase` is already the slid address of the header, which is where `__TEXT` starts, you do not need the ASLR slide. Two practical points OWASP leaves implicit:

- **Where the reference hash lives.** The hash covers `__text`, so the value must sit outside it, for example in `__TEXT,__const` or a data section. A build step can then patch it in after linking and before code signing (an Xcode Run Script phase runs before the final CodeSign step). Compute it per architecture slice.
- **App Store encryption does not get in the way.** FairPlay encrypts part of `__TEXT` on disk, but the check reads the decrypted pages in memory. Those match the hash computed from the unencrypted build.

#### What the hash does and does not catch

A `__text` hash catches patches to the app's own executable: a binary patched on disk and re-signed, and inline hooks that Frida's Interceptor or ElleKit place on functions *in the main executable*. It does not catch:

- hooks in frameworks you embed (`Frameworks/*.framework`, `*.dylib`): hash those separately;
- hooks in system libraries such as `libcommonCrypto.dylib` (where `CCCrypt` lives), `Security.framework` or `Foundation`, which come from the dyld shared cache. That is where MASTG-TEST-0354's example hooks are;
- Objective-C swizzling and symbol rebinding, which change data (method lists, symbol pointers), not `__text`;
- a pure re-sign with no code change. KNOW-0140 says the check helps detect "re-signed binaries", but re-signing does not touch `__text`. Use the signing identity and App Attest for that ([MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/)).

#### Beyond the code hash: swizzling, rebinding, inline hooks and injected images

These checks fill the gaps above, and they are what MASWE-0058 asks for on iOS.

**Objective-C implementation ownership.** Take the method you care about (`class_getInstanceMethod(cls, sel)` or `class_getClassMethod`), get its `IMP` with `method_getImplementation()`, and resolve it with `dladdr()`. The image that owns the IMP should be the image that defines the class: your executable for your classes, `/System/Library/Frameworks/LocalAuthentication.framework/LocalAuthentication` for `LAContext`, and so on. A swizzled or bridged IMP resolves into a tweak dylib, the Frida agent, or nothing at all (anonymous memory).

```objectivec
#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#if __has_feature(ptrauth_calls)
#import <ptrauth.h>
#endif

// YES if -[cls sel] is implemented by the image whose Mach-O header is `expectedHeader`.
static BOOL impOwnedBy(Class cls, SEL sel, const void *expectedHeader) {
    Method m = class_getInstanceMethod(cls, sel);
    if (m == NULL) return NO;
    const void *imp = (const void *)method_getImplementation(m);
#if __has_feature(ptrauth_calls)
    imp = ptrauth_strip(imp, ptrauth_key_function_pointer);
#endif
    Dl_info info;
    if (dladdr(imp, &info) == 0) return NO;          // not in any loaded image: anonymous memory
    return info.dli_fbase == expectedHeader;
}

// Example: a method of your own class must live in the main executable (image 0).
// impOwnedBy([PaymentSigner class], @selector(signPayload:), _dyld_get_image_header(0));
```

**C function ownership (symbol rebinding).** Taking the address of an imported function in your code normally goes through a symbol pointer that dyld bound (and that rebinding tools rewrite along with the call stubs' pointers), so `dladdr((void *)CCCrypt, &info)` tells you which image the pointer currently resolves to. It should be `/usr/lib/system/libcommonCrypto.dylib`. If fishhook-style rebinding replaced the pointer, it resolves elsewhere.

**Inline hooks on system functions.** Rebinding leaves the target's code alone, Interceptor does not: `dladdr` on a function with an inline hook still reports the right library, because the address has not changed. Its first instructions have. Read the first few instructions and flag the trampoline shapes described in the Android section (`LDR X16/X17, literal` + `BR X16/X17`, or a `B`/`BR` whose target `dladdr` resolves outside the function's image). For `arm64e` code, which most system libraries are, the genuine prologue usually begins with `PACIBSP` (`7F 23 03 D5`). Reference prologues differ between iOS versions, so pattern checks are more practical than exact comparisons for system code.

**Injected images.** `_dyld_image_count()` and `_dyld_get_image_name()` list the images dyld knows about. Instead of searching for bad names (the MASWE-0065 approach), allowlist good locations: the app bundle, `/System/Library/`, `/usr/lib/` and, where they apply, `/Developer/` paths on development devices. A dylib loaded from `/var/jb/...` (rootless jailbreaks), `/Library/MobileSubstrate/...` or a writable container path stands out whatever its name. You can also register `_dyld_register_func_for_add_image()` to see images that are loaded later. This catches Frida Gadget and anything loaded through dyld. It does **not** catch frida-server's injected agent, which Frida maps with its own Mach-O loader and never registers with dyld (BEST-0048 and KNOW-0087 say so). For that case, walk your own address space with `vm_region_recurse_64()` and flag executable regions that no dyld image accounts for. A normal App Store app has no executable memory outside signed images (third-party apps do not get JIT), so an unbacked `r-x` region is a strong signal.

#### How iOS checks are defeated, in general terms

The same moves as on Android: patch the stored hash or the comparison, hook `dladdr`, `_dyld_get_image_name` or `CC_SHA256` to return clean answers, hook the check function itself, or move the instrumentation to where the check does not look. KNOW-0140 and BEST-0067 say plainly that these checks are bypassable on jailbroken devices and should be treated as cost-raising, not as guarantees.

### Android: Runtime Application Self-Protection (MASTG-KNOW-0118)

Source: [MASTG-KNOW-0118](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0118/). OWASP files this page under Android, but everything in it applies to iOS too.

Runtime Application Self-Protection (RASP) is the umbrella term for protections that run inside the app and watch its own execution: root and emulator detection, debugger detection, tool detection, runtime integrity, anti-tampering, and the logic that decides what to do about a detection. Runtime integrity checks are one input to RASP, and RASP is how they become useful.

#### Architecture: sensors, policy, response, telemetry

A RASP implementation that holds up in a test has four parts, whether it is home-grown or bought:

| Part | What it does | What goes wrong |
|---|---|---|
| **Sensors** | Individual checks: prologue scans, mapping allowlists, ART/IMP ownership, code hashes, root and debugger signals, attestation results | Only one or two sensors, all artefact-based, all in Java/Swift |
| **Policy** | Combines sensor results into a decision, with weights (a renamed binary in `/data/local/tmp` is weaker evidence than a trampoline on `Cipher.doFinal`) | One boolean `isCompromised()`, which is the single point to hook |
| **Response** | Acts locally: block a feature, wipe secrets, terminate, require step-up | Immediate `exit(0)` at the moment of detection, which tells the attacker exactly where the check is |
| **Telemetry** | Tells the backend what was seen, bound to the session or transaction | Nothing sent, or a flag the server never reads |

The policy is best kept partly on the server. The app reports raw or lightly summarised signals, and the backend decides per operation, so that "suspicious device, browsing" and "suspicious device, transferring money" can get different answers.

#### Self-built, SDK and compiler-based RASP

OWASP distinguishes three ways to get RASP:

- **Self-implemented checks** based on the Knowledge pages in this series (root: KNOW-0027 and KNOW-0031, tools: KNOW-0030, runtime integrity: KNOW-0032, files: KNOW-0029). Cheap and transparent. Usually too centralised and too easy to find, unless the team invests in native code and obfuscation.
- **Commercial SDKs.** A library the app calls into. They bring maintained, obfuscated native checks and a telemetry backend. The weakness is structural: the app has to call out to the SDK and act on the answer, and that call and the code that acts on it are hookable boundaries in the app's own code.
- **Commercial compiler-based tools.** They inject checks into the app's own code at build time and obfuscate the result differently on every build. There is no single SDK boundary to hook, and checks move between releases.

KNOW-0118 also lists the Play Integrity API as a RASP component. Strictly, Play Integrity is attestation, not self-protection: Google's servers tell yours whether the binary is the one Play distributed (`appIntegrity`), whether the device passes integrity checks (`deviceIntegrity`), and optionally whether risky apps are running (`appAccessRiskVerdict`). It does not see runtime hooks inside a genuine app on a device that passes. It is still the right partner for runtime checks, because it gives the server a signal the client cannot simply leave out. The details are in [MASWE-0054](/mobile/maswe-0054-device-attestation-not-implemented/) and [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/). The iOS counterpart is App Attest.

#### Response strategies

| Response | Good for | Watch out for |
|---|---|---|
| Terminate the process | Stopping casual analysis | It shows the attacker where the check is, frustrates users on false positives, and does nothing server-side |
| Degrade: disable the sensitive feature, keep the rest | Payments, card display, key export | The decision must not be a single boolean that can be hooked back to `true` |
| Wipe local secrets and keys, force re-enrolment | Wallets, apps that hold device-bound credentials | Make sure the wipe covers Keystore/Keychain entries, not only preferences |
| Step-up authentication | Banking flows | Step-up has to be enforced server-side |
| Delayed or randomised reaction | Making the check harder to locate | Harder to support and debug, so document it for your own support team |
| Silent reporting only | Fraud analytics, games (to ban in waves) | Useful only if someone acts on the data |

OWASP's best practices (below) recommend terminating, clearing sensitive data and alerting the backend. In practice, the backend alert is the response that survives a bypass of the local reaction. A local response can always be patched out on a device the attacker controls.

#### Server-side signals

A tamper flag sent by the client has one property to keep in mind: an attacker who controls the app can suppress it. So the server must not treat "no tamper flag received" as "clean". Workable patterns:

- **Require positive evidence for high-risk operations.** Bind the operation to an attestation (a Play Integrity token whose `requestHash` covers the transaction, or an App Attest assertion over the request) and make the absence of a valid attestation the failure case, not the presence of a flag.
- **Treat RASP signals as risk inputs.** Combine them with attestation verdicts, velocity, device history and behaviour, and decide per operation.
- **Check for silence.** A build that should report a heartbeat with its sensor summary and stops doing so on a given account or device is itself a signal.
- **Make the signal costly to forge.** Sign or MAC the RASP report with a key generated in hardware-backed storage for that install, and include a server nonce, so that an attacker has to drive the real code to produce a valid report.

#### Limitations

OWASP lists four: RASP can be bypassed with enough time and control of the device; it is a cat-and-mouse game that needs ongoing updates; it costs performance and battery; and aggressive checks produce false positives (custom ROMs, accessibility tools, enterprise agents). Critical security decisions belong on the server where possible.

### Generic: Code Injection (MASTG-KNOW-0110)

Source: [MASTG-KNOW-0110](https://mas.owasp.org/MASTG/knowledge/generic/MASVS-RESILIENCE/MASTG-KNOW-0110/). Summary only.

Code injection is the attacker-side technique this weakness is about: putting your own code into the app's process to read and change its state, call its functions, and hook Java, Objective-C, Swift and native code. Testers rarely implement injection themselves. They use frameworks that automate it. KNOW-0110 names three:

- [Frida](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/) (Android and iOS), a full dynamic instrumentation toolkit. On a rooted or jailbroken device `frida-server` injects an agent containing a JavaScript runtime into the target, and on stock devices Frida Gadget is embedded in a repackaged app. It provides Java, Objective-C and native hooking (Interceptor), memory access and code tracing (Stalker).
- [Xposed](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0027/) (Android), now deprecated in OWASP's tool list in favour of [LSPosed](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0149/) forks, which load modules into app processes through zygote and hook Java methods.
- [ElleKit](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0139/) (iOS), the hooking library used by current jailbreaks such as Dopamine and palera1n, with Substrate- and libhooker-compatible APIs. Tweaks use it to hook functions and Objective-C methods.

KNOW-0110 also notes that tampering with process memory is harder to detect than patching files, which is why attackers prefer it. That is the reason this weakness exists separately from file and package integrity ([MASWE-0057](/mobile/maswe-0057-app-resources-integrity-not-verified/)). Our [traffic interception lab note](/mobile/mobile-traffic-interception-lab/) covers setting up Frida and objection on test devices.

## Tests

OWASP links two current tests to MASWE-0058: [MASTG-TEST-0341](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0341/) (Android) and [MASTG-TEST-0354](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0354/) (iOS). Both are dynamic: hook sensitive APIs, use the app, and see whether it notices. Each comes with three correlated demos: an unprotected app whose data the hook reads, a protected app that terminates, and a bypass of that protection. Following our series' safety scope, we document the bypass demos (MASTG-DEMO-0108 and MASTG-DEMO-0119) in prose only.

Both OWASP tests pass an app as soon as *any* detection stops the hook, including detection of tool artefacts. Both of OWASP's "pass" demos in fact detect artefacts: a `frida` string in `/proc/self/maps`, and a D-Bus reply on port 27042. Neither checks code integrity. Our two tests close that gap. GT-RES-0058-1 is a static inventory that classifies each check the app has. GT-RES-0058-2 varies the instrumentation so you can tell an integrity check from an artefact check and record the bypass effort.

These tests replace the following legacy v1 tests:

| Legacy test | Title | `covered_by` | Where the content went |
|---|---|---|---|
| [MASTG-TEST-0050](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0050/) (Android) | Testing Runtime Integrity Checks | MASTG-TEST-0341 | MASTG-TEST-0341 below, with the bypass-effort part in GT-RES-0058-2 |
| [MASTG-TEST-0048](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0048/) (Android) | Testing Reverse Engineering Tools Detection | MASTG-TEST-0341 | Hook-based part: MASTG-TEST-0341 below. Tool-artefact part: our [MASWE-0065 note](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/) |
| [MASTG-TEST-0091](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0091/) (iOS) | Testing Reverse Engineering Tools Detection | MASTG-TEST-0354 | Hook-based part: MASTG-TEST-0354 below. Tool-artefact part: our [MASWE-0065 note](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/) |

The legacy tests asked questions that the new ones dropped and that a client paying for an R-profile assessment still wants answered: can the mechanism be bypassed by hooking a single function, how hard is it to find, did you need custom code, how long did it take? GT-RES-0058-2 keeps those questions.

**Lab prerequisites for all four tests.** A rooted Android device or emulator and a jailbroken iOS device with a current `frida-server`, the matching `frida-tools` on your host, and optionally [frooky](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0145/) (OWASP's JSON-driven Frida hooker used in the Android demos) and objection. See our [lab note](/mobile/mobile-traffic-interception-lab/) for the set-up. Use the client's release build, not a debug build: debug builds often disable RASP.

A note on Frida versions: Frida 17 changed parts of the JavaScript API. For example, `Module.findExportByName(null, name)` became `Module.findGlobalExportByName(name)`, and the Java and ObjC bridges are no longer built into scripts loaded through the API (the `frida` REPL and `frida-trace` still include them). OWASP's demo scripts use the Frida 17 API. Some older MASTG technique pages, such as MASTG-TECH-0095, still use the older calls.

### MASTG-TEST-0341: Runtime Use of Hook Detection Techniques (Android)

*OWASP test: [MASTG-TEST-0341](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0341/). Platform: Android. Type: dynamic (hooks).*

#### Overview

You hook the APIs through which the app handles sensitive data and check whether the app detects the instrumentation and responds before the data passes through. OWASP's list of candidate APIs, with what a hook would expose:

| API | Exposes |
|---|---|
| `AccountManager.getPassword()`, `AccountManager.getAuthToken()` | Stored account passwords, OAuth and session tokens |
| `KeyStore.getKey()`, `KeyStore.getCertificate()` | Key handles and certificates (hardware-backed key material itself stays in the TEE, but the handle can be used) |
| `Cipher.doFinal()` | Plaintext going in or coming out, so session keys and secrets in transit |
| `SQLiteDatabase.rawQuery()`, `query()`, `execSQL()` | Database contents and queries |
| `EncryptedSharedPreferences` getters | Decrypted preference values |
| `KeyGenParameterSpec.Builder.setUserAuthenticationRequired()` | Whether new keys require user authentication: a hook can generate them without it |
| Any app method that handles or returns sensitive data | Whatever it handles |

The test does not assess how hard the detection is to bypass. That is GT-RES-0058-2.

#### Prerequisites

- Rooted device or emulator with `frida-server` ([MASTG-TOOL-0001](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0001/)), and the app installed ([MASTG-TECH-0005](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/)): `adb install-multiple base.apk split_*.apk`.
- `frida-tools`, and optionally frooky or objection.
- A list of the app's sensitive flows from the client or from your own mapping (login, key unlock, payment signing, content decryption).
- For apps that refuse to start on a rooted device: run the root-detection tests in [MASWE-0051](/mobile/maswe-0051-root-jailbreak-detection-not-implemented/) first. If root detection kills the app before any hook can run, record that. Then neutralise the app's own root check (for example with objection's `android root disable`) so you can reach the hook detection, and record that you did.

#### Steps

1. **Find what to hook.** Search the decompiled app for the APIs above and for the app's own sensitive wrappers:

   ```bash
   jadx -d out/ base.apk
   grep -rlE 'Cipher\.getInstance|AccountManager|KeyStore\.getInstance|rawQuery|EncryptedSharedPreferences' out/sources | head -50
   ```

   Note native libraries that do their own crypto (`readelf --dyn-syms -W lib/arm64-v8a/*.so | grep -E 'EVP_|AES_|SSL_'`). For those you hook native exports instead of Java methods.

2. **Hook with method hooking ([MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/)), spawning the app** so that the hooks are in place before any start-up check runs. Any of these works:

   ```bash
   # frida-trace: generates editable handlers in __handlers__/
   frida-trace -U -f com.example.app -j 'javax.crypto.Cipher!doFinal' -j 'android.accounts.AccountManager!get*'

   # frooky, as in OWASP's demo
   frooky -U -f com.example.app --platform android hooks.json

   # your own script (see the demo below)
   frida -U -f com.example.app -l trace-cipher.js -o run-spawn.log
   ```

3. **Exercise the app.** Log in, unlock, open the screens that show protected data, run a payment or signing flow, trigger a sync. Enter test data you will recognise in the output.

4. **Repeat with a late attach.** Let the app start cleanly without Frida, reach a logged-in state, then attach and repeat step 3. Start-up-only checks miss this case:

   ```bash
   frida -U -N com.example.app -l trace-cipher.js -o run-attach.log
   ```

5. **Watch the process and the backend at the same time:**

   ```bash
   adb logcat -v time | grep -iE 'com.example.app|has died|killProcess|tamper|integrity'
   ```

   Keep your proxy running. A response may be invisible locally (the app keeps working) but visible in traffic: a telemetry call with a risk flag, a step-up challenge, a refused transaction.

#### Observation

Collect, for each run (spawn and late attach):

- the hook output: arguments, return values and backtraces for each sensitive call, or the fact that none arrived;
- how and when the process ended (Frida prints `Process terminated`, logcat shows the ActivityManager death message), and which user action preceded it;
- any user-visible reaction (a warning dialog, a disabled feature, logout), and any server-side reaction seen in the proxy;
- whether the reaction came before or after the first sensitive data reached your hook.

#### Evaluation

The test **fails** when, in an app whose threat model includes R, your hooks on sensitive APIs run and return the expected data in at least one of the runs (spawn or late attach), and the app shows no detection or response, locally or on the server, before that data passes through.

The test **passes** when the hooking attempt is defeated by the app's defensive response in both runs: the process terminates, hook callbacks never fire for the sensitive calls, the sensitive feature refuses to run, or the server rejects the operation, all before sensitive data reaches the hook.

Two qualifications belong in the report. First, a pass says nothing about how easy the detection is to bypass. OWASP says so, and MASTG-DEMO-0108 shows a bypass in one hook. Second, a pass may come from artefact detection (MASWE-0065) rather than integrity verification. GT-RES-0058-2 tells you which. For an app without the R profile, a fail is an observation (Info), not a vulnerability.

#### Demo

OWASP's three correlated demos use one sample app. It encrypts and decrypts a string with AES/GCM under an Android Keystore key, and the hooks target `Cipher.doFinal()`.

[MASTG-DEMO-0106](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0106/MASTG-DEMO-0106/) (fail) is the unprotected app. The relevant code:

```kotlin
val encryptCipher = Cipher.getInstance("AES/GCM/NoPadding")
encryptCipher.init(Cipher.ENCRYPT_MODE, key)                 // key lives in AndroidKeyStore
val encrypted = encryptCipher.doFinal(secret.toByteArray())  // plaintext passes through doFinal
```

OWASP hooks it with frooky and this hook file (`frooky -U -f org.owasp.mastestapp --platform android hooks.json`), which hooks all seven `doFinal` overloads:

```json
{ "category": "CRYPTO", "hooks": [ { "class": "javax.crypto.Cipher", "methods": ["doFinal"] } ] }
```

The equivalent with plain Frida, logging only the app's own calls:

```javascript
// trace-cipher.js: log Cipher.doFinal(byte[]) input and output, with a backtrace
Java.perform(() => {
  const Cipher = Java.use("javax.crypto.Cipher");
  const JString = Java.use("java.lang.String");
  const Log = Java.use("android.util.Log");
  const Exception = Java.use("java.lang.Exception");
  const text = (b) => {
    const s = JString.$new(b, "UTF-8").toString();
    return /^[\x20-\x7e]+$/.test(s) ? s : `<${b.length} bytes>`;
  };
  Cipher.doFinal.overload("[B").implementation = function (input) {
    const out = this.doFinal(input);
    const mode = this.opmode.value === 1 ? "ENCRYPT" : this.opmode.value === 2 ? "DECRYPT" : this.opmode.value;
    console.log(`[doFinal] ${this.getAlgorithm()} ${mode}\n  in : ${text(input)}\n  out: ${text(out)}`);
    console.log(Log.getStackTraceString(Exception.$new()));
    return out;
  };
});
```

Output in the shape OWASP recorded (illustrative, our fake value in place of OWASP's sample string):

```text
[doFinal] AES/GCM/NoPadding ENCRYPT
  in : demo-value-not-a-secret
  out: <39 bytes>
java.lang.Exception
	at javax.crypto.Cipher.doFinal(Native Method)
	at org.owasp.mastestapp.MastgTest.mastgTest(MastgTest.kt:48)
[doFinal] AES/GCM/NoPadding DECRYPT
  in : <39 bytes>
  out: demo-value-not-a-secret
```

The test fails: the secret is visible on its way in and on its way out, and nothing reacted.

[MASTG-DEMO-0107](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0107/MASTG-DEMO-0107/) (pass) adds a check that runs when the class is created and again before the crypto. If it fires, the app kills its own process:

```kotlin
private fun detectHooking(): Boolean = try {
    BufferedReader(FileReader("/proc/self/maps")).useLines { lines ->
        lines.any { it.lowercase().let { l -> "frida" in l || "gadget" in l } }
    }
} catch (_: Exception) { false }

fun mastgTest(): String {
    if (detectHooking()) android.os.Process.killProcess(android.os.Process.myPid())
    // ... Cipher operations as above
}
```

(OWASP's version uses an explicit `readLine()` loop. We condensed it.) Run with the same hooks, the process dies before `doFinal` is called and the output is empty. The test passes. Look at what was detected, though: the string "frida" in a mapping name. That is an artefact check (KNOW-0030 territory, our [MASWE-0065 note](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/)), written in Kotlin, reading the map through a Java API. An integrity-oriented version of the same idea asks whether a mapping is *expected*, not what it is called, and does the read natively. A minimal sketch of the mapping test, with the raw read left out for brevity:

```c
#include <string.h>

// Called per line of /proc/self/maps, read with raw openat/read syscalls (not fopen).
// Returns 1 for an executable mapping that no legitimate component should have.
static int suspicious_exec_mapping(const char *perms, const char *path) {
    if (perms[2] != 'x') return 0;                                  // only executable mappings
    if (perms[1] == 'w') return 1;                                  // rwx is never expected
    if (strstr(path, "jit-cache") || strstr(path, "jit-code-cache")) return 0;  // ART JIT
    if (path[0] == '\0') return 1;                                  // anonymous executable memory
    if (strstr(path, " (deleted)")) return 1;                       // e.g. a memfd-backed agent
    static const char *ok[] = { "/system/", "/system_ext/", "/vendor/", "/product/",
                                "/apex/", "/data/app/", "[vdso]", NULL };
    for (int i = 0; ok[i]; i++) if (strncmp(path, ok[i], strlen(ok[i])) == 0) return 0;
    return 1;                                                       // anything else: unexpected
}
```

Treat this as a starting point to profile against your supported devices, not as a finished check. `/data/app/` in particular should be narrowed to your own install directory.

[MASTG-DEMO-0108](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0108/MASTG-DEMO-0108/) (fail) is OWASP's bypass of DEMO-0107, described here in prose. The tester loaded a script that hooked `java.io.BufferedReader.readLine()` for the whole process and silently skipped any line containing "frida" or "gadget", along with the `Cipher.doFinal()` trace. `detectHooking()` therefore read a clean-looking map and returned `false`, the kill path never ran, and the trace captured the plaintext going into encryption and coming out of decryption. OWASP's output shows eight hidden lines across the two scans, four per scan, all `/memfd:frida-agent-64.so (deleted)` mappings. The lesson for the report: a check that reads its evidence through a hookable Java API and matches a tool name falls to one generic hook of a few lines that does not even need to know the app's code. Rate such a control by what the bypass unlocks, as described in [Rating findings](#rating-findings).

### MASTG-TEST-0354: Runtime Use of Hook Detection Techniques (iOS)

*OWASP test: [MASTG-TEST-0354](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0354/). Platform: iOS. Type: dynamic (hooks).*

#### Overview

The iOS counterpart of MASTG-TEST-0341. OWASP's candidate APIs:

| API | Exposes |
|---|---|
| `SecItemCopyMatching`, `SecItemAdd`, `SecItemUpdate` | Keychain items: tokens, credentials, secrets |
| `SecKeyCreateSignature`, `SecKeyCreateDecryptedData`, `CCCrypt` | Data being signed, plaintext, keys passed to CommonCrypto |
| `LAContext.evaluatePolicy`, `LAContext.evaluateAccessControl` | The local-authentication decision (see our [MASWE-0020 note](/mobile/maswe-0020-local-authentication-bypass/)) |
| `URLSession.dataTask(with:completionHandler:)`, `uploadTask`, `downloadTask`, `URLSessionTask.resume` | Requests and responses before TLS, including when pinning is in place |
| Any app function that handles sensitive data | Whatever it handles |

OWASP marks robustness against bypass as out of scope for this test. It also lists expected false negatives: hooks that do not cover the sensitive code paths, flows that were not exercised, and detection that evades the instrumentation (native, obfuscated, dynamically loaded, or running before the hooks are installed). A clean result is therefore weaker evidence than a failing one.

#### Prerequisites

- Jailbroken device with `frida-server` ([MASTG-TOOL-0039](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/)), and the app installed ([MASTG-TECH-0056](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0056/)). Alternatively, a stock device with a Gadget-repackaged build that you are authorised to re-sign for testing. Note which one you used, because detection differs between them (see BEST-0048 below).
- `frida-tools`, and the app's bundle identifier (`frida-ps -Uai`).
- If jailbreak detection stops the app first, handle it as described in our [MASWE-0051 note](/mobile/maswe-0051-root-jailbreak-detection-not-implemented/) (for example objection's `ios jailbreak disable`) and record that you did.

#### Steps

1. **Find what to hook.** Imported symbols are readable even in an App Store-encrypted binary, because the symbol tables are not encrypted:

   ```bash
   unzip -q app.ipa -d app/
   nm -u app/Payload/Example.app/Example | grep -E '_CCCrypt|_SecItem|_SecKeyCreate|_CC_SHA256'
   ```

   Objective-C selectors and strings need a decrypted binary.

2. **Hook with method hooking ([MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/)), spawning the app:**

   ```bash
   frida-trace -U -f com.example.app -i CCCrypt -i SecItemCopyMatching -i SecKeyCreateSignature \
     -m '-[LAContext evaluatePolicy:localizedReason:reply:]'
   # or a script (see the demo below)
   frida -U -f com.example.app -l trace-cccrypt.js -o run-spawn.log
   ```

3. **Exercise the app** through login, Keychain-backed unlock, signing and payment flows.

4. **Repeat with a late attach** after a clean start: `frida -U -n Example -l trace-cccrypt.js -o run-attach.log`.

5. **Watch for the reaction:** Frida's `Process terminated` message, crash or exit entries in the device log (`idevicesyslog` or Console.app), changed behaviour in the UI, and traffic in your proxy.

#### Observation

As for MASTG-TEST-0341: hook output (arguments, return values, backtraces) or its absence, how and when the process ended, user-visible and server-side reactions, and the order of events relative to the first sensitive call.

#### Evaluation

The test **fails** when, in an R-profile app, the hooks on sensitive APIs run and return the expected data in at least one run (spawn or late attach) and nothing reacts before the data passes through.

It **passes** when the app's defensive response (termination, refusal of the sensitive operation, server-side rejection) prevents your hooks from capturing the data in both runs. As on Android, record whether the detection was artefact-based or integrity-based (GT-RES-0058-2) and say in the report that bypass resistance was not assessed by this test.

#### Demo

[MASTG-DEMO-0117](https://mas.owasp.org/MASTG/demos/ios/MASVS-RESILIENCE/MASTG-DEMO-0117/MASTG-DEMO-0117/) (fail) encrypts and decrypts a string with `CCCrypt` (AES-CBC, PKCS7). OWASP built it with Xcode 26 and tested it on iOS 16.7.10 with the Dopamine jailbreak. The sample also uses a key that is a hardcoded constant. That is a separate CRYPTO finding (see our [MASVS-CRYPTO guide](/mobile/masvs-crypto-cryptography-guide/)), not part of this test. OWASP's tracing script, trimmed:

```javascript
// trace-cccrypt.js (Frida 17+; on older Frida use Module.findExportByName(null, "CCCrypt"))
const show = (p, n) => {
  if (p.isNull() || n <= 0) return "<empty>";
  try { const s = p.readUtf8String(n); if (/^[\x20-\x7e]+$/.test(s)) return s; } catch (_) {}
  return `<${n} bytes>`;
};
Interceptor.attach(Module.findGlobalExportByName("CCCrypt"), {
  onEnter(args) {
    this.op = args[0].toInt32();                 // 0 = kCCEncrypt, 1 = kCCDecrypt
    this.inStr = show(args[6], args[7].toInt32()); // dataIn, dataInLength
    this.out = args[8]; this.moved = args[10];   // dataOut, dataOutMoved (size_t *)
    this.bt = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).slice(0, 4);
  },
  onLeave(ret) {
    const n = this.moved.isNull() ? 0 : this.moved.readU64().toNumber();
    console.log(`[CCCrypt] op=${this.op} status=${ret.toInt32()}\n  in : ${this.inStr}\n  out: ${show(this.out, n)}`);
    this.bt.forEach((s) => console.log("  " + s));
  },
});
```

Output in the shape OWASP recorded (illustrative, fake value):

```text
[CCCrypt] op=0 status=0
  in : demo-value-not-a-secret
  out: <32 bytes>
  0x104689934 MASTestApp.debug.dylib!closure #1 in ... static MastgTest.crypt(operation:data:key:iv:)
[CCCrypt] op=1 status=0
  in : <32 bytes>
  out: demo-value-not-a-secret
```

[MASTG-DEMO-0118](https://mas.owasp.org/MASTG/demos/ios/MASVS-RESILIENCE/MASTG-DEMO-0118/MASTG-DEMO-0118/) (pass) adds a `detectHooking()` that runs before the demo starts and before each `CCCrypt` call, and calls `exit(0)` when it fires. The check opens a TCP connection to `127.0.0.1:27042` (frida-server's default port), sends a D-Bus authentication probe and looks for a D-Bus reply:

```swift
// condensed from OWASP's sample: socket(), 1-second timeouts and sockaddr_in set-up omitted
guard connect(fd, addrPtr, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0 else { return false }
let probe = [UInt8]("\0AUTH\r\n".utf8)
guard send(fd, probe, probe.count, 0) == probe.count else { return false }
var buf = [UInt8](repeating: 0, count: 256)
let n = recv(fd, &buf, buf.count, 0)
guard n > 0 else { return false }
let reply = String(decoding: buf.prefix(n), as: UTF8.self).uppercased()
return reply.contains("REJECTED") || reply.contains("OK")   // a D-Bus server answered
```

With the same tracing script, the app exits before the first `CCCrypt` and the output contains only the script's start-up line. The test passes. As on Android, though, this detects a *tool* (a listening frida-server), not a *modification*. It is the D-Bus check from KNOW-0087 and BEST-0048, which belongs to our [MASWE-0065 note](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/). It would not notice Frida Gadget, frida-server on another port or in a different transport, or a hook made by ElleKit. An integrity check for the same risk would ask, before each call, whether `CCCrypt` still resolves into `libcommonCrypto.dylib` and whether its first instructions are a trampoline, as described under KNOW-0140 above.

[MASTG-DEMO-0119](https://mas.owasp.org/MASTG/demos/ios/MASVS-RESILIENCE/MASTG-DEMO-0119/MASTG-DEMO-0119/) (fail) is OWASP's bypass of DEMO-0118, described in prose. The tester hooked libc `connect()` inside the app process and, when the destination port was 27042, made the call report failure to its caller. The probe concluded that nothing was listening, `detectHooking()` returned `false` each time it ran (three blocked connections in OWASP's output), and the `CCCrypt` trace captured the plaintext on encryption and decryption. OWASP also notes the even simpler route of running frida-server on a non-default port. As with DEMO-0108, one generic hook defeats the check without any knowledge of the app's code.

### GT-RES-0058-1: Static inventory of runtime integrity checks (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Before you hook anything, find out which runtime checks the app contains, classify each as *integrity* (looks for modifications) or *artefact* (looks for tool names, ports, files, threads), and note where it runs and what it does on detection. This tells you which runs to plan in GT-RES-0058-2. In the report it separates "the app has no runtime integrity verification" (MASWE-0058) from "the app only detects tools" (MASWE-0065). Expect obfuscation and commercial protectors to hide some of this. The inventory is a lower bound.

#### Prerequisites

- Android: the APK and splits, `jadx`, `readelf`/`llvm-readelf`, `llvm-objdump`, `strings`, optionally Ghidra or r2.
- iOS: the IPA (and a decrypted binary for strings), `nm`, `otool`, `strings`, optionally Ghidra or r2.

#### Steps

1. **Android, Java/Kotlin layer.** Search for the evidence sources and reactions:

   ```bash
   grep -rnE '/proc/self/(maps|smaps|task|status)|getDeclaredMethod|Modifier\.isNative|XposedBridge|killProcess|exitProcess' out/sources | head -100
   ```

2. **Android, native layer.** List the imports that integrity checks need, look for raw system calls (checks that avoid libc to resist hooking) and for evidence paths:

   ```bash
   for f in lib/arm64-v8a/*.so; do
     echo "== $f"
     readelf --dyn-syms -W "$f" | grep -woE 'dl_iterate_phdr|dladdr|dlsym|mprotect|syscall|openat|pthread_create' | sort -u
     llvm-objdump -d --no-show-raw-insn "$f" | grep -cE 'svc[[:space:]]+#0'
     strings -a "$f" | grep -E '/proc/self|frida|gum-js|LIBFRIDA|xposed|linjector|jit-cache' | sort -u
   done
   ```

   `dl_iterate_phdr`, `dladdr`, `mprotect` and many `svc #0` instructions in an app library suggest home-grown integrity checks or a protector. Strings such as `frida`, `gum-js-loop` or `27042` (search for it with `strings` too) suggest artefact checks. Little to nothing visible combined with a large, high-entropy library suggests a packer or obfuscator (see [MASWE-0059](/mobile/maswe-0059-code-obfuscation-not-implemented/)).

3. **iOS.** Imports and strings:

   ```bash
   nm -u Payload/Example.app/Example | grep -E '_dladdr|_dyld_image_count|_dyld_get_image_(name|header)|_dyld_register_func_for_add_image|_method_getImplementation|_class_getMethodImplementation|_CC_SHA256|_vm_region|_task_info|_connect$|_ptrace|_sysctl'
   strings -a Example.decrypted | grep -E 'frida|Frida|cynject|MobileSubstrate|/var/jb|ellekit|libhooker|__text|27042' | sort -u
   ```

   Repeat for embedded frameworks in `Payload/Example.app/Frameworks/`. Protectors often live there.

4. **Classify each finding** in a table: check, layer (Kotlin/Swift or native), evidence source (maps, dyld list, IMP owner, prologue, code hash, port, file), integrity or artefact, where it is called (start-up, before sensitive operations, timer), and the reaction (exit, UI, wipe, network report). Use cross-references in jadx, Ghidra or r2 to find call sites and reactions.

#### Observation

The classification table, with code locations (class and method, or library and function offset), and screenshots or excerpts of the relevant decompiled code.

#### Evaluation

This is an inventory, not a pass/fail test on its own. It produces three inputs for the rating:

- **No runtime checks found** (statically, and confirmed dynamically by MASTG-TEST-0341/0354 failing): supports a MASWE-0058 finding.
- **Only artefact checks found**: report under MASWE-0065. For MASWE-0058, record that no integrity verification was identified.
- **Integrity checks found**: note their coverage (own code only, or also the system APIs used on sensitive paths), their layer and their call sites. Then test them with GT-RES-0058-2.

#### Demo

Applied to OWASP's DEMO-0107 APK, step 1 finds `/proc/self/maps` and `killProcess` in `org.owasp.mastestapp.MastgTest` and nothing in native code. That gives a single Kotlin check, artefact-based (matches "frida" and "gadget"), called at construction and before the crypto, with termination as the response and no server report. Applied to DEMO-0118, step 3 finds `_connect`, `_send` and `_recv` imports and the `\0AUTH` probe string, again a single artefact check, with `exit(0)` as the response. Neither app contains an integrity check. The result is illustrative: we derived it from OWASP's published source, not from a run of our own.

### GT-RES-0058-2: Integrity checks versus artefact checks, and bypass effort (Android and iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

MASTG-TEST-0341 and MASTG-TEST-0354 run one instrumentation set-up and record whether the app reacts. This test varies the set-up so the artefacts change but the modification stays the same, which tells you what the app is really detecting. It then measures how much effort it takes to neutralise the app's own check on your test device, which the legacy tests asked for and the v2 tests dropped. It stays within the series' safety scope: tracing the app's own functions, changing tool names and ports, and neutralising the app's own check on your own device with well-known techniques.

#### Prerequisites

- The lab from the OWASP tests, the inventory from GT-RES-0058-1, and the app's sensitive flows.
- A frida-server binary you can run under another file name and port.
- Optionally, a second hooking engine already in your lab (an LSPosed module on Android, an ElleKit-based tweak on iOS) that logs a call without changing it.

#### Steps

Run the same sensitive flow under each configuration and record whether the app reacts:

| Run | Set-up | What changes |
|---|---|---|
| A0 | Spawn with default frida-server and an empty script: Frida present, nothing hooked | Control run. Artefact checks fire here, integrity checks have nothing to find |
| A | Spawn with default frida-server, Java/ObjC hook on a sensitive API (the OWASP test) | Baseline |
| B | Late attach after a clean start, same hook | Defeats start-up-only checks |
| C | frida-server renamed and on a non-default port, then attach | Removes server-name and port artefacts. The agent's own mapping and thread names stay the same |
| D | Native inline hook (Interceptor, log only) on a function in the app's own library or executable, or on the system function the sensitive path calls | Tests prologue and code-hash checks, not Java/ObjC hook checks |
| E | Second engine (LSPosed or ElleKit) logs the same call, no Frida running | No Frida artefacts at all. Only integrity checks can fire |

For run A0, an empty script is enough: `frida -U -f com.example.app -l empty.js` with an `empty.js` that contains only a comment. Commands for run C:

```bash
# Android
adb push frida-server /data/local/tmp/svcd
adb shell "su -c 'chmod 755 /data/local/tmp/svcd && /data/local/tmp/svcd -l 127.0.0.1:47011 -D'"
adb forward tcp:47011 tcp:47011
frida -H 127.0.0.1:47011 -N com.example.app -l trace-cipher.js

# iOS (jailbroken): stop the packaged frida-server daemon first, then start a renamed copy by hand
# over SSH, e.g. /var/jb/usr/sbin/svcd -l 127.0.0.1:47011 (path depends on the jailbreak)
iproxy 47011 47011 &
frida -H 127.0.0.1:47011 -n Example -l trace-cccrypt.js
```

For run D, a tracing hook on a native function, for example an exported JNI function of the app's library (Android) or `CCCrypt` (iOS, the same script as above):

```javascript
// log-only inline hook on an app-owned native export (Frida 17+)
const lib = Process.getModuleByName("libpayments.so");
Interceptor.attach(lib.getExportByName("Java_com_example_pay_Signer_sign"), {
  onEnter() { console.log("[native] Signer.sign entered"); },
  onLeave(ret) { console.log("[native] Signer.sign returned " + ret); },
});
```

Then, for each check the app has, **measure bypass effort**:

1. Locate the check from the reaction: the backtrace at the `exit`, `killProcess` or `abort` call, the last calls traced before the process died, and the GT-RES-0058-1 inventory.
2. Trace the check itself to confirm what it reads and what it returns (log its arguments and return value).
3. On your own device, neutralise only that check with the simplest public technique that works. Make the app's own detection method report "clean" with a short hook, or remove the evidence it looks for (for example, a different port). Record what you changed, not just that you succeeded.
4. Record time spent, the number of hooks or patches needed, whether you needed to write custom code, and whether the bypass survives an app restart and a new release.

#### Observation

A run matrix (A0 to E) with the reaction for each, plus for each check: location, type, what neutralised it, the number of changes, and the time taken.

#### Evaluation

- **Integrity verification present:** the app reacts in run E, or it reacts in A or D but not in A0. In both cases the reaction is tied to the modification, not to Frida being present. This is what MASWE-0058 asks for.
- **Artefact detection only:** the app already reacts in A0 (Frida present, nothing hooked) and does not react in E. Renaming and moving the server (C) may or may not silence it. On Android the agent's own mapping keeps its name, so a maps name check still fires in C. Report it under [MASWE-0065](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/), and record for MASWE-0058 that no runtime integrity verification was found. An app that reacts in both A0 and E has both kinds of check.
- **Start-up-only:** the app reacts in A but not in B. Report this as a coverage gap whatever the check type.
- **Bypass effort**, as input to the rating: *trivial* (one generic hook, a renamed binary or a different port, under an hour), *moderate* (several app-specific hooks or patches, a few hours, some custom code), *significant* (native, inlined, redundant checks with server-side consequences, a day or more, or not completed in the time-box). Effort is not pass/fail. It goes into the report so the client can judge the control against their threat model.

#### Demo

Applying the matrix to OWASP's demo apps from their published source (illustrative, not our run): DEMO-0107 would react in every Frida run from A0 to D, because the agent's memfd mapping is called `frida-agent-64.so` whatever the server is called and whether or not anything is hooked. It would not react in E. Reacting in A0 but not in E makes it artefact detection, and DEMO-0108 puts the bypass effort at one generic hook. DEMO-0118 would react in A0, A, B and D (frida-server on its default port) but not in C or E. That is artefact detection again, and DEMO-0119 shows the same one-hook bypass.

## Best practices

OWASP links three best practices to this topic. Two of them, BEST-0041 and BEST-0048, mix integrity checks with tool detection. We summarise them here because the tests above cite them, and mark the tool-detection parts that our MASWE-0065 note covers in depth. The cross-cutting BEST-0029, "Implementing Resilience and RASP Signals", is summarised in the [series hub](/mobile/masvs-resilience-resilience-testing-guide/).

### MASTG-BEST-0041: Hardening Against Runtime Hooking (Android)

Source: [MASTG-BEST-0041](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0041/).

BEST-0041 organises defences into four kinds of control:

- **Preventive:** root detection and device/app attestation, because most hooking frameworks need root. It also warns that hooking works without root through a Gadget-repackaged app, so do not rely on prevention alone.
- **Detective:** combine artefact detection (KNOW-0030) with runtime integrity verification (KNOW-0032), because each has blind spots the other covers. The concrete techniques are memory scanning, code-section checksums verified periodically, GOT/PLT verification, prologue inspection for trampolines (`LDR X16, .+8; BR X16`), ART method entry-point verification, and D-Bus probing for frida-server (an artefact check).
- **Deterrent:** native implementation, obfuscation, scattering checks, varying their timing, inlining them (copy the logic at each call site, or use `__attribute__((always_inline))` in C/C++ and `private inline` functions in Kotlin), randomising check placement per release with build-time transformation, and repeating checks immediately before sensitive operations so that every bypassed instance is one more thing an attacker has to find.
- **Responsive:** terminate the session, clear sensitive data from memory and disk, alert the backend, and protect the response code itself.

Our additions:

- **"Native code is harder to hook"** needs a qualifier. Frida's Interceptor hooks native functions as easily as Java methods. What native code gives you is code that is harder to read and patch statically, and the option of avoiding libc and Java APIs (raw system calls), which removes the generic interception points that DEMO-0108 used. BEST-0041's own note applies: a result passed back to Java over JNI can be tampered with at that boundary, so make the native side act on its own result where possible (for example, by refusing to produce a signature) rather than returning a boolean.
- **ART entry-point checks via `FromReflectedMethod`** are not guaranteed to work (opaque JNI IDs, version-specific layouts), as KNOW-0032 itself warns. Build them to fail safe.
- **Prefer reporting to killing.** A server-side consequence survives a local bypass, as explained under KNOW-0118 above.

### MASTG-BEST-0048: Hardening Against Reverse Engineering Tools (iOS)

Source: [MASTG-BEST-0048](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0048/). OWASP links it from MASTG-TEST-0354. Most of its content is tool detection, so our [MASWE-0065 note](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/) treats it in full.

Its points:

- **Inspect loaded dynamic libraries** with `_dyld_image_count()` and `_dyld_get_image_name()` for names like `FridaGadget`, `frida-agent` or `cynject`. This works against Frida Gadget and anything loaded through dyld (for example via `DYLD_INSERT_LIBRARIES`). It does **not** work against frida-server's injected mode on official builds, because the injector uses Frida's own Mach-O mapper and prefers it over dyld, so the agent never shows up in dyld's list. A renamed library also defeats a name check.
- **Probe TCP port 27042** for a D-Bus AUTH reply (what DEMO-0118 does), and look for frida-server's named pipes.
- **Deterrent and responsive controls** as in BEST-0041: native C checks, obfuscation, scattering, inlining, and termination, data clearing and backend alerts.

For MASWE-0058, the useful reading is the inverse of the first point: turn the dyld walk into an allowlist of image *locations*, and add the IMP-ownership, symbol-ownership, prologue and unbacked-executable-region checks described under KNOW-0140 above. Unlike name and port checks, these do not depend on how the tool is named or configured.

### MASTG-BEST-0067: Implementing Source Code Integrity Checks on iOS

Source: [MASTG-BEST-0067](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0067/).

BEST-0067 recommends supplementing the OS code-signing check with the KNOW-0140 runtime check: locate `__TEXT,__text` via the Mach-O load commands, hash it with SHA-256 (`CC_SHA256`, not MD5), and compare with a reference value stored in a protected, ideally obfuscated, form. It warns that the check can be bypassed on jailbroken devices by hooking the check, patching the reference hash, or intercepting file-system calls. The last of these applies to checks that hash the file on disk. It does not apply to a hash over the loaded memory, which is what KNOW-0140 computes.

Our additions:

- **Hash every image you ship.** Embedded frameworks and dylibs as well as the main executable.
- **Patch in the reference hash after linking.** Keep it out of `__text`, and compute it per architecture slice.
- **Cover the system APIs on your sensitive paths too.** Add ownership and prologue checks for system functions such as `CCCrypt`, `SecItemCopyMatching` and `SecKeyCreateSignature`. A `__text` hash cannot see hooks there, and that is where MASTG-TEST-0354 puts its hooks.
- **Check repeatedly.** Run the check before sensitive operations and at intervals, not once at launch. An attacker who attaches after launch is otherwise never seen.

## Rating findings

Rate a MASWE-0058 finding on three things: whether the app's threat model includes **R**, what an attacker gains by hooking the app undetected (the business consequence, not the fact that a hook ran), and whether a server-side control limits that gain. These are the series-wide rules, adapted to runtime integrity:

- **No R profile.** For an app whose threat model does not include reverse engineering and tampering, missing runtime integrity checks are **Info**: an observation, with a recommendation if the client is moving into a higher-risk profile.
- **R profile, no integrity verification.** Usually **Low to Medium**. It is Low when undetected hooking only exposes the device owner's own data and logic of low value. It is Medium when it exposes material the business treats as protected (DRM content keys, a per-app licence or API signing secret, anti-cheat logic) or lets an attacker change client-side decisions that matter.
- **Medium to High only for concrete business abuse.** The rating goes up to this range only when undetected hooking directly enables abuse the client cares about and no server control stops it. Examples: changing the amount or payee after a client-side confirmation that the server trusts; driving the genuine app as a bot for account creation or promotion abuse where the API has no device or app attestation; unlocking paid content or in-game currency validated only on the client. Demonstrate the abuse path, do not just assert it.
- **A control that exists but is trivially bypassed** (one generic hook as in DEMO-0108 and DEMO-0119, a renamed binary, a different port, a late attach) is rated by what the bypass unlocks, on the same scale as a missing control. Include the bypass effort from GT-RES-0058-2.
- **Artefact detection only** is not a MASWE-0058 pass. Report the artefact checks under [MASWE-0065](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/), and record that no integrity verification was found.
- **Not rated here.** The data or logic a hook exposes often has its own finding with its own rating. A hardcoded key (as in OWASP's iOS demo) is a CRYPTO finding. A server that trusts a client-side decision is an authorisation or business-logic finding, usually rated higher than the missing integrity check. Debug mechanisms left enabled in a release build (`android:debuggable`, `get-task-allow`, WebView debugging) are real vulnerabilities in every profile ([MASWE-0063](/mobile/maswe-0063-debug-mechanisms-not-disabled/)). Reference those findings instead of folding them into this one.
- **Never Critical** on its own. The impact of runtime tampering is bounded by what the server accepts.

| Rating | Typical conditions |
|---|---|
| **High** | R-profile app, undetected hooking (or a trivial bypass) demonstrably enables fraud or large-scale abuse, for example a modified payment or a bot flow on an unattested API, and no server-side check catches it |
| **Medium** | R-profile app (banking, wallet, DRM, competitive game) with no runtime integrity verification, or only checks that fall to a trivial bypass, where hooking exposes protected material or changes decisions of business value |
| **Low** | R-profile app with no integrity verification, but hooking exposes only the user's own data or low-value logic and the server re-validates what matters; or integrity checks exist but have coverage gaps (start-up only, own code only) |
| **Info** | No R profile; or checks that held up in GT-RES-0058-2, with recommendations (server-side signals, more coverage); artefact-only detection noted here as context for the MASWE-0065 finding |

In the report, state the device and injection mode (rooted or jailbroken with frida-server, or a Gadget-repackaged build), the Frida and OS versions, the APIs hooked and the data observed (redacted), the run matrix and its results, the bypass effort with time spent, and the server-side behaviour you observed. Recommend specific changes: which checks to add (prologue, ownership, mapping allowlist, code hash), where to call them, and which server-side signal should carry the result.

## References

- OWASP MASWE: [MASWE-0058: Runtime Code Integrity Not Verified](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0058/); related [MASWE-0065](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0065/), [MASWE-0056](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0056/), [MASWE-0057](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0057/), [MASWE-0059](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0059/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-RESILIENCE-2](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-2/) (CC BY-SA 4.0)
- OWASP MASTG knowledge: [MASTG-KNOW-0032](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0032/), [MASTG-KNOW-0140](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0140/), [MASTG-KNOW-0118](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0118/), [MASTG-KNOW-0110](https://mas.owasp.org/MASTG/knowledge/generic/MASVS-RESILIENCE/MASTG-KNOW-0110/); for context [MASTG-KNOW-0030](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0030/), [MASTG-KNOW-0087](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0087/) (CC BY-SA 4.0)
- OWASP MASTG tests: [MASTG-TEST-0341](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0341/), [MASTG-TEST-0354](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0354/); legacy [MASTG-TEST-0050](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0050/), [MASTG-TEST-0048](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0048/), [MASTG-TEST-0091](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0091/) (CC BY-SA 4.0)
- OWASP MASTG demos: [MASTG-DEMO-0106](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0106/MASTG-DEMO-0106/), [MASTG-DEMO-0107](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0107/MASTG-DEMO-0107/), [MASTG-DEMO-0108](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0108/MASTG-DEMO-0108/), [MASTG-DEMO-0117](https://mas.owasp.org/MASTG/demos/ios/MASVS-RESILIENCE/MASTG-DEMO-0117/MASTG-DEMO-0117/), [MASTG-DEMO-0118](https://mas.owasp.org/MASTG/demos/ios/MASVS-RESILIENCE/MASTG-DEMO-0118/MASTG-DEMO-0118/), [MASTG-DEMO-0119](https://mas.owasp.org/MASTG/demos/ios/MASVS-RESILIENCE/MASTG-DEMO-0119/MASTG-DEMO-0119/) (CC BY-SA 4.0)
- OWASP MASTG best practices: [MASTG-BEST-0041](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0041/), [MASTG-BEST-0048](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0048/), [MASTG-BEST-0067](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0067/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0005](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/), [MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/), [MASTG-TECH-0026](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0026/), [MASTG-TECH-0056](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0056/), [MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/) (CC BY-SA 4.0)
- OWASP MASTG tools: [Frida (MASTG-TOOL-0031)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/), [Frida for Android (MASTG-TOOL-0001)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0001/), [Frida for iOS (MASTG-TOOL-0039)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/), [frooky (MASTG-TOOL-0145)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0145/), [objection (MASTG-TOOL-0038)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0038/), [Xposed (MASTG-TOOL-0027)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0027/), [LSPosed (MASTG-TOOL-0149)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0149/), [ElleKit (MASTG-TOOL-0139)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0139/) (CC BY-SA 4.0)
- Linux and Android: [proc_pid_maps(5)](https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html), [bionic linker source](https://android.googlesource.com/platform/bionic/+/main/linker/linker.cpp), [Android changes for NDK developers](https://android.googlesource.com/platform/bionic/+/main/android-changes-for-ndk-developers.md), [ART `art_method.h`](https://android.googlesource.com/platform/art/+/main/runtime/art_method.h), [Play Integrity API overview](https://developer.android.com/google/play/integrity/overview)
- Apple: [Overview of the Mach-O executable format (archive)](https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/MachOTopics/0-Introduction/introduction.html), [`method_getImplementation`](https://developer.apple.com/documentation/objectivec/method_getimplementation%28_:%29), [dyld(3) and dladdr(3) man pages](https://keith.github.io/xcode-man-pages/dyld.3.html), [Establishing your app's integrity (App Attest)](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity), [Apple Platform Security: runtime process security](https://support.apple.com/en-gb/guide/security/sec15bfe098e/web)
- Arm: [AAPCS64 procedure call standard](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst), [A64 instruction set encoding](https://developer.arm.com/documentation/ddi0602/latest/)
- Frida: [JavaScript API](https://frida.re/docs/javascript-api/), [frida-trace](https://frida.re/docs/frida-trace/), [Gadget](https://frida.re/docs/gadget/), [Darwin Mach-O mapper (frida-gum)](https://github.com/frida/frida-gum/blob/main/gum/backend-darwin/gummachomapper.c)
- Background: [Clang Control Flow Integrity](https://clang.llvm.org/docs/ControlFlowIntegrity.html), [O-MVLL anti-hook pass](https://obfuscator.re/omvll/passes/anti-hook/), [The Jiu-Jitsu of Detecting Frida (Bernhard Mueller, archived)](https://web.archive.org/web/20181227120751/http://www.vantagepoint.sg/blog/90-the-jiu-jitsu-of-detecting-frida), [LSPosed modern Xposed API](https://github.com/LSPosed/LSPosed/wiki/Develop-Xposed-Modules-Using-Modern-Xposed-API)
- CWE: [CWE-693](https://cwe.mitre.org/data/definitions/693.html) (our mapping; OWASP gives none)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
