---
title: "Memory Corruption in Android Apps: Where It Still Applies (MASTG-KNOW-0005)"
date: 2026-09-02
summary: "ART protects managed code, not JNI/NDK. What to test in native libraries, why MASTG dropped its black-box tests, and how to scope this in a report."
refs: [MASTG-KNOW-0005, MASVS-CODE-4, CWE-787, CWE-416, CWE-190]
tags: [android, ndk, jni, native, memory-safety, ghidra, masvs-code]
---

## What it is

Android applications normally run in a managed environment. The Android Runtime (ART) handles memory allocation and enforces type safety, which structurally prevents buffer overflows, out-of-bounds writes and use-after-free in code written in Java or Kotlin. For the managed portion of an app, this class of vulnerability is largely designed out.

The protection stops at the JNI boundary. Anything reached through the Java Native Interface or built with the Android NDK — C and C++ libraries, third-party native SDKs, media and crypto implementations, DRM and anti-tamper layers — runs outside the managed memory model and is exposed to the full range of traditional memory-safety issues.

Two historical cases illustrate the reach:

- **CVE-2018-9522** — a serialization flaw in Android's `Parcel` implementation (`StatsLogEventWrapper`), reachable across the IPC boundary.
- **Stagefright** — memory corruption in Android's native multimedia framework, demonstrated at BlackHat 2015, triggerable by media content the device merely processed.

**Memory leaks** are the other common concern and are far more frequent in practice than corruption. They typically occur when a `Context` or `Activity` reference is retained by a non-`Activity` helper, static field, singleton or long-lived callback, preventing garbage collection. The consequence is resource exhaustion and degraded performance rather than a directly exploitable condition, but on a long-running app it becomes a denial-of-service and stability issue worth reporting.

## Why MASTG removed its tests for this

This is worth understanding before you scope work, because it shapes what you can honestly deliver.

MASTG withdrew its memory-corruption tests on the basis that these flaws are best found during development, not through black-box penetration testing. Detecting buffer overflows, out-of-bounds access, integer overflows, use-after-free and format-string bugs in a compiled application without source code or debug symbols is complex and unreliable. Modern platforms also apply ASLR, stack canaries, and other runtime mitigations that substantially raise exploitation cost.

OWASP's position is that this class belongs to secure development — static and dynamic code analysis, compiler hardening, and secure coding practice — with SAMM and NIST SP 800-218 (SSDF) as the framework references.

The practical consequence for an engagement: **treat native memory safety as a source-code and configuration review activity, not as a black-box exploitation exercise**, unless the client has specifically scoped and funded native fuzzing. Promising memory-corruption findings from a two-week black-box mobile test is setting up a deliverable you cannot fill.

## How to test

### 1. Determine whether native code exists at all

```bash
unzip -l target.apk | grep '\.so$'
unzip -j target.apk 'lib/arm64-v8a/*.so' -d native/
```

No `.so` files and no `System.loadLibrary` calls means this section is not applicable — say so explicitly in the report rather than omitting it.

### 2. Map the JNI attack surface

The interesting boundary is where attacker-influenced data crosses into native code.

```bash
jadx -d out/ target.apk
grep -rn "System.loadLibrary\|native \|@FastNative\|@CriticalNative" out/sources/ | head -40
```

For each `native` method declaration, determine what feeds it: user input, file contents, network responses, `Intent` extras, deep-link parameters, `ContentProvider` data, or Bluetooth/NFC payloads. A native parser that consumes remote content is the surface that matters; one that only processes app-internal constants is not.

Enumerate exported JNI symbols:

```bash
nm -D --defined-only native/libtarget.so | grep Java_
readelf -Ws native/libtarget.so | grep Java_
```

### 3. Check compiler hardening

This is the highest-value, most defensible check in a black-box context, because it is objective and directly actionable.

```bash
# checksec-style inspection
checksec --file=native/libtarget.so

# or manually
readelf -a native/libtarget.so | grep -E "GNU_RELRO|BIND_NOW"   # RELRO
readelf -s native/libtarget.so | grep -i "__stack_chk_fail"      # stack canaries
readelf -h native/libtarget.so | grep Type                        # DYN = PIE, EXEC = no PIE
readelf -l native/libtarget.so | grep -A1 GNU_STACK               # NX
readelf -s native/libtarget.so | grep -iE "_chk$"                 # _FORTIFY_SOURCE
```

Report missing mitigations concretely: "libfoo.so is built without stack canaries and with partial RELRO" is a finding a developer can act on by adding `-fstack-protector-strong -Wl,-z,relro,-z,now -D_FORTIFY_SOURCE=2` to their `CMakeLists.txt` or `Android.mk`.

### 4. Look for the classic unsafe patterns

```bash
# dangerous imports present in the binary
nm -D --undefined-only native/libtarget.so | grep -E "strcpy|strcat|sprintf|gets|memcpy|alloca|system|popen"
strings -a native/libtarget.so | grep -iE "%s|%n" | head
```

In Ghidra, focus on the `Java_*` entry points and follow the parameters: `GetStringUTFChars` results copied into fixed-size stack buffers, `GetArrayLength` values used in arithmetic without overflow checks, and `memcpy` with a length derived from the input are the recurring patterns.

```bash
# headless triage
analyzeHeadless /tmp/ghidra_proj proj -import native/libtarget.so -postScript FunctionListing.java
```

### 5. Fuzz only where scope allows

If native parsing of untrusted input is in scope and the client wants depth, harness the library rather than the app:

```bash
# build the target function with sanitizers, on host or with the NDK toolchain
clang++ -fsanitize=address,fuzzer -g harness.cc -ltarget -o fuzz_target
./fuzz_target corpus/ -max_total_time=3600
```

On-device, ASan builds can be installed with `wrap.sh` on debuggable builds. This is a source-access activity in practice; note it as such when scoping.

### 6. Test for memory leaks

More likely to yield a real finding than corruption hunting:

```bash
adb shell dumpsys meminfo com.target.app
adb shell am start -W com.target.app/.MainActivity   # repeat rotation/navigation cycles
adb shell dumpsys meminfo com.target.app | grep -E "TOTAL|Objects|Views|Activities"
```

A monotonically rising `Activities` or `Views` count across repeated navigation indicates retained references. Confirm with a heap dump:

```bash
adb shell am dumpheap com.target.app /data/local/tmp/heap.hprof
adb pull /data/local/tmp/heap.hprof
hprof-conv heap.hprof heap-conv.hprof   # then open in Android Studio Memory Profiler / MAT
```

LeakCanary in a debug build gives the same answer far faster if you have build access.

## Impact

Where a native memory-corruption bug is reachable from untrusted input, impact is code execution in the app's process — the app's permissions, its data directory, its Keystore-held session, and its network position. That is **High** to **Critical**. The Stagefright class of issue, where merely processing received media triggers the bug, is the worst case because it requires no user interaction.

In practice, on a scoped black-box mobile assessment, most findings in this area are:

- **Missing compiler hardening** on bundled `.so` files — reported **Low**, sometimes **Informational**, but concrete and easily fixed. It raises exploitability of any other native bug, so it belongs in the report.
- **Vulnerable third-party native libraries** identified by version rather than by discovering the bug yourself — severity inherited from the CVE, filtered by reachability (see MASTG-KNOW-0004).
- **Memory leaks** causing degradation or crashes — **Low**, or **Medium** where the app is used in long sessions and the crash loses user data.

Modern mitigations mean a theoretical overflow is not automatically a critical finding. Score on demonstrated reachability and exploitability, and state your evidence. Where you identify a suspicious pattern without a working trigger, report it as a code-quality observation with the exact function and offset, not as an exploitable vulnerability — that is both accurate and more useful to the developer.

## Remediation

- Prefer memory-safe languages; use Rust or Kotlin/Java for new components rather than extending C/C++ layers.
- Build all native code with `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, full RELRO (`-Wl,-z,relro,-z,now`), PIE and NX.
- Validate every value crossing the JNI boundary in native code — lengths, indices and sizes — and never trust a length passed from Java.
- Run ASan/UBSan builds in CI, plus static analysis (`clang-tidy`, `cppcheck`, Semgrep C/C++ rules) on native sources.
- Fuzz native parsers that consume untrusted input as part of the development pipeline.
- Avoid retaining `Context` or `Activity` references in singletons, static fields or long-lived callbacks; use `WeakReference` or application context where appropriate.

## References

- OWASP MASTG — [MASTG-KNOW-0005: Memory Corruption Bugs](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0005/) (CC BY-SA 4.0)
- [Android Developers — Risks of using native code](https://developer.android.com/privacy-and-security/risks/use-of-native-code)
- [Stagefright: Scary Code in the Heart of Android (BlackHat US-15)](https://www.blackhat.com/docs/us-15/materials/us-15-Drake-Stagefright-Scary-Code-In-The-Heart-Of-Android.pdf)
- [NIST SP 800-218 — Secure Software Development Framework](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf)
- [OWASP SAMM](https://owaspsamm.org/model/)
