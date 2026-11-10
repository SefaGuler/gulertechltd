---
title: "MASWE-0064: Debugger Detection Not Implemented"
date: 2026-11-10 20:13:00 +0000
subcategory: resilience
summary: "Testing Android and iOS debugger detection: JDWP, TracerPid, ptrace, sysctl P_TRACED, exception ports, check placement, response and bypass effort."
refs: [MASWE-0064, MASVS-RESILIENCE-4]
tags: [android, ios, masvs-resilience, anti-debugging, jdwp, lldb]
---

This note is part of our [MASVS-RESILIENCE guide](/mobile/masvs-resilience-resilience-testing-guide/) and covers OWASP [MASWE-0064](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0064/): an app that lets a debugger attach to it at runtime without noticing or reacting. A debugger is the most direct way to take a running app apart. It can stop the process anywhere, read and write memory and registers, and change which branch a security check takes. Debugger detection does not make that impossible, because the attacker owns the device. What it does is force them to find and neutralise each check before they can work, and every well-placed check adds to that cost. The weakness is about the *running* app noticing a debugger. Whether the release build is debuggable in the first place (`android:debuggable`, `get-task-allow`) is [MASWE-0063](/mobile/maswe-0063-debug-mechanisms-not-disabled/), and that one is a real vulnerability in any app. Below you get the detection mechanisms on both platforms (JDWP and native checks on Android; `ptrace`, `sysctl`, parent-process, exception-port and terminal checks on iOS), how to get a debugger onto a release app on your test device, the four OWASP tests with their demos, how to measure how much effort a bypass takes, and how to rate what you find. Detection of Frida, Xposed and similar instrumentation is in the sibling note [MASWE-0065](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/).

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: Anti-Debugging (MASTG-KNOW-0028)](#android-anti-debugging-mastg-know-0028)
  - [iOS: Anti-Debugging Detection (MASTG-KNOW-0085)](#ios-anti-debugging-detection-mastg-know-0085)
  - [Generic: Debugging and Tracing (MASTG-KNOW-0114)](#generic-debugging-and-tracing-mastg-know-0114)
- [Tests](#tests)
  - [Before you start: getting a debugger onto a release app](#before-you-start-getting-a-debugger-onto-a-release-app)
  - [MASTG-TEST-0352: References to Debugging Detection APIs (Android)](#mastg-test-0352-references-to-debugging-detection-apis-android)
  - [MASTG-TEST-0353: Runtime Use of Debugging Detection APIs (Android)](#mastg-test-0353-runtime-use-of-debugging-detection-apis-android)
  - [MASTG-TEST-0401: References to Debugging Detection APIs (iOS)](#mastg-test-0401-references-to-debugging-detection-apis-ios)
  - [MASTG-TEST-0402: Runtime Use of Debugging Detection APIs (iOS)](#mastg-test-0402-runtime-use-of-debugging-detection-apis-ios)
  - [After the tests: measuring resistance](#after-the-tests-measuring-resistance)
- [Best practices](#best-practices)
  - [Continuous Anti-Debugging Checks (MASTG-BEST-0047)](#continuous-anti-debugging-checks-mastg-best-0047)
  - [Implementing Anti-Debugging Checks on iOS (MASTG-BEST-0074)](#implementing-anti-debugging-checks-on-ios-mastg-best-0074)
  - [Response design](#response-design)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

OWASP states the requirement as *"The app detects debugger attachment at runtime and responds to protect sensitive operations."* It maps to MASVS-RESILIENCE-4 ("The app implements anti-dynamic analysis techniques") and to the v1 requirement MSTG-RESILIENCE-2. OWASP gives no CWE. If your report template needs one, [CWE-693](https://cwe.mitre.org/data/definitions/693.html) (Protection Mechanism Failure) is the closest fit.

The threat is MAS-THREAT-0064, *"Attackers can inspect and manipulate the running app without resistance"*, reached through MAS-ATTACK-0002, *"Debugging the app at runtime"*. The weakness carries the **R** profile (plus EUDIW). It applies to apps whose threat model includes someone reverse engineering or tampering with the app on a device they control: banking and payments, wallets, DRM and media, games with an economy, apps that hold valuable IP or enforce licences on the client. For an app without that threat model, missing debugger detection is an observation, not a finding.

Be clear about what this control is. It is **defence in depth that raises attacker cost**. It does not replace any L1/L2 control. A debugger can only take from the client what the client has, so a secret that is not on the device, a decision that is made on the server, and a key that lives in hardware-backed storage and is bound to user authentication are all unaffected by whether the app detects lldb. Every client-side check can eventually be found and patched out. Good debugger detection buys time, makes automated and casual analysis fail, and, if it reports to a backend, gives the server a risk signal it can act on.

Three things are tested under this weakness:

| Question | Where |
|---|---|
| Does the app contain debugger checks at all, at the Java/Kotlin, native and Swift/Objective-C/C layers? | MASTG-TEST-0352 (Android) and MASTG-TEST-0401 (iOS), static |
| Do those checks actually run in the release build, at the right moments, and does the app react? | MASTG-TEST-0353 (Android) and MASTG-TEST-0402 (iOS), dynamic, plus attaching a real debugger |
| How much effort does it take to neutralise them? | [After the tests: measuring resistance](#after-the-tests-measuring-resistance), adapted from the legacy v1 tests |

Keep the neighbours apart:

| Question | Where it lives |
|---|---|
| Is the release build debuggable (`android:debuggable="true"`, `get-task-allow`, WebView debugging)? | [MASWE-0063](/mobile/maswe-0063-debug-mechanisms-not-disabled/) |
| Does the app detect Frida, Xposed/LSPosed, Substrate/ElleKit and similar tools? | [MASWE-0065](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/) |
| Does the app verify that its code in memory has not been hooked or patched? | [MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/) |
| Does the app run on a rooted or jailbroken device (where native debugging of release apps is easy)? | [MASWE-0051](/mobile/maswe-0051-root-jailbreak-detection-not-implemented/) |
| Are the checks themselves hidden by obfuscation? | [MASWE-0059](/mobile/maswe-0059-code-obfuscation-not-implemented/) |

## Modes of Introduction

**No checks at all.** The most common case. The team relies on the release build not being debuggable and assumes that is enough. It is not: on a rooted Android device or a jailbroken iPhone, a native debugger can attach to a non-debuggable app as root, and on Android the JDWP side can be switched on for every app with a system property or a hooking module.

**One check, once.** A single `Debug.isDebuggerConnected()` in `Application.onCreate()` or a single `PT_DENY_ATTACH` in `main()`. An attacker attaches a second later, or patches the one call site, and the protection is gone for the rest of the session.

**Only the Java layer.** `isDebuggerConnected()` sees a JDWP debugger only. A native debugger (lldb-server, gdbserver, anything built on `ptrace`) does not change its result. An app whose sensitive logic is in a native library, a Flutter engine or a React Native/Hermes runtime needs native checks.

**Checks in debug builds only, or dead code.** The check sits behind `BuildConfig.DEBUG`, a feature flag that is off in production, or an SDK initialiser the app never calls.

**Detection without response.** The app logs "debugger detected" to Logcat or sets a flag nothing reads. Detection that changes nothing is not a control.

**A single named choke point.** All checks funnel into one `SecurityManager.isDebugged()` (or one native export with a readable JNI name). One hook or one patched branch defeats everything.

**False-positive-driven removal.** The app blocked users who had USB debugging enabled (`Settings.Global.ADB_ENABLED`), complaints followed, and the whole check was removed rather than fixed.

## Impact

- **Bypass of client-side controls.** At a breakpoint the attacker flips the result of a root check, a PIN comparison, a licence check, or a pinning decision, and the app carries on as if it had passed.
- **Extraction of secrets from memory.** Session tokens, decrypted payloads, unwrapped keys, and values the app computes but never stores are readable while the process is stopped. This matters most for data that never touches disk and is therefore out of reach of storage-based attacks.
- **Faster reverse engineering.** Stepping through obfuscated or packed code reveals what static analysis hides: decrypted strings, the real call targets, the protocol the app speaks with its backend. That knowledge then feeds attacks that do not need a debugger, such as a bot that speaks the app's API.
- **Defeat of other resilience controls.** Root, integrity and tool-detection checks are only as strong as the debugger defence around them. A debugger is a generic way to skip any of them.

## Mitigations

- **Detect at both layers on Android**: JDWP (`Debug.isDebuggerConnected()`, `Debug.waitingForDebugger()`) and native (`TracerPid` in `/proc/self/status`, `ptrace`-based self-checks, timing), with the native part in C/C++ that does not go through an easily hooked Java wrapper.
- **Use more than one signal on iOS**: `sysctl` with `KERN_PROC_PID` and `P_TRACED`, `ptrace(PT_DENY_ATTACH)` where the distribution model allows it, parent-process and Mach exception-port checks.
- **Check continuously and close to what you protect**: before key use, payment approval, step-up authentication or secrets access, and periodically while those flows are active, not only at start-up.
- **Respond in a way that protects the asset**: stop the sensitive operation, drop transient secrets, require re-authentication, and send a generic risk signal to the backend. Do not tell the client which check fired.
- **Spread and hide the checks**: inline them at several call sites, vary the implementation, and obfuscate them ([MASWE-0059](/mobile/maswe-0059-code-obfuscation-not-implemented/)). Pair them with runtime integrity checks ([MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/)) so patching the check is itself detected.
- **Make the server decide**: for the operations that matter, the backend should treat a missing, stale or negative client signal as risk, and combine it with app and device attestation ([MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/), [MASWE-0054](/mobile/maswe-0054-device-attestation-not-implemented/)).
- **Test against real bypasses**, on every release: attach jdb and lldb, hook the obvious APIs, and record how long the defences held.

## Knowledge

OWASP does not link Knowledge pages from the weakness file. We assign three by topic: MASTG-KNOW-0028 (Android anti-debugging) and MASTG-KNOW-0085 (iOS anti-debugging detection) in full, and the generic MASTG-KNOW-0114 (debugging and tracing) as a summary. The Android tests also reference MASTG-KNOW-0007 (the `android:debuggable` attribute), which belongs to [MASWE-0063](/mobile/maswe-0063-debug-mechanisms-not-disabled/) and is covered in full there.

### Android: Anti-Debugging (MASTG-KNOW-0028)

Source: [MASTG-KNOW-0028](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0028/).

#### Two debuggers, two kinds of check

Android has two independent debugging mechanisms, and an app that wants to resist debugging has to cover both:

| | JDWP (Java Debug Wire Protocol) | Native (`ptrace`) |
|---|---|---|
| What it debugs | Managed code: Java/Kotlin bytecode running on ART | Everything in the process: native libraries, the ART runtime itself, Flutter/Hermes engines |
| Typical tools | jdb, Android Studio's Java debugger | lldb with `lldb-server`, gdbserver (deprecated), `strace`, any `ptrace` user |
| When the app allows it | Only if the process started with JDWP enabled: the app is `android:debuggable`, or the system enables JDWP for all apps (see below) | Any process the debugger may `ptrace`. For a non-debuggable app that means a root debugger on a rooted device |
| What the app can check | `Debug.isDebuggerConnected()`, `Debug.waitingForDebugger()`, `ApplicationInfo.FLAG_DEBUGGABLE`, timing | `TracerPid` in `/proc/self/status`, `ptrace`-based self-attach, timing, breakpoint instructions in its own code |

The table explains the most common gap: `isDebuggerConnected()` returns `false` while lldb is attached, because lldb does not speak JDWP. Conversely, `TracerPid` stays `0` while jdb is attached, because JDWP runs as a thread inside the process and does not use `ptrace`.

#### When does a release app accept a JDWP debugger?

Zygote decides at process start whether to start the JDWP agent. It does so when the app is `android:debuggable` (the manifest flag, which also makes `ApplicationInfo.FLAG_DEBUGGABLE` true), and on non-user builds of the OS depending on system properties: historically `ro.debuggable=1` turned it on for every app, and recent AOSP releases gate this on `userdebug` builds behind an additional `persist.debug.dalvik.vm.jdwp.enabled` property. Check the property names on the image you use; the details per version are in our [MASWE-0063 note](/mobile/maswe-0063-debug-mechanisms-not-disabled/). On a production (`user`) device, a non-debuggable app gets JDWP only if someone changes that: by patching and re-signing the manifest, by spoofing `ro.debuggable` on a rooted device (`resetprop ro.debuggable 1`, then restarting zygote), or with a hooking-framework module such as debugmepLS that rewrites `ApplicationInfo` and the process start flags in `system_server`. Each of these leaves a different trace, which is why apps combine checks.

#### JDWP checks

```kotlin
import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Debug
import android.provider.Settings

fun jdwpSignals(ctx: Context): Map<String, Boolean> = mapOf(
    // A JDWP debugger is attached right now.
    "connected" to Debug.isDebuggerConnected(),
    // The app was started with "wait for debugger" (am start -D) and is blocked waiting.
    "waiting" to Debug.waitingForDebugger(),
    // The installed package (or a hooked ApplicationInfo) says the app is debuggable.
    "debuggableFlag" to ((ctx.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0),
    // USB debugging is switched on. Weak, and a false-positive trap: see below.
    "adbEnabled" to (Settings.Global.getInt(ctx.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1),
)
```

- **`Debug.isDebuggerConnected()`** ([docs](https://developer.android.com/reference/android/os/Debug#isDebuggerConnected())) asks the runtime whether a JDWP debugger is connected. It is the canonical check and the first thing an attacker hooks, so on its own it is close to worthless against anyone with Frida. Its value is as one cheap signal among several and as a trip-wire for casual debugging.
- **`Debug.waitingForDebugger()`** ([docs](https://developer.android.com/reference/android/os/Debug#waitingForDebugger())) is true while a thread is blocked waiting for a debugger, which happens when the app is launched with `adb shell am start -D` or with "Wait for debugger" in Developer options. An attacker who wants to debug start-up code uses exactly this, so checking it early catches a common workflow.
- **`ApplicationInfo.FLAG_DEBUGGABLE`** ([docs](https://developer.android.com/reference/android/content/pm/ApplicationInfo#FLAG_DEBUGGABLE)) on a release build should always be clear. If it is set, the APK was patched and re-signed, or something hooked the framework to report it. It is a tamper signal more than a debugger signal, and it says nothing about the system-wide `ro.debuggable` route. Note that in decompiled code this constant often appears as the literal `2` (`(info.flags & 2) != 0`), because compile-time constants are inlined; search for both forms.
- **`Settings.Global.ADB_ENABLED`** ([docs](https://developer.android.com/reference/android/provider/Settings.Global#ADB_ENABLED)) is `1` when USB debugging is switched on, and `Settings.Global.DEVELOPMENT_SETTINGS_ENABLED` when Developer options are on. Both are cheap to read and both are **poor debugger signals**: a large number of ordinary users, every Android developer, many testers and power users, and some enterprise device setups have them on, and none of that means someone is debugging your app. Blocking on them alienates legitimate users and gets the check removed (a mode of introduction above). Use them, if at all, as a low-weight input to a risk score, never as a reason to terminate. In compiled code the constants are the strings `"adb_enabled"` and `"development_settings_enabled"`.

OWASP's knowledge page also shows a native check that reads `gDvm.debuggerConnected` from the Dalvik VM's global structure, and a technique that crashes or disconnects the JDWP thread by overwriting pointers in `DvmGlobals` (Dalvik, Android before 5.0) or in the vtable of ART's `JdwpAdbState` class. Treat both as history. Dalvik is gone, and ART's built-in JDWP implementation was replaced by an agent built on JVMTI and OpenJDK's `libjdwp` (loaded through ART's `adbconnection` plugin) around Android 9 and 10, so the `_ZTVN3art4JDWP12JdwpAdbStateE` symbol the technique relies on is not present on current devices. Patching runtime internals is also fragile across OEM builds. We do not recommend either for new code.

#### Timing checks

A process under a debugger is slower: breakpoints stop it, single-stepping is several orders of magnitude slower, and ART may fall back to the interpreter for code a JDWP debugger is watching. A timing check measures how long a short, predictable piece of work takes and treats an outlier as a signal.

OWASP's example measures `Debug.threadCpuTimeNanos()` around an empty loop. Two caveats. First, *CPU* time does not advance while a thread is stopped at a breakpoint, so this kind of check catches slow execution (interpretation, single-stepping) rather than a pause. To catch a pause, use a monotonic wall clock (`SystemClock.elapsedRealtimeNanos()` in Kotlin, `clock_gettime(CLOCK_MONOTONIC)` in C) around a section that should complete in microseconds. Second, an empty loop may be optimised away by R8 or the JIT, and thresholds that work on one phone fail on a slow device under load. Use generous thresholds, treat the result as one signal, and never terminate on a single sample.

```c
#include <time.h>

static long long now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/* Wrap a short, sensitive section. 200 ms is far beyond what it needs without a debugger. */
int sensitive_step_took_too_long(void (*step)(void)) {
    long long t0 = now_ns();
    step();
    return (now_ns() - t0) > 200000000LL;
}
```

#### TracerPid

On Linux, a process can be traced by at most one tracer at a time, and the kernel reports the tracer in the `TracerPid:` line of [`/proc/<pid>/status`](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html) (`0` when nobody traces it). lldb-server, gdbserver and `strace` all use `ptrace`, so while any of them is attached the value is the tracer's PID:

```bash
adb shell su -c 'grep TracerPid /proc/$(pidof com.example.app)/status'
```

```text
TracerPid:	11839
```

The app reads its own file. OWASP's demo (MASTG-DEMO-0116) does it three ways: from Kotlin with `File("/proc/self/status").readText()`, from C with `fopen`/`fgets`/`sscanf`, and from C with raw `openat`/`read`/`close` system calls issued by inline `svc #0` instructions so that hooks on libc functions do not see them:

```c
#include <stdio.h>
#include <string.h>

int tracer_pid(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    char line[256];
    int pid = -1;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            sscanf(line + 10, "%d", &pid);
            break;
        }
    }
    fclose(f);
    return pid;   /* >0: traced, 0: not traced, -1: could not read */
}
```

Points that matter when you assess an implementation:

- **It only sees `ptrace`.** A Java-only JDWP debugger leaves `TracerPid` at `0`.
- **Read `/proc/self/task/<tid>/status` too.** Threads can be traced individually; a debugger that attaches to one thread shows up in that thread's file. Robust implementations walk `/proc/self/task/`.
- **Frida briefly traces too.** On Android, frida-server injects its agent using `ptrace` and then detaches, so a tight polling loop can catch a non-zero `TracerPid` during injection. That is a bonus, not something to rely on.
- **Libc hooks defeat the simple version.** An attacker who hooks `fopen`, `read` or `fgets` can return a clean file. The inline-syscall variant forces them to patch your code instead, which is the point of it.
- **Kernels have been modified to lie.** On a fully attacker-controlled device, a custom kernel can report `0`. That is why the server, not the client, makes the final decision for anything important.

#### ptrace self-attach

Because only one tracer is allowed, an app can occupy the slot itself. Two patterns are common:

- **`ptrace(PTRACE_TRACEME, 0, NULL, NULL)`** asks the kernel to make the caller's parent its tracer. It fails with `EPERM` if the process is already traced, which makes the return value a detection signal. On Android the parent of an app process is zygote, which does not act as a debugger, so the side effects (signal stops reported to a parent that does not expect them) make this risky in practice. You see it more often in older or copied code than in current protection products.
- **Fork and attach to the parent.** The app forks a child, the child calls `ptrace(PTRACE_ATTACH, getppid(), ...)` or `PTRACE_SEIZE`, and from then on any external debugger's attach fails because the slot is taken. A failure in the child is itself a signal: OWASP's demo forks, tries `PTRACE_SEIZE` on the parent, and treats `EPERM` as "someone else is already tracing". Hardened variants keep the child alive as a watchdog, have parent and child monitor each other, and terminate the process group if the child dies, because the obvious attack is to kill the child and attach.

Two caveats for both. Whether an app process may `ptrace` its own parent or child depends on the kernel (Yama `ptrace_scope` where enabled) and on the device's SELinux policy, so an `EPERM` can come from policy rather than from a debugger; implementations must be tested on the OS versions they support. And `fork()` from a process that has started ART threads is fragile; the child should do as little as possible and never call back into Java.

#### Breakpoint scanning

A software breakpoint replaces an instruction with a trap. An app can scan its own sensitive functions for those trap instructions before running them:

| Architecture | Trap | Notes |
|---|---|---|
| AArch64 | `BRK #imm16`: base encoding `0xD4200000` with the 16-bit immediate in bits 5 to 20 | `BRK #0` is `0xD4200000`. lldb on AArch64 commonly uses a non-zero immediate, so match the whole class with the mask `0xFFE0001F`, not one value |
| x86 / x86-64 | `INT3`, the byte `0xCC` | Compilers pad between functions with `0xCC`, and the byte occurs inside other instructions, so scan only real instruction boundaries of a known function |
| 32-bit ARM | Debuggers often use an undefined-instruction pattern rather than `BKPT` | Hard to do reliably; few apps bother |

```c
#include <stddef.h>
#include <stdint.h>

/* Return 1 if any of the first n AArch64 instructions at fn is a BRK. */
int has_sw_breakpoint(const void *fn, size_t n) {
    const uint32_t *insn = (const uint32_t *)fn;
    for (size_t i = 0; i < n; i++) {
        if ((insn[i] & 0xFFE0001Fu) == 0xD4200000u) return 1;
    }
    return 0;
}
```

The limits: hardware breakpoints and watchpoints do not modify code and are invisible to a scan, and the check is part of the broader "is my code intact?" question that [MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/) covers (a Frida inline hook also rewrites the prologue).

#### One-shot versus continuous

A debugger can attach at any time. A check that runs once at start-up only proves nothing was attached at that instant; the attacker starts the app, waits, and attaches. Two complementary patterns fix this:

- **Checkpoints**: re-run cheap checks immediately before each sensitive action (key use, payment approval, PIN verification, export of data).
- **A watchdog**: a native thread that polls `TracerPid` (and, if used, the self-trace child) at a jittered interval while sensitive flows are active, and takes the response itself rather than calling back into Java.

```c
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

extern int tracer_pid(void);
extern void on_debugger_detected(void);   /* wipe transient secrets, flag the session, end the flow */

static void *watchdog(void *arg) {
    (void)arg;
    for (;;) {
        if (tracer_pid() > 0) on_debugger_detected();
        usleep(300000 + arc4random_uniform(400000));   /* 0.3 to 0.7 s, jittered */
    }
    return NULL;
}

void start_watchdog(void) {
    pthread_t t;
    pthread_create(&t, NULL, watchdog, NULL);
    pthread_detach(t);
}
```

OWASP's knowledge page ends with the classic fork-and-trace watchdog and an honest conclusion: killing the child, NOP-ing the `_exit` call or hooking `_exit` in libc gets past it, and each improvement invites a new bypass. That arms race is the nature of the control. The defender's goal is to make every round expensive and to keep the asset on the server.

#### How attackers get past these checks, in general terms

You need this to judge resistance in your report, not to build tooling: hooking the check APIs with Frida or an Xposed module so they return clean values; patching the compiled check (NOP the branch or the call) and re-signing; killing the self-trace child; hiding `TracerPid` with a modified kernel or a hooked `read`; and avoiding a debugger entirely by using instrumentation instead (which is why [MASWE-0065](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/) and [MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/) exist). A check that falls to the first of these in minutes earns little credit; one that needs the third or fourth, spread over many call sites and protected by integrity checks, earns a lot.

### iOS: Anti-Debugging Detection (MASTG-KNOW-0085)

Source: [MASTG-KNOW-0085](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0085/).

#### How debugging works on iOS

On iOS a debugger needs two things: the target's Mach task port (obtained through `task_for_pid`) to read and write memory and thread state, and `ptrace` for attach, continue and detach. The kernel only hands out a task port if the debugger is entitled to it and the target allows it. For an app that means the `get-task-allow` entitlement, which development-signed builds have and App Store builds do not ([MASWE-0063](/mobile/maswe-0063-debug-mechanisms-not-disabled/) covers that), or a debugger with `task_for_pid-allow` and related private entitlements on a jailbroken device (MASTG-TECH-0084). Debug events such as breakpoints are delivered as Mach exceptions to an exception port the debugger registers on the target task.

Anti-debugging on iOS is either **preventive** (stop the attach) or **reactive** (notice it and change behaviour). Every reactive check has to answer the same question as on Android: does it run at the right time, and does anything happen when it fires?

#### ptrace with PT_DENY_ATTACH

XNU's [`ptrace(2)`](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/ptrace.2.html) has a request that only makes sense for the target: `PT_DENY_ATTACH` (value `31`). If the calling process is not traced, the kernel sets a flag that makes later attach attempts fail. If it is already traced, the process exits with status `ENOTSUP` (45), which is what you see when you launch such an app under lldb:

```text
Process 2417 exited with status = 45 (0x0000002d)
```

`ptrace` is not declared in the public iOS SDK headers, so implementations declare the constant themselves and resolve the function at runtime:

```c
#include <dlfcn.h>
#include <sys/types.h>

#define PT_DENY_ATTACH 31
typedef int (*ptrace_fn)(int request, pid_t pid, caddr_t addr, int data);

void deny_attach(void) {
    ptrace_fn p = (ptrace_fn)dlsym(RTLD_DEFAULT, "ptrace");
    if (p) p(PT_DENY_ATTACH, 0, 0, 0);
}
```

Strengths and weaknesses:

- It is **preventive and cheap**, and it stops casual attach.
- It is **trivially visible**: the string `"ptrace"` next to `dlsym`, or the constant `0x1f` loaded before an indirect call. One hook on `ptrace` (or on `dlsym` returning a stub) neutralises it.
- Stronger implementations issue the system call directly with an inline `svc #0x80` and `x16 = 26` (`SYS_ptrace`), so there is no function to hook; the attacker must patch the instruction instead. Static analysis can find those instructions (see MASTG-TEST-0401).
- It is a **one-time call**. If the attacker suspends the app before `PT_DENY_ATTACH` runs (launch under a debugger with a breakpoint on `ptrace`), they can skip it.
- App Store review: calling non-public interfaces carries some review risk. Many shipping apps do it, but weigh it against your distribution model (OWASP raises the same caution).

#### sysctl and P_TRACED

Apple's own archived [Technical Q&A QA1361, "Detecting the Debugger"](https://developer.apple.com/library/archive/qa/qa1361/_index.html) shows the reactive check: ask the kernel for the current process's `kinfo_proc` and test `P_TRACED` in `kp_proc.p_flag`. Apple wrote it for debug builds, which is a reminder that it is a convenience, not a security boundary.

```swift
import Darwin

func isBeingTraced() -> Bool {
    var info = kinfo_proc()
    var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
    var size = MemoryLayout<kinfo_proc>.stride
    guard sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0) == 0 else { return false }
    return (info.kp_proc.p_flag & P_TRACED) != 0
}
```

`sysctl` is called by many libraries for innocent reasons (device model, memory size), so a `sysctl` import proves nothing. The anti-debugging fingerprint is the combination `CTL_KERN` (1), `KERN_PROC` (14), `KERN_PROC_PID` (1) and a test against `P_TRACED` (`0x800`). The Swift version above goes through the libc wrapper and can be hooked there; a version that issues `SYS___sysctl` (202) inline cannot. Run it at checkpoints, not once.

#### getppid

Apps on iOS are launched by `launchd`, PID 1, so `getppid()` normally returns `1`. An app launched by `debugserver` has the debugger as its parent. XNU has historically re-parented a process to its tracer on attach as well, but verify that on the iOS version you test rather than assuming it.

```c
#include <unistd.h>
int unexpected_parent(void) { return getppid() != 1; }
```

The check is cheap and almost free of false positives on a stock device, and it catches the "launch under debugger" workflow, but on its own it is one hook away from useless.

#### Mach exception ports

A debugger receives breakpoints and single-step events through an exception port registered for `EXC_MASK_BREAKPOINT` (and usually other masks). The app can ask which ports are registered on its own task:

```c
#include <mach/mach.h>

int breakpoint_port_registered(void) {
    exception_mask_t masks[EXC_TYPES_COUNT];
    mach_port_t ports[EXC_TYPES_COUNT];
    exception_behavior_t behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t flavors[EXC_TYPES_COUNT];
    mach_msg_type_number_t count = EXC_TYPES_COUNT;

    if (task_get_exception_ports(mach_task_self(), EXC_MASK_BREAKPOINT, masks, &count,
                                 ports, behaviors, flavors) != KERN_SUCCESS) return 0;
    for (mach_msg_type_number_t i = 0; i < count; i++) {
        if (MACH_PORT_VALID(ports[i])) return 1;
    }
    return 0;
}
```

This is a *supporting* signal. Crash reporters install task exception handlers too, and because Swift runtime traps on arm64 surface as `EXC_BREAKPOINT`, a crash SDK may register for exactly this mask. Test the check against the crash SDKs the app ships before you rely on it, and never terminate on it alone. Like the others, it can be hooked or run before the debugger attaches.

#### isatty and the terminal heuristic

Older guidance (including earlier MASTG editions) suggests `isatty(STDOUT_FILENO)` or `ioctl(STDOUT_FILENO, TIOCGWINSZ, ...)`: an app launched normally has its standard streams pointing at `/dev/null`, while one launched from a debugger with a console may have a terminal attached. It catches only that launch scenario, depends on how the debugger sets up stdio, and is easily hooked. If you find it, credit it as a weak extra signal and nothing more.

#### Putting the iOS signals together

| Signal | Kind | Catches | Typical weakness |
|---|---|---|---|
| `ptrace(PT_DENY_ATTACH)` | Preventive | Later attach; launch under debugger (process exits with 45) | One call, one hook; skipped if the app is suspended first |
| `sysctl` / `P_TRACED` | Reactive | Any traced state at the moment of the check | libc wrapper is hookable; must be repeated |
| `getppid() != 1` | Reactive | Launch under `debugserver` | Hookable; may miss a later attach |
| Exception port for `EXC_MASK_BREAKPOINT` | Reactive, supporting | Attached LLDB/debugserver | False positives from crash reporters |
| `isatty` | Reactive, weak | Launch with a terminal | Rarely meaningful today |

On a jailbroken device the attacker can also defeat all of these at once with tweaks and Frida scripts, which is why the tests below record *how long* the defences held, and why the backend should not trust the client's word.

### Generic: Debugging and Tracing (MASTG-KNOW-0114)

Source: [MASTG-KNOW-0114](https://mas.owasp.org/MASTG/knowledge/generic/MASVS-RESILIENCE/MASTG-KNOW-0114/). *Summary.*

Debugging means suspending a program and inspecting or changing its state: breakpoints, single-stepping, register and memory reads and writes. Reverse engineers use debuggers for exactly that, without caring about bugs. Tracing is the passive counterpart: logging what a program does (API calls, system calls, instructions) without stopping it. Tracing can be built on debugging APIs (`strace` uses `ptrace`, so `TracerPid` shows it), on function hooks (Frida's Interceptor, `frida-trace`), or on kernel facilities. Ole André Vadla Ravnås's ["Anatomy of a code tracer"](https://medium.com/@oleavr/anatomy-of-a-code-tracer-b081aadb0df8) explains how Frida's Stalker traces code by rewriting it on the fly. For this weakness the distinction matters in one way: debugger detection catches tracers built on `ptrace`, but not hook-based tracers, which is the territory of [MASWE-0065](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/).

## Tests

OWASP links four tests to this weakness, a static and a dynamic one per platform. They replace the legacy v1 tests MASTG-TEST-0046 "Testing Anti-Debugging Detection" (Android, `covered_by` 0352 and 0353) and MASTG-TEST-0089 (iOS, `covered_by` 0401 and 0402). All four are deliberately narrow: they establish that checks exist and run. They do not judge how hard the checks are to bypass, and OWASP says so explicitly. The legacy tests did ask that question (can it be bypassed with one hook, how long did it take, did you need custom code), and a report for an R-profile app should still answer it, so we keep that part as [After the tests: measuring resistance](#after-the-tests-measuring-resistance).

Run the static and the dynamic test of a platform together. Static analysis tells you where to look; dynamic analysis tells you whether that code runs in the release build and what it does. Either can miss checks the other finds.

### Before you start: getting a debugger onto a release app

The dynamic tests ask you to attach a real debugger and watch the app react. That requires a debugging route into a non-debuggable release build on your own test device, and the route you choose changes what the app can see. Write down which one you used.

**Android, JDWP (jdb or Android Studio).** In order of preference:

1. **A test build from the client** that is identical to the release build except for `android:debuggable="true"`. Easiest, but the app's own `FLAG_DEBUGGABLE` check will fire, which is a useful result in itself.
2. **An emulator or device running a `userdebug` image**, with JDWP enabled for all apps by the system properties described in the [MASWE-0063 note](/mobile/maswe-0063-debug-mechanisms-not-disabled/). The app's `FLAG_DEBUGGABLE` stays clear, so this tests whether the app also checks `isDebuggerConnected()`.
3. **A rooted device** with `ro.debuggable` spoofed (MASTG-TECH-0031) or with a module such as debugmepLS (Android 13+, LSPosed). Both bring their own artefacts (root, a hooking framework) that the app may detect for other reasons; separate those reactions from the debugger reaction.

Then attach:

```bash
# Start suspended, waiting for a debugger (only works when the process gets JDWP)
adb shell am start -D -n com.example.app/.MainActivity

adb jdwp                                   # lists PIDs that accept JDWP
adb forward tcp:7777 jdwp:$(adb shell pidof com.example.app)
{ echo "suspend"; cat; } | jdb -attach localhost:7777
```

In jdb, `resume`, `classes`, `stop in <class>.<method>` and `locals` are enough to confirm the attach works and to sit on a breakpoint while you exercise the app.

**Android, native (lldb).** You need root for a non-debuggable app. Take `lldb-server` for the device's ABI from the NDK (`toolchains/llvm/prebuilt/<host>/lib/clang/<version>/lib/linux/aarch64/lldb-server`; the exact path varies by NDK release):

```bash
adb push lldb-server /data/local/tmp/ && adb shell chmod 755 /data/local/tmp/lldb-server
adb shell su -c "/data/local/tmp/lldb-server platform --server --listen '*:1234'" &
adb forward tcp:1234 tcp:1234
lldb
```

```text
(lldb) platform select remote-android
(lldb) platform connect connect://localhost:1234
(lldb) process attach -p <pid>
```

Confirm with `adb shell su -c 'grep TracerPid /proc/<pid>/status'`. If you only need to make `TracerPid` non-zero (for example to test a watchdog), attaching `strace -p <pid>` as root is the quickest way, and it doubles as a system-call tracer.

**iOS.** Options, again in order of preference:

1. **A development-signed build** from the client, which carries `get-task-allow`. Attach from Xcode (Debug > Attach to Process) or launch it from Xcode to test the "launched under debugger" case.
2. **A jailbroken device** with `debugserver` re-signed with the entitlements in MASTG-TECH-0084, then `debugserver 0.0.0.0:1234 -a <pid>` (attach) or `debugserver -x backboard 0.0.0.0:1234 /path/to/App.app/App` (launch), and from the host `iproxy 1234 1234` and `(lldb) process connect connect://localhost:1234`.
3. **Re-signing the IPA with `get-task-allow`** (MASTG-TECH-0055). This changes the code signature, so integrity checks ([MASWE-0057](/mobile/maswe-0057-app-resources-integrity-not-verified/)) and app attestation ([MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/)) may fire as well.

Test both "launch under debugger" and "attach to a running app": `PT_DENY_ATTACH`, `getppid` and the timing of start-up checks behave differently in the two cases.

### MASTG-TEST-0352: References to Debugging Detection APIs (Android)

*OWASP test: [MASTG-TEST-0352](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0352/). Type: static, code, manual.*

#### Overview

The test looks for debugger checks in the app's code: JDWP checks in the DEX code and `ptrace`/`TracerPid`/inline-syscall patterns in the native libraries. It fails if there are none. It does not assess robustness, and a positive result is only a lead for MASTG-TEST-0353 and for the manual review that decides whether the check runs in release builds and leads to a response.

#### Prerequisites

- The APK and all splits (`adb shell pm path com.example.app`, then `adb pull` each path).
- jadx (MASTG-TECH-0013/0014), semgrep, `readelf` or `llvm-readelf`, `llvm-objdump` from the NDK, `strings`, and optionally radare2.
- The native libraries extracted (MASTG-TECH-0157): `unzip -o base.apk 'lib/*' -d app` and the same for the ABI split, e.g. `split_config.arm64_v8a.apk`.

#### Steps

1. **Decompile** the DEX code:

   ```bash
   jadx -d out base.apk
   ```

2. **Search the Java/Kotlin layer.** OWASP's rule (`mastg-android-debugger-checks.yml`) matches `Debug.isDebuggerConnected()` and `ApplicationInfo.FLAG_DEBUGGABLE`, and its native-indicator rule matches the strings `"/proc/self/status"`, `"TracerPid:"` and `PTRACE_(ATTACH|SEIZE)`. Our rule widens that to the other signals and to the forms that compiled code actually contains:

   ```yaml
   rules:
     - id: gt-android-debugger-signals
       languages: [java]
       severity: INFO
       message: Debugger or debug-environment signal (MASWE-0064)
       pattern-either:
         - pattern: Debug.isDebuggerConnected()
         - pattern: Debug.waitingForDebugger()
         - pattern: Debug.threadCpuTimeNanos()
         - pattern: ApplicationInfo.FLAG_DEBUGGABLE
         - pattern: '"adb_enabled"'
         - pattern: '"development_settings_enabled"'
         - pattern: '"/proc/self/status"'
         - pattern-regex: 'TracerPid|/proc/self/task|PTRACE_(ATTACH|SEIZE|TRACEME)'
         - pattern-regex: '\.flags\s*&\s*2\)'
   ```

   ```bash
   semgrep -c gt-debugger.yml out/sources --text
   ```

   A plain grep is a useful cross-check, because semgrep only reports what parses:

   ```bash
   grep -rnE 'isDebuggerConnected|waitingForDebugger|threadCpuTimeNanos|"adb_enabled"|TracerPid|/proc/self/(status|task)|\.flags & 2\)' out/sources
   ```

3. **Search the native libraries.** Imports, strings and inline system calls, per library:

   ```bash
   for so in app/lib/arm64-v8a/*.so; do
     echo "== $so"
     readelf --dyn-syms -W "$so" | awk '$7=="UND"{print $8}' \
       | grep -E '^(ptrace|fork|getppid|waitpid|prctl|clock_gettime|kill|_exit|syscall)(@|$)'
     strings -a "$so" | grep -E 'TracerPid|/proc/self/(status|task|maps)|/proc/%d/status' | sort -u
     echo "inline svc: $(llvm-objdump -d --no-show-raw-insn "$so" | grep -cE 'svc[[:space:]]+#0x0')"
   done
   ```

   Inline `svc #0` instructions outside libc are unusual in app code and are a strong hint of anti-debugging or anti-hooking logic. To see which system calls they make, look at the `x8` value loaded before each one (on arm64: `0x75` is `ptrace`, `0x38` `openat`, `0x3f` `read`, `0x81` `kill`, `0x5e` `exit_group`):

   ```bash
   llvm-objdump -d --no-show-raw-insn app/lib/arm64-v8a/libfoo.so \
     | grep -B4 -E 'svc[[:space:]]+#0x0' | grep -E 'mov[[:space:]]+x8|svc'
   ```

   OWASP's demo uses this radare2 script (`native_debugger_checks.r2`) for the same purpose:

   ```text
   e asm.bytes=false
   e scr.color=false
   izz~TracerPid,/proc/self/status
   ii~ptrace
   axt @ sym.imp.ptrace
   pd-- 16 @ `axtq @ sym.imp.ptrace`
   ```

   ```bash
   r2 -q -e bin.relocs.apply=true -i native_debugger_checks.r2 -A app/lib/arm64-v8a/libfoo.so
   ```

4. **Review every hit** in jadx or Ghidra (MASTG-TECH-0023 and MASTG-TECH-0018). For each one, answer: is it reachable in the release build (not behind `BuildConfig.DEBUG` or a disabled flag)? Where is it called from (start-up only, or before sensitive operations)? What happens with the result? Follow the boolean to its use; a check whose result is only logged is a finding.

5. **Attribute third-party hits.** Protection SDKs and some analytics SDKs carry their own checks. Note which hits are first-party and which come from a library, and whether the app actually initialises the library.

#### Observation

A list of code locations (class and method, or library and function/offset) with the matched API or pattern, the layer (Java/Kotlin, native, inline syscall), and for each the result of the manual review: release-reachable, call site and timing, response.

#### Evaluation

The test **fails** when neither the Java/Kotlin code nor any native library contains a debugger-detection pattern. It also fails, in our methodology, when the only checks found are dead code, debug-only, or have no effect on behaviour.

The test **passes** when at least one release-reachable check exists and its result leads to a response. Record the coverage in the report: JDWP only, native only, or both. An app with only `isDebuggerConnected()` passes OWASP's test but leaves native debugging uncovered; say so.

Expected false negatives: checks in obfuscated or packed code, in dynamically loaded DEX or native code ([MASWE-0049](/mobile/maswe-0049-unsafe-dynamic-code-loading/)), checks built from encrypted strings, and inline-syscall checks you did not look for. If static analysis finds nothing but you suspect a protection product (packed DEX, a native library with high entropy, a vendor name in the strings), rely on MASTG-TEST-0353 and on attaching a debugger.

Expected false positives: `Debug.isDebuggerConnected()` used by libraries to relax timeouts while developers debug (common in test and DI frameworks), and `/proc/self/status` reads for memory statistics (`VmRSS`). The manual review step separates them.

#### Demo

OWASP has two demos for this test, both "pass" samples.

[MASTG-DEMO-0115](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0115/MASTG-DEMO-0115/) calls the JDWP check:

```kotlin
val debuggerConnected = Debug.isDebuggerConnected()
if (debuggerConnected) {
    r.add(Status.FAIL, "Debug.isDebuggerConnected reports an attached JDWP debugger.")
} else {
    r.add(Status.PASS, "Debug.isDebuggerConnected reports no attached JDWP debugger.")
}
```

```text
    MastgTest_reversed.java
    ❯❱ rules.mastg-android-debugger-checks
          [MASVS-RESILIENCE-4] debugger checks detected.

           23┆ boolean debuggerConnected = Debug.isDebuggerConnected();
```

[MASTG-DEMO-0116](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0116/MASTG-DEMO-0116/) adds the native layer: a Kotlin `TracerPid` reader, a C `TracerPid` reader, the inline-syscall reader shown in the Knowledge section, and a fork-based `ptrace` self-check. The self-check, abridged:

```c
pid_t child = fork();
if (child == 0) {
    errno = 0;
    if (ptrace(PTRACE_SEIZE, getppid(), NULL, NULL) == 0) _exit(0);   /* no other tracer */
    _exit(errno == EPERM ? 1 : 2);                                    /* 1: probably traced */
}
int status = 0;
waitpid(child, &status, 0);
return WIFEXITED(status) ? WEXITSTATUS(status) : 2;
```

The semgrep rule finds the Kotlin side, and radare2 finds the native side, including the `PTRACE_SEIZE` request (`0x4206`) loaded before the call:

```text
    MastgTest_reversed.java
    ❯❱ rules.mastg-android-native-debugger-checks
          126┆ String statusText = FilesKt.readText$default(new File("/proc/self/status"), null, 1, null);
          133┆ if (StringsKt.startsWith$default(it2, "TracerPid:", false, 2, (Object) null)) {

Imported ptrace symbol:
16  0x000021c0 GLOBAL FUNC     ptrace

Cross-references to ptrace:
dbg.Java_org_owasp_mastestapp_MastgTest_ptraceSelfDetectNative 0x1fc4 [CALL:--x] bl sym.imp.ptrace

│      ││   0x00001fb8      mov w0, 0x4206      ; if (ptrace(PTRACE_SEIZE, parent_pid, nullptr, nullptr) == 0)
│           0x00001fc4      bl sym.imp.ptrace
```

Two things the demo does not show, and that you should look for in real apps: the inline-syscall reader has no `ptrace` import and no `fopen` of the path through libc, so only the `/proc/self/status` string and the `svc #0` instructions give it away; and the demo's sample library is unstripped and has DWARF info (`dbg.` names, source lines), which a release library will not.

### MASTG-TEST-0353: Runtime Use of Debugging Detection APIs (Android)

*OWASP test: [MASTG-TEST-0353](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0353/). Type: dynamic, hooks, manual.*

#### Overview

Static presence is not enough: a check can be debug-only, dead, or run once at start-up. This test hooks the debugger-detection APIs and traces the related system calls while you use the app, to see which checks really run, when, from where, and what they return. Then you attach a real debugger (MASTG-TECH-0031) and watch the response.

#### Prerequisites

- A rooted test device or an emulator with frida-server matching your Frida client version (see our [lab set-up note](/mobile/mobile-traffic-interception-lab/)), or the app repackaged with Frida Gadget if you cannot root.
- The release build installed (MASTG-TECH-0005), and a debugging route from [Before you start](#before-you-start-getting-a-debugger-onto-a-release-app).
- The hit list from MASTG-TEST-0352, so you know which app functions to watch.
- Be aware that Frida itself is an instrumentation tool. If the app detects it ([MASWE-0065](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/)), the app may react to Frida rather than to the debugger. Run the debugger part of the test once without Frida as well.

#### Steps

1. **Trace the app's checks** (MASTG-TECH-0043 and MASTG-TECH-0032). The script below only observes: it logs calls to the JDWP APIs, reads of `Settings.Global` debug keys, opens of `/proc/.../status`, and `ptrace` requests, each with a backtrace. It changes no return values. Written for Frida 17.

   ```javascript
   // trace-debug-checks.js: observe the app's own debugger checks, change nothing
   const libc = Process.getModuleByName('libc.so');

   function nbt(ctx) {
     return Thread.backtrace(ctx, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n    ');
   }

   ['open', 'openat'].forEach((name) => {
     const addr = libc.findExportByName(name);
     if (addr === null) return;
     Interceptor.attach(addr, {
       onEnter(args) {
         const path = (name === 'open' ? args[0] : args[1]).readCString();
         if (path && /\/proc\/(self|\d+)\/(task\/\d+\/)?status/.test(path)) {
           console.log(`[${name}] ${path}\n    ${nbt(this.context)}`);
         }
       }
     });
   });

   Interceptor.attach(libc.getExportByName('ptrace'), {
     onEnter(args) {
       this.req = args[0].toInt32();
       this.pid = args[1].toInt32();
     },
     onLeave(ret) {
       console.log(`[ptrace] request=0x${this.req.toString(16)} pid=${this.pid} ret=${ret.toInt32()}`);
     }
   });

   Java.perform(() => {
     const Log = Java.use('android.util.Log');
     const Exc = Java.use('java.lang.Exception');
     const jbt = () => Log.getStackTraceString(Exc.$new());

     const Debug = Java.use('android.os.Debug');
     ['isDebuggerConnected', 'waitingForDebugger'].forEach((m) => {
       Debug[m].implementation = function () {
         const r = this[m]();
         console.log(`[Debug.${m}] -> ${r}\n${jbt()}`);
         return r;
       };
     });

     const Global = Java.use('android.provider.Settings$Global');
     Global.getInt.overloads.forEach((o) => {
       o.implementation = function (...a) {
         const r = o.apply(this, a);
         if (/adb|development/.test(String(a[1]))) console.log(`[Settings.Global.getInt] ${a[1]} -> ${r}\n${jbt()}`);
         return r;
       };
     });
   });
   ```

   ```bash
   frida -U -f com.example.app -l trace-debug-checks.js
   ```

   If the app reads `ApplicationInfo.flags` directly, there is no method to hook; hook the app's own wrapper method found in MASTG-TEST-0352 instead (`frida-trace -U -f com.example.app -j 'com.example.app.security.*!*'` traces a whole package). Inline-syscall checks bypass libc and do not appear here at all; for those, a root `strace -f -e trace=openat,read,ptrace -p <pid>` shows them, and because `strace` attaches with `ptrace`, a working `TracerPid` check will also fire.

2. **Exercise the app.** Log in, reach every sensitive flow (payments, key operations, viewing secrets), background and resume the app, and leave it idle for a few minutes. Note *when* each check fires: only at start-up, on every sensitive action, or periodically.

3. **Attach a JDWP debugger** (without Frida) as described in [Before you start](#before-you-start-getting-a-debugger-onto-a-release-app). Try both: launch with `am start -D` and attach before anything runs, and attach to an app that is already running and logged in. Then trigger a sensitive flow and record what happens.

4. **Attach a native debugger** (lldb or `strace`) to the running app, then trigger a sensitive flow. Record what happens and after how long.

#### Observation

- The trace log: which checks ran, with return values and backtraces pointing into app code, and at which moments.
- For each debugger type and attach scenario: the app's behaviour (nothing, a warning, the flow refused, logout, termination, and whether a backend signal was sent, which you can see in the proxy).
- The time between attach and reaction, which tells you whether checks are continuous.

Illustrative output (not from a real app):

```text
[Debug.isDebuggerConnected] -> false
java.lang.Exception
	at android.os.Debug.isDebuggerConnected(Native Method)
	at com.example.app.a.c.b(SourceFile:41)
	at com.example.app.App.onCreate(SourceFile:22)
[openat] /proc/self/status
    0x7a1c2f1a34 libguard.so!0x1a34
    0x7a1c2f0f88 libguard.so!0x0f88
[ptrace] request=0x4206 pid=13021 ret=0
```

#### Evaluation

The test **fails** when no debugger-detection call is observed while you exercise the app. In our methodology it also fails, and you should report it, when:

- checks run only once at start-up, and attaching afterwards goes unnoticed;
- only JDWP is covered and a native debugger attaches unnoticed (or the reverse, for an app whose logic is native);
- a check fires but the app does not react in any way that protects the flow (no termination, no refusal, no re-authentication, no server signal).

It **passes** when checks run in the release build, around the sensitive flows and not only at start-up, cover the debugger types relevant to where the app's logic lives, and lead to a response. A pass here says nothing about how hard the checks are to bypass; that goes into [measuring resistance](#after-the-tests-measuring-resistance).

Expected false negatives: checks that run before Frida's hooks are installed (use spawn mode, `-f`, to reduce this), checks implemented with inline syscalls, and checks that the app disables when it detects Frida.

#### Demo

OWASP has no demo for this test. The demos for MASTG-TEST-0352 are the natural targets: run MASTG-DEMO-0116's app with the script above, and you see the Kotlin and C `TracerPid` readers open `/proc/self/status` and the self-check issue `ptrace` request `0x4206` (`PTRACE_SEIZE`). The inline-syscall reader does not appear in the trace, which is exactly its purpose. Attach `strace` to the process as root and tap the demo's button again: all three `TracerPid` readers now report the tracer's PID.

### MASTG-TEST-0401: References to Debugging Detection APIs (iOS)

*OWASP test: [MASTG-TEST-0401](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0401/). Type: static, code, manual.*

#### Overview

The test looks for anti-debugging patterns in the app's Mach-O binaries: `ptrace` and `PT_DENY_ATTACH`, `sysctl` with `KERN_PROC_PID` and `P_TRACED`, `getppid`, `task_get_exception_ports` with `EXC_MASK_BREAKPOINT`, the `dlsym` lookups that hide them, and inline system calls. Whether the app is *debuggable* (`get-task-allow`) is a different test, MASTG-TEST-0261, in the [MASWE-0063 note](/mobile/maswe-0063-debug-mechanisms-not-disabled/).

#### Prerequisites

- A **decrypted** IPA (App Store binaries are FairPlay-encrypted; MASTG-TECH-0058 and our [lab note](/mobile/mobile-traffic-interception-lab/) cover obtaining one), or a build from the client.
- macOS with Xcode command-line tools (`otool`, `nm`, `strings`) or radare2/rabin2 on any platform, and Ghidra for review (MASTG-TECH-0076).

#### Steps

1. **Unpack and list the Mach-O files**: the main executable, frameworks and app extensions.

   ```bash
   unzip -q App.ipa -d ipa
   APP=$(ls -d ipa/Payload/*.app)
   find "$APP" -type f -exec sh -c 'file "$1" | grep -q "Mach-O" && echo "$1"' _ {} \;
   ```

2. **Look for imports and strings** in each binary:

   ```bash
   BIN="$APP/$(plutil -extract CFBundleExecutable raw "$APP/Info.plist")"
   nm -u "$BIN" | grep -E '^_(ptrace|sysctl|getppid|task_get_exception_ports|isatty|ioctl|dlsym)$'
   strings -a "$BIN" | grep -xE 'ptrace|sysctl|task_get_exception_ports|PT_DENY_ATTACH'
   ```

   A `_dlsym` import plus the string `ptrace` is the classic `PT_DENY_ATTACH` pattern. `_sysctl` alone is common and harmless; it becomes interesting in combination with `getpid` and a test of `0x800` on the result. With rabin2: `rabin2 -i "$BIN" | grep -E 'ptrace|sysctl|getppid|task_get_exception_ports'` and `rabin2 -zz "$BIN" | grep -w ptrace`.

3. **Look for inline system calls.** App code does not normally contain `svc #0x80`; when it does, the value in `x16` says which call it is (`0x1a` = 26 `ptrace`, `0xca` = 202 `__sysctl`, `0x27` = 39 `getppid`, `0x25` = 37 `kill`, `0x1` = `exit`):

   ```bash
   otool -tv "$BIN" | grep -B4 -E 'svc[[:space:]]+#0x80' | grep -E 'mov[[:space:]]+(x|w)16|svc'
   ```

4. **Review the hits** in Ghidra or Hopper. Follow the `ptrace` pointer returned by `dlsym` to the call and check the first argument (`mov w0, #0x1f` is `PT_DENY_ATTACH`). For `sysctl`, check the MIB (`1, 14, 1, pid`) and the `0x800` test. For each check, find the call sites: only in `main`/`application(_:didFinishLaunchingWithOptions:)`, or also around sensitive flows? And what does the code do with the result?

5. **Attribute** hits to first-party code or to bundled frameworks (protection SDKs ship their own), and confirm the framework is actually initialised.

#### Observation

A list of binaries and functions or offsets with the matched API, constant or instruction, the call sites, and the response each one leads to.

#### Evaluation

The test **fails** when neither the main executable nor any bundled Mach-O library contains a debugger-detection pattern, or (our addition) when the only patterns found are unreachable, debug-only, or lead to no response.

It **passes** when release code contains at least one reachable check with a response. Note in the report whether it is preventive only (`PT_DENY_ATTACH` once at start-up), reactive, or both, and whether it is executed only at start-up.

Expected false negatives: obfuscated or encrypted strings, inline syscalls you did not search for, indirect calls through computed pointers, and checks inside a protection SDK that are hard to separate from the rest of its code. Expected false positives: `sysctl` for hardware information, `isatty` in logging libraries, `task_get_exception_ports` in crash reporters.

#### Demo

OWASP has no demo for this test. Our minimal sample combines the preventive and the reactive check:

```objectivec
#import <dlfcn.h>
#import <sys/sysctl.h>
#import <unistd.h>

static void gt_deny_attach(void) {
    int (*p)(int, pid_t, caddr_t, int) = dlsym(RTLD_DEFAULT, "ptrace");
    if (p) p(31 /* PT_DENY_ATTACH */, 0, 0, 0);
}

static BOOL gt_is_traced(void) {
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
    struct kinfo_proc info;
    size_t size = sizeof(info);
    memset(&info, 0, sizeof(info));
    if (sysctl(mib, 4, &info, &size, NULL, 0) != 0) return NO;
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}
```

Illustrative output of step 2 on the built sample:

```text
$ nm -u GTSample | grep -E '^_(ptrace|sysctl|getppid|dlsym)$'
_dlsym
_sysctl
$ strings -a GTSample | grep -xE 'ptrace'
ptrace
```

`ptrace` never appears as an import, only as a string next to `dlsym`. That is the pattern to look for.

### MASTG-TEST-0402: Runtime Use of Debugging Detection APIs (iOS)

*OWASP test: [MASTG-TEST-0402](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0402/). Type: dynamic, hooks, manual.*

#### Overview

The dynamic counterpart: hook the anti-debugging APIs (MASTG-TECH-0095) while you exercise the app, see which checks run and when, then attach a debugger (MASTG-TECH-0084, or MASTG-TECH-0055 for a re-signed debuggable build) and observe the reaction.

#### Prerequisites

- A jailbroken test device with frida-server, or the app with Frida Gadget embedded; a debugging route from [Before you start](#before-you-start-getting-a-debugger-onto-a-release-app).
- The hit list from MASTG-TEST-0401.
- As on Android, the app may react to Frida itself or to the jailbreak; separate those reactions from the debugger reaction by repeating the debugger part without Frida.

#### Steps

1. **Trace the checks.** Observation only; written for Frida 17. The `sysctl` hook decodes the `KERN_PROC_PID` query and reports whether the kernel's answer had `P_TRACED` set (`p_flag` is at offset 32 in `kinfo_proc` on arm64).

   ```javascript
   // trace-ios-debug-checks.js: observe the app's own debugger checks, change nothing
   function nbt(ctx) {
     return Thread.backtrace(ctx, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n    ');
   }
   function hook(name, callbacks) {
     const addr = Module.findGlobalExportByName(name);
     if (addr === null) {
       console.log(`[!] ${name} not found`);
       return;
     }
     Interceptor.attach(addr, callbacks);
   }

   hook('ptrace', {
     onEnter(a) {
       console.log(`[ptrace] request=${a[0].toInt32()}\n    ${nbt(this.context)}`);
     }
   });

   hook('sysctl', {
     onEnter(a) {
       const mib = a[0];
       this.procPid = a[1].toUInt32() === 4 && mib.readS32() === 1 &&
                      mib.add(4).readS32() === 14 && mib.add(8).readS32() === 1;
       this.info = a[2];
       if (this.procPid) this.bt = nbt(this.context);
     },
     onLeave(ret) {
       if (!this.procPid || this.info.isNull()) return;
       const traced = (this.info.add(32).readS32() & 0x800) !== 0;
       console.log(`[sysctl KERN_PROC_PID] ret=${ret.toInt32()} P_TRACED=${traced}\n    ${this.bt}`);
     }
   });

   hook('getppid', {
     onLeave(r) {
       console.log(`[getppid] -> ${r.toInt32()}`);
     }
   });

   hook('task_get_exception_ports', {
     onEnter(a) {
       console.log(`[task_get_exception_ports] mask=0x${a[1].toUInt32().toString(16)}`);
     }
   });

   hook('dlsym', {
     onEnter(a) {
       this.sym = a[1].readCString();
     },
     onLeave() {
       if (/^(ptrace|sysctl|task_get_exception_ports)$/.test(this.sym || '')) {
         console.log(`[dlsym] ${this.sym}`);
       }
     }
   });
   ```

   ```bash
   frida -U -f com.example.app -l trace-ios-debug-checks.js
   ```

   To trace the app's own wrapper functions found in MASTG-TEST-0401, add `frida-trace -U -f com.example.app -m '-[GTSecurity *]'` for Objective-C, or `-a 'App!0x1a2b4'` for an unexported function at a known offset.

2. **Exercise the app** through every sensitive flow, background and foreground it, and leave it idle. Note when checks fire.

3. **Attach a debugger without Frida**, in both scenarios: launch the app under the debugger, and attach to the running, logged-in app. Then trigger sensitive flows.

#### Observation

The trace log with return values and backtraces; for each attach scenario, whether the attach succeeded at all (a `PT_DENY_ATTACH` app refuses it, or exits with status 45 when launched under the debugger), what the app did, how quickly, and whether a backend signal appeared in the proxy.

Illustrative output (not from a real app):

```text
[dlsym] ptrace
[ptrace] request=31
    0x1022c4a10 App!0x8a10
[sysctl KERN_PROC_PID] ret=0 P_TRACED=false
    0x1022c5b3c App!0x9b3c
[getppid] -> 1
```

#### Evaluation

The test **fails** when no anti-debugging call is observed. In our methodology it also fails when the only check is a single start-up `PT_DENY_ATTACH` (or a single start-up `sysctl`), so that suspending the app before it runs, or attaching after it ran and was neutralised, goes unnoticed for the rest of the session; or when checks fire but nothing protects the flow.

It **passes** when checks run in the release build, around sensitive flows, with a response. As with Android, robustness is assessed separately.

Expected false negatives: checks issued with inline `svc #0x80` (invisible to these hooks; static analysis finds them), checks that run before the hooks are installed, and checks that are skipped because the app has already reacted to the jailbreak or to Frida.

#### Demo

OWASP has no demo for this test. With our sample from MASTG-TEST-0401 calling `gt_deny_attach()` in `main` and `gt_is_traced()` before a "reveal secret" action, the trace shows `[dlsym] ptrace` and `[ptrace] request=31` once at launch, and one `[sysctl KERN_PROC_PID]` line per tap. Launching the sample from lldb ends with `exited with status = 45`, and attaching to it after launch fails. Remove the `gt_deny_attach()` call, attach, tap the button, and the trace reports `P_TRACED=true`: the reactive check works, and the remaining question is what the app does with it.

### After the tests: measuring resistance

*Guler Tech methodology, adapted from the effectiveness assessment in the legacy MASTG-TEST-0046 and MASTG-TEST-0089.*

The OWASP v2 tests stop at "the checks exist and run". For an R-profile app, the client is paying to learn how much they cost an attacker. Measure it on your own test device, against the app's own checks only, with well-known techniques, and stop at the first level that works:

| Level | What you do | What it tells you |
|---|---|---|
| 1 | Attach jdb/lldb with no preparation | Whether any check fires at all |
| 2 | Generic tooling: objection's built-in options, a public "anti-debug" Frida snippet hooking `isDebuggerConnected`, `ptrace` and `sysctl` | Whether checks are only the textbook APIs |
| 3 | One targeted hook: a short Frida script that makes the app's own detection method (found in the static test) return "clean" | Whether there is a single choke point |
| 4 | Several targeted hooks or patches, including native code and inline syscalls | How distributed and layered the checks are |
| 5 | Patching and re-signing the binary | Whether integrity checks ([MASWE-0057](/mobile/maswe-0057-app-resources-integrity-not-verified/), [MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/)) and attestation ([MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/)) catch the modified app, and whether the backend notices |

Record, per platform: the level at which the debugger could be used freely in a sensitive flow, the time it took, whether you needed custom code, how many distinct checks you had to neutralise, and whether the backend reacted at any point (a risk signal, a refused transaction, a forced logout). The legacy tests' questions remain good report headings: can it be bypassed with one hook; how hard was the code to find statically and dynamically; did you need custom code, and how long did it take; and your overall assessment.

Keep the scope tight. Neutralise only the app's own checks, on your own device, and do not use the bypass to go further than proving that sensitive data or a sensitive decision is exposed (for example, showing that a breakpoint lets you read the session token or flip the outcome of a local PIN check).

## Best practices

OWASP's cross-cutting BEST-0029 ("Implementing Resilience and RASP Signals") is summarised in the [series hub](/mobile/masvs-resilience-resilience-testing-guide/). Two best practices are specific to this weakness.

### Continuous Anti-Debugging Checks (MASTG-BEST-0047)

Source: [MASTG-BEST-0047](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0047/) (Android).

- Do not rely on a start-up check. Re-check debugger state immediately before sensitive actions (key use, payment approval, privileged API calls, secrets access) and periodically while those flows are active.
- Combine `Debug.isDebuggerConnected()` in Java/Kotlin with native checks (`TracerPid`, `ptrace`) in the JNI paths that matter.
- Avoid tight polling loops; they cost battery and are easy to spot. Checkpoints plus short, jittered polling during sensitive flows give most of the benefit.
- Treat the result as defence in depth. Hooks, patching and instrumentation will eventually get past it.

What we add from testing experience: put the response in native code too, so that one hook on a Java callback does not neutralise a native check; and do not let the Java and native checks share a single JNI entry point with a readable name.

### Implementing Anti-Debugging Checks on iOS (MASTG-BEST-0074)

Source: [MASTG-BEST-0074](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0074/).

- **Layer signals**: `PT_DENY_ATTACH` where the distribution model allows it, `sysctl`/`P_TRACED`, parent-process and exception-port checks. Validate that any non-public API use is acceptable for App Store review.
- **Check sensitive flows**: key unwrapping or signing, payment approval, authentication and step-up, secrets access, premium enforcement, high-risk transaction submission.
- **Harden the check and the response**: obfuscate, avoid a single named dispatch function, prefer inline C (or inline syscalls) to Swift/Objective-C methods that Frida's bridges can replace by name.
- **Respond in proportion**: stop the operation, clear transient secrets, require re-authentication, reduce functionality, or send a generic risk signal to the backend. Do not reveal the reason to the client.
- **Test in release builds**: debug-only paths, start-up-only checks and single-hook responses give little resilience.

### Response design

Detection is only half the control, and it is where most implementations we test are weakest.

- **Protect the asset, not the process.** Killing the app is the obvious response, but it also shows the attacker exactly where the check is (the crash backtrace points at it). Often better: abort the sensitive operation, zero the transient secrets in memory, invalidate the local session, and let the server decide what happens next.
- **Report to the backend, quietly.** A generic "risk" flag attached to the next request (or a separate, signed telemetry call) lets the server step up authentication, hold a transaction, or flag the account without telling the client which check fired. Combine it with app attestation so a client that simply stops sending the flag is also treated as risky.
- **Delay and vary.** A response that happens some time after detection, or on the next sensitive action rather than at the check, makes the cause-and-effect harder to trace.
- **Avoid false-positive traps.** Do not terminate on `ADB_ENABLED`, on a single timing sample, or on an exception port that a crash reporter may own. Weigh weak signals; act hard only on strong ones (`TracerPid` > 0, `P_TRACED`, an attached JDWP debugger).
- **Keep the check and the response apart.** If one function both detects and reacts, one patch disables both.

## Rating findings

Apply the series-wide rules, adapted to debugger detection:

- **Not an R-profile app**: missing or weak debugger detection is **Info**. Mention it as an observation and move on.
- **R-profile app, no debugger detection, or only a start-up/JDWP-only check**: usually **Low**, **Medium** when sensitive logic or secrets live on the client and a debugger gives direct access to them (an offline PIN check, a key or token in memory that unlocks something valuable, a licence or DRM decision made locally).
- **Medium to High** only when the gap directly enables a concrete business abuse that you demonstrate: for example, a breakpoint that flips the result of a client-side transaction-signing or limit check the server trusts, or extracts a long-lived secret that lets an attacker act as the app at scale. In that case the root cause is usually also an L1/L2 issue (a decision that should be on the server, a secret that should not be on the client); report that as its own finding, rated on its own merits.
- **Detection exists but falls to one hook or one patch**: rate by what the bypass unlocks, using the same scale. A trivially bypassed check protecting nothing of value is Info; one that is the only barrier in front of a valuable client-side decision is rated like a missing control.
- **Debuggable release builds** (`android:debuggable="true"`, `get-task-allow` in an App Store or enterprise build) are a real vulnerability regardless of profile. Rate them under [MASWE-0063](/mobile/maswe-0063-debug-mechanisms-not-disabled/), not here.
- **Usability issues**: an app that blocks users because USB debugging or Developer options are on is not a security finding, but it is worth an Info note recommending that the check be turned into a weighted signal.

In the report give: which checks you found (layer, API, location), when they run, what they do on detection, the debugger types and attach scenarios you tried with the observed result, the resistance level and time from [measuring resistance](#after-the-tests-measuring-resistance), and what a debugger exposed when it was not stopped.

## References

- OWASP MASWE: [MASWE-0064: Debugger Detection Not Implemented](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0064/); related [MASWE-0063](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0063/), [MASWE-0065](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0065/), [MASWE-0058](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0058/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-RESILIENCE-4](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-4/) (CC BY-SA 4.0)
- OWASP MASTG knowledge: [MASTG-KNOW-0028](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0028/), [MASTG-KNOW-0085](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0085/), [MASTG-KNOW-0114](https://mas.owasp.org/MASTG/knowledge/generic/MASVS-RESILIENCE/MASTG-KNOW-0114/) (CC BY-SA 4.0)
- OWASP MASTG tests: [MASTG-TEST-0352](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0352/), [MASTG-TEST-0353](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0353/), [MASTG-TEST-0401](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0401/), [MASTG-TEST-0402](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0402/); legacy [MASTG-TEST-0046](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0046/), [MASTG-TEST-0089](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0089/) (CC BY-SA 4.0)
- OWASP MASTG demos: [MASTG-DEMO-0115](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0115/MASTG-DEMO-0115/), [MASTG-DEMO-0116](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0116/MASTG-DEMO-0116/) (CC BY-SA 4.0)
- OWASP MASTG best practices: [MASTG-BEST-0047](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0047/), [MASTG-BEST-0074](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0074/), [MASTG-BEST-0029](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0029/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0031 Debugging (Android)](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0031/), [MASTG-TECH-0084 Debugging (iOS)](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0084/), [MASTG-TECH-0055](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0055/), [MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/), [MASTG-TECH-0032](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0032/), [MASTG-TECH-0095](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0095/), [MASTG-TECH-0157](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0157/), [MASTG-TECH-0018](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0018/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0076](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076/) (CC BY-SA 4.0)
- OWASP MASTG tools: [jdb (MASTG-TOOL-0019)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0019/), [lldb for Android (MASTG-TOOL-0152)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0152/), [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/), [radare2 (MASTG-TOOL-0073)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/), [Frida (MASTG-TOOL-0031)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/), [debugmepLS (MASTG-TOOL-0151)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0151/) (CC BY-SA 4.0)
- Android: [`Debug`](https://developer.android.com/reference/android/os/Debug), [`ApplicationInfo.FLAG_DEBUGGABLE`](https://developer.android.com/reference/android/content/pm/ApplicationInfo#FLAG_DEBUGGABLE), [`Settings.Global.ADB_ENABLED`](https://developer.android.com/reference/android/provider/Settings.Global#ADB_ENABLED), [Debug your app (Android Studio)](https://developer.android.com/studio/debug), [Use debuggers (AOSP)](https://source.android.com/docs/core/tests/debug/gdb)
- Linux: [proc_pid_status(5)](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html), [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html), [Yama LSM](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
- Arm: [BRK instruction (Arm A64 ISA)](https://developer.arm.com/documentation/ddi0602/latest/Base-Instructions/BRK--Breakpoint-instruction-)
- Apple: [ptrace(2)](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/ptrace.2.html), [sysctl(3)](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/sysctl.3.html), [Technical Q&A QA1361: Detecting the Debugger](https://developer.apple.com/library/archive/qa/qa1361/_index.html)
- Background: Ole André Vadla Ravnås, ["Anatomy of a code tracer"](https://medium.com/@oleavr/anatomy-of-a-code-tracer-b081aadb0df8); [Frida JavaScript API](https://frida.re/docs/javascript-api/)
- CWE: [CWE-693](https://cwe.mitre.org/data/definitions/693.html) (our mapping; OWASP gives none)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
