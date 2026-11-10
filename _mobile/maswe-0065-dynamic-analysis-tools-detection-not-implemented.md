---
title: "MASWE-0065: Dynamic Analysis Tools Detection Not Implemented"
date: 2026-11-10 20:14:00 +0000
subcategory: resilience
summary: "Testing whether apps detect Frida, Xposed/LSPosed, Substrate/ElleKit and objection, how shallow the artefact checks are, and how they respond."
refs: [MASWE-0065, MASVS-RESILIENCE-4]
tags: [android, ios, masvs-resilience, frida, instrumentation, anti-hooking]
---

This note is part of our [MASVS-RESILIENCE guide](/mobile/masvs-resilience-resilience-testing-guide/) and covers OWASP [MASWE-0065](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0065/): an app that does not notice when dynamic instrumentation and hooking frameworks are running on the device or inside its own process. Frida, Xposed and LSPosed, Cydia Substrate and ElleKit let an attacker replace any function in a running app, read its arguments and change its results. They are how most client-side controls are defeated in practice, and they are the everyday tools of anyone testing mobile apps, including us. Detecting them is possible because each leaves traces: a listening port, a library in the memory map, a named thread, a pipe, a class on the class path, a dylib in dyld's list. It is also hard to do well, because every one of those traces can be renamed or hidden by someone who knows what you look for. This note explains the artefacts per tool and per platform, why each check on its own is shallow, how layering and a sensible response make the control worth having, and how to test it. OWASP has **no tests of its own** for this weakness; the four tests below are ours. Debugger detection is the sibling note [MASWE-0064](/mobile/maswe-0064-debugger-detection-not-implemented/), and detection of hooks by their effect on code (whatever tool placed them) is [MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/).

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: Reverse Engineering Tool Detection (MASTG-KNOW-0030)](#android-reverse-engineering-tool-detection-mastg-know-0030)
  - [iOS: Reverse Engineering Tools Detection (MASTG-KNOW-0087)](#ios-reverse-engineering-tools-detection-mastg-know-0087)
  - [Generic: Dynamic Binary Instrumentation (MASTG-KNOW-0115)](#generic-dynamic-binary-instrumentation-mastg-know-0115)
- [Tests](#tests)
  - [Where the OWASP tests are](#where-the-owasp-tests-are)
  - [GT-RES-0065-1: Static identification of tool-detection checks (Android, iOS)](#gt-res-0065-1-static-identification-of-tool-detection-checks-android-ios)
  - [GT-RES-0065-2: Runtime detection of a default Frida set-up (Android, iOS)](#gt-res-0065-2-runtime-detection-of-a-default-frida-set-up-android-ios)
  - [GT-RES-0065-3: Resistance to a renamed, relocated Frida (Android, iOS)](#gt-res-0065-3-resistance-to-a-renamed-relocated-frida-android-ios)
  - [GT-RES-0065-4: Hooking frameworks on the device (Android, iOS)](#gt-res-0065-4-hooking-frameworks-on-the-device-android-ios)
- [Best practices](#best-practices)
  - [Hardening Against Reverse Engineering Tools (MASTG-BEST-0048)](#hardening-against-reverse-engineering-tools-mastg-best-0048)
  - [Hardening Against Virtual Devices (MASTG-BEST-0053)](#hardening-against-virtual-devices-mastg-best-0053)
  - [Layering and response](#layering-and-response)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

OWASP's requirement is *"The app detects dynamic analysis tools and responds to protect sensitive operations."* It maps to MASVS-RESILIENCE-4 ("The app implements anti-dynamic analysis techniques") and to the v1 requirement MSTG-RESILIENCE-4. OWASP gives no CWE; [CWE-693](https://cwe.mitre.org/data/definitions/693.html) (Protection Mechanism Failure) is the closest fit if you need one. The threat is MAS-THREAT-0065, *"Attackers can observe and modify the running app without resistance"*, through MAS-ATTACK-0003, *"Using dynamic instrumentation"*.

The weakness has the **R** profile (plus EUDIW). It concerns apps whose threat model includes reverse engineering and tampering on a device the attacker controls: banking and payments, wallets, DRM, games with an economy, apps protecting valuable IP. Like every control in this series it is **defence in depth that raises attacker cost**. It never replaces the L1/L2 controls, and a check that runs only on the client, with no server-side consequence, will eventually be bypassed by someone who controls the device.

### Tool detection versus runtime code integrity

OWASP draws a line between this weakness and [MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/) (Runtime Code Integrity Not Verified), and it matters for where you report a finding:

| | MASWE-0065 (this note) | [MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/) |
|---|---|---|
| Question | Is a *known tool* present? | Has my *code or memory* been modified? |
| Evidence | Tool-specific artefacts: ports, library names in maps or dyld's list, thread names, pipes, framework classes, strings | Effects: rewritten function prologues (trampolines), changed method entry points, modified executable pages, unexpected executable memory |
| Strength | Catches default and lightly modified tools early, even before they hook anything | Catches hooks from any tool, including custom or renamed ones |
| Weakness | Defeated by renaming, relocating or rebuilding the tool | Has to know which code to verify; can be raced or patched |

The two are complementary and a mature app does both. OWASP's v2 tests for hook detection (MASTG-TEST-0341 for Android, MASTG-TEST-0354 for iOS) are assigned to MASWE-0058, and the legacy v1 "Testing Reverse Engineering Tools Detection" tests (MASTG-TEST-0048 for Android, MASTG-TEST-0091 for iOS) are marked `covered_by` those same two tests. In other words, OWASP moved its runtime tests to the effect-based weakness and left this one without a test of its own. We document 0341 and 0354 in full in the [MASWE-0058 note](/mobile/maswe-0058-runtime-code-integrity-not-verified/); this note adds four tests focused on the tool artefacts themselves.

### The tools in scope

| Tool | Platform | How it gets into the app | Typical artefacts |
|---|---|---|---|
| Frida (frida-server) | Android, iOS (rooted/jailbroken) | A daemon on the device injects an agent into the target process on attach or spawn | Listening port 27042, agent library in memory (`frida-agent-*.so`, often from a memfd on recent Android), threads `gum-js-loop`, `gmain`, `gdbus`, pipes or sockets used for injection |
| Frida Gadget | Android, iOS (no root needed) | A shared library embedded in a repackaged app, loaded at start-up | `libfrida-gadget.so` / `FridaGadget.dylib` in the package and in memory, by default a listener on 127.0.0.1:27042, the same threads |
| objection | Android, iOS | A Frida-based toolkit; uses frida-server or patches the package with Gadget (`objection patchapk`, `objection patchipa`) | Frida's artefacts, plus a re-signed package |
| Xposed / LSPosed | Android (root) | A framework loaded into zygote (classic Xposed) or via Zygisk/Riru (LSPosed, built on the LSPlant ART hooking library); modules are scoped to target apps | Framework classes and stack frames, modified ART method entry points, framework files and the manager app |
| Cydia Substrate, Substitute, libhooker, ElleKit | iOS (jailbreak) | Tweak injection loads dylibs into processes at launch | Tweak-injection dylibs in dyld's image list, injection environment, trampolines in hooked functions |

## Modes of Introduction

**No instrumentation checks.** The app relies on root/jailbreak detection ([MASWE-0051](/mobile/maswe-0051-root-jailbreak-detection-not-implemented/)) and assumes no root means no Frida. Frida Gadget and objection's patching work on unrooted and non-jailbroken devices, so this assumption is wrong.

**One shallow artefact.** The only check is "is anything listening on 27042" or "does `/proc/self/maps` contain the string `frida`". Both fall to a rename and a different port, which is public, documented and takes a minute.

**Checks in hookable code only.** The check is written in Kotlin or Swift and returns a boolean through a named method. Frida's Java and Objective-C bridges replace it by name before it runs. OWASP calls out "checking only from easily hooked Java/Swift code" as a mode of introduction for this reason.

**One-time checks.** A start-up check misses Frida attached later; Frida can attach to a running process at any time.

**Detection without response, or with a loud one.** The app logs the detection, or shows "Frida detected!" and exits at the same place, which tells the attacker which check to patch.

**Fragile checks that get removed.** A thread-name or library-name list that triggers on legitimate software (some accessibility, enterprise or security tools inject or use similar names), a port scan that trips on an unrelated local service. False positives lead to the check being switched off.

## Impact

- **Bypass of every client-side control.** Once instrumentation is running unchallenged, root detection, debugger detection, integrity checks, certificate pinning and local authentication can each be neutralised with a hook. Frida is the generic bypass tool for the rest of this series.
- **Exposure of data in use.** Hooks see function arguments and return values: plaintext before encryption, tokens after decryption, keys passed to crypto APIs, the contents of every request before TLS. None of that needs storage access.
- **Automation and abuse at scale.** Instrumentation lets an attacker drive the real app as an API client (sign requests with the app's own code, solve its challenges), which is a common route for bots, account takeover tooling and fraud.

## Mitigations

- **Detect the common tools in more than one way**: ports and protocol probes, in-process artefacts (maps, threads, file descriptors, memory strings), framework classes on Android, dyld images on iOS. Implement the checks in native code, not in Java/Kotlin/Swift methods that can be replaced by name.
- **Pair artefact checks with integrity checks** ([MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/)): verify the prologues of your sensitive functions and of the libc/system functions your checks rely on, so a renamed tool still gets caught by what it does.
- **Check continuously and in different places**: at start-up, before sensitive operations, and periodically during them, with different implementations at different sites.
- **Respond in a way that protects the asset**: stop the sensitive operation, drop transient secrets, and send a risk signal to the backend; avoid telling the client which check fired.
- **Let the server decide** for high-value operations, combining the client's signal with app and device attestation ([MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/), [MASWE-0054](/mobile/maswe-0054-device-attestation-not-implemented/)).
- **Re-test against current tool versions** on every release. Tool artefacts change between versions, and checks written for an old Frida can silently stop working.

## Knowledge

OWASP does not link Knowledge pages from the weakness file. We assign MASTG-KNOW-0030 (Android) and MASTG-KNOW-0087 (iOS) in full, and the generic MASTG-KNOW-0115 (dynamic binary instrumentation) as a summary. The neighbouring MASTG-KNOW-0032 (runtime integrity verification) and MASTG-KNOW-0118 (RASP) are covered in the [MASWE-0058 note](/mobile/maswe-0058-runtime-code-integrity-not-verified/).

### Android: Reverse Engineering Tool Detection (MASTG-KNOW-0030)

Source: [MASTG-KNOW-0030](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0030/).

OWASP's page is about artefact-based detection, with Frida as the worked example, and is candid about its limits: each artefact is a weak signal that can be renamed, removed, delayed or spoofed, and some can produce false positives on devices with legitimate developer or security software. The value lies in combining several independent signals and weighing them. We go through the artefact classes, then add Xposed/LSPosed and objection.

#### What an Android app can still see

Android has been closing windows onto other processes for years, which shapes what a detection check can do:

- **Other processes are invisible.** Since Android 7.0, `/proc` is mounted so that an app sees only its own processes, and `ActivityManager.getRunningServices()` returns only the caller's own services since Android 8.0. Looking for a process named `frida-server` with `ps` or the activity manager does not work on current devices.
- **`/proc/net` is restricted.** Recent Android versions do not let ordinary apps read `/proc/net/tcp` and friends, so listing listening sockets is out. Connecting to a port still works (with the `INTERNET` permission, which almost every app has).
- **The app's own process is fully visible.** `/proc/self/maps`, `/proc/self/task/*/comm` and `/proc/self/fd/*` are readable, and that is where instrumentation has to live to do anything. Most robust tool checks are in-process.

#### Frida: the listening port and the protocol probe

frida-server listens on TCP port `27042` by default, and Frida Gadget in its default "listen" mode binds `127.0.0.1:27042` as well. Connecting to that port is the cheapest check there is. It is also the weakest: the port is a command-line option of frida-server and a configuration value of Gadget, and an attacker can use port forwarding or a different transport entirely.

A slightly better variant does not just test whether the port is open, but whether whatever answers speaks Frida's protocol. Frida's control channel is based on D-Bus, and the classic probe sends a D-Bus authentication request and looks for `REJECTED` in the reply. Applied to every open port in a range, it can find a server on a non-default port.

```c
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* Returns 1 if something on 127.0.0.1:port answers a D-Bus AUTH probe. Needs INTERNET permission. */
int dbus_auth_answers(unsigned short port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return 0;
    struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 };
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);

    int hit = 0;
    if (connect(s, (struct sockaddr *)&sa, sizeof sa) == 0) {
        char buf[128];
        memset(buf, 0, sizeof buf);
        send(s, "\0", 1, 0);              /* D-Bus: initial NUL byte */
        send(s, "AUTH\r\n", 6, 0);        /* ask for the supported mechanisms */
        if (recv(s, buf, sizeof buf - 1, 0) > 0 && strstr(buf, "REJECTED")) hit = 1;
    }
    close(s);
    return hit;
}
```

Treat the D-Bus answer as version-dependent. OWASP calls the probe "fairly robust", but recent Frida releases negotiate their transport differently from the versions the technique was written against, so check on the Frida version you test with whether the server still answers a bare D-Bus `AUTH` on its socket. And no port check catches Frida modes that do not listen at all (Gadget with a script loaded from a file, or injection without a server).

#### Frida: libraries and mappings in /proc/self/maps

To do anything inside the app, Frida has to load its agent into the process. After an attach or spawn by frida-server, the agent shows up in `/proc/self/maps`. On older versions it was mapped from a file such as `/data/local/tmp/re.frida.server/frida-agent-64.so`; recent versions on Android may load it from an anonymous memory file, which appears as something like `/memfd:frida-agent-64.so (deleted)`. A repackaged app with Frida Gadget maps `libfrida-gadget.so` from its own `lib/` directory.

```text
71b6bd6000-71b7d62000 r-xp 00000000 fd:00 1234  /data/local/tmp/re.frida.server/frida-agent-64.so
71b865a000-71b97f1000 r-xp 00000000 fd:00 5678  /data/app/~~Xy==/com.example.app-Ab==/lib/arm64/libfrida-gadget.so
```

Two points about such checks:

- **Expect the agent only after an attach.** frida-server running on the device is not in your process until someone attaches or spawns. A start-up maps check can miss a later attach, so maps checks belong in a loop or at checkpoints.
- **Look at more than names.** Names are trivially changed. Better signals are executable mappings that do not belong to any expected file (anonymous `r-xp` regions, deleted files, memfd mappings) in a process that normally has none, and libraries loaded from unusual paths. These need tuning per app, because JIT code caches and some SDKs also create anonymous executable memory.

```c
#include <stdio.h>
#include <string.h>

/* One weak signal among several: known names in the app's own memory map. */
int maps_has_known_tool(void) {
    static const char *const needles[] = { "frida", "gadget", "gum-js", "linjector", NULL };
    FILE *f = fopen("/proc/self/maps", "re");
    if (!f) return 0;
    char line[512];
    int hit = 0;
    while (!hit && fgets(line, sizeof line, f)) {
        for (int i = 0; needles[i] != NULL; i++) {
            if (strstr(line, needles[i])) {
                hit = 1;
                break;
            }
        }
    }
    fclose(f);
    return hit;
}
```

`/proc/self/smaps` has the same mappings with more detail and is sometimes read as an alternative, because attackers who hook only the `maps` path miss it.

#### Frida: threads, pipes and sockets

The Frida agent starts its own threads in the target process. Historically they carry names such as `gum-js-loop` (the JavaScript runtime), `gmain` and `gdbus` (GLib's main loop and D-Bus worker) and `pool-frida`. An app can walk `/proc/self/task/` and read each thread's `comm`:

```c
#include <dirent.h>
#include <stdio.h>
#include <string.h>

int has_known_tool_thread(void) {
    DIR *d = opendir("/proc/self/task");
    if (!d) return 0;
    struct dirent *e;
    int hit = 0;
    while (!hit && (e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        char path[64], name[32];
        snprintf(path, sizeof path, "/proc/self/task/%s/comm", e->d_name);
        FILE *f = fopen(path, "re");
        if (!f) continue;
        if (fgets(name, sizeof name, f)) {
            name[strcspn(name, "\n")] = 0;
            hit = !strcmp(name, "gum-js-loop") || !strcmp(name, "gmain") ||
                  !strcmp(name, "gdbus") || !strcmp(name, "pool-frida");
        }
        fclose(f);
    }
    closedir(d);
    return hit;
}
```

`gmain` and `gdbus` are GLib names, so any GLib-based library in the app would also produce them; check that the app itself has none before weighting them. Thread names are also trivially renamed in a modified build.

Frida's injector and agent also communicate over pipes and Unix sockets. Historically the Linux injector used FIFOs named `linjector-*`, visible as targets of the app's file descriptors in `/proc/self/fd/`, and OWASP points to abstract Unix socket names with a `frida-zymbiote-` prefix in Frida 17.9.7. Both are highly version-specific. An app can `readlink()` each entry in `/proc/self/fd/` and look for unexpected pipes and sockets, but it should not treat a particular name as a stable signature.

#### Frida: memory string scanning

Instead of trusting names, an app can scan the readable regions of its own memory map for byte strings that occur inside Frida's agent, such as `LIBFRIDA` or strings from the agent's RPC layer (Bernhard Mueller's [frida-detection-demo](https://github.com/muellerberndt/frida-detection-demo) is the classic example). It catches a renamed agent, which is why OWASP rates it as stronger than names and ports. It is also expensive (do it at checkpoints, not in a tight loop), can be defeated by a build of the tool with those strings changed, and the scanning code itself is a target for a hook or patch. Implement it natively, scan with raw `read()` of `/proc/self/mem` or direct memory access rather than through libc functions the attacker may have hooked, and obfuscate the search patterns so they do not sit in the binary as plain strings.

#### Repackaging signs

Frida Gadget and objection's `patchapk` require repackaging and re-signing the APK. An app that verifies its own signing certificate (`PackageManager.GET_SIGNING_CERTIFICATES`, API 28+) against a pinned value catches the naive case. That is an app-integrity control and is covered in [MASWE-0057](/mobile/maswe-0057-app-resources-integrity-not-verified/) and [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/), where you will also find why a server-verified attestation is the stronger form.

#### Xposed and LSPosed

Classic Xposed replaced `app_process` so that every app forked from zygote carried the Xposed bridge; modern LSPosed loads through Zygisk or Riru, hooks with the LSPlant library, and injects only into the apps a module is scoped to. Detection approaches, roughly from weakest to strongest:

- **Framework classes.** Try to load `de.robv.android.xposed.XposedBridge` or `de.robv.android.xposed.XposedHelpers`. This caught classic Xposed reliably. LSPosed loads its bridge in a way that is not visible to the app's class loaders, and modern module APIs use different package names, so a negative result means little.
- **Stack frames.** Under classic Xposed, every app's stack had `de.robv.android.xposed.XposedBridge.main` at the bottom, and hooked methods are entered through bridge frames (for example `XposedBridge.handleHookedMethod`). Under LSPosed, a method hooked through LSPlant is entered through generated hooker classes; names beginning with `LSPHooker_` have been observed. Inspecting `Throwable().stackTrace` *inside your own sensitive methods* is therefore more useful than at start-up, because it shows whether that method was entered through a hook.
- **Installed packages and files.** The manager app or framework files. Package visibility on Android 11+ hides most other packages unless the app declares queries, and the LSPosed manager can be hidden or renamed. Weak.
- **ART hooking side effects.** Hooking frameworks change the `ArtMethod` structures of hooked methods (entry points that no longer point into the expected code, altered access flags such as a method suddenly marked native). Detecting that is runtime integrity verification, in the [MASWE-0058 note](/mobile/maswe-0058-runtime-code-integrity-not-verified/).

```kotlin
fun hookingFrameworkSignals(): List<String> {
    val hits = mutableListOf<String>()
    try {
        Class.forName("de.robv.android.xposed.XposedBridge", false, ClassLoader.getSystemClassLoader())
        hits += "XposedBridge class"
    } catch (e: ClassNotFoundException) {
        // expected on a clean device and under most LSPosed set-ups
    }
    for (frame in Throwable().stackTrace) {
        val c = frame.className
        if (c.contains("xposed", ignoreCase = true) || c.startsWith("LSPHooker_")) hits += "frame $c"
    }
    return hits
}
```

As with every check written in Kotlin, a hooking framework can replace `hookingFrameworkSignals()` itself; the same logic in native code, or inlined at several sites, is harder to remove.

Root-hiding modules (Zygisk-based hiding, DenyList and similar) exist precisely to hide these artefacts and root itself from selected apps. They are part of the threat landscape and the reason artefact checks degrade over time; their configuration is outside the scope of this guide.

#### objection

objection is a Frida-based toolkit. It brings no artefacts of its own beyond Frida's: on a rooted device it talks to frida-server, and on an unrooted one `objection patchapk` embeds Frida Gadget, adds a `System.loadLibrary` call to the launcher activity, and re-signs the APK. An app that detects Frida (or the re-signing) detects objection. Its built-in commands to disable root detection and pinning are a useful yardstick for testers: if a generic `android root disable` or `android sslpinning disable` works, the app's protections do not go beyond the textbook APIs.

#### Debugging tools that are not debuggers

Some tools enable debugging rather than instrument the app: hooking-framework modules such as debugmepLS that make a non-debuggable app report `FLAG_DEBUGGABLE`, or system-property spoofing of `ro.debuggable` on a rooted device. Their artefacts are covered under [MASWE-0064](/mobile/maswe-0064-debugger-detection-not-implemented/) (the app's debugger checks) and [MASWE-0051](/mobile/maswe-0051-root-jailbreak-detection-not-implemented/) (the root that makes them possible).

#### Effectiveness, in one table

| Check | Catches | Defeated by (general terms) | Cost to defender |
|---|---|---|---|
| Port 27042 open | Default frida-server or Gadget in listen mode | Different port, no listener | Trivial |
| D-Bus AUTH probe over a port range | frida-server on any scanned port (version-dependent) | No listener; transport changes | Low |
| Names in `/proc/self/maps` | Default agent or Gadget | Renamed files, memfd names, hooked `open`/`read` | Low |
| Anonymous or deleted executable mappings | Injected code regardless of name | Careful injection; noisy with JIT code | Medium (tuning) |
| Thread names | Default agent | Modified build | Low |
| Pipes and sockets in `/proc/self/fd` | Version-specific injector artefacts | Version change | Low, high maintenance |
| Memory string scan | Renamed agent | Modified build; patched scanner | Medium to high |
| Xposed classes and stack frames | Classic Xposed; some LSPosed hooks | Modern frameworks hide them | Low |
| Hook/integrity checks ([MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/)) | Any tool that rewrites code | Must be found and patched themselves | Medium to high |

No single row is strong. The combination is: an attacker who renames the server still trips the memory scan, one who rebuilds Frida still trips the prologue check, and one who patches all of them has to find every implementation at every call site, while the backend notices sessions that stopped sending a clean signal.

### iOS: Reverse Engineering Tools Detection (MASTG-KNOW-0087)

Source: [MASTG-KNOW-0087](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0087/).

iOS apps have far less visibility than Android apps: there is no `/proc`, no public API to list other processes or run commands (and apps that try, for example with private process APIs, risk App Store rejection). Tool detection on iOS therefore relies on what the app can see about itself: the images dyld has loaded, its environment, its threads, local ports, and the code of its own functions.

#### Loaded images: _dyld_image_count and _dyld_get_image_name

dyld keeps a list of the images it loaded. Iterating it finds Frida Gadget (`FridaGadget.dylib`, in the app's `Frameworks/` after `objection patchipa` or manual embedding), dylibs inserted with `DYLD_INSERT_LIBRARIES`, and jailbreak tweak-injection libraries: names such as `MobileSubstrate`, `SubstrateLoader`, `libsubstrate`, `libhooker`, `ellekit`/`libellekit`, `TweakInject`, `SubstrateInserter`, `cynject`, and individual tweaks such as `SSLKillSwitch`.

```c
#include <mach-o/dyld.h>
#include <stdlib.h>
#include <string.h>

static const char *const kSuspicious[] = {
    "frida", "gadget", "cynject", "substrate", "substitute",
    "libhooker", "ellekit", "tweakinject", "sslkillswitch", NULL
};

int suspicious_image_loaded(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name == NULL) continue;
        for (int k = 0; kSuspicious[k] != NULL; k++) {
            if (strcasestr(name, kSuspicious[k]) != NULL) return 1;
        }
    }
    return getenv("DYLD_INSERT_LIBRARIES") != NULL;
}
```

The important limitation, which OWASP documents: on jailbroken devices, frida-server injects its agent with its own Mach-O loader that bypasses dyld, so the agent **never appears in dyld's image list**. The dyld check catches Gadget, `DYLD_INSERT_LIBRARIES` and dyld-loaded tweaks, not the most common jailbroken Frida set-up. Also:

- Names are renamed with no effort. Rootless jailbreaks keep tweak libraries under `/var/jb/`, and some injection methods give libraries randomised names.
- Images loaded after the scan are missed; `_dyld_register_func_for_add_image` gives a callback for every image loaded later, including late `dlopen` calls.
- `DYLD_INSERT_LIBRARIES` is a weak signal. Jailbreak tweak injection on current jailbreaks does not necessarily set it, and the variable can be removed from the environment after use.
- Paths of tweak files on disk are jailbreak artefacts; checks for them belong to [MASWE-0051](/mobile/maswe-0051-root-jailbreak-detection-not-implemented/).

#### Ports and the D-Bus probe

frida-server on iOS listens on port 27042 by default, and an iOS app can connect to localhost. The port check and the D-Bus `AUTH` probe from the Android section work in the same way (and with the same version caveat). OWASP's table rates the plain port check as trivial to bypass and the D-Bus probe as fairly robust against frida-server, but useless against modes that do not run a server.

#### Threads, trampolines and Stalker

Frida's agent threads exist on iOS too. An app can enumerate its threads with `task_threads()` and read names with `pthread_from_mach_thread_np()` and `pthread_getname_np()`, with the same caveats as on Android.

OWASP also names two detection ideas beyond artefacts: named pipes used by frida-server, and **trampolines**, the branch instructions that Frida's Interceptor, Substrate and ElleKit write into the first bytes of a hooked function. Checking the prologue of your sensitive functions (and of the system functions your security code depends on, such as `SecTrustEvaluateWithError` or `ptrace`) catches hooks regardless of which tool placed them. That is runtime integrity, covered in the [MASWE-0058 note](/mobile/maswe-0058-runtime-code-integrity-not-verified/). Note OWASP's caveat: neither catches Frida's Stalker, which traces by rewriting code into a separate cache rather than patching the original.

#### Substrate, Substitute, libhooker and ElleKit

These are the hooking engines behind jailbreak tweaks. Substrate (`MSHookFunction`, `MSHookMessageEx`) defined the API; Substitute and libhooker re-implemented it; ElleKit is the current implementation on many modern (rootless) jailbreaks and provides Substrate-compatible APIs. All of them inject dylibs into processes at launch and patch functions with trampolines. For an app, the visible traces are the injected images (if loaded through dyld under a recognisable name), the trampolines, and the side effects of specific tweaks (a pinning-bypass tweak makes your pinning succeed against a proxy certificate, a jailbreak-hiding tweak makes file checks lie). Jailbreak-hiding tweaks are part of the threat landscape and outside the scope of this guide.

#### What OWASP's bypass list tells you

KNOW-0087 lists the bypass routes in general terms: patch the detection with a disassembler or binary patcher, or hook the file-system and loader APIs the checks use so they return clean results. For a tester this is the measure of resistance: if the app's detection falls to one hook on `_dyld_get_image_name` or `connect`, it is shallow. OWASP also mentions IOSSecuritySuite, an open-source library that implements several of these checks; when you see it in an app, you know exactly which checks to expect, and so does an attacker.

### Generic: Dynamic Binary Instrumentation (MASTG-KNOW-0115)

Source: [MASTG-KNOW-0115](https://mas.owasp.org/MASTG/knowledge/generic/MASVS-RESILIENCE/MASTG-KNOW-0115/). *Summary.*

Dynamic binary instrumentation (DBI) inserts generated code into a running process to observe or change it at instruction level. OWASP's page mentions general-purpose DBI frameworks such as Valgrind and Intel PIN (Valgrind builds for Android). Frida's Stalker is the DBI engine most mobile testers meet: it copies the code it traces into its own cache, rewriting it on the fly, and leaves the original untouched. For detection this matters in two ways. A DBI engine is still a library and threads inside the process, so in-process artefact checks can see it; but it does not patch function prologues, so integrity checks that look for trampolines do not. Timing checks may notice the slowdown that full instrumentation causes. A layered defence covers both.

## Tests

### Where the OWASP tests are

**OWASP has no tests for MASWE-0065.** Its two v2 runtime tests about instrumentation, MASTG-TEST-0341 (Android) and MASTG-TEST-0354 (iOS), "Runtime Use of Hook Detection Techniques", are assigned to MASWE-0058 and documented in full in our [MASWE-0058 note](/mobile/maswe-0058-runtime-code-integrity-not-verified/). They hook sensitive APIs (Keystore, Keychain, crypto, SQLite, `LAContext`, `URLSession`) and check whether the app notices and reacts, whatever detection method it uses. The legacy v1 tests for this weakness, MASTG-TEST-0048 (Android) and MASTG-TEST-0091 (iOS), "Testing Reverse Engineering Tools Detection", are deprecated with `covered_by` pointing at 0341 and 0354 respectively. If you run those two tests, part of this weakness is covered: an app that reacts to hooking usually also has some tool detection.

What the hook-detection tests do not tell you is *how* the app detects tools and how shallow that detection is. The four tests below are ours and fill that gap. Each is labelled as Guler Tech methodology. Run them on your own test devices only, against the app under test only.

### GT-RES-0065-1: Static identification of tool-detection checks (Android, iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Find the app's instrumentation-detection logic in its code: which tools it looks for, which artefacts, in which layer (Java/Kotlin/Swift or native), and where it is called from. The result guides the runtime tests and tells you early whether detection relies only on names and ports.

#### Prerequisites

- Android: the APK and splits, jadx, `readelf`/`llvm-readelf`, `llvm-objdump`, `strings`, semgrep.
- iOS: a decrypted IPA (or a build from the client), `otool`, `nm`, `strings` or rabin2, Ghidra or Hopper.

#### Steps

1. **Android, DEX layer.** Decompile with `jadx -d out base.apk` and search for tool names, artefact paths and probe strings:

   ```bash
   grep -rnE 'frida|gadget|27042|gum-js-loop|gmain|gdbus|linjector|LIBFRIDA|REJECTED|xposed|XposedBridge|lsposed|LSPHooker|substrate|/proc/self/(maps|smaps|task|fd)' out/sources
   ```

   A semgrep rule makes the same search repeatable in CI:

   ```yaml
   rules:
     - id: gt-android-instrumentation-detection
       languages: [java]
       severity: INFO
       message: Instrumentation-tool detection indicator (MASWE-0065)
       pattern-either:
         - pattern-regex: '(?i)frida|gadget|gum-js-loop|linjector|xposed|lsposed|lsphooker|substrate'
         - pattern-regex: '/proc/self/(maps|smaps|task|fd)'
         - pattern: '27042'
         - pattern: '"REJECTED"'
   ```

   ```bash
   semgrep -c gt-instrumentation.yml out/sources --text
   ```

2. **Android, native layer.** For each library, look for the imports a tool check needs and for the artefact strings:

   ```bash
   for so in app/lib/arm64-v8a/*.so; do
     echo "== $so"
     readelf --dyn-syms -W "$so" | awk '$7=="UND"{print $8}' \
       | grep -E '^(socket|connect|inet_pton|opendir|readdir|readlink|readlinkat|pthread_getname_np|dl_iterate_phdr)(@|$)'
     strings -a "$so" | grep -iE 'frida|gadget|gum-js|gmain|gdbus|linjector|LIBFRIDA|REJECTED|AUTH|xposed|/proc/self/(maps|smaps|task|fd)' | sort -u
   done
   ```

   The port often appears as a constant, not a string: 27042 is `0x69a2`, or `0xa269` after `htons`. `llvm-objdump -d --no-show-raw-insn lib.so | grep -iE '#0x(69a2|a269)'` finds it. No strings but `socket`/`connect`/`opendir` imports in a security library, plus high-entropy data, usually means obfuscated strings; decode them in Ghidra or at runtime (GT-RES-0065-2).

3. **iOS.** For the main executable and each framework:

   ```bash
   APP=$(ls -d ipa/Payload/*.app)
   BIN="$APP/$(plutil -extract CFBundleExecutable raw "$APP/Info.plist")"
   nm -u "$BIN" | grep -E '^_(_dyld_image_count|_dyld_get_image_name|_dyld_register_func_for_add_image|getenv|socket|connect|task_threads|pthread_getname_np)$'
   strings -a "$BIN" | grep -iE 'frida|gadget|cynject|substrate|substitute|libhooker|ellekit|tweakinject|DYLD_INSERT_LIBRARIES|REJECTED' | sort -u
   otool -tv "$BIN" | grep -iE '#0x(69a2|a269)'
   ```

   Look for bundled detection libraries too, for example IOSSecuritySuite (class and method names such as `amIReverseEngineered` and `amIRuntimeHooked`, if not stripped) or a commercial protection SDK.

4. **Review** each hit in jadx, Ghidra or Hopper. Classify it by artefact type (port, protocol probe, maps/images, threads, fd/pipes, memory scan, framework classes, stack frames), note the layer and whether the check sits behind a single named method, follow its result to a response, and record the call sites (start-up only, before sensitive operations, periodic).

#### Observation

A table of detection checks: tool, artefact, layer, location, call sites and timing, response. Note obfuscated or encrypted indicators you could not decode statically.

#### Evaluation

The test **fails** when no instrumentation-detection logic is found and runtime testing (GT-RES-0065-2) confirms there is none. Report it as **shallow** (a separate observation that feeds the rating) when all checks found are name- or port-based (port 27042, the string `frida` in maps or image names, `XposedBridge` class lookup) or live only in hookable Java/Kotlin/Swift methods behind one call site.

It **passes** when the app has reachable, native-implemented checks across more than one artefact class, with a response. Robustness is measured in GT-RES-0065-3.

False negatives: packed or dynamically loaded code ([MASWE-0049](/mobile/maswe-0049-unsafe-dynamic-code-loading/)), encrypted strings, and checks in a protection SDK that are hard to read statically. False positives: libraries that mention "gadget" or "substrate" for unrelated reasons (UI widgets, graphics), and `/proc/self/maps` reads by crash reporters and memory profilers.

#### Demo

An illustrative excerpt (not from a real app) of step 2 against a library with a layered check:

```text
== app/lib/arm64-v8a/libguard.so
connect
inet_pton
opendir
readdir
readlinkat
socket
/proc/self/maps
/proc/self/task/%s/comm
gum-js-loop
REJECTED
$ llvm-objdump -d --no-show-raw-insn app/lib/arm64-v8a/libguard.so | grep -iE '#0x(69a2|a269)'
   1c3f8:      	mov	w1, #0xa269
```

This library probes the port with a D-Bus `AUTH` (the `REJECTED` string), reads the memory map and the thread names, and inspects file descriptors (`readlinkat`). The next question is whether its result leads anywhere and how it behaves when the tool is renamed.

### GT-RES-0065-2: Runtime detection of a default Frida set-up (Android, iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Run the app against Frida in its default configuration, in each of the ways an attacker would use it, and observe whether and when the app detects it and how it responds. This is the baseline: an R-profile app that does not notice a default Frida set-up has no meaningful tool detection.

#### Prerequisites

- Android: a rooted test device or emulator with frida-server matching your Frida client; for the Gadget scenario, an unrooted device and a Gadget-patched build (`objection patchapk`, which re-signs the APK).
- iOS: a jailbroken test device with frida-server; for the Gadget scenario, a Gadget-embedded build (`objection patchipa`) signed with your development identity.
- An HTTPS proxy in front of the app, to see whether the app sends risk signals to its backend ([lab set-up](/mobile/mobile-traffic-interception-lab/)).
- Note that the Gadget scenarios re-sign the app, so signature and integrity checks ([MASWE-0057](/mobile/maswe-0057-app-resources-integrity-not-verified/)) may react first. Record which check reacted.

#### Steps

1. **Server running, no injection.** Start frida-server with default settings, then launch the app normally and use it. This tests port and protocol checks in isolation.
2. **Attach to the running app.** `frida -U -n <app name>` (or `-p <pid>`) with no script, after you have logged in, then continue through sensitive flows. This tests in-process checks that run continuously or at checkpoints.
3. **Spawn the app under Frida.** `frida -U -f com.example.app` with no script. This tests start-up checks.
4. **Gadget build.** Install the Gadget build and launch it; Gadget in its default mode waits for a client on 127.0.0.1:27042, so connect with `frida -U -n Gadget`, then use the app.
5. **Trace what the app probes.** In a separate run, load an observation-only script that logs the app's own probes, so you can map each reaction to a check. It logs connections to local ports, opens of `/proc/self` paths and the dyld image queries, and changes nothing. Written for Frida 17:

   ```javascript
   // trace-tool-probes.js: observe the app's own instrumentation checks, change nothing
   const darwin = Process.platform === 'darwin';
   function g(name) {
     return Module.findGlobalExportByName(name);
   }
   function bt(ctx) {
     return Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, 4).map(DebugSymbol.fromAddress).join(' <- ');
   }

   const connect = g('connect');
   if (connect !== null) {
     Interceptor.attach(connect, {
       onEnter(a) {
         const sa = a[1];
         const family = darwin ? sa.add(1).readU8() : sa.readU16();
         if (family !== 2) return;   // AF_INET only
         const port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
         console.log(`[connect] port=${port}  ${bt(this.context)}`);
       }
     });
   }

   if (!darwin) {
     ['open', 'openat', 'opendir', 'readlinkat'].forEach((name) => {
       const addr = g(name);
       if (addr === null) return;
       Interceptor.attach(addr, {
         onEnter(a) {
           const p = (name === 'openat' || name === 'readlinkat' ? a[1] : a[0]).readCString();
           if (p && /^\/proc\/self\/(maps|smaps|task|fd)/.test(p)) console.log(`[${name}] ${p}  ${bt(this.context)}`);
         }
       });
     });
   } else {
     ['_dyld_image_count', '_dyld_register_func_for_add_image', 'getenv'].forEach((name) => {
       const addr = g(name);
       if (addr === null) return;
       Interceptor.attach(addr, {
         onEnter(a) {
           if (name === 'getenv' && !/^DYLD_/.test(a[0].readCString() || '')) return;
           console.log(`[${name}] ${name === 'getenv' ? a[0].readCString() : ''}  ${bt(this.context)}`);
         }
       });
     });
   }
   ```

   ```bash
   frida -U -f com.example.app -l trace-tool-probes.js
   ```

   The trace itself injects Frida, so the app may react to it; that is fine, the purpose is to see what it probes.

6. **For each scenario**, exercise the sensitive flows and record what happens and when.

#### Observation

Per scenario (server only, attach, spawn, Gadget): detected or not, time from tool start to reaction, the reaction (none, warning, refusal of a flow, logout, wipe, termination, backend signal seen in the proxy), and from the trace which probes ran.

Illustrative trace output (not from a real app):

```text
[connect] port=27042  0x7b2a01c3f8 libguard.so!0x1c3f8 <- 0x7b2a01b120 libguard.so!0x1b120
[openat] /proc/self/maps  0x7b2a01a9d4 libguard.so!0x1a9d4
[opendir] /proc/self/task  0x7b2a01aa70 libguard.so!0x1aa70
```

#### Evaluation

The test **fails** for an R-profile app when none of the scenarios is detected, or when detection happens but nothing protects the sensitive flows (no refusal, no wipe, no re-authentication, no backend signal). Partial results are findings too, reported precisely: detection only of the server but not of Gadget (common when the only check is the port), only at start-up so that a later attach goes unnoticed, or only in a Java/Swift method.

It **passes** when all four scenarios are detected in time to protect the sensitive flows and lead to a response. Resistance is the subject of GT-RES-0065-3.

#### Demo

An illustrative run against an app whose only check is a start-up connect to 27042:

| Scenario | Result |
|---|---|
| Server running, app launched | Detected at start-up; dialog "Unsupported environment"; app closes |
| Attach after login | Not detected; sensitive flows usable |
| Spawn under Frida | Detected at start-up (server port open) |
| Gadget build | Detected at start-up (Gadget listens on 27042) |

Verdict: fails for the "attach after login" scenario. The trace shows one `connect` to 27042 at start-up and no in-process checks. The explicit dialog also tells an attacker which check fired.

### GT-RES-0065-3: Resistance to a renamed, relocated Frida (Android, iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Repeat GT-RES-0065-2 with the most basic evasion an attacker uses: the same Frida, but with its server file renamed and listening on a non-default port, and for Gadget, the library file renamed. This is public, well-known and takes minutes. It separates checks that look for names and default ports from checks that look at what the tool does in the process. We deliberately stop here; we do not build or use modified Frida releases, and we note in the report that a determined attacker can go further. The [MASWE-0058 note](/mobile/maswe-0058-runtime-code-integrity-not-verified/) runs the same change against the app's integrity checks (its test GT-RES-0058-2); run the two together and you see which layer still catches the renamed tool.

#### Prerequisites

- The set-up from GT-RES-0065-2, and the list of probes from its trace.

#### Steps

1. **Rename and relocate the server.** Start frida-server from a renamed copy of the binary in a different directory, and have it listen on a non-default port using its documented listen option; connect the client to that address with the client's remote-host option instead of `-U`. The Frida documentation covers both options.
2. **Rename the Gadget.** Rebuild the Gadget-patched package with the Gadget library under a different file name (adjusting the load call that references it), keeping its default configuration otherwise.
3. **Repeat scenarios 1 to 4** of GT-RES-0065-2 with the renamed set-ups, and run the observation-only trace again to see which probes still fire and what they return.
4. **Record per check** which one stopped detecting (name and port checks are expected to fall) and which still detect (memory scans, thread or anonymous-mapping checks, D-Bus probes over a port range, prologue and integrity checks from [MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/)).

#### Observation

A before-and-after table per scenario: detected with default Frida, detected with renamed Frida, which checks still fired, the response, and the time you spent on the change.

#### Evaluation

This is a resistance measurement, not a pass/fail test:

| Result | Meaning |
|---|---|
| Detection lost in every scenario | Detection is **shallow**: names and default ports only. Report it with the time taken (typically minutes) |
| Detection kept in some scenarios | Partly layered; list which artefact classes survived and which scenarios now go unnoticed |
| Detection kept in all scenarios, with a response | Layered detection; credit it, and note that modified tool builds and hooking of the checks themselves were not attempted |

Feed the result into the rating: a control that falls to a rename is rated by what that bypass unlocks, exactly like a missing control.

#### Demo

Continuing the illustrative app from GT-RES-0065-2, which also scans `/proc/self/task/*/comm` at checkpoints:

| Scenario | Default Frida | Renamed server, non-default port |
|---|---|---|
| Server running, app launched | Detected (port) | **Not detected** |
| Attach after login | Detected at next checkpoint (thread `gum-js-loop`) | Detected at next checkpoint (thread `gum-js-loop`) |
| Gadget (renamed library) | Detected (port, thread) | Detected (thread) |

Verdict: the port check is shallow, the thread-name check survived the rename. Next steps for the developer: add a memory or integrity check so that a modified build that renames its threads is still caught.

### GT-RES-0065-4: Hooking frameworks on the device (Android, iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Check whether the app detects the presence of a hooking framework and, more importantly, a hook from that framework inside its own process. On Android that means Xposed-family frameworks (LSPosed today); on iOS the tweak-injection engines of a jailbreak (Substrate, Substitute, libhooker, ElleKit). These frameworks are a common part of an attacker's set-up and they bring their own artefacts, different from Frida's.

#### Prerequisites

- Android: a rooted test device with LSPosed installed, and a module you trust whose scope you can set to the app under test. A logging-only module is ideal; MASTG lists debugmepLS for making an app debuggable, which also serves. Do not scope modules to other apps.
- iOS: a jailbroken test device with tweak injection active, and a tweak that injects into the app under test. OWASP's legacy test used SSL Kill Switch 3, which also tests whether pinning resists it ([MASWE-0028 note](/mobile/maswe-0028-insecure-identity-pinning/)).
- The response baseline from GT-RES-0065-2, so you can tell framework detection apart from root/jailbreak or Frida detection.

#### Steps

1. **Framework present, not scoped to the app.** Launch the app and use it. On Android this tests checks for the manager app, framework files and classes; on iOS, checks for tweak-injection images that load into every process.
2. **Framework scoped to the app.** Enable the module or tweak for the app, restart it, and use the sensitive flows. This tests stack-frame, class, image and hook checks.
3. **Note interactions.** The root or jailbreak needed for the framework may already trigger [MASWE-0051](/mobile/maswe-0051-root-jailbreak-detection-not-implemented/) checks. If the app refuses to run on a rooted or jailbroken device at all, note that and, if the engagement allows, neutralise only the app's root/jailbreak check on your test device (for example with objection's built-in option) to observe the framework detection separately.
4. **Record** the reaction and its timing in each step.

#### Observation

Per step: detected or not, the reaction, its timing, and any backend signal. If you identified the detection code in GT-RES-0065-1, note which check fired.

#### Evaluation

The test **fails** for an R-profile app when a framework scoped to the app, with a module or tweak that hooks it, goes unnoticed through the sensitive flows. It is a weaker finding when only the "present but not scoped" case goes unnoticed: that case is a jailbreak/root signal more than a hook.

It **passes** when the app detects a hook in its process (by artefact here, or by the integrity checks of [MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/)) and protects the sensitive flows. An app that also detects the unscoped framework earns extra credit, provided it does not block users on weak signals alone.

#### Demo

Illustrative results (not from a real app):

| Platform | Step | Result |
|---|---|---|
| Android | LSPosed installed, not scoped | Not detected (expected: nothing in the app's process) |
| Android | Logging module scoped to the app | Detected before payment approval; payment refused with a generic error; backend received a risk flag |
| iOS | ElleKit active, no tweak for the app | Not detected |
| iOS | SSL Kill Switch 3 injected | Not detected; pinning bypassed; traffic visible in the proxy |

Verdict: passes on Android, fails on iOS: the app's iOS build has no image or hook check, and a tweak that patches its trust evaluation goes unnoticed.

## Best practices

OWASP's cross-cutting BEST-0029 ("Implementing Resilience and RASP Signals") is summarised in the [series hub](/mobile/masvs-resilience-resilience-testing-guide/).

### Hardening Against Reverse Engineering Tools (MASTG-BEST-0048)

Source: [MASTG-BEST-0048](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0048/) (iOS). *Pointer: the full treatment is in the [MASWE-0058 note](/mobile/maswe-0058-runtime-code-integrity-not-verified/), where OWASP's hook-detection tests reference it.*

In short: combine **detective** controls (dyld image scanning for `FridaGadget`, `frida-agent`, `cynject` and similar, knowing it misses frida-server's dyld-bypassing injection; probing port 27042 for a D-Bus answer; named-pipe checks), **deterrent** controls (native C rather than Swift/Objective-C, obfuscation, checks scattered and inlined rather than behind one named function, varied timing), and **responsive** controls (end the session, clear sensitive memory, alert the backend), and protect the response itself by putting it in native code.

### Hardening Against Virtual Devices (MASTG-BEST-0053)

Source: [MASTG-BEST-0053](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0053/) (iOS). Its main home is the [MASWE-0053 note](/mobile/maswe-0053-emulator-virtual-device-detection-not-implemented/).

It is relevant here because research and virtualisation environments for iOS (Corellium and newer ones) are usually used together with instrumentation tools, and they can provide instrumentation the app cannot see. OWASP's recommendations carry over: treat local detection as a **risk signal**, not a final decision; pair it with server-side enforcement (App Attest validation, risk scoring, throttling, step-up, denying high-risk actions when several signals agree); obfuscate and diversify checks; and respond generically, without revealing which check fired.

### Layering and response

What we recommend, based on what holds up in testing:

- **At least three artefact classes, in native code**: a protocol-aware port probe over a range, an in-process check (anonymous executable mappings, thread names, file descriptors), and a memory or image scan, plus prologue checks on your security-critical functions ([MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/)).
- **Do not trust libc for your own checks.** Hooks on `open`, `read`, `connect`, `strstr` or `_dyld_get_image_name` blind every check that goes through them. Verify those functions' prologues, or read through direct system calls for the most important checks.
- **Checkpoints, not just start-up**: Frida can attach at any time. Run cheap checks before each sensitive operation, and heavier ones periodically while sensitive flows are active.
- **Weighted signals.** Weak signals (a framework app installed, `gmain` thread in an app that uses GLib) raise a score; strong ones (a known agent in memory, a hooked prologue in your own code) act on their own.
- **Quiet, server-side response.** Mark the session as risky and let the backend refuse or step up the operation, instead of a dialog naming the tool. Combine with app attestation so that a client that stops reporting is also treated as risky.
- **Maintenance.** Tool artefacts change between releases. Put "re-run GT-RES-0065-2 and -3 against the current Frida, LSPosed and ElleKit" on the release checklist.

## Rating findings

Apply the series-wide rules, adapted to tool detection:

- **Not an R-profile app**: missing instrumentation detection is **Info**.
- **R-profile app, no tool detection, or detection of a default set-up only** (falls to a rename or a different port, GT-RES-0065-3): usually **Low**; **Medium** when instrumentation directly exposes something valuable on the client (secrets in memory, a client-side decision such as a local PIN or limit check, request-signing logic that lets an attacker drive the API at scale).
- **Medium to High** only when the gap directly enables a concrete, demonstrated business abuse: for example, a bot farm or fraud scenario that relies on hooking the app's request signing, where the backend has no attestation or risk scoring to compensate. Report the missing server-side control as its own finding.
- **Detection exists but is trivially bypassed** (one hook, one rename): rate by what the bypass unlocks, on the same scale. A shallow check that protects nothing of value is Info.
- **Detection that blocks legitimate users** on weak signals (a GLib thread name, an unrelated local port) is not a security finding, but deserves an Info note recommending weighted signals.
- **Debug mechanisms left in the release build** (debuggable flag, `get-task-allow`, WebView debugging) are real vulnerabilities regardless of profile and are rated under [MASWE-0063](/mobile/maswe-0063-debug-mechanisms-not-disabled/).

In the report give: which tools and artefacts the app checks (from GT-RES-0065-1), which scenarios were detected with default and renamed tools (GT-RES-0065-2 and -3), the response and whether the backend saw a signal, the result of hooking frameworks (GT-RES-0065-4), the time it took to get an undetected instrumentation session in a sensitive flow, and what that session exposed. Cross-reference the hook-detection results from the [MASWE-0058 note](/mobile/maswe-0058-runtime-code-integrity-not-verified/) if you ran MASTG-TEST-0341 or MASTG-TEST-0354.

## References

- OWASP MASWE: [MASWE-0065: Dynamic Analysis Tools Detection Not Implemented](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0065/); related [MASWE-0058](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0058/), [MASWE-0064](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0064/), [MASWE-0051](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0051/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-RESILIENCE-4](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-4/) (CC BY-SA 4.0)
- OWASP MASTG knowledge: [MASTG-KNOW-0030](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0030/), [MASTG-KNOW-0087](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0087/), [MASTG-KNOW-0115](https://mas.owasp.org/MASTG/knowledge/generic/MASVS-RESILIENCE/MASTG-KNOW-0115/) (CC BY-SA 4.0)
- OWASP MASTG tests (documented in the MASWE-0058 note): [MASTG-TEST-0341](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0341/), [MASTG-TEST-0354](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0354/); legacy [MASTG-TEST-0048](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0048/), [MASTG-TEST-0091](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0091/) (CC BY-SA 4.0)
- OWASP MASTG best practices: [MASTG-BEST-0048](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0048/), [MASTG-BEST-0053](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0053/), [MASTG-BEST-0029](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0029/) (CC BY-SA 4.0)
- OWASP MASTG tools: [Frida (MASTG-TOOL-0031)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/), [Frida for iOS (MASTG-TOOL-0039)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0039/), [objection for Android (MASTG-TOOL-0029)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0029/), [objection for iOS (MASTG-TOOL-0074)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0074/), [Xposed (MASTG-TOOL-0027)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0027/), [LSPosed (MASTG-TOOL-0149)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0149/), [debugmepLS (MASTG-TOOL-0151)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0151/), [ElleKit (MASTG-TOOL-0139)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0139/), [SSL Kill Switch 3 (MASTG-TOOL-0066)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0066/), [IOSSecuritySuite (MASTG-TOOL-0141)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0141/), [Corellium (MASTG-TOOL-0108)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0108/) (CC BY-SA 4.0)
- Frida: [Documentation](https://frida.re/docs/home/), [Gadget](https://frida.re/docs/gadget/), [JavaScript API](https://frida.re/docs/javascript-api/), [frida-core source](https://github.com/frida/frida-core), [gumdarwinmapper (iOS Mach-O loader)](https://github.com/frida/frida-gum/blob/main/gum/backend-darwin/gumdarwinmapper.c)
- Hooking frameworks: [LSPosed](https://github.com/LSPosed/LSPosed), [LSPlant](https://github.com/LSPosed/LSPlant), [Cydia Substrate MSHookFunction](https://www.cydiasubstrate.com/api/c/MSHookFunction/), [ElleKit](https://github.com/tealbathingsuit/ellekit)
- Android: [`ActivityManager.getRunningServices`](https://developer.android.com/reference/android/app/ActivityManager#getRunningServices(int)), [`PackageManager.GET_SIGNING_CERTIFICATES`](https://developer.android.com/reference/android/content/pm/PackageManager#GET_SIGNING_CERTIFICATES), [Package visibility](https://developer.android.com/training/package-visibility); Linux [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)
- Apple: [dyld(3) (`_dyld_image_count`, `_dyld_get_image_name`)](https://keith.github.io/xcode-man-pages/dyld.3.html), [dyld source (DyldAPIs.cpp)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldAPIs.cpp)
- Background: Bernhard Mueller, ["The Jiu-Jitsu of Detecting Frida" (archived)](https://web.archive.org/web/20181227120751/http://www.vantagepoint.sg/blog/90-the-jiu-jitsu-of-detecting-frida), [frida-detection-demo](https://github.com/muellerberndt/frida-detection-demo); [Valgrind on Android](http://valgrind.org/docs/manual/dist.readme-android.html)
- CWE: [CWE-693](https://cwe.mitre.org/data/definitions/693.html) (our mapping; OWASP gives none)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
