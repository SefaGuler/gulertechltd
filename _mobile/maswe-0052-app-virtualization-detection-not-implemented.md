---
title: "MASWE-0052: App Virtualization Environment Detection Not Implemented"
date: 2026-11-10 20:01:00 +0000
subcategory: resilience
summary: "How Android app-virtualization and clone hosts run your app in their process, which anomalies give them away, and how to test detection."
refs: [MASWE-0052, MASVS-RESILIENCE-1, CWE-693]
tags: [android, ios, masvs-resilience, app-virtualization, app-cloning, anti-tampering]
---

This note is part of our [MASVS-RESILIENCE guide](/mobile/masvs-resilience-resilience-testing-guide/) and covers OWASP [MASWE-0052](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0052/): an app that never notices it is running inside another app. App-virtualization and "clone" hosts on Android load your APK into their own process, under their own UID, and pass your calls to the system through a layer they control. From the host's point of view your files, your memory and your API traffic are its own, and it gets all of that without root. That makes these hosts attractive to fraud tooling, to multi-accounting, and to anyone who wants to instrument an app on a device that would pass a root check. The weakness is Android-centric: iOS has no equivalent on stock devices, and the note explains why. OWASP has no tests or Knowledge pages for it yet, so the background, the two tests and the reference implementation below are ours. Like every control in this series, container detection is defence in depth that raises an attacker's cost. It never replaces the L1/L2 controls, and a client-side check without a server-side decision will be bypassed eventually.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Background](#background)
  - [Android: how app virtualization works](#android-how-app-virtualization-works)
  - [Android: legitimate multi-instance features](#android-legitimate-multi-instance-features)
  - [Android: detection signals](#android-detection-signals)
  - [iOS: why there is no equivalent on stock devices](#ios-why-there-is-no-equivalent-on-stock-devices)
- [Tests](#tests)
  - [GT-RES-0052-1: Static review of virtualization anomaly checks (Android)](#gt-res-0052-1-static-review-of-virtualization-anomaly-checks-android)
  - [GT-RES-0052-2: Running the app inside an app-virtualization host (Android)](#gt-res-0052-2-running-the-app-inside-an-app-virtualization-host-android)
- [Secure implementation](#secure-implementation)
  - [Android: layered container checks](#android-layered-container-checks)
  - [Server side: identity the host cannot forge](#server-side-identity-the-host-cannot-forge)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

The OWASP requirement is *"The app detects when it is running inside an app-virtualization environment."* It maps to MASVS-RESILIENCE-1 ("The app validates the integrity of the platform") and to [CWE-693](https://cwe.mitre.org/data/definitions/693.html) (Protection Mechanism Failure). The weakness carries OWASP's **R** profile and the **EUDIW** profile (the EU Digital Identity Wallet requirements). It is in scope when the app's threat model includes reverse engineering and tampering on a device the attacker controls, or abuse at scale: banking, payments, wallets, games with an economy, loyalty and promotion schemes, apps that limit one account per device. For an app without that threat model it is an observation, not a vulnerability.

OWASP frames it as threat MAS-THREAT-0052, *"Attackers can observe and manipulate the app from a hosting process"*, reached through MAS-ATTACK-0067, *"Running the app inside an app-virtualization or cloning framework"*. The second half of that sentence matters as much as the first. Some people run a clone host to inspect your app. Many more run one to have two or twenty instances of it, each logged in to a different account, on one cheap phone.

> **Note:** OWASP has no tests (in `tests-beta` or legacy v1) and no Knowledge pages for MASWE-0052 at the time of writing. The `## Background` section and the two `GT-RES-0052-x` tests below are Guler Tech methodology, not OWASP content.

Keep the neighbouring topics apart, because the same tooling often shows up in several of them:

| Question | Where it lives |
|---|---|
| Does the app notice it is running inside another app's process (a virtualization or clone host)? | This note (MASWE-0052) |
| Does the app notice root, Magisk, or a jailbreak? | [MASWE-0051](/mobile/maswe-0051-root-jailbreak-detection-not-implemented/) |
| Does the app notice an emulator, a cloud phone or a virtual iOS device? | [MASWE-0053](/mobile/maswe-0053-emulator-virtual-device-detection-not-implemented/) |
| Does the backend get server-verifiable proof of the device and app (Play Integrity, key attestation, App Attest)? | [MASWE-0054](/mobile/maswe-0054-device-attestation-not-implemented/) and [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/) |
| Was the APK itself modified, re-signed or renamed (a "cloned" APK with a new package name)? | [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/) and [MASWE-0057](/mobile/maswe-0057-app-resources-integrity-not-verified/) |
| Does the app notice Frida, Xposed-style hooks or other instrumentation in its process? | [MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/) and [MASWE-0065](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/) |

There are two quite different things people call "cloning". **Repackaging** clones rewrite the APK: new package name, new signature, installed as a separate app. That is an integrity problem, covered by MASWE-0056 and MASWE-0057. **Virtualization** clones leave your APK byte for byte intact and run it inside a host app. That is this note. Some commercial "app cloner" products do one, some the other, some both.

## Modes of Introduction

**No environment checks at all.** The app trusts that `getFilesDir()`, `getPackageCodePath()` and `Process.myUid()` describe a normal installation and never compares them with each other or with what the kernel reports.

**Checks only against a list of host package names.** A hard-coded list of known clone apps finds yesterday's hosts. Host apps rename themselves, and on Android 11 and later the app cannot even see most other packages without declaring `<queries>` entries or holding `QUERY_ALL_PACKAGES`, which Google Play restricts.

**Checks only through APIs the host can intercept.** A virtualization engine sits between your code and `system_server`. If every check asks `PackageManager` or reads a Java-level path, the engine can answer with whatever looks normal. Checks that compare those answers with the kernel's view (file ownership, `/proc/self/maps`, the real UID) are much harder to fake consistently.

**Treating legitimate profiles as hostile.** The opposite mistake. Work profiles, secondary users, Android 15's Private Space and OEM "dual app" features all run a second copy of your app, legitimately, under a different Android user. An app that blocks those generates support calls and gets its check disabled by the next release.

**Detection with no response.** The app logs or computes a signal and then carries on with full functionality, and nothing reaches the backend.

## Impact

- **Exposure of the app's data without root.** The guest runs under the host's UID, so its "private" files are files of the host app. Tokens, cached responses, databases and keys stored outside the Android Keystore are all readable and modifiable by the host.
- **Instrumentation on an unrooted device.** The host loads code into the same process before and alongside your code. Several public engines ship with Xposed-style hooking built in, so a user can hook your app on a device that passes every root check you have.
- **Interception of input and output.** The host proxies your Binder calls to the system and controls the window your activities draw into. It can observe intents, content provider queries and clipboard use, and show its own UI around yours.
- **Multi-accounting and promotion abuse.** One device, many instances, each with its own account and its own "fresh install" state. That breaks per-device limits, referral and sign-up bonuses, and device-based fraud scoring.
- **Undermined server trust.** If the backend relies on client-reported device identifiers or on "the app said it passed its checks", a host that runs many clean-looking instances defeats it.

## Mitigations

- **Compare the app's view with the kernel's view.** Check that the data directory, the code path and the native library directory have the shape a real installation has, and that the kernel agrees: your data directory is owned by `Process.myUid()`, the APK mapped into your process is your own, and your UID belongs to your package and no other.
- **Allow the legitimate cases explicitly.** Any Android user ID, adopted storage, device-protected storage, preinstalled system locations where they apply. Base the decision on structure, not on a hard-coded `/data/data/` prefix.
- **Use framework artefacts as a secondary signal.** Unexpected class loaders, host classes in stack traces, foreign APKs and DEX files in `/proc/self/maps`. Treat lists of known host packages as the weakest signal.
- **Respond through the backend.** Send the signals with sensitive requests and let the server decide: step-up verification, reduced limits, blocked promotions. Do not hard-fail on a single signal.
- **Use server-verified attestation.** Play Integrity evaluates the package the system sees as the caller, which inside a host is the host, not you (see [MASWE-0054](/mobile/maswe-0054-device-attestation-not-implemented/)). That is the one signal a virtualization host cannot simply rewrite.
- **Retest on every release** against current hosts. Engines change as Android changes.

## Background

### Android: how app virtualization works

#### Stub components and the host process

Android only runs components that are declared in an installed package's manifest. A virtualization host gets around that by declaring dozens or hundreds of **stub** components itself: generic activities, services, content providers and receivers, spread across several `android:process` names (`:p0`, `:p1`, and so on). When the user starts a guest app inside the host, the host:

1. Reads the guest APK. Installed APKs under `/data/app/` are readable by other apps, which is why a host can "clone" an installed app without root. Hosts can also take an APK file the user supplies.
2. Starts one of its own stub processes. That process is the host app's process: it has the host's UID, the host's SELinux context and the host's permissions.
3. Creates a class loader for the guest's DEX code and native libraries, builds an `Application` object for the guest and calls its `onCreate()`.
4. When the guest starts an activity or service, rewrites the request so the system launches a stub component, then swaps the guest's real component back in inside the process.

The open-source **VirtualApp** project popularised this design in the mid-2010s, and most later engines, open and commercial, follow the same pattern.

#### Binder proxies and framework hooks

Your app talks to the system through Binder interfaces such as `IActivityManager` and `IPackageManager`, reached through static fields in framework classes (`ActivityThread.sPackageManager`, the `IActivityManager` singleton). A host replaces those references in its own process with proxies. Every call your code makes passes through the host first. The host translates names (your package name to its own, your component to a stub), forwards the call to the real system service, and translates the answer back.

The consequences for detection:

- Anything you ask **through the framework** may be answered by the host. `getApplicationInfo()`, `getPackageInfo()`, `getRunningAppProcesses()`, even `getPackagesForUid()` can be rewritten.
- Anything the **kernel** enforces cannot be rewritten without also hooking the code that reads it. Your process's real UID, the owner of a directory, the files actually mapped into your address space.
- The host has to keep its lies consistent across dozens of APIs and two layers (Java and native). Detection works by finding the place where it slipped.

#### File system and native I/O redirection

The guest believes it lives in `/data/user/0/<guest-package>`. That directory belongs to the guest's real installation (if any) and is not accessible to the host's UID. So the host keeps the guest's data in a subdirectory of its own data directory, typically something like `/data/user/0/<host-package>/virtual/data/user/0/<guest-package>/`, and either:

- rewrites `ApplicationInfo.dataDir` and friends to point there, which makes paths look odd to anyone who checks; or
- reports normal-looking paths at Java level and redirects file access in native code, by hooking libc functions such as `open`, `openat`, `stat` and `access` in the process (inline hooks or PLT/GOT patches) and rewriting path arguments on the fly.

The second approach looks cleaner but leaves different traces: the kernel's view of an opened file (`/proc/self/fd/<n>`) or the owner of the directory you think is yours no longer matches the path you were given.

#### What the host can do to the guest

Because the guest runs inside the host's process, the host can do anything an in-process attacker can do: read and write the guest's files, read process memory, hook Java and native functions, see every intent and every Binder call, and change what the guest sees about the system. None of this requires root, and none of it shows up to root detection. Android's sandbox is per-UID, and the guest and the host share one.

### Android: legitimate multi-instance features

Several platform features run a second instance of your app on purpose. They are not hostile and should never be flagged as virtualization:

| Feature | How it works | What your app sees |
|---|---|---|
| Secondary users | A separate Android user with its own app data | `dataDir` under `/data/user/<n>/<pkg>`, UID = `n * 100000 + appId` |
| Work profile (Android Enterprise managed profile) | A profile user managed by an MDM | Same as above, plus the app may be managed by the profile owner |
| Private Space (Android 15+) | A separate profile the user can lock and hide | Same as above |
| OEM "dual app", "dual messenger", "app twin", "parallel apps" | Most OEM implementations create a hidden extra user or profile (vendors use their own user IDs) and install the same APK into it | Same as above |
| Adopted storage | The app was moved to an SD card formatted as internal storage | `dataDir` under `/mnt/expand/<volume-uuid>/user/<n>/<pkg>`, code under `/mnt/expand/<volume-uuid>/app/` |
| Direct Boot storage | Device-protected storage, or `android:defaultToDeviceProtectedStorage` | Paths under `/data/user_de/<n>/<pkg>` |

The common property of every legitimate case is that the **platform** installs your package for another user. Your code still runs in a process owned by your package, the data directory is owned by your UID, the APK path is your own, and the app ID (UID modulo 100000) is the same as in user 0. A virtualization host breaks all of those at once: the process belongs to someone else's package.

### Android: detection signals

These are the signals worth checking, from strongest to weakest. No single one is reliable on its own, and each has false positives, listed alongside.

| Signal | Normal installation | Inside a host | Pitfalls |
|---|---|---|---|
| `ApplicationInfo.dataDir`, `getFilesDir()` | `/data/user/<n>/<pkg>` (or `/data/data/<pkg>`, `/data/user_de/<n>/<pkg>`, `/mnt/expand/<uuid>/user/<n>/<pkg>`) | Path inside the host's data directory, or a normal-looking path that is redirected underneath | Do not hard-code `/data/data/` or user 0 |
| Owner of the data directory (`Os.stat(dataDir).st_uid`) | Equals `Process.myUid()` | Directory missing, or owned by another UID | Needs the path to be real; a redirected path may not exist at all, which is itself a signal |
| `getPackageCodePath()`, `ApplicationInfo.sourceDir` | `/data/app/~~<random>==/<pkg>-<random>==/base.apk` on Android 11+, `/data/app/<pkg>-<n>/base.apk` before | A copy inside the host's data directory, or another app's path | Preinstalled apps live under `/system`, `/product` or `/vendor`; split APKs live next to `base.apk` |
| `ApplicationInfo.nativeLibraryDir` | Next to the APK (`.../lib/arm64`) | Inside the host's data directory | App bundles with uncompressed native libraries load `.so` files directly from the APK |
| `getPackagesForUid(Process.myUid())` | Exactly your package (or your `sharedUserId` group) | The host's package, or more than one | The host may proxy this call; compare with the kernel-level signals |
| Process name (`Application.getProcessName()`, API 28+, or `/proc/self/cmdline`) | Your package name, or `<pkg>:<name>` for processes you declared | The host's stub process name, if not rewritten | Hosts often rewrite it; your own multi-process components are legitimate |
| `/proc/self/maps` | Your APK, system libraries, ART files, WebView and Google Play services modules | A second app's APK, DEX or `.so` files from another app's data directory, known engine libraries | WebView maps its own APK from `/data/app/`; Play services loads dynamic modules from its own data directory |
| Class loader chain | `PathClassLoader` (or `DelegateLastClassLoader`) over your own APK | A loader created by the host over a copied APK, host classes above yours in the stack | Your own dynamic code loading ([MASWE-0049](/mobile/maswe-0049-unsafe-dynamic-code-loading/)), test frameworks |
| Declared vs. observed components | Activities and services you declared | Stub component names in intents, `ComponentName` values or `getCallingActivity()` results that are not yours | Usually requires knowledge of a specific engine |
| Known host packages | n/a | Present on the device | Weakest signal: host renames, package visibility on Android 11+, user may have it for unrelated reasons |

Two practical notes:

- **Read twice, compare once.** The most robust checks ask the same question in two independent ways, for example the data directory path from `ApplicationInfo` and the real path of a file descriptor you just opened (`Os.readlink("/proc/self/fd/$fd")`). A host has to fake both consistently.
- **Do part of it in native code.** Java-level checks are easier to hook from the host's Java layer. A short check in a JNI library that reads `/proc/self/maps` and calls `stat()` directly is a different hook target. Neither is safe on its own: a host that hooks libc in-process can lie to native code too. The point is cost, not certainty.

### iOS: why there is no equivalent on stock devices

App virtualization as described above does not exist on a stock iPhone or iPad, and there is no meaningful client-side check to write for it:

- **One app, one sandbox, one container.** Each app runs in its own sandbox profile with its own data container. iOS has no mechanism for one app to host another app's executable in its process.
- **Code signing is enforced by the kernel.** Executable pages must come from code signed by Apple or by the developer's team, and an app can only load libraries signed by its own team or by Apple (library validation). A host app cannot `dlopen` someone else's App Store binary, and App Store binaries are FairPlay-encrypted on top.
- **No hidden-API surface to proxy.** Apps cannot replace the system's service connections the way an Android host replaces Binder proxies, and App Review rejects apps that download and run executable code.

The equivalent threats on iOS all need a jailbreak or a re-signed app. Jailbreak tweaks and re-signing tools can duplicate an app under a new bundle identifier so that two copies run side by side, and jailbreak tooling can inject code into any process. Those cases belong to [MASWE-0051](/mobile/maswe-0051-root-jailbreak-detection-not-implemented/) (jailbreak detection), [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/) (app attestation: an App Attest key is bound to the app's team and bundle ID, so a renamed duplicate cannot produce valid attestations for the original), and [MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/) (injected code). For an iOS-only assessment, record MASWE-0052 as *not applicable* and say why.

## Tests

OWASP has no tests for MASWE-0052. The two tests below cover Android. There is no iOS test (see the previous section).

### GT-RES-0052-1: Static review of virtualization anomaly checks (Android)

*Guler Tech methodology — not an OWASP test.*

#### Overview

The test looks for code that checks the app's own installation and process for signs of a virtualization host, and for what the app does with the result. It finds the checks, not their strength. Strength is GT-RES-0052-2.

#### Prerequisites

- The APK and all split APKs: `adb shell pm path com.example.app`, then `adb pull` each path.
- [jadx](https://github.com/skylot/jadx) (or jadx-gui) for Java and Kotlin, and `strings` or [rabin2](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/) plus Ghidra for native libraries.
- Optionally [semgrep](https://semgrep.dev/) for repeatable searches across the decompiled tree.

#### Steps

1. Decompile:

   ```bash
   jadx -d out/ --show-bad-code base.apk
   unzip -o -q base.apk 'lib/*' -d out/native/
   for s in split_config.*.apk; do unzip -o -q "$s" 'lib/*' -d out/native/ 2>/dev/null; done
   ```

2. Search the Java and Kotlin code for the APIs and strings that container checks use:

   ```bash
   grep -rnE 'getPackageCodePath|\.sourceDir|\.dataDir|nativeLibraryDir|getPackagesForUid|Process\.myUid|getProcessName|/proc/self/(maps|cmdline|fd)|Os\.(stat|readlink)' out/sources/ \
     | grep -vE '/(androidx|kotlin|kotlinx|com/google)/' | head -100
   ```

3. Search for strings that only make sense in a container check: `virtual`, `/virtual/data`, `dual`, `parallel`, `clone`, `multi`, path fragments of other apps' data directories, lists of package names. Large string arrays of package names next to `getPackageInfo` or `getLaunchIntentForPackage` calls are host lists.

4. Search native code. Container checks in JNI often read `/proc/self/maps` or `/proc/self/fd` and compare paths:

   ```bash
   for f in out/native/lib/arm64-v8a/*.so; do
     echo "== $f"; strings -a "$f" | grep -nE '/proc/self/(maps|fd|cmdline)|/data/(app|user|data)/|virtual' | head -20
   done
   ```

   Then open the library in Ghidra and follow cross-references from the strings to the functions that use them.

5. Check for a third-party RASP or anti-fraud SDK. Commercial RASP SDKs usually include container detection under names such as "app cloning", "virtual space" or "dual app". Identify the SDK by its package names in `out/sources/` and read its configuration (often a JSON or obfuscated asset): container detection may be present in the SDK but switched off.

6. For every check you find, trace the result: is it sent to the backend, shown to the user, used to disable features, or just logged?

7. Note the server side if you have access to it: does the backend verify a Play Integrity token and compare `appIntegrity.packageName`, the certificate digest and `appRecognitionVerdict` with the real app (see [MASWE-0054](/mobile/maswe-0054-device-attestation-not-implemented/))?

#### Observation

A list of checks with class and method (or native function and offset), the signal each one reads (data directory, code path, UID owners, maps, host list), and what happens with the result. Add the SDK name and version if the check comes from a RASP SDK.

#### Evaluation

- **Fail** if the app has an R-profile threat model and no container check at all, and there is no server-side attestation that compares the calling package.
- **Fail (weak)** if the only check is a list of known host package names, or if checks exist but their result is never used.
- **Pass, verify dynamically** if the app compares at least one framework-level value with a kernel-level value (data directory owner, mapped files, real UID) and sends the result somewhere that acts on it. Confirm with GT-RES-0052-2.
- **Pass with a note** if the app has no client-side check but the backend verifies Play Integrity and enforces the calling package. Record that client-side detection would improve the user-facing response but that the server already covers the business risk.

Do not fail an app because it lacks a check that would break legitimate profiles: an app that accepts work profiles, Private Space and OEM dual apps is doing the right thing.

#### Demo

A typical, simple check in decompiled form (illustrative, our own example) and the grep hit that finds it:

```java
public final class EnvGuard {
    public static boolean looksVirtualized(Context ctx) {
        String data = ctx.getApplicationInfo().dataDir;
        String code = ctx.getPackageCodePath();
        String pkg  = ctx.getPackageName();
        if (!data.endsWith("/" + pkg)) return true;
        if (!code.contains("/" + pkg + "-")) return true;
        String[] owners = ctx.getPackageManager().getPackagesForUid(Process.myUid());
        return owners == null || owners.length != 1 || !owners[0].equals(pkg);
    }
}
```

```text
$ grep -rnE 'getPackageCodePath|getPackagesForUid' out/sources/com/example/
out/sources/com/example/security/EnvGuard.java:6:        String code = ctx.getPackageCodePath();
out/sources/com/example/security/EnvGuard.java:9:        String[] owners = ctx.getPackageManager().getPackagesForUid(Process.myUid());
```

This check exists, which passes the static test, but it uses framework answers only, so a host that rewrites `ApplicationInfo` and proxies `getPackagesForUid` defeats it. That is a finding about strength, which GT-RES-0052-2 measures.

### GT-RES-0052-2: Running the app inside an app-virtualization host (Android)

*Guler Tech methodology — not an OWASP test.*

#### Overview

The test runs the production app inside a current virtualization host and records whether the app detects it and how it responds. It is the test that matters most for this weakness, because only a real host shows whether the app's checks survive the host's rewriting.

> **Warning:** Virtualization and clone host apps are untrusted software. By design they run other apps' code inside their own process and can read everything those apps store. Many are ad-supported, request broad permissions, and come from unclear sources. Use a dedicated test device that holds no personal accounts and no client data other than test accounts, install hosts only for the duration of the test, and remove them afterwards. Never sign in to real user accounts inside a host.

#### Prerequisites

- A dedicated physical test device (unrooted is fine and closer to the real attack), with USB debugging enabled.
- One or more current virtualization or clone hosts. Pick them by what is common in the app's market and in the client's fraud data rather than by brand. Prefer hosts that clone an installed app (true virtualization) over hosts that repackage it into a new APK, which is a different test ([MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/)).
- The production build of the app, installed normally from the store or the release APK, and test accounts.
- If the app is expected to accept legitimate profiles: a work profile or a secondary user on the same device, for the negative control.

#### Steps

1. Baseline. Launch the app normally, sign in with a test account, and exercise a sensitive flow (login, payment, adding a payee, claiming a promotion). Note the behaviour.

2. Install the host and add the app to it. Launch the app from inside the host.

3. Confirm that the app is really running inside the host and not as its own installation. From `adb shell`:

   ```bash
   adb shell ps -A -o USER,PID,NAME | grep -iE 'example|<host-package>'
   # A normal launch runs as the app's own user (u0_aNNN) with process name com.example.app.
   # Inside a host you will see the host's user and a host process name, or com.example.app
   # running under the host's UID.
   adb shell dumpsys package com.example.app | grep -E 'userId=|codePath='
   adb shell dumpsys package <host-package> | grep -E 'userId=|codePath='
   ```

   If the UID of the process that shows your app's UI is the host's `userId`, the app is virtualized. If the app crashed during start-up, check `adb logcat` before you call it "detection": many hosts cannot run modern apps at all (missing component support, target SDK features, native hooks that fail), and a crash is incompatibility, not a control.

4. Exercise the same sensitive flows. Record what the app does: a warning, a block, reduced functionality, a forced logout, nothing.

5. Collect evidence from logcat for the app's own messages and the host's:

   ```bash
   adb logcat -v time | grep -iE 'com\.example|<host-package>|virtual|clone'
   ```

6. Check the server side. If you have backend access or a test environment with logs, look at whether requests from the virtualized instance were flagged, and at the Play Integrity verdict for those requests. Google Play services evaluates the app the system reports as the caller, and inside a host the calling process belongs to the host package, so the verdict should not come back as `PLAY_RECOGNIZED` for your package and signing certificate (or the request should fail). Check `appIntegrity.packageName`, `appIntegrity.certificateSha256Digest` and `appRecognitionVerdict`; Google notes that `requestDetails.requestPackageName` can be spoofed in transit, so it is not enough on its own. A backend that accepts that is not checking the calling package.

7. Negative control. Run the app in a work profile or secondary user (`adb shell pm create-user`, or set up a work profile with a test DPC) and confirm the app works normally there.

8. Measure strength. If the app detected the host, record which signal triggered (from GT-RES-0052-1 or from its own messages) and try a second host built on a different engine. If the app's detection is a single Java method returning a boolean, the strength finding is the same as for any client-side check: see [MASWE-0065](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/) for how we record bypass effort. Do not build or modify host apps for this; you are testing the app's response to hosts that exist.

#### Observation

For each host: the host and its version, proof that the app ran inside it (`ps` and `dumpsys` output with UIDs), the app's behaviour in each sensitive flow (screenshots), relevant logcat lines, and the server-side outcome if available. For the negative control: the same flows in a work profile or secondary user.

#### Evaluation

- **Fail** if the app runs inside the host with full functionality, nothing reaches the backend, and the backend accepts requests from the virtualized instance.
- **Pass, server side only** if the app shows no client-side reaction but the backend rejects or flags the virtualized instance, for example because the Play Integrity verdict does not recognise the app. Recommend a clear client-side message for usability.
- **Pass** if the app detects the host and responds proportionately (restricts sensitive features, requires step-up, or the backend flags or blocks the session), and still works in the legitimate profile used as the negative control.
- **Pass with a note** if the app only detects some hosts. Name the ones it missed and the signal those hosts got past.
- **Fail (usability)** if the app blocks work profiles, Private Space or OEM dual-app instances. That is a false positive in the control, and it should be in the report even though it is not a security weakness.

#### Demo

*Illustrative output, not from a specific engagement.* `ps` and `dumpsys` showing the app's code running under a host's UID:

```text
$ adb shell dumpsys package com.example.app | grep userId=
    userId=10234
$ adb shell dumpsys package com.host.example | grep userId=
    userId=10311
$ adb shell ps -A -o USER,PID,NAME | grep -E 'u0_a234|u0_a311'
u0_a311       21877 com.host.example:p0
```

`u0_a311` is UID 10311, the host. The app's own UID (10234) has no process running, yet the app's login screen is on screen: the app is running inside `com.host.example:p0`. The app showed no warning and completed a test login and a transfer to a saved payee. Result: fail.

## Secure implementation

### Android: layered container checks

A Kotlin sketch that collects signals instead of returning a single boolean. It accepts all the legitimate locations from the table above and compares framework answers with what the kernel reports. Treat it as a starting point: the allow-lists need adjusting for preinstalled apps and for apps that load code from elsewhere.

```kotlin
object ContainerSignals {
    private val dataDirRe = Regex(
        "^(/data/data|/data/user/\\d+|/data/user_de/\\d+|/mnt/expand/[^/]+/user/\\d+)/(.+)$")

    fun collect(ctx: Context): List<String> {
        val hits = mutableListOf<String>()
        val pkg = ctx.packageName
        val ai = ctx.applicationInfo
        val uid = Process.myUid()

        // 1. Data directory has the shape of a real installation for this package
        val m = dataDirRe.matchEntire(ai.dataDir)
        if (m == null || m.groupValues[2] != pkg) hits += "dataDir"

        // 2. The kernel agrees that we own it
        try {
            if (Os.stat(ai.dataDir).st_uid != uid) hits += "dataDirOwner"
        } catch (e: ErrnoException) {
            hits += "dataDirStat:${e.errno}"
        }

        // 3. A file we just opened really lives where we were told
        val probe = File(ctx.filesDir, ".probe").apply { writeText("x") }
        ParcelFileDescriptor.open(probe, ParcelFileDescriptor.MODE_READ_ONLY).use { pfd ->
            val real = runCatching { Os.readlink("/proc/self/fd/${pfd.fd}") }.getOrNull()
            if (real != null && File(real).canonicalPath != probe.canonicalPath) hits += "fdPath"
        }

        // 4. Our UID belongs to us
        val owners = ctx.packageManager.getPackagesForUid(uid)?.toSet().orEmpty()
        if (pkg !in owners) hits += "uidOwners"

        // 5. Our own APK is mapped, and no other app's APK or DEX is
        val foreign = File("/proc/self/maps").readLines()
            .map { it.substringAfterLast(' ') }
            .filter { it.startsWith("/data/") && (it.endsWith(".apk") || it.endsWith(".dex")) }
            .filterNot { it.startsWith("/data/dalvik-cache/") || it.startsWith("/data/misc/apexdata/") }
            .filterNot { it.contains("/$pkg-") || it.contains("/$pkg/") }
            .filterNot { isKnownPlatformModule(it) }   // WebView, Trichrome, Play services modules
        if (foreign.isNotEmpty()) hits += "foreignMaps"
        return hits
    }
}
```

`isKnownPlatformModule` is left for you to write. Keep the `isKnownPlatformModule` allow-list narrow and based on the owning package of the path (WebView provider, Trichrome library, Google Play services), which you can confirm with `PackageManager.getPackageInfo` and the package's signing certificate.

Guidance on using it:

- **Run checks at start-up and again before sensitive actions**, not only in `Application.onCreate()`. Hosts that patch late are common.
- **Duplicate the most important checks in native code** and in an obfuscated form ([MASWE-0059](/mobile/maswe-0059-code-obfuscation-not-implemented/)), so that one Java hook does not remove them all.
- **Send the signal list to the backend** with sensitive requests, and let the server combine it with attestation, account history and velocity. Show the user a generic message ("This app can't run in this environment") rather than the specific reason.
- **Never block on the `/data/user/<n>/` user number.** A non-zero user is a work profile, Private Space, a secondary user or an OEM dual app.

### Server side: identity the host cannot forge

The strongest control for this weakness is on the server. When the app requests a Play Integrity token, Google Play services evaluates the app the system reports as the caller, and inside a host the calling process belongs to the host. A backend that decrypts and verifies the token, then checks that `requestDetails.requestPackageName` and `appIntegrity.packageName` equal your package, that `appIntegrity.certificateSha256Digest` matches your signing certificate, and that `appRecognitionVerdict` is `PLAY_RECOGNIZED`, rejects virtualized instances regardless of what the client-side code says. Google's own documentation warns that `requestPackageName` can be spoofed in transit, so make the decision on the `appIntegrity` fields and the request hash or nonce, not on `requestPackageName` alone. The details, including standard versus classic requests and the device verdicts, are in [MASWE-0054](/mobile/maswe-0054-device-attestation-not-implemented/) and [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/).

Add abuse controls that do not depend on detection at all: per-account and per-payment-instrument limits for promotions, server-side device binding with keys in the Android Keystore (a key generated inside a host belongs to the host's UID, and key attestation shows the host's package in the attestation application ID), and velocity rules across accounts.

## Rating findings

Series-wide rules apply, adapted here:

- **Info** if the app's threat model does not include the R profile. Missing container detection is an observation, and the report should say so plainly.
- **Low** for an R-profile app that has no container detection, but whose backend verifies Play Integrity and enforces the calling package, or whose sensitive functions do not depend on the device (no device-bound promotions, no per-device limits).
- **Medium** for an R-profile app that runs with full functionality inside a host, with no client-side response and no server-side package check, and that stores sensitive data or tokens readable by the host.
- **Medium–High** only when the gap directly enables concrete business abuse that you can show or that the client's data shows: multi-accounting against sign-up or referral bonuses, bypass of one-device-per-account limits on a payment or wallet app, or a host-based fraud pattern the client is already seeing. Show the abuse path in the report.
- A check that **exists but is trivially defeated** (a host package list, framework-only paths that a host rewrites) is rated by what the defeat unlocks, using the same scale. Say which host got through and why.
- Blocking **legitimate profiles** (work profile, Private Space, OEM dual apps) is a usability finding (Info or Low) with a recommendation, not a security weakness.

In the report give the host type (not necessarily the brand), proof of virtualization (`ps` and `dumpsys` UIDs), the sensitive flows that worked, what the backend received, and the specific remediation: kernel-level checks, a backend package check on Play Integrity, and the abuse controls that close the business risk.

## References

- OWASP MASWE: [MASWE-0052: App Virtualization Environment Detection Not Implemented](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0052/); related [MASWE-0051](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0051/), [MASWE-0053](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0053/), [MASWE-0054](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0054/), [MASWE-0056](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0056/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-RESILIENCE-1](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-1/) (CC BY-SA 4.0)
- OWASP MASTG tools: [rabin2 (MASTG-TOOL-0129)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/) (CC BY-SA 4.0)
- Android: [Application sandbox](https://source.android.com/docs/security/app-sandbox), [Supporting multiple users](https://source.android.com/docs/devices/admin/multi-user), [Work profiles (Android Enterprise)](https://developer.android.com/work/managed-profiles), [Private space](https://developer.android.com/about/versions/15/features#private-space), [Package visibility](https://developer.android.com/training/package-visibility), [Adoptable storage](https://source.android.com/docs/core/storage/adoptable), [Direct Boot](https://developer.android.com/privacy-and-security/direct-boot), [`ApplicationInfo`](https://developer.android.com/reference/android/content/pm/ApplicationInfo), [`PackageManager.getPackagesForUid`](https://developer.android.com/reference/android/content/pm/PackageManager#getPackagesForUid%28int%29), [`Application.getProcessName`](https://developer.android.com/reference/android/app/Application#getProcessName%28%29), [`android.system.Os`](https://developer.android.com/reference/android/system/Os)
- Google Play: [Play Integrity API overview](https://developer.android.com/google/play/integrity/overview), [Integrity verdicts](https://developer.android.com/google/play/integrity/verdicts)
- Apple: [Apple Platform Security: runtime process security](https://support.apple.com/en-gb/guide/security/sec15bfe098e/web), [Apple Platform Security: app code signing process](https://support.apple.com/en-gb/guide/security/sec7c917bf14/web), [Establishing your app's integrity (App Attest)](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity)
- Background: [VirtualApp (open-source app virtualization engine)](https://github.com/asLody/VirtualApp)
- CWE: [CWE-693](https://cwe.mitre.org/data/definitions/693.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
