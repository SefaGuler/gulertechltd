---
title: "MASWE-0051: Root/Jailbreak Detection Not Implemented"
date: 2026-11-10 20:00:00 +0000
subcategory: resilience
summary: "Root and jailbreak indicators on modern Android and iOS, how to find and trace an app's checks, how much effort a bypass costs, and how to rate gaps."
refs: [MASWE-0051, MASVS-RESILIENCE-1, MASVS-RESILIENCE-4, CWE-1326]
tags: [android, ios, masvs-resilience, root-detection, jailbreak-detection, rasp]
---

This note is part of our [MASVS-RESILIENCE guide](/mobile/masvs-resilience-resilience-testing-guide/) and covers OWASP [MASWE-0051](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0051/): an app that never checks whether it is running on a rooted Android device or a jailbroken iPhone, or checks so naively that the check costs an attacker nothing. Root and jailbreak are where most mobile reverse engineering starts. They give the attacker a process that can read your sandbox, attach to your app, load hooking frameworks into it and rewrite whatever the client decides. Root and jailbreak detection is the app's attempt to notice that. It is also one of the most misunderstood controls in mobile security. A check that runs on a device the attacker fully controls can always be defeated in the end, and many apps ship a single `isRooted()` call that falls to one off-the-shelf command. Below you get the indicators that still matter on current Android (systemless and kernel-based root) and iOS (rootless jailbreaks under `/var/jb`), why several classic indicators in OWASP's own pages no longer work, the four OWASP tests with their demos, two of our own tests that measure how much effort a bypass costs and whether the backend still makes the decision, and how to rate what you find. Like every control in this series, root and jailbreak detection is defence in depth that raises attacker cost. It never replaces the L1/L2 controls, and a client-side check without a server-side decision will be bypassed eventually.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
  - [Android: Root Detection (MASTG-KNOW-0027)](#android-root-detection-mastg-know-0027)
  - [iOS: Jailbreak Detection (MASTG-KNOW-0084)](#ios-jailbreak-detection-mastg-know-0084)
- [Tests](#tests)
  - [Before you start: the lab you need](#before-you-start-the-lab-you-need)
  - [MASTG-TEST-0324: References to Root Detection Mechanisms (Android)](#mastg-test-0324-references-to-root-detection-mechanisms-android)
  - [MASTG-TEST-0325: Runtime Use of Root Detection Techniques (Android)](#mastg-test-0325-runtime-use-of-root-detection-techniques-android)
  - [MASTG-TEST-0240: Jailbreak Detection in Code (iOS)](#mastg-test-0240-jailbreak-detection-in-code-ios)
  - [MASTG-TEST-0241: Runtime Use of Jailbreak Detection Techniques (iOS)](#mastg-test-0241-runtime-use-of-jailbreak-detection-techniques-ios)
  - [GT-RES-0051-1: Effort needed to neutralise the app's own checks (Android, iOS)](#gt-res-0051-1-effort-needed-to-neutralise-the-apps-own-checks-android-ios)
  - [GT-RES-0051-2: Detection response and server-side enforcement (Android, iOS)](#gt-res-0051-2-detection-response-and-server-side-enforcement-android-ios)
- [Best practices](#best-practices)
  - [Implementing Resilience and RASP Signals (MASTG-BEST-0029)](#implementing-resilience-and-rasp-signals-mastg-best-0029)
  - [Implementing Root Detection (MASTG-BEST-0030)](#implementing-root-detection-mastg-best-0030)
  - [What a good response looks like](#what-a-good-response-looks-like)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

The OWASP requirement is *"The app detects if it runs on a rooted/jailbroken device and reacts appropriately."* Both halves matter. Detection without a sensible reaction is a log line. A reaction without reliable detection is a coin toss.

MASWE-0051 maps to two MASVS controls:

- **MASVS-RESILIENCE-1**, "The app validates the integrity of the platform." A rooted or jailbroken OS no longer enforces the guarantees the rest of the MASVS relies on: the app sandbox, file permissions, the Keystore/Keychain access model, code-signing enforcement.
- **MASVS-RESILIENCE-4**, "The app implements anti-dynamic analysis techniques." Root and jailbreak are the usual way to run Frida server, attach debuggers and inject tweaks, so detecting them is also a first line against dynamic analysis.

OWASP's CWE mapping is [CWE-1326](https://cwe.mitre.org/data/definitions/1326.html) (Missing Immutable Root of Trust in Hardware). That is a hardware-design weakness and fits poorly. If your report template needs a CWE, [CWE-693](https://cwe.mitre.org/data/definitions/693.html) (Protection Mechanism Failure) describes a missing or weak resilience control better. We keep OWASP's mapping in the front matter for consistency.

The weakness carries the **R** profile (and **EUDIW**, the EU Digital Identity Wallet profile). It applies to apps whose threat model includes an attacker who controls the device the app runs on: banking and payments, wallets, DRM and media, games with economies, apps that protect high-value IP or enforce licensing. For an L1/L2-only assessment it is out of scope, and a missing check is at most an observation.

OWASP links the weakness to threat MAS-THREAT-0051, *"Attackers can run and manipulate the app in a privileged environment without resistance"*, reached through three attacks:

| Attack | Description | Role here |
|---|---|---|
| MAS-ATTACK-0065 | Running the app on a rooted or jailbroken device they control | The environment this weakness is about |
| MAS-ATTACK-0005 | Accessing the device storage on a compromised device | What root gives: the app's private files, databases, preferences, caches |
| MAS-ATTACK-0003 | Using dynamic instrumentation | What root makes easy: Frida server, Xposed/LSPosed-style hooking, tweak injection |

Keep the neighbouring topics apart. Several of them are often lumped together as "root detection" in RASP products:

| Question | Where it lives |
|---|---|
| Does the app look for signs of root or jailbreak on the device? | This note (MASWE-0051) |
| Does the backend get a verdict from Google or Apple about the device? | [MASWE-0054 device attestation](/mobile/maswe-0054-device-attestation-not-implemented/) |
| Does the app notice an emulator or simulator? | [MASWE-0053](/mobile/maswe-0053-emulator-virtual-device-detection-not-implemented/) |
| Does the app notice it runs inside a cloning or virtualization host? | [MASWE-0052](/mobile/maswe-0052-app-virtualization-detection-not-implemented/) |
| Does the app notice Frida, Xposed or injected code in its own process? | [MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/) and [MASWE-0065](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/) |
| Does the app notice an attached debugger? | [MASWE-0064](/mobile/maswe-0064-debugger-detection-not-implemented/) |
| Does the app require a device passcode or screen lock? | [MASWE-0017](/mobile/maswe-0017-device-secure-lock-not-enforced/) (its tests 0246–0249 sit in OWASP's RESILIENCE folder but are documented there) |

## Modes of Introduction

**No detection at all.** The app never looks at its environment. This is the default for most apps and is fine for most apps. It is a finding only when the threat model says R.

**A single, central check.** One `isDeviceRooted()` or `+[Security isJailbroken]` method, called once in `onCreate` or `application:didFinishLaunchingWithOptions:`, with a descriptive name and a single boolean return. One hook or one patched branch disables everything. This is the most common pattern we see in apps that "have root detection".

**Indicator lists from 2015.** Paths such as `/system/xbin/daemonsu`, `/Applications/Cydia.app` or `/var/lib/cydia` describe rooting and jailbreak tools that are no longer used. On a device rooted with current tools or jailbroken with a rootless jailbreak, these checks return "clean". Copying the lists from OWASP's Knowledge pages, from old blog posts or from a library's defaults produces checks that pass every review and detect little.

**Checks that the platform silently disables.** On Android 11 and later, `PackageManager` lookups for root manager apps return "not installed" unless the app declares the packages in `<queries>` (or holds `QUERY_ALL_PACKAGES`). Since Android 7 and 8, apps can no longer see other apps' processes or services. On iOS, `canOpenURL` returns `false` for any scheme not declared in `LSApplicationQueriesSchemes`. A check can compile, run and never fire.

**Java-only or Swift-only checks.** Checks that only use high-level APIs (`File.exists()`, `FileManager.fileExists(atPath:)`) are the first thing generic bypass scripts hook.

**Detection without a response strategy.** The app detects root and does nothing, or logs it locally, or shows a toast. Or the opposite: it calls `System.exit(0)` / `exit(0)` immediately, which tells an attacker exactly where the check is and also locks out legitimate users on custom ROMs.

**A client-side decision only.** The app decides locally to allow or refuse a payment based on its own `isRooted` flag, and the backend never learns or cares. Once the flag is hooked, nothing else stands in the way.

**Verbose responses.** Dialogs or logs that say *"Root detected: /system/xbin/su"* hand the attacker a map of the checks.

## Impact

- **Bypass of client-side protections.** Root gives the attacker the means to hook or patch the app's other resilience controls (integrity checks, pinning, anti-debugging), its business logic (licensing, feature gating, local limits) and its fraud signals.
- **Exposure of data at rest and in memory.** With root, the attacker reads the app's private storage and memory, including tokens, cached personal data and anything decrypted at run time. Hardware-backed keys cannot be extracted, but they can be *used* from inside the app process, which is often enough.
- **Automation and fraud at scale.** Rooted and jailbroken devices are the platform for bots, scripted account creation, promotion abuse and game cheating. An app that cannot tell these environments from a normal phone gives its backend nothing to act on.
- **Weakened MASVS assumptions.** Secure storage, local authentication and secure-lock checks all assume the OS enforces its rules. On a rooted device, the evidence from those other tests is weaker.

None of these is a vulnerability in the sense of a remote attacker gaining access to a victim's data. The attacker in this model is usually the device owner, or someone who has prepared a device. That is why rating depends so heavily on the profile and on what the bypass unlocks (see [Rating findings](#rating-findings)).

## Mitigations

- **Layer the detection.** Combine several kinds of signal (file and binary artefacts, system properties, boot and verified-boot state, mount and namespace anomalies, installed packages where visible, injected libraries), and implement some of them in native code.
- **Distribute the checks.** Run them near sensitive operations (login, adding a payee, payment, key provisioning), not only at start-up, and do not funnel them through one method that returns one boolean.
- **Respond in proportion.** Restrict high-risk features, require step-up authentication, shorten sessions, flag the account for review. Reserve hard blocking for cases where the risk justifies the support cost.
- **Let the server decide.** Send the signals to the backend bound to the request, and combine them with server-verified attestation ([MASWE-0054](/mobile/maswe-0054-device-attestation-not-implemented/), [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/)) so the decision survives a hooked client.
- **Keep it current.** Re-test the detection against current rooting and jailbreak tools and current public bypass scripts with each release, and rotate indicators.

## Knowledge

OWASP links two Knowledge pages to the tests of this weakness: MASTG-KNOW-0027 (Android root detection) and MASTG-KNOW-0084 (iOS jailbreak detection). Both are dated in places. The sections below explain each mechanism, say which classic indicators still work and which do not, and describe in general terms how attackers defeat them.

### Android: Root Detection (MASTG-KNOW-0027)

Source: [MASTG-KNOW-0027](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0027/).

OWASP defines root detection broadly for Android: it includes detecting custom ROMs, that is, telling a stock vendor build from a modified one. That definition is useful. Many signals (test-keys, an unlocked bootloader, a permissive SELinux policy) indicate a modified OS rather than a running `su`, and the risk is similar.

#### What rooting looks like today

The root solutions OWASP's page was written around (SuperSU, KingRoot, Superuser.apk) wrote `su` binaries into `/system`. That stopped working when Android moved to dm-verity, system-as-root and, from Android 10, read-only dynamic partitions. Current root solutions are different:

- **Magisk** ([MASTG-TOOL-0021](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0021/)) is *systemless*: it patches the boot image (ramdisk/init), keeps its own files under `/data/adb/` and overlays changes onto the system at boot with mounts instead of modifying the partitions. Its "Zygisk" feature runs module code inside the zygote and therefore inside every app process. Module frameworks such as LSPosed build on it to hook Java code.
- **KernelSU** and **APatch** implement root in the kernel (a patched kernel or a kernel module, and a patched kernel image respectively). They also keep state under `/data/adb/` and are designed so that apps that were not granted root generally do not see a `su` binary at all.
- **Hiding is part of the product.** Magisk's DenyList reverts its mounts in the mount namespace of selected apps, the Magisk manager can repackage itself under a random package name, and third-party modules (Shamiko is the best known) go further. Kernel-level solutions can hide files and mounts system-wide. We name these as part of the threat landscape only. What matters for testing is that a rooted device configured to hide from your app looks, from the app's own view of the file system, very much like a stock device.

The practical consequence: on a well-configured modern rooted device, many classic file checks return nothing. The signals that still carry weight are the ones the root solution cannot easily hide from inside your process (mount and namespace anomalies, injected code in your own memory, inconsistencies between APIs) and, above all, the verdicts that come from outside the device ([Play Integrity](#local-checks-versus-play-integrity)).

#### File and binary checks

The classic check looks for `su` and related binaries and files:

```text
/system/bin/su            /system/xbin/su          /sbin/su
/system/bin/failsafe/su   /system/sd/xbin/su       /su/bin/su
/data/local/su            /data/local/bin/su       /data/local/xbin/su
/system/xbin/busybox      /system/app/Superuser.apk
```

Variants check every directory in `PATH`:

```kotlin
fun suOnPath(): Boolean =
    System.getenv("PATH").orEmpty().split(":").any { File(it, "su").exists() }
```

What to know:

- **These checks are cheap and still catch careless setups**, such as an emulator image with `su` in `/system/xbin`, or a Magisk device that has not hidden itself from the app.
- **`/data/adb/` is where every current root solution keeps its state**, but `/data/adb` also exists on stock devices (init creates it, owned by root with mode 0700), and an unprivileged app cannot list it. Probing paths below it relies on side channels (the error an `access()` or `stat()` returns) whose behaviour depends on the SELinux policy and Android version. Treat such checks as fragile.
- **File checks can be done in Java/Kotlin or native code.** In Java, `File.exists()`, `File.canRead()`, `File.isDirectory()`. In native code, `access()`, `faccessat()`, `stat()`, `lstat()`, `fopen()`, `open()`/`openat()`, `opendir()`. The more robust implementations issue the system call directly (an inline `svc #0` on arm64) so that hooks on libc functions do not see it. OWASP's page shows the classic JNI pattern from rootinspector, which calls `stat()` through libc.

#### Executing su and other commands

`Runtime.getRuntime().exec("su")` or `exec(arrayOf("which", "su"))` asks the shell whether `su` resolves. An `IOException` means it was not found. The same approach runs `getprop`, `mount` or `id`.

Two caveats. First, actually executing `su` on a device with a root manager can trigger a root-permission prompt, which is poor UX and visible to the user. `which su` (provided by toybox on current Android) is the gentler variant. Second, these are some of the easiest checks to hook: `Runtime.exec`, `ProcessBuilder.start` and native `execve`/`posix_spawn` are standard hook targets.

#### System properties and build signatures

| Property | Stock retail value | What a different value suggests |
|---|---|---|
| `ro.build.tags` (exposed as `Build.TAGS`) | `release-keys` | `test-keys` or `dev-keys`: the build was signed with AOSP test keys, i.e. a custom or engineering build ([Signing builds for release](https://source.android.com/docs/core/ota/sign_builds)) |
| `ro.debuggable` | `0` | `1`: a `userdebug` or `eng` build, on which every app can be debugged. Also `1` on most emulator images |
| `ro.secure` | `1` | `0`: `adbd` runs as root by default (engineering builds) |
| `ro.boot.verifiedbootstate` | `green` | `orange` (bootloader unlocked) or `yellow` (custom root of trust) ([Verified Boot boot flow](https://source.android.com/docs/security/features/verifiedboot/boot-flow)) |
| `ro.boot.flash.locked`, `ro.boot.vbmeta.device_state` | `1`, `locked` | `0`, `unlocked`: unlocked bootloader. Not present on every device |
| `ro.build.type` | `user` | `userdebug` or `eng` |

Notes:

- `Build.TAGS` is a static field initialised from `ro.build.tags` when the framework starts. Reading it does not call `getprop` or `__system_property_get` in your process, so you will not see it in a native trace. You see it in decompiled code, and at run time only by hooking whatever the app does with the string.
- Apps read other properties through the hidden `android.os.SystemProperties.get()` (usually via reflection), by executing `getprop`, or natively through `__system_property_get()` / `__system_property_read_callback()`. Which properties are readable from the app sandbox is controlled by SELinux property contexts and varies between versions and vendors. Treat an unreadable property as "unknown".
- Root solutions can rewrite read-only properties in memory (Magisk's `resetprop` is the well-known example), and hiding modules restore "stock" values for `ro.build.tags` and the verified-boot properties. A clean property set is therefore weak evidence of a clean device, while a dirty one (an unlocked bootloader on a production phone) is fairly strong evidence of a modified one.
- OWASP mentions checking for Google's OTA certificates (`/system/etc/security/otacerts.zip`). The content of that file is the vendor's update certificate, not a universal Google certificate, so the check needs per-vendor knowledge and is rarely worth implementing today.

#### Installed packages and Android 11 package visibility

Detection libraries look for root managers and hooking frameworks with `PackageManager.getPackageInfo()` or `getApplicationInfo()`. Classic examples are `com.topjohnwu.magisk`, `eu.chainfire.supersu`, `com.noshufou.android.su` and `com.koushikdutta.superuser`. Current kernel-based root managers have their own package names (for example `me.weishu.kernelsu` for KernelSU's manager and `me.bmax.apatch` for APatch).

From **Android 11 (API 30)**, [package visibility filtering](https://developer.android.com/training/package-visibility) applies to apps that target API 30 or higher. A package the app cannot see behaves exactly like a package that is not installed: `getPackageInfo()` throws `PackageManager.NameNotFoundException`, and `getInstalledPackages()` leaves it out. To see specific packages, the app must name them in the manifest:

```xml
<queries>
    <package android:name="com.topjohnwu.magisk" />
    <package android:name="me.weishu.kernelsu" />
</queries>
```

The alternative is the `QUERY_ALL_PACKAGES` permission. Google Play restricts it ([Use of the broad package visibility permission](https://support.google.com/googleplay/android-developer/answer/10158779)): permitted core uses are device search, antivirus, file managers and browsers, and Play may grant a temporary exception to apps whose verifiable core purpose is financial transactions with regulated instruments (dedicated banking apps, digital wallets) *solely for security-based purposes*. The policy also says a use is not valid when a less broad method would do, so a short `<queries>` list is the defensible choice for root-manager checks.

Two consequences for testing:

- A package check in code with no matching `<queries>` entry (and no `QUERY_ALL_PACKAGES`) is dead code on Android 11+ when `targetSdkVersion` ≥ 30. Report it as ineffective, not as detection.
- A `<queries>` block listing root managers is itself a convenient static indicator that the app does root detection. OWASP's demo app declares twelve packages this way.

Package checks are weak even when visible: the Magisk manager can repackage itself under a random name, and LSPosed-style frameworks do not need a manager app installed in the usual way.

#### Running processes and services

OWASP's page describes looking for the SuperSU daemon (`daemonsu`) with `ActivityManager.getRunningServices()`, `getRunningAppProcesses()`, `ps` or `/proc`. These techniques no longer work for third-party apps:

- Since **Android 7.0**, `/proc` is mounted so that apps cannot see other apps' process entries.
- Since **Android 8.0 (API 26)**, [`getRunningServices()`](https://developer.android.com/reference/android/app/ActivityManager#getRunningServices%28int%29) returns only the caller's own services for third-party apps, and `getRunningAppProcesses()` has only reported the caller's own processes since Android 5.1.
- `daemonsu` belongs to SuperSU, which is no longer maintained.

If you find process-based checks in an app, report them as ineffective on supported Android versions. The modern equivalent is inspecting the app's *own* process: `/proc/self/maps` for injected libraries and `/proc/self/mountinfo` for unexpected mounts. Those checks belong partly to [MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/) and [MASWE-0065](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/).

#### Mounts, writable partitions and SELinux

OWASP suggests looking for `/system` or `/data` mounted read-write. On current devices with dm-verity and read-only dynamic partitions, `/system` is read-only even when rooted, because systemless root does not remount it. The check catches old root methods and devices with verity disabled. More useful today:

- **`/proc/self/mounts` and `/proc/self/mountinfo`** describe the mount namespace of your own process. Overlay, tmpfs or bind mounts on top of system paths, or mount entries whose source does not match the stock layout, indicate systemless modification, unless the root solution has reverted them for your app.
- **SELinux state.** All Android versions since 5.0 run SELinux in enforcing mode for all domains on certified devices ([SELinux in Android](https://source.android.com/docs/security/features/selinux)). A permissive device is modified. Apps sometimes read `/sys/fs/selinux/enforce` or run `getenforce`. Whether the app sandbox may read selinuxfs depends on the policy of the Android version, so a failed read means "unknown", not "enforcing".

#### Native checks and where to put them

Java/Kotlin checks are easy to find in jadx and easy to hook with the Java bridge of Frida. Native checks raise the cost:

- They are not visible in decompiled Java. The tester has to load the `.so` in Ghidra or r2 and follow the JNI function.
- They can bypass libc entirely with inline system calls, so hooks on `access()` or `stat()` see nothing.
- They can compare the answers of several APIs (Java `File.exists()` vs native `stat()` vs a direct syscall) and treat a disagreement as evidence of hooking.

None of this makes the check unbreakable. A determined attacker patches the native function or the JNI return value. It does make the generic one-command bypasses fail, which is what most R-profile threat models are about. Commercial RASP SDKs and open-source libraries such as RootBeer ([MASTG-TOOL-0146](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0146/), Java with a JNI component) and Android RASP ([MASTG-TOOL-0147](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0147/), Kotlin and Rust) package these techniques. OWASP endorses neither. Library defaults are public, and public bypass scripts target them by name. objection, for example, hooks RootBeer's methods directly.

#### Local checks versus Play Integrity

Everything above runs on the device the attacker controls. The Play Integrity API asks Google instead, and the answer is signed by Google and verified by your server ([Integrity verdicts](https://developer.android.com/google/play/integrity/verdicts)). In outline:

- `MEETS_DEVICE_INTEGRITY` means a genuine, Play-certified Android device. On **Android 13 and higher** it requires hardware-backed proof (key attestation) that the bootloader is locked and the loaded OS is a certified vendor image, so a typical rooted device with an unlocked bootloader fails it.
- `MEETS_STRONG_INTEGRITY` (opt-in) additionally requires, on Android 13+, security updates within the last year for all partitions. On Android 12 and lower it only requires hardware-backed boot integrity.
- `MEETS_BASIC_INTEGRITY` (opt-in) only says the device passes basic integrity checks. The bootloader may be unlocked.
- Optional signals such as `appAccessRiskVerdict` (apps that could capture or control the screen) and `playProtectVerdict` (Play Protect state) add environment context.

Server-side verdicts do not make local checks redundant. They need Google Play services, they cost latency and quota, they cannot run before every tap, and an ecosystem exists that tries to spoof attestation on rooted devices (for example with leaked attestation keys, which Google revokes). That is why server-side policy matters: requiring `MEETS_STRONG_INTEGRITY` for the riskiest actions, honouring revocation, and treating the verdict as one input to a risk score. Local checks fill the gaps between attestation calls and add signals Google does not report. The design, the verification and the tests are covered in [MASWE-0054](/mobile/maswe-0054-device-attestation-not-implemented/). SafetyNet Attestation, the predecessor, has been turned down. An app still calling it gets no useful verdict.

### iOS: Jailbreak Detection (MASTG-KNOW-0084)

Source: [MASTG-KNOW-0084](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0084/).

#### Rootful, rootless and hidden jailbreaks

A jailbreak exploits the kernel to disable or work around code-signing enforcement and the sandbox for the processes the attacker chooses, and installs a package manager and a tweak-injection system. Two generations matter:

- **Rootful jailbreaks** (checkra1n, unc0ver, Taurine, and palera1n in its rootful mode) remount or replace the root file system and install packages into `/Applications`, `/Library`, `/usr`, `/etc`, `/bin`. Cydia was their package manager ([MASTG-TOOL-0047](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0047/), now marked deprecated by OWASP itself). The classic indicator lists come from this era.
- **Rootless jailbreaks.** iOS 15 boots from a cryptographically sealed system volume, which makes modifying the root file system impractical. Current jailbreaks such as Dopamine and palera1n (rootless mode) leave it alone and install everything under a prefix in the preboot volume, reachable through the symlink **`/var/jb`**. Package managers are Sileo and Zebra, the bootstrap is Procursus, and tweaks are injected with ElleKit. On such a device `/Applications/Cydia.app`, `/bin/bash`, `/etc/apt` and `/usr/sbin/sshd` simply do not exist at those paths. `/var/jb/usr/bin/...` and `/var/jb/Applications/Sileo.app` do.
- **Hiding.** Jailbreak-hiding tweaks and variants such as "roothide" (which randomises the `/var/jb` path) exist precisely to defeat file checks. We name them as part of the threat landscape only.

An app whose indicator list only covers the rootful era passes MASTG-TEST-0240 (the strings are in the binary) and detects almost nothing on a current jailbreak. That is why our [GT-RES-0051-1](#gt-res-0051-1-effort-needed-to-neutralise-the-apps-own-checks-android-ios) test runs on a current device.

#### File-based checks

The app checks whether files or directories associated with a jailbreak exist. OWASP's list (rootful era) includes `/Applications/Cydia.app`, `/Library/MobileSubstrate/MobileSubstrate.dylib`, `/bin/bash`, `/bin/sh`, `/etc/apt`, `/usr/sbin/sshd`, `/usr/libexec/sftp-server`, `/private/var/lib/apt`, `/private/var/lib/cydia`, `/private/var/stash`, `/usr/sbin/frida-server` and others. A current list also needs at least `/var/jb` itself and paths under it, and the bundles of current package managers (`Sileo.app`, `Zebra.app`), under `/Applications` for rootful and under `/var/jb/Applications` for rootless installs.

APIs to know, because each is a separate hook target: `FileManager.fileExists(atPath:)` (which calls `-[NSFileManager fileExistsAtPath:]`), `fileExists(atPath:isDirectory:)`, `attributesOfItem(atPath:)`, `contentsOfDirectory(atPath:)`, and in C `stat()`, `lstat()`, `access()`, `open()`, `fopen()`, `opendir()`, `realpath()`, `statfs()`. Stronger implementations use several of them, compare their answers, and issue some system calls directly with `svc #0x80` so that hooks on libSystem do not see them.

#### Sandbox integrity: write and fork tests

On a stock device, the sandbox prevents an App Store app from writing outside its container and from creating new processes. So the app tries:

```swift
do {
    try "x".write(toFile: "/private/jb-probe.txt", atomically: true, encoding: .utf8)
    try? FileManager.default.removeItem(atPath: "/private/jb-probe.txt")
    // write succeeded: sandbox is not enforced for this process
} catch {
    // expected on a stock device
}
```

or calls `fork()` and treats a non-negative return as evidence that the sandbox has been relaxed.

These were strong checks against early jailbreaks that patched the sandbox globally. Current jailbreaks usually leave the sandbox of App Store apps in place and inject tweaks through other means, so both tests usually come back "clean" on a modern jailbreak. Keep them as cheap extra signals, never as the main check. `fork()` is in any case unavailable to sandboxed apps, and a check that reaches it will be flagged by any decent bypass script (objection hooks `fork` in `libSystem.B.dylib`).

#### URL schemes and LSApplicationQueriesSchemes

The app asks whether a jailbreak package manager's URL scheme can be opened:

```swift
if let url = URL(string: "sileo://"), UIApplication.shared.canOpenURL(url) {
    // a handler for sileo:// is installed
}
```

Since **iOS 9**, `canOpenURL(_:)` returns `false` for any scheme not declared in the app's `Info.plist` under `LSApplicationQueriesSchemes`, whether or not an app handles it ([`canOpenURL(_:)`](https://developer.apple.com/documentation/uikit/uiapplication/canopenurl%28_:%29)). Apps linked on or after iOS 15 may declare at most 50 schemes. Apple's documentation now also lists a limit of 25 entries for apps linked on or after iOS 27, and shows the method's availability ending at iOS 27, so expect this check to become even less useful. On the device you can see undeclared queries fail in the console log with *"This app is not allowed to query for scheme ..."*.

For testing this means: a `cydia://` or `sileo://` string in the binary without a matching `LSApplicationQueriesSchemes` entry is dead code. Report it as ineffective. And Cydia's scheme, which OWASP's page uses as its example, is irrelevant on current jailbreaks.

#### Injected libraries and dyld images

Tweak injection loads dynamic libraries into the app process. The app can enumerate the loaded images with `_dyld_image_count()` and `_dyld_get_image_name()`, or register a callback with `_dyld_register_func_for_add_image()`, and look for names such as `MobileSubstrate`, `SubstrateLoader`, `libsubstitute`, `libhooker`, `TweakInject`, `libellekit`, Frida's agent or gadget, `cycript`, and anything loaded from `/var/jb/` or `/Library/MobileSubstrate/`. A check of `getenv("DYLD_INSERT_LIBRARIES")` is common in sample code, including OWASP's demo, but modern injection does not depend on that variable being visible in the app's environment, so it is a weak signal.

Image checks overlap with [MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/) (code injection) and [MASWE-0065](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/) (Frida). They are worth having here because, unlike file checks, they look at the app's own process, which a jailbreak cannot hide from the app as easily as a path.

#### Symbolic links and file system state

Rootful jailbreaks used to move directories such as `/Applications` or `/usr/share` to the data partition and replace them with symbolic links. `lstat()` showing `S_IFLNK` for a path that is a real directory on stock iOS was a reliable sign. On rootless jailbreaks the equivalent is `/var/jb` itself, which is a symlink into the preboot volume. `statfs("/")` and `getfsstat()` reveal mount flags and mounted file systems, which differ on rootful installs that remount the root file system.

#### Where Apple's attestation fits

Apple offers no "jailbroken" verdict. App Attest (`DCAppAttestService`) lets your server verify that requests come from a genuine instance of your app on genuine Apple hardware, and DeviceCheck (`DCDevice`) stores two bits per device on Apple's servers. Neither is documented as a jailbreak detector. On iOS, the app's own jailbreak checks therefore remain the main platform-integrity signal, and their output is most useful when it is sent to the server inside a request that App Attest protects, so the server knows the report came from your real app. See [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/) and [MASWE-0054](/mobile/maswe-0054-device-attestation-not-implemented/).

#### How checks are defeated

In general terms (this is what you will measure in the tests, not a recipe):

- **Generic hooks.** objection's `ios jailbreak disable` and `android root disable`, and public Frida scripts, hook the common APIs and return "not found" for known paths. They defeat checks that use those APIs with those paths.
- **Targeted hooks.** The attacker finds the app's decision function (often named `isJailbroken`, `isRooted`, `checkRoot`) and forces its return value. One hook defeats every check behind a central function.
- **Patching.** The check or the branch after it is patched in the binary or in smali and the app is re-signed. That is countered by integrity checks ([MASWE-0057](/mobile/maswe-0057-app-resources-integrity-not-verified/), [MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/)) and app attestation ([MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/)).
- **Environment hiding.** DenyList-style namespace hiding, kernel-level hiding and jailbreak-hiding tweaks make the device look clean to file and package checks without touching the app.

Each layer the app adds forces a step up this list. That is the measurable value of the control.

## Tests

OWASP assigns four tests to MASWE-0051: two static and two dynamic, one pair per platform. They replace the legacy v1 tests [MASTG-TEST-0045](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0045/) (Testing Root Detection, `covered_by` 0324 and 0325) and [MASTG-TEST-0088](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0088/) (Testing Jailbreak Detection, `covered_by` 0240 and 0241).

The four OWASP tests answer one question: *is there detection?* They explicitly leave robustness out of scope. The legacy v1 tests did assess robustness (how many layers, which APIs, how long a bypass took), and that is what an R-profile client actually wants to know. Our two tests bring it back: GT-RES-0051-1 measures the effort needed to neutralise the app's own checks, and GT-RES-0051-2 checks what the app and its backend do with a detection. Run them in this order: static, dynamic, effort, response.

### Before you start: the lab you need

- **Android:** one device or emulator rooted with a current solution (Magisk, KernelSU or APatch) and a matching `frida-server`, plus one stock device with a locked bootloader for comparison. Run the detection tests first with no hiding enabled for the app, then, for GT-RES-0051-1, record whether the app still detects the device when the root solution's standard per-app hiding is on. Our [lab note](/mobile/mobile-traffic-interception-lab/) covers the set-up.
- **iOS:** one jailbroken device on a current rootless jailbreak with Frida installed from its package manager, plus one stock device. If your jailbroken device is on a rootful jailbreak, say so in the report: results do not transfer to rootless devices and vice versa.
- **Tools:** jadx, apktool, `aapt2`, semgrep ([MASTG-TOOL-0110](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/)), radare2 ([MASTG-TOOL-0073](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/)), Ghidra, Frida ([MASTG-TOOL-0031](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/)), objection ([MASTG-TOOL-0038](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0038/)), optionally Frooky ([MASTG-TOOL-0145](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0145/)), an intercepting proxy.
- **A false-positive baseline.** Run the app on the stock devices first and note its behaviour. A crash on a rooted device means nothing if the app also crashes on a stock one.

The commands below use `com.example.app` as the package or bundle identifier.

### MASTG-TEST-0324: References to Root Detection Mechanisms (Android)

*OWASP test: [MASTG-TEST-0324](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0324/). Type: static. Knowledge: MASTG-KNOW-0027. Best practices: MASTG-BEST-0029, MASTG-BEST-0030.*

#### Overview

The test looks through the decompiled app and its native libraries for root detection logic: `su` paths and other root artefacts, `Runtime.exec` of `su`, `which` or `getprop`, package lookups for root managers, `Build.TAGS` checks for `test-keys`, and reads of risky system properties. It produces a list of check locations to feed into MASTG-TEST-0325. OWASP's techniques are reverse engineering the APK ([MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)) and static analysis with grep and semgrep ([MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)). Robustness is out of scope for this test.

#### Prerequisites

- The APK and all splits (`adb shell pm path com.example.app`, then `adb pull` each path).
- jadx and apktool output, semgrep with OWASP's rule file `mastg-android-root-detection.yaml` from the MASTG repository (`rules/`), `aapt2`, `readelf` or `llvm-readelf`, `strings`.

#### Steps

1. Decompile:

   ```bash
   jadx -d jadx-out --show-bad-code base.apk
   apktool d -o apktool-out base.apk
   unzip -o -q base.apk 'lib/*' -d apk          # repeat for split_config.<abi>.apk
   ```

2. Run OWASP's semgrep rules over the decompiled Java. They flag `new File(...).exists()` on paths containing `su`, `magisk` or `Superuser.apk`, `getPackageInfo` calls, `Build.TAGS` checks for `test-keys`, `getprop` executions and any other `Runtime.exec`:

   ```bash
   semgrep -c mastg-android-root-detection.yaml jadx-out/sources/
   ```

3. Grep for indicators the rules do not cover, including the strings themselves (paths are often stored in arrays far from the `File` call):

   ```bash
   grep -rnE '"/(sbin|su/bin|system/(bin|xbin|sd/xbin|bin/failsafe)|data/local(/x?bin)?)/su"|Superuser\.apk|busybox|magisk|kernelsu|apatch|/data/adb|test-keys|ro\.debuggable|ro\.secure|ro\.boot\.(verifiedbootstate|flash\.locked|vbmeta)|/proc/self/(mounts|mountinfo|maps)|selinux/enforce|getenforce' jadx-out/sources/ | grep -v '/androidx/'
   ```

4. Check the manifest for package-visibility declarations and the broad permission, since a package check without them is dead code on Android 11+:

   ```bash
   grep -A30 '<queries>' jadx-out/resources/AndroidManifest.xml
   aapt2 dump permissions base.apk | grep -i QUERY_ALL_PACKAGES
   aapt2 dump badging base.apk | grep -E 'targetSdkVersion|sdkVersion'
   ```

5. Identify detection libraries and attestation clients. Known package prefixes are quick wins: `com.scottyab.rootbeer` (RootBeer), `com.securevale.rasp` (Android RASP), `com.google.android.play.core.integrity` (Play Integrity, which belongs to [MASWE-0054](/mobile/maswe-0054-device-attestation-not-implemented/) but tells you the server may also get a verdict). Commercial RASP SDKs usually have a recognisable package prefix and a native library of their own.

   ```bash
   ls jadx-out/sources/com/scottyab/rootbeer jadx-out/sources/com/securevale 2>/dev/null
   grep -rl 'com.google.android.play.core.integrity' jadx-out/sources | head
   ```

6. Look at the native libraries. Strings first, then imports of the functions native checks use, then signs of inline system calls:

   ```bash
   for f in apk/lib/arm64-v8a/*.so; do
     hits=$(strings -a "$f" | grep -cE '/su$|/su"|magisk|/data/adb|test-keys|ro\.boot\.verifiedbootstate|/proc/self/mount')
     [ "$hits" -gt 0 ] && echo "$f: $hits indicator strings"
   done
   readelf --dyn-syms -W apk/lib/arm64-v8a/libfoo.so | grep -E ' (access|faccessat|stat|lstat|fstatat|fopen|openat|opendir|popen|execve|__system_property_get|__system_property_read_callback|syscall)$'
   llvm-objdump -d --no-show-raw-insn apk/lib/arm64-v8a/libfoo.so | grep -c 'svc'
   ```

   Strings in hardened libraries are often encrypted, so a library with no hits but with `svc` instructions and file-access imports deserves a look in Ghidra.

7. For every hit, open the call site in jadx (or Ghidra for JNI functions, starting from the `native` methods and `JNI_OnLoad`) and record: what is checked, which API is used, where the result goes, and what the app does with it.

#### Observation

A table of detection checks: location (class and method, or library and function), category (file, exec, package, property, mount, native, library), the API used, and the indicators. Note the manifest's `<queries>` entries and `targetSdkVersion`, any detection libraries with their versions, and whether a Play Integrity client is present.

#### Evaluation

The test **fails** when the app has no root detection logic in Java/Kotlin or native code.

The test **passes** when root detection is present. Add the following qualifications to the report, because "present" is not "effective":

- Package checks without a matching `<queries>` entry or `QUERY_ALL_PACKAGES`, for `targetSdkVersion` ≥ 30, are ineffective.
- Process or service enumeration (`getRunningServices`, `getRunningAppProcesses`, `ps`, other apps' `/proc` entries) is ineffective on supported Android versions.
- Checks that consist only of `su` paths and `test-keys`, in Java, behind one method, will fall to a generic script. Carry that into GT-RES-0051-1.

Static analysis misses obfuscated, encrypted, dynamically loaded and native-only checks, so a negative result is not conclusive. Confirm it with MASTG-TEST-0325.

#### Demo

[MASTG-DEMO-0087](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0087/MASTG-DEMO-0087/) (OWASP, kind: pass). The sample app runs five checks: `su` paths, `which su`, root-manager packages (declared in `<queries>`), `Build.TAGS`, and `ro.debuggable`/`ro.secure` via `getprop`. Abridged:

```kotlin
private fun checkForSuBinary(): Boolean {
    val paths = arrayOf("/system/app/Superuser.apk", "/sbin/su", "/system/bin/su",
        "/system/xbin/su", "/data/local/xbin/su", "/data/local/bin/su",
        "/system/sd/xbin/su", "/system/bin/failsafe/su", "/data/local/su", "/su/bin/su")
    return paths.any { File(it).exists() }
}

private fun checkForWhichSu(): Boolean = try {
    val p = Runtime.getRuntime().exec(arrayOf("which", "su"))
    p.inputStream.bufferedReader().readText().isNotBlank() && p.waitFor() == 0
} catch (t: Throwable) { false }

private fun checkForRootPackages(): Boolean =
    listOf("com.topjohnwu.magisk", "eu.chainfire.supersu" /* ... 12 in total */).any {
        try { context.packageManager.getPackageInfo(it, 0); true }
        catch (e: PackageManager.NameNotFoundException) { false }
    }

private fun checkForTestKeys(): Boolean = Build.TAGS?.contains("test-keys") == true

private fun checkForDangerousProps(): Boolean =
    getSystemProperty("ro.debuggable") == "1" || getSystemProperty("ro.secure") == "0"
    // getSystemProperty() runs Runtime.exec(arrayOf("getprop", key))
```

OWASP runs semgrep on the jadx output (`MastgTest_reversed.java`). Output from the demo, abridged:

```text
┌─────────────────┐
│ 5 Code Findings │
└─────────────────┘
    MastgTest_reversed.java
     ❱ rules.mastg-android-root-detection-file-checks
           63┆ boolean exists = new File(path).exists();
     ❱ rules.mastg-android-root-detection-runtime-exec
           83┆ Process process = Runtime.getRuntime().exec(new String[]{"which", "su"});
     ❱ rules.mastg-android-root-detection-package-check
          133┆ this.context.getPackageManager().getPackageInfo(packageName, 0);
     ❱ rules.mastg-android-root-detection-test-keys
          151┆ if (buildTags != null && StringsKt.contains$default((CharSequence) buildTags,
     ❱ rules.mastg-android-root-detection-system-properties
          180┆ Process process = Runtime.getRuntime().exec(new String[]{"getprop", key});
```

The test passes: five kinds of check are present. Our reading for the report: all five are Java, all feed one boolean (`isRooted`), and two of them are weak by construction. `ro.debuggable=1` is also true on almost every emulator and on `userdebug` builds, so it causes false positives for testers and developers, and the package list is only effective because the demo declares it in `<queries>`.

### MASTG-TEST-0325: Runtime Use of Root Detection Techniques (Android)

*OWASP test: [MASTG-TEST-0325](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0325/). Type: dynamic (hooks). Knowledge: MASTG-KNOW-0027. Best practices: MASTG-BEST-0029, MASTG-BEST-0030.*

#### Overview

The test confirms at run time that the app actually performs root checks: it hooks the APIs root detection uses (method hooking, [MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/)) and traces system calls ([MASTG-TECH-0032](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0032/)) while you exercise the app. It finds checks that static analysis missed (obfuscated, native, loaded at run time) and tells you *when* they run. The hooks here only **log** what the app does and pass every call through unchanged. Neutralising checks is GT-RES-0051-1.

Run it on the rooted device so the checks have something to find. It also works on a stock device, because the app still probes the same paths and properties there, it just gets negative answers.

#### Prerequisites

- Rooted test device or emulator with `frida-server` of the same version as your Frida client.
- The app installed ([MASTG-TECH-0005](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/)): `adb install-multiple base.apk split_config.*.apk`.
- The list of checks from MASTG-TEST-0324, to know which flows to exercise.

#### Steps

1. Start `frida-server` on the device and confirm the client sees it: `frida-ps -U | head`.

2. Spawn the app with a logging script. The one below traces the Java and native APIs root checks commonly use and prints a short Java stack for each hit, so you can map it back to the app's code. It never changes a return value.

   ```javascript
   // trace-root-checks.js: log only, every call is passed through unchanged
   const RX = /(^|\/)su$|superuser|busybox|magisk|kernelsu|apatch|xposed|lsposed|zygisk|\/data\/adb|test-keys|ro\.(debuggable|secure|build\.tags|boot\.)|selinux|\/proc\/self\/mount/i;
   function exp(name) {   // works with Frida 16 and 17
     return Module.findGlobalExportByName ? Module.findGlobalExportByName(name)
                                          : Module.findExportByName(null, name);
   }
   Java.perform(() => {
     const Log = Java.use('android.util.Log');
     const Exc = Java.use('java.lang.Exception');
     const where = () => Log.getStackTraceString(Exc.$new()).split('\n').slice(2, 5).join(' | ');

     const File = Java.use('java.io.File');
     File.exists.implementation = function () {
       const r = this.exists();
       const p = this.getAbsolutePath();
       if (RX.test(p)) console.log(`[File.exists] ${p} -> ${r}  @ ${where()}`);
       return r;
     };

     const APM = Java.use('android.app.ApplicationPackageManager');
     APM.getPackageInfo.overloads.forEach(o => {
       o.implementation = function () {
         console.log(`[getPackageInfo] ${arguments[0]}  @ ${where()}`);
         return o.apply(this, arguments);   // NameNotFoundException propagates as usual
       };
     });

     const RT = Java.use('java.lang.Runtime');
     RT.exec.overloads.forEach(o => {
       o.implementation = function () {
         const a = arguments[0];
         const cmd = (typeof a === 'string') ? a : Array.prototype.join.call(a, ' ');
         console.log(`[Runtime.exec] ${cmd}  @ ${where()}`);
         return o.apply(this, arguments);
       };
     });

     try {   // hidden API class, usually called via reflection
       const SP = Java.use('android.os.SystemProperties');
       SP.get.overloads.forEach(o => {
         o.implementation = function () {
           const r = o.apply(this, arguments);
           if (RX.test(arguments[0])) console.log(`[SystemProperties.get] ${arguments[0]} = ${r}`);
           return r;
         };
       });
     } catch (e) { console.log(`SystemProperties not hooked: ${e}`); }
   });

   ['access', 'faccessat', 'stat', 'lstat', 'fopen', 'openat', 'opendir'].forEach(fn => {
     const addr = exp(fn);
     if (!addr) return;
     const pathArg = (fn === 'faccessat' || fn === 'openat') ? 1 : 0;
     Interceptor.attach(addr, {
       onEnter(args) { this.p = args[pathArg].readCString(); },
       onLeave(ret) { if (this.p && RX.test(this.p)) console.log(`[${fn}] ${this.p} -> ${ret.toInt32()}`); }
     });
   });
   const gp = exp('__system_property_get');
   if (gp) Interceptor.attach(gp, {
     onEnter(args) { this.k = args[0].readCString(); this.v = args[1]; },
     onLeave() { if (RX.test(this.k)) console.log(`[__system_property_get] ${this.k} = ${this.v.readCString()}`); }
   });
   ```

   ```bash
   frida -U -f com.example.app -l trace-root-checks.js
   ```

   (Older Frida releases needed `--no-pause`, which some tutorials, including OWASP's MASTG-TECH-0043, still show. Current Frida releases resume a spawned app by default, offer `--pause` for the opposite, and no longer accept `--no-pause`.) For `opendir`, `ret.toInt32()` prints a truncated pointer, and zero means "not found".

   OWASP's demo uses Frooky instead, which takes a declarative JSON list of hooks and writes JSON lines with stack traces:

   ```bash
   frooky -U -f com.example.app --platform android hooks.json
   ```

   For a quick look without a script, `frida-trace` can trace Java methods with `-j` and native functions with `-i`:

   ```bash
   frida-trace -U -f com.example.app -j 'java.io.File!exists' -j 'android.app.ApplicationPackageManager!getPackageInfo' -j 'java.lang.Runtime!exec' -i 'faccessat' -i '__system_property_get'
   ```

3. Exercise the app: cold start, log in, open every screen that handles money or personal data, start a payment or transfer, background and resume, and log out. Many apps check again at sensitive operations, not only at start-up.

4. For checks that bypass libc with inline system calls, the libc hooks see nothing. Trace at the system-call level instead, with `strace` built for Android (it is not on devices by default, and it fails if the app uses ptrace-based anti-debugging):

   ```bash
   adb shell su -c 'strace -f -e trace=openat,faccessat,newfstatat,readlinkat,execve -p $(pidof com.example.app)' 2>&1 | grep -Ei 'su"|magisk|/data/adb|mount'
   ```

5. Watch logcat while you do this. Apps and SDKs are often chatty about their findings, which is a separate finding under [MASWE-0061](/mobile/maswe-0061-debug-artifacts-not-removed/):

   ```bash
   adb logcat --pid=$(adb shell pidof -s com.example.app) | grep -iE 'root|magisk|tamper|integrity'
   ```

#### Observation

The log of hooked calls with their arguments, return values and call sites; the moment in the app flow at which each check ran; system-call traces for native checks; and what the app did visibly (dialog, exit, feature disabled, nothing).

#### Evaluation

The test **fails** when no root detection activity is observed across the exercised flows, on the rooted device.

The test **passes** when root checks are observed. As with the static test, this proves presence, not robustness. Note checks that ran but cannot fire (package lookups returning `NameNotFoundException` for packages that are installed but invisible), and checks that ran only once at start-up.

Expect false negatives when checks use inline system calls (use `strace`), run in a process you did not attach to (an `android:process` service), are loaded dynamically after your hooks were placed, or are disabled by the app because it detected Frida itself (in which case the app's behaviour usually changes visibly, which is evidence of [MASWE-0065](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/) controls). Library code that calls the same APIs (for example `androidx.profileinstaller` creating `File` objects, or system components calling `getPackageInfo`) appears in traces too. Use the stack to separate it.

#### Demo

[MASTG-DEMO-0088](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0088/MASTG-DEMO-0088/) (OWASP) runs the app from MASTG-DEMO-0087 under Frooky with this hook file (abridged):

```json
{
  "category": "RESILIENCE",
  "hooks": [
    { "class": "java.io.File", "method": "$init",
      "overloads": [ { "args": ["java.lang.String"] } ],
      "filterEventsByStacktrace": ["org.owasp.mastestapp.MastgTest"] },
    { "class": "android.app.ApplicationPackageManager", "method": "getPackageInfo",
      "overloads": [ { "args": ["java.lang.String", "int"] } ],
      "filterEventsByStacktrace": ["org.owasp.mastestapp.MastgTest"] },
    { "class": "java.lang.Runtime", "method": "exec",
      "overloads": [ { "args": ["[Ljava.lang.String;"] } ] }
  ]
}
```

One event from OWASP's output, shortened:

```json
{"type": "hook", "class": "java.io.File", "method": "$init",
 "stackTrace": ["java.io.File.<init>(Native Method)",
                "org.owasp.mastestapp.MastgTest.checkForSuBinary(MastgTest.kt:61)", "..."],
 "inputParameters": [{"declaredType": "java.lang.String", "value": "/sbin/su"}]}
```

The output shows ten `File` constructors with `su` paths from `checkForSuBinary`, `Runtime.exec` with `which su` and with `getprop ro.debuggable` / `getprop ro.secure`, and twelve `getPackageInfo` calls that throw `NameNotFoundException` because none of the packages is installed. The test passes. Note that the demo hooks the `File` constructor, not `exists()`: it shows which paths the app builds, not which it actually tests. Our script above hooks `exists()` and also records the answer.

### MASTG-TEST-0240: Jailbreak Detection in Code (iOS)

*OWASP test: [MASTG-TEST-0240](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0240/). Type: static. Knowledge: MASTG-KNOW-0084. OWASP marks it false-negative prone.*

#### Overview

The test searches the app binary for jailbreak detection: jailbreak file paths, package-manager URL schemes, sandbox write probes, dyld and environment checks, and strings that name the logic. OWASP's techniques are exploring the app package ([MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/)) and static analysis with radare2 ([MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/)).

#### Prerequisites

- A **decrypted** IPA. App Store binaries are FairPlay-encrypted, and string searches on an encrypted binary find nothing. Check with `otool -l Payload/App.app/App | grep -A4 LC_ENCRYPTION_INFO`: `cryptid 1` means still encrypted.
- radare2, `strings`, `nm` or `otool` (Xcode command-line tools), `plutil`, optionally Ghidra.

#### Steps

1. Unpack and find the main binary, frameworks and extensions:

   ```bash
   unzip -q App.ipa -d ipa
   BIN=$(plutil -extract CFBundleExecutable raw ipa/Payload/*.app/Info.plist)
   ls ipa/Payload/*.app/Frameworks ipa/Payload/*.app/PlugIns 2>/dev/null
   ```

2. Search strings in the main binary and every framework. Cover both eras:

   ```bash
   for f in ipa/Payload/*.app/"$BIN" ipa/Payload/*.app/Frameworks/*.framework/*; do
     [ -f "$f" ] || continue
     strings -a "$f" | grep -Ei 'cydia|sileo|zebra|filza|installer\.app|/var/jb|procursus|substrate|substitute|libhooker|ellekit|tweakinject|frida|cycript|/bin/(ba)?sh|/etc/apt|/var/lib/(apt|cydia)|sshd|DYLD_INSERT|jailbr' | sed "s|^|$(basename "$f"): |"
   done | sort -u
   ```

3. Check imports for the APIs that checks use. In `nm -u` output C symbols carry a leading underscore, so `_dyld_get_image_name` appears as `__dyld_get_image_name`:

   ```bash
   nm -u ipa/Payload/*.app/"$BIN" | grep -E '^_(fork|stat|lstat|access|fopen|open|opendir|statfs|getfsstat|realpath|getenv|dlopen|sysctl)$|__dyld_(image_count|get_image_name|register_func_for_add_image)'
   ```

   Swift code that calls `FileManager.fileExists(atPath:)` does not import `stat`. Look for the selector `fileExistsAtPath:` in the Objective-C method names instead (`strings -a ... | grep fileExistsAtPath`).

4. Check `Info.plist` for declared query schemes. A `canOpenURL` check on a scheme not listed here can never fire:

   ```bash
   plutil -p ipa/Payload/*.app/Info.plist | grep -A20 LSApplicationQueriesSchemes
   ```

5. Run OWASP's r2 script, or the same searches interactively, to find cross-references from the strings to code:

   ```bash
   r2 -q -i jailbreak_detection.r2 -A ipa/Payload/*.app/"$BIN" > output.asm
   ```

   Interactively: `iz~+jail` lists strings containing "jail", `axt @ <address>` shows the code that references one, and `pdf @ <function>` disassembles the function. Symbols often give it away: `is~+jail` and `ic~+jail` list symbols and classes.

6. Identify detection libraries: IOSSecuritySuite (`IOSSecuritySuite`, `amIJailbroken`), React Native's jail-monkey (class `JailMonkey`, method `isJailBroken`), Flutter plugins, and commercial RASP SDKs, usually shipped as their own framework.

#### Observation

The list of jailbreak indicators with the functions that use them, the APIs imported, the declared query schemes, and any detection library with its version. For each check, note whether it targets rootful-era or rootless artefacts.

#### Evaluation

The test **fails** when no jailbreak detection is found in the binary or its frameworks.

The test **passes** when detection is present. Qualify it in the report:

- `canOpenURL` checks for schemes missing from `LSApplicationQueriesSchemes` are ineffective.
- Indicator lists without `/var/jb` or any rootless artefact will miss current jailbreaks.
- Write and `fork()` probes alone do not detect current jailbreaks that leave the sandbox in place.
- `DYLD_INSERT_LIBRARIES` checks are weak.

Obfuscated strings, checks built from fragments at run time, and native checks in third-party frameworks produce false negatives. Confirm with MASTG-TEST-0241.

#### Demo

[MASTG-DEMO-0021](https://mas.owasp.org/MASTG/demos/ios/MASVS-RESILIENCE/MASTG-DEMO-0021/MASTG-DEMO-0021/) (OWASP). The sample collects four kinds of evidence. Abridged:

```swift
static func collectJailbreakProof() -> String {
    var reasons = [String]()
    let jailbreakPaths = ["/Applications/Cydia.app", "/Applications/Sileo.app", "/Applications/Zebra.app",
                          "/Library/MobileSubstrate/MobileSubstrate.dylib", "/usr/sbin/sshd", "/bin/bash",
                          "/etc/apt", "/var/lib/cydia", "/private/var/lib/undecimus" /* ... 19 in total */]
    for path in jailbreakPaths where FileManager.default.fileExists(atPath: path) {
        reasons.append("Detected jailbreak file or directory at \(path)")
    }
    for scheme in ["cydia://", "sileo://", "zebra://", "filza://"] {
        if let url = URL(string: scheme), UIApplication.shared.canOpenURL(url) {
            reasons.append("Able to open suspicious URL scheme: \(scheme)")
        }
    }
    for v in ["DYLD_INSERT_LIBRARIES", "DYLD_FRAMEWORK_PATH", "DYLD_LIBRARY_PATH"]
        where ProcessInfo.processInfo.environment[v] != nil {
        reasons.append("Suspicious environment variable detected: \(v)")
    }
    for path in ["/private/jailbreak.txt", "/private/var/mobile/Library/jailbreak.txt"] {
        if (try? "test".write(toFile: path, atomically: true, encoding: .utf8)) != nil {
            reasons.append("Write access detected at \(path)")
        }
    }
    return reasons.joined(separator: "\n")
}
```

OWASP's r2 script searches the binary for each path, scheme and variable name, lists strings containing "jail", and follows the cross-reference to the function that builds the result. Output from the demo, abridged:

```text
search for jailbreak path:
0x10011d850 hit4_0 "4/Applications/Cydia.app/Applic"
0x10011d870 hit5_0 "dia.app/Applications/Sileo.app/Applic"
0x1001a0d68 hit7_0 "@/usr/sbin/sshd/usr/bin/ssh"
0x10011da20 hit16_0 "H/private/jailbreak.txt/priva"
search for urlSchemes:
0x1001a0e50 hit18_0 "cydia://sileo://"
search for suspiciousEnvVars:
0x10011d9c0 hit22_0 "DYLD_INSERT_LIBRARIESDYLD_"
xrefs to Jailbreak strings:
sym.func.100008c14 0x100008dc8 [STRN:-w-] add x9, x9, str.Jailbreak:_True_n_nProof:_n_n
```

The test passes. Read against the Knowledge section above, the sample is also a good example of detection that passes the static test and finds little on a current device: no path is under `/var/jb`, so on a rootless jailbreak only checks that happen to match would fire; the sample has no `Info.plist` declaring the four schemes, so `canOpenURL` always returns `false`; modern tweak injection does not need the `DYLD_*` variables; and the write probe fails wherever the jailbreak leaves the sandbox in place. We have not run the demo on a rootless device. This is our analysis of the code, and GT-RES-0051-1 is how you would confirm it on a real app.

### MASTG-TEST-0241: Runtime Use of Jailbreak Detection Techniques (iOS)

*OWASP test: [MASTG-TEST-0241](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0241/). Type: dynamic (hooks). Knowledge: MASTG-KNOW-0084. OWASP marks it false-negative prone.*

#### Overview

The test runs the app on a jailbroken device, observes which jailbreak checks it performs, and applies the automated bypass from OWASP's technique for bypassing jailbreak detection ([MASTG-TECH-0152](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0152/)): objection's `ios jailbreak disable`. The bypass output is itself evidence, because objection reports each check it intercepts. Unlike the Android pair, OWASP's iOS test includes the bypass attempt. We split the work: here you trace and run the standard command, and in GT-RES-0051-1 you measure how far beyond it an attacker has to go.

#### Prerequisites

- A jailbroken device (state rootful or rootless in the report) with Frida installed from its package manager, and a stock device for the baseline.
- The app installed ([MASTG-TECH-0056](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0056/)): from the App Store or TestFlight, or a development or ad-hoc build with `xcrun devicectl device install app --device <UDID> App.ipa` or `ideviceinstaller -i App.ipa`.
- The check list from MASTG-TEST-0240.

#### Steps

1. Baseline on the jailbroken device without Frida attached: launch, log in, open sensitive screens. Note what the app does.

2. Spawn the app with a logging script. It records file probes, URL scheme queries, writes outside the container, `fork`, environment lookups and the image names the app enumerates. It never changes a return value.

   ```javascript
   // trace-jb-checks.js: log only, every call is passed through unchanged
   const RX = /cydia|sileo|zebra|filza|installer|\/var\/jb|procursus|substrate|substitute|libhooker|ellekit|tweakinject|frida|cycript|\/bin\/(ba)?sh|\/etc\/apt|\/var\/lib\/(apt|cydia)|sshd|undecimus|jailbr/i;
   function exp(name) {   // works with Frida 16 and 17
     return Module.findGlobalExportByName ? Module.findGlobalExportByName(name)
                                          : Module.findExportByName(null, name);
   }
   const caller = ctx => Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, 3)
                               .map(a => DebugSymbol.fromAddress(a).toString()).join(' | ');

   Interceptor.attach(ObjC.classes.NSFileManager['- fileExistsAtPath:'].implementation, {
     onEnter(args) { this.p = new ObjC.Object(args[2]).toString(); this.c = caller(this.context); },
     onLeave(ret) { if (RX.test(this.p)) console.log(`[fileExistsAtPath:] ${this.p} -> ${ret.toInt32() & 1}  @ ${this.c}`); }
   });
   Interceptor.attach(ObjC.classes.UIApplication['- canOpenURL:'].implementation, {
     onEnter(args) { this.u = new ObjC.Object(args[2]).absoluteString().toString(); },
     onLeave(ret) { console.log(`[canOpenURL:] ${this.u} -> ${ret.toInt32() & 1}`); }
   });
   // Swift's String.write(toFile:) is bridged to this NSString method
   Interceptor.attach(ObjC.classes.NSString['- writeToFile:atomically:encoding:error:'].implementation, {
     onEnter(args) {
       const p = new ObjC.Object(args[2]).toString();
       if (!p.includes('/Containers/')) console.log(`[writeToFile:] ${p} (outside the app container)`);
     }
   });
   ['stat', 'lstat', 'access', 'open', 'fopen', 'opendir', 'statfs', 'realpath'].forEach(fn => {
     const a = exp(fn);
     if (a) Interceptor.attach(a, {
       onEnter(args) { this.p = args[0].readCString(); },
       onLeave(ret) { if (this.p && RX.test(this.p)) console.log(`[${fn}] ${this.p} -> ${ret}`); }
     });
   });
   const fk = exp('fork');
   if (fk) Interceptor.attach(fk, { onLeave(ret) { console.log(`[fork] -> ${ret.toInt32()}`); } });
   const ge = exp('getenv');
   if (ge) Interceptor.attach(ge, { onEnter(args) { const n = args[0].readCString(); if (/^DYLD_/.test(n)) console.log(`[getenv] ${n}`); } });
   const gin = exp('_dyld_get_image_name');
   if (gin) Interceptor.attach(gin, { onLeave(ret) { const n = ret.isNull() ? '' : ret.readCString(); if (RX.test(n)) console.log(`[_dyld_get_image_name] ${n}`); } });
   ```

   ```bash
   frida -U -f com.example.app -l trace-jb-checks.js
   ```

   `_dyld_get_image_name` hits also appear when Frida's own agent or the jailbreak's injection libraries are enumerated by system code, so check the backtrace before attributing them to the app. For a quick look without a script, `frida-trace` takes Objective-C methods with `-m` and C functions with `-i`:

   ```bash
   frida-trace -U -f com.example.app -m '-[NSFileManager fileExistsAtPath:]' -m '-[UIApplication canOpenURL:]' -i 'lstat' -i 'access'
   ```

3. Exercise the same flows as in step 1.

4. Run the standard automated bypass and repeat the flows. With objection 1.12 (the version OWASP's techniques show), global options come before the `start` command, and `--startup-command` runs the bypass before the app's own start-up code:

   ```bash
   objection -n com.example.app -s start --startup-command "ios jailbreak disable"
   ```

   With objection 1.11 and older the equivalent is `objection -g com.example.app explore --startup-command "ios jailbreak disable"`.

5. Watch the device log for the app's own messages and for refused scheme queries (`idevicesyslog` from libimobiledevice, or Console.app on a Mac): undeclared schemes appear as *"This app is not allowed to query for scheme ..."*.

#### Observation

The traced checks with their arguments, results and callers; the app's behaviour with and without objection; and objection's own report of the checks it intercepted.

#### Evaluation

The test **fails** when no jailbreak checks are observed on the jailbroken device.

The test **passes** when checks are observed. Record two further facts for the report, as they decide the rating: whether the checks find the device at all (on a rootless jailbreak, a list of rootful paths returns "not found" everywhere, which is detection that does not detect), and whether `ios jailbreak disable` alone was enough to make the app behave as on a stock device. Both feed into GT-RES-0051-1.

False negatives come from checks in native code that use inline system calls, checks in app extensions or other processes, checks that run only on specific flows, and apps that change behaviour once they notice Frida (that is [MASWE-0065](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/) territory).

#### Demo

OWASP has no demo for this test. Ours uses the MASTG-DEMO-0021 app. What `ios jailbreak disable` intercepts follows from objection's agent source (`agent/src/ios/jailbreak.ts`, version 1.12.5): it hooks `-[NSFileManager fileExistsAtPath:]` and `fopen()` for a fixed list of 33 rootful-era paths, `-[UIApplication canOpenURL:]` for URLs that start with `cydia`, `fork()` in `libSystem.B.dylib`, and `-[JailMonkey isJailBroken]` if that class exists. Matched against the demo's checks:

| Check in MASTG-DEMO-0021 | Neutralised by `ios jailbreak disable` 1.12.5? |
|---|---|
| `fileExistsAtPath:` for `/Applications/Cydia.app`, `/bin/bash`, `/bin/sh`, `/etc/apt`, `/usr/sbin/sshd`, `/usr/bin/ssh`, `/var/cache/apt`, `/var/lib/cydia`, `/var/log/syslog`, `/usr/libexec/ssh-keysign`, `/Library/MobileSubstrate/MobileSubstrate.dylib` | Yes, these paths are on objection's list |
| `fileExistsAtPath:` for `/Applications/Sileo.app`, `/Applications/Zebra.app`, `/Applications/Installer.app`, `/usr/libexec/cydia`, `/var/lib/apt`, `/private/var/lib/undecimus`, `/private/etc/apt` and the PreferenceLoader path | No |
| `canOpenURL:` for `cydia://` | Yes (but the demo cannot query it anyway without `LSApplicationQueriesSchemes`) |
| `canOpenURL:` for `sileo://`, `zebra://`, `filza://` | No |
| `DYLD_*` environment variables | No |
| Writes to `/private/...` | No |

Illustrative objection output on a rootful lab device (the wording follows objection's source, the paths are the demo's):

```text
com.example.app on (iPhone: 16.5) [usb] # ios jailbreak disable
(agent) Registering job 123456. Name: ios-jailbreak-disable
(agent) [123456] fileExistsAtPath: check for /Applications/Cydia.app was successful with: 0x1, marking it as failed.
(agent) [123456] fileExistsAtPath: check for /bin/sh was successful with: 0x1, marking it as failed.
```

On a rootful device, `/Applications/Sileo.app` would still be found. On a rootless device most of the demo's paths do not exist in the first place. Either way, the generic command alone does not tell you whether the app is protected: you need the trace from step 2 to see what the app checks, and GT-RES-0051-1 to see what it costs to silence the rest.

### GT-RES-0051-1: Effort needed to neutralise the app's own checks (Android, iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

The OWASP tests stop at "detection is present". This test measures what R-profile clients care about: how much effort it takes to make the app behave on a rooted or jailbroken device as it does on a stock one. It restores the effectiveness assessment of the legacy tests [MASTG-TEST-0045](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0045/) and [MASTG-TEST-0088](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0088/): Are checks scattered or central? Do they operate on several API layers? Can standard tools defeat them? Is custom code needed? How long did it take? The test only neutralises **the app's own checks** on your own test device, with public techniques, and stops at an agreed time box.

#### Prerequisites

- The check inventory from the static and dynamic tests above.
- The lab devices described in [Before you start](#before-you-start-the-lab-you-need), on current rooting and jailbreak tools.
- A time box agreed with the client (we use half a day to one day for a standard R-profile assessment) and a clear target behaviour ("reach the transfer confirmation screen", "the app does not exit").

#### Steps

1. **Level 0, no tools.** Launch the app on the rooted or jailbroken device with nothing attached and no hiding enabled. Does the app detect the device? If it does not, stop here: the detection does not work on a current device. If your lab uses a root solution's built-in per-app hiding, record a second run with it enabled for the app, and note the result without changing anything else.

2. **Level 1, generic bypass.** Spawn the app with objection's standard command:

   ```bash
   objection -n com.example.app -s start --startup-command "android root disable"
   objection -n com.example.app -s start --startup-command "ios jailbreak disable"
   ```

   On Android, objection 1.12.5 hooks `File.exists()` for 13 classic `su`/SuperSU paths, the single-string overload of `Runtime.exec` for commands ending in `su`, `String.contains("test-keys")`, and RootBeer's main methods (`agent/src/android/root.ts`). It does not hook `getPackageInfo`, the `String[]` overloads of `exec`, property reads or anything native. Record which of the app's checks remain.

3. **Level 2, one targeted hook.** Using the inventory, find the app's own decision point (the method whose result the response depends on) and force its return value with a short Frida script. Android, for a Java/Kotlin method:

   ```javascript
   // neutralise-own-check.js: changes the return value of the app's own detection method
   Java.perform(() => {
     const C = Java.use('com.example.app.security.EnvGuard');   // from jadx, often obfuscated (e.g. "a.b.c")
     C.isCompromised.implementation = function () {
       console.log('[EnvGuard.isCompromised] forced false');
       return false;
     };
   });
   ```

   For a JNI function the app exports, the same idea at native level (find the name with `readelf --dyn-syms -W libfoo.so | grep Java_`):

   ```javascript
   const lib = Process.getModuleByName('libenvguard.so');
   Interceptor.attach(lib.getExportByName('Java_com_example_app_security_EnvGuard_nativeCheck'), {
     onLeave(ret) { ret.replace(ptr(0)); }   // jboolean false
   });
   ```

   iOS, following MASTG-TECH-0152: trace the app's own method with `frida-trace` and edit the generated handler to replace the return value:

   ```bash
   frida-trace -U -f com.example.app -m '-[EnvGuard isCompromised]'
   ```

   ```javascript
   // handler generated by frida-trace under __handlers__/ (exact path depends on the Frida version), onLeave edited
   onLeave(log, retval, state) {
     log(`-[EnvGuard isCompromised] returned ${retval}, forcing 0`);
     retval.replace(ptr(0));
   }
   ```

   For a Swift method, find the mangled symbol with `nm` or r2 and attach to that address the same way. If one hook makes the app behave as on a stock device, the checks are central: record that and stop.

4. **Level 3, multiple layers.** If checks remain, list them: native checks, inline system calls, checks in several places, checks that compare APIs, integrity checks that notice the hooks or a patched binary, Frida detection. Work through them until the target behaviour is reached or the time box runs out. Do not write tooling beyond hooks on the app's own functions. Where the app detects Frida itself, record it and refer to [MASWE-0065](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/). Do not attempt to make server-verified attestation (Play Integrity, App Attest) pass: that is out of scope, and GT-RES-0051-2 covers what the server does.

5. **Record the effort** in a table: level reached, tools used, lines of custom code, hours spent, which checks were defeated at each level, and which, if any, were never defeated.

#### Observation

The effort table, the scripts used (attach them to the report as evidence), screen recordings of the target behaviour before and after, and the list of check locations with the level at which each fell.

#### Evaluation

For an app in the **R** profile:

- **Fail:** the app does not detect the current rooted or jailbroken lab device at level 0; or objection's generic command (level 1) neutralises every check.
- **Weak (fail with lower rating):** a single targeted hook on one Java/Swift method (level 2) neutralises every check, or a single patched branch does.
- **Pass:** neutralising the checks needs level 3, meaning several checks in more than one layer (managed and native) and in more than one place, with at least some custom work beyond a single hook. Note how long it took. A pass here does not mean "unbreakable", only that the cost is proportionate to the threat model.

For apps outside the R profile, record the result as information.

#### Demo

*Ours, against the OWASP sample from MASTG-DEMO-0087.* Each of the sample's five checks is a private method returning a boolean, and `mastgTest()` combines them with `||`. Forcing all five takes one short script:

```javascript
Java.perform(() => {
  const T = Java.use('org.owasp.mastestapp.MastgTest');
  ['checkForSuBinary', 'checkForWhichSu', 'checkForRootPackages', 'checkForTestKeys', 'checkForDangerousProps']
    .forEach(m => { T[m].implementation = function () { console.log(`${m} -> false`); return false; }; });
});
```

Effort record (illustrative, for the sample app):

| Level | Tool | Custom code | Checks defeated | Remaining |
|---|---|---|---|---|
| 1 | `android root disable` (objection 1.12.5) | none | nine of the ten `su` paths (not `/su/bin/su`) | `which su` and `getprop` (the `String[]` overload of `exec`), package lookups, `test-keys` (Kotlin compiles `contains` to `StringsKt.contains$default`, which we expect not to reach `java.lang.String.contains`) |
| 2 | Frida, five method hooks in one class | 5 lines | all | none |

Result for an R-profile app built like this: **weak**. Every check is Java, in one class, with readable names, feeding one boolean.

### GT-RES-0051-2: Detection response and server-side enforcement (Android, iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

Detection only matters through what follows it. This test checks what the app does when it detects root or jailbreak, whether the backend learns about it, and whether the backend's decision survives a client whose checks have been neutralised (GT-RES-0051-1). It is the test that separates a cosmetic control from one that changes attacker cost for the actions that matter.

#### Prerequisites

- Stock and rooted/jailbroken lab devices, the neutralising scripts from GT-RES-0051-1, an intercepting proxy with the app's pinning handled (see [MASWE-0028](/mobile/maswe-0028-insecure-identity-pinning/) and the [lab note](/mobile/mobile-traffic-interception-lab/)).
- Test accounts, and the client's list of high-risk actions (login, payee creation, payment, card display, key provisioning, account recovery).

#### Steps

1. **Record the reference traffic.** On the stock device, perform each high-risk action and save the requests.

2. **Record the rooted/jailbroken traffic** (detection active, nothing neutralised). Diff against step 1. Look for: an environment field in request bodies or headers, calls to a RASP vendor's telemetry endpoint, a Play Integrity token or App Attest assertion, or a different flow (step-up challenge, refusal).

3. **Observe the client response.** Note what the user sees and what is restricted. Look for these problems:
   - the app exits or crashes immediately at the point of detection (easy to locate: `System.exit`, `Process.killProcess`, `finishAffinity`, `exit()`, `abort()` near the check);
   - the message names the indicator ("`/system/xbin/su` found"), or the reason is logged;
   - the block applies only to the UI, while the same action is reachable through a deep link, widget, notification action, App Intent or background sync.

4. **Neutralise the client checks** with the scripts from GT-RES-0051-1 and repeat the high-risk actions. Does the backend still refuse, challenge or flag them? If the app sends an attestation token, does the server still act on the device's verdict? You observe the server's behaviour only. Do not forge, replay across devices or otherwise tamper with attestation tokens.

5. **Tamper with the reported signal.** If the app reports its findings in a plain field (for example `"rooted": true` or a risk score), change or remove it in the proxy and repeat the action. A server that relaxes its decision based on an unauthenticated client claim is a finding in its own right. If the field is covered by a Play Integrity `requestHash` or an App Attest `clientDataHash`, the tampered request should be rejected.

6. **Check telemetry handling** with the client, if in scope: do detections reach a fraud or risk team, and are accounts that repeatedly report a compromised environment reviewed?

#### Observation

The diffed requests, screenshots or recordings of the client response, the server responses to the high-risk actions with and without neutralised checks, the result of tampering with the reported signal, and a list of alternative entry points tested.

#### Evaluation

- **Fail:** the decision for high-risk actions is made only on the client, so that after GT-RES-0051-1 the backend accepts the actions as on a stock device; or the server accepts a tampered environment signal; or the block is bypassable through another entry point in the app.
- **Weak:** the response is an immediate exit or crash at the detection site, or the message or logs disclose which indicator fired, while the server-side decision is sound.
- **Pass:** the backend receives the signal bound to the request (with attestation where the platform offers it), applies a proportionate policy to high-risk actions, and keeps doing so when the client's checks are neutralised; the client response is graded and does not reveal its checks.

#### Demo

*Ours, illustrative.* A request body that binds the client's environment findings to a payment, with a Play Integrity standard token whose `requestHash` is the SHA-256 of this exact body:

```json
{
  "action": "payment.submit",
  "amount": { "value": "250.00", "currency": "GBP" },
  "payee": "payee-7f3c",
  "environment": { "signals": ["su_path", "mount_overlay"], "checksVersion": 14 },
  "challenge": "c-01J9Z6K2Q8"
}
```

Server responses we would accept as a pass, depending on the verdict: `202` with `"stepUp": "biometric+otp"` when the local signals fire but the device still meets device integrity; `403` with a generic *"This action isn't available on this device"* when it does not. A server that returns `200` for the same body with `"signals": []` and a token from another request fails step 5.

## Best practices

### Implementing Resilience and RASP Signals (MASTG-BEST-0029)

Source: [MASTG-BEST-0029](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0029/). OWASP marks this page as a placeholder. Its one-paragraph note says what the whole series says: resilience and RASP checks are defence in depth that raise attacker cost by detecting risky environments and runtime tampering. They do not replace secure design, they are inherently bypassable, and they should be chosen and tuned to the app's threat model and risk tolerance. Our [series hub](/mobile/masvs-resilience-resilience-testing-guide/) expands it into a cross-cutting practice. For root and jailbreak detection it means: treat each check as a *signal*, send signals to the server, decide there, and measure the cost of bypass rather than the number of checks.

### Implementing Root Detection (MASTG-BEST-0030)

Source: [MASTG-BEST-0030](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0030/). OWASP frames root detection as an environment risk signal, a cost-raising and bypassable measure, worth adding only when rooted-device risk materially affects the app. Its seven practices, with what they mean in implementation (they apply equally to jailbreak detection):

1. **Layer defences.** Pair root signals with integrity checks ([MASWE-0057](/mobile/maswe-0057-app-resources-integrity-not-verified/), [MASWE-0058](/mobile/maswe-0058-runtime-code-integrity-not-verified/)), anti-debugging ([MASWE-0064](/mobile/maswe-0064-debugger-detection-not-implemented/)), instrumentation detection ([MASWE-0065](/mobile/maswe-0065-dynamic-analysis-tools-detection-not-implemented/)) and backend enforcement. Each makes the others harder to remove.
2. **Distribute checks.** Run checks at session establishment and next to each sensitive operation, from different classes and libraries. Avoid a single `isRooted()` gate whose return value decides everything.
3. **Use multiple methods.** File artefacts, properties and verified-boot state, mounts of your own process, injected images, package checks where visible, and native checks with direct system calls. Compare the answers of different APIs.
4. **Do not rely only on well-known patterns.** Public indicator lists and library defaults are exactly what public bypass scripts target. Use them, but add your own.
5. **Respond in proportion.** Restrict high-risk operations first, add step-up authentication ([MASWE-0023](/mobile/maswe-0023-step-up-authentication-not-implemented/)), and avoid full lockout when confidence is low.
6. **Validate on the server.** Let server policy decide whether a transaction proceeds, based on the signals, attestation verdicts and user context.
7. **Rotate and randomise.** Vary which checks run per session and per release, and change indicators, so a bypass script written for one release does not work on the next.

OWASP's caveats are worth repeating to clients. Root detection is bypassable through hooking, patching and hiding ([MASTG-TECH-0144](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0144/)). It flags legitimate users too (custom ROMs, enterprise test devices, security researchers), and aggressive blocking pushes users towards modified builds and raises support costs.

### What a good response looks like

A response strategy matches the strength of the evidence to the cost of the action:

| Evidence | Low-risk actions (browse, read) | High-risk actions (pay, add payee, change credentials, export keys) |
|---|---|---|
| No signals, attestation passes | Allow | Allow |
| Weak local signals only (test-keys, `ro.debuggable=1`, unlocked bootloader) | Allow, report to server | Step-up authentication, lower limits |
| Strong local signals (`su`, injected hooking libraries, `/var/jb`, sandbox not enforced) | Allow with warning, report | Refuse or require out-of-band confirmation; review the account |
| Attestation fails or is missing where expected | Allow read-only, report | Refuse |

Principles behind the table:

- **The server decides.** The client gathers signals and sends them, bound to the request so they cannot be swapped. On Android, put a hash of the request body (including the signals) into the Play Integrity standard request's `requestHash`. On iOS, put it into the App Attest assertion's `clientDataHash`.
- **Degrade, do not crash.** Disabling specific features is harder to locate and patch than a call to `exit()`, does not punish custom-ROM users for reading their balance, and keeps the session alive so the server can see what the device does next.
- **Respond away from the check.** Let detection set state and let the consequences appear elsewhere and later (on the next sensitive action, on the server). A dialog in the same method as the check marks it for the attacker.
- **Say little.** A generic message ("This feature isn't available on this device") and no indicator names in logs.
- **Keep the data.** Detection events are fraud telemetry. Counting them per account and per device is often more valuable than any single block.

A sketch of the Android side (imports and error handling omitted), using the Play Integrity standard API (`IntegrityManagerFactory.createStandard`, a token provider prepared in advance, and `requestHash`). `EnvironmentChecks` stands for your own Kotlin and JNI checks:

```kotlin
// Once, early (e.g. at app start): warm up a token provider.
val provider = IntegrityManagerFactory.createStandard(context)
    .prepareIntegrityToken(
        PrepareIntegrityTokenRequest.builder().setCloudProjectNumber(CLOUD_PROJECT_NUMBER).build()
    ).await()

suspend fun submitPayment(p: Payment): ApiResult {
    val env = EnvironmentChecks.collect()                  // run now, next to the sensitive action
    val body = Json.encodeToString(PaymentRequest(p, env, api.challenge()))
    val token = provider.request(
        StandardIntegrityTokenRequest.builder()
            .setRequestHash(sha256Base64(body))            // binds the verdict to this exact body
            .build()
    ).await().token()
    return api.postPayment(body, integrityToken = token)   // allow, step up or refuse: the server decides
}
```

And the iOS side, with App Attest (`DCAppAttestService.generateAssertion(_:clientDataHash:)`) protecting the body that carries the jailbreak signals:

```swift
func submitPayment(_ p: Payment, keyId: String) async throws -> PaymentResult {
    let env = EnvironmentChecks.collect()                  // jailbreak signals, gathered now
    let body = try JSONEncoder().encode(PaymentRequest(payment: p, environment: env,
                                                       challenge: try await api.challenge()))
    let clientDataHash = Data(SHA256.hash(data: body))     // CryptoKit
    let assertion = try await DCAppAttestService.shared.generateAssertion(keyId, clientDataHash: clientDataHash)
    return try await api.postPayment(body: body, assertion: assertion)
}
```

Server-side verification of both (decrypting and checking the Play Integrity token, validating the App Attest assertion and counter) is covered in [MASWE-0054](/mobile/maswe-0054-device-attestation-not-implemented/) and [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/).

## Rating findings

Rate in two steps. First, **profile**: does the client's threat model include R (an attacker who controls the device)? Second, **what the gap unlocks**: what can an attacker do on a rooted or jailbroken device that the app's controls were supposed to prevent, and does the backend still stand in the way?

Series-wide rules, adapted to this weakness:

- **Not R-profile:** a missing or weak root/jailbreak detection is **Info**. Say so in one line, and do not inflate it.
- **R-profile, control missing:** usually **Low–Medium**. Medium when the app handles money, identity or licensed content and nothing else (no attestation, no server-side risk decision) compensates.
- **R-profile, control present but trivially bypassed** (objection's generic command, one hook, a renamed binary): rate by what the bypass unlocks, normally the same as "missing".
- **Medium–High** only when the gap directly enables a concrete business abuse that you can describe, for example a payment or account-creation API with no device or app attestation that the client knows bots are abusing from rooted devices, or a licensing or DRM decision made only on the client.
- **Not this weakness:** debug mechanisms left on in release builds (`android:debuggable`, `get-task-allow`, WebView debugging) are real vulnerabilities regardless of profile. Rate them under [MASWE-0063](/mobile/maswe-0063-debug-mechanisms-not-disabled/). Sensitive data readable on a rooted device because it is stored in plain text is a storage finding ([STORAGE guide](/mobile/masvs-storage-1-secure-storage-guide/)), not a root-detection one.

| Rating | Conditions |
|---|---|
| **High** | R-profile app; high-risk actions (payments, account creation, credential changes) are decided only on the client; GT-RES-0051-2 shows the backend accepts them after the checks are neutralised or after a tampered signal; and there is a concrete abuse case (fraud, bot account creation, licence bypass) that the client confirms is in scope. |
| **Medium** | R-profile app with no root/jailbreak detection and no compensating server-side attestation or risk decision; or detection that does not fire on a current lab device (level 0 in GT-RES-0051-1); or detection neutralised by objection's generic command, where the server makes no independent decision. |
| **Low** | R-profile app whose detection falls to a single targeted hook (level 2), but whose backend still applies attestation or risk policy to high-risk actions; detection whose response is an immediate exit or a message naming the indicator; package checks dead on Android 11+ for lack of `<queries>`, `canOpenURL` checks dead for lack of `LSApplicationQueriesSchemes`, process checks dead since Android 7/8, where other checks remain. |
| **Info** | Apps outside the R profile; R-profile apps where detection needs level 3 effort and the server decides (record the effort as a positive observation); recommendations such as adding rootless indicators or moving checks to native code. |

In the report, give the platform, OS and rooting or jailbreak tool versions of the lab device, the check inventory with locations, the effort table from GT-RES-0051-1, the request and response evidence from GT-RES-0051-2, and the business action the gap exposes. Recommend layered checks, a graded response, and a server-side decision backed by attestation, not "add root detection".

## References

- OWASP MASWE: [MASWE-0051: Root/Jailbreak Detection Not Implemented](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0051/); related [MASWE-0054](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0054/), [MASWE-0058](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0058/), [MASWE-0065](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0065/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-RESILIENCE-1](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-1/), [MASVS-RESILIENCE-4](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-4/) (CC BY-SA 4.0)
- OWASP MASTG knowledge: [MASTG-KNOW-0027](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0027/), [MASTG-KNOW-0084](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0084/) (CC BY-SA 4.0)
- OWASP MASTG tests: [MASTG-TEST-0324](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0324/), [MASTG-TEST-0325](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0325/), [MASTG-TEST-0240](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0240/), [MASTG-TEST-0241](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0241/); legacy [MASTG-TEST-0045](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0045/), [MASTG-TEST-0088](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0088/) (CC BY-SA 4.0)
- OWASP MASTG demos: [MASTG-DEMO-0087](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0087/MASTG-DEMO-0087/), [MASTG-DEMO-0088](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0088/MASTG-DEMO-0088/), [MASTG-DEMO-0021](https://mas.owasp.org/MASTG/demos/ios/MASVS-RESILIENCE/MASTG-DEMO-0021/MASTG-DEMO-0021/) (CC BY-SA 4.0)
- OWASP MASTG best practices: [MASTG-BEST-0029](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0029/), [MASTG-BEST-0030](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0030/) (CC BY-SA 4.0)
- OWASP MASTG techniques: [MASTG-TECH-0005](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/), [MASTG-TECH-0013](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/), [MASTG-TECH-0014](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/), [MASTG-TECH-0032](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0032/), [MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/), [MASTG-TECH-0144](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0144/), [MASTG-TECH-0056](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0056/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0066](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0066/), [MASTG-TECH-0152](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0152/) (CC BY-SA 4.0)
- OWASP MASTG tools: [semgrep (MASTG-TOOL-0110)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/), [Frooky (MASTG-TOOL-0145)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0145/), [Frida (MASTG-TOOL-0031)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0031/), [objection (MASTG-TOOL-0038)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0038/), [objection for Android (MASTG-TOOL-0029)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0029/), [radare2 for iOS (MASTG-TOOL-0073)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/), [Magisk (MASTG-TOOL-0021)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0021/), [RootBeer (MASTG-TOOL-0146)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0146/), [Android RASP (MASTG-TOOL-0147)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0147/), [Cydia (MASTG-TOOL-0047)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0047/) (CC BY-SA 4.0)
- OWASP MASTG rule: `rules/mastg-android-root-detection.yaml` in the [MASTG repository](https://github.com/OWASP/mastg) (CC BY-SA 4.0)
- Android: [Package visibility filtering](https://developer.android.com/training/package-visibility), [Play Integrity verdicts](https://developer.android.com/google/play/integrity/verdicts), [Play Integrity standard requests](https://developer.android.com/google/play/integrity/standard), [Verified Boot boot flow](https://source.android.com/docs/security/features/verifiedboot/boot-flow), [Signing builds for release](https://source.android.com/docs/core/ota/sign_builds), [SELinux in Android](https://source.android.com/docs/security/features/selinux), [`ActivityManager.getRunningServices`](https://developer.android.com/reference/android/app/ActivityManager#getRunningServices%28int%29)
- Google Play policy: [Use of the broad package (app) visibility (QUERY_ALL_PACKAGES) permission](https://support.google.com/googleplay/android-developer/answer/10158779)
- Apple: [`canOpenURL(_:)`](https://developer.apple.com/documentation/uikit/uiapplication/canopenurl%28_:%29), [Establishing your app's integrity (App Attest)](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity), [`DCAppAttestService`](https://developer.apple.com/documentation/devicecheck/dcappattestservice), [Apple Platform Security: signed system volume security](https://support.apple.com/guide/security/signed-system-volume-security-secd698747c9/web)
- Tools: [objection](https://github.com/sensepost/objection) (agent sources `agent/src/android/root.ts` and `agent/src/ios/jailbreak.ts`, read at version 1.12.5), [Frida JavaScript API](https://frida.re/docs/javascript-api/), [Frooky](https://github.com/cpholguera/frooky)
- Background: The Apple Wiki on [rootless jailbreaks](https://theapplewiki.com/wiki/Rootless) and [Dopamine](https://theapplewiki.com/wiki/Dopamine); Dana Geist and Marat Nigmatullin, [Jailbreak/Root Detection Evasion Study on iOS and Android](https://web.archive.org/web/20230828210244/https://github.com/crazykid95/Backup-Mobile-Security-Report/blob/master/Jailbreak-Root-Detection-Evasion-Study-on-iOS-and-Android.pdf) (cited by OWASP)
- CWE: [CWE-1326](https://cwe.mitre.org/data/definitions/1326.html) (OWASP's mapping), [CWE-693](https://cwe.mitre.org/data/definitions/693.html) (our suggested alternative)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
