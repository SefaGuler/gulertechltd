---
title: "MASWE-0060: Resource Obfuscation Not Implemented"
date: 2026-11-10 20:09:00 +0000
subcategory: resilience
summary: "What APK and IPA resources reveal, what AAPT2 and asset catalogs really hide, and how to test encrypted assets by finding the key and decryption point."
refs: [MASWE-0060, MASVS-RESILIENCE-3, CWE-693]
tags: [android, ios, masvs-resilience, obfuscation, resources, assets]
---

This note is part of our [MASVS-RESILIENCE guide](/mobile/masvs-resilience-resilience-testing-guide/) and covers OWASP [MASWE-0060](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0060/): resources and assets shipped in a form that tells a reverse engineer how the app works. Code obfuscation ([MASWE-0059](/mobile/maswe-0059-code-obfuscation-not-implemented/)) gets all the attention, but the first thing most analysts open is not the code. It is `strings.xml`, the layouts, the JSON in `assets/`, the `Info.plist` and the JavaScript bundle, because they name features, screens, endpoints, feature flags and the exact wording of the "rooted device" dialog, and each of those leads straight back into the code. This note explains what leaks from resources on each platform, what the platform tools (resource shrinking, AAPT2 path shortening and name collapsing, asset catalogs, Hermes) really hide, why encrypting assets mostly moves the problem to wherever the key lives, and three tests of our own. One rule to keep in mind: a secret in a resource is a [MASWE-0004](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/) finding, and no amount of resource obfuscation fixes it.

## Contents

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Background](#background)
  - [Android: what an APK's resources reveal](#android-what-an-apks-resources-reveal)
  - [Android: resource shrinking](#android-resource-shrinking)
  - [Android: resource path shortening and name collapsing (AAPT2)](#android-resource-path-shortening-and-name-collapsing-aapt2)
  - [Android and iOS: asset encryption and where the key lives](#android-and-ios-asset-encryption-and-where-the-key-lives)
  - [iOS: what the app bundle reveals](#ios-what-the-app-bundle-reveals)
  - [iOS: asset catalogs and Core ML models](#ios-asset-catalogs-and-core-ml-models)
  - [Cross-platform: JavaScript bundles, Hermes and Flutter assets](#cross-platform-javascript-bundles-hermes-and-flutter-assets)
- [Tests](#tests)
  - [GT-RES-0060-1: Resource and asset review (Android)](#gt-res-0060-1-resource-and-asset-review-android)
  - [GT-RES-0060-2: Bundle resource review (iOS)](#gt-res-0060-2-bundle-resource-review-ios)
  - [GT-RES-0060-3: Encrypted assets: key location and decryption point (Android, iOS)](#gt-res-0060-3-encrypted-assets-key-location-and-decryption-point-android-ios)
- [Secure implementation](#secure-implementation)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

OWASP states the requirement as *"The app applies resource obfuscation to hinder reverse engineering."* MASWE-0060 maps to **MASVS-RESILIENCE-3** (*"The app implements anti-static analysis mechanisms"*), to MSTG-RESILIENCE-11 in MASVS v1, and to [CWE-693](https://cwe.mitre.org/data/definitions/693.html). Like every RESILIENCE weakness it carries the **R** profile (and EUDIW): it matters for apps whose threat model includes reverse engineering and tampering on a device the attacker controls. For other apps, what you find here is Info, unless it is really a secret, which makes it a STORAGE finding.

> **Note:** OWASP has **no tests and no Knowledge pages** for MASWE-0060, and no legacy v1 test is replaced by it. The `## Background` section below is ours, and the three tests are Guler Tech methodology, numbered GT-RES-0060-1 to GT-RES-0060-3. MASTG-KNOW-0033 and MASTG-KNOW-0089 (covered in our [MASWE-0059 note](/mobile/maswe-0059-code-obfuscation-not-implemented/)) each have a short section on resource and asset encryption, which we build on here.

OWASP's description makes two points worth keeping. First, resources "contain information about the app's inner workings" that attackers use to map features, find security-relevant configuration and pick tampering targets. Second, obfuscation or encryption of resources *without integrity validation* can itself be tampered with, so resource protection complements the integrity checks of [MASWE-0057](/mobile/maswe-0057-app-resources-integrity-not-verified/) rather than replacing them.

Be realistic about what this control can achieve. A large part of an app's resources must stay readable to the operating system: the manifest, the launcher icon and label, `network_security_config.xml`, FileProvider paths, `Info.plist`, entitlements, storyboards and nibs that UIKit loads, localisation files the framework reads. User-visible text is, by definition, visible to the user. What resource obfuscation can do is remove *meaningful identifiers* (so that `R.string.root_detected_title` becomes a number), keep *non-user-facing* configuration, rules, models and scripts out of plain view, and stop the package from shipping things that should never have been there.

Keep the neighbouring topics apart:

| Question | Where it lives |
|---|---|
| Do resources, assets and bundle files reveal how the app works? | This note (MASWE-0060) |
| Are there secrets (API keys, credentials, private keys) in resources or assets? | [MASWE-0004](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/), which also covers APK and IPA anatomy in depth |
| Can resources be modified and the app still runs with them? | [MASWE-0057](/mobile/maswe-0057-app-resources-integrity-not-verified/) |
| Does the code reveal how the app works? | [MASWE-0059](/mobile/maswe-0059-code-obfuscation-not-implemented/) |
| Are source maps, `mapping.txt`, debug Flutter artefacts or test data shipped? | [MASWE-0061](/mobile/maswe-0061-debug-artifacts-not-removed/), with the obfuscation angle here |
| Is network payload content readable? | [MASWE-0062](/mobile/maswe-0062-no-application-level-payload-encryption/) |

## Modes of Introduction

**Descriptive resource names.** `R.string.jailbreak_detected_message`, `@layout/activity_admin_debug_menu`, `@id/btn_skip_root_check`, `@bool/enable_certificate_pinning`. Names are kept in `resources.arsc` by default on Android and in nib, storyboard and asset catalog files on iOS, and they map one-to-one to features and controls.

**Configuration and rules in clear.** `assets/config.json` with environment URLs and feature flags (`"enforceIntegrity": true`), `res/raw/rules.yaml` with fraud thresholds, a `Settings.plist` with debug switches, remote-config defaults (`remote_config_defaults.xml`) that list every flag the backend can flip.

**Logic shipped as data.** Hybrid apps carry their entire UI and business logic as HTML and JavaScript in `assets/www/` or `public/`. React Native ships one JavaScript or Hermes bundle. Flutter assets, Lua or other scripting payloads in games, and rules engines all put logic where code obfuscators do not look.

**Valuable content in clear.** On-device ML models (`.tflite`, `.mlmodelc`), proprietary datasets, licensed fonts and media, offline maps, pre-populated SQLite databases.

**Build leftovers.** Source maps (`*.js.map`), unused debug layouts and screens that resource shrinking was never enabled to remove, sample data, test certificates, `README` and `.DS_Store` files, Flutter debug artefacts in a release bundle.

**Encryption with the key next to the lock.** Assets encrypted with a key in `BuildConfig`, a string resource or a native library in the same package, decrypted to a cache file on first use.

## Impact

- **Bypass of protection mechanisms.** The text of the warning dialog, the name of the layout that shows it and the flag that enables it give an analyst cross-references straight into the security-relevant code. A readable configuration file may also show which checks can be switched off, and without integrity validation ([MASWE-0057](/mobile/maswe-0057-app-resources-integrity-not-verified/)) a repackaged app can switch them off.
- **Feature and attack-surface mapping.** Hidden admin or debug screens, internal and staging endpoints, unreleased features behind flags, deep-link routes and WebView URLs show where to look for real vulnerabilities.
- **Intellectual property exposure.** ML models, datasets, game assets and proprietary content can be extracted and reused; a stolen model can also be probed offline to find inputs that evade it (relevant for liveness, fraud or anti-cheat models).
- **Compromise of sensitive data.** When resources contain credentials or keys, the impact is that of [MASWE-0004](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/).

## Mitigations

- **Do not ship what you do not need**: enable resource shrinking, keep debug screens and test data in debug source sets, strip source maps and build outputs from release packages.
- **Do not put secrets in resources**: move them to the server or to per-device, hardware-backed keys ([MASWE-0004](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/)).
- **Use non-descriptive identifiers** for resources tied to security controls, and collapse resource names in release builds where the app does not look resources up by name.
- **Keep security-relevant configuration and logic out of the package**, or deliver it from the server after attestation; where it must ship, encrypt it with a key that is not trivially recoverable from the same package and decrypt it in memory only.
- **Verify integrity** of every resource and asset that influences security behaviour ([MASWE-0057](/mobile/maswe-0057-app-resources-integrity-not-verified/)), and use authenticated encryption so that encrypted assets cannot be swapped or modified unnoticed.
- **Use generic user-facing messages** for security events ("This action is not available on this device") rather than naming the check that fired.

## Background

### Android: what an APK's resources reveal

An APK has four places where non-code content lives, and apktool ([MASTG-TOOL-0011](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/)) turns all of them back into near-source form:

| Location | Format in the APK | What it typically reveals |
|---|---|---|
| `resources.arsc` | Compiled resource table: every resource's type, **name** and ID, plus the values of `values/` resources (strings, booleans, integers, arrays, dimensions, colours) for every configuration | Feature names, user-facing messages (including security warnings), flags in `bools.xml`, API base URLs in strings, Firebase and Maps configuration generated from `google-services.json` |
| `res/` | Compiled binary XML (layouts, menus, `xml/`), images, `raw/` files as-is | Screens and their widgets (including hidden debug screens), `network_security_config.xml` (pinned domains, debug overrides), FileProvider paths, backup rules, raw config files |
| `assets/` | Files as-is, not compiled, not referenced through `R` | JSON/YAML configuration, scripts, web apps, ML models, databases, certificates, encrypted blobs |
| `AndroidManifest.xml` | Binary XML | Components, permissions, queries (which packages the app looks for, e.g. root managers, see [MASWE-0059](/mobile/maswe-0059-code-obfuscation-not-implemented/) demo 0132), metadata |

You can read them without decoding the whole APK using AAPT2 from the SDK build tools: `aapt2 dump resources app.apk` (the resource table with names and values), `aapt2 dump strings app.apk` (the global string pool) and `aapt2 dump xmltree --file res/layout/activity_main.xml app.apk` (one compiled XML file).

Why it matters for reverse engineering: code refers to resources by integer ID (`0x7f13002a`). jadx resolves those IDs through `resources.arsc` and prints `R.string.root_detected_title`, so a resource name is a direct cross-reference into the code that uses it. Even when names are removed, the user-visible value still identifies the resource: search the string pool for the dialog text, take the ID, search the decompiled code for the ID.

Things that are public by design and not findings on their own: the Firebase API key and project identifiers in `strings.xml` (their protection is Firebase security rules and API restrictions; see our [MASWE-0004 note](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/)), certificate pins in `network_security_config.xml` (the platform must read them), and user-facing text.

### Android: resource shrinking

Resource shrinking removes resources in `res/` that nothing references. It is enabled with `isShrinkResources = true` next to `isMinifyEnabled = true` (or automatically with the AGP 9.3 `optimization { enable = true }` DSL). Since AGP 9.0, *optimised resource shrinking* is the default when shrinking is on: R8 treats resources as part of the program's reference graph, so a layout or string used only by dead code is removed together with that code ([Enable app optimization](https://developer.android.com/topic/performance/app-optimization/enable-app-optimization)). In AGP 8.12 and 8.13 it needs `android.r8.optimizedResourceShrinking=true` in `gradle.properties`.

What it does and does not do for this weakness:

- It **removes** leftover debug layouts, unused strings and drawables from libraries, abandoned feature screens. Less shipped content is less to analyse.
- It **does not touch `assets/`**: assets are not referenced through `R`, so the shrinker has no way to know whether they are used.
- By default it runs in *safe* mode: resources whose names appear as strings in the code, or that could be reached through `Resources.getIdentifier()`, are kept. A `res/raw/keep.xml` with `tools:keep`, `tools:discard` and `tools:shrinkMode="strict"` controls this ([Customize which resources to keep](https://developer.android.com/topic/performance/app-optimization/customize-which-resources-to-keep)).
- It **does not rename or encrypt** anything.

### Android: resource path shortening and name collapsing (AAPT2)

This is the part most often misdescribed, so we checked the current AGP and AAPT2 sources rather than relying on blog posts.

- **What AGP does by default.** For non-debuggable variants, AGP runs an `optimize<Variant>Resources` task that calls `aapt2 optimize` with **`--shorten-resource-paths`** (controlled by the `android.enableResourceOptimizations` Gradle property, default `true` and deprecated as of AGP 9.0). Path shortening renames the *files* inside the APK, so `res/layout/activity_admin_debug.xml` is stored as something like `res/Xy.xml`, to save space. The resource *names* in `resources.arsc` are unchanged, and apktool and jadx rebuild the normal `res/layout/…` tree from the table. Path shortening has no reverse-engineering value.
- **What AGP does not do.** The same task can pass `--collapse-resource-names`, but in the current AGP source the "resource obfuscation" input is hard-coded to off, and there is no DSL switch for it. As of AGP 9.x (late 2026), a standard Gradle build ships every resource name in clear. Treat this as a version-dependent observation and check the build output if it matters.
- **What AAPT2 can do.** `aapt2 optimize --collapse-resource-names` replaces every name in the resource table's key string pool with the single value `0_resource_name_obfuscated`. Resources that must keep their name (anything looked up with `getIdentifier()`, some libraries that resolve resources by name) are exempted with a config file passed through `--resources-config-path`, one `type/name#no_collapse` line per resource. `--save-obfuscation-map` writes the original-to-collapsed mapping, which, like `mapping.txt`, must not ship:

  ```bash
  printf 'string/app_name#no_collapse\n' > resources.cfg
  aapt2 optimize --collapse-resource-names --resources-config-path resources.cfg \
      --save-obfuscation-map res-obfuscation-map.txt -o app-optimized.apk app-unsigned.apk
  # then zipalign and sign as usual
  ```

  Running this outside AGP means post-processing the APK in CI before signing. For App Bundles, bundletool's `BundleConfig` has a `collapsed_resource_names` resource optimisation (with `no_collapse_resources` exemptions), applied when APKs are generated from the bundle; AGP's `bundle {}` DSL does not, as far as we can tell, expose it.
- **What name collapsing achieves.** jadx and apktool now show numeric IDs or the placeholder name instead of `root_detected_title`, so name-based searching stops working. The **values** are untouched: the warning text, the URL in a string resource and the content of `res/raw` are exactly as readable as before. Commercial Android obfuscators add resource and asset encryption on top of renaming; older open-source tools that renamed resources (for example Tencent's AndResGuard) target AGP versions that are long out of date.

### Android and iOS: asset encryption and where the key lives

MASTG-KNOW-0033 and MASTG-KNOW-0089 both describe encrypting files in `assets/`, `res/raw/` or the app bundle (`rules.json.enc`, `model.bin.enc`) and decrypting them with `javax.crypto.Cipher`, CryptoKit or CommonCrypto before use. Both note the limit: this stops direct extraction from the package, not recovery during runtime analysis. Before you credit it as a control, answer four questions:

1. **Where does the key come from?** Shipped ciphertext has to be decryptable by every install of that version, so the key is either somewhere in the package (a constant, a string resource, a native library, derived from package data such as the signing certificate) or fetched from a server at runtime. A hardware-backed Keystore or Secure Enclave key cannot decrypt a file that was encrypted at build time, because that key did not exist then. If the key is in the package, the protection is exactly as strong as the obfuscation of the key-handling code ([MASWE-0059](/mobile/maswe-0059-code-obfuscation-not-implemented/)), and a static key recovered once works for every user.
2. **When and where is it decrypted?** In memory, just before use, is best. Decrypting everything at start-up into a cache file (`cacheDir/rules.json`, `Library/Caches/model.mlmodelc`) leaves plaintext on disk for anyone with root or a backup.
3. **Is it authenticated?** AES-GCM or ChaCha20-Poly1305 detect modification; AES-CBC without a MAC does not, and a security-relevant config protected only by CBC can be tampered with ([MASWE-0057](/mobile/maswe-0057-app-resources-integrity-not-verified/)).
4. **What is it protecting?** A key in the encrypted file is still a hardcoded secret ([MASWE-0004](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/)). Encryption is appropriate for logic, rules, models and content whose exposure costs money or helps an attacker. It is not a place to hide credentials.

The strongest pattern available to an app is to **not ship the asset at all**, or to ship it encrypted with a key that the server releases only after verifying an attestation token ([MASWE-0054](/mobile/maswe-0054-device-attestation-not-implemented/), [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/)), then keep the plaintext in memory. Even then, the plaintext exists on a device the attacker controls; the goal is cost, not secrecy.

### iOS: what the app bundle reveals

An `.app` bundle is a directory, and almost everything in it except the executable is readable with stock macOS tools. Our [MASWE-0004 note](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/) covers obtaining and decrypting the IPA; FairPlay encrypts only the executable code, never the resources, so resource review works even on an encrypted App Store download.

| File type | How to read it | What it reveals |
|---|---|---|
| `Info.plist`, other `.plist` (binary or XML) | `plutil -p` | Bundle configuration, URL schemes, ATS exceptions, custom keys (base URLs, environment, feature switches), `GoogleService-Info.plist` |
| `*.lproj/*.strings`, `*.stringsdict` (compiled from `.strings` files or string catalogs) | `plutil -p` | Every user-facing message, including security warnings, keyed by often descriptive keys (`"jailbreak.alert.title"`) |
| `*.storyboardc/`, `*.nib` | `strings`, nib parsers | View controller class names, storyboard IDs, segue identifiers, outlet and action names, hidden debug screens |
| `Assets.car` | `xcrun assetutil --info` | Asset names; images, colours and *data assets* (arbitrary files such as JSON or models) |
| `*.momd` | `strings`, Xcode | Core Data entity and attribute names |
| `*.mlmodelc` | Core ML tools, `strings` | Compiled Core ML model, unless encrypted |
| `.json`, `.yaml`, `.js`, `.html`, `.db`, `.cer`/`.der` | Directly | Configuration, rules, hybrid web apps, databases, pinned certificates |
| `Frameworks/*.framework/`, `*.bundle`, `PlugIns/*.appex/` | Same as above | Resources of SDKs and extensions, often forgotten in reviews |

### iOS: asset catalogs and Core ML models

**Asset catalogs.** Xcode compiles `.xcassets` into `Assets.car`, a binary archive. `xcrun assetutil --info Assets.car` prints a JSON description of every rendition: names, types, sizes, and for data assets their UTI. Extracting the actual images and data needs third-party tools, which exist and are widely used, so treat `Assets.car` as packaging, not protection. Data assets (`NSDataAsset`) are a convenient place to put JSON, models or certificates, and they are exactly as readable as loose files once extracted.

**Core ML model encryption.** Apple provides a real, platform-backed protection for Core ML models: Xcode can generate a model encryption key (stored by Apple and associated with your developer team), encrypt the compiled model at build time through a model compiler flag, and the app then loads the model asynchronously; on first use the device fetches the key from Apple, so the key never ships in the bundle ([Encrypting a model in your app](https://developer.apple.com/documentation/coreml/encrypting-a-model-in-your-app)). It requires iOS 14 or later and network access on first load. It protects the model file from static extraction; it does not stop an attacker with a jailbroken device from instrumenting the process after the model is loaded. Android has no equivalent built-in mechanism for `.tflite` files in `assets/`.

### Cross-platform: JavaScript bundles, Hermes and Flutter assets

- **Hybrid apps (Cordova, Capacitor, Ionic).** The whole web app sits in `assets/www/` or `assets/public/` (Android) and `www/` or `public/` in the iOS bundle: HTML, minified JavaScript and often source maps. For these apps the JavaScript *is* the application logic, so MASWE-0059 and this weakness meet here.
- **React Native.** The bundle is `assets/index.android.bundle` or `main.jsbundle`. With Hermes (the default engine) it is bytecode with an intact string table and function names, which public disassemblers read; without Hermes it is minified JavaScript. Images referenced from JavaScript are typically copied into `res/drawable-*` on Android with names derived from their source path (for example `src_screens_admin_debugicon.png`), which leaks the project structure. Never ship `*.map` files.
- **Flutter.** Declared assets live in `assets/flutter_assets/` (Android) or `App.framework/flutter_assets/` (iOS), with an asset manifest listing every one of them. Flutter's `--obfuscate` flag renames Dart symbols and, as Flutter's documentation says, *does not encrypt resources*. A release bundle should not contain debug artefacts such as `kernel_blob.bin`, which in debug builds carries the Dart program in kernel form; if you find it, the app was built in debug mode ([MASWE-0061](/mobile/maswe-0061-debug-artifacts-not-removed/), [MASWE-0063](/mobile/maswe-0063-debug-mechanisms-not-disabled/)).

## Tests

There are no OWASP tests for MASWE-0060. The three tests below are ours. Run GT-RES-0060-1 or GT-RES-0060-2 first; run GT-RES-0060-3 when you find encrypted or high-entropy assets, or when the app claims to protect its assets.

### GT-RES-0060-1: Resource and asset review (Android)

*Guler Tech methodology — not an OWASP test.*

#### Overview

The test inventories everything in the APK that is not code and answers three questions: which resources reveal security-relevant behaviour or valuable content, whether resource names are descriptive, and whether anything is shipped that should not be. It is static and takes about an hour on a typical app.

#### Prerequisites

- The release APK and all splits (`adb shell pm path <package>`, `adb pull`), or the AAB with bundletool.
- Android SDK build tools (`aapt2`), apktool, jadx, `file`, Python 3.

#### Steps

1. Decode resources and get the resource table:

   ```bash
   apktool d -f -s base.apk -o res_out                     # -s: skip smali, decode resources and manifest
   aapt2 dump resources base.apk > resources.txt
   grep -c '^ *resource 0x' resources.txt                   # number of resources
   grep -c '0_resource_name_obfuscated' resources.txt       # >0 means names were collapsed
   unzip -l base.apk | grep -E '^ .* res/[A-Za-z0-9_-]{1,4}\.[a-z]+$' | head   # shortened paths (size optimisation only)
   ```

2. Search names and values for security-relevant terms:

   ```bash
   grep -iE '(root|jailbr|tamper|integrity|frida|hook|debug|emulat|pinn|licen|attest|admin|internal|staging|feature|flag)' resources.txt | head -50
   grep -rhoE 'https?://[A-Za-z0-9._:/-]+' res_out/res res_out/assets 2>/dev/null | sort -u
   ```

3. Review layouts, menus and `xml/` for hidden screens and configuration:

   ```bash
   grep -rlE 'debug|admin|internal|developer|test' res_out/res/layout* res_out/res/menu* 2>/dev/null
   ls res_out/res/xml/ && cat res_out/res/xml/network_security_config.xml 2>/dev/null
   ```

4. Inventory `assets/` and `res/raw/` by type, and flag high-entropy files (likely encrypted or compressed):

   ```bash
   find res_out/assets res_out/res/raw -type f -exec file {} + 2>/dev/null | sed 's|res_out/||' | sort -t: -k2 | head -80
   python3 -I - res_out/assets res_out/res/raw <<'PY'
   import math, os, sys
   for root in sys.argv[1:]:
       for d, _, files in os.walk(root):
           for f in files:
               p = os.path.join(d, f); b = open(p, 'rb').read(1 << 20)
               if len(b) < 256: continue
               h = -sum(c / len(b) * math.log2(c / len(b)) for c in (b.count(i) for i in range(256)) if c)
               if h > 7.5: print(f'{h:.2f}  {p}')
   PY
   ```

   An entropy close to 8 bits per byte means encrypted or compressed data. `file` recognises ordinary compressed formats (PNG, JPEG, ZIP, gzip), so you can set those aside and look at what remains.

5. Look for content that should not ship and for logic shipped as data:

   ```bash
   unzip -l base.apk | grep -iE '\.map$|mapping\.txt|\.tflite$|\.onnx$|\.db$|\.sqlite$|\.(p12|pfx|bks|jks|pem|key)$|index\.android\.bundle|assets/(www|public)/|flutter_assets|kernel_blob\.bin|\.lua$'
   grep -rniE '"(enable|disable|enforce|skip|bypass|allow)[A-Za-z_]*"\s*:' res_out/assets 2>/dev/null | head
   ```

6. For every interesting resource, find where the code uses it (`R.string.<name>` or the numeric ID in jadx output) and note whether it leads to security-relevant logic.
7. Anything that looks like a credential or key goes to [MASWE-0004](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/); anything that changes security behaviour goes to GT-RES-0060-3 and [MASWE-0057](/mobile/maswe-0057-app-resources-integrity-not-verified/).

#### Observation

A table of relevant resources and assets: path or resource name, what it reveals, whether it is user-facing, whether the name is descriptive, the code that uses it, and the resource-table state (names collapsed or not, resource shrinking evidence, shortened paths). Plus a list of files that should not ship.

#### Evaluation

- **Fail** if non-user-facing resources or assets reveal security-relevant behaviour or configuration in clear (detection rules, feature flags controlling protections, fraud thresholds, internal endpoints of security services), or if valuable content (models, proprietary data) the app's threat model wants protected is in clear.
- **Fail** if resource names tied to security controls are descriptive (`root_detected_title`, `enable_pinning`) in an R-profile app, so they act as signposts into the code.
- **Fail** if source maps, obfuscation maps, debug artefacts or test material are shipped.
- **Pass** if security-relevant configuration and content are absent from the package or protected (and GT-RES-0060-3 passes for them), resource names are collapsed or non-descriptive for security-related resources, and nothing that should not ship is present. User-facing text and platform-required files remaining readable is expected and not a fail.

#### Demo

*Illustrative example, not from a specific engagement.* A release APK with resource shrinking on but names not collapsed:

```text
$ grep -iE 'root|pinn|integrity' resources.txt
    resource 0x7f13002a string/root_detected_title
      () "Security warning"
    resource 0x7f13002b string/root_detected_body
      () "This device appears to be rooted. Some features are disabled."
    resource 0x7f050003 bool/enforce_integrity_check
      () false
$ cat res_out/assets/config/security.json
{ "rootPolicy": "warn", "blockOnFrida": false, "minRiskScoreForStepUp": 70 }
```

Three findings in one minute: the resource names lead to the dialog code in jadx (`R.string.root_detected_title`), `bool/enforce_integrity_check` is `false` in the release build, and `security.json` tells the attacker the root policy only warns, Frida does not block, and step-up authentication starts at a risk score of 70. If the app reads `security.json` without verifying its integrity, the policy can also be edited in a repackaged copy (MASWE-0057).

### GT-RES-0060-2: Bundle resource review (iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

The iOS counterpart of GT-RES-0060-1. Resources in an `.app` bundle are never encrypted by FairPlay, so this test works on any IPA you can obtain. It covers the main app, embedded frameworks and app extensions.

#### Prerequisites

- The IPA (decryption not required for resources), macOS with Xcode command-line tools (`plutil`, `xcrun assetutil`), `strings`, `file`, Python 3.

#### Steps

1. Unpack and inventory by file type:

   ```bash
   unzip -q App.ipa -d ipa && cd ipa/Payload/App.app
   find . -type f | sed -E 's/.*\.([A-Za-z0-9]+)$/\1/' | sort | uniq -c | sort -rn | head -30
   find . -type f \( -name '*.json' -o -name '*.plist' -o -name '*.yaml' -o -name '*.js' -o -name '*.map' -o -name '*.db' -o -name '*.sqlite' -o -name '*.cer' -o -name '*.der' -o -name '*.p12' -o -name '*.mlmodelc' -o -name '*.enc' \) | grep -v '_CodeSignature' 
   ```

2. Property lists and localisation:

   ```bash
   plutil -p Info.plist | grep -viE 'CFBundleIcon|UISupported|UIRequired'
   for f in $(find . -name '*.plist' ! -path '*/_CodeSignature/*'); do echo "== $f"; plutil -p "$f" | head -40; done
   plutil -p en.lproj/Localizable.strings | grep -iE 'jailbr|root|tamper|integrity|debug|frida|security'
   ```

3. Interface files and asset catalogs:

   ```bash
   find . -name '*.nib' -o -name '*.storyboardc' | head
   strings -n 5 Base.lproj/Main.storyboardc/*.nib | grep -iE 'debug|admin|internal|jailbr|developer' | sort -u
   xcrun assetutil --info Assets.car | grep -E '"(AssetType|Name|UTI)"' | sort | uniq -c | sort -rn | head -40
   ```

4. JavaScript, Flutter and model content:

   ```bash
   ls main.jsbundle www public Frameworks/App.framework/flutter_assets 2>/dev/null
   xxd -l 8 main.jsbundle 2>/dev/null          # c6 1f bc 03 c1 03 19 1f = Hermes bytecode
   find . -name '*.mlmodelc' -maxdepth 3
   ```

5. Run the entropy check from GT-RES-0060-1 (step 4) on the bundle directory to find encrypted blobs, and repeat steps 2–4 inside every `Frameworks/*.framework`, `*.bundle` and `PlugIns/*.appex`.
6. For each interesting key, string or asset, find the code that reads it (strings and xrefs in the binary, see [MASWE-0059](/mobile/maswe-0059-code-obfuscation-not-implemented/) MASTG-TEST-0391) and move secrets to MASWE-0004 and security-relevant configuration to GT-RES-0060-3.

#### Observation

Same table as GT-RES-0060-1: file, what it reveals, user-facing or not, descriptive keys or names, consuming code, plus files that should not ship and whether Core ML models are encrypted.

#### Evaluation

- **Fail** if non-user-facing plists, JSON, data assets or scripts reveal security-relevant configuration or logic in clear, if localisation keys, storyboard identifiers or asset names act as signposts to security controls in an R-profile app, if valuable models or content are shipped unprotected where the threat model requires protection, or if source maps or debug material are present.
- **Pass** under the same conditions as GT-RES-0060-1. A Core ML model encrypted with Apple's model encryption counts as protected against static extraction; say so in the report.

#### Demo

*Illustrative example.*

```text
$ plutil -p Info.plist | grep -E 'API|ENV|FEATURE'
  "API_BASE_URL" => "https://api.example.com/v2"
  "FEATURE_JAILBREAK_BLOCK" => 0
$ plutil -p en.lproj/Localizable.strings | grep -i jailbr
  "security.jailbreak.alert.title" => "Unsupported device"
$ xcrun assetutil --info Assets.car | grep -A2 '"AssetType" : "Data"'
    "AssetType" : "Data",
    "Name" : "fraud_rules",
    "UTI" : "public.json",
```

`FEATURE_JAILBREAK_BLOCK = 0` tells the attacker the app does not block jailbroken devices in this build, the localisation key leads to the alert code, and the `fraud_rules` data asset is a JSON rules file shipped in clear inside the asset catalog.

### GT-RES-0060-3: Encrypted assets: key location and decryption point (Android, iOS)

*Guler Tech methodology — not an OWASP test.*

#### Overview

When an app encrypts assets, the useful questions are the four from the Background section: where the key comes from, when and where the data is decrypted, whether the encryption is authenticated, and what the protected content is. This test answers them by tracing **the app's own** asset loading and decryption on your own test device, without attempting to defeat any server-side protection. If the key comes from a server after attestation, record that and stop: testing the attestation itself belongs to [MASWE-0054](/mobile/maswe-0054-device-attestation-not-implemented/) and [MASWE-0056](/mobile/maswe-0056-app-attestation-not-implemented/).

#### Prerequisites

- The encrypted files identified in GT-RES-0060-1 or GT-RES-0060-2.
- jadx (Android) or Ghidra/r2 (iOS) for the static part.
- A rooted Android device or emulator, or a jailbroken iOS device, with Frida (see our [lab set-up](/mobile/mobile-traffic-interception-lab/)). If the app has root, jailbreak or Frida detection, work with the developer's test build or a build with those checks disabled, and note it.

#### Steps

1. **Static: find the loading code.** On Android, search the decompiled code for the asset name and for asset APIs near crypto APIs:

   ```bash
   grep -rnE 'rules\.json\.enc|getAssets\(\)\.open|openRawResource|AssetManager' out/sources | grep -vE '^out/sources/(androidx|com/google)/' | head
   grep -rnE 'Cipher\.getInstance|SecretKeySpec|GCMParameterSpec|IvParameterSpec' out/sources | grep -vE '^out/sources/(androidx|com/google)/' | head
   nm -D app/lib/arm64-v8a/*.so 2>/dev/null | grep -E 'AAssetManager_open|AAsset_read'   # native asset access
   ```

   On iOS, search the binary for the file name and for `CCCrypt`, `CCCryptorCreate`, CryptoKit symbols (`AES.GCM`, `ChaChaPoly` in demangled names) and `NSBundle` resource APIs. Note where the key comes from: a constant (`SecretKeySpec(byte[]{…})`), a resource, a native function, a derivation (PBKDF2 or HKDF over package data), or a network call.

2. **Dynamic (Android): trace the app's own asset reads and decryption.** The script logs which asset is opened, the cipher transformation, the key length and a short fingerprint of the key (not the key itself), and the size of the plaintext:

   ```javascript
   // trace-assets.js: frida -U -f com.example.app -l trace-assets.js
   Java.perform(() => {
     const AM = Java.use('android.content.res.AssetManager');
     AM.open.overloads.forEach((o) => {
       o.implementation = function (...args) {
         console.log('[asset] open ' + args[0]);
         return o.call(this, ...args);
       };
     });
     const MD = Java.use('java.security.MessageDigest');
     const Cipher = Java.use('javax.crypto.Cipher');
     Cipher.init.overloads.forEach((o) => {
       o.implementation = function (...args) {
         const key = args[1];
         let info = '';
         try {
           const enc = key.getEncoded();
           const fp = MD.getInstance('SHA-256').digest(enc);
           let hex = '';
           for (let i = 0; i < 4; i++) hex += ('0' + (fp[i] & 0xff).toString(16)).slice(-2);
           info = ' keyLen=' + enc.length + ' keySHA256[0..4]=' + hex;
         } catch (e) { info = ' key=' + key; }
         console.log('[cipher] init ' + this.getAlgorithm() + ' mode=' + args[0] + info);
         console.log(Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new()));
         return o.call(this, ...args);
       };
     });
     Cipher.doFinal.overloads.forEach((o) => {
       o.implementation = function (...args) {
         const out = o.call(this, ...args);
         if (out && out.length !== undefined) console.log('[cipher] doFinal -> ' + out.length + ' bytes');
         return out;
       };
     });
   });
   ```

   The stack trace on `Cipher.init` shows which (possibly obfuscated) class supplies the key; follow it back in jadx to the key source. If decryption is native, use `frida-trace -U -f com.example.app -i 'AAssetManager_open' -i 'AAsset_read'` and the library's own decryption function once you have found it statically.

3. **Dynamic (iOS): trace bundle reads and CommonCrypto.**

   ```javascript
   // trace-cccrypt.js: frida -U -f com.example.app -l trace-cccrypt.js
   const cc = Process.getModuleByName('libcommonCrypto.dylib').getExportByName('CCCrypt');
   Interceptor.attach(cc, {
     onEnter(args) {
       this.out = args[10];
       console.log('[CCCrypt] op=' + args[0].toInt32() + ' alg=' + args[1].toInt32() +
         ' opts=' + args[2].toInt32() + ' keyLen=' + args[4].toInt32() + ' inLen=' + args[7].toInt32());
       console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n'));
     },
     onLeave() {
       if (!this.out.isNull()) console.log('[CCCrypt] outLen=' + this.out.readULong());
     },
   });
   ```

   Combine with `frida-trace -U -f com.example.app -m '-[NSBundle pathForResource:ofType:]' -m '-[NSBundle URLForResource:withExtension:]'` to tie the decryption to a bundle file. CryptoKit does not go through CommonCrypto; if the app uses it, trace the app's own wrapper function that you located statically.

4. **Check for plaintext at rest.** After exercising the feature that uses the asset, look for decrypted copies:

   ```bash
   # Android (root): files modified in the app's sandbox in the last 10 minutes
   adb shell su -c "find /data/data/com.example.app /data/user_de/0/com.example.app -type f -mmin -10"
   # iOS (jailbroken, via SSH): the app's data container
   find /var/mobile/Containers/Data/Application/<UUID>/ -type f -mmin -10
   ```

   Then check whether any of them contains the plaintext (`file`, `head`, entropy).

5. **Check integrity.** Note the mode: GCM/ChaCha20-Poly1305 (authenticated) or CBC/CTR/ECB (not). With an unauthenticated mode and security-relevant content, note the tampering exposure for [MASWE-0057](/mobile/maswe-0057-app-resources-integrity-not-verified/).

#### Observation

For each encrypted asset: file, algorithm and mode, key length, key source (constant in code, resource, native library, derived from package data, fetched from server, fetched after attestation), time and place of decryption (start-up or on use; memory only or written to disk), the code location (class or function), and what the plaintext contains.

#### Evaluation

- **Fail** if the key is recoverable from the package by static analysis with reasonable effort (a constant, a resource, a readable native function), because then the encryption adds no more than the code obfuscation around it and one recovered key serves every install. Rate the weakness of the key-handling code under [MASWE-0059](/mobile/maswe-0059-code-obfuscation-not-implemented/) as well.
- **Fail** if plaintext is written to disk where the asset is security-relevant or valuable.
- **Fail** if the plaintext contains secrets (report under [MASWE-0004](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/)), or if security-relevant configuration is protected by unauthenticated encryption with no separate integrity check.
- **Pass** if the key is not in the package (server-delivered, ideally after attestation) or its derivation is protected at the level the threat model requires (Level 2+ in our MASWE-0059 scale), decryption happens in memory on use, the mode is authenticated, and no secrets are inside. State that runtime extraction remains possible on a compromised device; that is inherent and not a fail.

#### Demo

*Illustrative example.* An app ships `assets/rules.json.enc` and decrypts it at start-up:

```kotlin
object RulesLoader {
    private val KEY = "0123456789abcdef".toByteArray()          // hardcoded in the APK
    fun load(ctx: Context): JSONObject {
        val enc = ctx.assets.open("rules.json.enc").readBytes()
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(KEY, "AES"), IvParameterSpec(enc.copyOfRange(0, 16)))
        val plain = cipher.doFinal(enc, 16, enc.size - 16)
        File(ctx.cacheDir, "rules.json").writeBytes(plain)       // plaintext at rest
        return JSONObject(plain.decodeToString())
    }
}
```

Frida output:

```text
[asset] open rules.json.enc
[cipher] init AES/CBC/PKCS5Padding mode=2 keyLen=16 keySHA256[0..4]=9f9f5111
java.lang.Exception
    at javax.crypto.Cipher.init(Native Method)
    at a.b.c.a(SourceFile)
    at com.example.app.App.onCreate(SourceFile)
[cipher] doFinal -> 4182 bytes
```

Fail on three counts: the key is a constant that jadx shows in `a.b.c`, the plaintext is written to `cacheDir/rules.json`, and CBC without a MAC lets a repackaged app swap the rules. The fix is to fetch the rules from the server (or the key, after attestation), keep them in memory, and use AES-GCM.

## Secure implementation

**Android**

- Release build with `isMinifyEnabled = true` and `isShrinkResources = true` (or `optimization { enable = true }` on AGP 9.3+), and `res/raw/keep.xml` in strict mode if the app does not use `getIdentifier()`.
- Debug-only screens, menus, test data and mock configuration in the `debug` source set (`src/debug/res`, `src/debug/assets`), so they cannot reach a release build.
- Non-descriptive names for resources tied to security controls, generic user-facing messages, and, if your threat model justifies the CI work, collapsed resource names via `aapt2 optimize --collapse-resource-names` with explicit `no_collapse` exemptions, applied before signing; keep the obfuscation map private.
- Security-relevant configuration delivered from the server, or shipped encrypted with authenticated encryption and a key that is not a constant in the package; decrypt in memory only.
- A CI check on the final APK/AAB that fails the build on `*.map`, `mapping.txt`, private keys and known debug artefacts.

**iOS**

- Debug-only resources excluded from the release target (separate targets, build phases or `EXCLUDED_SOURCE_FILE_NAMES` per configuration), no environment switches in `Info.plist` that weaken security in release.
- Neutral localisation keys and storyboard identifiers for security-related UI.
- Core ML models protected with Apple's model encryption where the model is valuable; other valuable assets server-delivered or encrypted with a key the server releases after App Attest.
- The same CI check on the IPA for source maps, keys and debug material.

**Cross-platform**

- React Native and hybrid apps: no source maps in the package, security decisions not in JavaScript, and a JavaScript obfuscator for bundles that contain valuable logic. Flutter: release builds only, `--obfuscate`, and no secrets or rules in `flutter_assets`.

## Rating findings

The series-wide rules apply, adapted to resources:

- **App without the R profile**: unobfuscated resources are **Info**. Readable user-facing text and platform-required files are never a finding.
- **R-profile app**: descriptive security-related resource names, readable non-user-facing configuration that reveals how protections work, and valuable content in clear are usually **Low**, and **Medium** when the exposed resource directly drives a protection or business control the attacker can then evade or, without integrity checks, modify (a policy file that disables root blocking, fraud thresholds, a proprietary model that is a core business asset).
- **Medium–High** only when it directly enables a concrete business abuse, typically together with a missing integrity check or server-side control. Rate the tampering part under [MASWE-0057](/mobile/maswe-0057-app-resources-integrity-not-verified/).
- **Secrets in resources or in encrypted assets** are rated under [MASWE-0004](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/), by what the secret grants, regardless of profile.
- **Debug mechanisms** found through resources (a debug build of Flutter, WebView debugging enabled through a resource flag) are real vulnerabilities regardless of profile; see [MASWE-0063](/mobile/maswe-0063-debug-mechanisms-not-disabled/).

| Rating | Typical conditions |
|---|---|
| **Info** | Non-R app; readable user-facing strings; Firebase or Maps configuration that is public by design; pins in `network_security_config.xml`; AAPT2 path shortening present or absent |
| **Low** | R app; descriptive resource names or localisation keys for security controls; readable configuration revealing internal endpoints or feature flags without direct security effect; source maps in a native app with little JavaScript |
| **Medium** | R app; readable security policy or rules (root/Frida policy, fraud thresholds) that the client trusts; valuable model or content shipped in clear where the threat model requires protection; encrypted assets with the key recoverable from the package and plaintext written to disk; source maps for a hybrid or React Native app whose logic is in JavaScript |
| **Medium–High** | Readable or modifiable resource that directly enables demonstrated abuse (for example a policy file whose modification disables a payment risk control, accepted by the app because nothing verifies it) with no server-side compensating control |

In the report, give the file path or resource name, the exact value or excerpt (redacted if sensitive), the code that consumes it, why it helps an attacker, and the concrete fix (remove, move to server, rename, encrypt with authenticated encryption and a non-shipped key, verify integrity).

## References

- OWASP MASWE: [MASWE-0060: Resource Obfuscation Not Implemented](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0060/); related [MASWE-0059](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0059/), [MASWE-0057](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0057/), [MASWE-0004](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0004/) (CC BY-SA 4.0)
- OWASP MASVS: [MASVS-RESILIENCE-3](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-3/) (CC BY-SA 4.0)
- OWASP MASTG knowledge (resource and asset encryption sections): [MASTG-KNOW-0033](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0033/), [MASTG-KNOW-0089](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0089/) (CC BY-SA 4.0)
- OWASP MASTG tools and techniques: [Apktool (MASTG-TOOL-0011)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/), [jadx (MASTG-TOOL-0018)](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [Exploring the App Package (MASTG-TECH-0058)](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/) (CC BY-SA 4.0)
- Android: [Enable app optimization (resource shrinking, optimised resource shrinking)](https://developer.android.com/topic/performance/app-optimization/enable-app-optimization), [Customize which resources to keep](https://developer.android.com/topic/performance/app-optimization/customize-which-resources-to-keep), [AAPT2](https://developer.android.com/tools/aapt2), [AAPT2 `optimize` command source (`Optimize.h`)](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/tools/aapt2/cmd/Optimize.h), [AGP `OptimizeResourcesTask` source](https://android.googlesource.com/platform/tools/base/+/refs/heads/mirror-goog-studio-main/build-system/gradle-core/src/main/java/com/android/build/gradle/internal/tasks/OptimizeResourcesTask.kt), [bundletool `config.proto`](https://github.com/google/bundletool/blob/master/src/main/proto/config.proto), [Improve app performance with optimized resource shrinking (Android Developers Blog)](https://android-developers.googleblog.com/2025/09/improve-app-performance-with-optimized-resource-shrinking.html)
- Apple: [Encrypting a model in your app](https://developer.apple.com/documentation/coreml/encrypting-a-model-in-your-app), [Generating a model encryption key](https://developer.apple.com/documentation/coreml/generating-a-model-encryption-key), [Information property list](https://developer.apple.com/documentation/bundleresources/information-property-list), [NSDataAsset](https://developer.apple.com/documentation/uikit/nsdataasset)
- Flutter: [Obfuscating Dart code](https://docs.flutter.dev/deployment/obfuscate); React Native: [Using Hermes](https://reactnative.dev/docs/hermes)
- CWE: [CWE-693](https://cwe.mitre.org/data/definitions/693.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
