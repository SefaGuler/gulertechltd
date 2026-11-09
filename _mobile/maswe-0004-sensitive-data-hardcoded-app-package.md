---
title: "Sensitive Data Hardcoded in the App Package (MASWE-0004)"
date: 2026-11-08 12:01:00 +0000
summary: "Finding, validating and removing secrets shipped inside APKs and IPAs: package anatomy, framework bundles, safe live-key checks and backend fixes."
refs: [MASWE-0004, MASVS-STORAGE-1, CWE-798, CWE-540]
tags: [android, ios, masvs-storage, secrets, api-keys, reverse-engineering]
---

This note is part of our [MASVS-STORAGE-1 series](/mobile/masvs-storage-1-secure-storage-guide/) and covers the fourth weakness under "The app securely stores sensitive data": secrets and other sensitive values that are baked into the app package itself. Unlike the other storage weaknesses, nothing here depends on the device, the user or the runtime. Every copy of the APK or IPA carries the same data, every historical version stays on mirror sites indefinitely, and anyone who can download the app can read it with free tools in minutes. The question you are answering in the assessment is therefore not "can an attacker get this value?" (they can) but "what does this value let them do?".

> **Note:** At the time of writing, OWASP has not published any MASTG Knowledge items or Tests linked to [MASWE-0004](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0004/). The Knowledge and Testing sections below are Guler Tech's own methodology, written to match the weakness definition and cross-referenced to the existing MASTG techniques, tools and tests that genuinely apply. Where an OWASP test already covers a narrower case (hardcoded cryptographic keys, MASTG-TEST-0212/0213/0214), we link to it rather than duplicate it.

**Contents**

- [Overview](#overview)
- [Modes of Introduction](#modes-of-introduction)
- [Impact](#impact)
- [Mitigations](#mitigations)
- [Knowledge](#knowledge)
- [Testing](#testing)
- [Secure implementation](#secure-implementation)
- [Rating findings](#rating-findings)
- [References](#references)

## Overview

[MASWE-0004](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0004/) describes sensitive data that is embedded in the APK or IPA and shipped to every user. The requirement it maps to is blunt: *the app does not hardcode sensitive data in the application package.*

"Sensitive data" in this context covers four families:

- **Service credentials**: API keys and secrets for first-party backends and third-party services (cloud, payments, messaging, AI, analytics with write or admin scope).
- **Account credentials**: usernames and passwords, long-lived bearer tokens, refresh tokens, basic-auth headers, database connection strings.
- **Cryptographic material**: symmetric keys, private keys, client certificates and keystores with their passwords. How such keys *should* be stored is the subject of [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/); this note only cares that they are inside the package.
- **Developer leftovers that leak confidentiality**: staging and integration endpoints, internal hostnames, developer email addresses and usernames, source files, source maps and other build artefacts that should never have been packaged.

The boundary with [MASWE-0061 (Debug Artifacts Not Removed)](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0061/) is worth stating precisely because it changes how you report. MASWE-0061 is about artefacts that weaken the app's *resilience*: debug menus, hidden switches, verbose logging, an insecure trust manager left behind. MASWE-0004 is about artefacts that leak *confidential information* regardless of any anti-tampering posture. A staging URL in `strings.xml` is a MASWE-0004 finding; a hidden "disable pinning" toggle on that staging build is MASWE-0061.

| Mapping | Value |
|---|---|
| MASVS v2 | MASVS-STORAGE-1 |
| MASVS v1 | MSTG-STORAGE-1, MSTG-CODE-2 |
| CWE | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) Hard-coded Credentials, [CWE-540](https://cwe.mitre.org/data/definitions/540.html) Sensitive Information in Source Code, [CWE-321](https://cwe.mitre.org/data/definitions/321.html) Hard-coded Cryptographic Key, [CWE-312](https://cwe.mitre.org/data/definitions/312.html) Cleartext Storage |
| Profiles | L1, L2, EUDIW |
| Platforms | Android, iOS |

Two facts drive everything else in this note:

1. **The client is not a place to keep a secret.** Obfuscation, string encryption, splitting a key across native code, XOR tricks and white-box crypto all raise the cost of static extraction. None of them survive an attacker who runs the app and reads the value at the moment it is used, or simply proxies the HTTPS request that carries it.
2. **Not every value that looks like a key is a secret.** Many vendors issue identifiers that are *designed* to be embedded (Firebase config, Stripe publishable keys, Sentry DSNs, Maps keys with restrictions). Reporting these as critical wastes the client's time and erodes trust in the rest of your report. Classification and live validation are part of the test, not an optional extra.

## Modes of Introduction

- **App source code.** Constants such as `private const val API_KEY = "..."`, `static let secret = "..."`, credentials in a `Retrofit` interceptor, a hardcoded `Authorization: Basic ...` header, a `SecretKeySpec` built from a literal. Build-time injection (`buildConfigField`, `.xcconfig` values read into `Info.plist`, `--dart-define`, `react-native-config`) lands in the same place: the compiled package.
- **App assets and resources.** `res/values/strings.xml` and generated `values.xml`, `assets/*.json`, `res/raw/`, manifest `<meta-data>`, `Info.plist` and other property lists, `GoogleService-Info.plist`, `.env` files shipped as Flutter assets, bundled `.p12`/`.pem`/`.bks` files.
- **Libraries.** First-party modules shared across apps, third-party SDKs that need a key at initialisation, and transitive dependencies that carry their own configuration files or (occasionally) the vendor's own credentials.
- **Build and developer leftovers.** Staging base URLs, test accounts, developer names in file paths compiled into Swift binaries, `.swift`/`.m`/`.java` source files dragged into "Copy Bundle Resources", JavaScript source maps, `.DS_Store`, `.git` folders in hybrid-app `www/` directories, and debug provisioning profiles.

## Impact

- **Financial loss.** A leaked key for a pay-per-call API (generative AI, maps, SMS, email, speech, OCR) lets anyone run workload on the app owner's bill. This is the most common real-world consequence and it scales with the attacker's appetite, not the app's user count.
- **Compromise of backend integrity and operations.** Write-capable credentials allow data tampering, spam or phishing sent from the organisation's verified sending domain, abuse that triggers a provider's acceptable-use suspension (taking the legitimate app down with it), or quota exhaustion that denies service to real users.
- **Disclosure of sensitive data.** Credentials for storage buckets, databases, admin APIs or support tools expose user data directly. Hardcoded encryption keys let an attacker decrypt anything the app "protected" with them, on every device.
- **Bypass of protection mechanisms.** Licence keys, premium-unlock secrets, content-decryption keys and request-signing secrets let an attacker unlock paid features or forge requests that the backend trusts as coming from the genuine app.
- **Reconnaissance.** Staging hosts, internal API paths and developer identities shorten the path to other attacks: weaker non-production environments, credential stuffing against named staff, targeted phishing.

## Mitigations

OWASP lists the following mitigations. We expand each with concrete patterns in [Secure implementation](#secure-implementation).

- **Proxy static secrets through middleware.** If the upstream API only accepts a static key, put an API gateway or thin backend between the app and the API so the key never leaves your infrastructure. Authenticate the app's calls to the proxy with the user's session (JWT/JWS as appropriate), not with another static secret.
- **Prefer stateful, properly authenticated APIs.** Use services that support real client authentication and session control, issue short-lived tokens (for example one hour), and log and alert on misuse. For user-delegated access, use OAuth 2.0 with PKCE via a library such as AppAuth.
- **Retrieve secrets at runtime, conditionally.** Where a client genuinely needs a secret, deliver it from a key management service behind your backend, only after device and app integrity checks, over a pinned channel ([MASWE-0028](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0028/)).
- **Restrict anything you must ship.** If a key has to be in the package, give it the minimum scope: API restrictions, application restrictions, quotas and budget alerts.
- **Use platform keystores for keys.** Generate cryptographic keys on the device in Android Keystore or the iOS Keychain/Secure Enclave instead of embedding them ([MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/)).
- **Audit for secrets and leftovers.** Scan source, history and built artefacts with tools such as gitleaks, and strip source files and build artefacts from release packages.
- **Harden only as a last resort.** White-box cryptography, string obfuscation and RASP raise extraction cost. They do not prevent it and must never be the primary control.

## Knowledge

Because MASWE-0004 has no linked MASTG Knowledge items, this section explains the mechanisms you need from first principles: where data physically ends up in each package format, what the common cross-platform frameworks do to it, and how to tell a real secret from a public identifier.

### Related OWASP material

These MASTG items exist in the OWASP repository and are directly useful for this weakness. None of them is mapped to MASWE-0004 by OWASP; they are the building blocks our procedures use.

| Item | What it gives you here |
|---|---|
| [MASTG-TECH-0003](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0003/) Obtaining and Extracting Apps (Android) | Pulling the APK (and splits) from a device or store |
| [MASTG-TECH-0145](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0145/) Working with XAPK Files | Unpacking third-party store bundles of split APKs |
| [MASTG-TECH-0007](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0007/) Exploring the App Package (Android) | APK layout, `apktool d`, assets, native libraries |
| [MASTG-TECH-0017](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0017/) Decompiling Java Code | `jadx` decompilation of all `classes*.dex` |
| [MASTG-TECH-0019](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0019/) Retrieving Strings (Android) | DEX string table and native `.so` strings |
| [MASTG-TECH-0157](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0157/) Extracting Bundled Native Libraries | Locating `lib/<abi>/*.so` |
| [MASTG-TECH-0165](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0165/) Identifying Compilers, Obfuscators, and Packers | APKiD to see whether string encryption is in play |
| [MASTG-TECH-0156](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0156/) Reverse Engineering Flutter Applications | blutter on `libapp.so` |
| [MASTG-TECH-0054](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0054/) Obtaining and Extracting Apps (iOS) | FairPlay, decrypting with frida-ios-dump |
| [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/) Exploring the App Package (iOS) | `.app` bundle layout, `Info.plist`, frameworks |
| [MASTG-TECH-0070](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0070/) Extracting Information from the Application Binary | radare2 on Mach-O |
| [MASTG-TECH-0071](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0071/) Retrieving Strings (generic) | `strings`, `rabin2 -zz` |
| [MASTG-TECH-0138](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0138/) Convert Plist Files to JSON | `plutil`/`plistlib` conversion |
| [MASTG-TECH-0098](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0098/) Patching React Native Apps | Where `main.jsbundle` lives |
| [MASTG-TECH-0130](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0130/) / [MASTG-TECH-0132](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0132/) SCA by creating an SBOM | Dependency inventory before hunting SDK keys |
| [MASTG-TECH-0120](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0120/) Intercepting HTTP Traffic Using an Interception Proxy | Seeing a "protected" key on the wire |
| Tools: [jadx](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [Apktool](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/), [aapt2](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0124/), [APKiD](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0009/), [Apkleaks](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0125/), [rabin2](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/), [radare2 (iOS)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/), [semgrep](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/), [gitleaks](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0144/), [hermes-dec](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0104/), [blutter](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0116/), [frida-ios-dump](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0050/), [plutil](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0062/) | Used throughout the procedures |
| [MASTG-TEST-0212](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0212/), [MASTG-TEST-0213](https://mas.owasp.org/MASTG/tests/ios/MASVS-CRYPTO/MASTG-TEST-0213/), [MASTG-TEST-0214](https://mas.owasp.org/MASTG/tests/ios/MASVS-CRYPTO/MASTG-TEST-0214/) | Hardcoded cryptographic keys in code and files, mapped to MASWE-0003 and covered in our [MASWE-0003 note](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/) |
| [MASTG-TEST-0233](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0233/), [MASTG-TEST-0321](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0321/) Hardcoded HTTP URLs | Same string-extraction workflow, aimed at cleartext endpoints (MASWE-0026) |
| [MASTG-KNOW-0033](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0033/), [MASTG-KNOW-0089](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0089/), [MASTG-KNOW-0111](https://mas.owasp.org/MASTG/knowledge/generic/MASVS-RESILIENCE/MASTG-KNOW-0111/) Obfuscation | What renaming and string encryption do and do not hide |
| [MASTG-KNOW-0064](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CODE/MASTG-KNOW-0064/) Non-Production Resources (iOS) | Test endpoints, test credentials and dev profiles left in builds |
| [MASTG-KNOW-0004](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0004/), [MASTG-KNOW-0059](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CODE/MASTG-KNOW-0059/) Third-Party Libraries | Background for the dependency procedure |

### Android APK anatomy

An APK is a ZIP archive. A release APK (or the set of split APKs Google Play generates from an App Bundle) contains everything the app needs at runtime, and every file in it is readable by anyone who has the package. These are the places hardcoded data ends up, roughly in order of how often we find secrets there:

| Location | Contents | How you read it |
|---|---|---|
| `classes.dex`, `classes2.dex`, … | All Java/Kotlin bytecode, including every string literal in the DEX string table | `jadx`, `strings`, `rabin2 -zz` |
| `resources.arsc` | Compiled resource table: every value from `res/values/*.xml` (strings, integers, booleans) | `apktool d` (decodes to `res/values/strings.xml`), `aapt2 dump resources` |
| `res/raw/`, `res/xml/` | Arbitrary files and compiled XML (configs, certificates, JSON) | `apktool d` |
| `assets/` | Arbitrary files read via `AssetManager`: JSON configs, JavaScript bundles, databases, keystores, `.env` files | `unzip` |
| `lib/<abi>/*.so` | Native code (C/C++, Rust, Go, Dart AOT, framework engines) | `strings`, `rabin2`, Ghidra, radare2 |
| `AndroidManifest.xml` | Binary XML; `<meta-data>` values for SDK keys | `apktool d`, `aapt2 dump xmltree` |
| Root and `META-INF/` | Leftover `.properties`, `.version`, licence files; occasionally stray build files | `unzip -l` |

#### DEX bytecode and `BuildConfig`

Every literal string your code references is stored once in the DEX `string_ids` table, in modified UTF-8, which for ASCII keys means plain readable bytes. `strings` on a raw `classes.dex` therefore finds most keys without any decompilation.

Gradle's `buildConfigField` is the most common way teams "inject" keys:

```kotlin
// app/build.gradle.kts
android {
    defaultConfig {
        buildConfigField("String", "PAYMENTS_KEY", "\"sk_live_51Hx...\"")
    }
}
```

This generates `BuildConfig.PAYMENTS_KEY` as a `public static final String`. Because it is a compile-time constant, the Java and Kotlin compilers **inline the literal into every class that uses it**. R8 then often removes the `BuildConfig` class entirely, which leads developers to believe the value is gone. It is not: it now sits in the calling class's bytecode. Search the whole decompiled tree, not just `BuildConfig.java`.

The same applies to Google's [Secrets Gradle Plugin](https://github.com/google/secrets-gradle-plugin) and to `local.properties`-based setups. They keep the key **out of version control**, which is good hygiene, but they deliberately put it into `BuildConfig` and the merged manifest, i.e. into the APK. They are not a client-side secret-storage mechanism and their documentation does not claim to be.

#### Resources: `resources.arsc` and `strings.xml`

`res/values/strings.xml` and any `resValue(...)` Gradle entries are compiled into `resources.arsc`. `unzip` gives you the binary table; `apktool d` decodes it back to readable XML under `res/values/`. You can also dump the table without decoding the whole APK:

```bash
aapt2 dump resources app.apk | grep -iE 'key|secret|token|password|url'
```

Look at every `values*/` directory, not just the default one: per-flavour or per-locale overrides sometimes carry a different (staging) value.

#### `google-services.json` becomes string resources

The Firebase `google-services.json` file is **not** shipped as-is. The Google Services Gradle plugin reads it at build time and generates string resources, so in the decoded APK you find them in `res/values/strings.xml` (or `values.xml`):

| Generated resource | Meaning |
|---|---|
| `google_api_key`, `google_crash_reporting_api_key` | The Android API key for the Firebase/Google Cloud project |
| `google_app_id` | Firebase app ID (`1:<project-number>:android:<hash>`) |
| `gcm_defaultSenderId` | Project number |
| `project_id` | Firebase/GCP project ID |
| `firebase_database_url` | Realtime Database URL, if one exists |
| `google_storage_bucket` | Cloud Storage for Firebase bucket |
| `default_web_client_id` | OAuth client ID used for Google Sign-In |

None of these are secrets by themselves (see [Firebase configuration](#firebase-configuration-is-public-by-design) below), but together they tell you exactly which backend resources to check for misconfigured security rules.

#### Manifest `<meta-data>`

SDKs read their keys from manifest metadata. Typical entries:

```xml
<meta-data android:name="com.google.android.geo.API_KEY" android:value="@string/maps_api_key" />
<meta-data android:name="com.facebook.sdk.ApplicationId" android:value="@string/facebook_app_id" />
<meta-data android:name="com.facebook.sdk.ClientToken" android:value="@string/facebook_client_token" />
<meta-data android:name="io.sentry.dsn" android:value="https://abc@o0.ingest.sentry.io/1" />
```

Values may be literals or `@string/` references, so resolve each reference against the decoded resources. Manifest placeholders (`manifestPlaceholders`) are substituted at build time and appear as literals in the merged manifest.

#### `assets/` and `res/raw/`

Anything the developer drops in `src/main/assets/` ships byte for byte. This is where we find JSON config files with backend credentials, AWS Amplify's `awsconfiguration.json`/`amplifyconfiguration.json` (often in `res/raw/`), client certificates (`.p12`, `.bks`, `.pem`) for mutual TLS, pre-populated SQLite databases with test data, and the JavaScript or Dart assets of cross-platform frameworks.

#### Native libraries (`lib/<abi>/*.so`)

Moving a key into C/C++ via JNI is common advice on developer forums. It changes the tool you use, not the outcome:

```c
// The literal ends up in .rodata, readable with `strings`.
JNIEXPORT jstring JNICALL
Java_com_example_app_Keys_apiKey(JNIEnv *env, jobject thiz) {
    return (*env)->NewStringUTF(env, "AIzaSyD-EXAMPLE-EXAMPLE-EXAMPLE-EXAMPLE");
}
```

`strings -a -n 8 lib/arm64-v8a/libkeys.so` or `rabin2 -zz` finds plain literals. If the library XORs or splits the value, you hook the Java-side `Keys.apiKey()` with Frida and read the return value, which takes less time than reversing the de-obfuscation routine.

#### R8/ProGuard: what obfuscation does not hide

R8 (and ProGuard before it) shrinks, optimises and **renames** classes, methods and fields. That is all it does to code. Specifically, R8 does **not**:

- encrypt or encode string literals (keys, URLs, passwords remain verbatim in the DEX);
- touch `resources.arsc` values, `assets/`, `res/raw/` or manifest metadata (resource shrinking removes unused resources but never transforms the ones it keeps);
- affect native libraries.

The `mapping.txt` file that reverses the renaming is a build output uploaded to Play Console for crash de-obfuscation. It is not in the APK; if you do find one in `assets/` or the APK root, that is itself a leftover finding. Commercial and open-source obfuscators such as dProtect add string encryption on top of renaming (MASTG-KNOW-0033), but the decryption routine ships with the app and the plaintext exists in memory when used. Run APKiD (MASTG-TECH-0165) early to know which situation you are in.

#### Split APKs, App Bundles and XAPK

Apps distributed as Android App Bundles arrive on the device as a `base.apk` plus configuration splits (`split_config.arm64_v8a.apk`, density and language splits) and possibly dynamic feature modules. Native libraries usually live only in the ABI split, and feature modules can carry their own DEX and assets. Always pull every path that `pm path` returns and analyse them together. XAPK files from third-party stores are ZIPs of the same splits (MASTG-TECH-0145).

### iOS IPA anatomy

An IPA is a ZIP containing `Payload/<Name>.app/`, the application bundle. Unlike Android, a large part of the bundle is plain files on disk with no compilation step at all.

| Location | Contents | How you read it |
|---|---|---|
| `<Name>` (main Mach-O executable) | Compiled Swift/Objective-C, string literals in `__TEXT,__cstring` and related sections | `strings`, `rabin2 -zz`, radare2, Ghidra |
| `Info.plist` | App configuration, often custom keys and SDK identifiers | `plutil -p` |
| `GoogleService-Info.plist`, other `*.plist` | Firebase config, SDK configs, custom configuration plists | `plutil -p` |
| `Frameworks/*.framework`, `*.dylib` | Embedded dynamic frameworks, each with its own Mach-O, `Info.plist` and resources | Same as main binary |
| `PlugIns/*.appex` | App extensions, each with its own binary and plists | Same as main binary |
| `*.bundle` | Resource bundles (common with CocoaPods/SPM) containing JSON, plists, certificates | `find`, `plutil` |
| `Assets.car` | Compiled asset catalogue: images and *data assets* (arbitrary files) | `assetutil --info`, asset extraction tools |
| `*.json`, `*.txt`, `*.js`, `*.html`, certificates | Any file added to "Copy Bundle Resources" | Read directly |
| `embedded.mobileprovision` | Provisioning profile (development, ad hoc and enterprise builds) | `security cms -D -i` |

#### FairPlay encryption and why you need a decrypted IPA

Apps downloaded from the App Store have their executable code encrypted with Apple's FairPlay DRM. The encryption applies to the `__TEXT` segment of each Mach-O (main binary, frameworks, extensions) and is signalled by `LC_ENCRYPTION_INFO_64` with `cryptid 1`:

```bash
otool -l Payload/App.app/App | grep -A4 LC_ENCRYPTION_INFO
#           cmd LC_ENCRYPTION_INFO_64
#       cmdsize 24
#      cryptoff 16384
#     cryptsize 5341184
#       cryptid 1
```

Two practical consequences follow:

- **Resources are not encrypted.** Plists, JSON, bundles, `Assets.car` and JavaScript bundles in an App Store IPA are readable immediately. You can complete a large part of the resource review without a jailbreak.
- **Binary strings require decryption.** `strings` on an encrypted Mach-O returns mostly noise from the unencrypted segments. To review literals in code, either obtain the build from the client (a development or ad hoc IPA is not FairPlay-encrypted, though make sure it is built with the *release* configuration) or dump the decrypted binary from memory on a jailbroken device with frida-ios-dump (MASTG-TECH-0054) and confirm `cryptid 0` afterwards.

#### The Mach-O binary

Objective-C string literals are stored in `__TEXT,__cstring` and referenced from `__DATA,__cfstring` structures; non-ASCII literals go to `__TEXT,__ustring` as UTF-16. Swift string literals longer than 15 UTF-8 bytes are also emitted as C strings; shorter ones may be materialised as immediate values inside instructions (Swift's small-string representation), so they will not show up in `strings` at all. Most API keys are longer than 15 bytes, so `strings` remains effective, but do not treat a negative result as proof for short passwords or PINs.

Swift binaries routinely contain absolute source paths from `#file`/`#filePath` used by `fatalError`, `precondition` and logging, e.g. `/Users/jsmith/Projects/AppName/Sources/Network/APIClient.swift`. That leaks developer usernames and project structure.

#### `Info.plist` and other property lists

`Info.plist` is the place teams most often wire `.xcconfig` build settings into the app (`API_KEY = $(API_KEY)`), and it ships in the bundle. Like the Android Secrets Gradle Plugin, `.xcconfig` keeps the value out of Git, not out of the package. Expect also SDK identifiers such as `FacebookAppID`, `FacebookClientToken` and `GADApplicationIdentifier`, which are designed to be embedded.

`GoogleService-Info.plist` is copied into the bundle unchanged. Its keys (`API_KEY`, `GCM_SENDER_ID`, `PROJECT_ID`, `STORAGE_BUCKET`, `GOOGLE_APP_ID`, `DATABASE_URL`, `CLIENT_ID`, `REVERSED_CLIENT_ID`, `BUNDLE_ID`) mirror the Android resources above.

Look for other custom plists too (`Config.plist`, `Environment.plist`, `Credentials.plist`): teams often keep per-environment configurations side by side and ship all of them.

#### Embedded frameworks, bundles and `Assets.car`

Each framework under `Frameworks/` is its own Mach-O with its own strings and often its own `Info.plist` and resource bundle. In-house frameworks shared across a company's apps are a frequent source of keys, because the framework team assumes the app team will handle secrets and vice versa. Flutter (`App.framework`) and React Native code also live here.

`Assets.car` is a compiled asset catalogue. Besides images it can hold *data assets* (`NSDataAsset`), which are arbitrary files: JSON, certificates, ML models. `assetutil --info Assets.car` on macOS lists the entries and their types; third-party extractors can export the data assets for review.

#### Leftover source and build files

Xcode copies anything in a target's "Copy Bundle Resources" phase into the bundle. We regularly find `.swift`, `.m`, `.h`, `.xcconfig`, `README.md`, `.DS_Store`, `Podfile`, `.env` and JavaScript `.map` files. `embedded.mobileprovision`, present in development, ad hoc and enterprise builds, reveals the team identifier, certificate subjects and, for ad hoc builds, the UDIDs of registered test devices. MASTG-KNOW-0064 lists the broader family of non-production resources.

### Cross-platform framework packaging

Cross-platform frameworks add a second layer of packaging inside the APK or IPA, and each has its own habits for configuration and environment variables.

| Framework | Android location | iOS location | Notes |
|---|---|---|---|
| React Native | `assets/index.android.bundle` | `Payload/App.app/main.jsbundle` | Plain minified JS or Hermes bytecode |
| Expo (React Native) | `assets/app.config` plus the JS bundle | `EXConstants.bundle/app.config` plus `main.jsbundle` | `extra` config and `EXPO_PUBLIC_*` variables are inlined |
| Flutter | `lib/<abi>/libapp.so`, `assets/flutter_assets/` | `Frameworks/App.framework/App`, `Frameworks/App.framework/flutter_assets/` | Dart AOT snapshot plus plain assets |
| Cordova / Ionic | `assets/www/` | `Payload/App.app/www/` | Plain HTML/JS/CSS, often with source maps |
| Capacitor | `assets/public/`, `assets/capacitor.config.json` | `Payload/App.app/public/`, `capacitor.config.json` | Same as above |
| Xamarin / .NET MAUI | `assemblies/` or an assembly store blob | `.dll` files in the `.app` | .NET IL with UTF-16 user strings |
| Unity (IL2CPP) | `lib/<abi>/libil2cpp.so`, `assets/bin/Data/Managed/Metadata/global-metadata.dat` | `Frameworks/UnityFramework.framework`, `Data/Managed/Metadata/global-metadata.dat` | String literals live in `global-metadata.dat` |

#### React Native and Hermes

The whole JavaScript application is one bundle. Since React Native 0.70 Hermes is the default engine, so the bundle is usually Hermes bytecode rather than text:

```bash
file assets/index.android.bundle
# assets/index.android.bundle: Hermes JavaScript bytecode, version 96
```

Hermes keeps its string table uncompressed, so `strings -n 8` on the bundle already shows keys and URLs. For context (which function uses the value), decompile with hermes-dec (`hbc-decompiler assets/index.android.bundle out.js`). Libraries such as `react-native-config` read a `.env` file at build time and expose the values to JavaScript *and* to native code (on Android via `BuildConfig` and resources, on iOS via a generated Objective-C class and optionally `Info.plist`), so the same key can appear in three places. Expo's documentation is explicit that `EXPO_PUBLIC_` variables are inlined into the bundle and must not hold secrets.

#### Flutter

Dart code is compiled ahead of time into `libapp.so` (Android) or `App.framework/App` (iOS). Values passed with `--dart-define` or `--dart-define-from-file` and read with `String.fromEnvironment` are compile-time constants inside that snapshot. `flutter build --obfuscate --split-debug-info` renames symbols; it does not encrypt string literals. `strings` often recovers ASCII literals directly; blutter (MASTG-TECH-0156) gives you the object pool (`pp.txt`) with strings attached to the functions that use them.

The single most common Flutter leak we see is the `flutter_dotenv` package: it requires you to list `.env` as an asset in `pubspec.yaml`, so the file ships verbatim at `flutter_assets/.env`.

#### Cordova, Ionic and Capacitor

These are web apps in a native shell. The `www/` or `public/` directory is the deployed web build: readable JavaScript, frequently with `*.js.map` source maps whose `sourcesContent` field holds the original, unminified TypeScript including comments. Environment files (`environment.prod.ts` in Angular-based Ionic apps) are compiled straight into `main.*.js`. We have also found whole `.git` directories copied into `www/` by careless build scripts.

#### Xamarin and .NET MAUI

Managed code ships as .NET assemblies. Depending on the toolchain version, they are individual `.dll` files under `assemblies/` (often LZ4-compressed with an `XALZ` header) or packed into an assembly store blob that tools such as pyxamstore can unpack. Once you have the DLLs, decompile with ILSpy (`ilspycmd`) or dnSpy. String literals live in the assembly's user-string heap as **UTF-16LE**, so plain `strings` misses them; use `strings -el`. On iOS the code is AOT-compiled, but the DLLs are still present in the bundle for metadata and their user strings remain readable. Note that Xamarin reached end of support in May 2024; MAUI is its successor.

### Types of hardcoded secrets and how much they matter

The table below is how we classify what we find. The "Designed to be public" column reflects the vendor's own documentation: a value designed to be embedded is only a finding if it is misconfigured or used for something it was not designed for.

| Type | Typical shape | Designed to be public? | What decides severity |
|---|---|---|---|
| Google Cloud / Firebase API key | `AIza` + 35 chars | Yes, for Firebase and client SDKs | API restrictions, application restrictions, which billable APIs are enabled on the project |
| Firebase project config | Project ID, app ID, DB URL, bucket | Yes | Realtime Database, Firestore and Storage security rules; App Check enforcement |
| AWS access key | `AKIA…` (long-term) or `ASIA…` + session token | No | IAM permissions of the principal |
| AWS Cognito identity pool ID | `<region>:<uuid>` | Yes | Permissions of the unauthenticated IAM role |
| AWS AppSync API key | `da2-…` | Partly (intended for public, read-mostly APIs) | Which GraphQL operations the key authorises |
| Stripe keys | `pk_live_…` / `sk_live_…` / `rk_live_…` | Only `pk_` | `sk_` is full account access; `rk_` depends on restrictions |
| OAuth client secret | `GOCSPX-…` (Google), arbitrary strings elsewhere | No, and native apps should not have one | Whether the client is confidential and which grants it can use |
| Messaging and email | Slack `xoxb-`/`xoxp-`, Slack webhooks, SendGrid `SG.`, Twilio SID + auth token, Mailgun `key-` | No | Send capability from the organisation's identity, data access |
| Source control and CI | `ghp_`, `github_pat_`, `glpat-` | No | Repository and organisation scopes |
| AI / ML services | OpenAI `sk-…`, Anthropic `sk-ant-…`, Gemini via `AIza` keys | No | Direct billing exposure, data access to stored files or fine-tunes |
| Search / analytics | Algolia app ID + search key, Mixpanel/Segment write keys, Sentry DSN | Mostly yes | Algolia admin keys are critical; write keys allow data pollution only |
| Private keys and certificates | `-----BEGIN … PRIVATE KEY-----`, `.p12`, `.bks`, `.jks` | Never for private keys | What the key authenticates or decrypts; mTLS client certs are shared by every install |
| Hardcoded user credentials | Test account passwords, basic-auth headers, DB connection strings | No | Account privilege, whether it exists in production |
| Staging URLs, internal hosts | `api-staging.`, `uat.`, `10.x.x.x`, `*.internal` | Not secret, but not meant for users | Reachability from the internet and the security of what is behind them |
| Developer identities | Emails, usernames, file paths | Not secret | Usually Low/Info; supports social engineering |

#### Firebase configuration is public by design

Firebase's own documentation states that API keys for Firebase services are not secret: they identify your project to Google's servers and are needed by every client. Access control is enforced by **Firebase Security Rules** (Realtime Database, Cloud Firestore, Cloud Storage) and, optionally, **App Check**. So a tester who reports "Firebase API key hardcoded in strings.xml" as a vulnerability has reported nothing.

The real findings are next to the key:

- **Open database or storage rules.** Rules such as the following, often left over from "test mode", let anyone read and write the whole database using only the public config:

  ```json
  {
    "rules": {
      ".read": true,
      ".write": true
    }
  }
  ```

  Rules that only check `auth != null` are nearly as weak when email/password or anonymous sign-up is enabled, because anyone can create an account with the same public API key.
- **An unrestricted key on a project with other billable APIs.** A Firebase Android key is an ordinary Google Cloud API key. If the project also has, for example, Maps, Places or the Generative Language (Gemini) API enabled and the key has no API restrictions, the "public" Firebase key becomes a billing credential for those services.
- **Secrets in Remote Config.** Remote Config values are fetched by any client with the public config, so a secret stored there is still a secret handed to every user.

#### OAuth client secrets

RFC 8252 treats native apps as *public clients*: they cannot keep a secret, so they should use the authorisation code flow with PKCE and no client secret. Google's Android and iOS OAuth client types do not even have one. A client secret inside a mobile app usually means the developer registered a "web" (confidential) client and reused it. Anyone holding that secret can impersonate the app to the authorisation server, and depending on configuration may use grants the mobile app never needed (for example client credentials).

#### Private keys and certificates

Public certificates (`.cer`, `.crt`, pinning hashes) are fine to ship. Private keys are not, whatever they are for: a TLS client key for mutual TLS gives every attacker the same "client identity" as the genuine app, a JWT signing key lets them mint tokens the backend trusts, and a symmetric data key decrypts every user's data. A `.p12` or `.bks` file is protected only by its password, which in our experience is in the same package (or is `changeit`, `password` or the app name). The detection of hardcoded keys used by crypto APIs is covered by MASTG-TEST-0212, MASTG-TEST-0213 and MASTG-TEST-0214 in our [MASWE-0003 note](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/).

#### Staging URLs and developer emails

These are not credentials, and their severity depends entirely on what is behind them. A staging API that is reachable from the internet, runs older code, has debug endpoints enabled or accepts test credentials is often the easiest way into production data, because staging databases are frequently restored from production snapshots. A developer email in a comment is Informational unless it is part of a wider pattern (for example, alongside that developer's hardcoded test password).

## Testing

OWASP has not published MASTG tests for MASWE-0004. The procedures below are our methodology; each is self-contained, but on a real engagement you run them in order, because the discovery procedures feed the validation procedure at the end.

- [Static secret discovery in the APK](#static-secret-discovery-in-the-apk)
- [Static secret discovery in the IPA](#static-secret-discovery-in-the-ipa)
- [Secrets in cross-platform framework bundles](#secrets-in-cross-platform-framework-bundles)
- [Secrets in dependency and SDK configuration](#secrets-in-dependency-and-sdk-configuration)
- [Build and developer leftovers](#build-and-developer-leftovers)
- [Recovering obfuscated secrets at runtime](#recovering-obfuscated-secrets-at-runtime)
- [Validating whether a discovered key is live](#validating-whether-a-discovered-key-is-live)

All discovery procedures use the same pattern file. Save it once as `secrets.regex` and run `export SECRETS="$PWD/secrets.regex"` so every command below can find it. It is deliberately broad; you triage the noise afterwards.

```text
AIza[0-9A-Za-z_-]{35}
(AKIA|ASIA)[0-9A-Z]{16}
-----BEGIN ([A-Z]+ )?PRIVATE KEY-----
xox[abposr]-[0-9A-Za-z-]{10,}
hooks\.slack\.com/services/[0-9A-Za-z/_-]+
(sk|rk)_live_[0-9A-Za-z]{20,}
gh[pousr]_[0-9A-Za-z]{36}
github_pat_[0-9A-Za-z_]{40,}
glpat-[0-9A-Za-z_-]{20}
SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}
AC[0-9a-f]{32}
sk-(proj-|ant-)?[0-9A-Za-z_-]{20,}
GOCSPX-[0-9A-Za-z_-]{28}
da2-[0-9a-z]{26}
eyJ[0-9A-Za-z_-]{10,}\.eyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]*
[a-z0-9-]+\.firebaseio\.com
[a-z0-9-]+\.firebasedatabase\.app
[a-z0-9.-]+\.s3[.-]([a-z0-9-]+\.)?amazonaws\.com
[a-z0-9-]+\.appsync-api\.[a-z0-9-]+\.amazonaws\.com
```

### Static secret discovery in the APK

#### Overview

- **Platform:** Android
- **Type:** static (package and code)
- **Checks:** literals in DEX, compiled resources, manifest metadata, assets, raw resources and native libraries that are credentials, keys or other sensitive values.

#### Prerequisites

- The release APK and **all** split APKs (MASTG-TECH-0003). Do not test a debug build: build types can carry different keys.
- jadx, Apktool, aapt2 (Android SDK build tools), `strings`/rabin2, gitleaks, optionally Apkleaks and APKiD.

#### Steps

1. Pull every APK that makes up the installed app:

   ```bash
   mkdir -p apk && cd apk
   for p in $(adb shell pm path com.example.app | cut -d: -f2 | tr -d '\r'); do
     adb pull "$p"
   done
   ls   # base.apk split_config.arm64_v8a.apk split_config.en.apk ...
   ```

2. Check whether an obfuscator with string encryption is in play, so you know how much to trust negative static results:

   ```bash
   apkid base.apk
   ```

3. Decode resources and the manifest, and decompile the bytecode:

   ```bash
   apktool d -f base.apk -o decoded
   jadx -d jadx-out base.apk split_*.apk
   for s in split_*.apk; do unzip -o -q "$s" -d "splits/${s%.apk}"; done
   ```

4. Run the regex pass over everything, including binaries (`-a`), and keep only unique matches:

   ```bash
   grep -rEnoa -f "$SECRETS" decoded jadx-out splits | sort -u > hits-regex.txt
   wc -l hits-regex.txt
   ```

5. Run a keyword pass over decompiled sources, excluding the big framework packages to keep the signal readable (review them separately later if the app is small):

   ```bash
   grep -rniE '(api[_-]?key|secret|passw(or)?d|bearer|authorization|client[_-]?secret|private[_-]?key|x-api-key)' \
     jadx-out/sources \
     | grep -vE '^jadx-out/sources/(androidx|android|kotlin|kotlinx|com/google|okhttp3|okio|retrofit2)/' \
     > hits-keyword.txt
   ```

   Where identifier names survived (unobfuscated builds, or the client's source code in a grey-box test), a semgrep rule (saved as `secret-constants.yml`) over the decompiled Java catches secret-like constants by name and length. On R8-renamed code the name filter is useless and the regex pass is what finds the values.

   ```yaml
   rules:
     - id: secret-like-string-constant
       languages: [java]
       severity: WARNING
       message: String constant $NAME looks like a credential
       patterns:
         - pattern: $TYPE $NAME = "$VALUE";
         - metavariable-regex:
             metavariable: $NAME
             regex: (?i).*(api_?key|secret|token|passw|client_?secret|private_?key).*
         - metavariable-regex:
             metavariable: $VALUE
             regex: .{12,}
   ```

   ```bash
   semgrep --metrics=off --config secret-constants.yml jadx-out/sources
   ```

6. Review resources and manifest metadata explicitly; these are the places scanners under-report because the key name, not the value, is the signal:

   ```bash
   grep -nE 'name="(google_api_key|google_crash_reporting_api_key|firebase_database_url|google_storage_bucket|project_id|default_web_client_id)"' \
     decoded/res/values/strings.xml
   grep -n 'meta-data' decoded/AndroidManifest.xml
   grep -rniE 'key|secret|token|password|endpoint|url' decoded/res/values*/strings.xml | grep -viE 'hint|label|title|desc'
   ```

7. Inventory files that are interesting by type alone:

   ```bash
   find decoded/assets decoded/res/raw splits -type f \
     \( -iname '*.json' -o -iname '*.properties' -o -iname '*.env' -o -iname '*.yml' -o -iname '*.xml' \
        -o -iname '*.p12' -o -iname '*.pfx' -o -iname '*.bks' -o -iname '*.jks' -o -iname '*.keystore' \
        -o -iname '*.pem' -o -iname '*.key' -o -iname '*.db' -o -iname '*.sqlite' \) 2>/dev/null
   ```

8. Extract strings from native libraries (from the ABI split if the base APK has no `lib/`):

   ```bash
   for so in $(find decoded/lib splits -name '*.so'); do
     echo "== $so"; strings -a -n 8 "$so" | grep -Ef "$SECRETS"
   done
   rabin2 -zz splits/split_config.arm64_v8a/lib/arm64-v8a/libnative-lib.so | grep -iE 'key|secret|token|http'
   ```

9. Run the automated scanners as a second opinion, not a replacement:

   ```bash
   gitleaks dir decoded -v --report-path gitleaks-decoded.json      # gitleaks >= 8.19
   gitleaks dir jadx-out -v --report-path gitleaks-jadx.json
   # older gitleaks: gitleaks detect --no-git -s decoded -v
   apkleaks -f base.apk -o apkleaks.txt
   ```

10. For every candidate, open the code location in jadx-gui and trace the cross-references to find **where the value is used**: which host it is sent to, in which header, or which crypto API consumes it. Hardcoded keys passed to `SecretKeySpec` are MASTG-TEST-0212 territory; record them and handle them under MASWE-0003.

#### Observation

A list of candidate values, each with: the file and location (class/method, resource name or asset path), the decoded value (redacted in the report), the code that uses it and the destination it is sent to.

#### Evaluation

The test **fails** if the package contains any value that grants access, spends money, decrypts data or authenticates to a service and that is *not* designed by its vendor to be embedded in clients, or if a designed-to-be-public value is configured in a way that makes it effectively a secret (for example an unrestricted Google key on a project with billable APIs). Severity is assigned after [validation](#validating-whether-a-discovered-key-is-live).

The test **passes** for a value that is designed to be public *and* has been confirmed as correctly restricted, and for values that are only identifiers (project IDs, app IDs, sender IDs).

Common false positives to eliminate before reporting: Google Play services and Firebase SDK internal constants, sample keys in library documentation strings, `AIza` keys that belong to an SDK vendor rather than the app owner, test fixtures from bundled libraries, base64 blobs that decode to images or certificates (public certificates are fine), and placeholders such as `YOUR_API_KEY`.

#### Demo

A minimal vulnerable Kotlin client:

```kotlin
object ApiConfig {
    const val BASE_URL = "https://api-staging.example.com/v2/"
    const val MAPS_KEY = "AIzaSyB-EXAMPLEKEY-00000000000000000000"
}

class AuthInterceptor : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        val creds = Base64.encodeToString("svc_mobile:Winter2024!".toByteArray(), Base64.NO_WRAP)
        val req = chain.request().newBuilder().header("Authorization", "Basic $creds").build()
        return chain.proceed(req)
    }
}
```

After R8, `ApiConfig` is renamed or removed, but the literals survive and the regex and keyword passes surface them:

```text
jadx-out/sources/a/b/c.java:9:AIzaSyB-EXAMPLEKEY-00000000000000000000
jadx-out/sources/a/b/d.java:14:    String strEncodeToString = Base64.encodeToString("svc_mobile:Winter2024!".getBytes(...), 2);
jadx-out/sources/a/b/d.java:15:    ... .header("Authorization", "Basic " + strEncodeToString) ...
jadx-out/sources/a/b/e.java:22:    return new Retrofit.Builder().baseUrl("https://api-staging.example.com/v2/") ...
```

Three findings: a Google key to classify and validate, a service account password sent as HTTP Basic credentials (fail regardless of obfuscation), and a staging base URL in a release build.

### Static secret discovery in the IPA

#### Overview

- **Platform:** iOS
- **Type:** static (package and binary)
- **Checks:** literals in the main executable, frameworks and extensions; property lists; resource bundles; data assets and loose resource files.

#### Prerequisites

- An IPA. For resources, an App Store (encrypted) IPA is enough. For binary strings you need a **decrypted** binary: a release-configuration build from the client, or a dump with frida-ios-dump from a jailbroken device (MASTG-TECH-0054).
- macOS with Xcode command line tools (`otool`, `plutil`, `strings`, `assetutil`), or Linux with `libplist-utils`; radare2/rabin2; gitleaks.

#### Steps

1. Unpack and confirm the encryption state of every Mach-O:

   ```bash
   unzip -q App.ipa -d ipa && cd ipa/Payload/*.app
   APP=$(basename "$PWD" .app)
   for b in "$APP" Frameworks/*.framework/* PlugIns/*.appex/*; do
     [ -f "$b" ] && file "$b" | grep -q Mach-O && \
       printf '%s: ' "$b" && (otool -l "$b" | grep -m1 cryptid || echo "no LC_ENCRYPTION_INFO")
   done
   ```

   `cryptid 1` means the strings pass on that binary is meaningless until you decrypt it.

2. Review every property list. Convert binary plists on the fly:

   ```bash
   find . -name '*.plist' -print0 | while IFS= read -r -d '' f; do
     echo "== $f"; plutil -p "$f"
   done > ../../../plists.txt
   grep -niE 'key|secret|token|password|client|url|endpoint' ../../../plists.txt
   ```

   On Linux, replace `plutil -p` with `plistutil -i "$f" -o -`. Read `Info.plist`, `GoogleService-Info.plist` and any custom configuration plist in full rather than relying on the grep.

3. Run the regex pass over the whole bundle, binaries included:

   ```bash
   grep -rEnoa -f "$SECRETS" . | sort -u > ../../../hits-regex.txt
   ```

4. Extract strings from each decrypted binary and look for keys, URLs and developer paths:

   ```bash
   strings -a -n 8 "$APP" > ../../../strings-main.txt
   grep -Ef "$SECRETS" ../../../strings-main.txt
   grep -iE 'https?://' ../../../strings-main.txt | sort -u
   grep -E '^/Users/[^/]+/' ../../../strings-main.txt | sort -u | head
   rabin2 -zz "$APP" | grep -iE 'secret|apikey|api_key|token|passw'
   for f in Frameworks/*.framework; do
     n=$(basename "$f" .framework); [ -f "$f/$n" ] && strings -a -n 8 "$f/$n" | grep -Ef "$SECRETS"
   done
   ```

5. Inventory files by type, including inside resource bundles:

   ```bash
   find . -type f \( -iname '*.json' -o -iname '*.env' -o -iname '*.xcconfig' -o -iname '*.p12' -o -iname '*.pfx' \
     -o -iname '*.pem' -o -iname '*.key' -o -iname '*.der' -o -iname '*.sqlite' -o -iname '*.db' -o -iname '*.js' \)
   ```

6. List data assets in the asset catalogue (macOS):

   ```bash
   assetutil --info Assets.car | grep -iE '"AssetType"|"Name"' | paste - - | grep -i data
   ```

   Export any data asset whose name suggests configuration or key material and review it.

7. For each candidate in the binary, find the code that references it in radare2 (MASTG-TECH-0070) and identify the consumer: a `URLRequest` header, an SDK initialiser, or a crypto API such as `SecKeyCreateWithData`/`CCCrypt` (the latter belong to MASTG-TEST-0213/0214 under MASWE-0003).

8. Run gitleaks over the unpacked bundle as a second opinion:

   ```bash
   gitleaks dir . -v --report-path ../../../gitleaks-ipa.json
   ```

#### Observation

The same evidence as for Android: location (binary and section, plist key, file path), value, consumer and destination. Note explicitly whether the binary analysed was decrypted, because that bounds the confidence of a negative result.

#### Evaluation

Identical criteria to the APK procedure. Additionally, record as a limitation (not a pass) if binary strings could not be reviewed because no decrypted binary was available.

#### Demo

```swift
enum Secrets {
    static let sendGridKey = "SG.EXAMPLEexampleEXAMPLEex.EXAMPLEexampleEXAMPLEexampleEXAMPLEexample1"
    static let backendURL = "https://uat-api.example.com"
}

func sendReceipt(to email: String) {
    var req = URLRequest(url: URL(string: "https://api.sendgrid.com/v3/mail/send")!)
    req.setValue("Bearer \(Secrets.sendGridKey)", forHTTPHeaderField: "Authorization")
    // ...
}
```

On the decrypted binary:

```text
$ strings -a -n 8 MyApp | grep -E 'SG\.|https://'
SG.EXAMPLEexampleEXAMPLEex.EXAMPLEexampleEXAMPLEexampleEXAMPLEexample1
https://uat-api.example.com
https://api.sendgrid.com/v3/mail/send
/Users/jsmith/Code/MyApp/MyApp/Networking/Mailer.swift
```

A SendGrid key with send permissions lets anyone send email as the company's verified domain. The UAT host and the developer path are separate, lower-severity findings.

### Secrets in cross-platform framework bundles

#### Overview

- **Platform:** Android and iOS
- **Type:** static (package)
- **Checks:** configuration and literals inside React Native, Expo, Flutter, Cordova/Ionic/Capacitor, Xamarin/MAUI and Unity payloads, which generic scanners often miss because they are bytecode, snapshots or UTF-16.

#### Prerequisites

- The unpacked APK/IPA from the previous procedures.
- hermes-dec, blutter (Flutter, Android), a JavaScript beautifier, ILSpy (`ilspycmd`) and pyxamstore for .NET, `file`, `strings`.

#### Steps

1. Identify the framework from tell-tale files:

   ```bash
   find decoded splits ipa -type f \( -name 'index.android.bundle' -o -name 'main.jsbundle' -o -name 'libhermes*.so' \
     -o -name 'libapp.so' -o -name 'libflutter.so' -o -name 'cordova.js' -o -name 'capacitor.config.json' \
     -o -name 'libmonodroid.so' -o -name '*.dll' -o -name 'assemblies*.blob' -o -name 'global-metadata.dat' -o -name 'app.config' \) 2>/dev/null
   find ipa -type d \( -name 'App.framework' -o -name 'hermes.framework' -o -name 'www' -o -name 'public' -o -name 'EXConstants.bundle' \)
   ```

2. **React Native / Expo.** Determine the bundle format, then search it:

   ```bash
   B=decoded/assets/index.android.bundle      # iOS: ipa/Payload/App.app/main.jsbundle
   file "$B"
   strings -n 8 "$B" | grep -Ef "$SECRETS"
   strings -n 8 "$B" | grep -iE 'api[_-]?key|secret|token|https?://' | sort -u | head -100
   hbc-decompiler "$B" rn-decompiled.js         # only if Hermes bytecode
   cat decoded/assets/app.config 2>/dev/null | python3 -m json.tool   # Expo: look at "extra"
   ```

   If the app uses `react-native-config`, check `BuildConfig` (Android) and the plists (iOS) for the same variable names.

3. **Flutter.** Check the plain assets first, then the snapshot:

   ```bash
   find . -path '*flutter_assets*' -type f | grep -vE '\.(png|jpg|ttf|otf|webp)$'
   unzip -p base.apk 'assets/flutter_assets/.env' 2>/dev/null
   strings -a -n 8 splits/split_config.arm64_v8a/lib/arm64-v8a/libapp.so | grep -Ef "$SECRETS"
   python3 blutter.py splits/split_config.arm64_v8a/lib/arm64-v8a out_blutter   # then review out_blutter/pp.txt
   ```

   On iOS, run `strings` against `Frameworks/App.framework/App` (decrypted).

4. **Cordova / Ionic / Capacitor.** Grep the web build and look for source maps:

   ```bash
   W=decoded/assets/www     # Capacitor: decoded/assets/public ; iOS: ipa/Payload/App.app/www or public
   grep -rEnoa -f "$SECRETS" "$W"
   find "$W" -name '*.map' | head
   find "$W" -name '.git' -o -name '.env' -o -name 'environment*.ts'
   ```

   If `.map` files exist, extract `sourcesContent` and review the original sources and comments:

   ```bash
   python3 -c 'import json,sys; m=json.load(open(sys.argv[1])); [print("// ==", s, "\n", c) for s,c in zip(m["sources"], m.get("sourcesContent") or [])]' "$W/main.js.map" > original-sources.txt
   ```

5. **Xamarin / .NET MAUI.** Unpack the assemblies, then search UTF-16 strings and decompile:

   ```bash
   # If assemblies are packed in a blob, unpack it with pyxamstore first (see its README).
   for d in $(find . -name '*.dll'); do strings -el "$d" | grep -Ef "$SECRETS" && echo "  <- $d"; done
   ilspycmd -p -o il-out path/to/App.dll
   grep -rniE 'apikey|secret|password|connectionstring' il-out
   ```

6. **Unity (IL2CPP).** String literals for managed code live in `global-metadata.dat`:

   ```bash
   strings -a -n 8 decoded/assets/bin/Data/Managed/Metadata/global-metadata.dat | grep -Ef "$SECRETS"
   ```

#### Observation

Framework identified, the location of each candidate inside the framework payload (bundle offset, asset path, function in decompiled output, assembly and type) and the consumer of the value.

#### Evaluation

Same criteria as the APK and IPA procedures. A `.env` file or source map with secrets in the package is a fail even if the app never reads the secret at runtime; the value is exposed either way.

#### Demo

A Flutter app using `flutter_dotenv`:

```yaml
# pubspec.yaml
flutter:
  assets:
    - .env
```

```text
$ unzip -p app.apk 'assets/flutter_assets/.env'
API_BASE=https://api.example.com
OPENAI_API_KEY=sk-proj-EXAMPLEexampleEXAMPLEexample
SENTRY_DSN=https://abc123@o0.ingest.sentry.io/42
```

The OpenAI key is a direct billing credential and a fail. The Sentry DSN is designed to be public and is not.

### Secrets in dependency and SDK configuration

#### Overview

- **Platform:** Android and iOS
- **Type:** static (package), with vendor documentation review
- **Checks:** keys and configuration that SDKs require at initialisation, configuration files that libraries bring with them, and secrets embedded by first- or third-party libraries themselves.

#### Prerequisites

- Decoded package and decompiled sources from the earlier procedures.
- An inventory of dependencies: from jadx package names and `Frameworks/`, or an SBOM (MASTG-TECH-0130 for Android, MASTG-TECH-0132 for iOS).

#### Steps

1. List the SDKs present. On Android, top-level packages in `jadx-out/sources` are a fast first pass; on iOS, `Frameworks/`, `*.bundle` names and CocoaPods acknowledgement plists:

   ```bash
   find jadx-out/sources -maxdepth 3 -type d | sed 's|jadx-out/sources/||' | sort | head -100
   ls ipa/Payload/*.app/Frameworks ipa/Payload/*.app/*.bundle 2>/dev/null
   find ipa -iname '*acknowledgements*.plist' -exec plutil -p {} \; | grep -i '"Title"'
   ```

2. Find SDK initialisation calls and the arguments passed to them. Search for common entry points and inspect the arguments in context:

   ```bash
   grep -rnE '\.(initialize|init|configure|setup|start|with)\(' jadx-out/sources \
     | grep -iE 'key|token|secret|dsn|appid|clientid' | head -50
   ```

   On iOS, use radare2 cross-references from the SDK's initialiser symbol (for example a `configure(withAPIKey:)` selector) back to the string that feeds it.

3. Inspect known library configuration files:

   ```bash
   find decoded splits ipa -type f \( -name 'awsconfiguration.json' -o -name 'amplifyconfiguration.json' \
     -o -name 'auth_config*.json' -o -name 'Auth0.plist' -o -name 'branch.json' -o -name '*sdk*config*.json' \
     -o -name 'GoogleService-Info*.plist' -o -name 'firebase*.json' \) 2>/dev/null
   ```

   Look at multiple `GoogleService-Info-*.plist` or environment-suffixed configs: shipping staging and production Firebase projects together is common.

4. For each key found, classify it with the vendor's documentation: is this the client-side key the vendor intends you to embed (publishable key, client token, DSN, search-only key, write key), or a server-side secret (secret key, admin key, management token, server API key)? Record the documentation reference in your notes.

5. Check whether any library ships **its own** credentials (the vendor's key, a shared default password, a test certificate) by searching the library packages you excluded in the APK procedure:

   ```bash
   grep -rEnoa -f "$SECRETS" jadx-out/sources/com jadx-out/sources/io jadx-out/sources/net | grep -v '/com/google/'
   ```

#### Observation

A table of SDKs, the identifiers or keys each uses, their classification (client-side by design or server-side secret) with the vendor reference, and the location in the package.

#### Evaluation

The test **fails** if a server-side secret for any SDK or service is present, if a client-side key is used with a scope it was not designed for (for example an Algolia key with `addObject`/`deleteObject` ACLs, or an AppSync API key on an API that exposes user data), or if a library embeds credentials that give access to the app owner's or vendor's resources. Vendor-shipped credentials should also be reported to the client as a supply-chain issue for them to raise with the vendor.

#### Demo

An Amplify configuration file bundled in `res/raw/`:

```json
{
  "api": {
    "plugins": {
      "awsAPIPlugin": {
        "ordersApi": {
          "endpointType": "GraphQL",
          "endpoint": "https://abcd1234.appsync-api.eu-west-2.amazonaws.com/graphql",
          "region": "eu-west-2",
          "authorizationType": "API_KEY",
          "apiKey": "da2-exampleexampleexampleexa"
        }
      }
    }
  }
}
```

An AppSync API key is a legitimate client-side mechanism for public, read-only APIs. Whether this is a fail depends on what the `ordersApi` schema lets an API-key caller read or mutate, which is what the [validation procedure](#validating-whether-a-discovered-key-is-live) establishes.

### Build and developer leftovers

#### Overview

- **Platform:** Android and iOS
- **Type:** static (package)
- **Checks:** staging/integration endpoints, internal hostnames and IP ranges, developer identities, source code and source maps, version-control metadata, provisioning profiles and other files that should not be in a release package.

#### Prerequisites

- Decoded APK and unpacked IPA.

#### Steps

1. Look for files that should never ship:

   ```bash
   find decoded splits ipa -type f \( -name '*.java' -o -name '*.kt' -o -name '*.swift' -o -name '*.m' -o -name '*.h' \
     -o -name '*.c' -o -name '*.cpp' -o -name '*.map' -o -name '*.env' -o -name '.env*' -o -name '*.xcconfig' \
     -o -name '.DS_Store' -o -name '*.orig' -o -name '*.bak' -o -name '*.log' -o -name 'mapping.txt' \
     -o -name 'Podfile*' -o -name '*.gradle' -o -name 'local.properties' -o -name 'README*' \) 2>/dev/null
   find decoded splits ipa -type d -name '.git' 2>/dev/null
   ```

2. Find non-production endpoints and internal addresses in every text and binary source:

   ```bash
   grep -rEhoa 'https?://[A-Za-z0-9._-]+' decoded jadx-out splits ipa 2>/dev/null | sort -u > urls.txt
   grep -iE '(dev|staging|stage|stg|uat|qa|test|preprod|sandbox|internal|local)[.-]' urls.txt
   grep -rEhoa '\b(10\.[0-9]{1,3}|192\.168|172\.(1[6-9]|2[0-9]|3[01]))\.[0-9]{1,3}\.[0-9]{1,3}\b' decoded jadx-out ipa | sort -u
   grep -rEhoa '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' decoded jadx-out ipa | sort -u
   ```

3. Check for developer paths and machine names in binaries:

   ```bash
   strings -a ipa/Payload/MyApp.app/MyApp | grep -E '^/Users/|^/home/|^C:\\Users\\' | sort -u | head
   ```

4. Decode the provisioning profile, if present:

   ```bash
   security cms -D -i ipa/Payload/*.app/embedded.mobileprovision > profile.plist
   plutil -p profile.plist | grep -E 'TeamName|TeamIdentifier|ProvisionedDevices|get-task-allow' -A2
   ```

5. For each staging or internal host, check (passively first, then with a single request if in scope) whether it resolves and is reachable from the internet, and whether it is listed in the engagement scope before you interact with it further.

#### Observation

The list of leftover files with paths, the set of non-production URLs and whether each resolves/is reachable, developer identities found, and the provisioning profile type.

#### Evaluation

The test **fails** if the release package contains source files, source maps with `sourcesContent`, version-control metadata, credentials for test accounts, or non-production endpoints that are reachable from the internet. Unreachable staging hostnames, developer usernames in file paths and email addresses are reported as Low or Informational. An ad hoc or enterprise profile with `get-task-allow` in a build you were told is the release build is a MASWE-0061 finding; cross-reference it.

### Recovering obfuscated secrets at runtime

#### Overview

- **Platform:** Android and iOS
- **Type:** dynamic
- **Checks:** whether a secret that static analysis could not recover (string encryption, native assembly, white-box) is still obtainable by an attacker. This turns "we suspect a key is in there" into a demonstrated finding.

#### Prerequisites

- A device you can instrument (rooted/jailbroken, or a repackaged app with Frida Gadget), Frida, and an interception proxy configured with pinning bypassed where necessary (MASTG-TECH-0120).

#### Steps

1. **Proxy the traffic first.** Exercise the feature that uses the third-party service and look in Burp or mitmproxy for keys in headers (`Authorization`, `x-api-key`, `X-Goog-Api-Key`), query strings (`?key=`, `?access_token=`) and bodies. If the app talks to the vendor directly, the key is on the wire and the obfuscation is moot.

2. **Hook the consumer on Android.** If the network library is not renamed, hook header construction:

   ```javascript
   Java.perform(() => {
     const Builder = Java.use('okhttp3.Request$Builder');
     ['header', 'addHeader'].forEach((m) => {
       Builder[m].implementation = function (name, value) {
         if (/key|token|auth|secret/i.test(name)) console.log(`[okhttp] ${name}: ${value}`);
         return this[m](name, value);
       };
     });
   });
   ```

   If OkHttp has been renamed by R8, hook the app's own getter instead (the method that returns the decrypted string), identified via jadx cross-references to the call site.

3. **Hook the consumer on iOS:**

   ```javascript
   const m = ObjC.classes.NSMutableURLRequest['- setValue:forHTTPHeaderField:'];
   Interceptor.attach(m.implementation, {
     onEnter(args) {
       const field = new ObjC.Object(args[3]).toString();
       if (/key|token|auth|secret/i.test(field)) console.log(`[urlreq] ${field}: ${new ObjC.Object(args[2])}`);
     }
   });
   ```

   Swift `URLRequest` normally forwards to this method; if nothing is printed, rely on the proxy.

4. **Hook crypto key construction** when the secret is a key: `javax.crypto.spec.SecretKeySpec.$init` on Android, `CCCrypt` or `SecKeyCreateWithData` on iOS. Details are in the [MASWE-0003 note](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/).

#### Observation

The plaintext secret as captured at runtime, with the hook or proxy evidence and the time it took.

#### Evaluation

The test **fails** if the secret can be recovered at runtime. Report it as the same MASWE-0004 finding, noting that obfuscation was present and was bypassed, and how long it took. Obfuscation that adds a few minutes of work does not lower the severity.

### Validating whether a discovered key is live

#### Overview

- **Platform:** independent of platform (network calls to the service that issued the credential)
- **Type:** dynamic, external
- **Checks:** whether a candidate secret is currently valid, which account/project it belongs to, and what it grants, using the smallest read-only request that answers each question.

> **Warning:** Only validate credentials against systems covered by your written authorisation. A credential found in your client's app may belong to a third party (an SDK vendor, a partner, a previous contractor), and the client cannot authorise access to someone else's account. Agree in the rules of engagement whether you may make live calls with discovered credentials at all. Never use a credential beyond what is needed to confirm validity and scope: no data download, no writes, no privilege escalation, no pivoting. If you are not authorised, report the finding as "unverified" with the evidence of format, location and usage, and recommend rotation anyway.

#### Prerequisites

- Written confirmation that live validation is in scope, and for which services.
- A dedicated, logged testing host with a fixed egress IP (the client's provider logs will show your calls; tell them the IP).
- A clean shell: do not load credentials into your normal CLI profiles. Pass them as environment variables in a subshell and clear history afterwards.

#### Steps

1. **Classify before calling anything.** Identify the issuer from the prefix or the code that uses it. If the vendor designs the value to be public, your validation question changes from "is it live?" to "is it restricted?".

2. **Pick the least-privilege, read-only identity call** for that provider. The table summarises the checks we use; commands follow.

   | Credential | Check | What a success proves | Cost / side effect |
   |---|---|---|---|
   | AWS access key | `sts get-caller-identity` | Valid key, account ID, principal ARN | None; cannot be denied by IAM, logged in the owner's CloudTrail |
   | Cognito identity pool ID | `get-id` then `get-credentials-for-identity` | Unauthenticated role is enabled | Creates an identity ID |
   | AppSync API key | GraphQL `__typename` query | Key is valid for the API | None |
   | Google API key | Free metadata call (Gemini model list) or one request per suspect API | Key valid; which APIs are enabled for it | Paid APIs bill a fraction of a cent per call |
   | Firebase RTDB | `GET /.json?shallow=true` | World-readable database | Returns top-level keys only |
   | Firebase Storage | List objects with `maxResults=1` | World-listable bucket | Returns at most one object name |
   | Stripe secret key | `GET /v1/balance` | Live secret key | None, but reveals account data; record minimally |
   | Slack token | `auth.test` | Valid token, workspace and bot/user identity | None |
   | GitHub token | `GET /user`, read `X-OAuth-Scopes` | Valid token and (classic) scopes | None |
   | SendGrid key | `GET /v3/scopes` | Valid key and permission list | None |
   | Twilio SID + token | `GET /Accounts/<SID>.json` | Valid credentials | None |
   | OpenAI key | `GET /v1/models` | Valid key | None (no tokens consumed) |
   | Algolia key | `GET /1/keys/<key>` | Key's ACL (search-only vs admin) | None |

3. **AWS.** Identity only:

   ```bash
   ( export AWS_ACCESS_KEY_ID='AKIA...' AWS_SECRET_ACCESS_KEY='...' AWS_REGION=eu-west-2
     aws sts get-caller-identity )
   # {"UserId":"AIDA...","Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/mobile-uploader"}
   ```

   Stop here unless permission enumeration is explicitly in scope. The ARN usually tells you enough (`user/mobile-uploader`, `role/...admin...`). For a Cognito identity pool, check whether unauthenticated access is enabled and confirm the role it maps to:

   ```bash
   aws cognito-identity get-id --identity-pool-id 'eu-west-2:00000000-0000-0000-0000-000000000000' --region eu-west-2
   aws cognito-identity get-credentials-for-identity --identity-id 'eu-west-2:<id-from-previous-call>' --region eu-west-2
   # Use the temporary credentials with sts get-caller-identity to see the unauthenticated role ARN.
   ```

4. **AppSync.** A schema-agnostic no-op query:

   ```bash
   curl -s -X POST 'https://abcd1234.appsync-api.eu-west-2.amazonaws.com/graphql' \
     -H 'Content-Type: application/json' -H 'x-api-key: da2-...' \
     -d '{"query":"query { __typename }"}'
   # valid:   {"data": {"__typename": "Query"} }
   # invalid: {"errors":[{"errorType":"UnauthorizedException", ...
   ```

   To assess impact, read the operations used by the app's own code (they are in the package) and, if in scope, run one of those read queries with a limit of one item.

5. **Google Cloud and Firebase API keys.** First check whether the key is valid and unrestricted using a free call, then test the specific paid APIs the project plausibly uses with one request each:

   ```bash
   KEY='AIza...'
   curl -s "https://generativelanguage.googleapis.com/v1beta/models?key=$KEY" | head -c 300; echo
   curl -s "https://maps.googleapis.com/maps/api/geocode/json?address=London&key=$KEY" | head -c 300; echo
   ```

   Interpret the responses: a model list or `"status" : "OK"` means the API is enabled for this key; `SERVICE_DISABLED` ("has not been used in project … or it is disabled"), `API_KEY_SERVICE_BLOCKED` or "This API project is not authorized to use this API" means it is not usable with this key; "not authorized to use this API key" / `API_KEY_ANDROID_APP_BLOCKED` / `API_KEY_IOS_APP_BLOCKED` means an application restriction is in place.

   Application restrictions are enforced using headers the client sends. If a request is blocked by an Android or iOS restriction, demonstrate that the restriction is satisfied by anyone who has the package:

   ```bash
   apksigner verify --print-certs base.apk | grep 'SHA-1'
   curl -s "https://maps.googleapis.com/maps/api/geocode/json?address=London&key=$KEY" \
     -H 'X-Android-Package: com.example.app' \
     -H 'X-Android-Cert: <SHA-1 of the signing certificate, 40 hex chars without colons>'
   # iOS: -H 'X-Ios-Bundle-Identifier: com.example.app'
   ```

   This is not a reason to tell the client to drop restrictions; it is the reason restrictions must be paired with quotas, budget alerts and, for anything sensitive, a backend.

6. **Firebase data stores.** Use the project values from `strings.xml` or `GoogleService-Info.plist`:

   ```bash
   DB='https://example-app-default-rtdb.europe-west1.firebasedatabase.app'   # or https://<project>.firebaseio.com
   curl -s "$DB/.json?shallow=true"
   # locked: {"error" : "Permission denied"}
   # open:   {"users":true,"orders":true,"config":true}

   BUCKET='example-app.appspot.com'       # newer projects: example-app.firebasestorage.app
   curl -s "https://firebasestorage.googleapis.com/v0/b/$BUCKET/o?maxResults=1"

   PROJECT='example-app'                  # use a collection name taken from the app's code
   curl -s "https://firestore.googleapis.com/v1/projects/$PROJECT/databases/(default)/documents/users?pageSize=1&key=$KEY"
   ```

   Do not test write access by writing unless explicitly authorised. If you are, write a single uniquely named node under a path you choose, then delete it, and record both requests. Remote Config can be fetched with the public config and should be reviewed for secrets:

   ```bash
   curl -s -X POST "https://firebaseremoteconfig.googleapis.com/v1/projects/<project-number>/namespaces/firebase:fetch?key=$KEY" \
     -H 'Content-Type: application/json' \
     -d '{"appId":"<google_app_id>","appInstanceId":"gt-test-0001"}'
   ```

7. **SaaS tokens.** One identity call each:

   ```bash
   curl -s https://api.stripe.com/v1/balance -u 'sk_live_...:' | head -c 200; echo
   curl -s -X POST https://slack.com/api/auth.test -H 'Authorization: Bearer xoxb-...'
   curl -s -D - -o /dev/null https://api.github.com/user -H 'Authorization: Bearer ghp_...' | grep -i '^x-oauth-scopes'
   curl -s https://api.sendgrid.com/v3/scopes -H 'Authorization: Bearer SG....'
   curl -s -u 'AC...:<auth-token>' "https://api.twilio.com/2010-04-01/Accounts/AC....json" | head -c 200; echo
   curl -s https://api.openai.com/v1/models -H 'Authorization: Bearer sk-...' | head -c 200; echo
   curl -s "https://<APPID>-dsn.algolia.net/1/keys/<KEY>" -H 'X-Algolia-Application-Id: <APPID>' -H 'X-Algolia-API-Key: <KEY>'
   ```

   Do not post to Slack webhooks, send email or SMS, or create objects to "prove" write access. The scope lists returned above prove it without side effects.

8. **Tokens and keys without an API.** Decode JWTs locally and check `exp`, `iss`, `aud` and the subject:

   ```bash
   python3 -c 'import sys,base64;p=sys.argv[1].split(".")[1];print(base64.urlsafe_b64decode(p+"="*(-len(p)%4)).decode())' "$JWT"
   ```

   Inspect private keys and keystores locally (OpenSSL 3 may need `-legacy` for older PKCS#12 files):

   ```bash
   openssl pkey -in found.pem -noout -text | head -3
   openssl pkcs12 -in client.p12 -info -noout -passin 'pass:<password from the code>'
   ```

9. **Notify immediately** if you confirm a live production secret rated High or Critical. Rotation should not wait for the final report, and the client needs to know that the key is already in every published version of the app.

10. **Record evidence with redaction:** show only the first and last four characters of the secret, the exact request (with the secret masked), the response status and the minimum of response body needed to prove the point, the timestamp and your source IP.

#### Observation

For each candidate: the validity result (live, revoked, invalid, unverified), the owning account or project, the permissions or enabled APIs it has, the restriction status, and the redacted request/response evidence.

#### Evaluation

The finding is **confirmed** when a non-public credential is live, or when a public-by-design identifier leads to a misconfiguration (open rules, unrestricted billable APIs, an over-privileged unauthenticated role). A revoked or invalid credential is still reported (the client must find out how it got into the build and whether other copies are live), but at a lower severity. A credential you were not authorised to validate is reported as unverified and rated on its apparent type and usage, with that limitation stated.

## Secure implementation

The aim is that nothing in the package grants more than a public identifier does. The patterns below implement OWASP's mitigations, roughly in order of preference.

### Move vendor secrets behind a backend you control

If a third-party API needs a secret key, the app should call **your** backend, authenticated with the user's session, and the backend calls the vendor. The app never sees the vendor key, and you gain a place to enforce per-user rate limits, input validation and logging.

```kotlin
// App: calls your API with the user's short-lived access token. No vendor key in the package.
interface AssistantApi {
    @POST("v1/assistant/complete")
    suspend fun complete(@Header("Authorization") bearer: String, @Body req: CompletionRequest): CompletionResponse
}
```

```javascript
// Backend (Express): verifies the user, applies limits, then adds the vendor key from server-side config.
app.post('/v1/assistant/complete', requireUser, perUserRateLimit, async (req, res) => {
  const prompt = validatePrompt(req.body.prompt);           // size and content limits
  const r = await fetch('https://api.vendor.example/v1/complete', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${process.env.VENDOR_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ prompt, max_tokens: 512 })
  });
  res.status(r.status).json(await r.json());
});
```

A proxy that forwards anything with the vendor key attached, without authenticating the user, has only moved the problem: the proxy URL becomes the new shared secret. Authenticate and limit at the proxy.

### Issue short-lived, scoped credentials

Where the client genuinely needs to talk to a service directly (uploads, real-time media, maps tiles), have the backend mint a credential that is scoped to that user and expires quickly:

- **Cloud storage:** pre-signed upload/download URLs (S3) or signed URLs (Cloud Storage) for a single object and a few minutes, instead of bucket credentials.
- **AWS:** Cognito identity pools with an **authenticated** role tied to your user pool or OIDC provider, and either no unauthenticated role or one with near-zero permissions. The app receives temporary STS credentials, never long-term `AKIA` keys.
- **Real-time and messaging SDKs:** server-generated access tokens (most voice/video/chat vendors offer them) with a TTL measured in minutes to an hour.
- **User-delegated access:** OAuth 2.0 authorisation code flow with PKCE via AppAuth, registered as a native (public) client with no client secret, following RFC 8252.

### Bind backend access to genuine app instances

Attestation lets your backend (or Firebase) check that a request comes from your unmodified app on a genuine device. It does not authenticate the user and can be defeated with enough effort on a compromised device, but it removes the cheap attack of reusing a key from a script.

- **Firebase App Check** with the Play Integrity provider on Android and App Attest (DeviceCheck fallback) on iOS. Enable **enforcement** per product in the Firebase console once metrics show legitimate traffic is passing; monitoring mode alone protects nothing.

  ```kotlin
  Firebase.initialize(context)
  Firebase.appCheck.installAppCheckProviderFactory(PlayIntegrityAppCheckProviderFactory.getInstance())
  ```

  ```swift
  final class AttestProviderFactory: NSObject, AppCheckProviderFactory {
      func createProvider(with app: FirebaseApp) -> AppCheckProvider? { AppAttestProvider(app: app) }
  }
  AppCheck.setAppCheckProviderFactory(AttestProviderFactory())
  FirebaseApp.configure()
  ```

- **Your own backend** can require the App Check token as well and verify it server-side:

  ```javascript
  const { getAppCheck } = require('firebase-admin/app-check');
  async function requireAppCheck(req, res, next) {
    try { await getAppCheck().verifyToken(req.header('X-Firebase-AppCheck')); next(); }
    catch { res.status(401).end(); }
  }
  ```

- **Play Integrity API** and **App Attest** can be used directly without Firebase. On Android, request a token bound to a server nonce or request hash, decode it server-side and require `appRecognitionVerdict == PLAY_RECOGNIZED` and `MEETS_DEVICE_INTEGRITY`. On iOS, generate a key with `DCAppAttestService.generateKey`, attest it once with `attestKey(_:clientDataHash:)`, then sign each sensitive request with `generateAssertion(_:clientDataHash:)` and verify server-side, including the counter.

A sensible end state for "the app must reach a secret-bearing service" is: user session + attestation token at your proxy, vendor key on the server, short-lived scoped credential back to the app where direct access is needed.

### Restrict the keys you must ship

Some keys have to be in the package (Maps SDK, Firebase config). Make them worthless outside their intended use:

- **API restrictions** limit which Google APIs a key can call. A Maps SDK key should only allow the Maps SDK for Android or iOS; a Firebase key only the Firebase services the app uses. This stops the "public" key from being billed for Gemini, Places or anything else enabled on the project.
- **Application restrictions** bind the key to your Android package name plus signing-certificate SHA-1, or to your iOS bundle ID:

  ```bash
  gcloud services api-keys update projects/PROJECT_ID/locations/global/keys/KEY_ID \
    --allowed-application=sha1_fingerprint=AA:BB:CC:...:99,package_name=com.example.app \
    --api-target=service=maps-android-backend.googleapis.com

  gcloud services api-keys update projects/PROJECT_ID/locations/global/keys/IOS_KEY_ID \
    --allowed-bundle-ids=com.example.app \
    --api-target=service=maps-ios-backend.googleapis.com
  ```

  With Play App Signing, use the SHA-1 of the **app signing key** shown in Play Console, not your upload key, or the restriction will block production users. Remember that these restrictions are checked from client-supplied headers, so they deter casual reuse rather than authenticate (see the validation procedure). Use a **separate key per platform and per purpose** so one can be rotated without breaking the others.
- **Quotas and budget alerts.** Set per-API daily quotas close to real usage and a billing budget with alerts. This is what actually caps the damage when a restricted key is abused.
- **Vendor-specific publishable keys.** Use Stripe publishable keys (`pk_`) in the app and keep `sk_`/`rk_` on the server. Use Algolia search-only or secured API keys generated per user, never the admin key. Use Mapbox public (`pk.`) tokens with URL restrictions, never secret (`sk.`) tokens.
- **Lock down what the public config reaches.** For Firebase, write Security Rules that authorise per user and per document, and disable unused sign-in methods:

  ```text
  rules_version = '2';
  service cloud.firestore {
    match /databases/{database}/documents {
      match /users/{userId} {
        allow read, write: if request.auth != null && request.auth.uid == userId;
      }
    }
  }
  ```

### Keep secrets out of the build, and prove it in CI

Keeping secrets out of Git (Secrets Gradle Plugin, `.xcconfig` files in `.gitignore`, CI-injected variables) is necessary but not sufficient: those mechanisms inject the value into the package by design. The checks that matter are on both sides of the build.

- **Pre-commit and repository scanning** with gitleaks, including history:

  ```bash
  gitleaks git . -v                      # gitleaks >= 8.19; older: gitleaks detect -v
  gitleaks git . --log-opts="--all" -v   # every branch
  ```

- **CI on every pull request** (GitHub Actions example; the action needs the token for PR scanning):

{% raw %}
```yaml
name: secret-scan
on: [pull_request, push]
jobs:
  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```
{% endraw %}

- **Scan the built artefact, not just the source.** Secrets injected at build time only exist in the output. Add a release-pipeline step that decodes the APK/IPA and fails the build on findings:

  ```bash
  apktool d -f app-release.apk -o /tmp/apk-decoded
  gitleaks dir /tmp/apk-decoded --exit-code 1 --report-path gitleaks-apk.json
  unzip -q -o App.ipa -d /tmp/ipa && gitleaks dir /tmp/ipa --exit-code 1 --report-path gitleaks-ipa.json
  ```

- **Strip leftovers deliberately.** On Android, exclude stray files at packaging time:

  ```kotlin
  android {
      packaging {
          resources {
              excludes += listOf("**/*.kt", "**/*.java", "**/*.map", "**/.env", "**/README*")
          }
      }
  }
  ```

  On iOS, review each target's "Copy Bundle Resources" phase and remove source files, `.xcconfig`, `.env` and documentation. For React Native, Cordova and Capacitor, make sure release builds do not emit source maps into the web or bundle directory (upload them to your crash reporter instead). For Flutter, do not use `.env` assets for secrets; anything in `flutter_assets` is public.

### Treat every shipped secret as compromised

Removing a key from the next release does not un-ship it. Every published version of the app is archived by APK mirror sites and remains installable. Once a secret has been in a release package:

1. Rotate or revoke it at the provider immediately; check the provider's logs for prior abuse.
2. Replace it with one of the patterns above, not with a better-hidden copy.
3. If old app versions depend on the old key, use a forced-update mechanism and plan the cut-over rather than leaving the old key live indefinitely.

### Obfuscation and white-box as a last resort

String encryption (dProtect for Java/Kotlin, O-MVLL for native code), white-box cryptography and RASP increase the time an attacker spends, and they are legitimate defence-in-depth for keys that must exist on the client (DRM content keys, for example). They never change the classification of a finding from "secret in the package" to "secret protected", because the runtime recovery procedure above defeats all of them. If you rely on them, combine them with short key lifetimes, per-device keys where possible, server-side anomaly detection and the ability to rotate quickly.

## Rating findings

Rate on what the value grants after validation, not on how hard it was to extract. Obfuscation is not a mitigating factor; a live secret recovered in an hour is the same severity as one found with `strings`.

| Rating | Conditions |
|---|---|
| **Critical** | A live credential grants write or administrative access to production systems or broad access to user data: AWS keys with wide IAM permissions, database or storage admin credentials, `sk_live_` payment keys, CI/source-control tokens with write scope, a private key that signs tokens or firmware the backend trusts, or a Firebase database/storage readable or writable by anyone and containing personal data. |
| **High** | A live credential gives read access to non-public data, sends communications as the organisation (email, SMS, push, Slack), or enables billing abuse without effective limits (AI/ML API keys, an unrestricted Google key on a project with costly APIs). Also a symmetric key that decrypts user data stored on every device, or a shared mTLS client key and its password. |
| **Medium** | A live credential with limited scope that still allows abuse: quota exhaustion, data pollution through write-only analytics keys of business importance, an AppSync/API key exposing internal but non-personal data, an OAuth confidential client secret in a native app, or a reachable staging environment with weaker authentication than production. A credential reported as unverified because validation was out of scope usually lands here unless its type and usage clearly indicate higher impact. |
| **Low** | Revoked or expired credentials (the process failure remains), restricted keys whose only demonstrated impact is that client-header restrictions can be spoofed while quotas cap the damage, unreachable staging/internal hostnames, leftover source files or source maps without secrets, developer usernames in binary paths, test account names without working passwords. |
| **Info** | Values designed to be public and confirmed correctly configured: Firebase config with locked-down rules and App Check, Stripe publishable keys, Sentry DSNs, Algolia search-only keys, Facebook App ID and client token, a Maps key restricted by API and application with quotas. Report them as observations so the client knows they were reviewed. |

Adjust upwards when a finding chains with another (for example a "public" Firebase key plus anonymous sign-in plus `auth != null` rules on user data), and when the same secret appears across several apps from the same organisation.

## References

OWASP:

- [MASWE-0004: Sensitive Data Hardcoded in the App Package](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0004/) (CC BY-SA 4.0)
- [MASWE-0003: Cryptographic Keys Stored Outside of Platform Keystore](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0003/) (CC BY-SA 4.0)
- [MASWE-0061: Debug Artifacts Not Removed](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0061/) (CC BY-SA 4.0)
- [MASWE-0028: Insecure Identity Pinning](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0028/) (CC BY-SA 4.0)
- [MASTG-TEST-0212: Use of Hardcoded Cryptographic Keys in Code (Android)](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0212/) (CC BY-SA 4.0)
- [MASTG-TEST-0213: Use of Hardcoded Cryptographic Keys in Code (iOS)](https://mas.owasp.org/MASTG/tests/ios/MASVS-CRYPTO/MASTG-TEST-0213/) (CC BY-SA 4.0)
- [MASTG-TEST-0214: Hardcoded Cryptographic Keys in Files (iOS)](https://mas.owasp.org/MASTG/tests/ios/MASVS-CRYPTO/MASTG-TEST-0214/) (CC BY-SA 4.0)
- [MASTG-TEST-0233: Hardcoded HTTP URLs (Android)](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0233/) and [MASTG-TEST-0321 (iOS)](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0321/) (CC BY-SA 4.0)
- [MASTG-KNOW-0033: Obfuscation (Android)](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0033/), [MASTG-KNOW-0089 (iOS)](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0089/), [MASTG-KNOW-0111 (generic)](https://mas.owasp.org/MASTG/knowledge/generic/MASVS-RESILIENCE/MASTG-KNOW-0111/) (CC BY-SA 4.0)
- [MASTG-KNOW-0064: Non-Production Resources](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CODE/MASTG-KNOW-0064/) (CC BY-SA 4.0)
- [MASTG-KNOW-0004: Third-Party Libraries (Android)](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0004/) and [MASTG-KNOW-0059 (iOS)](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CODE/MASTG-KNOW-0059/) (CC BY-SA 4.0)
- Techniques: [MASTG-TECH-0003](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0003/), [MASTG-TECH-0007](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0007/), [MASTG-TECH-0017](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0017/), [MASTG-TECH-0019](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0019/), [MASTG-TECH-0130](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0130/), [MASTG-TECH-0145](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0145/), [MASTG-TECH-0156](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0156/), [MASTG-TECH-0157](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0157/), [MASTG-TECH-0165](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0165/), [MASTG-TECH-0054](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0054/), [MASTG-TECH-0058](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0058/), [MASTG-TECH-0070](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0070/), [MASTG-TECH-0098](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0098/), [MASTG-TECH-0132](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0132/), [MASTG-TECH-0138](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0138/), [MASTG-TECH-0071](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0071/), [MASTG-TECH-0120](https://mas.owasp.org/MASTG/techniques/generic/MASTG-TECH-0120/) (CC BY-SA 4.0)
- Tools: [MASTG-TOOL-0009 APKiD](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0009/), [MASTG-TOOL-0011 Apktool](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/), [MASTG-TOOL-0018 jadx](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/), [MASTG-TOOL-0116 blutter](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0116/), [MASTG-TOOL-0124 aapt2](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0124/), [MASTG-TOOL-0125 Apkleaks](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0125/), [MASTG-TOOL-0104 hermes-dec](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0104/), [MASTG-TOOL-0110 semgrep](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/), [MASTG-TOOL-0129 rabin2](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0129/), [MASTG-TOOL-0144 gitleaks](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0144/), [MASTG-TOOL-0050 frida-ios-dump](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0050/), [MASTG-TOOL-0062 plutil](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0062/), [MASTG-TOOL-0073 radare2 (iOS)](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0073/) (CC BY-SA 4.0)

Vendor and standards documentation:

- [Google Cloud: Best practices for securing API keys](https://cloud.google.com/docs/authentication/api-keys#securing) and [API key restrictions](https://cloud.google.com/docs/authentication/api-keys#api_key_restrictions)
- [Firebase: Learn about using and managing API keys for Firebase](https://firebase.google.com/docs/projects/api-keys)
- [Firebase Security Rules](https://firebase.google.com/docs/rules) and [Firebase App Check](https://firebase.google.com/docs/app-check)
- [Firebase Realtime Database REST API](https://firebase.google.com/docs/reference/rest/database)
- [Google Services Gradle plugin: processing the JSON file](https://developers.google.com/android/guides/google-services-plugin)
- [Secrets Gradle Plugin for Android](https://github.com/google/secrets-gradle-plugin)
- [Android Developers: Play Integrity API](https://developer.android.com/google/play/integrity)
- [Apple Developer: Establishing your app's integrity (App Attest)](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity)
- [AWS STS: GetCallerIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html)
- [RFC 8252: OAuth 2.0 for Native Apps](https://datatracker.ietf.org/doc/html/rfc8252) and [AppAuth](https://appauth.io/)
- [Expo: Environment variables](https://docs.expo.dev/guides/environment-variables/)
- [Flutter: Obfuscating Dart code](https://docs.flutter.dev/deployment/obfuscate)
- [gitleaks](https://github.com/gitleaks/gitleaks) and [gitleaks-action](https://github.com/gitleaks/gitleaks-action)
- [CWE-798](https://cwe.mitre.org/data/definitions/798.html), [CWE-540](https://cwe.mitre.org/data/definitions/540.html), [CWE-321](https://cwe.mitre.org/data/definitions/321.html), [CWE-312](https://cwe.mitre.org/data/definitions/312.html)

> Adapted and extended from the OWASP MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
