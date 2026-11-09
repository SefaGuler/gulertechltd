---
title: "MASVS-STORAGE-1: Testing Secure Storage of Sensitive Data on Android and iOS"
date: 2026-11-08 12:05:00 +0000
subcategory: storage
summary: "Hub for the MASVS-STORAGE-1 series: the four MASWE weaknesses, every linked MASTG Knowledge and Test item, a test plan, and a command cheat sheet."
refs: [MASVS-STORAGE-1, MASWE-0001, MASWE-0002, MASWE-0003, MASWE-0004]
tags: [android, ios, masvs-storage, data-storage, methodology]
---

This is the entry point to a series of notes covering **OWASP MASVS-STORAGE-1 — "The app securely stores sensitive data"** end to end. It follows the structure OWASP uses on the [MASWE](https://mas.owasp.org/MASWE/) site: the control is broken down into four weaknesses, and each weakness note carries its own **Knowledge** (how the platform works) and **Tests** (how to prove the weakness is or is not present). This page maps the whole area, gives you a test plan, and collects the commands you will use most.

## Contents

- [What MASVS-STORAGE-1 covers](#what-masvs-storage-1-covers)
- [The four weaknesses](#the-four-weaknesses)
- [Knowledge and Tests map](#knowledge-and-tests-map)
- [What counts as sensitive data](#what-counts-as-sensitive-data)
- [Where data should live: a decision guide](#where-data-should-live-a-decision-guide)
- [Test plan](#test-plan)
- [Command cheat sheet](#command-cheat-sheet)
- [Reporting storage findings](#reporting-storage-findings)
- [References](#references)

## What MASVS-STORAGE-1 covers

Apps receive sensitive data from the user, the backend, system services and other apps, and most of them persist some of it locally. MASVS-STORAGE-1 is about data the app stores **on purpose**: whatever the destination — the private sandbox, shared/external storage, the keystore, or the app package itself — the data must be protected appropriately for that location.

Its sibling control, **MASVS-STORAGE-2 — "The app prevents leakage of sensitive data"**, covers *unintentional* storage: logs (MASWE-0005), backups (MASWE-0006), and similar side-effects of platform APIs. The boundary matters when you write a report: a session token written to `SharedPreferences` in plaintext is STORAGE-1; the same token turning up in `logcat` is STORAGE-2. Several weaknesses (MASWE-0001, MASWE-0002) are mapped to both controls, because data stored unencrypted in the sandbox is also what ends up in a backup.

Two things the control does **not** assume:

- **That the sandbox is a security boundary you can rely on alone.** The sandbox stops other apps, not an attacker with a rooted/jailbroken device, a forensic image, an exploit chain, a backup, or physical access to an unlocked phone. That is why MASWE-0001 exists at all.
- **That obfuscation protects anything at rest.** Anything shipped in the APK/IPA, or written to disk with a key that is also on disk, should be treated as readable.

## The four weaknesses

| ID | Weakness | Platforms | Profiles | Linked tests | Note |
|----|----------|-----------|----------|--------------|------|
| MASWE-0001 | Sensitive Data Stored Unencrypted in Private Storage | Android, iOS | L2, EUDIW | 11 | [Read](/mobile/maswe-0001-sensitive-data-unencrypted-private-storage/) |
| MASWE-0002 | Sensitive Data Stored Unencrypted Outside of Private Storage | Android, iOS | L1, L2, EUDIW | 4 | [Read](/mobile/maswe-0002-sensitive-data-unencrypted-outside-private-storage/) |
| MASWE-0003 | Cryptographic Keys Stored Outside of Platform Keystore | Android, iOS | L1, L2, EUDIW | 3 | [Read](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/) |
| MASWE-0004 | Sensitive Data Hardcoded in the App Package | Android, iOS | L1, L2, EUDIW | 0 (methodology note) | [Read](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/) |

The profile column tells you when a weakness applies. **L1** is the baseline for every app. **L2** is defence-in-depth for apps handling highly sensitive data (banking, health, government ID), which is why encrypting data *inside* the sandbox (MASWE-0001) is an L2 requirement while not writing it to shared storage in the clear (MASWE-0002) applies to everyone. **EUDIW** is the profile for EU Digital Identity Wallet apps.

In short:

- **MASWE-0001** — the data is in the right place (the sandbox) but stored in plaintext, protected with a key that sits next to it, or exposed through loose permissions, shared containers or stale caches.
- **MASWE-0002** — the data is in the wrong place: external/shared storage, `MediaStore`, the Files app, or a document exported by the user, without encryption.
- **MASWE-0003** — the keys that protect everything else are themselves stored outside the Android Keystore / iOS Keychain or Secure Enclave: in code, in resources, in preferences or files.
- **MASWE-0004** — secrets ship inside the package: API keys, credentials, private keys, staging endpoints, developer leftovers.

## Knowledge and Tests map

Every OWASP item linked from the four weaknesses, and where it is covered in this series.

### MASWE-0001 — Sensitive Data Stored Unencrypted in Private Storage

| Type | ID | Title | Platform |
|------|----|-------|----------|
| Knowledge | MASTG-KNOW-0041 | Internal Storage | Android |
| Knowledge | MASTG-KNOW-0036 | Shared Preferences | Android |
| Knowledge | MASTG-KNOW-0037 | SQLite Database | Android |
| Knowledge | MASTG-KNOW-0018 | WebViews | Android |
| Knowledge | MASTG-KNOW-0108 | App Sandbox Directories | iOS |
| Knowledge | MASTG-KNOW-0091 | File System APIs | iOS |
| Knowledge | MASTG-KNOW-0057 | Keychain Services | iOS |
| Knowledge | MASTG-KNOW-0082 | App Extensions | iOS |
| Test | MASTG-TEST-0207 | Runtime Storage of Unencrypted Data in the App Sandbox | Android |
| Test | MASTG-TEST-0287 | Runtime Storage of Unencrypted Data via the SharedPreferences API | Android |
| Test | MASTG-TEST-0305 | Sensitive Data Stored Unencrypted via DataStore | Android |
| Test | MASTG-TEST-0304 | References to Sensitive Data Unencrypted via Android Room Database | Android |
| Test | MASTG-TEST-0306 | References to Sensitive Data Stored Unencrypted via Android Room DB | Android |
| Test | MASTG-TEST-0320 | WebViews Not Cleaning Up Sensitive Data | Android |
| Test | MASTG-TEST-0299 | Data Protection Classes for Files in Private Storage | iOS |
| Test | MASTG-TEST-0300 | References to APIs for Storing Unencrypted Data in Private Storage | iOS |
| Test | MASTG-TEST-0301 | Runtime Use of APIs for Storing Unencrypted Data in Private Storage | iOS |
| Test | MASTG-TEST-0302 | Sensitive Data Unencrypted in Private Storage Files | iOS |
| Test | MASTG-TEST-0388 | References to Sensitive Data Stored Unprotected in Shared App Group Containers | iOS |
| Best practice | MASTG-BEST-0050 | Store Data Encrypted in App Sandbox Directory | Android |
| Best practice | MASTG-BEST-0028 | WebViews Cache Cleanup | Android |
| Best practice | MASTG-BEST-0024 | Store Data Encrypted in App Sandbox Directory | iOS |
| Best practice | MASTG-BEST-0068 | Secure Data Sharing Between App Extensions and Containing Apps | iOS |

### MASWE-0002 — Sensitive Data Stored Unencrypted Outside of Private Storage

| Type | ID | Title | Platform |
|------|----|-------|----------|
| Knowledge | MASTG-KNOW-0042 | External Storage | Android |
| Knowledge | MASTG-KNOW-0122 | Document Picker, Document Interaction, and Open in Place | iOS |
| Test | MASTG-TEST-0200 | Files Written to External Storage | Android |
| Test | MASTG-TEST-0201 | Runtime Use of APIs to Access External Storage | Android |
| Test | MASTG-TEST-0202 | References to APIs and Permissions for Accessing External Storage | Android |
| Test | MASTG-TEST-0303 | References to APIs for Storing Unencrypted Data in Shared Storage | iOS |

### MASWE-0003 — Cryptographic Keys Stored Outside of Platform Keystore

| Type | ID | Title | Platform |
|------|----|-------|----------|
| Knowledge | MASTG-KNOW-0012 | Key Generation | Android |
| Test | MASTG-TEST-0212 | Use of Hardcoded Cryptographic Keys in Code | Android |
| Test | MASTG-TEST-0213 | Use of Hardcoded Cryptographic Keys in Code | iOS |
| Test | MASTG-TEST-0214 | Hardcoded Cryptographic Keys in Files | iOS |

### MASWE-0004 — Sensitive Data Hardcoded in the App Package

OWASP has not yet linked any Knowledge or Test items to MASWE-0004. The [MASWE-0004 note](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/) covers it with our own methodology, and cross-references the hardcoded-key tests under MASWE-0003.

## What counts as sensitive data

Before you can say "sensitive data is stored unencrypted", you need to agree on what is sensitive for *this* app. Agree it with the client at scoping and write it into the report, otherwise every storage finding turns into an argument about severity. A workable baseline:

| Class | Examples | Default expectation |
|-------|----------|---------------------|
| Authentication material | passwords, PINs, session/refresh tokens, OAuth codes, cookies, biometric-bound secrets | Never in plaintext anywhere. Tokens in Keychain / Keystore-encrypted storage only. |
| Cryptographic material | symmetric keys, private keys, key seeds, wrapped DEKs | Generated and held inside the Keystore / Keychain / Secure Enclave; non-exportable where possible. |
| Regulated personal data | name + address, national ID, passport/ID document images, health data, precise location history, financial data (PAN, IBAN, balances) | Avoid storing; if required, encrypted at rest with a keystore-backed key and removed when no longer needed. |
| Business-sensitive data | premium/entitlement flags, licence state, pricing, internal endpoints, feature flags that gate paid features | Integrity-protected; never trusted from local storage alone. |
| Low sensitivity | UI preferences, cached public content, non-identifying analytics IDs | Plaintext in the sandbox is acceptable. |

Two practical rules:

- **Use canary values.** Create test accounts with distinctive data (`CANARY-PAN-4111…`, a username like `gt-canary-7f3a`) so you can grep the whole sandbox for them after each flow. This is the single most effective way to find storage issues, and it is what the OWASP dynamic tests do.
- **Judge by what an attacker gains**, not by the API used. A plaintext JWT with a 30-day refresh lifetime is worse than an encrypted blob with the key sitting next to it, which is worse than correctly Keystore-backed data.

## Where data should live: a decision guide

Use this when writing remediation advice — it is the short version of the mitigations in each note.

1. **Does the app need to store it at all?** If the value can be fetched from the backend when needed, or held in memory for the session, do that. Clear caches and tokens on logout.
2. **Is it a key or credential?** Put it in the **Android Keystore** (generated on device, ideally StrongBox-backed for high-value keys) or the **iOS Keychain** with the strictest workable accessibility class (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly` or `…WhenPasscodeSetThisDeviceOnly`), or the **Secure Enclave** for asymmetric keys. See [MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/).
3. **Is it other sensitive data that must persist?** Keep it in the app's **private storage** and **encrypt it** with a keystore-backed key (envelope encryption: a data key wrapped by a non-exportable key). On iOS, also set file protection to `.complete` where the app's background behaviour allows it. See [MASWE-0001](/mobile/maswe-0001-sensitive-data-unencrypted-private-storage/).
4. **Must it be shared with other apps or the user?** Share through a `FileProvider` with per-URI grants (Android) or a document picker / App Group with minimal contents (iOS). Do not write sensitive data to external or shared storage; if there is no alternative, encrypt it first. See [MASWE-0002](/mobile/maswe-0002-sensitive-data-unencrypted-outside-private-storage/).
5. **Is it a secret the app "needs to ship with"?** It almost certainly does not. Move it server-side behind a proxy, or replace it with short-lived tokens plus app attestation. See [MASWE-0004](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/).

## Test plan

The order below gets you the most coverage per hour on a typical engagement. Each step names the notes and tests it exercises.

### 1. Lab setup

- **Android:** a rooted physical device or a Google APIs (not Google Play) emulator image, so `adb root` works. Install Frida server and objection. If the build is debuggable, `run-as <package>` gives sandbox access on a non-rooted device.
- **iOS:** a jailbroken device on an iOS version the app supports (rootless jailbreaks put tools under `/var/jb`), Frida, objection, and a **decrypted** IPA for static work (App Store binaries are FairPlay-encrypted).
- Static toolkit: `jadx`, `apktool`, `semgrep`, `radare2`/`rabin2`, `gitleaks`, `sqlite3`, `plutil`.
- Test accounts loaded with canary values (see above).

### 2. Static pass on the package (MASWE-0004, MASWE-0003, plus "References to…" tests)

- Decompile and grep for secrets, keys, endpoints and leftovers ([MASWE-0004](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/)).
- Look for hardcoded key material passed to crypto APIs: MASTG-TEST-0212 (Android), MASTG-TEST-0213 / 0214 (iOS) ([MASWE-0003](/mobile/maswe-0003-crypto-keys-outside-platform-keystore/)).
- Enumerate storage APIs used: `SharedPreferences`, `DataStore`, Room/SQLite, `openFileOutput`, `getExternal*`, `MediaStore` on Android (MASTG-TEST-0202, 0304, 0305, 0306); `UserDefaults`, `Data.write(to:options:)`, `FileManager.createFile`, `NSFileProtection*`, App Group containers on iOS (MASTG-TEST-0300, 0303, 0388).
- Check the manifest / `Info.plist` for storage-related configuration: `requestLegacyExternalStorage`, storage permissions, `FileProvider` paths, `UIFileSharingEnabled`, `LSSupportsOpeningDocumentsInPlace`, App Group entitlements.

### 3. Dynamic pass (runtime hooks)

- Hook the storage APIs while you walk through every sensitive flow (login, profile, payments, document upload, logout), and record what is written and where: MASTG-TEST-0201, 0207, 0287 (Android), MASTG-TEST-0301 (iOS).

### 4. Filesystem pass (what actually ended up on disk)

- Snapshot the sandbox **before** and **after** each flow, then diff and grep for canaries: MASTG-TEST-0207, 0200 (Android), MASTG-TEST-0302 (iOS).
- Check file protection classes on iOS: MASTG-TEST-0299.
- Check what the WebView left behind after logout: MASTG-TEST-0320.
- Check external/shared storage locations, not just the sandbox.

### 5. Lifecycle checks

- **Logout:** is data removed (tokens, caches, databases, WebView state, App Group files)?
- **Reinstall (iOS):** Keychain items survive app deletion on iOS; check whether the app trusts stale tokens on first launch.
- **Locked device (iOS):** for files that claim `.complete` protection, confirm they are unreadable while the device is locked.

### 6. Correlate and rate

Tie each finding back to the MASWE, the test that proved it, and a concrete attacker scenario (rooted device, backup extraction, malicious app with storage permission, physical access). Use the "Rating findings" section in each note.

## Command cheat sheet

### Android

```bash
# Package name and paths
adb shell pm list packages | grep -i <keyword>
adb shell pm path <package>

# Sandbox access (rooted / emulator)
adb root
adb shell ls -la /data/data/<package>/
adb shell ls -la /data/data/<package>/{shared_prefs,databases,files,cache,no_backup,app_webview}

# Sandbox access on a debuggable build, no root
adb shell run-as <package> ls -la
adb exec-out run-as <package> cat shared_prefs/<file>.xml

# Pull the whole sandbox for offline grep
adb shell "su -c 'tar -C /data/data -czf /data/local/tmp/sb.tgz <package>'"
adb pull /data/local/tmp/sb.tgz && mkdir sb && tar -xzf sb.tgz -C sb
grep -rnaI -E 'CANARY|eyJ[A-Za-z0-9_-]{10,}\.' sb/

# SQLite databases
sqlite3 sb/<package>/databases/<db> '.tables'
sqlite3 sb/<package>/databases/<db> '.dump' | grep -i canary

# External storage owned by the app
adb shell ls -laR /sdcard/Android/data/<package>/
adb shell find /sdcard -newer /data/local/tmp/marker -type f 2>/dev/null

# objection
objection -g <package> explore
#   env
#   android keystore list
```

### iOS

```bash
# Find the app's containers on a jailbroken device
objection -g <bundle-id> explore
#   env                       -> BundlePath, DocumentDirectory, LibraryDirectory, CachesDirectory
#   ios keychain dump
#   ios nsuserdefaults get
#   ios plist cat <path>

# Or by hand over SSH
find /var/mobile/Containers/Data/Application -maxdepth 2 -name '.com.apple.mobile_container_manager.metadata.plist' \
  -exec sh -c 'plutil -p "$1" | grep -q "<bundle-id>" && dirname "$1"' _ {} \;

# App Group containers
ls /var/mobile/Containers/Shared/AppGroup/

# Pull and grep
scp -r root@<device>:/var/mobile/Containers/Data/Application/<UUID> ./sb
grep -rnaI 'CANARY' ./sb
plutil -p ./sb/Library/Preferences/<bundle-id>.plist
sqlite3 ./sb/Library/Caches/<bundle-id>/Cache.db '.tables'
```

### Static

```bash
# Android
jadx -d out/ app.apk
apktool d app.apk -o apktool_out/
grep -rnE 'getSharedPreferences|openFileOutput|getExternalFilesDir|getExternalStorageDirectory|MediaStore|SecretKeySpec' out/
gitleaks dir out/ --no-banner

# iOS (decrypted IPA)
unzip -q app.ipa -d ipa/
rabin2 -zz ipa/Payload/*.app/<binary> | grep -iE 'api[_-]?key|secret|token|-----BEGIN'
plutil -p ipa/Payload/*.app/Info.plist
```

The command syntax for each step is explained in context in the individual notes.

## Reporting storage findings

- **Name the weakness and the evidence.** "MASWE-0001 — session refresh token stored in plaintext in `shared_prefs/auth.xml` (MASTG-TEST-0207)" is a finding; "insecure data storage" is not.
- **State the attacker precondition honestly.** Most private-storage findings need a rooted/jailbroken device, a backup, malware with a privilege-escalation exploit, or physical access. That does not make them informational — it is exactly the threat L2 exists for — but it should drive the rating.
- **Show the data, redacted.** Include the file path, the relevant key/column, and a redacted value. Never paste real user data into a report.
- **Give remediation that fits the platform**: Keystore-backed encryption and `FileProvider` on Android; Keychain accessibility classes, Data Protection, and App Group hygiene on iOS. Point out the Jetpack Security deprecation if you recommend `EncryptedSharedPreferences`.
- **Group duplicates.** Twelve plaintext preference keys from one root cause are one finding with twelve evidence items.

## References

- OWASP MASVS — [MASVS-STORAGE-1](https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/) (CC BY-SA 4.0)
- OWASP MASWE — [Weakness index](https://mas.owasp.org/MASWE/) (CC BY-SA 4.0)
- OWASP MASWE — [MASWE-0001](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0001/), [MASWE-0002](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0002/), [MASWE-0003](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0003/), [MASWE-0004](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0004/) (CC BY-SA 4.0)
- OWASP MASTG — [Knowledge](https://mas.owasp.org/MASTG/knowledge/), [Tests](https://mas.owasp.org/MASTG/tests/), [Best Practices](https://mas.owasp.org/MASTG/best-practices/) (CC BY-SA 4.0)
- [Android Developers — Data and file storage overview](https://developer.android.com/training/data-storage)
- [Android Developers — Security tips: internal and external storage](https://developer.android.com/privacy-and-security/security-tips)
- [Apple — Encrypting your app's files](https://developer.apple.com/documentation/uikit/protecting_the_user_s_privacy/encrypting_your_app_s_files)
- [Apple Platform Security Guide — Data Protection](https://support.apple.com/guide/security/data-protection-overview-secf6276da8a/web)

> Adapted and extended from the OWASP MASVS, MASWE and MASTG (https://mas.owasp.org), licensed under CC BY-SA 4.0. This note is distributed under the same licence.
